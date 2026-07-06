// ═══════════════════════════════════════════════════════════════════════════
// VM Bytecode Decoder — JSON-driven implementation.
//
// Loads a decoder descriptor from JSON and uses multi-level mask+compare
// routing + bit-field extraction micro-ops to decode VM instruction words
// into human-readable assembly text.
//
// See vm_decoder.h for the design overview.
// ═══════════════════════════════════════════════════════════════════════════

#include "analysis/passes/vm/vm_decoder.h"

#include <fmt/core.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace tenet {

using json = nlohmann::json;

// ─── Default batch decode ────────────────────────────────────────────────

std::vector<VMDecodedInsn>
VMBytecodeDecoder::decode_all(const std::vector<VMStep>& steps,
                               const VMAbstractResult& ctx) const {
    std::vector<VMDecodedInsn> out;
    out.reserve(steps.size());
    for (const auto& s : steps) {
        out.push_back(decode(s, ctx));
    }
    return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// Bit-field extraction micro-ops
// ═══════════════════════════════════════════════════════════════════════════

/// A single micro-op in a bit-field extraction pipeline.
/// Operates on a (value, accumulator) pair; the final result is
/// `accumulator | value` after all ops execute.
struct ExtractOp {
    enum class Kind : uint8_t {
        Lsr,          // value >>= imm
        Lsl,          // value <<= imm
        And,          // value &= imm
        Or,           // value |= imm
        Xor,          // value ^= imm
        LsrAnd,      // value = (value >> lsr_imm) & and_imm  (combined)
        OrAccum,      // accum |= value; value = 0  (flush to accumulator)
        Sext,         // sign-extend value from `imm` bits
        Mul,          // value *= imm  (for ×4 branch offset scaling etc.)
    };
    Kind     kind;
    uint64_t imm = 0;       // primary immediate
    uint64_t imm2 = 0;      // secondary (for LsrAnd: and_mask)
};

/// Execute an extraction pipeline on a word, returning the decoded value.
static uint64_t run_extract(const std::vector<ExtractOp>& ops, uint64_t word) {
    uint64_t val = word;
    uint64_t accum = 0;
    for (const auto& op : ops) {
        switch (op.kind) {
            case ExtractOp::Kind::Lsr:     val >>= (op.imm & 63); break;
            case ExtractOp::Kind::Lsl:     val <<= (op.imm & 63); break;
            case ExtractOp::Kind::And:     val &= op.imm; break;
            case ExtractOp::Kind::Or:      val |= op.imm; break;
            case ExtractOp::Kind::Xor:     val ^= op.imm; break;
            case ExtractOp::Kind::LsrAnd:  val = (val >> (op.imm & 63)) & op.imm2; break;
            case ExtractOp::Kind::OrAccum: accum |= val; val = word; break;
            case ExtractOp::Kind::Sext: {
                uint64_t w = op.imm & 63;
                if (w > 0 && w < 64) {
                    uint64_t sign_bit = uint64_t(1) << (w - 1);
                    val = (val ^ sign_bit) - sign_bit;
                }
                break;
            }
            case ExtractOp::Kind::Mul:     val *= op.imm; break;
        }
    }
    return accum | val;
}

// ═══════════════════════════════════════════════════════════════════════════
// Routing rule
// ═══════════════════════════════════════════════════════════════════════════

/// Operand display type.
enum class OperandDisplayType : uint8_t {
    VmReg,         // value is a register index → "R{value}"
    Imm,           // decimal immediate
    ImmHex,        // hex immediate → "0x{value:X}"
    ImmSigned,     // signed decimal (value treated as sign-extended)
    BranchRel,     // relative branch offset (×scale, from current vm_pc)
    BranchAbs,     // absolute branch target (vm_pc + offset)
    Raw,           // raw hex, no decoration
};

/// Display descriptor for one named operand.
struct OperandDisplay {
    std::string         name;
    OperandDisplayType  type = OperandDisplayType::Raw;
    std::string         prefix;      // register prefix (e.g. "R", "V")
    int64_t             scale = 1;   // branch offset scale factor
    std::vector<ExtractOp> extract;  // extraction pipeline from the word
};

/// A single routing rule: mask+match → mnemonic + operand extraction.
struct RoutingRule {
    uint64_t    mask = 0;
    uint64_t    match = 0;
    std::string mnemonic;
    std::string format;     // format string with {name} placeholders
    std::vector<OperandDisplay> operands;
};

// ═══════════════════════════════════════════════════════════════════════════
// JsonDrivenDecoder implementation
// ═══════════════════════════════════════════════════════════════════════════

class JsonDrivenDecoder final : public VMBytecodeDecoder {
public:
    explicit JsonDrivenDecoder(std::string name,
                                std::vector<RoutingRule> rules,
                                std::string default_op,
                                std::string reg_prefix,
                                uint32_t reg_count)
        : name_(std::move(name))
        , rules_(std::move(rules))
        , default_op_(std::move(default_op))
        , reg_prefix_(std::move(reg_prefix))
        , reg_count_(reg_count) {}

    std::string_view name() const override { return name_; }

    VMDecodedInsn decode(const VMStep& step,
                          const VMAbstractResult& /*ctx*/) const override {
        if (!step.opcode_valid) {
            return {"???", "???", false};
        }

        uint64_t word = step.opcode_value;

        // Walk routing rules in order — first match wins.
        for (const auto& rule : rules_) {
            if ((word & rule.mask) != rule.match) continue;

            // Extract operand values.
            std::vector<std::pair<std::string, std::string>> named_values;
            named_values.reserve(rule.operands.size());

            for (const auto& opd : rule.operands) {
                uint64_t val = run_extract(opd.extract, word);
                std::string text = format_operand(opd, val, step);
                named_values.emplace_back(opd.name, std::move(text));
            }

            // Build asm_text from format string.
            std::string asm_text = rule.mnemonic;
            if (!rule.format.empty()) {
                asm_text += " ";
                asm_text += expand_format(rule.format, named_values);
            }

            return {rule.mnemonic, std::move(asm_text), true};
        }

        // No rule matched — use default.
        std::string text = default_op_.empty()
            ? fmt::format("UNK 0x{:08X}", word)
            : fmt::format("{} 0x{:08X}", default_op_, word);
        return {default_op_.empty() ? "UNK" : default_op_, std::move(text), false};
    }

private:
    std::string name_;
    std::vector<RoutingRule> rules_;
    std::string default_op_;
    std::string reg_prefix_;
    uint32_t    reg_count_ = 32;

    /// Format a single operand value according to its display type.
    std::string format_operand(const OperandDisplay& opd,
                                uint64_t val,
                                const VMStep& step) const {
        switch (opd.type) {
            case OperandDisplayType::VmReg: {
                const auto& pfx = opd.prefix.empty() ? reg_prefix_ : opd.prefix;
                return fmt::format("{}{}", pfx, val & 0x1F);
            }
            case OperandDisplayType::Imm:
                return fmt::format("{}", val);
            case OperandDisplayType::ImmHex:
                return fmt::format("0x{:X}", val);
            case OperandDisplayType::ImmSigned: {
                auto sval = static_cast<int64_t>(val);
                if (sval < 0) return fmt::format("-0x{:X}", static_cast<uint64_t>(-sval));
                return fmt::format("0x{:X}", val);
            }
            case OperandDisplayType::BranchRel: {
                auto sval = static_cast<int64_t>(val);
                if (sval < 0) return fmt::format("-0x{:X}", static_cast<uint64_t>(-sval));
                return fmt::format("+0x{:X}", val);
            }
            case OperandDisplayType::BranchAbs: {
                if (step.vm_pc_valid) {
                    auto sval = static_cast<int64_t>(val);
                    uint64_t target = step.vm_pc_value + sval;
                    return fmt::format("0x{:X}", target);
                }
                // Fallback to relative if no VM-PC.
                auto sval = static_cast<int64_t>(val);
                if (sval < 0) return fmt::format("VPC-0x{:X}", static_cast<uint64_t>(-sval));
                return fmt::format("VPC+0x{:X}", val);
            }
            case OperandDisplayType::Raw:
            default:
                return fmt::format("0x{:X}", val);
        }
    }

    /// Expand a format string like "{dst}, {src1}, {src2}" using named values.
    static std::string expand_format(
            const std::string& fmt_str,
            const std::vector<std::pair<std::string, std::string>>& named) {
        std::string out;
        out.reserve(fmt_str.size() + 32);
        size_t i = 0;
        while (i < fmt_str.size()) {
            if (fmt_str[i] == '{') {
                size_t end = fmt_str.find('}', i + 1);
                if (end == std::string::npos) {
                    out.push_back(fmt_str[i]);
                    i++;
                    continue;
                }
                std::string key = fmt_str.substr(i + 1, end - i - 1);
                bool found = false;
                for (const auto& [k, v] : named) {
                    if (k == key) {
                        out += v;
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    out += "{";
                    out += key;
                    out += "}";
                }
                i = end + 1;
            } else {
                out.push_back(fmt_str[i]);
                i++;
            }
        }
        return out;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// JSON parsing helpers
// ═══════════════════════════════════════════════════════════════════════════

namespace {

uint64_t parse_hex_or_int(const json& v) {
    if (v.is_number_unsigned()) return v.get<uint64_t>();
    if (v.is_number_integer()) return static_cast<uint64_t>(v.get<int64_t>());
    if (v.is_string()) {
        const auto& s = v.get_ref<const std::string&>();
        return std::stoull(s, nullptr, 0);  // auto-detect 0x prefix
    }
    return 0;
}

OperandDisplayType parse_display_type(const std::string& s) {
    if (s == "vm_reg" || s == "reg")        return OperandDisplayType::VmReg;
    if (s == "imm" || s == "decimal")       return OperandDisplayType::Imm;
    if (s == "imm_hex" || s == "hex")       return OperandDisplayType::ImmHex;
    if (s == "imm_signed" || s == "signed") return OperandDisplayType::ImmSigned;
    if (s == "branch_rel")                  return OperandDisplayType::BranchRel;
    if (s == "branch_abs")                  return OperandDisplayType::BranchAbs;
    if (s == "raw")                         return OperandDisplayType::Raw;
    return OperandDisplayType::Raw;
}

ExtractOp parse_extract_op(const json& j) {
    ExtractOp op;
    std::string kind = j.value("op", std::string{});

    if (kind == "lsr") {
        op.kind = ExtractOp::Kind::Lsr;
        op.imm = parse_hex_or_int(j.at("imm"));
    } else if (kind == "lsl") {
        op.kind = ExtractOp::Kind::Lsl;
        op.imm = parse_hex_or_int(j.at("imm"));
    } else if (kind == "and") {
        op.kind = ExtractOp::Kind::And;
        op.imm = parse_hex_or_int(j.at("imm"));
    } else if (kind == "or") {
        op.kind = ExtractOp::Kind::Or;
        op.imm = parse_hex_or_int(j.at("imm"));
    } else if (kind == "xor") {
        op.kind = ExtractOp::Kind::Xor;
        op.imm = parse_hex_or_int(j.at("imm"));
    } else if (kind == "lsr_and") {
        op.kind = ExtractOp::Kind::LsrAnd;
        op.imm = parse_hex_or_int(j.at("lsr"));
        op.imm2 = parse_hex_or_int(j.at("and"));
    } else if (kind == "or_accum") {
        op.kind = ExtractOp::Kind::OrAccum;
    } else if (kind == "sext") {
        op.kind = ExtractOp::Kind::Sext;
        op.imm = parse_hex_or_int(j.at("width"));
    } else if (kind == "mul") {
        op.kind = ExtractOp::Kind::Mul;
        op.imm = parse_hex_or_int(j.at("imm"));
    } else {
        throw std::runtime_error("Unknown extract op: " + kind);
    }
    return op;
}

std::vector<ExtractOp> parse_extract_pipeline(const json& arr) {
    std::vector<ExtractOp> ops;
    ops.reserve(arr.size());
    for (const auto& j : arr) {
        ops.push_back(parse_extract_op(j));
    }
    return ops;
}

/// Resolve an extract pipeline: either an inline array of ops, or a "$ref"
/// string referencing a named template from extract_templates.
std::vector<ExtractOp> resolve_extract(
        const json& j_extract,
        const std::map<std::string, std::vector<ExtractOp>>& templates) {
    if (j_extract.is_array()) {
        return parse_extract_pipeline(j_extract);
    }
    if (j_extract.is_string()) {
        // "$ref" syntax: "fmt_a_dst" → look up in templates.
        const auto& ref = j_extract.get_ref<const std::string&>();
        auto it = templates.find(ref);
        if (it != templates.end()) return it->second;
        throw std::runtime_error("Unknown extract template: " + ref);
    }
    return {};
}

OperandDisplay parse_operand_display(
        const std::string& name, const json& j,
        const std::map<std::string, std::vector<ExtractOp>>& templates) {
    OperandDisplay opd;
    opd.name = name;
    if (j.contains("type")) opd.type = parse_display_type(j["type"].get<std::string>());
    if (j.contains("prefix")) opd.prefix = j["prefix"].get<std::string>();
    if (j.contains("scale")) opd.scale = j["scale"].get<int64_t>();
    if (j.contains("extract")) {
        opd.extract = resolve_extract(j["extract"], templates);
    }
    return opd;
}

RoutingRule parse_routing_rule(const json& j, const std::string& default_reg_prefix,
                                const std::map<std::string, std::vector<ExtractOp>>& templates) {
    RoutingRule rule;
    rule.mask    = parse_hex_or_int(j.at("mask"));
    rule.match   = parse_hex_or_int(j.at("match"));
    rule.mnemonic = j.value("op", std::string{"UNK"});
    rule.format   = j.value("format", std::string{});

    if (j.contains("operands") && j["operands"].is_object()) {
        // Preserve declaration order: use the format string to determine order.
        // First collect all operand names from the format.
        std::vector<std::string> ordered_names;
        {
            const auto& fmt_str = rule.format;
            size_t pos = 0;
            while (pos < fmt_str.size()) {
                if (fmt_str[pos] == '{') {
                    size_t end = fmt_str.find('}', pos + 1);
                    if (end != std::string::npos) {
                        ordered_names.push_back(fmt_str.substr(pos + 1, end - pos - 1));
                        pos = end + 1;
                    } else {
                        pos++;
                    }
                } else {
                    pos++;
                }
            }
        }

        const auto& operands_obj = j["operands"];

        // Add operands in format order first, then any remaining.
        std::vector<std::string> added;
        for (const auto& name : ordered_names) {
            if (operands_obj.contains(name)) {
                auto opd = parse_operand_display(name, operands_obj[name], templates);
                if (opd.type == OperandDisplayType::VmReg && opd.prefix.empty()) {
                    opd.prefix = default_reg_prefix;
                }
                rule.operands.push_back(std::move(opd));
                added.push_back(name);
            }
        }
        // Add any operands not referenced in format (for completeness).
        for (auto& [name, val] : operands_obj.items()) {
            if (std::find(added.begin(), added.end(), name) == added.end()) {
                auto opd = parse_operand_display(name, val, templates);
                if (opd.type == OperandDisplayType::VmReg && opd.prefix.empty()) {
                    opd.prefix = default_reg_prefix;
                }
                rule.operands.push_back(std::move(opd));
            }
        }
    }

    return rule;
}

}  // namespace

// ═══════════════════════════════════════════════════════════════════════════
// Public API: load_decoder_from_json
// ═══════════════════════════════════════════════════════════════════════════

std::unique_ptr<VMBytecodeDecoder> load_decoder_from_json(const std::string& path) {
    std::ifstream f(path);
    if (!f.good()) {
        fmt::print(stderr, "[vm-decoder] Error: decoder file not found: {}\n", path);
        return nullptr;
    }

    json j;
    try {
        f >> j;
    } catch (const std::exception& e) {
        fmt::print(stderr, "[vm-decoder] Error: invalid JSON: {}\n", e.what());
        return nullptr;
    }

    try {
        std::string name = j.value("name", std::string{"unnamed"});
        std::string default_op = j.value("default_op", std::string{"UNK"});

        // Register config.
        std::string reg_prefix = "R";
        uint32_t reg_count = 32;
        if (j.contains("registers")) {
            const auto& rj = j["registers"];
            reg_prefix = rj.value("prefix", std::string{"R"});
            reg_count = rj.value("count", 32u);
        }

        // Parse extract templates (reusable bit-field extraction pipelines).
        std::map<std::string, std::vector<ExtractOp>> templates;
        if (j.contains("extract_templates") && j["extract_templates"].is_object()) {
            for (auto& [tname, tval] : j["extract_templates"].items()) {
                if (tname.empty() || tname[0] == '_') continue;  // skip doc fields
                if (tval.is_array()) {
                    templates[tname] = parse_extract_pipeline(tval);
                }
            }
            fmt::print(stderr, "[vm-decoder]   {} extract templates loaded\n", templates.size());
        }

        // Parse routing rules (skip comment-only entries like {"_": "..."}).
        std::vector<RoutingRule> rules;
        if (j.contains("routing") && j["routing"].is_array()) {
            rules.reserve(j["routing"].size());
            for (const auto& rj : j["routing"]) {
                if (!rj.is_object() || !rj.contains("mask")) continue;  // skip comments
                rules.push_back(parse_routing_rule(rj, reg_prefix, templates));
            }
        }

        fmt::print(stderr, "[vm-decoder] Loaded '{}': {} routing rules, registers {}0-{}{}\n",
                   name, rules.size(), reg_prefix, reg_prefix, reg_count - 1);

        return std::make_unique<JsonDrivenDecoder>(
            std::move(name), std::move(rules), std::move(default_op),
            std::move(reg_prefix), reg_count);

    } catch (const std::exception& e) {
        throw std::runtime_error(
            fmt::format("Error parsing decoder JSON: {}", e.what()));
    }
}

}  // namespace tenet
