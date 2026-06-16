#include "analysis/passes/pattern_pass.h"
#include "io/trace_reader.h"
#include "io/code_table.h"
#include "core/instruction_decoder.h"
#include "core/register_file.h"

#ifdef TENET_HAS_YARA
#include <yara.h>
#endif

#include <fmt/core.h>
#include <deque>
#include <algorithm>
#include <cstring>
#include <string_view>

namespace tenet {

// ─── Anonymous namespace for constants ────────────────────────────────────

namespace {

// XOR loop detection parameters
constexpr size_t XOR_WINDOW_SIZE = 8;
constexpr size_t XOR_THRESHOLD  = 4;

// Constant loading detection threshold
constexpr size_t CONST_LOAD_THRESHOLD = 3;

// AArch64 register index for x16 (syscall number on Darwin)
constexpr uint8_t REG_X16 = 16;

// Syscall buffer entry size: 8 (inst_id) + 2 (syscall_no) + 6 (pad) = 16
constexpr size_t SYSCALL_ENTRY_SIZE = 16;

}  // anonymous namespace

// ─── YARA callback context ────────────────────────────────────────────────

#ifdef TENET_HAS_YARA
namespace {

struct YaraScanContext {
    PatternResult* result;
    PatternPass* pass;
    const std::string* buffer_name;
    const std::vector<uint64_t>* offset_to_inst_id;
    const std::vector<uint64_t>* offset_to_pc;
    const std::vector<PatternPass::SyscallEntry>* syscall_entries;
};

int yara_scan_callback(YR_SCAN_CONTEXT* context, int message,
                       void* message_data, void* user_data) {
    if (message != CALLBACK_MSG_RULE_MATCHING)
        return CALLBACK_CONTINUE;

    auto* ctx = static_cast<YaraScanContext*>(user_data);
    auto* rule = static_cast<YR_RULE*>(message_data);

    // Extract meta fields
    std::string rule_desc = rule->identifier ? rule->identifier : "unknown";
    std::string category_str = "crypto";
    std::string confidence_str = "medium";
    std::string meta_desc;

    YR_META* meta;
    yr_rule_metas_foreach(rule, meta) {
        if (std::strcmp(meta->identifier, "category") == 0 && meta->type == META_TYPE_STRING) {
            category_str = meta->string;
        } else if (std::strcmp(meta->identifier, "confidence") == 0 && meta->type == META_TYPE_STRING) {
            confidence_str = meta->string;
        } else if (std::strcmp(meta->identifier, "description") == 0 && meta->type == META_TYPE_STRING) {
            meta_desc = meta->string;
        }
    }

    auto category = PatternPass::parse_category(category_str);
    auto confidence = PatternPass::parse_confidence(confidence_str);

    // Get match offset for the first matching string
    uint64_t match_offset = 0;
    YR_STRING* str;
    yr_rule_strings_foreach(rule, str) {
        YR_MATCH* match;
        yr_string_matches_foreach(context, str, match) {
            match_offset = match->offset;
            goto got_offset;
        }
    }
got_offset:

    // Determine inst_id/PC from offset based on buffer type
    uint64_t inst_id = 0;
    uint64_t pc = 0;

    if (*ctx->buffer_name == "reg_value" && ctx->offset_to_inst_id) {
        size_t slot = match_offset / 8;
        if (slot < ctx->offset_to_inst_id->size()) {
            inst_id = (*ctx->offset_to_inst_id)[slot];
        }
    } else if (*ctx->buffer_name == "code" && ctx->offset_to_pc) {
        size_t slot = match_offset / 4;
        if (slot < ctx->offset_to_pc->size()) {
            pc = (*ctx->offset_to_pc)[slot];
        }
    } else if (*ctx->buffer_name == "syscall" && ctx->syscall_entries) {
        size_t entry_idx = match_offset / SYSCALL_ENTRY_SIZE;
        if (entry_idx < ctx->syscall_entries->size()) {
            inst_id = (*ctx->syscall_entries)[entry_idx].inst_id;
        }
    }

    std::string desc = meta_desc.empty()
        ? fmt::format("YARA rule '{}' matched in {} buffer at offset {}",
                      rule_desc, *ctx->buffer_name, match_offset)
        : fmt::format("{} (rule: {}, offset: {})", meta_desc, rule_desc, match_offset);

    PatternMatch pm;
    pm.pattern_name = rule_desc;
    pm.category = category;
    pm.confidence = confidence;
    pm.start_inst_id = inst_id;
    pm.end_inst_id = inst_id;
    pm.anchor_pc = pc;
    pm.description = std::move(desc);
    if (inst_id != 0) {
        pm.related_inst_ids.push_back(inst_id);
    }

    ctx->result->matches.push_back(std::move(pm));
    return CALLBACK_CONTINUE;
}

}  // anonymous namespace
#endif  // TENET_HAS_YARA

// ─── PatternPass lifecycle ────────────────────────────────────────────────

PatternPass::PatternPass() = default;

PatternPass::~PatternPass() {
#ifdef TENET_HAS_YARA
    if (yr_rules_) {
        yr_rules_destroy(yr_rules_);
        yr_rules_ = nullptr;
    }
#endif
}

PatternPass::PatternPass(PatternPass&& o) noexcept
    : rules_dir_(std::move(o.rules_dir_)),
#ifdef TENET_HAS_YARA
      yr_rules_(o.yr_rules_),
#endif
      rules_loaded_(o.rules_loaded_) {
#ifdef TENET_HAS_YARA
    o.yr_rules_ = nullptr;
#endif
    o.rules_loaded_ = false;
}

PatternPass& PatternPass::operator=(PatternPass&& o) noexcept {
    if (this != &o) {
#ifdef TENET_HAS_YARA
        if (yr_rules_) yr_rules_destroy(yr_rules_);
#endif
        rules_dir_ = std::move(o.rules_dir_);
#ifdef TENET_HAS_YARA
        yr_rules_ = o.yr_rules_;
#endif
        rules_loaded_ = o.rules_loaded_;
#ifdef TENET_HAS_YARA
        o.yr_rules_ = nullptr;
#endif
        o.rules_loaded_ = false;
    }
    return *this;
}

// ─── YARA rule loading ───────────────────────────────────────────────────

bool PatternPass::load_rules() {
#ifdef TENET_HAS_YARA
    if (rules_loaded_) return yr_rules_ != nullptr;

    rules_loaded_ = true;

    if (yr_initialize() != ERROR_SUCCESS) {
        return false;
    }

    if (rules_dir_.empty()) {
        rules_dir_ = "rules";
    }

    if (!std::filesystem::exists(rules_dir_) ||
        !std::filesystem::is_directory(rules_dir_)) {
        return false;
    }

    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        return false;
    }

    int file_count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(rules_dir_)) {
        if (entry.path().extension() == ".yar" || entry.path().extension() == ".yara") {
            FILE* fp = fopen(entry.path().c_str(), "r");
            if (!fp) continue;

            int errors = yr_compiler_add_file(compiler, fp, nullptr, entry.path().filename().c_str());
            fclose(fp);

            if (errors > 0) continue;
            file_count++;
        }
    }

    if (file_count == 0) {
        yr_compiler_destroy(compiler);
        return false;
    }

    if (yr_compiler_get_rules(compiler, &yr_rules_) != ERROR_SUCCESS) {
        yr_compiler_destroy(compiler);
        return false;
    }

    yr_compiler_destroy(compiler);
    return true;
#else
    rules_loaded_ = true;
    return false;
#endif
}

// ─── PatternPass::run ─────────────────────────────────────────────────────

PassResult PatternPass::run(PassContext& ctx) {
    PatternResult result;

    // Phase 1: Load YARA rules
    bool has_yara = load_rules();

    // Phase 2: Build scannable buffers and run YARA
#ifdef TENET_HAS_YARA
    if (has_yara) {
        ctx.progress(0.1f, "Pattern: scanning register values with YARA...");

        auto reg_buf = build_reg_value_buffer(ctx);
        if (!reg_buf.data.empty()) {
            std::string name = "reg_value";
            YaraScanContext scan_ctx;
            scan_ctx.result = &result;
            scan_ctx.pass = this;
            scan_ctx.buffer_name = &name;
            scan_ctx.offset_to_inst_id = &reg_buf.offset_to_inst_id;
            scan_ctx.offset_to_pc = nullptr;
            scan_ctx.syscall_entries = nullptr;

            yr_rules_scan_mem(yr_rules_, reg_buf.data.data(), reg_buf.data.size(),
                              0, yara_scan_callback, &scan_ctx, 0);
        }

        ctx.progress(0.3f, "Pattern: scanning code bytes with YARA...");

        auto code_buf = build_code_buffer(ctx);
        if (!code_buf.data.empty()) {
            std::string name = "code";
            YaraScanContext scan_ctx;
            scan_ctx.result = &result;
            scan_ctx.pass = this;
            scan_ctx.buffer_name = &name;
            scan_ctx.offset_to_inst_id = nullptr;
            scan_ctx.offset_to_pc = &code_buf.offset_to_pc;
            scan_ctx.syscall_entries = nullptr;

            yr_rules_scan_mem(yr_rules_, code_buf.data.data(), code_buf.data.size(),
                              0, yara_scan_callback, &scan_ctx, 0);
        }

        ctx.progress(0.5f, "Pattern: scanning syscalls with YARA...");

        auto sys_buf = build_syscall_buffer(ctx);
        if (!sys_buf.data.empty()) {
            std::string name = "syscall";
            YaraScanContext scan_ctx;
            scan_ctx.result = &result;
            scan_ctx.pass = this;
            scan_ctx.buffer_name = &name;
            scan_ctx.offset_to_inst_id = nullptr;
            scan_ctx.offset_to_pc = nullptr;
            scan_ctx.syscall_entries = &sys_buf.entries;

            yr_rules_scan_mem(yr_rules_, sys_buf.data.data(), sys_buf.data.size(),
                              0, yara_scan_callback, &scan_ctx, 0);
        }
    }
#else
    (void)has_yara;
#endif

    // Phase 3: Mnemonic-based detection (retained for HW crypto, XOR loops, const loading)
    ctx.progress(0.6f, "Pattern: detecting hardware crypto instructions...");
    detect_hw_crypto(ctx, result);

    ctx.progress(0.7f, "Pattern: detecting XOR loops...");
    detect_xor_loops(ctx, result);

    ctx.progress(0.85f, "Pattern: detecting constant loading sequences...");
    detect_constant_loading(ctx, result);

    // Phase 4: Build category index
    build_category_index(result);

    ctx.progress(1.0f, fmt::format("Pattern: {} matches found (YARA {})",
                                    result.total(), has_yara ? "enabled" : "disabled"));
    return PassResult::success(std::move(result));
}

// ─── Buffer construction ──────────────────────────────────────────────────

PatternPass::RegValueBuffer PatternPass::build_reg_value_buffer(PassContext& ctx) {
    RegValueBuffer buf;
    auto& reader = ctx.reader();
    auto& index = ctx.index();

    const auto& range = ctx.range();
    uint64_t start = range.start_inst_id;
    uint64_t end = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    buf.data.reserve((end - start) * 2 * 8);
    buf.offset_to_inst_id.reserve((end - start) * 2);

    uint64_t inst_id = 0;
    for (auto it = reader.begin(); it != reader.end() && inst_id < end; ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        if (inst_id < start) { inst_id++; continue; }

        auto inst = rec.as_inst();
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            if (diff.index >= 31 && diff.index <= 33) continue;

            uint64_t val = diff.value;
            const auto* bytes = reinterpret_cast<const uint8_t*>(&val);
            buf.data.insert(buf.data.end(), bytes, bytes + 8);
            buf.offset_to_inst_id.push_back(inst_id);
        }

        inst_id++;
        if (ctx.cancelled()) break;
    }

    return buf;
}

PatternPass::SyscallBuffer PatternPass::build_syscall_buffer(PassContext& ctx) {
    SyscallBuffer buf;
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& regfile = ctx.regfile();
    auto& code_table = ctx.code_table();
    auto& decoder = ctx.decoder();

    const auto& range = ctx.range();
    uint64_t start = range.start_inst_id;
    uint64_t end = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    uint64_t inst_id = 0;
    for (auto it = reader.begin(); it != reader.end() && inst_id < end; ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        if (inst_id < start) { inst_id++; continue; }

        auto inst = rec.as_inst();

        auto opcode_opt = code_table.opcode_at(inst.pc);
        if (opcode_opt) {
            auto decoded = decoder.decode(inst.pc, *opcode_opt);
            if (decoded && decoded->mnemonic_sv() == "svc") {
                auto state = regfile.state_before(inst_id);
                uint16_t syscall_no = static_cast<uint16_t>(state.gpr[REG_X16] & 0xFFFF);

                SyscallEntry entry;
                entry.inst_id = inst_id;
                entry.syscall_no = syscall_no;
                buf.entries.push_back(entry);

                uint8_t record[SYSCALL_ENTRY_SIZE] = {};
                std::memcpy(record, &inst_id, 8);
                std::memcpy(record + 8, &syscall_no, 2);
                buf.data.insert(buf.data.end(), record, record + SYSCALL_ENTRY_SIZE);
            }
        }

        inst_id++;
        if (ctx.cancelled()) break;
    }

    return buf;
}

PatternPass::CodeBuffer PatternPass::build_code_buffer(PassContext& ctx) {
    CodeBuffer buf;
    auto& code_table = ctx.code_table();

    auto entries = code_table.all_entries();

    buf.data.reserve(entries.size() * 4);
    buf.offset_to_pc.reserve(entries.size());

    for (const auto& [pc, opcode] : entries) {
        const auto* bytes = reinterpret_cast<const uint8_t*>(&opcode);
        buf.data.insert(buf.data.end(), bytes, bytes + 4);
        buf.offset_to_pc.push_back(pc);
    }

    return buf;
}

// ─── Mnemonic-based detection: HW crypto ──────────────────────────────────

void PatternPass::detect_hw_crypto(PassContext& ctx, PatternResult& result) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& code_table = ctx.code_table();
    auto& decoder = ctx.decoder();

    const auto& range = ctx.range();
    uint64_t start = range.start_inst_id;
    uint64_t end = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    uint64_t inst_id = 0;

    for (auto it = reader.begin(); it != reader.end() && inst_id < end; ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        if (inst_id < start) { inst_id++; continue; }

        auto inst = rec.as_inst();

        auto opcode_opt = code_table.opcode_at(inst.pc);
        if (opcode_opt) {
            auto decoded = decoder.decode(inst.pc, *opcode_opt);
            if (decoded) {
                std::string_view mn = decoded->mnemonic_sv();

                if (mn == "aese" || mn == "aesd" || mn == "aesmc" || mn == "aesimc") {
                    add_match(result, PatternMatch{
                        fmt::format("AES instruction ({})", mn),
                        PatternCategory::Crypto,
                        PatternConfidence::High,
                        inst_id, inst_id, inst.pc,
                        fmt::format("Hardware AES instruction {} at PC 0x{:x}", mn, inst.pc),
                        {inst_id}, {},
                    });
                }

                if (mn == "sha1c" || mn == "sha1h" || mn == "sha1m" ||
                    mn == "sha1p" || mn == "sha1su0" || mn == "sha1su1" ||
                    mn == "sha256h" || mn == "sha256h2" ||
                    mn == "sha256su0" || mn == "sha256su1") {
                    add_match(result, PatternMatch{
                        fmt::format("SHA instruction ({})", mn),
                        PatternCategory::Crypto,
                        PatternConfidence::High,
                        inst_id, inst_id, inst.pc,
                        fmt::format("Hardware SHA instruction {} at PC 0x{:x}", mn, inst.pc),
                        {inst_id}, {},
                    });
                }
            }
        }

        inst_id++;
        if (ctx.cancelled()) return;
    }
}

// ─── XOR loop detection ───────────────────────────────────────────────────

void PatternPass::detect_xor_loops(PassContext& ctx, PatternResult& result) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& code_table = ctx.code_table();
    auto& decoder = ctx.decoder();

    const auto& range = ctx.range();
    uint64_t start = range.start_inst_id;
    uint64_t end = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    uint64_t inst_id = 0;
    std::deque<bool> window;
    size_t eor_count = 0;
    bool in_xor_loop = false;
    uint64_t xor_loop_start = 0;
    std::vector<uint64_t> xor_loop_insts;

    for (auto it = reader.begin(); it != reader.end() && inst_id < end; ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        if (inst_id < start) { inst_id++; continue; }

        auto inst = rec.as_inst();
        bool is_eor = false;

        auto opcode_opt = code_table.opcode_at(inst.pc);
        if (opcode_opt) {
            auto decoded = decoder.decode(inst.pc, *opcode_opt);
            if (decoded) {
                is_eor = (decoded->mnemonic_sv() == "eor");
            }
        }

        if (window.size() >= XOR_WINDOW_SIZE) {
            if (window.front()) eor_count--;
            window.pop_front();
        }
        window.push_back(is_eor);
        if (is_eor) eor_count++;

        if (window.size() >= XOR_WINDOW_SIZE && eor_count >= XOR_THRESHOLD) {
            if (!in_xor_loop) {
                in_xor_loop = true;
                xor_loop_start = (inst_id >= XOR_WINDOW_SIZE - 1)
                                     ? inst_id - XOR_WINDOW_SIZE + 1 : 0;
                xor_loop_insts.clear();
            }
            xor_loop_insts.push_back(inst_id);
        } else {
            if (in_xor_loop && !xor_loop_insts.empty()) {
                add_match(result, PatternMatch{
                    "XOR loop",
                    PatternCategory::Crypto,
                    PatternConfidence::Medium,
                    xor_loop_start, xor_loop_insts.back(), inst.pc,
                    fmt::format("XOR loop: {} eor instructions at inst #{}-#{}",
                                 xor_loop_insts.size(), xor_loop_start, xor_loop_insts.back()),
                    std::move(xor_loop_insts), {},
                });
                xor_loop_insts.clear();
            }
            in_xor_loop = false;
        }

        inst_id++;
        if (ctx.cancelled()) return;
    }

    if (in_xor_loop && !xor_loop_insts.empty()) {
        add_match(result, PatternMatch{
            "XOR loop",
            PatternCategory::Crypto,
            PatternConfidence::Medium,
            xor_loop_start, xor_loop_insts.back(), 0,
            fmt::format("XOR loop: {} eor instructions at inst #{}-#{} (end of trace)",
                         xor_loop_insts.size(), xor_loop_start, xor_loop_insts.back()),
            std::move(xor_loop_insts), {},
        });
    }
}

// ─── Constant loading detection ───────────────────────────────────────────

void PatternPass::detect_constant_loading(PassContext& ctx, PatternResult& result) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& code_table = ctx.code_table();
    auto& decoder = ctx.decoder();

    const auto& range = ctx.range();
    uint64_t start = range.start_inst_id;
    uint64_t end = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    uint64_t inst_id = 0;
    bool in_load_seq = false;
    uint64_t load_seq_start = 0;
    std::vector<uint64_t> load_seq_insts;
    uint64_t last_movz_pc = 0;

    for (auto it = reader.begin(); it != reader.end() && inst_id < end; ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        if (inst_id < start) { inst_id++; continue; }

        auto inst = rec.as_inst();
        bool is_movz = false;
        bool is_movk = false;

        auto opcode_opt = code_table.opcode_at(inst.pc);
        if (opcode_opt) {
            auto decoded = decoder.decode(inst.pc, *opcode_opt);
            if (decoded) {
                std::string_view mn = decoded->mnemonic_sv();
                if (mn == "movz" || mn == "mov") is_movz = true;
                else if (mn == "movk") is_movk = true;
            }
        }

        if (is_movz) {
            if (!in_load_seq) {
                in_load_seq = true;
                load_seq_start = inst_id;
                load_seq_insts.clear();
            } else {
                if (load_seq_insts.size() >= CONST_LOAD_THRESHOLD) {
                    add_match(result, PatternMatch{
                        "Constant loading sequence",
                        PatternCategory::KeySchedule,
                        PatternConfidence::Medium,
                        load_seq_start, load_seq_insts.back(), last_movz_pc,
                        fmt::format("Key schedule: {} movz/movk instructions at inst #{}-#{}",
                                     load_seq_insts.size(), load_seq_start, load_seq_insts.back()),
                        load_seq_insts, {},
                    });
                }
                load_seq_insts.clear();
                load_seq_start = inst_id;
            }
            last_movz_pc = inst.pc;
            load_seq_insts.push_back(inst_id);
        } else if (is_movk && in_load_seq) {
            load_seq_insts.push_back(inst_id);
        } else if (in_load_seq) {
            if (load_seq_insts.size() >= CONST_LOAD_THRESHOLD) {
                add_match(result, PatternMatch{
                    "Constant loading sequence",
                    PatternCategory::KeySchedule,
                    PatternConfidence::Medium,
                    load_seq_start, load_seq_insts.back(), last_movz_pc,
                    fmt::format("Key schedule: {} movz/movk instructions at inst #{}-#{}",
                                 load_seq_insts.size(), load_seq_start, load_seq_insts.back()),
                    load_seq_insts, {},
                });
            }
            in_load_seq = false;
            load_seq_insts.clear();
        }

        inst_id++;
        if (ctx.cancelled()) return;
    }

    if (in_load_seq && load_seq_insts.size() >= CONST_LOAD_THRESHOLD) {
        add_match(result, PatternMatch{
            "Constant loading sequence",
            PatternCategory::KeySchedule,
            PatternConfidence::Medium,
            load_seq_start, load_seq_insts.back(), last_movz_pc,
            fmt::format("Key schedule: {} movz/movk instructions at inst #{}-#{} (end of trace)",
                         load_seq_insts.size(), load_seq_start, load_seq_insts.back()),
            load_seq_insts, {},
        });
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────

PatternCategory PatternPass::parse_category(const std::string& s) {
    if (s == "crypto")      return PatternCategory::Crypto;
    if (s == "anti_debug")  return PatternCategory::AntiDebug;
    if (s == "anti_tamper") return PatternCategory::AntiTamper;
    if (s == "obfuscation") return PatternCategory::Obfuscation;
    if (s == "networking")  return PatternCategory::Networking;
    if (s == "key_schedule") return PatternCategory::KeySchedule;
    return PatternCategory::Crypto;
}

PatternConfidence PatternPass::parse_confidence(const std::string& s) {
    if (s == "low")    return PatternConfidence::Low;
    if (s == "medium") return PatternConfidence::Medium;
    if (s == "high")   return PatternConfidence::High;
    return PatternConfidence::Medium;
}

void PatternPass::build_category_index(PatternResult& result) {
    result.by_category.clear();
    for (size_t i = 0; i < result.matches.size(); i++) {
        result.by_category[result.matches[i].category].push_back(i);
    }
}

PatternMatch& PatternPass::add_match(PatternResult& result, PatternMatch match) {
    result.matches.push_back(std::move(match));
    return result.matches.back();
}

// ─── PatternResult helpers ────────────────────────────────────────────────

std::vector<const PatternMatch*> PatternResult::crypto_matches() const {
    std::vector<const PatternMatch*> out;
    auto it = by_category.find(PatternCategory::Crypto);
    if (it != by_category.end()) {
        for (size_t idx : it->second) {
            out.push_back(&matches[idx]);
        }
    }
    auto it2 = by_category.find(PatternCategory::KeySchedule);
    if (it2 != by_category.end()) {
        for (size_t idx : it2->second) {
            out.push_back(&matches[idx]);
        }
    }
    return out;
}

std::vector<const PatternMatch*> PatternResult::anti_debug_matches() const {
    std::vector<const PatternMatch*> out;
    auto it = by_category.find(PatternCategory::AntiDebug);
    if (it != by_category.end()) {
        for (size_t idx : it->second) {
            out.push_back(&matches[idx]);
        }
    }
    return out;
}

}  // namespace tenet
