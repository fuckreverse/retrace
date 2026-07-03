#include "analysis/passes/pattern_pass.h"
#include "analysis/trace_collector.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/instruction_decoder.h"
#include "core/register_file.h"

#ifdef TENET_HAS_YARA
#include <yara.h>
#endif

#include <ankerl/unordered_dense.h>
#include <fmt/core.h>
#include <algorithm>
#include <cstring>
#include <functional>
#include <string_view>

namespace tenet {

// ─── Blob persistence helpers ─────────────────────────────────────────────

static constexpr uint32_t PATTERN_BLOB_MAGIC   = 0x50415454u;  // "PATT"
static constexpr uint32_t PATTERN_BLOB_VERSION = 1u;

/// Serialize PatternResult into a compact binary blob.
/// Format: [magic:u32][version:u32][num_matches:u64]
///   per match: [name_len:u32][name][cat:u8][conf:u8][start:u64][end:u64]
///              [anchor_pc:u64][desc_len:u32][desc]
///              [num_related:u32][related_inst_ids...]
///              [num_consts:u32][constants...]
static std::string pattern_serialize(const PatternResult& res) {
    // Estimate buffer size
    size_t est = 4 + 4 + 8;
    for (const auto& m : res.matches) {
        est += 4 + m.pattern_name.size() + 2 + 24 + 4 + m.description.size()
             + 4 + m.related_inst_ids.size() * 8
             + 4 + m.constants_found.size() * 8;
    }

    std::string buf;
    buf.reserve(est);

    auto write = [&](const void* data, size_t n) {
        buf.append(reinterpret_cast<const char*>(data), n);
    };
    auto write_u8  = [&](uint8_t v)  { write(&v, 1); };
    auto write_u32 = [&](uint32_t v) { write(&v, 4); };
    auto write_u64 = [&](uint64_t v) { write(&v, 8); };
    auto write_str = [&](const std::string& s) {
        write_u32(static_cast<uint32_t>(s.size()));
        if (!s.empty()) write(s.data(), s.size());
    };

    write_u32(PATTERN_BLOB_MAGIC);
    write_u32(PATTERN_BLOB_VERSION);
    write_u64(static_cast<uint64_t>(res.matches.size()));

    for (const auto& m : res.matches) {
        write_str(m.pattern_name);
        write_u8(static_cast<uint8_t>(m.category));
        write_u8(static_cast<uint8_t>(m.confidence));
        write_u64(m.start_inst_id);
        write_u64(m.end_inst_id);
        write_u64(m.anchor_pc);
        write_str(m.description);
        write_u32(static_cast<uint32_t>(m.related_inst_ids.size()));
        for (uint64_t id : m.related_inst_ids) write_u64(id);
        write_u32(static_cast<uint32_t>(m.constants_found.size()));
        for (uint64_t c : m.constants_found) write_u64(c);
    }

    return buf;
}

/// Deserialize PatternResult from a binary blob. Returns false on corruption.
static bool pattern_deserialize(const std::string& blob, PatternResult& out) {
    if (blob.size() < 4 + 4 + 8) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto remaining = [&]() -> size_t { return static_cast<size_t>(end - p); };
    auto read_u8  = [&]() -> uint8_t  { uint8_t  v; std::memcpy(&v, p, 1); p += 1; return v; };
    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_u64 = [&]() -> uint64_t { uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; };
    auto read_str = [&](std::string& s) -> bool {
        if (remaining() < 4) return false;
        uint32_t len = read_u32();
        if (remaining() < len) return false;
        s.assign(p, len);
        p += len;
        return true;
    };

    uint32_t magic = read_u32();
    uint32_t version = read_u32();
    if (magic != PATTERN_BLOB_MAGIC || version != PATTERN_BLOB_VERSION) return false;

    uint64_t num_matches = read_u64();
    out.matches.resize(static_cast<size_t>(num_matches));

    for (size_t i = 0; i < num_matches; i++) {
        auto& m = out.matches[i];
        if (!read_str(m.pattern_name)) return false;
        if (remaining() < 2 + 24) return false;
        m.category   = static_cast<PatternCategory>(read_u8());
        m.confidence = static_cast<PatternConfidence>(read_u8());
        m.start_inst_id = read_u64();
        m.end_inst_id   = read_u64();
        m.anchor_pc     = read_u64();
        if (!read_str(m.description)) return false;

        if (remaining() < 4) return false;
        uint32_t num_related = read_u32();
        if (remaining() < num_related * 8) return false;
        m.related_inst_ids.resize(num_related);
        for (uint32_t j = 0; j < num_related; j++) m.related_inst_ids[j] = read_u64();

        if (remaining() < 4) return false;
        uint32_t num_consts = read_u32();
        if (remaining() < num_consts * 8) return false;
        m.constants_found.resize(num_consts);
        for (uint32_t j = 0; j < num_consts; j++) m.constants_found[j] = read_u64();
    }

    return true;
}

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
    const std::function<bool()>* cancel_check = nullptr;
};

static constexpr size_t SYSCALL_ENTRY_SIZE = 16;

int yara_scan_callback(YR_SCAN_CONTEXT* context, int message,
                       void* message_data, void* user_data) {
    auto* ctx = static_cast<YaraScanContext*>(user_data);
    if (ctx->cancel_check && *ctx->cancel_check && (*ctx->cancel_check)()) {
        return CALLBACK_ABORT;
    }
    if (message != CALLBACK_MSG_RULE_MATCHING)
        return CALLBACK_CONTINUE;

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

// ─── PatternCollector implementation ──────────────────────────────────────

PatternCollector::PatternCollector(CodeTable& code_table,
                                   InstructionDecoder& decoder,
                                   RegisterFile* regfile,
                                   bool build_yara_buffers,
                                   const ConstantMaterializationResult* constmat,
                                   uint32_t target_os)
    : code_table_(code_table)
    , decoder_(decoder)
    , regfile_(regfile)
    , build_yara_buffers_(build_yara_buffers)
    , constmat_(constmat)
    , syscall_reg_((target_os == 2 || target_os == 3) ? REG_X8 : REG_X16)  // Android/Linux → x8, Darwin/Unknown → x16
{}

bool PatternCollector::begin(uint64_t start_inst_id, uint64_t end_inst_id) {
    result_ = PatternResult{};

    // Reset all detector state
    hw_sites_.clear();
    std::memset(xor_ring_, 0, sizeof(xor_ring_));
    std::memset(xor_pc_ring_, 0, sizeof(xor_pc_ring_));
    std::memset(xor_inst_id_ring_, 0, sizeof(xor_inst_id_ring_));
    xor_ring_pos_ = 0;
    xor_ring_size_ = 0;
    xor_eor_count_ = 0;
    in_xor_loop_ = false;
    xor_loop_start_ = 0;
    xor_loop_insts_.clear();
    xor_loop_unique_pcs_.clear();
    in_load_seq_ = false;
    load_seq_start_ = 0;
    load_seq_insts_.clear();
    last_movz_pc_ = 0;
    last_pc_ = ~0ULL;
    reg_buf_ = {};
    sys_buf_ = {};

    // Pre-classify all unique PCs from code table
    pc_info_.clear();
    auto all = code_table_.all_entries();
    pc_info_.reserve(all.size());

    for (const auto& [pc, opcode] : all) {
        PCInfo info;
        auto d = decoder_.decode(pc, opcode);
        if (d) {
            std::string_view mn = d->mnemonic_sv();
            if (mn == "aese" || mn == "aesd" || mn == "aesmc" || mn == "aesimc") {
                info.cls = MC_HW_AES;
            } else if (mn == "sha1c" || mn == "sha1h" || mn == "sha1m" ||
                       mn == "sha1p" || mn == "sha1su0" || mn == "sha1su1" ||
                       mn == "sha256h" || mn == "sha256h2" ||
                       mn == "sha256su0" || mn == "sha256su1") {
                info.cls = MC_HW_SHA;
            } else if (mn == "eor") {
                info.cls = MC_EOR;
            } else if (mn == "movz" || mn == "mov") {
                info.cls = MC_MOVZ;
            } else if (mn == "movk") {
                info.cls = MC_MOVK;
            } else if (mn == "svc") {
                info.cls = MC_SVC;
                info.is_svc = true;
            }
            auto n = std::min(mn.size(), sizeof(info.mnemonic) - 1);
            std::memcpy(info.mnemonic, mn.data(), n);
            info.mnemonic[n] = '\0';
        }
        pc_info_.emplace(pc, info);
    }

    // Pre-allocate reg_value buffer when building YARA buffers
    if (build_yara_buffers_) {
        uint64_t range = end_inst_id - start_inst_id;
        reg_buf_.data.reserve(range * 2 * 8);
        reg_buf_.offset_to_inst_id.reserve(range * 2);
    }

    return true;
}

void PatternCollector::on_inst(uint64_t inst_id, const InstView& inst) {
    // Look up pre-classified info - 1-entry cache for loop locality
    MnemonicClass cls;
    const char* mn_str;
    bool is_svc;
    if (inst.pc == last_pc_) {
        cls = last_cls_;
        mn_str = last_mn_str_;
        is_svc = last_is_svc_;
    } else {
        cls = MC_OTHER;
        mn_str = "";
        is_svc = false;
        auto pc_it = pc_info_.find(inst.pc);
        if (pc_it != pc_info_.end()) {
            cls = pc_it->second.cls;
            mn_str = pc_it->second.mnemonic;
            is_svc = pc_it->second.is_svc;
        }
        last_pc_ = inst.pc;
        last_cls_ = cls;
        last_mn_str_ = mn_str;
        last_is_svc_ = is_svc;
    }

    // ── Collect reg-value entries (only when building YARA buffer) ──
    if (build_yara_buffers_) {
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            if (diff.index >= 31 && diff.index <= 33) continue;
            uint64_t val = diff.value;
            const auto* bytes = reinterpret_cast<const uint8_t*>(&val);
            reg_buf_.data.insert(reg_buf_.data.end(), bytes, bytes + 8);
            reg_buf_.offset_to_inst_id.push_back(inst_id);
        }
    }

    // ── Collect syscall entries (only when building YARA buffer) ──
    if (build_yara_buffers_ && is_svc && regfile_) {
        auto state = regfile_->state_before(inst_id);
        uint16_t syscall_no = static_cast<uint16_t>(state.gpr[syscall_reg_] & 0xFFFF);
        SyscallEntry entry;
        entry.inst_id = inst_id;
        entry.syscall_no = syscall_no;
        sys_buf_.entries.push_back(entry);
        uint8_t record[SYSCALL_ENTRY_SIZE] = {};
        std::memcpy(record, &inst_id, 8);
        std::memcpy(record + 8, &syscall_no, 2);
        sys_buf_.data.insert(sys_buf_.data.end(), record, record + SYSCALL_ENTRY_SIZE);
    }

    // ─── Detector 1: Hardware crypto (PC-deduped) ─────────────────────
    if (cls == MC_HW_AES || cls == MC_HW_SHA) {
        auto& site = hw_sites_[inst.pc];
        if (site.exec_count == 0) {
            site.cls          = cls;
            std::strncpy(site.mn, mn_str, sizeof(site.mn) - 1);
            site.mn[sizeof(site.mn) - 1] = '\0';
            site.first_inst_id = inst_id;
        }
        site.exec_count++;
        site.last_inst_id = inst_id;
    }

    // ─── Detector 2: XOR loop (sliding window) ───────────────────────
    //
    // A dense-EOR window alone only tells us "lots of XORs happened
    // recently" — that is equally consistent with a real crypto round
    // function (few PCs, executed repeatedly) and with straight-line
    // bit-packing/checksum code (many distinct PCs, each executed once).
    // We track distinct PCs across the whole candidate run
    // (xor_loop_unique_pcs_) so the confidence assigned at flush time
    // reflects which of those two shapes we saw.
    {
        bool is_eor = (cls == MC_EOR);

        if (xor_ring_size_ >= XOR_WINDOW_SIZE) {
            if (xor_ring_[xor_ring_pos_]) xor_eor_count_--;
        } else {
            xor_ring_size_++;
        }
        xor_ring_[xor_ring_pos_] = is_eor;
        xor_pc_ring_[xor_ring_pos_] = inst.pc;
        xor_inst_id_ring_[xor_ring_pos_] = inst_id;
        xor_ring_pos_ = (xor_ring_pos_ + 1) % XOR_WINDOW_SIZE;
        if (is_eor) xor_eor_count_++;

        if (xor_ring_size_ >= XOR_WINDOW_SIZE && xor_eor_count_ >= XOR_THRESHOLD) {
            if (!in_xor_loop_) {
                in_xor_loop_ = true;
                xor_loop_start_ = (inst_id >= XOR_WINDOW_SIZE - 1)
                                     ? inst_id - XOR_WINDOW_SIZE + 1 : 0;
                xor_loop_insts_.clear();
                xor_loop_unique_pcs_.clear();
                // Backfill with the EOR instructions already sitting in the
                // window — without this, a run's first flush would only
                // ever contain the single triggering instruction and thus
                // always look like "1 unique PC" (falsely "loop-like"),
                // regardless of whether the window was actually a tight
                // loop or 8 unrelated straight-line EORs.
                seed_xor_loop_from_ring();
            } else {
                xor_loop_insts_.push_back(inst_id);
                xor_loop_unique_pcs_.insert(inst.pc);
            }
        } else {
            if (in_xor_loop_ && !xor_loop_insts_.empty()) {
                flush_xor_loop_match(inst.pc);
            }
            in_xor_loop_ = false;
        }
    }

    // ─── Detector 3: Constant loading (movz + movk sequences) ────────
    // Skipped when constmat result is available (more precise, no duplication).
    // This fallback path never validates the loaded *value* against a known
    // crypto constant table, so it is always reported at Low confidence —
    // see flush_const_load_match().
    if (!constmat_) {
        bool is_movz = (cls == MC_MOVZ);
        bool is_movk = (cls == MC_MOVK);

        if (is_movz) {
            if (!in_load_seq_) {
                in_load_seq_ = true;
                load_seq_start_ = inst_id;
                load_seq_insts_.clear();
            } else {
                if (load_seq_insts_.size() >= CONST_LOAD_THRESHOLD) {
                    flush_const_load_match();
                }
                load_seq_insts_.clear();
                load_seq_start_ = inst_id;
            }
            last_movz_pc_ = inst.pc;
            load_seq_insts_.push_back(inst_id);
        } else if (is_movk && in_load_seq_) {
            load_seq_insts_.push_back(inst_id);
        } else if (in_load_seq_) {
            if (load_seq_insts_.size() >= CONST_LOAD_THRESHOLD) {
                flush_const_load_match();
            }
            in_load_seq_ = false;
            load_seq_insts_.clear();
        }
    }
}

void PatternCollector::end() {
    // ─── Emit one match per unique HW crypto PC ──────────────────────
    for (const auto& [pc, site] : hw_sites_) {
        bool is_aes = (site.cls == MC_HW_AES);
        add_match(PatternMatch{
            fmt::format("{} instruction ({})", is_aes ? "AES" : "SHA", site.mn),
            PatternCategory::Crypto,
            PatternConfidence::High,
            site.first_inst_id, site.last_inst_id, pc,
            fmt::format("Hardware {} instruction {} at PC 0x{:x} ({} executions)",
                        is_aes ? "AES" : "SHA", site.mn, pc, site.exec_count),
            {site.first_inst_id}, {},
        });
    }

    // Flush pending XOR loop (trace ended mid-run; no "breaking" PC to record).
    if (in_xor_loop_ && !xor_loop_insts_.empty()) {
        flush_xor_loop_match(0);
    }

    // Flush pending constant loading (only when not using constmat)
    if (!constmat_ && in_load_seq_ && load_seq_insts_.size() >= CONST_LOAD_THRESHOLD) {
        flush_const_load_match();
    }
}

void PatternCollector::seed_xor_loop_from_ring() {
    // xor_ring_pos_ currently points at the OLDEST slot (the one that is
    // about to be overwritten on the next iteration), so walking forward
    // from there for XOR_WINDOW_SIZE steps visits the whole window in
    // chronological order (oldest → newest). Only the EOR instructions
    // matter for "unique PCs in this run" — the interleaved non-EOR
    // instructions are noise the detector already ignores elsewhere.
    for (size_t i = 0; i < XOR_WINDOW_SIZE; ++i) {
        size_t slot = (xor_ring_pos_ + i) % XOR_WINDOW_SIZE;
        if (!xor_ring_[slot]) continue;  // not an eor
        xor_loop_insts_.push_back(xor_inst_id_ring_[slot]);
        xor_loop_unique_pcs_.insert(xor_pc_ring_[slot]);
    }
}

void PatternCollector::flush_const_load_match() {
    // Always Low confidence: this fallback path (only active when
    // constant_materialization hasn't run) never checks the assembled
    // value against a known crypto constant table — it only knows that a
    // register was built from >=3 movz/movk immediate parts. Any 32/64-bit
    // literal (pointer, offset, magic number, timestamp, ...) can produce
    // the same instruction shape, so this is a much weaker signal than a
    // verified constant-table hit (which constant_materialization reports
    // at High confidence via constmat_to_pattern_matches()).
    add_match(PatternMatch{
        "Constant loading sequence (unverified)",
        PatternCategory::KeySchedule,
        PatternConfidence::Low,
        load_seq_start_, load_seq_insts_.back(), last_movz_pc_,
        fmt::format("{} movz/movk instructions at inst #{}-#{} assembled a "
                     "register value — value NOT checked against any known "
                     "cryptographic constant table (run constant_materialization "
                     "for a verified match), may simply be a pointer/offset/magic "
                     "number",
                     load_seq_insts_.size(), load_seq_start_, load_seq_insts_.back()),
        load_seq_insts_, {},
    });
}

void PatternCollector::flush_xor_loop_match(uint64_t end_pc) {
    size_t n_insts = xor_loop_insts_.size();
    size_t n_unique_pcs = xor_loop_unique_pcs_.size();
    uint64_t last_inst = xor_loop_insts_.back();

    // A tight loop body re-executes the same few PCs; straight-line code
    // marching through many EORs visits close to one new PC per step. Use
    // that ratio to separate "looks like a real crypto loop" from "just a
    // burst of XORs in straight-line code" instead of always claiming the
    // same confidence for both.
    bool looks_like_loop = n_unique_pcs <= XOR_LOOP_MAX_UNIQUE_PCS;
    PatternConfidence confidence = looks_like_loop ? PatternConfidence::Medium
                                                    : PatternConfidence::Low;
    std::string desc = looks_like_loop
        ? fmt::format("XOR loop: {} eor instructions across {} unique PC(s) "
                       "at inst #{}-#{} (repeating code region, consistent "
                       "with a crypto round function)",
                       n_insts, n_unique_pcs, xor_loop_start_, last_inst)
        : fmt::format("XOR-dense code: {} eor instructions across {} unique "
                       "PCs at inst #{}-#{} (straight-line code, not a tight "
                       "loop — likely bit-packing/checksum, not necessarily "
                       "crypto)",
                       n_insts, n_unique_pcs, xor_loop_start_, last_inst);

    add_match(PatternMatch{
        looks_like_loop ? "XOR loop" : "XOR-dense code (non-loop)",
        PatternCategory::Crypto,
        confidence,
        xor_loop_start_, last_inst, end_pc,
        std::move(desc),
        std::move(xor_loop_insts_), {},
    });
    xor_loop_insts_.clear();
    xor_loop_unique_pcs_.clear();
}

PatternMatch& PatternCollector::add_match(PatternMatch match) {
    result_.matches.push_back(std::move(match));
    return result_.matches.back();
}

// ─── PatternPass::run (delegates to PatternCollector) ─────────────────────

PassResult PatternPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& code_table = ctx.code_table();
    auto& decoder = ctx.decoder();
    const auto& range = ctx.range();

    const uint64_t total_insts = index.inst_count();
    if (total_insts == 0) {
        return PassResult::failed("Empty trace");
    }

    // ─── Fast path: load from persisted cache ─────────────────────────────
    if (range.is_full_trace()) {
        std::string blob;
        if (index.load_pass_blob("pattern", blob)) {
            PatternResult cached;
            if (pattern_deserialize(blob, cached)) {
                build_category_index(cached);
                ctx.progress(1.0f, fmt::format(
                    "Pattern: {} matches found (from cache)",
                    cached.total()));
                return PassResult::success(std::move(cached));
            }
        }
    }

    // Phase 1: Load YARA rules
    bool has_yara = load_rules();

    // Phase 2: Set up collector and run scan
    const auto* constmat = ctx.try_require<ConstantMaterializationResult>("constant_materialization");

    ctx.progress(0.0f, "Pattern: scanning trace...");

    // regfile is only needed when building YARA syscall buffers
    RegisterFile* regfile_ptr = has_yara ? &ctx.regfile() : nullptr;
    PatternCollector collector(code_table, decoder, regfile_ptr, has_yara, constmat,
                               static_cast<uint32_t>(reader.header().target_os));

    auto* engine = ctx.scan_engine();
    if (engine) {
        engine->add_collector(&collector);
        engine->run();
    } else {
        TraceScanEngine local_engine(reader, total_insts, &index);
        local_engine.set_progress([&](uint64_t processed, uint64_t total) {
            if (total > 0) {
                ctx.progress(static_cast<float>(processed) / static_cast<float>(total) * 0.6f);
            }
        });
        local_engine.set_cancel_check([&]() { return ctx.cancelled(); });
        local_engine.set_cancel_token(&ctx.global_cancel_flag());
        local_engine.add_collector(&collector);
        local_engine.run();
    }

    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }

    auto result = collector.take_result();

    // Phase 3: Run YARA on built buffers (if enabled)
#ifdef TENET_HAS_YARA
    if (has_yara) {
        auto reg_buf = collector.take_reg_buf();
        auto sys_buf = collector.take_sys_buf();

        if (ctx.cancelled()) return PassResult::failed("cancelled by user");
        ctx.progress(0.7f, "Pattern: scanning register values with YARA...");
        if (!reg_buf.data.empty()) {
            std::string name = "reg_value";
            YaraScanContext scan_ctx;
            scan_ctx.result = &result;
            scan_ctx.pass = this;
            scan_ctx.buffer_name = &name;
            scan_ctx.offset_to_inst_id = &reg_buf.offset_to_inst_id;
            scan_ctx.offset_to_pc = nullptr;
            scan_ctx.syscall_entries = nullptr;
            scan_ctx.cancel_check = nullptr;

            std::function<bool()> cancel_check = [&]() { return ctx.cancelled(); };
            scan_ctx.cancel_check = &cancel_check;
            yr_rules_scan_mem(yr_rules_, reg_buf.data.data(), reg_buf.data.size(),
                              0, yara_scan_callback, &scan_ctx, 0);
        }

        if (ctx.cancelled()) return PassResult::failed("cancelled by user");
        ctx.progress(0.8f, "Pattern: scanning code bytes with YARA...");
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
            scan_ctx.cancel_check = nullptr;

            std::function<bool()> cancel_check = [&]() { return ctx.cancelled(); };
            scan_ctx.cancel_check = &cancel_check;
            yr_rules_scan_mem(yr_rules_, code_buf.data.data(), code_buf.data.size(),
                              0, yara_scan_callback, &scan_ctx, 0);
        }

        if (ctx.cancelled()) return PassResult::failed("cancelled by user");
        ctx.progress(0.9f, "Pattern: scanning syscalls with YARA...");
        if (!sys_buf.data.empty()) {
            std::string name = "syscall";
            YaraScanContext scan_ctx;
            scan_ctx.result = &result;
            scan_ctx.pass = this;
            scan_ctx.buffer_name = &name;
            scan_ctx.offset_to_inst_id = nullptr;
            scan_ctx.offset_to_pc = nullptr;
            scan_ctx.syscall_entries = &sys_buf.entries;
            scan_ctx.cancel_check = nullptr;

            std::function<bool()> cancel_check = [&]() { return ctx.cancelled(); };
            scan_ctx.cancel_check = &cancel_check;
            yr_rules_scan_mem(yr_rules_, sys_buf.data.data(), sys_buf.data.size(),
                              0, yara_scan_callback, &scan_ctx, 0);
        }
    }
#else
    (void)has_yara;
#endif

    // Phase 4: Convert constmat results to PatternMatch entries
    if (constmat) {
        constmat_to_pattern_matches(*constmat, result);
    }

    // Phase 5: Build category index
    build_category_index(result);

    // ─── Persist result for future sessions ───────────────────────────────
    if (range.is_full_trace()) {
        std::string blob = pattern_serialize(result);
        if (!blob.empty()) {
            index.save_pass_blob("pattern", blob.data(), blob.size());
        }
    }

    ctx.progress(1.0f, fmt::format("Pattern: {} matches found (YARA {})",
                                    result.total(), has_yara ? "enabled" : "disabled"));
    return PassResult::success(std::move(result));
}

// ─── constmat → PatternMatch conversion ────────────────────────────────────

void PatternPass::constmat_to_pattern_matches(const ConstantMaterializationResult& cm,
                                               PatternResult& result) {
    for (size_t idx : cm.identified_indices) {
        const auto& mc = cm.constants[idx];
        PatternMatch pm;
        pm.pattern_name = fmt::format("Known constant: {} ({})",
                                       mc.known_match->name, mc.known_match->algorithm);
        pm.category = PatternCategory::KeySchedule;
        pm.confidence = PatternConfidence::High;
        pm.start_inst_id = mc.first_inst_id;
        pm.end_inst_id   = mc.last_inst_id;
        pm.anchor_pc     = mc.pc_first;
        pm.description   = fmt::format(
            "{} constant 0x{:x} ({}) at inst #{}-#{}, reg x{}",
            mc.known_match->algorithm, mc.value, mc.known_match->name,
            mc.first_inst_id, mc.last_inst_id, mc.dst_reg);
        pm.constants_found.push_back(mc.value);
        result.matches.push_back(std::move(pm));
    }

    for (size_t i = 0; i < cm.constants.size(); ++i) {
        if (cm.constants[i].known_match) continue;
        const auto& mc = cm.constants[i];
        if (mc.num_parts < 3) continue;
        PatternMatch pm;
        pm.pattern_name   = "Constant loading sequence";
        pm.category       = PatternCategory::KeySchedule;
        pm.confidence     = PatternConfidence::Medium;
        pm.start_inst_id  = mc.first_inst_id;
        pm.end_inst_id    = mc.last_inst_id;
        pm.anchor_pc      = mc.pc_first;
        pm.description    = fmt::format(
            "Key schedule: {} movz/movk instructions at inst #{}-#{} (value 0x{:x})",
            mc.num_parts, mc.first_inst_id, mc.last_inst_id, mc.value);
        pm.constants_found.push_back(mc.value);
        result.matches.push_back(std::move(pm));
    }
}

// ─── Code buffer construction ─────────────────────────────────────────────

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
