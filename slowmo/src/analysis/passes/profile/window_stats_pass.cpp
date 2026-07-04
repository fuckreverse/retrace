#include "analysis/passes/profile/window_stats_pass.h"
#include "analysis/trace_collector.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/instruction_decoder.h"
#include "common/aarch64_classify.h"

#include <fmt/core.h>
#include <ankerl/unordered_dense.h>
#include <algorithm>
#include <cmath>
#include <cstring>

namespace tenet {

// ─── WindowStatsResult serialization helpers ──────────────────────────────
//
// Blob format (all little-endian):
//   u32  magic   = 0x57535453 ("WSTS")
//   u32  version = 2
//   u64  window_size
//   u64  total_windows
//   u64  hottest_mem_window
//   u64  most_diverse_window
//   u64  densest_branch_window
//   u64  num_windows
//   for each WindowSnapshot:
//     u64  start_inst_id
//     u64  end_inst_id
//     u64  instruction_count
//     u64  mem_read_count
//     u64  mem_write_count
//     u64  unique_mem_addrs
//     u64  unique_pcs
//     f32  mnemonic_entropy
//     f32  branch_density
//     u32[34] reg_write_counts
//     u32  num_top_mnemonics
//     for each MnemonicStat:
//       u16  mnemonic_id
//       u64  count
//       u8   mnemonic_len   (v2+)
//       char mnemonic[mnemonic_len]  (v2+, not NUL-terminated)
//
// Version history:
//   v1: initial format (no human-readable mnemonic string).
//   v2: added `mnemonic` (resolved via InstructionDecoder at flush time).
//       v1 blobs are still readable (mnemonic defaults to empty string).

namespace {

static constexpr uint32_t WSTS_BLOB_MAGIC     = 0x57535453u;  // "WSTS"
static constexpr uint32_t WSTS_BLOB_VERSION_1 = 1u;
static constexpr uint32_t WSTS_BLOB_VERSION   = 2u;

std::string window_stats_serialize(const WindowStatsResult& res) {
    size_t total = 4 + 4 + 8 + 8 + 8 + 8 + 8 + 8;  // header fields
    for (const auto& w : res.windows) {
        total += 8 * 7;   // start,end,inst_count,mem_r,mem_w,unique_mem,unique_pcs
        total += 4 + 4;   // mnemonic_entropy (f32), branch_density (f32)
        total += 4 * 34;  // reg_write_counts
        total += 4;       // num_top_mnemonics
        for (const auto& ms : w.top_mnemonics) {
            total += 2 + 8 + 1 + ms.mnemonic.size();  // id(u16)+count(u64)+len(u8)+chars
        }
    }

    std::string buf(total, '\0');
    char* p = buf.data();

    auto write_u16 = [&](uint16_t v) { std::memcpy(p, &v, 2); p += 2; };
    auto write_u32 = [&](uint32_t v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_f32 = [&](float    v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_u64 = [&](uint64_t v) { std::memcpy(p, &v, 8); p += 8; };

    write_u32(WSTS_BLOB_MAGIC);
    write_u32(WSTS_BLOB_VERSION);
    write_u64(res.window_size);
    write_u64(res.total_windows);
    write_u64(static_cast<uint64_t>(res.hottest_mem_window));
    write_u64(static_cast<uint64_t>(res.most_diverse_window));
    write_u64(static_cast<uint64_t>(res.densest_branch_window));
    write_u64(static_cast<uint64_t>(res.windows.size()));

    for (const auto& w : res.windows) {
        write_u64(w.start_inst_id);
        write_u64(w.end_inst_id);
        write_u64(w.instruction_count);
        write_u64(w.mem_read_count);
        write_u64(w.mem_write_count);
        write_u64(w.unique_mem_addrs);
        write_u64(w.unique_pcs);
        write_f32(w.mnemonic_entropy);
        write_f32(w.branch_density);
        for (uint32_t c : w.reg_write_counts) write_u32(c);
        write_u32(static_cast<uint32_t>(w.top_mnemonics.size()));
        for (const auto& ms : w.top_mnemonics) {
            write_u16(ms.mnemonic_id);
            write_u64(ms.count);
            uint8_t len = static_cast<uint8_t>(std::min<size_t>(ms.mnemonic.size(), 255));
            p[0] = static_cast<char>(len);
            p += 1;
            std::memcpy(p, ms.mnemonic.data(), len);
            p += len;
        }
    }

    return buf;
}

bool window_stats_deserialize(const std::string& blob, WindowStatsResult& out) {
    if (blob.size() < 4 + 4 + 8 * 6) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto read_u16 = [&]() -> uint16_t { uint16_t v; std::memcpy(&v, p, 2); p += 2; return v; };
    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_f32 = [&]() -> float    { float    v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_u64 = [&]() -> uint64_t { uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; };

    if (read_u32() != WSTS_BLOB_MAGIC) return false;
    const uint32_t version = read_u32();
    if (version != WSTS_BLOB_VERSION && version != WSTS_BLOB_VERSION_1) return false;

    out.window_size           = read_u64();
    out.total_windows         = read_u64();
    out.hottest_mem_window    = static_cast<size_t>(read_u64());
    out.most_diverse_window   = static_cast<size_t>(read_u64());
    out.densest_branch_window = static_cast<size_t>(read_u64());

    uint64_t n = read_u64();
    out.windows.reserve(static_cast<size_t>(n));

    for (uint64_t i = 0; i < n; i++) {
        if (p + 8 * 7 + 4 + 4 + 4 * 34 + 4 > end) return false;
        WindowSnapshot w;
        w.start_inst_id      = read_u64();
        w.end_inst_id        = read_u64();
        w.instruction_count  = read_u64();
        w.mem_read_count     = read_u64();
        w.mem_write_count    = read_u64();
        w.unique_mem_addrs   = read_u64();
        w.unique_pcs         = read_u64();
        w.mnemonic_entropy   = read_f32();
        w.branch_density     = read_f32();
        for (uint32_t j = 0; j < 34; j++) w.reg_write_counts[j] = read_u32();
        uint32_t nm = read_u32();
        w.top_mnemonics.reserve(nm);
        for (uint32_t j = 0; j < nm; j++) {
            if (p + 2 + 8 > end) return false;
            WindowSnapshot::MnemonicStat ms;
            ms.mnemonic_id = read_u16();
            ms.count       = read_u64();
            if (version >= 2) {
                if (p + 1 > end) return false;
                uint8_t len = static_cast<uint8_t>(*p);
                p += 1;
                if (p + len > end) return false;
                ms.mnemonic.assign(p, len);
                p += len;
            }
            w.top_mnemonics.push_back(std::move(ms));
        }
        out.windows.push_back(std::move(w));
    }

    return true;
}

}  // anonymous namespace (window_stats serialization)

// OpcodeInfo and classify_opcode are now provided by common/aarch64_classify.h
using OpcodeInfo = aarch64::OpcodeInfo;

namespace {
inline OpcodeInfo classify_opcode(uint32_t opcode) noexcept {
    return aarch64::OpcodeInfo::classify(opcode);
}
}  // anonymous namespace

// ─── WindowStatsCollector ─────────────────────────────────────────────────

/// Sequential TraceCollector that accumulates per-window statistics.
class WindowStatsCollector final : public TraceCollector {
public:
    WindowStatsCollector(const WindowStatsConfig& cfg,
                         CodeTable& code_table,
                         uint64_t total_insts,
                         InstructionDecoder* decoder)
        : cfg_(cfg)
        , code_table_(code_table)
        , total_insts_(total_insts)
        , decoder_(decoder)
    {
        window_size_ = cfg_.window_size;
        stride_ = (cfg_.stride > 0) ? cfg_.stride : window_size_;
    }

    std::string_view name() const override { return "WindowStatsCollector"; }

    bool begin(uint64_t /*start*/, uint64_t /*end*/) override {
        result_ = WindowStatsResult{};
        result_.window_size = window_size_;
        result_.total_windows = (total_insts_ + stride_ - 1) / stride_;
        result_.windows.reserve(result_.total_windows);

        // Reset per-window accumulators
        current_window_ = WindowSnapshot{};
        current_window_.start_inst_id = 1;
        window_inst_count_ = 0;
        branch_count_ = 0;
        inst_id_ = 0;
        pc_cache_.clear();
        pc_cache_.reserve(4096);
        mnemonic_counts_.clear();
        unique_pcs_.clear();
        unique_pcs_.reserve(std::min(window_size_, uint64_t(16384)));
        unique_mem_addrs_.clear();
        unique_mem_addrs_.reserve(1024);
        return true;
    }

    void on_code(const CodeView& /*code*/) override {
        // Code records not needed — we use code_table for opcode lookup
    }

    void on_inst(uint64_t inst_id, const InstView& inst) override {
        inst_id_ = inst_id + 1;  // Track for window boundary detection
        window_inst_count_++;

        // Track unique PCs
        unique_pcs_.insert(inst.pc);

        // Track register writes
        if (cfg_.track_reg_activity) {
            for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
                auto diff = inst.reg_diff(d);
                if (diff.index < 34) {
                    current_window_.reg_write_counts[diff.index]++;
                }
            }
        }

        // Track memory accesses
        if (cfg_.track_mem_hotspots) {
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto mem = inst.mem_access(m);
                if (mem.type & 0x02) {
                    current_window_.mem_write_count++;
                } else {
                    current_window_.mem_read_count++;
                }
                unique_mem_addrs_.insert(mem.addr);
            }
        }

        // Classify instruction via cached opcode lookup
        auto [cache_it, inserted] = pc_cache_.try_emplace(inst.pc, OpcodeInfo{0, false});
        if (inserted) {
            auto opcode_opt = code_table_.opcode_at(inst.pc);
            if (opcode_opt) {
                cache_it->second = classify_opcode(*opcode_opt);
            }
        }
        const auto& info = cache_it->second;
        mnemonic_counts_[info.mnemonic_id]++;
        if (info.is_branch) branch_count_++;

        // Remember one representative PC per mnemonic_id group so that, at
        // flush time, we can resolve a human-readable name for whichever
        // groups make the top-N cut — without decoding every instruction.
        mnemonic_sample_pc_.try_emplace(info.mnemonic_id, inst.pc);

        // Check if window is complete
        if (window_inst_count_ >= window_size_) {
            flush_window(inst_id_);
        }
    }

    void end() override {
        // Handle partial last window
        if (window_inst_count_ > 0) {
            flush_window(inst_id_);
        }

        // Find hottest windows
        if (!result_.windows.empty()) {
            for (size_t i = 0; i < result_.windows.size(); i++) {
                if (result_.windows[i].mem_read_count + result_.windows[i].mem_write_count >
                    result_.windows[result_.hottest_mem_window].mem_read_count +
                    result_.windows[result_.hottest_mem_window].mem_write_count) {
                    result_.hottest_mem_window = i;
                }
                if (result_.windows[i].mnemonic_entropy >
                    result_.windows[result_.most_diverse_window].mnemonic_entropy) {
                    result_.most_diverse_window = i;
                }
                if (result_.windows[i].branch_density >
                    result_.windows[result_.densest_branch_window].branch_density) {
                    result_.densest_branch_window = i;
                }
            }
        }
    }

    WindowStatsResult take_result() { return std::move(result_); }

private:
    void flush_window(uint64_t end_inst_id) {
        current_window_.end_inst_id = end_inst_id;
        current_window_.instruction_count = window_inst_count_;
        current_window_.unique_pcs = unique_pcs_.size();
        current_window_.unique_mem_addrs = unique_mem_addrs_.size();
        current_window_.branch_density =
            (window_inst_count_ > 0)
            ? static_cast<float>(branch_count_) / window_inst_count_
            : 0.0f;

        // Compute mnemonic entropy
        float entropy = 0.0f;
        uint64_t total_mnem = 0;
        for (const auto& [_, cnt] : mnemonic_counts_) total_mnem += cnt;
        if (total_mnem > 0) {
            for (const auto& [_, cnt] : mnemonic_counts_) {
                float p = static_cast<float>(cnt) / total_mnem;
                if (p > 0) entropy -= p * std::log2(p);
            }
        }
        current_window_.mnemonic_entropy = entropy;

        // Top mnemonics
        std::vector<std::pair<uint16_t, uint64_t>> sorted_mnems(
            mnemonic_counts_.begin(), mnemonic_counts_.end());
        std::sort(sorted_mnems.begin(), sorted_mnems.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        for (uint32_t i = 0; i < cfg_.top_mnemonics && i < sorted_mnems.size(); i++) {
            WindowSnapshot::MnemonicStat ms;
            ms.mnemonic_id = sorted_mnems[i].first;
            ms.count       = sorted_mnems[i].second;
            ms.mnemonic    = resolve_mnemonic_name(ms.mnemonic_id);
            current_window_.top_mnemonics.push_back(std::move(ms));
        }

        result_.windows.push_back(std::move(current_window_));

        // Reset for next window
        current_window_ = WindowSnapshot{};
        current_window_.start_inst_id = end_inst_id + 1;
        window_inst_count_ = 0;
        branch_count_ = 0;
        mnemonic_counts_.clear();
        mnemonic_sample_pc_.clear();
        unique_pcs_.clear();
        unique_mem_addrs_.clear();
    }

    /// Resolve a human-readable mnemonic name for a mnemonic_id group by
    /// decoding one representative PC from that group. Only called for the
    /// (small) top-N set per window, so the Capstone decode cost is
    /// negligible relative to the O(window_size) scan.
    /// Falls back to "id:N" when no decoder is available or decode fails,
    /// so callers always get a non-empty, unambiguous label.
    std::string resolve_mnemonic_name(uint16_t mnemonic_id) {
        auto it = mnemonic_sample_pc_.find(mnemonic_id);
        if (it == mnemonic_sample_pc_.end() || !decoder_) {
            return fmt::format("id:{}", mnemonic_id);
        }
        auto decoded = decoder_->decode(it->second, code_table_);
        if (!decoded) {
            return fmt::format("id:{}", mnemonic_id);
        }
        return std::string(decoded->mnemonic_sv());
    }

    const WindowStatsConfig& cfg_;
    CodeTable& code_table_;
    uint64_t total_insts_;
    InstructionDecoder* decoder_ = nullptr;  // optional; nullptr → "id:N" labels
    uint64_t window_size_ = 1000;
    uint64_t stride_ = 1000;

    // Per-window state
    WindowSnapshot current_window_;
    uint64_t window_inst_count_ = 0;
    uint64_t branch_count_ = 0;
    uint64_t inst_id_ = 0;

    ankerl::unordered_dense::map<uint64_t, OpcodeInfo> pc_cache_;
    ankerl::unordered_dense::map<uint16_t, uint64_t> mnemonic_counts_;
    ankerl::unordered_dense::map<uint16_t, uint64_t> mnemonic_sample_pc_;
    ankerl::unordered_dense::set<uint64_t> unique_pcs_;
    ankerl::unordered_dense::set<uint64_t> unique_mem_addrs_;

    WindowStatsResult result_;
};

// ─── WindowStatsPass::run ─────────────────────────────────────────────────

PassResult WindowStatsPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& code_table = ctx.code_table();

    const uint64_t total_insts = index.inst_count();
    if (total_insts == 0) {
        return PassResult::failed("Empty trace");
    }

    // ── Fast path: load from persisted cache ──────────────────────────────
    // Only cache for full-trace analysis with default window config to keep
    // the cache key unambiguous.
    const bool is_default_cfg =
        cfg_.window_size == 1000 && cfg_.stride == 0 &&
        cfg_.top_mnemonics == 10 &&
        cfg_.track_mem_hotspots && cfg_.track_reg_activity;
    if (is_default_cfg && ctx.range().is_full_trace()) {
        std::string blob;
        if (index.load_pass_blob("window_stats", blob)) {
            WindowStatsResult cached;
            if (window_stats_deserialize(blob, cached)) {
                ctx.progress(1.0f, fmt::format(
                    "WindowStats: {} windows (from cache)", cached.windows.size()));
                return PassResult::success(std::move(cached));
            }
        }
    }

    ctx.progress(0.0f, "WindowStats: computing sliding window metrics...");

    WindowStatsCollector collector(cfg_, code_table, total_insts, &ctx.decoder());

    // Use shared scan engine if available; otherwise create a local one.
    // This allows future fusion with other collector-based passes.
    auto* engine = ctx.scan_engine();
    if (engine) {
        engine->add_collector(&collector);
        engine->run();
    } else {
        TraceScanEngine local_engine(reader, total_insts, &index);
        local_engine.set_progress([&](uint64_t processed, uint64_t total) {
            if (total > 0) {
                ctx.progress(static_cast<float>(processed) / static_cast<float>(total));
            }
        });
        local_engine.set_cancel_check([&]() { return ctx.cancelled(); });
        local_engine.add_collector(&collector);
        local_engine.run();
    }

    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }

    auto result = collector.take_result();

    // ── Persist result for future sessions ───────────────────────────────
    if (is_default_cfg && ctx.range().is_full_trace()) {
        std::string blob = window_stats_serialize(result);
        if (!blob.empty()) {
            index.save_pass_blob("window_stats", blob.data(), blob.size());
        }
    }

    ctx.progress(1.0f, fmt::format("WindowStats: {} windows complete", result.windows.size()));
    return PassResult::success(std::move(result));
}

}  // namespace tenet
