#include "analysis/passes/profile/window_stats_pass.h"
#include "analysis/trace_collector.h"
#include "infra/scan_orchestrator.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/instruction_decoder.h"
#include "common/aarch64_classify.h"

#include "common/byte_codec.h"
#include <fmt/core.h>
#include <ankerl/unordered_dense.h>
#include <algorithm>
#include <cmath>

namespace tenet {

// ─── WindowStatsPass lifecycle (must be defined where WindowStatsCollector is complete) ──

WindowStatsPass::WindowStatsPass(WindowStatsConfig cfg) : cfg_(std::move(cfg)) {}

WindowStatsPass::~WindowStatsPass() = default;

WindowStatsPass::WindowStatsPass(WindowStatsPass&& o) noexcept
    : collector_(std::move(o.collector_)), cfg_(std::move(o.cfg_)) {}

WindowStatsPass& WindowStatsPass::operator=(WindowStatsPass&& o) noexcept {
    if (this != &o) {
        collector_ = std::move(o.collector_);
        cfg_ = std::move(o.cfg_);
    }
    return *this;
}

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
    ByteWriter w;
    w.u32(WSTS_BLOB_MAGIC);
    w.u32(WSTS_BLOB_VERSION);
    w.u64(res.window_size);
    w.u64(res.total_windows);
    w.u64(static_cast<uint64_t>(res.hottest_mem_window));
    w.u64(static_cast<uint64_t>(res.most_diverse_window));
    w.u64(static_cast<uint64_t>(res.densest_branch_window));
    w.u64(static_cast<uint64_t>(res.windows.size()));

    for (const auto& wnd : res.windows) {
        w.u64(wnd.start_inst_id);
        w.u64(wnd.end_inst_id);
        w.u64(wnd.instruction_count);
        w.u64(wnd.mem_read_count);
        w.u64(wnd.mem_write_count);
        w.u64(wnd.unique_mem_addrs);
        w.u64(wnd.unique_pcs);
        w.f32(wnd.mnemonic_entropy);
        w.f32(wnd.branch_density);
        for (uint32_t c : wnd.reg_write_counts) w.u32(c);
        w.u32(static_cast<uint32_t>(wnd.top_mnemonics.size()));
        for (const auto& ms : wnd.top_mnemonics) {
            w.u16(ms.mnemonic_id);
            w.u64(ms.count);
            uint8_t len = static_cast<uint8_t>(std::min<size_t>(ms.mnemonic.size(), 255));
            w.u8(len);
            w.bytes(ms.mnemonic.data(), len);
        }
    }

    return std::move(w).take();
}

bool window_stats_deserialize(const std::string& blob, WindowStatsResult& out) {
    ByteReader r(blob.data(), blob.size());

    if (r.u32() != WSTS_BLOB_MAGIC) return false;
    const uint32_t version = r.u32();
    if (version != WSTS_BLOB_VERSION && version != WSTS_BLOB_VERSION_1) return false;

    out.window_size           = r.u64();
    out.total_windows         = r.u64();
    out.hottest_mem_window    = static_cast<size_t>(r.u64());
    out.most_diverse_window   = static_cast<size_t>(r.u64());
    out.densest_branch_window = static_cast<size_t>(r.u64());

    uint64_t n = r.u64();
    if (!r.ok()) return false;
    out.windows.reserve(static_cast<size_t>(n));

    for (uint64_t i = 0; i < n; i++) {
        WindowSnapshot w;
        w.start_inst_id      = r.u64();
        w.end_inst_id        = r.u64();
        w.instruction_count  = r.u64();
        w.mem_read_count     = r.u64();
        w.mem_write_count    = r.u64();
        w.unique_mem_addrs   = r.u64();
        w.unique_pcs         = r.u64();
        w.mnemonic_entropy   = r.f32();
        w.branch_density     = r.f32();
        for (uint32_t j = 0; j < 34; j++) w.reg_write_counts[j] = r.u32();
        uint32_t nm = r.u32();
        if (!r.ok()) return false;
        w.top_mnemonics.reserve(nm);
        for (uint32_t j = 0; j < nm; j++) {
            WindowSnapshot::MnemonicStat ms;
            ms.mnemonic_id = r.u16();
            ms.count       = r.u64();
            if (version >= 2) {
                uint8_t len = r.u8();
                if (!r.ok()) return false;
                ms.mnemonic.resize(len);
                r.bytes(ms.mnemonic.data(), len);
            }
            w.top_mnemonics.push_back(std::move(ms));
        }
        out.windows.push_back(std::move(w));
    }

    return r.ok();
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
class WindowStatsPass::WindowStatsCollector final : public TraceCollector {
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

// ─── WindowStatsPass::declare_scan ────────────────────────────────────────

void WindowStatsPass::declare_scan(ScanOrchestrator& orch, PassContext& ctx) {
    auto& code_table = ctx.code_table();
    auto& index = ctx.index();
    uint64_t total_insts = index.inst_count();

    collector_ = std::make_unique<WindowStatsCollector>(
        cfg_, code_table, total_insts, &ctx.decoder());
    orch.declare({name(), collector_.get(), /*wants_parallel=*/false});
}

// ─── WindowStatsPass::run ─────────────────────────────────────────────────

PassResult WindowStatsPass::run(PassContext& ctx) {
    auto& index = ctx.index();

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
                collector_.reset();  // no scan needed on cache hit
                ctx.progress(1.0f, fmt::format(
                    "WindowStats: {} windows (from cache)", cached.windows.size()));
                return PassResult::success(std::move(cached));
            }
        }
    }

    // collector_ was populated by declare_scan() + ScanOrchestrator::execute_scan()
    if (!collector_) {
        return PassResult::failed("declare_scan() was not called before run()");
    }

    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }

    auto result = collector_->take_result();

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
