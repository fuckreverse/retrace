#include "analysis/passes/window_stats_pass.h"
#include "analysis/trace_collector.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "common/aarch64_classify.h"

#include <ankerl/unordered_dense.h>
#include <algorithm>
#include <cmath>

namespace tenet {

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
                         uint64_t total_insts)
        : cfg_(cfg)
        , code_table_(code_table)
        , total_insts_(total_insts)
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
            current_window_.top_mnemonics.push_back(
                {sorted_mnems[i].first, sorted_mnems[i].second});
        }

        result_.windows.push_back(std::move(current_window_));

        // Reset for next window
        current_window_ = WindowSnapshot{};
        current_window_.start_inst_id = end_inst_id + 1;
        window_inst_count_ = 0;
        branch_count_ = 0;
        mnemonic_counts_.clear();
        unique_pcs_.clear();
        unique_mem_addrs_.clear();
    }

    const WindowStatsConfig& cfg_;
    CodeTable& code_table_;
    uint64_t total_insts_;
    uint64_t window_size_ = 1000;
    uint64_t stride_ = 1000;

    // Per-window state
    WindowSnapshot current_window_;
    uint64_t window_inst_count_ = 0;
    uint64_t branch_count_ = 0;
    uint64_t inst_id_ = 0;

    ankerl::unordered_dense::map<uint64_t, OpcodeInfo> pc_cache_;
    ankerl::unordered_dense::map<uint16_t, uint64_t> mnemonic_counts_;
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

    ctx.progress(0.0f, "WindowStats: computing sliding window metrics...");

    WindowStatsCollector collector(cfg_, code_table, total_insts);

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

    ctx.progress(1.0f, "WindowStats: complete");
    return PassResult::success(collector.take_result());
}

}  // namespace tenet
