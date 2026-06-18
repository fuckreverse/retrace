#include "analysis/passes/window_stats_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"

#include <ankerl/unordered_dense.h>
#include <algorithm>
#include <cmath>

namespace tenet {

namespace {

// Pre-computed classification from a 4-byte AArch64 opcode.
struct OpcodeInfo {
    uint16_t mnemonic_id;  // top 11 bits as grouping key
    bool is_branch;
};

OpcodeInfo classify_opcode(uint32_t opcode) {
    OpcodeInfo info;
    info.mnemonic_id = static_cast<uint16_t>(opcode >> 21);

    uint32_t top6 = opcode >> 26;
    info.is_branch = (top6 == 0x05 || top6 == 0x25 ||    // B, BL
                      (opcode & 0xFF000010u) == 0x54000000u || // B.cond
                      (opcode & 0xFFFFFC1Fu) == 0xD65F0000u || // RET
                      (opcode & 0xFFFFFC1Fu) == 0xD63F0000u);  // BLR
    return info;
}

}  // anonymous namespace

PassResult WindowStatsPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& code_table = ctx.code_table();

    const uint64_t total_insts = index.inst_count();
    if (total_insts == 0) {
        return PassResult::failed("Empty trace");
    }

    const uint64_t window_size = cfg_.window_size;
    const uint64_t stride = (cfg_.stride > 0) ? cfg_.stride : window_size;

    WindowStatsResult result;
    result.window_size = window_size;
    result.total_windows = (total_insts + stride - 1) / stride;
    result.windows.reserve(result.total_windows);

    ctx.progress(0.0f, "WindowStats: computing sliding window metrics...");

    // ── Optimization 1: pc → OpcodeInfo cache ──────────────────────────────
    // Avoids repeated code_table.code_at() + memcpy for the same PC.
    // In tight loops the same PC hits thousands of times.
    ankerl::unordered_dense::map<uint64_t, OpcodeInfo> pc_cache;
    pc_cache.reserve(4096);

    // ── Optimization 2: ankerl dense sets for unique tracking ──────────────
    // Open-addressing → no per-node heap allocation, better cache locality.
    ankerl::unordered_dense::set<uint64_t> unique_pcs;
    ankerl::unordered_dense::set<uint64_t> unique_mem_addrs;
    unique_pcs.reserve(std::min(window_size, uint64_t(16384)));
    unique_mem_addrs.reserve(1024);

    // Per-window accumulators
    ankerl::unordered_dense::map<uint16_t, uint64_t> mnemonic_counts;

    WindowSnapshot current_window;
    current_window.start_inst_id = 1;
    uint64_t window_inst_count = 0;
    uint64_t inst_id = 0;
    uint64_t branch_count = 0;

    reader.advise_sequential();

    for (auto it = reader.begin(); it != reader.end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        inst_id++;
        window_inst_count++;

        auto inst = rec.as_inst();

        // Track unique PCs
        unique_pcs.insert(inst.pc);

        // Track register writes
        if (cfg_.track_reg_activity) {
            for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
                auto diff = inst.reg_diff(d);
                if (diff.index < 34) {
                    current_window.reg_write_counts[diff.index]++;
                }
            }
        }

        // Track memory accesses
        if (cfg_.track_mem_hotspots) {
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto mem = inst.mem_access(m);
                if (mem.type & 0x02) {
                    current_window.mem_write_count++;
                } else {
                    current_window.mem_read_count++;
                }
                unique_mem_addrs.insert(mem.addr);
            }
        }

        // ── Classify instruction via cached opcode lookup ──────────────────
        auto [cache_it, inserted] = pc_cache.try_emplace(inst.pc, OpcodeInfo{0, false});
        if (inserted) {
            // First time seeing this PC — look up code table
            auto opcode_opt = code_table.opcode_at(inst.pc);
            if (opcode_opt) {
                cache_it->second = classify_opcode(*opcode_opt);
            }
        }
        const auto& info = cache_it->second;
        mnemonic_counts[info.mnemonic_id]++;
        if (info.is_branch) branch_count++;

        // Check if window is complete
        if (window_inst_count >= window_size) {
            current_window.end_inst_id = inst_id;
            current_window.instruction_count = window_inst_count;
            current_window.unique_pcs = unique_pcs.size();
            current_window.unique_mem_addrs = unique_mem_addrs.size();
            current_window.branch_density =
                static_cast<float>(branch_count) / window_inst_count;

            // Compute mnemonic entropy
            float entropy = 0.0f;
            uint64_t total_mnem = 0;
            for (const auto& [_, cnt] : mnemonic_counts) total_mnem += cnt;
            if (total_mnem > 0) {
                for (const auto& [_, cnt] : mnemonic_counts) {
                    float p = static_cast<float>(cnt) / total_mnem;
                    if (p > 0) entropy -= p * std::log2(p);
                }
            }
            current_window.mnemonic_entropy = entropy;

            // Top mnemonics
            std::vector<std::pair<uint16_t, uint64_t>> sorted_mnems(
                mnemonic_counts.begin(), mnemonic_counts.end());
            std::sort(sorted_mnems.begin(), sorted_mnems.end(),
                      [](const auto& a, const auto& b) { return a.second > b.second; });
            for (uint32_t i = 0; i < cfg_.top_mnemonics && i < sorted_mnems.size(); i++) {
                current_window.top_mnemonics.push_back(
                    {sorted_mnems[i].first, sorted_mnems[i].second});
            }

            result.windows.push_back(std::move(current_window));

            // Reset for next window
            current_window = WindowSnapshot{};
            current_window.start_inst_id = inst_id + 1;
            window_inst_count = 0;
            branch_count = 0;
            mnemonic_counts.clear();
            unique_pcs.clear();
            unique_mem_addrs.clear();
        }

        if (inst_id % 10000 == 0) {
            ctx.progress(static_cast<float>(inst_id) / total_insts);
        }
    }

    reader.advise_random();

    // Handle partial last window
    if (window_inst_count > 0) {
        current_window.end_inst_id = inst_id;
        current_window.instruction_count = window_inst_count;
        current_window.unique_pcs = unique_pcs.size();
        current_window.unique_mem_addrs = unique_mem_addrs.size();
        current_window.branch_density =
            (window_inst_count > 0) ? static_cast<float>(branch_count) / window_inst_count : 0;
        result.windows.push_back(std::move(current_window));
    }

    // Find hottest windows
    if (!result.windows.empty()) {
        for (size_t i = 0; i < result.windows.size(); i++) {
            if (result.windows[i].mem_read_count + result.windows[i].mem_write_count >
                result.windows[result.hottest_mem_window].mem_read_count +
                result.windows[result.hottest_mem_window].mem_write_count) {
                result.hottest_mem_window = i;
            }
            if (result.windows[i].mnemonic_entropy >
                result.windows[result.most_diverse_window].mnemonic_entropy) {
                result.most_diverse_window = i;
            }
            if (result.windows[i].branch_density >
                result.windows[result.densest_branch_window].branch_density) {
                result.densest_branch_window = i;
            }
        }
    }

    ctx.progress(1.0f, "WindowStats: complete");
    return PassResult::success(std::move(result));
}

}  // namespace tenet
