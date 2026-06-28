#include "analysis/passes/memory_snapshot_pass.h"
#include "analysis/passes/function_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/memory_model.h"
#include "core/register_file.h"
#include <fmt/core.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <numeric>

namespace tenet {

// ─── Hex dump formatting ──────────────────────────────────────────────────

std::string MemorySnapshotResult::hex_dump(const MemoryRegion& region) {
    std::string result;
    const size_t bytes_per_line = 16;
    const size_t total = region.data.size();

    for (size_t offset = 0; offset < total; offset += bytes_per_line) {
        // Address column
        result += fmt::format("{:08x}: ", region.addr + offset);

        // Hex bytes (two groups of 8)
        for (size_t i = 0; i < bytes_per_line; ++i) {
            if (i == 8) result += ' ';
            size_t idx = offset + i;
            if (idx < total && region.known[idx]) {
                result += fmt::format("{:02x}", region.data[idx]);
            } else if (idx < total) {
                result += "??";
            } else {
                result += "  ";
            }
            result += ' ';
        }

        // ASCII column
        result += ' ';
        for (size_t i = 0; i < bytes_per_line && (offset + i) < total; ++i) {
            size_t idx = offset + i;
            if (region.known[idx]) {
                uint8_t c = region.data[idx];
                result += (c >= 0x20 && c < 0x7f) ? static_cast<char>(c) : '.';
            } else {
                result += '.';
            }
        }
        result += '\n';
    }
    return result;
}

// ─── Region capture using read_region (batched, TL-page-cache friendly) ───

MemoryRegion MemorySnapshotPass::capture_region(MemoryModel& memory,
                                                 uint64_t addr,
                                                 uint64_t size,
                                                 uint64_t at_inst_id,
                                                 std::string label) {
    MemoryRegion region;
    region.addr = addr;
    region.at_inst_id = at_inst_id;
    region.label = std::move(label);

    // Use read_region() which handles chunking internally and benefits from
    // thread-local page cache (skips mutex + hash lookup for same-page accesses).
    auto rr = memory.read_region(addr, static_cast<size_t>(size), at_inst_id);
    region.data = std::move(rr.data);
    region.known.resize(rr.known.size());
    for (size_t i = 0; i < rr.known.size(); ++i)
        region.known[i] = rr.known[i];

    return region;
}

// ─── Pass implementation ──────────────────────────────────────────────────

PassResult MemorySnapshotPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& memory = ctx.memory();
    auto& regfile = ctx.regfile();

    const auto& range = ctx.range();
    uint64_t end_id = std::min(range.end_inst_id, index.inst_count());
    if (end_id == 0) end_id = index.inst_count();

    MemorySnapshotResult result;
    using HiResClock = std::chrono::high_resolution_clock;

    // Timing accumulators for diagnostics
    double regfile_us = 0, memread_us = 0;
    size_t regfile_calls = 0, memread_calls = 0;

    // ═══════════════════════════════════════════════════════════════════════
    // TWO-PHASE OPTIMIZATION: "collect then batch-read by page"
    //
    // The dominant cost (~93%) is capture_region → MemoryModel::read_region.
    // Each call may trigger a cold load_page_index from RocksDB (~6 ms).
    // When snapshot addresses are scattered across many pages and processed
    // in call-event order, the 512-page LRU cache thrashes badly.
    //
    // Solution:
    //   Phase A: collect all (addr, inst_id, label) tuples without reading
    //            memory (only regfile.state_before — 170μs/call, ~2.5% cost).
    //   Phase B: sort collected requests by page number, then execute
    //            capture_region in page-sorted order. Consecutive accesses
    //            to the same page hit the thread-local cache (zero-cost).
    //            Different pages are loaded in sequential order, which is
    //            also faster than random access on RocksDB iterators.
    // ═══════════════════════════════════════════════════════════════════════

    /// A deferred snapshot request (collected in Phase A, executed in Phase B).
    struct SnapshotRequest {
        uint64_t addr;
        uint64_t inst_id;
        std::string label;
        uint64_t page;  // addr >> 12, for sorting
    };

    std::vector<SnapshotRequest> requests;
    requests.reserve(config_.max_snapshots);

    // Helper: check if we've hit the snapshot limit (based on collected requests).
    auto limit_reached = [&]() -> bool {
        return requests.size() >= config_.max_snapshots;
    };

    // Helper: collect pointer-like registers (x0-x7) at a given inst_id.
    auto collect_pointers = [&](uint64_t inst_id, const std::string& target_label) {
        auto t0 = HiResClock::now();
        const RegState& regs = regfile.state_before(inst_id);
        auto t1 = HiResClock::now();
        regfile_us += std::chrono::duration<double, std::micro>(t1 - t0).count();
        regfile_calls++;

        for (int r = 0; r < 8; ++r) {
            if (limit_reached()) break;
            uint64_t val = regs.gpr[r];
            if (val >= 0x100000000ULL) {  // Likely a pointer on AArch64
                requests.push_back({
                    val, inst_id,
                    fmt::format("x{} at {}", r, target_label),
                    val >> 12
                });
            }
        }
    };

    // ─── Phase A: Collect all snapshot requests ───────────────────────────

    // Phase A.1: Handle explicit snapshot_inst_ids
    {
        auto explicit_ids = config_.snapshot_inst_ids;
        std::sort(explicit_ids.begin(), explicit_ids.end());

        for (uint64_t iid : explicit_ids) {
            if (limit_reached() || ctx.cancelled()) break;
            if (iid < range.start_inst_id || iid > end_id) continue;

            const RegState& regs = regfile.state_before(iid);

            // Collect SP-relative (stack frame)
            uint64_t sp = regs.sp();
            if (sp != 0 && !limit_reached()) {
                requests.push_back({
                    sp, iid,
                    fmt::format("SP at inst #{}", iid),
                    sp >> 12
                });
            }

            // Collect x0-x7 if they look like pointers
            collect_pointers(iid, fmt::format("inst #{}", iid));
        }
    }

    // Phase A.2: Function-call snapshots
    if (config_.snapshot_at_function_calls && !limit_reached() && !ctx.cancelled()) {
        const FunctionResult* func_result = ctx.try_require<FunctionResult>("function");

        if (func_result && !func_result->call_events.empty()) {
            // ── Fast path: use pre-computed call events ──────────────────
            const auto& events = func_result->call_events;
            ctx.progress(0.0f, "Collecting snapshot targets (fast path)");

            size_t processed = 0;
            fmt::print(stderr, "[memory_snapshot] fast-path: {} call events, limit={}\n",
                       events.size(), config_.max_snapshots);

            for (const auto& ev : events) {
                if (limit_reached() || ctx.cancelled()) break;
                if (ev.call_inst_id < range.start_inst_id) continue;
                if (ev.call_inst_id > end_id) break;

                std::string target_label = ev.target_pc
                    ? fmt::format("BL sub_{:x}", ev.target_pc)
                    : "BL unknown";

                collect_pointers(ev.call_inst_id, target_label);

                processed++;
                if ((processed & 0x3FF) == 0) {
                    ctx.progress(
                        static_cast<float>(processed) / static_cast<float>(events.size()) * 0.3f,
                        "Collecting snapshot targets");
                }
            }

            fmt::print(stderr, "[memory_snapshot] collected {} requests from {} call events\n",
                       requests.size(), processed);
        } else {
            // ── Fallback: scan trace linearly (original algorithm) ───────
            auto& code_table = ctx.code_table();

            uint64_t start_0based = (range.start_inst_id > 0)
                                        ? (range.start_inst_id - 1) : 0;
            uint64_t start_offset = 0;
            if (start_0based > 0) {
                auto [off, pc] = index.offset_of_with_pc(start_0based, reader);
                start_offset = off;
            }

            auto it_begin = (start_0based > 0)
                ? TraceReader::Iterator(&reader, start_offset)
                : reader.begin();
            uint64_t inst_id = (start_0based > 0) ? start_0based : 0;

            for (auto it = it_begin; it != reader.end(); ++it) {
                if (ctx.cancelled() || limit_reached()) break;

                auto rec = *it;
                if (rec.kind != RecordKind::Inst) continue;

                auto inst = rec.as_inst();
                inst_id++;
                if (inst_id > end_id) break;

                if ((inst_id & 0xFFFF) == 0) {
                    float pct = static_cast<float>(inst_id - range.start_inst_id) /
                                static_cast<float>(end_id - range.start_inst_id + 1);
                    ctx.progress(pct * 0.3f, "Scanning for snapshot points (fallback)");
                }

                auto opcode_opt = code_table.opcode_at(inst.pc);
                if (!opcode_opt) continue;

                uint32_t opcode = *opcode_opt;
                bool is_bl  = (opcode & 0xFC000000u) == 0x94000000u;
                bool is_blr = (opcode & 0xFFFFFC1Fu) == 0xD63F0000u;

                if (is_bl || is_blr) {
                    const RegState& regs = regfile.state_before(inst_id);

                    uint64_t target_pc = 0;
                    if (is_bl) {
                        int64_t imm26 = (int64_t)(int32_t)((opcode & 0x03FFFFFFu) << 6) >> 4;
                        target_pc = inst.pc + imm26;
                    } else {
                        uint8_t rn = (opcode >> 5) & 0x1F;
                        if (rn < 31) target_pc = regs.gpr[rn];
                    }

                    std::string target_label = target_pc
                        ? fmt::format("BL sub_{:x}", target_pc) : "BL unknown";

                    collect_pointers(inst_id, target_label);
                }
            }
        }
    }

    // ─── Phase B: Sort by page and batch-execute capture_region ───────────
    if (!requests.empty()) {
        // Create an index array for stable-sort by page (preserves relative
        // order within the same page for deterministic output).
        std::vector<size_t> order(requests.size());
        std::iota(order.begin(), order.end(), 0);
        std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) {
            return requests[a].page < requests[b].page;
        });

        // Count unique pages for diagnostics
        size_t unique_pages = 1;
        for (size_t i = 1; i < order.size(); ++i) {
            if (requests[order[i]].page != requests[order[i-1]].page)
                ++unique_pages;
        }
        fmt::print(stderr, "[memory_snapshot] batch read: {} requests across {} unique pages\n"
                   "  ({} bytes/req = {} total byte-reads)\n",
                   requests.size(), unique_pages,
                   config_.snapshot_size,
                   requests.size() * config_.snapshot_size);

        ctx.progress(0.3f, "Batch reading memory (page-sorted)");

        // Execute in page-sorted order — consecutive same-page accesses
        // hit the thread-local page cache with zero overhead.
        // To preserve the original insertion order in the result, we store
        // (original_index, MemoryRegion) pairs and sort back afterwards.
        struct IndexedRegion {
            size_t original_idx;
            MemoryRegion region;
        };
        std::vector<IndexedRegion> indexed_regions;
        indexed_regions.reserve(requests.size());

        for (size_t i = 0; i < order.size(); ++i) {
            if (ctx.cancelled()) break;

            auto& req = requests[order[i]];
            auto t2 = HiResClock::now();
            auto region = capture_region(
                memory, req.addr, config_.snapshot_size, req.inst_id,
                std::move(req.label));
            auto t3 = HiResClock::now();
            memread_us += std::chrono::duration<double, std::micro>(t3 - t2).count();
            memread_calls++;

            indexed_regions.push_back({order[i], std::move(region)});

            if ((i & 0xFF) == 0) {
                ctx.progress(
                    0.3f + 0.7f * static_cast<float>(i) / static_cast<float>(order.size()),
                    "Batch reading memory");
            }
        }

        // Sort back to original insertion order for deterministic output.
        std::sort(indexed_regions.begin(), indexed_regions.end(),
                  [](const IndexedRegion& a, const IndexedRegion& b) {
                      return a.original_idx < b.original_idx;
                  });

        // Build the result.
        for (auto& ir : indexed_regions) {
            uint64_t iid = ir.region.at_inst_id;
            size_t idx = result.snapshots.size();
            result.snapshots.push_back(std::move(ir.region));
            result.by_inst_id[iid].push_back(idx);
        }
    }

    fmt::print(stderr, "[memory_snapshot] timing breakdown:\n"
                       "  regfile.state_before: {:.1f} ms ({} calls, avg {:.1f} us/call)\n"
                       "  capture_region:       {:.1f} ms ({} calls, avg {:.1f} us/call)\n",
               regfile_us / 1000.0, regfile_calls,
               regfile_calls ? regfile_us / regfile_calls : 0.0,
               memread_us / 1000.0, memread_calls,
               memread_calls ? memread_us / memread_calls : 0.0);

    ctx.progress(1.0f, fmt::format("Done: {} snapshots captured", result.total()));
    return PassResult::success(std::move(result));
}

}  // namespace tenet
