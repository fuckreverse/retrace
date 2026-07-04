#include "analysis/passes/memory/memory_snapshot_pass.h"
#include "analysis/passes/structure/function_pass.h"
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
#if TENET_HAS_TBB
#include <tbb/parallel_for_each.h>
#include <mutex>
#endif

namespace tenet {

// ─── MemorySnapshotResult serialization helpers ────────────────────────────
//
// Blob format (all little-endian):
//   u32  magic   = 0x4D534E50 ("MSNP")
//   u32  version = 1
//   u64  num_snapshots
//   for each MemoryRegion:
//     u64  addr
//     u64  at_inst_id
//     u32  label_len; u8[] label
//     u64  data_len
//     u8[] data[data_len]
//     u64  known_len (== data_len)
//     u8[] known_bits: packed as bytes (bit i = known[i])
//   (by_inst_id is rebuilt after deserialization)

namespace {

static constexpr uint32_t MSNP_BLOB_MAGIC   = 0x4D534E50u;  // "MSNP"
static constexpr uint32_t MSNP_BLOB_VERSION = 1u;

std::string memory_snapshot_serialize(const MemorySnapshotResult& res) {
    size_t total = 4 + 4 + 8;  // magic, version, num_snapshots
    for (const auto& r : res.snapshots) {
        total += 8 + 8;  // addr, at_inst_id
        total += 4 + r.label.size();
        size_t n = r.data.size();
        total += 8 + n;  // data_len + data
        // known: pack into bytes (ceil(n/8) bytes)
        size_t known_bytes = (n + 7) / 8;
        total += 8 + known_bytes;
    }

    std::string buf(total, '\0');
    char* p = buf.data();

    auto write_u32 = [&](uint32_t v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_u64 = [&](uint64_t v) { std::memcpy(p, &v, 8); p += 8; };
    auto write_str = [&](const std::string& s) {
        write_u32(static_cast<uint32_t>(s.size()));
        std::memcpy(p, s.data(), s.size()); p += s.size();
    };

    write_u32(MSNP_BLOB_MAGIC);
    write_u32(MSNP_BLOB_VERSION);
    write_u64(static_cast<uint64_t>(res.snapshots.size()));

    for (const auto& r : res.snapshots) {
        write_u64(r.addr);
        write_u64(r.at_inst_id);
        write_str(r.label);

        size_t n = r.data.size();
        write_u64(static_cast<uint64_t>(n));
        std::memcpy(p, r.data.data(), n); p += n;

        // Pack known bits
        size_t known_bytes = (n + 7) / 8;
        write_u64(static_cast<uint64_t>(known_bytes));
        std::memset(p, 0, known_bytes);
        for (size_t i = 0; i < n; i++) {
            if (r.known[i]) {
                reinterpret_cast<uint8_t*>(p)[i / 8] |= static_cast<uint8_t>(1u << (i % 8));
            }
        }
        p += known_bytes;
    }

    return buf;
}

bool memory_snapshot_deserialize(const std::string& blob, MemorySnapshotResult& out) {
    if (blob.size() < 4 + 4 + 8) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_u64 = [&]() -> uint64_t { uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; };
    auto read_str = [&](std::string& s) -> bool {
        if (p + 4 > end) return false;
        uint32_t len = read_u32();
        if (p + len > end) return false;
        s.assign(p, len); p += len;
        return true;
    };

    if (read_u32() != MSNP_BLOB_MAGIC)   return false;
    if (read_u32() != MSNP_BLOB_VERSION) return false;

    uint64_t n_snaps = read_u64();
    out.snapshots.reserve(static_cast<size_t>(n_snaps));

    for (uint64_t i = 0; i < n_snaps; i++) {
        MemoryRegion r;
        if (p + 8 + 8 > end) return false;
        r.addr       = read_u64();
        r.at_inst_id = read_u64();
        if (!read_str(r.label)) return false;

        if (p + 8 > end) return false;
        uint64_t data_len = read_u64();
        if (p + data_len > end) return false;
        r.data.assign(reinterpret_cast<const uint8_t*>(p),
                      reinterpret_cast<const uint8_t*>(p) + data_len);
        p += data_len;

        if (p + 8 > end) return false;
        uint64_t known_bytes = read_u64();
        if (p + known_bytes > end) return false;
        r.known.resize(static_cast<size_t>(data_len), false);
        for (size_t bi = 0; bi < static_cast<size_t>(data_len); bi++) {
            uint8_t byte = reinterpret_cast<const uint8_t*>(p)[bi / 8];
            r.known[bi] = (byte >> (bi % 8)) & 1u;
        }
        p += known_bytes;

        out.snapshots.push_back(std::move(r));
    }

    // Rebuild by_inst_id index
    for (size_t idx = 0; idx < out.snapshots.size(); idx++) {
        out.by_inst_id[out.snapshots[idx].at_inst_id].push_back(idx);
    }

    return true;
}

}  // anonymous namespace (memory_snapshot serialization)

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

    // ─── Fast path: load from persisted cache ─────────────────────────────
    // Only cache default config (snapshot_at_function_calls, no explicit ids).
    bool is_default_config = (config_.snapshot_inst_ids.empty() &&
                              config_.snapshot_at_function_calls);
    if (ctx.range().is_full_trace() && is_default_config) {
        std::string blob;
        if (index.load_pass_blob("memory_snapshot", blob)) {
            MemorySnapshotResult cached;
            if (memory_snapshot_deserialize(blob, cached)) {
                ctx.progress(1.0f, fmt::format(
                    "Memory snapshot: {} snapshots (from cache)", cached.total()));
                return PassResult::success(std::move(cached));
            }
        }
    }
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

            // ── Opt: pre-cache regfile for all call sites before the loop ──
            // state_before(inst_id) rebuilds from the nearest anchor and
            // replays diffs.  When call events are sparse (avg gap >> anchor
            // interval), warm_range with a fixed stride creates too many
            // useless checkpoints.  Instead, warm_at each target directly in
            // ascending order so the I/O traversal is sequential and each
            // call site gets its result cached before the timing loop starts.
            {
                auto t_warm0 = HiResClock::now();
                size_t warmed = 0;
                for (const auto& ev : events) {
                    if (ev.call_inst_id < range.start_inst_id) continue;
                    if (ev.call_inst_id > end_id) break;
                    regfile.warm_at(ev.call_inst_id);
                    ++warmed;
                    if (warmed >= config_.max_snapshots) break;
                }
                auto t_warm1 = HiResClock::now();
                double warm_ms = std::chrono::duration<double, std::milli>(t_warm1 - t_warm0).count();
                fmt::print(stderr, "[memory_snapshot] warm_at {} call sites: {:.1f} ms\n",
                           warmed, warm_ms);
            }

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
        // Pre-allocate result slots so threads can write without re-allocation.
        std::vector<IndexedRegion> indexed_regions(order.size());
        for (size_t i = 0; i < order.size(); ++i)
            indexed_regions[i].original_idx = order[i];

#if TENET_HAS_TBB
        // ── Phase B (TBB parallel): group by page and process concurrently ──
        // Each page group is independent: read_region uses thread-local RocksDB
        // iterators, so no sharing.  memread_us/memread_calls accumulation uses
        // a small mutex so the diagnostic output is still accurate.
        //
        // Build page-group ranges first (we already have order[] sorted by page).
        struct PageGroup { size_t begin; size_t end; };
        std::vector<PageGroup> page_groups;
        {
            size_t g_start = 0;
            for (size_t i = 1; i <= order.size(); ++i) {
                bool last = (i == order.size());
                bool new_page = !last &&
                    (requests[order[i]].page != requests[order[i-1]].page);
                if (last || new_page) {
                    page_groups.push_back({g_start, i});
                    g_start = i;
                }
            }
        }

        std::mutex diag_mutex;
        tbb::parallel_for_each(
            page_groups.begin(), page_groups.end(),
            [&](const PageGroup& grp) {
                if (ctx.cancelled()) return;
                double local_us = 0;
                for (size_t i = grp.begin; i < grp.end; ++i) {
                    auto& req = requests[order[i]];
                    auto t2 = HiResClock::now();
                    indexed_regions[i].region = capture_region(
                        memory, req.addr, config_.snapshot_size, req.inst_id,
                        std::move(req.label));
                    auto t3 = HiResClock::now();
                    local_us += std::chrono::duration<double, std::micro>(t3 - t2).count();
                }
                {
                    std::lock_guard<std::mutex> lk(diag_mutex);
                    memread_us    += local_us;
                    memread_calls += static_cast<size_t>(grp.end - grp.begin);
                }
            });
#else
        // ── Phase B (serial): page-sorted to maximise TL-cache hits ─────────
        for (size_t i = 0; i < order.size(); ++i) {
            if (ctx.cancelled()) break;

            auto& req = requests[order[i]];
            auto t2 = HiResClock::now();
            indexed_regions[i].region = capture_region(
                memory, req.addr, config_.snapshot_size, req.inst_id,
                std::move(req.label));
            auto t3 = HiResClock::now();
            memread_us += std::chrono::duration<double, std::micro>(t3 - t2).count();
            memread_calls++;

            if ((i & 0xFF) == 0) {
                ctx.progress(
                    0.3f + 0.7f * static_cast<float>(i) / static_cast<float>(order.size()),
                    "Batch reading memory");
            }
        }
#endif

        // Sort back to original insertion order for deterministic output.
        // (indexed_regions[i].original_idx == order[i], so sort by original_idx
        // restores the insertion order regardless of TBB task scheduling.)
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

    // ─── Persist to cache ─────────────────────────────────────────────────
    if (ctx.range().is_full_trace() && is_default_config) {
        std::string blob = memory_snapshot_serialize(result);
        if (!blob.empty()) {
            index.save_pass_blob("memory_snapshot", blob.data(), blob.size());
        }
    }

    return PassResult::success(std::move(result));
}

}  // namespace tenet
