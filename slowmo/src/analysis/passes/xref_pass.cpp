#include "analysis/passes/xref_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <fmt/core.h>
#include <thread>
#include <algorithm>
#include <cstring>

#include <sys/mman.h>

// Pull CRoaring C API types into our namespace
using roaring::api::roaring64_bitmap_t;
using roaring::api::roaring64_bulk_context_t;
using roaring::api::roaring64_iterator_t;
using roaring::api::roaring64_bitmap_create;
using roaring::api::roaring64_bitmap_free;
using roaring::api::roaring64_bitmap_add_bulk;
using roaring::api::roaring64_bitmap_or_inplace;
using roaring::api::roaring64_bitmap_run_optimize;
using roaring::api::roaring64_bitmap_get_cardinality;
using roaring::api::roaring64_bitmap_to_uint64_array;
using roaring::api::roaring64_iterator_create;
using roaring::api::roaring64_iterator_has_value;
using roaring::api::roaring64_iterator_read;
using roaring::api::roaring64_iterator_free;

namespace tenet {

// ─── Helpers for raw pointer record parsing ──────────────────────────────────

namespace {

/// Compute record size from raw pointer (avoids virtual dispatch and RecordView overhead)
/// All sizes include compiler alignment padding (structures NOT packed):
///   qbditrace_inst_head_t    = 16 (4B fields + 4B pad + 8B pc)
///   qbditrace_inst_head_v5_t = 6  (kind+nzcv+n_regdiff+n_mem+pc_delta)
///   qbditrace_regdiff_t      = 16 (1B index + 7B pad + 8B value)
///   qbditrace_memacc_t       = 32 (4B fields + 4B pad + 8B addr + 8B value + 8B value_hi)
///   qbditrace_memacc_v6_t    = 48 (v5 + 16B old_value fields)
///   qbditrace_anchor_head_t  = 16 (4B fields + 4B pad + 8B pc)
///   qbditrace_thread_head_t  = 16 (4B fields + 4B pad + 8B thread_id)
///   qbditrace_event_head_t   = 24 (4B fields + 4B pad + 8B addr + 8B site)
///   qbditrace_svc_head_t     = 72 (4B+4B pad+8B pc+8B syscall_no+48B args)
///   qbditrace_objc_head_t    = 80 (4B+4B pad+8B pc+8B recv+8B sel+48B cls)
///   qbditrace_code_head_t    = 16 (4B fields + 4B pad + 8B pc)
/// P1.7: is_v6 controls whether memacc uses the 48-byte v6 layout.
inline size_t raw_record_size(const uint8_t* ptr, uint32_t num_gpr,
                               bool is_v5 = false, bool is_v6 = false) {
    switch (ptr[0]) {
    case 0: { // INST
        uint8_t n_regdiff = ptr[2];
        uint8_t n_mem = ptr[3];
        size_t hdr = is_v5
            ? sizeof(qbditrace::qbditrace_inst_head_v5_t)    // 6 bytes
            : sizeof(qbditrace::qbditrace_inst_head_t);      // 16 bytes
        size_t macc = is_v6
            ? sizeof(qbditrace::qbditrace_memacc_v6_t)       // 48 bytes
            : sizeof(qbditrace::qbditrace_memacc_t);         // 32 bytes
        return hdr
            + n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)   // 16 bytes each
            + n_mem     * macc;
    }
    case 1: // ANCHOR
        return sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr * 8;   // 16 + N*8
    case 2: // THREAD
        return sizeof(qbditrace::qbditrace_thread_head_t);  // 16
    case 3: // EVENT
        return sizeof(qbditrace::qbditrace_event_head_t);   // 24
    case 4: // SVC
        return sizeof(qbditrace::qbditrace_svc_head_t);     // 72
    case 5: // OBJC
        return sizeof(qbditrace::qbditrace_objc_head_t);    // 80
    case 6: // CODE
        return sizeof(qbditrace::qbditrace_code_head_t) + ptr[1];  // 16 + size
    default:
        return 1; // shouldn't happen
    }
}

/// Extract PC from a v4 INST record.
/// qbditrace_inst_head_t layout: kind(1)+nzcv(1)+n_regdiff(1)+n_mem(1)+pad(4)+pc(8)
/// PC is at byte offset 8 (not 4!), due to alignment padding before the uint64_t field.
inline uint64_t raw_inst_pc(const uint8_t* ptr) {
    const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_t*>(ptr);
    return hdr->pc;
}

/// Determine hardware concurrency, capped to reasonable values
inline unsigned worker_count() {
    unsigned n = std::thread::hardware_concurrency();
    if (n == 0) n = 4;
    return std::min(n, 16u);
}

// ─── Shard structure ─────────────────────────────────────────────────────────

struct Shard {
    uint64_t file_start;      // file offset of first record in shard
    uint64_t file_end;        // one-past-last byte offset of last record
    uint64_t start_inst_id;   // inst_id of the first INST record in this shard
    uint64_t end_inst_id;     // one-past-last inst_id for this shard
};

// ─── Per-shard scan result ───────────────────────────────────────────────────

struct ShardResult {
    // PC → roaring64_bitmap_t* (using C API for bulk performance)
    ankerl::unordered_dense::map<uint64_t, roaring64_bitmap_t*> pc_bitmaps;

    ShardResult() { pc_bitmaps.reserve(2048); }

    ~ShardResult() {
        for (auto& [_, bm] : pc_bitmaps) {
            roaring64_bitmap_free(bm);
        }
    }

    // Non-copyable
    ShardResult(const ShardResult&) = delete;
    ShardResult& operator=(const ShardResult&) = delete;

    // Movable
    ShardResult(ShardResult&& o) noexcept : pc_bitmaps(std::move(o.pc_bitmaps)) {
        o.pc_bitmaps.clear();
    }
    ShardResult& operator=(ShardResult&& o) noexcept {
        if (this != &o) {
            for (auto& [_, bm] : pc_bitmaps) roaring64_bitmap_free(bm);
            pc_bitmaps = std::move(o.pc_bitmaps);
            o.pc_bitmaps.clear();
        }
        return *this;
    }
};

/// Scan a shard using raw pointer arithmetic and bulk bitmap insertion.
/// This is the hot loop — every cycle counts.
/// P1.7: is_v5/is_v6 flags control INST header and memacc sizes.
void scan_shard(const Shard& shard, uint32_t num_gpr,
                bool is_v5, bool is_v6, ShardResult& out,
                const TraceReader& reader) {
    uint64_t offset = shard.file_start;
    const uint64_t end_offset = shard.file_end;
    uint64_t inst_id = shard.start_inst_id;

    // Pre-compute sizes to avoid branching in the inner loop.
    const size_t inst_hdr_sz = is_v5
        ? sizeof(qbditrace::qbditrace_inst_head_v5_t)  // 6 bytes
        : sizeof(qbditrace::qbditrace_inst_head_t);    // 16 bytes
    const size_t memacc_sz = is_v6
        ? sizeof(qbditrace::qbditrace_memacc_v6_t)     // 48 bytes
        : sizeof(qbditrace::qbditrace_memacc_t);       // 32 bytes

    // Per-PC bulk context cache: avoid repeated ART lookups in roaring64
    // We cache the last-used PC's bitmap + bulk context for temporal locality.
    uint64_t last_pc = UINT64_MAX;
    roaring64_bitmap_t* last_bm = nullptr;
    roaring64_bulk_context_t last_ctx = {};

    while (offset < end_offset) {
        const uint8_t* ptr = reader.data_at(offset);
        uint8_t kind = ptr[0];

        if (kind == 0) { // INST — the hot path (>95% of records)
            uint64_t pc = is_v5 ? 0 : raw_inst_pc(ptr);

            if (!is_v5) {
                if (__builtin_expect(pc == last_pc, 1)) {
                    roaring64_bitmap_add_bulk(last_bm, &last_ctx, inst_id);
                } else {
                    auto& bm_slot = out.pc_bitmaps[pc];
                    if (__builtin_expect(bm_slot == nullptr, 0)) {
                        bm_slot = roaring64_bitmap_create();
                    }
                    last_pc = pc;
                    last_bm = bm_slot;
                    last_ctx = {};
                    roaring64_bitmap_add_bulk(last_bm, &last_ctx, inst_id);
                }
            }

            uint8_t n_regdiff = ptr[2];
            uint8_t n_mem = ptr[3];
            offset += inst_hdr_sz
                + n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)
                + n_mem     * memacc_sz;
            inst_id++;
        } else {
            offset += raw_record_size(ptr, num_gpr, is_v5, is_v6);
        }
    }
}

} // anonymous namespace

// ─── XrefResult serialization helpers ────────────────────────────────────────
//
// Blob format (little-endian unless noted):
//   u32  magic         = 0x58524546 ("XREF")
//   u32  version       = 1
//   u64  total_indexed
//   u64  unique_pc_count
//   u64  num_entries
//   for each entry:
//     u64  pc
//     u64  exec_count
//     u64  bitmap_bytes          (portable Roaring64Map size)
//     u8[] bitmap_data[bitmap_bytes]
//
// Roaring64Map portable serialisation is endian-safe and cross-platform.

namespace {

static constexpr uint32_t XREF_BLOB_MAGIC   = 0x58524546u;  // "XREF"
static constexpr uint32_t XREF_BLOB_VERSION = 1u;

/// Serialise an XrefResult into a byte buffer.
std::string xref_serialize(const XrefResult& res) {
    // ── compute total size first (one-pass) ───────────────────────────────
    size_t total = 4 + 4 + 8 + 8 + 8;  // header
    for (const auto& [pc, bm] : res.pc_to_inst_ids) {
        total += 8 + 8 + 8 + bm.getSizeInBytes(true);
    }

    std::string buf(total, '\0');
    char* p = buf.data();

    auto write_u32 = [&](uint32_t v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_u64 = [&](uint64_t v) { std::memcpy(p, &v, 8); p += 8; };

    write_u32(XREF_BLOB_MAGIC);
    write_u32(XREF_BLOB_VERSION);
    write_u64(res.total_indexed);
    write_u64(static_cast<uint64_t>(res.unique_pc_count));
    write_u64(static_cast<uint64_t>(res.pc_to_inst_ids.size()));

    for (const auto& [pc, bm] : res.pc_to_inst_ids) {
        uint64_t bm_bytes = static_cast<uint64_t>(bm.getSizeInBytes(true));
        auto exec_it = res.pc_exec_count.find(pc);
        uint64_t exec_count = (exec_it != res.pc_exec_count.end()) ? exec_it->second : 0;

        write_u64(pc);
        write_u64(exec_count);
        write_u64(bm_bytes);
        bm.write(p, true);
        p += bm_bytes;
    }

    return buf;
}

/// Deserialise an XrefResult from a byte buffer.
/// Returns false on format mismatch.
bool xref_deserialize(const std::string& blob, XrefResult& out) {
    if (blob.size() < 4 + 4 + 8 + 8 + 8) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto read_u32 = [&]() -> uint32_t {
        uint32_t v; std::memcpy(&v, p, 4); p += 4; return v;
    };
    auto read_u64 = [&]() -> uint64_t {
        uint64_t v; std::memcpy(&v, p, 8); p += 8; return v;
    };

    if (read_u32() != XREF_BLOB_MAGIC)   return false;
    if (read_u32() != XREF_BLOB_VERSION) return false;

    out.total_indexed   = read_u64();
    out.unique_pc_count = static_cast<size_t>(read_u64());
    uint64_t n_entries  = read_u64();

    out.pc_to_inst_ids.reserve(n_entries);
    out.pc_exec_count.reserve(n_entries);

    for (uint64_t i = 0; i < n_entries; i++) {
        if (p + 8 + 8 + 8 > end) return false;
        uint64_t pc         = read_u64();
        uint64_t exec_count = read_u64();
        uint64_t bm_bytes   = read_u64();
        if (p + bm_bytes > end) return false;

        roaring::Roaring64Map bm = roaring::Roaring64Map::readSafe(p, bm_bytes);
        p += bm_bytes;

        out.pc_to_inst_ids.emplace(pc, std::move(bm));
        out.pc_exec_count.emplace(pc, exec_count);
    }

    return true;
}

}  // anonymous namespace (serialization helpers)

// ─── XrefPass::run ───────────────────────────────────────────────────────────

PassResult XrefPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    const auto& range = ctx.range();

    // ─── Fast path: load from persisted cache ─────────────────────────────
    // Only cache the full-trace result (range.is_full_trace()) because partial
    // ranges are rarely re-run and are cheap (proportionally smaller scan).
    if (range.is_full_trace()) {
        std::string blob;
        if (index.load_pass_blob("xref", blob)) {
            XrefResult cached;
            if (xref_deserialize(blob, cached)) {
                ctx.progress(1.0f, fmt::format(
                    "Xref: {} unique PCs, {} instructions (from cache)",
                    cached.unique_pc_count, cached.total_indexed));
                return PassResult::success(std::move(cached));
            }
            // Blob corrupt / version mismatch — fall through to recompute
        }
    }

    uint64_t total_insts = index.inst_count();
    uint64_t start = range.start_inst_id;
    uint64_t end = std::min(range.end_inst_id, total_insts);
    if (end == 0) end = total_insts;

    const uint32_t num_gpr = reader.header().num_gpr;
    const uint64_t file_size = reader.file_size();

    // ─── Phase 0: Determine sharding strategy ─────────────────────────────

    unsigned n_workers = worker_count();

    // For small traces (<50K instructions), single-threaded is faster (no thread overhead)
    if (total_insts < 50000) {
        n_workers = 1;
    }

    // Build shard boundaries using the sparse offset index.
    // Each shard gets a contiguous range of inst_ids.
    uint64_t insts_per_shard = (end - start + n_workers - 1) / n_workers;

    std::vector<Shard> shards;
    shards.reserve(n_workers);

    for (unsigned i = 0; i < n_workers; i++) {
        uint64_t shard_start_id = start + i * insts_per_shard;
        uint64_t shard_end_id = std::min(shard_start_id + insts_per_shard, end);
        if (shard_start_id >= end) break;

        // Resolve file offsets from the sparse index
        uint64_t start_offset = index.offset_of(shard_start_id, reader);
        uint64_t end_offset;
        if (shard_end_id >= end) {
            end_offset = file_size;
        } else {
            end_offset = index.offset_of(shard_end_id, reader);
        }

        // Sanity check
        if (start_offset >= file_size) start_offset = file_size;
        if (end_offset > file_size) end_offset = file_size;
        if (start_offset >= end_offset) continue;

        Shard s;
        s.file_start = start_offset;
        s.file_end = end_offset;
        s.start_inst_id = shard_start_id;
        s.end_inst_id = shard_end_id;
        shards.push_back(s);
    }

    if (shards.empty()) {
        return PassResult::success(XrefResult{});
    }

    // ─── Phase 1: Parallel scan ───────────────────────────────────────────

    // Prefetch entire file for sequential reads
    reader.advise_sequential();

    std::vector<ShardResult> shard_results(shards.size());
    std::vector<std::thread> threads;
    threads.reserve(shards.size() - 1);

    // Launch worker threads for shards[1..N-1], run shard[0] on current thread
    // Determine trace format flags for the shard scanner
    const bool xref_is_v5 = (reader.header().flags & qbditrace::QBDITRACE_HF_PC_DELTA)  != 0;
    const bool xref_is_v6 = (reader.header().flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0;

    // Pin all blocks during the parallel scan to prevent LRU eviction.
    reader.pin_all();

    for (size_t i = 1; i < shards.size(); i++) {
        threads.emplace_back([&shards, &shard_results, num_gpr, xref_is_v5, xref_is_v6, &reader, i]() {
            scan_shard(shards[i], num_gpr, xref_is_v5, xref_is_v6, shard_results[i], reader);
        });
    }

    // Shard 0 runs on this thread
    scan_shard(shards[0], num_gpr, xref_is_v5, xref_is_v6, shard_results[0], reader);

    ctx.progress(0.7f, "Xref: merging shards...");

    // Wait for all workers
    for (auto& t : threads) t.join();

    reader.unpin_all();

    if (ctx.cancelled()) {
        return PassResult::failed("cancelled");
    }

    // ─── Phase 2: Merge shard results ─────────────────────────────────────

    // Use shard[0] as the accumulator (it likely has the most data for hot PCs)
    auto& merged = shard_results[0];

    for (size_t i = 1; i < shard_results.size(); i++) {
        for (auto& [pc, bm] : shard_results[i].pc_bitmaps) {
            auto& dst = merged.pc_bitmaps[pc];
            if (dst == nullptr) {
                // Steal the bitmap (move ownership)
                dst = bm;
                bm = nullptr;
            } else {
                // OR-merge in place
                roaring64_bitmap_or_inplace(dst, bm);
                roaring64_bitmap_free(bm);
                bm = nullptr;
            }
        }
        shard_results[i].pc_bitmaps.clear();
    }

    ctx.progress(0.85f, "Xref: building result...");

    // ─── Phase 3: Convert to XrefResult (Roaring64Map wrapper) ────────────

    XrefResult result;
    result.pc_to_inst_ids.reserve(merged.pc_bitmaps.size());
    result.pc_exec_count.reserve(merged.pc_bitmaps.size());

    uint64_t total_indexed = 0;

    for (auto& [pc, bm] : merged.pc_bitmaps) {
        // Run-optimize for better compression and iteration
        roaring64_bitmap_run_optimize(bm);

        uint64_t card = roaring64_bitmap_get_cardinality(bm);
        result.pc_exec_count[pc] = card;
        total_indexed += card;

        // Move the C bitmap into a Roaring64Map by serialization roundtrip.
        // Unfortunately Roaring64Map doesn't expose a "take ownership of C bitmap"
        // API, so we use addMany with the values.
        // For large bitmaps, iterate and addMany in chunks.
        auto& dst_map = result.pc_to_inst_ids[pc];

        if (card <= 8192) {
            // Small bitmap: extract all values and addMany
            std::vector<uint64_t> vals(card);
            roaring64_bitmap_to_uint64_array(bm, vals.data());
            dst_map.addMany(card, vals.data());
        } else {
            // Large bitmap: iterate in chunks to avoid huge allocation
            constexpr size_t CHUNK = 65536;
            std::vector<uint64_t> chunk_buf(CHUNK);
            roaring64_iterator_t* iter = roaring64_iterator_create(bm);
            while (roaring64_iterator_has_value(iter)) {
                size_t n = roaring64_iterator_read(iter, chunk_buf.data(), CHUNK);
                if (n == 0) break;
                dst_map.addMany(n, chunk_buf.data());
            }
            roaring64_iterator_free(iter);
        }

        // Run-optimize the final Roaring64Map too
        dst_map.runOptimize();
    }

    // Free all C bitmaps (now consumed)
    for (auto& [_, bm] : merged.pc_bitmaps) {
        if (bm) { roaring64_bitmap_free(bm); bm = nullptr; }
    }
    merged.pc_bitmaps.clear();

    result.unique_pc_count = result.pc_to_inst_ids.size();
    result.total_indexed = total_indexed;

    // Restore madvise
    reader.advise_random();

    // ─── Persist result for future sessions ───────────────────────────────
    // Only cache full-trace results (same restriction as the load path).
    if (range.is_full_trace()) {
        std::string blob = xref_serialize(result);
        if (!blob.empty()) {
            index.save_pass_blob("xref", blob.data(), blob.size());
        }
    }

    ctx.progress(1.0f, fmt::format("Xref: {} unique PCs, {} instructions ({} threads)",
                                    result.unique_pc_count, result.total_indexed,
                                    shards.size()));
    return PassResult::success(std::move(result));
}

}  // namespace tenet
