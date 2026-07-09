#include "analysis/passes/structure/xref_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <fmt/core.h>
#include <thread>
#include <algorithm>
#include <cstring>

#include <sys/mman.h>

#include "common/byte_codec.h"

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
//
// raw_record_size(), fprdiff_byte_offset(), and inst_header_size() are now
// shared from trace_reader.h to prevent format-parsing divergence.
// This file uses the shared ::tenet::raw_record_size directly.

namespace {

/// Extract PC from an INST record.
/// v4: qbditrace_inst_head_t layout: kind(1)+nzcv(1)+n_regdiff(1)+n_mem(1)+pad(4)+pc(8)
///     PC is at byte offset 8 (not 4!), due to alignment padding before the uint64_t field.
/// v7: qbditrace_inst_head_v7_t layout: kind(1)+nzcv(1)+n_regdiff(1)+n_mem(1)+pc(8)+n_fprdiff(1)+pad(7)
///     PC is at byte offset 4 (no padding before pc in v7).
inline uint64_t raw_inst_pc(const uint8_t* ptr, bool is_v7 = false) {
    if (is_v7) {
        const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_v7_t*>(ptr);
        return hdr->pc;
    }
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
    uint64_t seed_pc = 0;     // v5 only: absolute PC at file_start (from index)
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
/// Uses a per-thread ThreadReader to avoid mutex contention.
/// For v5 (HF_PC_DELTA) traces, shard.seed_pc seeds the running PC accumulator;
/// ANCHOR records resync it from their absolute PC field.
void scan_shard(const Shard& shard, uint32_t num_gpr,
                bool is_v5, bool is_v6, bool is_v7, ShardResult& out,
                const TraceReader::ThreadReader& thread_reader,
                const std::atomic<bool>& cancelled,
                const std::vector<std::pair<uint64_t, uint64_t>>& exclude_ranges = {}) {
    uint64_t offset = shard.file_start;
    const uint64_t end_offset = shard.file_end;
    uint64_t inst_id = shard.start_inst_id;

    // Pre-compute sizes to avoid branching in the inner loop.
    const size_t inst_hdr_sz = inst_header_size(is_v5, is_v7);
    const size_t memacc_sz = is_v6
        ? sizeof(qbditrace::qbditrace_memacc_v6_t)     // 48 bytes
        : sizeof(qbditrace::qbditrace_memacc_t);       // 32 bytes
    const size_t fprdiff_sz = is_v7
        ? sizeof(qbditrace::qbditrace_fprdiff_t)       // 24 bytes
        : 0;
    const size_t fprdiff_offset = fprdiff_byte_offset(is_v5, is_v7);

    // Per-PC bulk context cache: avoid repeated ART lookups in roaring64
    // We cache the last-used PC's bitmap + bulk context for temporal locality.
    uint64_t last_pc = UINT64_MAX;
    roaring64_bitmap_t* last_bm = nullptr;
    roaring64_bulk_context_t last_ctx = {};
    const bool has_excludes = !exclude_ranges.empty();

    // v5: running PC accumulator seeded from index (each shard starts at an anchor boundary).
    // For each INST: running_pc += pc_delta.  For each ANCHOR: running_pc = anchor.pc.
    uint64_t running_pc = shard.seed_pc;

    while (offset < end_offset) {
        // Check for cancellation every 64K instructions to allow
        // prompt shutdown without measurably impacting scan throughput.
        if ((inst_id & 0xFFFF) == 0 &&
            cancelled.load(std::memory_order_relaxed)) {
            return;
        }

        const uint8_t* ptr = thread_reader.data_at(offset);
        uint8_t kind = ptr[0];

        if (kind == 0) { // INST — the hot path (>95% of records)
            uint64_t pc;
            if (is_v5) {
                // v5: decode pc_delta (int16 at byte offset 4) and advance running_pc.
                int16_t delta;
                std::memcpy(&delta, ptr + 4, 2);
                running_pc += static_cast<int64_t>(delta);
                pc = running_pc;
            } else {
                pc = raw_inst_pc(ptr, is_v7);
            }

            // Skip excluded PC ranges
            bool excluded = false;
            if (has_excludes) {
                for (const auto& [s, e] : exclude_ranges) {
                    if (pc >= s && pc < e) { excluded = true; break; }
                }
            }

            if (!excluded) {
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
            uint8_t n_fprdiff = is_v7 ? ptr[fprdiff_offset] : 0;
            offset += inst_hdr_sz
                + n_regdiff  * sizeof(qbditrace::qbditrace_regdiff_t)
                + n_fprdiff  * fprdiff_sz
                + n_mem      * memacc_sz;
            inst_id++;
        } else {
            // For v5 traces, resync running_pc from ANCHOR records.
            if (is_v5 && kind == 1) { // ANCHOR
                const auto* a_hdr = reinterpret_cast<const qbditrace::qbditrace_anchor_head_t*>(ptr);
                running_pc = a_hdr->pc;
            }
            offset += raw_record_size(ptr, num_gpr, is_v5, is_v6, is_v7);
        }
    }
}

} // anonymous namespace

// ─── XrefBitmapLoader implementation ─────────────────────────────────────────
//
// xref_bitmaps.bin format (little-endian, UNCOMPRESSED, random-access):
//
//  Header (28 bytes):
//   u32  magic         = 0x58524249 ("XRBI")
//   u32  version       = 2
//   u64  total_indexed
//   u64  unique_pc_count   (= num_entries)
//   u64  num_entries
//
//  Offset Table (num_entries × 24 bytes, sorted by pc ASC):
//   for each entry i:
//     u64  pc
//     u64  exec_count
//     u64  bitmap_offset    (absolute byte offset in file where bitmap_bytes field starts)
//
//  Bitmap Data (variable):
//   for each entry (in same order as offset table):
//     u64  bitmap_bytes
//     u8[] bitmap_data[bitmap_bytes]   (Roaring64Map portable format)
//
// The offset table enables O(log N) lookup by PC (binary search), then a
// single fseek + fread loads exactly one bitmap.  The file is uncompressed
// so fseek into the middle works without decompressing the whole file.

static constexpr uint32_t XRBI_MAGIC   = 0x58524249u;  // "XRBI"
static constexpr uint32_t XRBI_VERSION = 2u;

// Lightweight header-only blob stored via save_pass_blob (zstd-compressed).
// Contains everything needed to reconstruct XrefResult except the bitmaps.
//
//  u32  magic         = 0x58524548 ("XREH")
//  u32  version       = 1
//  u64  total_indexed
//  u64  unique_pc_count
//  u64  num_entries
//  for each entry:
//    u64  pc
//    u64  exec_count
static constexpr uint32_t XREH_MAGIC   = 0x58524548u;  // "XREH"
static constexpr uint32_t XREH_VERSION = 1u;

// Legacy v1 blob format (used for backward compat detection).
static constexpr uint32_t XREF_BLOB_MAGIC_V1   = 0x58524546u;  // "XREF"
static constexpr uint32_t XREF_BLOB_VERSION_V1 = 1u;

// ─── XrefBitmapLoader ────────────────────────────────────────────────────────

bool XrefBitmapLoader::open(const std::filesystem::path& p) {
    path = p;
    valid = false;
    table.clear();

    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;

    // Read header
    uint32_t magic = 0, version = 0;
    uint64_t total_indexed = 0, unique_pc_count = 0, num_entries = 0;
    if (std::fread(&magic,          4, 1, f) != 1 || magic   != XRBI_MAGIC)   { std::fclose(f); return false; }
    if (std::fread(&version,        4, 1, f) != 1 || version != XRBI_VERSION)  { std::fclose(f); return false; }
    if (std::fread(&total_indexed,  8, 1, f) != 1) { std::fclose(f); return false; }
    if (std::fread(&unique_pc_count,8, 1, f) != 1) { std::fclose(f); return false; }
    if (std::fread(&num_entries,    8, 1, f) != 1) { std::fclose(f); return false; }

    // Read offset table
    table.resize(static_cast<size_t>(num_entries));
    for (uint64_t i = 0; i < num_entries; ++i) {
        if (std::fread(&table[i].pc,            8, 1, f) != 1) { std::fclose(f); table.clear(); return false; }
        if (std::fread(&table[i].exec_count,    8, 1, f) != 1) { std::fclose(f); table.clear(); return false; }
        if (std::fread(&table[i].bitmap_offset, 8, 1, f) != 1) { std::fclose(f); table.clear(); return false; }
    }
    std::fclose(f);

    // Keep file open for later bitmap reads
    valid = true;
    return true;
}

FILE* XrefBitmapLoader::ensure_open() const {
    if (!file_) {
        file_ = std::fopen(path.c_str(), "rb");
    }
    return file_;
}

std::vector<uint64_t> XrefBitmapLoader::load_inst_ids(uint64_t pc) const {
    if (!valid) return {};
    // Binary search in offset table
    auto it = std::lower_bound(table.begin(), table.end(), pc,
        [](const Entry& e, uint64_t v){ return e.pc < v; });
    if (it == table.end() || it->pc != pc) return {};

    std::lock_guard<std::mutex> lk(file_mutex_);
    FILE* f = ensure_open();
    if (!f) return {};

    // Seek to bitmap_bytes field
    if (std::fseek(f, static_cast<long>(it->bitmap_offset), SEEK_SET) != 0) return {};

    uint64_t bm_bytes = 0;
    if (std::fread(&bm_bytes, 8, 1, f) != 1 || bm_bytes == 0) return {};

    std::vector<char> buf(static_cast<size_t>(bm_bytes));
    if (std::fread(buf.data(), 1, buf.size(), f) != buf.size()) return {};

    roaring::Roaring64Map bm = roaring::Roaring64Map::readSafe(buf.data(), buf.size());
    std::vector<uint64_t> result;
    result.reserve(static_cast<size_t>(bm.cardinality()));
    for (uint64_t id : bm) result.push_back(id);
    return result;
}

roaring::Roaring64Map XrefBitmapLoader::load_bitmap(uint64_t pc) const {
    if (!valid) return {};
    auto it = std::lower_bound(table.begin(), table.end(), pc,
        [](const Entry& e, uint64_t v){ return e.pc < v; });
    if (it == table.end() || it->pc != pc) return {};

    std::lock_guard<std::mutex> lk(file_mutex_);
    FILE* f = ensure_open();
    if (!f) return {};

    if (std::fseek(f, static_cast<long>(it->bitmap_offset), SEEK_SET) != 0) return {};

    uint64_t bm_bytes = 0;
    if (std::fread(&bm_bytes, 8, 1, f) != 1 || bm_bytes == 0) return {};

    std::vector<char> buf(static_cast<size_t>(bm_bytes));
    if (std::fread(buf.data(), 1, buf.size(), f) != buf.size()) return {};

    return roaring::Roaring64Map::readSafe(buf.data(), buf.size());
}

uint64_t XrefBitmapLoader::exec_count(uint64_t pc) const {
    if (!valid) return 0;
    auto it = std::lower_bound(table.begin(), table.end(), pc,
        [](const Entry& e, uint64_t v){ return e.pc < v; });
    if (it == table.end() || it->pc != pc) return 0;
    return it->exec_count;
}

uint64_t XrefBitmapLoader::first_inst_id(uint64_t pc) const {
    if (!valid) return UINT64_MAX;
    auto it = std::lower_bound(table.begin(), table.end(), pc,
        [](const Entry& e, uint64_t v){ return e.pc < v; });
    if (it == table.end() || it->pc != pc) return UINT64_MAX;

    std::lock_guard<std::mutex> lk(file_mutex_);
    FILE* f = ensure_open();
    if (!f) return UINT64_MAX;

    if (std::fseek(f, static_cast<long>(it->bitmap_offset), SEEK_SET) != 0)
        return UINT64_MAX;

    uint64_t bm_bytes = 0;
    if (std::fread(&bm_bytes, 8, 1, f) != 1 || bm_bytes == 0)
        return UINT64_MAX;

    std::vector<char> buf(static_cast<size_t>(bm_bytes));
    if (std::fread(buf.data(), 1, buf.size(), f) != buf.size())
        return UINT64_MAX;

    roaring::Roaring64Map bm = roaring::Roaring64Map::readSafe(buf.data(), buf.size());
    if (bm.isEmpty()) return UINT64_MAX;
    return bm.minimum();
}

// ─── XrefResult::inst_ids_at / first_inst_id_at / bitmap_at ──────────────────

std::vector<uint64_t> XrefResult::inst_ids_at(uint64_t pc) const {
    // Fast path: in-memory map (partial traces or freshly computed)
    if (!pc_to_inst_ids.empty()) {
        auto it = pc_to_inst_ids.find(pc);
        if (it == pc_to_inst_ids.end()) return {};
        std::vector<uint64_t> result;
        result.reserve(static_cast<size_t>(it->second.cardinality()));
        for (auto val : it->second) result.push_back(val);
        return result;
    }
    // Lazy path: read from file
    if (lazy_loader && lazy_loader->valid) {
        return lazy_loader->load_inst_ids(pc);
    }
    return {};
}

uint64_t XrefResult::first_inst_id_at(uint64_t pc) const {
    // Fast path: in-memory map
    if (!pc_to_inst_ids.empty()) {
        auto it = pc_to_inst_ids.find(pc);
        if (it == pc_to_inst_ids.end()) return UINT64_MAX;
        if (it->second.isEmpty()) return UINT64_MAX;
        return it->second.minimum();  // O(1) on Roaring bitmap
    }
    // Lazy path: read from file
    if (lazy_loader && lazy_loader->valid) {
        return lazy_loader->first_inst_id(pc);
    }
    return UINT64_MAX;
}

roaring::Roaring64Map XrefResult::bitmap_at(uint64_t pc) const {
    if (!pc_to_inst_ids.empty()) {
        auto it = pc_to_inst_ids.find(pc);
        if (it == pc_to_inst_ids.end()) return {};
        return it->second;  // copy
    }
    if (lazy_loader && lazy_loader->valid) {
        return lazy_loader->load_bitmap(pc);
    }
    return {};
}

// ─── Serialization helpers ────────────────────────────────────────────────────

namespace {

/// Write the xref_bitmaps.bin file (random-access, uncompressed).
/// Returns the path to the written file.
bool xref_write_bitmaps_file(
    const std::filesystem::path& bitmaps_path,
    const XrefResult& res)
{
    // Sort PCs for deterministic binary-search in the offset table
    std::vector<uint64_t> sorted_pcs;
    sorted_pcs.reserve(res.pc_to_inst_ids.size());
    for (const auto& [pc, _] : res.pc_to_inst_ids) sorted_pcs.push_back(pc);
    std::sort(sorted_pcs.begin(), sorted_pcs.end());

    const uint64_t num_entries = sorted_pcs.size();

    // ── Compute offset table ──────────────────────────────────────────────
    // Header: 4+4+8+8+8 = 32 bytes
    // Offset table: num_entries * 24 bytes
    const uint64_t header_size = 32;
    const uint64_t table_size  = num_entries * 24;
    const uint64_t data_start  = header_size + table_size;

    // First pass: compute bitmap sizes to fill offset table
    struct TableEntry { uint64_t pc; uint64_t exec_count; uint64_t bitmap_offset; };
    std::vector<TableEntry> table(num_entries);
    uint64_t cur_offset = data_start;
    for (uint64_t i = 0; i < num_entries; ++i) {
        const uint64_t pc = sorted_pcs[i];
        const auto& bm = res.pc_to_inst_ids.at(pc);
        auto exec_it = res.pc_exec_count.find(pc);
        table[i].pc            = pc;
        table[i].exec_count    = (exec_it != res.pc_exec_count.end()) ? exec_it->second : 0;
        table[i].bitmap_offset = cur_offset;
        cur_offset += 8 + bm.getSizeInBytes(true);  // u64 bm_bytes + data
    }

    // Write file
    auto tmp_path = bitmaps_path;
    tmp_path += ".tmp";
    FILE* f = std::fopen(tmp_path.c_str(), "wb");
    if (!f) return false;

    auto write_u32 = [&](uint32_t v) { std::fwrite(&v, 4, 1, f); };
    auto write_u64 = [&](uint64_t v) { std::fwrite(&v, 8, 1, f); };

    // Header
    write_u32(XRBI_MAGIC);
    write_u32(XRBI_VERSION);
    write_u64(res.total_indexed);
    write_u64(static_cast<uint64_t>(res.unique_pc_count));
    write_u64(num_entries);

    // Offset table
    for (const auto& e : table) {
        write_u64(e.pc);
        write_u64(e.exec_count);
        write_u64(e.bitmap_offset);
    }

    // Bitmap data
    for (uint64_t i = 0; i < num_entries; ++i) {
        const auto& bm = res.pc_to_inst_ids.at(sorted_pcs[i]);
        uint64_t bm_bytes = bm.getSizeInBytes(true);
        write_u64(bm_bytes);
        // Write bitmap data via a temporary buffer
        std::vector<char> bmbuf(static_cast<size_t>(bm_bytes));
        bm.write(bmbuf.data(), true);
        std::fwrite(bmbuf.data(), 1, bmbuf.size(), f);
    }

    std::fflush(f);
    int ferr = std::ferror(f);
    std::fclose(f);
    if (ferr) {
        std::filesystem::remove(tmp_path);
        return false;
    }

    std::error_code ec;
    std::filesystem::rename(tmp_path, bitmaps_path, ec);
    if (ec) {
        std::filesystem::remove(tmp_path, ec);
        return false;
    }
    return true;
}

/// Serialize the lightweight header (exec_count only, no bitmaps) into a buffer
/// for storage via save_pass_blob (zstd-compressed).
std::string xref_serialize_header(const XrefResult& res) {
    const uint64_t n = res.pc_exec_count.size();
    ByteWriter w;

    w.u32(XREH_MAGIC);
    w.u32(XREH_VERSION);
    w.u64(res.total_indexed);
    w.u64(static_cast<uint64_t>(res.unique_pc_count));
    w.u64(n);

    // Sort PCs for deterministic iteration
    std::vector<uint64_t> sorted_pcs;
    sorted_pcs.reserve(n);
    for (const auto& [pc, _] : res.pc_exec_count) sorted_pcs.push_back(pc);
    std::sort(sorted_pcs.begin(), sorted_pcs.end());

    for (uint64_t pc : sorted_pcs) {
        auto it = res.pc_exec_count.find(pc);
        w.u64(pc);
        w.u64(it != res.pc_exec_count.end() ? it->second : 0);
    }
    return std::move(w).take();
}

/// Deserialize the lightweight header blob back into an XrefResult
/// (only populates pc_exec_count / unique_pc_count / total_indexed).
bool xref_deserialize_header(const std::string& blob, XrefResult& out) {
    ByteReader r(blob.data(), blob.size());

    uint32_t magic   = r.u32();
    uint32_t version = r.u32();

    // Accept both the new XREH format and the legacy XREF v1 format so that
    // old cache blobs still trigger a graceful fallback to the v1 path.
    if (magic == XREF_BLOB_MAGIC_V1 && version == XREF_BLOB_VERSION_V1) {
        // Legacy v1 blob — caller should fall back to full v1 deserialisation.
        return false;
    }
    if (magic != XREH_MAGIC || version != XREH_VERSION) return false;

    out.total_indexed   = r.u64();
    out.unique_pc_count = static_cast<size_t>(r.u64());
    uint64_t n_entries  = r.u64();

    if (!r.ok() || r.remaining() < n_entries * 16) return false;

    out.pc_exec_count.reserve(static_cast<size_t>(n_entries));
    for (uint64_t i = 0; i < n_entries; ++i) {
        uint64_t pc         = r.u64();
        uint64_t exec_count = r.u64();
        out.pc_exec_count.emplace(pc, exec_count);
    }
    return r.ok();
}

/// Legacy v1 full deserialisation (in-memory bitmaps).  Used as fallback
/// when the xref_bitmaps.bin file is missing (e.g. first run after upgrade).
bool xref_deserialize_v1(const std::string& blob, XrefResult& out) {
    if (blob.size() < 4 + 4 + 8 + 8 + 8) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_u64 = [&]() -> uint64_t { uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; };

    if (read_u32() != XREF_BLOB_MAGIC_V1)   return false;
    if (read_u32() != XREF_BLOB_VERSION_V1) return false;

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
    // We maintain two cache files:
    //  1. "xref" blob (zstd-compressed): lightweight header — pc_exec_count only.
    //  2. "xref_bitmaps" file (uncompressed): offset table + bitmap data for
    //     random-access lazy loading.  This file may be large but is only
    //     accessed on demand (inst_ids_at calls), never loaded fully into RAM.
    if (range.is_full_trace()) {
        std::string header_blob;
        if (index.load_pass_blob("xref", header_blob)) {
            XrefResult cached;
            bool header_ok = xref_deserialize_header(header_blob, cached);

            // Try to attach the lazy loader (xref_bitmaps.bin).
            // If xref_bitmaps.bin exists, we go fully lazy (no in-memory bitmaps).
            // If not, we fall back to v1 full deserialisation.
            if (header_ok) {
                // Load the bitmaps file path from the "xref_bitmaps_path" blob,
                // which was stored as a tiny string by a previous run.
                std::string path_blob;
                if (index.load_pass_blob("xref_bitmaps_path", path_blob) && !path_blob.empty()) {
                    std::filesystem::path bm_path(path_blob);
                    auto loader = std::make_shared<XrefBitmapLoader>();
                    if (loader->open(bm_path)) {
                        cached.lazy_loader = std::move(loader);
                        // pc_to_inst_ids stays empty — all bitmap access goes through loader
                        ctx.progress(1.0f, fmt::format(
                            "Xref: {} unique PCs, {} instructions (from cache, lazy)",
                            cached.unique_pc_count, cached.total_indexed));
                        return PassResult::success(std::move(cached));
                    }
                }
                // bitmaps file missing or corrupt — fall through to recompute
            }

            // Legacy v1 full blob fallback (old cache from before this change).
            if (xref_deserialize_v1(header_blob, cached)) {
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

    // For v5 (HF_PC_DELTA) traces, we need the absolute PC at each shard boundary
    // so scan_shard can reconstruct PCs from pc_delta fields.
    // Use offset_of_with_pc() which already implements this via the anchor table.
    const bool build_is_v5 = (reader.header().flags & qbditrace::QBDITRACE_HF_PC_DELTA) != 0;

    for (unsigned i = 0; i < n_workers; i++) {
        uint64_t shard_start_id = start + i * insts_per_shard;
        uint64_t shard_end_id = std::min(shard_start_id + insts_per_shard, end);
        if (shard_start_id >= end) break;

        // Resolve file offsets from the sparse index.
        // For v5 traces, also capture the seed_pc at the shard boundary.
        auto [start_offset, seed_pc] = index.offset_of_with_pc(shard_start_id, reader);
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

        // For v5: seed_pc from offset_of_with_pc() is the PC *after* applying the
        // first instruction's pc_delta.  scan_shard applies the delta itself, so we
        // need to pass the pre-delta value (running_pc before the first delta).
        // Read the first record's pc_delta and subtract it to get pre-delta running_pc.
        if (build_is_v5 && start_offset < file_size) {
            const uint8_t* first_ptr = reader.data_at(start_offset);
            if (first_ptr[0] == 0) { // INST record
                int16_t first_delta;
                std::memcpy(&first_delta, first_ptr + 4, 2);
                s.seed_pc = seed_pc - static_cast<int64_t>(first_delta);
            } else {
                s.seed_pc = seed_pc;  // anchor or other: seed_pc is pre-delta already
            }
        } else {
            s.seed_pc = 0;  // v4: not used
        }
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
    const bool xref_is_v7 = (reader.header().flags & qbditrace::QBDITRACE_HF_HAS_FPR)    != 0;

    // Create per-shard ThreadReaders to eliminate mutex contention.
    std::vector<TraceReader::ThreadReader> thread_readers;
    thread_readers.reserve(shards.size());
    for (size_t i = 0; i < shards.size(); i++) {
        thread_readers.push_back(reader.create_thread_reader(8));
    }

    // Get cancellation flag reference for shard threads.
    const std::atomic<bool>& cancel_flag = ctx.global_cancel_flag();
    const auto& excludes = range.exclude_pc_ranges;

    for (size_t i = 1; i < shards.size(); i++) {
        threads.emplace_back([&shards, &shard_results, &thread_readers, &cancel_flag, &excludes, num_gpr, xref_is_v5, xref_is_v6, xref_is_v7, i]() {
            scan_shard(shards[i], num_gpr, xref_is_v5, xref_is_v6, xref_is_v7, shard_results[i], thread_readers[i], cancel_flag, excludes);
        });
    }

    // Shard 0 runs on this thread
    scan_shard(shards[0], num_gpr, xref_is_v5, xref_is_v6, xref_is_v7, shard_results[0], thread_readers[0], cancel_flag, excludes);

    ctx.progress(0.7f, "Xref: merging shards...");

    // Wait for all workers
    for (auto& t : threads) t.join();

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

    // ─── Phase 3: Convert to XrefResult ──────────────────────────────────
    // Build pc_exec_count + pc_to_inst_ids (needed for serialization).
    // For full-trace runs we will immediately serialize to disk then drop the
    // in-memory bitmaps from the returned result to save RAM.

    XrefResult result;
    result.pc_exec_count.reserve(merged.pc_bitmaps.size());

    // We also need pc_to_inst_ids populated for xref_write_bitmaps_file.
    // Use a temporary Roaring64Map wrapper per PC.
    result.pc_to_inst_ids.reserve(merged.pc_bitmaps.size());

    uint64_t total_indexed = 0;

    for (auto& [pc, bm] : merged.pc_bitmaps) {
        roaring64_bitmap_run_optimize(bm);
        uint64_t card = roaring64_bitmap_get_cardinality(bm);
        result.pc_exec_count[pc] = card;
        total_indexed += card;

        // Build Roaring64Map wrapper from the C bitmap.
        auto& dst_map = result.pc_to_inst_ids[pc];
        if (card <= 8192) {
            std::vector<uint64_t> vals(card);
            roaring64_bitmap_to_uint64_array(bm, vals.data());
            dst_map.addMany(card, vals.data());
        } else {
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

    // ─── Persist result for future sessions & switch to lazy mode ─────────
    // For full-trace results:
    //  1. Write xref_bitmaps.bin (uncompressed, random-access)
    //  2. Write xref blob (lightweight header — exec_count only, zstd)
    //  3. Drop pc_to_inst_ids from the returned result; attach lazy_loader instead.
    //
    // This means after construction the returned XrefResult uses ~32 MB (exec_count
    // map only) instead of several GB for a 1.3B-instruction trace.
    if (range.is_full_trace()) {
        ctx.progress(0.95f, "Xref: writing bitmap index to disk...");

        // ── Determine path for xref_bitmaps.bin ────────────────────────────
        // We piggyback on save_pass_blob to find the pass_cache directory:
        // write a tiny sentinel to get the directory, then construct the path.
        // Simpler: write the absolute path of xref_bitmaps.bin into a tiny blob.

        // Write the lightweight header blob (pc_exec_count)
        std::string header_blob = xref_serialize_header(result);
        index.save_pass_blob("xref", header_blob.data(), header_blob.size());

        // Derive the bitmaps file path via the newly-added pass_blob_file_path()
        // helper, which returns <db_path>/pass_cache/xref_bitmaps.bin.
        std::filesystem::path bm_path = index.pass_blob_file_path("xref_bitmaps");
        if (!bm_path.empty()) {
            if (xref_write_bitmaps_file(bm_path, result)) {
                // Store the path so the loader can find it after restart.
                std::string path_str = bm_path.string();
                index.save_pass_blob("xref_bitmaps_path",
                                     path_str.data(), path_str.size());

                // Attach lazy loader and drop in-memory bitmaps.
                auto loader = std::make_shared<XrefBitmapLoader>();
                if (loader->open(bm_path)) {
                    result.lazy_loader = std::move(loader);
                    // Clear the in-memory bitmap map — all future access goes
                    // through lazy_loader.  This is the memory-saving step.
                    { decltype(result.pc_to_inst_ids) empty; empty.swap(result.pc_to_inst_ids); }
                }
            } else {
                // Failed to write bitmaps file — keep in-memory bitmaps.
                // pc_to_inst_ids remains populated (fallback to full RAM).
            }
        }
    }

    ctx.progress(1.0f, fmt::format("Xref: {} unique PCs, {} instructions ({} threads)",
                                    result.unique_pc_count, result.total_indexed,
                                    shards.size()));
    return PassResult::success(std::move(result));
}

}  // namespace tenet
