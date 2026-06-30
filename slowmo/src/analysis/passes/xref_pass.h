#pragma once

#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
#include <cstdint>
#include <vector>
#include <algorithm>
#include <roaring64map.hh>
#include <roaring/roaring64.h>
#include <ankerl/unordered_dense.h>

#include <filesystem>
#include <memory>
#include <mutex>
#include <cstdio>

namespace tenet {

// ─── Xref lazy bitmap loader ──────────────────────────────────────────────
//
// xref_bitmaps.bin format (little-endian, uncompressed):
//   u32  magic         = 0x58524249 ("XRBI")
//   u32  version       = 2
//   u64  num_entries
//   -- Offset Table (num_entries entries, fixed 24 bytes each) --
//   for each entry:
//     u64  pc
//     u64  exec_count
//     u64  bitmap_offset   (byte offset from start-of-file to bitmap_bytes field)
//   -- Bitmap Data --
//   for each entry (in same order as offset table):
//     u64  bitmap_bytes
//     u8[] bitmap_data[bitmap_bytes]
//
// The offset table enables O(1) lookup: binary-search by PC, then fseek to
// bitmap_offset and read exactly that bitmap.  No decompression needed.
// The file is written once at analysis time; subsequent runs load from it.

struct XrefBitmapLoader {
    // Offset table entry (24 bytes, packed)
    struct Entry {
        uint64_t pc;
        uint64_t exec_count;
        uint64_t bitmap_offset;  // byte offset of the u64 bitmap_bytes field
    };

    std::filesystem::path  path;          // xref_bitmaps.bin path
    std::vector<Entry>     table;         // loaded offset table, sorted by pc
    bool                   valid = false; // true if file exists and table loaded

    /// Try to open and parse the offset table from the file.
    /// Does NOT load any bitmap data — just the header + table.
    bool open(const std::filesystem::path& p);

    /// Load the bitmap for the given PC. Returns empty vector on miss.
    /// Thread-safe: serialises file reads through an internal mutex.
    std::vector<uint64_t> load_inst_ids(uint64_t pc) const;

    /// Same as load_inst_ids but loads into a Roaring64Map.
    roaring::Roaring64Map load_bitmap(uint64_t pc) const;

    /// Return the minimum inst_id for the given PC (O(1) on Roaring bitmap).
    /// Returns UINT64_MAX on miss.
    uint64_t first_inst_id(uint64_t pc) const;

    /// Find the exec_count for a given PC from the table (no file I/O).
    uint64_t exec_count(uint64_t pc) const;

private:
    mutable std::mutex file_mutex_;
    mutable FILE*      file_ = nullptr;   // kept open for reuse; guarded by file_mutex_

    FILE* ensure_open() const;
};

// ─── Xref pass result ─────────────────────────────────────────────────────

/// PC → compressed bitmap of inst_ids that executed at that PC.
///
/// Memory layout:
///   - pc_exec_count: always in RAM (~32 MB for large traces)
///   - pc_to_inst_ids: EMPTY in normal operation; populated only for small/partial traces
///     or during pass construction (immediately cleared after serialisation)
///   - lazy_loader: if non-null, inst_ids_at() reads from xref_bitmaps.bin on demand
struct XrefResult {
    /// Forward index: PC → compressed bitmap.
    /// ONLY populated for partial traces (range != full trace) or for in-memory
    /// passes that haven't been persisted yet.
    /// For full-trace results loaded from cache, this map is EMPTY; use
    /// inst_ids_at() which calls through lazy_loader instead.
    ankerl::unordered_dense::map<uint64_t, roaring::Roaring64Map> pc_to_inst_ids;

    /// Fast execution count per PC (avoids calling cardinality() on bitmap).
    ankerl::unordered_dense::map<uint64_t, uint64_t> pc_exec_count;

    /// Total unique PCs in the trace.
    size_t unique_pc_count = 0;

    /// Total inst_ids indexed.
    uint64_t total_indexed = 0;

    /// Lazy loader for full-trace results (non-null = use file-backed storage).
    std::shared_ptr<XrefBitmapLoader> lazy_loader;

    /// How many times was this PC executed?
    uint64_t execution_count(uint64_t pc) const {
        auto it = pc_exec_count.find(pc);
        if (it == pc_exec_count.end()) return 0;
        return it->second;
    }

    /// Check if a PC was ever executed.
    bool has_pc(uint64_t pc) const {
        return pc_exec_count.find(pc) != pc_exec_count.end();
    }

    /// Get the N hottest PCs (most executed).
    std::vector<std::pair<uint64_t, uint64_t>> hottest(size_t n) const {
        std::vector<std::pair<uint64_t, uint64_t>> entries;
        entries.reserve(pc_exec_count.size());
        for (const auto& [pc, count] : pc_exec_count) {
            entries.emplace_back(pc, count);
        }
        std::partial_sort(entries.begin(),
                          entries.begin() + std::min(n, entries.size()),
                          entries.end(),
                          [](const auto& a, const auto& b) { return a.second > b.second; });
        if (entries.size() > n) entries.resize(n);
        return entries;
    }

    /// Get all inst_ids at a given PC.
    ///
    /// For full-trace results (lazy_loader != null):
    ///   reads from the xref_bitmaps.bin file (a few ms per call, cached).
    ///
    /// For small/partial traces (pc_to_inst_ids populated):
    ///   returns data directly from the in-memory map.
    ///
    /// Returns empty vector if PC not found in either store.
    std::vector<uint64_t> inst_ids_at(uint64_t pc) const;

    /// Return the first (minimum) inst_id at a given PC.
    /// O(1) for in-memory bitmaps, O(bitmap_bytes) for lazy-loaded but avoids
    /// expanding the full bitmap into a vector.
    /// Returns UINT64_MAX if PC not found.
    uint64_t first_inst_id_at(uint64_t pc) const;

    /// Load the full bitmap for a PC (same backing store as inst_ids_at).
    roaring::Roaring64Map bitmap_at(uint64_t pc) const;

    /// Returns true if the bitmap for this PC is available (in-memory or on disk).
    bool has_bitmap(uint64_t pc) const {
        if (!pc_to_inst_ids.empty()) return pc_to_inst_ids.count(pc) > 0;
        if (lazy_loader && lazy_loader->valid) {
            // Check offset table (no I/O)
            const auto& tbl = lazy_loader->table;
            auto it = std::lower_bound(tbl.begin(), tbl.end(), pc,
                [](const XrefBitmapLoader::Entry& e, uint64_t v){ return e.pc < v; });
            return it != tbl.end() && it->pc == pc;
        }
        return false;
    }
};

// ─── Xref collector (single-pass scan) ────────────────────────────────────

/// Collector that builds the xref index during a single-pass scan.
class XrefCollector final : public TraceCollector {
public:
    std::string_view name() const override { return "xref_collector"; }

    bool begin(uint64_t start, uint64_t end) override {
        (void)start; (void)end;
        return true;
    }

    void on_inst(uint64_t inst_id, const InstView& inst) override {
        result.pc_to_inst_ids[inst.pc].add(inst_id);
        result.pc_exec_count[inst.pc]++;
        result.total_indexed++;
    }

    void end() override {
        result.unique_pc_count = result.pc_exec_count.size();
    }

    // ─── Parallel scanning support ───────────────────────────────────────
    bool supports_parallel() const override { return true; }

    std::unique_ptr<TraceCollector> clone() const override {
        return std::make_unique<XrefCollector>();
    }

    void merge(TraceCollector& shard) override {
        auto& other = static_cast<XrefCollector&>(shard);
        for (auto& [pc, bitmap] : other.result.pc_to_inst_ids) {
            result.pc_to_inst_ids[pc] |= bitmap;
        }
        for (const auto& [pc, count] : other.result.pc_exec_count) {
            result.pc_exec_count[pc] += count;
        }
        result.total_indexed += other.result.total_indexed;
    }

    XrefResult result;
};

// ─── Xref pass ────────────────────────────────────────────────────────────

/// Builds a PC → inst_id cross-reference index using Roaring64Map bitmaps.
/// Result type: XrefResult
class XrefPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "xref"; }
    std::string_view description() const override {
        return "Build PC cross-reference index (PC -> inst_id bitmap)";
    }

    std::vector<std::string_view> dependencies() const override {
        return {};  // No dependencies
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 6.0f; }
};

}  // namespace tenet
