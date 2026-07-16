#include "analysis/passes/memory/string_pass.h"
#include "analysis/trace_collector.h"
#include "infra/scan_orchestrator.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "core/memory_model.h"
#include "common/byte_codec.h"

#include <fmt/core.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <ankerl/unordered_dense.h>

namespace tenet {

// ─── Blob persistence helpers ─────────────────────────────────────────────

static constexpr uint32_t STRING_BLOB_MAGIC   = 0x53545247u;  // "STRG"
static constexpr uint32_t STRING_BLOB_VERSION = 1u;

/// Serialize StringResult into a compact binary blob.
/// Format: [magic:u32][version:u32][num_strings:u64]
///   per StringRef:
///     [addr:u64][discovered_at:u64][encoding:u8][pad:3]
///     [content_len:u32][content]
///     [num_refs:u32] per ref: [inst_id:u64][pc:u64]
/// (addr_to_index and inst_to_strings are rebuilt on deserialization)
static std::string string_serialize(const StringResult& res) {
    ByteWriter w;

    w.u32(STRING_BLOB_MAGIC);
    w.u32(STRING_BLOB_VERSION);
    w.u64(static_cast<uint64_t>(res.strings.size()));

    for (const auto& s : res.strings) {
        w.u64(s.addr);
        w.u64(s.discovered_at);
        w.u8(static_cast<uint8_t>(s.encoding));
        w.u8(0); w.u8(0); w.u8(0);  // padding
        w.str(s.content);
        w.u32(static_cast<uint32_t>(s.references.size()));
        for (const auto& ref : s.references) {
            w.u64(ref.inst_id);
            w.u64(ref.pc);
        }
    }

    return std::move(w).take();
}

/// Deserialize StringResult from a binary blob. Returns false on corruption.
/// Rebuilds addr_to_index and inst_to_strings derived indices.
static bool string_deserialize(const std::string& blob, StringResult& out) {
    ByteReader r(blob.data(), blob.size());

    uint32_t magic = r.u32();
    uint32_t version = r.u32();
    if (magic != STRING_BLOB_MAGIC || version != STRING_BLOB_VERSION) return false;

    uint64_t num_strings = r.u64();
    out.strings.resize(static_cast<size_t>(num_strings));

    for (size_t i = 0; i < num_strings; i++) {
        auto& s = out.strings[i];
        s.addr          = r.u64();
        s.discovered_at = r.u64();
        s.encoding      = static_cast<StringRef::Encoding>(r.u8());
        r.u8(); r.u8(); r.u8();  // skip padding
        if (!r.str(s.content)) return false;

        uint32_t num_refs = r.u32();
        s.references.resize(num_refs);
        for (uint32_t j = 0; j < num_refs; j++) {
            s.references[j].inst_id = r.u64();
            s.references[j].pc      = r.u64();
        }

        // Rebuild addr_to_index — last-written entry for a given address wins,
        // matching StringPass::run()'s "most recent content at this address"
        // semantics (see the incremental construction in run()).
        out.addr_to_index[s.addr] = i;
        // Rebuild inst_to_strings
        for (const auto& ref : s.references) {
            out.inst_to_strings[ref.inst_id].push_back(i);
        }
    }

    return r.ok();
}

// ─── Helpers ──────────────────────────────────────────────────────────────

static bool is_printable(uint8_t c) {
    return (c >= 0x20 && c <= 0x7E) || c == '\t' || c == '\n' || c == '\r';
}

/// Case-insensitive substring search.
static bool ci_contains(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) return true;
    if (haystack.size() < needle.size()) return false;

    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        });
    return it != haystack.end();
}

// ─── StringResult::search ────────────────────────────────────────────────

std::vector<const StringRef*> StringResult::search(const std::string& pattern) const {
    std::vector<const StringRef*> hits;
    for (const auto& s : strings) {
        if (ci_contains(s.content, pattern)) {
            hits.push_back(&s);
        }
    }
    return hits;
}

// ─── Local string scan over a reconstructed byte window ────────────────────

namespace {

struct WindowHit {
    size_t offset;       // offset within the scanned window
    std::string content;
    StringRef::Encoding encoding;
};

/// Scan a reconstructed memory window for printable ASCII and UTF-16LE runs.
/// Mirrors MemoryStringPass::scan_for_strings but returns StringRef::Encoding.
std::vector<WindowHit> scan_window(const std::vector<uint8_t>& data,
                                    const std::vector<bool>& known,
                                    size_t min_len, size_t max_len) {
    std::vector<WindowHit> hits;
    const size_t size = data.size();

    // ─── ASCII scan ────────────────────────────────────────────────────
    size_t i = 0;
    while (i < size) {
        if (!known[i] || !is_printable(data[i])) {
            i++;
            continue;
        }
        size_t start = i;
        while (i < size && known[i] && is_printable(data[i])) i++;

        size_t len = i - start;
        if (len >= min_len) {
            WindowHit hit;
            hit.offset = start;
            hit.content.assign(reinterpret_cast<const char*>(data.data() + start),
                                std::min(len, max_len));
            hit.encoding = StringRef::ASCII;
            hits.push_back(std::move(hit));
        }
    }

    // ─── UTF-16LE scan ──────────────────────────────────────────────────
    // Sequences of [printable_byte, 0x00] pairs. No overlap with the ASCII
    // scan above since ASCII runs stop at the first 0x00 byte.
    i = 0;
    while (i + 1 < size) {
        if (!known[i] || !known[i + 1] || data[i + 1] != 0x00 || !is_printable(data[i])) {
            i++;
            continue;
        }
        size_t start = i;
        std::string content;
        while (i + 1 < size && known[i] && known[i + 1] &&
               data[i + 1] == 0x00 && is_printable(data[i]) &&
               content.size() < max_len) {
            content.push_back(static_cast<char>(data[i]));
            i += 2;
        }

        if (content.size() >= min_len) {
            WindowHit hit;
            hit.offset = start;
            hit.content = std::move(content);
            hit.encoding = StringRef::UTF16LE;
            hits.push_back(std::move(hit));
        } else {
            i = start + 1;
        }
    }

    return hits;
}

}  // namespace

// ─── StringPass::declare_scan ─────────────────────────────────────────────

void StringPass::declare_scan(ScanOrchestrator& orch, PassContext& ctx) {
    auto& index = ctx.index();
    uint64_t start = ctx.range().start_inst_id;
    uint64_t end = std::min(ctx.range().end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    collector_ = std::make_unique<WriteEventCollector>(start, end);
    orch.declare({name(), collector_.get(), /*wants_parallel=*/true});
}

// ─── StringPass::run ─────────────────────────────────────────────────────

std::optional<PassResult> StringPass::try_load_cached(PassContext& ctx) {
    if (!ctx.range().is_full_trace()) return std::nullopt;

    std::string blob;
    if (!ctx.index().load_pass_blob("strings", blob)) return std::nullopt;

    StringResult cached;
    if (!string_deserialize(blob, cached)) return std::nullopt;

    collector_.reset();
    ctx.progress(1.0f, fmt::format(
        "Strings: {} discovered (from cache)", cached.total()));
    return PassResult::success(std::move(cached));
}

PassResult StringPass::run(PassContext& ctx) {
    auto& index  = ctx.index();
    auto& memory = ctx.memory();
    const auto& range = ctx.range();

    // collector_ was populated by declare_scan() + ScanOrchestrator::execute_scan()
    if (!collector_) {
        return PassResult::failed("declare_scan() was not called before run()");
    }

    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }

    auto events = collector_->take_events();
    ctx.progress(0.4f, fmt::format("Collected {} memory write events", events.size()));

    // ─── Phase 2: for each write, reconstruct a time-consistent window ────
    // via MemoryModel and scan it for strings. Using MemoryModel guarantees
    // every byte considered together for one string was observed at the
    // exact same instant — unlike a flat "last value per address" byte
    // cache, this cannot stitch bytes from different points in time into a
    // bogus string.
    StringResult result;

    // Tracks write-addr -> last written 64-bit value at that address, so
    // that a run of consecutive writes carrying the *same* bytes to the
    // *same* address (spinlocks, refcounts, hot counters) only pays for one
    // read_region + scan instead of re-probing on every single write.
    // Only used for writes of size <= 8 (value_hi covers 9-16 byte stores,
    // which are rare for string-bearing data and not worth the extra key
    // width).
    ankerl::unordered_dense::map<uint64_t, uint64_t> last_write_value;

    // Tracks write-addr -> the strings[] index that the most recent probe at
    // this write address resolved to (SIZE_MAX if the probe touched no
    // string). NOTE: this is keyed by the *write* address (ev.addr), which
    // may differ from the string's own start address (str_addr) when the
    // string begins a few bytes before the write — addr_to_index alone can't
    // be reused here for that reason.
    ankerl::unordered_dense::map<uint64_t, size_t> last_write_hit;

    const size_t half_window = StringPass::PROBE_WINDOW / 2;

    size_t processed = 0;
    for (const auto& ev : events) {
        if (ctx.cancelled()) return PassResult::failed("cancelled by user");

        processed++;
        if ((processed & 0x3FF) == 0) {
            float pct = 0.4f + 0.6f * static_cast<float>(processed) /
                        static_cast<float>(events.size());
            ctx.progress(pct, "Scanning memory writes for strings...");
        }

        // Skip the expensive read_region()+scan when this write repeats the
        // exact same value already probed at this address (e.g. spinlocks,
        // refcounts, hot counters written in a loop): the reconstructed
        // window would be byte-identical to the previous probe, so it would
        // always re-discover the exact same string(s). We still want that
        // string's `references` to reflect this instruction though, so if
        // the previous probe at this write address resolved to a live
        // string entry, append a reference for it directly without
        // re-touching MemoryModel.
        if (ev.size > 0 && ev.size <= 8) {
            auto val_it = last_write_value.find(ev.addr);
            if (val_it != last_write_value.end() && val_it->second == ev.value) {
                auto hit_it = last_write_hit.find(ev.addr);
                if (hit_it != last_write_hit.end() && hit_it->second != StringResult::NOT_STRING) {
                    result.strings[hit_it->second].references.push_back({ev.inst_id, ev.pc});
                    result.inst_to_strings[ev.inst_id].push_back(hit_it->second);
                }
                continue;
            }
            last_write_value[ev.addr] = ev.value;
        }

        // Reconstruct memory as it existed immediately AFTER this write
        // executed. MemoryModel::read_region()'s at_inst_id is exclusive
        // ("state before instruction N"), so inst_id + 1 yields the
        // post-write state.
        uint64_t at_inst_id = ev.inst_id + 1;

        // Probe a window straddling the write: the string may start before
        // the written bytes (e.g. only the terminating NUL was (re)written)
        // or extend after them.
        uint64_t window_start = (ev.addr > half_window) ? ev.addr - half_window : 0;
        size_t window_size = half_window + std::max<size_t>(ev.size, half_window);

        auto region = memory.read_region(window_start, window_size, at_inst_id);
        if (region.known_count < StringResult::MIN_STRING_LEN) {
            if (ev.size > 0 && ev.size <= 8) last_write_hit[ev.addr] = StringResult::NOT_STRING;
            continue;
        }

        auto hits = scan_window(region.data, region.known,
                                 StringResult::MIN_STRING_LEN, StringResult::MAX_STRING_LEN);
        if (hits.empty()) {
            if (ev.size > 0 && ev.size <= 8) last_write_hit[ev.addr] = StringResult::NOT_STRING;
            continue;
        }

        // Remember the first overlapping hit's resolved string index so a
        // subsequent byte-identical write to the same address can shortcut
        // straight to appending a reference (see last_write_hit above).
        bool recorded_hit_for_dedup = false;

        for (auto& hit : hits) {
            uint64_t str_addr = window_start + hit.offset;

            // Only record strings that overlap the byte range actually
            // touched by this write — otherwise the same unrelated
            // neighboring string would be re-discovered (and re-referenced)
            // on every unrelated write within PROBE_WINDOW bytes of it.
            uint64_t hit_end = str_addr + hit.content.size() *
                                (hit.encoding == StringRef::UTF16LE ? 2 : 1);
            uint64_t write_end = ev.addr + ev.size;
            bool overlaps = str_addr < write_end && hit_end > ev.addr;
            if (!overlaps) continue;

            auto existing = result.addr_to_index.find(str_addr);
            size_t resolved_idx;
            if (existing != result.addr_to_index.end() &&
                existing->second != StringResult::NOT_STRING &&
                result.strings[existing->second].content == hit.content &&
                result.strings[existing->second].encoding == hit.encoding) {
                // Same content already recorded at this address — just add a
                // reference for this instruction instead of duplicating.
                resolved_idx = existing->second;
                result.strings[resolved_idx].references.push_back({ev.inst_id, ev.pc});
                result.inst_to_strings[ev.inst_id].push_back(resolved_idx);
            } else {
                // New content at this address (either first sighting, or
                // memory reuse producing a different string than before) —
                // append a fresh entry and make addr_to_index point at the
                // most recent one.
                resolved_idx = result.strings.size();
                StringRef ref;
                ref.addr          = str_addr;
                ref.discovered_at = ev.inst_id;
                ref.content       = hit.content;
                ref.encoding      = hit.encoding;
                ref.references.push_back({ev.inst_id, ev.pc});
                result.strings.push_back(std::move(ref));
                result.addr_to_index[str_addr] = resolved_idx;
                result.inst_to_strings[ev.inst_id].push_back(resolved_idx);
            }

            // Record the dedup shortcut target using the first (typically
            // only) hit that overlaps the write. If multiple distinct
            // strings overlap the same write, later byte-identical writes
            // will re-probe rather than pick an arbitrary one — favors
            // correctness over the (rare) extra RocksDB lookup.
            if (!recorded_hit_for_dedup && ev.size > 0 && ev.size <= 8) {
                last_write_hit[ev.addr] = resolved_idx;
                recorded_hit_for_dedup = true;
            }
        }

        if (!recorded_hit_for_dedup && ev.size > 0 && ev.size <= 8) {
            // No hit overlapped this write at all (hits existed but were all
            // unrelated neighboring strings) — remember that so we don't
            // treat it as "produces string X" on the next identical write.
            last_write_hit[ev.addr] = StringResult::NOT_STRING;
        }
    }

    // ─── Persist result for future sessions ───────────────────────────────
    if (range.is_full_trace()) {
        std::string blob = string_serialize(result);
        if (!blob.empty()) {
            index.save_pass_blob("strings", blob.data(), blob.size());
        }
    }

    ctx.progress(1.0f, fmt::format("Strings: {} discovered from {} write events",
                                    result.total(), events.size()));
    return PassResult::success(std::move(result));
}

}  // namespace tenet
