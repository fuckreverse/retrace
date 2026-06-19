#include "analysis/passes/string_pass.h"
#include "core/memory_model.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <fmt/core.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

namespace tenet {

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

// ─── Byte cache: collects memory content from both reads and writes ──────

/// A simple page-indexed byte cache that records bytes seen in trace memory events.
/// This allows probing string content that was only *read* (from read-only segments)
/// and never written during the trace, which the MemoryModel cannot provide.
class ReadByteCache {
public:
    /// Record bytes from a memory access event (read or write).
    void record(uint64_t addr, uint16_t size, uint64_t value, uint64_t value_hi) {
        uint8_t buf[16];
        std::memcpy(buf, &value, 8);
        std::memcpy(buf + 8, &value_hi, 8);
        uint16_t actual_size = std::min<uint16_t>(size, 16);
        for (uint16_t i = 0; i < actual_size; ++i) {
            bytes_[addr + i] = buf[i];
        }
    }

    /// Get a byte at the given address, or nullopt if never seen.
    std::optional<uint8_t> get(uint64_t addr) const {
        auto it = bytes_.find(addr);
        if (it != bytes_.end()) return it->second;
        return std::nullopt;
    }

    /// Direct access to underlying map (for iteration/sorting).
    const std::unordered_map<uint64_t, uint8_t>& raw_map() const { return bytes_; }

    size_t size() const { return bytes_.size(); }

private:
    std::unordered_map<uint64_t, uint8_t> bytes_;
};

/// Fast byte access that returns 0xFF for unknown bytes (used in linear scan).
static uint8_t cache_get_fast(const ReadByteCache& cache, uint64_t addr) {
    auto val = cache.get(addr);
    return val.has_value() ? *val : 0xFF;
}

/// Try to read a contiguous printable ASCII string from the byte cache.
static std::optional<std::string> probe_ascii_from_cache(
    const ReadByteCache& cache, uint64_t addr)
{
    std::string result;
    result.reserve(StringResult::MIN_STRING_LEN + 16);

    for (size_t i = 0; i < StringResult::MAX_STRING_LEN; ++i) {
        auto byte = cache.get(addr + i);
        if (!byte.has_value()) break;          // Unknown byte — stop

        uint8_t c = *byte;
        if (c == 0) break;                     // NUL terminator — end of string
        if (!is_printable(c)) break;           // Non-printable — not a string

        result.push_back(static_cast<char>(c));
    }

    if (result.size() < StringResult::MIN_STRING_LEN) return std::nullopt;
    return result;
}

/// Try to read a contiguous printable UTF-16LE string from the byte cache.
static std::optional<std::string> probe_utf16le_from_cache(
    const ReadByteCache& cache, uint64_t addr)
{
    std::string result;
    result.reserve(StringResult::MIN_STRING_LEN + 16);

    for (size_t i = 0; i < StringResult::MAX_STRING_LEN; ++i) {
        uint64_t off = i * 2;
        auto lo = cache.get(addr + off);
        auto hi = cache.get(addr + off + 1);

        if (!lo.has_value() || !hi.has_value()) break;

        uint8_t lo_byte = *lo;
        uint8_t hi_byte = *hi;

        if (lo_byte == 0 && hi_byte == 0) break;
        if (hi_byte != 0) break;
        if (!is_printable(lo_byte)) break;

        result.push_back(static_cast<char>(lo_byte));
    }

    if (result.size() < StringResult::MIN_STRING_LEN) return std::nullopt;
    return result;
}

// ─── StringPass::run ─────────────────────────────────────────────────────

PassResult StringPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index  = ctx.index();
    const auto& range = ctx.range();

    uint64_t start = range.start_inst_id;
    uint64_t end   = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    StringResult result;
    ReadByteCache byte_cache;

    // ─── Phase 1: Collect all memory bytes from read and write events ─────
    uint64_t inst_id   = 0;
    uint64_t total     = end - start;

    // Also track: for each address, which inst_id first touched it
    std::unordered_map<uint64_t, uint64_t> addr_first_inst;

    for (auto it = reader.begin(); it != reader.end() && inst_id < end; ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        if (inst_id < start) {
            inst_id++;
            continue;
        }

        auto inst = rec.as_inst();

        for (uint8_t m = 0; m < inst.mem_access_count; ++m) {
            auto mem = inst.mem_access(m);
            if (mem.addr == 0) continue;

            // Record bytes into byte cache
            byte_cache.record(mem.addr, mem.size, mem.value, mem.value_hi);

            // Track first instruction that touched each byte address
            uint16_t actual_size = std::min<uint16_t>(mem.size, 16);
            for (uint16_t i = 0; i < actual_size; ++i) {
                uint64_t a = mem.addr + i;
                if (addr_first_inst.find(a) == addr_first_inst.end()) {
                    addr_first_inst[a] = inst_id;
                }
            }
        }

        inst_id++;

        if ((inst_id - start) % 500000 == 0) {
            ctx.progress(0.4f * static_cast<float>(inst_id - start) / static_cast<float>(total),
                         "Collecting memory bytes...");
            if (ctx.cancelled()) {
                return PassResult::failed("cancelled by user");
            }
        }
    }

    ctx.progress(0.4f, fmt::format("Collected {} unique byte addresses from trace",
                                    byte_cache.size()));

    // ─── Phase 2: Linear scan of byte cache for strings ───────────────────
    // Sort all cached addresses and scan for contiguous printable regions.
    // This is much more thorough than probing only at event start addresses —
    // it finds strings at ANY position in observed memory.

    std::vector<uint64_t> all_addrs;
    all_addrs.reserve(byte_cache.size());
    for (const auto& [addr, _] : byte_cache.raw_map()) {
        all_addrs.push_back(addr);
    }
    std::sort(all_addrs.begin(), all_addrs.end());

    ctx.progress(0.5f, fmt::format("Sorted {} addresses, scanning for strings...",
                                    all_addrs.size()));

    // Scan: walk through sorted addresses, find contiguous printable runs
    size_t i = 0;
    size_t n = all_addrs.size();
    uint64_t strings_found = 0;

    while (i < n) {
        uint64_t run_start = all_addrs[i];
        std::string run_content;
        run_content.reserve(64);

        // Extend while consecutive and printable
        size_t j = i;
        while (j < n) {
            uint64_t expected_addr = run_start + (j - i);
            if (all_addrs[j] != expected_addr) break;  // Non-contiguous

            auto byte = cache_get_fast(byte_cache, all_addrs[j]);
            if (byte == 0) {
                // NUL terminator — end of potential string
                j++;
                break;
            }
            if (!is_printable(byte)) break;  // Non-printable

            run_content.push_back(static_cast<char>(byte));
            j++;

            if (run_content.size() >= StringResult::MAX_STRING_LEN) break;
        }

        // If we got a valid string, register it
        if (run_content.size() >= StringResult::MIN_STRING_LEN) {
            uint64_t str_addr = run_start;
            // Find the inst_id that first referenced this string
            auto first_it = addr_first_inst.find(str_addr);
            uint64_t disc_inst = (first_it != addr_first_inst.end()) ? first_it->second : 0;

            size_t idx = result.strings.size();
            StringRef ref;
            ref.addr          = str_addr;
            ref.discovered_at = disc_inst;
            ref.content       = std::move(run_content);
            ref.encoding      = StringRef::ASCII;
            ref.references.push_back({disc_inst, 0});
            result.strings.push_back(std::move(ref));
            result.addr_to_index[str_addr] = idx;
            strings_found++;
        }

        // Advance: skip past this run (whether it was a string or not)
        if (j > i) {
            i = j;
        } else {
            i++;
        }

        if (strings_found % 1000 == 0 && strings_found > 0) {
            ctx.progress(0.5f + 0.5f * static_cast<float>(i) / static_cast<float>(n),
                         fmt::format("Scanning... {} strings found", strings_found));
            if (ctx.cancelled()) {
                return PassResult::failed("cancelled by user");
            }
        }
    }

    ctx.progress(1.0f, fmt::format("Strings: {} discovered from {} byte addresses",
                                    result.total(), byte_cache.size()));
    return PassResult::success(std::move(result));
}

}  // namespace tenet
