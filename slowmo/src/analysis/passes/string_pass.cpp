#include "analysis/passes/string_pass.h"
#include "core/memory_model.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <fmt/core.h>
#include <algorithm>
#include <cctype>

namespace tenet {

// ─── Helpers ──────────────────────────────────────────────────────────────

static bool is_printable(uint8_t c) {
    return (c >= 0x20 && c <= 0x7E) || c == '\t' || c == '\n' || c == '\r';
}

/// Try to read a contiguous printable ASCII string starting at `addr`.
/// Returns the string content (without NUL terminator) or nullopt if the
/// sequence is shorter than MIN_STRING_LEN.
static std::optional<std::string> probe_ascii(
    MemoryModel& mem, uint64_t addr, uint64_t at_inst_id)
{
    std::string result;
    result.reserve(StringResult::MIN_STRING_LEN + 16);

    for (size_t i = 0; i < StringResult::MAX_STRING_LEN; ++i) {
        auto byte = mem.byte_at(addr + i, at_inst_id);
        if (!byte.has_value()) break;          // Unknown byte — stop

        uint8_t c = *byte;
        if (c == 0) break;                     // NUL terminator — end of string
        if (!is_printable(c)) break;           // Non-printable — not a string

        result.push_back(static_cast<char>(c));
    }

    if (result.size() < StringResult::MIN_STRING_LEN) return std::nullopt;
    return result;
}

/// Try to read a contiguous printable UTF-16LE string starting at `addr`.
/// UTF-16LE pattern: every odd byte is 0x00, every even byte is printable ASCII.
/// Returns the decoded ASCII content or nullopt if too short.
static std::optional<std::string> probe_utf16le(
    MemoryModel& mem, uint64_t addr, uint64_t at_inst_id)
{
    std::string result;
    result.reserve(StringResult::MIN_STRING_LEN + 16);

    for (size_t i = 0; i < StringResult::MAX_STRING_LEN; ++i) {
        uint64_t off = i * 2;
        auto lo = mem.byte_at(addr + off, at_inst_id);
        auto hi = mem.byte_at(addr + off + 1, at_inst_id);

        if (!lo.has_value() || !hi.has_value()) break;

        uint8_t lo_byte = *lo;
        uint8_t hi_byte = *hi;

        // NUL terminator: both bytes are 0
        if (lo_byte == 0 && hi_byte == 0) break;

        // UTF-16LE: high byte should be 0 for basic ASCII range
        if (hi_byte != 0) break;
        if (!is_printable(lo_byte)) break;

        result.push_back(static_cast<char>(lo_byte));
    }

    if (result.size() < StringResult::MIN_STRING_LEN) return std::nullopt;
    return result;
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

// ─── StringPass::run ─────────────────────────────────────────────────────

PassResult StringPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index  = ctx.index();
    auto& memory = ctx.memory();
    const auto& range = ctx.range();

    uint64_t start = range.start_inst_id;
    uint64_t end   = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    StringResult result;

    uint64_t inst_id   = 0;
    uint64_t processed = 0;
    uint64_t total     = end - start;

    for (auto it = reader.begin(); it != reader.end() && inst_id < end; ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        if (inst_id < start) {
            inst_id++;
            continue;
        }

        auto inst = rec.as_inst();

        // Examine every memory access on this instruction.
        for (uint8_t m = 0; m < inst.mem_access_count; ++m) {
            auto mem = inst.mem_access(m);

            // Only interested in read accesses (bit 0 = read)
            if ((mem.type & 0x01) == 0) continue;

            uint64_t read_addr = mem.addr;

            // Skip address 0 — never a valid string pointer
            if (read_addr == 0) continue;

            // Check if we already probed this address
            auto probe_it = result.addr_to_index.find(read_addr);
            if (probe_it != result.addr_to_index.end()) {
                // Already known — just add a reference if it's a real string
                if (probe_it->second != StringResult::NOT_STRING) {
                    auto& ref = result.strings[probe_it->second];
                    ref.references.push_back({inst_id, inst.pc});
                    result.inst_to_strings[inst_id].push_back(probe_it->second);
                }
                continue;
            }

            // Try ASCII first (most common case).
            auto ascii_str = probe_ascii(memory, read_addr, inst_id);
            if (ascii_str.has_value()) {
                size_t idx = result.strings.size();
                StringRef ref;
                ref.addr          = read_addr;
                ref.discovered_at = inst_id;
                ref.content       = std::move(*ascii_str);
                ref.encoding      = StringRef::ASCII;
                ref.references.push_back({inst_id, inst.pc});
                result.strings.push_back(std::move(ref));
                result.addr_to_index[read_addr] = idx;
                result.inst_to_strings[inst_id].push_back(idx);
                continue;
            }

            // Try UTF-16LE.
            auto utf16_str = probe_utf16le(memory, read_addr, inst_id);
            if (utf16_str.has_value()) {
                size_t idx = result.strings.size();
                StringRef ref;
                ref.addr          = read_addr;
                ref.discovered_at = inst_id;
                ref.content       = std::move(*utf16_str);
                ref.encoding      = StringRef::UTF16LE;
                ref.references.push_back({inst_id, inst.pc});
                result.strings.push_back(std::move(ref));
                result.addr_to_index[read_addr] = idx;
                result.inst_to_strings[inst_id].push_back(idx);
                continue;
            }

            // Not a string — mark as probed-but-empty to avoid re-probing.
            result.addr_to_index[read_addr] = StringResult::NOT_STRING;
        }

        inst_id++;
        processed++;

        if (processed % 50000 == 0) {
            ctx.progress(static_cast<float>(processed) / static_cast<float>(total));
            if (ctx.cancelled()) {
                return PassResult::failed("cancelled by user");
            }
        }
    }

    ctx.progress(1.0f, fmt::format("Strings: {} discovered, {} unique addresses probed",
                                    result.total(), result.addr_to_index.size()));
    return PassResult::success(std::move(result));
}

}  // namespace tenet
