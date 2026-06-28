#include "analysis/passes/string_pass.h"
#include "analysis/trace_collector.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <fmt/core.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

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
    // Estimate buffer size
    size_t est = 4 + 4 + 8;
    for (const auto& s : res.strings) {
        est += 8 + 8 + 1 + 3          // addr, discovered_at, encoding, pad
             + 4 + s.content.size()    // content
             + 4 + s.references.size() * 16;  // references
    }

    std::string buf;
    buf.reserve(est);

    auto write = [&](const void* data, size_t n) {
        buf.append(reinterpret_cast<const char*>(data), n);
    };
    auto write_u8  = [&](uint8_t v)  { write(&v, 1); };
    auto write_u32 = [&](uint32_t v) { write(&v, 4); };
    auto write_u64 = [&](uint64_t v) { write(&v, 8); };
    auto write_str = [&](const std::string& s) {
        write_u32(static_cast<uint32_t>(s.size()));
        if (!s.empty()) write(s.data(), s.size());
    };

    write_u32(STRING_BLOB_MAGIC);
    write_u32(STRING_BLOB_VERSION);
    write_u64(static_cast<uint64_t>(res.strings.size()));

    for (const auto& s : res.strings) {
        write_u64(s.addr);
        write_u64(s.discovered_at);
        write_u8(static_cast<uint8_t>(s.encoding));
        write_u8(0); write_u8(0); write_u8(0);  // padding
        write_str(s.content);
        write_u32(static_cast<uint32_t>(s.references.size()));
        for (const auto& r : s.references) {
            write_u64(r.inst_id);
            write_u64(r.pc);
        }
    }

    return buf;
}

/// Deserialize StringResult from a binary blob. Returns false on corruption.
/// Rebuilds addr_to_index and inst_to_strings derived indices.
static bool string_deserialize(const std::string& blob, StringResult& out) {
    if (blob.size() < 4 + 4 + 8) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto remaining = [&]() -> size_t { return static_cast<size_t>(end - p); };
    auto read_u8  = [&]() -> uint8_t  { uint8_t  v; std::memcpy(&v, p, 1); p += 1; return v; };
    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_u64 = [&]() -> uint64_t { uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; };
    auto read_str = [&](std::string& s) -> bool {
        if (remaining() < 4) return false;
        uint32_t len = read_u32();
        if (remaining() < len) return false;
        s.assign(p, len);
        p += len;
        return true;
    };

    uint32_t magic = read_u32();
    uint32_t version = read_u32();
    if (magic != STRING_BLOB_MAGIC || version != STRING_BLOB_VERSION) return false;

    uint64_t num_strings = read_u64();
    out.strings.resize(static_cast<size_t>(num_strings));

    for (size_t i = 0; i < num_strings; i++) {
        auto& s = out.strings[i];
        if (remaining() < 8 + 8 + 4) return false;  // addr + discovered_at + encoding + pad
        s.addr          = read_u64();
        s.discovered_at = read_u64();
        s.encoding      = static_cast<StringRef::Encoding>(read_u8());
        read_u8(); read_u8(); read_u8();  // skip padding
        if (!read_str(s.content)) return false;

        if (remaining() < 4) return false;
        uint32_t num_refs = read_u32();
        if (remaining() < num_refs * 16) return false;
        s.references.resize(num_refs);
        for (uint32_t j = 0; j < num_refs; j++) {
            s.references[j].inst_id = read_u64();
            s.references[j].pc      = read_u64();
        }

        // Rebuild addr_to_index
        out.addr_to_index[s.addr] = i;
        // Rebuild inst_to_strings
        for (const auto& r : s.references) {
            out.inst_to_strings[r.inst_id].push_back(i);
        }
    }

    return true;
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

// ─── StringCollector ──────────────────────────────────────────────────────

/// Sequential TraceCollector that collects memory bytes from inst memory
/// accesses, then (in end()) does a linear scan to extract printable strings.
class StringCollector final : public TraceCollector {
public:
    StringCollector(uint64_t start_inst_id, uint64_t end_inst_id)
        : range_start_(start_inst_id), range_end_(end_inst_id) {}

    std::string_view name() const override { return "StringCollector"; }

    bool begin(uint64_t /*start*/, uint64_t /*end*/) override {
        bytes_.clear();
        addr_first_inst_.clear();
        result_ = StringResult{};
        return true;
    }

    void on_inst(uint64_t inst_id, const InstView& inst) override {
        if (inst_id < range_start_ || inst_id >= range_end_) return;

        for (uint8_t m = 0; m < inst.mem_access_count; ++m) {
            auto mem = inst.mem_access(m);
            if (mem.addr == 0) continue;

            // Record bytes
            uint8_t buf[16];
            std::memcpy(buf, &mem.value, 8);
            std::memcpy(buf + 8, &mem.value_hi, 8);
            uint16_t actual_size = std::min<uint16_t>(mem.size, 16);

            for (uint16_t i = 0; i < actual_size; ++i) {
                uint64_t addr = mem.addr + i;
                bytes_[addr] = buf[i];

                // Track first instruction that touched each byte
                if (addr_first_inst_.find(addr) == addr_first_inst_.end()) {
                    addr_first_inst_[addr] = inst_id;
                }
            }
        }
    }

    void end() override {
        // Phase 2: Linear scan for strings (same logic as original StringPass)
        std::vector<uint64_t> all_addrs;
        all_addrs.reserve(bytes_.size());
        for (const auto& [addr, _] : bytes_) {
            all_addrs.push_back(addr);
        }
        std::sort(all_addrs.begin(), all_addrs.end());

        size_t i = 0;
        size_t n = all_addrs.size();

        while (i < n) {
            uint64_t run_start = all_addrs[i];
            std::string run_content;
            run_content.reserve(64);

            size_t j = i;
            while (j < n) {
                uint64_t expected_addr = run_start + (j - i);
                if (all_addrs[j] != expected_addr) break;

                auto it = bytes_.find(all_addrs[j]);
                uint8_t byte = (it != bytes_.end()) ? it->second : 0xFF;

                if (byte == 0) {
                    j++;
                    break;
                }
                if (!is_printable(byte)) break;

                run_content.push_back(static_cast<char>(byte));
                j++;

                if (run_content.size() >= StringResult::MAX_STRING_LEN) break;
            }

            if (run_content.size() >= StringResult::MIN_STRING_LEN) {
                uint64_t str_addr = run_start;
                auto first_it = addr_first_inst_.find(str_addr);
                uint64_t disc_inst = (first_it != addr_first_inst_.end())
                                     ? first_it->second : 0;

                size_t idx = result_.strings.size();
                StringRef ref;
                ref.addr          = str_addr;
                ref.discovered_at = disc_inst;
                ref.content       = std::move(run_content);
                ref.encoding      = StringRef::ASCII;
                ref.references.push_back({disc_inst, 0});
                result_.strings.push_back(std::move(ref));
                result_.addr_to_index[str_addr] = idx;
            }

            if (j > i) i = j;
            else        i++;
        }

        // ─── UTF-16LE scan ────────────────────────────────────────────
        // Look for sequences of [printable_byte, 0x00] pairs. The ASCII scan
        // above breaks on 0x00, so genuine UTF-16LE strings are invisible to
        // it; there is no overlap. We walk every observed address as a candidate
        // start and extend while pairs remain (printable lo, 0x00 hi).
        for (size_t k = 0; k < n; ++k) {
            uint64_t start = all_addrs[k];

            // Skip if an ASCII string was already recorded at this address —
            // ASCII takes priority (a real ASCII run would have consumed these
            // bytes already, so this is mostly defensive).
            auto existing = result_.addr_to_index.find(start);
            if (existing != result_.addr_to_index.end() &&
                existing->second != StringResult::NOT_STRING) {
                continue;
            }

            auto it_lo = bytes_.find(start);
            auto it_hi = bytes_.find(start + 1);
            if (it_lo == bytes_.end() || it_hi == bytes_.end()) continue;
            if (it_hi->second != 0x00) continue;
            if (!is_printable(it_lo->second)) continue;

            // Extend the run of [printable, 0x00] pairs.
            std::string run_content;
            run_content.push_back(static_cast<char>(it_lo->second));
            uint64_t addr = start + 2;
            while (run_content.size() < StringResult::MAX_STRING_LEN) {
                auto lo = bytes_.find(addr);
                auto hi = bytes_.find(addr + 1);
                if (lo == bytes_.end() || hi == bytes_.end()) break;
                if (hi->second != 0x00) break;
                if (!is_printable(lo->second)) break;
                run_content.push_back(static_cast<char>(lo->second));
                addr += 2;
            }

            if (run_content.size() >= StringResult::MIN_STRING_LEN) {
                auto first_it = addr_first_inst_.find(start);
                uint64_t disc_inst = (first_it != addr_first_inst_.end())
                                     ? first_it->second : 0;

                size_t idx = result_.strings.size();
                StringRef ref;
                ref.addr          = start;
                ref.discovered_at = disc_inst;
                ref.content       = std::move(run_content);
                ref.encoding      = StringRef::UTF16LE;
                ref.references.push_back({disc_inst, 0});
                result_.strings.push_back(std::move(ref));
                result_.addr_to_index[start] = idx;
            }
        }
    }

    StringResult take_result() { return std::move(result_); }
    size_t byte_cache_size() const { return bytes_.size(); }

private:
    uint64_t range_start_;
    uint64_t range_end_;

    std::unordered_map<uint64_t, uint8_t> bytes_;
    std::unordered_map<uint64_t, uint64_t> addr_first_inst_;
    StringResult result_;
};

// ─── StringPass::run ─────────────────────────────────────────────────────

PassResult StringPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index  = ctx.index();
    const auto& range = ctx.range();

    // ─── Fast path: load from persisted cache ─────────────────────────────
    if (range.is_full_trace()) {
        std::string blob;
        if (index.load_pass_blob("strings", blob)) {
            StringResult cached;
            if (string_deserialize(blob, cached)) {
                ctx.progress(1.0f, fmt::format(
                    "Strings: {} discovered (from cache)",
                    cached.total()));
                return PassResult::success(std::move(cached));
            }
        }
    }

    uint64_t start = range.start_inst_id;
    uint64_t end   = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    // ─── Phase 1 via TraceScanEngine ─────────────────────────────────────
    StringCollector collector(start, end);

    TraceScanEngine local_engine(reader, index.inst_count(), &index);
    local_engine.set_progress([&](uint64_t processed, uint64_t total) {
        if (total > 0) {
            // Phase 1 is 40% of total work (matches original progress weights)
            ctx.progress(0.4f * static_cast<float>(processed) / static_cast<float>(total),
                         "Collecting memory bytes...");
        }
    });
    local_engine.set_cancel_check([&]() { return ctx.cancelled(); });
    local_engine.add_collector(&collector);

    local_engine.run(start, end);

    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }

    ctx.progress(0.4f, fmt::format("Collected {} unique byte addresses from trace",
                                    collector.byte_cache_size()));

    // Phase 2 happens inside collector.end() which was called by the engine.
    // The result is now ready.

    size_t byte_cache_size = collector.byte_cache_size();

    ctx.progress(0.5f, fmt::format("Sorted {} addresses, scanning for strings...",
                                    byte_cache_size));

    StringResult result = collector.take_result();

    // ─── Persist result for future sessions ───────────────────────────────
    if (range.is_full_trace()) {
        std::string blob = string_serialize(result);
        if (!blob.empty()) {
            index.save_pass_blob("strings", blob.data(), blob.size());
        }
    }

    ctx.progress(1.0f, fmt::format("Strings: {} discovered from {} byte addresses",
                                    result.total(), byte_cache_size));
    return PassResult::success(std::move(result));
}

}  // namespace tenet
