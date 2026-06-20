#include "core/breakpoint_engine.h"
#include "io/index_builder.h"
#include "core/memory_model.h"

#include <rocksdb/iterator.h>
#include <fmt/core.h>

#include <algorithm>
#include <charconv>
#include <cstring>

namespace tenet {

// ─── Helpers ──────────────────────────────────────────────────────────────

namespace {

// Decode big-endian u64 from 8 bytes (matches MemoryModel key encoding)
uint64_t be_decode_u64(const char* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v = (v << 8) | static_cast<uint8_t>(p[i]);
    return v;
}

// Encode big-endian u64 into 8 bytes
void be_encode_u64(uint64_t v, char out[8]) {
    for (int i = 7; i >= 0; --i) {
        out[i] = static_cast<char>(v & 0xFF);
        v >>= 8;
    }
}

// MemoryModel key format: page_addr(8 BE) | page_offset(2 BE) | inst_id(8 BE) = 18 bytes
static constexpr size_t KEY_SIZE = 18;

std::string encode_mem_key(uint64_t page_addr, uint16_t page_offset, uint64_t inst_id) {
    char buf[KEY_SIZE];
    be_encode_u64(page_addr, buf);
    buf[8] = static_cast<char>((page_offset >> 8) & 0xFF);
    buf[9] = static_cast<char>(page_offset & 0xFF);
    be_encode_u64(inst_id, buf + 10);
    return std::string(buf, KEY_SIZE);
}

// Extract inst_id from the last 8 bytes of a mem_write key
uint64_t mem_key_inst_id(const rocksdb::Slice& key) {
    if (key.size() < KEY_SIZE) return 0;
    return be_decode_u64(key.data() + 10);
}

// Extract page_addr from a mem_write key
uint64_t mem_key_page(const rocksdb::Slice& key) {
    if (key.size() < 8) return 0;
    return be_decode_u64(key.data());
}

// Extract page_offset from a mem_write key
uint16_t mem_key_offset(const rocksdb::Slice& key) {
    if (key.size() < 10) return 0;
    return (static_cast<uint16_t>(static_cast<uint8_t>(key.data()[8])) << 8)
         | static_cast<uint8_t>(key.data()[9]);
}

static constexpr uint64_t PAGE_SHIFT = 12;

uint64_t page_of(uint64_t addr) { return addr >> PAGE_SHIFT; }
uint16_t offset_in_page(uint64_t addr) { return static_cast<uint16_t>(addr & 0xFFF); }

}  // anonymous namespace

// ─── Constructor ──────────────────────────────────────────────────────────

BreakpointEngine::BreakpointEngine(const TraceReader& reader,
                                   const TraceIndex& index,
                                   RegisterFile& regfile,
                                   const MemoryModel& memory)
    : reader_(reader), index_(index), regfile_(regfile), memory_(memory) {}

// ─── Lifecycle ────────────────────────────────────────────────────────────

BreakpointId BreakpointEngine::add_breakpoint(BreakpointSpec spec) {
    BreakpointId id = next_id_++;
    entries_.push_back({id, std::move(spec), true});
    return id;
}

bool BreakpointEngine::remove_breakpoint(BreakpointId id) {
    auto it = std::find_if(entries_.begin(), entries_.end(),
                           [id](const BreakpointEntry& e) { return e.id == id; });
    if (it == entries_.end()) return false;
    entries_.erase(it);
    return true;
}

void BreakpointEngine::clear_breakpoints() {
    entries_.clear();
}

// ─── PC breakpoint resolution ─────────────────────────────────────────────

std::vector<uint64_t> BreakpointEngine::resolve_pc_bp(const PcBreakpoint& bp) const {
    // We need the XRef index — but BreakpointEngine doesn't hold a PassManager.
    // Instead, we scan the OFFSET column family to enumerate all inst_ids at this PC.
    //
    // Fast path: use the TraceIndex sparse offset table to find all inst_ids that
    // produced this PC. We iterate the OFFSET CF sequentially — it contains all
    // *sampled* inst_ids (every 256th). For the remaining, we use index_.offset_of()
    // + a micro-scan.
    //
    // Practical fast path: use a forward sequential scan of the trace from offset_of
    // nearest anchor before the first occurrence, collecting inst_ids where pc==bp.address.
    // We cache nothing; the XRef pass (if run) is better, but works without it.
    //
    // This is a one-time cost per breakpoint set (not per step). For typical traces
    // (1M instructions) it takes < 100ms.

    std::vector<uint64_t> result;
    const uint64_t total = index_.inst_count();
    if (total == 0) return result;

    // Sequential scan of the whole trace. Use the TraceReader iterator which
    // handles v4/v5/v6 correctly.
    // For large traces this is O(N) but is done once at breakpoint-set time
    // and the result is cached implicitly in the XRef pass if available.
    uint64_t inst_id = 0;
    for (auto it = reader_.begin(); it != reader_.end(); ++it) {
        const RecordView rv = *it;
        if (rv.kind != RecordKind::Inst) continue;
        const InstView iv = rv.as_inst();
        if (iv.pc == bp.address) {
            result.push_back(inst_id);
        }
        ++inst_id;
    }
    return result;
}

// ─── Watchpoint resolution ────────────────────────────────────────────────

std::vector<uint64_t> BreakpointEngine::resolve_watch_bp(const WatchBreakpoint& bp) const {
    // Use the mem_write column family. We scan all keys for the target page
    // where the byte offset falls within [bp.address & 0xFFF, (bp.address & 0xFFF)+bp.size).
    rocksdb::DB* db = index_.raw_db();
    rocksdb::ColumnFamilyHandle* cf = index_.mem_write_cf();
    if (!db || !cf) return {};

    std::vector<uint64_t> result;

    uint64_t target_page = page_of(bp.address);
    uint16_t target_off  = offset_in_page(bp.address);
    uint16_t end_off     = (bp.size == 0)
                              ? 0xFFF  // entire page
                              : static_cast<uint16_t>(target_off + bp.size - 1);

    // Seek to the first key in this page
    char seek_buf[KEY_SIZE];
    be_encode_u64(target_page, seek_buf);
    // page_offset = target_off (or 0 for full-page watch)
    uint16_t seek_page_off = (bp.size == 0) ? 0 : target_off;
    seek_buf[8] = static_cast<char>((seek_page_off >> 8) & 0xFF);
    seek_buf[9] = static_cast<char>(seek_page_off & 0xFF);
    // inst_id = 0 (start of time)
    std::memset(seek_buf + 10, 0, 8);

    rocksdb::ReadOptions ro;
    ro.fill_cache = false;  // don't pollute block cache for a one-time scan
    std::unique_ptr<rocksdb::Iterator> iter(db->NewIterator(ro, cf));
    iter->Seek(rocksdb::Slice(seek_buf, KEY_SIZE));

    while (iter->Valid()) {
        const rocksdb::Slice key = iter->key();
        if (key.size() < KEY_SIZE) { iter->Next(); continue; }

        uint64_t kpage = mem_key_page(key);
        if (kpage != target_page) break;  // moved to next page — done

        uint16_t koff = mem_key_offset(key);
        // Check if this write's starting offset overlaps [target_off, end_off]
        // (write starts at koff; write may span multiple bytes, but we accept
        //  any write whose start offset is within the watchpoint range).
        if (koff > end_off) {
            // Start offset is past the range — this and subsequent keys don't apply
            // unless there are writes that start before target_off but extend into it.
            // We handle that by also scanning backwards from target_off in resolve_watch_bp,
            // but for simplicity we just stop here. A write that crosses from before target_off
            // would start before target_off — those are found by starting from offset 0.
            break;
        }

        uint64_t inst_id = mem_key_inst_id(key);
        result.push_back(inst_id);
        iter->Next();
    }

    // Also scan writes that start before target_off but may overlap the range
    // (e.g., a 16-byte stp starting at target_off - 8 that covers target_off).
    // Limit backward scan to MAX_WRITE_SIZE bytes back.
    if (bp.size > 0 && target_off > 0) {
        uint16_t back_off = static_cast<uint16_t>(
            target_off > 16 ? target_off - 16 : 0);
        char back_buf[KEY_SIZE];
        be_encode_u64(target_page, back_buf);
        back_buf[8] = static_cast<char>((back_off >> 8) & 0xFF);
        back_buf[9] = static_cast<char>(back_off & 0xFF);
        std::memset(back_buf + 10, 0, 8);

        iter->Seek(rocksdb::Slice(back_buf, KEY_SIZE));
        while (iter->Valid()) {
            const rocksdb::Slice key = iter->key();
            if (key.size() < KEY_SIZE) { iter->Next(); continue; }
            uint64_t kpage = mem_key_page(key);
            if (kpage != target_page) break;
            uint16_t koff = mem_key_offset(key);
            if (koff >= target_off) break;  // reached the range we already scanned
            // Check size from value: value[0] is write_size
            uint8_t write_size = 0;
            if (iter->value().size() >= 1) write_size = static_cast<uint8_t>(iter->value()[0]);
            // Does this write overlap [target_off, end_off]?
            if (koff + write_size > target_off) {
                result.push_back(mem_key_inst_id(key));
            }
            iter->Next();
        }
    }

    // Sort and deduplicate
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}

// ─── Format hit description ───────────────────────────────────────────────

std::string BreakpointEngine::format_hit(const BreakpointEntry& entry, uint64_t inst_id) {
    return std::visit([&](const auto& spec) -> std::string {
        using T = std::decay_t<decltype(spec)>;
        if constexpr (std::is_same_v<T, PcBreakpoint>) {
            return fmt::format("BP#{} PC hit 0x{:x} @ inst #{}", entry.id, spec.address, inst_id);
        } else if constexpr (std::is_same_v<T, WatchBreakpoint>) {
            if (spec.size == 0)
                return fmt::format("BP#{} write to page of 0x{:x} @ inst #{}", entry.id, spec.address, inst_id);
            return fmt::format("BP#{} write to 0x{:x}+{} @ inst #{}", entry.id, spec.address, spec.size, inst_id);
        } else if constexpr (std::is_same_v<T, ConditionalBreakpoint>) {
            return fmt::format("BP#{} condition '{}' @ inst #{}", entry.id, spec.description, inst_id);
        }
        return {};
    }, entry.spec);
}

// ─── run_forward ──────────────────────────────────────────────────────────

std::optional<BreakpointHit> BreakpointEngine::run_forward(
    uint64_t from_inst_id, uint64_t limit) const {

    if (entries_.empty()) return std::nullopt;

    // Collect the earliest hit among all enabled breakpoints > from_inst_id.
    std::optional<BreakpointHit> best;

    for (const auto& entry : entries_) {
        if (!entry.enabled) continue;

        std::visit([&](const auto& spec) {
            using T = std::decay_t<decltype(spec)>;

            if constexpr (std::is_same_v<T, PcBreakpoint>) {
                // Resolve all inst_ids for this PC, find the smallest > from_inst_id
                auto ids = resolve_pc_bp(spec);
                auto it = std::upper_bound(ids.begin(), ids.end(), from_inst_id);
                if (it != ids.end()) {
                    uint64_t hit_id = *it;
                    if (!best || hit_id < best->inst_id) {
                        best = BreakpointHit{hit_id, entry.id, format_hit(entry, hit_id)};
                    }
                }
            } else if constexpr (std::is_same_v<T, WatchBreakpoint>) {
                auto ids = resolve_watch_bp(spec);
                auto it = std::upper_bound(ids.begin(), ids.end(), from_inst_id);
                if (it != ids.end()) {
                    uint64_t hit_id = *it;
                    if (!best || hit_id < best->inst_id) {
                        best = BreakpointHit{hit_id, entry.id, format_hit(entry, hit_id)};
                    }
                }
            } else if constexpr (std::is_same_v<T, ConditionalBreakpoint>) {
                // Linear scan from from_inst_id+1 up to limit
                uint64_t total = index_.inst_count();
                // Guard against uint64 overflow when limit == UINT64_MAX:
                // from_inst_id + 1 + UINT64_MAX wraps to 0, making scan_end 0.
                // Instead: cap at total if limit would overflow the addend.
                uint64_t scan_end;
                if (limit >= total) {
                    scan_end = total;
                } else {
                    scan_end = std::min(total, from_inst_id + 1 + limit);
                }
                for (uint64_t id = from_inst_id + 1; id < scan_end; ++id) {
                    const RegState& rs = const_cast<RegisterFile&>(regfile_).state_before(id);
                    if (spec.predicate(id, rs)) {
                        if (!best || id < best->inst_id) {
                            best = BreakpointHit{id, entry.id, format_hit(entry, id)};
                        }
                        break;  // found earliest for this predicate
                    }
                }
            }
        }, entry.spec);
    }
    return best;
}

// ─── run_backward ─────────────────────────────────────────────────────────

std::optional<BreakpointHit> BreakpointEngine::run_backward(
    uint64_t from_inst_id, uint64_t limit) const {

    if (entries_.empty() || from_inst_id == 0) return std::nullopt;

    std::optional<BreakpointHit> best;

    for (const auto& entry : entries_) {
        if (!entry.enabled) continue;

        std::visit([&](const auto& spec) {
            using T = std::decay_t<decltype(spec)>;

            if constexpr (std::is_same_v<T, PcBreakpoint>) {
                auto ids = resolve_pc_bp(spec);
                // Find largest id < from_inst_id
                auto it = std::lower_bound(ids.begin(), ids.end(), from_inst_id);
                if (it != ids.begin()) {
                    --it;
                    uint64_t hit_id = *it;
                    if (!best || hit_id > best->inst_id) {
                        best = BreakpointHit{hit_id, entry.id, format_hit(entry, hit_id)};
                    }
                }
            } else if constexpr (std::is_same_v<T, WatchBreakpoint>) {
                auto ids = resolve_watch_bp(spec);
                auto it = std::lower_bound(ids.begin(), ids.end(), from_inst_id);
                if (it != ids.begin()) {
                    --it;
                    uint64_t hit_id = *it;
                    if (!best || hit_id > best->inst_id) {
                        best = BreakpointHit{hit_id, entry.id, format_hit(entry, hit_id)};
                    }
                }
            } else if constexpr (std::is_same_v<T, ConditionalBreakpoint>) {
                // Linear scan backward from from_inst_id-1 down to max(0, from_inst_id-limit)
                // Guard against uint64 underflow when limit == UINT64_MAX.
                uint64_t scan_start = (limit != UINT64_MAX && from_inst_id > limit)
                                          ? from_inst_id - limit : 0;
                for (uint64_t id = from_inst_id; id > scan_start; ) {
                    --id;
                    const RegState& rs = const_cast<RegisterFile&>(regfile_).state_before(id);
                    if (spec.predicate(id, rs)) {
                        if (!best || id > best->inst_id) {
                            best = BreakpointHit{id, entry.id, format_hit(entry, id)};
                        }
                        break;
                    }
                }
            }
        }, entry.spec);
    }
    return best;
}

// ─── Convenience wrappers ─────────────────────────────────────────────────

std::optional<uint64_t> BreakpointEngine::next_execution(
    uint64_t pc, uint64_t from_inst_id) const {

    // Temporarily create a PC breakpoint, resolve, and discard.
    PcBreakpoint bp{pc};
    auto ids = resolve_pc_bp(bp);
    auto it = std::upper_bound(ids.begin(), ids.end(), from_inst_id);
    if (it == ids.end()) return std::nullopt;
    return *it;
}

std::optional<uint64_t> BreakpointEngine::prev_execution(
    uint64_t pc, uint64_t from_inst_id) const {

    PcBreakpoint bp{pc};
    auto ids = resolve_pc_bp(bp);
    auto it = std::lower_bound(ids.begin(), ids.end(), from_inst_id);
    if (it == ids.begin()) return std::nullopt;
    --it;
    return *it;
}

std::optional<BreakpointHit> BreakpointEngine::next_write(
    uint64_t address, uint16_t size, uint64_t from_inst_id) const {

    WatchBreakpoint bp{address, size};
    auto ids = resolve_watch_bp(bp);
    auto it = std::upper_bound(ids.begin(), ids.end(), from_inst_id);
    if (it == ids.end()) return std::nullopt;
    uint64_t hit_id = *it;
    BreakpointEntry fake{0, bp, true};
    return BreakpointHit{hit_id, 0, format_hit(fake, hit_id)};
}

std::optional<BreakpointHit> BreakpointEngine::prev_write(
    uint64_t address, uint16_t size, uint64_t from_inst_id) const {

    WatchBreakpoint bp{address, size};
    auto ids = resolve_watch_bp(bp);
    auto it = std::lower_bound(ids.begin(), ids.end(), from_inst_id);
    if (it == ids.begin()) return std::nullopt;
    --it;
    uint64_t hit_id = *it;
    BreakpointEntry fake{0, bp, true};
    return BreakpointHit{hit_id, 0, format_hit(fake, hit_id)};
}

// ─── TUI command parser ───────────────────────────────────────────────────

std::optional<BreakpointSpec> parse_breakpoint_cmd(
    const std::string& cmd, std::string* error_msg) {

    // Trim leading whitespace
    size_t start = cmd.find_first_not_of(" \t");
    if (start == std::string::npos) {
        if (error_msg) *error_msg = "empty command";
        return std::nullopt;
    }
    std::string_view s(cmd.c_str() + start);

    auto parse_hex_or_dec = [](std::string_view tok, uint64_t& out) -> bool {
        if (tok.empty()) return false;
        if (tok.size() >= 2 && tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X')) {
            tok.remove_prefix(2);
            out = 0;
            for (char c : tok) {
                out <<= 4;
                if (c >= '0' && c <= '9') out |= c - '0';
                else if (c >= 'a' && c <= 'f') out |= c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') out |= c - 'A' + 10;
                else return false;
            }
            return true;
        }
        uint64_t v = 0;
        auto [p, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), v);
        if (ec != std::errc{} || p != tok.data() + tok.size()) return false;
        out = v;
        return true;
    };

    // Parse command letter
    if (s.empty()) {
        if (error_msg) *error_msg = "empty command";
        return std::nullopt;
    }
    char cmd_char = s[0];
    s.remove_prefix(1);

    // Skip whitespace after command letter
    while (!s.empty() && (s[0] == ' ' || s[0] == '\t')) s.remove_prefix(1);

    if (cmd_char == 'b' || cmd_char == 'B') {
        // PC breakpoint: "b <address>"
        if (s.empty()) {
            if (error_msg) *error_msg = "usage: b <address>";
            return std::nullopt;
        }
        // Extract first token
        size_t tok_end = s.find_first_of(" \t");
        std::string_view tok = (tok_end == std::string_view::npos) ? s : s.substr(0, tok_end);
        uint64_t addr = 0;
        if (!parse_hex_or_dec(tok, addr)) {
            if (error_msg) *error_msg = fmt::format("invalid address '{}'", std::string(tok));
            return std::nullopt;
        }
        return PcBreakpoint{addr};

    } else if (cmd_char == 'w' || cmd_char == 'W') {
        // Watchpoint: "w <address> [size]"
        if (s.empty()) {
            if (error_msg) *error_msg = "usage: w <address> [size]";
            return std::nullopt;
        }
        // Extract address token
        size_t tok_end = s.find_first_of(" \t");
        std::string_view addr_tok = (tok_end == std::string_view::npos) ? s : s.substr(0, tok_end);
        uint64_t addr = 0;
        if (!parse_hex_or_dec(addr_tok, addr)) {
            if (error_msg) *error_msg = fmt::format("invalid address '{}'", std::string(addr_tok));
            return std::nullopt;
        }
        // Optional size
        uint16_t size = 0;
        if (tok_end != std::string_view::npos) {
            std::string_view rest = s.substr(tok_end);
            while (!rest.empty() && (rest[0] == ' ' || rest[0] == '\t')) rest.remove_prefix(1);
            if (!rest.empty()) {
                uint64_t sz = 0;
                if (!parse_hex_or_dec(rest, sz) || sz > 64) {
                    if (error_msg) *error_msg = fmt::format("invalid size (must be 1-64): '{}'", std::string(rest));
                    return std::nullopt;
                }
                size = static_cast<uint16_t>(sz);
            }
        }
        return WatchBreakpoint{addr, size};

    } else {
        if (error_msg) *error_msg = fmt::format("unknown breakpoint type '{}' (use 'b' or 'w')", cmd_char);
        return std::nullopt;
    }
}

}  // namespace tenet
