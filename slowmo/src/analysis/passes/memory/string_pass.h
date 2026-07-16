#pragma once

#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
#include "infra/scan_orchestrator.h"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <memory>
#include <ankerl/unordered_dense.h>

namespace tenet {

// ─── String pass result ──────────────────────────────────────────────────

/// A reference to a string discovered in traced memory.
struct StringRef {
    uint64_t addr;              // String start address
    uint64_t discovered_at;     // inst_id when this string was first found
    std::string content;        // UTF-8 content (up to MAX_STRING_LEN chars)

    enum Encoding {
        ASCII,
        UTF8,
        UTF16LE,
        Wide,       // wchar_t
    };
    Encoding encoding = ASCII;

    /// Reference information: which instruction accessed this string.
    struct Reference {
        uint64_t inst_id;       // Which instruction referenced it
        uint64_t pc;            // PC of that instruction
    };
    std::vector<Reference> references;  // All instructions that referenced this string
};

/// Result of the string discovery pass.
struct StringResult {
    std::vector<StringRef> strings;                             // All discovered strings
    ankerl::unordered_dense::map<uint64_t, size_t> addr_to_index;        // addr → strings[] index
    ankerl::unordered_dense::map<uint64_t, std::vector<size_t>> inst_to_strings; // inst_id → referenced string indices

    static constexpr size_t MAX_STRING_LEN = 256;
    static constexpr size_t MIN_STRING_LEN = 4;    // Minimum 4 chars to qualify as a string

    // Sentinel value in addr_to_index meaning "probed at this address but the
    // bytes did not form a qualifying string". Lets the pass remember a
    // negative probe result without re-scanning the same address on every
    // subsequent memory access (see StringPass::run()).
    static constexpr size_t NOT_STRING = SIZE_MAX;

    /// Lookup a string by its start address.
    const StringRef* at_addr(uint64_t addr) const {
        auto it = addr_to_index.find(addr);
        if (it == addr_to_index.end() || it->second == NOT_STRING) return nullptr;
        return &strings[it->second];
    }

    /// Find all strings referenced by a given instruction.
    std::vector<const StringRef*> at_inst(uint64_t inst_id) const {
        std::vector<const StringRef*> result;
        auto it = inst_to_strings.find(inst_id);
        if (it != inst_to_strings.end()) {
            result.reserve(it->second.size());
            for (size_t idx : it->second) {
                result.push_back(&strings[idx]);
            }
        }
        return result;
    }

    /// Case-insensitive substring search across all discovered strings.
    std::vector<const StringRef*> search(const std::string& pattern) const;

    /// Total number of discovered strings.
    size_t total() const { return strings.size(); }
};

// ─── String pass ─────────────────────────────────────────────────────────

/// Discovers printable strings in traced memory by scanning memory write
/// events through the time-indexed MemoryModel.
///
/// Strategy: for every memory *write* observed in the trace (reads are
/// skipped — a read cannot introduce new byte content, so any string visible
/// at a read was already produced by an earlier write and will be found
/// there), reconstruct a small window of memory around the written address
/// as it existed immediately after that instruction executed
/// (`MemoryModel::read_region(addr, size, inst_id + 1)`), then scan the
/// reconstructed window for printable ASCII/UTF-16LE runs.
///
/// Because every probe reads a single MemoryModel snapshot at one specific
/// instant, all bytes considered for a given string are guaranteed to be
/// mutually consistent in time — unlike a naive "last value seen at each
/// address" byte cache, this cannot stitch together bytes that existed at
/// different points in time into a bogus string.
///
/// Each time a string is (re)found at a given address, the discovering
/// instruction is appended to the string's `references` list, so
/// `StringResult::at_inst()` reflects every access that produced/observed
/// that exact string, not just the first one.
///
/// Result type: StringResult
class StringPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "strings"; }
    std::string_view description() const override {
        return "Discover printable strings in traced memory";
    }

    std::vector<std::string_view> dependencies() const override {
        return {};  // No dependencies — runs independently
    }

    bool has_scan() const override { return true; }
    std::optional<PassResult> try_load_cached(PassContext& ctx) override;
    void declare_scan(ScanOrchestrator& orch, PassContext& ctx) override;
    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 5.0f; }

    /// Maximum bytes probed around a write's start address when looking for
    /// a string boundary (the string may start before the write, e.g. when
    /// only the NUL terminator byte of a pre-existing string is (re)written).
    static constexpr size_t PROBE_WINDOW = 320;

private:
    /// Sequential TraceCollector that records every memory *write* event
    /// (address, size, inst_id, pc). Reads are intentionally skipped: a read
    /// cannot introduce new byte content into memory, so any string visible at a
    /// read address was already produced by an earlier write and will already be
    /// discovered when that write is processed.
    class WriteEventCollector final : public TraceCollector {
    public:
        struct WriteEvent {
            uint64_t inst_id;
            uint64_t pc;
            uint64_t addr;
            uint16_t size;
            uint64_t value;     // low 8 bytes of the written value (for dedup)
            uint64_t value_hi;  // high bytes for 9-16 byte stores
        };

        WriteEventCollector(uint64_t start_inst_id, uint64_t end_inst_id)
            : range_start_(start_inst_id), range_end_(end_inst_id) {}

        std::string_view name() const override { return "WriteEventCollector"; }

        // Parallel scanning support: each shard collects its own write events,
        // then merge() concatenates them.  The events_ vector is the only
        // mutable state, and each shard clone has its own — fully thread-safe.
        bool supports_parallel() const override { return true; }
        std::unique_ptr<TraceCollector> clone() const override {
            return std::make_unique<WriteEventCollector>(range_start_, range_end_);
        }
        void merge(TraceCollector& shard) override {
            auto* other = dynamic_cast<WriteEventCollector*>(&shard);
            if (other) {
                events_.insert(events_.end(),
                               std::make_move_iterator(other->events_.begin()),
                               std::make_move_iterator(other->events_.end()));
            }
        }

        bool begin(uint64_t /*start*/, uint64_t /*end*/) override {
            events_.clear();
            return true;
        }

        void on_inst(uint64_t inst_id, const InstView& inst) override {
            if (inst_id < range_start_ || inst_id >= range_end_) return;

            for (uint8_t m = 0; m < inst.mem_access_count; ++m) {
                auto mem = inst.mem_access(m);
                if (mem.addr == 0) continue;
                // mem_type: bit0 = read, bit1 = write (QBDI::MemoryAccessType).
                bool is_write = (mem.type & 0x02) != 0;
                if (!is_write) continue;

                events_.push_back({inst_id, inst.pc, mem.addr, mem.size, mem.value, mem.value_hi});
            }
        }

        void end() override {}

        const std::vector<WriteEvent>& events() const { return events_; }
        std::vector<WriteEvent> take_events() { return std::move(events_); }

    private:
        uint64_t range_start_;
        uint64_t range_end_;
        std::vector<WriteEvent> events_;
    };

    std::unique_ptr<WriteEventCollector> collector_;
};

}  // namespace tenet
