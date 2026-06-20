#pragma once

#include "common/types.h"
#include "TraceFormat.h"

#include <filesystem>
#include <cstring>

namespace tenet {

// ─── Zero-copy record views ───────────────────────────────────────────────

struct RegDiffView {
    uint8_t index;
    uint64_t value;
};

struct MemAccessView {
    uint8_t type;
    uint8_t flags;
    uint16_t size;
    uint64_t addr;
    uint64_t value;        // new value (post-write)
    uint64_t value_hi;     // new value high bytes (9-16 byte stores)
    uint64_t old_value;    // v6: pre-write value (0 if v4/v5 or read access)
    uint64_t old_value_hi; // v6: pre-write high bytes
    bool has_old_value;    // true if this record carries valid old_value data
};

struct InstView {
    uint64_t pc;
    uint8_t nzcv;
    uint8_t reg_diff_count;
    uint8_t mem_access_count;
    const uint8_t* raw_diffs;   // points into mmap region
    const uint8_t* raw_mems;    // points into mmap region
    bool is_v5 = false;  // true when record uses v5 (pc_delta) layout
    bool is_v6 = false;  // true when record uses v6 (old_value) layout

    RegDiffView reg_diff(uint8_t i) const {
        // qbditrace_regdiff_t: u8 reg_index @0, pad[7], u64 value @8
        // stride = sizeof(qbditrace_regdiff_t) (includes padding)
        const uint8_t* p = raw_diffs + i * sizeof(qbditrace::qbditrace_regdiff_t);
        const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_regdiff_t*>(p);
        RegDiffView d;
        d.index = hdr->reg_index;
        d.value = hdr->value;
        return d;
    }

    MemAccessView mem_access(uint8_t i) const {
        MemAccessView m;
        m.old_value     = 0;
        m.old_value_hi  = 0;
        m.has_old_value = false;
        if (is_v6) {
            // v6: qbditrace_memacc_v6_t (48 bytes)
            const uint8_t* p = raw_mems + i * sizeof(qbditrace::qbditrace_memacc_v6_t);
            const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_memacc_v6_t*>(p);
            m.type      = hdr->mem_type;
            m.flags     = hdr->mem_flags;
            m.size      = hdr->size;
            m.addr      = hdr->addr;
            m.value     = hdr->value;
            m.value_hi  = hdr->value_hi;
            // old_value is valid for WRITE accesses when MF_OLD_UNKNOWN is not set.
            // Note: QBDITRACE_MF_OLD_UNKNOWN is a #define (not a namespace member).
            if ((hdr->mem_type & 0x02) &&  // MEMORY_WRITE bit
                !(hdr->mem_flags & QBDITRACE_MF_OLD_UNKNOWN)) {
                m.old_value     = hdr->old_value;
                m.old_value_hi  = hdr->old_value_hi;
                m.has_old_value = true;
            }
        } else {
            // v4/v5: qbditrace_memacc_t (32 bytes)
            const uint8_t* p = raw_mems + i * sizeof(qbditrace::qbditrace_memacc_t);
            const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_memacc_t*>(p);
            m.type      = hdr->mem_type;
            m.flags     = hdr->mem_flags;
            m.size      = hdr->size;
            m.addr      = hdr->addr;
            m.value     = hdr->value;
            m.value_hi  = hdr->value_hi;
        }
        return m;
    }

    // Total byte size of this INST record
    size_t byte_size() const {
        size_t hdr = is_v5
            ? sizeof(qbditrace::qbditrace_inst_head_v5_t)
            : sizeof(qbditrace::qbditrace_inst_head_t);
        // Use sizeof() to respect struct alignment padding in the on-disk layout.
        // qbditrace_regdiff_t:    reg_index(u8) + pad(7) + value(u64) = 16 bytes
        // qbditrace_memacc_t:     type+flags+size(4) + pad(4) + addr+value+value_hi = 32 bytes
        // qbditrace_memacc_v6_t:  same + old_value+old_value_hi = 48 bytes
        size_t memacc_sz = is_v6
            ? sizeof(qbditrace::qbditrace_memacc_v6_t)
            : sizeof(qbditrace::qbditrace_memacc_t);
        return hdr
            + reg_diff_count  * sizeof(qbditrace::qbditrace_regdiff_t)
            + mem_access_count * memacc_sz;
    }
};

struct AnchorView {
    uint64_t pc;
    const uint64_t* gpr_values;  // points to num_gpr uint64_t values in mmap
    uint32_t num_gpr;

    size_t byte_size() const {
        return sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr * 8;
    }
};

struct CodeView {
    uint64_t pc;
    uint8_t size;
    const uint8_t* bytes;  // instruction bytes in mmap

    size_t byte_size() const {
        return sizeof(qbditrace::qbditrace_code_head_t) + size;
    }
};

struct EventView {
    uint8_t event;
    uint64_t addr;
    uint64_t site;

    size_t byte_size() const {
        return sizeof(qbditrace::qbditrace_event_head_t);
    }
};

struct SvcView {
    uint64_t pc;
    uint64_t syscall_no;
    const uint64_t* args;  // 6 args

    size_t byte_size() const {
        return sizeof(qbditrace::qbditrace_svc_head_t);
    }
};

struct ObjcView {
    uint8_t variant;
    uint64_t pc;
    uint64_t recv;
    uint64_t sel;
    const char* cls;  // 48-byte class name

    size_t byte_size() const {
        return sizeof(qbditrace::qbditrace_objc_head_t);
    }
};

struct ThreadView {
    uint64_t thread_id;

    size_t byte_size() const {
        return sizeof(qbditrace::qbditrace_thread_head_t);
    }
};

/// A tagged union view of any trace record.
struct RecordView {
    RecordKind kind;
    uint64_t file_offset;
    const uint8_t* raw_ptr;  // start of record in mmap

    // Resolved absolute PC for this record.
    // - v5 (HF_PC_DELTA): Iterator reconstructs it from pc_delta chain and stores it here;
    //   record_at(offset, seed_pc) stores seed_pc (as computed by offset_of_with_pc).
    // - v4: Iterator and record_at() both leave this 0; as_inst() reads pc from raw_ptr.
    uint64_t resolved_pc = 0;
    // is_v5: true when the INST record uses the 6-byte qbditrace_inst_head_v5_t layout
    //        (HF_PC_DELTA). Set symmetrically with is_v6 by Iterator and record_at().
    bool is_v5 = false;
    // is_v6: true when memory access records use the 48-byte qbditrace_memacc_v6_t layout
    //        (HF_OLD_VALUE). Set by Iterator and record_at().
    bool is_v6 = false;

    // Parse helpers (caller checks kind first)
    InstView as_inst() const;
    AnchorView as_anchor(uint32_t num_gpr) const;
    CodeView as_code() const;
    EventView as_event() const;
    SvcView as_svc() const;
    ObjcView as_objc() const;
    ThreadView as_thread() const;

    /// Compute the byte size of this record (needed to advance to next)
    size_t byte_size(uint32_t num_gpr) const;
};

// ─── File header wrapper ──────────────────────────────────────────────────

struct FileHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t arch;
    uint32_t num_gpr;
    uint64_t module_base;
    uint64_t module_slide;
    uint64_t trace_start;
    uint64_t trace_end;
    uint64_t flags;
    std::string module_name;

    bool has_mem() const       { return flags & qbditrace::QBDITRACE_HF_HAS_MEM; }
    bool has_nzcv() const      { return flags & qbditrace::QBDITRACE_HF_HAS_NZCV; }
    bool has_code() const      { return flags & qbditrace::QBDITRACE_HF_HAS_CODE; }
    bool reg_diff() const      { return flags & qbditrace::QBDITRACE_HF_REG_DIFF; }
    bool has_old_value() const { return flags & qbditrace::QBDITRACE_HF_OLD_VALUE; }
};

// ─── TraceReader ──────────────────────────────────────────────────────────

class TraceReader {
public:
    ~TraceReader();
    TraceReader(TraceReader&& other) noexcept;
    TraceReader& operator=(TraceReader&& other) noexcept;

    // Non-copyable
    TraceReader(const TraceReader&) = delete;
    TraceReader& operator=(const TraceReader&) = delete;

    /// Open a trace file. Returns error if file is invalid.
    static Result<TraceReader> open(const std::filesystem::path& path);

    /// Close and release mmap.
    void close();

    // ─── Accessors ──────────────────────────────────────────────────────
    const FileHeader& header() const { return header_; }
    uint64_t file_size() const { return size_; }
    const std::filesystem::path& path() const { return path_; }

    /// Raw byte access to mmap region (for IndexBuilder etc.)
    const uint8_t* data() const { return static_cast<const uint8_t*>(mapped_); }
    const uint8_t* data_at(uint64_t offset) const { return data() + offset; }

    /// Get a RecordView at a given file offset.
    RecordView record_at(uint64_t offset) const;

    /// Get a RecordView at a given file offset, with a pre-resolved absolute PC.
    /// Use this for v5 (HF_PC_DELTA) traces when calling as_inst() on a record
    /// obtained via random access (not Iterator). `seed_pc` is the absolute PC of
    /// the instruction at `offset`, as computed by offset_of_with_pc().
    /// Sets is_v5 and is_v6 from the file header so as_inst() uses the correct layout.
    RecordView record_at(uint64_t offset, uint64_t seed_pc) const {
        RecordView rv = record_at(offset);
        rv.resolved_pc = seed_pc;
        rv.is_v5 = (header_.flags & qbditrace::QBDITRACE_HF_PC_DELTA) != 0;
        rv.is_v6 = (header_.flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0;
        return rv;
    }

    // ─── Sequential iteration ───────────────────────────────────────────

    class Iterator {
    public:
        Iterator(const TraceReader* reader, uint64_t offset)
            : reader_(reader), offset_(offset), current_pc_(0) {}

        // Constructor with a pre-seeded `current_pc` for v5 mid-stream seek.
        Iterator(const TraceReader* reader, uint64_t offset, uint64_t seed_pc)
            : reader_(reader), offset_(offset), current_pc_(seed_pc) {}

        RecordView operator*() const;
        Iterator& operator++();
        bool operator==(const Iterator& other) const { return offset_ >= other.offset_; }
        bool operator!=(const Iterator& other) const { return !(*this == other); }

        /// Current PC state (valid after at least one INST record in v5 mode).
        uint64_t current_pc() const { return current_pc_; }

    private:
        const TraceReader* reader_;
        uint64_t offset_;
        mutable uint64_t current_pc_;  // running PC for HF_PC_DELTA reconstruction
    };

    Iterator begin() const;
    Iterator end() const;

    /// Set madvise hint for access pattern
    void advise_sequential() const;
    void advise_random() const;

private:
    TraceReader() = default;

    std::filesystem::path path_;
    int fd_ = -1;
    void* mapped_ = nullptr;
    uint64_t size_ = 0;
    FileHeader header_;
};

}  // namespace tenet
