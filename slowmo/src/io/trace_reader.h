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
    uint64_t value;
    uint64_t value_hi;
};

struct InstView {
    uint64_t pc;
    uint8_t nzcv;
    uint8_t reg_diff_count;
    uint8_t mem_access_count;
    const uint8_t* raw_diffs;   // points into mmap region
    const uint8_t* raw_mems;    // points into mmap region

    RegDiffView reg_diff(uint8_t i) const {
        // Each regdiff is 9 bytes: u8 index + u64 value (packed, little-endian)
        const uint8_t* p = raw_diffs + i * 9;
        RegDiffView d;
        d.index = p[0];
        std::memcpy(&d.value, p + 1, 8);
        return d;
    }

    MemAccessView mem_access(uint8_t i) const {
        // Each memacc is 28 bytes: u8+u8+u16+u64+u64+u64
        const uint8_t* p = raw_mems + i * 28;
        MemAccessView m;
        m.type = p[0];
        m.flags = p[1];
        std::memcpy(&m.size, p + 2, 2);
        std::memcpy(&m.addr, p + 4, 8);
        std::memcpy(&m.value, p + 12, 8);
        std::memcpy(&m.value_hi, p + 20, 8);
        return m;
    }

    // Total byte size of this INST record
    size_t byte_size() const {
        return sizeof(qbditrace::qbditrace_inst_head_t) +
               reg_diff_count * 9 +
               mem_access_count * 28;
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

    bool has_mem() const  { return flags & qbditrace::QBDITRACE_HF_HAS_MEM; }
    bool has_nzcv() const { return flags & qbditrace::QBDITRACE_HF_HAS_NZCV; }
    bool has_code() const { return flags & qbditrace::QBDITRACE_HF_HAS_CODE; }
    bool reg_diff() const { return flags & qbditrace::QBDITRACE_HF_REG_DIFF; }
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

    // ─── Sequential iteration ───────────────────────────────────────────

    class Iterator {
    public:
        Iterator(const TraceReader* reader, uint64_t offset)
            : reader_(reader), offset_(offset) {}

        RecordView operator*() const { return reader_->record_at(offset_); }
        Iterator& operator++();
        bool operator==(const Iterator& other) const { return offset_ >= other.offset_; }
        bool operator!=(const Iterator& other) const { return !(*this == other); }

    private:
        const TraceReader* reader_;
        uint64_t offset_;
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
