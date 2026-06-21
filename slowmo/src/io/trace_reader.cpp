#include "io/trace_reader.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstring>

namespace tenet {

// ─── RecordView implementation ────────────────────────────────────────────

InstView RecordView::as_inst() const {
    // is_v5 / is_v6 are set by Iterator::operator*() or record_at(offset, seed_pc).
    // They select the correct on-disk struct layout:
    //   is_v5 == true  → qbditrace_inst_head_v5_t (6 bytes); pc from resolved_pc
    //   is_v5 == false → qbditrace_inst_head_t    (16 bytes); pc from raw struct
    //   is_v6 == true  → qbditrace_memacc_v6_t (48 bytes) stride in mem_access()
    //   is_v6 == false → qbditrace_memacc_t    (32 bytes) stride
    if (is_v5) {
        // v5 (or v5+v6): header is qbditrace_inst_head_v5_t (6 bytes)
        const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_v5_t*>(raw_ptr);
        InstView v;
        v.pc = resolved_pc;  // set by Iterator or record_at(offset, seed_pc)
        v.nzcv = hdr->nzcv;
        v.reg_diff_count = hdr->n_regdiff;
        v.mem_access_count = hdr->n_mem;
        v.raw_diffs = raw_ptr + sizeof(qbditrace::qbditrace_inst_head_v5_t);
        v.raw_mems = v.raw_diffs + v.reg_diff_count * sizeof(qbditrace::qbditrace_regdiff_t);
        v.is_v5 = true;
        v.is_v6 = is_v6;
        return v;
    }
    // v4 (or v4+v6): header is qbditrace_inst_head_t (16 bytes)
    const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_t*>(raw_ptr);
    InstView v;
    v.pc = hdr->pc;
    v.nzcv = hdr->nzcv;
    v.reg_diff_count = hdr->n_regdiff;
    v.mem_access_count = hdr->n_mem;
    v.raw_diffs = raw_ptr + sizeof(qbditrace::qbditrace_inst_head_t);
    v.raw_mems = v.raw_diffs + v.reg_diff_count * sizeof(qbditrace::qbditrace_regdiff_t);
    v.is_v5 = false;
    v.is_v6 = is_v6;
    return v;
}

AnchorView RecordView::as_anchor(uint32_t num_gpr) const {
    const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_anchor_head_t*>(raw_ptr);
    AnchorView v;
    v.pc = hdr->pc;
    v.num_gpr = num_gpr;
    v.gpr_values = reinterpret_cast<const uint64_t*>(raw_ptr + sizeof(qbditrace::qbditrace_anchor_head_t));
    return v;
}

CodeView RecordView::as_code() const {
    const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_code_head_t*>(raw_ptr);
    CodeView v;
    v.pc = hdr->pc;
    v.size = hdr->size;
    v.bytes = raw_ptr + sizeof(qbditrace::qbditrace_code_head_t);
    return v;
}

EventView RecordView::as_event() const {
    const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_event_head_t*>(raw_ptr);
    EventView v;
    v.event = hdr->event;
    v.addr = hdr->addr;
    v.site = hdr->site;
    return v;
}

SvcView RecordView::as_svc() const {
    const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_svc_head_t*>(raw_ptr);
    SvcView v;
    v.pc = hdr->pc;
    v.syscall_no = hdr->syscall_no;
    v.args = hdr->args;
    return v;
}

ObjcView RecordView::as_objc() const {
    const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_objc_head_t*>(raw_ptr);
    ObjcView v;
    v.variant = hdr->variant;
    v.pc = hdr->pc;
    v.recv = hdr->recv;
    v.sel = hdr->sel;
    v.cls = hdr->cls;
    return v;
}

ThreadView RecordView::as_thread() const {
    const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_thread_head_t*>(raw_ptr);
    ThreadView v;
    v.thread_id = hdr->thread_id;
    return v;
}

size_t RecordView::byte_size(uint32_t num_gpr) const {
    switch (kind) {
    case RecordKind::Inst: {
        // is_v5 / is_v6 select the correct header and memacc struct sizes.
        const uint8_t* p = raw_ptr;
        size_t hdr_size = is_v5
            ? sizeof(qbditrace::qbditrace_inst_head_v5_t)
            : sizeof(qbditrace::qbditrace_inst_head_t);
        size_t memacc_sz = is_v6
            ? sizeof(qbditrace::qbditrace_memacc_v6_t)
            : sizeof(qbditrace::qbditrace_memacc_t);
        uint8_t n_regdiff, n_mem;
        if (is_v5) {
            const auto* h = reinterpret_cast<const qbditrace::qbditrace_inst_head_v5_t*>(p);
            n_regdiff = h->n_regdiff;
            n_mem = h->n_mem;
        } else {
            const auto* h = reinterpret_cast<const qbditrace::qbditrace_inst_head_t*>(p);
            n_regdiff = h->n_regdiff;
            n_mem = h->n_mem;
        }
        return hdr_size
            + n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)
            + n_mem     * memacc_sz;
    }
    case RecordKind::Anchor:
        return sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr * 8;
    case RecordKind::Thread:
        return sizeof(qbditrace::qbditrace_thread_head_t);
    case RecordKind::Event:
        return sizeof(qbditrace::qbditrace_event_head_t);
    case RecordKind::Svc:
        return sizeof(qbditrace::qbditrace_svc_head_t);
    case RecordKind::Objc:
        return sizeof(qbditrace::qbditrace_objc_head_t);
    case RecordKind::Code: {
        auto code = as_code();
        return code.byte_size();
    }
    }
    return 1;  // unknown kind, skip 1 byte (shouldn't happen)
}

// ─── TraceReader implementation ───────────────────────────────────────────

TraceReader::~TraceReader() {
    close();
}

TraceReader::TraceReader(TraceReader&& other) noexcept
    : path_(std::move(other.path_)),
      fd_(other.fd_),
      mapped_(other.mapped_),
      size_(other.size_),
      header_(std::move(other.header_)) {
    other.fd_ = -1;
    other.mapped_ = nullptr;
    other.size_ = 0;
}

TraceReader& TraceReader::operator=(TraceReader&& other) noexcept {
    if (this != &other) {
        close();
        path_ = std::move(other.path_);
        fd_ = other.fd_;
        mapped_ = other.mapped_;
        size_ = other.size_;
        header_ = std::move(other.header_);
        other.fd_ = -1;
        other.mapped_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

Result<TraceReader> TraceReader::open(const std::filesystem::path& path) {
    TraceReader reader;
    reader.path_ = path;

    // Open file
    reader.fd_ = ::open(path.c_str(), O_RDONLY);
    if (reader.fd_ < 0) {
        return Error::file_not_found(path.string());
    }

    // Get file size
    struct stat st{};
    if (fstat(reader.fd_, &st) < 0) {
        ::close(reader.fd_);
        return Error::mmap_failed("fstat failed");
    }
    reader.size_ = static_cast<uint64_t>(st.st_size);

    // Validate minimum size (at least file header)
    if (reader.size_ < sizeof(qbditrace::qbditrace_file_header_t)) {
        ::close(reader.fd_);
        return Error::invalid_magic();
    }

    // mmap the entire file read-only
    reader.mapped_ = ::mmap(nullptr, reader.size_, PROT_READ,
                            MAP_PRIVATE | MAP_NORESERVE, reader.fd_, 0);
    if (reader.mapped_ == MAP_FAILED) {
        ::close(reader.fd_);
        return Error::mmap_failed(strerror(errno));
    }

    // Parse file header
    const auto* raw_hdr = static_cast<const qbditrace::qbditrace_file_header_t*>(reader.mapped_);

    if (raw_hdr->magic != TRACE_MAGIC) {
        reader.close();
        return Error::invalid_magic();
    }

    // Accept v4, v5 (PC-delta), and v6 (old-value) trace files.
    // v5 is identified by version == QBDITRACE_VERSION_V5_PC_DELTA (5) and HF_PC_DELTA.
    // v6 is identified by version == QBDITRACE_VERSION_V6_OLD_VALUE (6) and HF_OLD_VALUE.
    // v6 may also combine with PC-delta encoding (both flags set).
    // Any other version is rejected.
    bool is_v4 = (raw_hdr->version == TRACE_VERSION);
    // Note: QBDITRACE_VERSION_V5_PC_DELTA and QBDITRACE_VERSION_V6_OLD_VALUE are
    // #define macros (not namespace members), so they must not be qualified.
    bool is_v5 = (raw_hdr->version == QBDITRACE_VERSION_V5_PC_DELTA &&
                  (raw_hdr->flags & qbditrace::QBDITRACE_HF_PC_DELTA));
    bool is_v6 = (raw_hdr->version == QBDITRACE_VERSION_V6_OLD_VALUE &&
                  (raw_hdr->flags & qbditrace::QBDITRACE_HF_OLD_VALUE));
    // v6 can also use PC-delta encoding (HF_PC_DELTA + HF_OLD_VALUE + version==6)
    if (!is_v4 && !is_v5 && !is_v6) {
        uint32_t bad_version = raw_hdr->version;  // read before munmap
        reader.close();
        return Error::version_mismatch(bad_version, TRACE_VERSION);
    }

    reader.header_.magic = raw_hdr->magic;
    reader.header_.version = raw_hdr->version;
    reader.header_.arch = raw_hdr->arch;
    reader.header_.num_gpr = raw_hdr->num_gpr;
    reader.header_.module_base = raw_hdr->module_base;
    reader.header_.module_slide = raw_hdr->module_slide;
    reader.header_.trace_start = raw_hdr->trace_start;
    reader.header_.trace_end = raw_hdr->trace_end;
    reader.header_.flags = raw_hdr->flags;
    reader.header_.module_name = std::string(raw_hdr->module_name);

    return reader;
}

void TraceReader::close() {
    if (mapped_ && mapped_ != MAP_FAILED) {
        ::munmap(mapped_, size_);
        mapped_ = nullptr;
    }
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    size_ = 0;
}

RecordView TraceReader::record_at(uint64_t offset) const {
    const uint8_t* ptr = data() + offset;
    RecordView rv;
    rv.kind = static_cast<RecordKind>(ptr[0]);
    rv.file_offset = offset;
    rv.raw_ptr = ptr;
    return rv;
}

RecordView TraceReader::Iterator::operator*() const {
    RecordView rv = reader_->record_at(offset_);

    const uint64_t flags = reader_->header_.flags;
    const bool use_pc_delta  = (flags & qbditrace::QBDITRACE_HF_PC_DELTA)  != 0;
    const bool use_old_value = (flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0;

    // Propagate is_v5 / is_v6 so as_inst() and mem_access() use the right struct layout.
    rv.is_v5 = use_pc_delta;
    rv.is_v6 = use_old_value;

    if (rv.kind == RecordKind::Inst && use_pc_delta) {
        // v5/v6+v5: reconstruct absolute PC from pc_delta.
        const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_v5_t*>(rv.raw_ptr);
        int16_t delta;
        std::memcpy(&delta, &hdr->pc_delta, sizeof(delta));  // LE decode
        uint64_t new_pc = current_pc_ + static_cast<int64_t>(delta);
        rv.resolved_pc = new_pc;
        current_pc_ = new_pc;  // advance state
    } else if (rv.kind == RecordKind::Anchor && use_pc_delta) {
        // Anchor carries absolute PC — resync running_pc
        const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_anchor_head_t*>(rv.raw_ptr);
        current_pc_ = hdr->pc;
    }

    return rv;
}

TraceReader::Iterator& TraceReader::Iterator::operator++() {
    // ── Performance optimization ──────────────────────────────────────────
    // Old code called `**this` (operator*) then byte_size(), meaning every
    // record was fully parsed TWICE: once in the loop body's `*it`, once here.
    // For GB-level traces (100M+ records) this doubled the parsing cost.
    //
    // New approach: compute byte_size directly from the raw header byte.
    // For v5 PC-delta mode we still need to update current_pc_ here only if
    // the caller did NOT call operator*() (which is unusual — defensive).
    // In the normal `for(*it; ++it)` pattern, current_pc_ was already updated
    // by operator*() in the loop body.

    const uint8_t* ptr = reader_->data() + offset_;
    auto kind = static_cast<RecordKind>(ptr[0]);
    size_t rec_size = 0;

    switch (kind) {
    case RecordKind::Inst: {
        const uint64_t flags = reader_->header_.flags;
        const bool use_pc_delta  = (flags & qbditrace::QBDITRACE_HF_PC_DELTA) != 0;
        const bool use_old_value = (flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0;
        // v6 uses the 48-byte memacc_v6_t; v4/v5 use the 32-byte memacc_t.
        size_t memacc_sz = use_old_value
            ? sizeof(qbditrace::qbditrace_memacc_v6_t)
            : sizeof(qbditrace::qbditrace_memacc_t);
        if (use_pc_delta) {
            // v5/v6+v5: inst_head_v5 + reg_diffs + mem_accesses
            const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_v5_t*>(ptr);
            rec_size = sizeof(qbditrace::qbditrace_inst_head_v5_t)
                + hdr->n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)
                + hdr->n_mem * memacc_sz;
        } else {
            // v4/v6: inst_head + reg_diffs + mem_accesses
            const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_t*>(ptr);
            rec_size = sizeof(qbditrace::qbditrace_inst_head_t)
                + hdr->n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)
                + hdr->n_mem * memacc_sz;
        }
        break;
    }
    case RecordKind::Anchor:
        rec_size = sizeof(qbditrace::qbditrace_anchor_head_t)
            + reader_->header_.num_gpr * sizeof(uint64_t);
        break;
    case RecordKind::Thread:
        rec_size = sizeof(qbditrace::qbditrace_thread_head_t);
        break;
    case RecordKind::Event:
        rec_size = sizeof(qbditrace::qbditrace_event_head_t);
        break;
    case RecordKind::Svc:
        rec_size = sizeof(qbditrace::qbditrace_svc_head_t);
        break;
    case RecordKind::Objc:
        rec_size = sizeof(qbditrace::qbditrace_objc_head_t);
        break;
    case RecordKind::Code:
        rec_size = sizeof(qbditrace::qbditrace_code_head_t)
            + ptr[1]; // code_size is the 2nd byte
        break;
    default:
        // Fallback: parse via RecordView (shouldn't happen in valid traces)
        rec_size = reader_->record_at(offset_).byte_size(reader_->header_.num_gpr);
        break;
    }

    // Prefetch the next record's cache line (hides L2 miss latency)
    __builtin_prefetch(ptr + rec_size, 0, 1);

    offset_ += rec_size;
    return *this;
}

TraceReader::Iterator TraceReader::begin() const {
    // Records start after the 536-byte file header
    return Iterator(this, sizeof(qbditrace::qbditrace_file_header_t));
}

TraceReader::Iterator TraceReader::end() const {
    return Iterator(this, size_);
}

void TraceReader::advise_sequential() const {
    if (mapped_) {
        ::madvise(mapped_, size_, MADV_SEQUENTIAL);
    }
}

void TraceReader::advise_random() const {
    if (mapped_) {
        ::madvise(mapped_, size_, MADV_RANDOM);
    }
}

}  // namespace tenet
