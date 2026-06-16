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
    const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_t*>(raw_ptr);
    InstView v;
    v.pc = hdr->pc;
    v.nzcv = hdr->nzcv;
    v.reg_diff_count = hdr->n_regdiff;
    v.mem_access_count = hdr->n_mem;
    v.raw_diffs = raw_ptr + sizeof(qbditrace::qbditrace_inst_head_t);
    v.raw_mems = v.raw_diffs + v.reg_diff_count * 9;
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
        auto inst = as_inst();
        return inst.byte_size();
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

    if (raw_hdr->version != TRACE_VERSION) {
        reader.close();
        return Error::version_mismatch(raw_hdr->version, TRACE_VERSION);
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

TraceReader::Iterator& TraceReader::Iterator::operator++() {
    auto rec = reader_->record_at(offset_);
    offset_ += rec.byte_size(reader_->header_.num_gpr);
    return *this;
}

TraceReader::Iterator TraceReader::begin() const {
    // Records start after the 512-byte file header
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
