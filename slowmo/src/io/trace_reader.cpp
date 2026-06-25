#include "io/trace_reader.h"
#include "common/Profiling.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <memory>    // std::make_unique

#if TENET_HAS_ZSTD
#include <zstd.h>
#endif

namespace tenet {

// ─── RecordView implementation ────────────────────────────────────────────

InstView RecordView::as_inst() const {
    // is_v5 / is_v6 / is_v7 are set by Iterator::operator*() or record_at().
    //   is_v7 + is_v5 → qbditrace_inst_head_v7_v5_t (8 bytes)
    //   is_v7         → qbditrace_inst_head_v7_t    (24 bytes)
    //   is_v5         → qbditrace_inst_head_v5_t    (6 bytes)
    //   else          → qbditrace_inst_head_t       (16 bytes)
    //   is_v6 == true → qbditrace_memacc_v6_t (48 bytes) stride in mem_access()
    //   is_v7 == true → FPR diff section between GPR diffs and mems
    InstView v;
    v.is_v5 = is_v5;
    v.is_v6 = is_v6;
    v.is_v7 = is_v7;
    v.fpr_diff_count = 0;
    v.raw_fprdiffs = nullptr;

    if (is_v7 && is_v5) {
        const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_v7_v5_t*>(raw_ptr);
        v.pc = resolved_pc;
        v.nzcv = hdr->nzcv;
        v.reg_diff_count  = hdr->n_regdiff;
        v.fpr_diff_count  = hdr->n_fprdiff;
        v.mem_access_count = hdr->n_mem;
        v.raw_diffs = raw_ptr + sizeof(qbditrace::qbditrace_inst_head_v7_v5_t);
    } else if (is_v7) {
        const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_v7_t*>(raw_ptr);
        v.pc = hdr->pc;
        v.nzcv = hdr->nzcv;
        v.reg_diff_count  = hdr->n_regdiff;
        v.fpr_diff_count  = hdr->n_fprdiff;
        v.mem_access_count = hdr->n_mem;
        v.raw_diffs = raw_ptr + sizeof(qbditrace::qbditrace_inst_head_v7_t);
    } else if (is_v5) {
        const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_v5_t*>(raw_ptr);
        v.pc = resolved_pc;
        v.nzcv = hdr->nzcv;
        v.reg_diff_count  = hdr->n_regdiff;
        v.mem_access_count = hdr->n_mem;
        v.raw_diffs = raw_ptr + sizeof(qbditrace::qbditrace_inst_head_v5_t);
    } else {
        const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_t*>(raw_ptr);
        v.pc = hdr->pc;
        v.nzcv = hdr->nzcv;
        v.reg_diff_count  = hdr->n_regdiff;
        v.mem_access_count = hdr->n_mem;
        v.raw_diffs = raw_ptr + sizeof(qbditrace::qbditrace_inst_head_t);
    }

    // FPR diffs (v7 only) come right after the GPR diff section.
    v.raw_fprdiffs = v.raw_diffs + v.reg_diff_count * sizeof(qbditrace::qbditrace_regdiff_t);
    // Memory accesses come after the FPR diff section.
    v.raw_mems = v.raw_fprdiffs + v.fpr_diff_count * sizeof(qbditrace::qbditrace_fprdiff_t);
    return v;
}

AnchorView RecordView::as_anchor(uint32_t num_gpr) const {
    const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_anchor_head_t*>(raw_ptr);
    AnchorView v;
    v.pc = hdr->pc;
    v.num_gpr = num_gpr;
    const uint8_t* gpr_start = raw_ptr + sizeof(qbditrace::qbditrace_anchor_head_t);
    v.gpr_values = reinterpret_cast<const uint64_t*>(gpr_start);
    // v7: FPR snapshot appended after GPR block.
    // Layout: 32 × lo (u64) followed by 32 × hi (u64).
    if (is_v7) {
        const uint8_t* fpr_start = gpr_start + num_gpr * 8;
        v.fpr_lo  = reinterpret_cast<const uint64_t*>(fpr_start);
        v.fpr_hi  = v.fpr_lo + QBDITRACE_AARCH64_NUM_FPR;
        v.has_fpr = true;
    }
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
        // is_v5 / is_v6 / is_v7 select the correct header and struct sizes.
        const uint8_t* p = raw_ptr;
        size_t hdr_size;
        uint8_t n_regdiff, n_fprdiff = 0, n_mem;
        if (is_v7 && is_v5) {
            hdr_size = sizeof(qbditrace::qbditrace_inst_head_v7_v5_t);
            const auto* h = reinterpret_cast<const qbditrace::qbditrace_inst_head_v7_v5_t*>(p);
            n_regdiff = h->n_regdiff; n_fprdiff = h->n_fprdiff; n_mem = h->n_mem;
        } else if (is_v7) {
            hdr_size = sizeof(qbditrace::qbditrace_inst_head_v7_t);
            const auto* h = reinterpret_cast<const qbditrace::qbditrace_inst_head_v7_t*>(p);
            n_regdiff = h->n_regdiff; n_fprdiff = h->n_fprdiff; n_mem = h->n_mem;
        } else if (is_v5) {
            hdr_size = sizeof(qbditrace::qbditrace_inst_head_v5_t);
            const auto* h = reinterpret_cast<const qbditrace::qbditrace_inst_head_v5_t*>(p);
            n_regdiff = h->n_regdiff; n_mem = h->n_mem;
        } else {
            hdr_size = sizeof(qbditrace::qbditrace_inst_head_t);
            const auto* h = reinterpret_cast<const qbditrace::qbditrace_inst_head_t*>(p);
            n_regdiff = h->n_regdiff; n_mem = h->n_mem;
        }
        size_t memacc_sz = is_v6
            ? sizeof(qbditrace::qbditrace_memacc_v6_t)
            : sizeof(qbditrace::qbditrace_memacc_t);
        return hdr_size
            + n_regdiff  * sizeof(qbditrace::qbditrace_regdiff_t)
            + n_fprdiff  * sizeof(qbditrace::qbditrace_fprdiff_t)
            + n_mem      * memacc_sz;
    }
    case RecordKind::Anchor: {
        size_t fpr_bytes = is_v7 ? QBDITRACE_AARCH64_FPR_SNAPSHOT_BYTES : 0;
        return sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr * 8 + fpr_bytes;
    }
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
      header_(std::move(other.header_)),
      temp_path_(std::move(other.temp_path_)) {
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
        temp_path_ = std::move(other.temp_path_);
        other.fd_ = -1;
        other.mapped_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

Result<TraceReader> TraceReader::open(const std::filesystem::path& path) {
    TENET_ZONE_NAMED("TraceReader::open");
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

    // Accept v4, v5 (PC-delta), v6 (old-value), and v7 (FPR) trace files.
    // v5 is identified by version == QBDITRACE_VERSION_V5_PC_DELTA (5) and HF_PC_DELTA.
    // v6 is identified by version == QBDITRACE_VERSION_V6_OLD_VALUE (6) and HF_OLD_VALUE.
    // v7 is identified by version == QBDITRACE_VERSION_V7_HAS_FPR (7) and HF_HAS_FPR.
    // Any version may combine PC-delta (HF_PC_DELTA) with its primary flag.
    // Any other version is rejected.
    // Note: QBDITRACE_VERSION_* are #define macros, not namespace members.
    const uint32_t ver = raw_hdr->version;
    const uint64_t flg = raw_hdr->flags;
    bool version_ok = false;
    if (ver == TRACE_VERSION)
        version_ok = true;  // v4 baseline
    if (ver == QBDITRACE_VERSION_V5_PC_DELTA && (flg & qbditrace::QBDITRACE_HF_PC_DELTA))
        version_ok = true;
    if (ver == QBDITRACE_VERSION_V6_OLD_VALUE && (flg & qbditrace::QBDITRACE_HF_OLD_VALUE))
        version_ok = true;
    if (ver == QBDITRACE_VERSION_V7_HAS_FPR  && (flg & qbditrace::QBDITRACE_HF_HAS_FPR))
        version_ok = true;
    if (!version_ok) {
        uint32_t bad_version = raw_hdr->version;  // read before munmap
        reader.close();
        return Error::version_mismatch(bad_version, TRACE_VERSION_MAX);
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

    // ── Handle compressed traces ─────────────────────────────────────────
    if (reader.header_.flags & qbditrace::QBDITRACE_HF_COMPRESSED) {
#if TENET_HAS_ZSTD
        // Transfer ownership of the raw mmap/fd to decompress_to_temp,
        // which will release them and replace with the decompressed file.
        int raw_fd = reader.fd_;
        void* raw_mapped = reader.mapped_;
        uint64_t raw_size = reader.size_;
        reader.fd_ = -1;
        reader.mapped_ = nullptr;
        reader.size_ = 0;
        return decompress_to_temp(std::move(reader), raw_fd, raw_mapped, raw_size);
#else
        reader.close();
        return Error(ErrorCode::MmapFailed,
                     "Compressed trace requires zstd support, but tenet was "
                     "built without TENET_HAS_ZSTD");
#endif
    }

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
    // Clean up the temp file created for decompressed traces.
    if (!temp_path_.empty()) {
        std::filesystem::remove(temp_path_);
        temp_path_.clear();
    }
}

// ─── Decompression (zstd) ─────────────────────────────────────────────────

#if TENET_HAS_ZSTD

Result<TraceReader> TraceReader::decompress_to_temp(
    TraceReader&& reader, int raw_fd, void* raw_mapped, uint64_t raw_size)
{
    constexpr size_t kHeaderSize = sizeof(qbditrace::qbditrace_file_header_t);
    const auto* src = static_cast<const uint8_t*>(raw_mapped);
    const uint8_t* compressed_start = src + kHeaderSize;
    size_t compressed_size = raw_size - kHeaderSize;

    // Create a temp file for the decompressed trace.
    // Use the original file's directory so we stay on the same filesystem
    // (avoids cross-device issues and keeps the temp near the source).
    auto temp_dir = reader.path_.parent_path();
    auto temp_template = temp_dir / ".tenet-decomp-XXXXXX";
    // mkstemp needs a mutable char buffer.
    std::string temp_str = temp_template.string();
    int tmp_fd = ::mkstemp(temp_str.data());
    if (tmp_fd < 0) {
        // Fallback: try /tmp if the source directory is read-only
        temp_str = "/tmp/.tenet-decomp-XXXXXX";
        tmp_fd = ::mkstemp(temp_str.data());
    }
    if (tmp_fd < 0) {
        ::munmap(raw_mapped, raw_size);
        ::close(raw_fd);
        return Error(ErrorCode::MmapFailed,
                     std::string("Failed to create temp file for decompression: ") +
                     strerror(errno));
    }
    std::filesystem::path temp_path(temp_str);

    // Write the header first (with HF_COMPRESSED flag cleared).
    qbditrace::qbditrace_file_header_t hdr;
    std::memcpy(&hdr, src, kHeaderSize);
    hdr.flags &= ~static_cast<uint64_t>(qbditrace::QBDITRACE_HF_COMPRESSED);
    if (::write(tmp_fd, &hdr, kHeaderSize) != static_cast<ssize_t>(kHeaderSize)) {
        ::close(tmp_fd);
        std::filesystem::remove(temp_path);
        ::munmap(raw_mapped, raw_size);
        ::close(raw_fd);
        return Error(ErrorCode::MmapFailed, "Failed to write header to temp file");
    }

    // Streaming decompression using ZSTD_DCtx.
    ZSTD_DCtx* dctx = ZSTD_createDCtx();
    if (!dctx) {
        ::close(tmp_fd);
        std::filesystem::remove(temp_path);
        ::munmap(raw_mapped, raw_size);
        ::close(raw_fd);
        return Error(ErrorCode::MmapFailed, "ZSTD_createDCtx failed");
    }

    // Use a 256K output buffer — balances syscall overhead and memory use.
    constexpr size_t kOutBufSize = 256 * 1024;
    auto out_buf = std::make_unique<uint8_t[]>(kOutBufSize);

    ZSTD_inBuffer in = { compressed_start, compressed_size, 0 };
    bool ok = true;
    std::string err_msg;

    while (in.pos < in.size) {
        ZSTD_outBuffer out = { out_buf.get(), kOutBufSize, 0 };
        size_t ret = ZSTD_decompressStream(dctx, &out, &in);
        if (ZSTD_isError(ret)) {
            err_msg = std::string("zstd decompression error: ") +
                      ZSTD_getErrorName(ret);
            ok = false;
            break;
        }
        if (out.pos > 0) {
            ssize_t written = ::write(tmp_fd, out_buf.get(), out.pos);
            if (written != static_cast<ssize_t>(out.pos)) {
                err_msg = std::string("write to temp file failed: ") +
                          strerror(errno);
                ok = false;
                break;
            }
        }
    }

    ZSTD_freeDCtx(dctx);

    // Release the original compressed file resources.
    ::munmap(raw_mapped, raw_size);
    ::close(raw_fd);

    if (!ok) {
        ::close(tmp_fd);
        std::filesystem::remove(temp_path);
        return Error(ErrorCode::MmapFailed, err_msg);
    }

    // Get the decompressed file size.
    struct stat st{};
    if (fstat(tmp_fd, &st) < 0) {
        ::close(tmp_fd);
        std::filesystem::remove(temp_path);
        return Error(ErrorCode::MmapFailed,
                     std::string("fstat on decompressed temp file failed: ") +
                     strerror(errno));
    }
    uint64_t decompressed_size = static_cast<uint64_t>(st.st_size);

    // mmap the decompressed file.
    void* mapped = ::mmap(nullptr, decompressed_size, PROT_READ,
                          MAP_PRIVATE | MAP_NORESERVE, tmp_fd, 0);
    if (mapped == MAP_FAILED) {
        ::close(tmp_fd);
        std::filesystem::remove(temp_path);
        return Error(ErrorCode::MmapFailed,
                     std::string("mmap decompressed temp file failed: ") +
                     strerror(errno));
    }

    // Update the reader to point at the decompressed data.
    reader.fd_ = tmp_fd;
    reader.mapped_ = mapped;
    reader.size_ = decompressed_size;
    reader.temp_path_ = temp_path;
    // Clear the compressed flag in the in-memory header so downstream code
    // does not attempt to decompress again.
    reader.header_.flags &= ~static_cast<uint64_t>(qbditrace::QBDITRACE_HF_COMPRESSED);

    return std::move(reader);
}

#else  // !TENET_HAS_ZSTD

Result<TraceReader> TraceReader::decompress_to_temp(
    TraceReader&& /*reader*/, int raw_fd, void* raw_mapped, uint64_t raw_size)
{
    ::munmap(raw_mapped, raw_size);
    ::close(raw_fd);
    return Error(ErrorCode::MmapFailed,
                 "Compressed trace requires zstd support, but tenet was "
                 "built without TENET_HAS_ZSTD");
}

#endif  // TENET_HAS_ZSTD

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
    const bool use_fpr       = (flags & qbditrace::QBDITRACE_HF_HAS_FPR)   != 0;

    // Propagate is_v5 / is_v6 / is_v7 so as_inst() and mem_access() use
    // the right struct layout.
    rv.is_v5 = use_pc_delta;
    rv.is_v6 = use_old_value;
    rv.is_v7 = use_fpr;

    if (rv.kind == RecordKind::Inst && use_pc_delta) {
        // v5/v6+v5/v7+v5: reconstruct absolute PC from pc_delta.
        // The pc_delta field is at the same offset in v5, v7+v5 headers.
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
        const bool use_fpr       = (flags & qbditrace::QBDITRACE_HF_HAS_FPR)   != 0;
        size_t memacc_sz = use_old_value
            ? sizeof(qbditrace::qbditrace_memacc_v6_t)
            : sizeof(qbditrace::qbditrace_memacc_t);
        if (use_fpr && use_pc_delta) {
            const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_v7_v5_t*>(ptr);
            rec_size = sizeof(qbditrace::qbditrace_inst_head_v7_v5_t)
                + hdr->n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)
                + hdr->n_fprdiff * sizeof(qbditrace::qbditrace_fprdiff_t)
                + hdr->n_mem * memacc_sz;
        } else if (use_fpr) {
            const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_v7_t*>(ptr);
            rec_size = sizeof(qbditrace::qbditrace_inst_head_v7_t)
                + hdr->n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)
                + hdr->n_fprdiff * sizeof(qbditrace::qbditrace_fprdiff_t)
                + hdr->n_mem * memacc_sz;
        } else if (use_pc_delta) {
            const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_v5_t*>(ptr);
            rec_size = sizeof(qbditrace::qbditrace_inst_head_v5_t)
                + hdr->n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)
                + hdr->n_mem * memacc_sz;
        } else {
            const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_t*>(ptr);
            rec_size = sizeof(qbditrace::qbditrace_inst_head_t)
                + hdr->n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)
                + hdr->n_mem * memacc_sz;
        }
        break;
    }
    case RecordKind::Anchor: {
        const bool use_fpr = (reader_->header_.flags & qbditrace::QBDITRACE_HF_HAS_FPR) != 0;
        size_t fpr_bytes = use_fpr ? QBDITRACE_AARCH64_FPR_SNAPSHOT_BYTES : 0;
        rec_size = sizeof(qbditrace::qbditrace_anchor_head_t)
            + reader_->header_.num_gpr * sizeof(uint64_t)
            + fpr_bytes;
        break;
    }
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
