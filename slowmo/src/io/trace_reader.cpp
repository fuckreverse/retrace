#include "io/trace_reader.h"
#include "common/Profiling.h"
#include "common/logger.h"
#include "common/platform_mmap.h"

#include <fmt/format.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <memory>    // std::make_unique
#include <algorithm>

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
    v.flags = hdr->reserved[0];
    return v;
}

ObjcView RecordView::as_objc() const {
    ObjcView v;
    v.is_v8 = is_v8;
    if (is_v8) {
        const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_objc_head_v8_t*>(raw_ptr);
        v.variant = hdr->variant;
        v.sel_len = hdr->sel_len;
        v.flags = hdr->flags;
        v.pc = hdr->pc;
        v.recv = hdr->recv;
        v.sel = hdr->sel;
        v.cls = hdr->cls;
        v.selector_name = reinterpret_cast<const char*>(raw_ptr + sizeof(*hdr));
    } else {
        const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_objc_head_t*>(raw_ptr);
        v.variant = hdr->variant;
        v.pc = hdr->pc;
        v.recv = hdr->recv;
        v.sel = hdr->sel;
        v.cls = hdr->cls;
    }
    return v;
}

CapiCallView RecordView::as_capicall() const {
    CapiCallView v;
    v.is_v8 = is_v8;
    if (is_v8) {
        const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_capicall_head_v8_t*>(raw_ptr);
        v.api_id    = hdr->api_id;
        v.arg_count = hdr->arg_count;
        v.str_count = hdr->str_count;
        v.pc        = hdr->pc;
        v.target    = hdr->target;
        v.args      = hdr->args;
    } else {
        const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_capicall_head_t*>(raw_ptr);
        v.api_id    = hdr->api_id;  // uint8_t -> uint16_t, zero-extended
        v.arg_count = hdr->arg_count;
        v.str_count = hdr->str_count;
        v.pc        = hdr->pc;
        v.target    = hdr->target;
        v.args      = hdr->args;
    }
    return v;
}

ThreadView RecordView::as_thread() const {
    const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_thread_head_t*>(raw_ptr);
    ThreadView v;
    v.thread_id = hdr->thread_id;
    return v;
}

MemImgView RecordView::as_memimg() const {
    qbditrace::qbditrace_memimg_t hdr{};
    std::memcpy(&hdr, raw_ptr, std::min(available_size, sizeof(hdr)));
    return {hdr.seq, hdr.addr, hdr.len,
            raw_ptr + sizeof(qbditrace::qbditrace_memimg_t)};
}

RetvalView RecordView::as_retval() const {
    qbditrace::qbditrace_retval_t hdr{};
    std::memcpy(&hdr, raw_ptr, std::min(available_size, sizeof(hdr)));
    int32_t errno_before = 0;
    int32_t errno_after = 0;
    constexpr size_t errno_extension_size = sizeof(int32_t) * 2;
    if ((hdr.flags & QBDITRACE_RET_FL_ERRNO_VALID) != 0 &&
        hdr.record_size >= sizeof(hdr) + errno_extension_size &&
        available_size >= sizeof(hdr) + errno_extension_size) {
        std::memcpy(&errno_before, raw_ptr + sizeof(hdr), sizeof(errno_before));
        std::memcpy(&errno_after, raw_ptr + sizeof(hdr) + sizeof(errno_before),
                    sizeof(errno_after));
    }
    return {hdr.source_kind, hdr.flags, hdr.aux_id, hdr.record_size,
            hdr.source_id, hdr.site, hdr.target, hdr.resume, hdr.x0,
            hdr.x1, hdr.nzcv, errno_before, errno_after, available_size};
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
        return as_objc().byte_size();
    case RecordKind::CapiCall: {
        auto cc = as_capicall();
        return cc.byte_size();
    }
    case RecordKind::Code: {
        auto code = as_code();
        return code.byte_size();
    }
    case RecordKind::Retval:
        return as_retval().byte_size();
    case RecordKind::MemImg:
        return as_memimg().byte_size();
    }
    return 1;  // unknown kind, skip 1 byte (shouldn't happen)
}

// ─── TraceReader implementation ───────────────────────────────────────────

TraceReader::~TraceReader() {
    close();
}

TraceReader::TraceReader(TraceReader&& other) noexcept
    : path_(std::move(other.path_)),
      mapped_file_(std::move(other.mapped_file_)),
      logical_size_(other.logical_size_),
      header_size_(other.header_size_),
      header_(std::move(other.header_)),
      temp_path_(std::move(other.temp_path_)),
      block_cache_(std::move(other.block_cache_)) {
    other.logical_size_ = 0;
}

TraceReader& TraceReader::operator=(TraceReader&& other) noexcept {
    if (this != &other) {
        close();
        path_ = std::move(other.path_);
        mapped_file_ = std::move(other.mapped_file_);
        logical_size_ = other.logical_size_;
        header_size_ = other.header_size_;
        header_ = std::move(other.header_);
        temp_path_ = std::move(other.temp_path_);
        block_cache_ = std::move(other.block_cache_);
        other.logical_size_ = 0;
    }
    return *this;
}

Result<TraceReader> TraceReader::open(const std::filesystem::path& path) {
    TENET_ZONE_NAMED("TraceReader::open");
    TraceReader reader;
    reader.path_ = path;
    reader.header_size_ = sizeof(qbditrace::qbditrace_file_header_t);

    // Open and map the entire file read-only.
    std::string map_error;
    reader.mapped_file_ = platform::MappedFile::open(path.string(), &map_error);
    if (!reader.mapped_file_.valid()) {
        // std::string::starts_with() is C++20-only; project targets C++17.
        if (map_error.rfind("open() failed", 0) == 0 ||
            map_error.rfind("CreateFileW failed", 0) == 0) {
            return Error::file_not_found(path.string());
        }
        return Error::mmap_failed(map_error);
    }

    // Validate minimum size (at least file header).
    if (reader.mapped_file_.size() < sizeof(qbditrace::qbditrace_file_header_t)) {
        return Error::invalid_magic();
    }

    // Parse file header.
    const auto* raw_hdr = reinterpret_cast<const qbditrace::qbditrace_file_header_t*>(
        reader.mapped_file_.data());

    if (raw_hdr->magic != TRACE_MAGIC) {
        reader.close();
        return Error::invalid_magic();
    }

    // Version tags describe the newest layout contract in use. v8 CALL_META
    // and v9 MEMIMG may compose with earlier layout flags.
    const uint32_t ver = raw_hdr->version;
    const uint64_t flg = raw_hdr->flags;
    const bool pc_delta = (flg & qbditrace::QBDITRACE_HF_PC_DELTA) != 0;
    const bool old_value = (flg & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0;
    const bool has_fpr = (flg & qbditrace::QBDITRACE_HF_HAS_FPR) != 0;
    const bool call_meta = (flg & qbditrace::QBDITRACE_HF_CALL_META) != 0;
    bool version_ok = false;
    switch (ver) {
    case TRACE_VERSION:
        version_ok = !pc_delta && !old_value && !has_fpr && !call_meta;
        break;
    case QBDITRACE_VERSION_V5_PC_DELTA:
        version_ok = pc_delta && !old_value && !has_fpr && !call_meta;
        break;
    case QBDITRACE_VERSION_V6_OLD_VALUE:
        version_ok = old_value && !has_fpr && !call_meta;
        break;
    case QBDITRACE_VERSION_V7_HAS_FPR:
        version_ok = has_fpr && !call_meta;
        break;
    case QBDITRACE_VERSION_V8_CALL_META:
        version_ok = call_meta;
        break;
    case QBDITRACE_VERSION_V9_MEMIMG:
        version_ok = (flg & qbditrace::QBDITRACE_HF_MEMIMG) != 0;
        break;
    default:
        break;
    }
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

    // ── Target OS: read from header, fall back to heuristic for old traces ──
    {
        uint32_t raw_os = raw_hdr->target_os;
        if (raw_os >= static_cast<uint32_t>(TargetOS::iOS) &&
            raw_os <= static_cast<uint32_t>(TargetOS::Linux)) {
            reader.header_.target_os = static_cast<TargetOS>(raw_os);
        } else {
            // Heuristic fallback for pre-target_os traces (target_os == 0):
            // infer from module_name path patterns.
            const auto& mn = reader.header_.module_name;
            if (mn.find("/data/") == 0 || mn.find("/system/") == 0 ||
                mn.find(".so") != std::string::npos) {
                reader.header_.target_os = TargetOS::Android;
            } else if (mn.find("/var/") == 0 || mn.find("/private/") == 0 ||
                       mn.find("/Library/") != std::string::npos ||
                       mn.find(".dylib") != std::string::npos ||
                       mn.find(".app/") != std::string::npos) {
                reader.header_.target_os = TargetOS::iOS;
            } else {
                reader.header_.target_os = TargetOS::Unknown;
            }
        }
    }

    // ── Handle block-compressed traces (new path) ─────────────────────────
    if (reader.header_.is_block_compressed()) {
#if TENET_HAS_ZSTD
        return init_block_compressed(std::move(reader));
#else
        reader.close();
        return Error(ErrorCode::MmapFailed,
                     "Block-compressed trace requires zstd support, but tenet was "
                     "built without TENET_HAS_ZSTD");
#endif
    }

    // ── Handle legacy stream-compressed traces ────────────────────────────
    if (reader.header_.is_compressed()) {
#if TENET_HAS_ZSTD
        // Transfer ownership of the raw mapping to decompress_to_temp, which
        // releases it and replaces it with the decompressed file mapping.
        auto raw_mapping = std::move(reader.mapped_file_);
        return decompress_to_temp(std::move(reader), std::move(raw_mapping));
#else
        reader.close();
        return Error(ErrorCode::MmapFailed,
                     "Compressed trace requires zstd support, but tenet was "
                     "built without TENET_HAS_ZSTD");
#endif
    }

    // ── Uncompressed trace: logical size == file size on disk ──────────────
    reader.logical_size_ = reader.mapped_file_.size();

    return reader;
}

void TraceReader::close() {
    // Release block cache first (it references the mmap'd region).
    block_cache_.reset();

    mapped_file_.reset();
    logical_size_ = 0;
    // Clean up the temp file created for decompressed traces.
    if (!temp_path_.empty()) {
        std::filesystem::remove(temp_path_);
        temp_path_.clear();
    }
}

// ─── Block-compressed initialization ──────────────────────────────────────

#if TENET_HAS_ZSTD

Result<TraceReader> TraceReader::init_block_compressed(TraceReader&& reader) {
    constexpr size_t kHeaderSize = sizeof(qbditrace::qbditrace_file_header_t);

    auto cache = std::make_unique<BlockCacheReader>();
    bool ok = cache->init(
        reader.mapped_file_.data(),
        reader.mapped_file_.size(),
        kHeaderSize);
    if (!ok) {
        reader.close();
        return Error(ErrorCode::MmapFailed,
                     "Failed to initialize block-compressed reader: "
                     "corrupt block index or footer (and recovery failed)");
    }

    // Logical size = header + decompressed records
    reader.logical_size_ = kHeaderSize + cache->logical_size();

    if (cache->was_recovered()) {
        fmt::print(stderr,
                   "[WARNING] Block-compressed trace has no footer — {}\n",
                   cache->recovery_message());
    }

    reader.block_cache_ = std::move(cache);

    // Clear the block-compressed flag in the in-memory header so that
    // downstream code (e.g. record_at, Iterator) does not need to check it.
    // The is_block_mode() method uses block_cache_ != nullptr instead.
    reader.header_.flags &= ~static_cast<uint64_t>(qbditrace::QBDITRACE_HF_BLOCK_COMPRESSED);

    fmt::print(stderr, "Block-compressed trace: {:.1f} MB on disk → {:.1f} MB logical\n",
               reader.mapped_file_.size() / (1024.0 * 1024.0),
               reader.logical_size_ / (1024.0 * 1024.0));

    return std::move(reader);
}

#else  // !TENET_HAS_ZSTD

Result<TraceReader> TraceReader::init_block_compressed(TraceReader&& reader) {
    reader.close();
    return Error(ErrorCode::MmapFailed,
                 "Block-compressed trace requires zstd support, but tenet was "
                 "built without TENET_HAS_ZSTD");
}

#endif  // TENET_HAS_ZSTD

// ─── Decompression (zstd, legacy stream) ──────────────────────────────────

#if TENET_HAS_ZSTD

Result<TraceReader> TraceReader::decompress_to_temp(
    TraceReader&& reader, platform::MappedFile raw_mapping)
{
    constexpr size_t kHeaderSize = sizeof(qbditrace::qbditrace_file_header_t);
    const uint8_t* src = raw_mapping.data();
    const uint64_t raw_size = raw_mapping.size();
    const uint8_t* compressed_start = src + kHeaderSize;
    size_t compressed_size = raw_size - kHeaderSize;

    // Create a temp file for the decompressed trace.
    auto temp_dir = reader.path_.parent_path();
    auto temp_template = temp_dir / ".tenet-decomp-XXXXXX";
    std::string temp_str = temp_template.string();
    int tmp_fd = ::mkstemp(temp_str.data());
    if (tmp_fd < 0) {
        // Fallback: try /tmp if the source directory is read-only
        temp_str = "/tmp/.tenet-decomp-XXXXXX";
        tmp_fd = ::mkstemp(temp_str.data());
    }
    if (tmp_fd < 0) {
        return Error(ErrorCode::MmapFailed,
                     std::string("Failed to create temp file for decompression: ") +
                     strerror(errno));
    }
    std::filesystem::path temp_path(temp_str);

    fmt::print(stderr, "Decompressing trace to {}\n", temp_str);
    LOG_INFO_M(::tenet::log::Module::Io, "decompressing compressed trace ({:.2f} MB) to {}",
             raw_size / (1024.0 * 1024.0), temp_str);

    // Write the header first (with HF_COMPRESSED flag cleared).
    qbditrace::qbditrace_file_header_t hdr;
    std::memcpy(&hdr, src, kHeaderSize);
    hdr.flags &= ~static_cast<uint64_t>(qbditrace::QBDITRACE_HF_COMPRESSED);
    if (::write(tmp_fd, &hdr, kHeaderSize) != static_cast<ssize_t>(kHeaderSize)) {
        ::close(tmp_fd);
        std::filesystem::remove(temp_path);
        return Error(ErrorCode::MmapFailed, "Failed to write header to temp file");
    }

    // Streaming decompression using ZSTD_DCtx.
    ZSTD_DCtx* dctx = ZSTD_createDCtx();
    if (!dctx) {
        ::close(tmp_fd);
        std::filesystem::remove(temp_path);
        return Error(ErrorCode::MmapFailed, "ZSTD_createDCtx failed");
    }

    constexpr size_t kOutBufSize = 256 * 1024;
    auto out_buf = std::make_unique<uint8_t[]>(kOutBufSize);

    ZSTD_inBuffer in = { compressed_start, compressed_size, 0 };
    bool ok = true;
    std::string err_msg;
    uint64_t total_written = kHeaderSize;  // header already written
    int last_pct = -1;

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
            total_written += out.pos;
        }
        // Progress based on compressed input consumed (reliable denominator).
        int pct = static_cast<int>(in.pos * 100 / in.size);
        if (pct != last_pct) {
            last_pct = pct;
            fmt::print(stderr, "\r  Decompressing: {:3d}%  ({:.1f} MB written)",
                       pct, total_written / (1024.0 * 1024.0));
        }
    }

    ZSTD_freeDCtx(dctx);

    // Release the original compressed file mapping.
    raw_mapping.reset();

    if (!ok) {
        fmt::print(stderr, "\n  Decompression failed: {}\n", err_msg);
        ::close(tmp_fd);
        std::filesystem::remove(temp_path);
        return Error(ErrorCode::MmapFailed, err_msg);
    }

    fmt::print(stderr, "\r  Decompressed: {:.1f} MB  \n", total_written / (1024.0 * 1024.0));
    LOG_INFO_M(::tenet::log::Module::Io, "decompression complete: {:.2f} MB", total_written / (1024.0 * 1024.0));

    // Close the writer, then map the completed decompressed file read-only.
    ::close(tmp_fd);
    std::string map_error;
    auto decompressed_mapping = platform::MappedFile::open(temp_str, &map_error);
    if (!decompressed_mapping.valid()) {
        std::filesystem::remove(temp_path);
        return Error(ErrorCode::MmapFailed,
                     "Failed to map decompressed temp file: " + map_error);
    }

    // Update the reader to point at the decompressed data.
    reader.logical_size_ = decompressed_mapping.size();
    reader.mapped_file_ = std::move(decompressed_mapping);
    reader.temp_path_ = temp_path;
    // Clear the compressed flag in the in-memory header so downstream code
    // does not attempt to decompress again.
    reader.header_.flags &= ~static_cast<uint64_t>(qbditrace::QBDITRACE_HF_COMPRESSED);

    return std::move(reader);
}

#else  // !TENET_HAS_ZSTD

Result<TraceReader> TraceReader::decompress_to_temp(
    TraceReader&& /*reader*/, platform::MappedFile /*raw_mapping*/)
{
    return Error(ErrorCode::MmapFailed,
                 "Compressed trace requires zstd support, but tenet was "
                 "built without TENET_HAS_ZSTD");
}

#endif  // TENET_HAS_ZSTD

RecordView TraceReader::record_at(uint64_t offset) const {
    const uint8_t* ptr = data_at(offset);
    RecordView rv;
    rv.kind = static_cast<RecordKind>(ptr[0]);
    rv.file_offset = offset;
    rv.raw_ptr = ptr;
    rv.available_size = offset < logical_size_
        ? static_cast<size_t>(logical_size_ - offset) : 0;
    // Set format flags from header so byte_size() computes correct sizes
    // (e.g. v7 ANCHOR records include a 512-byte FPR snapshot).
    rv.is_v5 = (header_.flags & qbditrace::QBDITRACE_HF_PC_DELTA) != 0;
    rv.is_v6 = (header_.flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0;
    rv.is_v7 = (header_.flags & qbditrace::QBDITRACE_HF_HAS_FPR) != 0;
    rv.is_v8 = (header_.flags & qbditrace::QBDITRACE_HF_WIDE_API_ID) != 0;
    return rv;
}

RecordView TraceReader::Iterator::operator*() const {
    const uint8_t* ptr = read_at(offset_);
    RecordView rv;
    rv.kind = static_cast<RecordKind>(ptr[0]);
    rv.file_offset = offset_;
    rv.raw_ptr = ptr;
    rv.available_size = offset_ < reader_->logical_size_
        ? static_cast<size_t>(reader_->logical_size_ - offset_) : 0;

    const uint64_t flags = reader_->header_.flags;
    const bool use_pc_delta  = (flags & qbditrace::QBDITRACE_HF_PC_DELTA)  != 0;
    const bool use_old_value = (flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0;
    const bool use_fpr       = (flags & qbditrace::QBDITRACE_HF_HAS_FPR)   != 0;
    const bool use_wide_api  = (flags & qbditrace::QBDITRACE_HF_WIDE_API_ID) != 0;

    // Propagate is_v5 / is_v6 / is_v7 / is_v8 so as_inst(), as_capicall()
    // and mem_access() use the right struct layout.
    rv.is_v5 = use_pc_delta;
    rv.is_v6 = use_old_value;
    rv.is_v7 = use_fpr;
    rv.is_v8 = use_wide_api;

    if (rv.kind == RecordKind::Thread) {
        // THREAD markers delimit per-producer streams. Keep the legacy scalar
        // current_pc_ in sync for old single-thread traces, but maintain an
        // independent v5 delta chain for every observed thread.
        const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_thread_head_t*>(rv.raw_ptr);
        current_thread_id_ = hdr->thread_id;
        const auto it = thread_pcs_.try_emplace(current_thread_id_, 0).first;
        current_pc_ = it->second;
    } else if (rv.kind == RecordKind::Inst && use_pc_delta) {
        // v5/v6+v5/v7+v5: reconstruct absolute PC from this producer
        // thread's PC chain. The no-THREAD legacy stream uses tid=0.
        const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_v5_t*>(rv.raw_ptr);
        int16_t delta;
        std::memcpy(&delta, &hdr->pc_delta, sizeof(delta));  // LE decode
        auto& running_pc = thread_pcs_[current_thread_id_];
        const uint64_t new_pc = running_pc + static_cast<int64_t>(delta);
        rv.resolved_pc = new_pc;
        running_pc = new_pc;
        current_pc_ = new_pc;
    } else if (rv.kind == RecordKind::Anchor && use_pc_delta) {
        // Anchor carries absolute PC — resync the current producer thread.
        const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_anchor_head_t*>(rv.raw_ptr);
        thread_pcs_[current_thread_id_] = hdr->pc;
        current_pc_ = hdr->pc;
    }

    return rv;
}

TraceReader::Iterator& TraceReader::Iterator::operator++() {
    // ── Performance optimization ──────────────────────────────────────────
    // Read the record header at current offset to compute its size, then
    // advance past it.  Uses thread-local reader when available to avoid
    // mutex contention on the shared BlockCacheReader.

    if (offset_ >= reader_->logical_size_) return *this;
    const size_t remaining = static_cast<size_t>(reader_->logical_size_ - offset_);
    const uint8_t* ptr = read_at(offset_);
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
        if (remaining < (reader_->header_.has_call_meta()
                ? sizeof(qbditrace::qbditrace_objc_head_v8_t)
                : sizeof(qbditrace::qbditrace_objc_head_t))) {
            rec_size = remaining;
        } else {
            rec_size = raw_record_size(ptr, reader_->header_, remaining);
        }
        break;
    case RecordKind::CapiCall: {
        // Fixed header + variable-length string captures.
        // v8 and legacy fixed headers are both 88 bytes; field order differs.
        const bool use_wide_api = (reader_->header_.flags & qbditrace::QBDITRACE_HF_WIDE_API_ID) != 0;
        const size_t fixed_size = use_wide_api
            ? sizeof(qbditrace::qbditrace_capicall_head_v8_t)
            : sizeof(qbditrace::qbditrace_capicall_head_t);
        if (remaining < fixed_size) {
            rec_size = remaining;
            break;
        }
        if (use_wide_api) {
            const auto* cc = reinterpret_cast<const qbditrace::qbditrace_capicall_head_v8_t*>(ptr);
            rec_size = sizeof(qbditrace::qbditrace_capicall_head_v8_t);
            const uint8_t* sp = ptr + sizeof(qbditrace::qbditrace_capicall_head_v8_t);
            for (uint8_t s = 0; s < cc->str_count; ++s) {
                if (rec_size + sizeof(qbditrace::qbditrace_capicall_str_t) > remaining) {
                    rec_size = remaining;
                    break;
                }
                const auto* sh = reinterpret_cast<const qbditrace::qbditrace_capicall_str_t*>(sp);
                uint16_t data_bytes = sh->str_len + 1;
                uint16_t padded = (data_bytes + 3u) & ~3u;
                rec_size += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
                sp += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
            }
        } else {
            const auto* cc = reinterpret_cast<const qbditrace::qbditrace_capicall_head_t*>(ptr);
            rec_size = sizeof(qbditrace::qbditrace_capicall_head_t);
            const uint8_t* sp = ptr + sizeof(qbditrace::qbditrace_capicall_head_t);
            for (uint8_t s = 0; s < cc->str_count; ++s) {
                if (rec_size + sizeof(qbditrace::qbditrace_capicall_str_t) > remaining) {
                    rec_size = remaining;
                    break;
                }
                const auto* sh = reinterpret_cast<const qbditrace::qbditrace_capicall_str_t*>(sp);
                uint16_t data_bytes = sh->str_len + 1;
                uint16_t padded = (data_bytes + 3u) & ~3u;
                rec_size += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
                sp += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
            }
        }
        break;
    }
    case RecordKind::Code:
        rec_size = sizeof(qbditrace::qbditrace_code_head_t)
            + ptr[1]; // code_size is the 2nd byte
        break;
    case RecordKind::Retval:
        if (remaining < offsetof(qbditrace::qbditrace_retval_t, source_id)) {
            rec_size = remaining;
        } else {
            const auto* rv = reinterpret_cast<const qbditrace::qbditrace_retval_t*>(ptr);
            rec_size = std::max<size_t>(rv->record_size,
                                        sizeof(qbditrace::qbditrace_retval_t));
        }
        break;
    case RecordKind::MemImg:
        if (remaining < sizeof(qbditrace::qbditrace_memimg_t)) {
            rec_size = remaining;
        } else {
            rec_size = raw_record_size(ptr, reader_->header_, remaining);
        }
        break;
    default:
        // Fallback: parse via RecordView (shouldn't happen in valid traces)
        rec_size = reader_->record_at(offset_).byte_size(reader_->header_.num_gpr);
        break;
    }

    // A malformed/truncated variable record must never advance or prefetch
    // beyond the logical stream. Consume the remainder as one terminal record.
    rec_size = std::min(rec_size, remaining);
    if (rec_size == 0) rec_size = remaining;

    // Prefetch hint — only useful in mmap mode; harmless in block mode
    // (the address may be in a different decompressed block anyway).
    if (!reader_->is_block_mode() && rec_size < remaining) {
        __builtin_prefetch(ptr + rec_size, 0, 1);
    }

    offset_ += rec_size;
    return *this;
}

TraceReader::Iterator TraceReader::begin() const {
    // Records start after the 536-byte file header
    return Iterator(this, header_size_);
}

TraceReader::Iterator TraceReader::end() const {
    return Iterator(this, logical_size_);
}

std::vector<MemSnapshotRegion> TraceReader::collect_memimg_regions() const {
    std::vector<MemSnapshotRegion> regions;
    for (auto it = begin(); it != end(); ++it) {
        const auto rec = *it;
        if (rec.kind == RecordKind::Inst) break;
        if (rec.kind != RecordKind::MemImg) continue;

        const auto memimg = rec.as_memimg();
        if (memimg.len == 0) continue;

        const auto* raw_header = reinterpret_cast<const qbditrace::qbditrace_memimg_t*>(
            rec.raw_ptr);
        const size_t record_payload = raw_header->record_size > sizeof(*raw_header)
            ? raw_header->record_size - sizeof(*raw_header)
            : 0;
        const size_t stream_payload = rec.available_size > sizeof(*raw_header)
            ? rec.available_size - sizeof(*raw_header)
            : 0;
        const size_t payload_size = std::min<size_t>(
            memimg.len, std::min(record_payload, stream_payload));
        if (payload_size == 0) continue;

        MemSnapshotRegion region;
        region.addr = memimg.addr;
        region.data.assign(memimg.data, memimg.data + payload_size);
        regions.push_back(std::move(region));
    }

    std::stable_sort(regions.begin(), regions.end(),
                     [](const MemSnapshotRegion& lhs, const MemSnapshotRegion& rhs) {
                         return lhs.addr < rhs.addr;
                     });

    std::vector<MemSnapshotRegion> merged;
    merged.reserve(regions.size());
    for (auto& region : regions) {
        if (merged.empty() || region.addr > merged.back().end()) {
            merged.push_back(std::move(region));
            continue;
        }

        auto& previous = merged.back();
        if (region.end() <= previous.end()) continue;

        const size_t overlap = static_cast<size_t>(previous.end() - region.addr);
        previous.data.insert(previous.data.end(),
                             region.data.begin() + static_cast<std::ptrdiff_t>(overlap),
                             region.data.end());
    }
    return merged;
}

TraceReader::Iterator TraceReader::begin(const ThreadReader& tr) const {
    return Iterator(this, header_size_, &tr);
}

TraceReader::Iterator TraceReader::end(const ThreadReader& tr) const {
    return Iterator(this, logical_size_, &tr);
}

void TraceReader::advise_sequential() const {
    mapped_file_.advise(platform::AccessHint::Sequential);
}

void TraceReader::advise_random() const {
    mapped_file_.advise(platform::AccessHint::Random);
}

}  // namespace tenet
