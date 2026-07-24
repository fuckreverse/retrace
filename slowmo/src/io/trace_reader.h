#pragma once

#include "common/types.h"
#include "TraceFormat.h"
#include "io/block_cache_reader.h"

#include <filesystem>
#include <cstring>
#include <memory>

namespace tenet {

// ─── Zero-copy record views ───────────────────────────────────────────────

struct RegDiffView {
    uint8_t index;
    uint64_t value;
};

struct FprDiffView {
    uint8_t index;   // 0..31 = v0..v31
    uint64_t lo;     // bits  63:0
    uint64_t hi;     // bits 127:64
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
    uint8_t nzcv;            // bits[3:0] = N/Z/C/V flags; bits[7:4] = branch hint (when HF_BRANCH_HINT is set)
    uint8_t reg_diff_count;
    uint8_t fpr_diff_count;  // v7 only; 0 for v4/v5/v6
    uint8_t mem_access_count;
    const uint8_t* raw_diffs;    // points into mmap/cache region (GPR diffs)
    const uint8_t* raw_fprdiffs; // points into mmap/cache region (FPR diffs, v7)
    const uint8_t* raw_mems;     // points into mmap/cache region
    bool is_v5 = false;  // true when record uses v5 (pc_delta) layout
    bool is_v6 = false;  // true when record uses v6 (old_value) layout
    bool is_v7 = false;  // true when record uses v7 (HF_HAS_FPR) layout

    /// Extract the branch-hint nibble from the high 4 bits of nzcv.
    /// Returns 0 (NONE), 1 (CALL), 2 (RET), or 4 (BRANCH).
    /// Only meaningful when the trace file has HF_BRANCH_HINT set.
    uint8_t branch_hint() const { return (nzcv >> 4) & 0xF; }

    /// The actual N/Z/C/V flags (low nibble only).
    uint8_t nzcv_flags() const { return nzcv & 0xF; }

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

    FprDiffView fpr_diff(uint8_t i) const {
        // qbditrace_fprdiff_t: u8 fpr_index @0, pad[7], u64 lo @8, u64 hi @16
        const uint8_t* p = raw_fprdiffs + i * sizeof(qbditrace::qbditrace_fprdiff_t);
        const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_fprdiff_t*>(p);
        FprDiffView d;
        d.index = hdr->fpr_index;
        d.lo    = hdr->lo;
        d.hi    = hdr->hi;
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
        size_t hdr;
        if (is_v7 && is_v5)
            hdr = sizeof(qbditrace::qbditrace_inst_head_v7_v5_t);
        else if (is_v7)
            hdr = sizeof(qbditrace::qbditrace_inst_head_v7_t);
        else if (is_v5)
            hdr = sizeof(qbditrace::qbditrace_inst_head_v5_t);
        else
            hdr = sizeof(qbditrace::qbditrace_inst_head_t);
        // Use sizeof() to respect struct alignment padding in the on-disk layout.
        // qbditrace_regdiff_t:    reg_index(u8) + pad(7) + value(u64) = 16 bytes
        // qbditrace_fprdiff_t:    fpr_index(u8) + pad(7) + lo(u64) + hi(u64) = 24 bytes
        // qbditrace_memacc_t:     type+flags+size(4) + pad(4) + addr+value+value_hi = 32 bytes
        // qbditrace_memacc_v6_t:  same + old_value+old_value_hi = 48 bytes
        size_t memacc_sz = is_v6
            ? sizeof(qbditrace::qbditrace_memacc_v6_t)
            : sizeof(qbditrace::qbditrace_memacc_t);
        return hdr
            + reg_diff_count  * sizeof(qbditrace::qbditrace_regdiff_t)
            + fpr_diff_count  * sizeof(qbditrace::qbditrace_fprdiff_t)
            + mem_access_count * memacc_sz;
    }
};

struct AnchorView {
    uint64_t pc;
    const uint64_t* gpr_values;  // points to num_gpr uint64_t values in mmap/cache
    uint32_t num_gpr;
    // FPR snapshot (v7 only): when has_fpr is true, fpr_lo and fpr_hi each
    // point to an array of 32 uint64_t values in the mmap/cache region.
    const uint64_t* fpr_lo = nullptr;  // bits  63:0  for v0..v31
    const uint64_t* fpr_hi = nullptr;  // bits 127:64 for v0..v31
    bool has_fpr = false;

    size_t byte_size() const {
        size_t fpr_bytes = has_fpr ? QBDITRACE_AARCH64_FPR_SNAPSHOT_BYTES : 0;
        return sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr * 8 + fpr_bytes;
    }
};

struct CodeView {
    uint64_t pc;
    uint8_t size;
    const uint8_t* bytes;  // instruction bytes in mmap/cache

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
    uint8_t flags = 0;     // qbditrace QBDITRACE_SVC_FL_* bits

    size_t byte_size() const {
        return sizeof(qbditrace::qbditrace_svc_head_t);
    }
};

struct ObjcView {
    uint8_t variant;
    uint8_t sel_len = 0;
    uint8_t flags = 0;
    uint64_t pc;
    uint64_t recv;
    uint64_t sel;
    const char* cls;
    const char* selector_name = "";
    bool is_v8 = false;

    size_t byte_size() const {
        if (!is_v8) return sizeof(qbditrace::qbditrace_objc_head_t);
        size_t payload = (static_cast<size_t>(sel_len) + 1u + 3u) & ~size_t{3};
        return sizeof(qbditrace::qbditrace_objc_head_v8_t) + payload;
    }
};

struct RetvalView {
    uint8_t source_kind;
    uint8_t flags;
    uint16_t aux_id;
    uint16_t record_size;
    uint64_t source_id;
    uint64_t site;
    uint64_t target;
    uint64_t resume;
    uint64_t x0;
    uint64_t x1;
    uint32_t nzcv;
    int32_t errno_before = 0; // compatibility view; not asserted valid by v8 writer
    int32_t errno_after = 0;
    size_t available_size = SIZE_MAX;
    size_t byte_size() const {
        return std::min(std::max<size_t>(record_size,
                                         sizeof(qbditrace::qbditrace_retval_t)),
                        available_size);
    }
};

struct CapiCallStrView {
    uint8_t  arg_idx;    // which arg index this string came from
    uint8_t  str_len;    // byte length of content (not counting NUL)
    uint8_t  str_flags;  // QBDITRACE_SF_* bits
    const char* data;    // pointer to NUL-terminated content in mmap/cache

    bool is_truncated()      const { return str_flags & 0x01; }
    bool is_binary()         const { return str_flags & 0x02; }
    bool is_safe_read_fail() const { return str_flags & 0x04; }
};

struct CapiCallView {
    uint16_t api_id;     // qbditrace_capi_id_t (uint16_t for v8, was uint8_t for v4-v7)
    uint8_t  arg_count;  // number of valid entries in args[]
    uint8_t  str_count;  // number of inline string captures
    uint64_t pc;         // call-site PC
    uint64_t target;     // runtime address of called function
    const uint64_t* args; // pointer to args[8] in mmap/cache
    bool is_v8 = false;   // true when file-wide HF_CALL_META is set

    size_t byte_size() const {
        size_t total = is_v8
            ? sizeof(qbditrace::qbditrace_capicall_head_v8_t)
            : sizeof(qbditrace::qbditrace_capicall_head_t);
        // Variable-length string captures follow the fixed header.
        // Parse them to compute total record size.
        const uint8_t* p = reinterpret_cast<const uint8_t*>(args) + 8 * 8;
        for (uint8_t i = 0; i < str_count; ++i) {
            const auto* sh = reinterpret_cast<const qbditrace::qbditrace_capicall_str_t*>(p);
            uint16_t data_bytes = sh->str_len + 1; // content + NUL
            uint16_t padded = (data_bytes + 3u) & ~3u; // pad to 4-byte alignment
            total += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
            p += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
        }
        return total;
    }

    /// Access the i-th string capture (0 <= i < str_count).
    CapiCallStrView str_at(uint8_t i) const {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(args) + 8 * 8;
        for (uint8_t j = 0; j < i; ++j) {
            const auto* sh = reinterpret_cast<const qbditrace::qbditrace_capicall_str_t*>(p);
            uint16_t data_bytes = sh->str_len + 1;
            uint16_t padded = (data_bytes + 3u) & ~3u;
            p += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
        }
        const auto* sh = reinterpret_cast<const qbditrace::qbditrace_capicall_str_t*>(p);
        CapiCallStrView sv;
        sv.arg_idx   = sh->str_arg_idx;
        sv.str_len   = sh->str_len;
        sv.str_flags = sh->str_flags;
        sv.data      = reinterpret_cast<const char*>(p + sizeof(qbditrace::qbditrace_capicall_str_t));
        return sv;
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
    const uint8_t* raw_ptr;  // start of record in mmap/cache

    // Resolved absolute PC for this record.
    // - v5 (HF_PC_DELTA): Iterator reconstructs it from pc_delta chain and stores it here;
    //   record_at(offset, seed_pc) stores seed_pc (as computed by offset_of_with_pc).
    // - v4: Iterator and record_at() both leave this 0; as_inst() reads pc from raw_ptr.
    uint64_t resolved_pc = 0;
    // is_v5: true when the INST record uses the 6-byte qbditrace_inst_head_v5_t layout
    //        (HF_PC_DELTA). Set symmetrically with is_v6/is_v7 by Iterator and record_at().
    bool is_v5 = false;
    // is_v6: true when memory access records use the 48-byte qbditrace_memacc_v6_t layout
    //        (HF_OLD_VALUE). Set by Iterator and record_at().
    bool is_v6 = false;
    // is_v7: true when INST records carry FPR diffs and ANCHOR records carry FPR
    //        snapshots (HF_HAS_FPR). Set by Iterator and record_at().
    bool is_v7 = false;
    // is_v8: true when the file-wide call metadata layouts are enabled.
    //        Set by Iterator and record_at().
    bool is_v8 = false;
    // Bytes remaining in the logical stream from raw_ptr. Iterator/record_at
    // populate this so self-describing sizes cannot escape a truncated file.
    size_t available_size = SIZE_MAX;

    // Parse helpers (caller checks kind first)
    InstView as_inst() const;
    AnchorView as_anchor(uint32_t num_gpr) const;
    CodeView as_code() const;
    EventView as_event() const;
    SvcView as_svc() const;
    ObjcView as_objc() const;
    CapiCallView as_capicall() const;
    ThreadView as_thread() const;
    RetvalView as_retval() const;

    /// Compute the byte size of this record (needed to advance to next)
    size_t byte_size(uint32_t num_gpr) const;
};

// ─── File header wrapper ──────────────────────────────────────────────────

/// Target OS of the traced process (matches qbditrace_target_os_t).
enum class TargetOS : uint32_t {
    Unknown = 0,
    iOS     = 1,   // iOS / macOS (Darwin)
    Android = 2,   // Android (Linux kernel, Bionic libc)
    Linux   = 3,   // Desktop / server Linux
};

/// Returns a short display string for a TargetOS value.
inline const char* target_os_name(TargetOS os) {
    switch (os) {
        case TargetOS::iOS:     return "iOS";
        case TargetOS::Android: return "Android";
        case TargetOS::Linux:   return "Linux";
        default:                return "Unknown";
    }
}

/// Whether the target OS uses Darwin conventions (Mach-O, ObjC, x16 syscall).
inline bool is_darwin(TargetOS os) { return os == TargetOS::iOS; }

/// Whether the target OS uses Linux conventions (ELF, x8 syscall).
inline bool is_linux_like(TargetOS os) {
    return os == TargetOS::Android || os == TargetOS::Linux;
}

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
    TargetOS target_os = TargetOS::Unknown;

    bool has_mem() const       { return flags & qbditrace::QBDITRACE_HF_HAS_MEM; }
    bool has_nzcv() const      { return flags & qbditrace::QBDITRACE_HF_HAS_NZCV; }
    bool has_code() const      { return flags & qbditrace::QBDITRACE_HF_HAS_CODE; }
    bool reg_diff() const      { return flags & qbditrace::QBDITRACE_HF_REG_DIFF; }
    bool has_old_value() const { return flags & qbditrace::QBDITRACE_HF_OLD_VALUE; }
    bool has_fpr() const          { return flags & qbditrace::QBDITRACE_HF_HAS_FPR; }
    bool is_compressed() const    { return flags & qbditrace::QBDITRACE_HF_COMPRESSED; }
    bool is_block_compressed() const { return flags & qbditrace::QBDITRACE_HF_BLOCK_COMPRESSED; }
    /// When true, every REC_INST nzcv byte encodes the branch class in bits[7:4]:
    ///   0 = not a branch, 1 = CALL (BL/BLR), 2 = RET, 4 = BRANCH (B/BR).
    /// The low nibble retains the normal N/Z/C/V flags.
    bool has_branch_hint() const  { return flags & qbditrace::QBDITRACE_HF_BRANCH_HINT; }
    /// Compatibility spelling for v8 call metadata.
    bool has_call_meta() const      { return flags & qbditrace::QBDITRACE_HF_CALL_META; }
    bool has_wide_api_id() const    { return has_call_meta(); }
};

// ─── Shared raw record size calculation ───────────────────────────────────
//
// Computes the byte size of a trace record from a raw pointer.
// Handles ALL 8 record types (INST, ANCHOR, THREAD, EVENT, SVC, OBJC, CODE,
// CapiCall) and ALL 4 INST header formats (v4=16B, v5=6B, v7=24B, v7+v5=8B).
//
// This is the single source of truth for raw-pointer-based record sizing.
// All fast-scan passes (xref, objc, trace_collector) should use this instead
// of maintaining their own copies, to prevent format-parsing divergence.
//
// Parameters:
//   ptr     — pointer to the record's first byte (kind field)
//   num_gpr — number of GPR registers (from file header, typically 34)
//   is_v5   — HF_PC_DELTA: INST head is 6B (v4/v7) or 8B (v7+v5) with pc_delta
//   is_v6   — HF_OLD_VALUE: memacc uses 48-byte layout (with old_value)
//   is_v7   — HF_HAS_FPR: INST head includes n_fprdiff, ANCHOR includes 512B FPR
inline size_t raw_record_size(const uint8_t* ptr, uint32_t num_gpr,
                               bool is_v5 = false, bool is_v6 = false,
                               bool is_v7 = false, bool is_v8 = false) {
    switch (ptr[0]) {
    case 0: { // INST
        uint8_t n_regdiff = ptr[2];
        uint8_t n_mem = ptr[3];
        size_t hdr;
        uint8_t n_fprdiff = 0;
        if (is_v7 && is_v5) {
            // qbditrace_inst_head_v7_v5_t = 8 bytes
            // [kind, nzcv, n_regdiff, n_mem, delta_lo, delta_hi, n_fprdiff, reserved]
            hdr = sizeof(qbditrace::qbditrace_inst_head_v7_v5_t);
            n_fprdiff = ptr[6];  // n_fprdiff at byte offset 6
        } else if (is_v7) {
            // qbditrace_inst_head_v7_t = 24 bytes
            hdr = sizeof(qbditrace::qbditrace_inst_head_v7_t);
            n_fprdiff = ptr[16]; // n_fprdiff at byte offset 16
        } else if (is_v5) {
            // qbditrace_inst_head_v5_t = 6 bytes (no n_fprdiff field)
            hdr = sizeof(qbditrace::qbditrace_inst_head_v5_t);
        } else {
            // qbditrace_inst_head_t = 16 bytes (v4 baseline)
            hdr = sizeof(qbditrace::qbditrace_inst_head_t);
        }
        size_t macc = is_v6
            ? sizeof(qbditrace::qbditrace_memacc_v6_t)       // 48 bytes
            : sizeof(qbditrace::qbditrace_memacc_t);          // 32 bytes
        return hdr
            + n_regdiff  * sizeof(qbditrace::qbditrace_regdiff_t)   // 16 bytes each
            + n_fprdiff  * sizeof(qbditrace::qbditrace_fprdiff_t)   // 24 bytes each (v7 only)
            + n_mem      * macc;
    }
    case 1: // ANCHOR
        return sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr * 8   // 16 + N*8
             + (is_v7 ? 32 * 16 : 0);                                      // +512 bytes FPR (v7)
    case 2: // THREAD
        return sizeof(qbditrace::qbditrace_thread_head_t);  // 16
    case 3: // EVENT
        return sizeof(qbditrace::qbditrace_event_head_t);   // 24
    case 4: // SVC
        return sizeof(qbditrace::qbditrace_svc_head_t);     // 72
    case 5: { // OBJC
        if (!is_v8) return sizeof(qbditrace::qbditrace_objc_head_t);
        const auto* oh = reinterpret_cast<const qbditrace::qbditrace_objc_head_v8_t*>(ptr);
        size_t payload = (static_cast<size_t>(oh->sel_len) + 1u + 3u) & ~size_t{3};
        return sizeof(qbditrace::qbditrace_objc_head_v8_t) + payload;
    }
    case 6: // CODE
        return sizeof(qbditrace::qbditrace_code_head_t) + ptr[1];  // 16 + size
    case 7: { // CapiCall — variable length (fixed header + string captures)
        if (is_v8) {
            const auto* cc = reinterpret_cast<const qbditrace::qbditrace_capicall_head_v8_t*>(ptr);
            size_t sz = sizeof(qbditrace::qbditrace_capicall_head_v8_t);  // 88 bytes
            const uint8_t* sp = ptr + sizeof(qbditrace::qbditrace_capicall_head_v8_t);
            for (uint8_t s = 0; s < cc->str_count; ++s) {
                const auto* sh = reinterpret_cast<const qbditrace::qbditrace_capicall_str_t*>(sp);
                uint16_t data_bytes = sh->str_len + 1;
                uint16_t padded = (data_bytes + 3u) & ~3u;
                sz += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
                sp += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
            }
            return sz;
        } else {
            const auto* cc = reinterpret_cast<const qbditrace::qbditrace_capicall_head_t*>(ptr);
            size_t sz = sizeof(qbditrace::qbditrace_capicall_head_t);  // 88 bytes
            const uint8_t* sp = ptr + sizeof(qbditrace::qbditrace_capicall_head_t);
            for (uint8_t s = 0; s < cc->str_count; ++s) {
                const auto* sh = reinterpret_cast<const qbditrace::qbditrace_capicall_str_t*>(sp);
                uint16_t data_bytes = sh->str_len + 1;
                uint16_t padded = (data_bytes + 3u) & ~3u;
                sz += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
                sp += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
            }
            return sz;
        }
    }
    case 8: { // RETVAL — self describing
        const auto* rv = reinterpret_cast<const qbditrace::qbditrace_retval_t*>(ptr);
        return std::max<size_t>(rv->record_size, sizeof(qbditrace::qbditrace_retval_t));
    }
    default:
        return 1; // shouldn't happen
    }
}

/// Convenience overload: extract format flags from a FileHeader.
inline size_t raw_record_size(const uint8_t* ptr, const FileHeader& hdr,
                              size_t remaining = SIZE_MAX) {
    size_t size = raw_record_size(
        ptr, hdr.num_gpr,
        (hdr.flags & qbditrace::QBDITRACE_HF_PC_DELTA) != 0,
        (hdr.flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0,
        (hdr.flags & qbditrace::QBDITRACE_HF_HAS_FPR) != 0,
        (hdr.flags & qbditrace::QBDITRACE_HF_CALL_META) != 0);
    return std::min(size, remaining);
}

/// Compute the byte offset of n_fprdiff within an INST header.
///   v7+v5: offset 6  (qbditrace_inst_head_v7_v5_t)
///   v7:    offset 16 (qbditrace_inst_head_v7_t)
///   v4/v5: N/A (no FPR diffs, returns 0)
inline size_t fprdiff_byte_offset(bool is_v5, bool is_v7) {
    return (is_v7 && is_v5) ? 6 : (is_v7 ? 16 : 0);
}

/// Compute INST header size for the given format flags.
///   v4:    16 bytes (qbditrace_inst_head_t)
///   v5:     6 bytes (qbditrace_inst_head_v5_t)
///   v7:    24 bytes (qbditrace_inst_head_v7_t)
///   v7+v5:  8 bytes (qbditrace_inst_head_v7_v5_t)
inline size_t inst_header_size(bool is_v5, bool is_v7) {
    if (is_v7 && is_v5) return sizeof(qbditrace::qbditrace_inst_head_v7_v5_t);
    if (is_v7)          return sizeof(qbditrace::qbditrace_inst_head_v7_t);
    if (is_v5)          return sizeof(qbditrace::qbditrace_inst_head_v5_t);
    return                     sizeof(qbditrace::qbditrace_inst_head_t);
}

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
    /// Logical file size: for block-compressed traces this is the
    /// decompressed size (header + records); for mmap'd traces it is the
    /// actual file size.
    uint64_t file_size() const { return logical_size_; }
    const std::filesystem::path& path() const { return path_; }

    /// Whether this trace uses block-compressed on-demand decompression.
    bool is_block_mode() const { return block_cache_ != nullptr; }

    /// Number of compressed blocks (0 for non-block mode).
    uint32_t block_count() const {
        return block_cache_ ? block_cache_->block_count() : 0;
    }

    /// Create a lightweight thread-local reading proxy that shares the same
    /// mmap and block index but has an independent LRU cache.
    /// This eliminates mutex contention when multiple threads scan the trace
    /// concurrently.  The returned object is valid as long as `this` is alive.
    /// For mmap (non-block) mode, this just returns a thin wrapper over the
    /// shared mmap pointer (no contention in that case anyway).
    class ThreadReader {
    public:
        ThreadReader() = default;

        /// Access byte at a given logical file offset (same semantics as
        /// TraceReader::data_at).
        const uint8_t* data_at(uint64_t offset) const {
            if (local_cache_) {
                return local_cache_->data_at(offset - header_size_);
            }
            return mmap_base_ + offset;
        }

    private:
        friend class TraceReader;
        const uint8_t* mmap_base_ = nullptr;
        uint64_t header_size_ = 0;
        std::unique_ptr<BlockCacheReader> local_cache_;
    };

    /// Create a thread-local reader. `cache_blocks` controls the per-thread
    /// LRU cache size (smaller is fine for sequential scans — 4~8 blocks).
    ThreadReader create_thread_reader(size_t cache_blocks = 8) const {
        ThreadReader tr;
        tr.mmap_base_ = static_cast<const uint8_t*>(mapped_);
        tr.header_size_ = header_size_;
        if (block_cache_) {
            tr.local_cache_ = block_cache_->clone(cache_blocks);
        }
        return tr;
    }

    /// Size of the file header in bytes (needed to convert between
    /// logical block offsets and absolute file offsets).
    uint64_t header_size() const { return header_size_; }

    /// Decompress a single block into a caller-owned buffer.
    /// Bypasses the LRU cache entirely — designed for bulk sequential scans.
    /// `out_logical_offset` is relative to the record stream start (after header).
    /// Returns false if block_id is out of range or decompression fails.
    bool decompress_block(uint32_t block_id,
                          std::vector<uint8_t>& out_buf,
                          const uint8_t*& out_data,
                          uint32_t& out_size,
                          uint64_t& out_logical_offset) const {
        if (!block_cache_) return false;
        return block_cache_->decompress_block(block_id, out_buf, out_data,
                                               out_size, out_logical_offset);
    }

    /// Find the block_id containing the given logical offset (relative to
    /// the record stream start, i.e. after header).  Returns 0 for
    /// non-block mode (meaningless).
    uint32_t find_block_for_offset(uint64_t logical_offset) const {
        if (!block_cache_) return 0;
        return block_cache_->find_block(logical_offset);
    }

    /// Raw byte access.
    /// For mmap'd (uncompressed / stream-compressed + temp) traces, this
    /// returns the mmap base pointer.  For block-compressed traces, this
    /// returns nullptr — callers must use data_at() instead.
    const uint8_t* data() const {
        return static_cast<const uint8_t*>(mapped_);
    }

    /// Access byte at a given logical file offset.
    /// Works for both mmap'd and block-compressed traces.
    /// For block-compressed mode, the pointer is valid until the containing
    /// block is evicted from the LRU cache; use pin_all()/unpin_all() if
    /// you need longer lifetime.
    const uint8_t* data_at(uint64_t offset) const {
        if (block_cache_) {
            // In block mode, offset is a logical file offset (header + records).
            // The block cache uses logical offsets relative to the record start
            // (i.e. after the header), so subtract header_size_.
            return block_cache_->data_at(offset - header_size_);
        }
        return data() + offset;
    }

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
rv.is_v7 = (header_.flags & qbditrace::QBDITRACE_HF_HAS_FPR) != 0;
rv.is_v8 = (header_.flags & qbditrace::QBDITRACE_HF_WIDE_API_ID) != 0;
return rv;
}

    // ─── Pin / unpin (block-compressed mode) ─────────────────────────────
    /// Prevent all cached blocks from being evicted. Must be balanced by
    /// unpin_all(). Safe to call in mmap mode (no-op).
    void pin_all() const {
        if (block_cache_) block_cache_->pin_all();
    }
    void unpin_all() const {
        if (block_cache_) block_cache_->unpin_all();
    }

    // ─── Sequential iteration ───────────────────────────────────────────

    class Iterator {
    public:
        Iterator(const TraceReader* reader, uint64_t offset)
            : reader_(reader), offset_(offset), current_pc_(0) {}

        // Constructor with a pre-seeded `current_pc` for v5 mid-stream seek.
        Iterator(const TraceReader* reader, uint64_t offset, uint64_t seed_pc)
            : reader_(reader), offset_(offset), current_pc_(seed_pc) {}

        // Constructor with a ThreadReader for lock-free data access.
        Iterator(const TraceReader* reader, uint64_t offset, const ThreadReader* thread_reader)
            : reader_(reader), offset_(offset), current_pc_(0), thread_reader_(thread_reader) {}

        RecordView operator*() const;
        Iterator& operator++();
        bool operator==(const Iterator& other) const { return offset_ >= other.offset_; }
        bool operator!=(const Iterator& other) const { return !(*this == other); }

        /// Current PC state (valid after at least one INST record in v5 mode).
        uint64_t current_pc() const { return current_pc_; }

    private:
        /// Read bytes at offset — uses thread_reader_ if set, otherwise reader_.
        const uint8_t* read_at(uint64_t off) const {
            if (thread_reader_) return thread_reader_->data_at(off);
            return reader_->data_at(off);
        }

        const TraceReader* reader_;
        uint64_t offset_;
        mutable uint64_t current_pc_;  // running PC for HF_PC_DELTA reconstruction
        const ThreadReader* thread_reader_ = nullptr;
    };

    Iterator begin() const;
    Iterator end() const;

    /// Create iterators that use a ThreadReader for lock-free data access.
    Iterator begin(const ThreadReader& tr) const;
    Iterator end(const ThreadReader& tr) const;

    /// Set madvise hint for access pattern
    void advise_sequential() const;
    void advise_random() const;

private:
    TraceReader() = default;

    /// Decompress a stream-compressed trace to a temp file (legacy path).
    static Result<TraceReader> decompress_to_temp(
        TraceReader&& reader, int raw_fd, void* raw_mapped, uint64_t raw_size);

    /// Initialize block-compressed reading mode.
    static Result<TraceReader> init_block_compressed(
        TraceReader&& reader);

    std::filesystem::path path_;
    int fd_ = -1;
    void* mapped_ = nullptr;
    uint64_t raw_file_size_ = 0;   // actual file size on disk (for mmap)
    uint64_t logical_size_ = 0;    // logical size (header + decompressed records)
    uint64_t header_size_ = 0;     // file header size (536 bytes)
    FileHeader header_;
    // When reading a compressed trace, the decompressed data lives in a temp
    // file that we own.  We keep the path so the destructor can unlink it.
    std::filesystem::path temp_path_;
    // Block-compressed mode: on-demand decompression with LRU cache.
    // When non-null, data_at() goes through block_cache_ instead of mmap.
    mutable std::unique_ptr<BlockCacheReader> block_cache_;
};

}  // namespace tenet
