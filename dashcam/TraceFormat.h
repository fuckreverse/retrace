/*
 * qbditrace - high performance instruction tracer built on QBDI
 *
 * TraceFormat.h
 *
 * Binary trace format shared between the injected tracer (writer) and the
 * offline decoder (reader). The format is designed for maximum write speed on
 * the hot path: fixed file header, per-thread record streams, variable-length
 * records that store only the *changes* an instruction produced (register diff,
 * NZCV, memory accesses), plus periodic full register snapshots ("anchors") so
 * the decoder can reliably rebuild the complete register state at any point.
 *
 * Endianness: little-endian (native to AArch64 / x86_64 targets).
 * All multi-byte integers are stored in native byte order; the decoder runs on
 * the same host class so no conversion is performed.
 */
#ifndef QBDITRACE_TRACEFORMAT_H_
#define QBDITRACE_TRACEFORMAT_H_

#include <stdint.h>

#ifdef __cplusplus
namespace qbditrace {
#endif

/* Bump whenever the on-disk layout changes incompatibly.
 * v7 changes vs v6 (backward-incompatible, gated by HF_HAS_FPR flag):
 *   - ANCHOR records optionally carry a FPR snapshot appended after the GPR
 *     block: 32 × 16-byte values (v0..v31, each stored as two little-endian
 *     uint64_t, lo then hi). When HF_HAS_FPR is set the anchor byte size is
 *     sizeof(anchor_head) + num_gpr*8 + 32*16 = 16 + 272 + 512 = 800 bytes.
 *   - REC_INST gains an optional FPR diff section interleaved between the GPR
 *     diff section and the memory access section:
 *       n_fprdiff × qbditrace_fprdiff_t  (24 bytes each)
 *     The n_fprdiff count is stored in bits[7:0] of the `n_fprdiff` byte
 *     appended to the existing 4-byte INST header fields.
 *     For backward-compatibility this byte occupies the first reserved[0]
 *     position; v4/v5/v6 readers that read it as reserved[0] simply see a
 *     non-zero padding byte, which is harmless.
 *     On-disk INST layout (v7, HF_PC_DELTA not set):
 *       qbditrace_inst_head_v7_t  (8 bytes)
 *       n_regdiff  × qbditrace_regdiff_t   (16 bytes each)
 *       n_fprdiff  × qbditrace_fprdiff_t   (24 bytes each)
 *       n_mem      × qbditrace_memacc_*    (32 or 48 bytes each)
 *     When HF_PC_DELTA is also set, the v7 INST header is
 *       qbditrace_inst_head_v7_v5_t (8 bytes).
 *     Readers that do not recognise HF_HAS_FPR must reject the file.
 * v6 changes vs v5 (backward-incompatible, gated by HF_OLD_VALUE flag):
 *   - qbditrace_memacc_t gains two new fields: `old_value` and `old_value_hi`.
 *     When HF_OLD_VALUE is set in the file header, every WRITE memory access
 *     carries the bytes that were in memory BEFORE the write executed.
 *     This enables true time-travel: the decoder can "undo" any write by
 *     restoring the old value, enabling reverse-execution queries without
 *     rescanning from the start.
 *     The struct grows from 32 bytes to 48 bytes (two extra 8-byte fields).
 *     Readers that do not recognise HF_OLD_VALUE must reject or ignore the file.
 * v5 changes vs v4 (backward-incompatible, gated by HF_PC_DELTA flag):
 *   - REC_INST uses qbditrace_inst_head_v5_t: the 8-byte absolute `pc` field
 *     is replaced by a 2-byte signed `pc_delta` (little-endian int16).
 *     AArch64 sequential execution: delta = +4 (fits in 1-2 bytes after VLE).
 *     For taken branches / irregular deltas, the writer stores the raw delta;
 *     if |delta| overflows int16 it falls back to emitting a full ANCHOR first
 *     (which re-anchors the decoder's running PC) and then delta = ±4.
 *     The decoder reconstructs the absolute PC as: pc = prev_pc + pc_delta.
 *     The HF_PC_DELTA flag in the file header activates this layout.
 *   - No other record types are changed. Readers that do not recognise
 *     HF_PC_DELTA should reject the file (or treat it as unknown version).
 * v4 changes vs v3:
 *   - New REC_CODE record carries the raw instruction bytes for each distinct
 *     executed PC (emitted once, on first sight). With it the offline decoder
 *     can disassemble straight from the trace file, so --image is optional.
 *     The HF_HAS_CODE header flag advertises that an embedded code table is
 *     present. Only executed instructions are stored (deduplicated by PC), so
 *     the cost is "distinct instructions executed x ~6 bytes", not per-step.
 * v3 changes vs v2:
 *   - REC_INST register diffs no longer store prev_value (the decoder rebuilds
 *     it from the running register file), shrinking each diff 17B -> 9B.
 *   - REC_MEMACC carries a second value word (value_hi) so 9..16 byte stores
 *     (stp x,x / 128-bit NEON) keep their value instead of <unknown>.
 *   - ANCHORs are emitted on an interval (or after a control-flow reset) rather
 *     than on every sequence entry, removing the dominant space cost.
 */
#define QBDITRACE_MAGIC 0x51424454u /* "QBDT" */
#define QBDITRACE_VERSION 4u  /* writer still produces v4 unless HF_PC_DELTA is set */
#define QBDITRACE_VERSION_V5_PC_DELTA 5u  /* version tag written when HF_PC_DELTA is used */
#define QBDITRACE_VERSION_V6_OLD_VALUE 6u /* version tag written when HF_OLD_VALUE is used */
#define QBDITRACE_VERSION_V7_HAS_FPR   7u /* version tag written when HF_HAS_FPR is used */
#define QBDITRACE_VERSION_V8_CALL_META 8u /* v8 call metadata: CAPI/OBJC/RETVAL */
#define QBDITRACE_VERSION_V9_MEMIMG   9u /* v9: REC_MEMIMG memory snapshot chunks */
/* Source compatibility for the short-lived wide-id name. */
#define QBDITRACE_VERSION_V8_WIDE_API_ID QBDITRACE_VERSION_V8_CALL_META

/* Architecture tags (kept independent of QBDI enums for decoder portability). */
typedef enum {
  QBDITRACE_ARCH_AARCH64 = 1,
  QBDITRACE_ARCH_X86_64 = 2,
} qbditrace_arch_t;

/* Target OS tags — identifies the OS on which the trace was recorded.
 * Stored in the first 4 bytes of the file header's reserved[] area so that
 * older readers (which zero-fill reserved[]) silently treat new traces as
 * QBDITRACE_OS_UNKNOWN. */
typedef enum {
  QBDITRACE_OS_UNKNOWN = 0,  /* pre-target_os traces (reserved[] was all zeros) */
  QBDITRACE_OS_IOS     = 1,  /* iOS / macOS (Darwin kernel) */
  QBDITRACE_OS_ANDROID = 2,  /* Android (Linux kernel, Bionic libc) */
  QBDITRACE_OS_LINUX   = 3,  /* Desktop / server Linux */
} qbditrace_target_os_t;

/*
 * File header. Written once at the start of trace.bin. Contains everything the
 * decoder needs to relocate addresses back to the static (on-disk) image and to
 * interpret register indices.
 *
 * Address normalization:
 *   static_address = runtime_address - module_slide
 * The decoder uses module_slide + module_base to map traced PCs back onto the
 * binary you opened in IDA/Ghidra.
 */
typedef struct {
  uint32_t magic;        /* QBDITRACE_MAGIC */
  uint32_t version;      /* QBDITRACE_VERSION */
  uint32_t arch;         /* qbditrace_arch_t */
  uint32_t num_gpr;      /* number of GPR slots captured in a snapshot */
  uint64_t module_base;  /* runtime base address of the traced module */
  uint64_t module_slide; /* ASLR slide (runtime_base - static_preferred_base) */
  uint64_t trace_start;  /* runtime start address of the traced range */
  uint64_t trace_end;    /* runtime end address (excluded) of the traced range */
  uint64_t flags;        /* qbditrace_header_flags */
  char module_name[256]; /* NUL-terminated, best-effort module path */
  uint32_t target_os;    /* qbditrace_target_os_t — 0 for old traces (was reserved[0..3]) */
  uint8_t reserved[220]; /* pad header to 536 bytes for easy hex inspection */
} qbditrace_file_header_t;

typedef enum {
  QBDITRACE_HF_HAS_MEM  = 1u << 0, /* records may carry memory accesses */
  QBDITRACE_HF_HAS_NZCV = 1u << 1,
  QBDITRACE_HF_REG_DIFF = 1u << 2, /* records store reg diff (vs full snapshot) */
  QBDITRACE_HF_HAS_CODE = 1u << 3, /* stream contains REC_CODE (raw insn bytes) */
  /* v5: REC_INST uses pc_delta (int16) instead of absolute pc (uint64).
   * The decoder maintains a running `current_pc` and reconstructs each
   * instruction's absolute address as: current_pc += pc_delta.
   * Writers that overflow int16 emit an ANCHOR (which carries the full PC)
   * and resume from delta = 0 after it.
   * Incompatible with v4 readers — check this flag before parsing. */
  QBDITRACE_HF_PC_DELTA = 1u << 4,
  /* v6: qbditrace_memacc_v6_t extends the memory access record with two
   * additional 8-byte fields (old_value, old_value_hi) that capture the bytes
   * in memory BEFORE the write was performed. The struct grows from 32 bytes to
   * 48 bytes; only WRITE accesses carry old values (READ accesses leave these
   * fields zeroed). When this flag is set, sizeof(qbditrace_memacc_t) == 48 in
   * the on-disk layout; readers that don't support v6 must reject the file.
   * Enabling this flag also bumps the file version to QBDITRACE_VERSION_V6_OLD_VALUE. */
  QBDITRACE_HF_OLD_VALUE = 1u << 5,
  /* v7: ANCHOR records carry a 512-byte FPR snapshot (v0..v31) appended after
   * the GPR block, and INST records carry an FPR diff section between the GPR
   * diffs and the memory accesses. See qbditrace_fprdiff_t and the v7 INST
   * header types. Readers that do not support v7 must reject the file.
   * Enabling this flag also bumps the file version to QBDITRACE_VERSION_V7_HAS_FPR. */
  QBDITRACE_HF_HAS_FPR = 1u << 6,
  /* Legacy zstd stream compression. When set, the file header (536 bytes) is
   * stored uncompressed and all bytes after it are one zstd frame. The current
   * qbditrace writer emits HF_BLOCK_COMPRESSED instead; this flag remains part
   * of the format contract so readers can open historical single-frame traces.
   * This flag is orthogonal to version — any version (v4–v7) may carry it. */
  QBDITRACE_HF_COMPRESSED = 1u << 7,
  /* Block-compressed format. When set, the data after the file header is laid
   * out as:
   *
   *   [block_index_footer]   ← last 16 bytes of file
   *     uint64_t  index_offset;    — file offset of the block index table
   *     uint32_t  block_count;     — number of blocks
   *     uint32_t  magic;           — QBDITRACE_BLOCK_INDEX_MAGIC (0x51424249)
   *
   *   [block_index_table]    ← at `index_offset`, block_count entries:
   *     per entry (24 bytes):
   *       uint64_t  original_offset;     — logical (decompressed) offset from
   *                                        start of records (after header)
   *       uint64_t  compressed_offset;   — physical file offset of the block
   *       uint32_t  original_size;       — decompressed size of this block
   *       uint32_t  compressed_size;     — compressed size on disk
   *
   *   [block data]           ← each block is an independent zstd frame
   *
   * The logical (decompressed) record stream is identical to the uncompressed
   * format. Each block decompresses independently, enabling random access with
   * O(1) block lookups. Default block size: 1 MB decompressed.
   *
   * HF_COMPRESSED and HF_BLOCK_COMPRESSED are mutually exclusive.
   * This flag is orthogonal to version — any version (v4–v7) can use it. */
  QBDITRACE_HF_BLOCK_COMPRESSED = 1u << 8,
  /* Branch-hint encoding in nzcv high bits.  When set, every REC_INST record
   * encodes the instruction's branch class in the high 4 bits of the `nzcv`
   * byte (bits[7:4]).  The low 4 bits retain the normal N/Z/C/V flags.
   *
   * High-nibble encoding (bits[7:4]):
   *   0b0000  (0)  — ordinary instruction (not a branch)
   *   0b0001  (1)  — CALL  (BL / BLR)
   *   0b0010  (2)  — RET   (RET, RETAA, RETAB)
   *   0b0100  (4)  — BRANCH (B, BR — unconditional non-call jump)
   *
   * This allows offline decoders (e.g. tenet FunctionPass) to skip the
   * per-instruction binary search in the pc_kind table for the vast majority
   * of instructions (ordinary) and use a fast bit-shift for branch-class
   * instructions (~2–5% of the stream).  Zero additional bytes on disk.
   *
   * Backward compatibility: on traces without this flag the high nibble is
   * always 0 (old writers never set it), so old readers that ignore the high
   * nibble see no change.  New readers can detect this flag and skip the
   * pc_kind table lookup when the high nibble is non-zero; they fall back to
   * the table for instructions whose high nibble is 0 (which includes all
   * instructions on older traces). */
  QBDITRACE_HF_BRANCH_HINT = 1u << 9,
  /* v8 call metadata. When set, every OBJC/CAPICALL record in the file uses
   * its v8 layout, and REC_RETVAL records may be present. This flag is a
   * file-wide layout contract; writers must not select layouts per record. */
  QBDITRACE_HF_CALL_META = 1u << 10,
  /* Source compatibility alias for the initial v8 prototype. */
  QBDITRACE_HF_WIDE_API_ID = QBDITRACE_HF_CALL_META,
  /* v9: the stream contains REC_MEMIMG records (memory-image snapshot chunks
   * captured at configure() time, before the first traced instruction).
   * All MEMIMG records appear BEFORE the first REC_INST in the logical
   * stream, so a reader can collect them with a cheap prefix scan.
   * Enabling this flag also bumps the file version to
   * QBDITRACE_VERSION_V9_MEMIMG; readers that do not support v9 must reject
   * the file (unknown record kinds cannot be skipped safely by old readers). */
  QBDITRACE_HF_MEMIMG = 1u << 11,
} qbditrace_header_flags;

/* Branch-hint nibble values (bits[7:4] of the nzcv byte in REC_INST). */
#define QBDITRACE_BRANCH_HINT_NONE   0u  /* ordinary instruction */
#define QBDITRACE_BRANCH_HINT_CALL   1u  /* BL / BLR */
#define QBDITRACE_BRANCH_HINT_RET    2u  /* RET / RETAA / RETAB */
#define QBDITRACE_BRANCH_HINT_BRANCH 4u  /* B / BR (unconditional jump) */

#define QBDITRACE_BLOCK_INDEX_MAGIC 0x51424249u /* "QBBI" */
#define QBDITRACE_DEFAULT_BLOCK_SIZE (1u << 20) /* 1 MB decompressed */

/* On-disk footer stored as the last 16 bytes of a block-compressed trace. */
typedef struct {
  uint64_t index_offset;   /* file offset of the first block index entry */
  uint32_t block_count;    /* number of compressed blocks */
  uint32_t magic;          /* QBDITRACE_BLOCK_INDEX_MAGIC */
} qbditrace_block_footer_t;

/* One entry in the block index table. */
typedef struct {
  uint64_t original_offset;   /* logical byte offset (decompressed, from rec start) */
  uint64_t compressed_offset; /* physical file offset of the compressed block */
  uint32_t original_size;     /* decompressed byte count */
  uint32_t compressed_size;   /* compressed byte count on disk */
} qbditrace_block_entry_t;

/*
 * Each record begins with a single-byte `kind` tag selecting the record
 * variant; the remainder of the record depends on the kind.
 */
typedef enum {
  QBDITRACE_REC_INST = 0,     /* per-instruction diff record */
  QBDITRACE_REC_ANCHOR = 1,   /* full register snapshot (rebuild checkpoint) */
  QBDITRACE_REC_THREAD = 2,   /* thread context marker */
  QBDITRACE_REC_EVENT = 3,    /* VM event (sequence/exec-transfer) */
  QBDITRACE_REC_SVC = 4,      /* supervisor call (syscall) site */
  QBDITRACE_REC_OBJC = 5,     /* objc_msgSend-family dispatch site */
  QBDITRACE_REC_CODE = 6,     /* raw instruction bytes for one distinct PC */
  QBDITRACE_REC_CAPICALL = 7, /* C/platform API call site with semantic args */
  QBDITRACE_REC_RETVAL = 8,   /* return fact for OBJC/CAPI/SVC */
  QBDITRACE_REC_MEMIMG = 9,   /* memory-image snapshot chunk (configure-time) */
} qbditrace_record_kind_t;

/* ---- QBDITRACE_REC_INST ----
 * On-disk layout: structures are written with std::memcpy(p, &struct, sizeof(struct)),
 * so the C compiler's natural alignment padding IS present in the stream.
 * Decoder must use sizeof() to determine field offsets, NOT hand-counted byte sizes.
 *
 * Effective sizes on AArch64/x86_64 (64-bit, 8-byte alignment for uint64_t):
 *   qbditrace_inst_head_t   = 16 bytes  (4B fields + 4B pad + 8B pc)
 *   qbditrace_inst_head_v5_t = 6 bytes  (4B fields + 2B pc_delta, no pad needed)
 *   qbditrace_regdiff_t      = 16 bytes (1B reg_index + 7B pad + 8B value)
 *   qbditrace_memacc_t       = 32 bytes (4B fields + 4B pad + 8B addr + 8B value + 8B value_hi)
 *
 * Logical layout (v4, HF_PC_DELTA not set):
 *   qbditrace_inst_head_t  (16 bytes)
 *   n_regdiff * qbditrace_regdiff_t  (16 bytes each)
 *   n_mem      * qbditrace_memacc_t  (32 bytes each)
 *
 * reg_index uses the QBDI GPR ordering (0=x0 ... 30=lr, 31=sp, 32=nzcv, 33=pc).
 * The previous value is NOT stored: the decoder rebuilds the register file from
 * anchors + diffs and therefore already knows the value before this write.
 * mem_type:  bit0 read, bit1 write (matches QBDI MemoryAccessType).
 * mem_flags: bit0 unknown_size, bit1 minimum_size, bit2 unknown_value
 *            (matches QBDI MemoryAccessFlags).
 * For stores of 9..16 bytes the low 8 bytes are in `value` and the high bytes
 * in `value_hi`; for <=8 byte accesses `value_hi` is 0.
 */
typedef struct {
  uint8_t kind;
  uint8_t nzcv;
  uint8_t n_regdiff;
  uint8_t n_mem;
  uint64_t pc;
} qbditrace_inst_head_t;

/* v5 variant (HF_PC_DELTA): identical to qbditrace_inst_head_t except the
 * 8-byte absolute `pc` is replaced by a 2-byte signed `pc_delta` (LE int16).
 * Record size: 6 bytes (vs 16 bytes for v4), reducing the INST record header
 * size by over 60% for sequential code (delta = +4 every instruction).
 *
 * The decoder maintains a `running_pc` state variable:
 *   running_pc += pc_delta   after reading each REC_INST
 * REC_ANCHOR resets `running_pc` to the anchor's absolute PC (carried in the
 * anchor's existing `pc` field, which is always 8-byte absolute).
 *
 * Writers that produce a delta outside [-32768, +32767] must emit an ANCHOR
 * immediately before the problematic INST and set pc_delta = 0.
 */
typedef struct {
  uint8_t  kind;
  uint8_t  nzcv;
  uint8_t  n_regdiff;
  uint8_t  n_mem;
  int16_t  pc_delta; /* signed delta from previous instruction's PC (LE) */
} qbditrace_inst_head_v5_t;

/* v7 variant (HF_HAS_FPR, HF_PC_DELTA not set): extends the v4 header with
 * an n_fprdiff byte and a reserved byte to keep the struct naturally aligned.
 * On-disk layout after this header:
 *   n_regdiff × qbditrace_regdiff_t
 *   n_fprdiff × qbditrace_fprdiff_t
 *   n_mem     × qbditrace_memacc_* (v4/v5/v6 size depending on other flags)
 */
typedef struct {
  uint8_t  kind;
  uint8_t  nzcv;
  uint8_t  n_regdiff;
  uint8_t  n_mem;
  uint64_t pc;
  uint8_t  n_fprdiff;
  uint8_t  reserved_v7[7]; /* pad to keep subsequent sections 8-byte aligned */
} qbditrace_inst_head_v7_t;

/* v7 + HF_PC_DELTA variant: 6-byte base (v5 style) + n_fprdiff + reserved. */
typedef struct {
  uint8_t  kind;
  uint8_t  nzcv;
  uint8_t  n_regdiff;
  uint8_t  n_mem;
  int16_t  pc_delta;
  uint8_t  n_fprdiff;
  uint8_t  reserved_v7; /* pad to 8 bytes total */
} qbditrace_inst_head_v7_v5_t;

/* ---- qbditrace_fprdiff_t ----
 * Records the 128-bit value of one FPR (NEON/SVE) register written by
 * an instruction.  The register is identified by `fpr_index` (0..31 for
 * v0..v31 on AArch64).  The full 128-bit value is stored as two 64-bit
 * words in little-endian order: `lo` = bits[63:0], `hi` = bits[127:64].
 *
 * On-disk layout: 24 bytes (1B index + 7B pad + 8B lo + 8B hi).
 */
typedef struct {
  uint8_t  fpr_index;  /* 0..31 (v0..v31 on AArch64) */
  uint8_t  reserved[7];
  uint64_t lo;         /* bits  63:0  of the vector register */
  uint64_t hi;         /* bits 127:64 of the vector register */
} qbditrace_fprdiff_t;

typedef struct {
  uint8_t reg_index;
  uint64_t value; /* value after the instruction executed */
} qbditrace_regdiff_t;

typedef struct {
  uint8_t mem_type;
  uint8_t mem_flags;
  uint16_t size;
  uint64_t addr;
  uint64_t value;    /* low 8 bytes (for size<=8 this is the whole value) */
  uint64_t value_hi; /* high bytes for 9..16 byte stores; 0 otherwise */
} qbditrace_memacc_t;

/* v6 extension of qbditrace_memacc_t (HF_OLD_VALUE).
 * When HF_OLD_VALUE is set in the file header, every memory access record is
 * this larger struct (48 bytes) instead of qbditrace_memacc_t (32 bytes).
 * The old_value / old_value_hi fields capture the memory content BEFORE the
 * write was performed (time-travel: "what was here before?").
 * For READ accesses: old_value and old_value_hi are zero (reads don't overwrite).
 * For WRITE accesses: old_value[_hi] = bytes at addr before the instruction ran.
 * If the pre-write read fails (guard page, unmapped): both fields stay zero and
 * QBDITRACE_MF_OLD_UNKNOWN is set in mem_flags. */
typedef struct {
  uint8_t mem_type;
  uint8_t mem_flags;
  uint16_t size;
  uint64_t addr;
  uint64_t value;        /* new value low  8 bytes */
  uint64_t value_hi;     /* new value high 8 bytes (9..16 byte stores) */
  uint64_t old_value;    /* old value low  8 bytes (writes only; 0 for reads) */
  uint64_t old_value_hi; /* old value high 8 bytes (writes only; 0 for reads) */
} qbditrace_memacc_v6_t;

/* mem_flags extension for v6: set when old_value could not be captured.
 * Fits in the existing mem_flags byte (bits 0-2 used by QBDI MemoryAccessFlags). */
#define QBDITRACE_MF_OLD_UNKNOWN (1u << 3) /* old value unavailable (guard page etc.) */

/* ---- QBDITRACE_REC_ANCHOR ----
 * Layout (v4/v5/v6, HF_HAS_FPR not set):
 *   u8  kind            (== QBDITRACE_REC_ANCHOR)
 *   u8  reserved[3]
 *   u64 pc              (runtime address where the snapshot was taken)
 *   u64 regs[num_gpr]   (full GPR snapshot, indexed by QBDI GPR ordering)
 *
 * Layout (v7, HF_HAS_FPR set): same as above, then immediately followed by:
 *   u64 fpr_lo[32]      (bits  63:0  of v0..v31)
 *   u64 fpr_hi[32]      (bits 127:64 of v0..v31)
 * Total appended FPR block: 32*8 + 32*8 = 512 bytes.
 * Total anchor size: 16 + 272 + 512 = 800 bytes.
 */
typedef struct {
  uint8_t kind;
  uint8_t reserved[3];
  uint64_t pc;
  /* followed by num_gpr * u64 */
} qbditrace_anchor_head_t;

/* ---- QBDITRACE_REC_THREAD ----
 * Layout:
 *   u8  kind            (== QBDITRACE_REC_THREAD)
 *   u8  reserved[3]
 *   u64 thread_id
 * Emitted at the start of each per-thread stream so the decoder can attribute
 * the following records to a thread.
 */
typedef struct {
  uint8_t kind;
  uint8_t reserved[3];
  uint64_t thread_id;
} qbditrace_thread_head_t;

/* ---- QBDITRACE_REC_EVENT ----
 * Layout:
 *   u8  kind            (== QBDITRACE_REC_EVENT)
 *   u8  event           (qbditrace_event_t)
 *   u8  reserved[2]
 *   u64 addr
 */
typedef enum {
  QBDITRACE_EV_SEQ_ENTRY = 1,
  QBDITRACE_EV_SEQ_EXIT = 2,
  QBDITRACE_EV_XFER_CALL = 3,   /* left traced range into uninstrumented code */
  QBDITRACE_EV_XFER_RETURN = 4, /* returned back into traced range */
} qbditrace_event_t;

/* ---- QBDITRACE_REC_EVENT ----
 * For XFER_CALL the `addr` field carries the *target* address the execution
 * transferred to (e.g. the resolved IMP / library routine entry); `site`
 * carries the PC of the call site inside the traced range. For XFER_RETURN the
 * `addr` is the return target inside the traced range and `site` is 0.
 */
typedef struct {
  uint8_t kind;
  uint8_t event;
  uint8_t reserved[2];
  uint64_t addr;
  uint64_t site; /* call-site PC for XFER_CALL; 0 otherwise */
} qbditrace_event_head_t;

/* ---- QBDITRACE_REC_SVC ----
 * Emitted just before an `svc #0` executes. Captures the syscall number plus
 * the first six argument registers so the decoder can name the syscall and show
 * its arguments.
 *   - Darwin arm64: syscall number is in x16.
 *   - Linux/Android arm64: syscall number is in x8.
 *   u8  kind            (== QBDITRACE_REC_SVC)
 *   u8  reserved[3]
 *   u64 pc              (address of the svc instruction)
 *   u64 syscall_no      (x16 on Darwin, x8 on Linux/Android)
 *   u64 args[6]         (x0..x5)
 */
typedef struct {
  uint8_t kind;
  uint8_t reserved[3];
  uint64_t pc;
  uint64_t syscall_no;
  uint64_t args[6];
} qbditrace_svc_head_t;

/* ---- QBDITRACE_REC_OBJC ----
 * Emitted just before a call into an objc_msgSend-family dispatcher. Captures
 * the receiver (x0) and selector pointer (x1) so the decoder can resolve the
 * class name and the selector string offline.
 *   u8  kind            (== QBDITRACE_REC_OBJC)
 *   u8  variant         (qbditrace_objc_variant_t)
 *   u8  reserved[2]
 *   u64 pc              (call-site PC)
 *   u64 recv            (x0: receiver / super struct ptr)
 *   u64 sel             (x1: selector ptr, or x2 for *Super variants)
 *   char cls[48]        (NUL-terminated receiver class name captured at runtime
 *                        via object_getClassName; empty if unavailable. The
 *                        class can only be resolved live, not from the static
 *                        image, so the tracer records it here.)
 */
typedef enum {
  QBDITRACE_OBJC_MSGSEND = 0,
  QBDITRACE_OBJC_MSGSEND_SUPER = 1,
  QBDITRACE_OBJC_MSGSEND_SUPER2 = 2,
  QBDITRACE_OBJC_MSGSEND_STRET = 3,
} qbditrace_objc_variant_t;

typedef struct {
  uint8_t kind;
  uint8_t variant;
  uint8_t reserved[2];
  uint64_t pc;
  uint64_t recv;
  uint64_t sel;
  char cls[48]; /* runtime class name of recv, NUL-terminated; "" if unknown */
} qbditrace_objc_head_t;

/* v8 fixed OBJC header. The fixed portion remains 80 bytes; selector_name is
 * appended as sel_len content bytes plus a NUL, padded to 4-byte alignment. */
typedef struct {
  uint8_t kind;
  uint8_t variant;
  uint8_t sel_len;
  uint8_t flags;
  uint32_t reserved;
  uint64_t pc;
  uint64_t recv;
  uint64_t sel;
  char cls[48];
} qbditrace_objc_head_v8_t;

#define QBDITRACE_OBJC_FL_SEL_TRUNCATED (1u << 0)
#define QBDITRACE_OBJC_FL_SEL_READ_FAIL (1u << 1)
#define QBDITRACE_OBJC_MAX_SEL_BYTES 255u

/* ---- QBDITRACE_REC_CODE ----
 * Raw bytes of one distinct executed instruction, emitted exactly once the
 * first time that PC is seen (deduplicated by the tracer). Lets the offline
 * decoder disassemble without an external --image. `pc` is the runtime address;
 * the decoder normalizes it to a static address the same way it does for INST
 * records (static = pc - module_slide).
 *   u8  kind            (== QBDITRACE_REC_CODE)
 *   u8  size            (instruction length in bytes; 4 on AArch64)
 *   u8  reserved[2]
 *   u64 pc              (runtime address of the instruction)
 *   u8  bytes[size]     (raw little-endian encoding)
 */
typedef struct {
  uint8_t kind;
  uint8_t size;
  uint8_t reserved[2];
  uint64_t pc;
  /* followed by `size` raw bytes */
} qbditrace_code_head_t;

/* ---- QBDITRACE_REC_CAPICALL ----
 * Emitted just before a call into a well-known C/platform API function exits
 * the traced range (via EXEC_TRANSFER_CALL). Carries the function identity
 * (api_id), the raw argument registers (x0..x7), and an optional inline string
 * payload for pointer-argument dereferencing (e.g. the content of the src/dst
 * buffers for mem*, the string passed to strcmp, etc.).
 *
 * This record enables tenet to answer "what did memcpy/memset/strcmp/strlen/
 * fopen/... actually receive?" without having to symbolicate a library address
 * offline and without per-instruction instrumentation of the library itself.
 *
 * On-disk layout:
 *   u8  kind            (== QBDITRACE_REC_CAPICALL)
 *   u8  api_id          (qbditrace_capi_id_t, 0 = unknown)
 *   u8  arg_count       (number of valid entries in args[], 0..8)
 *   u8  str_count       (number of inline C-string captures, 0..4)
 *   u64 pc              (call-site PC inside the traced range)
 *   u64 target          (runtime address of the called function)
 *   u64 args[8]         (x0..x7 at call time; only arg_count entries are valid)
 *   --- followed by str_count variable-length C strings ---
 *   For each string capture:
 *     u8  str_arg_idx   (which arg index this string came from, 0..7)
 *     u8  str_len       (length of string content in bytes, not counting NUL)
 *     u8  str_flags     (QBDITRACE_SF_* bits)
 *     u8  _reserved
 *     char str_data[str_len + 1]  (NUL-terminated; padded to 4-byte alignment)
 *
 * The fixed portion is sizeof(qbditrace_capicall_head_t) bytes (88 bytes);
 * variable string captures are appended immediately after and are parsed by
 * the decoder using str_count as the loop bound.
 *
 * str_flags bits:
 *   bit 0 (QBDITRACE_SF_TRUNCATED): string was longer than CAPICALL_MAX_STR_BYTES
 *          and was truncated; the stored content is the first str_len bytes.
 *   bit 1 (QBDITRACE_SF_BINARY):    string contains non-printable bytes; content
 *          is the raw memory bytes (may not be valid UTF-8 / C string).
 *   bit 2 (QBDITRACE_SF_SAFE_READ_FAIL): the memory probe returned an error;
 *          str_len is 0 and str_data is empty (capture failed gracefully).
 *
 * Maximum single string payload: QBDITRACE_CAPICALL_MAX_STR_BYTES = 256 bytes
 * Maximum string captures per record: 4 (str_count <= 4)
 * Maximum total per-record variable bytes: 4 × (4 + 256 + 1 + pad) ≈ 1 KB
 */

/* Maximum bytes captured from a single string/buffer argument.
 * Must fit in uint8_t str_len field (max 255). */
#define QBDITRACE_CAPICALL_MAX_STR_BYTES 255u
/* Maximum number of string captures per REC_CAPICALL record. */
#define QBDITRACE_CAPICALL_MAX_STR_CAPS  4u

/* Bit flags for per-string capture status (str_flags field). */
#define QBDITRACE_SF_TRUNCATED      (1u << 0) /* content truncated at MAX_STR_BYTES */
#define QBDITRACE_SF_BINARY         (1u << 1) /* raw bytes, not a C string */
#define QBDITRACE_SF_SAFE_READ_FAIL (1u << 2) /* safeRead failed; capture is empty */

/* The legacy v4-v7 layout stores api_id in uint8_t. Under the file-wide v8
 * HF_CALL_META contract every CAPICALL uses qbditrace_capicall_head_v8_t,
 * regardless of the actual id, so a file never mixes legacy and v8 layouts. */

/* Fixed header for REC_CAPICALL (v4-v7, HF_WIDE_API_ID not set).
 * Variable-length string captures follow.
 * NOTE: api_id is uint8_t here, which truncates ids >= 256.
 * Use qbditrace_capicall_head_v8_t (with HF_WIDE_API_ID) for full range. */
typedef struct {
  uint8_t  kind;       /* == QBDITRACE_REC_CAPICALL */
  uint8_t  api_id;     /* qbditrace_capi_id_t — truncated to 0..255; use v8 for full range */
  uint8_t  arg_count;  /* number of valid entries in args[] (0..8) */
  uint8_t  str_count;  /* number of inline string captures that follow (0..4) */
  uint64_t pc;         /* call-site PC (inside the traced range) */
  uint64_t target;     /* runtime address of the called function */
  uint64_t args[8];    /* x0..x7 at call time */
} qbditrace_capicall_head_t;

/* Fixed header for REC_CAPICALL (v8, HF_CALL_META set). The field order keeps
 * the fixed header at 88 bytes while widening api_id to uint16_t. */
typedef struct {
  uint8_t  kind;
  uint8_t  arg_count;
  uint8_t  str_count;
  uint8_t  flags;
  uint16_t api_id;
  uint16_t reserved;
  uint64_t pc;
  uint64_t target;
  uint64_t args[8];
} qbditrace_capicall_head_v8_t;

/* Self-describing return fact. record_size permits future extension while old
 * v8 readers can skip the complete record. source_kind is one of SVC/OBJC/
 * CAPICALL. source_id preserves the complete source identity (notably the
 * full 64-bit Darwin syscall selector); aux_id is a compact variant/API hint.
 * x0/x1/nzcv are the raw architectural return state. */
typedef struct {
  uint8_t  kind;
  uint8_t  source_kind;
  uint8_t  flags;
  uint8_t  reserved8;
  uint16_t aux_id;
  uint16_t record_size;
  uint64_t source_id;
  uint64_t site;
  uint64_t target;
  uint64_t resume;
  uint64_t x0;
  uint64_t x1;
  uint32_t nzcv;
  uint32_t reserved32;
} qbditrace_retval_t;

/* Reserved for producers that can prove an errno value belongs to the call.
 * The native SVC producer intentionally does not set this from ambient TLS. */
#define QBDITRACE_RET_FL_ERRNO_VALID (1u << 0)

/* Per-string capture header (precedes the str_data bytes). */
typedef struct {
  uint8_t str_arg_idx; /* index into args[] (0..7) that this string came from */
  uint8_t str_len;     /* byte length of str_data (not counting trailing NUL) */
  uint8_t str_flags;   /* QBDITRACE_SF_* bits */
  uint8_t _reserved;
  /* followed by str_len + 1 bytes of NUL-terminated content, padded to 4B alignment */
} qbditrace_capicall_str_t;

/* ---- QBDITRACE_REC_MEMIMG ----
 *
 * One chunk of a process-memory snapshot captured at qbditrace_configure()
 * time (i.e. the state BEFORE the first traced instruction executes).  The
 * writer emits these only when the caller opts in via
 * qbditrace_config_t::enable_mem_snapshot + snapshot_ranges[].
 *
 * Purpose: give the offline analyser (tenet) a base layer for addresses that
 * were set up by UNINSTRUMENTED code before tracing started (decrypted
 * strings/keys in .data/.bss, runtime-filled tables) and are never written
 * by traced code.  tenet layers it UNDER the per-instruction write/read log:
 * a byte resolved from the write or read log always wins; the snapshot only
 * fills bytes that have no logged access, and is explicitly tagged as
 * "snapshot" (an approximation of the value at query time).
 *
 * Layout: fixed 24-byte header followed by `len` raw bytes (no trailing
 * padding).  record_size == sizeof(header) + len, making the record fully
 * self-describing (readers may skip it via record_size alone).
 *
 * Stream contract: ALL MEMIMG records precede the first REC_INST record.
 * Chunks belonging to one configured range share monotonically increasing
 * `seq`; chunks are at most QBDITRACE_MEMIMG_CHUNK_MAX bytes of payload.
 * Ranges that are (partially) unreadable are emitted with holes: only the
 * readable runs appear as records. */
typedef struct {
  uint8_t  kind;        /* == QBDITRACE_REC_MEMIMG */
  uint8_t  flags;       /* reserved, must be 0 */
  uint16_t record_size; /* total bytes of this record (header + len) */
  uint32_t seq;         /* chunk sequence number within the snapshot (0-based) */
  uint64_t addr;        /* runtime address of data[0] */
  uint32_t len;         /* number of valid payload bytes that follow */
  uint32_t reserved;    /* must be 0 */
  /* uint8_t data[len]; — raw bytes follow immediately */
} qbditrace_memimg_t;

/* Maximum payload bytes per MEMIMG record.  Chosen so record_size
 * (24 + payload) stays well within the uint16_t record_size field. */
#define QBDITRACE_MEMIMG_CHUNK_MAX (32u * 1024u)

/* ---- qbditrace_capi_id_t ----
 * Stable numeric identifiers for well-known C / platform API functions.
 * Grouped by category; new entries must be appended (never reorder existing
 * entries — the IDs are stored in binary traces and must remain stable across
 * tracer versions). tenet uses these IDs to route records to the correct
 * semantic analysis without doing a string comparison per record.
 *
 * Platform annotation:
 *   [common]  — present on both iOS and Android (libc / standard)
 *   [ios]     — iOS / macOS only (libSystem / libobjc / CoreFoundation)
 *   [android] — Android / Bionic only
 *   [jni]     — JNI functions (Android, via art/libjni.so)
 */
typedef enum {
  /* ── 0: unknown / unclassified ─────────────────────────────────── */
  QBDITRACE_CAPI_UNKNOWN = 0,

  /* ── Memory copy / move / set (1–19) [common] ───────────────────── */
  QBDITRACE_CAPI_MEMCPY          = 1,   /* void *memcpy(dst, src, n)          */
  QBDITRACE_CAPI_MEMMOVE         = 2,   /* void *memmove(dst, src, n)         */
  QBDITRACE_CAPI_MEMSET          = 3,   /* void *memset(dst, c, n)            */
  QBDITRACE_CAPI_MEMCMP          = 4,   /* int   memcmp(a, b, n)              */
  QBDITRACE_CAPI_MEMCHR          = 5,   /* void *memchr(s, c, n)              */
  QBDITRACE_CAPI_BCOPY           = 6,   /* void  bcopy(src, dst, n) [BSD]     */
  QBDITRACE_CAPI_BZERO           = 7,   /* void  bzero(s, n)       [BSD]      */
  QBDITRACE_CAPI_MEMMEM          = 8,   /* void *memmem(hay,hl,ndl,nl)        */
  /* 9–19 reserved for future mem* variants */

  /* ── String operations (20–59) [common] ─────────────────────────── */
  QBDITRACE_CAPI_STRLEN          = 20,  /* size_t strlen(s)                   */
  QBDITRACE_CAPI_STRNLEN         = 21,  /* size_t strnlen(s, n)               */
  QBDITRACE_CAPI_STRCMP          = 22,  /* int    strcmp(a, b)                */
  QBDITRACE_CAPI_STRNCMP         = 23,  /* int    strncmp(a, b, n)            */
  QBDITRACE_CAPI_STRCASECMP      = 24,  /* int    strcasecmp(a, b)            */
  QBDITRACE_CAPI_STRNCASECMP     = 25,  /* int    strncasecmp(a, b, n)        */
  QBDITRACE_CAPI_STRCPY          = 26,  /* char  *strcpy(dst, src)            */
  QBDITRACE_CAPI_STRNCPY         = 27,  /* char  *strncpy(dst, src, n)        */
  QBDITRACE_CAPI_STRLCPY         = 28,  /* size_t strlcpy(dst, src, n) [BSD]  */
  QBDITRACE_CAPI_STRCAT          = 29,  /* char  *strcat(dst, src)            */
  QBDITRACE_CAPI_STRNCAT         = 30,  /* char  *strncat(dst, src, n)        */
  QBDITRACE_CAPI_STRLCAT         = 31,  /* size_t strlcat(dst, src, n) [BSD]  */
  QBDITRACE_CAPI_STRDUP          = 32,  /* char  *strdup(s)                   */
  QBDITRACE_CAPI_STRNDUP         = 33,  /* char  *strndup(s, n)               */
  QBDITRACE_CAPI_STRCHR          = 34,  /* char  *strchr(s, c)                */
  QBDITRACE_CAPI_STRRCHR         = 35,  /* char  *strrchr(s, c)               */
  QBDITRACE_CAPI_STRSTR          = 36,  /* char  *strstr(hay, ndl)            */
  QBDITRACE_CAPI_STRTOK          = 37,  /* char  *strtok(str, delim)          */
  QBDITRACE_CAPI_STRTOK_R        = 38,  /* char  *strtok_r(str, delim, save)  */
  QBDITRACE_CAPI_SPRINTF         = 39,  /* int    sprintf(buf, fmt, ...)      */
  QBDITRACE_CAPI_SNPRINTF        = 40,  /* int    snprintf(buf, n, fmt, ...)  */
  QBDITRACE_CAPI_SSCANF          = 41,  /* int    sscanf(str, fmt, ...)       */
  QBDITRACE_CAPI_ATOI            = 42,  /* int    atoi(s)                     */
  QBDITRACE_CAPI_ATOL            = 43,  /* long   atol(s)                     */
  QBDITRACE_CAPI_ATOLL           = 44,  /* long long atoll(s)                 */
  QBDITRACE_CAPI_STRTOL          = 45,  /* long   strtol(s, ep, base)         */
  QBDITRACE_CAPI_STRTOLL         = 46,  /* long long strtoll(s, ep, base)     */
  QBDITRACE_CAPI_STRTOUL         = 47,  /* unsigned long strtoul(s, ep, base) */
  QBDITRACE_CAPI_STRTOULL        = 48,  /* unsigned long long strtoull(...)   */
  /* 49–59 reserved for future str* variants */

  /* ── Heap allocation (60–79) [common] ───────────────────────────── */
  QBDITRACE_CAPI_MALLOC          = 60,  /* void *malloc(size)                 */
  QBDITRACE_CAPI_CALLOC          = 61,  /* void *calloc(nmemb, size)          */
  QBDITRACE_CAPI_REALLOC         = 62,  /* void *realloc(ptr, size)           */
  QBDITRACE_CAPI_FREE            = 63,  /* void  free(ptr)                    */
  QBDITRACE_CAPI_POSIX_MEMALIGN  = 64,  /* int   posix_memalign(pp,align,sz)  */
  QBDITRACE_CAPI_VALLOC          = 65,  /* void *valloc(size)                 */
  /* 66–79 reserved */

  /* ── I/O (80–99) [common] ───────────────────────────────────────── */
  QBDITRACE_CAPI_FOPEN           = 80,  /* FILE *fopen(path, mode)            */
  QBDITRACE_CAPI_FCLOSE          = 81,  /* int   fclose(FILE*)                */
  QBDITRACE_CAPI_FREAD           = 82,  /* size_t fread(ptr,sz,nmemb,FILE*)   */
  QBDITRACE_CAPI_FWRITE          = 83,  /* size_t fwrite(ptr,sz,nmemb,FILE*)  */
  QBDITRACE_CAPI_FGETS           = 84,  /* char  *fgets(s, n, FILE*)          */
  QBDITRACE_CAPI_FPUTS           = 85,  /* int    fputs(s, FILE*)             */
  QBDITRACE_CAPI_READ            = 86,  /* ssize_t read(fd, buf, n)           */
  QBDITRACE_CAPI_WRITE           = 87,  /* ssize_t write(fd, buf, n)          */
  QBDITRACE_CAPI_PREAD           = 88,  /* ssize_t pread(fd, buf, n, off)     */
  QBDITRACE_CAPI_PWRITE          = 89,  /* ssize_t pwrite(fd, buf, n, off)    */
  QBDITRACE_CAPI_OPEN            = 90,  /* int    open(path, flags, ...)      */
  QBDITRACE_CAPI_CLOSE           = 91,  /* int    close(fd)                   */
  /* 92–99 reserved */

  /* ── Crypto (libc-level) (100–129) [common] ─────────────────────── */
  QBDITRACE_CAPI_ARC4RANDOM      = 100, /* uint32_t arc4random()              */
  QBDITRACE_CAPI_ARC4RANDOM_BUF  = 101, /* void arc4random_buf(buf, nbytes)   */
  QBDITRACE_CAPI_GETRANDOM       = 102, /* ssize_t getrandom(buf, n, flags)   */

  /* ── iOS / macOS platform APIs (130–199) [ios] ───────────────────── */
  /* CoreFoundation string */
  QBDITRACE_CAPI_CF_STR_CREATE_UTF8  = 130, /* CFStringCreateWithCString(...UTF8) */
  QBDITRACE_CAPI_CF_STR_CREATE_BYTES = 131, /* CFStringCreateWithBytes(...)        */
  QBDITRACE_CAPI_CF_DATA_CREATE      = 132, /* CFDataCreate(alloc, bytes, len)     */
  QBDITRACE_CAPI_CF_DATA_GET_BYTES   = 133, /* CFDataGetBytePtr / GetLength        */
  /* CommonCrypto */
  QBDITRACE_CAPI_CC_CRYPT            = 134, /* CCCrypt(op,alg,opt,key,kl,iv,...) */
  QBDITRACE_CAPI_CC_HMAC             = 135, /* CCHmac(alg,key,kl,data,dl,mac)    */
  QBDITRACE_CAPI_CC_DIGEST           = 136, /* CC_SHA256/MD5/... (data,len,out)  */
  QBDITRACE_CAPI_CC_KEY_DERIVE_PBKDF = 137, /* CCKeyDerivationPBKDF(...)          */
  /* Security framework */
  QBDITRACE_CAPI_SEC_ITEM_COPY_MATCH = 138, /* SecItemCopyMatching(query,result) */
  QBDITRACE_CAPI_SEC_KEY_CREATE_RSA  = 139, /* SecKeyCreateWithData(...)          */
  QBDITRACE_CAPI_SEC_TRANSFORM       = 140, /* SecTransformExecute / SetAttr      */
  /* Network */
  QBDITRACE_CAPI_CF_URL_CREATE       = 141, /* CFURLCreateWithBytes(...)          */
  QBDITRACE_CAPI_NS_URL_SESSION_DT   = 142, /* NSURLSession dataTask (via msgSend)*/
  /* 143–199 reserved for iOS */

  /* ── Android / Bionic platform APIs (200–279) [android] ─────────── */
  /* Bionic string extras */
  QBDITRACE_CAPI_ANDROID_STRLCPY     = 200, /* strlcpy (Bionic re-export)          */
  /* android_log */
  QBDITRACE_CAPI_ALOG_PRINT          = 201, /* __android_log_print(prio,tag,fmt,...) */
  QBDITRACE_CAPI_ALOG_WRITE          = 202, /* __android_log_write(prio,tag,text)  */
  /* SharedPreferences / key-value (via JNI) */
  QBDITRACE_CAPI_ANDROID_SP_GET      = 203, /* SharedPreferences.getString (JNI)   */
  QBDITRACE_CAPI_ANDROID_SP_PUT      = 204, /* SharedPreferences.putString (JNI)   */
  /* Binder */
  QBDITRACE_CAPI_BINDER_TRANSACT     = 205, /* android::IBinder::transact(...)     */
  /* dl* */
  QBDITRACE_CAPI_DLOPEN              = 206, /* dlopen(path, flags)                 */
  QBDITRACE_CAPI_DLSYM               = 207, /* dlsym(handle, symbol)               */
  /* 208–279 reserved for Android */

  /* ── JNI functions (280–359) [jni] ──────────────────────────────── */
  QBDITRACE_CAPI_JNI_GET_STRING_UTF  = 280, /* GetStringUTFChars(env,jstr,copy)   */
  QBDITRACE_CAPI_JNI_RELEASE_STR_UTF = 281, /* ReleaseStringUTFChars(env,jstr,cp) */
  QBDITRACE_CAPI_JNI_NEW_STRING_UTF  = 282, /* NewStringUTF(env, bytes)            */
  QBDITRACE_CAPI_JNI_GET_STR_LEN_UTF = 283, /* GetStringUTFLength(env, jstr)       */
  QBDITRACE_CAPI_JNI_GET_BYTE_ARR    = 284, /* GetByteArrayElements(env,arr,copy) */
  QBDITRACE_CAPI_JNI_REL_BYTE_ARR    = 285, /* ReleaseByteArrayElements(...)       */
  QBDITRACE_CAPI_JNI_GET_BYTE_REG    = 286, /* GetByteArrayRegion(env,arr,s,l,buf)*/
  QBDITRACE_CAPI_JNI_SET_BYTE_REG    = 287, /* SetByteArrayRegion(...)             */
  QBDITRACE_CAPI_JNI_NEW_BYTE_ARR    = 288, /* NewByteArray(env, length)           */
  QBDITRACE_CAPI_JNI_FIND_CLASS      = 289, /* FindClass(env, name)                */
  QBDITRACE_CAPI_JNI_GET_METHOD_ID   = 290, /* GetMethodID(env,cls,name,sig)       */
  QBDITRACE_CAPI_JNI_GET_STATIC_MID  = 291, /* GetStaticMethodID(env,cls,name,sig)*/
  QBDITRACE_CAPI_JNI_CALL_OBJ_METHOD = 292, /* CallObjectMethod(env,obj,mid,...)   */
  QBDITRACE_CAPI_JNI_CALL_STATIC_OBJ = 293, /* CallStaticObjectMethod(...)         */
  QBDITRACE_CAPI_JNI_CALL_VOID       = 294, /* CallVoidMethod(env,obj,mid,...)     */
  QBDITRACE_CAPI_JNI_CALL_BOOL       = 295, /* CallBooleanMethod(...)              */
  QBDITRACE_CAPI_JNI_CALL_INT        = 296, /* CallIntMethod(...)                  */
  QBDITRACE_CAPI_JNI_CALL_LONG       = 297, /* CallLongMethod(...)                 */
  QBDITRACE_CAPI_JNI_EXCEPTION_CHECK = 298, /* ExceptionCheck(env)                 */
  QBDITRACE_CAPI_JNI_EXCEPTION_CLEAR = 299, /* ExceptionClear(env)                 */
  QBDITRACE_CAPI_JNI_DEFINE_CLASS    = 300, /* DefineClass(env,name,ld,buf,len)    */
  /* 301–359 reserved for JNI */

  /* ── pthread / synchronization (360–379) [common] ───────────────── */
  QBDITRACE_CAPI_PTHREAD_CREATE      = 360, /* pthread_create(thr,attr,fn,arg)    */
  QBDITRACE_CAPI_PTHREAD_JOIN        = 361, /* pthread_join(thread, retval)        */
  QBDITRACE_CAPI_PTHREAD_MUTEX_LOCK  = 362, /* pthread_mutex_lock(mutex)           */
  QBDITRACE_CAPI_PTHREAD_MUTEX_UNLOCK= 363, /* pthread_mutex_unlock(mutex)         */

  /* ── Network (380–399) [common] ─────────────────────────────────── */
  QBDITRACE_CAPI_SOCKET              = 380, /* socket(domain, type, proto)         */
  QBDITRACE_CAPI_CONNECT             = 381, /* connect(fd, addr, addrlen)          */
  QBDITRACE_CAPI_SEND                = 382, /* send(fd, buf, len, flags)           */
  QBDITRACE_CAPI_RECV                = 383, /* recv(fd, buf, len, flags)           */
  QBDITRACE_CAPI_SENDTO              = 384, /* sendto(fd,buf,n,fl,addr,al)        */
  QBDITRACE_CAPI_RECVFROM            = 385, /* recvfrom(fd,buf,n,fl,addr,al)      */

  /* ── Encoding helpers (400–419) [common] ────────────────────────── */
  QBDITRACE_CAPI_BASE64_ENCODE       = 400, /* various base64 encoders             */
  QBDITRACE_CAPI_BASE64_DECODE       = 401, /* various base64 decoders             */

  /* ── Anti-debug / integrity checks (420–449) [common] ───────────── */
  QBDITRACE_CAPI_PTRACE              = 420, /* ptrace(request,pid,addr,data)      */
  QBDITRACE_CAPI_SYSCTL              = 421, /* sysctl(name,nlen,old,olen,new,nl)  */
  QBDITRACE_CAPI_PRCTL               = 422, /* prctl(option, ...)  [linux/android]*/
  QBDITRACE_CAPI_GETENV              = 423, /* getenv(name)                        */
  QBDITRACE_CAPI_ACCESS              = 424, /* access(path, mode)                  */
  QBDITRACE_CAPI_STAT                = 425, /* stat(path, stat_buf)                */
  QBDITRACE_CAPI_KILL                = 426, /* kill(pid, sig)                      */
  QBDITRACE_CAPI_GETPID              = 427, /* getpid()                            */
  QBDITRACE_CAPI_SYSCTLBYNAME        = 428, /* sysctlbyname(name,old,olen,new,nl) [darwin/ios] */
  QBDITRACE_CAPI_ISATTY              = 429, /* isatty(fd)                          */
  /* 430–449 reserved */

  /* ── More I/O / file system (450–469) [common] ───────────────────── */
  QBDITRACE_CAPI_RENAME              = 450, /* rename(old, new)                    */
  QBDITRACE_CAPI_UNLINK              = 451, /* unlink(path)                        */
  QBDITRACE_CAPI_MKDIR               = 452, /* mkdir(path, mode)                   */
  QBDITRACE_CAPI_RMDIR               = 453, /* rmdir(path)                         */
  QBDITRACE_CAPI_OPENAT              = 454, /* openat(dirfd, path, flags, ...)     */
  QBDITRACE_CAPI_PREAD64             = 455, /* pread64(fd, buf, n, off)            */
  QBDITRACE_CAPI_PWRITE64            = 456, /* pwrite64(fd, buf, n, off)           */
  QBDITRACE_CAPI_LSEEK               = 457, /* lseek(fd, off, whence)              */
  QBDITRACE_CAPI_MMAP                = 458, /* mmap(addr,len,prot,flags,fd,off)    */
  QBDITRACE_CAPI_MUNMAP              = 459, /* munmap(addr, len)                   */
  QBDITRACE_CAPI_MPROTECT            = 460, /* mprotect(addr, len, prot)           */
  /* 461–469 reserved */

  /* ── iOS / macOS platform APIs — extended (470–599) [ios] ────────── */
  /* CommonCrypto additional */
  QBDITRACE_CAPI_CC_SHA224           = 470, /* CC_SHA224(data, len, out)           */
  QBDITRACE_CAPI_CC_SHA384           = 471, /* CC_SHA384(data, len, out)           */
  QBDITRACE_CAPI_CC_SHA512           = 472, /* CC_SHA512(data, len, out)           */
  QBDITRACE_CAPI_CC_SHA256_INIT      = 473, /* CC_SHA256_Init(ctx)                 */
  QBDITRACE_CAPI_CC_SHA256_UPDATE    = 474, /* CC_SHA256_Update(ctx,data,len)      */
  QBDITRACE_CAPI_CC_SHA256_FINAL     = 475, /* CC_SHA256_Final(out, ctx)           */
  QBDITRACE_CAPI_CC_HMAC_INIT        = 476, /* CCHmacInit(ctx, alg, key, kl)      */
  QBDITRACE_CAPI_CC_HMAC_UPDATE      = 477, /* CCHmacUpdate(ctx, data, len)        */
  QBDITRACE_CAPI_CC_HMAC_FINAL       = 478, /* CCHmacFinal(ctx, mac)               */
  QBDITRACE_CAPI_CC_CRYPTOR_CREATE   = 479, /* CCCryptorCreate(op,alg,opt,key,...) */
  QBDITRACE_CAPI_CC_CRYPTOR_UPDATE   = 480, /* CCCryptorUpdate(ref,in,il,out,ol,*) */
  QBDITRACE_CAPI_CC_CRYPTOR_FINAL    = 481, /* CCCryptorFinal(ref, out, ol, *)     */
  QBDITRACE_CAPI_CC_CRYPTOR_RELEASE  = 482, /* CCCryptorRelease(ref)               */
  QBDITRACE_CAPI_CC_RANDOM_GENERATE  = 483, /* CCRandomGenerateBytes(buf, n)       */
  /* CoreFoundation extended */
  QBDITRACE_CAPI_CF_STR_GET_CSTR     = 484, /* CFStringGetCString(str,buf,n,enc)   */
  QBDITRACE_CAPI_CF_STR_GET_PTR      = 485, /* CFStringGetCStringPtr(str, enc)     */
  QBDITRACE_CAPI_CF_STR_COMPARE      = 486, /* CFStringCompare(a, b, opts)         */
  QBDITRACE_CAPI_CF_STR_HASPREFIX    = 487, /* CFStringHasPrefix(str, prefix)      */
  QBDITRACE_CAPI_CF_STR_HASSUFFIX    = 488, /* CFStringHasSuffix(str, suffix)      */
  QBDITRACE_CAPI_CF_DATA_GET_PTR     = 489, /* CFDataGetBytePtr(data)              */
  QBDITRACE_CAPI_CF_DATA_GET_LEN     = 490, /* CFDataGetLength(data)               */
  QBDITRACE_CAPI_CF_DICT_GET_VAL     = 491, /* CFDictionaryGetValue(dict, key)     */
  QBDITRACE_CAPI_CF_DICT_CREATE      = 492, /* CFDictionaryCreate(...)             */
  QBDITRACE_CAPI_CF_ARRAY_CREATE     = 493, /* CFArrayCreate(alloc, vals, n, cbs)  */
  QBDITRACE_CAPI_CF_ARRAY_GET_VAL    = 494, /* CFArrayGetValueAtIndex(arr, idx)    */
  QBDITRACE_CAPI_CF_NUMBER_CREATE    = 495, /* CFNumberCreate(alloc, type, val)    */
  QBDITRACE_CAPI_CF_NUMBER_GET_VAL   = 496, /* CFNumberGetValue(num, type, val)    */
  QBDITRACE_CAPI_CF_PLIST_CREATE_DATA= 497, /* CFPropertyListCreateWithData(...)   */
  QBDITRACE_CAPI_CF_PLIST_CREATE_XML = 498, /* CFPropertyListCreateXMLData(...)    */
  QBDITRACE_CAPI_CF_RELEASE          = 499, /* CFRelease(cf)                       */
  QBDITRACE_CAPI_CF_RETAIN           = 500, /* CFRetain(cf)                        */
  /* Security framework extended */
  QBDITRACE_CAPI_SEC_RAND_COPY_BYTES = 501, /* SecRandomCopyBytes(rnd, n, bytes)   */
  QBDITRACE_CAPI_SEC_KEY_COPY_EXT    = 502, /* SecKeyCopyExternalRepresentation(k,e)*/
  QBDITRACE_CAPI_SEC_KEY_CREATE_FROM = 503, /* SecKeyCreateFromData / SecKeyCreate  */
  QBDITRACE_CAPI_SEC_KEY_ENCRYPT     = 504, /* SecKeyEncrypt(key,pad,pt,pl,ct,cl)  */
  QBDITRACE_CAPI_SEC_KEY_DECRYPT     = 505, /* SecKeyDecrypt(key,pad,ct,cl,pt,pl)  */
  QBDITRACE_CAPI_SEC_CERT_CREATE     = 506, /* SecCertificateCreateWithData(...)   */
  QBDITRACE_CAPI_SEC_IDENTITY_COPY   = 507, /* SecIdentityCopyCertificate(id, cert)*/
  QBDITRACE_CAPI_SEC_TRUST_EVAL      = 508, /* SecTrustEvaluate(trust, result)     */
  QBDITRACE_CAPI_SEC_ITEM_ADD        = 509, /* SecItemAdd(attrs, result)           */
  QBDITRACE_CAPI_SEC_ITEM_UPDATE     = 510, /* SecItemUpdate(query, attrs)         */
  QBDITRACE_CAPI_SEC_ITEM_DELETE     = 511, /* SecItemDelete(query)                */
  /* URL / Network CF */
  QBDITRACE_CAPI_CF_URL_GET_STR      = 512, /* CFURLGetString(url)                 */
  QBDITRACE_CAPI_CF_HTTP_MSG_CREATE  = 513, /* CFHTTPMessageCreateRequest(...)     */
  QBDITRACE_CAPI_CF_HTTP_MSG_SET_HDR = 514, /* CFHTTPMessageSetHeaderFieldValue(...)*/
  QBDITRACE_CAPI_CF_HTTP_MSG_SET_BODY= 515, /* CFHTTPMessageSetBody(msg, body)     */
  /* dispatch / GCD */
  QBDITRACE_CAPI_DISPATCH_ASYNC      = 516, /* dispatch_async(queue, block)        */
  QBDITRACE_CAPI_DISPATCH_SYNC       = 517, /* dispatch_sync(queue, block)         */
  QBDITRACE_CAPI_DISPATCH_AFTER      = 518, /* dispatch_after(when, queue, block)  */
  QBDITRACE_CAPI_DISPATCH_ONCE       = 519, /* dispatch_once(pred, block)          */
  /* NSString bridging */
  QBDITRACE_CAPI_NS_STR_UTF8         = 520, /* -[NSString UTF8String]  (via msgSend)*/
  QBDITRACE_CAPI_NS_STR_ENCODE       = 521, /* -[NSString dataUsingEncoding:]      */
  QBDITRACE_CAPI_NS_DATA_BYTES       = 522, /* -[NSData bytes]                     */
  /* Base64 (iOS libSystem) */
  QBDITRACE_CAPI_IOS_BASE64_ENCODE   = 523, /* b64_encode / SecBase64Encode        */
  QBDITRACE_CAPI_IOS_BASE64_DECODE   = 524, /* b64_decode / SecBase64Decode        */
  /* Encoding */
  QBDITRACE_CAPI_ICONV_OPEN          = 525, /* iconv_open(to, from)                */
  QBDITRACE_CAPI_ICONV               = 526, /* iconv(cd, in, il, out, ol)          */
  /* 527–599 reserved for iOS */

  /* ── Android / Bionic platform APIs — extended (600–699) [android] ── */
  /* OpenSSL / BoringSSL (libcrypto.so / libssl.so) */
  QBDITRACE_CAPI_EVP_ENCRYPT_INIT    = 600, /* EVP_EncryptInit_ex(ctx,type,eng,k,iv) */
  QBDITRACE_CAPI_EVP_ENCRYPT_UPDATE  = 601, /* EVP_EncryptUpdate(ctx,out,ol,in,il)  */
  QBDITRACE_CAPI_EVP_ENCRYPT_FINAL   = 602, /* EVP_EncryptFinal_ex(ctx, out, ol)    */
  QBDITRACE_CAPI_EVP_DECRYPT_INIT    = 603, /* EVP_DecryptInit_ex(...)              */
  QBDITRACE_CAPI_EVP_DECRYPT_UPDATE  = 604, /* EVP_DecryptUpdate(...)               */
  QBDITRACE_CAPI_EVP_DECRYPT_FINAL   = 605, /* EVP_DecryptFinal_ex(...)             */
  QBDITRACE_CAPI_EVP_DIGESTINIT      = 606, /* EVP_DigestInit_ex(ctx, type, eng)    */
  QBDITRACE_CAPI_EVP_DIGESTUPDATE    = 607, /* EVP_DigestUpdate(ctx, data, cnt)     */
  QBDITRACE_CAPI_EVP_DIGESTFINAL     = 608, /* EVP_DigestFinal_ex(ctx, md, s)       */
  QBDITRACE_CAPI_HMAC_CTX_NEW        = 609, /* HMAC_CTX_new()                       */
  QBDITRACE_CAPI_HMAC_INIT_EX        = 610, /* HMAC_Init_ex(ctx,key,kl,md,eng)     */
  QBDITRACE_CAPI_HMAC_UPDATE         = 611, /* HMAC_Update(ctx, data, len)          */
  QBDITRACE_CAPI_HMAC_FINAL          = 612, /* HMAC_Final(ctx, md, len)             */
  QBDITRACE_CAPI_SHA256_INIT         = 613, /* SHA256_Init(ctx)                     */
  QBDITRACE_CAPI_SHA256_UPDATE       = 614, /* SHA256_Update(ctx, data, len)        */
  QBDITRACE_CAPI_SHA256_FINAL        = 615, /* SHA256_Final(md, ctx)                */
  QBDITRACE_CAPI_AES_SET_ENC_KEY     = 616, /* AES_set_encrypt_key(key,bits,ks)    */
  QBDITRACE_CAPI_AES_SET_DEC_KEY     = 617, /* AES_set_decrypt_key(key,bits,ks)    */
  QBDITRACE_CAPI_AES_CBC_ENCRYPT     = 618, /* AES_cbc_encrypt(in,out,l,ks,iv,enc) */
  QBDITRACE_CAPI_RSA_SIGN            = 619, /* RSA_sign(type,m,ml,sig,sl,rsa)      */
  QBDITRACE_CAPI_RSA_VERIFY          = 620, /* RSA_verify(type,m,ml,sig,sl,rsa)    */
  QBDITRACE_CAPI_RAND_BYTES          = 621, /* RAND_bytes(buf, num)                 */
  QBDITRACE_CAPI_RAND_PRIV_BYTES     = 622, /* RAND_priv_bytes(buf, num)            */
  QBDITRACE_CAPI_EVP_MD5             = 623, /* EVP_md5()                            */
  QBDITRACE_CAPI_EVP_SHA1            = 624, /* EVP_sha1()                           */
  QBDITRACE_CAPI_EVP_SHA256          = 625, /* EVP_sha256()                         */
  QBDITRACE_CAPI_BIO_NEW_MEM_BUF     = 626, /* BIO_new_mem_buf(buf, len)            */
  QBDITRACE_CAPI_PEM_READ_BIO        = 627, /* PEM_read_bio_RSAPublicKey / PrivKey  */
  /* Base64 (Android) */
  QBDITRACE_CAPI_ANDROID_BASE64_ENC  = 628, /* android.util.Base64.encode (JNI)    */
  QBDITRACE_CAPI_ANDROID_BASE64_DEC  = 629, /* android.util.Base64.decode (JNI)    */
  /* SQLite (Android apps often embed libsqlite3.so) */
  QBDITRACE_CAPI_SQLITE3_OPEN        = 630, /* sqlite3_open(filename, ppDb)         */
  QBDITRACE_CAPI_SQLITE3_PREPARE     = 631, /* sqlite3_prepare_v2(db,sql,n,stmt,t) */
  QBDITRACE_CAPI_SQLITE3_STEP        = 632, /* sqlite3_step(stmt)                   */
  QBDITRACE_CAPI_SQLITE3_COLUMN_TEXT = 633, /* sqlite3_column_text(stmt, col)       */
  QBDITRACE_CAPI_SQLITE3_CLOSE       = 634, /* sqlite3_close(db)                    */
  QBDITRACE_CAPI_SQLITE3_EXEC        = 635, /* sqlite3_exec(db,sql,cb,arg,errmsg)  */
  /* Android KeyStore / Keymaster (native side, libkeystore*.so) */
  QBDITRACE_CAPI_KEYMASTER_IMPORT    = 636, /* importKey / importWrappedKey         */
  QBDITRACE_CAPI_KEYMASTER_EXPORT    = 637, /* exportKey                            */
  QBDITRACE_CAPI_KEYMASTER_FINISH    = 638, /* finish(op,input,sig,out)             */
  /* ART runtime helpers (libart.so) */
  QBDITRACE_CAPI_ART_INVOKE_VIRTUAL  = 639, /* art::InvokeVirtual (JNI bridge)      */
  QBDITRACE_CAPI_ART_THREAD_SELF     = 640, /* art::Thread::Current()               */
  /* Networking (Android extras) */
  QBDITRACE_CAPI_GETADDRINFO         = 641, /* getaddrinfo(node, serv, hints, res)  */
  QBDITRACE_CAPI_GETNAMEINFO         = 642, /* getnameinfo(sa,sl,host,hl,serv,sl,f) */
  QBDITRACE_CAPI_INET_ATON           = 643, /* inet_aton(cp, inp)                   */
  QBDITRACE_CAPI_INET_NTOP           = 644, /* inet_ntop(af, src, dst, size)        */
  /* 645–699 reserved for Android */

  /* ── JNI functions — extended (700–799) [jni] ───────────────────── */
  QBDITRACE_CAPI_JNI_GET_INT_FIELD   = 700, /* GetIntField(env, obj, fid)           */
  QBDITRACE_CAPI_JNI_GET_LONG_FIELD  = 701, /* GetLongField(env, obj, fid)          */
  QBDITRACE_CAPI_JNI_GET_OBJ_FIELD   = 702, /* GetObjectField(env, obj, fid)        */
  QBDITRACE_CAPI_JNI_SET_OBJ_FIELD   = 703, /* SetObjectField(env, obj, fid, val)   */
  QBDITRACE_CAPI_JNI_GET_FIELD_ID    = 704, /* GetFieldID(env, cls, name, sig)      */
  QBDITRACE_CAPI_JNI_GET_STATIC_FIELD= 705, /* GetStaticFieldID(env,cls,name,sig)  */
  QBDITRACE_CAPI_JNI_GET_STR_REG     = 706, /* GetStringUTFRegion(env,s,st,l,buf)  */
  QBDITRACE_CAPI_JNI_GET_ARR_LEN     = 707, /* GetArrayLength(env, array)           */
  QBDITRACE_CAPI_JNI_NEW_OBJ_ARR     = 708, /* NewObjectArray(env,len,cls,init)    */
  QBDITRACE_CAPI_JNI_GET_OBJ_ARR_EL  = 709, /* GetObjectArrayElement(env,arr,idx)  */
  QBDITRACE_CAPI_JNI_SET_OBJ_ARR_EL  = 710, /* SetObjectArrayElement(env,arr,i,v)  */
  QBDITRACE_CAPI_JNI_NEW_INT_ARR     = 711, /* NewIntArray(env, length)             */
  QBDITRACE_CAPI_JNI_GET_INT_ARR     = 712, /* GetIntArrayElements(env, arr, copy) */
  QBDITRACE_CAPI_JNI_REL_INT_ARR     = 713, /* ReleaseIntArrayElements(...)         */
  QBDITRACE_CAPI_JNI_CALL_STATIC_INT = 714, /* CallStaticIntMethod(env,cls,mid,...) */
  QBDITRACE_CAPI_JNI_CALL_STATIC_BOOL= 715, /* CallStaticBooleanMethod(...)         */
  QBDITRACE_CAPI_JNI_NEW_OBJ         = 716, /* NewObject(env, cls, mid, ...)        */
  QBDITRACE_CAPI_JNI_IS_INST_OF      = 717, /* IsInstanceOf(env, obj, cls)          */
  QBDITRACE_CAPI_JNI_NEW_GLOBAL_REF  = 718, /* NewGlobalRef(env, lobj)              */
  QBDITRACE_CAPI_JNI_DELETE_GLOBAL   = 719, /* DeleteGlobalRef(env, gref)           */
  QBDITRACE_CAPI_JNI_DELETE_LOCAL    = 720, /* DeleteLocalRef(env, lref)            */
  QBDITRACE_CAPI_JNI_PUSH_LOCAL_FRAME= 721, /* PushLocalFrame(env, capacity)        */
  QBDITRACE_CAPI_JNI_POP_LOCAL_FRAME = 722, /* PopLocalFrame(env, result)           */
  QBDITRACE_CAPI_JNI_GET_VERSION     = 723, /* GetVersion(env)                      */
  QBDITRACE_CAPI_JNI_MONITOR_ENTER   = 724, /* MonitorEnter(env, obj)               */
  QBDITRACE_CAPI_JNI_MONITOR_EXIT    = 725, /* MonitorExit(env, obj)                */
  QBDITRACE_CAPI_JNI_GET_JAVA_VM     = 726, /* GetJavaVM(env, vm)                   */
  /* 727–799 reserved for JNI */

} qbditrace_capi_id_t;

/* ---- SVC extended flags ----
 * Stored in svc_head_t.reserved[0] (previously always 0) to encode extra
 * platform-specific metadata about the syscall site without changing the
 * fixed struct layout. tenet uses these to quickly route the record to the
 * right analysis pass without re-inspecting syscall_no.
 */
#define QBDITRACE_SVC_FL_MACH_TRAP  (1u << 0) /* Darwin: Mach trap (x16 > 0 & MSB) */
#define QBDITRACE_SVC_FL_BINDER_IOC (1u << 1) /* Android: ioctl on /dev/binder fd   */
#define QBDITRACE_SVC_FL_MEM_OP     (1u << 2) /* syscall is a mem r/w (read/write/mmap/mprotect) */
#define QBDITRACE_SVC_FL_FILE_OP    (1u << 3) /* syscall is a file-system op         */
#define QBDITRACE_SVC_FL_NET_OP     (1u << 4) /* syscall is a network op             */
#define QBDITRACE_SVC_FL_CRYPTO_OP  (1u << 5) /* syscall touches a crypto primitive  */

/* GPR ordering constants (AArch64), mirroring QBDI's State.h layout. */
#define QBDITRACE_AARCH64_NUM_GPR 34 /* x0..x28, fp, lr, sp, nzcv, pc */
#define QBDITRACE_AARCH64_IDX_LR 30
#define QBDITRACE_AARCH64_IDX_SP 31
#define QBDITRACE_AARCH64_IDX_NZCV 32
#define QBDITRACE_AARCH64_IDX_PC 33

/* FPR (NEON) constants (AArch64). */
#define QBDITRACE_AARCH64_NUM_FPR 32 /* v0..v31 */
/* Byte size of the FPR snapshot block appended to each ANCHOR when HF_HAS_FPR
 * is set: 32 registers × (lo 8B + hi 8B) = 512 bytes. */
#define QBDITRACE_AARCH64_FPR_SNAPSHOT_BYTES (32 * 16)

/* --- Compile-time layout assertions ---
 * These ensure the on-disk struct sizes match the decoder's expectations across
 * different compilers and platforms. If any of these fire, it means a compiler
 * inserted unexpected padding or a field type change broke the layout. The
 * decoder relies on sizeof() for record parsing (as documented above), so any
 * mismatch would silently corrupt the decode. */
#ifdef __cplusplus
static_assert(sizeof(qbditrace_file_header_t) == 536,
              "file header must be exactly 536 bytes");
static_assert(sizeof(qbditrace_inst_head_t) == 16,
              "v4 INST header must be 16 bytes (4B fields + 4B pad + 8B pc)");
static_assert(sizeof(qbditrace_inst_head_v5_t) == 6,
              "v5 INST header must be 6 bytes (4B fields + 2B pc_delta)");
static_assert(sizeof(qbditrace_inst_head_v7_t) == 24,
              "v7 INST header must be 24 bytes (4B fields + 4B pad + 8B pc + 1B n_fprdiff + 7B reserved)");
static_assert(sizeof(qbditrace_inst_head_v7_v5_t) == 8,
              "v7+v5 INST header must be 8 bytes (4B fields + 2B pc_delta + 1B n_fprdiff + 1B reserved)");
static_assert(sizeof(qbditrace_fprdiff_t) == 24,
              "fprdiff must be 24 bytes (1B index + 7B pad + 8B lo + 8B hi)");
static_assert(sizeof(qbditrace_regdiff_t) == 16,
              "regdiff must be 16 bytes (1B index + 7B pad + 8B value)");
static_assert(sizeof(qbditrace_memacc_t) == 32,
              "memacc must be 32 bytes (4B fields + 4B pad + 3x8B)");
static_assert(sizeof(qbditrace_memacc_v6_t) == 48,
              "memacc_v6 must be 48 bytes (4B fields + 4B pad + 5x8B)");
static_assert(sizeof(qbditrace_anchor_head_t) == 16,
              "anchor head must be 16 bytes (4B kind+reserved + 4B pad + 8B pc)");
static_assert(sizeof(qbditrace_thread_head_t) == 16,
              "thread head must be 16 bytes (4B kind+reserved + 4B pad + 8B tid)");
static_assert(sizeof(qbditrace_event_head_t) == 24,
              "event head must be 24 bytes (4B kind+event+reserved + 4B pad + 2x8B)");
static_assert(sizeof(qbditrace_svc_head_t) == 72,
              "svc head must be 72 bytes (4B + 4B pad + 8B pc + 8B no + 6x8B args)");
static_assert(sizeof(qbditrace_objc_head_t) == 80,
              "objc head must be 80 bytes (4B + 4B pad + 3x8B + 48B cls)");
static_assert(sizeof(qbditrace_code_head_t) == 16,
              "code head must be 16 bytes (4B kind+size+reserved + 4B pad + 8B pc)");
static_assert(sizeof(qbditrace_capicall_head_t) == 88,
              "capicall head must be 88 bytes (4B header + 4B pad + 8B pc + 8B target + 8*8B args)");
static_assert(sizeof(qbditrace_capicall_head_v8_t) == 88,
              "capicall head v8 must remain 88 bytes");
static_assert(sizeof(qbditrace_objc_head_v8_t) == 80,
              "objc head v8 must remain 80 bytes");
static_assert(sizeof(qbditrace_retval_t) == 64,
              "retval record must be 64 bytes");
static_assert(sizeof(qbditrace_memimg_t) == 24,
              "memimg head must be 24 bytes (4B + 4B seq + 8B addr + 4B len + 4B reserved)");
static_assert(sizeof(qbditrace_capicall_str_t) == 4,
              "capicall str must be 4 bytes (4 × u8)");
#endif

#ifdef __cplusplus
} /* namespace qbditrace */
#endif

#endif /* QBDITRACE_TRACEFORMAT_H_ */
