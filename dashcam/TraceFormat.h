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

/* Architecture tags (kept independent of QBDI enums for decoder portability). */
typedef enum {
  QBDITRACE_ARCH_AARCH64 = 1,
  QBDITRACE_ARCH_X86_64 = 2,
} qbditrace_arch_t;

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
  uint8_t reserved[224]; /* pad header to 536 bytes for easy hex inspection */
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
} qbditrace_header_flags;

/*
 * Each record begins with a single-byte `kind` tag selecting the record
 * variant; the remainder of the record depends on the kind.
 */
typedef enum {
  QBDITRACE_REC_INST = 0,   /* per-instruction diff record */
  QBDITRACE_REC_ANCHOR = 1, /* full register snapshot (rebuild checkpoint) */
  QBDITRACE_REC_THREAD = 2, /* thread context marker */
  QBDITRACE_REC_EVENT = 3,  /* VM event (sequence/exec-transfer) */
  QBDITRACE_REC_SVC = 4,    /* supervisor call (syscall) site */
  QBDITRACE_REC_OBJC = 5,   /* objc_msgSend-family dispatch site */
  QBDITRACE_REC_CODE = 6,   /* raw instruction bytes for one distinct PC */
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
 * Emitted just before an `svc #0` executes. Captures the Linux/XNU syscall
 * selector (x16 on Darwin arm64) plus the first six argument registers so the
 * decoder can name the syscall and show its arguments.
 *   u8  kind            (== QBDITRACE_REC_SVC)
 *   u8  reserved[3]
 *   u64 pc              (address of the svc instruction)
 *   u64 syscall_no      (x16)
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
#endif

#ifdef __cplusplus
} /* namespace qbditrace */
#endif

#endif /* QBDITRACE_TRACEFORMAT_H_ */
