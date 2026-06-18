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
  uint8_t reserved[224]; /* pad header to 512 bytes for easy hex inspection */
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
 * Record size: 6 bytes (vs 12 bytes for v4), reducing the INST record header
 * size by 50% for sequential code (delta = +4 every instruction).
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

/* ---- QBDITRACE_REC_ANCHOR ----
 * Layout:
 *   u8  kind            (== QBDITRACE_REC_ANCHOR)
 *   u8  reserved[3]
 *   u64 pc              (runtime address where the snapshot was taken)
 *   u64 regs[num_gpr]   (full GPR snapshot, indexed by QBDI GPR ordering)
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

#ifdef __cplusplus
} /* namespace qbditrace */
#endif

#endif /* QBDITRACE_TRACEFORMAT_H_ */
