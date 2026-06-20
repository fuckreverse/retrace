/*
 * qbditrace - high performance instruction tracer built on QBDI
 *
 * QBDITrace.h
 *
 * Public C ABI of the tracer dylib. The dylib is intended to be loaded into a
 * target process (e.g. via Frida `Module.load`) and driven from the loader by
 * calling these exported functions. Once configured, the heavy lifting (QBDI
 * VM, per-instruction callbacks, ring buffer, background flushing) happens
 * entirely in native code with no dependency on the loader.
 *
 * Typical Frida flow:
 *   1. Module.load("/path/libqbditrace.dylib")
 *   2. cfg = { ... }  ->  qbditrace_configure(&cfg)
 *   3. Interceptor.replace(targetFn, NativeCallback that calls
 *        qbditrace_run_call(retOut, targetFn, args...))
 *   or attach at entry and call qbditrace_run_call from onEnter.
 */
#ifndef QBDITRACE_QBDITRACE_H_
#define QBDITRACE_QBDITRACE_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bit flags controlling what the tracer records (qbditrace_config.record). */
enum {
  QBDITRACE_REC_NZCV = 1u << 0,    /* capture NZCV flags per instruction */
  QBDITRACE_REC_REGDIFF = 1u << 1, /* capture written-register diffs */
  QBDITRACE_REC_MEM = 1u << 2,     /* capture memory accesses (read/write) */
  QBDITRACE_REC_SYSCALL = 1u << 3, /* capture svc (syscall) sites */
  QBDITRACE_REC_MSGSEND = 1u << 4, /* capture objc_msgSend dispatch sites */
  QBDITRACE_REC_DEFAULT =
      QBDITRACE_REC_NZCV | QBDITRACE_REC_REGDIFF | QBDITRACE_REC_MEM |
      QBDITRACE_REC_SYSCALL | QBDITRACE_REC_MSGSEND,
};

/*
 * Tracer configuration. All addresses are *runtime* addresses (already slid by
 * ASLR). The loader is responsible for resolving them, typically via
 * Module.findBaseAddress(name) + static_offset.
 *
 * ABI forward-compatibility: callers MUST set `struct_size = sizeof(qbditrace_config_t)`
 * before passing the struct to qbditrace_configure(). This allows the library to
 * detect older callers that have a shorter struct (missing newly-added fields at the
 * end) and safely default those fields to zero. Callers that zero-initialize the
 * struct (memset 0 + set struct_size) are guaranteed forward-compatible with any
 * future field additions.
 */
typedef struct {
  uint32_t struct_size;  /* MUST be set to sizeof(qbditrace_config_t) by caller */
  uint32_t _reserved0;   /* padding for 8-byte alignment */
  uint64_t trace_start;  /* runtime start address of the range to trace */
  uint64_t trace_end;    /* runtime end address (excluded) */
  uint64_t module_base;  /* runtime base of the traced module (for ASLR norm) */
  uint64_t module_slide; /* ASLR slide; static = runtime - slide */
  const char *module_name; /* best-effort module path (may be NULL) */
  const char *output_path; /* path to write trace.bin; NULL => default */
  uint32_t record;         /* bitmask of QBDITRACE_REC_* */
  uint32_t anchor_interval; /* emit a full register resync snapshot every N
                             * instructions (0 => library default, 1024).
                             * Anchors are only resync checkpoints: register
                             * diffs store absolute values, so the decoder can
                             * rebuild state across sequence/transfer boundaries
                             * without an anchor at each one. */
  uint64_t ring_bytes;      /* per-thread ring buffer size in bytes
                             * (0 => default 64 MiB). */
  /* Runtime addresses of the objc_msgSend family, resolved by the loader (e.g.
   * Module.findExportByName("libobjc.A.dylib", "objc_msgSend")). Any may be 0
   * if unavailable / not wanted. When an EXEC_TRANSFER_CALL targets one of
   * these, the tracer emits an OBJC record carrying x0 (receiver) and the
   * selector register so the decoder can resolve class/selector offline. */
  uint64_t objc_msgSend;       /* x0=self, x1=SEL */
  uint64_t objc_msgSendSuper;  /* x0=super struct, x1=SEL */
  uint64_t objc_msgSendSuper2; /* x0=super struct, x1=SEL */
  uint64_t objc_msgSend_stret; /* x0=hidden ret ptr, x1=self, x2=SEL */
  /* Optional second instrumented range [extra_range_start, extra_range_end).
   * Both 0 => unused. Useful on iOS to keep the symbol-resolution stubs
   * (__stubs / __auth_stubs) inside the traced set so an objc_msgSend call,
   * which leaves the main range only at the stub's `br x16`, is observed with
   * its *real* objc_msgSend target (so OBJC classification fires). It can also
   * be used to trace a second function of interest. */
  uint64_t extra_range_start;
  uint64_t extra_range_end;
  /* Embedded code table. By default the tracer writes the raw bytes of each
   * distinct executed instruction into the trace (REC_CODE), so the offline
   * decoder can disassemble without an external --image. The sense is inverted
   * (0 = enabled) so a zero-initialized config gets the default-on behavior and
   * remains ABI-compatible with callers built before this field existed. Set to
   * non-zero only to squeeze out the (tiny, deduplicated) extra writes. */
  uint32_t disable_embed_code;

  /* v5 PC-delta encoding.  Set to non-zero to enable version-5 INST records:
   * the 8-byte absolute pc field is replaced by a 2-byte signed int16 delta
   * from the previous instruction's PC.  Sequential AArch64 code yields
   * delta=+4 per instruction, shrinking the INST header from 12 to 6 bytes
   * (≈40-60% file size reduction for straight-line code).
   * The file header version is bumped to 5 and HF_PC_DELTA is set; old readers
   * that check for version==4 will reject the file gracefully.
   * Zero (the default) keeps the original v4 layout for full compatibility. */
  uint32_t enable_pc_delta;

  /* v6 old-value capture.  Set to non-zero to record the memory content BEFORE
   * each write, enabling true time-travel: the decoder can undo any store by
   * restoring the captured old bytes without rescanning from the start.
   * Each memory access record grows from 32 bytes to 48 bytes (two extra 8-byte
   * fields: old_value + old_value_hi).  For reads the extra fields are zero.
   * For writes, the tracer calls safeRead() on the target address immediately
   * before the write executes (in preInstCB); if the read fails (guard page,
   * unmapped), the fields stay zero and QBDITRACE_MF_OLD_UNKNOWN is set.
   * The file header version is bumped to 6 and HF_OLD_VALUE is set.
   * Zero (the default) keeps the v4/v5 layout unchanged. */
  uint32_t enable_old_value;
} qbditrace_config_t;

/*
 * Insert a full-register ANCHOR snapshot at the current execution point.
 * Can be called from a Frida script (or any external thread) while a
 * qbditrace_run_* is in progress to force an exact checkpoint at an
 * interesting moment (e.g. just before a critical function call).
 * Thread-safe; the anchor is written to the calling thread's buffer.
 * Returns 0 on success, negative if the tracer is not running.
 */
int qbditrace_force_anchor(void);

/*
 * Configure the tracer. Must be called before any qbditrace_run_*.
 * Returns 0 on success, negative on error. Copies the config (strings are
 * duplicated), so the caller need not keep the struct alive.
 */
int qbditrace_configure(const qbditrace_config_t *cfg);

/*
 * Take over the execution of `function` with the supplied integer arguments
 * using the QBDI VM, tracing everything that falls within the configured range.
 * Returns 0 on success; the function's return value is written to *ret_out
 * when ret_out is non-NULL.
 *
 * This is the recommended entry point: hook the target function with Frida and,
 * from the hook, divert the call here with the original arguments.
 *
 * argc may be 0..8 (AArch64 / SysV style integer arguments).
 */
int qbditrace_run_call(uint64_t *ret_out, uint64_t function, uint32_t argc,
                       const uint64_t *argv);

/*
 * In-place trace of a *real* call, replaying the captured register context.
 *
 * Use this for non-reentrant functions whose behaviour depends on the caller's
 * already-prepared stack frame and globals (e.g. thin VM-dispatch wrappers).
 * Hook the target's entry, capture the full register file, then call this:
 *
 *   start_pc : runtime entry PC of the function (the hooked address)
 *   gpr      : array of 30 values = x0..x28 (indices 0..28) then x29/FP (29)
 *   sp       : the live stack pointer captured at entry
 *   lr       : the real return address captured at entry; the VM runs until
 *              control returns here (the function's terminal `ret`)
 *
 * The VM is seeded with these exact registers and SP (no fake stack), so the
 * traced code sees the same environment as the real call. The function's
 * return value (x0 after the run) is written to *ret_out when non-NULL.
 * Returns 0 on success, negative on error. (arm64 only.)
 */
int qbditrace_run_at(uint64_t *ret_out, uint64_t start_pc, const uint64_t *gpr,
                     uint64_t sp, uint64_t lr);

/*
 * Flush all pending buffers to disk and finalize the trace file. Safe to call
 * multiple times. Implicitly called at process exit, but calling it explicitly
 * (e.g. from the loader after the traced call returns) guarantees the trace is
 * complete and readable.
 */
void qbditrace_stop(void);

/*
 * Returns the path of the trace file currently being written (or the default
 * if none configured yet). The returned pointer is owned by the library.
 */
const char *qbditrace_output_path(void);

/*
 * Diagnostic: dump the crash-locating PC ring window to `path` (appended), or
 * to stderr when path is null/empty. Intended to be called from the Frida side
 * after Frida's own exception handler intercepts a fault inside the
 * qbditrace_run_call NativeFunction trampoline (where our SIGSEGV handler
 * never runs). The ring contains the last N executed PCs leading up to the
 * crash, enabling post-mortem identification of the faulting instruction.
 * Returns the number of PC entries written.
 */
int qbditrace_dump_pcring(const char *path);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QBDITRACE_QBDITRACE_H_ */
