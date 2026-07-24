/*
 * qbditrace - standalone test harness
 *
 * test_harness.c
 *
 * Drives the tracer entirely in-process (no Frida): it computes the runtime
 * address range of trace_target(), configures the tracer, then asks it to take
 * over a call to trace_target() via qbditrace_run_call(). Finally it compares
 * the instrumented result against a reference value computed by calling
 * trace_target() natively, and prints the trace path so it can be fed to the
 * offline decoder.
 *
 * This lets us validate the full pipeline (instrumentation -> ring buffer ->
 * trace.bin -> decoder) on Apple Silicon macOS before touching a real device.
 *
 * Build/run: see tools/qbditrace/test/run_macos.sh
 */

#include <dlfcn.h>
#include <inttypes.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "QBDITrace.h"

/*
 * Locate the runtime [start,end) of a (segment,section) in the main executable.
 * Used to add the lazy/auth symbol stubs to the instrumented set so that an
 * objc_msgSend call -- which only leaves the main range at the stub's `br x16`
 * -- is observed with its real objc_msgSend target. Returns 0 on failure.
 */
static int find_section(const char *seg, const char *sect, uint64_t *start,
                        uint64_t *end) {
  const struct mach_header_64 *mh =
      (const struct mach_header_64 *)_dyld_get_image_header(0);
  intptr_t slide = _dyld_get_image_vmaddr_slide(0);
  unsigned long size = 0;
  uint8_t *p = getsectiondata(mh, seg, sect, &size);
  if (!p || size == 0) {
    /* getsectiondata already returns a slid pointer; if it failed try the
     * non-slid lookup + manual slide as a fallback. */
    const struct section_64 *s = getsectbynamefromheader_64(mh, seg, sect);
    if (!s || s->size == 0)
      return 0;
    *start = (uint64_t)(s->addr + (uint64_t)slide);
    *end = *start + s->size;
    return 1;
  }
  *start = (uint64_t)(uintptr_t)p;
  *end = *start + size;
  return 1;
}

/* Provided by test_target.c */
extern uint64_t trace_target(uint64_t seed);
extern void trace_target_end(void);

/*
 * The instrumented range is [trace_target, trace_target_end). The linker is
 * free to reorder, so trace_target_end may land *before* trace_target. We
 * therefore normalise: if end <= start, fall back to a conservative fixed span
 * that comfortably covers a function of this size.
 */
static void compute_range(uint64_t *start, uint64_t *end) {
  uint64_t s = (uint64_t)(uintptr_t)&trace_target;
  uint64_t e = (uint64_t)(uintptr_t)&trace_target_end;
  if (e <= s || (e - s) > 0x4000) {
    e = s + 0x1000; /* 4 KiB is plenty for this target */
  }
  *start = s;
  *end = e;
}

int main(int argc, char **argv) {
  const uint64_t seed = (argc > 1) ? strtoull(argv[1], NULL, 0) : 0x1234;
  const char *out = (argc > 2) ? argv[2] : "/tmp/qbditrace-test.bin";

  uint64_t start = 0, end = 0;
  compute_range(&start, &end);

  printf("[harness] trace_target      = 0x%016" PRIx64 "\n", start);
  printf("[harness] trace_target_end  = 0x%016" PRIx64
         " (range end = 0x%016" PRIx64 ")\n",
         (uint64_t)(uintptr_t)&trace_target_end, end);
  printf("[harness] seed              = 0x%" PRIx64 "\n", seed);
  printf("[harness] output            = %s\n", out);

  /* Reference result (native, no instrumentation). */
  uint64_t ref = trace_target(seed);
  printf("[harness] native result     = 0x%016" PRIx64 "\n", ref);

  /* Resolve the objc_msgSend family if present in this process. On macOS this
   * is a plain dlsym; harmless to pass 0 when not linked against ObjC. */
  uint64_t msgSend = (uint64_t)(uintptr_t)dlsym(RTLD_DEFAULT, "objc_msgSend");
  uint64_t msgSendSuper =
      (uint64_t)(uintptr_t)dlsym(RTLD_DEFAULT, "objc_msgSendSuper");
  uint64_t msgSendSuper2 =
      (uint64_t)(uintptr_t)dlsym(RTLD_DEFAULT, "objc_msgSendSuper2");
  uint64_t msgSendStret =
      (uint64_t)(uintptr_t)dlsym(RTLD_DEFAULT, "objc_msgSend_stret");
  printf("[harness] objc_msgSend      = 0x%016" PRIx64 "%s\n", msgSend,
         msgSend ? "" : " (not present)");

  /* Diagnostic: print the runtime entry of every external function the target
   * calls, so we can match them against the EXEC_TRANSFER_CALL targets in the
   * decoded trace (they go through __auth_stubs first on macOS/iOS). */
  {
    const char *ext[] = {"objc_getClass", "sel_registerName", "objc_msgSend",
                         "getpid"};
    for (unsigned i = 0; i < sizeof(ext) / sizeof(ext[0]); ++i) {
      void *p = dlsym(RTLD_DEFAULT, ext[i]);
      printf("[harness]   ext %-16s = 0x%016" PRIx64 "\n", ext[i],
             (uint64_t)(uintptr_t)p);
    }
  }

  qbditrace_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.trace_start = start;
  cfg.trace_end = end;
  cfg.module_base = start;       /* single-module test: normalise against start */
  cfg.module_slide = 0;          /* keep static == runtime for easy reading */
  cfg.module_name = "test_target";
  cfg.output_path = out;
  cfg.record = QBDITRACE_REC_DEFAULT;
  cfg.anchor_interval = 0;
  cfg.ring_bytes = 0; /* default */
  /* The standalone harness compiles QBDITrace.cpp directly without linking
   * zstd. Keep this trace uncompressed; Tenet still exercises the complete
   * record/decode/analysis path without a misleading compression warning. */
  cfg.disable_compress = 1;
  cfg.objc_msgSend = msgSend;
  cfg.objc_msgSendSuper = msgSendSuper;
  cfg.objc_msgSendSuper2 = msgSendSuper2;
  cfg.objc_msgSend_stret = msgSendStret;

  /* Also instrument the executable's symbol stubs so an objc_msgSend call,
   * which goes target -> __auth_stubs/__stubs -> br x16 -> real objc_msgSend,
   * surfaces the real objc_msgSend as the transfer target (OBJC record fires).
   * Try __auth_stubs (arm64e style) first, then plain __stubs. */
  uint64_t stub_s = 0, stub_e = 0;
  if (find_section("__TEXT", "__auth_stubs", &stub_s, &stub_e) ||
      find_section("__TEXT", "__stubs", &stub_s, &stub_e)) {
    cfg.extra_range_start = stub_s;
    cfg.extra_range_end = stub_e;
    printf("[harness] stubs range       = 0x%016" PRIx64 " - 0x%016" PRIx64
           "\n",
           stub_s, stub_e);
  } else {
    printf("[harness] stubs range       = (not found; objc target stays stub)\n");
  }

  if (qbditrace_configure(&cfg) != 0) {
    fprintf(stderr, "[harness] qbditrace_configure failed\n");
    return 2;
  }

  /* HISTORICAL / DEBUG ONLY. Dump the raw bytes of the instrumented range so the
   * offline decoder *could* disassemble via --image <out>.image --image-base
   * <start>. This is no longer needed: traces now embed a deduplicated code
   * table (REC_CODE) and the decoder is self-contained, so the normal test path
   * runs without --image. We keep this dump as a fallback for manually
   * cross-checking instruction bytes, and because --image is currently only
   * deprecated (see decoder usage), not removed. */
  {
    char img[1100];
    snprintf(img, sizeof(img), "%s.image", out);
    FILE *fi = fopen(img, "wb");
    if (fi) {
      fwrite((const void *)(uintptr_t)start, 1, (size_t)(end - start), fi);
      fclose(fi);
      printf("[harness] image dumped to   = %s (base 0x%016" PRIx64
             ", %llu bytes)\n",
             img, start, (unsigned long long)(end - start));
    } else {
      printf("[harness] image dump failed for %s\n", img);
    }
  }

  uint64_t ret = 0;
  uint64_t args[1] = {seed};
  int rc = qbditrace_run_call(&ret, (uint64_t)(uintptr_t)&trace_target, 1, args);
  qbditrace_stop();

  printf("[harness] run_call rc       = %d\n", rc);
  printf("[harness] instrumented ret  = 0x%016" PRIx64 "\n", ret);
  printf("[harness] trace written to  = %s\n", qbditrace_output_path());

  if (rc != 0) {
    fprintf(stderr, "[harness] run_call returned error\n");
    return 3;
  }
  if (ret != ref) {
    fprintf(stderr,
            "[harness] MISMATCH: instrumented 0x%" PRIx64
            " != native 0x%" PRIx64 "\n",
            ret, ref);
    return 4;
  }
  printf("[harness] OK: instrumented result matches native reference\n");
  return 0;
}
