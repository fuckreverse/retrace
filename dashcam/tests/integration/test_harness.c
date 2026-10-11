/*
 * qbditrace - standalone test harness
 *
 * test_harness.c
 *
 * Drives the tracer entirely in-process (no Frida): it computes the runtime
 * address range of a target function, configures the tracer, then asks it to
 * take over a call to that function via qbditrace_run_call(). Finally it
 * compares the instrumented result against a reference value computed by
 * calling the target natively, and prints the trace path so it can be fed to
 * the offline decoder.
 *
 * This lets us validate the full pipeline (instrumentation -> ring buffer ->
 * trace.bin -> decoder) on Apple Silicon macOS before touching a real device.
 *
 * Scenario selection (argv[3], optional, defaults to "core"):
 *   core     - test_target.c:trace_target()      (control flow, mem, ObjC, SVC, CAPI)
 *   crypto   - target_crypto.c:crypto_target()   (AES-const idiom, XOR/ARX loops)
 *   profile  - target_profile.c:profile_target() (long loop, sentinel value, high-entropy buffer)
 *
 * Each scenario target is compiled into the harness binary unconditionally
 * (see run_pass_e2e.sh / e2e/lib.sh); only the ONE selected by argv[3] is
 * executed and traced per run, keeping every produced trace small and
 * focused on the pass(es) under test.
 *
 * Build/run: see dashcam/tests/integration/run_macos.sh (core scenario)
 *            dashcam/tests/integration/e2e/run_pass_e2e.sh (all scenarios)
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

/* Provided by test_target.c (always linked in). */
extern uint64_t trace_target(uint64_t seed);
extern void trace_target_end(void);

/*
 * Provided by target_crypto.c / target_profile.c when linked in. These are
 * declared as weak symbols so the "core"-only build (run_macos.sh, which does
 * not compile the extra scenario files) still links; scenario_lookup() will
 * simply refuse to select a scenario whose function pointer resolved to NULL.
 */
#if defined(__has_attribute) && __has_attribute(weak)
__attribute__((weak)) uint64_t crypto_target(uint64_t seed);
__attribute__((weak)) void crypto_target_end(void);
__attribute__((weak)) uint64_t profile_target(uint64_t seed);
__attribute__((weak)) void profile_target_end(void);
#else
extern uint64_t crypto_target(uint64_t seed);
extern void crypto_target_end(void);
extern uint64_t profile_target(uint64_t seed);
extern void profile_target_end(void);
#endif

typedef uint64_t (*target_fn_t)(uint64_t);
typedef void (*target_end_fn_t)(void);

typedef struct {
  const char *name;
  target_fn_t fn;
  target_end_fn_t end_fn;
  const char *module_name;
} scenario_t;

static const scenario_t kScenarios[] = {
    {"core", trace_target, trace_target_end, "test_target"},
    {"crypto", crypto_target, crypto_target_end, "target_crypto"},
    {"profile", profile_target, profile_target_end, "target_profile"},
};
#define N_SCENARIOS (sizeof(kScenarios) / sizeof(kScenarios[0]))

/* Look up a scenario by name; NULL/unknown falls back to "core". Returns NULL
 * only if the resolved scenario's weak symbol was never linked in (fn==0). */
static const scenario_t *scenario_lookup(const char *name) {
  const scenario_t *fallback = &kScenarios[0];
  for (size_t i = 0; i < N_SCENARIOS; ++i) {
    if (name && strcmp(kScenarios[i].name, name) == 0) {
      if (!kScenarios[i].fn) {
        fprintf(stderr,
                "[harness] scenario '%s' requested but not linked in "
                "(missing target_%s.c in build)\n",
                name, name);
        return NULL;
      }
      return &kScenarios[i];
    }
  }
  return fallback;
}

/*
 * The instrumented range is [entry, entry_end). The linker is free to
 * reorder, so entry_end may land *before* entry. We therefore normalise: if
 * end <= start, fall back to a conservative fixed span that comfortably
 * covers a function of this size.
 */
static void compute_range(target_fn_t fn, target_end_fn_t end_fn,
                           uint64_t *start, uint64_t *end) {
  uint64_t s = (uint64_t)(uintptr_t)fn;
  uint64_t e = (uint64_t)(uintptr_t)end_fn;
  if (e <= s || (e - s) > 0x8000) {
    e = s + 0x2000; /* 8 KiB is plenty for these targets */
  }
  *start = s;
  *end = e;
}

int main(int argc, char **argv) {
  const uint64_t seed = (argc > 1) ? strtoull(argv[1], NULL, 0) : 0x1234;
  const char *out = (argc > 2) ? argv[2] : "/tmp/qbditrace-test.bin";
  const char *scenario_name = (argc > 3) ? argv[3] : "core";

  const scenario_t *scenario = scenario_lookup(scenario_name);
  if (!scenario) {
    return 5;
  }
  printf("[harness] scenario          = %s\n", scenario->name);

  uint64_t start = 0, end = 0;
  compute_range(scenario->fn, scenario->end_fn, &start, &end);

  printf("[harness] target entry      = 0x%016" PRIx64 "\n", start);
  printf("[harness] target entry_end  = 0x%016" PRIx64
         " (range end = 0x%016" PRIx64 ")\n",
         (uint64_t)(uintptr_t)scenario->end_fn, end);
  printf("[harness] seed              = 0x%" PRIx64 "\n", seed);
  printf("[harness] output            = %s\n", out);

  /* Reference result (native, no instrumentation). */
  uint64_t ref = scenario->fn(seed);
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
  cfg.module_name = scenario->module_name;
  cfg.output_path = out;
cfg.record = QBDITRACE_REC_DEFAULT;
/* Opt in to C API interception; n_capi_funcs stays 0 so the native tracer
 * auto-resolves its standard table (CC_SHA256, memcpy, strcmp, ...) via
 * dlsym at configure time. */
cfg.enable_capi_intercept = 1;
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
  int rc = qbditrace_run_call(&ret, start, 1, args);
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
