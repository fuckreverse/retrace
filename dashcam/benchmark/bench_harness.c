/*
 * qbditrace benchmark — universal harness
 *
 * Drives every target function through the QBDI tracer, comparing the
 * instrumented return value against a native reference to validate correctness.
 * Also measures wall-clock time and trace file size for performance evaluation.
 *
 * Usage:
 *   bench_harness [--seed <hex>] [--filter <name>] [--output-dir <dir>]
 *
 * Each target produces a separate trace file: <output-dir>/<target_name>.bin
 * Results are printed as a table and optionally as CSV.
 */

#include <dlfcn.h>
#include <inttypes.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "QBDITrace.h"
#include "targets.h"

/* ---------- Timing -------------------------------------------------------- */

static double now_sec(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (double)tv.tv_sec + (double)tv.tv_usec * 1e-6;
}

/* ---------- Target registry ----------------------------------------------- */

typedef uint64_t (*target_fn_t)(uint64_t);

typedef struct {
  const char *name;
  target_fn_t fn;
  const char *category;
} target_entry_t;

static const target_entry_t TARGETS[] = {
    /* Category 1: Simple */
    {"arith_mix", target_arith_mix, "simple"},
    {"bitops", target_bitops, "simple"},
    /* Category 2: Branchy */
    {"branch32", target_branch32, "branchy"},
    {"nested_branch", target_nested_branch, "branchy"},
    /* Category 3: Loopy */
    {"bubblesort", target_bubblesort, "loopy"},
    {"matmul8", target_matmul8, "loopy"},
    {"linkedlist", target_linkedlist, "loopy"},
    /* Category 4: Recursive */
    {"fib25", target_fib25, "recursive"},
    {"ackermann", target_ackermann, "recursive"},
    {"mergesort", target_mergesort, "recursive"},
    /* Category 5: CFF-like */
    {"cff_switch16", target_cff_switch16, "cff"},
    {"cff_dispatch", target_cff_dispatch, "cff"},
    {"opaque_pred", target_opaque_pred, "cff"},
    /* Category 6: Crypto */
    {"tea_encrypt", target_tea_encrypt, "crypto"},
    {"rc4", target_rc4, "crypto"},
    {"md5_block", target_md5_block, "crypto"},
    /* Category 7: Large */
    {"hash_10k", target_hash_10k, "large"},
    {"hash_100k", target_hash_100k, "large"},
    {"combined", target_combined, "large"},
};

#define NUM_TARGETS (sizeof(TARGETS) / sizeof(TARGETS[0]))

/* ---------- Harness logic ------------------------------------------------- */

/*
 * Compute the instrumented range covering ALL target functions.
 * Since they're all in the same compilation unit and we have a sentinel
 * at the end, we use [first_fn, sentinel) as the range.
 *
 * NOTE: compiler may reorder, so we take min/max of all function addresses.
 */
static void compute_full_range(uint64_t *start, uint64_t *end) {
  uint64_t lo = (uint64_t)(uintptr_t)TARGETS[0].fn;
  uint64_t hi = lo;

  for (unsigned i = 1; i < NUM_TARGETS; i++) {
    uint64_t addr = (uint64_t)(uintptr_t)TARGETS[i].fn;
    if (addr < lo) lo = addr;
    if (addr > hi) hi = addr;
  }

  /* Include the sentinel */
  uint64_t sentinel = (uint64_t)(uintptr_t)&benchmark_targets_end;
  if (sentinel > hi) hi = sentinel;

  /* Sanity: if range looks bogus, use a generous span */
  if (hi <= lo || (hi - lo) > 0x100000) {
    hi = lo + 0x40000; /* 256 KiB should cover all targets */
  }

  *start = lo;
  *end = hi;
}

static int find_section(const char *seg, const char *sect, uint64_t *start,
                        uint64_t *end) {
  const struct mach_header_64 *mh =
      (const struct mach_header_64 *)_dyld_get_image_header(0);
  intptr_t slide = _dyld_get_image_vmaddr_slide(0);
  unsigned long size = 0;
  uint8_t *p = getsectiondata(mh, seg, sect, &size);
  if (!p || size == 0) {
    const struct section_64 *s = getsectbynamefromheader_64(mh, seg, sect);
    if (!s || s->size == 0) return 0;
    *start = (uint64_t)(s->addr + (uint64_t)slide);
    *end = *start + s->size;
    return 1;
  }
  *start = (uint64_t)(uintptr_t)p;
  *end = *start + size;
  return 1;
}

static long file_size(const char *path) {
  struct stat st;
  if (stat(path, &st) != 0) return -1;
  return (long)st.st_size;
}

/* ---------- Main ---------------------------------------------------------- */

int main(int argc, char **argv) {
  uint64_t seed = 0x1234567890ABCDEFULL;
  const char *filter = NULL;
  const char *outdir = "/tmp/qbditrace-bench";
  int csv = 0;

  /* Parse args */
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
      seed = strtoull(argv[++i], NULL, 0);
    } else if (strcmp(argv[i], "--filter") == 0 && i + 1 < argc) {
      filter = argv[++i];
    } else if (strcmp(argv[i], "--output-dir") == 0 && i + 1 < argc) {
      outdir = argv[++i];
    } else if (strcmp(argv[i], "--csv") == 0) {
      csv = 1;
    } else if (strcmp(argv[i], "--help") == 0) {
      printf("Usage: %s [--seed <hex>] [--filter <name>] "
             "[--output-dir <dir>] [--csv]\n",
             argv[0]);
      return 0;
    }
  }

  /* Create output directory */
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "mkdir -p %s", outdir);
  (void)system(cmd);

  printf("=== qbditrace benchmark ===\n");
  printf("seed       = 0x%" PRIx64 "\n", seed);
  printf("output_dir = %s\n", outdir);
  printf("targets    = %zu\n", NUM_TARGETS);
  if (filter) printf("filter     = %s\n", filter);
  printf("\n");

  /* Compute instrumentation range */
  uint64_t range_start, range_end;
  compute_full_range(&range_start, &range_end);
  printf("[range] 0x%016" PRIx64 " - 0x%016" PRIx64 " (%llu bytes)\n\n",
         range_start, range_end,
         (unsigned long long)(range_end - range_start));

  /* Find stubs */
  uint64_t stub_s = 0, stub_e = 0;
  find_section("__TEXT", "__auth_stubs", &stub_s, &stub_e) ||
      find_section("__TEXT", "__stubs", &stub_s, &stub_e);

  /* Print header */
  if (csv) {
    printf("target,category,native_us,trace_us,overhead_x,trace_bytes,"
           "correct\n");
  } else {
    printf("%-16s %-10s %10s %10s %8s %12s %s\n", "TARGET", "CATEGORY",
           "NATIVE(us)", "TRACE(us)", "OVRHEAD", "BYTES", "OK?");
    printf("%-16s %-10s %10s %10s %8s %12s %s\n", "------", "--------",
           "---------", "---------", "-------", "-----", "---");
  }

  int total = 0, passed = 0, failed = 0, skipped = 0;

  for (unsigned i = 0; i < NUM_TARGETS; i++) {
    const target_entry_t *t = &TARGETS[i];

    /* Apply filter */
    if (filter && strstr(t->name, filter) == NULL) {
      skipped++;
      continue;
    }
    total++;

    /* --- Native reference --- */
    double t0 = now_sec();
    uint64_t ref = t->fn(seed);
    double native_us = (now_sec() - t0) * 1e6;

    /* --- Configure tracer for this target --- */
    char outpath[1024];
    snprintf(outpath, sizeof(outpath), "%s/%s.bin", outdir, t->name);

    qbditrace_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.trace_start = range_start;
    cfg.trace_end = range_end;
    cfg.module_base = range_start;
    cfg.module_slide = 0;
    cfg.module_name = "benchmark";
    cfg.output_path = outpath;
    cfg.record = QBDITRACE_REC_DEFAULT;
    cfg.anchor_interval = 0; /* default */
    cfg.ring_bytes = 0;
    cfg.extra_range_start = stub_s;
    cfg.extra_range_end = stub_e;

    if (qbditrace_configure(&cfg) != 0) {
      fprintf(stderr, "[FAIL] %s: configure failed\n", t->name);
      failed++;
      continue;
    }

    /* --- Instrumented run --- */
    uint64_t ret = 0;
    uint64_t args[1] = {seed};
    double t1 = now_sec();
    int rc = qbditrace_run_call(&ret, (uint64_t)(uintptr_t)t->fn, 1, args);
    double trace_us = (now_sec() - t1) * 1e6;
    qbditrace_stop();

    if (rc != 0) {
      fprintf(stderr, "[FAIL] %s: run_call returned %d\n", t->name, rc);
      failed++;
      continue;
    }

    /* --- Verify --- */
    int correct = (ret == ref);
    long bytes = file_size(outpath);
    double overhead = (native_us > 0.01) ? (trace_us / native_us) : 0.0;

    if (correct) {
      passed++;
    } else {
      failed++;
      fprintf(stderr,
              "[MISMATCH] %s: native=0x%" PRIx64 " instrumented=0x%" PRIx64
              "\n",
              t->name, ref, ret);
    }

    /* --- Print result --- */
    if (csv) {
      printf("%s,%s,%.1f,%.1f,%.1f,%ld,%s\n", t->name, t->category, native_us,
             trace_us, overhead, bytes, correct ? "yes" : "NO");
    } else {
      printf("%-16s %-10s %10.1f %10.1f %7.1fx %12ld %s\n", t->name,
             t->category, native_us, trace_us, overhead, bytes,
             correct ? "PASS" : "FAIL");
    }
  }

  /* --- Summary --- */
  printf("\n=== Summary ===\n");
  printf("Total: %d | Passed: %d | Failed: %d | Skipped: %d\n", total, passed,
         failed, skipped);
  printf("Trace files in: %s/\n", outdir);

  return (failed > 0) ? 1 : 0;
}
