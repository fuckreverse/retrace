/*
 * qbditrace advanced benchmark — harness
 *
 * Drives all advanced target functions through QBDI instrumentation.
 * Validates correctness and collects timing/size data for each target.
 *
 * This harness is structured identically to the basic bench_harness.c
 * but operates on the advanced target set (crypto, obfuscation, scenarios).
 *
 * Usage:
 *   advanced_harness [--seed <hex>] [--filter <name>] [--output-dir <dir>]
 *                    [--csv] [--group <A|B|C|D>]
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
#include "advanced_targets.h"

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
  const char *group;     /* A=crypto, B=obfuscation, C=scenario, D=stress */
  const char *category;  /* descriptive sub-category */
  const char *tenet_test; /* what tenet capability this tests */
} target_entry_t;

static const target_entry_t TARGETS[] = {
    /* ── Group A: Production Crypto ── */
    {"aes128_encrypt", target_aes128_encrypt, "A", "crypto",
     "PatternPass(AES S-Box), TaintPass(key→ctext)"},
    {"aes128_keyexp", target_aes128_keyexp, "A", "crypto",
     "PatternPass(AES Rcon), TaintPass(key expansion)"},
    {"chacha20_block", target_chacha20_block, "A", "crypto",
     "PatternPass(ChaCha constants), CFGPass(round structure)"},
    {"sha256_compress", target_sha256_compress, "A", "crypto",
     "PatternPass(SHA256 K), CFGPass(64-round loop)"},
    {"hmac_sha256", target_hmac_sha256, "A", "crypto",
     "TaintPass(ipad/opad key masking), XRefPass(nested hash)"},
    {"xtea64", target_xtea64, "A", "crypto",
     "PatternPass(delta 0x9E3779B9), CFGPass(Feistel rounds)"},
    {"sm4_encrypt", target_sm4_encrypt, "A", "crypto",
     "PatternPass(SM4 S-Box), TaintPass(key→ctext)"},

    /* ── Group B: OLLVM Obfuscation Variants ── */
    {"xtea_cff", target_xtea_cff, "B", "obfuscation",
     "CFGPass(recover rounds from CFF), PatternPass(detect dispatcher)"},
    {"xtea_bcf", target_xtea_bcf, "B", "obfuscation",
     "CFGPass(identify dead branches), SlicePass(opaque predicates)"},
    {"xtea_sub", target_xtea_sub, "B", "obfuscation",
     "TaintPass(track through MBA), PatternPass(MBA pattern)"},
    {"xtea_constenc", target_xtea_constenc, "B", "obfuscation",
     "PatternPass(XOR decrypt), TaintPass(constant decrypt chain)"},
    {"xtea_allobf", target_xtea_allobf, "B", "obfuscation",
     "ALL passes combined — hardest obfuscation case"},

    /* ── Group C: Real-World Scenarios ── */
    {"pbkdf2_sha256", target_pbkdf2_sha256, "C", "scenario",
     "Performance(repetitive trace), TaintPass(password→key)"},
    {"request_sign", target_request_sign, "C", "scenario",
     "TaintPass(secret→signature), XRefPass(pipeline stages)"},
    {"antitamper_crc", target_antitamper_crc, "C", "scenario",
     "PatternPass(CRC32), CFGPass(conditional tamper response)"},
    {"mini_vm", target_mini_vm, "C", "scenario",
     "CFGPass(dispatch loop), PatternPass(VM interpreter)"},
    {"layered_crypto", target_layered_crypto, "C", "scenario",
     "TaintPass(3-layer propagation), XRefPass(cross-algorithm)"},
    {"aes_cff_mba", target_aes_cff_mba, "C", "scenario",
     "Boss fight: CFF+MBA on AES — all passes stressed"},

    /* ── Group D: Tenet Stress Tests ── */
    {"branch_explosion", target_branch_explosion, "D", "stress",
     "CFGPass(32768 paths), Performance(large CFG)"},
    {"aes_tablebased", target_aes_tablebased, "D", "stress",
     "MemoryModel(4KB tables), Performance(many distinct addrs)"},
    {"deep_callchain", target_deep_callchain, "D", "stress",
     "CallGraphPass(depth 50), FunctionPass(many frames)"},
    {"decrypt_execute", target_decrypt_execute, "D", "stress",
     "PatternPass(decrypt+exec), TaintPass(encrypted code)"},
};

#define NUM_TARGETS (sizeof(TARGETS) / sizeof(TARGETS[0]))

/* ---------- Helpers ------------------------------------------------------- */

static void compute_full_range(uint64_t *start, uint64_t *end) {
  uint64_t lo = (uint64_t)(uintptr_t)TARGETS[0].fn;
  uint64_t hi = lo;

  for (unsigned i = 1; i < NUM_TARGETS; i++) {
    uint64_t addr = (uint64_t)(uintptr_t)TARGETS[i].fn;
    if (addr < lo) lo = addr;
    if (addr > hi) hi = addr;
  }

  uint64_t sentinel = (uint64_t)(uintptr_t)&advanced_targets_end;
  if (sentinel > hi) hi = sentinel;

  /* Advanced targets are larger; allow up to 512KB */
  if (hi <= lo || (hi - lo) > 0x200000) {
    hi = lo + 0x80000;
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

static const char *human_size(long bytes, char *buf, size_t buflen) {
  if (bytes < 1024)
    snprintf(buf, buflen, "%ldB", bytes);
  else if (bytes < 1024 * 1024)
    snprintf(buf, buflen, "%.1fKB", bytes / 1024.0);
  else
    snprintf(buf, buflen, "%.1fMB", bytes / (1024.0 * 1024.0));
  return buf;
}

/* ---------- Main ---------------------------------------------------------- */

int main(int argc, char **argv) {
  uint64_t seed = 0x1234567890ABCDEFULL;
  const char *filter = NULL;
  const char *outdir = "/tmp/qbditrace-advanced";
  const char *group_filter = NULL;
  int csv = 0;
  int verbose = 0;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
      seed = strtoull(argv[++i], NULL, 0);
    } else if (strcmp(argv[i], "--filter") == 0 && i + 1 < argc) {
      filter = argv[++i];
    } else if (strcmp(argv[i], "--output-dir") == 0 && i + 1 < argc) {
      outdir = argv[++i];
    } else if (strcmp(argv[i], "--group") == 0 && i + 1 < argc) {
      group_filter = argv[++i];
    } else if (strcmp(argv[i], "--csv") == 0) {
      csv = 1;
    } else if (strcmp(argv[i], "--verbose") == 0) {
      verbose = 1;
    } else if (strcmp(argv[i], "--help") == 0) {
      printf("Usage: %s [--seed <hex>] [--filter <name>] [--group A|B|C|D]\n"
             "          [--output-dir <dir>] [--csv] [--verbose]\n",
             argv[0]);
      return 0;
    }
  }

  /* Create output directory */
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "mkdir -p %s", outdir);
  (void)system(cmd);

  printf("╔══════════════════════════════════════════════════════════════════╗\n");
  printf("║       qbditrace ADVANCED benchmark suite                        ║\n");
  printf("║       (crypto + obfuscation + scenarios + stress)               ║\n");
  printf("╚══════════════════════════════════════════════════════════════════╝\n\n");

  printf("seed       = 0x%" PRIx64 "\n", seed);
  printf("output_dir = %s\n", outdir);
  printf("targets    = %zu total\n", NUM_TARGETS);
  if (filter) printf("filter     = %s\n", filter);
  if (group_filter) printf("group      = %s\n", group_filter);
  printf("\n");

  /* Compute instrumentation range */
  uint64_t range_start, range_end;
  compute_full_range(&range_start, &range_end);
  printf("[range] 0x%016" PRIx64 " - 0x%016" PRIx64 " (%llu bytes)\n\n",
         range_start, range_end,
         (unsigned long long)(range_end - range_start));

  /* Find stubs for library call tracking */
  uint64_t stub_s = 0, stub_e = 0;
  find_section("__TEXT", "__auth_stubs", &stub_s, &stub_e) ||
      find_section("__TEXT", "__stubs", &stub_s, &stub_e);

  /* Print header */
  if (csv) {
    printf("target,group,category,native_us,trace_us,overhead_x,trace_bytes,"
           "correct,tenet_test\n");
  } else {
    printf("%-20s %-5s %-12s %10s %10s %8s %10s %s\n",
           "TARGET", "GRP", "CATEGORY", "NATIVE(us)", "TRACE(us)",
           "OVRHEAD", "SIZE", "OK?");
    printf("%-20s %-5s %-12s %10s %10s %8s %10s %s\n",
           "────────────────────", "─────", "────────────",
           "──────────", "──────────", "────────", "──────────", "───");
  }

  int total = 0, passed = 0, failed = 0, skipped = 0;

  for (unsigned i = 0; i < NUM_TARGETS; i++) {
    const target_entry_t *t = &TARGETS[i];

    /* Apply group filter */
    if (group_filter && strcmp(t->group, group_filter) != 0) {
      skipped++;
      continue;
    }
    /* Apply name filter */
    if (filter && strstr(t->name, filter) == NULL) {
      skipped++;
      continue;
    }
    total++;

    /* --- Native reference --- */
    double t0 = now_sec();
    uint64_t ref = t->fn(seed);
    double native_us = (now_sec() - t0) * 1e6;

    /* --- Configure tracer --- */
    char outpath[1024];
    snprintf(outpath, sizeof(outpath), "%s/%s_%s.bin", outdir, t->group, t->name);

    qbditrace_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.trace_start = range_start;
    cfg.trace_end = range_end;
    cfg.module_base = range_start;
    cfg.module_slide = 0;
    cfg.module_name = "advanced_bench";
    cfg.output_path = outpath;
    cfg.record = QBDITRACE_REC_DEFAULT;
    cfg.anchor_interval = 0;
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
    char sizebuf[32];

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
      printf("%s,%s,%s,%.1f,%.1f,%.1f,%ld,%s,\"%s\"\n",
             t->name, t->group, t->category,
             native_us, trace_us, overhead, bytes,
             correct ? "yes" : "NO", t->tenet_test);
    } else {
      printf("%-20s %-5s %-12s %10.1f %10.1f %7.1fx %10s %s\n",
             t->name, t->group, t->category,
             native_us, trace_us, overhead,
             human_size(bytes, sizebuf, sizeof(sizebuf)),
             correct ? "PASS" : "FAIL");
    }

    if (verbose && !csv) {
      printf("  → tenet: %s\n", t->tenet_test);
    }
  }

  /* --- Summary --- */
  printf("\n");
  printf("═══════════════════════════════════════════════════════════════════\n");
  printf("  Total: %d  |  Passed: %d  |  Failed: %d  |  Skipped: %d\n",
         total, passed, failed, skipped);
  printf("  Trace files: %s/\n", outdir);
  printf("═══════════════════════════════════════════════════════════════════\n");

  if (failed > 0) {
    printf("\n  ⚠️  %d target(s) FAILED correctness check!\n", failed);
  } else {
    printf("\n  ✅ All targets passed correctness verification.\n");
  }

  return (failed > 0) ? 1 : 0;
}
