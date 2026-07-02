/*
 * harness_fpr.c — FPR mode (v7) harness for e2e integration tests.
 *
 * Like test_harness.c but enables enable_fpr=1 to exercise the v7
 * QBDITRACE_HF_HAS_FPR format path.
 */
#include "QBDITrace.h"
#include "TraceFormat.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern uint64_t trace_target(uint64_t);
extern void trace_target_end(void);

int main(int argc, char **argv) {
    const uint64_t seed = (argc > 1) ? (uint64_t)strtoull(argv[1], 0, 0) : 0x1234;
    const char *out = (argc > 2) ? argv[2] : "/tmp/e2e_fpr_test.bin";

    uint64_t start = (uint64_t)(uintptr_t)&trace_target;
    uint64_t end   = (uint64_t)(uintptr_t)&trace_target_end;
    if (end <= start || end - start > 0x4000) end = start + 0x1000;

    uint64_t ref = trace_target(seed);

    qbditrace_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.struct_size    = sizeof(cfg);
    cfg.trace_start    = start;
    cfg.trace_end      = end;
    cfg.module_base    = start;
    cfg.module_name    = "fpr_target";
    cfg.output_path    = out;
    cfg.record         = QBDITRACE_REC_DEFAULT;
    cfg.anchor_interval = 32;
    cfg.enable_fpr     = 1;  /* v7 FPR mode */

    if (qbditrace_configure(&cfg) != 0) {
        fputs("[fpr_harness] configure failed\n", stderr);
        return 2;
    }

    uint64_t ret = 0;
    uint64_t args[1] = {seed};
    int rc = qbditrace_run_call(&ret, start, 1, args);
    qbditrace_stop();

    if (rc != 0 || ret != ref) {
        fprintf(stderr, "[fpr_harness] MISMATCH: instrumented 0x%llx != native 0x%llx\n",
                (unsigned long long)ret, (unsigned long long)ref);
        return 3;
    }
    printf("OK: instrumented result matches native reference\n");
    return 0;
}
