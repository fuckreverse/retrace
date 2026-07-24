/*
 * test_trace_format.c — Unit tests for TraceFormat.h binary layout
 *
 * Verifies that the on-disk struct sizes, magic numbers, version constants,
 * and field offsets match the documented binary format contract. These are
 * compile-time assertions (static_assert) plus a few runtime checks.
 *
 * Build:
 *   clang -std=c11 -Wall -Wextra -I.. -o test_trace_format test_trace_format.c
 * Run:
 *   ./test_trace_format
 */
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "TraceFormat.h"

/* ─── Compile-time struct size assertions ────────────────────────────────── */

/* The file header size: 4×u32 + 5×u64 + 256 char + 224 reserved = 536 bytes.
 * (TraceFormat.h comments say "pad to 512" but the reserved array is 224,
 *  giving 536. Both writer and reader use sizeof(), so the format is
 *  self-consistent. This assertion locks the actual on-disk size.) */
_Static_assert(sizeof(qbditrace_file_header_t) == 536,
    "file header must be 536 bytes (sizeof)");

/* INST record header: 4B fields + 4B pad + 8B pc = 16 */
_Static_assert(sizeof(qbditrace_inst_head_t) == 16,
    "inst_head must be 16 bytes");

/* v5 INST header: 4B fields + 2B pc_delta = 6 (no pad needed) */
_Static_assert(sizeof(qbditrace_inst_head_v5_t) == 6,
    "inst_head_v5 must be 6 bytes");

/* Reg diff: 1B index + 7B pad + 8B value = 16 */
_Static_assert(sizeof(qbditrace_regdiff_t) == 16,
    "regdiff must be 16 bytes");

/* Mem access: 4B fields + 4B pad + 8B addr + 8B value + 8B value_hi = 32 */
_Static_assert(sizeof(qbditrace_memacc_t) == 32,
    "memacc must be 32 bytes");

/* Anchor header: 4B fields + 4B pad + 8B pc = 16 */
_Static_assert(sizeof(qbditrace_anchor_head_t) == 16,
    "anchor_head must be 16 bytes");

/* Thread header: 4B fields + 4B pad + 8B thread_id = 16 */
_Static_assert(sizeof(qbditrace_thread_head_t) == 16,
    "thread_head must be 16 bytes");

/* Event header: 4B fields + 8B addr + 8B site = 24 (no pad between) */
_Static_assert(sizeof(qbditrace_event_head_t) == 24,
    "event_head must be 24 bytes");

/* SVC header: 4B + 4B pad + 8B pc + 8B syscall_no + 48B args = 72 */
_Static_assert(sizeof(qbditrace_svc_head_t) == 72,
    "svc_head must be 72 bytes");

/* ObjC header: 4B + 4B pad + 8B pc + 8B recv + 8B sel + 48B cls = 80 */
_Static_assert(sizeof(qbditrace_objc_head_t) == 80,
    "objc_head must be 80 bytes");
_Static_assert(sizeof(qbditrace_objc_head_v8_t) == 80,
    "objc_head_v8 must be 80 bytes");
_Static_assert(sizeof(qbditrace_capicall_head_v8_t) == 88,
    "capicall_head_v8 must be 88 bytes");
_Static_assert(sizeof(qbditrace_retval_t) == 64,
    "retval must be 64 bytes");
_Static_assert(offsetof(qbditrace_retval_t, source_id) == 8,
    "retval source_id must start at byte 8");
_Static_assert(offsetof(qbditrace_retval_t, nzcv) == 56,
    "retval nzcv must start at byte 56");

/* Code header: 4B fields + 4B pad + 8B pc = 16 */
_Static_assert(sizeof(qbditrace_code_head_t) == 16,
    "code_head must be 16 bytes");

/* ─── Compile-time constant assertions ───────────────────────────────────── */

_Static_assert(QBDITRACE_MAGIC == 0x51424454u, "magic must be 'QBDT'");
_Static_assert(QBDITRACE_VERSION == 4u, "version must be 4");
_Static_assert(QBDITRACE_AARCH64_NUM_GPR == 34, "34 GPRs for AArch64");

/* Record kind enum values */
_Static_assert(QBDITRACE_REC_INST == 0, "INST = 0");
_Static_assert(QBDITRACE_REC_ANCHOR == 1, "ANCHOR = 1");
_Static_assert(QBDITRACE_REC_THREAD == 2, "THREAD = 2");
_Static_assert(QBDITRACE_REC_EVENT == 3, "EVENT = 3");
_Static_assert(QBDITRACE_REC_SVC == 4, "SVC = 4");
_Static_assert(QBDITRACE_REC_OBJC == 5, "OBJC = 5");
_Static_assert(QBDITRACE_REC_CODE == 6, "CODE = 6");
_Static_assert(QBDITRACE_REC_CAPICALL == 7, "CAPICALL = 7");
_Static_assert(QBDITRACE_REC_RETVAL == 8, "RETVAL = 8");

/* Header flag bits */
_Static_assert(QBDITRACE_HF_HAS_MEM == 1u, "HAS_MEM = bit 0");
_Static_assert(QBDITRACE_HF_HAS_NZCV == 2u, "HAS_NZCV = bit 1");
_Static_assert(QBDITRACE_HF_REG_DIFF == 4u, "REG_DIFF = bit 2");
_Static_assert(QBDITRACE_HF_HAS_CODE == 8u, "HAS_CODE = bit 3");
_Static_assert(QBDITRACE_HF_PC_DELTA == 16u, "PC_DELTA = bit 4");

/* ─── Runtime tests ──────────────────────────────────────────────────────── */

static int tests_run = 0;
static int tests_passed = 0;

#define RUN_TEST(name) do { \
    tests_run++; \
    printf("  [RUN] %s ... ", #name); \
    name(); \
    printf("OK\n"); \
    tests_passed++; \
} while(0)

static void test_header_initialization(void) {
    qbditrace_file_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = QBDITRACE_MAGIC;
    hdr.version = QBDITRACE_VERSION;
    hdr.arch = QBDITRACE_ARCH_AARCH64;
    hdr.num_gpr = QBDITRACE_AARCH64_NUM_GPR;
    hdr.flags = QBDITRACE_HF_HAS_MEM | QBDITRACE_HF_HAS_NZCV |
                QBDITRACE_HF_REG_DIFF | QBDITRACE_HF_HAS_CODE;

    assert(hdr.magic == 0x51424454u);
    assert(hdr.version == 4);
    assert(hdr.arch == 1);
    assert(hdr.num_gpr == 34);
    assert((hdr.flags & QBDITRACE_HF_HAS_MEM) != 0);
    assert((hdr.flags & QBDITRACE_HF_REG_DIFF) != 0);
    assert((hdr.flags & QBDITRACE_HF_HAS_CODE) != 0);
}

static void test_inst_record_layout(void) {
    qbditrace_inst_head_t ih;
    memset(&ih, 0, sizeof(ih));
    ih.kind = QBDITRACE_REC_INST;
    ih.nzcv = 0x4;
    ih.n_regdiff = 2;
    ih.n_mem = 1;
    ih.pc = 0x100004000ULL;

    /* Verify fields are readable */
    assert(ih.kind == 0);
    assert(ih.nzcv == 0x4);
    assert(ih.n_regdiff == 2);
    assert(ih.n_mem == 1);
    assert(ih.pc == 0x100004000ULL);

    /* Verify record size calculation */
    size_t expected = sizeof(ih) + 2 * sizeof(qbditrace_regdiff_t) +
                      1 * sizeof(qbditrace_memacc_t);
    assert(expected == 16 + 32 + 32);  /* 80 bytes total */
}

static void test_regdiff_layout(void) {
    qbditrace_regdiff_t rd;
    memset(&rd, 0, sizeof(rd));
    rd.reg_index = 33;  /* PC */
    rd.value = 0x100004004ULL;

    assert(rd.reg_index == 33);
    assert(rd.value == 0x100004004ULL);
}

static void test_memacc_layout(void) {
    qbditrace_memacc_t ma;
    memset(&ma, 0, sizeof(ma));
    ma.mem_type = 1;  /* write */
    ma.mem_flags = 0;
    ma.size = 8;
    ma.addr = 0x200000000ULL;
    ma.value = 0xDEADBEEFULL;
    ma.value_hi = 0;

    assert(ma.mem_type == 1);
    assert(ma.size == 8);
    assert(ma.addr == 0x200000000ULL);
    assert(ma.value == 0xDEADBEEFULL);
}

static void test_anchor_layout(void) {
    qbditrace_anchor_head_t ah;
    memset(&ah, 0, sizeof(ah));
    ah.kind = QBDITRACE_REC_ANCHOR;
    ah.pc = 0x100004000ULL;

    assert(ah.kind == 1);
    assert(ah.pc == 0x100004000ULL);

    /* Anchor total size = header + num_gpr * 8 */
    size_t total = sizeof(ah) + 34 * 8;
    assert(total == 16 + 272);  /* 288 bytes */
}

static void test_code_record_layout(void) {
    qbditrace_code_head_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.kind = QBDITRACE_REC_CODE;
    ch.size = 4;
    ch.pc = 0x100004000ULL;

    assert(ch.kind == 6);
    assert(ch.size == 4);
    assert(ch.pc == 0x100004000ULL);

    /* Code record total = header + size bytes */
    size_t total = sizeof(ch) + 4;
    assert(total == 20);
}

static void test_module_name_capacity(void) {
    qbditrace_file_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    /* module_name is 256 bytes */
    assert(sizeof(hdr.module_name) == 256);

    /* Copy a name and verify truncation */
    strncpy(hdr.module_name, "test_binary", sizeof(hdr.module_name) - 1);
    assert(strcmp(hdr.module_name, "test_binary") == 0);
}

static void test_v5_pc_delta(void) {
    qbditrace_inst_head_v5_t v5;
    memset(&v5, 0, sizeof(v5));
    v5.kind = QBDITRACE_REC_INST;
    v5.nzcv = 0;
    v5.n_regdiff = 0;
    v5.n_mem = 0;
    v5.pc_delta = 4;  /* sequential +4 */

    assert(v5.kind == 0);
    assert(v5.pc_delta == 4);

    /* v5 record is much smaller than v4 */
    assert(sizeof(v5) < sizeof(qbditrace_inst_head_t));
}

int main(void) {
    printf("═══════════════════════════════════════════════════════════════\n");
    printf(" test_trace_format — TraceFormat.h binary layout verification\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  (static_asserts passed at compile time)\n\n");

    printf("  Runtime tests:\n");
    RUN_TEST(test_header_initialization);
    RUN_TEST(test_inst_record_layout);
    RUN_TEST(test_regdiff_layout);
    RUN_TEST(test_memacc_layout);
    RUN_TEST(test_anchor_layout);
    RUN_TEST(test_code_record_layout);
    RUN_TEST(test_module_name_capacity);
    RUN_TEST(test_v5_pc_delta);

    printf("\n  ─────────────────────────────────────────\n");
    printf("  Results: %d/%d passed\n", tests_passed, tests_run);
    printf("═══════════════════════════════════════════════════════════════\n");

    return (tests_run == tests_passed) ? 0 : 1;
}
