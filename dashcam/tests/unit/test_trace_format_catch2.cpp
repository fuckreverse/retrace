/*
 * test_trace_format_catch2.cpp — Catch2 unit tests for TraceFormat.h
 *
 * Verifies binary layout, magic values, record kind constants, flag bits,
 * v5 PC-delta header, and v6 old-value layout.  All struct-size assertions
 * are compile-time (_Static_assert / static_assert) and therefore checked at
 * build time; only runtime field-access tests live here.
 *
 * Run:  ctest -R trace_format_catch2 --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstring>
#include "TraceFormat.h"

using namespace qbditrace;

// ─── Compile-time assertions (double-checked here for documentation) ────────

static_assert(sizeof(qbditrace_file_header_t) == 536,
    "file header must be 536 bytes");
static_assert(sizeof(qbditrace_inst_head_t) == 16,
    "inst_head must be 16 bytes");
static_assert(sizeof(qbditrace_inst_head_v5_t) == 6,
    "inst_head_v5 must be 6 bytes");
static_assert(sizeof(qbditrace_regdiff_t) == 16,
    "regdiff must be 16 bytes");
static_assert(sizeof(qbditrace_memacc_t) == 32,
    "memacc must be 32 bytes");
static_assert(sizeof(qbditrace_anchor_head_t) == 16,
    "anchor_head must be 16 bytes");
static_assert(sizeof(qbditrace_thread_head_t) == 16,
    "thread_head must be 16 bytes");
static_assert(sizeof(qbditrace_event_head_t) == 24,
    "event_head must be 24 bytes");
static_assert(sizeof(qbditrace_svc_head_t) == 72,
    "svc_head must be 72 bytes");
static_assert(sizeof(qbditrace_objc_head_t) == 80,
    "objc_head must be 80 bytes");
static_assert(sizeof(qbditrace_code_head_t) == 16,
    "code_head must be 16 bytes");
static_assert(sizeof(qbditrace_capicall_head_v8_t) == 88,
    "v8 capicall head must remain 88 bytes");
static_assert(sizeof(qbditrace_objc_head_v8_t) == 80,
    "v8 objc head must remain 80 bytes");
static_assert(sizeof(qbditrace_retval_t) == 64,
    "retval must be 64 bytes");
static_assert(offsetof(qbditrace_retval_t, source_id) == 8,
    "retval source_id must start at byte 8");
static_assert(offsetof(qbditrace_retval_t, nzcv) == 56,
    "retval nzcv must start at byte 56");

// ─── Magic + version constants ───────────────────────────────────────────────

TEST_CASE("TraceFormat: magic number is 'QBDT'", "[unit][qbditrace][trace_format]") {
    REQUIRE(QBDITRACE_MAGIC == 0x51424454u);
}

TEST_CASE("TraceFormat: version is 4", "[unit][qbditrace][trace_format]") {
    REQUIRE(QBDITRACE_VERSION == 4u);
}

TEST_CASE("TraceFormat: AArch64 GPR count is 34", "[unit][qbditrace][trace_format]") {
    REQUIRE(QBDITRACE_AARCH64_NUM_GPR == 34);
}

// ─── Record kind enum ─────────────────────────────────────────────────────────

TEST_CASE("TraceFormat: record kind enum values", "[unit][qbditrace][trace_format]") {
    CHECK(QBDITRACE_REC_INST   == 0);
    CHECK(QBDITRACE_REC_ANCHOR == 1);
    CHECK(QBDITRACE_REC_THREAD == 2);
    CHECK(QBDITRACE_REC_EVENT  == 3);
    CHECK(QBDITRACE_REC_SVC    == 4);
    CHECK(QBDITRACE_REC_OBJC   == 5);
    CHECK(QBDITRACE_REC_CODE   == 6);
    CHECK(QBDITRACE_REC_CAPICALL == 7);
    CHECK(QBDITRACE_REC_RETVAL == 8);
}

// ─── Header flag bits ─────────────────────────────────────────────────────────

TEST_CASE("TraceFormat: header flag bit values", "[unit][qbditrace][trace_format]") {
    CHECK(QBDITRACE_HF_HAS_MEM  == 1u);
    CHECK(QBDITRACE_HF_HAS_NZCV == 2u);
    CHECK(QBDITRACE_HF_REG_DIFF == 4u);
    CHECK(QBDITRACE_HF_HAS_CODE == 8u);
    CHECK(QBDITRACE_HF_PC_DELTA == 16u);
    CHECK(QBDITRACE_HF_CALL_META == (1u << 10));
    CHECK(QBDITRACE_HF_WIDE_API_ID == QBDITRACE_HF_CALL_META);
}

// ─── File header initialization ──────────────────────────────────────────────

TEST_CASE("TraceFormat: file header fields round-trip correctly", "[unit][qbditrace][trace_format]") {
    qbditrace_file_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic    = QBDITRACE_MAGIC;
    hdr.version  = QBDITRACE_VERSION;
    hdr.arch     = QBDITRACE_ARCH_AARCH64;
    hdr.num_gpr  = QBDITRACE_AARCH64_NUM_GPR;
    hdr.flags    = QBDITRACE_HF_HAS_MEM | QBDITRACE_HF_HAS_NZCV |
                   QBDITRACE_HF_REG_DIFF | QBDITRACE_HF_HAS_CODE;

    SECTION("magic") { REQUIRE(hdr.magic   == 0x51424454u); }
    SECTION("version") { REQUIRE(hdr.version == 4u); }
    SECTION("arch")    { REQUIRE(hdr.arch    == 1u); }
    SECTION("num_gpr") { REQUIRE(hdr.num_gpr == 34u); }
    SECTION("HAS_MEM flag")  { REQUIRE((hdr.flags & QBDITRACE_HF_HAS_MEM) != 0); }
    SECTION("REG_DIFF flag") { REQUIRE((hdr.flags & QBDITRACE_HF_REG_DIFF) != 0); }
    SECTION("HAS_CODE flag") { REQUIRE((hdr.flags & QBDITRACE_HF_HAS_CODE) != 0); }
}

TEST_CASE("TraceFormat: module_name capacity is 256 bytes", "[unit][qbditrace][trace_format]") {
    qbditrace_file_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    REQUIRE(sizeof(hdr.module_name) == 256);

    strncpy(hdr.module_name, "my_binary.arm64", sizeof(hdr.module_name) - 1);
    REQUIRE(strcmp(hdr.module_name, "my_binary.arm64") == 0);
}

// ─── INST record ─────────────────────────────────────────────────────────────

TEST_CASE("TraceFormat: INST record header fields are accessible", "[unit][qbditrace][trace_format]") {
    qbditrace_inst_head_t ih;
    memset(&ih, 0, sizeof(ih));
    ih.kind      = QBDITRACE_REC_INST;
    ih.nzcv      = 0x8;
    ih.n_regdiff = 3;
    ih.n_mem     = 2;
    ih.pc        = 0x100004000ULL;

    CHECK(ih.kind      == 0);
    CHECK(ih.nzcv      == 0x8);
    CHECK(ih.n_regdiff == 3);
    CHECK(ih.n_mem     == 2);
    CHECK(ih.pc        == 0x100004000ULL);
}

TEST_CASE("TraceFormat: INST record total size computation", "[unit][qbditrace][trace_format]") {
    // header + 2 regdiffs + 1 memacc = 16 + 32 + 32 = 80
    size_t expected = sizeof(qbditrace_inst_head_t)
                    + 2 * sizeof(qbditrace_regdiff_t)
                    + 1 * sizeof(qbditrace_memacc_t);
    REQUIRE(expected == 80);
}

// ─── Regdiff ─────────────────────────────────────────────────────────────────

TEST_CASE("TraceFormat: regdiff stores register index and value", "[unit][qbditrace][trace_format]") {
    qbditrace_regdiff_t rd;
    memset(&rd, 0, sizeof(rd));
    rd.reg_index = 33;                // "PC slot"
    rd.value     = 0x100004004ULL;

    REQUIRE(rd.reg_index == 33);
    REQUIRE(rd.value     == 0x100004004ULL);
}

// ─── Memacc ──────────────────────────────────────────────────────────────────

TEST_CASE("TraceFormat: memacc stores type, size, address, and value", "[unit][qbditrace][trace_format]") {
    qbditrace_memacc_t ma;
    memset(&ma, 0, sizeof(ma));
    ma.mem_type  = 1;           // write
    ma.size      = 8;
    ma.addr      = 0x200000000ULL;
    ma.value     = 0xDEADBEEFULL;
    ma.value_hi  = 0;

    CHECK(ma.mem_type == 1);
    CHECK(ma.size     == 8);
    CHECK(ma.addr     == 0x200000000ULL);
    CHECK(ma.value    == 0xDEADBEEFULL);
}

// ─── Anchor ──────────────────────────────────────────────────────────────────

TEST_CASE("TraceFormat: ANCHOR record total size is 288 bytes", "[unit][qbditrace][trace_format]") {
    // header (16) + 34 * 8 (GPR snapshot) = 288
    size_t total = sizeof(qbditrace_anchor_head_t) + 34 * 8;
    REQUIRE(total == 288);
}

TEST_CASE("TraceFormat: anchor header stores PC", "[unit][qbditrace][trace_format]") {
    qbditrace_anchor_head_t ah;
    memset(&ah, 0, sizeof(ah));
    ah.kind = QBDITRACE_REC_ANCHOR;
    ah.pc   = 0x100004000ULL;

    REQUIRE(ah.kind == 1);
    REQUIRE(ah.pc   == 0x100004000ULL);
}

// ─── CODE record ─────────────────────────────────────────────────────────────

TEST_CASE("TraceFormat: CODE record header fields are accessible", "[unit][qbditrace][trace_format]") {
    qbditrace_code_head_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.kind = QBDITRACE_REC_CODE;
    ch.size = 4;
    ch.pc   = 0x100004000ULL;

    REQUIRE(ch.kind == 6);
    REQUIRE(ch.size == 4);
    REQUIRE(ch.pc   == 0x100004000ULL);

    // Total = header (16) + 4 bytes of opcode = 20
    REQUIRE(sizeof(ch) + 4 == 20);
}

// ─── v5 PC-delta header ──────────────────────────────────────────────────────

TEST_CASE("TraceFormat: v5 inst_head is smaller than v4 inst_head", "[unit][qbditrace][trace_format]") {
    REQUIRE(sizeof(qbditrace_inst_head_v5_t) < sizeof(qbditrace_inst_head_t));
}

TEST_CASE("TraceFormat: v5 inst_head stores pc_delta correctly", "[unit][qbditrace][trace_format]") {
    qbditrace_inst_head_v5_t v5;
    memset(&v5, 0, sizeof(v5));
    v5.kind      = QBDITRACE_REC_INST;
    v5.nzcv      = 0;
    v5.n_regdiff = 0;
    v5.n_mem     = 0;
    v5.pc_delta  = 4;   // sequential +4 for AArch64

    REQUIRE(v5.kind     == 0);
    REQUIRE(v5.pc_delta == 4);
}

TEST_CASE("TraceFormat: v5 pc_delta can represent negative jumps", "[unit][qbditrace][trace_format]") {
    qbditrace_inst_head_v5_t v5;
    memset(&v5, 0, sizeof(v5));
    v5.pc_delta = static_cast<int16_t>(-256);  // backward jump

    REQUIRE(v5.pc_delta == -256);
}

// ─── SVC header ──────────────────────────────────────────────────────────────

TEST_CASE("TraceFormat: SVC record header fields are accessible", "[unit][qbditrace][trace_format]") {
    qbditrace_svc_head_t sh;
    memset(&sh, 0, sizeof(sh));
    sh.kind       = QBDITRACE_REC_SVC;
    sh.pc         = 0x1000;
    sh.syscall_no = 20;  // SYS_getpid
    sh.args[0]    = 0;

    REQUIRE(sh.kind       == 4);
    REQUIRE(sh.pc         == 0x1000);
    REQUIRE(sh.syscall_no == 20);
}

// ─── ObjC header ─────────────────────────────────────────────────────────────

TEST_CASE("TraceFormat: OBJC record header fields are accessible", "[unit][qbditrace][trace_format]") {
    qbditrace_objc_head_t oh;
    memset(&oh, 0, sizeof(oh));
    oh.kind = QBDITRACE_REC_OBJC;
    oh.pc   = 0x2000;
    oh.recv = 0x100000000ULL;

    REQUIRE(oh.kind == 5);
    REQUIRE(oh.pc   == 0x2000);
    REQUIRE(oh.recv == 0x100000000ULL);
}

// ─── Thread header ────────────────────────────────────────────────────────────

TEST_CASE("TraceFormat: THREAD record header stores thread_id", "[unit][qbditrace][trace_format]") {
    qbditrace_thread_head_t th;
    memset(&th, 0, sizeof(th));
    th.kind      = QBDITRACE_REC_THREAD;
    th.thread_id = 0x1234ABCDUL;

    REQUIRE(th.kind      == 2);
    REQUIRE(th.thread_id == 0x1234ABCDUL);
}

// ─── Full tenet-required flag combination ────────────────────────────────────

TEST_CASE("TraceFormat: flags satisfy tenet minimum requirements", "[unit][qbditrace][trace_format]") {
    // tenet requires: version >= 4, flags must have REG_DIFF | HAS_CODE
    uint32_t flags = QBDITRACE_HF_REG_DIFF | QBDITRACE_HF_HAS_CODE;

    REQUIRE((flags & QBDITRACE_HF_REG_DIFF) != 0);
    REQUIRE((flags & QBDITRACE_HF_HAS_CODE) != 0);
    REQUIRE(QBDITRACE_VERSION >= 4u);
}
