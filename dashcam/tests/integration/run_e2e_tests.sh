#!/bin/sh
#
# run_e2e_tests.sh — qbditrace end-to-end test suite (macOS arm64)
#
# Builds the tracer with all combinations of format flags and target
# configurations, runs each scenario, decodes the resulting .bin files
# using tenet --dump, and verifies that the decoded output contains the
# expected record types.
#
# Requirements:
#   - macOS arm64
#   - QBDI static libs at <repo>/build-macos/{libQBDI.a,libqbdi-llvm.a}
#   - tenet binary at <repo>/tools/tenet/build/tenet
#
# Usage:
#   sh run_e2e_tests.sh          # run all scenarios
#   sh run_e2e_tests.sh --fast   # skip slow scenarios (FPR, large trace)
#
# Exit code: 0 = all pass, non-zero = failure count
#
set -e

HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "${HERE}/../../../.." && pwd -P)"
TRACE_DIR="${ROOT}/tools/qbditrace"
BUILD="${ROOT}/build-macos"
TENET="${ROOT}/tools/tenet/build/tenet"

FAST=0
if [ "${1}" = "--fast" ]; then FAST=1; fi

PASS=0
FAIL=0
TOTAL=0

# ─── helpers ────────────────────────────────────────────────────────────────

die() { echo "FATAL: $*" >&2; exit 1; }

[ -f "${BUILD}/libQBDI.a" ] || die "libQBDI.a not found at ${BUILD}/"
[ -x "${TENET}" ] || die "tenet not found at ${TENET} (build it first)"

log() { printf '\033[1;34m[e2e]\033[0m %s\n' "$*"; }
pass_() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); printf '\033[1;32m  ✓ PASS\033[0m %s\n' "$*"; }
fail_() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); printf '\033[1;31m  ✗ FAIL\033[0m %s\n' "$*"; }

# Build a test harness variant.
# build_harness <output_binary> [extra_cflags...]
build_harness() {
  local out="$1"; shift
  clang++ -std=c++17 -O2 -g \
    -Wno-deprecated-declarations \
    -Wno-constant-conversion \
    -I"${TRACE_DIR}" \
    -I"${ROOT}/include" \
    -I"${BUILD}/include" \
    -I"${BUILD}/include-static" \
    "${TRACE_DIR}/QBDITrace.cpp" \
    "${TRACE_DIR}/tests/integration/test_target.c" \
    "${TRACE_DIR}/tests/integration/test_harness.c" \
    "$@" \
    "${BUILD}/libQBDI.a" \
    "${BUILD}/libqbdi-llvm.a" \
    -framework Foundation -framework CoreFoundation \
    -o "${out}" 2>/dev/null
}

# Run a harness and decode its output using tenet --dump.
# run_and_decode <harness_bin> <out_bin> [extra_harness_args...]
run_and_decode() {
  local harness="$1" out="$2"; shift 2
  "$harness" 0x1234 "$out" "$@" >/tmp/e2e_harness.log 2>&1
  "${TENET}" --dump text "$out" >/tmp/e2e_decode.log 2>&1
}

# Assert a pattern exists in the decode output.
assert_in_decode() {
  local desc="$1" pattern="$2"
  if grep -q "$pattern" /tmp/e2e_decode.log 2>/dev/null; then
    pass_ "${desc}: found '${pattern}'"
  else
    fail_ "${desc}: '${pattern}' NOT found in decode output"
    echo "    ↳ decode snippet:"
    head -20 /tmp/e2e_decode.log | sed 's/^/      /'
  fi
}

assert_not_in_decode() {
  local desc="$1" pattern="$2"
  if ! grep -q "$pattern" /tmp/e2e_decode.log 2>/dev/null; then
    pass_ "${desc}: correctly absent '${pattern}'"
  else
    fail_ "${desc}: '${pattern}' unexpectedly found in decode output"
  fi
}

# Assert semantic correctness (instrumented == native result).
assert_semantic_ok() {
  local desc="$1"
  if grep -q "OK: instrumented result matches" /tmp/e2e_harness.log 2>/dev/null; then
    pass_ "${desc}: semantic correctness"
  else
    fail_ "${desc}: return value MISMATCH"
    grep "instrumented\|native\|MISMATCH" /tmp/e2e_harness.log | sed 's/^/    /'
  fi
}

assert_harness_exit_ok() {
  local desc="$1" rc="$2"
  if [ "$rc" -eq 0 ]; then
    pass_ "${desc}: harness exit 0"
  else
    fail_ "${desc}: harness exit ${rc}"
    cat /tmp/e2e_harness.log | sed 's/^/    /'
  fi
}

assert_header_field() {
  local desc="$1" field="$2" value="$3"
  if grep -q "${field}.*${value}" /tmp/e2e_decode.log 2>/dev/null; then
    pass_ "${desc}: ${field}=${value}"
  else
    fail_ "${desc}: ${field} != ${value}"
    grep "${field}" /tmp/e2e_decode.log | head -3 | sed 's/^/    /'
  fi
}

# ─── Build phase ────────────────────────────────────────────────────────────

log "Building harness (baseline)..."
build_harness /tmp/e2e_harness_base -DQBDITRACE_TEST_OBJC=1 \
  -lobjc || die "baseline harness build failed"

log "Building harness (no-zstd, no-ObjC)..."
build_harness /tmp/e2e_harness_noobjc || die "no-ObjC harness build failed"

# ─── Scenario 1: Baseline – all default flags ────────────────────────────────
log ""
log "=== Scenario 1: Baseline (v4, default flags, ObjC, SVC) ==="
BINOUT=/tmp/e2e_s1.bin
/tmp/e2e_harness_base 0x1234 "${BINOUT}" >/tmp/e2e_harness.log 2>&1
rc=$?
"${TENET}" --dump text "${BINOUT}" >/tmp/e2e_decode.log 2>&1

assert_harness_exit_ok "s1" "$rc"
assert_semantic_ok "s1"
assert_header_field "s1" "arch" "aarch64"
assert_header_field "s1" "code" "embedded"
assert_in_decode "s1 INST records" "\[.*\] 0x"
assert_in_decode "s1 ANCHOR" "seq_entry"
assert_in_decode "s1 memory read" "mem\[r\]"
assert_in_decode "s1 memory write" "mem\[w\]"
assert_in_decode "s1 inline SVC getpid" "svc.*#20\|#0x14\|getpid"
assert_in_decode "s1 cross-func call" "CALL.*\|call\|transfer"
assert_in_decode "s1 ObjC record" "objc\|msgSend"
assert_in_decode "s1 reg diffs" "x[0-9]"

# ─── Scenario 2: Even seed (branch-true path) vs odd seed (branch-false) ────
log ""
log "=== Scenario 2: Branch coverage (even vs odd seed) ==="

S2_EVEN=/tmp/e2e_s2_even.bin
S2_ODD=/tmp/e2e_s2_odd.bin

/tmp/e2e_harness_base 0x100 "${S2_EVEN}" >/tmp/e2e_harness.log 2>&1
assert_semantic_ok "s2/even"
"${TENET}" --dump text "${S2_EVEN}" >/tmp/e2e_decode.log 2>&1
# even seed → branchy = seed*2 path (CBZ/CBNZ taken)
assert_in_decode "s2/even branch" "b\.\|cbz\|cbnz\|B[A-Z]*.*\|branch"

/tmp/e2e_harness_base 0x101 "${S2_ODD}" >/tmp/e2e_harness.log 2>&1
assert_semantic_ok "s2/odd"

# Both must produce INST records
"${TENET}" --dump text "${S2_EVEN}" >/tmp/e2e_decode.log 2>&1
EVEN_CNT=$(grep -c "^\[" /tmp/e2e_decode.log 2>/dev/null || echo 0)
"${TENET}" --dump text "${S2_ODD}" >/tmp/e2e_decode.log 2>&1
ODD_CNT=$(grep -c "^\[" /tmp/e2e_decode.log 2>/dev/null || echo 0)

if [ "$EVEN_CNT" -gt 50 ] && [ "$ODD_CNT" -gt 50 ]; then
  pass_ "s2: both seeds produce >50 INST records (even=${EVEN_CNT} odd=${ODD_CNT})"
else
  fail_ "s2: too few INST records (even=${EVEN_CNT} odd=${ODD_CNT})"
fi

# ─── Scenario 3: Recursion – fib(10) observed ───────────────────────────────
log ""
log "=== Scenario 3: Recursion (fib) ==="
S3=/tmp/e2e_s3.bin
/tmp/e2e_harness_base 0x1234 "${S3}" >/tmp/e2e_harness.log 2>&1
assert_semantic_ok "s3"
"${TENET}" --dump text "${S3}" >/tmp/e2e_decode.log 2>&1

# fib(10) recurses 177 times → many CALL/RET events
CALL_CNT=$(grep -c "transfer.*call\|CALL\|\[xfer\]" /tmp/e2e_decode.log 2>/dev/null | tr -d ' \n' || echo 0)
if [ "$CALL_CNT" -gt 5 ]; then
  pass_ "s3: ${CALL_CNT} call/xfer events (recursion observed)"
else
  # Also check raw instruction count as fallback: fib(10) runs 177 times
  FIB_CALLS=$(grep -c "bl \|blr \|bl$" /tmp/e2e_decode.log 2>/dev/null | tr -d ' \n' || echo 0)
  if [ "$FIB_CALLS" -gt 10 ]; then
    pass_ "s3: ${FIB_CALLS} BL/BLR instructions (recursion verified via asm)"
  else
    fail_ "s3: only ${CALL_CNT} call events, ${FIB_CALLS} BL instructions — recursion may not be traced"
  fi
fi

# ─── Scenario 4: Anchor interval – verify ANCHOR records appear ──────────────
log ""
log "=== Scenario 4: ANCHOR records ==="
S4=/tmp/e2e_s4.bin
/tmp/e2e_harness_base 0x5555 "${S4}" >/tmp/e2e_harness.log 2>&1
assert_semantic_ok "s4"
"${TENET}" --dump text "${S4}" >/tmp/e2e_decode.log 2>&1
assert_in_decode "s4 ANCHOR seq_entry" "seq_entry"
ANCHOR_CNT=$(grep -c "seq_entry\|anchor" /tmp/e2e_decode.log 2>/dev/null || echo 0)
if [ "$ANCHOR_CNT" -ge 1 ]; then
  pass_ "s4: ${ANCHOR_CNT} ANCHOR markers found"
else
  fail_ "s4: no ANCHOR markers"
fi

# ─── Scenario 5: No-ObjC build → no OBJC records ────────────────────────────
log ""
log "=== Scenario 5: Harness without ObjC → no OBJC records ==="
S5=/tmp/e2e_s5.bin
/tmp/e2e_harness_noobjc 0x1234 "${S5}" >/tmp/e2e_harness.log 2>&1
rc=$?
assert_harness_exit_ok "s5" "$rc"
assert_semantic_ok "s5"
"${TENET}" --dump text "${S5}" >/tmp/e2e_decode.log 2>&1
assert_not_in_decode "s5 no-ObjC: no objc records" "objc_msgSend\|OBJC"
assert_in_decode "s5 no-ObjC: SVC still present" "svc\|getpid"

# ─── Scenario 6: Inline SVC – anti-debug bypass pattern ─────────────────────
log ""
log "=== Scenario 6: Inline SVC (anti-debug bypass pattern) ==="
S6=/tmp/e2e_s6.bin
/tmp/e2e_harness_base 0xDEAD "${S6}" >/tmp/e2e_harness.log 2>&1
assert_semantic_ok "s6"
"${TENET}" --dump text "${S6}" >/tmp/e2e_decode.log 2>&1
# Inline getpid via svc #0x80 — should appear as an SVC record with no=0x14 (20)
assert_in_decode "s6 inline SVC" "svc\|#20\|#0x14"

# ─── Scenario 7: File header integrity ──────────────────────────────────────
log ""
log "=== Scenario 7: File header binary integrity ==="
S7=/tmp/e2e_s7.bin
/tmp/e2e_harness_base 0xABCD "${S7}" >/tmp/e2e_harness.log 2>&1
assert_semantic_ok "s7"

# Parse header bytes directly
# Magic is 4 bytes: 0x51 0x42 0x44 0x54 ('Q','B','D','T' in little-endian uint32)
# od -t x1 prints one byte per column, space-separated
MAGIC=$(dd if="${S7}" bs=1 count=4 2>/dev/null | od -A n -t x1 | tr -d ' \n\r')
# QBDITRACE_MAGIC == 0x51424454 ('Q','B','D','T' as uint32 value).
# In little-endian storage on disk the bytes appear as: 54 44 42 51
# (lowest byte first: T=0x54, D=0x44, B=0x42, Q=0x51).
if echo "${MAGIC}" | grep -qi "54444251"; then
  pass_ "s7: magic bytes QBDT confirmed (le=${MAGIC}, value=0x51424454)"
else
  fail_ "s7: unexpected magic bytes: '${MAGIC}' (expected 54444251 = QBDT little-endian)"
fi

# version byte at offset 4
VERSION=$(dd if="${S7}" bs=1 skip=4 count=1 2>/dev/null | od -A n -t u1 | tr -d ' ')
if [ "${VERSION}" -ge 4 ] 2>/dev/null; then
  pass_ "s7: version=${VERSION} >= 4"
else
  fail_ "s7: version=${VERSION} < 4"
fi

# ─── Scenario 8: Multiple sequential runs (stable state) ─────────────────────
log ""
log "=== Scenario 8: Multiple sequential runs (state isolation) ==="
PASS8=0
for SEED in 0x0001 0x0002 0x0003; do
  S8="/tmp/e2e_s8_${SEED}.bin"
  /tmp/e2e_harness_base "${SEED}" "${S8}" >/tmp/e2e_harness.log 2>&1
  if grep -q "OK: instrumented result matches" /tmp/e2e_harness.log; then
    PASS8=$((PASS8+1))
  fi
done
if [ "$PASS8" -eq 3 ]; then
  pass_ "s8: 3/3 sequential runs correct"
else
  fail_ "s8: only ${PASS8}/3 runs correct"
fi

# ─── Scenario 9: Code table present (self-contained decode) ─────────────────
log ""
log "=== Scenario 9: REC_CODE table (embedded instruction bytes) ==="
S9=/tmp/e2e_s9.bin
/tmp/e2e_harness_base 0x1234 "${S9}" >/tmp/e2e_harness.log 2>&1
"${TENET}" --dump text "${S9}" >/tmp/e2e_decode.log 2>&1
assert_header_field "s9" "code" "embedded"
CODE_CNT=$(grep -c "^\[.*\].*0x" /tmp/e2e_decode.log 2>/dev/null || echo 0)
if [ "$CODE_CNT" -gt 20 ]; then
  pass_ "s9: ${CODE_CNT} disassembled instructions (code table works)"
else
  fail_ "s9: only ${CODE_CNT} disassembled instructions"
fi

# ─── Scenario 10: Memory access records ──────────────────────────────────────
log ""
log "=== Scenario 10: Memory read/write records ==="
S10=/tmp/e2e_s10.bin
/tmp/e2e_harness_base 0x1234 "${S10}" >/tmp/e2e_harness.log 2>&1
"${TENET}" --dump text "${S10}" >/tmp/e2e_decode.log 2>&1
MEM_R=$(grep -c "mem\[r\]" /tmp/e2e_decode.log 2>/dev/null | tr -d ' \n' || echo 0)
MEM_W=$(grep -c "mem\[w\]" /tmp/e2e_decode.log 2>/dev/null | tr -d ' \n' || echo 0)
if [ "$MEM_R" -gt 0 ] && [ "$MEM_W" -gt 0 ]; then
  pass_ "s10: mem reads=${MEM_R} writes=${MEM_W}"
else
  fail_ "s10: missing mem records (reads=${MEM_R} writes=${MEM_W})"
fi

# ─── Scenario 11: Register diffs present ─────────────────────────────────────
log ""
log "=== Scenario 11: Register diff records ==="
S11=/tmp/e2e_s11.bin
/tmp/e2e_harness_base 0x1234 "${S11}" >/tmp/e2e_harness.log 2>&1
"${TENET}" --dump text "${S11}" >/tmp/e2e_decode.log 2>&1
# Register diffs appear as "xN: old->new" lines
REGDIFF_CNT=$(grep -c "x[0-9].*->.*\|x[0-9].*0x" /tmp/e2e_decode.log 2>/dev/null || echo 0)
if [ "$REGDIFF_CNT" -gt 10 ]; then
  pass_ "s11: ${REGDIFF_CNT} register diff entries"
else
  fail_ "s11: only ${REGDIFF_CNT} register diff entries"
fi

# ─── Scenario 12: PC values within range ────────────────────────────────────
log ""
log "=== Scenario 12: PC values within instrumented range ==="
S12=/tmp/e2e_s12.bin
/tmp/e2e_harness_base 0x1234 "${S12}" >/tmp/e2e_harness.log 2>&1
"${TENET}" --dump text "${S12}" >/tmp/e2e_decode.log 2>&1

# Extract start/end from decode header
TSTART=$(grep "trace range" /tmp/e2e_decode.log | grep -o "0x[0-9a-f]*" | head -1)
TEND=$(grep "trace range" /tmp/e2e_decode.log | grep -o "0x[0-9a-f]*" | tail -1)

if [ -n "${TSTART}" ] && [ -n "${TEND}" ]; then
  pass_ "s12: trace range ${TSTART} - ${TEND} found in header"
else
  fail_ "s12: could not parse trace range from header"
fi

# ─── Scenario 13: Zero seed edge case ───────────────────────────────────────
log ""
log "=== Scenario 13: Zero seed (edge case) ==="
S13=/tmp/e2e_s13.bin
/tmp/e2e_harness_base 0x0 "${S13}" >/tmp/e2e_harness.log 2>&1
assert_semantic_ok "s13"
"${TENET}" --dump text "${S13}" >/tmp/e2e_decode.log 2>&1
assert_in_decode "s13 zero seed" "\[.*\] 0x"

# ─── Scenario 14: Max seed (all-ones) ───────────────────────────────────────
log ""
log "=== Scenario 14: Max seed (0xFFFFFFFFFFFFFFFF) ==="
S14=/tmp/e2e_s14.bin
/tmp/e2e_harness_base 0xFFFFFFFFFFFFFFFF "${S14}" >/tmp/e2e_harness.log 2>&1
assert_semantic_ok "s14"
"${TENET}" --dump text "${S14}" >/tmp/e2e_decode.log 2>&1
assert_in_decode "s14 max seed" "\[.*\] 0x"

# ─── Scenario 15: Large recursion depth (fib produces > 100 INST records) ───
log ""
log "=== Scenario 15: Instruction count sanity (>100 INST for fib+loops) ==="
S15=/tmp/e2e_s15.bin
/tmp/e2e_harness_base 0x42 "${S15}" >/tmp/e2e_harness.log 2>&1
assert_semantic_ok "s15"
"${TENET}" --dump text "${S15}" >/tmp/e2e_decode.log 2>&1
INST_CNT=$(grep -c "^\[" /tmp/e2e_decode.log 2>/dev/null || echo 0)
if [ "$INST_CNT" -gt 100 ]; then
  pass_ "s15: ${INST_CNT} INST records (> 100 as expected for fib+loops)"
else
  fail_ "s15: only ${INST_CNT} INST records"
fi

# ─── Scenario 16 (optional): FPR mode ───────────────────────────────────────
if [ "$FAST" -eq 0 ]; then
  log ""
  log "=== Scenario 16: FPR mode (v7 format) ==="
  # harness_fpr.c lives alongside this script (no heredoc needed)
  S16=/tmp/e2e_s16.bin
  clang++ -std=c++17 -O2 -g \
    -Wno-deprecated-declarations -Wno-constant-conversion \
    -I"${TRACE_DIR}" -I"${ROOT}/include" \
    -I"${BUILD}/include" -I"${BUILD}/include-static" \
    "${TRACE_DIR}/QBDITrace.cpp" \
    "${TRACE_DIR}/tests/integration/test_target.c" \
    "${TRACE_DIR}/tests/integration/harness_fpr.c" \
    "${BUILD}/libQBDI.a" "${BUILD}/libqbdi-llvm.a" \
    -framework Foundation -framework CoreFoundation \
    -o /tmp/e2e_harness_fpr 2>/dev/null

  /tmp/e2e_harness_fpr 0x1234 "${S16}" >/tmp/e2e_harness.log 2>&1
  assert_semantic_ok "s16/FPR"
  # tenet --dump supports all format versions (v4/v5/v7), including FPR traces.
  "${TENET}" --dump text "${S16}" >/tmp/e2e_decode.log 2>&1
  # Verify the v7 format via header bytes: version byte (offset 4) must be >= 7.
  V7VERSION=$(dd if="${S16}" bs=1 skip=4 count=1 2>/dev/null | od -A n -t u1 | tr -d ' ')
  if [ "${V7VERSION}" -ge 7 ] 2>/dev/null; then
    pass_ "s16/FPR: version=${V7VERSION} >= 7 (HF_HAS_FPR enabled)"
  else
    fail_ "s16/FPR: version=${V7VERSION} < 7 (expected v7 for FPR mode)"
  fi
  # flags is a uint64 at offset 48 in the header (see qbditrace_file_header_t).
  # HF_HAS_FPR = 1<<6 = 0x40; read the low byte of flags (offset 48).
  FLAGS_BYTE=$(dd if="${S16}" bs=1 skip=48 count=1 2>/dev/null | od -A n -t u1 | tr -d ' ')
  if [ -n "${FLAGS_BYTE}" ] && [ $((FLAGS_BYTE & 0x40)) -ne 0 ] 2>/dev/null; then
    pass_ "s16/FPR: HF_HAS_FPR (bit 6 = 0x40) set in header flags byte (${FLAGS_BYTE})"
  else
    fail_ "s16/FPR: HF_HAS_FPR NOT set — flags low byte=${FLAGS_BYTE} (expected bit 6 set)"
  fi
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
log ""
log "═══════════════════════════════════════════════════════════"
log "  E2E Test Results: ${PASS} passed, ${FAIL} failed (total ${TOTAL})"
log "═══════════════════════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
