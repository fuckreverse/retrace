# Validate forward taint, backward taint, and source annotation against a real
# trace whose seed flows through register, memory, call, and return-value logic.

TAINT_TRACE=/tmp/e2e_pass_taint_core.bin

log "Recording core scenario for taint passes..."
run_scenario core "${TAINT_TRACE}"
assert_semantic_ok "taint/core"

dump_trace "${TAINT_TRACE}"
TAINT_SINK_INST=$(grep -E 'INST #[0-9]+.*: eor[[:space:]]+x0,' /tmp/e2e_decode.log \
    | tail -1 | sed -E 's/^INST #([0-9]+).*/\1/')
assert_in "taint/backward sink instruction" /tmp/e2e_decode.log \
    "INST #${TAINT_SINK_INST}.*: eor[[:space:]]+x0,"

log "Running forward taint from seed register x0..."
run_tenet "${TAINT_TRACE}" --taint 0
assert_tenet_ok "taint/forward"
assert_in "taint/forward propagation across many instructions" /tmp/e2e_out.log \
    '"steps_count": (1[1-9]|[2-9][0-9]|[1-9][0-9]{2,})'
log "Checking forward register-to-register propagation classification..."
assert_in "taint/forward RegToReg propagation" /tmp/e2e_out.log \
    '"type": "RegToReg"'

log "Running backward taint from the final return-value computation..."
run_tenet "${TAINT_TRACE}" --backward-taint "${TAINT_SINK_INST}" 0
assert_tenet_ok "taint/backward"
assert_in "taint/backward non-trivial chain" /tmp/e2e_out.log \
    '"contributing_count": ([4-9]|[1-9][0-9]+)'
log "Checking backward propagation through the seed buffer..."
# KNOWN FAILING (2 assertions): these currently FAIL because backward_taint's
# slice for this sink stops at the fib constant chain and never emits
# loads_from/stores_to, even though test_target.c's seed provably flows
# through a stack buffer (buf[i]=seed+i*3) and back out via helper_sum's
# memory reads. Kept as precise, deliberately-failing assertions (rather than
# weakened or removed) to document the product-side coverage gap; remove this
# comment and these two assertions only when backward_taint's memory
# propagation is fixed to actually traverse this store->load chain.
assert_in "taint/backward memory load propagation (KNOWN FAIL: mem chain not traversed)" /tmp/e2e_out.log \
    '"loads_from": \['
assert_in "taint/backward matching memory store propagation (KNOWN FAIL: mem chain not traversed)" /tmp/e2e_out.log \
    '"stores_to": "0x[0-9A-F]+"'

log "Running backward taint source annotation..."
run_tenet "${TAINT_TRACE}" --backward-taint "${TAINT_SINK_INST}" 0 \
    --taint-source-annotation
assert_tenet_ok "taint/source_annotation"
log "Checking the concrete source kind and payload at the backward leaf..."
assert_in "taint/source_annotation immediate constant kind" /tmp/e2e_out.log \
    '"kind": "ImmediateConstant"'
assert_in "taint/source_annotation materialized fib constant" /tmp/e2e_out.log \
    '"constant": "0x9"'
assert_in "taint/source_annotation exact source count" /tmp/e2e_out.log \
    '"constant_count": 1'
assert_not_in "taint/source_annotation no unknown fallback" /tmp/e2e_out.log \
    '"kind": "Unknown"'
