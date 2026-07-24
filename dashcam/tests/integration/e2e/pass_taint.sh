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

log "Running backward taint from the final return-value computation..."
run_tenet "${TAINT_TRACE}" --backward-taint "${TAINT_SINK_INST}" 0
assert_tenet_ok "taint/backward"
assert_in "taint/backward non-trivial chain" /tmp/e2e_out.log \
    '"contributing_count": ([4-9]|[1-9][0-9]+)'

log "Running backward taint source annotation..."
run_tenet "${TAINT_TRACE}" --backward-taint "${TAINT_SINK_INST}" 0 \
    --taint-source-annotation
assert_tenet_ok "taint/source_annotation"
assert_in "taint/source_annotation classified endpoint" /tmp/e2e_out.log \
    '"kind": "(ImmediateConstant|MemoryLoad|ObjcGetter|FunctionReturn|Unknown)"'
