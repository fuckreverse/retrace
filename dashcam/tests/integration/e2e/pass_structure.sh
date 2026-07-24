# Validate tenet's structural analysis passes against a real core trace with
# branches, loops, non-inlined calls, and recursion.

STRUCTURE_TRACE=/tmp/e2e_pass_structure_core.bin

log "Recording core scenario for structure passes..."
run_scenario core "${STRUCTURE_TRACE}"
assert_semantic_ok "structure/core"

log "Running xref pass..."
run_tenet "${STRUCTURE_TRACE}" --run-pass xref
assert_tenet_ok "structure/xref"
assert_in "structure/xref indexed PCs" /tmp/e2e_out.log '\[run-pass\] xref: unique PCs: [1-9][0-9]*, insts indexed: [1-9][0-9]*'

log "Running cfg pass..."
run_tenet "${STRUCTURE_TRACE}" --run-pass cfg
assert_tenet_ok "structure/cfg"
assert_in "structure/cfg non-empty graph" /tmp/e2e_out.log '\[run-pass\] cfg: blocks: [1-9][0-9]*, edges: [1-9][0-9]*'

log "Running loop pass..."
run_tenet "${STRUCTURE_TRACE}" --run-pass loop
assert_tenet_ok "structure/loop"
assert_in "structure/loop detected loops" /tmp/e2e_out.log '\[run-pass\] loop: loops: [1-9][0-9]*'

log "Running function pass..."
run_tenet "${STRUCTURE_TRACE}" --run-pass function
assert_tenet_ok "structure/function"
assert_in "structure/function detected multiple functions" /tmp/e2e_out.log '\[run-pass\] function: functions: ([2-9]|[1-9][0-9]+)'

log "Running call_graph pass..."
run_tenet "${STRUCTURE_TRACE}" --run-pass call_graph
assert_tenet_ok "structure/call_graph"
assert_in "structure/call_graph non-empty edges" /tmp/e2e_out.log '\[run-pass\] call_graph: nodes: [1-9][0-9]*, edges: [1-9][0-9]*'

log "Running cfg_layout pass..."
run_tenet "${STRUCTURE_TRACE}" --run-pass cfg_layout
assert_tenet_ok "structure/cfg_layout"
