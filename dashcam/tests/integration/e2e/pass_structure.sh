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

STRUCTURE_CFG_DOT=/tmp/e2e_pass_structure_cfg.dot
log "Exporting CFG to verify branch, call, return, and fallthrough semantics..."
run_tenet "${STRUCTURE_TRACE}" --export-cfg "${STRUCTURE_CFG_DOT}"
assert_tenet_ok "structure/cfg export"
assert_in "structure/cfg DOT has counted edges" "${STRUCTURE_CFG_DOT}" ' -> .*\[label="[1-9][0-9]*"'
assert_in "structure/cfg classifies call edges" "${STRUCTURE_CFG_DOT}" ' -> .*style=dashed'
assert_in "structure/cfg contains unconditional branches" "${STRUCTURE_CFG_DOT}" ': b #0x[0-9a-f]+'
assert_in "structure/cfg contains conditional branches" "${STRUCTURE_CFG_DOT}" ': (b\.[a-z]+|cbn?z|tbn?z) '
assert_in "structure/cfg contains returns" "${STRUCTURE_CFG_DOT}" ': ret '
assert_in "structure/cfg marks fallthrough edges" "${STRUCTURE_CFG_DOT}" ' -> .*color="#888888"'

log "Running loop pass..."
run_tenet "${STRUCTURE_TRACE}" --run-pass loop
assert_tenet_ok "structure/loop"
assert_in "structure/loop detected loops" /tmp/e2e_out.log '\[run-pass\] loop: loops: [1-9][0-9]*'

log "Running function pass..."
run_tenet "${STRUCTURE_TRACE}" --run-pass function
assert_tenet_ok "structure/function"
assert_in "structure/function detected exact core function count" /tmp/e2e_out.log '\[run-pass\] function: functions: 19$'

log "Running call_graph pass..."
run_tenet "${STRUCTURE_TRACE}" --run-pass call_graph
assert_tenet_ok "structure/call_graph"
assert_in "structure/call_graph non-empty edges" /tmp/e2e_out.log '\[run-pass\] call_graph: nodes: [1-9][0-9]*, edges: [1-9][0-9]*'
assert_in "structure/call_graph exact size and max depth" /tmp/e2e_out.log '\[run-pass\] call_graph: nodes: 21, edges: 22, max depth: 21$'

# FunctionPass names unsymbolized functions as sub_<runtime-PC>. Resolve the
# local helper/fib symbols from the harness and relocate them by trace_target's
# observed ASLR slide so DOT assertions remain independent of load address.
trace_runtime=$(sed -n 's/.*target entry      = 0x\([0-9a-fA-F]*\).*/\1/p' /tmp/e2e_harness.log | head -1)
trace_static=$(nm -an "${HARNESS}" | awk '/__Z12trace_targety$/ { print $1; exit }')
helper_static=$(nm -an "${HARNESS}" | awk '/__ZL10helper_sumPKyi$/ { print $1; exit }')
fib_static=$(nm -an "${HARNESS}" | awk '/__ZL3fiby$/ { print $1; exit }')
slide=$((0x${trace_runtime} - 0x${trace_static}))
helper_pc=$(printf '%X' $((0x${helper_static} + slide)))
fib_pc=$(printf '%X' $((0x${fib_static} + slide)))

STRUCTURE_CG_DOT=/tmp/e2e_pass_structure_call_graph.dot
log "Exporting call graph to verify helper_sum and fib recursion edges..."
run_tenet "${STRUCTURE_TRACE}" --call-graph "${STRUCTURE_CG_DOT}"
assert_tenet_ok "structure/call_graph export"
assert_in "structure/call_graph DOT non-empty" "${STRUCTURE_CG_DOT}" '^digraph callgraph \{'
assert_in "structure/call_graph contains helper_sum node" "${STRUCTURE_CG_DOT}" "\"0x${helper_pc}\" \\[label=\"sub_[0-9a-f]+\"\\]"
assert_in "structure/call_graph detects fib self-recursion" "${STRUCTURE_CG_DOT}" "\"0x${fib_pc}\" -> \"0x${fib_pc}\" \\[label=\"[1-9][0-9]*\"\\]"

log "Running cfg_layout pass..."
run_tenet "${STRUCTURE_TRACE}" --run-pass cfg_layout
assert_tenet_ok "structure/cfg_layout"
assert_in "structure/cfg_layout non-empty block layouts" /tmp/e2e_out.log '\[run-pass\] cfg_layout: block layouts: [1-9][0-9]*'
