# Validate tenet's profile analysis passes against real profile/core traces.
# trace_fold uses --run-pass because the high-level --trace-fold path omits
# CFGPass even though LoopPass depends on cfg.

PROFILE_TRACE=/tmp/e2e_pass_profile_fold.bin
PROFILE_CORE_TRACE=/tmp/e2e_pass_profile_core.bin
PROFILE_END=500

log "Recording profile scenario for trace_fold..."
run_scenario profile "${PROFILE_TRACE}"
assert_semantic_ok "profile/fold"

log "Running trace_fold pass with automatic dependency resolution..."
run_tenet "${PROFILE_TRACE}" --run-pass trace_fold
assert_tenet_ok "profile/trace_fold"
assert_in "profile/trace_fold folded regions" /tmp/e2e_out.log '\[run-pass\] trace_fold: folded regions: [1-9][0-9]*, removed [1-9][0-9]* insts'

log "Recording core scenario for timeline, context, statistics, diff, and dataflow..."
run_scenario core "${PROFILE_CORE_TRACE}"
assert_semantic_ok "profile/core"

log "Running reg_timeline pass for x0..."
run_tenet "${PROFILE_CORE_TRACE}" --reg-timeline 0 --reg-timeline-range 0 "${PROFILE_END}"
assert_tenet_ok "profile/reg_timeline"
assert_in "profile/reg_timeline x0 changes" /tmp/e2e_out.log '\[reg-timeline\] x0: [1-9][0-9]* change events'
assert_in "profile/reg_timeline event values" /tmp/e2e_out.log '"(old_value|new_value)": "0x[0-9A-F]+"'

log "Running call_context inside recursive fib execution..."
run_tenet "${PROFILE_CORE_TRACE}" --call-context 200
assert_tenet_ok "profile/call_context"
assert_in "profile/call_context non-empty stack" /tmp/e2e_out.log '\[call-context\] stack depth=[1-9][0-9]*'
assert_in "profile/call_context frame" /tmp/e2e_out.log '"call_inst_id": [0-9]+'

log "Running window_stats pass..."
run_tenet "${PROFILE_CORE_TRACE}" --window-stats 0 "${PROFILE_END}" --window-stats-size 100
assert_tenet_ok "profile/window_stats"
assert_in "profile/window_stats windows" /tmp/e2e_out.log '\[window-stats\] [1-9][0-9]* windows analyzed'
assert_in "profile/window_stats metrics" /tmp/e2e_out.log '"instruction_count": [1-9][0-9]*'

log "Running dataflow_graph pass..."
run_tenet "${PROFILE_CORE_TRACE}" --dataflow-graph 0 200
assert_tenet_ok "profile/dataflow_graph"
assert_in "profile/dataflow_graph non-empty graph" /tmp/e2e_out.log '\[dataflow-graph\] [1-9][0-9]* nodes, [1-9][0-9]* edges'

log "Running trace_diff on two core trace regions..."
run_tenet "${PROFILE_CORE_TRACE}" --trace-diff 0 50 50 100
assert_tenet_ok "profile/trace_diff"
assert_in "profile/trace_diff comparison result" /tmp/e2e_out.log '\[trace-diff\] [0-9]+ total_diverged, [0-9]+ segments'
