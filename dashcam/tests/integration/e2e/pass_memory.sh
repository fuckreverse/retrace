# Validate tenet's string and memory-analysis passes against real core/profile
# traces. Entropy is intentionally excluded: its CLI cannot set addr/size and
# therefore only analyzes an unusable default region near address zero.

MEMORY_CORE_TRACE=/tmp/e2e_pass_memory_core.bin
MEMORY_PROFILE_TRACE=/tmp/e2e_pass_memory_profile.bin

log "Recording core scenario for string and snapshot passes..."
run_scenario core "${MEMORY_CORE_TRACE}"
assert_semantic_ok "memory/core"

log "Running strings pass..."
run_tenet "${MEMORY_CORE_TRACE}" --strings
assert_tenet_ok "memory/strings"
assert_in "memory/strings completed" /tmp/e2e_out.log '\[strings\] Found [0-9]+ strings'

log "Running memory_strings pass..."
run_tenet "${MEMORY_CORE_TRACE}" --memory-strings
assert_tenet_ok "memory/memory_strings"
assert_in "memory/memory_strings content" /tmp/e2e_out.log '"content": "tenet-e2e"'

dump_trace "${MEMORY_CORE_TRACE}"
MEMORY_TRACE_LINES=$(wc -l < /tmp/e2e_decode.log | tr -d ' ')
MEMORY_SNAPSHOT_ID=$((MEMORY_TRACE_LINES / 2))
log "Running memory_snapshot pass at inst_id ${MEMORY_SNAPSHOT_ID}..."
run_tenet "${MEMORY_CORE_TRACE}" --memory-snapshot "${MEMORY_SNAPSHOT_ID}"
assert_tenet_ok "memory/memory_snapshot"

log "Recording profile scenario for search and YARA passes..."
run_scenario profile "${MEMORY_PROFILE_TRACE}"
assert_semantic_ok "memory/profile"

log "Running mem_search pass across the complete trace..."
run_tenet "${MEMORY_PROFILE_TRACE}" \
    --mem-search-value CAFEF00DDEADC0DE --mem-search-range 0 999999
assert_tenet_ok "memory/mem_search"
assert_in "memory/mem_search one sentinel match" /tmp/e2e_out.log '\[mem-search\] 1 matches found'
assert_in "memory/mem_search sentinel value" /tmp/e2e_out.log '"matched_value": "0xCAFEF00DDEADC0DE"'

log "Running yara_mem_scan pass..."
run_tenet "${MEMORY_PROFILE_TRACE}" --yara-mem-scan
assert_tenet_ok "memory/yara_mem_scan"
assert_in "memory/yara_mem_scan scanned pages" /tmp/e2e_out.log '[1-9][0-9]* pages scanned'
