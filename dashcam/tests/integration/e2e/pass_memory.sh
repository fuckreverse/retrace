# Validate tenet's string and memory-analysis passes against real core/profile
# traces.

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
assert_in "memory/memory_snapshot non-empty result" /tmp/e2e_out.log '"total": [1-9][0-9]*'
assert_in "memory/memory_snapshot region content" /tmp/e2e_out.log '"hex": "[0-9A-Fa-f]+: '

log "Recording profile scenario for search and YARA passes..."
run_scenario profile "${MEMORY_PROFILE_TRACE}"
assert_semantic_ok "memory/profile"

log "Running mem_search pass across the full trace (no --mem-search-range)..."
run_tenet "${MEMORY_PROFILE_TRACE}" --mem-search-value CAFEF00DDEADC0DE
assert_tenet_ok "memory/mem_search"
assert_in "memory/mem_search one sentinel match" /tmp/e2e_out.log '\[mem-search\] 1 matches found'
assert_in "memory/mem_search sentinel value" /tmp/e2e_out.log '"matched_value": "0xCAFEF00DDEADC0DE"'
SENTINEL_INST_ID=$(grep -o '"inst_id": [0-9]*' /tmp/e2e_out.log | head -1 | grep -o '[0-9]*')

log "Running yara_mem_scan pass with the trace's code buffer..."
run_tenet "${MEMORY_PROFILE_TRACE}" --yara-mem-scan --yara-scan-code
assert_tenet_ok "memory/yara_mem_scan"
assert_in "memory/yara_mem_scan scanned pages" /tmp/e2e_out.log '[1-9][0-9]* pages scanned'
assert_in "memory/yara_mem_scan concrete rule" /tmp/e2e_out.log '"rule_name": "Dlopen_Check"'
assert_in "memory/yara_mem_scan concrete match address" /tmp/e2e_out.log '"match_addr": "0x[1-9A-Fa-f][0-9A-Fa-f]*"'
assert_in "memory/yara_mem_scan concrete match length" /tmp/e2e_out.log '"match_length": 2'

log "Locating target_profile.c's hi_entropy buffer via its marker constant..."
run_tenet "${MEMORY_PROFILE_TRACE}" --mem-search-value E47A0DDE55A2D2C1
assert_tenet_ok "memory/mem_search entropy marker"
assert_in "memory/mem_search entropy marker one match" /tmp/e2e_out.log '\[mem-search\] 1 matches found'
ENTROPY_ADDR=$(grep -o '"addr": "0x[0-9A-Fa-f]*"' /tmp/e2e_out.log | head -1 | grep -o '0x[0-9A-Fa-f]*')
ENTROPY_MARKER_INST_ID=$(grep -o '"inst_id": [0-9]*' /tmp/e2e_out.log | head -1 | grep -o '[0-9]*')

log "Running memory_snapshot pass after the entropy marker write..."
if [ -n "${ENTROPY_MARKER_INST_ID:-}" ]; then
    run_tenet "${MEMORY_PROFILE_TRACE}" --memory-snapshot "${ENTROPY_MARKER_INST_ID}"
    assert_tenet_ok "memory/memory_snapshot marker"
    assert_in "memory/memory_snapshot marker non-empty" /tmp/e2e_out.log '"total": [1-9][0-9]*'
    assert_in "memory/memory_snapshot marker bytes" /tmp/e2e_out.log \
        'c1 d2 a2 55 de 0d 7a e4'
else
    fail_ "memory/memory_snapshot marker: could not extract marker inst_id"
fi

log "Running entropy pass over hi_entropy (addr=${ENTROPY_ADDR:-<missing>}, size=128)..."
if [ -n "${ENTROPY_ADDR:-}" ]; then
    run_tenet "${MEMORY_PROFILE_TRACE}" --entropy "${ENTROPY_ADDR#0x}" 128
    assert_tenet_ok "memory/entropy"
    assert_in "memory/entropy compressed classification" /tmp/e2e_out.log \
        '\[entropy\] classification=2, entropy=6\.[0-9]+'

    log "Running entropy pass over the marker word for Plaintext classification..."
    run_tenet "${MEMORY_PROFILE_TRACE}" --entropy "${ENTROPY_ADDR#0x}" 8
    assert_tenet_ok "memory/entropy plaintext"
    assert_in "memory/entropy plaintext classification" /tmp/e2e_out.log \
        '\[entropy\] classification=1, entropy=3\.0000'
else
    fail_ "memory/entropy: could not extract hi_entropy address from mem_search output"
fi

log "Running entropy-at before and after hi_entropy is filled..."
if [ -n "${ENTROPY_ADDR:-}" ] && [ -n "${SENTINEL_INST_ID:-}" ] && \
        [ -n "${ENTROPY_MARKER_INST_ID:-}" ]; then
    ENTROPY_AFTER_INST_ID=$((ENTROPY_MARKER_INST_ID - 1))

    run_tenet "${MEMORY_PROFILE_TRACE}" --entropy "${ENTROPY_ADDR#0x}" 128 \
        --entropy-at "${SENTINEL_INST_ID}"
    assert_tenet_ok "memory/entropy-at before fill"
    assert_in "memory/entropy-at before fill unknown" /tmp/e2e_out.log \
        '\[entropy\] classification=0, entropy=0\.0000'

    run_tenet "${MEMORY_PROFILE_TRACE}" --entropy "${ENTROPY_ADDR#0x}" 128 \
        --entropy-at "${ENTROPY_AFTER_INST_ID}"
    assert_tenet_ok "memory/entropy-at after fill"
    assert_in "memory/entropy-at after fill compressed" /tmp/e2e_out.log \
        '\[entropy\] classification=2, entropy=6\.[0-9]+'
else
    fail_ "memory/entropy-at: could not extract marker address or inst_id"
fi
