# Validate tenet's pattern, loop semantics, algorithm summary, and ObjC crypto
# correlation passes against a real crypto trace.
#
# --loop-semantics / --algorithm-summary used to fail here because
# batch_analysis.cpp manually registered LoopPass/LoopSemanticsPass without
# their transitive xref/cfg dependencies (fixed: both flags now register the
# full xref -> cfg -> loop -> loop_semantics chain, matching what
# `--run-pass <name>` already did via pass_registry.cpp's automatic
# dependency resolution).

CRYPTO_TRACE=/tmp/e2e_pass_crypto_trace.bin

log "Recording crypto scenario for crypto-analysis passes..."
run_scenario crypto "${CRYPTO_TRACE}"
assert_semantic_ok "crypto/scenario"

log "Running pattern pass..."
run_tenet "${CRYPTO_TRACE}" --pattern
assert_tenet_ok "crypto/pattern"
assert_in "crypto/pattern TEA known constant" /tmp/e2e_out.log '(TEA_DELTA|TEA)'

log "Running loop_semantics pass via its high-level CLI flag..."
run_tenet "${CRYPTO_TRACE}" --loop-semantics
assert_tenet_ok "crypto/loop_semantics"
assert_in "crypto/loop_semantics classified both loops" /tmp/e2e_out.log '\[loop-semantics\] 2 loops analyzed, 2 Feistel, 2 crypto'

log "Running algorithm_summary pass via its high-level CLI flag..."
run_tenet "${CRYPTO_TRACE}" --algorithm-summary
assert_tenet_ok "crypto/algorithm_summary"
assert_in "crypto/algorithm_summary identified algorithm" /tmp/e2e_out.log '"name": "TEA"'

log "Running objc_crypto pass..."
run_tenet "${CRYPTO_TRACE}" --objc-crypto
assert_tenet_ok "crypto/objc_crypto"
assert_in "crypto/objc_crypto NSObject context" /tmp/e2e_out.log '"(class_name|class)": "NSObject"'
assert_in "crypto/objc_crypto description selector" /tmp/e2e_out.log '"(selector_name|selector)": "description"'
assert_in "crypto/objc_crypto TEA association" /tmp/e2e_out.log '(TEA_DELTA|TEA)'
assert_in "crypto/objc_crypto contextual hit count" /tmp/e2e_out.log '"in_objc_count": ([1-9]|[1-9][0-9]+)'
