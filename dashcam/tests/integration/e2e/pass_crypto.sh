# Validate tenet's pattern, loop semantics, algorithm summary, and ObjC crypto
# correlation passes against a real crypto trace. Use --run-pass for
# loop_semantics and algorithm_summary because their high-level CLI flags omit
# the xref/cfg dependencies required by LoopPass.

CRYPTO_TRACE=/tmp/e2e_pass_crypto_trace.bin

log "Recording crypto scenario for crypto-analysis passes..."
run_scenario crypto "${CRYPTO_TRACE}"
assert_semantic_ok "crypto/scenario"

log "Running pattern pass..."
run_tenet "${CRYPTO_TRACE}" --pattern
assert_tenet_ok "crypto/pattern"
assert_in "crypto/pattern TEA known constant" /tmp/e2e_out.log '(TEA_DELTA|TEA)'

log "Running loop_semantics pass with automatic dependency resolution..."
run_tenet "${CRYPTO_TRACE}" --run-pass loop_semantics
assert_tenet_ok "crypto/loop_semantics"
assert_in "crypto/loop_semantics classified both loops" /tmp/e2e_out.log '\[run-pass\] loop_semantics: loops: 2 \(2 crypto\)'

log "Running algorithm_summary pass with automatic dependency resolution..."
run_tenet "${CRYPTO_TRACE}" --run-pass algorithm_summary
assert_tenet_ok "crypto/algorithm_summary"
assert_in "crypto/algorithm_summary identified algorithm" /tmp/e2e_out.log '\[run-pass\] algorithm_summary: algorithms: [1-9][0-9]*'

log "Running objc_crypto pass..."
run_tenet "${CRYPTO_TRACE}" --objc-crypto
assert_tenet_ok "crypto/objc_crypto"
assert_in "crypto/objc_crypto NSObject context" /tmp/e2e_out.log '"(class_name|class)": "NSObject"'
assert_in "crypto/objc_crypto description selector" /tmp/e2e_out.log '"(selector_name|selector)": "description"'
assert_in "crypto/objc_crypto TEA association" /tmp/e2e_out.log '(TEA_DELTA|TEA)'
assert_in "crypto/objc_crypto contextual hit count" /tmp/e2e_out.log '"in_objc_count": ([1-9]|[1-9][0-9]+)'
