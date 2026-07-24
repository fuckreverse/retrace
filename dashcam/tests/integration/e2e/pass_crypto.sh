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

# Beyond TEA: target_crypto.c also materializes one known constant from each
# of six other algorithm families (AES, DES, SHA-256 x2, MD5, CRC32, ChaCha20
# x2) via movz+movk asm pairs, exercising more of PatternCollector's
# known-constant database (pattern_pass.cpp's known_db()) than a single
# algorithm can.
assert_in "crypto/pattern AES known constant" /tmp/e2e_out.log 'AES_RCON1 \(AES\)'
assert_in "crypto/pattern DES known constant" /tmp/e2e_out.log 'DES_MASK_NIBBLE \(DES\)'
assert_in "crypto/pattern SHA-256 known constants" /tmp/e2e_out.log 'SHA256_H0 \(SHA-256\)'
assert_in "crypto/pattern MD5 known constant" /tmp/e2e_out.log 'MD5_T1 \(MD5\)'
assert_in "crypto/pattern CRC32 known constant" /tmp/e2e_out.log 'CRC32_POLY \(CRC32\)'
assert_in "crypto/pattern ChaCha20 known constants" /tmp/e2e_out.log 'CHACHA20_SIGMA0 \(ChaCha20\)'

log "Running loop_semantics pass via its high-level CLI flag..."
run_tenet "${CRYPTO_TRACE}" --loop-semantics
assert_tenet_ok "crypto/loop_semantics"
assert_in "crypto/loop_semantics classified both loops" /tmp/e2e_out.log '\[loop-semantics\] 2 loops analyzed, 2 Feistel, 2 crypto'

log "Running algorithm_summary pass via its high-level CLI flag..."
run_tenet "${CRYPTO_TRACE}" --algorithm-summary
assert_tenet_ok "crypto/algorithm_summary"
assert_in "crypto/algorithm_summary identified algorithm" /tmp/e2e_out.log '"name": "TEA"'
# Cross-references the pattern-pass known-constant hits above (AES/DES/
# SHA-256/MD5/CRC32/ChaCha20) into standalone algorithm candidates too, not
# just TEA — confirms the pattern -> algorithm_summary evidence pipeline
# actually surfaces every algorithm family, not merely the loop-correlated one.
assert_in "crypto/algorithm_summary AES candidate" /tmp/e2e_out.log '"family": "AES"'
assert_in "crypto/algorithm_summary DES candidate" /tmp/e2e_out.log '"family": "DES"'
assert_in "crypto/algorithm_summary SHA-256 candidate" /tmp/e2e_out.log '"family": "SHA-256"'
assert_in "crypto/algorithm_summary MD5 candidate" /tmp/e2e_out.log '"family": "MD5"'
assert_in "crypto/algorithm_summary CRC32 candidate" /tmp/e2e_out.log '"family": "CRC32"'
assert_in "crypto/algorithm_summary ChaCha20 candidate" /tmp/e2e_out.log '"family": "ChaCha20"'
assert_in "crypto/algorithm_summary detected 8 algorithms" /tmp/e2e_out.log '\[algorithm-summary\] 8 algorithms detected'

log "Running objc_crypto pass..."
run_tenet "${CRYPTO_TRACE}" --objc-crypto
assert_tenet_ok "crypto/objc_crypto"
assert_in "crypto/objc_crypto NSObject context" /tmp/e2e_out.log '"(class_name|class)": "NSObject"'
assert_in "crypto/objc_crypto description selector" /tmp/e2e_out.log '"(selector_name|selector)": "description"'
assert_in "crypto/objc_crypto TEA association" /tmp/e2e_out.log '(TEA_DELTA|TEA)'
assert_in "crypto/objc_crypto contextual hit count" /tmp/e2e_out.log '"in_objc_count": ([1-9]|[1-9][0-9]+)'
