# Validate ObjC message/return decoding and C API, syscall, and Mach-trap
# interception against a trace recorded from the core integration scenario.

PLATFORM_TRACE=/tmp/e2e_pass_platform_core.bin

log "Recording core scenario for platform passes..."
run_scenario core "${PLATFORM_TRACE}"
assert_semantic_ok "platform/core"

log "Running objc pass..."
run_tenet "${PLATFORM_TRACE}" --objc
assert_tenet_ok "platform/objc"
assert_in "platform/objc NSObject class" /tmp/e2e_out.log '"class_name": "NSObject"'
assert_in "platform/objc description getter" /tmp/e2e_out.log '"selector_name": "description"'
assert_in "platform/objc NSString class" /tmp/e2e_out.log '"class_name": "NSString"'
assert_in "platform/objc NSString factory" /tmp/e2e_out.log '"selector_name": "stringWithUTF8String:"'
assert_in "platform/objc NSString length" /tmp/e2e_out.log '"selector_name": "length"'
assert_in "platform/objc NSString UTF8String" /tmp/e2e_out.log '"selector_name": "UTF8String"'
tr '\n' ' ' </tmp/e2e_out.log >/tmp/e2e_objc_flat.log
log "Checking that tenet-e2e is decoded specifically from an ObjC return..."
assert_in "platform/objc returned string" /tmp/e2e_objc_flat.log '"return": \{[^}]*"string": "tenet-e2e"'
log "Checking ObjC metadata enum values..."
assert_in "platform/objc inline selector source" /tmp/e2e_out.log '"selector_source": "inline"'
assert_in "platform/objc resolved class" /tmp/e2e_out.log '"class_resolution": "resolved"'
assert_in "platform/objc resolved selector" /tmp/e2e_out.log '"selector_resolution": "resolved"'
assert_in "platform/objc msgSend variant" /tmp/e2e_out.log '"variant": 0'
assert_in "platform/objc x0 return kind" /tmp/e2e_out.log '"return_kind": "x0"'
rm -f /tmp/e2e_objc_flat.log

log "Running syscall_intercept pass..."
run_tenet "${PLATFORM_TRACE}" --syscall-intercept
assert_tenet_ok "platform/syscall_intercept"
log "Checking CC_SHA256 is emitted exactly once..."
cc_sha256_count=$(grep -c '"callee": "CC_SHA256"' /tmp/e2e_out.log || true)
if [ "${cc_sha256_count}" -eq 1 ]; then
    pass_ "platform/syscall_intercept CC_SHA256: exact count 1"
else
    fail_ "platform/syscall_intercept CC_SHA256: expected count 1, got ${cc_sha256_count}"
fi
tr '\n' ' ' </tmp/e2e_out.log >/tmp/e2e_syscall_flat.log
log "Checking CC_SHA256 category and captured data length..."
assert_in "platform/syscall_intercept CC_SHA256 category" /tmp/e2e_syscall_flat.log '"callee": "CC_SHA256"[^}]*"category": "CommonCrypto"'
assert_in "platform/syscall_intercept CC_SHA256 data length" /tmp/e2e_syscall_flat.log '"callee": "CC_SHA256"[^}]*"data_length": 9'
assert_in "platform/syscall_intercept inline input capture" /tmp/e2e_out.log '"data_hex_first64": "74656e65742d653265"'
assert_in "platform/syscall_intercept getpid syscall" /tmp/e2e_out.log '"callee": "getpid"'
log "Checking Mach trap name and raw number independently..."
assert_in "platform/syscall_intercept Mach trap name" /tmp/e2e_out.log '"callee": "thread_self_trap"'
assert_in "platform/syscall_intercept Mach trap raw number" /tmp/e2e_out.log 'raw=-27'
rm -f /tmp/e2e_syscall_flat.log
