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
assert_in "platform/objc NSString messages" /tmp/e2e_out.log '"selector_name": "(stringWithUTF8String:|length|UTF8String)"'
assert_in "platform/objc returned string" /tmp/e2e_out.log '"string": "tenet-e2e"'

log "Running syscall_intercept pass..."
run_tenet "${PLATFORM_TRACE}" --syscall-intercept
assert_tenet_ok "platform/syscall_intercept"
assert_in "platform/syscall_intercept CC_SHA256" /tmp/e2e_out.log '"callee": "CC_SHA256"'
assert_in "platform/syscall_intercept inline input capture" /tmp/e2e_out.log '"data_hex_first64": "74656e65742d653265"'
assert_in "platform/syscall_intercept getpid syscall" /tmp/e2e_out.log '"callee": "getpid"'
assert_in "platform/syscall_intercept Mach trap" /tmp/e2e_out.log '(thread_self_trap|raw=-27)'
