#!/usr/bin/env python3
"""
qbditrace_runner.py — Python loader for the QBDI instruction tracer.

This is the ONLY supported way to run qbditrace. Do NOT use `frida -l qbditrace.js`
directly — the agent requires configuration injected via script.post().

Usage:
    python3 qbditrace_runner.py [options]

Examples:
    # iOS: Trace a function by offset in the main executable
    python3 qbditrace_runner.py \\
        --target com.example.app \\
        --entry 0xEE91EC \\
        --output /var/mobile/Documents/trace.bin

    # iOS: Trace an exported symbol
    python3 qbditrace_runner.py \\
        --target com.example.app \\
        --entry _CCCrypt \\
        --output /var/mobile/Documents/cccrypt.bin

    # Android: Trace a native library function
    python3 qbditrace_runner.py \\
        --target com.example.app \\
        --android \\
        --module libnative.so \\
        --entry 0x1234 \\
        --output /data/local/tmp/trace.bin

    # Trace a function in a specific framework module
    python3 qbditrace_runner.py \\
        --target com.example.app \\
        --module SomeFramework \\
        --entry 0x1234 \\
        --output /var/mobile/Documents/trace.bin

    # Multi-trace mode (capture 5 invocations)
    python3 qbditrace_runner.py \\
        --target com.example.app \\
        --entry 0xABC \\
        --trace-mode 5 \\
        --output /var/mobile/Documents/trace.bin

    # With GCD block tracing enabled (iOS only)
    python3 qbditrace_runner.py \\
        --target com.example.app \\
        --entry 0xABC \\
        --trace-gcd \\
        --output /var/mobile/Documents/trace.bin

    # Attach to running process
    python3 qbditrace_runner.py \\
        --target com.example.app \\
        --attach \\
        --entry 0xABC \\
        --output /var/mobile/Documents/trace.bin

    # Invoke mode: actively call a function with typed arguments
    python3 qbditrace_runner.py \\
        --target com.example.app \\
        --attach \\
        --entry 0xEE91EC \\
        --invoke \\
        --args "bytes:aabbccdd0011" "int:32" "buf:64" \\
        --output /var/mobile/Documents/trace.bin

    # Invoke with ObjC types (iOS)
    python3 qbditrace_runner.py \\
        --target com.example.app \\
        --attach \\
        --entry 0x1234 \\
        --invoke \\
        --args "nsstr:hello" "nsdata:aabbccdd" "int:0" \\
        --output /var/mobile/Documents/trace.bin

    # Invoke with string and nullptr
    python3 qbditrace_runner.py \\
        --target com.example.app \\
        --attach \\
        --entry _CCCrypt \\
        --invoke \\
        --args "int:0" "int:0" "str:mykey" "int:5" "str:plaintext" "int:9" "buf:64" "buf:8" \\
        --output /var/mobile/Documents/cccrypt.bin
"""

import argparse
import frida
import os
import signal
import sys
import threading
import time


# =============================================================================
# Typed argument parsing for --invoke mode
# =============================================================================

# Supported argument types:
#   int:N        — integer or pointer value (hex with 0x prefix, or decimal)
#   str:TEXT      — UTF-8 C string, JS allocates and passes pointer
#   bytes:HEX    — raw byte buffer from hex (e.g. bytes:aabbccdd)
#   buf:SIZE     — zero-filled output buffer, size in decimal or 0xHex
#   nullptr      — null pointer (0x0)
#   nsstr:TEXT    — ObjC NSString (iOS only)
#   nsdata:HEX   — ObjC NSData from hex bytes (iOS only)
#   nsnum:N      — ObjC NSNumber from integer (iOS only)
#   Bare value   — treated as int (e.g. 0x1234 or 42)

def _parse_typed_arg(raw, parser):
    """Parse a single TYPE:VALUE argument spec into {'type': ..., 'value': ...}."""
    raw = raw.strip()

    # nullptr is special — no colon, no value
    if raw.lower() == 'nullptr':
        return {'type': 'nullptr', 'value': None}

    # Check for TYPE:VALUE syntax
    if ':' in raw:
        type_name, _, value = raw.partition(':')
        type_name = type_name.lower().strip()

        if type_name == 'int':
            try:
                return {'type': 'int', 'value': str(int(value.strip(), 0))}
            except ValueError:
                parser.error(f'--args: invalid int value: "{value}"')

        elif type_name == 'str':
            return {'type': 'str', 'value': value}

        elif type_name == 'bytes':
            # Validate hex string
            hex_val = value.strip().replace(' ', '')
            if len(hex_val) % 2 != 0:
                parser.error(f'--args: bytes hex must have even length: "{value}"')
            try:
                bytes.fromhex(hex_val)
            except ValueError:
                parser.error(f'--args: invalid hex in bytes: "{value}"')
            return {'type': 'bytes', 'value': hex_val}

        elif type_name == 'buf':
            try:
                size = int(value.strip(), 0)
                if size <= 0:
                    parser.error(f'--args: buf size must be positive: "{value}"')
                return {'type': 'buf', 'value': str(size)}
            except ValueError:
                parser.error(f'--args: invalid buf size: "{value}"')

        elif type_name == 'nsstr':
            return {'type': 'nsstr', 'value': value}

        elif type_name == 'nsdata':
            hex_val = value.strip().replace(' ', '')
            if len(hex_val) % 2 != 0:
                parser.error(f'--args: nsdata hex must have even length: "{value}"')
            try:
                bytes.fromhex(hex_val)
            except ValueError:
                parser.error(f'--args: invalid hex in nsdata: "{value}"')
            return {'type': 'nsdata', 'value': hex_val}

        elif type_name == 'nsnum':
            try:
                return {'type': 'nsnum', 'value': str(int(value.strip(), 0))}
            except ValueError:
                parser.error(f'--args: invalid nsnum value: "{value}"')

        else:
            # Unknown type prefix — might be a bare hex value with 0x: prefix
            # (e.g. someone typed "0x1234" which has "0x1234" with partition "0x":"1234")
            pass

    # Bare value — try parsing as integer
    try:
        return {'type': 'int', 'value': str(int(raw, 0))}
    except ValueError:
        parser.error(f'--args: cannot parse argument: "{raw}". '
                     f'Use TYPE:VALUE syntax (int:, str:, bytes:, buf:, nullptr, '
                     f'nsstr:, nsdata:, nsnum:) or a bare integer.')


# =============================================================================
# Argument parsing
# =============================================================================

def parse_args():
    p = argparse.ArgumentParser(
        description='qbditrace Python loader — the ONLY supported way to run qbditrace.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # --- Connection ---
    conn = p.add_argument_group('Connection')
    conn.add_argument('--host', default='127.0.0.1:27042',
                      help='Frida remote device address (default: 127.0.0.1:27042)')
    conn.add_argument('--usb', action='store_true',
                      help='Use USB device instead of remote')
    conn.add_argument('--android', action='store_true',
                      help='Target is an Android device (adjusts default paths)')

    # --- Target ---
    tgt = p.add_argument_group('Target')
    tgt.add_argument('--target', '-t', required=True,
                     help='Bundle ID (for spawn) or process name (for attach)')
    tgt.add_argument('--attach', '-a', action='store_true',
                     help='Attach to running process instead of spawning')

    # --- What to trace ---
    trace = p.add_argument_group('What to trace')
    trace.add_argument('--module', '-m', default=None,
                       help='Module to trace (framework/dylib name). '
                            'Default: main executable. '
                            'All execution within this module will be recorded.')
    trace.add_argument('--entry', '-e', required=True,
                       help='Entry point that triggers tracing. Can be: '
                            '(1) a hex offset like 0xEE91EC (= IDA addr - image base), or '
                            '(2) an exported symbol name like _CCCrypt. '
                            'Tracing starts when this function is called and ends '
                            'when it returns. All execution within --module is recorded.')
    trace.add_argument('--arg-count', type=int, default=None,
                       help='Number of integer arguments the entry function takes '
                            '(default: 1, max: 8). Auto-inferred from --args in invoke mode.')
    trace.add_argument('--range-size', type=lambda x: int(x, 0), default=None,
                       help='[Advanced] Fallback range size in bytes if module '
                            'resolution fails (hex). Normally not needed — the '
                            'tracer instruments the entire module automatically.')

    # --- Output ---
    out = p.add_argument_group('Output')
    out.add_argument('--output', '-o', required=True,
                     help='Path on device to write the trace file '
                          '(e.g. /var/mobile/Documents/trace.bin)')
    out.add_argument('--dylib', default=None,
                     help='Path to the tracer library on device. '
                          'Default: /var/jb/usr/lib/libqbditrace.dylib (iOS) '
                          'or /data/local/tmp/libqbditrace.so (Android)')

    # --- Recording options ---
    rec = p.add_argument_group('Recording options')
    rec.add_argument('--record', type=lambda x: int(x, 0), default=31,
                     help='Record bitmask: 1=NZCV 2=REGDIFF 4=MEM 8=SVC 16=OBJC '
                          '(default: 31 = all)')
    rec.add_argument('--no-objc', action='store_true',
                     help='Disable ObjC msgSend resolution')
    rec.add_argument('--anchor-interval', type=int, default=0,
                     help='Instructions between full register snapshots '
                          '(0 = library default 1024)')
    rec.add_argument('--ring-bytes', type=lambda x: int(x, 0), default=0,
                     help='Per-thread ring buffer size in bytes '
                          '(0 = default 64 MiB)')
    rec.add_argument('--no-embed-code', action='store_true',
                     help='Disable embedding deduplicated code table in trace')
    rec.add_argument('--pc-delta', action='store_true',
                     help='Enable v5 PC-delta encoding (2-byte delta instead of '
                          '8-byte absolute PC, ~40-60%% smaller for straight-line code)')
    rec.add_argument('--fpr', action='store_true',
                     help='Enable v7 FPR/NEON register recording '
                          '(128-bit vector regs, essential for AES/SHA analysis)')
    rec.add_argument('--no-compress', action='store_true',
                     help='Disable zstd stream compression (compression is ON by default)')
    rec.add_argument('--exclude-range', type=str, action='append', default=[],
                     help='Exclude address range from tracing (format: START-END or '
                          'START:SIZE, hex). Can be specified multiple times (max 8). '
                          'Code in excluded ranges executes natively without recording. '
                          'Example: --exclude-range 0x1234-0x5678 --exclude-range 0xA000:0x200')

    # --- Invoke mode ---
    inv = p.add_argument_group('Invoke mode (active call)')
    inv.add_argument('--invoke', action='store_true',
                     help='Invoke the entry function immediately with the given '
                          'arguments instead of hooking and waiting for a passive call. '
                          'Requires --args to supply typed argument values.')
    inv.add_argument('--args', nargs='+', default=[],
                     help='Typed arguments for --invoke mode (max 8). Each argument '
                          'uses TYPE:VALUE syntax. Supported types: '
                          'int:N (integer/pointer, hex with 0x prefix), '
                          'str:TEXT (UTF-8 string, passed as pointer), '
                          'bytes:HEXDATA (raw byte buffer, e.g. bytes:aabbccdd), '
                          'buf:SIZE (zero-filled output buffer, size in decimal or 0xHex), '
                          'nullptr (null pointer, no value needed), '
                          'nsstr:TEXT (ObjC NSString, iOS only), '
                          'nsdata:HEXDATA (ObjC NSData from hex, iOS only), '
                          'nsnum:N (ObjC NSNumber, iOS only). '
                          'Bare integers (0x1234 or 42) without prefix are treated as int.')

    # --- Trace mode ---
    mode = p.add_argument_group('Trace mode')
    mode.add_argument('--trace-mode', default='once',
                      help='"once" (default), "multi" (unlimited), or a number N')
    mode.add_argument('--no-rehook', action='store_true',
                      help='Do not re-install hook between captures (multi mode)')

    # --- GCD ---
    gcd = p.add_argument_group('GCD block tracing (iOS only)')
    gcd.add_argument('--trace-gcd', action='store_true',
                     help='Enable GCD block tracing (dispatch_async etc., iOS only)')
    gcd.add_argument('--gcd-no-filter', action='store_true',
                     help='Trace ALL GCD blocks, not just those in target module')
    gcd.add_argument('--gcd-max', type=int, default=0,
                     help='Max GCD block captures (0 = unlimited)')

    # --- Runtime ---
    rt = p.add_argument_group('Runtime control')
    rt.add_argument('--timeout', type=int, default=0,
                    help='Auto-exit after N seconds (0 = wait indefinitely)')
    rt.add_argument('--wait-for-done', action='store_true',
                    help='Exit automatically after all traces are captured '
                         '(default in "once" mode)')

    args = p.parse_args()

    # Apply platform-specific defaults
    if args.dylib is None:
        if args.android:
            args.dylib = '/data/local/tmp/libqbditrace.so'
        else:
            args.dylib = '/var/jb/usr/lib/libqbditrace.dylib'

    # Parse --entry: detect if it's a hex offset or a symbol name
    args._entry_is_offset = False
    args._entry_offset = 0
    args._entry_name = None
    entry = args.entry.strip()
    try:
        # Try parsing as hex/int (0x... or plain number)
        args._entry_offset = int(entry, 0)
        args._entry_is_offset = True
    except ValueError:
        # It's a symbol name
        args._entry_name = entry

    # Validate and parse --invoke / --args
    args._invoke_args = []
    if args.invoke:
        if len(args.args) > 8:
            p.error('--args: maximum 8 arguments supported')
        for raw in args.args:
            args._invoke_args.append(_parse_typed_arg(raw, p))
        # Auto-infer arg-count from --args if not explicitly set
        if args.arg_count is None:
            args.arg_count = len(args._invoke_args)
        elif args.arg_count != len(args._invoke_args):
            p.error(f'--arg-count ({args.arg_count}) does not match '
                    f'number of --args ({len(args._invoke_args)})')
        # Invoke mode forces trace-mode to "once" — no multi-trace
        if args.trace_mode != 'once':
            print('[!] WARNING: --invoke forces --trace-mode once', file=sys.stderr)
            args.trace_mode = 'once'
    else:
        if args.arg_count is None:
            args.arg_count = 1

    # Parse trace-mode
    if args.trace_mode == 'once':
        pass
    elif args.trace_mode == 'multi':
        print('[!] WARNING: --trace-mode multi will trace every call with no '
              'upper limit. Consider using a number (e.g. --trace-mode 5) '
              'to set a safe limit.', file=sys.stderr)
    else:
        try:
            args.trace_mode = int(args.trace_mode)
            if args.trace_mode < 1:
                p.error('--trace-mode number must be >= 1')
        except ValueError:
            p.error('--trace-mode must be "once", "multi", or a positive integer')

    # Parse --exclude-range (can be specified multiple times): "START-END" or "START:SIZE"
    args._exclude_ranges = []
    if len(args.exclude_range) > 8:
        p.error('--exclude-range: maximum 8 ranges supported')
    for er_raw in args.exclude_range:
        er = er_raw.strip().lstrip('0x').lstrip('0X')
        # Re-parse from the original to handle "0x" prefix properly
        er = er_raw.strip()
        try:
            if '-' in er and ':' not in er:
                parts = er.split('-', 1)
                start = int(parts[0], 16)
                end = int(parts[1], 16)
            elif ':' in er:
                parts = er.split(':', 1)
                start = int(parts[0], 16)
                size = int(parts[1], 16)
                end = start + size
            else:
                p.error(f'--exclude-range "{er_raw}": must be START-END or START:SIZE (hex)')
                return  # unreachable
            if end <= start:
                p.error(f'--exclude-range "{er_raw}": end must be greater than start')
            args._exclude_ranges.append({'start': start, 'end': end})
        except ValueError:
            p.error(f'--exclude-range "{er_raw}": invalid hex address format')

    return args


# =============================================================================
# Build CONFIG dict to send to the JS agent
# =============================================================================

def build_config(args):
    record = args.record
    if args.no_objc:
        record &= ~(1 << 4)  # clear MSGSEND bit

    cfg = {
        'dylibPath': args.dylib,
        'moduleName': args.module,

        # Entry point resolution
        'funcName': args._entry_name,
        'funcOffset': args._entry_offset,

        # Module-wide tracing: rangeSize=0 signals the agent to use the full
        # module size. A non-zero value is only used as fallback.
        'rangeSize': args.range_size or 0,

        'outputPath': args.output,
        'record': record,
        'resolveObjc': not args.no_objc,
        'anchorInterval': args.anchor_interval,
        'ringBytes': args.ring_bytes,
        'embedCode': not args.no_embed_code,
        'pcDelta': args.pc_delta,
        'fpr': args.fpr,
        'noCompress': args.no_compress,
        'excludeRanges': args._exclude_ranges,
        'argCount': args.arg_count,
        'traceMode': args.trace_mode,
        'rehook': not args.no_rehook,
        'traceGCD': args.trace_gcd,
        'gcdFilterByModule': not args.gcd_no_filter,
        'gcdMaxCaptures': args.gcd_max,

        # Invoke mode
        'invoke': args.invoke,
        'invokeArgs': args._invoke_args,
    }
    return cfg


# =============================================================================
# Frida session management
# =============================================================================

class TracerSession:
    def __init__(self, args):
        self.args = args
        self.device = None
        self.session = None
        self.script = None
        self.pid = None
        self.stop_event = threading.Event()
        self.traces_done = 0
        self.all_done = False

    def connect(self):
        """Connect to the Frida device."""
        if self.args.usb:
            self.device = frida.get_usb_device()
        else:
            mgr = frida.get_device_manager()
            self.device = mgr.add_remote_device(self.args.host)
        print(f'[*] Connected to device: {self.device.name}')

    def start(self):
        """Spawn or attach to the target process."""
        if self.args.attach:
            self.session = self.device.attach(self.args.target)
            self.pid = self.session.pid
            print(f'[*] Attached to "{self.args.target}" (PID={self.pid})')
        else:
            self.pid = self.device.spawn([self.args.target])
            self.session = self.device.attach(self.pid)
            print(f'[*] Spawned "{self.args.target}" (PID={self.pid})')

        self.session.on('detached', self._on_detached)

    def load_agent(self):
        """Load the JS agent and send CONFIG."""
        agent_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  'qbditrace.js')
        with open(agent_path, 'r') as f:
            agent_source = f.read()

        self.script = self.session.create_script(agent_source)
        self.script.on('message', self._on_message)
        self.script.set_log_handler(self._on_log)
        self.script.load()

        # Send configuration to the agent
        config = build_config(self.args)
        self.script.post({'type': 'config', 'payload': config})
        print('[*] Config sent to agent')

    def resume(self):
        """Resume the target process (only needed for spawn mode)."""
        if not self.args.attach:
            self.device.resume(self.pid)
            print(f'[*] Process resumed (PID={self.pid})')

    def wait(self):
        """Wait for completion or timeout."""
        timeout = self.args.timeout if self.args.timeout > 0 else None

        # In "once" mode, default to wait-for-done behavior
        wait_for_done = self.args.wait_for_done
        if self.args.trace_mode == 'once':
            wait_for_done = True

        print('[*] Waiting for traces... (Ctrl+C to stop)')
        self.stop_event.wait(timeout=timeout)

        if not self.stop_event.is_set():
            if timeout:
                print(f'\n[*] Timeout ({timeout}s) reached.')
            # If wait_for_done and not yet done, keep waiting
            if wait_for_done and not self.all_done:
                print('[*] Traces not yet complete, waiting...')
                self.stop_event.wait()

    def cleanup(self):
        """Unload script and detach."""
        try:
            if self.script:
                self.script.unload()
        except Exception:
            pass
        try:
            if self.session:
                self.session.detach()
        except Exception:
            pass
        print(f'[*] Done. {self.traces_done} trace(s) captured.')

    # --- Callbacks ---

    def _on_message(self, message, data):
        """Handle messages from the JS agent."""
        if message['type'] == 'send':
            payload = message['payload']
            msg_type = payload.get('type', '')

            if msg_type == 'log':
                level = payload.get('level', 'info')
                text = payload.get('text', '')
                if level == 'error':
                    print(f'\033[91m{text}\033[0m', file=sys.stderr)
                else:
                    print(text)

            elif msg_type == 'status':
                event = payload.get('event', '')
                detail = payload.get('detail', {})
                self._handle_status(event, detail)

            elif msg_type == 'error':
                print(f'\033[91m[FATAL] {payload.get("text", "")}\033[0m',
                      file=sys.stderr)
                self.stop_event.set()

        elif message['type'] == 'error':
            print(f'\033[91m[JS ERROR] {message.get("stack", message)}\033[0m',
                  file=sys.stderr)

    def _on_log(self, level, text):
        """Handle console.log from the agent (should not be used, but just in case)."""
        print(f'[console.{level}] {text}')

    def _on_detached(self, reason, crash):
        """Handle session detach."""
        print(f'\n[!] Session detached: {reason}')
        if crash:
            print(f'    Crash: {crash}')
        self.stop_event.set()

    def _handle_status(self, event, detail):
        """Process status events from the agent."""
        if event == 'agent_loaded':
            pass  # Agent is ready, config will be sent
        elif event == 'initializing':
            print('[*] Agent initializing...')
        elif event == 'invoke_start':
            func_start = detail.get('funcStart', '?')
            argc = detail.get('argc', '?')
            print(f'[*] Invoking {func_start} with {argc} arg(s)...')
        elif event == 'hook_installed':
            func_start = detail.get('funcStart', '?')
            mode = detail.get('mode', '?')
            max_traces = detail.get('maxTraces', '?')
            module_name = detail.get('moduleName', '?')
            module_size = detail.get('moduleSize', '?')
            print(f'[*] Hook installed @ {func_start}')
            print(f'    Module: {module_name} (size={module_size})')
            print(f'    Mode: {mode}, max traces: {max_traces}')
            print('[*] Trigger the target function to start tracing.')
        elif event == 'trace_start':
            idx = detail.get('index', '?')
            print(f'[*] Trace #{idx} started...')
        elif event == 'trace_done':
            idx = detail.get('index', '?')
            output = detail.get('output', '?')
            ret = detail.get('ret', '?')
            self.traces_done += 1
            print(f'[+] Trace #{idx} complete -> {output} (ret={ret})')
        elif event == 'gcd_trace_done':
            idx = detail.get('index', '?')
            path = detail.get('path', '?')
            print(f'[+] GCD trace #{idx} complete -> {path}')
        elif event == 'all_done':
            total = detail.get('total', self.traces_done)
            print(f'[*] All {total} trace(s) captured.')
            self.all_done = True
            self.stop_event.set()


# =============================================================================
# Main
# =============================================================================

def main():
    args = parse_args()

    # Print summary
    print('=' * 60)
    print('  qbditrace — QBDI Instruction Tracer (Python Loader)')
    print('=' * 60)
    print(f'  Target:      {args.target} ({"attach" if args.attach else "spawn"})')
    print(f'  Module:      {args.module or "(main executable)"}')
    if args._entry_name:
        print(f'  Entry:       {args._entry_name} (symbol)')
    else:
        print(f'  Entry:       0x{args._entry_offset:X} (offset)')
    print(f'  Trace scope: entire module (all execution within module is recorded)')
    if args.range_size:
        print(f'  Fallback:    range-size 0x{args.range_size:X} (if module resolution fails)')
    print(f'  Output:      {args.output}')
    print(f'  Record:      0x{args.record:02X} '
          f'(NZCV={bool(args.record & 1)}, REGDIFF={bool(args.record & 2)}, '
          f'MEM={bool(args.record & 4)}, SVC={bool(args.record & 8)}, '
          f'OBJC={bool(args.record & 16)})')
    extras = []
    if args.pc_delta:    extras.append('pc-delta(v5)')
    if args.fpr:         extras.append('fpr(v7)')
    if args.no_compress: extras.append('no-compress')
    else:                extras.append('zstd-compress')
    print(f'  Features:    {" | ".join(extras)}')
    for i, er in enumerate(args._exclude_ranges):
        print(f'  Exclude[{i}]:  0x{er["start"]:X} - 0x{er["end"]:X} '
              f'(size 0x{er["end"] - er["start"]:X})')
    if args.invoke:
        print(f'  Mode:        INVOKE (active call)')
        for i, a in enumerate(args._invoke_args):
            if a['value'] is not None:
                print(f'  Arg[{i}]:      {a["type"]}:{a["value"]}')
            else:
                print(f'  Arg[{i}]:      {a["type"]}')
    else:
        print(f'  Mode:        HOOK (passive, trace-mode={args.trace_mode})')
    if args.trace_gcd:
        print(f'  GCD trace:   ON (filter={not args.gcd_no_filter}, max={args.gcd_max})')
    if args.timeout:
        print(f'  Timeout:     {args.timeout}s')
    print('=' * 60)

    ts = TracerSession(args)

    # Handle Ctrl+C gracefully
    def sigint_handler(sig, frame):
        print('\n[*] Interrupted by user.')
        ts.stop_event.set()

    signal.signal(signal.SIGINT, sigint_handler)

    try:
        ts.connect()
        ts.start()
        ts.load_agent()
        ts.resume()
        ts.wait()
    except frida.ServerNotRunningError:
        print('[!] Frida server is not running on the device.', file=sys.stderr)
        print('    Start it with: frida-server &', file=sys.stderr)
        sys.exit(1)
    except frida.ProcessNotFoundError:
        print(f'[!] Process "{args.target}" not found.', file=sys.stderr)
        sys.exit(1)
    except frida.TransportError as e:
        print(f'[!] Transport error: {e}', file=sys.stderr)
        print('    Check SSH tunnel / network connectivity.', file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f'[!] Error: {e}', file=sys.stderr)
        sys.exit(1)
    finally:
        ts.cleanup()


if __name__ == '__main__':
    main()
