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

    # Capture an opt-in memory snapshot before tracing
    python3 qbditrace_runner.py \\
        --target com.example.app \\
        --entry 0xABC \\
        --snapshot-range 0x100010000 0x100012000 \\
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
from pathlib import Path
import signal
import sys
import threading
import time

# Frida 17.x: ObjC/Java bridges are loaded on-demand via 'frida:load-bridge' messages.
# We need to handle these requests by sending back the bridge source from frida_tools/bridges/.
_BRIDGES_DIR = None
def _find_bridges_dir():
    global _BRIDGES_DIR
    if _BRIDGES_DIR is not None:
        return _BRIDGES_DIR
    # Try frida_tools package
    try:
        import frida_tools
        candidate = Path(frida_tools.__file__).parent / 'bridges'
        if candidate.is_dir():
            _BRIDGES_DIR = candidate
            return _BRIDGES_DIR
    except ImportError:
        pass
    # Try common locations
    for p in [Path(sys.prefix) / 'lib' / 'python3' / 'site-packages' / 'frida_tools' / 'bridges',
              Path.home() / 'Library' / 'Python' / '3.14' / 'lib' / 'python' / 'site-packages' / 'frida_tools' / 'bridges']:
        if p.is_dir():
            _BRIDGES_DIR = p
            return _BRIDGES_DIR
    return None

# Bridge loader JS snippet — inject this before the agent code so ObjC/Java globals are available.
_BRIDGE_LOADER_JS = r'''
(function() {
    function loadBridge(name) {
        send({type: "frida:load-bridge", name: name});
        var result = null;
        recv("frida:bridge-loaded", function(msg) {
            result = msg;
        }).wait();
        if (result === null) throw new Error("Failed to load bridge: " + name);
        return Script.evaluate("/frida/bridges/" + result.filename,
            "(function () { " + [result.source,
            "Object.defineProperty(globalThis, '" + name + "', { value: bridge });",
            "return bridge;"].join("\\n") + " })();");
    }
    ["ObjC", "Java", "Swift"].forEach(function(name) {
        Object.defineProperty(globalThis, name, {
            enumerable: true,
            configurable: true,
            get: function() {
                var bridge = loadBridge(name);
                Object.defineProperty(globalThis, name, { value: bridge });
                return bridge;
            }
        });
    });
})();
'''


# =============================================================================
# Record bitmask constants (must mirror QBDITrace.h QBDITRACE_REC_* exactly)
# =============================================================================

QBDITRACE_REC_NZCV      = 1 << 0
QBDITRACE_REC_REGDIFF   = 1 << 1
QBDITRACE_REC_MEM       = 1 << 2
QBDITRACE_REC_SYSCALL   = 1 << 3
QBDITRACE_REC_MSGSEND   = 1 << 4
QBDITRACE_REC_CAPI      = 1 << 5
QBDITRACE_REC_SEQEVENTS = 1 << 6
QBDITRACE_REC_DEFAULT = (QBDITRACE_REC_NZCV | QBDITRACE_REC_REGDIFF |
                         QBDITRACE_REC_MEM | QBDITRACE_REC_SYSCALL |
                         QBDITRACE_REC_MSGSEND | QBDITRACE_REC_CAPI |
                         QBDITRACE_REC_SEQEVENTS)
# Sentinel bit: forces `record` non-zero without turning on any content bit,
# so the native ABI shim (which treats record==0 as "caller didn't set it"
# and substitutes QBDITRACE_REC_DEFAULT) does not override it. See the
# QBDITRACE_REC_SAMPLING comment in QBDITrace.h for the full rationale.
QBDITRACE_REC_SAMPLING = 1 << 31

# Large but finite default anchor interval for --sampling: exact register
# state is not needed for loop/hotspot discovery, only the PC stream, so
# resync checkpoints can be very sparse. Kept finite (not 0, which would mean
# "use the library's small 1024 default") to actually reduce ANCHOR volume.
SAMPLING_DEFAULT_ANCHOR_INTERVAL = 1 << 20


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

def _parse_patch_spec(raw, parser):
    """Parse a single --patch ADDR:HEXBYTES spec.

    Formats:
        0x100abc:00112233         — absolute runtime address
        +0x1abc:00112233          — offset from module base ('+' prefix)
    Returns {'addr': str, 'hex': str, 'is_offset': bool}.
    """
    raw = raw.strip()
    if ':' not in raw:
        parser.error(f'--patch: missing colon separator in "{raw}". '
                     f'Format: ADDR:HEXBYTES or +OFFSET:HEXBYTES')

    addr_part, _, hex_part = raw.partition(':')
    addr_part = addr_part.strip()
    hex_part = hex_part.strip().replace(' ', '')

    # Validate hex data
    if len(hex_part) == 0:
        parser.error(f'--patch: empty hex data in "{raw}"')
    if len(hex_part) % 2 != 0:
        parser.error(f'--patch: hex data must have even length in "{raw}"')
    try:
        bytes.fromhex(hex_part)
    except ValueError:
        parser.error(f'--patch: invalid hex data in "{raw}"')

    # Parse address (with optional '+' prefix for offset mode)
    is_offset = addr_part.startswith('+')
    if is_offset:
        addr_part = addr_part[1:]
    try:
        addr_val = int(addr_part, 0)
    except ValueError:
        parser.error(f'--patch: invalid address "{addr_part}" in "{raw}"')

    return {
        'addr': hex(addr_val),
        'hex': hex_part,
        'is_offset': is_offset,
    }


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
    rec.add_argument('--record', type=lambda x: int(x, 0), default=None,
                     help='Record bitmask: 1=NZCV 2=REGDIFF 4=MEM 8=SVC 16=OBJC '
                          '32=CAPI 64=SEQEVENTS (default: 127 = all, i.e. '
                          'QBDITRACE_REC_DEFAULT). Ignored if --sampling is set.')
    rec.add_argument('--no-objc', action='store_true',
                     help='Disable ObjC msgSend resolution')
    rec.add_argument('--anchor-interval', type=int, default=None,
                     help='Instructions between full register snapshots '
                          '(default: library default 1024, or a much larger '
                          'value automatically under --sampling)')
    rec.add_argument('--ring-bytes', type=lambda x: int(x, 0), default=0,
                     help='Per-thread ring buffer size in bytes '
                          '(0 = default 64 MiB)')
    rec.add_argument('--no-embed-code', action='store_true',
                     help='Disable embedding deduplicated code table in trace')
    rec.add_argument('--pc-delta', action='store_true',
                     help='Enable v5 PC-delta encoding (2-byte delta instead of '
                          '8-byte absolute PC, ~40-60%% smaller for straight-line code). '
                          'Implied by --sampling.')
    rec.add_argument('--fpr', action='store_true',
                     help='Enable v7 FPR/NEON register recording '
                          '(128-bit vector regs, essential for AES/SHA analysis)')
    rec.add_argument('--no-compress', action='store_true',
                     help='Disable zstd block compression (1 MiB independent frames + '
                          'footer index; compression is ON by default)')
    rec.add_argument('--exclude-range', type=str, action='append', default=[],
                     help='Exclude address range from tracing (format: START-END or '
                          'START:SIZE, hex). Can be specified multiple times (max 8). '
                          'Code in excluded ranges executes natively without recording. '
                          'Example: --exclude-range 0x1234-0x5678 --exclude-range 0xA000:0x200')
    rec.add_argument('--snapshot-range', nargs=2, metavar=('START', 'END'),
                     action='append', default=[],
                     help='Capture an opt-in memory snapshot of absolute runtime range '
                          '[START, END) before tracing. Addresses accept decimal or 0x-prefixed '
                          'hex. Can be specified multiple times (max 8).')
    rec.add_argument('--sampling', action='store_true',
                     help='Reconnaissance mode: produce a small, bare PC-stream trace '
                          '(record = QBDITRACE_REC_SAMPLING, i.e. only REC_INST + '
                          'REC_CODE + REC_ANCHOR — no reg diffs, no memory accesses, '
                          'no SEQ_ENTRY/EXIT bookkeeping) meant to be fed to tenet\'s '
                          '`loop`/`cfg`/`window_stats` passes BEFORE committing to a '
                          'full trace. This still walks every instruction (so loop '
                          'iteration counts and back-edges are exact, unlike a '
                          'statistically down-sampled profile) but skips all the '
                          'expensive per-instruction payload, typically shrinking the '
                          'trace by 80%%+ in loop-heavy code. Workflow: run with '
                          '--sampling first, run `tenet --run-pass loop` (or '
                          '--suggest-excludes) on the result to find huge, likely-'
                          'irrelevant loops, confirm them statically in IDA, then '
                          'pass the confirmed ranges as --exclude-range on the real, '
                          'fully-recorded trace. Implies --pc-delta and a large '
                          '--anchor-interval unless explicitly overridden; --record '
                          'is ignored when this is set.')

    # --- Pre-trace memory patches ---
    patch = p.add_argument_group('Pre-trace memory patches')
    patch.add_argument('--patch', type=str, action='append', default=[],
                       help='Write bytes to target process memory before tracing starts. '
                            'Format: ADDR:HEXBYTES (absolute runtime address) or '
                            '+OFFSET:HEXBYTES (offset from module base). '
                            'Can be specified multiple times. Original bytes are '
                            'saved and restored after tracing completes. '
                            'Example: --patch 0x100abc:00000000 --patch +0x1abc:01')

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

    # --- Multi-thread ---
    mt = p.add_argument_group('Multi-thread tracing')
    mt.add_argument('--trace-threads', action='store_true',
                    help='Trace pthread child threads whose start_routine is in the '
                         'target module, into the SAME trace file (interleaved '
                         'THREAD chunks; analyze with tenet --thread)')
    mt.add_argument('--threads-no-filter', action='store_true',
                    help='Trace ALL pthread children, not just module-resident routines')
    mt.add_argument('--threads-max', type=int, default=0,
                    help='Max traced child threads (0 = unlimited)')

    je = p.add_argument_group('Java entry trigger (Android only)')
    je.add_argument('--java-entry', type=str, default=None, metavar='CLASS.METHOD',
                    help='Hook a Java method (e.g. com.example.NativeBridge.doWork) '
                         'as the trace trigger: Java args are materialized into '
                         'native pointers and the native entry is invoked via '
                         'run_call. Android only; requires --android')

    # --- Runtime ---
    rt = p.add_argument_group('Runtime control')
    rt.add_argument('--timeout', type=int, default=0,
                    help='Auto-exit after N seconds (0 = wait indefinitely)')
    rt.add_argument('--wait-for-done', action='store_true',
                    help='Exit automatically after all traces are captured '
                         '(default in "once" mode)')

    args = p.parse_args()

    # --- Validate --java-entry ---
    if args.java_entry:
        if not args.android:
            p.error('--java-entry requires --android')
        if args.invoke:
            p.error('--java-entry and --invoke are mutually exclusive')
        if '.' not in args.java_entry:
            p.error('--java-entry must be "fully.qualified.Class.method"')

    # --- Apply --sampling preset (before generic record/anchor defaulting) ---
    # Sampling mode overrides --record entirely (a real "record almost
    # nothing" requires the QBDITRACE_REC_SAMPLING sentinel bit — see
    # QBDITrace.h — which a plain numeric --record can't express safely) and
    # implies --pc-delta plus a large --anchor-interval unless the user
    # explicitly passed one.
    if args.sampling:
        if args.record is not None:
            print('[!] WARNING: --record is ignored because --sampling is set '
                  '(sampling forces record=QBDITRACE_REC_SAMPLING)', file=sys.stderr)
        args.record = QBDITRACE_REC_SAMPLING
        args.pc_delta = True
        if args.anchor_interval is None:
            args.anchor_interval = SAMPLING_DEFAULT_ANCHOR_INTERVAL
        # embed_code must stay on (default) — tenet's cfg/loop passes need the
        # REC_CODE table to disassemble and classify loop bodies.
        if args.no_embed_code:
            print('[!] WARNING: --no-embed-code with --sampling will prevent '
                  'tenet from disassembling the trace; re-enabling embed-code.',
                  file=sys.stderr)
            args.no_embed_code = False

    # Fill in the conventional defaults for callers that didn't ask for
    # --sampling (kept as None above so --sampling can tell "unset" apart
    # from "explicitly 0").
    if args.record is None:
        args.record = QBDITRACE_REC_DEFAULT
    if args.anchor_interval is None:
        args.anchor_interval = 0

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

    # Parse --patch specs
    args._patches = []
    for patch_raw in args.patch:
        args._patches.append(_parse_patch_spec(patch_raw, p))

    # Parse --snapshot-range (absolute runtime addresses).
    args._snapshot_ranges = []
    if len(args.snapshot_range) > 8:
        p.error('--snapshot-range: maximum 8 ranges supported')
    for start_raw, end_raw in args.snapshot_range:
        try:
            start = int(start_raw, 0)
            end = int(end_raw, 0)
        except ValueError:
            p.error(f'--snapshot-range "{start_raw} {end_raw}": invalid address; '
                    f'use decimal or 0x-prefixed hexadecimal')
        if start < 0 or end < 0:
            p.error(f'--snapshot-range "{start_raw} {end_raw}": addresses must be non-negative')
        if end <= start:
            p.error(f'--snapshot-range "{start_raw} {end_raw}": end must be greater than start')
        # Encode as strings so JSON transport does not lose 64-bit address precision.
        args._snapshot_ranges.append({'start': hex(start), 'end': hex(end)})

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
        record &= ~QBDITRACE_REC_MSGSEND

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
        'memSnapshot': {'ranges': args._snapshot_ranges},
        'argCount': args.arg_count,
        'traceMode': args.trace_mode,
        'rehook': not args.no_rehook,
        'traceGCD': args.trace_gcd,
        'gcdFilterByModule': not args.gcd_no_filter,
        'gcdMaxCaptures': args.gcd_max,

        # Multi-thread tracing (Phase 2)
        'traceThreads': args.trace_threads,
        'pthreadFilterByModule': not args.threads_no_filter,
        'pthreadMaxCaptures': args.threads_max,

        # Java entry trigger (Android)
        'javaEntry': args.java_entry,

        # Invoke mode
        'invoke': args.invoke,
        'invokeArgs': args._invoke_args,

        # Pre-trace memory patches
        'patches': args._patches,
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
            # Resolve target name to PID first (Frida Session has no .pid)
            procs = self.device.enumerate_processes()
            match = None
            for p in procs:
                if p.name == self.args.target or str(p.pid) == self.args.target:
                    match = p
                    break
            if match is None:
                # Try case-insensitive partial match
                for p in procs:
                    if self.args.target.lower() in p.name.lower():
                        match = p
                        break
            if match is None:
                raise RuntimeError(f'Process "{self.args.target}" not found')
            self.pid = match.pid
            self.session = self.device.attach(self.pid)
            print(f'[*] Attached to "{match.name}" (PID={self.pid})')
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

        # Frida 17.x: prepend bridge loader so ObjC/Java globals work
        agent_source = _BRIDGE_LOADER_JS + '\n' + agent_source

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

            # Frida 17.x: handle on-demand bridge loading
            if isinstance(payload, dict) and payload.get('type') == 'frida:load-bridge':
                name = payload['name']
                bridges_dir = _find_bridges_dir()
                if bridges_dir is not None:
                    bridge_file = bridges_dir / (name.lower() + '.js')
                    if bridge_file.exists():
                        source = bridge_file.read_text(encoding='utf-8')
                        self.script.post({
                            'type': 'frida:bridge-loaded',
                            'filename': bridge_file.name,
                            'source': source
                        })
                        return
                print(f'\033[91m[bridge] Failed to load {name} bridge\033[0m', file=sys.stderr)
                self.script.post({
                    'type': 'frida:bridge-loaded',
                    'filename': name.lower() + '.js',
                    'source': 'var bridge = {};'
                })
                return

            msg_type = payload.get('type', '')

            if msg_type == 'log':
                level = payload.get('level', 'info')
                text = payload.get('text', '')
                if level == 'error':
                    print(f'\033[91m{text}\033[0m', file=sys.stderr)
                else:
                    print(text)

            elif msg_type == 'stats':
                self._handle_stats(payload)

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

    def _handle_stats(self, payload):
        """Display live trace statistics (called from setInterval in the JS agent)."""
        is_final = payload.get('final', False)
        insns = int(payload.get('insns', 0))
        anchors = int(payload.get('anchors', 0))
        mem = int(payload.get('mem', 0))
        events = int(payload.get('events', 0))
        svc = int(payload.get('svc', 0))
        objc = int(payload.get('objc', 0))
        code = int(payload.get('code', 0))
        capi = int(payload.get('capi', 0))
        raw_bytes = int(payload.get('bytes', 0))
        elapsed_ns = int(payload.get('elapsedNs', 0))

        elapsed_s = elapsed_ns / 1e9 if elapsed_ns > 0 else 0
        rate = insns / elapsed_s if elapsed_s > 0 else 0
        mb = raw_bytes / (1024 * 1024)

        # Build a compact one-line status string
        parts = [f'{insns:,} insns']
        if elapsed_s > 0:
            parts.append(f'{elapsed_s:.1f}s')
            parts.append(f'{rate / 1e6:.1f}M/s')
        parts.append(f'{mb:.1f}MB')
        # Optional record counts (only show if non-zero)
        extras = []
        if anchors: extras.append(f'anch={anchors:,}')
        if mem:     extras.append(f'mem={mem:,}')
        if svc:     extras.append(f'svc={svc:,}')
        if objc:    extras.append(f'objc={objc:,}')
        if capi:    extras.append(f'capi={capi:,}')
        if code:    extras.append(f'code={code:,}')
        if events:  extras.append(f'ev={events:,}')
        if extras:
            parts.append(' '.join(extras))

        line = ' | '.join(parts)
        if is_final:
            # Final stats: print on a new line with a marker
            print(f'\r\033[K[+] Stats: {line}')
        else:
            # In-progress: overwrite the current terminal line
            print(f'\r\033[K[*] Tracing: {line}', end='', flush=True)

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
            # Clear the in-progress stats line before printing the completion message
            print(f'\r\033[K[+] Trace #{idx} complete -> {output} (ret={ret})')
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
    if args.sampling:
        print(f'  Record:      0x{args.record:08X} (SAMPLING — bare PC stream only: '
              f'REC_INST + REC_CODE + REC_ANCHOR, no reg/mem/seqevent payload)')
    else:
        print(f'  Record:      0x{args.record:02X} '
              f'(NZCV={bool(args.record & QBDITRACE_REC_NZCV)}, '
              f'REGDIFF={bool(args.record & QBDITRACE_REC_REGDIFF)}, '
              f'MEM={bool(args.record & QBDITRACE_REC_MEM)}, '
              f'SVC={bool(args.record & QBDITRACE_REC_SYSCALL)}, '
              f'OBJC={bool(args.record & QBDITRACE_REC_MSGSEND)}, '
              f'CAPI={bool(args.record & QBDITRACE_REC_CAPI)}, '
              f'SEQEVENTS={bool(args.record & QBDITRACE_REC_SEQEVENTS)})')
    extras = []
    if args.sampling:    extras.append('SAMPLING (reconnaissance mode)')
    if args.pc_delta:    extras.append('pc-delta(v5)')
    if args.fpr:         extras.append('fpr(v7)')
    if args.no_compress: extras.append('no-compress')
    else:                extras.append('zstd-compress')
    print(f'  Features:    {" | ".join(extras)}')
    if args.sampling:
        print(f'  Anchor int.: {args.anchor_interval} instructions (sparse — sampling '
              f'mode only needs the PC stream, not exact register state)')
        print(f'  Next steps:  tenet --run-pass loop {args.output}   '
              f'(or --suggest-excludes once available)')
    for i, er in enumerate(args._exclude_ranges):
        print(f'  Exclude[{i}]:  0x{er["start"]:X} - 0x{er["end"]:X} '
              f'(size 0x{er["end"] - er["start"]:X})')
    for i, sr in enumerate(args._snapshot_ranges):
        start = int(sr['start'], 0)
        end = int(sr['end'], 0)
        print(f'  Snapshot[{i}]: 0x{start:X} - 0x{end:X} (size 0x{end - start:X})')
    for i, p in enumerate(args._patches):
        prefix = '+' if p['is_offset'] else ''
        nbytes = len(p['hex']) // 2
        preview = p['hex'][:32] + ('...' if len(p['hex']) > 32 else '')
        print(f'  Patch[{i}]:    {prefix}{p["addr"]} <- {preview} ({nbytes} byte(s))')
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
    if args.trace_threads:
        print(f'  Threads:     ON (filter={not args.threads_no_filter}, max={args.threads_max})')
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
