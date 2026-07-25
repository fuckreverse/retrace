---
title: QBDITrace configuration and arguments
sidebar:
  order: 2
---

## Python loader

The only supported way to run QBDITrace is through `qbditrace_runner.py`. Do **not** load `qbditrace.js` directly with Frida—the agent requires configuration injected via `script.post()`.

```bash
# Trace a function by offset in the main executable
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xEE91EC \
    --output /var/mobile/Documents/trace.bin

# Trace an exported symbol
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry _CCCrypt \
    --output /var/mobile/Documents/cccrypt.bin

# Trace a function inside a specific framework module
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --module SomeFramework \
    --entry 0x1234 \
    --output /var/mobile/Documents/trace.bin
```

## Connection options

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `127.0.0.1:27042` | Frida remote device address |
| `--usb` | off | Use USB connection instead of remote |
| `--android` | off | Use Android default paths; dylib switches to `/data/local/tmp/libqbditrace.so` |

## Target options

| Flag | Default | Description |
|------|---------|-------------|
| `--target` / `-t` | (required) | Bundle ID (spawn) or process name (attach) |
| `--attach` / `-a` | off | Attach to a running process instead of spawning |

## Trace scope

| Flag | Default | Description |
|------|---------|-------------|
| `--module` / `-m` | main executable | Module to trace. All code inside the module is recorded; code outside runs natively |
| `--entry` / `-e` | (required) | Entry point: hex offset (e.g. `0xEE91EC`) or exported symbol name. Trace starts at call, ends at return |
| `--arg-count` | 1 | Number of integer arguments to the entry function (x0–x7, max 8) |
| `--range-size` | auto (full module) | Fallback range size when module resolution fails. Normally not needed |

## Recording controls

| Flag | Default | Description |
|------|---------|-------------|
| `--record` | 127 (all) | Bitmask: 1=NZCV, 2=REGDIFF, 4=MEM, 8=SVC, 16=OBJC, 32=CAPI, 64=SEQEVENTS |
| `--no-objc` | off | Disable ObjC msgSend resolution |
| `--anchor-interval` | 0 (default 1024) | Emit a full register snapshot every N instructions |
| `--ring-bytes` | 0 (default 64 MiB) | Per-thread ring buffer size |
| `--no-embed-code` | off | Disable embedded code table; CFG/loop analysis in Tenet degrades without an external image |
| `--pc-delta` | off | Enable v5 PC-delta encoding: 2-byte signed deltas shrink INST headers by ≈60% |
| `--fpr` | off | Enable v7 FPR/NEON recording: FPR diffs per instruction + 512 B FPR snapshot per anchor |
| `--no-compress` | off | Disable default 1 MiB block zstd compression |
| `--exclude-range` | none | Exclude address ranges (format: `START-END` or `START:SIZE`, hex static offsets). Up to 8 ranges. Code inside excluded ranges runs natively with zero trace overhead |
| `--sampling` | off | **Scout mode**: bare PC stream only (no registers, memory, or sequence events). ≈80%+ size reduction while loop counts and back-edges remain exact. Implies `--pc-delta` and a large anchor interval. See *Scout workflow* below |

## Pre-trace memory patches

| Flag | Default | Description |
|------|---------|-------------|
| `--patch` | none | Write bytes to target process memory before tracing. Format: `ADDR:HEXBYTES` (absolute runtime) or `+OFFSET:HEXBYTES` (module-base offset). May be specified multiple times. Original bytes are restored after the trace completes. Use to clear cache flags, modify branch conditions, etc. |

```bash
# Clear a 4-byte cache flag at module offset +0x1abc
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --patch +0x1abc:00000000 \
    --output /var/mobile/Documents/trace.bin
```

## Invoke mode

| Flag | Default | Description |
|------|---------|-------------|
| `--invoke` | off | Actively call the entry function instead of hooking. Requires `--args` |
| `--args` | none | Typed argument list (up to 8). Syntax: `TYPE:VALUE` |

Supported argument types:

| Type | Syntax | Description | Platform |
|------|--------|-------------|----------|
| `int` | `int:42` or `int:0x1234` | Integer / pointer immediate | All |
| `str` | `str:hello` | UTF-8 C string (auto-allocated, pointer passed) | All |
| `bytes` | `bytes:aabbccdd` | Raw byte buffer from hex (auto-allocated) | All |
| `buf` | `buf:64` or `buf:0x100` | Zero-filled output buffer (specified size); first 64 bytes dumped after call | All |
| `nullptr` | `nullptr` | Null pointer | All |
| `nsstr` | `nsstr:hello` | ObjC `NSString` (auto-created, handle passed) | iOS |
| `nsdata` | `nsdata:aabbccdd` | ObjC `NSData` from hex (auto-created, handle passed) | iOS |
| `nsnum` | `nsnum:42` | ObjC `NSNumber` from integer (auto-created, handle passed) | iOS |
| (bare integer) | `0x1234` or `42` | Parsed as `int` | All |

When `--invoke` is used, `--arg-count` is inferred from `--args` and `--trace-mode` is forced to `once`.

```bash
# Invoke CCCrypt with full typed arguments
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app --attach \
    --entry _CCCrypt \
    --invoke \
    --args "int:0" "int:0" "str:mykey" "int:5" \
           "str:plaintext" "int:9" "buf:64" "buf:8" \
    --output /var/mobile/Documents/cccrypt.bin
```

## Hook mode options

| Flag | Default | Description |
|------|---------|-------------|
| `--trace-mode` | `once` | `once` / `multi` (unlimited) / positive integer N |
| `--no-rehook` | off | Do not reinstall hook in multi-trace mode |

## GCD options (iOS)

| Flag | Default | Description |
|------|---------|-------------|
| `--trace-gcd` | off | Hook GCD dispatcher and synchronously re-invoke discovered block invoke pointers (each in its own trace file). Not a true multi-thread trace |
| `--gcd-no-filter` | off | Trace all blocks regardless of whether invoke is inside the target module |
| `--gcd-max` | 0 (unlimited) | Maximum number of extra block executions to capture |

## Run control

| Flag | Default | Description |
|------|---------|-------------|
| `--timeout` | 0 (unlimited) | Exit after N seconds |
| `--wait-for-done` | off (auto in once mode) | Exit after the trace completes |
| `--output` / `-o` | (required) | Trace file output path on the device |
| `--dylib` | platform default | iOS: `/var/jb/usr/lib/libqbditrace.dylib`; Android: `/data/local/tmp/libqbditrace.so` |

## Scout workflow

Use the two-phase scout workflow to reduce trace size when the target contains large irrelevant loops:

```bash
# Phase 1: run a lightweight scout trace (bare PC stream)
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --sampling \
    --output /var/mobile/Documents/scout.bin

# Phase 2: analyze the scout trace to find dominant loops
./tenet --suggest-excludes /var/mobile/Documents/scout.bin

# Phase 3: run the full trace with exclude ranges confirmed
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --exclude-range 12000-13500 \
    --output /var/mobile/Documents/trace.bin
```

## Troubleshooting

- **No instructions recorded:** verify runtime addresses include the ASLR slide and that the target runs on the VM-controlled thread.
- **Frida cannot connect:** the Python bindings and device service must use matching versions.
- **Trace rejected by Tenet:** check for a valid magic number, a supported format version with consistent layout flags (including rejecting versions older than v4), and a non-corrupt file with complete records.
- **Missing register diffs (`REG_DIFF`):** the trace still opens and indexes normally, but register queries, taint propagation, and other analyses that depend on register state are degraded or unavailable.
- **Missing embedded code table (`HAS_CODE`):** the trace still opens; disassembly-dependent analyses such as CFG and pattern recognition require an external image supplied with `--image`.
- **Missing asynchronous work:** capture the worker entry separately or make the target path synchronous.
- **Crash near the target:** export the 2048-entry PC ring with `qbditrace_dump_pcring` and inspect the last executed addresses.
