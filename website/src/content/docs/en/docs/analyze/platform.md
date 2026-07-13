---
title: ObjC, syscalls and platform API
sidebar:
  order: 6
---

Platform-specific passes translate low-level trace events into high-level API semantics. They answer "which system or framework call occurred, with what arguments, and which high-level method triggered it?"

## Target OS detection and fallback

Tenet reads `target_os` from the trace header (`TraceFormat.h`, offset `0x138`, 4 bytes):

| Value | Meaning |
|---|---|
| 0 | Unknown (legacy traces, written before the field existed) |
| 1 | iOS / Darwin |
| 2 | Android |
| 3 | Linux |

When `target_os = 0`, Tenet falls back to the `module_name` path: `/data/`, `/system/`, or `.so` implies Android; `/var/`, `/private/`, `/Library/`, `.dylib`, or `.app/` implies iOS; otherwise it remains Unknown. This fallback is best-effort.

:::note[Old traces and target_os]
Older qbditrace recordings write `target_os = 0`. `objc` and `objc_crypto` skip explicit Android/Linux targets but continue on Unknown for compatibility; `syscall_intercept` uses compatible tables in Unknown mode. Re-record with a current qbditrace if the heuristic is wrong.
:::

## Objective-C messages

`objc` parses ObjC record kinds from `REC_OBJC` (=5). It extracts, per message send:

- **receiver** (x0 at the `objc_msgSend` call site) — the object the message is sent to;
- **selector** (x1) — the SEL pointer; resolved to a selector string from the binary's selector references or the trace memory;
- **class name** — derived from the receiver's isa pointer (ObjC runtime class lookup via trace memory);
- **arguments** (x2–x7, up to 6) — each arg value is recorded, and when it looks like a userspace pointer, `objc` attempts to dereference it as a C string;
- **return value** (x0 at the next OBJC record or trace end) — also dereferenced as a string when applicable.

Only the four msgSend variants are parsed (`objc_msgSend`, `objc_msgSendSuper`, `objc_msgSendSuper2`, `objc_msgSend_stret`), matching whatever addresses were passed in `qbditrace_config_t` at record time. The `variant` field on `ObjcMessage` distinguishes which variant fired (0 = msgSend, 1 = stret, 2 = super/super2).

`objc` operates only on Darwin targets. On Android and Linux traces the pass returns an empty result immediately.

```bash
./tenet [options] trace.bin --objc
./tenet [options] trace.bin --objc --objc-class NSString
```

`--objc-class <name>` filters output to messages sent to instances of that class. The match is exact on class name.

### ObjC × crypto correlation

`objc_crypto` brings together `pattern` (crypto primitive detections) and `objc` (message-sends that surrounded each detection). For each crypto hit it finds the nearest enclosing ObjC call stack, answering "which user-visible method (e.g. `-[NSURLConnection delegate]` → `-[MyManager connectionDidFinish:]`) triggered this CCCrypt call?"

```bash
./tenet [options] trace.bin --objc --pattern --objc-crypto
```

The pass also highlights cases where a crypto call happens *without* an enclosing ObjC frame — those are usually low-level or C API paths.

## System calls and C API intercepts

`syscall_intercept` reconstructs high-level API calls from three data sources, used in strict priority order:

| Priority | Source | Precision | Notes |
|---|---|---|---|
| 1 | `REC_CAPICALL` | Highest | Tracer-side resolved: symbol name, arguments, and inline string captures. Requires `enable_capi_intercept` at record time |
| 2 | `REC_SVC` | Medium | Raw syscall number + arguments. Classified by platform syscall table |
| 3 | `XFER_CALL` heuristic | Lowest | Cross-module call/return pairs (`REC_EVENT` records marking exits and re-entries). No symbol; may misattribute |

### Data sources in detail

**`REC_CAPICALL`** is emitted when `qbditrace_config_t::enable_capi_intercept` is set and explicit `capi_funcs[]` entries (or auto-resolved dlsym entries for native, Frida-supplied entries for JNI) are matched. Each record carries:
- runtime target address;
- `api_id` (index into the known-API table);
- argument values (up to 8);
- `str_args` bitmask indicating which arguments are known string pointers — the tracer captures those inline so tenet does not need to reconstruct memory for them.

This is the gold standard: symbol name, typed arguments, and dereferenced strings all arrive pre-packaged.

**`REC_SVC`** (syscall records) capture supervisor-call events. On Darwin these include `mach_msg`, `mach_vm_map`, `read`, `write`, etc.; on Linux/Android `ioctl`, `mmap`, `mprotect` and so on. Tenet classifies each syscall using the `target_os`-selected table.

**`XFER_CALL` heuristic** works on `REC_EVENT` records marking cross-module exits and re-entries. When the traced code transfers execution outside the instrumented range and comes back, tenet reconstructs a synthetic call. No symbol resolution is available, so calls are labeled by the target PC.

### Intercepted API tables

| Platform | APIs classified |
|---|---|
| Darwin (iOS) | **CommonCrypto:** `CCCrypt`, `CCCryptorCreate`, `CCCryptorCreateWithMode`, `CCHmac`, digest/PBKDF families  **Security.framework:** `SecKeyCreateSignature`, `SecKeyRawSign`, `SecKeyRawVerify`, `SecKeyEncrypt`, `SecKeyDecrypt`, `SecKeyCreateWithData`  **BoringSSL / OpenSSL:** EVP cipher and digest families |
| Android | **BoringSSL:** same EVP/SSL surface as above  **JNI:** `RegisterNatives`, `FindClass`, `CallVoidMethod`, `GetMethodID`, etc. |
| Linux | **OpenSSL:** EVP_* and friends  **Syscall-level:** `mmap`, `mprotect`, `write`, `open`, `ioctl`, etc. (from `REC_SVC` where present) |
| Unknown | Heuristic — tries both iOS and Android tables; quality depends on which modules appear in the trace |

```bash
./tenet [options] trace.bin --syscall-intercept
./tenet [options] trace.bin --syscall-intercept --syscall-intercept-bytes 128
```

`--syscall-intercept-bytes <N>` controls how many bytes are read per pointer argument (default 64). Larger values capture more of long buffers at the cost of memory and processing time.

### How to read platform-API results

Each intercepted call reports:
- the API name and category;
- all argument values, with pointer arguments dereferenced to strings (where feasible);
- the call site PC and inst_id;
- the return value;
- the source (`REC_CAPICALL` / `REC_SVC` / `XFER_CALL`) used to resolve it.

When multiple sources cover the same underlying call, only the highest-priority source produces output — tenet does not duplicate across sources.

## Real interface surfaces

### CLI (batch mode)

Every pass above has both a CLI flag and a `--run-pass` name, so you can drive them from scripts:

```bash
./tenet [options] trace.bin --objc --objc-class NSString
./tenet [options] trace.bin --objc --pattern --objc-crypto
./tenet [options] trace.bin --syscall-intercept --syscall-intercept-bytes 128

# Equivalent via generic runner
./tenet [options] trace.bin --run-pass objc
./tenet [options] trace.bin --run-pass objc_crypto
./tenet [options] trace.bin --run-pass syscall_intercept
```

Batch mode (`-c`, or an analysis/query option that selects non-interactive execution) writes JSON to stdout.

### GUI

`--objc` and `--syscall-intercept` both register panels in the GUI's **Platform** group after the pass runs. ObjC results show per-class message frequency; syscall results show per-API frequency. Filtering by class (`--objc-class`) narrows the GUI table.

### TUI

The same flags work with `--tui`. The TUI shows the ObjC message table and syscall intercept table as browsable lists.

### MCP

MCP exposes `objc_messages`, `syscall_intercept`, and `objc_crypto`. `objc_messages` uses exact class matching and selector substring matching; `syscall_intercept` uses `capture_bytes` for capture size. See the [MCP tool catalog](/en/docs/automate/mcp/#tool-catalog) for exact response and pagination fields.

## Platform limitations

| Feature | iOS / Darwin | Android | Linux | Unknown |
|---|---|---|---|---|
| ObjC messages | Full | Skipped | Skipped | Continue best-effort (old iOS compatibility) |
| CommonCrypto / Security / CryptoKit | Classification only (needs `REC_CAPICALL`) | N/A | N/A | Heuristic |
| Encryption primitive detection | Pattern-based (`pattern` pass) | Pattern-based | Pattern-based | Pattern-based |
| Cross-source correlation (`objc_crypto`) | Works | N/A | N/A | N/A |

**Recording prerequisites:**
- ObjC: the trace must contain `REC_OBJC` records (set `record |= QBDITRACE_REC_MSGSEND` at record time; configure `objc_msgSend` addresses in `qbditrace_config_t`);
- `REC_CAPICALL`: set `enable_capi_intercept = 1` with `n_capi_funcs > 0` (or rely on native dlsym auto-resolve); without it, only `REC_SVC` and `XFER_CALL` are available;
- `REC_SVC`: default enabled in `QBDITRACE_REC_DEFAULT` (127); explicitly disable via `record &= ~QBDITRACE_REC_SYSCALL` to reduce trace size.

## Recommended workflow

1. **Inspect platform origin** — open the trace in GUI or run `--stats` first to confirm `target_os`, module name, and record flags.
2. **For iOS traces** — run `--objc` to map user-visible behavior, then `--pattern` to find crypto primitives; combine with `--objc-crypto` to link each primitive to the ObjC method that triggered it.
3. **For crypto material** — `--syscall-intercept` recovers keys, IVs, and plaintext buffers from CommonCrypto / BoringSSL / JNI calls. Increase `--syscall-intercept-bytes` if buffers exceed 64 B.
4. **For classification confidence** — if the trace has no `REC_CAPICALL`, results rely on `REC_SVC` + `XFER_CALL`, which may misattribute or miss calls; note the source field in results.

## Troubleshooting

### `objc` returns no messages

- Explicit Android/Linux targets are skipped; Unknown continues best-effort parsing. Re-record with a current qbditrace if an old trace's `module_name` heuristic is unreliable.
- Confirm the trace contains `REC_OBJC` records — if `record` was set without `QBDITRACE_REC_MSGSEND`, ObjC records are never emitted.
- Confirm `objc_msgSend` (and its super/stret variants) were provided in `qbditrace_config_t`; tenet's pass only parses those four symbols.

### `syscall_intercept` finds no API calls

- The trace may lack `REC_CAPICALL` and `REC_SVC`. Check `record` in the trace header.
- `enable_capi_intercept` may not have been enabled at record time; without it, only syscall-level interception works.
- On Unknown-target traces, the API table may not match — re-record with correct `target_os`.

### Results differ between CLI and GUI

They should not; both use the same pass pipeline. If output discrepancies appear, confirm the GUI hasn't loaded a cached pass result from a previous run with different parameters — clear via `--cache-delete`.
