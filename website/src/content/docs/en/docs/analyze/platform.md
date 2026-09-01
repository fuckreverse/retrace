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
- **selector** (x1) — v8 captures the `sel_getName` result inline (`selector_source=inline`); older traces fall back through image and trace-memory resolution, then show hex. `selector_resolution` reports `resolved`, `truncated`, `read_failed`, or `unresolved`;
- **class name** — derived from the receiver's isa pointer (ObjC runtime class lookup via trace memory); `class_resolution` reports the same status, and unavailable classes are explicitly `unknown`;
- **arguments** (x2–x7, up to 6) — each arg value is recorded, and when it looks like a userspace pointer, `objc` attempts to dereference it as a C string;
- **return value** — v8 `REC_RETVAL` captures the actual return-time x0/x1/NZCV and associates it with the call by site/target/source ID. v4–v7 have no return fact, so show `return=unknown` rather than inferring a later x0. `objc_msgSend_stret` is marked `stret raw`: x0 is the hidden result buffer, not an ordinary scalar return.

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
- `api_id` (index into the known-API table; `uint16_t` in v8, so BoringSSL 600+ and JNI 700+ IDs are preserved);
- argument values (up to 8);
- `str_args` bitmask indicating which arguments are known string pointers — the tracer captures those inline so tenet does not need to reconstruct memory for them.

This is the gold standard: symbol name, typed arguments, and dereferenced strings all arrive pre-packaged.

**`REC_SVC`** (syscall records) capture supervisor-call events and v8 flags. On Darwin these include `mach_msg`, `mach_vm_map`, `read`, `write`, etc.; on Linux/Android `ioctl`, `mmap`, `mprotect` and so on. Tenet selects the table by `target_os`; Darwin class prefixes are normalized for naming while the raw number remains available.

#### Darwin Mach traps

For Darwin SVCs with a negative `x16`, `syscall_intercept` uses the Mach-trap table rather than the BSD syscall table (for example, `thread_self_trap`, `task_for_pid`, `iokit_user_client_trap`, and `mach_vm_protect`). Unmapped traps remain visible as `mach_trap_N`; positive BSD syscall and class-prefix handling is unchanged.

For sent `mach_msg_trap`, `mach_msg_overwrite_trap`, and `mach_msg2_trap` requests, Tenet reads `msgh_id` from offset 20 of a readable Mach message header and resolves common MIG routines (Mach VM, task, thread, host, port, VM map, and clock families). A resolved call is summarized as `mach_vm_protect via mach_msg_trap(msgh_id=0x12c2)` and JSON additionally exposes `mach_msgh_id` and `mach_msg_via`. Unknown routine IDs, receive-only messages, and unreadable headers gracefully fall back to the trap-level result.

For `REC_CAPICALL`, `REC_SVC`, and ObjC, v8 `REC_RETVAL` supplies the actual x0/x1/NZCV at return time and links it precisely by site/target/source ID. A syscall failure is derived from Darwin NZCV carry (bit 29) or Linux x0 in `[-4095,-1]`; native SVC does not treat environment TLS `errno` as valid. Opaque objects such as `SecKeyRef` remain opaque rather than being decoded as key bytes.

**`XFER_CALL` heuristic** works on `REC_EVENT` records marking cross-module exits and re-entries. When the traced code transfers execution outside the instrumented range and comes back, tenet reconstructs a synthetic call. No symbol resolution is available, so calls are labeled by the target PC.

### Intercepted API tables

| Platform | APIs classified |
|---|---|
| Darwin (iOS) | **CommonCrypto:** `CCCrypt`, `CCCryptorCreate`, `CCCryptorCreateWithMode`, `CCHmac`, digest/PBKDF families  **Security.framework:** `SecKeyCreateSignature`, `SecKeyRawSign`, `SecKeyRawVerify`, `SecKeyEncrypt`, `SecKeyDecrypt`, `SecKeyCreateWithData`  **BoringSSL / OpenSSL:** EVP cipher and digest families |
| Android | **BoringSSL:** same EVP/SSL surface as above, plus `RAND_bytes`  **SQLite:** `sqlite3_open`/`sqlite3_exec`/`sqlite3_close` etc.  **liblog:** `__android_log_print`, `__android_log_write`  **JNI:** the full `JNINativeInterface_` vtable is read at capture time (`RegisterNatives`, `FindClass`, `GetMethodID`, `CallVoidMethod`, `GetStringUTFChars`, … — 112 function pointers), so calls through the JNIEnv vtable are classified too |
| Linux | **OpenSSL:** EVP_* and friends  **Syscall-level:** `mmap`, `mprotect`, `write`, `open`, `ioctl`, `socket`, `getrandom`, etc. (from `REC_SVC` where present; inline `svc` instructions get names from the Linux syscall table) |
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
- the return value — the return-time `REC_RETVAL` fact on v8; `unknown` on v4–v7, which contain no return fact;
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

### Tauri frontend

The Tauri frontend requests the same backend pass pipeline over WebSocket and presents ObjC and syscall results in its Platform group. ObjC results show per-class message frequency; syscall results show per-API frequency.

### TUI

Running `./tenet trace.bin` directly opens the TUI. Supplying analysis options such as `--objc` or `--syscall-intercept` selects non-interactive batch mode and writes JSON to stdout instead of opening the TUI.

### MCP

MCP exposes `objc_messages`, `syscall_intercept`, and `objc_crypto`. `objc_messages` uses exact class matching and selector substring matching; `syscall_intercept` uses `capture_bytes` for capture size. See the [MCP tool catalog](/en/docs/automate/mcp/#tool-catalog) for exact response and pagination fields.

## Platform limitations

| Feature | iOS / Darwin | Android | Linux | Unknown |
|---|---|---|---|---|
| ObjC messages | Full | Skipped | Skipped | Continue best-effort (old iOS compatibility) |
| CommonCrypto / Security / CryptoKit | Classification only (needs `REC_CAPICALL`) | N/A | N/A | Heuristic |
| Encryption primitive detection | Pattern-based (`pattern` pass) | Pattern-based | Pattern-based | Pattern-based |
| Cross-source correlation (`objc_crypto`) | Works | N/A | N/A | N/A |
| Exact platform-call returns | v8 `REC_RETVAL`; older traces `unknown` | v8 `REC_RETVAL`; older traces `unknown` | v8 `REC_RETVAL`; older traces `unknown` | Depends on trace version |

**Recording prerequisites:**
- ObjC: the trace must contain `REC_OBJC` records (set `record |= QBDITRACE_REC_MSGSEND` at record time; configure `objc_msgSend` addresses in `qbditrace_config_t`);
- `REC_CAPICALL`: set `enable_capi_intercept = 1` with `n_capi_funcs > 0` (or rely on native dlsym auto-resolve); without it, only `REC_SVC` and `XFER_CALL` are available;
- `REC_SVC`: default enabled in `QBDITRACE_REC_DEFAULT` (127); explicitly disable via `record &= ~QBDITRACE_REC_SYSCALL` to reduce trace size;
- Exact ObjC/C API/SVC returns, inline ObjC selectors, and 16-bit C API IDs require a v8 trace with `HF_CALL_META` and `REC_RETVAL`; v4–v7 remain readable but have no return facts.

## Recommended workflow

1. **Inspect platform origin** — open the trace in the Tauri desktop application or run `--stats` first to confirm `target_os`, module name, and record flags.
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

### Return value is `unknown`

- The trace is v4–v7 or otherwise lacks v8 `REC_RETVAL`; it contains no trustworthy return-time fact. Re-record with a v8 `HF_CALL_META` trace. Tenet deliberately does not infer a return from a later record's x0.

### Results differ between CLI and the Tauri frontend

Both obtain results through the same backend pass pipeline and persisted cache, so identical parameters should agree. If output discrepancies appear, confirm the Tauri sidecar has not loaded a cache produced with different parameters; clear it with `--cache-delete <pass|all>` and rerun.
