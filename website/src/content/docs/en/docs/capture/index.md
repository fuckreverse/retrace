---
title: Capture
sidebar:
  order: 1
---

Tenet consumes traces that conform to the [binary trace format](/en/docs/reference/). Any tool that emits a compliant `.bin` file can feed the analysis pipeline.

## Official capture: QBDITrace

QBDITrace is the reference capture engine for iOS and Android AArch64. It runs inside the target process and writes a compact binary stream while expensive disassembly, symbol work, and analysis remain offline.

### iOS

```bash
bash dashcam/build-dashcam-ios.sh
ldid -S dashcam/build-ios/libqbditrace.dylib
scp -P 2222 dashcam/build-ios/libqbditrace.dylib root@localhost:/var/jb/usr/lib/
```

### Android

```bash
export NDK_PATH=/path/to/android-ndk
bash dashcam/build-dashcam-android.sh
adb push dashcam/build-android/libqbditrace.so /data/local/tmp/
```

### Hook and Invoke modes

**Hook mode** waits for the application to invoke the target naturally—use it for paths that depend on application state. **Invoke mode** constructs typed arguments and calls the target through `qbditrace_run_call`—use it for repeatable isolated calls.

### What QBDITrace records

| Category | Details |
|----------|---------|
| Instructions | Per-instruction PC, NZCV flags, and written-register diffs (absolute values) |
| Memory | Load/store addresses, sizes, and values—including 9–16 byte wide stores |
| Embedded code | Raw bytes of each distinct executed instruction (deduplicated), so offline disassembly needs no external image |
| ObjC dispatch | `objc_msgSend` family: receiver, selector, and runtime class name captured at the call site |
| System calls | `svc` instruction sites with syscall number and arguments |
| C API calls | Interception of `memcpy`, `strcmp`, `strlen`, CommonCrypto, BoringSSL, JNI, etc. with argument snapshots and string captures |
| Cross-boundary transfers | Call-site PC and target address when execution leaves or re-enters the instrumented module |
| FPR / NEON (v7) | 128-bit vector register diffs and anchor snapshots (opt-in) |

### Design highlights

- **Module-level tracing**: the entire executable segment of the target module is instrumented; code outside the module runs natively and generates only transfer events.
- **Anchor + diff reconstruction**: periodic full-register anchors let the decoder rebuild exact state at any instruction; the rest of the stream stores only what changed.
- **Fault-tolerant memory reads**: `vm_read_overwrite` is used to safely probe store values, ObjC class names, and embedded code bytes—bad addresses return errors instead of crashing.
- **arm64e pointer authentication**: QBDI bypasses PAC so `braa`/`blraa` indirect jumps (including `objc_msgSend` tail calls) are traced correctly.
- **ARC-safe return address**: a dedicated RX page replaces QBDI's default fake return value so `objc_autoreleaseReturnValue` probes do not fault.
- **1 MiB block compression** with a tail index for random access; PC-delta encoding (v5) shrinks INST headers from 16 to 6 bytes.
- **Crash PC ring**: a 2048-entry ring buffer always captures the last executed PCs; on SIGSEGV/SIGBUS the fault handler dumps them automatically, or call `qbditrace_dump_pcring` from a Frida exception handler.

### Threading and GCD

A QBDI VM controls only the calling thread. Work moved to other threads is captured two ways:

- **Android — `--trace-threads`:** intercepts `pthread_create` and redirects each child thread whose start routine lives in the traced module into `qbditrace_run_thread()`, which runs the routine inside the child's own QBDI VM. All threads record into the **same trace file**, interleaved and separated by `THREAD` markers — a true multi-thread trace. Tenet partitions it per thread (`--run-pass thread`, `--thread-filter`).
- **iOS — `--trace-gcd`:** hooks the GCD dispatcher and synchronously re-invokes discovered block invoke pointers—each in its own trace file. This is **not** a true multi-thread trace: blocks execute an extra time on the calling thread, so side-effectful or queue-dependent blocks may behave differently. Prefer serializing capture whenever possible.

## Custom collectors

Tenet does not require QBDITrace. Any runtime that can emit the binary trace format can serve as a capture source. Common alternatives:

- **Frida Stalker**: instrument a thread with `Stalker.follow` and write `REC_INST` + `REC_ANCHOR` + `REC_CODE` records.
- **Other DBI frameworks**: DynamoRIO, Pin, or custom engines that produce compliant `.bin` files.
- **Emulators**: Unicorn or QEMU instrumented to log per-instruction state into the format.
- **Static analysis output**: synthetic traces for test and validation purposes.

The minimum requirement for Tenet to open a trace is: valid `QBDT` magic, version ≥ 4, and a complete per-instruction PC stream. See the [compatibility tiers](/en/docs/reference/#compatibility-tiers) for how additional record types unlock richer analysis.

### Choosing what to emit

| Tier | Required records | Unlocked analysis |
|------|-----------------|-------------------|
| **Minimum** | `REC_INST` (PC only), `REC_ANCHOR` | Basic instruction listing, address normalization |
| **Structure** | + `REC_CODE`, branch hints, `REC_EVENT` (XFER_CALL/RETURN) | CFG recovery, function boundaries, call graphs, loop detection |
| **State** | + GPR diffs, `REC_INST` NZCV, memory accesses | Register reconstruction, memory model, taint analysis, data-flow slices |
| **Platform** | + `REC_SVC`, `REC_OBJC`, `REC_CAPICALL` | Syscall naming, ObjC message resolution, C API argument capture |
| **Vector** | + `REC_INST` FPR diffs, `REC_ANCHOR` FPR snapshots (v7) | NEON/vector register reconstruction, crypto algorithm identification |

Missing records degrade gracefully: Tenet opens the trace and runs the passes whose inputs are present.
