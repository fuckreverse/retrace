---
title: Compatibility and limits
sidebar:
  order: 2
---

Tenet degrades gracefully when trace evidence is incomplete. This page documents what each capability requires and how it behaves when evidence is missing.

## Format version requirements

| Version | Flags | Required for |
|---|---|---|
| v4 | Baseline | All features |
| v5 | `HF_PC_DELTA` | Reduced file size (pc_delta mode); Tenet auto-detects |
| v7 | `HF_HAS_FPR` | FPR (NEON v0-v31) reconstruction |
| v8 | `HF_CALL_META` (required; may combine with `HF_PC_DELTA` / `HF_HAS_FPR`) | Call metadata: true return values (`REC_RETVAL`), inline selectors, and wider API IDs |
| v6 | `HF_OLD_VALUE` | Pre-write memory values (writer removed; no current trace produces this) |

Tenet opens any trace with version ≥ 4.

## Evidence requirements by capability

### Timeline and navigation

| Evidence | Required | Degradation when missing |
|---|---|---|
| PC stream | Yes | Cannot open |
| `inst_id` sequence | Yes | Cannot navigate |
| GPR anchors/diffs | For register queries | Registers always show 0 |
| Memory accesses | For memory history | Memory reads return unknown |
| Embedded code (`HF_HAS_CODE`) | For disassembly | Need `--image` fallback |
| Branch hints (`HF_BRANCH_HINT`) | For call/return classification | Heuristic classification only |

### Structure recovery

| Evidence | Required | Degradation when missing |
|---|---|---|
| Embedded code or external image | Yes | No CFG, no loop detection |
| Branch hints or events | For call/return | Function pass heuristic only |
| GPR diffs | For SP-based stack walk | Call stack may be incomplete |

### Taint and data flow

| Evidence | Required | Degradation when missing |
|---|---|---|
| GPR anchors/diffs | Yes | No taint propagation |
| Memory accesses | For memory taint | Memory propagation disabled |
| Triton (optional) | For precise semantics | Fallback semantics only |

### Memory and strings

| Evidence | Required | Degradation when missing |
|---|---|---|
| Memory accesses (writes) | Yes | No memory reconstruction |
| Memory accesses (reads) | For uninstrumented data | Unknown bytes for unread pages |
| Embedded code or image | For string scanning | Stack/heap only |

### Platform API

| Evidence | Required | Degradation when missing |
|---|---|---|
| `REC_CAPICALL` records | Best quality | Heuristic fallback |
| `REC_SVC` records | For syscall intercept; Darwin BSD syscalls, negative Mach traps, and readable sent Mach-message headers can be classified | No syscall data; unavailable or unreadable message headers remain trap-level results |
| `REC_OBJC` records | For ObjC messages | No ObjC analysis |
| `REC_RETVAL` records | For true return values | Returns reported as unknown; legacy v4-v7 traces have no such records |
| Darwin target | For ObjC / CryptoKit | Skipped on Android/Linux |

### Algorithm and pattern

| Evidence | Required | Degradation when missing |
|---|---|---|
| Embedded code or image | Yes | No pattern or constant detection |
| Loop structure | For loop semantics | No loop classification |
| Call graph | For algorithm summary | No cross-referencing |
| Platform API | For `objc_crypto` | No ObjC correlation |
| Static-analysis VM hints + loop structure/CFG/xref | For `vm_abstract` | No VM execution abstraction; the pass does not discover dispatchers automatically |

## Trace capture target platform support

Here, platform means the instrumented target process recorded in `target_os`, not the host OS that runs the `tenet` backend.

| Platform | ObjC | API intercepts | FPR | Notes |
|---|---|---|---|---|
| iOS (Darwin) | Full | CommonCrypto, Security, CryptoKit, BoringSSL | v7 | Full capability |
| Android | Skipped | BoringSSL, JNI | v7 | No ObjC |
| Linux | Skipped | OpenSSL, syscalls | v7 | No ObjC |
| Unknown | Heuristic | Heuristic from module name | — | Reduced precision |

## Tenet backend host platforms

The pure-backend `tenet` executable targets Windows, Linux, and macOS on x86_64 and arm64. This is independent of the trace capture target dimension above: traces captured on iOS, Android, or Linux are offline files and can be analyzed on any supported host through the CLI, TUI, TCP-loopback RPC, or MCP.

WebSocket service is enabled by default on macOS and Linux. On Windows, uSockets has no IOCP backend wired into the current build, so `TENET_ENABLE_WS` defaults to `OFF` and enabling it is currently unsupported. Consequently, the standalone Tauri desktop/Web frontend cannot yet connect to a Windows backend over FlatBuffers WebSocket. This does not affect offline CLI/TUI/RPC/MCP analysis on the Windows backend.

## Sampling traces

Sampling traces (where `REG_DIFF`, `HAS_MEM` or `HAS_NZCV` sampling flags are set) contain only partial evidence. Capabilities degrade accordingly:

- Reduced GPR diffs → fewer taint propagation steps, less precise register state.
- Missing memory accesses → no memory reconstruction, no memory taint.
- Missing code → need `--image` for any disassembly-dependent feature.

Tenet opens and indexes sampling traces; analysis passes report which evidence categories are available and limit their results accordingly.

## Single-thread assumption

Tenet currently assumes single-thread traces. `THREAD` records are parsed but do not partition the timeline. Multi-thread traces open with a warning; analysis applies to the interleaved instruction stream. Use `thread_filter` to isolate a single thread's instructions if needed.
