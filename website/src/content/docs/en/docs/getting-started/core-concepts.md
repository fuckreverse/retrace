---
title: Core concepts
sidebar:
  order: 4
---

Tenet turns one recorded execution into a local database that can be navigated and queried repeatedly. It explains **what happened in this run**; it does not enumerate paths that were never executed.

## The instruction timeline

Every executed instruction receives a monotonically increasing `inst_id`. A PC may occur many times, while an `inst_id` identifies one exact occurrence. Use PCs to discuss code locations and instruction IDs to discuss time.

All addresses in a trace are runtime addresses. Convert them for a static image with:

```text
static_address = runtime_address - module_slide
```

## State before and after

`state_before(N)` describes registers immediately before instruction N. `state_after(N)` applies its recorded diffs. Tenet reconstructs state from periodic full-register anchors plus instruction diffs, then builds dense in-memory checkpoints at open time so random queries replay only a short window.

## Time-aware memory

Tenet does not expose only a final memory dump. It indexes writes by address and instruction ID, then reconstructs a region at a chosen point in time. A write at N becomes visible after N executes. Recorded reads can also recover values prepared by uninstrumented code.

Unknown bytes remain unknown (`??`); Tenet does not invent missing data.

## Executed structure

Functions, XRefs, CFG edges, calls and loops are derived from observed execution. This handles indirect branches, runtime dispatch and decrypted code well, but an absent edge means “not observed,” not “impossible.”

## Analysis passes

Each analysis is an independent pass with declared dependencies and a cacheable result. The standalone Tauri desktop application calls the Tenet backend over WebSocket and uses the same pass implementations as the TUI, CLI, RPC, and MCP interfaces. Multiple scan-oriented passes can share one trace traversal.

## Capability follows evidence

| Trace evidence | Available capability |
|---|---|
| PC stream | Timeline, counts, basic XRefs |
| Embedded code or external image | Disassembly, CFG, branch classification |
| GPR diffs and anchors | Register state, taint and data flow |
| Memory accesses | Time-aware memory, strings, write history |
| Events and branch hints | Calls, returns, functions and loops |
| SVC / ObjC / C API records | Platform-level semantics |
| FPR diffs (v7) | NEON/vector reconstruction |

See [Compatibility and limits](/en/docs/reference/compatibility/) for precise degradation rules.
