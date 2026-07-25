---
title: Analyze a trace
sidebar:
  order: 1
---

Tenet's terminal TUI, batch CLI, MCP services, and separate Tauri frontend share the same core, passes, and result cache. This page orients you to the full analysis surface, helps you pick a starting chapter by problem type, and lays out a recommended investigation order.

## Analysis capability map

| Area | What you can do | Primary tools |
|---|---|---|
| Structure | Recover functions, CFG, XRefs, loops, call graph | `function`, `xref`, `cfg`, `loop`, `call_graph`, `cfg_layout` |
| Taint & data flow | Forward/backward taint, critical path, data-flow graph | `taint`, `backward_taint`, `taint_source_annotation`, `dataflow_graph` |
| Memory & strings | Snapshots, value search, entropy, YARA, string discovery | `memory_snapshot`, `memory_strings`, `mem_search`, `entropy`, `yara_mem_scan`, `strings` |
| Algorithms & patterns | Pattern scan, materialized constants, loop semantics, algorithm summary | `pattern`, `loop_semantics`, `algorithm_summary` |
| Platform API | ObjC messages, system calls, C API intercepts (CommonCrypto / BoringSSL / JNI) | `objc`, `syscall_intercept`, `objc_crypto` |
| Trace comparison | Fold repeated iterations, diff regions, window statistics, register timelines | `trace_fold`, `trace_diff`, `window_stats`, `reg_timeline`, `call_context` |
| VM analysis | Handler identification, dispatch recovery, state mapping, backward slice | `vm_abstract` + MCP `vm_summary` / `vm_steps_query` / `vm_reg_timeline` / `vm_backward_slice` |

Every MCP tool is listed in the [MCP server guide](/en/docs/automate/mcp/#tool-catalog); every pass with its CLI flag is listed in the [Pass catalog](/en/docs/reference/pass-catalog/).

## Choose by problem

Start with the chapter that matches your question:

| I want to… | Start here |
|---|---|
| Identify the interesting functions / understand the overall flow | [Recover program structure](./structure/) |
| Trace a key value backward to its source, or forward to its sinks | [Taint and data flow](./taint/) |
| Find strings, structures, or encryption material in memory | [Memory, strings and value search](./memory/) |
| Determine which algorithm a loopnest implements | [Algorithm and pattern recognition](./algorithms/) |
| Inspect ObjC messages, system calls, or boundary API inputs/outputs | [ObjC, syscalls and platform API](./platform/) |
| Compare two recordings or summarize a hot loop | [Trace tools](./trace-tools/) |
| Analyze VMP-style virtualized code | [Virtual machine analysis](./vmp/) |

## Recommended investigation order

A trace is a flat instruction stream; analysis builds a hierarchy of views on top of it. Work from cheap and global toward expensive and precise:

```
1.  trace_info / structure        → functions, CFG, XRef, loops
2.  taint / dataflow              → forward taint, backward taint, critical path
3.  memory / strings              → snapshots, value search, entropy, YARA
4.  algorithms / patterns         → pattern scan, constants, loop_semantics, algorithm_summary
5.  platform API                  → objc, syscall_intercept, objc_crypto
6.  trace comparison              → trace_fold, trace_diff, window_stats, reg_timeline
7.  VM analysis                   → vm_abstract (requires static hints from IDA/Ghidra)
```

This order is a recommendation, not a constraint. Each step is independent and can be re-run in any order, but results compound: for example `algorithm_summary` cross-references `pattern` and `loop_semantics`, so it should run after both.

## Evidence hierarchy

Tenet analyses produce results at different confidence levels. Treat them accordingly when making conclusions:

| Level | Kind of claim | Typical sources |
|---|---|---|
| Recorded fact | Directly observed in the trace | GPR/FPR snapshots, memory accesses, instructions executed, PCs |
| Reconstructed state | Derived by replaying recorded writes | `RegisterFile` at any `inst_id`, `MemoryModel` write history, `get_regs`, `memread` |
| Structural inference | Inferred from execution structure | Functions, CFG, loops, XRef, VM handler segmentation, call graph |
| Candidate explanation | Heuristic synthesis from multiple signals | `algorithm_summary`, `loop_semantics` labels, `pattern` signatures |

Do not treat a candidate explanation as a recorded fact. Use `verify_evidence` (MCP) or re-inspect the relevant `inst_id` / register timeline to upgrade a hypothesis into verified evidence.

## Entry point selection

| Entry | Start with | Best for |
|---|---|---|
| Tauri desktop application | The app launches a `tenet --ws-port <port> <trace> --mcp-hub` sidecar | Graphical exploration and structure/analysis panels |
| TUI | `./tenet trace.bin` | Default interactive entry; terminal-only, keyboard-driven inspection |
| CLI | `./tenet --taint 0 trace.bin` (or `--pattern`, `--call-graph`, `--export-cfg`, …) | One-shot batch analysis from scripts or CI |
| MCP | `./tenet trace.bin --mcp` or `--mcp-hub` | Agent-driven, IDE-integrated, or multi-trace workflows |

These entry points share the same reader, index, pass pipeline, and persisted result cache. The Tauri application connects to a pure-backend `tenet` sidecar over WebSocket/MCP; the `tenet` executable does not contain a graphical interface.

## Minimal quick flow

```bash
# 1. Verify the trace is readable
tenet --dump text trace.bin --limit 100

# 2. Open interactively and let default passes run
./tenet trace.bin                         # opens the terminal TUI by default

# 3. Run one-shot CLI analyses
./tenet --pattern trace.bin
./tenet --algorithm-summary trace.bin
./tenet --call-graph cg.dot trace.bin
./tenet --export-cfg func.dot trace.bin

# 4. Run targeted taint from x0
./tenet --taint 0 trace.bin
# or backward-taint register x4 (register index 4) at inst_id 1200:
./tenet --backward-taint 1200 4 trace.bin
```

`tenet --dump` supports v4/v5/v7 (including block-compressed traces); no separate build is needed.

## Prerequisites

### Recording quality check

| Check | Why it matters | What to look for |
|---|---|---|
| Format version | Tenet requires `version >= 4` | `trace_info` shows version; older formats are rejected |
| Code embedding | Analyses needing disassembly degrade without it | Check header flag `HAS_CODE`; without recorded code, instruction-semantic analyses may be unavailable or less precise |
| GPR / MEM diffs | Without register or memory diffs, state reconstruction loses precision | Sampling traces may omit `REG_DIFF`, `HAS_MEM`, or `HAS_NZCV`; treat resulting evidence as intentionally sparse |
| Block compression | Default recording uses 1 MiB zstd chunks | `tenet --dump` and all tenet analysis modes support compressed traces (v4/v5/v7) |
| Address consistency | Trace records runtime addresses with the ASLR slide | CLI address conventions vary by command; MCP rebases PC parameters through `image_base` and `module_slide`, while memory-address fields such as VM `mem_anchor_addr` remain runtime addresses |

### Optional dependencies

| Feature | Depends on | Enabled when |
|---|---|---|
| Triton-backed taint semantics | Triton | `TENET_ENABLE_TRITON=ON`; otherwise taint tools use their heuristic fallback |
| YARA memory scan (`yara_mem_scan`) | libyara | `TENET_ENABLE_YARA=ON` at build time |
| Tauri desktop application | Tauri / Web frontend toolchain | Built separately under `tools/tenet/web/` |
| Trace compression (modern default) | zstd | `QBDITRACE_ENABLE_ZSTD=ON` in qbditrace |
| Parallel indexing / task scheduling | Intel oneTBB | `TENET_ENABLE_TBB=ON`, default on |

A build without Triton or YARA still supports structural and most other analyses, but tools that explicitly depend on those libraries are unavailable or reduced according to the current build.

## What's next

Each chapter below drills into one analysis area with its concepts, entry points, and troubleshooting:

| Chapter | Cross-link |
|---|---|
| [Recover program structure](./structure/) | `function`, `xref`, `cfg`, `loop`, `call_graph` |
| [Taint and data flow](./taint/) | `taint`, `backward_taint`, `taint_source_annotation`, `dataflow_graph` |
| [Memory, strings and value search](./memory/) | `mem_search`, `memory_strings`, `memory_snapshot`, `entropy`, `yara_mem_scan` |
| [Algorithm and pattern recognition](./algorithms/) | `pattern`, `loop_semantics`, `algorithm_summary` |
| [ObjC, syscalls and platform API](./platform/) | `objc`, `syscall_intercept`, `objc_crypto` |
| [Trace tools](./trace-tools/) | `trace_fold`, `trace_diff`, `window_stats`, `reg_timeline` |
| [Virtual machine analysis](./vmp/) | `vm_abstract` + MCP VM tools |

For the complete pass list with CLI flags and a dependency graph, see the [Pass catalog](/en/docs/reference/pass-catalog/). For all MCP tools, see the [MCP server guide](/en/docs/automate/mcp/).
