---
title: Pass catalog
sidebar:
  order: 1
---

Every analysis in Tenet is a pass. This page lists all passes in the catalog, grouped by category. Default-on passes run when the Tauri Web frontend asks the backend to run the default pass set, or when analysis is started in the TUI; others are started on demand.

## Structure

| Pass | CLI flag | Default | Summary |
|---|---|---|---|
| `function` | `--run-pass function` | Yes | Discover call/return pairs, build function list |
| `xref` | `--run-pass xref` | Yes | PC → inst_ids cross-reference index |
| `cfg` | `--run-pass cfg` | Yes | Control-flow graph (basic blocks + edges) |
| `cfg_layout` | `--run-pass cfg_layout` | No | Graph layout coordinates for CFG view |
| `call_graph` | `--run-pass call_graph` | Yes | Inter-function call graph |
| `loop` | `--run-pass loop` | Yes | Detect loops via back-edges in CFG |
| `vm_abstract` | `--vm-abstract` | No | Use a static-analysis-provided dispatcher anchor plus optional indirect-branch/handler hints to build VM step sequences, decode opcodes/operands, and capture context/register/stack snapshots; does not discover dispatchers automatically |

## Taint

| Pass | CLI flag | Default | Summary |
|---|---|---|---|
| `taint` | `--taint` | No | Forward taint from current register |
| `backward_taint` | `--backward-taint` | No | Backward taint from current instruction |
| `taint_source_annotation` | `--taint-source-annotation` | No | Annotate backward-taint endpoints (ObjC/mem/const) |

## Crypto / Pattern

| Pass | CLI flag | Default | Summary |
|---|---|---|---|
| `pattern` | `--pattern` | Yes | Crypto/anti-debug patterns + materialized constants (`constant_materialization` merged into pattern) |
| `loop_semantics` | `--loop-semantics` | Yes | Classify loops (Feistel/SPN/ARX/memcpy…) |
| `algorithm_summary` | `--algorithm-summary` | Yes | Cross-reference constants+patterns → algorithm ID |
| `objc_crypto` | `--objc-crypto` | No | Correlate crypto patterns with ObjC call stacks |

## Memory / String

| Pass | CLI flag | Default | Summary |
|---|---|---|---|
| `strings` | `--strings` | Yes | String accesses in the trace |
| `memory_strings` | `--memory-strings` | No | Time-aware string discovery via memory reconstruction |
| `memory_snapshot` | `--memory-snapshot` | No | Capture memory snapshots at call sites / inst_ids |
| `mem_search` | `--run-pass mem_search` | No | Multi-pattern + exact-value/immediate search (`literal_search` deprecated alias) |
| `entropy` | `--entropy` | No | Shannon entropy of a memory region |
| `yara_mem_scan` | `--yara-mem-scan` | No | YARA scan of heap/stack memory |

## Platform API

| Pass | CLI flag | Default | Summary |
|---|---|---|---|
| `objc` | `--objc` | No | Objective-C message send analysis |
| `syscall_intercept` | `--syscall-intercept` | No | Intercept crypto/system API calls (platform-aware) |

## Profile / Trace

| Pass | CLI flag | Default | Summary |
|---|---|---|---|
| `trace_fold` | `--trace-fold` | No | Fold repetitive loop iterations into summaries |
| `reg_timeline` | `--reg-timeline` | No | Timeline of all writes to a register |
| `call_context` | `--call-context` | No | Call stack + loop position + neighbors at an inst |
| `window_stats` | `--window-stats` | No | Sliding window statistics (hot regions, entropy…) |
| `trace_diff` | `--trace-diff` | No | Compare two trace regions for divergence |
| `dataflow_graph` | `--dataflow-graph` | No | Register-level data-flow graph for a region |

## Multi-thread

| Pass | CLI flag | Default | Summary |
|---|---|---|---|
| `thread` | `--run-pass thread` | Yes | Thread timeline / switching statistics for multi-thread traces |
| `thread_filter` | `--thread-filter [tid,…]` | No | Per-thread instruction bitmaps; restricts the instruction view to the given tids (re-configurable — the pass is re-registered on each new selection) |
| `cross_thread_dataflow` | `--cross-thread-dataflow` | No | Shared-memory handoffs between threads: writer→reader edges aggregated into channels with producer→consumer statistics |

## Dependency graph

```text
function ──> call_graph
    ├───────────────> algorithm_summary
    └───────────────> call_context

xref ──> cfg ──> cfg_layout
  │       └──> loop ──> loop_semantics
  │              │          └──> algorithm_summary
  │              ├──────────────> trace_fold
  │              ├──────────────> call_context
  │              └──────────────> vm_abstract
  ├──────────────> loop_semantics
  ├──────────────> trace_fold
  └──────────────> vm_abstract

pattern ─────────> algorithm_summary
  └──────────────> objc_crypto
call_graph ──────> algorithm_summary
objc ────────────> objc_crypto
  └──────────────> taint_source_annotation
backward_taint ──> taint_source_annotation
cfg ─────────────> vm_abstract
thread ──────────> thread_filter
```

The graph above shows the main dependencies declared in the source; `taint` depends on `xref` only when xref acceleration is enabled. For the complete current set, refer to `--list-passes` and each pass's `dependencies()` declaration.
