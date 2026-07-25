---
title: Trace tools
sidebar:
  order: 7
---

Trace tools operate on the execution history as a whole: compressing repetitive loops, comparing trace regions, tracking register changes, and summarizing instruction windows. They do not derive new semantic facts about a single trace — they help you select, condense, and compare the timeline.

## Trace Fold

`trace_fold` detects repetitive loop iterations and folds them into a compressed summary. Instead of showing every iteration, it keeps a few representative ones (first and last N) and reports the register/NEON state changes that occurred across the folded region.

Required Pass dependencies are `loop` (loop discovery) and `xref` (PC cross-references). The MCP wrapper also schedules `function` for surrounding context.

```bash
./tenet [options] trace.bin --trace-fold <start> <end>
./tenet [options] trace.bin --trace-fold <start> <end> --trace-fold-min-iter 5
./tenet [options] trace.bin --trace-fold <start> <end> --trace-fold-keep-iter 3
```

All arguments are **instruction IDs** (not PCs) — the contiguous inst_id range to fold within.

### Additional parameters

| Parameter | Default | Description |
|---|---|---|
| `--trace-fold-min-iter <N>` | 3 | Minimum consecutive iterations required to fold a loop |
| `--trace-fold-keep-iter <N>` | 2 | Representative iterations kept (first N + last N) |
| `--trace-fold-samples <N>` | 6 | Interior sample points used to classify each register's change pattern (monotonic / oscillating / constant) |
| `--trace-fold-no-fpr` | off | Disable FPR (NEON v0–v31) diff summary even if the trace carries v7 FPR data |

### What fold reports

For each folded region:

- **header PC**: the loop's branch-back target;
- **total iterations / instructions folded**: how much was removed;
- **kept iterations**: the inst_id ranges of representative first/last iterations that remain in the simplified view;
- **GPR changes**: for each modified register, the first value, the last value, and the inferred pattern (`constant`, `monotonic`, `oscillating`) across sampled interior points — a quick heuristic hinting at counter/accumulator vs. scratch reuse;
- **FPR changes** (v7 FPR-enabled traces only, unless `--trace-fold-no-fpr`): first/last 128-bit value of each modified NEON register;
- **compression ratio**: `original / folded`.

### How to read fold results

The pattern classification is intentionally cheap — it is NOT a replacement for `loop_semantics`. Use it to:

- collapse `memset`-style byte loops whose registers show `monotonic` addressing;
- spot loops that modify no GPRs beyond the program counter (`constant` everywhere = a likely busy-wait or delay);
- identify accumulator-style loops (`monotonic` on xN suggesting a running total).

For rigorous loop classification (Feistel, SPN, ARX, memcpy, etc.) run `--loop-semantics` on the unfolded trace or on the kept iterations.

### State summary

`trace_fold` uses `regfile.warm_range()` to batch-preheat all anchor caches across the fold region before sampling, avoiding per-iteration cold replay. The first/last + interior sample points are taken at evenly spaced iterations plus a half-period companion point, which helps prevent aliasing on periodic signals (e.g. a `+delta / -delta` alternating scratch register being misclassified as `monotonic`).

## Trace Diff

`trace_diff` compares two instruction ranges and finds where they diverge. It supports both same-trace region comparison and cross-file comparison (differential cryptanalysis / white-box analysis).

```bash
# Same-trace region comparison
./tenet [options] trace.bin --trace-diff <a_start> <a_end> <b_start> <b_end>

# Cross-file: compare against a second trace
./tenet [options] trace.bin --trace-diff <a_start> <a_end> <b_start> <b_end> --trace-diff-file other.bin
```

All arguments are **instruction IDs**. Ranges are half-open: `[start, end)`.

### Additional parameters

| Parameter | Default | Description |
|---|---|---|
| `--trace-diff-file <path>` | (same trace) | Path to trace B for cross-file comparison |
| `--trace-diff-window <n>` | 16384 | Resync lookahead window — how many instructions to search forward for a matching PC after divergence |
| `--trace-diff-max-diffs <n>` | 100000 | Maximum divergence segments to record; beyond this the result is truncated |

### Alignment and resynchronization

Diff walks both ranges in inst_id order. Differences fall into three types:

| Type | Meaning | Resync behavior |
|---|---|---|
| `ControlFlow` | PCs differ | Triggers a resync search: scan up to `resync_window` instructions ahead in both ranges looking for a matching PC pair (preferring CALL/RET boundaries as anchor points) |
| `RegisterValue` | Same PC but output register values differ | Reported inline; both ranges continue in lock-step |
| `MemoryValue` | Same PC but memory access values differ | Reported inline; both ranges continue in lock-step |

When resync succeeds, the segment is marked `resynced = true` with the resync point in both ranges. When it fails (permanent divergence), `resynced = false`.

Each `DivergeSegment` records:
- divergence start (inst_id in A, inst_id in B, PC at divergence, type);
- divergence length in both ranges (`skip_a`, `skip_b`);
- resync point when successful.

### Same-file vs cross-file

- **Same file** (no `--trace-diff-file`): useful when a function is called twice within one trace (e.g. same primitive with two inputs). Tenet simply opens the same trace twice under independent readers.
- **Cross-file**: Tenet subtracts each trace's own `module_slide` and compares normalized PCs. Architectures and GPR counts must match; differing module names produce a reliability warning. Format versions must be compatible. Mismatched ranges or divergent module layouts produce confusing diffs — validate both traces open cleanly in tenet before diffing.

### Interpreting results

Result summary fields:
- `matched_count`: instructions that matched perfectly (PC + data);
- `total_diverged`: total instructions in diverged regions;
- `resync_count`: number of successful resynchronizations;
- `permanent_divergence_count`: segments that never resynced;
- `truncated`: `true` if `max_diffs` was reached.

A healthy differential analysis of two inputs to the same function shows an early match, a divergence segment at the input-dependent branch, then successful resync at a common convergence point (function epilogue).

## Window statistics

`window_stats` computes per-window metrics over a contiguous inst_id range: instruction mix (mnemonic distribution), register write activity, memory access density, unique PCs, branch density, and mnemonic entropy. Useful for profiling which phases of execution are most active.

```bash
./tenet [options] trace.bin --window-stats <start> <end>
./tenet [options] trace.bin --window-stats <start> <end> --window-stats-size 2048
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `--window-stats <start> <end>` | — | Inst_id range to scan (required) |
| `--window-stats-size <n>` | 1024 | Number of instructions per window (MCP defaults to 1000) |

### What window stats reports

Each `WindowSnapshot` includes:
- instruction count;
- top-N mnemonics by count;
- per-register write counts (34 GPRs);
- read/write counts and unique memory addresses;
- unique PCs (instruction diversity);
- mnemonic entropy of the instruction mix;
- branch density.

Aggregate result highlights: hottest memory window, most diverse window (highest entropy), densest branch window.

Use `--window-stats-size` to tune granularity: smaller windows localize hot spots more tightly; larger windows smooth over noise but may merge distinct phases.

## Register timeline

`reg_timeline` builds a per-write history for one GPR across an inst_id range: every write event records the PC, the old value, and the new value.

```bash
./tenet [options] trace.bin --reg-timeline <reg_index>
./tenet [options] trace.bin --reg-timeline <reg_index> --reg-timeline-range <start> <end>
```

| Parameter | Default | Description |
|---|---|---|
| `--reg-timeline <reg_index>` | — | Register index (0–28 for x0–x28, 29=fp, 30=lr, 31=sp, 32=nzcv, 33=pc) |
| `--reg-timeline-range <start> <end>` | full trace | Inst_id range to scan |

### Tauri frontend / MCP entry point

The Tauri frontend provides a Register Timeline panel: choose a common register or enter a custom register name, inspect the plotted value changes, and click the timeline to navigate the main instruction view. MCP exposes `reg_timeline` with parameters matching the CLI.

## Call context

`call_context` reconstructs, for a single instruction, the call stack (via `FunctionResult::call_stack_at()`), the loop context (which loops contain the target, their nesting depth, iteration count), and the surrounding instructions before/after the target.

```bash
./tenet [options] trace.bin --call-context <inst_id>
```

| Parameter | Default | Description |
|---|---|---|
| `--call-context <inst_id>` | — | Target instruction ID |

### Result structure

- `call_stack`: outermost-first list of `CallStackFrame` (call site PC, callee PC, call/return inst_ids, tail-call flag);
- `loop_contexts`: which loops contain the target, with header PC, nesting depth, and total observed iterations;
- `instructions`: surrounding instructions (10 before / 10 after by default), each annotated with loop depth and whether it is the target.

### CLI / MCP entry point

The current Tauri frontend does not implement a Call Context result panel or auto-populate it from main-timeline selection. Use `--call-context <inst_id>` above or the MCP `call_context` tool. MCP accepts either an exact `inst_id` or a `pc`; the PC form uses XRef to select an observed instruction occurrence.

## Performance profiling entry points

Tenet has **no `--profile` CLI flag**. The Instruments workflow below is a macOS-specific recommendation for Tenet developers profiling backend performance, not a platform limit on Tenet's analysis capabilities; Linux and Windows developers can use their platform profilers:

- **Time Profiler** samples CPU at function level — find the slowest pass or function;
- **System Trace** visualizes thread scheduling and context switches;
- **CPU Counters** expose IPC, cache miss rates, branch misprediction;
- **os_signpost** intervals from `TENET_ZONE_NAMED(...)` appear as "Points of Interest" in Instruments, labeled with pass names.

For profiling commands and methodology, see the bundled `tools/tenet/docs/profiling.md` guide (Instruments, signpost marks, and benchmark suites).

## Recommended workflow

1. **First look** — open the trace in the Tauri desktop application or `--stats` to check total inst count and index status.
2. **Identify hot regions** — run `--window-stats 0 <end>` to find the most active instruction bands.
3. **Fold noise loops** — if window_stats surfaces a dense, high-iteration region (memset-style), run `--trace-fold` on that inst_id range to collapse it before deeper analysis.
4. **Diff behavior** — for same-function/different-input traces, use `--trace-diff` (or `--trace-diff-file`) to locate where data dependencies cause divergence.
5. **Register-level drill** — once you have a PC of interest, use `--reg-timeline <reg>` in that region and `--call-context <inst>` to reconstruct control flow context.

## Limitations and troubleshooting

- **Fold works on inst_id ranges**, not PC ranges. If you want to fold a specific loop, find its inst_id span from the Tauri frontend or with `--search-pc <header_pc>` first.
- **Diff requires comparable format/version.** Both traces (or both same-trace regions) must open cleanly in tenet. Delta-encoded (v5) and FPR (v7) traces are fully supported.
- **Offline decoding** is done via `tenet --dump text` or `tenet --dump jsonl`, supporting v4/v5/v7 (including block-compressed). The legacy standalone `trace_decode` has been removed.
- **Register Timeline has a Tauri frontend panel; Call Context is not yet wired into the Web frontend** and is available through CLI/MCP. There is no `--profile`/`--hotspot` CLI flag. Instruments is only a macOS backend-profiling option for developers and does not limit cross-platform trace analysis.
- **Fold keeps representative iterations;** it does not remove them from the underlying trace data. Passes that run after fold see the original instruction stream.
- **Window stats stride = window size** (non-overlapping) by default; overlapping windows are not exposed via CLI at this time.
