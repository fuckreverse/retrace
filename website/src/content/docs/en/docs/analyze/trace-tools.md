---
title: Trace tools
sidebar:
  order: 7
---

Trace tools operate on the execution history as a whole: comparing, folding, profiling and diffing traces. They do not derive new semantic facts about a single trace but help select, compare and summarize the timeline.

## Trace Fold

`trace_fold` compresses trace regions matching a function or loop into a single representative block. The result is a simplified timeline that retains all non-folded execution while showing a single entry/exit per folded region.

Use it to:

- Remove library boilerplate from the timeline while preserving entry/exit.
- Collapse known loops to see surrounding context more clearly.
- Focus on a specific function range and fold everything outside it.

```bash
./tenet trace.bin --trace-fold --fold-function 0x100123456
./tenet trace.bin --trace-fold --fold-loop
```

Fold is reversible: the original timeline is preserved and fold/unfold can be toggled without reprocessing.

## Trace Diff

`trace_diff` compares two traces instruction by instruction. Provide a second trace to find where executions diverge:

```bash
./tenet trace.bin --diff-trace other.bin --diff-output diff.json
```

Differences include PC mismatches, register-value differences and memory-access differences at corresponding instruction IDs. The result is a structured JSON report.

Typical use cases:

- Compare two inputs to the same function.
- Verify that a patch changed only the intended behavior.
- Detect environment-dependent execution differences.

## Window statistics

`window_stats` computes per-window instruction counts, memory-access counts and basic-block coverage. It is useful for profiling which phases of execution are most active:

```bash
./tenet trace.bin --window-stats --window-size 10000
```

## Profile and hotspot

`profile` computes per-function and per-basic-block execution statistics. It complements structure recovery with quantitative data:

```bash
./tenet trace.bin --profile --profile-format json
./tenet trace.bin --profile --profile-format csv
```

Hotspot analysis identifies the most-executed functions and blocks. Use it with Trace Fold to compress uninteresting hot regions and reveal surrounding cold code.

## Limitations

- Trace Fold and Diff work on instruction-level granularity. Semantic differences (e.g., same PC but different data) are reported but not explained.
- Window statistics sample evenly; uneven instruction density may need smaller windows.
- Profile data reflects only the recorded execution. It is not a general performance model.
- Diff requires both traces to have compatible format versions and module configurations.
