---
title: Taint and data flow
sidebar:
  order: 3
---

Taint analysis connects values across the executed timeline. Forward taint asks where a source went; backward taint asks what contributed to a sink.

## Source and sink selection

- **Forward source**: a register index at a specific instruction occurrence. The value in that register at that point becomes the initial taint seed.
- **Backward sink**: a register index at a specific instruction (`inst_id`). The analysis walks backward to find all instructions that contributed to that value.

Both use **numeric register indices** (0–28 map to x0–x28, 29 = fp, 30 = lr, 31 = sp, 32 = nzcv, 33 = pc). Forward analysis also supports memory sources through `--taint-mem`.

## Forward taint configuration

Choose a register and optionally an instruction occurrence and memory sources:

```bash
./tenet [options] trace.bin --taint 0 --taint-inst 12000
./tenet [options] trace.bin --taint 0 --taint-mem 0x16fdff200 \
  --taint-stop-pc 0x100123456 --taint-max-width 16
```

Controls:

- `--taint-inst <inst_id>` — start from a specific occurrence (not just the first write to the register).
- `--taint-mem <addr>` — add a memory address as an additional taint source (repeatable).
- `--taint-stop-pc <addr>` — stop propagation when execution reaches this PC (repeatable, useful for bounding investigation at known sinks).
- `--taint-max-width <N>` — stop when the number of simultaneously tainted registers exceeds N (prevents uncontrolled fan-out).
- `--taint-no-calls` — do not propagate taint through function calls.
- `--taint-no-xref` — disable XRef acceleration (slower but useful for diagnosing propagation issues).
- `--taint-no-kills` — do not emit kill events in the output.

XRef acceleration is enabled by forward taint by default; it requires the `xref` pass to be registered.

## Backward taint: writers and overlap

`--backward-taint` follows the last register writer chain and overlapping memory writes:

```bash
./tenet [options] trace.bin --backward-taint 58000 0
./tenet [options] trace.bin --backward-taint 58000 0 \
  --backward-taint-max-steps 5000 \
  --backward-taint-graph graph.json
```

- `--backward-taint <inst_id> <reg>` — mandatory: the sink instruction and register index.
- `--backward-taint-max-steps <N>` — limit how far back to walk (default: unlimited, bounded only by trace start).
- `--backward-taint-graph <file>` — export the dataflow dependency graph built during backward walk (`.dot` or `.json`). This is the **backward taint's own** dependency graph; it is distinct from the independent `--dataflow-graph` pass.

The pass follows both register writers (reg_diff) and memory load←store chains. Memory matching is **overlap-aware**: partial overlaps and unaligned accesses are tracked, so a write to `0x1000` contributes to a read from `0x1004` if their address ranges intersect.

## `--critical-path`: requires backward taint

`--critical-path` computes the intersection of forward reachability (source → everywhere it reached) and backward contribution (everything that fed the sink). The result is the instruction sequence that actually transforms source data into the sink value.

**CLI semantics**: `--critical-path` **must** be combined with `--backward-taint <inst_id> <reg>`. It also requires forward taint; if `--taint` is not specified, the backward sink register becomes the forward source. The start comes from `--taint-inst`, or defaults to the beginning of the trace.

```bash
./tenet [options] trace.bin \
  --taint 0 --taint-inst 10000 \
  --backward-taint 58000 0 \
  --critical-path
```

Output includes `critical_path_count` (intersection size), `backward_count`, and `forward_count`. The first 200 critical-path instruction IDs are listed.

MCP equivalent: call `critical_path` once with `source_reg`, `source_inst_id`, `sink_reg`, and `sink_inst_id`; the tool runs both directions internally.

## `--backward-taint-graph` vs `--dataflow-graph`

These are two distinct analyses:

| | `--backward-taint-graph` | `--dataflow-graph` |
|---|---|---|
| Scope | All contributing instructions found during backward walk from the sink | A user-specified instruction range `[start, end)` |
| Trigger flag | `--backward-taint-graph <file>` (paired with `--backward-taint`) | `--dataflow-graph <start> <end>` |
| Output path | Same flag | `--dataflow-graph-output <file>` |
| Pass name | builtin to `backward_taint` | `dataflow_graph` |
| Limit | All contributing instructions | Default 5000 nodes |

```bash
# Backward taint's own dependency graph (follows sink contribution chain)
./tenet [options] trace.bin --backward-taint 58000 0 \
  --backward-taint-graph bt-graph.json

# Independent dataflow for an arbitrary range
./tenet [options] trace.bin --dataflow-graph 20000 24000 \
  --dataflow-graph-output dfg.dot
```

## Source annotation

`taint_source_annotation` enriches backward taint leaf sources with contextual classification:

```bash
./tenet [options] trace.bin --backward-taint 58000 0 --taint-source-annotation
```

Each leaf (an endpoint that cannot be traced further back) is classified as:

- `ObjcGetter` / `ObjcArg` / `ObjcReturn` — value originated from an Objective-C method (iOS/macOS only).
- `MemoryLoad` — value came from a memory read with no prior write in the contributing set.
- `Constant` — value was materialized by immediate-loading instructions (MOVZ/MOVK chain, ADRP+ADD).
- `FunctionReturn` — value was returned by a function call.

**Dependencies**: requires `backward_taint` (hard) and `objc` (hard). `function` is a soft dependency used to attribute `FunctionReturn` sources to a specific callee. Android/Linux traces cannot receive ObjC annotations (no ObjC runtime).

## Triton and fallback semantics

When Tenet is built with Triton (`TENET_ENABLE_TRITON=ON`) and the Triton bridge is available, both forward and backward taint use Triton's symbolic engine for precise per-instruction semantics. This captures flag-level dependencies and complex AArch64 addressing modes.

When Triton is unavailable (build without it, or runtime absence), both passes fall back to the **heuristic engine**:

- Register pollution is inferred from `reg_diff` entries (any register with a diff is treated as written).
- Kill semantics are applied: if a register is fully overwritten (no dependency on its prior value), the old taint is killed.
- Memory propagation uses store←load overlap matching via the memory model.
- NZCV and SP are excluded from ordinary value taint.

The heuristic is less precise for instructions with partial register updates or flag-dependent operations, but covers the vast majority of AArch64 integer code.

## GUI, TUI, and MCP

- **GUI**: tainted instructions are highlighted in the instruction list; the Producer Chain panel shows a bounded preview of `backward_taint` results (not a separate analysis). The "Taint" mode displays forward taint events.
- **TUI**: press `t` to run forward taint and `B` (Shift+b) to run backward taint; tainted instructions are marked in the listing.
- **MCP**: `taint_forward` requires `reg_index` and accepts `inst_id`, `mem_addrs`, `stop_pcs`, `max_width`, and step pagination. `taint_backward` uses `sink_inst_id` / `sink_reg` with optional limits and event pagination. `critical_path` takes both source and sink in one call. `dataflow_graph` uses `start_inst_id` / `end_inst_id`, with optional `max_nodes` and `format`.

## Result interpretation

- Taint proves a **recorded data dependency** in this specific execution — it does not necessarily imply semantic intent or cryptographic relevance.
- A tainted path does not guarantee the source value's bitwise identical presence at the sink (intermediate transformations may have altered it).
- Missing or uninstrumented operations (unrecorded calls, excluded ranges) can break a chain, producing gaps in propagation.
- Forward taint over-approximates: if a register's new value does not actually depend on its prior value but the pass cannot prove it, the old taint may survive (heuristic mode only; Triton is more precise).

## Performance and caching

- Forward taint uses XRef acceleration by fast-forwarding across instructions that do not touch the tainted set. Disable with `--taint-no-xref` only for diagnosis.
- Backward taint bound by `--backward-taint-max-steps` keeps walk time predictable for large traces.
- The forward pass is single-stream from source to end; its cost scales with the number of instructions touched by the taint set, not total trace size.
- Results are not cached between runs; re-running taint re-runs the pass. The underlying `xref` pass may be cached as a RocksDB blob if the trace range is unchanged.

## Troubleshooting

### Forward taint reaches almost everything

The taint set is fanning out without mitigation. Add `--taint-max-width` to cap the register set, `--taint-stop-pc` to bound by location, or `--taint-no-calls` to prevent cross-function spread.

### Backward taint finds no upstream values

The sink register may have been set by an uninstrumented operation (gap in trace), or the trace lacks the `reg_diff` data needed to identify writer instructions. Verify the trace was recorded with `QBDITRACE_REC_REGDIFF` and that the sink instruction is within the instrumented range.

### `--critical-path` produces an empty result

The forward and backward taint sets do not overlap. Verify that the source register value actually flows to the sink by running forward taint first and inspecting where it reaches, then run backward taint from the suspected sink and confirm the contributing set intersects.

### Taint chain has gaps at call boundaries

Use C API records (`REC_CAPICALL`) or read observations to inspect parameter passing across untraced calls. Source annotation can also identify when a value originated from an uninstrumented function return.

### Triton and heuristic disagree

 Triton has precise semantics for more AArch64 instructions; the heuristic may over-taint in corner cases. Prefer Triton builds when exact precision is required.
