---
title: Recover program structure
sidebar:
  order: 2
---

Structure recovery organizes the executed timeline into code locations, functions, basic blocks, edges, calls and loops. It is normally the first analysis stage because later passes reuse these results.

## Capability chain and dependencies

```text
xref ──> cfg ──> cfg_layout
            └──> loop
function ──> call_graph
```

| Pass | Dependencies | Answers | Main result |
|---|---|---|---|
| `function` | none | Which calls/returns and function invocations were observed? | Call events, dynamic call stack, function table |
| `xref` | none | Where and how often did a PC execute? | PC → `inst_id` occurrences and counts |
| `cfg` | `xref` | How did executed basic blocks connect? | Blocks, edges, execution heat, terminators |
| `cfg_layout` | `cfg` | Where should CFG nodes be drawn? | Visual coordinates, annotated DOT |
| `call_graph` | `function` | Which observed functions called each other? | Caller→callee edges, sites and counts |
| `loop` | `cfg` | Which CFG back-edges form loops? | Headers, bodies, iterations, nesting |

The dependency graph is resolved automatically by PassManager: requesting `--export-cfg` registers `xref`, `cfg`, and `cfg_layout`; requesting `--call-graph` registers `function` and `call_graph`.

## Dynamic functions and call/return semantics

`function` identifies function boundaries by pairing BL/BLR (call) with RET using a simulated call stack. It is a **dynamic** reconstruction:

- A function appears only when a call to its entry PC was observed during this run.
- Indirect calls (BLR) and runtime dispatch are resolved to their observed target PC.
- Tail calls (unconditional B/BR that reuse the caller's stack frame) are detected via SP tracking and marked `is_tail_call`.
- Each `CallEvent` records `call_inst_id`, `target_pc`, `return_inst_id` (0 if not yet returned), and call-stack depth.
- Function names come from the binary's symbol table; unnamed entries render as `sub_<hex>`.

Memory usage is bounded by default (call events capped at 20 M, per-function indices at 1 000). Use `FunctionConfig::full_mode` only for small traces that need complete per-call navigation.

## XRef

`xref` builds a PC→inst_id index over every executed instruction. It powers:

- Execution-count heatmaps in the CFG panel.
- First/prev/next/last navigation across visits to the same block or PC.
- Acceleration for forward taint (enabled by default; disable with `--taint-no-xref`).

## CFG and full `--export-cfg`

`cfg` constructs a control-flow graph from executed basic blocks. `--export-cfg` writes a Graphviz DOT file containing every function's CFG with full disassembly in each node:

```bash
./tenet [options] trace.bin --export-cfg all.dot
```

The output is the annotated DOT from `cfg_layout` (`CFGLayoutResult::dot_annotated`). Open it with `dot -Tsvg all.dot -o all.svg` or any Graphviz renderer. Block color reflects execution heat; edges show observed control flow.

:::note[Block-count threshold]
Full disassembly is embedded in each node only when the CFG has ≤ 500 blocks. For larger graphs the output contains a placeholder; use the GUI or MCP `cfg_export` (JSON format) to explore individual blocks on demand.
:::

## Layout

`cfg_layout` computes visual coordinates for CFG nodes using a hierarchical grid algorithm (similar to Ghidra's decompiler layout). It is registered automatically by `--export-cfg` and otherwise runs on demand when a layout view requests it. Standalone CLI use is rare; most users consume the layout through the GUI or the generated DOT.

## Loops

`loop` detects natural loops via dominator-tree analysis on the CFG (LLVM-style Semi-NCA algorithm). For each loop it reports:

- `header_pc` and `back_edge_pc`
- `iteration_count` (how many times the back-edge was taken)
- `nesting_depth` (0 = outermost)
- `body_pcs` (all PCs in the loop body)

Loop results feed Loop Semantics, Trace Fold, and hotspot analysis.

## Call graph

`call_graph` aggregates `function` results into an inter-procedural call graph. `--call-graph` exports it as Graphviz DOT:

```bash
./tenet [options] trace.bin --call-graph cg.dot
```

Each node is a function (by entry PC); edges carry call counts and site PCs.

## Recommended workflow

1. Open the trace in GUI/TUI — the structure passes `function`, `xref`, `cfg`, `call_graph`, and `loop` are among the default startup set.
2. Browse the Functions panel to locate the target function.
3. Use the Call Stack panel to follow call/return navigation.
4. Open the CFG panel to inspect hot blocks and edges; use prev/next visit to step through executions.
5. Check the Loops panel for iteration counts and nesting.
6. If you need a persistent artifact, use `--export-cfg` or `--call-graph` from CLI.

## Interactive entry points

- **Functions panel** (`show_functions_`): sort/filter by call count, instruction count, or name. Right-click a function to jump to its entry, run Xref, or inspect callers/callees.
- **Call Stack panel** (`show_callstack_`): lists frames at the current instruction. Right-click a frame to jump to its call site or function entry.
- **CFG panel** (`show_cfg_`): renders the CFG layout. Click a block to select it; use first/prev/next/last to navigate visits (powered by Xref). Right-click a block to jump to a specific execution.
- **Call Graph panel** (`show_call_graph_`): hot-callees ranking and full edge list. Click a node to navigate to its entry.
- **XRef navigation**: in the Call Stack panel, the PC xref controls (Prev/Next) step through every execution of the current PC. In the GUI, pressing `X` runs Xref if not already run, then cycles through visits.
- **TUI**: `:pass function`, `:pass xref`, `:pass cfg`, `:pass loop`, `:pass call_graph` run individual passes. `:analyze` runs the default set.

## MCP call order

1. `functions` — list observed functions (entry PC, name, call count, instruction count).
2. `find_function` — locate a function by PC.
3. `xref` — query PC→inst_id occurrences.
4. `cfg_export` — export CFG in DOT or JSON format (auto-runs `xref`, `cfg`, `cfg_layout`).
5. `call_graph` — export call graph in DOT or JSON format (auto-runs `function`, `call_graph`).
6. `loops` — query detected loops (header, body, iteration count, nesting).

PC values returned by MCP tools use the current `image_base` (default `0x100000000`, matching IDA for AArch64 Mach-O). Adjust with `set_image_base` if your static tool uses a different base.

## Result interpretation

- **Dynamic coverage**: an edge, function, or loop appears only if this run executed evidence for it. Unexecuted error paths, alternate switch cases, and callbacks are absent.
- **Indirect calls**: resolved to observed targets; if a function pointer had multiple callees across the run, each appears as a separate edge.
- **Execution count**: measures this input and run, not general likelihood.
- **Function boundaries**: derived from observed call/return pairs, not from binary metadata. A function with no observed caller still appears if it was the trace start point.

## Sampling, branch hint, and missing-code boundaries

- **Branch hint** (`HF_BRANCH_HINT`): when present in the trace, the tracer encodes call/ret/branch class in the NZCV high nibble at recording time. `function` uses this O(1) path to classify ~95% of instructions immediately. Without branch hint, it falls back to a binary-search table over the code table (still correct, slightly slower).
- **Sampling**: if the trace used instruction sampling, some call/return pairs may be missed, producing incomplete call stacks or phantom tail calls. `FunctionResult::non_local_unwinds_` counts detected anomalies.
- **Missing code** (`REC_CODE` disabled): without embedded opcodes, the code table is empty and `function` cannot classify branch-class PCs. Call/return pairing degrades or fails. Re-record with code embedding enabled, or provide an external mirror for disassembly.

## Troubleshooting

### Call stack shows unexpected depth or non-local unwinds

The trace may have missing RET events (sampling, instrumentation gaps) or non-standard control flow (longjmp, exception unwinding). Check `FunctionResult::non_local_unwinds_` for the count of detected anomalies.

### A function I expected is absent

The function was not called during the traced execution, or its call used an indirect branch whose target was not observed. Verify the trace range covers the code path, and check Xref for the expected entry PC.

### `--export-cfg` produces an empty or trivial DOT

Ensure the trace contains enough executed instructions to form basic blocks. Very short traces or heavily sampled traces may produce a single-block graph. Also verify that `REC_CODE` or an external mirror is available so block boundaries can be resolved.

### Loop iteration count seems wrong

Loop detection depends on CFG accuracy. If sampling missed back-edges, iteration counts will be under-reported. Use a trace recorded without sampling for accurate loop metrics.
