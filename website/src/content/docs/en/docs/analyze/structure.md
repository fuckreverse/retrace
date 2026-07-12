---
title: Recover program structure
sidebar:
  order: 2
---

Structure recovery organizes the executed timeline into code locations, functions, basic blocks, edges, calls and loops. It is normally the first analysis stage because later passes reuse these results.

## Capability chain

```text
xref ──> cfg ──> cfg_layout
            └──> loop
function ──> call_graph
```

| Pass | Answers | Main result |
|---|---|---|
| `function` | Which calls/returns and function invocations were observed? | Functions, call events, dynamic call stacks |
| `xref` | Where and how often did a PC execute? | PC→`inst_id` occurrences and counts |
| `cfg` | How did executed basic blocks connect? | Blocks, edges, execution heat, terminators |
| `cfg_layout` | Where should CFG nodes be drawn? | Visual coordinates / DOT layout |
| `call_graph` | Which observed functions called each other? | Caller→callee edges, sites and counts |
| `loop` | Which CFG back-edges form loops? | Headers, bodies, iterations, nesting |

## Run from CLI

```bash
./tenet trace.bin --export-cfg function.dot
./tenet trace.bin --call-graph callgraph.dot
./tenet trace.bin --symbol-annotation
./tenet trace.bin --run-pass function --run-pass xref --run-pass loop
```

`--symbol-annotation` combines existing function, loop and pattern evidence into annotations; it is not a separate pass.

## Use interactively

- **Functions:** filter/sort observed functions, inspect invocation counts and callers/callees.
- **Call Stack:** select frames, jump to call sites/entries, follow calls and returns.
- **CFG:** select a function, inspect hot blocks/edges, click nodes to navigate.
- **XRef:** move among every occurrence of the same PC.
- **Loops:** feed Loop Semantics, Trace Fold and hotspot analysis.

MCP equivalents include `functions`, `find_function`, `xref`, `cfg_export`, `call_graph` and `loops`.

## Interpretation boundaries

This is a **dynamic** structure:

- An edge or function appears only if this run executed evidence for it.
- Indirect calls and runtime dispatch are resolved to their observed targets.
- Unexecuted error paths, alternate switch cases and callbacks are absent.
- Function boundaries depend on recorded branch/code evidence; sampling or missing code reduces precision.
- Execution count measures this input and run, not general likelihood.

Use structure recovery to choose an exact source or sink, then continue with [Taint and data flow](./taint/).
