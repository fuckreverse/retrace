---
title: Taint and data flow
sidebar:
  order: 3
---

Taint analysis connects values across the executed timeline. Forward taint asks where a source went; backward taint asks what contributed to a sink.

## Forward taint

Choose a source register and instruction occurrence, optionally add a memory source, then propagate toward later consumers:

```bash
./tenet trace.bin --taint 0 --taint-inst 12000
./tenet trace.bin --taint 0 --taint-mem 0x16fdff200 \
  --taint-stop-pc 0x100123456 --taint-max-width 16
```

Useful controls:

- `--taint-stop-pc` bounds the investigation at known sinks.
- `--taint-max-width` stops uncontrolled fan-out.
- `--taint-no-calls` prevents propagation through calls.
- `--taint-no-xref` disables XRef acceleration for diagnosis.

GUI/TUI highlight tainted instructions; `[` and `]` traverse propagation events. MCP uses `taint_forward`.

## Backward taint

Start from a sink instruction and register:

```bash
./tenet trace.bin --backward-taint 58000 0
./tenet trace.bin --backward-taint 58000 0 \
  --backward-taint-max-steps 5000 \
  --backward-taint-graph graph.json
```

The pass follows last register writers and overlapping memory writes. The GUI's **Producer Chain** is only a bounded preview of `backward_taint`, not a separate analysis. MCP uses `taint_backward`.

## Critical path and graph

`--critical-path` intersects forward reachability with backward contribution, reducing broad propagation to evidence connecting source and sink. `dataflow_graph` builds a register/memory producer-consumer graph for an explicit instruction range:

```bash
./tenet trace.bin --dataflow-graph 20000 24000 \
  --dataflow-graph-output dfg.dot
```

Graphs are bounded to 5000 nodes; narrow the range for larger regions.

## Source annotation

`taint_source_annotation` enriches backward leaves with context such as ObjC getter/argument/return, memory load, constant or function return. It depends on `backward_taint` and `objc`; Android/Linux traces cannot receive ObjC annotations.

```bash
./tenet trace.bin --backward-taint 58000 0 --taint-source-annotation
```

## Precision and evidence

- GPR anchors/diffs and memory accesses are required for useful propagation.
- Memory matching is overlap-aware, including partial and unaligned accesses.
- NZCV, SP and PC are excluded from ordinary value taint by default.
- Triton supplies precise local instruction semantics when available; builds without it degrade to supported fallback semantics.
- Taint proves a recorded dependency, not necessarily semantic intent or cryptographic relevance.
- Missing/uninstrumented operations can break a chain; use C API records, read observations and source annotations to explain gaps.
