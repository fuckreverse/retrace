---
title: Virtual machine and code virtualization
sidebar:
  order: 8
---

VMP-style protections replace native code with a custom bytecode interpreter. Tenet's VM analysis framework recovers handler structure, data flow, dispatch patterns and lifted semantics from the observed execution—without needing the original compiler or bytecode specification.

## VM analysis taxonomy

| Category | Analysis goal | Relevant passes |
|---|---|---|
| Handler identification | Find dispatcher and handler boundaries | `xref`, `cfg`, `loop`, `vm_abstract` |
| Dispatch pattern | Classify direct/indirect/threaded dispatch | `vm_abstract`, `cfg` |
| Handler semantics | Lift operations to native-like IR | `vm_abstract`, `backward_taint`, `dataflow_graph` |
| State mapping | Map virtual registers to physical locations | `backward_taint`, `taint_source_annotation` |
| Control flow | Reconstruct virtual branches and loops | `cfg`, `loop`, `loop_semantics` |

## vm_abstract

`vm_abstract` is the primary entry point. It:

1. Locates the dispatch loop using loop analysis and CFG structure.
2. Identifies handler entry points from dispatch targets.
3. Classifies dispatch patterns (direct, indirect, threaded).
4. Extracts per-handler instruction counts and edge frequencies.

```bash
./tenet trace.bin --vm-abstract
```

## Complementary passes

Combine `vm_abstract` results with other passes for deeper analysis:

- **`backward_taint`** on a virtual register or stack slot reveals its physical mapping and producer chain.
- **`dataflow_graph`** inside a handler shows its register/memory transform.
- **`loop_semantics`** classifies the dispatch loop itself (often ARX or Counter Loop).
- **`cfg`** and **`function`** locate the containing interpreter and its boundaries.
- **`pattern`** may identify anti-debug or obfuscation techniques within handlers.

## VM Workspace (GUI)

The Desktop GUI includes a VM Workspace window that presents handler summary, dispatch visualization, handler-to-instruction mapping and integration with taint results. This is the recommended interface for multi-step VM analysis.

## Limitations

- VM analysis depends on the dispatcher executing in the trace. Inlined or flattened dispatch without a loop may require manual handler identification.
- Handler lifting is bounded: complex handlers with many memory indirections may not fully resolve.
- The analysis observes one execution; unexecuted handlers and dispatch targets are not reported.
- State mapping precision depends on recorded GPR diffs and memory accesses. Sampling or missing evidence reduces accuracy.
- `vm_abstract` does not de-virtualize or recompile code; it produces structural analysis for downstream tools.
