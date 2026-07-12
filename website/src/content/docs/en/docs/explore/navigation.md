---
title: Navigation and breakpoints
sidebar:
  order: 4
---

Tenet navigates a finished execution history. Continue, step and break operations search the existing timeline; they never resume the target process.

## Direct navigation

- **Instruction ID:** jump to one exact execution occurrence.
- **Runtime PC:** jump to an executed code location.
- **Function:** jump to an observed invocation or entry.
- **Search:** locate instruction text, symbols or known strings.
- **History:** move backward/forward through prior navigation decisions.
- **Bookmark:** save investigation landmarks across sessions.

## Repeated execution and XRefs

The `xref` pass maps each PC to all matching instruction IDs. Previous/next XRef moves between loop iterations, repeated calls or shared handlers while preserving exact state at each occurrence. Execution count is observed frequency, not a static reachability estimate.

## Calls and returns

The function pass pairs observed calls and returns. **Follow Call** moves to the dynamic callee invocation; **Follow Return** moves to its observed return. The call-stack view navigates call sites and entries and may annotate tail-call context recovered from the trace.

## Breakpoints on a static timeline

| Type | Match source | Best use |
|---|---|---|
| PC breakpoint | XRef PC→instruction IDs | Next/previous execution of code |
| Write watchpoint | Memory-write index | Find when a buffer or field changes |
| Conditional breakpoint | Predicate evaluated while scanning | Stop on a state-dependent event |

Forward/reverse continue chooses the next/previous matching occurrence. Because no program executes, reverse continue needs no checkpoint restore or target replay.

## Value-oriented navigation

- **Register Timeline:** every recorded write to one register, with old/new values.
- **Memory Write History:** all writes overlapping an address range.
- **Last Writer:** nearest earlier write contributing the selected byte/region.
- **Backward Taint:** transitive producer chain from a register sink.
- **Taint navigation:** move among propagation events after a taint run.

## Runtime versus static addresses

UI navigation uses runtime addresses. When carrying an address to IDA or Ghidra, subtract `module_slide`; when bringing a static address back, add it. MCP clients can use the configured rebase support rather than performing this manually.
