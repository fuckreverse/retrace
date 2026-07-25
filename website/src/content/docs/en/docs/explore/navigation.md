---
title: Navigation and breakpoints
sidebar:
  order: 4
---

Tenet navigates a finished execution history. Continue, step and break operations search the existing timeline; they never resume the target process. The Tauri desktop application (Desktop) and TUI use the same backend state semantics, but their interaction surfaces are not identical.

## Direct navigation

- **Instruction ID:** jump to one exact execution occurrence.
- **Runtime PC:** jump to an executed code location.
- **Function:** jump to an observed invocation or entry.
- **Search:** locate instruction text, symbols or known strings.
- **History:** move backward/forward through prior navigation decisions.
- **Bookmark:** persist an investigation landmark in the trace index for recovery in a later session.

## Repeated execution and XRefs

The `xref` pass maps each PC to all matching instruction IDs. Execution count is observed frequency, not a static reachability estimate.

- **TUI:** `x` / `X` directly selects the next/previous XRef occurrence, moving among loop iterations, repeated calls or shared handlers while restoring exact state at each occurrence.
- **Desktop:** the Goto dialog uses the XRef index to resolve an address or function and jumps to its first matching occurrence. The current Web frontend has no direct previous/next XRef control or XRef result list equivalent to the TUI operation.

## Calls and returns

The function pass pairs observed calls and returns and reconstructs the dynamic call stack.

- **TUI:** direct **Follow Call** / **Follow Return** shortcuts jump to the dynamic callee's first instruction and the corresponding call site, respectively.
- **Desktop:** frames in the Call Stack panel are clickable and navigate to their call sites; the Functions panel lists discovered functions. The current Web frontend has no shortcut equivalent to the TUI Follow Call/Return operations.

## Breakpoints on a static timeline (TUI)

These operations are provided by the static-timeline `BreakpointEngine` wired into the TUI. The current Desktop instruction context menu cannot set breakpoints or watchpoints.

| Type | Match source | Best use |
|---|---|---|
| PC breakpoint | XRef PC→instruction IDs | Next/previous execution of code |
| Write watchpoint | Memory-write index | Find when a buffer or field changes |
| Conditional breakpoint | Predicate evaluated while scanning | Stop on a state-dependent event |

TUI forward/reverse continue selects the next/previous matching occurrence. Because no program executes, reverse continue needs no checkpoint restore or target replay.

## Value-oriented navigation

- **Register Timeline:** the backend `reg_timeline` pass records each register write's instruction location and before/after values; the TUI result view can display those old/new fields. The current Desktop RegTimeline panel instead plots and lists the current value at each sample, with click-to-navigate, and does not show a per-row old/new comparison.
- **Memory Write History:** all writes overlapping an address range.
- **Last Writer:** nearest earlier write contributing the selected byte/region.
- **Backward Taint:** transitive producer chain from a register sink.
- **Taint navigation:** move among propagation events after a taint run; the available entry point depends on the frontend.

## Runtime versus static addresses

UI navigation uses runtime addresses. When carrying an address to IDA or Ghidra, subtract `module_slide`; when bringing a static address back, add it.
