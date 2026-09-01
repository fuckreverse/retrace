---
title: Terminal UI
sidebar:
  order: 3
---

Use the TUI over SSH or on machines without a graphical session:

```bash
./tenet /path/to/trace.bin
```

With no analysis or service options, Tenet enters the interactive TUI by default. It shares backend analysis semantics and persisted state with Desktop, but their specific operation entry points and feature coverage are not identical.

## Workspace

The terminal layout provides instruction, register, memory, call-stack, function, string, thread, breakpoint and Hex Dump views. Goto, search, bookmarks, XRef navigation and taint navigation operate on the shared `inst_id` timeline.

Common controls include:

| Action | Key / command |
|---|---|
| Open Analysis Results | `A` |
| Next / previous XRef | `x` / `X` |
| Next / previous tainted instruction | `]` / `[` |
| Run forward taint | `t` |
| Run backward taint | `B` |
| Run loop analysis | `O` |
| Toggle Hex Dump | `H` |
| Search instructions / disassembly | `/` |
| Run a named pass | `:pass <name>` |
| List passes | `:passes` |
| Start the analysis workflow | `:analyze` |

The exact key legend is displayed in the active build; use it when a terminal or version remaps a key.

## Thread panel (multi-thread traces)

For traces recorded with multiple threads, the Thread panel lists every thread with its instruction count. `Enter` toggles a thread's selection; the instruction view filters to the selected set through the `thread_filter` pass. The XThread panel shows cross-thread dataflow — shared-memory handoffs between a writer thread and a reader thread, aggregated per address.

## Analysis Results

Press `A` to open a two-level browser:

1. **Catalog:** pass category, state, progress and one-line summary. `Enter` runs an unstarted/failed pass or opens a completed result; `R` forces a rerun.
2. **Details:** structured entries such as CFG blocks, pattern matches, ObjC messages, search hits or VM handlers. `Enter` jumps to entries with an instruction location; `Esc` returns to the catalog.

Every catalog pass has a browsable TUI result. Parameter-heavy queries are usually easier through commands or CLI, but their results use the same detail browser.

## Remote-session advice

- Keep the terminal large enough for simultaneous timeline and state panels.
- Let the first index build finish before disconnecting.
- Preserve the `<trace-file>.tenet/` persistence directory beside the trace file between sessions.
- Use bookmarks before closing; cursor and bookmarks persist.
- For long batch exports, prefer CLI so terminal rendering is not involved.
