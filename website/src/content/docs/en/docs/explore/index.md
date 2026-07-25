---
title: Explore an execution
sidebar:
  order: 1
---

Interactive exploration answers a different question from batch analysis: not only “what was detected?” but “what was true at this exact moment?” The standalone Tauri desktop application (Desktop) and TUI use the same backend timeline, state model and persistence format. Bookmarks and the last cursor are stored in the trace's adjacent index directory and can be restored by a later session in either frontend. An exclusive session lock protects each trace, so Desktop and TUI cannot open it concurrently and synchronize their cursors in real time.

## Start with the timeline

Select an instruction occurrence by `inst_id`. A Desktop instruction row shows the runtime PC and disassembly; recorded reads and writes appear separately in the **Mem Access** panel. Registers, Mem Access, Hex Dump and other panels update with the cursor. The TUI is likewise centered on the instruction timeline and uses separate panels to inspect register and memory state. Both present trace state for the selected occurrence—not a static approximation.

## Move by evidence

| Goal | Navigation action | Frontend |
|---|---|---|
| Revisit a location | Goto PC or instruction ID | Desktop and TUI |
| Move among executions of the same PC | Previous/next XRef | Direct TUI operation; Desktop Goto selects only the first match |
| Follow dynamic calls | Call stack; Follow Call and Follow Return | Desktop has clickable call-stack frames; direct Follow shortcuts are TUI operations |
| Find a value change | Register Timeline or memory write history | Backend analysis; Desktop RegTimeline shows sampled values, while the TUI result can show old/new values |
| Stop on an event | PC breakpoint, write watchpoint or condition | TUI `BreakpointEngine` |
| Review an investigation | Back/forward history and bookmarks | Desktop and TUI; restored across sessions, not synchronized concurrently |
| Traverse taint evidence | Previous/next tainted instruction | Direct TUI operation |

## Inspect state

- **Registers:** GPR state at the selected instruction; exact before/after and read/write highlighting presentation depends on the frontend.
- **Memory / Mem Access:** recorded reads and writes for the current instruction; Desktop presents address, size and value in the separate Mem Access panel.
- **Hex Dump:** known and unknown bytes at a chosen address and time.
- **Call Stack:** dynamically reconstructed frames; Desktop frames are clickable and navigate to their call sites.
- **Functions and CFG:** structures recovered from executed control flow and browsed in their respective panels.

## Trigger analysis in context

The current Desktop instruction context menu is limited to navigating to the instruction, adding/removing a bookmark, starting forward taint with fixed source `x0`, opening the PC in Hex Dump, and copying the address or disassembly. Backward taint, XRef, CFG, breakpoints/watchpoints and Memory Snapshot are not direct options in that menu; use the corresponding Analysis panel or other available entry point to run those passes. Backend analysis results are cached and can be revisited in later sessions.

Choose the standalone [Tauri Desktop](./desktop/) for visual multi-panel work, [TUI](./tui/) for terminal sessions, or review [Navigation and breakpoints](./navigation/) for precise movement and frontend-specific boundaries.
