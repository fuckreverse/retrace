---
title: Explore an execution
sidebar:
  order: 1
---

Interactive exploration answers a different question from batch analysis: not only “what was detected?” but “what was true at this exact moment?” Desktop and TUI share the same timeline, state models, pass results, bookmarks and navigation semantics.

## Start with the timeline

Select an instruction occurrence by `inst_id`. The main row combines its runtime PC, disassembly and memory accesses. Registers and memory panels follow the cursor and show state for that occurrence—not a static approximation.

## Move by evidence

| Goal | Navigation action |
|---|---|
| Revisit a location | Goto PC or instruction ID |
| Move among repeated executions | Previous/next XRef occurrence |
| Follow dynamic calls | Call stack, Follow Call, Follow Return |
| Find a value change | Register Timeline or memory write history |
| Stop on an event | PC breakpoint, write watchpoint, condition |
| Review an investigation | Back/forward history and bookmarks |
| Traverse taint evidence | Previous/next tainted instruction |

## Inspect state

- **Registers:** complete GPR state before/after the selected instruction, with read/write highlighting.
- **Memory:** recorded accesses, time-aware region reads, last writer and write history.
- **Hex Dump:** known and unknown bytes at a chosen address and time.
- **Call Stack:** dynamically reconstructed frames, including observed tail-call context.
- **Functions and CFG:** structures recovered from executed control flow.

## Trigger analysis in context

Use the instruction context menu or analysis controls to start forward/backward taint, XRef, CFG, memory snapshots and other passes from the current location. Results are cached and can be revisited without repeating the scan.

Choose [Desktop GUI](./desktop/) for visual multi-panel work, [TUI](./tui/) for terminal sessions, or review [Navigation and breakpoints](./navigation/) for precise movement.
