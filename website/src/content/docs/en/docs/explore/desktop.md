---
title: Desktop GUI
sidebar:
  order: 2
---

Tenet Desktop is the default Apple Silicon interface for long-form investigation. It combines immediate state views with asynchronous analysis windows without duplicating analysis logic.

## Main workspace

| View | What it shows |
|---|---|
| Instructions | `inst_id`, runtime PC, disassembly and recorded memory accesses |
| Registers | Current GPR values; green=read, red=write, yellow=read/write |
| Memory | Access type, address, value, Hex Dump and last writer |
| Call Stack | Dynamic frames at the cursor; jump to call site or function entry |
| Functions | Names/addresses, invocation counts, executed instructions, callers/callees |
| CFG | Executed basic blocks and edges with heat; click a block to navigate |
| Strings | Final-snapshot and time-aware discovered strings |
| Output | Filterable logs by level, subsystem and text |

The cursor is shared across views. Selecting a function, call frame, CFG block or analysis hit navigates the same instruction timeline.

## Navigation workflow

1. Select an instruction and compare register reads/writes.
2. Inspect recorded memory accesses and open a Hex Dump for pointers.
3. Use the Call Stack and Functions views to identify the containing behavior.
4. Move among repeated executions with XRef navigation.
5. Bookmark important sources, transformations and sinks.

## Analysis control

The **Analysis** window lists catalog passes by category with Not Run, Running, Completed or Failed states. Running passes expose progress and cancellation; completed results can be rerun after invalidating their cache.

Queries that require parameters use dedicated windows, including:

- Memory Search and YARA Memory Scan
- Register Timeline and Call Context
- Memory Snapshots and Entropy
- Dataflow Graph and Window Stats
- Trace Fold and Trace Diff
- VM Abstract / VM Workspace

Other dedicated result windows cover Patterns, Constants, Loop Semantics, Algorithm Summary, ObjC Messages, ObjC × Crypto, API Intercepts, Call Graph and CFG.

## Context actions

Right-click an instruction to run XRef, forward or backward taint, inspect producers, set a breakpoint/watchpoint, open CFG, copy addresses or jump to related evidence. Long analyses run asynchronously; the UI remains navigable and shutdown cancels active work safely.

## Symbols and missing code

The Symbol Info view can consume supported symbol exports. If the trace lacks some code bytes, reopen it with `--image` so disassembly and code-dependent passes can use the matching image as fallback.
