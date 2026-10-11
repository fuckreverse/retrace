---
title: Desktop GUI
sidebar:
  order: 2
---

Tenet Desktop is a standalone Tauri application in `slowmo/web/`, not a native GUI embedded in the `tenet` executable. When a trace is opened, the app launches the headless `tenet` backend as a sidecar with arguments that include `--ws-port <port> <trace> --mcp-hub`. The React frontend accesses the backend over WebSocket using the FlatBuffers binary protocol, while MCP Hub also provides instance coordination for external tools.

Desktop currently supports macOS and Linux. The Windows backend disables `TENET_ENABLE_WS` by default because the uSockets event loop used by the project does not yet have an IOCP backend; consequently, Tauri Desktop cannot currently connect to the Windows `tenet` backend.

## Main workspace

The interface is organized into `SidebarLeft`, `CenterArea`, and `SidebarRight`, with a shared timeline and status bar below them.

| Area | Current views | What they show |
|---|---|---|
| Left sidebar | Functions, Strings | Filtering and sorting for discovered functions, plus string-analysis results |
| Center top | Instructions, CFG, Strings, Reg Timeline, Dataflow | The searchable instruction timeline, control-flow graph, strings, register timeline, and dataflow graph |
| Center bottom | Analysis, Call Stack, and analysis-result tabs | The pass controller, current call stack, and views for Patterns, Algorithms, Constants, Loops, API Intercepts, ObjC, Call Graph, taint, memory search, Entropy, YARA, Trace Fold/Diff, Snapshots, Threads / XThread Data (multi-thread), DWARF, VM Workspace, Cache, Log, Settings, and more |
| Right sidebar | Registers, Hex Dump, Mem Access | GPR/NZCV state before the current instruction, an addressable hexadecimal memory view, and memory reads/writes recorded for the current instruction |

The navigation position is shared through the frontend store. Selecting an instruction, call frame, or analysis result with an instruction location updates related panels around the same `inst_id`. The toolbar, timeline, and Navigate menu also provide back/forward history, first/last jumps, Go to, search, and bookmarks.

## Navigation workflow

1. Select an instruction in **Instructions** to inspect its runtime PC, disassembly, and search matches.
2. Use **Registers** to compare current values, writes, and changes from the neighboring instruction.
3. Inspect recorded reads and writes in **Mem Access**, then send an address or register value to **Hex Dump**.
4. Add behavioral context with **Call Stack**, **Functions**, **CFG**, and the analysis-result tabs.
5. Bookmark important sources, transformations, and sinks. Use the TUI when you need XRef previous/next, Follow Call/Return, breakpoints, or watchpoints.

## Analysis control

**Analysis** is a tab in the lower center area. It groups the backend pass catalog into Structure, Taint, Crypto-Pattern, Memory-String, ObjC-Platform, Profile-Trace, and Misc categories, and reports Not Run, Running, Completed, or Failed states.

A running pass shows its phase message and percentage progress. Passes that are not running can be started or rerun with the play/rerun control; completed entries display the rerun control. **Clear All** clears analysis state and results. The current panel has no per-task cancel action, so progress reporting should not be interpreted as cancellation support.

Parameterized or specialized features live in their corresponding tabs, including Memory Search, YARA, Entropy, Register Timeline, Dataflow, Backward Taint, Trace Fold, Trace Diff, and VM Workspace. Results such as Patterns, Constants, Loops, Algorithms, ObjC, ObjC×Crypto, API Intercepts, and Call Graph are also shown as tabbed panels rather than separate pop-up windows by default. At present, only **VM Workspace** is explicitly exposed through an “Open in New Window” menu item.

For multi-thread traces, the **Threads** tab lists every thread with its instruction count and switch events — selecting threads filters the instruction view through the `thread_filter` pass. The **XThread Data** tab shows cross-thread dataflow: shared-memory handoffs between a writer thread and a reader thread, aggregated per address into channels with producer→consumer statistics.

## Context actions

The current **Instructions** context menu contains only:

- Navigate Here
- Add Bookmark / Remove Bookmark
- Taint Forward (x0)
- Open PC in Hex Dump
- Copy Address
- Copy Disassembly

The **Registers** context menu can send a register value to Hex Dump or copy that value. Start XRef, backward taint, and other analyses from **Analysis** or the corresponding result tabs. Interactions such as XRef previous/next, Follow Call/Return, breakpoints, and write watchpoints are currently provided mainly by the TUI and should not be assumed to exist in the Desktop instruction context menu.

## Symbols and missing code

The **DWARF / Symbol Info** tab displays file, line, function, and variable information returned by the backend.

If a trace does not embed the required code bytes, the backend CLI accepts `--image <path>` to load a matching image for disassembly and code-dependent analysis fallback. `--image` is a command-line argument supplied when starting the `tenet` backend. The current Tauri open-trace flow passes WebSocket, trace, and MCP Hub arguments to the sidecar, but does not expose an in-app image picker or a “reopen with `--image`” action. Use an explicit CLI workflow with `--image` when that fallback is required.
