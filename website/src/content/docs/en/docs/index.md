---
title: Documentation
description: Choose a path through capture, exploration, analysis, and automation.
sidebar:
  order: 0
  label: Overview
---

Tenet connects focused on-device capture with reproducible offline analysis. The Tenet backend targets Windows, Linux, and macOS on x86_64 and arm64. Because uSockets does not yet provide the required IOCP backend, Windows builds disable `TENET_ENABLE_WS` by default, so the separate Tauri desktop/Web frontend cannot currently connect to the Windows backend; CLI, TUI, RPC, and MCP remain available. Choose the path that matches your current goal.

## Start here

1. [Install Tenet](./getting-started/install/)
2. [Record a trace](./capture/) with QBDITrace or a compatible collector
3. [Open it](./getting-started/open-a-trace/) and verify the session

## Explore an execution

[Navigate the timeline](./explore/), inspect registers and memory at any moment, set breakpoints on a static history, and follow dynamic calls and returns. Use the separate [Tauri desktop/Web frontend](./explore/desktop/) or the [TUI](./explore/tui/); the `tenet` executable itself is a pure backend with no native GUI.

## Analyze a trace

- [Recover program structure](./analyze/structure/) — functions, CFG, XRefs, loops
- [Trace data flow](./analyze/taint/) — forward and backward taint, critical path
- [Inspect memory and strings](./analyze/memory/) — snapshots, search, entropy, YARA
- [Recognize algorithms](./analyze/algorithms/) — patterns, constants, loop semantics
- [Platform semantics](./analyze/platform/) — ObjC, syscalls, C API intercepts
- [Trace tools](./analyze/trace-tools/) — fold, diff, profile
- [Virtual machine analysis](./analyze/vmp/) — handler identification and dispatch recovery

## Automate an investigation

Use the [CLI](./automate/cli/) for batch jobs, [JSON-RPC](./automate/rpc/) for programmatic access, and [MCP Hub and the IDA bridge](./automate/mcp/) for static/dynamic navigation and LLM integration. There are two distinct [WebSocket channels](./automate/websocket/): the MCP Hub JSON WebSocket (`/ws/<instance-id>`) serves AI tools, IDA, and other clients, while the FlatBuffers binary WebSocket started by `--ws-port` is dedicated to high-throughput access from the Tauri desktop/Web frontend.

## Reference

- [Pass catalog](./reference/pass-catalog/) — every analysis pass, its CLI flag and dependencies
- [Compatibility and limits](./reference/compatibility/) — what each capability requires and how it degrades
- [Trace format](./reference/) — binary format specification for custom collectors

> Tenet Desktop is a separate Tauri application that launches and connects to a local `tenet --ws-port <port> <trace> --mcp-hub` backend as a sidecar; it is not a window built into the `tenet` binary. Trace files are analyzed locally, and the documentation website never receives your trace data.
