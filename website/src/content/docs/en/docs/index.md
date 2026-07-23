---
title: Documentation
description: Choose a path through capture, exploration, analysis, and automation.
sidebar:
  order: 0
  label: Overview
---

Tenet connects focused on-device capture with reproducible offline analysis. Choose the path that matches your current goal.

## Start here

1. [Install Tenet](./getting-started/install/)
2. [Record a trace](./capture/) with QBDITrace or a compatible collector
3. [Open it](./getting-started/open-a-trace/) and verify the session

## Explore an execution

[Navigate the timeline](./explore/), inspect registers and memory at any moment, set breakpoints on a static history, and follow dynamic calls and returns. Available in [Desktop GUI](./explore/desktop/) and [TUI](./explore/tui/).

## Analyze a trace

- [Recover program structure](./analyze/structure/) — functions, CFG, XRefs, loops
- [Trace data flow](./analyze/taint/) — forward and backward taint, critical path
- [Inspect memory and strings](./analyze/memory/) — snapshots, search, entropy, YARA
- [Recognize algorithms](./analyze/algorithms/) — patterns, constants, loop semantics
- [Platform semantics](./analyze/platform/) — ObjC, syscalls, C API intercepts
- [Trace tools](./analyze/trace-tools/) — fold, diff, profile
- [Virtual machine analysis](./analyze/vmp/) — handler identification and dispatch recovery

## Automate an investigation

Use the [CLI](./automate/cli/) for batch jobs, [JSON-RPC](./automate/rpc/) for programmatic access, [MCP Hub and the IDA bridge](./automate/mcp/) for static/dynamic navigation and LLM integration, or the separate [WebSocket protocols](./automate/websocket/) for local JSON-RPC and high-throughput frontend access.

## Reference

- [Pass catalog](./reference/pass-catalog/) — every analysis pass, its CLI flag and dependencies
- [Compatibility and limits](./reference/compatibility/) — what each capability requires and how it degrades
- [Trace format](./reference/) — binary format specification for custom collectors

> Tenet Desktop analyzes trace files locally. The documentation website never receives your trace data.
