---
title: Analyze a trace
sidebar:
  order: 1
---

Tenet uses the same core and analysis passes across Desktop, TUI, CLI, RPC, and MCP entry points. Choose a topic below for the full guide.

## Guides

| Topic | Goal |
|---|---|
| [Recover program structure](./structure/) | Functions, CFG, XRefs, loops, call graph |
| [Taint and data flow](./taint/) | Forward taint, backward taint, critical path, dataflow graph |
| [Memory, strings and value search](./memory/) | Snapshots, search, entropy, YARA, string discovery |
| [Algorithm and pattern recognition](./algorithms/) | Pattern scan, constants, loop semantics, algorithm summary |
| [ObjC, syscalls and platform API](./platform/) | ObjC messages, system calls, C API intercepts |
| [Trace tools](./trace-tools/) | Fold, diff, profile, window stats |
| [Virtual machine analysis](./vmp/) | VM handler identification, dispatch recovery, state mapping |

## Quick reference

Every analysis is a pass. Default-on passes run automatically; others are started on demand. See the [Pass catalog](/en/docs/reference/pass-catalog/) for the complete list with CLI flags and dependencies.

## Analysis workflow

1. Open a trace and let default passes complete.
2. Inspect recovered functions, CFG and XRefs to locate the region of interest.
3. Run targeted passes: forward/backward taint, pattern, memory search.
4. Combine evidence: algorithm summary cross-references pattern + constant + loop + call-graph.
5. Export results: DOT graphs, JSON reports, profile data.
