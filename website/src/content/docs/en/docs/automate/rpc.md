---
title: JSON-RPC server
sidebar:
  order: 3
---

The JSON-RPC server exposes all analysis capabilities over a standard protocol. Start it alongside any open trace:

```bash
./tenet trace.bin --rpc-port 4321
```

Or start from a GUI session using **File → Start RPC Server**.

## Protocol

JSON-RPC 2.0 over TCP. Each request is a single JSON object; each response is a single JSON object. Notifications (no `id`) are supported for progress events.

## Core methods

| Method | Description |
|---|---|
| `open_trace` | Open a trace file by path |
| `close_trace` | Close the current trace |
| `trace_info` | Get metadata and session status |
| `list_passes` | List available passes and their states |
| `run_pass` | Run a pass by name with optional parameters |
| `pass_result` | Retrieve cached pass results |
| `cancel_pass` | Cancel a running pass |

## State queries

| Method | Description |
|---|---|
| `get_registers` | Register values at an instruction ID |
| `get_memory` | Memory region at an instruction ID |
| `get_hex_dump` | Raw bytes at an address and time |
| `get_call_stack` | Dynamic call stack at an instruction ID |
| `get_functions` | List observed functions |
| `get_xrefs` | XRef occurrences for a PC |

## Navigation

| Method | Description |
|---|---|
| `goto_inst` | Jump to instruction ID |
| `goto_pc` | Jump to runtime PC |
| `set_breakpoint` | Set a PC breakpoint |
| `set_watchpoint` | Set a memory write watchpoint |
| `list_breakpoints` | List active breakpoints/watchpoints |

## Analysis shortcuts

| Method | Description |
|---|---|
| `taint_forward` | Run forward taint |
| `taint_backward` | Run backward taint |
| `cfg_export` | Export CFG as DOT |
| `call_graph` | Export call graph as DOT |
| `functions` | List/search functions |
| `find_function` | Find a function by name or address |
| `strings` | List discovered strings |
| `objc_messages` | List ObjC messages |
| `loops` | List loops |
| `algorithm_summary` | Get algorithm candidates |
| `pattern_results` | Get pattern scan results |
| `entropy_analysis` | Run entropy analysis |
| `mem_search` | Search memory |
| `vm_abstract` | Run VM abstract analysis |

## Progress and cancellation

Long-running analyses emit progress notifications. Cancel with `cancel_pass`. Results remain cached after cancellation at the last completed checkpoint.

## Integration patterns

- Connect from a Python script using a JSON-RPC client library.
- Automate repetitive analysis: open, run passes, export, close.
- Bridge to other tools that need structured analysis results.
- Pair with the MCP server for LLM-based analysis workflows.
