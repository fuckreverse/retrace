---
title: MCP server
sidebar:
  order: 4
---

The Model Context Protocol (MCP) server allows LLM agents and IDE integrations to query analysis results, navigate the timeline, and trigger passes through a structured tool interface.

## Start the server

```bash
./tenet trace.bin --mcp-port 13337
```

Or start from a GUI session using **File → Start MCP Server**. The server uses the same session and pass results as the running GUI/TUI/CLI.

## Available tools

MCP tools mirror the JSON-RPC methods with additional metadata and structured parameter schemas:

### Session and trace

- `trace_info` — Trace metadata, format version, module information
- `list_passes` — Catalog of available passes with states
- `run_pass` — Run a named pass with optional parameters
- `pass_result` — Retrieve cached results for a completed pass
- `cancel_pass` — Cancel a running pass

### Navigation

- `goto_inst` — Jump to instruction ID
- `goto_pc` — Jump to runtime PC
- `set_breakpoint` / `set_watchpoint` — Set PC or memory breakpoints
- `list_breakpoints` — List active breakpoints

### State queries

- `get_registers` — GPR state at an instruction
- `get_memory` — Memory region at a point in time
- `get_hex_dump` — Raw byte dump
- `get_call_stack` — Dynamic call stack

### Analysis

- `taint_forward` / `taint_backward` — Taint analysis
- `cfg_export` — Export CFG as DOT
- `call_graph` — Export call graph
- `functions` / `find_function` — Function queries
- `xref` — XRef occurrences for a PC
- `strings` — Discovered strings
- `objc_messages` — ObjC message analysis
- `loops` — Loop information
- `algorithm_summary` — Algorithm candidates
- `pattern_results` — Pattern scan results
- `entropy_analysis` — Entropy measurement
- `mem_search` — Memory value/pattern search
- `vm_abstract` — VM handler analysis

### Address rebase

- `rebase_addr` — Convert between runtime and static addresses using the trace's `module_slide`. Use this instead of manual arithmetic when carrying addresses to/from IDA or Ghidra.

## Integration with IDA

Tenet's MCP server is designed to work alongside IDA's own MCP hub. A typical workflow:

1. Open the trace in Tenet with `--mcp-port`.
2. Open the same binary in IDA with its MCP server.
3. Use an MCP client (or IDE integration) that connects to both servers.
4. Query Tenet for dynamic evidence (taint, values, call stacks) at addresses obtained from IDA.
5. Use `rebase_addr` to translate between runtime (Tenet) and static (IDA) addresses.

## Limitations

- The MCP server requires an active Tenet process with an open trace.
- It shares the same session lock: only one process can own a trace at a time.
- Long-running passes return progress notifications; the client must handle these.
- Not all pass parameters are exposed through MCP; use JSON-RPC or CLI for fine-grained control.
