---
title: Automate analysis
sidebar:
  order: 1
---

Choose the narrowest interface that fits the integration. All interfaces use the same pass implementations and cached results.

## Interfaces

| Interface | Best for | Protocol |
|---|---|---|
| [CLI](./cli/) | Batch jobs, CI, file exports | Command-line flags and stdout |
| [JSON-RPC](./rpc/) | Programmatic access from scripts | JSON-RPC 2.0 over TCP |
| [MCP](./mcp/) | LLM and IDE integration | Model Context Protocol |
| [WebSocket](./websocket/) | Real-time dashboards, streaming | FlatBuffers over WebSocket |

## Quick start

```bash
# Batch analysis via CLI
./tenet trace.bin --pattern --algorithm-summary --export-cfg func.dot

# Start JSON-RPC server
./tenet trace.bin --rpc-port 4321

# Start MCP Hub for LLM integration (default: 127.0.0.1:10444)
./tenet trace.bin --mcp-hub

# Start WebSocket streaming
./tenet trace.bin --ws-port 9090
```

All interfaces share the same session lock: only one process may own a given trace at a time. Results are cached and shared across interfaces.
