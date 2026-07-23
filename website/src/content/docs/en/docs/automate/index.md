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
| [MCP and IDA](./mcp/) | LLM, IDE, and IDAPython integration | MCP HTTP plus instance-bound JSON WebSocket |
| [WebSocket](./websocket/) | Local IDA bridge or high-throughput frontends | Hub JSON-RPC or FlatBuffers, on separate endpoints |

## Quick start

```bash
# Batch analysis via CLI
./tenet trace.bin --pattern --algorithm-summary --export-cfg func.dot

# Start JSON-RPC server
./tenet trace.bin --rpc-port 4321

# Start MCP Hub for LLM and IDA integration (default: 127.0.0.1:10444)
./tenet trace.bin --mcp-hub
# IDA uses ws://127.0.0.1:10444/ws/<instance-id>

# Start the independent FlatBuffers WebSocket
./tenet trace.bin --ws-port 9090
```

All interfaces share the same session lock: only one process may own a given trace at a time. Results are cached and shared across interfaces.
