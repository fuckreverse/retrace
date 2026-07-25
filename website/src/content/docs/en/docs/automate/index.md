---
title: Automate analysis
sidebar:
  order: 1
---

Choose the narrowest interface that fits the integration. All interfaces share the same backend implementation and persistent pass cache.

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
./tenet trace.bin --rpc 4321
# Bare --rpc defaults to 127.0.0.1:0, letting the OS choose a free port

# Start MCP Hub for LLM and IDA integration (default: 127.0.0.1:10444)
./tenet trace.bin --mcp-hub
# IDA uses ws://127.0.0.1:10444/ws/<instance-id>

# Start the independent FlatBuffers WebSocket
./tenet trace.bin --ws-port 9090
```

These interfaces reuse the same backend implementation and can reuse the persistent pass cache; this does not mean that multiple processes can concurrently share one trace session. An exclusive session lock allows only one process to own a given trace at a time.
