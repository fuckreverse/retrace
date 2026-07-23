---
title: WebSocket and streaming
sidebar:
  order: 5
---

Tenet provides two different WebSocket protocols. Choose the endpoint by client type; they are not wire-compatible.

| Endpoint | Protocol | Intended clients |
|---|---|---|
| `ws://127.0.0.1:10444/ws/<instance-id>` | JSON-RPC/MCP text frames | IDAPython and local interactive integrations |
| `ws://host:<port>` from `--ws-port` | Binary FlatBuffers | Web/Tauri frontends and high-throughput visualization |

## Hub JSON WebSocket

Start Tenet in Hub mode, or open a trace in the GUI, which joins the Hub automatically:

```bash
./tenet trace.bin --mcp-hub
```

Discover instance IDs over `http://127.0.0.1:10444/mcp`, then connect to:

```text
ws://127.0.0.1:10444/ws/<instance-id>
```

The URL binds the connection to one trace. Text frames carry the same JSON-RPC/MCP requests and responses used by `tools/call`. The endpoint supports ping/pong and close handling, validates RFC 6455 framing and UTF-8, rejects binary application messages, and limits payload size.

The Hub JSON endpoint is deliberately **loopback-only**. It is designed for local tools such as the [IDA Pro bridge](./mcp/#connect-ida-pro), not for direct exposure to a network. If the selected Worker exits, the Hub closes sessions bound to that instance so clients cannot continue querying stale state.

## FlatBuffers WebSocket

Start the independent binary service on an explicit port:

```bash
./tenet trace.bin --ws-port 9090
```

### Protocol

- **Transport:** WebSocket on the configured port.
- **Schema:** FlatBuffers (`.fbs` definitions in the Tenet source).
- **Encoding:** binary frames with no JSON parsing overhead.
- **Use case:** high-throughput frontend queries, analysis jobs, and visualization.

This service is separate from MCP Hub. Do not connect the IDAPython bridge or a JSON-RPC client to `--ws-port`, and do not send FlatBuffers messages to port `10444`.

## Streaming index

WebSocket transport is also distinct from `--streaming`. Streaming mode tails a growing trace and incrementally updates its index:

```bash
./tenet trace.bin --streaming
```

Use it to pre-build index data while capture is still active. It does not itself create either WebSocket endpoint.

## Operational boundaries

- Both WebSocket services require an active Tenet process with an open trace.
- Hub JSON sessions are instance-scoped and close when their Worker disappears.
- FlatBuffers schema stability is not guaranteed across versions; update custom clients with Tenet.
- Bound high-volume requests and debounce cursor updates in interactive clients.
