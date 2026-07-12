---
title: WebSocket and streaming
sidebar:
  order: 5
---

The WebSocket server streams analysis results, trace events and state changes to remote clients in real time using a binary FlatBuffers protocol.

## Start the server

```bash
./tenet trace.bin --ws-port 9090
```

## Protocol

- **Transport:** WebSocket on the configured port.
- **Schema:** FlatBuffers (`.fbs` definitions in the Tenet source). Binary encoding, no JSON parsing overhead.
- **Direction:** Server pushes events; clients subscribe to topics.

## Event topics

| Topic | Content |
|---|---|
| `timeline` | Instruction cursor movement, navigation events |
| `pass_state` | Pass state changes (started, progress, completed, failed) |
| `analysis_result` | Structured pass results as they complete |
| `register_update` | Register value changes at the current cursor |
| `memory_update` | Memory region changes |
| `breakpoint` | Breakpoint/watchpoint hit events |

## Usage patterns

- **Live dashboard:** Build a web-based trace monitor that updates as analysis proceeds.
- **Remote collaboration:** Multiple clients connect to the same Tenet instance; all see the same cursor and results.
- **CI integration:** A CI job opens a trace, runs passes, streams results and exits.
- **Custom visualization:** Render CFG, taint graphs or memory heatmaps in a web UI using the streamed events.

## Connection lifecycle

1. Client connects to `ws://host:port`.
2. Client subscribes to one or more topics.
3. Server pushes events for subscribed topics.
4. Client can also send JSON-RPC requests on the same connection for interactive queries.
5. On disconnect, the server continues the session; the next client reconnects to the same state.

## Limitations

- WebSocket streaming requires an active Tenet process; it is not an offline API.
- FlatBuffers schema stability is not guaranteed across versions; clients may need updates when upgrading Tenet.
- High-frequency events (e.g., timeline cursor at every instruction) may need client-side throttling or debouncing.
