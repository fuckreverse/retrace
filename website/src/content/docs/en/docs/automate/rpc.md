---
title: JSON-RPC server
sidebar:
  order: 3
---

The JSON-RPC server is a compact query interface for local scripts and tool integrations. Tenet opens one trace from the CLI when the process starts; after connecting, an RPC client queries that already-open trace.

## Starting the server

`--rpc` accepts `[[host:]port]`. The default endpoint is `127.0.0.1:0`; port `0` asks the OS to allocate a free port, and Tenet prints the effective endpoint to standard error.

```bash
./tenet trace.bin --rpc 4321
./tenet trace.bin --rpc 127.0.0.1:4321
./tenet trace.bin --rpc
```

RPC mode keeps the process running until it receives `SIGINT` or `SIGTERM`. The server uses IPv4 TCP and should normally remain bound to a loopback address rather than being exposed to an untrusted network.

## Protocol

The server uses JSON-RPC 2.0 over TCP. Every request and response is one line of JSON terminated by a newline (`\n`). Request IDs may be integers or strings; omitted `params` are treated as an empty object. The server handles client connections and requests sequentially and does not push progress notifications.

Request:

```json
{"jsonrpc":"2.0","id":1,"method":"get_reg","params":{"inst_id":42,"reg_name":"x0"}}
```

Response:

```json
{"jsonrpc":"2.0","id":1,"result":{"inst_id":42,"reg_name":"x0","value":"0x1234"}}
```

Numeric parameters accept a JSON number, a decimal string, or a hexadecimal string prefixed with `0x`. Result fields representing addresses and values are generally hexadecimal strings.

## Available methods

| Method | Parameters | Result and behavior |
|---|---|---|
| `ping` | None | Returns `{"pong": true}`. |
| `get_progress` | `kind?: string` | Returns a `tasks` snapshot, optionally filtered by `kind`. Each item contains `id`, `kind`, `label`, `phase`, `state`, `progress`, `completed`, `total`, `message`, `error`, and `revision`. |
| `get_stats` | None | Returns `inst_count`, `anchor_count`, `code_count`, `build_seconds`, `module_name`, `module_base`, `module_slide`, and `file_size`. The module base and slide are hexadecimal strings. |
| `get_reg` | `inst_id`, `reg_name?` | Returns `inst_id`, `reg_name`, and `value` before the specified instruction executes. `reg_name` defaults to `x0`; accepted names are `x0`–`x28`, `fp`/`x29`, `lr`/`x30`, `sp`, `nzcv`, and `pc`. An unknown name produces error `-32602`. |
| `get_regs` | `inst_id` | Returns `inst_id` and `regs`, containing all 34 AArch64 GPR values before the specified instruction. Keys use the canonical names `x0`–`x28`, `fp`, `lr`, `sp`, `nzcv`, and `pc`. |
| `read_mem` | `addr`, `size?`, `inst_id?` | Performs a time-aware memory read. `size` defaults to 16 and is capped at 4096; `inst_id` defaults to the trace instruction count. Returns `addr`, `size`, `inst_id`, the byte array `data`, the per-byte validity array `known`, and `known_count`. |
| `get_range` | `start?`, `end?` | Returns instruction rows in `[start,end)`. `start` defaults to 0, `end` to `start + 100`, and the requested ID range is capped at 1000. The result contains `rows`, `start`, and `end`; each row contains `inst_id`, `pc`, `reg_diffs`, and `mem_accesses`. |
| `get_xref` | `pc` | Obtains/runs the `xref` pass and returns `pc`, `inst_ids`, and the full `exec_count`; `inst_ids` is capped at 10,000 entries. If the pass is unavailable, the result contains an empty array, count 0, and a `warning`. |
| `get_cfg` | None | Requires a `PassManager`; obtains/runs the `cfg_layout` pass and returns annotated Graphviz `dot`. An unavailable manager or failed pass produces error `-32603`. |
| `get_call_graph` | None | Requires a `PassManager`; obtains/runs the call-graph pass and returns `nodes` and `edges`. Nodes contain `pc`, `name`, `is_root`, `calls_made`, and `calls_received`; edges contain `caller`, `callee`, and `call_count`. |
| `get_taint` | `inst_id?` | Requires a `PassManager` and an obtainable `taint` pass result. Returns `instructions_processed`, final `tainted_regs`, the full `step_count`, and up to 500 `steps`; a truncated result includes `steps_truncated: true`. Each step contains `inst_id`, `pc`, and `dst_reg`. The current implementation accepts `inst_id` (default 0) but does not use it to reconfigure the taint source. |

## Progress and analysis scope

The server does not emit progress events. Clients can poll `get_progress` for snapshots of current tasks.

RPC exposes only a limited surface for basic state, registers, memory, instruction ranges, XRefs, taint results, and graph queries. The process has already opened its trace at startup; RPC clients cannot switch or close it. For complete analysis workflows that actively run broader analyses—including additional taint workflows, CFG export, and algorithm identification—use the [MCP server](./mcp/).

## Integration patterns

- Connect with a TCP client that supports newline-delimited JSON, or a Python JSON-RPC client.
- Perform lightweight, structured local queries against the already-open trace.
- Bridge register, memory, XRef, and graph results into other tools.
- Leave full analysis automation to MCP while keeping RPC as a small query surface.
