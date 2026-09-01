---
title: Command-line interface
sidebar:
  order: 2
---

The CLI runs analysis, exports data, and produces reports without an interactive session. Every batch analysis mode uses the same pass implementations as the terminal TUI and the Tauri sidecar/backend.

## Batch analysis

```bash
# Structure
./tenet trace.bin --export-cfg func.dot
./tenet trace.bin --call-graph cg.dot
./tenet trace.bin --symbol-annotation

# Taint
./tenet trace.bin --taint 0 --taint-inst 12000
./tenet trace.bin --backward-taint 58000 0
./tenet trace.bin --critical-path --taint 0 --backward-taint 58000 0

# Algorithms
./tenet trace.bin --pattern
./tenet trace.bin --constants
./tenet trace.bin --algorithm-summary
./tenet trace.bin --loop-semantics

# Memory and strings
./tenet trace.bin --strings
./tenet trace.bin --memory-strings
./tenet trace.bin --memread 0x16fdff200 32 50000
./tenet trace.bin --mem-history 0x16fdff200 32
./tenet trace.bin --memory-snapshot 5000

# Platform
./tenet trace.bin --objc
./tenet trace.bin --objc --objc-class NSString
./tenet trace.bin --syscall-intercept

# VM analysis (--vm-abstract requires at least one static hint)
./tenet trace.bin --vm-abstract --vm-hints hints.json
./tenet trace.bin --backward-taint 10000 0 --taint-source-annotation

# Trace tools (instruction-ID ranges)
./tenet trace.bin --trace-fold 10000 50000 --trace-fold-min-iter 3
./tenet trace.bin --trace-diff 10000 20000 30000 40000 --trace-diff-file other.bin
./tenet trace.bin --window-stats 0 100000 --window-stats-size 10000
./tenet trace.bin --reg-timeline 0 --reg-timeline-range 10000 50000
```

## Selecting passes explicitly

```bash
./tenet trace.bin --run-pass function --run-pass xref --run-pass cfg
```

Use `--run-pass` for fine-grained control when the convenience flags do not map to the desired pass set.

## Multi-thread analysis

```bash
# Thread summary and switch events
./tenet trace.bin --run-pass thread

# Restrict the instruction view to specific threads (comma-separated tids)
./tenet trace.bin --thread-filter 4711,4712

# Cross-thread handoffs through shared memory (writer → reader edges)
./tenet trace.bin --cross-thread-dataflow
```

`--thread-filter` builds a per-thread instruction bitmap; omit the tid list to build all bitmaps first and filter later. `--cross-thread-dataflow` scans the memory write history and reports each "thread A writes address X → thread B reads address X (no intervening write)" pair, aggregated by address into channels with producer→consumer statistics.

## Exclude ranges

```bash
./tenet trace.bin --exclude-range 0x1001000 0x1002000 --exclude-range 0x2001000 0x2002000
```

Exclude ranges filter instructions during analysis. They do not modify the trace file.

## External image

```bash
./tenet trace.bin --image /path/to/binary
```

## Interactive and service entry points

There is currently no `--tui` option. Running `./tenet trace.bin` without an analysis or service option enters the terminal TUI by default.

| Option | Behavior |
|---|---|
| `--rpc [[host:]port]` | Start TCP JSON-RPC; bare `--rpc` defaults to `127.0.0.1:0` (automatic port) |
| `--mcp` | Start MCP JSON-RPC over stdin/stdout until stdin closes |
| `--mcp-http [host:port]` | Start MCP Streamable HTTP, defaulting to `127.0.0.1:10444`; supports `--mcp-host`, `--mcp-port`, and `--mcp-auth` |
| `--mcp-hub [host:port]` | Start multi-instance Hub/Worker coordination, defaulting to `127.0.0.1:10444` |
| `--ws-port <port>` | Start the loopback-bound FlatBuffers WebSocket service; currently unavailable on Windows |
| `--streaming` | Tail a growing trace and build its index in real time |
| `--stats` | Print trace statistics as JSON |

The Tauri desktop application launches `tenet --ws-port <port> <trace> --mcp-hub` as a sidecar. Windows builds currently do not support `--ws-port`, but CLI, TUI, RPC, and MCP remain available.

## Output and reports

Most CLI modes print structured text to stdout. Graph exports (CFG, call graph, dataflow graph) write Graphviz DOT files. Profile supports JSON and CSV. Diff writes JSON. `--backward-taint-graph <file>` exports `.dot` or `.json`, selected by the filename extension.

## Headless considerations

- The CLI, terminal TUI, and Tauri sidecar/backend read and write the same `.tenet/` index and respect the same session lock.
- Long batch runs do not render a UI; they are faster than TUI for large exports.
- Pass results are cached; repeated runs with the same parameters complete quickly.
