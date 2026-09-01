---
title: MCP server
sidebar:
  order: 4
---

Tenet's Model Context Protocol (MCP) server lets LLM agents and IDEs query traces, reconstruct state, run analyses, and verify conclusions through structured tools. Every entry point reuses the same `TraceReader`, index, pass pipeline, and result cache.

Tenet has two recommended entry points:

| Mode | Start with | Best for |
|---|---|---|
| stdio | `--mcp` | One client launching one Tenet process for one trace |
| MCP Hub | `--mcp-hub` | Automatic connection by backend sidecars launched by the Tauri desktop application, multiple open traces, and one stable endpoint |

## stdio: one trace

```bash
./tenet trace.bin --mcp
```

Tenet exchanges JSON-RPC messages over stdin/stdout and writes diagnostics to stderr. The process remains active until the client closes stdin.

Client configuration example:

```json
{
  "mcpServers": {
    "tenet": {
      "command": "/absolute/path/to/tenet",
      "args": [
        "/absolute/path/to/trace.bin",
        "--mcp"
      ]
    }
  }
}
```

Use absolute paths because an MCP client's working directory may differ from your terminal. Stdio is bound to one trace and does not require an `instance` argument.

## MCP Hub: stable endpoint and multiple instances

```bash
./tenet trace.bin --mcp-hub
```

The default endpoint is:

```text
http://127.0.0.1:10444/mcp
```

The bind address and instance name can be explicit:

```bash
./tenet trace.bin \
  --mcp-hub 127.0.0.1:10444 \
  --mcp-hub-name signing-trace
```

Client configuration example:

```json
{
  "mcpServers": {
    "tenet": {
      "url": "http://127.0.0.1:10444/mcp"
    }
  }
}
```

:::note[Port convention]
MCP Hub listens on **10444** by default; sidecars launched by the Tauri desktop application join the same Hub by default. You do not need a separate port for every trace.
:::

### How the Hub organizes traces

The first Tenet process to acquire `~/.tenet/mcp-hub.lock` becomes the Hub and listens on `10444`. Later processes become Workers and reverse-connect to it instead of opening public ports. The Hub:

- serves tools for its own trace;
- tracks every instance ID, PID, trace path, and module name;
- routes tool calls to the target instance;
- relies on `flock` to release election ownership automatically on exit.

Discover instances first:

```text
list_instances()
```

The default is **sessionless**, so every ordinary tool call must include `instance`:

```text
trace_info(instance="signing-trace")
get_regs(instance="signing-trace", inst_id=1200)
```

This prevents concurrent agents or sessions sharing the Hub from accidentally switching to another trace.

### Session mode

For clients that benefit from a default instance:

```bash
./tenet trace.bin --mcp-hub --mcp-hub-session
```

Select it once:

```text
select_instance(instance="signing-trace")
```

Subsequent ordinary calls may omit `instance`. `list_instances` is available in both modes; `select_instance` is registered only in session mode.

### Tauri sidecar behavior

The Tauri desktop application starts one `tenet` sidecar with `--mcp-hub` for each trace window. The first sidecar to acquire the platform file lock becomes the Hub; the remaining sidecars reverse-connect as Workers. The default remains `127.0.0.1:10444`, with sessionless routing. A client normally needs only one connection to `10444`, regardless of how many Tauri desktop windows are open.

## Connect IDA Pro

Tenet includes an IDAPython bridge that keeps static disassembly and the dynamic trace cursor connected through the Hub.

### Install the plugin

Copy the entry point and its Python package into IDA's user plugin directory:

```bash
cp tools/tenet/python/tenet_ida.py ~/.idapro/plugins/
cp -R tools/tenet/python/tenet ~/.idapro/plugins/
```

If your IDA user directory differs, use the directory reported by IDA for user plugins. Restart IDA and open the matching binary. After the Tenet backend starts that trace with `--mcp-hub`, or the Tauri desktop application launches its sidecar, run the **Tenet: Connect** plugin action. An ordinary TUI/CLI session without `--mcp-hub` does not automatically provide a Hub.

The plugin exposes four actions:

- **Tenet: Connect** — discover Hub instances, prefer a module-name match for the current IDB, and open the instance WebSocket;
- **Tenet: Disconnect** — close the session and stop synchronization;
- **Tenet: Toggle Sync** — enable or pause two-way cursor synchronization;
- **Tenet: Show Current Registers** — reconstruct and display registers at the active Tenet instruction.

### What is synchronized

The bridge discovers instances over `http://127.0.0.1:10444/mcp`, then connects to:

```text
ws://127.0.0.1:10444/ws/<instance-id>
```

This endpoint carries JSON-RPC/MCP text messages and is bound to one trace instance. On connect, the plugin sets Tenet's image base to the current IDB image base.

- Moving the Tenet cursor jumps IDA to the corresponding static address.
- Moving in IDA calls `search_pc` and navigates Tenet to the execution nearest the current trace cursor. This avoids jumping to an unrelated loop iteration when one PC executed many times.
- A Worker disconnect closes its bound WebSocket session. The plugin stops synchronization, reports the disconnect, and remains reconnectable.
- Hub WebSocket access is loopback-only. It is separate from the FlatBuffers service started by `--ws-port`.

:::tip[Multiple traces]
Open multiple Tauri desktop windows/traces; the Tenet sidecar for each window registers as either the Hub or a Worker. The plugin compares the current IDB input filename with each instance's module name, then falls back to the trace filename and finally the first available instance.
:::

## Start with three tools

After connecting, establish context in this order:

1. `list_instances` (Hub) — choose the target trace;
2. `trace_info` — confirm module, format version, instruction count, slide, and address range;
3. `disasm` / `search_pc` / `get_regs` — ground the question in a concrete execution point and state.

Do not start every expensive analysis immediately. Narrow the PC or `inst_id` range before running taint, graph, or VM queries.

## Tool catalog

Tool schemas are the authoritative parameter reference. Clients should use MCP `tools/list` to discover what the current build actually provides. The current interfaces are grouped below by purpose.

### Trace, instructions, and state

| Tool | Purpose |
|---|---|
| `trace_info` | Trace format, module, addresses, flags, and instruction statistics |
| `disasm` | Page through executed instructions, register diffs, and memory accesses |
| `get_regs` | Reconstruct all 34 AArch64 GPRs by `inst_id` or PC |
| `memread` | Time-travel memory read at an instruction |
| `mem_write_history` | Query historical writes to an address range |
| `search_pc` | O(1) lookup of executions for a PC; `nearest_to_inst_id` selects the closest occurrence independently of pagination |
| `reg_timeline` | Timeline of register value changes |
| `call_context` | Dynamic call context at an instruction |

### Data flow and graphs

| Tool | Purpose |
|---|---|
| `taint_forward` | Forward taint; uses Triton when available and otherwise falls back to heuristics |
| `taint_backward` | Trace data dependencies backward from a sink |
| `critical_path` | Intersection of forward and backward taint |
| `cfg_export` | Export the executed CFG as JSON or DOT |
| `call_graph` | Export the dynamic call graph as JSON or DOT |
| `dataflow_graph` | Export data flow for a bounded instruction range |

### Multi-thread

| Tool | Purpose |
|---|---|
| `threads` | Thread summary and switch events for multi-thread traces |
| `thread_filter` | Restrict the instruction view to a set of thread ids (rebuilds the pass with the new selection) |
| `cross_thread_dataflow` | Shared-memory handoffs between threads: writer→reader edges, aggregated into channels with producer→consumer statistics (paginated via `edge_offset`/`edge_limit`/`channel_limit`) |

### Structure, patterns, and platform semantics

| Tool | Purpose |
|---|---|
| `functions` / `find_function` | Enumerate or locate execution-backed functions |
| `loops` / `loop_semantics` | Loop structure and algorithm-semantic classification |
| `xref` | PC cross-reference and hotness statistics |
| `pattern_scan` / `constants_scan` | Crypto, anti-analysis, obfuscation patterns and materialized constants |
| `algorithm_summary` | Summarize algorithm candidates and evidence |
| `strings_scan` / `memory_strings` | Scan write history or point-in-time memory for strings |
| `mem_search` / `yara_mem_scan` | Value, byte-pattern, and YARA memory search |
| `memory_snapshot` / `entropy_analysis` | Memory snapshots and entropy measurement |
| `objc_messages` / `objc_crypto` | Objective-C messages and crypto context |
| `syscall_intercept` | CommonCrypto, BoringSSL, JNI, and other boundary calls |
| `symbol_annotation` | Aggregate function, loop, constant, and pattern labels for PCs |
| `taint_source_annotation` | Add source semantics to backward-taint leaves |
| `trace_fold` / `trace_diff` | Fold repeated execution or compare ranges/traces |
| `window_stats` | Page through instruction-window statistics |

### VM analysis

| Tool | Purpose |
|---|---|
| `vm_abstract` | Build a VM abstraction from IDA/Ghidra hints |
| `vm_summary` | Overview of dispatcher, architecture, and handler hotness; requires an existing `vm_abstract` result |
| `vm_steps_query` | Filter VM steps by opcode, VM-PC, label, or register change; requires an existing `vm_abstract` result |
| `vm_reg_timeline` | Timeline of a virtual register's values; requires an existing `vm_abstract` result |
| `vm_backward_slice` | Step-level backward slice for a virtual register; requires an existing `vm_abstract` result |

`vm_abstract` does not detect a VM without hints. See [Virtual machines and code virtualization](/en/docs/analyze/vmp/) for the input contract.

### Evidence and hypotheses for agents

| Tool | Purpose |
|---|---|
| `batch_query` | Run up to 20 independent queries in one round trip |
| `verify_evidence` | Validate referenced PCs, instructions, registers, or memory evidence |
| `hypothesis_add` | Create a hypothesis to investigate |
| `hypothesis_evidence` | Attach supporting/opposing evidence and verification state |
| `hypothesis_conclude` | Confirm a hypothesis when verified evidence exists |
| `hypothesis_abandon` | Abandon a disproven hypothesis |
| `hypothesis_list` / `hypothesis_get` | Enumerate or inspect the hypothesis ledger |
| `hypothesis_mark_reviewed` | Record human review state |

Prefer the sequence “hypothesis → query → `verify_evidence` → conclusion.” Do not treat an analysis tool's candidate result as a proven fact.

## Address space and IDA integration

By default, MCP converts PCs to the address style commonly displayed by IDA for AArch64 Mach-O:

```text
displayed_pc = runtime_pc - module_slide + image_base
image_base = 0x100000000
```

An IDA address such as `0x10001A2E4` can therefore usually be passed directly to `search_pc`, and Tenet results can be carried back into IDA unchanged.

For another address style, call:

```text
set_image_base(image_base="0x0")
```

- `0x100000000`: default IDA displayed addresses;
- `0x0`: slide-relative static offsets;
- `module_slide`: raw runtime addresses.

`set_image_base` affects every subsequent PC input and output. Do not continue passing PCs from the previous address space after changing it.

A typical workflow is:

1. locate a static function, dispatcher, or suspicious call site in IDA;
2. use `search_pc` to confirm that it actually executed;
3. use the returned `inst_id` with `disasm`, `get_regs`, `memread`, or taint tools;
4. validate the static hypothesis with Tenet's dynamic evidence;
5. for VM analysis, place IDA addresses in a hints JSON file and call `vm_abstract`.

## Performance, capability, and security boundaries

- Large results are paginated. Bound the range instead of repeatedly requesting the full trace.
- `batch_query` combines at most 20 queries; use it for bounded parallel reads, not unbounded expensive analyses.
- `taint_forward`, `taint_backward`, and `critical_path` use Triton when enabled and fall back to heuristic semantics otherwise.
- `yara_mem_scan` requires a build with YARA enabled.
- Tenet currently analyzes traces with single-thread semantics.
- Hub Worker forwarding has a timeout; reduce the analysis range before retrying a long request.
- Hub binds only to `127.0.0.1` by default and provides no authentication or TLS. Do not expose `0.0.0.0:10444` to an untrusted network; use a controlled tunnel or access layer for remote use.
- MCP requires an active Tenet process with an open trace. Rediscover instances after a process exits.
