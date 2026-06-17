#!/usr/bin/env python3
"""
tenet MCP Server — Model Context Protocol server for tenet trace analyzer.

Exposes tenet's analysis capabilities (taint propagation, CFG, pattern detection,
memory queries, register state, etc.) as MCP tools callable by LLMs.

Protocol: MCP 2024-11-05 (JSON-RPC 2.0 over stdio)
Dependencies: Python 3.9+ standard library only (zero external deps)

Usage:
    python3 tenet_mcp_server.py [--tenet-bin /path/to/tenet]

The server keeps a loaded trace session and dispatches tool calls to the
tenet binary, returning structured JSON results.
"""

import sys
import os
import json
import subprocess
import tempfile
from typing import Any, Optional
from pathlib import Path

# ─── Configuration ──────────────────────────────────────────────────────────

TENET_BIN = os.environ.get("TENET_BIN", "tenet")
SERVER_NAME = "tenet-trace-analyzer"
SERVER_VERSION = "0.1.0"
PROTOCOL_VERSION = "2024-11-05"

# Current session state
_current_trace: Optional[str] = None
_tenet_bin: str = TENET_BIN


def log(msg: str):
    """Log to stderr (visible to humans, invisible to MCP transport)."""
    print(f"[tenet-mcp] {msg}", file=sys.stderr, flush=True)


# ─── MCP Tool Definitions ──────────────────────────────────────────────────

TOOLS = [
    {
        "name": "trace_open",
        "description": (
            "Open a QBDI trace file (.bin) for analysis. Must be called before any "
            "other analysis tool. Returns trace metadata (architecture, instruction count, "
            "module info, file size)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the .bin trace file"
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "trace_info",
        "description": (
            "Get metadata about the currently loaded trace: architecture, instruction count, "
            "module base/slide, address range, flags (memory/nzcv/code/regdiff)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "disasm",
        "description": (
            "Disassemble instructions from the trace. Returns disassembly with PC, mnemonic, "
            "operands, register diffs, and memory accesses for each instruction."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "start_inst_id": {
                    "type": "integer",
                    "description": "Starting instruction ID (0-based index in trace)",
                    "default": 0
                },
                "count": {
                    "type": "integer",
                    "description": "Number of instructions to disassemble (max 500)",
                    "default": 50
                },
                "show_regs": {
                    "type": "boolean",
                    "description": "Include register state changes",
                    "default": True
                },
                "show_mem": {
                    "type": "boolean",
                    "description": "Include memory accesses",
                    "default": True
                }
            }
        }
    },
    {
        "name": "taint_forward",
        "description": (
            "Perform precise forward taint analysis using Triton semantic engine. "
            "Starting from a register (or memory address) at a specific instruction, "
            "trace data flow forward through the execution. Returns the complete "
            "propagation chain with each step's type (RegToReg, RegToMem, MemToReg, etc.), "
            "precise source/destination, and whether Triton resolved the semantics. "
            "This is EXACT taint — not pattern matching — it handles implicit operands, "
            "sub-register aliases, conditional execution, and SIMD lane operations correctly."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "reg_index": {
                    "type": "integer",
                    "description": (
                        "Register index to taint (0-28=x0-x28, 29=fp, 30=lr, 31=sp, 33=pc)"
                    )
                },
                "inst_id": {
                    "type": "integer",
                    "description": "Instruction ID to start taint from (0 = trace start)",
                    "default": 0
                },
                "mem_addrs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional memory addresses to taint (hex strings, e.g. '0x16fdff200')"
                },
                "stop_pcs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Stop taint propagation when reaching these PCs (hex strings)"
                },
                "max_width": {
                    "type": "integer",
                    "description": "Stop when taint spreads to more than N registers (explosion guard)",
                    "default": 0
                },
                "propagate_through_calls": {
                    "type": "boolean",
                    "description": "Whether to follow taint into function calls",
                    "default": True
                }
            },
            "required": ["reg_index"]
        }
    },
    {
        "name": "taint_backward",
        "description": (
            "Perform precise backward taint analysis (reverse data-flow). "
            "Starting from a register at a specific instruction (the 'sink'), walk "
            "backward to find all instructions that contributed to computing that value. "
            "Useful for answering 'where did this value come from?' with full "
            "memory-mediated dependencies resolved."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "sink_inst_id": {
                    "type": "integer",
                    "description": "Instruction ID where the value of interest is observed"
                },
                "sink_reg": {
                    "type": "integer",
                    "description": "Register index holding the value to trace backward"
                },
                "max_steps": {
                    "type": "integer",
                    "description": "Maximum backward walk steps (0 = unlimited)",
                    "default": 10000
                }
            },
            "required": ["sink_inst_id", "sink_reg"]
        }
    },
    {
        "name": "cfg_export",
        "description": (
            "Extract the Control Flow Graph from the trace. Returns the CFG as a DOT "
            "graph with annotated basic blocks (instruction ranges, hit counts). "
            "Uses Graphviz-compatible Sugiyama layout algorithm."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "format": {
                    "type": "string",
                    "enum": ["dot", "json"],
                    "description": "Output format: 'dot' for Graphviz DOT, 'json' for structured data",
                    "default": "json"
                }
            }
        }
    },
    {
        "name": "call_graph",
        "description": (
            "Build the full call graph from the trace execution. Returns all functions, "
            "their call relationships, and call counts. Detects tail calls."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "format": {
                    "type": "string",
                    "enum": ["dot", "json"],
                    "description": "Output format",
                    "default": "json"
                }
            }
        }
    },
    {
        "name": "pattern_scan",
        "description": (
            "Scan the trace for known patterns: cryptographic algorithms (AES, SHA256, SM3/4, "
            "HMAC, etc.), anti-debug techniques, obfuscation patterns (CFF, MBA, opaque "
            "predicates), and key schedule patterns. Each match has a confidence level "
            "(High/Medium/Low) and the instruction range where it was detected."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "strings_scan",
        "description": (
            "Discover all printable strings in traced memory. Returns strings with their "
            "addresses, encoding (ASCII/UTF8/UTF16), length, and cross-references "
            "(which instructions accessed them)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "constants_scan",
        "description": (
            "Extract all constants materialized via movz+movk instruction sequences in the "
            "trace. Identifies known cryptographic constants (SHA-256, AES, SM3, SM4, ChaCha20, "
            "TEA, Blowfish, etc.) and reports: the 64-bit value, destination register, "
            "instruction range, number of parts, and algorithm identification. Extremely useful "
            "for identifying which crypto algorithms are used without relying on symbol names."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "min_parts": {
                    "type": "integer",
                    "description": "Minimum movz+movk parts to report (1=include standalone movz, 2+=multi-part only)",
                    "default": 2
                }
            }
        }
    },
    {
        "name": "regstate",
        "description": (
            "Get the full register state at a specific instruction. Returns all 34 GPR "
            "values (x0-x28, fp, lr, sp, nzcv, pc) as they were BEFORE or AFTER that "
            "instruction executed."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "inst_id": {
                    "type": "integer",
                    "description": "Instruction ID to query register state at"
                },
                "when": {
                    "type": "string",
                    "enum": ["before", "after"],
                    "description": "Get state before or after instruction executes",
                    "default": "before"
                }
            },
            "required": ["inst_id"]
        }
    },
    {
        "name": "memread",
        "description": (
            "Read memory contents at a specific point in trace execution time. "
            "Returns the byte values and which instruction last wrote each byte. "
            "This is time-aware memory — you see memory as it was at that exact moment."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "addr": {
                    "type": "string",
                    "description": "Memory address to read (hex string, e.g. '0x16fdff200')"
                },
                "size": {
                    "type": "integer",
                    "description": "Number of bytes to read (1-256)",
                    "default": 16
                },
                "at_inst_id": {
                    "type": "integer",
                    "description": "Read memory as it was at this instruction ID"
                }
            },
            "required": ["addr", "at_inst_id"]
        }
    },
    {
        "name": "mem_write_history",
        "description": (
            "Find all instructions that wrote to a given memory address. "
            "Returns a timeline of writes with inst_id, written value, and write size. "
            "Useful for tracking buffer mutations over time."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "addr": {
                    "type": "string",
                    "description": "Memory address to query (hex string)"
                },
                "size": {
                    "type": "integer",
                    "description": "Number of bytes (1-16)",
                    "default": 8
                }
            },
            "required": ["addr"]
        }
    },
    {
        "name": "critical_path",
        "description": (
            "Compute the critical data-flow path: intersection of forward taint from a "
            "source and backward taint from a sink. This gives exactly the instruction "
            "sequence that transforms source data into the sink value — the minimal "
            "algorithm extraction. Extremely powerful for isolating crypto/encoding logic."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_reg": {
                    "type": "integer",
                    "description": "Source register index for forward taint"
                },
                "source_inst_id": {
                    "type": "integer",
                    "description": "Instruction ID where source value is defined"
                },
                "sink_reg": {
                    "type": "integer",
                    "description": "Sink register index for backward taint"
                },
                "sink_inst_id": {
                    "type": "integer",
                    "description": "Instruction ID where result is observed"
                }
            },
            "required": ["source_reg", "source_inst_id", "sink_reg", "sink_inst_id"]
        }
    },
    {
        "name": "search_pc",
        "description": (
            "Find all instructions at a given PC address. Returns a list of instruction IDs "
            "where execution visited this address, useful for locating function entries, "
            "loop headers, or specific code points."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "pc": {
                    "type": "string",
                    "description": "Program counter address (hex string, e.g. '0x100abc000')"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results",
                    "default": 100
                }
            },
            "required": ["pc"]
        }
    },
    {
        "name": "trace_diff",
        "description": (
            "Differential trace analysis: compare two instruction ranges within the same "
            "trace to find divergence points. Essential for algorithm reverse engineering — "
            "run the target with two different inputs and diff the execution to isolate "
            "input-dependent branches and value differences."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "a_start": {"type": "integer", "description": "Start inst_id of range A"},
                "a_end": {"type": "integer", "description": "End inst_id of range A"},
                "b_start": {"type": "integer", "description": "Start inst_id of range B"},
                "b_end": {"type": "integer", "description": "End inst_id of range B"}
            },
            "required": ["a_start", "a_end", "b_start", "b_end"]
        }
    },
    {
        "name": "loop_semantics",
        "description": (
            "Analyze loop semantics to identify round functions and crypto loops. "
            "Detects Feistel network structures, SPN (substitution-permutation) loops, "
            "and other cryptographic iteration patterns. Reports iteration counts, "
            "classifications, and confidence scores."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "symbol_annotation",
        "description": (
            "Generate human-readable symbol annotations for all PCs in the trace. "
            "Combines function names, loop info, constant identifications, and pattern "
            "matches into a unified annotation layer that makes disassembly output "
            "much more readable."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "memory_snapshot",
        "description": (
            "Capture memory snapshots at specific instruction points. Shows the state "
            "of memory regions (stack, heap, arguments) at critical moments — function "
            "entry/exit, before/after encryption rounds, etc. Solves the 'input data "
            "visibility' problem in trace analysis."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "inst_ids": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "List of instruction IDs to snapshot at"
                },
                "snapshot_size": {
                    "type": "integer",
                    "description": "Bytes per memory region in snapshot (default: 64)",
                    "default": 64
                }
            },
            "required": ["inst_ids"]
        }
    },
    {
        "name": "dataflow_graph",
        "description": (
            "Build a dataflow graph for a given instruction range. Shows how data flows "
            "between registers and memory through instructions. Output as DOT or JSON. "
            "Useful for visualizing algorithm structure and data dependencies."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "start_inst_id": {"type": "integer", "description": "Start of instruction range"},
                "end_inst_id": {"type": "integer", "description": "End of instruction range"},
                "format": {
                    "type": "string",
                    "enum": ["json", "dot"],
                    "description": "Output format",
                    "default": "json"
                }
            },
            "required": ["start_inst_id", "end_inst_id"]
        }
    },
    {
        "name": "algorithm_summary",
        "description": (
            "Generate a comprehensive algorithm summary report. Combines pattern detection, "
            "constant identification, loop semantics, function analysis, and call graph "
            "into a unified report that identifies which cryptographic or encoding "
            "algorithms are present, their locations, and confidence levels. Returns both "
            "structured JSON and a human-readable Markdown summary."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "objc_messages",
        "description": (
            "Analyze Objective-C message sends (objc_msgSend) recorded in the trace. "
            "Returns all ObjC method calls with class names, selectors, receiver addresses, "
            "call frequency by class, and hottest classes. Essential for iOS reverse "
            "engineering to understand which ObjC methods are being called."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]


# ─── Tool Execution ────────────────────────────────────────────────────────

def _run_tenet(args: list, timeout: int = 120) -> dict:
    """Run tenet CLI with given arguments and return parsed output."""
    cmd = [_tenet_bin] + args
    log(f"exec: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "tenet command timed out", "returncode": -1}
    except FileNotFoundError:
        return {"stdout": "", "stderr": f"tenet binary not found: {_tenet_bin}", "returncode": -1}


def _ensure_trace_loaded() -> Optional[dict]:
    """Check that a trace is loaded; return error response if not."""
    if _current_trace is None:
        return {"error": "No trace loaded. Call trace_open first."}
    return None


def handle_trace_open(params: dict) -> dict:
    global _current_trace
    path = params["path"]

    if not os.path.isfile(path):
        return {"error": f"File not found: {path}"}

    # Run tenet in batch mode to get trace info
    result = _run_tenet([path, "-c", "-n", "0", "-i"])
    if result["returncode"] != 0:
        return {"error": f"Failed to open trace: {result['stderr']}"}

    _current_trace = path

    # Parse the output for trace metadata
    info = _parse_trace_info(result["stdout"] + result["stderr"])
    info["status"] = "loaded"
    info["path"] = path
    return info


def handle_trace_info(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    result = _run_tenet([_current_trace, "-c", "-n", "0", "-i"])
    if result["returncode"] != 0:
        return {"error": f"Failed to get trace info: {result['stderr']}"}

    info = _parse_trace_info(result["stdout"] + result["stderr"])
    info["path"] = _current_trace
    return info


def handle_disasm(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    start = params.get("start_inst_id", 0)
    count = min(params.get("count", 50), 500)
    args = [_current_trace, "-c", "-s", str(start), "-n", str(count)]

    if params.get("show_regs", True):
        args.append("-r")
    if params.get("show_mem", True):
        args.append("-m")

    result = _run_tenet(args)
    if result["returncode"] != 0:
        return {"error": f"Disassembly failed: {result['stderr']}"}

    return {"disassembly": result["stdout"], "start_inst_id": start, "count": count}


def handle_taint_forward(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    reg_index = params["reg_index"]
    inst_id = params.get("inst_id", 0)
    args = [_current_trace, "--taint", str(reg_index), "--taint-inst", str(inst_id)]

    # Optional memory sources
    for addr in params.get("mem_addrs", []):
        clean_addr = addr.replace("0x", "").replace("0X", "")
        args.extend(["--taint-mem", clean_addr])

    # Optional stop PCs
    for pc in params.get("stop_pcs", []):
        clean_pc = pc.replace("0x", "").replace("0X", "")
        args.extend(["--taint-stop-pc", clean_pc])

    # Max width
    max_width = params.get("max_width", 0)
    if max_width > 0:
        args.extend(["--taint-max-width", str(max_width)])

    # Propagation flags
    if not params.get("propagate_through_calls", True):
        args.append("--taint-no-calls")

    result = _run_tenet(args, timeout=300)
    if result["returncode"] != 0:
        return {"error": f"Forward taint failed: {result['stderr']}"}

    # tenet outputs JSON for --taint
    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_taint_backward(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    sink_id = params["sink_inst_id"]
    sink_reg = params["sink_reg"]
    max_steps = params.get("max_steps", 10000)

    args = [_current_trace, "--backward-taint", str(sink_id), str(sink_reg)]
    if max_steps > 0:
        args.extend(["--backward-taint-max-steps", str(max_steps)])

    result = _run_tenet(args, timeout=300)
    if result["returncode"] != 0:
        return {"error": f"Backward taint failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_cfg_export(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    fmt = params.get("format", "json")
    ext = ".json" if fmt == "json" else ".dot"

    with tempfile.NamedTemporaryFile(suffix=ext, delete=False, mode="w") as f:
        tmp_path = f.name

    try:
        args = [_current_trace, "--export-cfg", tmp_path]
        result = _run_tenet(args, timeout=300)
        if result["returncode"] != 0:
            return {"error": f"CFG export failed: {result['stderr']}"}

        with open(tmp_path, "r") as f:
            content = f.read()

        if fmt == "json":
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                return {"dot": content, "format": "dot"}
        else:
            return {"dot": content, "format": "dot"}
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def handle_call_graph(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    fmt = params.get("format", "json")
    ext = ".json" if fmt == "json" else ".dot"

    with tempfile.NamedTemporaryFile(suffix=ext, delete=False, mode="w") as f:
        tmp_path = f.name

    try:
        args = [_current_trace, "--call-graph", tmp_path]
        result = _run_tenet(args, timeout=300)
        if result["returncode"] != 0:
            return {"error": f"Call graph failed: {result['stderr']}"}

        with open(tmp_path, "r") as f:
            content = f.read()

        if fmt == "json":
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                return {"dot": content, "format": "dot"}
        else:
            return {"dot": content, "format": "dot"}
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def handle_pattern_scan(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    args = [_current_trace, "--pattern"]
    result = _run_tenet(args, timeout=120)
    if result["returncode"] != 0:
        return {"error": f"Pattern scan failed: {result['stderr']}"}

    return _parse_pattern_output(result["stdout"] + result["stderr"])


def handle_strings_scan(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    args = [_current_trace, "--strings"]
    result = _run_tenet(args, timeout=120)
    if result["returncode"] != 0:
        return {"error": f"String scan failed: {result['stderr']}"}

    return _parse_strings_output(result["stdout"] + result["stderr"])


def handle_constants_scan(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    min_parts = params.get("min_parts", 2)
    args = [_current_trace, "--constants", "--constants-min-parts", str(min_parts)]
    result = _run_tenet(args, timeout=180)
    if result["returncode"] != 0:
        return {"error": f"Constants scan failed: {result['stderr']}"}

    return _parse_constants_output(result["stdout"] + result["stderr"])


def handle_regstate(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    inst_id = params["inst_id"]
    when = params.get("when", "before")

    # Use batch mode to show register state at the instruction
    args = [_current_trace, "-c", "-s", str(inst_id), "-n", "1", "-r"]
    result = _run_tenet(args)
    if result["returncode"] != 0:
        return {"error": f"Register state query failed: {result['stderr']}"}

    return {"inst_id": inst_id, "when": when, "output": result["stdout"]}


def handle_memread(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    addr = params["addr"]
    size = min(params.get("size", 16), 256)
    at_inst_id = params["at_inst_id"]

    args = [_current_trace, "--memread", addr, str(size), str(at_inst_id)]
    result = _run_tenet(args)
    if result["returncode"] != 0:
        return {"error": f"Memory read failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_mem_write_history(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    addr = params["addr"]
    size = min(params.get("size", 8), 16)

    args = [_current_trace, "--mem-history", addr, str(size)]
    result = _run_tenet(args)
    if result["returncode"] != 0:
        return {"error": f"Memory history query failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_critical_path(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    source_reg = params["source_reg"]
    source_inst = params["source_inst_id"]
    sink_reg = params["sink_reg"]
    sink_inst = params["sink_inst_id"]

    args = [
        _current_trace,
        "--taint", str(source_reg),
        "--taint-inst", str(source_inst),
        "--backward-taint", str(sink_inst), str(sink_reg),
        "--critical-path"
    ]

    result = _run_tenet(args, timeout=600)
    if result["returncode"] != 0:
        return {"error": f"Critical path failed: {result['stderr']}"}

    # tenet outputs multiple JSON blocks; take the last one (critical path)
    stdout = result["stdout"].strip()
    json_blocks = _extract_json_blocks(stdout)

    if json_blocks:
        try:
            return json.loads(json_blocks[-1])
        except json.JSONDecodeError:
            pass

    return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_search_pc(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    pc = params["pc"]
    limit = params.get("limit", 100)

    args = [_current_trace, "--search-pc", pc, str(limit)]
    result = _run_tenet(args)
    if result["returncode"] != 0:
        return {"error": f"PC search failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_trace_diff(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    a_start = params["a_start"]
    a_end = params["a_end"]
    b_start = params["b_start"]
    b_end = params["b_end"]

    args = [_current_trace, "--trace-diff",
            str(a_start), str(a_end), str(b_start), str(b_end)]
    result = _run_tenet(args, timeout=300)
    if result["returncode"] != 0:
        return {"error": f"Trace diff failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_loop_semantics(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    args = [_current_trace, "--loop-semantics"]
    result = _run_tenet(args, timeout=300)
    if result["returncode"] != 0:
        return {"error": f"Loop semantics failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_symbol_annotation(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    args = [_current_trace, "--symbol-annotation"]
    result = _run_tenet(args, timeout=300)
    if result["returncode"] != 0:
        return {"error": f"Symbol annotation failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_memory_snapshot(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    inst_ids = params["inst_ids"]
    snapshot_size = params.get("snapshot_size", 64)

    args = [_current_trace]
    for iid in inst_ids:
        args.extend(["--memory-snapshot", str(iid)])
    args.extend(["--memory-snapshot-size", str(snapshot_size)])

    result = _run_tenet(args, timeout=300)
    if result["returncode"] != 0:
        return {"error": f"Memory snapshot failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_dataflow_graph(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    start = params["start_inst_id"]
    end = params["end_inst_id"]
    fmt = params.get("format", "json")

    args = [_current_trace, "--dataflow-graph", str(start), str(end)]

    if fmt == "dot":
        with tempfile.NamedTemporaryFile(suffix=".dot", delete=False, mode="w") as f:
            tmp_path = f.name
        args.extend(["--dataflow-graph-output", tmp_path])
        try:
            result = _run_tenet(args, timeout=300)
            if result["returncode"] != 0:
                return {"error": f"Dataflow graph failed: {result['stderr']}"}
            with open(tmp_path, "r") as f:
                content = f.read()
            return {"dot": content, "format": "dot"}
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    else:
        result = _run_tenet(args, timeout=300)
        if result["returncode"] != 0:
            return {"error": f"Dataflow graph failed: {result['stderr']}"}
        try:
            return json.loads(result["stdout"])
        except json.JSONDecodeError:
            return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_algorithm_summary(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    args = [_current_trace, "--algorithm-summary"]
    result = _run_tenet(args, timeout=600)
    if result["returncode"] != 0:
        return {"error": f"Algorithm summary failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_objc_messages(params: dict) -> dict:
    err = _ensure_trace_loaded()
    if err:
        return err

    args = [_current_trace, "--objc"]
    result = _run_tenet(args, timeout=300)
    if result["returncode"] != 0:
        return {"error": f"ObjC analysis failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


# ─── Output Parsers ────────────────────────────────────────────────────────

def _parse_trace_info(output: str) -> dict:
    """Parse tenet's startup output into structured metadata."""
    info = {}
    for line in output.split("\n"):
        line = line.strip()
        if "Magic:" in line:
            info["magic"] = line.split(":", 1)[1].strip()
        elif "Version:" in line:
            info["version"] = line.split(":", 1)[1].strip()
        elif "Arch:" in line:
            info["arch"] = line.split(":", 1)[1].strip()
        elif "GPR count:" in line:
            info["gpr_count"] = int(line.split(":", 1)[1].strip())
        elif "Module:" in line and "module_name" not in info:
            info["module_name"] = line.split(":", 1)[1].strip()
        elif "Base:" in line:
            info["module_base"] = line.split(":", 1)[1].strip()
        elif "Slide:" in line:
            info["module_slide"] = line.split(":", 1)[1].strip()
        elif "Range:" in line:
            info["address_range"] = line.split(":", 1)[1].strip()
        elif "File size:" in line:
            info["file_size"] = line.split(":", 1)[1].strip()
        elif "Flags:" in line:
            info["flags"] = line.split(":", 1)[1].strip()
        elif "instructions" in line.lower() and "Done." in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "instructions," and i > 0:
                    try:
                        info["instruction_count"] = int(parts[i - 1])
                    except ValueError:
                        pass
                elif p == "anchors," and i > 0:
                    try:
                        info["anchor_count"] = int(parts[i - 1])
                    except ValueError:
                        pass
        elif "Loaded" in line and "distinct PCs" in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "distinct" and i > 0:
                    try:
                        info["distinct_pcs"] = int(parts[i - 1])
                    except ValueError:
                        pass
    return info


def _parse_pattern_output(output: str) -> dict:
    """Parse tenet --pattern tabular output into structured JSON."""
    matches = []
    in_table = False
    for line in output.split("\n"):
        line = line.strip()
        if "CATEGORY" in line and "CONFIDENCE" in line:
            in_table = True
            continue
        if in_table and line and not line.startswith("["):
            parts = line.split()
            if len(parts) >= 5:
                category = parts[0]
                confidence = parts[1]
                # Find pattern name (last element after the range)
                # Format: "Category  Confidence  #START - #END  PatternName"
                match_entry = {
                    "category": category,
                    "confidence": confidence,
                    "raw": line
                }
                # Try to extract inst range
                for j, p in enumerate(parts):
                    if p.startswith("#"):
                        try:
                            match_entry["start_inst_id"] = int(p.lstrip("#"))
                        except ValueError:
                            pass
                    if p == "-" and j + 1 < len(parts) and parts[j + 1].startswith("#"):
                        try:
                            match_entry["end_inst_id"] = int(parts[j + 1].lstrip("#"))
                        except ValueError:
                            pass
                # Pattern name is typically the last token
                if len(parts) > 4:
                    match_entry["pattern_name"] = parts[-1]
                matches.append(match_entry)
        elif line.startswith("[patterns]"):
            pass

    return {"matches": matches, "total": len(matches)}


def _parse_strings_output(output: str) -> dict:
    """Parse tenet --strings tabular output into structured JSON."""
    strings = []
    in_table = False
    for line in output.split("\n"):
        stripped = line.strip()
        if "ADDR" in stripped and "CONTENT" in stripped:
            in_table = True
            continue
        if in_table and stripped:
            parts = stripped.split('"')
            if len(parts) >= 2:
                content = parts[1] if len(parts) > 1 else ""
                meta = parts[0].split()
                entry = {
                    "content": content,
                    "addr": meta[0] if len(meta) > 0 else "",
                    "length": int(meta[1]) if len(meta) > 1 else 0,
                    "encoding": meta[2] if len(meta) > 2 else "",
                    "refs": int(meta[3]) if len(meta) > 3 else 0,
                }
                strings.append(entry)

    return {"strings": strings, "total": len(strings)}


def _parse_constants_output(output: str) -> dict:
    """Parse tenet --constants tabular output into structured JSON."""
    identified = []
    all_constants = []
    by_algorithm = {}
    total = 0
    identified_count = 0

    section = None  # track which section we're parsing
    for line in output.split("\n"):
        stripped = line.strip()

        if stripped.startswith("[constants]"):
            # Parse summary line
            import re
            m = re.search(r"Found (\d+) materialized constants \((\d+) identified", stripped)
            if m:
                total = int(m.group(1))
                identified_count = int(m.group(2))
            continue

        if "=== Identified Algorithm Constants ===" in stripped:
            section = "identified"
            continue
        elif "=== Summary by Algorithm ===" in stripped:
            section = "summary"
            continue
        elif "=== All Materialized Constants" in stripped:
            section = "all"
            continue

        if section == "identified" and stripped and not stripped.startswith("VALUE"):
            parts = stripped.split()
            if len(parts) >= 5 and parts[0].startswith("0x"):
                entry = {
                    "value": parts[0],
                    "register": parts[1],
                    "algorithm": parts[2],
                    "name": parts[3],
                    "inst_range": parts[4] if len(parts) > 4 else ""
                }
                identified.append(entry)

        elif section == "summary" and stripped and ":" in stripped:
            algo_parts = stripped.split(":")
            if len(algo_parts) == 2:
                algo_name = algo_parts[0].strip()
                count_str = algo_parts[1].strip().split()[0]
                try:
                    by_algorithm[algo_name] = int(count_str)
                except ValueError:
                    pass

        elif section == "all" and stripped and not stripped.startswith("VALUE") and not stripped.startswith("..."):
            parts = stripped.split()
            if len(parts) >= 5 and parts[0].startswith("0x"):
                known = " ".join(parts[5:]) if len(parts) > 5 else "-"
                entry = {
                    "value": parts[0],
                    "register": parts[1],
                    "parts": int(parts[2]) if parts[2].isdigit() else 0,
                    "inst_range": f"{parts[3]}-{parts[4]}" if len(parts) > 4 else "",
                    "known_as": known if known != "-" else None
                }
                all_constants.append(entry)

    return {
        "total": total,
        "identified_count": identified_count,
        "identified_constants": identified,
        "by_algorithm": by_algorithm,
        "constants": all_constants
    }


def _extract_json_blocks(text: str) -> list:
    """Extract complete JSON object blocks from text output."""
    blocks = []
    current = []
    depth = 0
    for line in text.split("\n"):
        if depth == 0 and "{" in line:
            current = [line]
            depth = line.count("{") - line.count("}")
        elif depth > 0:
            current.append(line)
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                blocks.append("\n".join(current))
                current = []
                depth = 0
    return blocks


# ─── Tool Dispatch ─────────────────────────────────────────────────────────

TOOL_HANDLERS = {
    "trace_open": handle_trace_open,
    "trace_info": handle_trace_info,
    "disasm": handle_disasm,
    "taint_forward": handle_taint_forward,
    "taint_backward": handle_taint_backward,
    "cfg_export": handle_cfg_export,
    "call_graph": handle_call_graph,
    "pattern_scan": handle_pattern_scan,
    "strings_scan": handle_strings_scan,
    "constants_scan": handle_constants_scan,
    "regstate": handle_regstate,
    "memread": handle_memread,
    "mem_write_history": handle_mem_write_history,
    "critical_path": handle_critical_path,
    "search_pc": handle_search_pc,
    "trace_diff": handle_trace_diff,
    "loop_semantics": handle_loop_semantics,
    "symbol_annotation": handle_symbol_annotation,
    "memory_snapshot": handle_memory_snapshot,
    "dataflow_graph": handle_dataflow_graph,
    "algorithm_summary": handle_algorithm_summary,
    "objc_messages": handle_objc_messages,
}


def handle_tools_call(params: dict) -> dict:
    """Handle tools/call requests."""
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})

    handler = TOOL_HANDLERS.get(tool_name)
    if not handler:
        return {
            "content": [{"type": "text", "text": json.dumps({"error": f"Unknown tool: {tool_name}"})}],
            "isError": True,
        }

    try:
        result = handler(arguments)
        text_content = json.dumps(result, ensure_ascii=False, indent=2)
        return {
            "content": [{"type": "text", "text": text_content}],
            "isError": False,
        }
    except Exception as e:
        return {
            "content": [{"type": "text", "text": json.dumps({"error": str(e)})}],
            "isError": True,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# JSON-RPC stdio transport (MCP 2024-11-05)
# ═══════════════════════════════════════════════════════════════════════════════


def process_message(msg: dict) -> Optional[dict]:
    """Process a single JSON-RPC message and return a response (or None for notifications)."""
    method = msg.get("method", "")
    msg_id = msg.get("id")  # None for notifications
    params = msg.get("params", {})

    # Notifications (no id) — no response expected
    if msg_id is None:
        if method == "notifications/initialized":
            log("Client initialized.")
        return None

    if method == "initialize":
        result = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": {"listChanged": False}
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
            },
        }
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    elif method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}

    elif method == "tools/call":
        result = handle_tools_call(params)
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    elif method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    else:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }


def main():
    """Main loop: read JSON-RPC messages from stdin, write responses to stdout."""
    global _tenet_bin

    # Parse CLI args
    import argparse
    parser = argparse.ArgumentParser(description="tenet MCP server")
    parser.add_argument("--tenet-bin", default=TENET_BIN,
                        help="Path to tenet binary")
    args = parser.parse_args()
    _tenet_bin = args.tenet_bin

    log(f"tenet-mcp server v{SERVER_VERSION} starting...")
    log(f"tenet binary: {_tenet_bin}")
    log(f"Protocol: MCP {PROTOCOL_VERSION}")
    log("Waiting for JSON-RPC messages on stdin...")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            error_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {e}"},
            }
            sys.stdout.write(json.dumps(error_resp) + "\n")
            sys.stdout.flush()
            continue

        response = process_message(msg)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()

    log("tenet-mcp server exiting.")


if __name__ == "__main__":
    main()
