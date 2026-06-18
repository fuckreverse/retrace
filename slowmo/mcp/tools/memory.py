"""
Tools: regstate, memread, mem_write_history, memory_snapshot
"""

import json

from . import register_tools
from ..session import Session
from ..config import TIMEOUT_LIGHT, TIMEOUT_MEDIUM

_session: Session = None


def init(session: Session):
    global _session
    _session = session


# ─── Handlers ────────────────────────────────────────────────────────────────

def handle_regstate(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    inst_id = params["inst_id"]
    when = params.get("when", "before")

    args = [_session.current_trace, "-c", "-s", str(inst_id), "-n", "1", "-r"]
    result = _session.run_tenet(args)
    if result["returncode"] != 0:
        return {"error": f"Register state query failed: {result['stderr']}"}

    return {"inst_id": inst_id, "when": when, "output": result["stdout"]}


def handle_memread(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    addr = params["addr"]
    size = min(params.get("size", 16), 256)
    at_inst_id = params["at_inst_id"]

    args = [_session.current_trace, "--memread", addr, str(size), str(at_inst_id)]
    result = _session.run_tenet(args)
    if result["returncode"] != 0:
        return {"error": f"Memory read failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_mem_write_history(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    addr = params["addr"]
    size = min(params.get("size", 8), 16)

    args = [_session.current_trace, "--mem-history", addr, str(size)]
    result = _session.run_tenet(args)
    if result["returncode"] != 0:
        return {"error": f"Memory history query failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_memory_snapshot(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    inst_ids = params["inst_ids"]
    snapshot_size = params.get("snapshot_size", 64)

    args = [_session.current_trace]
    for iid in inst_ids:
        args.extend(["--memory-snapshot", str(iid)])
    args.extend(["--memory-snapshot-size", str(snapshot_size)])

    result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)
    if result["returncode"] != 0:
        return {"error": f"Memory snapshot failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


# ─── Schemas ─────────────────────────────────────────────────────────────────

SCHEMA_REGSTATE = {
    "name": "regstate",
    "description": (
        "Get the full register state at a specific instruction. Returns all 34 GPR "
        "values (x0-x28, fp, lr, sp, nzcv, pc) as they were BEFORE or AFTER that "
        "instruction executed."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "inst_id": {"type": "integer", "description": "Instruction ID to query register state at"},
            "when": {
                "type": "string",
                "enum": ["before", "after"],
                "description": "Get state before or after instruction executes",
                "default": "before"
            }
        },
        "required": ["inst_id"]
    }
}

SCHEMA_MEMREAD = {
    "name": "memread",
    "description": (
        "Read memory contents at a specific point in trace execution time. "
        "Returns the byte values and which instruction last wrote each byte. "
        "This is time-aware memory — you see memory as it was at that exact moment."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "addr": {"type": "string", "description": "Memory address to read (hex string, e.g. '0x16fdff200')"},
            "size": {"type": "integer", "description": "Number of bytes to read (1-256)", "default": 16},
            "at_inst_id": {"type": "integer", "description": "Read memory as it was at this instruction ID"}
        },
        "required": ["addr", "at_inst_id"]
    }
}

SCHEMA_MEM_WRITE_HISTORY = {
    "name": "mem_write_history",
    "description": (
        "Find all instructions that wrote to a given memory address. "
        "Returns a timeline of writes with inst_id, written value, and write size."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "addr": {"type": "string", "description": "Memory address to query (hex string)"},
            "size": {"type": "integer", "description": "Number of bytes (1-16)", "default": 8}
        },
        "required": ["addr"]
    }
}

SCHEMA_MEMORY_SNAPSHOT = {
    "name": "memory_snapshot",
    "description": (
        "Capture memory snapshots at specific instruction points. Shows the state "
        "of memory regions (stack, heap, arguments) at critical moments."
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
}

# ─── Registration ────────────────────────────────────────────────────────────

register_tools([
    (SCHEMA_REGSTATE, handle_regstate),
    (SCHEMA_MEMREAD, handle_memread),
    (SCHEMA_MEM_WRITE_HISTORY, handle_mem_write_history),
    (SCHEMA_MEMORY_SNAPSHOT, handle_memory_snapshot),
])
