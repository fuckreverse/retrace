"""
Tools: trace_open, trace_info, disasm
"""

import os

from . import register_tools
from ..session import Session
from ..parsers import parse_trace_info
from ..config import TIMEOUT_LIGHT

# Module-level reference to the shared session (set by server.py at startup)
_session: Session = None


def init(session: Session):
    global _session
    _session = session


# ─── Handlers ────────────────────────────────────────────────────────────────

def handle_trace_open(params: dict) -> dict:
    path = params["path"]
    if not os.path.isfile(path):
        return {"error": f"File not found: {path}"}

    result = _session.run_tenet([path, "-c", "-n", "0", "-i"])
    if result["returncode"] != 0:
        return {"error": f"Failed to open trace: {result['stderr']}"}

    _session.current_trace = path
    info = parse_trace_info(result["stdout"] + result["stderr"])
    info["status"] = "loaded"
    info["path"] = path
    return info


def handle_trace_info(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    result = _session.run_tenet([_session.current_trace, "-c", "-n", "0", "-i"])
    if result["returncode"] != 0:
        return {"error": f"Failed to get trace info: {result['stderr']}"}

    info = parse_trace_info(result["stdout"] + result["stderr"])
    info["path"] = _session.current_trace
    return info


def handle_disasm(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    start = params.get("start_inst_id", 0)
    count = min(params.get("count", 50), 500)
    args = [_session.current_trace, "-c", "-s", str(start), "-n", str(count)]

    if params.get("show_regs", True):
        args.append("-r")
    if params.get("show_mem", True):
        args.append("-m")

    result = _session.run_tenet(args)
    if result["returncode"] != 0:
        return {"error": f"Disassembly failed: {result['stderr']}"}

    return {"disassembly": result["stdout"], "start_inst_id": start, "count": count}


# ─── Schemas ─────────────────────────────────────────────────────────────────

SCHEMA_TRACE_OPEN = {
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
}

SCHEMA_TRACE_INFO = {
    "name": "trace_info",
    "description": (
        "Get metadata about the currently loaded trace: architecture, instruction count, "
        "module base/slide, address range, flags (memory/nzcv/code/regdiff)."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {}
    }
}

SCHEMA_DISASM = {
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
}

# ─── Registration ────────────────────────────────────────────────────────────

register_tools([
    (SCHEMA_TRACE_OPEN, handle_trace_open),
    (SCHEMA_TRACE_INFO, handle_trace_info),
    (SCHEMA_DISASM, handle_disasm),
])
