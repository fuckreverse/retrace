"""
Tools: search_pc, trace_diff, objc_messages
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

def handle_search_pc(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    pc = params["pc"]
    limit = params.get("limit", 100)

    args = [_session.current_trace, "--search-pc", pc, str(limit)]
    result = _session.run_tenet(args)
    if result["returncode"] != 0:
        return {"error": f"PC search failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_trace_diff(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    a_start = params["a_start"]
    a_end = params["a_end"]
    b_start = params["b_start"]
    b_end = params["b_end"]

    args = [_session.current_trace, "--trace-diff",
            str(a_start), str(a_end), str(b_start), str(b_end)]
    result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)
    if result["returncode"] != 0:
        return {"error": f"Trace diff failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_objc_messages(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    args = [_session.current_trace, "--objc"]
    result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)
    if result["returncode"] != 0:
        return {"error": f"ObjC analysis failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


# ─── Schemas ─────────────────────────────────────────────────────────────────

SCHEMA_SEARCH_PC = {
    "name": "search_pc",
    "description": (
        "Find all instructions at a given PC address. Returns a list of instruction IDs "
        "where execution visited this address."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "pc": {"type": "string", "description": "Program counter address (hex string, e.g. '0x100abc000')"},
            "limit": {"type": "integer", "description": "Maximum number of results", "default": 100}
        },
        "required": ["pc"]
    }
}

SCHEMA_TRACE_DIFF = {
    "name": "trace_diff",
    "description": (
        "Differential trace analysis: compare two instruction ranges within the same "
        "trace to find divergence points. Essential for isolating input-dependent logic."
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
}

SCHEMA_OBJC_MESSAGES = {
    "name": "objc_messages",
    "description": (
        "Analyze Objective-C message sends (objc_msgSend) recorded in the trace. "
        "Returns all ObjC method calls with class names, selectors, receiver addresses, "
        "and call frequency."
    ),
    "inputSchema": {"type": "object", "properties": {}}
}

# ─── Registration ────────────────────────────────────────────────────────────

register_tools([
    (SCHEMA_SEARCH_PC, handle_search_pc),
    (SCHEMA_TRACE_DIFF, handle_trace_diff),
    (SCHEMA_OBJC_MESSAGES, handle_objc_messages),
])
