"""
Tool: mem_pattern_search — search for byte patterns in memory write history.
"""

import json

from . import register_tools
from ..session import Session
from ..config import TIMEOUT_MEDIUM

_session: Session = None


def init(session: Session):
    global _session
    _session = session


# ─── Handler ─────────────────────────────────────────────────────────────────

def handle_mem_pattern_search(params: dict) -> dict:
    """Search for byte patterns in the trace's memory writes or register values."""
    err = _session.ensure_trace_loaded()
    if err:
        return err

    pattern = params["pattern"]
    search_in = params.get("search_in", "memory_writes")
    start = params.get("start_inst_id", 0)
    end = params.get("end_inst_id")
    max_results = params.get("max_results", 20)

    # Try native CLI command
    args = [_session.current_trace, "--mem-search", pattern]
    args.extend(["--mem-search-in", search_in])
    args.extend(["--mem-search-start", str(start)])
    if end is not None:
        args.extend(["--mem-search-end", str(end)])
    args.extend(["--mem-search-max", str(max_results)])

    result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)
    if result["returncode"] == 0:
        try:
            return json.loads(result["stdout"])
        except json.JSONDecodeError:
            return {"raw_output": result["stdout"]}

    # Fallback: inform that the CLI feature is not yet available
    return {
        "error": "mem_pattern_search requires tenet CLI --mem-search support (not yet built)",
        "suggestion": (
            "This tool requires a C++ implementation in tenet. For now, use "
            "mem_write_history on suspected addresses, or strings_scan / constants_scan "
            "to locate known byte patterns."
        ),
        "pattern": pattern,
        "search_in": search_in
    }


# ─── Schema ──────────────────────────────────────────────────────────────────

SCHEMA_MEM_PATTERN_SEARCH = {
    "name": "mem_pattern_search",
    "description": (
        "Search for byte patterns in the trace's memory write history or register "
        "values. Use to locate when/where a specific byte sequence (key, IV, ciphertext, "
        "magic bytes) first appears in memory. Supports hex patterns with ?? wildcards. "
        "Examples: '48656C6C6F' (literal 'Hello'), 'AE??CF??01' (with wildcards). "
        "NOTE: Requires tenet CLI --mem-search support. If unavailable, use "
        "mem_write_history on suspected addresses as a workaround."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "pattern": {
                "type": "string",
                "description": "Hex byte pattern, ?? for wildcards. E.g. '48656C6C6F' or 'AE??CF??01'"
            },
            "search_in": {
                "type": "string",
                "enum": ["memory_writes", "register_values", "both"],
                "description": "Where to search",
                "default": "memory_writes"
            },
            "start_inst_id": {
                "type": "integer",
                "description": "Start search from this instruction",
                "default": 0
            },
            "end_inst_id": {
                "type": "integer",
                "description": "End search at this instruction (default: trace end)"
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum matches to return",
                "default": 20
            }
        },
        "required": ["pattern"]
    }
}

# ─── Registration ────────────────────────────────────────────────────────────

register_tools([
    (SCHEMA_MEM_PATTERN_SEARCH, handle_mem_pattern_search),
])
