"""
Tool: batch_query — execute multiple queries in a single MCP call.
"""

import json

from . import register_tools
from ..session import Session

_session: Session = None


def init(session: Session):
    global _session
    _session = session


# ─── Handler ─────────────────────────────────────────────────────────────────

def handle_batch_query(params: dict) -> dict:
    """Execute multiple tool queries in one call, reducing MCP round-trips."""
    from . import TOOL_HANDLERS

    queries = params.get("queries", [])
    if not queries:
        return {"error": "No queries provided"}
    if len(queries) > 20:
        return {"error": "Maximum 20 queries per batch"}

    results = []
    for i, query in enumerate(queries):
        tool_name = query.get("tool", "")
        tool_params = query.get("params", {})

        handler = TOOL_HANDLERS.get(tool_name)
        if not handler:
            results.append({
                "index": i,
                "tool": tool_name,
                "error": f"Unknown tool: {tool_name}"
            })
            continue

        try:
            result = handler(tool_params)
            results.append({
                "index": i,
                "tool": tool_name,
                "result": result
            })
        except Exception as e:
            results.append({
                "index": i,
                "tool": tool_name,
                "error": str(e)
            })

    return {
        "batch_size": len(queries),
        "results": results,
        "errors": sum(1 for r in results if "error" in r)
    }


# ─── Schema ──────────────────────────────────────────────────────────────────

SCHEMA_BATCH_QUERY = {
    "name": "batch_query",
    "description": (
        "Execute multiple tool queries in a single MCP call to reduce round-trip "
        "latency. Up to 20 queries can be batched. Each query specifies a tool name "
        "and its parameters. Results are returned in order. Useful when you need "
        "register states at multiple points, or want to combine memread + disasm + "
        "regstate for the same instruction range."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "queries": {
                "type": "array",
                "description": "Array of queries to execute",
                "items": {
                    "type": "object",
                    "properties": {
                        "tool": {
                            "type": "string",
                            "description": "Tool name to call (e.g. 'regstate', 'memread', 'disasm')"
                        },
                        "params": {
                            "type": "object",
                            "description": "Parameters for the tool"
                        }
                    },
                    "required": ["tool", "params"]
                },
                "maxItems": 20
            }
        },
        "required": ["queries"]
    }
}

# ─── Registration ────────────────────────────────────────────────────────────

register_tools([
    (SCHEMA_BATCH_QUERY, handle_batch_query),
])
