"""
Tool: call_context — function context and call stack at any instruction.
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

def handle_call_context(params: dict) -> dict:
    """Query function context and call stack at a given instruction."""
    err = _session.ensure_trace_loaded()
    if err:
        return err

    inst_id = params["inst_id"]
    stack_depth = params.get("stack_depth", 8)

    # Try native CLI command first
    args = [_session.current_trace, "--call-context", str(inst_id),
            "--context-depth", str(stack_depth)]
    result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)

    if result["returncode"] == 0:
        try:
            return json.loads(result["stdout"])
        except json.JSONDecodeError:
            return {"raw_output": result["stdout"]}

    # Fallback: build context from call_graph data
    return _build_context_from_call_graph(inst_id, stack_depth)


def _build_context_from_call_graph(inst_id: int, stack_depth: int) -> dict:
    """Reconstruct call context using call_graph + disasm."""
    import tempfile
    import os

    # Get call graph
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        tmp_path = f.name

    try:
        args = [_session.current_trace, "--call-graph", tmp_path]
        result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)
        if result["returncode"] != 0:
            return {"error": f"Cannot build context: {result['stderr']}"}

        with open(tmp_path, "r") as f:
            content = f.read()

        try:
            cg_data = json.loads(content)
        except json.JSONDecodeError:
            return {"error": "Cannot parse call graph for context reconstruction"}

        # Find which function contains this inst_id
        functions = cg_data.get("functions", cg_data.get("nodes", []))
        containing_func = None
        call_stack = []

        for func in functions:
            func_start = func.get("start_inst_id", func.get("entry_inst_id", 0))
            func_end = func.get("end_inst_id", func.get("exit_inst_id", 0))
            if func_start <= inst_id <= func_end:
                containing_func = func
                break

        if containing_func:
            # Walk callers to build stack
            call_stack.append({
                "function_pc": containing_func.get("pc", containing_func.get("entry_pc", "?")),
                "name": containing_func.get("name", "sub_" + str(containing_func.get("pc", "?"))),
                "entry_inst_id": containing_func.get("start_inst_id", containing_func.get("entry_inst_id")),
                "depth": 0
            })

            # Try to find callers up to stack_depth
            edges = cg_data.get("edges", cg_data.get("calls", []))
            current_pc = containing_func.get("pc", "")
            for depth in range(1, stack_depth):
                caller = None
                for edge in edges:
                    if edge.get("callee", edge.get("target", "")) == current_pc:
                        caller_pc = edge.get("caller", edge.get("source", ""))
                        # Find function by PC
                        for func in functions:
                            if func.get("pc", func.get("entry_pc", "")) == caller_pc:
                                caller = func
                                break
                        break
                if caller:
                    call_stack.append({
                        "function_pc": caller.get("pc", "?"),
                        "name": caller.get("name", "sub_" + str(caller.get("pc", "?"))),
                        "entry_inst_id": caller.get("start_inst_id", caller.get("entry_inst_id")),
                        "depth": depth
                    })
                    current_pc = caller.get("pc", "")
                else:
                    break

        return {
            "inst_id": inst_id,
            "current_function": containing_func.get("name", "unknown") if containing_func else "unknown",
            "current_function_pc": containing_func.get("pc", "?") if containing_func else "?",
            "call_stack": call_stack,
            "stack_depth": len(call_stack),
            "note": "Reconstructed from call_graph pass"
        }

    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ─── Schema ──────────────────────────────────────────────────────────────────

SCHEMA_CALL_CONTEXT = {
    "name": "call_context",
    "description": (
        "Query the function context at a specific instruction: which function contains "
        "this instruction, what is the call stack (from outermost caller to current), "
        "function entry/exit boundaries. Essential for understanding WHERE you are in the "
        "program during trace analysis."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "inst_id": {
                "type": "integer",
                "description": "Instruction ID to query context for"
            },
            "stack_depth": {
                "type": "integer",
                "description": "Maximum call stack depth to reconstruct",
                "default": 8
            }
        },
        "required": ["inst_id"]
    }
}

# ─── Registration ────────────────────────────────────────────────────────────

register_tools([
    (SCHEMA_CALL_CONTEXT, handle_call_context),
])
