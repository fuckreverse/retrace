"""
Tools: cfg_export, call_graph, dataflow_graph
"""

import json
import os
import tempfile

from . import register_tools
from ..session import Session
from ..config import TIMEOUT_MEDIUM

_session: Session = None


def init(session: Session):
    global _session
    _session = session


# ─── Handlers ────────────────────────────────────────────────────────────────

def handle_cfg_export(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    fmt = params.get("format", "json")
    ext = ".json" if fmt == "json" else ".dot"

    with tempfile.NamedTemporaryFile(suffix=ext, delete=False, mode="w") as f:
        tmp_path = f.name

    try:
        args = [_session.current_trace, "--export-cfg", tmp_path]
        result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)
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
    err = _session.ensure_trace_loaded()
    if err:
        return err

    fmt = params.get("format", "json")
    ext = ".json" if fmt == "json" else ".dot"

    with tempfile.NamedTemporaryFile(suffix=ext, delete=False, mode="w") as f:
        tmp_path = f.name

    try:
        args = [_session.current_trace, "--call-graph", tmp_path]
        result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)
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


def handle_dataflow_graph(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    start = params["start_inst_id"]
    end = params["end_inst_id"]
    fmt = params.get("format", "json")

    args = [_session.current_trace, "--dataflow-graph", str(start), str(end)]

    if fmt == "dot":
        with tempfile.NamedTemporaryFile(suffix=".dot", delete=False, mode="w") as f:
            tmp_path = f.name
        args.extend(["--dataflow-graph-output", tmp_path])
        try:
            result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)
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
        result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)
        if result["returncode"] != 0:
            return {"error": f"Dataflow graph failed: {result['stderr']}"}
        try:
            return json.loads(result["stdout"])
        except json.JSONDecodeError:
            return {"raw_output": result["stdout"], "stderr": result["stderr"]}


# ─── Schemas ─────────────────────────────────────────────────────────────────

SCHEMA_CFG_EXPORT = {
    "name": "cfg_export",
    "description": (
        "Extract the Control Flow Graph from the trace. Returns the CFG as a DOT "
        "graph with annotated basic blocks (instruction ranges, hit counts)."
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
}

SCHEMA_CALL_GRAPH = {
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
}

SCHEMA_DATAFLOW_GRAPH = {
    "name": "dataflow_graph",
    "description": (
        "Build a dataflow graph for a given instruction range. Shows how data flows "
        "between registers and memory through instructions. Output as DOT or JSON."
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
}

# ─── Registration ────────────────────────────────────────────────────────────

register_tools([
    (SCHEMA_CFG_EXPORT, handle_cfg_export),
    (SCHEMA_CALL_GRAPH, handle_call_graph),
    (SCHEMA_DATAFLOW_GRAPH, handle_dataflow_graph),
])
