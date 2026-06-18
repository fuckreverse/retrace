"""
Tools: taint_forward, taint_backward, critical_path
"""

import json

from . import register_tools
from ..session import Session
from ..parsers import extract_json_blocks
from ..config import TIMEOUT_MEDIUM, TIMEOUT_HEAVY

_session: Session = None


def init(session: Session):
    global _session
    _session = session


# ─── Handlers ────────────────────────────────────────────────────────────────

def handle_taint_forward(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    reg_index = params["reg_index"]
    inst_id = params.get("inst_id", 0)
    args = [_session.current_trace, "--taint", str(reg_index), "--taint-inst", str(inst_id)]

    for addr in params.get("mem_addrs", []):
        clean_addr = addr.replace("0x", "").replace("0X", "")
        args.extend(["--taint-mem", clean_addr])

    for pc in params.get("stop_pcs", []):
        clean_pc = pc.replace("0x", "").replace("0X", "")
        args.extend(["--taint-stop-pc", clean_pc])

    max_width = params.get("max_width", 0)
    if max_width > 0:
        args.extend(["--taint-max-width", str(max_width)])

    if not params.get("propagate_through_calls", True):
        args.append("--taint-no-calls")

    result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)
    if result["returncode"] != 0:
        return {"error": f"Forward taint failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_taint_backward(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    sink_id = params["sink_inst_id"]
    sink_reg = params["sink_reg"]
    max_steps = params.get("max_steps", 10000)

    args = [_session.current_trace, "--backward-taint", str(sink_id), str(sink_reg)]
    if max_steps > 0:
        args.extend(["--backward-taint-max-steps", str(max_steps)])

    result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)
    if result["returncode"] != 0:
        return {"error": f"Backward taint failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_critical_path(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    source_reg = params["source_reg"]
    source_inst = params["source_inst_id"]
    sink_reg = params["sink_reg"]
    sink_inst = params["sink_inst_id"]

    args = [
        _session.current_trace,
        "--taint", str(source_reg),
        "--taint-inst", str(source_inst),
        "--backward-taint", str(sink_inst), str(sink_reg),
        "--critical-path"
    ]

    result = _session.run_tenet(args, timeout=TIMEOUT_HEAVY)
    if result["returncode"] != 0:
        return {"error": f"Critical path failed: {result['stderr']}"}

    stdout = result["stdout"].strip()
    json_blocks = extract_json_blocks(stdout)

    if json_blocks:
        try:
            return json.loads(json_blocks[-1])
        except json.JSONDecodeError:
            pass

    return {"raw_output": result["stdout"], "stderr": result["stderr"]}


# ─── Schemas ─────────────────────────────────────────────────────────────────

SCHEMA_TAINT_FORWARD = {
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
                "description": "Register index to taint (0-28=x0-x28, 29=fp, 30=lr, 31=sp, 33=pc)"
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
}

SCHEMA_TAINT_BACKWARD = {
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
}

SCHEMA_CRITICAL_PATH = {
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
            "source_reg": {"type": "integer", "description": "Source register index for forward taint"},
            "source_inst_id": {"type": "integer", "description": "Instruction ID where source value is defined"},
            "sink_reg": {"type": "integer", "description": "Sink register index for backward taint"},
            "sink_inst_id": {"type": "integer", "description": "Instruction ID where result is observed"}
        },
        "required": ["source_reg", "source_inst_id", "sink_reg", "sink_inst_id"]
    }
}

# ─── Registration ────────────────────────────────────────────────────────────

register_tools([
    (SCHEMA_TAINT_FORWARD, handle_taint_forward),
    (SCHEMA_TAINT_BACKWARD, handle_taint_backward),
    (SCHEMA_CRITICAL_PATH, handle_critical_path),
])
