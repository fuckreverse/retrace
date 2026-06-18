"""
Tools: trace_fold (loop folding/compression), reg_timeline (register value timeline)
"""

import json

from . import register_tools
from ..session import Session
from ..config import TIMEOUT_MEDIUM

_session: Session = None


def init(session: Session):
    global _session
    _session = session


# ─── Handlers ────────────────────────────────────────────────────────────────

def handle_trace_fold(params: dict) -> dict:
    """Fold/compress loops in a trace range into a summary view."""
    err = _session.ensure_trace_loaded()
    if err:
        return err

    start = params.get("start_inst_id", 0)
    end = params.get("end_inst_id")
    max_detail = params.get("max_iterations_detail", 3)

    # Use loop_semantics to get loop boundaries, then summarize
    args = [_session.current_trace, "--trace-fold"]
    if end is not None:
        args.extend(["--fold-range", str(start), str(end)])
    else:
        args.extend(["--fold-start", str(start)])
    args.extend(["--fold-detail-iters", str(max_detail)])

    result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)
    if result["returncode"] != 0:
        # Fallback: if --trace-fold not yet in CLI, synthesize from loop_semantics
        return _fold_via_loop_semantics(start, end, max_detail)

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def _fold_via_loop_semantics(start: int, end, max_detail: int) -> dict:
    """Fallback: use loop_semantics + disasm to synthesize fold view."""
    # Get loop info
    args = [_session.current_trace, "--loop-semantics"]
    result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)
    if result["returncode"] != 0:
        return {"error": f"Loop semantics failed: {result['stderr']}"}

    try:
        loops_data = json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"error": "Cannot parse loop semantics output", "raw": result["stdout"][:500]}

    # Filter loops within requested range
    loops = loops_data.get("loops", loops_data.get("results", []))
    folded_regions = []

    for loop in loops:
        loop_start = loop.get("start_inst_id", loop.get("header_inst_id", 0))
        loop_end = loop.get("end_inst_id", loop.get("exit_inst_id", 0))
        iterations = loop.get("iterations", loop.get("iteration_count", 0))

        if end is not None and (loop_start < start or loop_end > end):
            continue

        folded_regions.append({
            "type": "loop",
            "start_inst_id": loop_start,
            "end_inst_id": loop_end,
            "iterations": iterations,
            "classification": loop.get("classification", "unknown"),
            "body_size": loop_end - loop_start if loop_end > loop_start else 0,
            "folded": True,
            "summary": f"Loop ({iterations} iters, {loop.get('classification', '?')})"
        })

    return {
        "folded_regions": folded_regions,
        "total_loops_found": len(folded_regions),
        "range": {"start": start, "end": end},
        "note": "Synthesized from loop_semantics pass"
    }


def handle_reg_timeline(params: dict) -> dict:
    """Track a register's value changes over time."""
    err = _session.ensure_trace_loaded()
    if err:
        return err

    register = params["register"]
    start = params.get("start_inst_id", 0)
    end = params.get("end_inst_id")
    max_changes = params.get("max_changes", 100)

    args = [_session.current_trace, "--reg-timeline", register]
    args.extend(["--timeline-start", str(start)])
    if end is not None:
        args.extend(["--timeline-end", str(end)])
    args.extend(["--timeline-max", str(max_changes)])

    result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)
    if result["returncode"] != 0:
        # Fallback: use disasm with reg diff to track changes
        return _timeline_via_disasm(register, start, end, max_changes)

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def _timeline_via_disasm(register: str, start: int, end, max_changes: int) -> dict:
    """Fallback: scan disassembly for register changes."""
    # Get a window of instructions and parse reg diffs
    count = min((end - start) if end else 1000, 2000)
    args = [_session.current_trace, "-c", "-s", str(start), "-n", str(count), "-r"]
    result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)
    if result["returncode"] != 0:
        return {"error": f"Disasm failed: {result['stderr']}"}

    # Parse output for register changes
    reg_lower = register.lower()
    changes = []
    current_inst_id = start

    for line in result["stdout"].split("\n"):
        line_stripped = line.strip()

        # Track instruction IDs
        if line_stripped.startswith("#"):
            try:
                current_inst_id = int(line_stripped.split()[0].lstrip("#"))
            except (ValueError, IndexError):
                pass

        # Look for register diffs like "x0: 0x0 -> 0xdeadbeef"
        if reg_lower in line_stripped.lower() and "->" in line_stripped:
            parts = line_stripped.split("->")
            if len(parts) == 2:
                before_part = parts[0].strip()
                after_val = parts[1].strip().split()[0] if parts[1].strip() else ""
                # Extract the "before" value
                before_tokens = before_part.split()
                before_val = before_tokens[-1] if before_tokens else ""

                changes.append({
                    "inst_id": current_inst_id,
                    "old_value": before_val,
                    "new_value": after_val,
                })

                if len(changes) >= max_changes:
                    break

    return {
        "register": register,
        "changes": changes,
        "total_changes": len(changes),
        "range": {"start": start, "end": end},
        "truncated": len(changes) >= max_changes,
        "note": "Synthesized from disassembly output"
    }


# ─── Schemas ─────────────────────────────────────────────────────────────────

SCHEMA_TRACE_FOLD = {
    "name": "trace_fold",
    "description": (
        "Fold/compress loops in a trace range into a summary view. Instead of "
        "showing every iteration, returns loop boundaries, iteration counts, "
        "classifications (Feistel/SPN/ARX/memcpy/etc.), and key register deltas. "
        "Ideal for AI to quickly grasp repetitive structure without reading thousands "
        "of repeated instructions."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "start_inst_id": {
                "type": "integer",
                "description": "Start of range to fold (default: 0)",
                "default": 0
            },
            "end_inst_id": {
                "type": "integer",
                "description": "End of range to fold (default: entire trace)"
            },
            "max_iterations_detail": {
                "type": "integer",
                "description": "Show full detail for first N iterations of each loop",
                "default": 3
            }
        }
    }
}

SCHEMA_REG_TIMELINE = {
    "name": "reg_timeline",
    "description": (
        "Track a register's value changes over time. Returns a timeline of "
        "(inst_id, old_value, new_value) tuples showing every modification. "
        "Useful for understanding how a value evolves through an algorithm — "
        "e.g. tracking x0 through a key schedule to see each round key derivation step."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "register": {
                "type": "string",
                "description": "Register name to track (x0-x28, fp, lr, sp, pc)"
            },
            "start_inst_id": {
                "type": "integer",
                "description": "Start tracking from this instruction",
                "default": 0
            },
            "end_inst_id": {
                "type": "integer",
                "description": "Stop tracking at this instruction (default: trace end)"
            },
            "max_changes": {
                "type": "integer",
                "description": "Maximum number of changes to return",
                "default": 100
            }
        },
        "required": ["register"]
    }
}

# ─── Registration ────────────────────────────────────────────────────────────

register_tools([
    (SCHEMA_TRACE_FOLD, handle_trace_fold),
    (SCHEMA_REG_TIMELINE, handle_reg_timeline),
])
