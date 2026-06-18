"""
Tool: verify_evidence — validates that AI-cited data actually exists in the trace.

This is the bridge between algokiller-plugin's hypothesis ledger and tenet's
ground-truth data. When the AI claims "x0 = 0xdeadbeef at inst 42", this tool
verifies it against the real trace.
"""

import json

from . import register_tools
from ..session import Session
from ..config import TIMEOUT_LIGHT

_session: Session = None


def init(session: Session):
    global _session
    _session = session


def handle_verify_evidence(params: dict) -> dict:
    """Verify a batch of evidence claims against the trace."""
    err = _session.ensure_trace_loaded()
    if err:
        return err

    checks = params.get("checks", [])
    if not checks:
        return {"error": "No checks provided"}

    results = []
    for i, check in enumerate(checks):
        check_type = check.get("type")
        inst_id = check.get("inst_id")

        if check_type == "register":
            # Verify a register value at a given instruction
            reg = check.get("register", "")
            expected = check.get("expected_value", "")
            verdict = _verify_register(inst_id, reg, expected)

        elif check_type == "memory":
            # Verify memory content at a given instruction
            addr = check.get("address", "")
            expected_bytes = check.get("expected_bytes", "")
            size = len(expected_bytes) // 2 if expected_bytes else 1
            verdict = _verify_memory(inst_id, addr, expected_bytes, size)

        elif check_type == "instruction":
            # Verify an instruction's mnemonic at a given position
            expected_mnem = check.get("expected_mnemonic", "")
            expected_pc = check.get("expected_pc", "")
            verdict = _verify_instruction(inst_id, expected_mnem, expected_pc)

        else:
            verdict = {"valid": False, "reason": f"Unknown check type: {check_type}"}

        verdict["check_index"] = i
        verdict["check_type"] = check_type
        results.append(verdict)

    all_valid = all(r.get("valid", False) for r in results)
    return {
        "all_valid": all_valid,
        "checks_passed": sum(1 for r in results if r.get("valid")),
        "checks_total": len(results),
        "results": results
    }


def _verify_register(inst_id: int, reg: str, expected: str) -> dict:
    """Check if register has expected value at inst_id."""
    args = [_session.current_trace, "-c", "-s", str(inst_id), "-n", "1", "-r"]
    result = _session.run_tenet(args, timeout=TIMEOUT_LIGHT)
    if result["returncode"] != 0:
        return {"valid": False, "reason": f"tenet error: {result['stderr']}"}

    output = result["stdout"]
    # Normalize expected value for comparison
    expected_norm = expected.lower().replace("0x", "")

    # Search for the register value in output
    reg_lower = reg.lower()
    for line in output.split("\n"):
        line_lower = line.lower().strip()
        if reg_lower in line_lower:
            # Try to find a hex value in this line
            parts = line.split()
            for part in parts:
                part_clean = part.lower().replace("0x", "").rstrip(",")
                if expected_norm and part_clean == expected_norm:
                    return {"valid": True, "actual_line": line.strip()}

    return {
        "valid": False,
        "reason": f"Register {reg} does not hold 0x{expected_norm} at inst #{inst_id}",
        "actual_output": output[:500]
    }


def _verify_memory(inst_id: int, addr: str, expected_bytes: str, size: int) -> dict:
    """Check if memory at addr has expected bytes at inst_id."""
    size = max(size, 1)
    args = [_session.current_trace, "--memread", addr, str(size), str(inst_id)]
    result = _session.run_tenet(args, timeout=TIMEOUT_LIGHT)
    if result["returncode"] != 0:
        return {"valid": False, "reason": f"tenet error: {result['stderr']}"}

    try:
        data = json.loads(result["stdout"])
    except json.JSONDecodeError:
        # If not JSON, check raw output
        output = result["stdout"].lower()
        expected_norm = expected_bytes.lower()
        if expected_norm in output.replace(" ", ""):
            return {"valid": True}
        return {"valid": False, "reason": "Cannot parse memread output", "raw": result["stdout"][:500]}

    # Compare bytes from structured output
    actual_hex = data.get("hex", data.get("bytes", "")).lower().replace(" ", "")
    expected_norm = expected_bytes.lower().replace(" ", "")

    if expected_norm in actual_hex:
        return {"valid": True, "actual_hex": actual_hex}
    else:
        return {
            "valid": False,
            "reason": f"Memory mismatch at {addr}",
            "expected": expected_norm,
            "actual": actual_hex[:64]
        }


def _verify_instruction(inst_id: int, expected_mnem: str, expected_pc: str) -> dict:
    """Check if instruction at inst_id has expected mnemonic/PC."""
    args = [_session.current_trace, "-c", "-s", str(inst_id), "-n", "1"]
    result = _session.run_tenet(args, timeout=TIMEOUT_LIGHT)
    if result["returncode"] != 0:
        return {"valid": False, "reason": f"tenet error: {result['stderr']}"}

    output = result["stdout"]
    valid = True
    reasons = []

    if expected_mnem:
        if expected_mnem.lower() not in output.lower():
            valid = False
            reasons.append(f"Mnemonic '{expected_mnem}' not found")

    if expected_pc:
        pc_norm = expected_pc.lower().replace("0x", "")
        if pc_norm not in output.lower().replace("0x", ""):
            valid = False
            reasons.append(f"PC '{expected_pc}' not found")

    if valid:
        return {"valid": True, "actual_line": output.strip().split("\n")[0] if output else ""}
    else:
        return {"valid": False, "reason": "; ".join(reasons), "actual_output": output[:300]}


# ─── Schema ──────────────────────────────────────────────────────────────────

SCHEMA_VERIFY_EVIDENCE = {
    "name": "verify_evidence",
    "description": (
        "Verify that data cited by the AI actually exists in the trace. "
        "Supports checking: register values, memory contents, and instruction mnemonics "
        "at specific instruction IDs. Used by the hypothesis ledger to ensure all "
        "evidence references are grounded in real trace data (anti-hallucination). "
        "Returns pass/fail for each check with details on mismatches."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "checks": {
                "type": "array",
                "description": "Array of evidence claims to verify against the trace",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": ["register", "memory", "instruction"],
                            "description": "Type of evidence to verify"
                        },
                        "inst_id": {
                            "type": "integer",
                            "description": "Instruction ID where the claim is made"
                        },
                        "register": {
                            "type": "string",
                            "description": "(type=register) Register name, e.g. 'x0', 'lr'"
                        },
                        "expected_value": {
                            "type": "string",
                            "description": "(type=register) Expected hex value, e.g. '0xdeadbeef'"
                        },
                        "address": {
                            "type": "string",
                            "description": "(type=memory) Memory address to check"
                        },
                        "expected_bytes": {
                            "type": "string",
                            "description": "(type=memory) Expected hex bytes, e.g. '48656c6c6f'"
                        },
                        "expected_mnemonic": {
                            "type": "string",
                            "description": "(type=instruction) Expected mnemonic, e.g. 'aese'"
                        },
                        "expected_pc": {
                            "type": "string",
                            "description": "(type=instruction) Expected PC address"
                        }
                    },
                    "required": ["type", "inst_id"]
                }
            }
        },
        "required": ["checks"]
    }
}

# ─── Registration ────────────────────────────────────────────────────────────

register_tools([
    (SCHEMA_VERIFY_EVIDENCE, handle_verify_evidence),
])
