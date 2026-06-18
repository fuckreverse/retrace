"""
Tools: pattern_scan, strings_scan, constants_scan, loop_semantics,
       algorithm_summary, symbol_annotation
"""

import json

from . import register_tools
from ..session import Session
from ..parsers import parse_pattern_output, parse_strings_output, parse_constants_output
from ..config import TIMEOUT_LIGHT, TIMEOUT_MEDIUM, TIMEOUT_HEAVY

_session: Session = None


def init(session: Session):
    global _session
    _session = session


# ─── Handlers ────────────────────────────────────────────────────────────────

def handle_pattern_scan(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    args = [_session.current_trace, "--pattern"]
    result = _session.run_tenet(args, timeout=TIMEOUT_LIGHT)
    if result["returncode"] != 0:
        return {"error": f"Pattern scan failed: {result['stderr']}"}

    return parse_pattern_output(result["stdout"] + result["stderr"])


def handle_strings_scan(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    args = [_session.current_trace, "--strings"]
    result = _session.run_tenet(args, timeout=TIMEOUT_LIGHT)
    if result["returncode"] != 0:
        return {"error": f"String scan failed: {result['stderr']}"}

    return parse_strings_output(result["stdout"] + result["stderr"])


def handle_constants_scan(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    min_parts = params.get("min_parts", 2)
    args = [_session.current_trace, "--constants", "--constants-min-parts", str(min_parts)]
    result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)
    if result["returncode"] != 0:
        return {"error": f"Constants scan failed: {result['stderr']}"}

    return parse_constants_output(result["stdout"] + result["stderr"])


def handle_loop_semantics(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    args = [_session.current_trace, "--loop-semantics"]
    result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)
    if result["returncode"] != 0:
        return {"error": f"Loop semantics failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_algorithm_summary(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    args = [_session.current_trace, "--algorithm-summary"]
    result = _session.run_tenet(args, timeout=TIMEOUT_HEAVY)
    if result["returncode"] != 0:
        return {"error": f"Algorithm summary failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


def handle_symbol_annotation(params: dict) -> dict:
    err = _session.ensure_trace_loaded()
    if err:
        return err

    args = [_session.current_trace, "--symbol-annotation"]
    result = _session.run_tenet(args, timeout=TIMEOUT_MEDIUM)
    if result["returncode"] != 0:
        return {"error": f"Symbol annotation failed: {result['stderr']}"}

    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"], "stderr": result["stderr"]}


# ─── Schemas ─────────────────────────────────────────────────────────────────

SCHEMA_PATTERN_SCAN = {
    "name": "pattern_scan",
    "description": (
        "Scan the trace for known patterns: cryptographic algorithms (AES, SHA256, SM3/4, "
        "HMAC, etc.), anti-debug techniques, obfuscation patterns (CFF, MBA, opaque "
        "predicates), and key schedule patterns."
    ),
    "inputSchema": {"type": "object", "properties": {}}
}

SCHEMA_STRINGS_SCAN = {
    "name": "strings_scan",
    "description": (
        "Discover all printable strings in traced memory. Returns strings with their "
        "addresses, encoding (ASCII/UTF8/UTF16), length, and cross-references."
    ),
    "inputSchema": {"type": "object", "properties": {}}
}

SCHEMA_CONSTANTS_SCAN = {
    "name": "constants_scan",
    "description": (
        "Extract all constants materialized via movz+movk instruction sequences. "
        "Identifies known cryptographic constants (SHA-256, AES, SM3, SM4, ChaCha20, "
        "TEA, Blowfish, etc.)."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "min_parts": {
                "type": "integer",
                "description": "Minimum movz+movk parts to report (1=standalone movz, 2+=multi-part)",
                "default": 2
            }
        }
    }
}

SCHEMA_LOOP_SEMANTICS = {
    "name": "loop_semantics",
    "description": (
        "Analyze loop semantics to identify round functions and crypto loops. "
        "Detects Feistel networks, SPN loops, and other cryptographic iteration patterns."
    ),
    "inputSchema": {"type": "object", "properties": {}}
}

SCHEMA_ALGORITHM_SUMMARY = {
    "name": "algorithm_summary",
    "description": (
        "Generate a comprehensive algorithm summary report. Combines pattern detection, "
        "constant identification, loop semantics, function analysis, and call graph "
        "into a unified report identifying cryptographic/encoding algorithms."
    ),
    "inputSchema": {"type": "object", "properties": {}}
}

SCHEMA_SYMBOL_ANNOTATION = {
    "name": "symbol_annotation",
    "description": (
        "Generate human-readable symbol annotations for all PCs. Combines function names, "
        "loop info, constant identifications, and pattern matches into a unified annotation layer."
    ),
    "inputSchema": {"type": "object", "properties": {}}
}

# ─── Registration ────────────────────────────────────────────────────────────

register_tools([
    (SCHEMA_PATTERN_SCAN, handle_pattern_scan),
    (SCHEMA_STRINGS_SCAN, handle_strings_scan),
    (SCHEMA_CONSTANTS_SCAN, handle_constants_scan),
    (SCHEMA_LOOP_SEMANTICS, handle_loop_semantics),
    (SCHEMA_ALGORITHM_SUMMARY, handle_algorithm_summary),
    (SCHEMA_SYMBOL_ANNOTATION, handle_symbol_annotation),
])
