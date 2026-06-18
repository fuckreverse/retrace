"""
MCP tool wrappers for the Hypothesis Ledger.
"""

from ..tools import register_tools
from .ledger import HypothesisLedger

# Shared ledger instance (initialized by server.py)
_ledger: HypothesisLedger = None


def init(ledger: HypothesisLedger):
    global _ledger
    _ledger = ledger


# ─── Handlers ────────────────────────────────────────────────────────────────

def handle_hypothesis_add(params: dict) -> dict:
    return _ledger.add(
        statement=params["statement"],
        category=params.get("category", "general"),
        conflicts_with=params.get("conflicts_with")
    )


def handle_hypothesis_activate(params: dict) -> dict:
    return _ledger.activate(params["id"])


def handle_hypothesis_evidence(params: dict) -> dict:
    return _ledger.add_evidence(
        hid=params["id"],
        description=params["description"],
        source_tool=params["source_tool"],
        inst_id=params.get("inst_id"),
        data=params.get("data"),
        supports=params.get("supports", True),
        verified=params.get("verified", False)
    )


def handle_hypothesis_conclude(params: dict) -> dict:
    return _ledger.conclude(params["id"], params["conclusion"])


def handle_hypothesis_abandon(params: dict) -> dict:
    return _ledger.abandon(params["id"], params["reason"])


def handle_hypothesis_list(params: dict) -> dict:
    return _ledger.list_all(status_filter=params.get("status"))


def handle_hypothesis_get(params: dict) -> dict:
    return _ledger.get(params["id"])


def handle_hypothesis_mark_reviewed(params: dict) -> dict:
    return _ledger.mark_reviewed(params["id"])


# ─── Schemas ─────────────────────────────────────────────────────────────────

SCHEMA_HYPOTHESIS_ADD = {
    "name": "hypothesis_add",
    "description": (
        "Propose a new hypothesis about the trace being analyzed. "
        "REQUIRED before drawing any conclusion. Forces structured reasoning: "
        "hypothesis → evidence → verification → conclusion."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "statement": {
                "type": "string",
                "description": "The hypothesis statement (what you believe might be true)"
            },
            "category": {
                "type": "string",
                "enum": ["crypto_algorithm", "key_source", "data_flow",
                         "function_purpose", "obfuscation", "anti_debug", "general"],
                "description": "Category of the hypothesis",
                "default": "general"
            },
            "conflicts_with": {
                "type": "array",
                "items": {"type": "string"},
                "description": "IDs of hypotheses that conflict with this one (cannot both be true)"
            }
        },
        "required": ["statement"]
    }
}

SCHEMA_HYPOTHESIS_ACTIVATE = {
    "name": "hypothesis_activate",
    "description": "Move a hypothesis from 'proposed' to 'active' (ready for evidence gathering).",
    "inputSchema": {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Hypothesis ID (e.g. 'H001')"}
        },
        "required": ["id"]
    }
}

SCHEMA_HYPOTHESIS_EVIDENCE = {
    "name": "hypothesis_evidence",
    "description": (
        "Add evidence to a hypothesis. Evidence should reference concrete trace data "
        "(instruction IDs, register values, memory contents). Set verified=true ONLY "
        "after using verify_evidence to confirm the data exists in the trace."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Hypothesis ID"},
            "description": {"type": "string", "description": "What this evidence shows"},
            "source_tool": {
                "type": "string",
                "description": "Which tool produced this evidence (e.g. 'taint_forward', 'memread')"
            },
            "inst_id": {"type": "integer", "description": "Related instruction ID (if applicable)"},
            "data": {"type": "object", "description": "Raw evidence data from the tool"},
            "supports": {
                "type": "boolean",
                "description": "True if evidence supports hypothesis, false if it contradicts",
                "default": True
            },
            "verified": {
                "type": "boolean",
                "description": "True ONLY if verify_evidence has confirmed this data exists",
                "default": False
            }
        },
        "required": ["id", "description", "source_tool"]
    }
}

SCHEMA_HYPOTHESIS_CONCLUDE = {
    "name": "hypothesis_conclude",
    "description": (
        "Conclude a hypothesis (confirm it as true). REQUIRES at least one "
        "piece of verified evidence. Cannot conclude if conflicting hypotheses "
        "are already concluded."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Hypothesis ID to conclude"},
            "conclusion": {"type": "string", "description": "Final conclusion statement"}
        },
        "required": ["id", "conclusion"]
    }
}

SCHEMA_HYPOTHESIS_ABANDON = {
    "name": "hypothesis_abandon",
    "description": "Abandon a hypothesis (evidence disproved it or it's no longer relevant).",
    "inputSchema": {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Hypothesis ID to abandon"},
            "reason": {"type": "string", "description": "Why this hypothesis is being abandoned"}
        },
        "required": ["id", "reason"]
    }
}

SCHEMA_HYPOTHESIS_LIST = {
    "name": "hypothesis_list",
    "description": (
        "List all hypotheses in the ledger. Shows status, confidence, evidence counts, "
        "and conflicts. Use to review the current state of analysis reasoning."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "enum": ["proposed", "active", "concluded", "abandoned"],
                "description": "Filter by status (optional, default: show all)"
            }
        }
    }
}

SCHEMA_HYPOTHESIS_GET = {
    "name": "hypothesis_get",
    "description": "Get full details of a hypothesis including all evidence items.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Hypothesis ID"}
        },
        "required": ["id"]
    }
}

SCHEMA_HYPOTHESIS_MARK_REVIEWED = {
    "name": "hypothesis_mark_reviewed",
    "description": "Mark a hypothesis as reviewed (audited for correctness).",
    "inputSchema": {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Hypothesis ID"}
        },
        "required": ["id"]
    }
}


# ─── Registration ────────────────────────────────────────────────────────────

def register_hypothesis_tools():
    """Register all hypothesis tools. Called after ledger is initialized."""
    register_tools([
        (SCHEMA_HYPOTHESIS_ADD, handle_hypothesis_add),
        (SCHEMA_HYPOTHESIS_ACTIVATE, handle_hypothesis_activate),
        (SCHEMA_HYPOTHESIS_EVIDENCE, handle_hypothesis_evidence),
        (SCHEMA_HYPOTHESIS_CONCLUDE, handle_hypothesis_conclude),
        (SCHEMA_HYPOTHESIS_ABANDON, handle_hypothesis_abandon),
        (SCHEMA_HYPOTHESIS_LIST, handle_hypothesis_list),
        (SCHEMA_HYPOTHESIS_GET, handle_hypothesis_get),
        (SCHEMA_HYPOTHESIS_MARK_REVIEWED, handle_hypothesis_mark_reviewed),
    ])
