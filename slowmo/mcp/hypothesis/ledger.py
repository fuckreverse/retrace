"""
HypothesisLedger — core state machine for hypothesis lifecycle management.

States:
    proposed → active → concluded | abandoned
                ↑          ↓
                └── reopened (rare)

Each hypothesis must accumulate evidence before concluding.
Conflicting hypotheses cannot both be concluded.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class HypothesisStatus(Enum):
    PROPOSED = "proposed"
    ACTIVE = "active"
    CONCLUDED = "concluded"
    ABANDONED = "abandoned"


@dataclass
class Evidence:
    """A piece of evidence supporting or refuting a hypothesis."""
    description: str
    source_tool: str           # which MCP tool produced this evidence
    inst_id: Optional[int]     # instruction ID reference (if applicable)
    data: dict                 # raw data from the tool
    verified: bool = False     # has verify_evidence confirmed this?
    timestamp: float = field(default_factory=time.time)


@dataclass
class Hypothesis:
    """A single hypothesis in the ledger."""
    id: str
    statement: str             # what we think is true
    category: str              # e.g. "crypto_algorithm", "key_source", "data_flow"
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    evidence_for: List[Evidence] = field(default_factory=list)
    evidence_against: List[Evidence] = field(default_factory=list)
    conclusion: Optional[str] = None
    confidence: float = 0.0    # 0.0 to 1.0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    conflicts_with: List[str] = field(default_factory=list)  # IDs of conflicting hypotheses
    reviewed: bool = False


class HypothesisLedger:
    """
    Manages the full lifecycle of hypotheses during trace analysis.

    Anti-hallucination rules enforced:
    - Cannot conclude without at least 1 verified piece of evidence
    - Conflicting hypotheses cannot both be concluded
    - Abandoned hypotheses are kept for audit trail
    - Evidence must reference real trace data (verified via verify_evidence)
    """

    def __init__(self):
        self._hypotheses: Dict[str, Hypothesis] = {}
        self._next_id: int = 1
        self._conflict_graph: Dict[str, List[str]] = {}  # id -> [conflicting_ids]

    def add(self, statement: str, category: str = "general",
            conflicts_with: Optional[List[str]] = None) -> dict:
        """Propose a new hypothesis."""
        hid = f"H{self._next_id:03d}"
        self._next_id += 1

        h = Hypothesis(
            id=hid,
            statement=statement,
            category=category,
            status=HypothesisStatus.PROPOSED,
            conflicts_with=conflicts_with or []
        )
        self._hypotheses[hid] = h

        # Register conflicts bidirectionally
        if conflicts_with:
            for conflict_id in conflicts_with:
                if conflict_id in self._hypotheses:
                    self._hypotheses[conflict_id].conflicts_with.append(hid)
                self._conflict_graph.setdefault(hid, []).append(conflict_id)
                self._conflict_graph.setdefault(conflict_id, []).append(hid)

        return {"id": hid, "status": "proposed", "statement": statement}

    def activate(self, hid: str) -> dict:
        """Move a hypothesis from proposed to active (ready for evidence gathering)."""
        h = self._hypotheses.get(hid)
        if not h:
            return {"error": f"Hypothesis {hid} not found"}
        if h.status != HypothesisStatus.PROPOSED:
            return {"error": f"Can only activate PROPOSED hypotheses (current: {h.status.value})"}

        h.status = HypothesisStatus.ACTIVE
        h.updated_at = time.time()
        return {"id": hid, "status": "active"}

    def add_evidence(self, hid: str, description: str, source_tool: str,
                     inst_id: Optional[int] = None, data: Optional[dict] = None,
                     supports: bool = True, verified: bool = False) -> dict:
        """Add evidence to a hypothesis."""
        h = self._hypotheses.get(hid)
        if not h:
            return {"error": f"Hypothesis {hid} not found"}
        if h.status not in (HypothesisStatus.PROPOSED, HypothesisStatus.ACTIVE):
            return {"error": f"Cannot add evidence to {h.status.value} hypothesis"}

        # Auto-activate if still proposed
        if h.status == HypothesisStatus.PROPOSED:
            h.status = HypothesisStatus.ACTIVE

        evidence = Evidence(
            description=description,
            source_tool=source_tool,
            inst_id=inst_id,
            data=data or {},
            verified=verified
        )

        if supports:
            h.evidence_for.append(evidence)
        else:
            h.evidence_against.append(evidence)

        h.updated_at = time.time()
        h.confidence = self._compute_confidence(h)

        return {
            "id": hid,
            "evidence_count": len(h.evidence_for) + len(h.evidence_against),
            "confidence": h.confidence,
            "verified": verified
        }

    def conclude(self, hid: str, conclusion: str) -> dict:
        """Conclude a hypothesis (mark as confirmed/true)."""
        h = self._hypotheses.get(hid)
        if not h:
            return {"error": f"Hypothesis {hid} not found"}
        if h.status != HypothesisStatus.ACTIVE:
            return {"error": f"Can only conclude ACTIVE hypotheses (current: {h.status.value})"}

        # Anti-hallucination check: need at least one verified evidence
        verified_evidence = [e for e in h.evidence_for if e.verified]
        if not verified_evidence:
            return {
                "error": "Cannot conclude without verified evidence. "
                         "Use verify_evidence tool first, then add_evidence with verified=true.",
                "evidence_for_count": len(h.evidence_for),
                "verified_count": 0,
                "hint": "Call verify_evidence to validate your observations, then re-add as verified"
            }

        # Conflict check: no conflicting hypothesis can be concluded
        for conflict_id in h.conflicts_with:
            conflict = self._hypotheses.get(conflict_id)
            if conflict and conflict.status == HypothesisStatus.CONCLUDED:
                return {
                    "error": f"Conflict: {conflict_id} is already concluded. "
                             f"Cannot conclude contradicting hypothesis.",
                    "conflicting_hypothesis": conflict_id,
                    "conflict_statement": conflict.statement
                }

        h.status = HypothesisStatus.CONCLUDED
        h.conclusion = conclusion
        h.updated_at = time.time()

        return {
            "id": hid,
            "status": "concluded",
            "conclusion": conclusion,
            "confidence": h.confidence,
            "evidence_count": len(h.evidence_for)
        }

    def abandon(self, hid: str, reason: str) -> dict:
        """Abandon a hypothesis (evidence disproved it or it's no longer relevant)."""
        h = self._hypotheses.get(hid)
        if not h:
            return {"error": f"Hypothesis {hid} not found"}
        if h.status == HypothesisStatus.CONCLUDED:
            return {"error": "Cannot abandon a concluded hypothesis. Use reopen first."}

        h.status = HypothesisStatus.ABANDONED
        h.conclusion = f"ABANDONED: {reason}"
        h.updated_at = time.time()

        return {"id": hid, "status": "abandoned", "reason": reason}

    def list_all(self, status_filter: Optional[str] = None) -> dict:
        """List all hypotheses, optionally filtered by status."""
        results = []
        for h in self._hypotheses.values():
            if status_filter and h.status.value != status_filter:
                continue
            results.append({
                "id": h.id,
                "statement": h.statement,
                "category": h.category,
                "status": h.status.value,
                "confidence": h.confidence,
                "evidence_for": len(h.evidence_for),
                "evidence_against": len(h.evidence_against),
                "verified_evidence": sum(1 for e in h.evidence_for if e.verified),
                "conflicts_with": h.conflicts_with,
                "reviewed": h.reviewed
            })

        return {
            "hypotheses": results,
            "total": len(results),
            "by_status": {
                "proposed": sum(1 for h in self._hypotheses.values() if h.status == HypothesisStatus.PROPOSED),
                "active": sum(1 for h in self._hypotheses.values() if h.status == HypothesisStatus.ACTIVE),
                "concluded": sum(1 for h in self._hypotheses.values() if h.status == HypothesisStatus.CONCLUDED),
                "abandoned": sum(1 for h in self._hypotheses.values() if h.status == HypothesisStatus.ABANDONED),
            }
        }

    def get(self, hid: str) -> dict:
        """Get full details of a hypothesis including all evidence."""
        h = self._hypotheses.get(hid)
        if not h:
            return {"error": f"Hypothesis {hid} not found"}

        return {
            "id": h.id,
            "statement": h.statement,
            "category": h.category,
            "status": h.status.value,
            "confidence": h.confidence,
            "conclusion": h.conclusion,
            "conflicts_with": h.conflicts_with,
            "reviewed": h.reviewed,
            "created_at": h.created_at,
            "updated_at": h.updated_at,
            "evidence_for": [
                {
                    "description": e.description,
                    "source_tool": e.source_tool,
                    "inst_id": e.inst_id,
                    "verified": e.verified,
                    "timestamp": e.timestamp
                }
                for e in h.evidence_for
            ],
            "evidence_against": [
                {
                    "description": e.description,
                    "source_tool": e.source_tool,
                    "inst_id": e.inst_id,
                    "verified": e.verified,
                    "timestamp": e.timestamp
                }
                for e in h.evidence_against
            ]
        }

    def mark_reviewed(self, hid: str) -> dict:
        """Mark a hypothesis as reviewed (human or AI auditor has checked it)."""
        h = self._hypotheses.get(hid)
        if not h:
            return {"error": f"Hypothesis {hid} not found"}
        h.reviewed = True
        h.updated_at = time.time()
        return {"id": hid, "reviewed": True}

    def _compute_confidence(self, h: Hypothesis) -> float:
        """Compute confidence score based on evidence quality."""
        if not h.evidence_for and not h.evidence_against:
            return 0.0

        verified_for = sum(1 for e in h.evidence_for if e.verified)
        unverified_for = len(h.evidence_for) - verified_for
        against = len(h.evidence_against)

        # Verified evidence counts 3x, unverified 1x, against -2x
        score = (verified_for * 3.0 + unverified_for * 1.0 - against * 2.0)
        max_possible = (verified_for + unverified_for) * 3.0 + 1.0  # +1 to avoid div/0

        confidence = max(0.0, min(1.0, score / max_possible))
        return round(confidence, 3)
