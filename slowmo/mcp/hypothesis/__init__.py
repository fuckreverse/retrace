"""
Hypothesis Ledger — anti-hallucination framework for AI-driven trace analysis.

Forces the AI to follow a scientific method:
  1. Propose a hypothesis
  2. Search for evidence in the trace
  3. Verify evidence is real (via verify_evidence tool)
  4. Conclude or abandon the hypothesis

Ported from algokiller-plugin's hypothesis system, adapted for tenet's
binary trace format and richer analysis capabilities.
"""

from .ledger import HypothesisLedger
from .tools import register_hypothesis_tools

__all__ = ["HypothesisLedger", "register_hypothesis_tools"]
