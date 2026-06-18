"""
DisciplineInjector — periodic rule reinjection to combat LLM drift.

During long analysis sessions, LLMs tend to "forget" constraints and start
hallucinating or taking shortcuts. This system periodically appends reminders
to tool responses.

Two modes:
- Short reminder: brief 1-line nudge every N calls
- Full reinjection: complete rule block every M calls
"""

from typing import Optional


# Core analysis rules (inspired by algokiller's critical-rules.md)
FULL_RULES = """
═══ TENET ANALYSIS DISCIPLINE (Auto-injected) ═══

R1: NEVER claim a register/memory value without checking via regstate/memread.
R2: NEVER conclude an algorithm identification without at least 2 independent evidence sources.
R3: ALWAYS use hypothesis_add BEFORE claiming something is true.
R4: ALWAYS verify evidence via verify_evidence BEFORE marking it as verified.
R5: When taint shows propagation, CONFIRM the actual values at source and sink.
R6: Do NOT assume function names or purposes — verify via disasm + call_context.
R7: If loop_semantics reports "Feistel" or "SPN", cross-check with constants_scan.
R8: Memory addresses are RUNTIME addresses (contain ASLR slide). Always note the slide.
R9: If you find yourself making claims without tool calls, STOP and use tools to verify.

═══ END DISCIPLINE BLOCK ═══
""".strip()

# Short reminders (rotated through)
SHORT_REMINDERS = [
    "⚡ Reminder: Verify claims with tools. Don't assume — check regstate/memread.",
    "⚡ Reminder: Use hypothesis_add before drawing conclusions.",
    "⚡ Reminder: Evidence must be verified (verify_evidence) before concluding.",
    "⚡ Reminder: Cross-check algorithm IDs with at least 2 sources (constants + patterns + loops).",
    "⚡ Reminder: All addresses include ASLR slide. Static addr = runtime - slide.",
]


class DisciplineInjector:
    """
    Tracks tool call count and injects discipline reminders into responses.

    Usage:
        injector = DisciplineInjector()
        # After each tool call:
        reminder = injector.on_tool_call(tool_name)
        if reminder:
            result["_discipline"] = reminder
    """

    def __init__(self, short_interval: int = 5, full_interval: int = 20):
        """
        Args:
            short_interval: Inject short reminder every N tool calls
            full_interval: Inject full rules every M tool calls
        """
        self.short_interval = short_interval
        self.full_interval = full_interval
        self.call_count = 0
        self._reminder_index = 0

    def on_tool_call(self, tool_name: str) -> Optional[str]:
        """
        Called after each tool invocation. Returns a discipline message to
        append to the response, or None if no injection needed.

        Certain tools are exempt from injection (hypothesis_* tools already
        enforce discipline by their nature).
        """
        self.call_count += 1

        # Hypothesis tools are already disciplined — don't nag
        if tool_name.startswith("hypothesis_") or tool_name == "verify_evidence":
            return None

        # Full reinjection every full_interval calls
        if self.call_count % self.full_interval == 0:
            return FULL_RULES

        # Short reminder every short_interval calls
        if self.call_count % self.short_interval == 0:
            reminder = SHORT_REMINDERS[self._reminder_index % len(SHORT_REMINDERS)]
            self._reminder_index += 1
            return reminder

        return None

    def reset(self):
        """Reset counters (e.g. when a new trace is loaded)."""
        self.call_count = 0
        self._reminder_index = 0

    @property
    def stats(self) -> dict:
        """Return injection stats."""
        return {
            "total_tool_calls": self.call_count,
            "short_reminders_sent": self.call_count // self.short_interval,
            "full_injections_sent": self.call_count // self.full_interval,
            "next_short_in": self.short_interval - (self.call_count % self.short_interval),
            "next_full_in": self.full_interval - (self.call_count % self.full_interval),
        }
