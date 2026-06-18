"""
Session state management for tenet MCP server.
"""

import os
import subprocess
import sys
from typing import Optional

from .config import TENET_BIN


def log(msg: str):
    """Log to stderr (visible to humans, invisible to MCP transport)."""
    print(f"[tenet-mcp] {msg}", file=sys.stderr, flush=True)


class Session:
    """Holds the current trace session state."""

    def __init__(self, tenet_bin: str = TENET_BIN):
        self.tenet_bin: str = tenet_bin
        self.current_trace: Optional[str] = None
        # Track tool call count for discipline injection
        self.tool_call_count: int = 0

    def ensure_trace_loaded(self) -> Optional[dict]:
        """Check that a trace is loaded; return error dict if not."""
        if self.current_trace is None:
            return {"error": "No trace loaded. Call trace_open first."}
        return None

    def run_tenet(self, args: list, timeout: int = 120) -> dict:
        """Run tenet CLI with given arguments and return parsed output."""
        cmd = [self.tenet_bin] + args
        log(f"exec: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "tenet command timed out", "returncode": -1}
        except FileNotFoundError:
            return {"stdout": "", "stderr": f"tenet binary not found: {self.tenet_bin}", "returncode": -1}
