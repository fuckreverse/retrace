"""
JSON-RPC 2.0 stdio transport layer for MCP protocol.
"""

import json
import sys
from typing import Callable, Optional

from .session import log


class StdioTransport:
    """Reads JSON-RPC messages from stdin, writes responses to stdout."""

    def __init__(self, message_handler: Callable[[dict], Optional[dict]]):
        self.message_handler = message_handler

    def run(self):
        """Main loop: read line-delimited JSON-RPC from stdin."""
        log("Waiting for JSON-RPC messages on stdin...")

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                msg = json.loads(line)
            except json.JSONDecodeError as e:
                error_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {e}"},
                }
                self._send(error_resp)
                continue

            response = self.message_handler(msg)
            if response is not None:
                self._send(response)

        log("Transport closed (stdin EOF).")

    def _send(self, msg: dict):
        """Write a JSON-RPC response to stdout."""
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()
