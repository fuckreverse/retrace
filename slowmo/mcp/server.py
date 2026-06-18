"""
tenet MCP Server — main server logic.

Handles:
- JSON-RPC message dispatch (initialize, tools/list, tools/call, ping)
- Session lifecycle
- Discipline injection on tool responses
- Hypothesis ledger integration
"""

import json
from typing import Optional

from .config import PROTOCOL_VERSION, SERVER_NAME, SERVER_VERSION
from .session import Session, log
from .transport import StdioTransport
from .hypothesis.ledger import HypothesisLedger
from .hypothesis.tools import register_hypothesis_tools, init as init_hypothesis
from .discipline import DisciplineInjector
from .tools import TOOLS, TOOL_HANDLERS
from .tools import trace, taint, graph, memory, analysis, search, evidence, fold, context, batch, mem_search


class TenetMcpServer:
    """Main MCP server orchestrator."""

    def __init__(self, tenet_bin: str):
        self.session = Session(tenet_bin=tenet_bin)
        self.ledger = HypothesisLedger()
        self.discipline = DisciplineInjector(short_interval=5, full_interval=20)

        # Initialize all tool modules with session reference
        trace.init(self.session)
        taint.init(self.session)
        graph.init(self.session)
        memory.init(self.session)
        analysis.init(self.session)
        search.init(self.session)
        evidence.init(self.session)
        fold.init(self.session)
        context.init(self.session)
        batch.init(self.session)
        mem_search.init(self.session)

        # Initialize hypothesis tools with ledger
        init_hypothesis(self.ledger)
        register_hypothesis_tools()

        log(f"Registered {len(TOOLS)} tools, {len(TOOL_HANDLERS)} handlers")

    def process_message(self, msg: dict) -> Optional[dict]:
        """Process a single JSON-RPC message and return a response."""
        method = msg.get("method", "")
        msg_id = msg.get("id")
        params = msg.get("params", {})

        # Notifications (no id) — no response expected
        if msg_id is None:
            if method == "notifications/initialized":
                log("Client initialized.")
            return None

        if method == "initialize":
            result = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False}
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION,
                },
            }
            return {"jsonrpc": "2.0", "id": msg_id, "result": result}

        elif method == "tools/list":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}

        elif method == "tools/call":
            result = self._handle_tool_call(params)
            return {"jsonrpc": "2.0", "id": msg_id, "result": result}

        elif method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

        else:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }

    def _handle_tool_call(self, params: dict) -> dict:
        """Handle tools/call with discipline injection."""
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        handler = TOOL_HANDLERS.get(tool_name)
        if not handler:
            return {
                "content": [{"type": "text", "text": json.dumps({"error": f"Unknown tool: {tool_name}"})}],
                "isError": True,
            }

        try:
            result = handler(arguments)

            # Track tool calls in session
            self.session.tool_call_count += 1

            # Discipline injection
            discipline_msg = self.discipline.on_tool_call(tool_name)
            if discipline_msg:
                result["_discipline"] = discipline_msg

            text_content = json.dumps(result, ensure_ascii=False, indent=2)
            return {
                "content": [{"type": "text", "text": text_content}],
                "isError": False,
            }
        except Exception as e:
            log(f"Tool {tool_name} error: {e}")
            return {
                "content": [{"type": "text", "text": json.dumps({"error": str(e)})}],
                "isError": True,
            }

    def run(self):
        """Start the server (stdio transport)."""
        log(f"tenet-mcp server v{SERVER_VERSION} starting...")
        log(f"tenet binary: {self.session.tenet_bin}")
        log(f"Protocol: MCP {PROTOCOL_VERSION}")
        log(f"Tools loaded: {len(TOOLS)}")

        transport = StdioTransport(self.process_message)
        transport.run()

        log("tenet-mcp server exiting.")
