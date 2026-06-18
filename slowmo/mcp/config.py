"""
Configuration constants for tenet MCP server.
"""

import os

TENET_BIN = os.environ.get("TENET_BIN", "tenet")
SERVER_NAME = "tenet-trace-analyzer"
SERVER_VERSION = "0.2.0"
PROTOCOL_VERSION = "2024-11-05"

# Timeout presets (seconds)
TIMEOUT_LIGHT = 120    # disasm, regstate, memread, search
TIMEOUT_MEDIUM = 300   # taint, cfg, call_graph, loop_semantics
TIMEOUT_HEAVY = 600    # critical_path, algorithm_summary
