#!/usr/bin/env python3
"""
Entry point for: python -m mcp

Usage:
    cd tools/tenet && python -m mcp [--tenet-bin /path/to/tenet]
"""

import argparse
import sys
import os

# Allow running from tools/tenet/ directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.config import TENET_BIN
from mcp.server import TenetMcpServer


def main():
    parser = argparse.ArgumentParser(
        description="tenet MCP Server — trace analysis for AI agents"
    )
    parser.add_argument(
        "--tenet-bin",
        default=TENET_BIN,
        help="Path to tenet binary (default: $TENET_BIN or 'tenet')"
    )
    args = parser.parse_args()

    server = TenetMcpServer(tenet_bin=args.tenet_bin)
    server.run()


if __name__ == "__main__":
    main()
