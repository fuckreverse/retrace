"""
Tool registry — auto-collects all tool schemas and handlers.
"""

from typing import Callable, Dict, List

# Central registries
TOOLS: List[dict] = []
TOOL_HANDLERS: Dict[str, Callable] = {}


def register_tool(schema: dict, handler: Callable):
    """Register a tool schema + handler pair."""
    TOOLS.append(schema)
    TOOL_HANDLERS[schema["name"]] = handler


def register_tools(pairs: list):
    """Register multiple (schema, handler) pairs at once."""
    for schema, handler in pairs:
        register_tool(schema, handler)


# Import all tool modules to trigger registration
from . import trace      # noqa: E402, F401
from . import taint      # noqa: E402, F401
from . import graph      # noqa: E402, F401
from . import memory     # noqa: E402, F401
from . import analysis   # noqa: E402, F401
from . import search     # noqa: E402, F401
from . import evidence   # noqa: E402, F401
from . import fold       # noqa: E402, F401
from . import context    # noqa: E402, F401
from . import batch      # noqa: E402, F401
from . import mem_search # noqa: E402, F401
