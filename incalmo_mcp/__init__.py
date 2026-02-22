"""
Incalmo MCP Server package.

Exposes Incalmo's environment state and attack graph as subscribable MCP
resources, and high-level attack actions as executable MCP tools.

Usage::

    from incalmo_mcp import configure_services, run_server
    configure_services(environment_state_service, attack_graph_service)
    asyncio.create_task(run_server())
"""

from .server import configure_services, run_server

# Importing these subpackages triggers their @mcp_server.resource / @mcp_server.tool
# decorator registrations. The imports must happen after server.py is loaded so
# that the mcp_server instance already exists when the decorators run.
from . import resources, tools  # noqa: F401 — side-effect imports

__all__ = ["configure_services", "run_server"]
