"""Import submodules so their @mcp_server.tool decorators are registered."""

from . import execute, query

__all__ = ["execute", "query"]
