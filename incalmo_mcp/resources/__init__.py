"""Import submodules so their @mcp_server.resource decorators are registered."""

from . import attack_graph, environment

__all__ = ["environment", "attack_graph"]
