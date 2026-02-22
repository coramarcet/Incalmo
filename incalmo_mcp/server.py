"""FastMCP instance, service singletons, and the public configure/run API."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from mcp.server.fastmcp import FastMCP

from incalmo.core.services.attack_graph_service import AttackGraphService
from incalmo.core.services.environment_state_service import EnvironmentStateService

if TYPE_CHECKING:
    from incalmo.core.services.high_level_action_orchestrator import (
        HighLevelActionOrchestrator,
    )

MCP_PORT = 8765

mcp_server = FastMCP(
    "incalmo-mcp",
    instructions=(
        "Provides live Incalmo environment state and attack graph as subscribable "
        "resources, and the high-level action catalogue as a tool."
    ),
    host="0.0.0.0",
    port=MCP_PORT,
)

_env_service: EnvironmentStateService | None = None
_graph_service: AttackGraphService | None = None
_high_level_orch: HighLevelActionOrchestrator | None = None


def get_services() -> tuple[EnvironmentStateService, AttackGraphService]:
    """Return the live service instances; raise if not yet configured."""
    if _env_service is None or _graph_service is None:
        raise RuntimeError(
            "Incalmo services are not initialised. "
            "Call configure_services() before running the server."
        )
    return _env_service, _graph_service


def get_orchestrator() -> HighLevelActionOrchestrator:
    """Return the high-level action orchestrator; raise if not configured."""
    if _high_level_orch is None:
        raise RuntimeError(
            "High-level orchestrator is not configured. "
            "Pass high_level_orchestrator to configure_services()."
        )
    return _high_level_orch


def configure_services(
    env_service: EnvironmentStateService,
    graph_service: AttackGraphService,
    high_level_orchestrator: HighLevelActionOrchestrator | None = None,
) -> None:
    """
    Inject the live service instances created by the running strategy.

    Pass high_level_orchestrator to enable the MCP execution tools (scan,
    lateral_move_to_host, escalate_privilege, etc.).  If omitted the server
    starts in read-only mode — resources and list_available_actions work, but
    the execution tools will raise at call time.

    Call once at startup, then run the server as a background task:

        from incalmo_mcp import configure_services, run_server
        configure_services(env_service, graph_service, high_level_orchestrator)
        asyncio.create_task(run_server())
    """
    global _env_service, _graph_service, _high_level_orch
    _env_service = env_service
    _graph_service = graph_service
    _high_level_orch = high_level_orchestrator


async def run_server() -> None:
    """
    Start the MCP server over SSE. Call configure_services() first.

    Listens on http://0.0.0.0:{MCP_PORT}/sse so clients can connect from
    outside the container. Uses SSE (not stdio) so it does not interfere
    with the process's stdin/stdout, which Incalmo uses for logging.
    """
    get_services()  # validates they are set before entering the serve loop
    try:
        await mcp_server.run_sse_async()
    except asyncio.CancelledError:
        if not asyncio.current_task().cancelling():
            raise
