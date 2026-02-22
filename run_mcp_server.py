"""
Standalone entry point for the Incalmo MCP server.

Run this to start the MCP SSE server without launching a full strategy, e.g.
to test that resources and tools are reachable:

    python run_mcp_server.py

Then verify with:
    curl -N http://localhost:8765/sse
"""

import asyncio

from incalmo.core.services.attack_graph_service import AttackGraphService
from incalmo.core.services.config_service import ConfigService
from incalmo.core.services.environment_state_service import EnvironmentStateService
from incalmo.api.server_api import C2ApiClient
from incalmo_mcp import configure_services, run_server


async def main() -> None:
    config = ConfigService().get_config()
    c2api_client = C2ApiClient()
    env_service = EnvironmentStateService(c2api_client, config)
    graph_service = AttackGraphService(env_service)
    configure_services(env_service, graph_service)
    print(f"Starting MCP server on http://0.0.0.0:8765/sse — Ctrl+C to stop")
    await run_server()


if __name__ == "__main__":
    asyncio.run(main())
