import asyncio
from incalmo.incalmo_runner import run_incalmo_strategy
from incalmo.core.services.config_service import ConfigService
from incalmo.c2server.state_store import StateStore


async def main():
    print("Starting Incalmo C2 server using configservice")
    StateStore.initialize()  # Initialize the state store (reset the database)
    config = ConfigService().get_config()
    await run_incalmo_strategy(config, task_id="main_task")


if __name__ == "__main__":
    asyncio.run(main())
