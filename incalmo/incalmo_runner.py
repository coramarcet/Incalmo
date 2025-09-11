import asyncio
from incalmo.core.strategies.incalmo_strategy import IncalmoStrategy
from config.attacker_config import AttackerConfig
from incalmo.models.attack_report import AttackReport

# TODO Does not work without this import. Needed for imports? Debug this
from incalmo.core.strategies.llm.langchain_strategy import LangChainStrategy

TIMEOUT_SECONDS = 75 * 60


async def run_incalmo_strategy(config: AttackerConfig, task_id: str) -> AttackReport:
    """Run incalmo with the specified strategy"""

    if not config.strategy.planning_llm:
        raise Exception("No planning llm specified")

    strategy = IncalmoStrategy.build_strategy(
        config.strategy.planning_llm, config, task_id
    )

    await strategy.initialize()

    start_time = asyncio.get_event_loop().time()

    while True:
        result = await strategy.main()
        if result:
            break
        if asyncio.get_event_loop().time() - start_time > TIMEOUT_SECONDS:
            break
        await asyncio.sleep(0.5)

    return strategy.environment_state_service.get_attack_report(task_id)
