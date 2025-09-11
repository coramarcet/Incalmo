from incalmo.incalmo_runner import run_incalmo_strategy
from config.attacker_config import AttackerConfig
import asyncio

from incalmo.c2server.celery.celery_worker import celery_worker
from incalmo.c2server.shared import TaskState


@celery_worker.task(bind=True, name="run_incalmo_strategy_task")
def run_incalmo_strategy_task(self, config_dict: dict):
    config = AttackerConfig(**config_dict)
    if not config.id:
        raise Exception("No task ID specified")

    # Run the strategy
    task_id = config.id
    asyncio.run(run_incalmo_strategy(config, task_id))

    return {"status": str(TaskState.SUCCESS)}


@celery_worker.task(bind=True, name="cancel_strategy_task")
def cancel_strategy_task(self, task_id: str):
    """Cancel a running strategy task."""
    celery_worker.control.revoke(task_id, terminate=True, signal="SIGTERM")
    return {"status": str(TaskState.SUCCESS), "message": f"Task {task_id} cancelled"}
