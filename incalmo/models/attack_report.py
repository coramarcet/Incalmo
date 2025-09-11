from pydantic import BaseModel
from incalmo.core.models.events import ExfiltratedData


class AttackReport(BaseModel):
    strategy_id: str
    # exfiltrated_data: list[ExfiltratedData]
    infected_hosts: dict[str, list[str]]
