from ..low_level_action import LowLevelAction
from incalmo.core.models.attacker.agent import Agent
from incalmo.models.command_result import CommandResult

from incalmo.core.models.events import Event, VulnerableServiceFound


class NiktoScan(LowLevelAction):
    def __init__(
        self,
        agent: Agent,
        host: str,
        port: int,
        service: str,
        is_ssl: bool = False,
    ):
        self.host = host
        self.port = port
        self.service = service
        self.is_ssl = is_ssl

        # Use https:// for SSL services, otherwise use regular host
        if is_ssl:
            target = f"https://{host}"
        else:
            target = host
            
        command = f"nikto -h {target} -p {port} -maxtime 10s -timeout 3 -ask no"
        super().__init__(agent, command)

    async def get_result(
        self,
        result: CommandResult,
    ) -> list[Event]:
        if result.output is None:
            return []

        if "CVE-2017-5638" in result.output:
            return [
                VulnerableServiceFound(
                    port=self.port,
                    host=self.host,
                    service=self.service,
                    cve="CVE-2017-5638",
                )
            ]

        return []
