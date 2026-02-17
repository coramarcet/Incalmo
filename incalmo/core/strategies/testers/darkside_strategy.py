import random
from abc import ABC
from enum import Enum

from incalmo.core.strategies.incalmo_strategy import IncalmoStrategy
from incalmo.core.actions.HighLevel import (
    FindInformationOnAHost,
    AttackPathLateralMove,
    LateralMoveToHost,
    Scan,
    ExfiltrateData,
    EscelatePrivledge,
)
from incalmo.core.models.network import Host
from incalmo.core.models.events import InfectedNewHost
from incalmo.core.strategies.util.event_util import any_events_are_type
from config.attacker_config import AttackerConfig


class DarksideState(Enum):
    InitialAccess = 0
    InfectNetwork = 1
    CompleteMission = 2
    Finished = 3


class DarksideStrategy(IncalmoStrategy, ABC, name="darkside_strategy"):
    """
    A simulation of the Darkside ransomware group's attack strategy.

    This strategy models the two-phase approach used by Darkside:
      1. InitialAccess - gain a foothold via the webserver, then spread to the
         first reachable host via attack paths.
      2. InfectNetwork - iteratively explore each newly infected host: escalate
         privileges, perform internal recon, then attempt lateral movement to
         all uninfected hosts.
      3. CompleteMission - once the whole reachable network is infected,
         exfiltrate critical data from every compromised host.
      4. Finished - signal campaign completion.
    """

    def __init__(self, config: AttackerConfig, **kwargs):
        super().__init__(config, **kwargs)

        self.logger = self.logging_service.setup_logger(logger_name="attacker")

        # Overall campaign state
        self.state = DarksideState.InitialAccess

        # Hosts that have already been fully explored
        self.hosts_explored: list[Host] = []

    #! STEP 1: Gather information about the current environment
    def collect_telemetry(self) -> None:
        """
        Observe current telemetry.
        The Incalmo services handle telemetry parsing into the world model,
        so no additional collection is needed here.
        """
        pass

    #! STEP 2: Update world model based on collected telemetry
    def update_world_model(self) -> dict:
        """
        Build a snapshot of the current environment state.
        """
        agents = self.c2_client.get_agents()
        hosts = self.environment_state_service.network.get_all_hosts()
        subnets = self.environment_state_service.network.get_all_subnets()
        hosts_with_agents = self.environment_state_service.get_hosts_with_agents()
        hosts_without_agents = self.environment_state_service.get_hosts_without_agents()

        return {
            "agents": agents,
            "hosts": hosts,
            "subnets": subnets,
            "hosts_with_agents": hosts_with_agents,
            "hosts_without_agents": hosts_without_agents,
        }

    #! STEP 3: Plan your next action based on the updated world model
    def planner(self, world_model: dict) -> None:
        """
        No additional stateful planning needed — phase transitions are handled
        inside each act helper based on observed results.
        """
        pass

    #! STEP 4: Execute your chosen action
    async def act(self, world_model: dict) -> None:
        """
        Dispatch to the appropriate phase handler.
        """
        if self.state == DarksideState.InitialAccess:
            await self._initial_access(world_model)

        elif self.state == DarksideState.InfectNetwork:
            await self._infect_network(world_model)

        elif self.state == DarksideState.CompleteMission:
            await self._complete_mission(world_model)

        elif self.state == DarksideState.Finished:
            self.logger.info("Darkside campaign finished.")

    # ------------------------------------------------------------------ #
    # Internal phase helpers                                               #
    # ------------------------------------------------------------------ #

    async def _initial_access(self, world_model: dict) -> None:
        """
        Scan each host that already has an agent, then attempt attack-path
        lateral moves until one succeeds (InfectedNewHost event). If no path
        succeeds, transition directly to Finished.
        """
        for host in world_model["hosts_with_agents"]:
            self.hosts_explored.append(host)
            scan = Scan(host, world_model["subnets"])
            await self.high_level_action_orchestrator.run_action(scan)
            self.logger.info(f"Scanned initial host: {host}")

        # Collect and shuffle all attack paths from initial hosts
        paths = []
        for host in world_model["hosts_with_agents"]:
            new_paths = self.attack_graph_service.get_possible_targets_from_host(host)
            paths.extend(new_paths)

        random.shuffle(paths)

        for path in paths:
            events = await self.high_level_action_orchestrator.run_action(
                AttackPathLateralMove(path, skip_if_already_executed=True)
            )
            if any_events_are_type(events, InfectedNewHost):
                self.logger.info(f"Initial access gained via path: {path}")
                self.state = DarksideState.InfectNetwork
                return

        # No path succeeded
        self.logger.info("Unable to gain initial access — no viable attack paths")
        self.state = DarksideState.Finished

    async def _infect_network(self, world_model: dict) -> None:
        """
        Pick the next unexplored infected host and:
          1. Escalate privileges
          2. Gather host information (internal recon)
          3. Attempt lateral movement to every uninfected host

        When all infected hosts have been explored, transition to CompleteMission.
        """
        host_to_explore = None
        for host in world_model["hosts_with_agents"]:
            if host not in self.hosts_explored:
                host_to_explore = host
                break

        if host_to_explore is None:
            self.logger.info("All infected hosts explored — moving to CompleteMission")
            self.state = DarksideState.CompleteMission
            return

        self.hosts_explored.append(host_to_explore)
        self.logger.info(f"Exploring host: {host_to_explore}")

        # Escalate privileges
        await self.high_level_action_orchestrator.run_action(
            EscelatePrivledge(host_to_explore)
        )
        self.logger.info(f"Escalated privileges on: {host_to_explore}")

        # Internal recon
        await self.high_level_action_orchestrator.run_action(
            FindInformationOnAHost(host_to_explore)
        )
        self.logger.info(f"Collected information from: {host_to_explore}")

        # Scan from this host to discover new hosts in the network model
        await self.high_level_action_orchestrator.run_action(
            Scan(host_to_explore, world_model["subnets"])
        )
        self.logger.info(f"Scanned from: {host_to_explore}")

        # Lateral movement to all uninfected hosts (now includes newly discovered hosts)
        uninfected_hosts = list(self.environment_state_service.get_hosts_without_agents())
        random.shuffle(uninfected_hosts)
        for uninfected_host in uninfected_hosts:
            await self.high_level_action_orchestrator.run_action(
                LateralMoveToHost(uninfected_host, host_to_explore)
            )
            self.logger.info(
                f"Attempted lateral move from {host_to_explore} to {uninfected_host}"
            )

    async def _complete_mission(self, world_model: dict) -> None:
        """
        Exfiltrate critical data from every compromised host, then finish.
        """
        for host in world_model["hosts_with_agents"]:
            if len(host.critical_data_files) > 0:
                await self.high_level_action_orchestrator.run_action(
                    ExfiltrateData(host)
                )
                self.logger.info(f"Exfiltrated data from: {host}")

        self.state = DarksideState.Finished

    # ------------------------------------------------------------------ #
    # Main loop                                                            #
    # ------------------------------------------------------------------ #

    async def step(self) -> bool:
        """
        Called repeatedly until the campaign is complete.

        Returns:
            bool: True when the Darkside campaign is finished, False while
                  work remains.
        """
        self.collect_telemetry()                 #! STEP 1: Gather information
        world_model = self.update_world_model()  #! STEP 2: Update world model
        self.planner(world_model)                #! STEP 3: Plan next action
        await self.act(world_model)              #! STEP 4: Execute action

        if self.state == DarksideState.Finished:
            self.logger.info("Darkside strategy completed successfully")
            return True

        return False
