import random
from abc import ABC
from incalmo.core.strategies.incalmo_strategy import IncalmoStrategy

from config.attacker_config import AttackerConfig
from incalmo.core.actions.HighLevel import (
    Scan,
    FindInformationOnAHost,
    ExfiltrateData,
    EscelatePrivledge,
    AttackPathLateralMove,
)

from enum import Enum


class AgentState(Enum):
    FIND_HOST_INFORMATION = 0
    FINISHED = 1


class DFSState(Enum):
    InitialAccess = 0
    Spread = 1
    Finished = 2


class DFSStrategy(IncalmoStrategy, ABC, name="dfs_strategy"):
    """
    A DFS (Depth-First Search) graph traversal attack strategy.

    This strategy dives as deep as possible into the network before backtracking,
    prioritizing depth over breadth. It proceeds through three phases:
      1. InitialAccess - scan and gather information from hosts that already
         have agents, then seed the attack-path stack.
      2. Spread - pop the most recently discovered paths first (DFS order),
         escalate privileges, collect host information, exfiltrate any critical
         data, and prepend newly discovered paths to the front of the stack.
      3. Finished - all agents are done and the stack is empty; signal
         completion.

    The key difference from BFS: new attack paths are prepended to the front
    of the queue (stack behavior), so the most recently discovered paths are
    explored first, driving the search deeper before backtracking.
    """

    def __init__(self, config: AttackerConfig, **kwargs):
        super().__init__(config, **kwargs)

        self.logger = self.logging_service.setup_logger(logger_name="attacker")

        # Overall campaign state
        self.state = DFSState.InitialAccess

        # Per-agent state tracking: agent paw -> AgentState
        self.agent_states: dict[str, AgentState] = {}

        # DFS stack of AttackPath objects to process (front = top of stack)
        self.attack_path_queue = []

        # Paws of agents that existed before the campaign started
        self.initial_agents_paws = []

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
        all_agents = self.environment_state_service.get_agents()

        return {
            "agents": agents,
            "hosts": hosts,
            "subnets": subnets,
            "hosts_with_agents": hosts_with_agents,
            "all_agents": all_agents,
        }

    #! STEP 3: Plan your next action based on the updated world model
    def planner(self, world_model: dict) -> None:
        """
        Register any newly discovered agents so they get processed during Spread.
        """
        for agent in world_model["all_agents"]:
            if (
                agent.paw not in self.agent_states
                and agent.paw not in self.initial_agents_paws
            ):
                self.agent_states[agent.paw] = AgentState.FIND_HOST_INFORMATION

    #! STEP 4: Execute your chosen action
    async def act(self, world_model: dict) -> None:
        """
        Execute the action for the current campaign phase.
        """
        if self.state == DFSState.InitialAccess:
            await self._initial_access(world_model)

        elif self.state == DFSState.Spread:
            await self._spread()

        elif self.state == DFSState.Finished:
            self.logger.info("DFS campaign finished.")

    # ------------------------------------------------------------------ #
    # Internal phase helpers                                               #
    # ------------------------------------------------------------------ #

    async def _initial_access(self, world_model: dict) -> None:
        """
        Scan each host that already has an agent, collect host information,
        then seed the DFS stack with all reachable attack paths.
        """
        for host in world_model["hosts_with_agents"]:
            scan = Scan(host, world_model["subnets"])
            await self.high_level_action_orchestrator.run_action(scan)
            self.logger.info(f"Scanned initial host: {host}")

            find_info = FindInformationOnAHost(host)
            await self.high_level_action_orchestrator.run_action(find_info)
            self.logger.info(f"Collected information from initial host: {host}")

        # Seed the DFS stack from every initial host
        paths = []
        for host in world_model["hosts_with_agents"]:
            new_paths = self.attack_graph_service.get_possible_targets_from_host(host)
            paths.extend(new_paths)

        random.shuffle(paths)
        # DFS: prepend to the front so these are explored first
        self.attack_path_queue = paths + self.attack_path_queue
        self.logger.info(f"Seeded DFS stack with {len(paths)} attack paths")

        self.state = DFSState.Spread

    async def _spread(self) -> None:
        """
        One DFS iteration:
          - If stack is empty and all agents are done, transition to Finished.
          - Otherwise pop the front path (top of stack), attempt a lateral move,
            then process every agent that is in the FIND_HOST_INFORMATION state,
            prepending newly discovered paths to drive the search deeper.
        """
        if self._all_agents_finished() and len(self.attack_path_queue) == 0:
            self.state = DFSState.Finished
            return

        # Pop from the front for DFS ordering (stack behavior)
        if len(self.attack_path_queue) > 0:
            attack_path = self.attack_path_queue.pop(0)
            if not self.attack_graph_service.already_executed_attack_path(attack_path):
                await self.high_level_action_orchestrator.run_action(
                    AttackPathLateralMove(attack_path)
                )
                self.logger.info(f"Lateral move via attack path: {attack_path}")

        for agent_paw, agent_state in self.agent_states.items():
            if agent_state != AgentState.FIND_HOST_INFORMATION:
                continue

            agent = self.environment_state_service.get_agent_by_paw(agent_paw)
            host = self.environment_state_service.network.find_host_by_agent(agent)
            if host is None:
                continue

            # Escalate privileges if not already root
            if agent.username != "root":
                await self.high_level_action_orchestrator.run_action(
                    EscelatePrivledge(host)
                )
                self.logger.info(f"Escalated privileges on: {host}")

            # Gather host information
            await self.high_level_action_orchestrator.run_action(
                FindInformationOnAHost(host)
            )
            self.logger.info(f"Collected information from: {host}")

            # Exfiltrate any critical data found on this host
            if len(host.critical_data_files) > 0:
                await self.high_level_action_orchestrator.run_action(
                    ExfiltrateData(host)
                )
                self.logger.info(f"Exfiltrated data from: {host}")

            # DFS: prepend new paths to the front of the stack so they are
            # explored before any previously queued paths (go deeper first)
            new_paths = self.attack_graph_service.get_possible_targets_from_host(host)
            random.shuffle(new_paths)
            self.attack_path_queue = new_paths + self.attack_path_queue
            self.logger.info(f"Added {len(new_paths)} new paths to DFS stack")

            self.agent_states[agent_paw] = AgentState.FINISHED

    def _all_agents_finished(self) -> bool:
        return all(
            state == AgentState.FINISHED for state in self.agent_states.values()
        )

    # ------------------------------------------------------------------ #
    # Main loop                                                            #
    # ------------------------------------------------------------------ #

    async def step(self) -> bool:
        """
        Called repeatedly until the campaign is complete.

        Returns:
            bool: True when all hosts reachable via DFS have been processed,
                  False while work remains.
        """
        self.collect_telemetry()                 #! STEP 1: Gather information
        world_model = self.update_world_model()  #! STEP 2: Update world model
        self.planner(world_model)                #! STEP 3: Plan next action
        await self.act(world_model)              #! STEP 4: Execute action

        if self.state == DFSState.Finished:
            self.logger.info("DFS strategy completed successfully")
            return True

        return False
