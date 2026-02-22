from incalmo.core.strategies.llm.llm_strategy import LLMStrategy
from incalmo.core.strategies.llm.interfaces.llm_interface import LLMInterface
from incalmo.core.strategies.llm.interfaces.langchain_interface import (
    LangChainInterface,
)
from incalmo.core.strategies.llm.interfaces.mcp_langchain_interface import (
    MCPLangChainInterface,
)
from config.attacker_config import AbstractionLevel, AttackerConfig
from enum import Enum


class EquifaxAttackerState(Enum):
    InitialAccess = 0
    CredExfiltrate = 1
    Finished = 2


class LangChainStrategy(LLMStrategy, name="langchain"):
    def __init__(self, config: AttackerConfig, planning_llm: str = "", **kwargs):
        self.planning_llm = planning_llm
        super().__init__(config, **kwargs)

    def create_llm_interface(self) -> LLMInterface:
        if self.config.strategy.abstraction == AbstractionLevel.INCALMO_MCP:
            return MCPLangChainInterface(
                self.logger, self.environment_state_service, self.config
            )
        return LangChainInterface(
            self.logger, self.environment_state_service, self.config
        )
