"""
LangChain interface that drives an LLM via native MCP tool calls.

Each outer step runs an inner agent loop:

  1. The model queries live environment state by calling the named query
     tools (get_network_state, get_attack_paths_from, etc.).
  2. The model executes attack actions by calling the typed execution tools
     (scan, lateral_move_to_host, escalate_privilege, etc.).
  3. The loop continues until the model produces a text response with no
     tool calls — that text is returned to llm_strategy.py.

All tools are registered on the MCP server and discovered automatically
via client.get_tools() — no session access or custom tool construction
needed in this file.

If the final text contains <finished>, the outer strategy loop terminates
the engagement.  Otherwise llm_strategy.py sends a continuation prompt and
calls this interface again for the next step.
"""

from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_mcp_adapters.client import MultiServerMCPClient

from incalmo.core.strategies.llm.interfaces.langchain_interface import LangChainInterface
from incalmo.core.strategies.llm.llm_response import LLMResponse, LLMResponseType

MCP_URL = "http://localhost:8765/sse"

# Hard cap on consecutive tool calls within one outer step.  If the model
# keeps calling tools without producing a final text, we break the loop and
# ask it to summarise so the outer loop can make progress.
MAX_TOOL_ROUNDS = 30


class MCPLangChainInterface(LangChainInterface):
    """LangChain interface with a native MCP tool-calling agent loop."""

    async def get_llm_action(self, incalmo_response: str | None = None):
        if incalmo_response and len(incalmo_response) > self.max_message_len:
            incalmo_response = incalmo_response[: self.max_message_len]
            incalmo_response += "\n[Message truncated to fit within the max length]"

        llm_response = await self.get_response(incalmo_response)

        if "<finished>" in llm_response:
            return LLMResponse(LLMResponseType.FINISHED, llm_response)

        # Inner loop completed a full reasoning cycle but engagement is not over.
        return LLMResponse(LLMResponseType.MCP_STEP_DONE, llm_response)

    async def get_response(self, incalmo_response: str | None = None) -> str:
        if not incalmo_response and len(self.conversation) <= 1:
            incalmo_response = (
                "Hello, I need your assistance with a cybersecurity assessment."
            )

        if incalmo_response:
            self.conversation.append({"role": "user", "content": incalmo_response})
            self.logger.info(f"Incalmo's response:\n{incalmo_response}")

        client = MultiServerMCPClient(
            {"incalmo": {"url": MCP_URL, "transport": "sse"}}
        )
        # All tools — query tools (get_network_state, get_attack_paths_from, …)
        # and execution tools (scan, lateral_move_to_host, …) — are registered
        # on the MCP server and picked up here automatically.
        all_tools = await client.get_tools()
        model = self._registry.get_model(self.model_name).bind_tools(all_tools)
        lc_messages = _build_lc_messages(self.conversation)
        final_text = await _run_agent_loop(
            model, all_tools, lc_messages, self.logger, MAX_TOOL_ROUNDS
        )

        self.logger.info(f"{self.model_name} response:\n{final_text}")
        self.conversation.append({"role": "assistant", "content": final_text})
        return final_text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_lc_messages(conversation: list[dict]):
    """Convert the dict-based conversation history to LangChain message objects."""
    lc = []
    for msg in conversation:
        role = msg["role"]
        content = msg["content"]
        if role == "system":
            lc.append(SystemMessage(content=content))
        elif role == "user":
            lc.append(HumanMessage(content=content))
        elif role == "assistant":
            lc.append(AIMessage(content=content))
    return lc


async def _run_agent_loop(model, tools, lc_messages, logger, max_rounds: int) -> str:
    """
    Run the model/tool loop until the model produces a final text response.

    Returns the final text string.  If max_rounds is reached before the model
    stops calling tools, a forced summarisation prompt is injected and one
    final model call is made.
    """
    tool_map = {t.name: t for t in tools}

    for _ in range(max_rounds):
        response = await model.ainvoke(lc_messages)
        lc_messages.append(response)

        if not response.tool_calls:
            return response.content

        for tc in response.tool_calls:
            tool_name = tc["name"]
            tool_args = tc["args"]
            tool_call_id = tc["id"]

            logger.info(f"[MCP tool call] {tool_name}({tool_args})")

            if tool_name not in tool_map:
                result_text = f"Error: unknown tool '{tool_name}'"
            else:
                try:
                    result_text = str(await tool_map[tool_name].ainvoke(tool_args))
                except Exception as exc:
                    result_text = f"Error executing {tool_name}: {exc}"

            logger.info(f"[MCP tool result] {tool_name} -> {result_text[:200]}")
            lc_messages.append(
                ToolMessage(content=result_text, tool_call_id=tool_call_id)
            )

    # Safety exit: model kept calling tools for max_rounds rounds.
    logger.warning(
        f"[MCPLangChainInterface] Reached {max_rounds} tool-call rounds; "
        "forcing a final response."
    )
    lc_messages.append(
        HumanMessage(
            content=(
                f"You have made {max_rounds} consecutive tool calls. "
                "Summarise what you have learned and accomplished so far, "
                "then output <finished> if the engagement is complete or "
                "describe your next planned step if it is not."
            )
        )
    )
    response = await model.ainvoke(lc_messages)
    return response.content
