"""Agents package for Gauntlet."""

from gauntlet.agents.baseline import (
    BASELINE_SYSTEM_PROMPT,
    BASELINE_TOOL_NAMES,
    MINIMAL_SYSTEM_PROMPT,
    STRONG_SYSTEM_PROMPT,
    BaselineAgent,
)
from gauntlet.agents.llm_client import (
    AnthropicClient,
    LLMClient,
    LLMResponse,
    OpenAICompatibleClient,
    ToolCallItem,
)
from gauntlet.agents.mock_agent import MockAgent
from gauntlet.agents.scripted import ScriptedAgent
from gauntlet.agents.trace import AgentTrace, ToolCallRecord

__all__ = [
    "BaselineAgent",
    "MockAgent",
    "ScriptedAgent",
    "AgentTrace",
    "ToolCallRecord",
    "LLMClient",
    "LLMResponse",
    "ToolCallItem",
    "AnthropicClient",
    "OpenAICompatibleClient",
    "BASELINE_SYSTEM_PROMPT",
    "STRONG_SYSTEM_PROMPT",
    "MINIMAL_SYSTEM_PROMPT",
    "BASELINE_TOOL_NAMES",
]
