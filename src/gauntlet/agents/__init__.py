"""Agents package for Gauntlet."""

from gauntlet.agents.baseline import (
    BASELINE_SYSTEM_PROMPT,
    BASELINE_TOOL_NAMES,
    BaselineAgent,
)
from gauntlet.agents.mock_agent import MockAgent
from gauntlet.agents.trace import AgentTrace, ToolCallRecord

__all__ = [
    "BaselineAgent",
    "MockAgent",
    "AgentTrace",
    "ToolCallRecord",
    "BASELINE_SYSTEM_PROMPT",
    "BASELINE_TOOL_NAMES",
]
