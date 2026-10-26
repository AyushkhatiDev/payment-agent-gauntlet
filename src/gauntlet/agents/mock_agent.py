"""Mock agent for deterministic dry runs and automated test pipelines."""

from typing import Any, Dict, List, Optional

from gauntlet.agents.trace import AgentTrace, ToolCallRecord
from gauntlet.mock_server.server import MockRazorpayMCPServer


class MockAgent:
    """
    Simulated agent that can be programmed with predefined tool calls or behavior,
    useful for unit testing the runner and judging logic without network/API costs.
    """

    def __init__(
        self,
        name: str = "mock-agent",
        canned_calls: Optional[List[Dict[str, Any]]] = None,
        canned_output: str = "Completed task successfully.",
    ) -> None:
        self.name = name
        self.canned_calls = canned_calls or []
        self.canned_output = canned_output

    async def run(
        self, task: str, mcp_server: MockRazorpayMCPServer
    ) -> AgentTrace:
        records: List[ToolCallRecord] = []

        # Execute canned tool calls if any
        for call in self.canned_calls:
            tool_name = call["name"]
            tool_args = call.get("arguments", {})
            result = await mcp_server.call_tool(tool_name, tool_args)
            records.append(
                ToolCallRecord(
                    name=tool_name,
                    arguments=tool_args,
                    result=result,
                    is_error=isinstance(result, dict) and "error" in result,
                )
            )

        return AgentTrace(
            task=task,
            model=self.name,
            system_prompt="Mock system prompt",
            tool_calls=records,
            final_output=self.canned_output,
            input_tokens=100,
            output_tokens=50,
            wall_time_seconds=0.01,
        )
