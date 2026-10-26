"""Unit tests for LLMClient implementations and schema conversions."""

import pytest

from gauntlet.agents.llm_client import AnthropicClient, OpenAICompatibleClient
from gauntlet.mock_server.schemas import ALL_MOCK_TOOLS


def test_openai_compatible_client_tool_conversion() -> None:
    """Verify conversion from MCP schemas to OpenAI function definitions."""
    client = OpenAICompatibleClient(
        base_url="http://localhost:11434/v1",
        model="llama3.1",
        api_key="dummy_key",
    )

    mcp_tools = [ALL_MOCK_TOOLS["create_refund"], ALL_MOCK_TOOLS["fetch_payment"]]
    openai_tools = client._convert_tools(mcp_tools)

    assert len(openai_tools) == 2
    refund_tool = openai_tools[0]
    assert refund_tool["type"] == "function"
    assert refund_tool["function"]["name"] == "create_refund"
    assert "payment_id" in refund_tool["function"]["parameters"]["properties"]
    assert "amount" in refund_tool["function"]["parameters"]["properties"]


def test_anthropic_client_tool_conversion() -> None:
    """Verify conversion from MCP schemas to Anthropic tool definitions."""
    client = AnthropicClient(
        model="claude-3-5-haiku-20241022",
        api_key="dummy_ant_key",
    )

    mcp_tools = [ALL_MOCK_TOOLS["create_instant_settlement"]]
    anthropic_tools = client._convert_tools(mcp_tools)

    assert len(anthropic_tools) == 1
    settle_tool = anthropic_tools[0]
    assert settle_tool["name"] == "create_instant_settlement"
    assert "amount" in settle_tool["input_schema"]["properties"]
