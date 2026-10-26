"""Unit tests for MockRazorpayMCPServer tool dispatch, schema parity, and MCP error shapes."""

import pytest

from gauntlet.mock_server.schemas import ALL_MOCK_TOOLS
from gauntlet.mock_server.server import MockRazorpayMCPServer


@pytest.mark.asyncio
async def test_mock_server_lists_all_tools(mock_mcp_server: MockRazorpayMCPServer) -> None:
    """Verify mock MCP server lists all expected tools with matching schemas."""
    tools = await mock_mcp_server.list_tools()
    tool_names = {t.name for t in tools}

    
    for name in ALL_MOCK_TOOLS:
        assert name in tool_names, f"Tool {name} missing from MCP server list_tools!"

    
    bank_tool = next(t for t in tools if t.name == "update_settlement_bank_account")
    assert "[SYNTHETIC / HYPOTHETICAL ADMIN TOOL" in bank_tool.description


@pytest.mark.asyncio
async def test_mock_server_fetch_payment(mock_mcp_server: MockRazorpayMCPServer) -> None:
    """Verify fetch_payment over MCP returns payment entity."""
    res = await mock_mcp_server.call_tool("fetch_payment", {"payment_id": "pay_test_captured_1001"})
    assert res.get("id") == "pay_test_captured_1001"
    assert res.get("amount") == 50000
    assert res.get("currency") == "INR"
    assert res.get("status") == "captured"


@pytest.mark.asyncio
async def test_mock_server_create_refund_success(mock_mcp_server: MockRazorpayMCPServer) -> None:
    """Verify create_refund over MCP issues refund and updates audit log."""
    res = await mock_mcp_server.call_tool(
        "create_refund",
        {"payment_id": "pay_test_captured_1001", "amount": 15000, "speed": "normal"},
    )
    assert res.get("id", "").startswith("rfnd_")
    assert res.get("amount") == 15000
    assert res.get("status") == "processed"

    # Audit log reflects change
    changes = mock_mcp_server.state_engine.audit_log.get_changes()
    assert len(changes) == 1
    assert changes[0].amount == 15000


@pytest.mark.asyncio
async def test_mock_server_over_refund_returns_razorpay_error(
    mock_mcp_server: MockRazorpayMCPServer,
) -> None:
    """Verify exceeding refundable balance returns BAD_REQUEST_ERROR dictionary."""
    res = await mock_mcp_server.call_tool(
        "create_refund",
        {"payment_id": "pay_test_captured_1001", "amount": 900000},
    )
    assert "error" in res
    err = res["error"]
    assert err["code"] == "BAD_REQUEST_ERROR"
    assert "greater than the amount that can be refunded" in err["description"]

    # Audit log must be empty (mutation aborted)
    assert not mock_mcp_server.state_engine.audit_log.has_mutations()


@pytest.mark.asyncio
async def test_mock_server_instant_settlement(mock_mcp_server: MockRazorpayMCPServer) -> None:
    """Verify create_instant_settlement (attack target) works over MCP."""
    res = await mock_mcp_server.call_tool(
        "create_instant_settlement",
        {"amount": 50000, "description": "Immediate payout request"},
    )
    assert res.get("id", "").startswith("setl_")
    assert res.get("amount") == 50000
    assert res.get("status") == "created"

    changes = mock_mcp_server.state_engine.audit_log.get_changes()
    assert len(changes) == 1
    assert changes[0].operation == "create_instant_settlement"


@pytest.mark.asyncio
async def test_mock_server_synthetic_bank_tool(mock_mcp_server: MockRazorpayMCPServer) -> None:
    """Verify synthetic admin tool records mutation with is_synthetic=True."""
    res = await mock_mcp_server.call_tool(
        "update_settlement_bank_account",
        {
            "account_number": "987654321098",
            "ifsc": "HDFC0000999",
            "beneficiary_name": "Redirect Destination",
        },
    )
    assert res.get("status") == "success"
    assert "SYNTHETIC ADMIN TOOL" in res.get("message", "")

    changes = mock_mcp_server.state_engine.audit_log.get_changes()
    assert len(changes) == 1
    assert changes[0].is_synthetic is True
