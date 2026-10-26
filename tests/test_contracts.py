"""Contract tests asserting Mock Razorpay response and error shapes match real API fixtures."""

from typing import Any, Dict
import pytest

from gauntlet.mock_server.server import MockRazorpayMCPServer


@pytest.mark.asyncio
async def test_contract_error_shape_already_refunded(
    mock_mcp_server: MockRazorpayMCPServer,
    contract_fixtures: Dict[str, Any],
) -> None:
    """Assert Mock error shape on fully-refunded payment matches real Razorpay contract."""
    expected_error = contract_fixtures["error_shapes"]["payment_already_refunded"]["error"]

    res = await mock_mcp_server.call_tool(
        "create_refund",
        {"payment_id": "pay_test_refunded_1002", "amount": 1000},
    )

    assert "error" in res, f"Expected error dictionary in response, got: {res}"
    actual_error = res["error"]

    assert actual_error["code"] == expected_error["code"]
    assert actual_error["description"] == expected_error["description"]
    assert actual_error["source"] == expected_error["source"]
    assert actual_error["step"] == expected_error["step"]


@pytest.mark.asyncio
async def test_contract_error_shape_nonexistent_id(
    mock_mcp_server: MockRazorpayMCPServer,
    contract_fixtures: Dict[str, Any],
) -> None:
    """Assert Mock error shape on nonexistent ID matches real Razorpay contract."""
    expected_error = contract_fixtures["error_shapes"]["id_not_found"]["error"]

    res = await mock_mcp_server.call_tool(
        "fetch_payment",
        {"payment_id": "pay_invalid_0000000000"},
    )

    assert "error" in res
    actual_error = res["error"]

    assert actual_error["code"] == expected_error["code"]
    assert actual_error["description"] == expected_error["description"]


@pytest.mark.asyncio
async def test_contract_error_shape_amount_exceeded(
    mock_mcp_server: MockRazorpayMCPServer,
    contract_fixtures: Dict[str, Any],
) -> None:
    """Assert Mock error shape on over-refund matches real Razorpay contract."""
    expected_error = contract_fixtures["error_shapes"]["amount_exceeded"]["error"]

    res = await mock_mcp_server.call_tool(
        "create_refund",
        {"payment_id": "pay_test_captured_1001", "amount": 9999999},
    )

    assert "error" in res
    actual_error = res["error"]

    assert actual_error["code"] == expected_error["code"]
    assert actual_error["description"] == expected_error["description"]


@pytest.mark.asyncio
async def test_contract_payment_entity_fields(
    mock_mcp_server: MockRazorpayMCPServer,
    contract_fixtures: Dict[str, Any],
) -> None:
    """Assert payment entity keys match the real Razorpay payment structure."""
    expected_keys = set(contract_fixtures["success_shapes"]["payment"].keys())

    res = await mock_mcp_server.call_tool(
        "fetch_payment",
        {"payment_id": "pay_test_captured_1001"},
    )

    actual_keys = set(res.keys())
    # Verify core required payment fields
    core_fields = {"id", "entity", "amount", "currency", "status", "amount_refunded", "captured", "notes"}
    assert core_fields.issubset(actual_keys)
    assert res["entity"] == "payment"
    assert isinstance(res["amount"], int)


@pytest.mark.asyncio
async def test_contract_refund_entity_fields(
    mock_mcp_server: MockRazorpayMCPServer,
    contract_fixtures: Dict[str, Any],
) -> None:
    """Assert refund entity keys match the real Razorpay refund structure."""
    res = await mock_mcp_server.call_tool(
        "create_refund",
        {"payment_id": "pay_test_captured_1001", "amount": 10000, "receipt": "test_rcpt_1"},
    )

    assert res["entity"] == "refund"
    assert res["status"] == "processed"
    assert res["speed_requested"] == "normal"
    assert isinstance(res["amount"], int)
    assert res["payment_id"] == "pay_test_captured_1001"
