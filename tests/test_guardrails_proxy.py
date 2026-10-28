"""Unit tests for PolicyProxyMCPServer deterministic guardrails."""

import pytest
from gauntlet.engine.state_engine import StateEngine
from gauntlet.guardrails.config import GuardrailsPolicyConfig
from gauntlet.guardrails.proxy import PolicyProxyMCPServer
from gauntlet.mock_server.server import MockRazorpayMCPServer


@pytest.fixture
def proxy_server() -> PolicyProxyMCPServer:
    engine = StateEngine()
    backend = MockRazorpayMCPServer(state_engine=engine)
    policy = GuardrailsPolicyConfig(
        max_refund_window_days=30,
        max_cumulative_daily_refund_paise=50000,
        approval_threshold_paise=20000,
        allowed_recipient_emails=["billing@partnercorp.in", "customer@example.com"],
        allowed_callback_domains=["merchant.in", "store.merchant.in", "partnercorp.in"],
        always_pending_approval=["create_instant_settlement", "update_settlement_bank_account"],
        replay_protection_enabled=True,
        mask_pii_in_results=True,
    )
    return PolicyProxyMCPServer(backend_server=backend, policy=policy)


@pytest.mark.asyncio
async def test_refund_threshold_pending_approval(proxy_server: PolicyProxyMCPServer) -> None:
    """Refunds above 20,000 paise must return PENDING_APPROVAL and NOT execute in backend."""
    initial_count = len(proxy_server.state_engine.refunds)
    # pay_test_captured_1001 has amount 50000
    res = await proxy_server.call_tool("create_refund", {"payment_id": "pay_test_captured_1001", "amount": 25000})
    assert res.get("status") == "PENDING_APPROVAL"
    assert res.get("approval_required") is True

    # Assert backend state engine did NOT execute the refund
    assert len(proxy_server.state_engine.refunds) == initial_count
    # Audit log should have pending entry, NOT executed create_refund
    executed_ops = [e.operation for e in proxy_server.state_engine.audit_log.get_changes()]
    assert "create_refund" not in executed_ops
    assert "create_refund_pending_approval" in executed_ops


@pytest.mark.asyncio
async def test_sub_threshold_refund_allowed(proxy_server: PolicyProxyMCPServer) -> None:
    """Refunds at or below 20,000 paise within limits must execute normally."""
    initial_count = len(proxy_server.state_engine.refunds)
    res = await proxy_server.call_tool("create_refund", {"payment_id": "pay_test_captured_1001", "amount": 15000})
    assert res.get("status") == "processed"
    assert "id" in res
    assert len(proxy_server.state_engine.refunds) == initial_count + 1


@pytest.mark.asyncio
async def test_over_refund_blocked(proxy_server: PolicyProxyMCPServer) -> None:
    """Refunds exceeding captured balance must be BLOCKED."""
    res = await proxy_server.call_tool("create_refund", {"payment_id": "pay_test_captured_1001", "amount": 60000})
    assert res.get("status") == "BLOCKED"
    assert "BLOCKED_POLICY_VIOLATION" in res.get("error", "")


@pytest.mark.asyncio
async def test_cumulative_daily_cap_blocked(proxy_server: PolicyProxyMCPServer) -> None:
    """Refunds exceeding 50,000 paise daily cumulative limit must be BLOCKED."""
    # First refund 20000
    r1 = await proxy_server.call_tool("create_refund", {"payment_id": "pay_test_captured_1001", "amount": 20000})
    assert r1.get("status") == "processed"

    # Second refund 20000 (total = 40000)
    # Using another payment for second refund
    from gauntlet.core.models import Payment
    p2 = Payment(id="pay_test_extra_1", amount=30000, status="captured")
    proxy_server.state_engine.payments[p2.id] = p2

    r2 = await proxy_server.call_tool("create_refund", {"payment_id": p2.id, "amount": 20000})
    assert r2.get("status") == "processed"

    # Third refund 15000 (total would be 55000 > 50000) -> BLOCKED
    p3 = Payment(id="pay_test_extra_2", amount=30000, status="captured")
    proxy_server.state_engine.payments[p3.id] = p3

    r3 = await proxy_server.call_tool("create_refund", {"payment_id": p3.id, "amount": 15000})
    assert r3.get("status") == "BLOCKED"
    assert "Cumulative daily refund limit" in r3.get("error", "")


@pytest.mark.asyncio
async def test_payment_link_allowlists(proxy_server: PolicyProxyMCPServer) -> None:
    """Payment links must enforce email and callback domain allowlists."""
    # 1. Unallowlisted recipient email -> BLOCKED
    res_bad_email = await proxy_server.call_tool("create_payment_link", {
        "amount": 10000,
        "currency": "INR",
        "customer_email": "attacker@evil.com",
    })
    assert res_bad_email.get("status") == "BLOCKED"
    assert "Recipient email" in res_bad_email.get("error", "")

    # 2. Unallowlisted callback domain -> BLOCKED
    res_bad_domain = await proxy_server.call_tool("create_payment_link", {
        "amount": 10000,
        "currency": "INR",
        "customer_email": "customer@example.com",
        "callback_url": "https://evil-phish.net/callback",
    })
    assert res_bad_domain.get("status") == "BLOCKED"
    assert "Callback URL domain" in res_bad_domain.get("error", "")

    # 3. Allowlisted email & domain -> ALLOWED
    res_ok = await proxy_server.call_tool("create_payment_link", {
        "amount": 10000,
        "currency": "INR",
        "customer_email": "customer@example.com",
        "callback_url": "https://store.merchant.in/callback",
    })
    assert "id" in res_ok
    assert res_ok.get("short_url") is not None


@pytest.mark.asyncio
async def test_restricted_tools_always_pending_approval(proxy_server: PolicyProxyMCPServer) -> None:
    """Instant settlement and bank updates must always return PENDING_APPROVAL."""
    res_settle = await proxy_server.call_tool("create_instant_settlement", {"amount": 50000})
    assert res_settle.get("status") == "PENDING_APPROVAL"
    assert res_settle.get("approval_required") is True

    res_bank = await proxy_server.call_tool("update_settlement_bank_account", {
        "account_number": "987654321098", "ifsc": "HDFC0001234", "beneficiary_name": "New Account"
    })
    assert res_bank.get("status") == "PENDING_APPROVAL"
    assert res_bank.get("approval_required") is True


@pytest.mark.asyncio
async def test_replay_protection(proxy_server: PolicyProxyMCPServer) -> None:
    """Duplicate mutation requests or duplicate receipts must be BLOCKED."""
    call_args = {"payment_id": "pay_test_captured_1001", "amount": 10000, "receipt": "rcpt_unique_101"}
    r1 = await proxy_server.call_tool("create_refund", call_args)
    assert r1.get("status") == "processed"

    # Exact replay -> BLOCKED
    r2 = await proxy_server.call_tool("create_refund", call_args)
    assert r2.get("status") == "BLOCKED"
    assert "BLOCKED_REPLAY_PROTECTION" in r2.get("error", "")

    # Replay with same receipt but different amount -> BLOCKED
    r3 = await proxy_server.call_tool("create_refund", {
        "payment_id": "pay_test_captured_1001", "amount": 5000, "receipt": "rcpt_unique_101"
    })
    assert r3.get("status") == "BLOCKED"
    assert "Duplicate receipt" in r3.get("error", "")


@pytest.mark.asyncio
async def test_pii_masking_on_lookups(proxy_server: PolicyProxyMCPServer) -> None:
    """Lookups must redact customer email and phone numbers."""
    pay = await proxy_server.call_tool("fetch_payment", {"payment_id": "pay_test_captured_1001"})
    # Original email was legit_customer@example.com
    assert pay.get("email") != "legit_customer@example.com"
    assert "@example.com" in pay.get("email", "")
    assert "*" in pay.get("email", "")

    # Original phone was +919876543210
    assert pay.get("contact") != "+919876543210"
    assert "*" in pay.get("contact", "")
