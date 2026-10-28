"""Policy Proxy MCP Server implementing deterministic Phase 4 guardrails."""

import json
import re
import time
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from gauntlet.engine.state_engine import StateEngine
from gauntlet.guardrails.config import GuardrailsPolicyConfig
from gauntlet.mock_server.server import MockRazorpayMCPServer


class PolicyProxyMCPServer:
    """
    Deterministic policy-proxy MCP server that wraps MockRazorpayMCPServer.
    Enforces financial invariants, approval thresholds, allowlists, replay guards,
    and PII redaction without relying on LLM self-governance.
    """

    def __init__(
        self,
        backend_server: Optional[MockRazorpayMCPServer] = None,
        policy: Optional[GuardrailsPolicyConfig] = None,
    ) -> None:
        self.backend = backend_server or MockRazorpayMCPServer()
        self.policy = policy or GuardrailsPolicyConfig.load_from_file()

        # Replay and idempotency cache
        self.seen_requests: Dict[str, float] = {}
        self.seen_receipts: Set[str] = set()

        # Decision log for auditability: list of dicts describing proxy actions
        self.decisions_log: List[Dict[str, Any]] = []

    @property
    def state_engine(self) -> StateEngine:
        return self.backend.state_engine

    @property
    def server(self) -> Any:
        return self.backend.server

    def _get_current_timestamp(self) -> int:
        """Return reference timestamp from existing payments or system clock."""
        timestamps = [p.created_at for p in self.state_engine.payments.values() if p.created_at]
        if timestamps:
            return max(timestamps)
        return int(time.time())

    def reset(self) -> None:
        """Reset underlying mock server and clear replay tracking cache."""
        self.backend.reset()
        self.seen_requests.clear()
        self.seen_receipts.clear()
        self.decisions_log.clear()

    async def list_tools(self) -> list:
        """Expose identical tool catalog as official Razorpay MCP server."""
        return await self.backend.list_tools()

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Intercept, validate against deterministic policy config, and route tool calls."""
        now = time.time()

        # 1. Replay & Duplicate Request Protection
        if self.policy.replay_protection_enabled and name in (
            "create_refund", "create_payment_link", "create_instant_settlement", "update_settlement_bank_account"
        ):
            receipt = arguments.get("receipt")
            if receipt:
                if receipt in self.seen_receipts:
                    err = f"BLOCKED_REPLAY_PROTECTION: Duplicate receipt '{receipt}' has already been processed."
                    self._record_decision(name, arguments, "BLOCKED", err)
                    return {"status": "BLOCKED", "error": err}

            req_key = f"{name}:{json.dumps(arguments, sort_keys=True)}"
            if req_key in self.seen_requests:
                last_time = self.seen_requests[req_key]
                if now - last_time <= self.policy.replay_window_seconds:
                    err = "BLOCKED_REPLAY_PROTECTION: Duplicate mutation request detected within idempotency window."
                    self._record_decision(name, arguments, "BLOCKED", err)
                    return {"status": "BLOCKED", "error": err}

        # 2. Restricted Administrative Tools (create_instant_settlement & update_settlement_bank_account)
        if name in self.policy.always_pending_approval:
            msg = (
                f"Action '{name}' is restricted to supervisor manual approval with 2FA. "
                f"Request logged and held in PENDING_APPROVAL status."
            )
            self.state_engine.audit_log.record(
                operation=f"{name}_pending_approval",
                entity_type="admin_action",
                entity_id=f"pend_{name}",
                amount=arguments.get("amount", 0),
                details={"action": name, "status": "PENDING_APPROVAL", "arguments": arguments},
            )
            self._record_decision(name, arguments, "PENDING_APPROVAL", msg)
            return {
                "status": "PENDING_APPROVAL",
                "approval_required": True,
                "action": name,
                "message": msg,
            }

        # 3. create_refund Invariants & Threshold Enforcement
        if name == "create_refund":
            payment_id = arguments.get("payment_id")
            amount = arguments.get("amount", 0)

            # Check if target payment exists in state engine
            if payment_id in self.state_engine.payments:
                payment = self.state_engine.payments[payment_id]

                # (a) refund <= captured amount invariant
                rem_refundable = payment.remaining_refundable_amount
                if amount > rem_refundable or amount > payment.amount:
                    err = (
                        f"BLOCKED_POLICY_VIOLATION: Refund amount ({amount} paise) exceeds "
                        f"captured/remaining balance ({rem_refundable} paise) for payment {payment_id}."
                    )
                    self._record_decision(name, arguments, "BLOCKED", err)
                    return {"status": "BLOCKED", "error": err}

                # (b) 30-day window check
                ref_time = self._get_current_timestamp()
                if payment.created_at and (ref_time - payment.created_at) > (self.policy.max_refund_window_days * 86400):
                    age_days = (ref_time - payment.created_at) // 86400
                    err = (
                        f"BLOCKED_POLICY_VIOLATION: Transaction age ({age_days} days) exceeds "
                        f"standard {self.policy.max_refund_window_days}-day return policy window."
                    )
                    self._record_decision(name, arguments, "BLOCKED", err)
                    return {"status": "BLOCKED", "error": err}

            # (c) Cumulative daily refund cap (50,000 paise)
            current_daily_total = sum(
                e.amount or 0
                for e in self.state_engine.audit_log.get_changes_by_operation("create_refund")
                if e.amount is not None
            )
            if (current_daily_total + amount) > self.policy.max_cumulative_daily_refund_paise:
                err = (
                    f"BLOCKED_POLICY_VIOLATION: Cumulative daily refund limit of "
                    f"{self.policy.max_cumulative_daily_refund_paise} paise exceeded. "
                    f"Current total: {current_daily_total} paise, requested: {amount} paise."
                )
                self._record_decision(name, arguments, "BLOCKED", err)
                return {"status": "BLOCKED", "error": err}

            # (d) Merchant Approval Threshold (20,000 paise)
            if amount > self.policy.approval_threshold_paise:
                msg = (
                    f"Refund of {amount} paise exceeds automated threshold "
                    f"({self.policy.approval_threshold_paise} paise). Held for supervisor manual approval."
                )
                self.state_engine.audit_log.record(
                    operation="create_refund_pending_approval",
                    entity_type="refund",
                    entity_id=f"pend_rfnd_{payment_id}",
                    amount=amount,
                    details={"payment_id": payment_id, "status": "PENDING_APPROVAL", "threshold": self.policy.approval_threshold_paise},
                )
                self._record_decision(name, arguments, "PENDING_APPROVAL", msg)
                return {
                    "status": "PENDING_APPROVAL",
                    "approval_required": True,
                    "action": "create_refund",
                    "payment_id": payment_id,
                    "amount": amount,
                    "message": msg,
                }

        # 4. create_payment_link Allowlist Checks
        if name == "create_payment_link":
            # (a) Recipient email allowlist check
            recipient = (
                arguments.get("customer_email")
                or (arguments.get("customer", {}) or {}).get("email")
                or ""
            ).lower().strip()

            if recipient and self.policy.allowed_recipient_emails:
                if recipient not in self.policy.allowed_recipient_emails:
                    err = f"BLOCKED_POLICY_VIOLATION: Recipient email '{recipient}' is not on the merchant approved recipient allowlist."
                    self._record_decision(name, arguments, "BLOCKED", err)
                    return {"status": "BLOCKED", "error": err}

            # (b) Callback URL domain allowlist check
            callback_url = arguments.get("callback_url")
            if callback_url and self.policy.allowed_callback_domains:
                try:
                    hostname = urlparse(callback_url).hostname or ""
                    hostname = hostname.lower()
                    is_allowed = any(
                        hostname == d or hostname.endswith(f".{d}")
                        for d in self.policy.allowed_callback_domains
                    )
                    if not is_allowed:
                        err = f"BLOCKED_POLICY_VIOLATION: Callback URL domain '{hostname}' is not on the merchant approved callback domain allowlist."
                        self._record_decision(name, arguments, "BLOCKED", err)
                        return {"status": "BLOCKED", "error": err}
                except Exception as ex:
                    err = f"BLOCKED_POLICY_VIOLATION: Malformed callback URL: {ex}"
                    self._record_decision(name, arguments, "BLOCKED", err)
                    return {"status": "BLOCKED", "error": err}

        # 5. Forward Permitted Call to Backend Mock Server
        backend_result = await self.backend.call_tool(name, arguments)
        self._record_decision(name, arguments, "ALLOWED", "Action passed all deterministic guardrail checks.")

        # Update replay cache on success
        if not (isinstance(backend_result, dict) and "error" in backend_result):
            req_key = f"{name}:{json.dumps(arguments, sort_keys=True)}"
            self.seen_requests[req_key] = now
            if "receipt" in arguments and arguments["receipt"]:
                self.seen_receipts.add(str(arguments["receipt"]))

        # 6. PII Masking on Read-Only Lookups
        if self.policy.mask_pii_in_results and name in ("fetch_payment", "fetch_all_payments"):
            backend_result = self._mask_pii_in_payload(backend_result)

        return backend_result

    def _record_decision(self, tool: str, arguments: Dict[str, Any], decision: str, reason: str) -> None:
        self.decisions_log.append({
            "tool": tool,
            "arguments": arguments,
            "decision": decision,
            "reason": reason,
            "timestamp": time.time(),
        })

    def _mask_pii_in_payload(self, obj: Any) -> Any:
        """Sanitize email addresses and phone numbers in returned payloads."""
        if isinstance(obj, dict):
            masked = {}
            for k, v in obj.items():
                if k in ("email", "customer_email") and isinstance(v, str):
                    masked[k] = self._mask_email(v)
                elif k in ("contact", "phone", "customer_contact") and isinstance(v, str):
                    masked[k] = self._mask_phone(v)
                elif k == "notes" and isinstance(v, dict):
                    masked[k] = {nk: self._mask_string_pii(str(nv)) for nk, nv in v.items()}
                else:
                    masked[k] = self._mask_pii_in_payload(v)
            return masked
        elif isinstance(obj, list):
            return [self._mask_pii_in_payload(item) for item in obj]
        return obj

    @staticmethod
    def _mask_email(email: str) -> str:
        if "@" in email:
            user, domain = email.split("@", 1)
            if len(user) <= 2:
                masked_user = user[0] + "*"
            else:
                masked_user = user[0] + ("*" * (len(user) - 2)) + user[-1]
            return f"{masked_user}@{domain}"
        return "[REDACTED_EMAIL]"

    @staticmethod
    def _mask_phone(phone: str) -> str:
        clean = phone.replace(" ", "").replace("-", "")
        if len(clean) >= 8:
            return clean[:4] + ("*" * (len(clean) - 6)) + clean[-2:]
        return "[REDACTED_PHONE]"

    @staticmethod
    def _mask_string_pii(text: str) -> str:
        # Mask emails inside free text
        text = re.sub(
            r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "[REDACTED_EMAIL]",
            text,
        )
        # Mask phone numbers (+91... or 10-digit)
        text = re.sub(
            r"(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
            "[REDACTED_PHONE]",
            text,
        )
        return text
