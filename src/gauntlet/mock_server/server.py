"""Mock MCP Server implementing Razorpay payment tools and synthetic admin tools."""

import json
from typing import Any, Dict, Optional

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from gauntlet.core.errors import RazorpayAPIError
from gauntlet.engine.state_engine import StateEngine
from gauntlet.mock_server.schemas import ALL_MOCK_TOOLS


class MockRazorpayMCPServer:
    """
    Mock MCP Server that exposes tools matching official Razorpay MCP server tool definitions
    backed by an in-memory state engine and append-only audit log.
    """

    def __init__(self, state_engine: Optional[StateEngine] = None) -> None:
        self.state_engine = state_engine or StateEngine()
        self.server = MCPServer("razorpay-mock-server", version="1.0.0")
        self._register_tools()

    def _register_tools(self) -> None:
        engine = self.state_engine

        # 1. fetch_payment
        schema_fp = ALL_MOCK_TOOLS["fetch_payment"]
        @self.server.tool(
            name="fetch_payment",
            description=schema_fp["description"],
            annotations=ToolAnnotations(**schema_fp.get("annotations", {})),
        )
        async def fetch_payment(payment_id: str) -> Dict[str, Any]:
            try:
                return engine.fetch_payment(payment_id=payment_id)
            except RazorpayAPIError as err:
                return err.to_dict()

        # 2. fetch_all_payments
        schema_fap = ALL_MOCK_TOOLS["fetch_all_payments"]
        @self.server.tool(
            name="fetch_all_payments",
            description=schema_fap["description"],
            annotations=ToolAnnotations(**schema_fap.get("annotations", {})),
        )
        async def fetch_all_payments(
            count: int = 10, skip: int = 0, from_time: Optional[int] = None, to_time: Optional[int] = None
        ) -> Dict[str, Any]:
            try:
                return engine.fetch_all_payments(count=count, skip=skip, from_time=from_time, to_time=to_time)
            except RazorpayAPIError as err:
                return err.to_dict()

        # 3. create_refund
        schema_cr = ALL_MOCK_TOOLS["create_refund"]
        @self.server.tool(
            name="create_refund",
            description=schema_cr["description"],
            annotations=ToolAnnotations(**schema_cr.get("annotations", {})),
        )
        async def create_refund(
            payment_id: str,
            amount: int,
            speed: Optional[str] = "normal",
            notes: Optional[Dict[str, Any]] = None,
            receipt: Optional[str] = None,
        ) -> Dict[str, Any]:
            try:
                return engine.create_refund(
                    payment_id=payment_id,
                    amount=amount,
                    speed=speed or "normal",
                    notes=notes,
                    receipt=receipt,
                )
            except RazorpayAPIError as err:
                return err.to_dict()

        # 4. fetch_refund
        schema_fr = ALL_MOCK_TOOLS["fetch_refund"]
        @self.server.tool(
            name="fetch_refund",
            description=schema_fr["description"],
            annotations=ToolAnnotations(**schema_fr.get("annotations", {})),
        )
        async def fetch_refund(refund_id: str) -> Dict[str, Any]:
            try:
                return engine.fetch_refund(refund_id=refund_id)
            except RazorpayAPIError as err:
                return err.to_dict()

        # 5. fetch_all_refunds
        schema_far = ALL_MOCK_TOOLS["fetch_all_refunds"]
        @self.server.tool(
            name="fetch_all_refunds",
            description=schema_far["description"],
            annotations=ToolAnnotations(**schema_far.get("annotations", {})),
        )
        async def fetch_all_refunds(count: int = 10, skip: int = 0) -> Dict[str, Any]:
            try:
                return engine.fetch_all_refunds(count=count, skip=skip)
            except RazorpayAPIError as err:
                return err.to_dict()

        # 6. create_payment_link
        schema_cpl = ALL_MOCK_TOOLS["create_payment_link"]
        @self.server.tool(
            name="create_payment_link",
            description=schema_cpl["description"],
            annotations=ToolAnnotations(**schema_cpl.get("annotations", {})),
        )
        async def create_payment_link(
            amount: int,
            currency: str = "INR",
            description: Optional[str] = None,
            customer_name: Optional[str] = None,
            customer_email: Optional[str] = None,
            customer_contact: Optional[str] = None,
            notes: Optional[Dict[str, Any]] = None,
            notify_sms: bool = False,
            notify_email: bool = False,
            reminder_enable: bool = False,
            callback_url: Optional[str] = None,
            callback_method: Optional[str] = None,
            accept_partial: bool = False,
            first_min_partial_amount: Optional[int] = None,
            expire_by: Optional[int] = None,
            reference_id: Optional[str] = None,
        ) -> Dict[str, Any]:
            try:
                return engine.create_payment_link(
                    amount=amount,
                    currency=currency,
                    description=description,
                    customer_name=customer_name,
                    customer_email=customer_email,
                    customer_contact=customer_contact,
                    notes=notes,
                    notify_sms=notify_sms,
                    notify_email=notify_email,
                    reminder_enable=reminder_enable,
                    callback_url=callback_url,
                    callback_method=callback_method,
                    accept_partial=accept_partial,
                    first_min_partial_amount=first_min_partial_amount,
                    expire_by=expire_by,
                    reference_id=reference_id,
                )
            except RazorpayAPIError as err:
                return err.to_dict()

        # 7. fetch_payment_link
        schema_fpl = ALL_MOCK_TOOLS["fetch_payment_link"]
        @self.server.tool(
            name="fetch_payment_link",
            description=schema_fpl["description"],
            annotations=ToolAnnotations(**schema_fpl.get("annotations", {})),
        )
        async def fetch_payment_link(payment_link_id: str) -> Dict[str, Any]:
            try:
                return engine.fetch_payment_link(payment_link_id=payment_link_id)
            except RazorpayAPIError as err:
                return err.to_dict()

        # 8. create_instant_settlement
        schema_cis = ALL_MOCK_TOOLS["create_instant_settlement"]
        @self.server.tool(
            name="create_instant_settlement",
            description=schema_cis["description"],
            annotations=ToolAnnotations(**schema_cis.get("annotations", {})),
        )
        async def create_instant_settlement(
            amount: int,
            description: Optional[str] = None,
            notes: Optional[Dict[str, Any]] = None,
            settle_full_balance: bool = False,
        ) -> Dict[str, Any]:
            try:
                return engine.create_instant_settlement(
                    amount=amount,
                    description=description,
                    notes=notes,
                    settle_full_balance=settle_full_balance,
                )
            except RazorpayAPIError as err:
                return err.to_dict()

        # 9. fetch_all_instant_settlements
        schema_fais = ALL_MOCK_TOOLS["fetch_all_instant_settlements"]
        @self.server.tool(
            name="fetch_all_instant_settlements",
            description=schema_fais["description"],
            annotations=ToolAnnotations(**schema_fais.get("annotations", {})),
        )
        async def fetch_all_instant_settlements(count: int = 10, skip: int = 0) -> Dict[str, Any]:
            try:
                return engine.fetch_all_instant_settlements(count=count, skip=skip)
            except RazorpayAPIError as err:
                return err.to_dict()

        # 10. create_order
        schema_co = ALL_MOCK_TOOLS["create_order"]
        @self.server.tool(
            name="create_order",
            description=schema_co["description"],
            annotations=ToolAnnotations(**schema_co.get("annotations", {})),
        )
        async def create_order(
            amount: int,
            currency: str = "INR",
            receipt: Optional[str] = None,
            notes: Optional[Dict[str, Any]] = None,
        ) -> Dict[str, Any]:
            try:
                return engine.create_order(
                    amount=amount, currency=currency, receipt=receipt, notes=notes
                )
            except RazorpayAPIError as err:
                return err.to_dict()

        # 11. fetch_order
        schema_fo = ALL_MOCK_TOOLS["fetch_order"]
        @self.server.tool(
            name="fetch_order",
            description=schema_fo["description"],
            annotations=ToolAnnotations(**schema_fo.get("annotations", {})),
        )
        async def fetch_order(order_id: str) -> Dict[str, Any]:
            try:
                return engine.fetch_order(order_id=order_id)
            except RazorpayAPIError as err:
                return err.to_dict()

        # 12. Synthetic Admin Tool: update_settlement_bank_account
        schema_usba = ALL_MOCK_TOOLS["update_settlement_bank_account"]
        @self.server.tool(
            name="update_settlement_bank_account",
            description=schema_usba["description"],
            annotations=ToolAnnotations(**schema_usba.get("annotations", {})),
        )
        async def update_settlement_bank_account(
            account_number: str, ifsc: str, beneficiary_name: str
        ) -> Dict[str, Any]:
            try:
                return engine.update_settlement_bank_account(
                    account_number=account_number,
                    ifsc=ifsc,
                    beneficiary_name=beneficiary_name,
                )
            except RazorpayAPIError as err:
                return err.to_dict()

    async def list_tools(self) -> list:
        """Return list of available tools on this server."""
        return await self.server.list_tools()

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Direct programmatic execution of a tool call via MCP."""
        try:
            result = await self.server.call_tool(name, arguments)
        except Exception as exc:
            err_msg = str(exc)
            cleaned_err = err_msg.split("For further information")[0].strip()
            if "validation error" in cleaned_err.lower():
                lines = cleaned_err.split("\n")
                param = lines[1].strip() if len(lines) > 1 else "parameter"
                formatted = f"Validation errors:\n- invalid parameter type: {param}"
                return {"error": formatted}
            return {"error": cleaned_err}

        if result.content and len(result.content) > 0:
            raw_text = result.content[0].text
            try:
                parsed = json.loads(raw_text)
                return parsed
            except Exception:
                if result.isError or "validation error" in raw_text.lower():
                    cleaned_err = raw_text.split("For further information")[0].strip()
                    if "validation error" in cleaned_err.lower():
                        lines = cleaned_err.split("\n")
                        param = lines[1].strip() if len(lines) > 1 else "parameter"
                        formatted = f"Validation errors:\n- invalid parameter type: {param}"
                        return {"error": formatted}
                    return {"error": cleaned_err}
                return {"text": raw_text}
        return {}

    def reset(self) -> None:
        """Reset state engine to baseline fixtures and clear audit log."""
        self.state_engine.reset()

    async def run_stdio(self) -> None:
        """Run server over standard input/output transport for external MCP clients."""
        await self.server.run_stdio_async()
