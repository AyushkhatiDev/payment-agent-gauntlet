"""Standard Razorpay API error shapes, provenance tags, and exception classes."""

from typing import Any, Dict, Optional


class RazorpayAPIError(Exception):
    """Exception representing a Razorpay API error response."""

    def __init__(
        self,
        code: str = "BAD_REQUEST_ERROR",
        description: str = "Invalid request",
        source: str = "internal",
        step: str = "payment_operation",
        reason: Optional[str] = None,
        status_code: int = 400,
        provenance: str = "assumed",
    ) -> None:
        super().__init__(description)
        self.code = code
        self.description = description
        self.source = source
        self.step = step
        self.reason = reason
        self.status_code = status_code
        self.provenance = provenance  # 'recorded', 'documented', or 'assumed'

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to standard Razorpay API error response JSON shape."""
        error_payload: Dict[str, Any] = {
            "code": self.code,
            "description": self.description,
            "source": self.source,
            "step": self.step,
        }
        if self.reason:
            error_payload["reason"] = self.reason
        return {"error": error_payload}


class EntityNotFoundError(RazorpayAPIError):
    """
    PROVENANCE: RECORDED from live test-mode API call
    GET https://api.razorpay.com/v1/payments/pay_nonexistent_9999999999
    Response: {"error":{"code":"BAD_REQUEST_ERROR","description":"The id provided does not exist","source":"internal","step":"payment_initiation","reason":"input_validation_failed","metadata":{}}}
    """

    def __init__(self, description: str = "The id provided does not exist") -> None:
        super().__init__(
            code="BAD_REQUEST_ERROR",
            description=description,
            source="internal",
            step="payment_initiation",
            reason="input_validation_failed",
            provenance="recorded",
        )


class PaymentAlreadyRefundedError(RazorpayAPIError):
    """
    PROVENANCE: ASSUMED (could not record live without server-side captured payment).
    Derived from Razorpay developer documentation and forums.
    """

    def __init__(self, description: str = "The payment has already been refunded") -> None:
        super().__init__(
            code="BAD_REQUEST_ERROR",
            description=description,
            source="business",
            step="payment_refund",
            reason="payment_already_refunded",
            provenance="assumed",
        )


class AmountExceededError(RazorpayAPIError):
    """
    PROVENANCE: ASSUMED (could not record live without server-side captured payment).
    Derived from Razorpay refund documentation.
    """

    def __init__(
        self,
        description: str = "The refund amount provided is greater than the amount that can be refunded.",
    ) -> None:
        super().__init__(
            code="BAD_REQUEST_ERROR",
            description=description,
            source="business",
            step="payment_refund",
            reason="amount_exceeded",
            provenance="assumed",
        )


class InvalidAmountError(RazorpayAPIError):
    """
    PROVENANCE: DOCUMENTED
    Razorpay documentation specifies amounts must be integer subunits (paise).
    """

    def __init__(
        self,
        description: str = "Amount must be an integer in smallest currency unit (paise)",
    ) -> None:
        super().__init__(
            code="BAD_REQUEST_ERROR",
            description=description,
            source="input",
            step="validation",
            reason="invalid_amount",
            provenance="documented",
        )


class DuplicateRequestError(RazorpayAPIError):
    """
    PROVENANCE: MOCK-ONLY CONVENIENCE (Unverified in real Razorpay).
    Real Razorpay uses the 'X-Refund-Idempotency' HTTP header for idempotency,
    not the receipt parameter. Scenarios MUST NOT depend on receipt-based deduplication.
    """

    def __init__(
        self,
        description: str = "Duplicate request: a transaction with this receipt already exists [mock-only convenience]",
    ) -> None:
        super().__init__(
            code="BAD_REQUEST_ERROR",
            description=description,
            source="business",
            step="idempotency",
            reason="duplicate_request",
            provenance="assumed",
        )
