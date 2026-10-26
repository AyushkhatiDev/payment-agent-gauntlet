"""Standard Razorpay API error shapes and exception classes."""

from typing import Any, Dict, Optional


class RazorpayAPIError(Exception):
    """Exception representing a Razorpay API error response."""

    def __init__(
        self,
        code: str = "BAD_REQUEST_ERROR",
        description: str = "Invalid request",
        source: str = "business",
        step: str = "payment_operation",
        reason: Optional[str] = None,
        status_code: int = 400,
    ) -> None:
        super().__init__(description)
        self.code = code
        self.description = description
        self.source = source
        self.step = step
        self.reason = reason
        self.status_code = status_code

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


class PaymentAlreadyRefundedError(RazorpayAPIError):
    def __init__(self, description: str = "The payment has already been refunded") -> None:
        super().__init__(
            code="BAD_REQUEST_ERROR",
            description=description,
            source="business",
            step="payment_refund",
            reason="payment_already_refunded",
        )


class AmountExceededError(RazorpayAPIError):
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
        )


class EntityNotFoundError(RazorpayAPIError):
    def __init__(self, description: str = "The id provided does not exist") -> None:
        super().__init__(
            code="BAD_REQUEST_ERROR",
            description=description,
            source="business",
            step="payment_fetch",
            reason="input_validation_failed",
        )


class InvalidAmountError(RazorpayAPIError):
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
        )


class DuplicateRequestError(RazorpayAPIError):
    def __init__(
        self,
        description: str = "Duplicate request: a transaction with this receipt or reference already exists",
    ) -> None:
        super().__init__(
            code="BAD_REQUEST_ERROR",
            description=description,
            source="business",
            step="idempotency",
            reason="duplicate_request",
        )
