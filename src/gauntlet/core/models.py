"""Domain models for payment entities and synthetic administrative resources."""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class Payment(BaseModel):
    """Payment entity matching Razorpay schema."""

    id: str
    entity: str = "payment"
    amount: int  # in paise
    currency: str = "INR"
    status: str = "captured"  # 'authorized', 'captured', 'refunded', 'failed'
    order_id: Optional[str] = None
    invoice_id: Optional[str] = None
    international: bool = False
    method: str = "card"
    amount_refunded: int = 0  # in paise
    refund_status: Optional[str] = None  # None, 'partial', 'full'
    captured: bool = True
    description: Optional[str] = None  # Free-form text (injection vector)
    card_id: Optional[str] = None
    bank: Optional[str] = None
    wallet: Optional[str] = None
    vpa: Optional[str] = None
    email: Optional[str] = "customer@example.com"
    contact: Optional[str] = "+919876543210"
    notes: Dict[str, Any] = Field(default_factory=dict)  # Free-form key-value pairs (injection vector)
    fee: int = 0
    tax: int = 0
    error_code: Optional[str] = None
    error_description: Optional[str] = None
    created_at: int = Field(default=1729000000)

    @property
    def remaining_refundable_amount(self) -> int:
        return max(0, self.amount - self.amount_refunded)


class Refund(BaseModel):
    """Refund entity matching Razorpay schema."""

    id: str
    entity: str = "refund"
    amount: int  # in paise
    currency: str = "INR"
    payment_id: str
    notes: Dict[str, Any] = Field(default_factory=dict)  # Untrusted user notes
    receipt: Optional[str] = None
    acquirer_data: Dict[str, Any] = Field(default_factory=lambda: {"arn": "100000000000"})
    created_at: int = Field(default=1729000100)
    batch_id: Optional[str] = None
    status: str = "processed"
    speed_processed: str = "normal"
    speed_requested: str = "normal"


class PaymentLink(BaseModel):
    """Payment Link entity matching Razorpay schema."""

    id: str
    entity: str = "payment_link"
    amount: int  # in paise
    currency: str = "INR"
    status: str = "created"
    short_url: str
    description: Optional[str] = None  # Untrusted description
    customer: Dict[str, Any] = Field(default_factory=dict)
    notes: Dict[str, Any] = Field(default_factory=dict)
    notify: Dict[str, bool] = Field(default_factory=dict)
    reminder_enable: bool = False
    callback_url: Optional[str] = None
    callback_method: Optional[str] = None
    accept_partial: bool = False
    first_min_partial_amount: Optional[int] = None
    expire_by: Optional[int] = None
    reference_id: Optional[str] = None
    created_at: int = Field(default=1729000200)


class InstantSettlement(BaseModel):
    """Instant Settlement entity matching Razorpay schema."""

    id: str
    entity: str = "settlement"
    amount: int  # in paise
    currency: str = "INR"
    status: str = "created"
    description: Optional[str] = None
    notes: Dict[str, Any] = Field(default_factory=dict)
    fees: int = 1500  # in paise
    tax: int = 270  # in paise
    utr: Optional[str] = None
    created_at: int = Field(default=1729000300)


class Order(BaseModel):
    """Order entity matching Razorpay schema."""

    id: str
    entity: str = "order"
    amount: int  # in paise
    currency: str = "INR"
    status: str = "created"
    receipt: Optional[str] = None
    notes: Dict[str, Any] = Field(default_factory=dict)
    created_at: int = Field(default=1729000400)


class SettlementBankAccount(BaseModel):
    """
    SYNTHETIC / HYPOTHETICAL ADMIN RESOURCE.
    Note: Real Razorpay settlement bank accounts are NOT accessible via MCP tools.
    This model exists purely to test social engineering / unauthorized account takeover attacks.
    """

    account_number: str
    ifsc: str
    beneficiary_name: str
    updated_at: int = Field(default=1729000000)
