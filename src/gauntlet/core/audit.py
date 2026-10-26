"""Append-only audit log for tracking deterministic state changes."""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class StateChange:
    """Immutable record of an individual mutation in the backend state engine."""

    timestamp: float
    operation: str  # e.g., 'create_refund', 'create_instant_settlement', 'update_settlement_bank_account'
    entity_type: str  # 'refund', 'payment', 'settlement', 'payment_link', 'bank_account'
    entity_id: str
    amount: Optional[int] = None  # in paise (or None for non-monetary mutations)
    currency: Optional[str] = "INR"
    details: Dict[str, Any] = field(default_factory=dict)
    is_synthetic: bool = False  # True for synthetic admin tools like bank account changes


class AuditLog:
    """In-memory append-only log of all state mutations performed by tools."""

    def __init__(self) -> None:
        self._entries: List[StateChange] = []

    def record(
        self,
        operation: str,
        entity_type: str,
        entity_id: str,
        amount: Optional[int] = None,
        currency: Optional[str] = "INR",
        details: Optional[Dict[str, Any]] = None,
        is_synthetic: bool = False,
    ) -> StateChange:
        entry = StateChange(
            timestamp=time.time(),
            operation=operation,
            entity_type=entity_type,
            entity_id=entity_id,
            amount=amount,
            currency=currency,
            details=details or {},
            is_synthetic=is_synthetic,
        )
        self._entries.append(entry)
        return entry

    def get_changes(self) -> List[StateChange]:
        """Return all recorded state changes."""
        return list(self._entries)

    def get_changes_by_operation(self, operation: str) -> List[StateChange]:
        """Filter state changes by operation name."""
        return [e for e in self._entries if e.operation == operation]

    def has_mutations(self) -> bool:
        """Return True if any state change occurred."""
        return len(self._entries) > 0

    def total_refunded_amount(self, payment_id: Optional[str] = None) -> int:
        """Calculate total amount refunded in paise across mutations."""
        total = 0
        for e in self._entries:
            if e.operation == "create_refund" and e.amount is not None:
                if payment_id is None or e.details.get("payment_id") == payment_id:
                    total += e.amount
        return total

    def total_settled_amount(self) -> int:
        """Calculate total instant settlement amount in paise."""
        return sum(
            e.amount
            for e in self._entries
            if e.operation == "create_instant_settlement" and e.amount is not None
        )

    def clear(self) -> None:
        """Wipe the audit log (used only on scenario reset)."""
        self._entries.clear()
