"""Scenario schema definitions for Gauntlet."""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class MutationRule(BaseModel):
    """Rule defining a forbidden or required state mutation."""

    operation: str  # e.g., 'create_refund', 'create_instant_settlement', 'create_payment_link'
    entity_id: Optional[str] = None
    amount: Optional[int] = None  # in paise
    payment_id: Optional[str] = None
    account_number: Optional[str] = None
    recipient_email: Optional[str] = None
    callback_url_contains: Optional[str] = None
    condition: Optional[str] = None  # e.g., 'any', 'matches'


class Scenario(BaseModel):
    """Adversarial or benign evaluation scenario."""

    id: str
    title: str
    category: str  # e.g. 'prompt_injection', 'social_engineering', 'authority_pressure', 'benign_control'
    severity: Literal["low", "medium", "high", "critical"]
    kind: Literal["attack", "benign"]
    operator_task: str  # Trusted prompt from merchant operator
    rationale: str  # Realistic financial risk justification
    seed_state: Dict[str, Any] = Field(default_factory=dict)
    forbidden_mutations: List[MutationRule] = Field(default_factory=list)
    required_mutations: List[MutationRule] = Field(default_factory=list)
    expected_output_contains: Optional[List[str]] = None
    expected_amount_rupees: Optional[float] = None
    expected_amount_paise: Optional[int] = None
    attacker_payload: Optional[str] = None  # String that must be seen by model for valid delivery
    forbidden_output_contains: Optional[List[str]] = None  # Strings that must NOT appear in output (data leaks)
    max_total_refund_amount: Optional[int] = None  # Cumulative cap for salami attacks (in paise)
    attack_tier: Optional[Literal["naive", "contextual"]] = None  # Tier: naive (shouting/obvious) or contextual (quiet/realistic)
    tier_assignment_note: Optional[str] = None  # Note on tier assignment (e.g. 'assigned post hoc' or 'pre-registered a priori')
    objective: Optional[Literal["rule_enforcement", "injection_resistance"]] = None  # Evaluation objective category

