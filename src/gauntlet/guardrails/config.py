"""Configuration loader and schema for Phase 4 Policy Proxy Guardrails."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml


@dataclass
class GuardrailsPolicyConfig:
    """Deterministic policy rules enforced by PolicyProxyMCPServer."""

    version: str = "1.0.0"
    policy_name: str = "merchant_ops_guardrail_policy"

    # Refund rules
    max_refund_window_days: int = 30
    max_cumulative_daily_refund_paise: int = 50000
    approval_threshold_paise: int = 20000
    enforce_captured_balance: bool = True

    # Payment link allowlists
    allowed_recipient_emails: List[str] = field(default_factory=list)
    allowed_callback_domains: List[str] = field(default_factory=list)

    # Restricted tools
    always_pending_approval: List[str] = field(default_factory=list)

    # Replay protection
    replay_protection_enabled: bool = True
    replay_window_seconds: int = 300
    track_receipts: bool = True

    # Privacy
    mask_pii_in_results: bool = True

    @classmethod
    def load_from_file(cls, path: Optional[Path] = None) -> "GuardrailsPolicyConfig":
        """Load policy config from YAML file or return defaults."""
        config_path = path or Path("config/guardrails_policy.yaml")
        if not config_path.exists():
            return cls()

        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        refunds = data.get("refunds", {})
        links = data.get("payment_links", {})
        restricted = data.get("restricted_tools", {})
        replay = data.get("replay_protection", {})
        privacy = data.get("privacy", {})

        return cls(
            version=data.get("version", "1.0.0"),
            policy_name=data.get("policy_name", "merchant_ops_guardrail_policy"),
            max_refund_window_days=refunds.get("max_refund_window_days", 30),
            max_cumulative_daily_refund_paise=refunds.get("max_cumulative_daily_refund_paise", 50000),
            approval_threshold_paise=refunds.get("approval_threshold_paise", 20000),
            enforce_captured_balance=refunds.get("enforce_captured_balance", True),
            allowed_recipient_emails=[e.lower().strip() for e in links.get("allowed_recipient_emails", [])],
            allowed_callback_domains=[d.lower().strip() for d in links.get("allowed_callback_domains", [])],
            always_pending_approval=restricted.get("always_pending_approval", ["create_instant_settlement", "update_settlement_bank_account"]),
            replay_protection_enabled=replay.get("enabled", True),
            replay_window_seconds=replay.get("window_seconds", 300),
            track_receipts=replay.get("track_receipts", True),
            mask_pii_in_results=privacy.get("mask_pii_in_results", True),
        )
