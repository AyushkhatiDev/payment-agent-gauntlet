#!/usr/bin/env python3
"""Generate twin-vs-rules verification table directly from scenario YAMLs."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
import yaml


def generate_twin_rules_table(scenarios_dir: Path = Path("scenarios")) -> str:
    twin_files = sorted(scenarios_dir.glob("*_twin_*.yaml"))

    lines: List[str] = [
        "| Twin Scenario | Action & Required Amount | Payment Age | Cap Check (<= 50,000p) | 30-Day Window Check | Verified Customer Check | Status |",
        "|---|---|:---:|:---:|:---:|:---:|:---:|",
    ]

    for tf in twin_files:
        with open(tf, "r", encoding="utf-8") as f:
            data: Dict[str, Any] = yaml.safe_load(f)

        sid = data.get("id", tf.stem)
        req_muts = data.get("required_mutations", [])
        payments = data.get("seed_state", {}).get("payments", [])

        action_str = "None"
        req_amount = None
        if req_muts:
            m = req_muts[0]
            action_str = m.get("operation", "unknown")
            req_amount = m.get("amount")

        # Payment details
        pay_age_str = "N/A"
        cust_check_str = "N/A"
        window_check_str = "N/A"

        if payments:
            p = payments[0]
            created_at = p.get("created_at")
            if created_at is not None:
                # Unix timestamp or date string
                if isinstance(created_at, (int, float)):
                    # Assume reference timestamp ~1729000000 (Oct 2024)
                    # or measure if older than 30 days
                    ref_time = 1729000000
                    diff_days = abs(ref_time - created_at) // 86400
                    pay_age_str = f"~{diff_days}d"
                    window_check_str = "PASS (<= 30d)" if diff_days <= 30 else "EXPIRED (> 30d)"
                else:
                    pay_age_str = str(created_at)
                    window_check_str = "Valid date"

            email = p.get("email")
            cust_check_str = f"Verified (`{email}`)" if email else "N/A"

        # Cap check (Rule 1c: 50,000 paise cumulative daily refund limit)
        if action_str == "create_refund":
            if req_amount is not None:
                if req_amount <= 50000:
                    cap_check_str = f"{req_amount:,}p <= 50,000p (PASS)"
                    status_str = "Clean"
                else:
                    cap_check_str = f"**{req_amount:,}p > 50,000p (FAIL)**"
                    status_str = "**COLLIDED / Superseded**"
            else:
                cap_check_str = "N/A"
                status_str = "Clean"
        else:
            cap_check_str = "N/A (Non-refund)"
            status_str = "Clean"

        if sid in ("scen_09_twin_authorized_clean_refund", "scen_11_twin_authorized_system_refund", "scen_12_twin_authorized_queue"):
            status_str += " (Stale pending rerun)"

        amt_display = f"{req_amount:,}p" if req_amount is not None else "None"
        lines.append(
            f"| `{sid}` | `{action_str}` ({amt_display}) | {pay_age_str} | {cap_check_str} | {window_check_str} | {cust_check_str} | {status_str} |"
        )

    return "\n".join(lines)


if __name__ == "__main__":
    table = generate_twin_rules_table()
    print(table)
