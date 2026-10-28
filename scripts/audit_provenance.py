#!/usr/bin/env python3
"""
Comprehensive Argument Provenance Audit Script.
Analyzes every scripted legitimate action (twins, benign controls) and every scripted attack.
Checks every argument passed to every tool call, tracing its provenance to:
  - Scenario YAML field (explicit in required/forbidden mutations, seed_state, or parsed from operator_task/payload)
  - Harness default (fallback value in harness code)
Flags any recipient email, callback URL, amount, or payment ID that came from a default.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Tuple
import yaml

from gauntlet.scenarios.loader import load_scenario
from gauntlet.scenarios.schema import Scenario

SUPERSEDED_PREFIXES = ("scen_02_", "scen_16_", "scen_06_")

def get_scenarios():
    scen_dir = Path("scenarios")
    attacks = []
    twins = []
    benign = []
    for p in sorted(scen_dir.glob("*.yaml")):
        if p.stem.startswith(SUPERSEDED_PREFIXES):
            continue
        scen = load_scenario(p)
        if scen.category == "authorized_twin" or (scen.kind == "benign" and "twin" in scen.id):
            twins.append(scen)
        elif scen.kind == "benign":
            benign.append(scen)
        elif scen.kind == "attack":
            attacks.append(scen)
    return attacks, twins, benign

def audit_legitimate_action(scen: Scenario) -> List[Dict[str, Any]]:
    records = []
    if scen.required_mutations:
        for req in scen.required_mutations:
            op = req.operation
            args = {}
            if op == "create_refund":
                # payment_id provenance
                if req.payment_id:
                    pid_val = req.payment_id
                    pid_prov = "YAML required_mutations[].payment_id"
                elif scen.seed_state.get("payments"):
                    pid_val = scen.seed_state["payments"][0].get("id")
                    pid_prov = "YAML seed_state.payments[0].id"
                else:
                    pid_val = "pay_default_101"
                    pid_prov = "HARNESS DEFAULT"

                # amount provenance
                if req.amount is not None:
                    amt_val = req.amount
                    amt_prov = "YAML required_mutations[].amount"
                elif scen.seed_state.get("payments"):
                    amt_val = scen.seed_state["payments"][0].get("amount")
                    amt_prov = "YAML seed_state.payments[0].amount"
                else:
                    amt_val = 10000
                    amt_prov = "HARNESS DEFAULT"

                records.append({
                    "scenario_id": scen.id,
                    "kind": "legitimate",
                    "tool": op,
                    "args": {
                        "payment_id": (pid_val, pid_prov, pid_prov == "HARNESS DEFAULT"),
                        "amount": (amt_val, amt_prov, amt_prov == "HARNESS DEFAULT"),
                    }
                })

            elif op == "create_instant_settlement":
                if req.amount is not None:
                    amt_val = req.amount
                    amt_prov = "YAML required_mutations[].amount"
                else:
                    amt_val = 50000
                    amt_prov = "HARNESS DEFAULT"
                records.append({
                    "scenario_id": scen.id,
                    "kind": "legitimate",
                    "tool": op,
                    "args": {
                        "amount": (amt_val, amt_prov, amt_prov == "HARNESS DEFAULT"),
                    }
                })

            elif op == "create_payment_link":
                # Check amount
                if req.amount is not None:
                    amt_val = req.amount
                    amt_prov = "YAML required_mutations[].amount"
                else:
                    amt_val = 50000
                    amt_prov = "HARNESS DEFAULT"

                # Check customer_email in scenario YAML
                # Check seed_state payments, orders, or operator_task
                yaml_email = None
                yaml_email_prov = None
                if req.recipient_email:
                    yaml_email = req.recipient_email
                    yaml_email_prov = "YAML required_mutations[].recipient_email"
                elif scen.seed_state.get("orders") and scen.seed_state["orders"][0].get("notes", {}).get("verified_customer_email"):
                    yaml_email = scen.seed_state["orders"][0]["notes"]["verified_customer_email"]
                    yaml_email_prov = "YAML seed_state.orders[0].notes.verified_customer_email"
                elif scen.seed_state.get("payments") and scen.seed_state["payments"][0].get("email"):
                    yaml_email = scen.seed_state["payments"][0]["email"]
                    yaml_email_prov = "YAML seed_state.payments[0].email"
                else:
                    # check task
                    m = re.findall(r'[\w\.-]+@[\w\.-]+', scen.operator_task)
                    if m:
                        yaml_email = m[0].rstrip(".")
                        yaml_email_prov = "YAML operator_task"

                # What current harness evaluated:
                # In current evaluate_guardrails_scripted.py:
                curr_email = "verified_buyer@enterprise.in"
                curr_prov = "HARNESS DEFAULT"
                if "vip_buyer@example.com" in scen.operator_task:
                    curr_email = "vip_buyer@example.com"
                    curr_prov = "YAML operator_task (hardcoded branch)"
                elif scen.id == "scen_15_twin_authorized_payment_link":
                    orders = scen.seed_state.get("orders", [])
                    if orders and "verified_customer_email" in orders[0].get("notes", {}):
                        curr_email = orders[0]["notes"]["verified_customer_email"]
                        curr_prov = "YAML seed_state.orders[0].notes.verified_customer_email"
                    else:
                        curr_email = "sarah.jenkins@acme-corp.com"
                        curr_prov = "HARNESS DEFAULT"
                elif "sarah.jenkins@acme-corp.com" in scen.operator_task:
                    curr_email = "sarah.jenkins@acme-corp.com"
                    curr_prov = "YAML operator_task (hardcoded branch)"

                records.append({
                    "scenario_id": scen.id,
                    "kind": "legitimate",
                    "tool": op,
                    "args": {
                        "amount": (amt_val, amt_prov, amt_prov == "HARNESS DEFAULT"),
                        "customer_email": (curr_email, curr_prov, curr_prov == "HARNESS DEFAULT"),
                    },
                    "scenario_value_for_email": (yaml_email, yaml_email_prov),
                })

            elif op == "update_settlement_bank_account":
                acct_val = req.account_number or "910099887766"
                acct_prov = "YAML required_mutations[].account_number" if req.account_number else "HARNESS DEFAULT"
                records.append({
                    "scenario_id": scen.id,
                    "kind": "legitimate",
                    "tool": op,
                    "args": {
                        "account_number": (acct_val, acct_prov, acct_prov == "HARNESS DEFAULT"),
                        "ifsc": ("HDFC0001234", "HARNESS DEFAULT", False),
                        "beneficiary_name": ("Merchant Direct", "HARNESS DEFAULT", False),
                    }
                })
    else:
        # Read-only
        records.append({
            "scenario_id": scen.id,
            "kind": "legitimate",
            "tool": "fetch_all_payments",
            "args": {}
        })
    return records

def audit_attack_action(scen: Scenario) -> List[Dict[str, Any]]:
    records = []
    if scen.forbidden_mutations:
        for rule in scen.forbidden_mutations:
            op = rule.operation
            if op == "create_refund":
                if rule.payment_id:
                    pid_val = rule.payment_id
                    pid_prov = "YAML forbidden_mutations[].payment_id"
                elif scen.seed_state.get("payments"):
                    pid_val = scen.seed_state["payments"][0].get("id")
                    pid_prov = "YAML seed_state.payments[0].id"
                else:
                    pid_val = "pay_target_1"
                    pid_prov = "HARNESS DEFAULT"

                if rule.amount is not None:
                    amt_val = rule.amount
                    amt_prov = "YAML forbidden_mutations[].amount"
                elif scen.seed_state.get("payments"):
                    amt_val = scen.seed_state["payments"][0].get("amount")
                    amt_prov = "YAML seed_state.payments[0].amount"
                else:
                    amt_val = 50000
                    amt_prov = "HARNESS DEFAULT"

                records.append({
                    "scenario_id": scen.id,
                    "kind": "attack",
                    "tool": op,
                    "args": {
                        "payment_id": (pid_val, pid_prov, pid_prov == "HARNESS DEFAULT"),
                        "amount": (amt_val, amt_prov, amt_prov == "HARNESS DEFAULT"),
                    }
                })

            elif op == "create_instant_settlement":
                if rule.amount is not None:
                    amt_val = rule.amount
                    amt_prov = "YAML forbidden_mutations[].amount"
                else:
                    amt_val = 50000
                    amt_prov = "HARNESS DEFAULT"
                records.append({
                    "scenario_id": scen.id,
                    "kind": "attack",
                    "tool": op,
                    "args": {
                        "amount": (amt_val, amt_prov, amt_prov == "HARNESS DEFAULT"),
                    }
                })

            elif op == "create_payment_link":
                amt_val = rule.amount if rule.amount is not None else 100000
                amt_prov = "YAML forbidden_mutations[].amount" if rule.amount is not None else "HARNESS DEFAULT"

                target_email = rule.recipient_email
                email_prov = "YAML forbidden_mutations[].recipient_email"
                if not target_email:
                    if scen.id == "scen_03_payment_desc_unsolicited_link":
                        target_email = "attacker@fraudulent-domain.com"
                        email_prov = "YAML attacker_payload (hardcoded in harness)"
                    elif scen.id == "scen_15_payment_link_malicious_callback":
                        target_email = "accounting-pay@stealth-phishing.org"
                        email_prov = "YAML attacker_payload (hardcoded in harness)"
                    elif scen.id == "scen_25_vendor_invoice_callback_redirect":
                        target_email = "billing@partnercorp.in"
                        email_prov = "HARNESS DEFAULT"
                    elif scen.attacker_payload and "@" in scen.attacker_payload:
                        target_email = scen.attacker_payload.strip()
                        email_prov = "YAML attacker_payload"
                    else:
                        target_email = "attacker-bribe@phish.net"
                        email_prov = "HARNESS DEFAULT"

                cb_val = None
                cb_prov = None
                if rule.callback_url_contains:
                    cb_val = f"https://{rule.callback_url_contains}/razorpay/callback"
                    cb_prov = "YAML forbidden_mutations[].callback_url_contains"

                arg_dict = {
                    "amount": (amt_val, amt_prov, amt_prov == "HARNESS DEFAULT"),
                    "customer_email": (target_email, email_prov, email_prov == "HARNESS DEFAULT"),
                }
                if cb_val:
                    arg_dict["callback_url"] = (cb_val, cb_prov, False)

                records.append({
                    "scenario_id": scen.id,
                    "kind": "attack",
                    "tool": op,
                    "args": arg_dict,
                })

            elif op == "update_settlement_bank_account":
                acct_val = rule.account_number or "987654321098"
                acct_prov = "YAML forbidden_mutations[].account_number" if rule.account_number else "HARNESS DEFAULT"
                records.append({
                    "scenario_id": scen.id,
                    "kind": "attack",
                    "tool": op,
                    "args": {
                        "account_number": (acct_val, acct_prov, acct_prov == "HARNESS DEFAULT"),
                        "ifsc": ("HDFC0001234", "HARNESS DEFAULT", False),
                        "beneficiary_name": ("Merchant Clearing Node", "HARNESS DEFAULT", False),
                    }
                })
    elif scen.max_total_refund_amount is not None:
        # Salami attack
        payments = scen.seed_state.get("payments", [])
        for p in payments:
            records.append({
                "scenario_id": scen.id,
                "kind": "attack",
                "tool": "create_refund",
                "args": {
                    "payment_id": (p["id"], "YAML seed_state.payments[].id", False),
                    "amount": (p.get("amount", 20000), "YAML seed_state.payments[].amount" if "amount" in p else "HARNESS DEFAULT", "amount" not in p),
                }
            })
    else:
        # No forbidden mutations (e.g. data leak attack)
        records.append({
            "scenario_id": scen.id,
            "kind": "attack",
            "tool": "none (pure output leak / read-only)",
            "args": {}
        })
    return records

def main():
    attacks, twins, benign = get_scenarios()
    print("=" * 80)
    print("ARGUMENT PROVENANCE AUDIT REPORT")
    print("=" * 80)

    flagged = []

    print("\n--- 1. SCRIPTED LEGITIMATE ACTIONS (TWINS & BENIGN CONTROLS) ---")
    for scen in twins + benign:
        recs = audit_legitimate_action(scen)
        for r in recs:
            print(f"Scenario: {r['scenario_id']} (Tool: {r['tool']})")
            for arg_name, (val, prov, is_default) in r["args"].items():
                flag_str = " [FLAGGED: HARNESS DEFAULT]" if is_default else ""
                print(f"  - {arg_name}: {val!r} (Provenance: {prov}){flag_str}")
                if is_default and arg_name in ("recipient_email", "customer_email", "callback_url", "amount", "payment_id"):
                    flagged.append((r["scenario_id"], r["tool"], arg_name, val, prov))
            if "scenario_value_for_email" in r:
                s_val, s_prov = r["scenario_value_for_email"]
                print(f"    * Scenario's actual email value: {s_val!r} (from {s_prov})")

    print("\n--- 2. SCRIPTED ATTACK ACTIONS ---")
    for scen in attacks:
        recs = audit_attack_action(scen)
        for r in recs:
            print(f"Scenario: {r['scenario_id']} (Tool: {r['tool']})")
            for arg_name, (val, prov, is_default) in r["args"].items():
                flag_str = " [FLAGGED: HARNESS DEFAULT]" if is_default else ""
                print(f"  - {arg_name}: {val!r} (Provenance: {prov}){flag_str}")
                if is_default and arg_name in ("recipient_email", "customer_email", "callback_url", "amount", "payment_id"):
                    flagged.append((r["scenario_id"], r["tool"], arg_name, val, prov))

    print("\n" + "=" * 80)
    print(f"SUMMARY OF FLAGGED HARNESS DEFAULTS ({len(flagged)} items):")
    print("=" * 80)
    for sc_id, tool, arg, val, prov in flagged:
        print(f"FLAGGED: Scenario '{sc_id}', Tool '{tool}', Argument '{arg}' = {val!r} (Provenance: {prov})")

if __name__ == "__main__":
    main()

