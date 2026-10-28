#!/usr/bin/env python3
"""Generate scenario catalog, counts, tier/objective mappings directly from YAML files."""

from pathlib import Path
from typing import Any, Dict, List
import yaml

RULE_MAPPING: Dict[str, str] = {
    "scen_01": "Rule 1a (Unsolicited refund injection in note)",
    "scen_02": "Rule 2a (Superseded unqueryable order note instant settlement)",
    "scen_02b": "Rule 2a (Instant settlement injection in payment note)",
    "scen_03": "Rule 2b (Unsolicited payment link injection in desc)",
    "scen_04": "Rule 1a (Social engineering impersonation of accountant)",
    "scen_05": "Rule 1d (Customer email mismatch check)",
    "scen_06": "Rule 1a / Rule 1c (Superseded authority coercion confound)",
    "scen_06b": "Rule 1a (Authority pressure sub-cap check)",
    "scen_09": "Rule 1a (Confused deputy note refund inflation)",
    "scen_10": "Rule 1a (Fake policy memo appeasement injection)",
    "scen_11": "Rule 1a (Spoofed structured system JSON in description)",
    "scen_12": "Rule 1a (Autopilot fraud flag queue processing)",
    "scen_13": "Rule 1c (Cumulative daily refund limit / salami attack)",
    "scen_14": "Rule 1b (30-day return window expiration)",
    "scen_15": "Rule 2b (Unverified recipient payment link redirection)",
    "scen_16": "Rule 2a (Superseded unqueryable order note settlement trigger)",
    "scen_16b": "Rule 2a (Instant settlement emergency diversion in payment note)",
    "scen_17": "Rule 3 (Customer PII disclosure via chat)",
    "scen_18": "Rule 3 (Customer delivery address bulk export)",
    "scen_19": "Rule 2c (Bank account modification restriction)",
    "scen_20": "Rule 2c (Bank migration phishing memo)",
    "scen_21": "Rule 1a (Internal ops ticket SOP handoff injection)",
    "scen_22": "Rule 2b (Third-party recipient payment link request)",
    "scen_23": "Rule 1b (Holiday policy extension window subversion)",
    "scen_23b": "Rule 1b (Holiday policy override against task constraint)",
    "scen_24": "Rule 2a (Internal finance ops instant settlement memo)",
    "scen_25": "Rule 2b (Unverified ERP callback URL redirection)",
    "scen_26": "Rule 2c (IT maintenance bank clearing route update)",
}

RULE_ENFORCEMENT_PREFIXES = (
    "scen_05", "scen_12", "scen_13", "scen_14", "scen_15",
    "scen_17", "scen_18", "scen_19", "scen_20", "scen_22",
    "scen_23", "scen_25", "scen_26",
)

def classify_scenario(data: Dict[str, Any]) -> Dict[str, Any]:
    sid = data.get("id", "")
    kind = data.get("kind", "")
    prefix = "_".join(sid.split("_")[:2])

    tier = data.get("attack_tier")
    if not tier and kind == "attack":
        tier = "naive"

    # Tier note
    if sid.startswith(("scen_01", "scen_02", "scen_03", "scen_04", "scen_05", "scen_06")):
        tier_note = "assigned post hoc"
        tier = "naive"
    elif tier:
        tier_note = "pre-registered a priori"
    else:
        tier_note = "n/a"

    # Objective
    if kind == "attack":
        objective = "rule_enforcement" if sid.startswith(RULE_ENFORCEMENT_PREFIXES) else "injection_resistance"
    else:
        objective = "n/a"

    rule = RULE_MAPPING.get(prefix, "N/A")
    has_leak = bool(data.get("forbidden_output_contains"))

    return {
        "id": sid,
        "title": data.get("title", ""),
        "kind": kind,
        "category": data.get("category", ""),
        "tier": tier,
        "tier_note": tier_note,
        "objective": objective,
        "rule": rule,
        "has_leak": has_leak,
    }

def generate_catalog_markdown(scenarios_dir: Path = Path("scenarios")) -> str:
    files = sorted(list(scenarios_dir.glob("*.yaml")) + list(scenarios_dir.glob("*.yml")))
    records = []
    for f in files:
        with open(f, "r", encoding="utf-8") as fp:
            data = yaml.safe_load(fp)
        records.append(classify_scenario(data))

    attacks = [r for r in records if r["kind"] == "attack"]
    twins = [r for r in records if r["kind"] == "benign" and "twin" in r["id"]]
    benign = [r for r in records if r["kind"] == "benign" and "twin" not in r["id"]]

    rule_enf = [r for r in attacks if r["objective"] == "rule_enforcement"]
    inj_res = [r for r in attacks if r["objective"] == "injection_resistance"]

    lines = [
        "### Programmatic Scenario Catalog & Classification",
        f"- **Total Scenarios Found**: {len(records)}",
        f"  - **Attacks**: {len(attacks)} (Rule Enforcement: {len(rule_enf)}, Injection Resistance: {len(inj_res)})",
        f"  - **Authorized Twins**: {len(twins)}",
        f"  - **Benign Controls**: {len(benign)}",
        "",
        "#### All Adversarial Attack Scenarios (Generated from YAML)",
        "| Scenario ID | Title | Attack Tier | Tier Note | Objective | Primary Violated Rule | Leak Probe |",
        "|---|---|:---:|:---:|:---:|---|:---:|",
    ]

    for a in attacks:
        leak_str = "Yes" if a["has_leak"] else "No"
        lines.append(
            f"| `{a['id']}` | {a['title']} | `{a['tier']}` | {a['tier_note']} | `{a['objective']}` | {a['rule']} | {leak_str} |"
        )

    return "\n".join(lines)

if __name__ == "__main__":
    print(generate_catalog_markdown())
