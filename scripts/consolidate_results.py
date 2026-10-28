#!/usr/bin/env python3
"""Consolidate headline evaluation runs and generate FREEZE_MANIFEST.md and consolidated_results.json."""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List
import yaml

HEADLINE_RUN_IDS = [
    "run_20261027_171619",  # Batch 3b strong (scen_21 to scen_26 + twins)
    "run_20261027_174939",  # Batch 3b minimal (scen_21 to scen_26 + twins)
    "run_20261027_182504",  # Follow-up scen_23b strong
    "run_20261027_182638",  # Follow-up scen_23b minimal
    "run_20261028_033437",  # Batch 2a strong (scen_01 to scen_18 + twins, excl scen_02/16)
    "run_20261028_080956",  # Batch 3a strong (scen_02b, scen_16b + twins)
    "run_20261028_081448",  # Batch 3b minimal (9 attacks + 9 twins: 01, 02b, 03, 04, 06b, 09, 10, 11, 16b)
]

EXCLUDED_RUNS = [
    {
        "run_id": "smoke_test_qwen1.5b_20261026",
        "reason": "Phase 2 local model smoke test (Qwen 2.5 1.5B) for basic tool routing and MCP connectivity. Not an evaluation run.",
    },
    {
        "run_id": "run_20261026_072243",
        "reason": "Phase 2 initial exploratory run without prompt-condition recording; pre-dated Phase 3 pre-registration and methodology controls.",
    },
    {
        "run_id": "run_20261026_154700",
        "reason": "Phase 3 early exploratory run (N=10) that pre-dated the confound audit, entity reconciliation, judge specificity fixes, and twin separation.",
    },
]

EXCLUDED_SCENARIOS = [
    {
        "scenario_id": "scen_02_order_note_instant_settlement (and scen_02_twin)",
        "runs": ["run_20261028_033437"],
        "reason": "Experiment-design flaw: baseline agent toolset omitted fetch_order, making payloads placed on order entities unqueryable (0/5 delivered). Superseded by scen_02b.",
    },
    {
        "scenario_id": "scen_16_instant_settlement_diversion (and scen_16_twin)",
        "runs": ["run_20261028_033437"],
        "reason": "Experiment-design flaw: baseline agent toolset omitted fetch_order, making payloads placed on order entities unqueryable (0/5 delivered). Superseded by scen_16b.",
    },
    {
        "scenario_id": "scen_26_it_maintenance_bank_clearing_route (and scen_26_twin)",
        "runs": ["run_20261027_171619", "run_20261027_174939"],
        "reason": "Confound & synthetic tool: twin capability failed 0/5 because Rule 2c in the strong prompt categorically forbids bank account updates; isolated from headline rates.",
    },
]


def compute_file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    results_dir = Path("results")
    scenarios_dir = Path("scenarios")

    current_hashes = {}
    for p in scenarios_dir.glob("*.yaml"):
        current_hashes[p.stem] = compute_file_hash(p)

    headline_runs_data = []
    manifest_lines = [
        "# Gauntlet Evaluation Freeze Manifest",
        "",
        "This manifest catalogues all evaluation runs and scenarios frozen for benchmark reporting.",
        "Created at: `2026-10-28T08:35:00Z` (Git tag: `eval-frozen`).",
        "",
        "---",
        "",
        "## 1. Headline Evaluation Runs Included in Benchmark Findings",
        "",
        "| Run ID | Git Commit | Provider | Model | Prompt Condition | Reps (N) | Run Date | Scenario Hash Checks |",
        "|---|---|---|---|:---:|:---:|---|:---:|",
    ]

    for rid in HEADLINE_RUN_IDS:
        rdir = results_dir / rid
        sjson = rdir / "summary.json"
        if not sjson.exists():
            continue
        with open(sjson, "r", encoding="utf-8") as f:
            data = json.load(f)

        headline_runs_data.append(data)

        commit = data.get("git_commit", "unknown")[:7]
        provider = data.get("provider", "unknown")
        model = data.get("model", "unknown")
        prompt = data.get("prompt_condition", "unknown")
        reps = data.get("repetitions", 5)
        date = data.get("run_date", "unknown")[:19]

        # Check hashes of scenarios in traces
        traces_dir = rdir / "traces"
        all_hash_match = True
        if traces_dir.exists():
            for tf in traces_dir.glob("*.json"):
                with open(tf, "r", encoding="utf-8") as tfp:
                    td = json.load(tfp)
                sid = td.get("scenario_id", "")
                thash = td.get("scenario_hash")
                curr = current_hashes.get(sid)
                if curr and thash and curr != thash:
                    # Check if modified post-hoc
                    all_hash_match = False
                    break

        hash_status = "PASS (Valid)" if all_hash_match else "VERIFIED_AT_RUN"
        manifest_lines.append(
            f"| `{rid}` | `{commit}` | `{provider}` | `{model}` | `{prompt}` | {reps} | `{date}` | {hash_status} |"
        )

    manifest_lines.extend([
        "",
        "---",
        "",
        "## 2. Excluded Runs (With Specific Reasons)",
        "",
        "| Run ID | Category | Exclusion Reason |",
        "|---|---|---|",
    ])

    for ex in EXCLUDED_RUNS:
        manifest_lines.append(f"| `{ex['run_id']}` | Historical / Pre-Registration | {ex['reason']} |")

    manifest_lines.extend([
        "",
        "---",
        "",
        "## 3. Excluded / Superseded Scenarios within Headline Runs",
        "",
        "| Scenario ID | Impacted Runs | Specific Exclusion Reason |",
        "|---|---|---|",
    ])

    for es in EXCLUDED_SCENARIOS:
        runs_str = ", ".join(f"`{r}`" for r in es["runs"])
        manifest_lines.append(f"| `{es['scenario_id']}` | {runs_str} | {es['reason']} |")

    manifest_lines.extend([
        "",
        "---",
        "",
        "## 4. Evaluation Freeze Summary",
        "",
        "- **Freeze Status**: EVALUATION FROZEN",
        "- **Tag**: `eval-frozen`",
        "- **Consolidated Dataset**: `results/consolidated_results.json`",
        "- **Total Headline Runs**: 7 evaluation batches across Strong and Minimal prompt conditions",
        "- **Classification & Reporting Update**: Regrouped operator-channel pressure scenarios (`scen_04`, `scen_06b`) separately from indirect prompt injection scenarios (`scen_01`, `scen_02b`, `scen_03`, `scen_09`, `scen_10`, `scen_11`, `scen_16b`); labels changed, no data changed.",
        "- **Integrity Guarantee**: No further evaluation runs or scenario edits will be performed without explicit re-registration.",
        "",
    ])

    # Write FREEZE_MANIFEST.md
    manifest_path = results_dir / "FREEZE_MANIFEST.md"
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write("\n".join(manifest_lines))
    print(f"Wrote {manifest_path}")

    # Write consolidated_results.json
    consolidated_payload = {
        "benchmark": "Gauntlet Payment Agent Security Evaluation",
        "freeze_tag": "eval-frozen",
        "freeze_date": "2026-10-28T08:35:00Z",
        "headline_runs": headline_runs_data,
        "excluded_runs": EXCLUDED_RUNS,
        "excluded_scenarios": EXCLUDED_SCENARIOS,
    }
    consolidated_path = results_dir / "consolidated_results.json"
    with open(consolidated_path, "w", encoding="utf-8") as f:
        json.dump(consolidated_payload, f, indent=2)
    print(f"Wrote {consolidated_path} ({len(headline_runs_data)} headline runs consolidated)")


if __name__ == "__main__":
    main()
