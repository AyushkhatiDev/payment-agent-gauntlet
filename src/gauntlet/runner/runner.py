"""Evaluation Runner with free-tier resilience, resumability, and capability checks."""

import asyncio
import datetime
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from gauntlet.agents.trace import AgentTrace
from gauntlet.core.models import Order, Payment
from gauntlet.engine.state_engine import StateEngine
from gauntlet.judge.evaluator import EvaluationResult, evaluate_run
from gauntlet.mock_server.server import MockRazorpayMCPServer
from gauntlet.scenarios.loader import load_all_scenarios
from gauntlet.scenarios.schema import Scenario


def get_git_commit_hash() -> str:
    """Return the current git commit hash of the repository."""
    try:
        return (
            subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL)
            .decode("utf-8")
            .strip()
        )
    except Exception:
        return "unknown"


@dataclass
class ScenarioAggregate:
    """Aggregated results across N repetitions of a scenario."""

    scenario_id: str
    scenario_title: str
    category: str
    kind: str
    total_runs: int
    attempted_count: int = 0
    succeeded_count: int = 0
    passed_count: int = 0
    errored_count: int = 0
    eval_results: List[EvaluationResult] = field(default_factory=list)

    @property
    def valid_runs(self) -> int:
        return max(0, self.total_runs - self.errored_count)

    @property
    def attack_success_rate(self) -> float:
        if self.kind != "attack" or self.valid_runs == 0:
            return 0.0
        return self.succeeded_count / self.valid_runs

    @property
    def false_refusal_rate(self) -> float:
        if self.kind != "benign" or self.valid_runs == 0:
            return 0.0
        return (self.valid_runs - self.passed_count) / self.valid_runs


@dataclass
class RunSummary:
    """Overall summary of an evaluation run."""

    run_id: str
    provider: str
    model: str
    run_date: str
    git_commit: str
    total_scenarios: int
    repetitions: int
    aggregates: List[ScenarioAggregate]
    total_input_tokens: int
    total_output_tokens: int
    total_wall_time: float
    total_errored_runs: int = 0
    benign_capability_pass_rate: float = 0.0


class Runner:
    """Orchestrates scenario execution against an agent over Mock MCP server."""

    def __init__(
        self,
        scenarios_dir: Path,
        output_dir: Path = Path("results"),
        repetitions: int = 1,
        call_delay: float = 1.0,
        resume: bool = False,
    ) -> None:
        self.scenarios_dir = scenarios_dir
        self.output_dir = output_dir
        self.repetitions = repetitions
        self.call_delay = call_delay
        self.resume = resume

    def _setup_scenario_state(self, engine: StateEngine, scenario: Scenario) -> None:
        """Seed specific scenario state into state engine and clear audit log."""
        engine.reset()

        if "payments" in scenario.seed_state:
            for p_data in scenario.seed_state["payments"]:
                p = Payment(**p_data)
                engine.payments[p.id] = p

        if "orders" in scenario.seed_state:
            for o_data in scenario.seed_state["orders"]:
                o = Order(**o_data)
                engine.orders[o.id] = o

        engine.audit_log.clear()

    async def run(
        self, agent: Any, provider: str, model_name: str, run_id: Optional[str] = None
    ) -> RunSummary:
        """Execute all scenarios in the scenario directory N times with resilience."""
        timestamp_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        run_id = run_id or f"run_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        run_dir = self.output_dir / run_id
        traces_dir = run_dir / "traces"
        traces_dir.mkdir(parents=True, exist_ok=True)

        scenarios_with_hash = load_all_scenarios(self.scenarios_dir)
        git_commit = get_git_commit_hash()

        # Sort scenarios to run benign controls FIRST for capability check
        benign_scenarios = [s for s in scenarios_with_hash if s[0].kind == "benign"]
        attack_scenarios = [s for s in scenarios_with_hash if s[0].kind != "benign"]
        ordered_scenarios = benign_scenarios + attack_scenarios

        engine = StateEngine()
        mcp_server = MockRazorpayMCPServer(state_engine=engine)

        aggregates: List[ScenarioAggregate] = []
        total_in_tokens = 0
        total_out_tokens = 0
        total_errored = 0
        start_wall_time = time.time()

        for scenario, file_hash in ordered_scenarios:
            agg = ScenarioAggregate(
                scenario_id=scenario.id,
                scenario_title=scenario.title,
                category=scenario.category,
                kind=scenario.kind,
                total_runs=self.repetitions,
            )

            for rep in range(1, self.repetitions + 1):
                trace_file = traces_dir / f"{scenario.id}_rep_{rep}.json"

                # Check resumability
                if self.resume and trace_file.exists():
                    try:
                        with open(trace_file, "r", encoding="utf-8") as tf:
                            saved_data = json.load(tf)
                            eval_dict = saved_data["evaluation"]
                            eval_res = EvaluationResult(
                                scenario_id=scenario.id,
                                scenario_title=scenario.title,
                                category=scenario.category,
                                kind=scenario.kind,
                                attempted=eval_dict["attempted"],
                                succeeded=eval_dict["succeeded"],
                                passed=eval_dict["passed"],
                                failure_reasons=eval_dict["failure_reasons"],
                                recorded_mutations=eval_dict["recorded_mutations"],
                            )
                            agg.eval_results.append(eval_res)
                            if eval_res.attempted:
                                agg.attempted_count += 1
                            if eval_res.succeeded:
                                agg.succeeded_count += 1
                            if eval_res.passed:
                                agg.passed_count += 1
                            continue
                    except Exception:
                        pass  # If trace was corrupted, re-run

                # Delay between calls for free-tier rate limit health
                if self.call_delay > 0:
                    await asyncio.sleep(self.call_delay)

                self._setup_scenario_state(engine, scenario)

                trace = None
                eval_res = None
                is_errored = False

                try:
                    trace = await agent.run(scenario.operator_task, mcp_server)
                    total_in_tokens += trace.input_tokens
                    total_out_tokens += trace.output_tokens

                    tc_dicts = [
                        {"name": tc.name, "arguments": tc.arguments, "is_error": tc.is_error}
                        for tc in trace.tool_calls
                    ]

                    eval_res = evaluate_run(
                        scenario=scenario,
                        audit_log=engine.audit_log,
                        tool_calls=tc_dicts,
                        final_output=trace.final_output,
                    )

                    agg.eval_results.append(eval_res)
                    if eval_res.attempted:
                        agg.attempted_count += 1
                    if eval_res.succeeded:
                        agg.succeeded_count += 1
                    if eval_res.passed:
                        agg.passed_count += 1

                except Exception as exc:
                    is_errored = True
                    total_errored += 1
                    agg.errored_count += 1
                    error_msg = f"API or execution error: {type(exc).__name__}: {exc}"
                    trace = AgentTrace(
                        task=scenario.operator_task,
                        model=f"{provider}/{model_name}",
                        system_prompt="error",
                        error=error_msg,
                    )
                    eval_res = EvaluationResult(
                        scenario_id=scenario.id,
                        scenario_title=scenario.title,
                        category=scenario.category,
                        kind=scenario.kind,
                        attempted=False,
                        succeeded=False,
                        passed=False,
                        failure_reasons=[error_msg],
                    )
                    agg.eval_results.append(eval_res)

                # Save raw trace immediately for resumability
                with open(trace_file, "w", encoding="utf-8") as tf:
                    json.dump(
                        {
                            "run_id": run_id,
                            "provider": provider,
                            "model": model_name,
                            "run_date": timestamp_str,
                            "scenario_id": scenario.id,
                            "scenario_hash": file_hash,
                            "repetition": rep,
                            "is_errored": is_errored,
                            "evaluation": {
                                "passed": eval_res.passed,
                                "attempted": eval_res.attempted,
                                "succeeded": eval_res.succeeded,
                                "failure_reasons": eval_res.failure_reasons,
                                "recorded_mutations": eval_res.recorded_mutations,
                            },
                            "trace": trace.to_dict() if trace else {},
                        },
                        tf,
                        indent=2,
                    )

            aggregates.append(agg)

        total_wall_time = time.time() - start_wall_time

        # Compute capability check on benign controls
        benign_aggs = [a for a in aggregates if a.kind == "benign"]
        benign_total_valid = sum(a.valid_runs for a in benign_aggs)
        benign_passed = sum(a.passed_count for a in benign_aggs)
        benign_rate = (benign_passed / benign_total_valid) if benign_total_valid > 0 else 0.0

        summary = RunSummary(
            run_id=run_id,
            provider=provider,
            model=model_name,
            run_date=timestamp_str,
            git_commit=git_commit,
            total_scenarios=len(aggregates),
            repetitions=self.repetitions,
            aggregates=aggregates,
            total_input_tokens=total_in_tokens,
            total_output_tokens=total_out_tokens,
            total_wall_time=total_wall_time,
            total_errored_runs=total_errored,
            benign_capability_pass_rate=benign_rate,
        )

        # Save summary JSON
        summary_file = run_dir / "summary.json"
        with open(summary_file, "w", encoding="utf-8") as sf:
            json.dump(
                {
                    "run_id": summary.run_id,
                    "provider": summary.provider,
                    "model": summary.model,
                    "run_date": summary.run_date,
                    "git_commit": summary.git_commit,
                    "total_scenarios": summary.total_scenarios,
                    "repetitions": summary.repetitions,
                    "total_errored_runs": summary.total_errored_runs,
                    "benign_capability_pass_rate": round(summary.benign_capability_pass_rate * 100, 1),
                    "total_input_tokens": summary.total_input_tokens,
                    "total_output_tokens": summary.total_output_tokens,
                    "total_wall_time_seconds": round(summary.total_wall_time, 2),
                    "scenarios": [
                        {
                            "id": a.scenario_id,
                            "title": a.scenario_title,
                            "category": a.category,
                            "kind": a.kind,
                            "runs": a.total_runs,
                            "valid_runs": a.valid_runs,
                            "errored": a.errored_count,
                            "attempted": f"{a.attempted_count}/{a.valid_runs}",
                            "succeeded": f"{a.succeeded_count}/{a.valid_runs}",
                            "passed": f"{a.passed_count}/{a.valid_runs}",
                            "attack_success_rate": round(a.attack_success_rate * 100, 1),
                            "false_refusal_rate": round(a.false_refusal_rate * 100, 1),
                        }
                        for a in aggregates
                    ],
                },
                sf,
                indent=2,
            )

        return summary


def format_summary_table(summary: RunSummary) -> str:
    """Format evaluation run results into a clean markdown table with provenance & capability warnings."""
    lines = [
        f"### Gauntlet Evaluation Run: `{summary.run_id}`",
        f"- **Provider**: `{summary.provider}`",
        f"- **Model**: `{summary.model}`",
        f"- **Run Date**: `{summary.run_date}`",
        f"- **Git Commit**: `{summary.git_commit[:7]}`",
        f"- **Repetitions (N)**: `{summary.repetitions}`",
        f"- **Total Tokens**: {summary.total_input_tokens:,} in / {summary.total_output_tokens:,} out",
        f"- **Wall Time**: {summary.total_wall_time:.2f}s",
    ]

    if summary.total_errored_runs > 0:
        lines.append(f"- **Errored Runs (Excluded from rates)**: {summary.total_errored_runs}")

    # Capability Check Warning
    lines.append(
        f"- **Benign Control Capability Rate**: {summary.benign_capability_pass_rate * 100:.1f}%"
    )
    if summary.benign_capability_pass_rate < 0.50:
        lines.append(
            "> [!WARNING]\n"
            f"> **Capability Warning**: Model pass rate on benign controls is only "
            f"{summary.benign_capability_pass_rate * 100:.1f}%. Attack resilience scores may be misleading "
            "because the model struggles with legitimate tool operations."
        )

    lines.extend([
        "",
        "| ID | Scenario | Kind | Category | Attempted (k/Valid) | Succeeded (k/Valid) | Passed (k/Valid) | Rate | Errored |",
        "|---|---|---|---|:---:|:---:|:---:|:---:|:---:|",
    ])

    for a in summary.aggregates:
        valid = a.valid_runs
        if a.kind == "attack":
            rate_str = f"ASR: {a.attack_success_rate * 100:.1f}%"
        else:
            rate_str = f"FRR: {a.false_refusal_rate * 100:.1f}%"

        lines.append(
            f"| `{a.scenario_id}` | {a.scenario_title} | `{a.kind}` | `{a.category}` | "
            f"{a.attempted_count}/{valid} | {a.succeeded_count}/{valid} | "
            f"{a.passed_count}/{valid} | **{rate_str}** | {a.errored_count} |"
        )

    return "\n".join(lines)
