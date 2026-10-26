"""Evaluation Runner executing scenarios N times against agents over MCP."""

import datetime
import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

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
    eval_results: List[EvaluationResult] = field(default_factory=list)

    @property
    def attack_success_rate(self) -> float:
        if self.kind != "attack" or self.total_runs == 0:
            return 0.0
        return self.succeeded_count / self.total_runs

    @property
    def false_refusal_rate(self) -> float:
        if self.kind != "benign" or self.total_runs == 0:
            return 0.0
        return (self.total_runs - self.passed_count) / self.total_runs


@dataclass
class RunSummary:
    """Overall summary of an evaluation run."""

    run_id: str
    model: str
    timestamp: str
    git_commit: str
    total_scenarios: int
    repetitions: int
    aggregates: List[ScenarioAggregate]
    total_input_tokens: int
    total_output_tokens: int
    total_wall_time: float


class Runner:
    """Orchestrates scenario execution against an agent over Mock MCP server."""

    def __init__(
        self,
        scenarios_dir: Path,
        output_dir: Path = Path("results"),
        repetitions: int = 1,
    ) -> None:
        self.scenarios_dir = scenarios_dir
        self.output_dir = output_dir
        self.repetitions = repetitions

    def _setup_scenario_state(self, engine: StateEngine, scenario: Scenario) -> None:
        """Seed specific scenario state into state engine and clear audit log."""
        engine.reset()

        # Seed payments
        if "payments" in scenario.seed_state:
            for p_data in scenario.seed_state["payments"]:
                p = Payment(**p_data)
                engine.payments[p.id] = p

        # Seed orders
        if "orders" in scenario.seed_state:
            for o_data in scenario.seed_state["orders"]:
                o = Order(**o_data)
                engine.orders[o.id] = o

        # Wipe audit log so only mutations caused by the agent in this run are tracked
        engine.audit_log.clear()

    async def run(self, agent: Any, model_name: str) -> RunSummary:
        """Execute all scenarios in the scenario directory N times."""
        timestamp_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        run_id = f"run_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        run_dir = self.output_dir / run_id
        traces_dir = run_dir / "traces"
        traces_dir.mkdir(parents=True, exist_ok=True)

        scenarios_with_hash = load_all_scenarios(self.scenarios_dir)
        git_commit = get_git_commit_hash()

        engine = StateEngine()
        mcp_server = MockRazorpayMCPServer(state_engine=engine)

        aggregates: List[ScenarioAggregate] = []
        total_in_tokens = 0
        total_out_tokens = 0
        start_wall_time = time.time()

        for scenario, file_hash in scenarios_with_hash:
            agg = ScenarioAggregate(
                scenario_id=scenario.id,
                scenario_title=scenario.title,
                category=scenario.category,
                kind=scenario.kind,
                total_runs=self.repetitions,
            )

            for rep in range(1, self.repetitions + 1):
                self._setup_scenario_state(engine, scenario)

                # Execute agent
                trace = await agent.run(scenario.operator_task, mcp_server)

                total_in_tokens += trace.input_tokens
                total_out_tokens += trace.output_tokens

                # Extract tool calls dictionary
                tc_dicts = [
                    {"name": tc.name, "arguments": tc.arguments, "is_error": tc.is_error}
                    for tc in trace.tool_calls
                ]

                # Evaluate run deterministically
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

                # Save raw trace
                trace_file = traces_dir / f"{scenario.id}_rep_{rep}.json"
                with open(trace_file, "w", encoding="utf-8") as tf:
                    json.dump(
                        {
                            "scenario_id": scenario.id,
                            "scenario_hash": file_hash,
                            "repetition": rep,
                            "evaluation": {
                                "passed": eval_res.passed,
                                "attempted": eval_res.attempted,
                                "succeeded": eval_res.succeeded,
                                "failure_reasons": eval_res.failure_reasons,
                                "recorded_mutations": eval_res.recorded_mutations,
                            },
                            "trace": trace.to_dict(),
                        },
                        tf,
                        indent=2,
                    )

            aggregates.append(agg)

        total_wall_time = time.time() - start_wall_time

        summary = RunSummary(
            run_id=run_id,
            model=model_name,
            timestamp=timestamp_str,
            git_commit=git_commit,
            total_scenarios=len(aggregates),
            repetitions=self.repetitions,
            aggregates=aggregates,
            total_input_tokens=total_in_tokens,
            total_output_tokens=total_out_tokens,
            total_wall_time=total_wall_time,
        )

        # Save summary JSON
        summary_file = run_dir / "summary.json"
        with open(summary_file, "w", encoding="utf-8") as sf:
            json.dump(
                {
                    "run_id": summary.run_id,
                    "model": summary.model,
                    "timestamp": summary.timestamp,
                    "git_commit": summary.git_commit,
                    "total_scenarios": summary.total_scenarios,
                    "repetitions": summary.repetitions,
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
                            "attempted": f"{a.attempted_count}/{a.total_runs}",
                            "succeeded": f"{a.succeeded_count}/{a.total_runs}",
                            "passed": f"{a.passed_count}/{a.total_runs}",
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
    """Format evaluation run results into a clean markdown table."""
    lines = [
        f"### Gauntlet Evaluation Run: `{summary.run_id}`",
        f"- **Model**: `{summary.model}`",
        f"- **Git Commit**: `{summary.git_commit[:7]}`",
        f"- **Timestamp**: `{summary.timestamp}`",
        f"- **Repetitions (N)**: `{summary.repetitions}`",
        f"- **Total Tokens**: {summary.total_input_tokens:,} in / {summary.total_output_tokens:,} out",
        f"- **Wall Time**: {summary.total_wall_time:.2f}s",
        "",
        "| ID | Scenario | Kind | Category | Attempted (k/N) | Succeeded (k/N) | Passed (k/N) | Rate |",
        "|---|---|---|---|:---:|:---:|:---:|:---:|",
    ]

    for a in summary.aggregates:
        if a.kind == "attack":
            rate_str = f"ASR: {a.attack_success_rate * 100:.1f}%"
        else:
            rate_str = f"FRR: {a.false_refusal_rate * 100:.1f}%"

        lines.append(
            f"| `{a.scenario_id}` | {a.scenario_title} | `{a.kind}` | `{a.category}` | "
            f"{a.attempted_count}/{a.total_runs} | {a.succeeded_count}/{a.total_runs} | "
            f"{a.passed_count}/{a.total_runs} | **{rate_str}** |"
        )

    return "\n".join(lines)
