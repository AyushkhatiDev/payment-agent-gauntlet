"""CLI entrypoint for Gauntlet."""

import argparse
import asyncio
from pathlib import Path
import sys

from gauntlet.agents.baseline import BaselineAgent
from gauntlet.agents.mock_agent import MockAgent
from gauntlet.mock_server.server import MockRazorpayMCPServer
from gauntlet.runner.runner import Runner, format_summary_table


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Gauntlet: Adversarial Safety Test Harness for Payment Agents"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # 1. serve-mcp command
    server_parser = subparsers.add_parser(
        "serve-mcp", help="Run Mock Razorpay MCP server over stdio"
    )
    server_parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio"],
        help="MCP transport protocol (default: stdio)",
    )

    # 2. run command
    run_parser = subparsers.add_parser("run", help="Run evaluation scenarios against an agent")
    run_parser.add_argument(
        "--scenarios",
        default="scenarios",
        type=str,
        help="Path to scenarios directory (default: scenarios)",
    )
    run_parser.add_argument(
        "--agent",
        default="baseline",
        choices=["baseline", "mock"],
        help="Agent under test (baseline, mock)",
    )
    run_parser.add_argument(
        "--model",
        default="claude-3-5-sonnet-20241022",
        type=str,
        help="LLM model identifier for agent",
    )
    run_parser.add_argument(
        "-n",
        "--n",
        default=1,
        type=int,
        help="Number of repetitions per scenario (default: 1)",
    )
    run_parser.add_argument(
        "--output-dir",
        default="results",
        type=str,
        help="Directory to save run results (default: results)",
    )

    args = parser.parse_args()

    if args.command == "serve-mcp":
        server = MockRazorpayMCPServer()
        asyncio.run(server.run_stdio())

    elif args.command == "run":
        scenarios_path = Path(args.scenarios)
        output_path = Path(args.output_dir)

        if args.agent == "baseline":
            agent = BaselineAgent(model=args.model)
        else:
            agent = MockAgent(name="mock-dryrun")

        runner = Runner(
            scenarios_dir=scenarios_path,
            output_dir=output_path,
            repetitions=args.n,
        )

        print(f"\n🚀 Running Gauntlet Evaluation Suite...")
        print(f"   Agent: {args.agent} (Model: {args.model})")
        print(f"   Scenarios: {scenarios_path}")
        print(f"   Repetitions: {args.n}\n")

        summary = asyncio.run(runner.run(agent=agent, model_name=args.model))
        table_output = format_summary_table(summary)
        print("\n" + table_output + "\n")
        print(f"Results and raw traces saved to: {output_path / summary.run_id}\n")

    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
