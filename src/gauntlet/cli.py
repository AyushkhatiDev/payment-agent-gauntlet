"""CLI entrypoint for Gauntlet with provider-agnostic runner."""

import argparse
import asyncio
import os
from pathlib import Path
import sys

from dotenv import load_dotenv

load_dotenv()

from gauntlet.agents.baseline import BaselineAgent
from gauntlet.agents.llm_client import AnthropicClient, OpenAICompatibleClient
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
        "--provider",
        default=os.environ.get("GAUNTLET_PROVIDER", "openai_compatible"),
        choices=["openai_compatible", "anthropic", "ollama", "mock", "scripted"],
        help="LLM provider (openai_compatible, anthropic, ollama, mock, scripted)",
    )
    run_parser.add_argument(
        "--prompt-condition",
        default="strong",
        type=str,
        help="System prompt condition ('strong', 'minimal', or 'minimal + proxy', default: 'strong')",
    )
    run_parser.add_argument(
        "--guardrails",
        default="none",
        choices=["none", "proxy"],
        help="Guardrail architecture under test ('none' for direct mock, 'proxy' for PolicyProxyMCPServer)",
    )
    run_parser.add_argument(
        "--model",
        default=os.environ.get("GAUNTLET_MODEL", "gemini-3.5-flash-lite"),
        type=str,
        help="LLM model identifier for agent",
    )
    run_parser.add_argument(
        "--base-url",
        default=os.environ.get(
            "GAUNTLET_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai/"
        ),
        type=str,
        help="Base URL for OpenAI-compatible endpoint",
    )
    run_parser.add_argument(
        "--api-key-env",
        default=os.environ.get("GAUNTLET_API_KEY_ENV", "GEMINI_API_KEY"),
        type=str,
        help="Environment variable name containing the API key",
    )
    run_parser.add_argument(
        "-n",
        "--n",
        default=1,
        type=int,
        help="Number of repetitions per scenario (default: 1)",
    )
    run_parser.add_argument(
        "--call-delay",
        default=float(os.environ.get("GAUNTLET_CALL_DELAY", "1.0")),
        type=float,
        help="Delay in seconds between calls for free-tier rate limits (default: 1.0)",
    )
    run_parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume an existing run, skipping completed scenario traces",
    )
    run_parser.add_argument(
        "--run-id",
        type=str,
        default=None,
        help="Specific run ID to resume or output into",
    )
    run_parser.add_argument(
        "--filter",
        default=None,
        type=str,
        help="Regex pattern to filter scenarios by id (e.g. 'scen_0[78]|scen_09|scen_1[0-9]|scen_20')",
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

        if args.provider == "mock":
            agent = MockAgent(name="mock-agent")
        elif args.provider == "scripted":
            from gauntlet.agents.scripted import ScriptedAgent
            agent = ScriptedAgent(name="scripted-compromised")
        elif args.provider == "anthropic":
            llm_client = AnthropicClient(model=args.model)
            agent = BaselineAgent(llm_client=llm_client, prompt_condition=args.prompt_condition)
        elif args.provider == "ollama":
            base_url = (
                args.base_url
                if args.base_url != "https://generativelanguage.googleapis.com/v1beta/openai/"
                else "http://localhost:11434/v1"
            )
            model = args.model if args.model != "gemini-3.5-flash-lite" else "qwen2.5:7b"
            llm_client = OpenAICompatibleClient(
                base_url=base_url,
                model=model,
                api_key="ollama",
            )
            agent = BaselineAgent(llm_client=llm_client, prompt_condition=args.prompt_condition)
        else:
            llm_client = OpenAICompatibleClient(
                base_url=args.base_url,
                model=args.model,
                api_key_env_var=args.api_key_env,
            )
            agent = BaselineAgent(llm_client=llm_client, prompt_condition=args.prompt_condition)

        use_proxy = (args.guardrails == "proxy") or ("proxy" in args.prompt_condition)
        runner = Runner(
            scenarios_dir=scenarios_path,
            output_dir=output_path,
            repetitions=args.n,
            call_delay=args.call_delay,
            resume=args.resume,
            filter_pattern=args.filter,
            use_guardrails_proxy=use_proxy,
        )

        print(f"\n🚀 Running Gauntlet Evaluation Suite...")
        print(f"   Provider: {args.provider}")
        print(f"   Model: {args.model}")
        if args.provider == "openai_compatible":
            print(f"   Base URL: {args.base_url}")
            print(f"   Key Env: {args.api_key_env}")
        print(f"   Scenarios: {scenarios_path}")
        print(f"   Repetitions (N): {args.n}")
        print(f"   Call Delay: {args.call_delay}s\n")

        summary = asyncio.run(
            runner.run(agent=agent, provider=args.provider, model_name=args.model, run_id=args.run_id)
        )
        table_output = format_summary_table(summary)
        print("\n" + table_output + "\n")
        print(f"Results and raw traces saved to: {output_path / summary.run_id}\n")

    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
