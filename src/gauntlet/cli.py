"""CLI entrypoint for Gauntlet."""

import argparse
import asyncio
import sys

from gauntlet.mock_server.server import MockRazorpayMCPServer


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Gauntlet: Adversarial Safety Test Harness for Payment Agents"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # mock-server command
    server_parser = subparsers.add_parser("serve-mcp", help="Run Mock Razorpay MCP server over stdio")
    server_parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio"],
        help="MCP transport protocol (default: stdio)",
    )

    args = parser.parse_args()

    if args.command == "serve-mcp":
        server = MockRazorpayMCPServer()
        asyncio.run(server.run_stdio())
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
