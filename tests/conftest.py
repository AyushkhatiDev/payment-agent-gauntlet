"""Pytest configuration and shared fixtures for Gauntlet."""

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from gauntlet.engine.state_engine import StateEngine
from gauntlet.mock_server.server import MockRazorpayMCPServer


@pytest.fixture
def engine() -> StateEngine:
    """Fresh state engine instance reset to baseline."""
    eng = StateEngine()
    eng.reset()
    return eng


@pytest.fixture
def mock_mcp_server(engine: StateEngine) -> MockRazorpayMCPServer:
    """Mock MCP server backed by fresh state engine."""
    return MockRazorpayMCPServer(state_engine=engine)


@pytest.fixture
def contract_fixtures() -> Dict[str, Any]:
    """Load recorded contract response fixtures."""
    fixture_path = Path("fixtures/contract_responses.json")
    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f)
