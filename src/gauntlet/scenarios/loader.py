"""Scenario loader supporting YAML and JSON files."""

import hashlib
from pathlib import Path
from typing import List, Tuple
import yaml

from gauntlet.scenarios.schema import Scenario


def compute_file_hash(path: Path) -> str:
    """Compute sha256 checksum of a file."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def load_scenario(file_path: Path) -> Scenario:
    """Load a single scenario from a YAML or JSON file."""
    with open(file_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return Scenario.model_validate(data)


def load_all_scenarios(scenarios_dir: Path) -> List[Tuple[Scenario, str]]:
    """
    Load all scenario files from a directory.
    Returns list of tuples: (Scenario, file_sha256).
    """
    results: List[Tuple[Scenario, str]] = []
    files = sorted(list(scenarios_dir.glob("*.yaml")) + list(scenarios_dir.glob("*.yml")))
    for path in files:
        file_hash = compute_file_hash(path)
        scenario = load_scenario(path)
        results.append((scenario, file_hash))
    return results
