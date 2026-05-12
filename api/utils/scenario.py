"""Dynamic loader for the optional scenario-profiles plugin."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any


def load_scenario_runner(base_dir: Path) -> Any | None:
    """Load `plugins/scenario_profiles.ScenarioRunner` from disk.

    Returns `None` instead of raising so routes can fall back gracefully when
    the scenario plugin is unavailable.
    """
    try:
        spec = importlib.util.spec_from_file_location(
            "scenario_profiles",
            base_dir / "plugins" / "scenario_profiles.py",
        )
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.ScenarioRunner()
    except Exception:
        return None
