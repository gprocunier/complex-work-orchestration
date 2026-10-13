"""Explicit inactive-v3 fixtures for historical Spark/v2 compatibility tests.

Only policy input is replaced. Real route, receipt, packet, release and
supervision validators remain in place. Never apply this context to a test
claiming current Luna-first dispatch authority.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from pathlib import Path
import runpy
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import policy  # noqa: E402


@contextmanager
def historical_v2_policy():
    """Read historical records under an explicitly nonactivated v3 policy."""
    original = policy._load_policy_cached
    native = copy.deepcopy(original("native-worker-execution.yaml"))
    selected = native["task_selected_routing"]
    selected["status"] = "inactive-prospective"
    selected["activation"].update(active=False, dispatch_authority=False)

    def load(filename):
        if filename == "native-worker-execution.yaml":
            return copy.deepcopy(native)
        return original(filename)

    with patch.object(policy, "_load_policy_cached", side_effect=load):
        yield native


def historical_cli_args(script: str | Path, *args: str) -> list[str]:
    """Run the real CLI in a subprocess with only the historical policy input."""
    return [sys.executable, str(Path(__file__).resolve()), str(script), *args]


if __name__ == "__main__":
    script = Path(sys.argv[1]).resolve()
    # This helper cannot launch arbitrary commands: historical fixtures only
    # cover repository scripts, and nothing changes the installed/live policy.
    if script.parent != ROOT / "scripts" or script.suffix != ".py":
        raise SystemExit("historical CLI fixture requires a repository Python script")
    sys.argv = sys.argv[1:]
    with historical_v2_policy():
        runpy.run_path(str(script), run_name="__main__")
