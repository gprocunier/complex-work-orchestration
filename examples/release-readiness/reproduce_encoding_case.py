#!/usr/bin/env python3
"""Re-execute the observed encoding case against the actual current CLI."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    with tempfile.TemporaryDirectory(prefix="cwo-json-encoding-") as tmp:
        root = Path(tmp)
        (root / "scripts").mkdir()
        (root / "tests/fixtures").mkdir(parents=True)
        shutil.copy2(ROOT / "scripts/check_documentation.py", root / "scripts/check_documentation.py")
        (root / "README.md").write_text("[Missing](café.md)", encoding="utf-8")
        (root / "CONTRIBUTING.md").write_text("")
        (root / "tests/fixtures/site-legacy-routes.json").write_text("{}")
        env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "ascii", "PYTHONDONTWRITEBYTECODE": "1"}
        result = subprocess.run([sys.executable, str(root / "scripts/check_documentation.py"), "--json"], env=env, text=True, capture_output=True)
        report = json.loads(result.stdout)
        assert result.returncode == 1 and result.stderr == ""
        assert type(report["ok"]) is bool and report["ok"] is False
        assert report["errors"] == ["README.md: missing/outside target café.md"]
        print(json.dumps({"exit_code": result.returncode, "report": report}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
