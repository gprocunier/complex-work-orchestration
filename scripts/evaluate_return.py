#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from orchestration_lib import load_policy


def section_present(text: str, section: str) -> bool:
    pattern = rf"^\s*{re.escape(section)}\s*:"
    return re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE) is not None


def evaluate(text: str, bead: str | None = None) -> dict[str, object]:
    required = load_policy("acceptance-policy").get("contractor_return_required_sections", [])
    missing = [section for section in required if not section_present(text, str(section))]
    escalation_yes = re.search(r"^\s*Escalation needed\s*:\s*(yes|true|required)", text, flags=re.IGNORECASE | re.MULTILINE)
    verdict = "ready-for-architect-review" if not missing else "needs-clarification"
    return {
        "bead": bead,
        "verdict": verdict,
        "missing_sections": missing,
        "architect_review_required": True,
        "escalation_flagged": bool(escalation_yes),
        "note": "Do not convert contractor findings into implementation work until architect review accepts them.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a contractor return against the acceptance policy.")
    parser.add_argument("--file", required=True, help="Contractor return text file.")
    parser.add_argument("--bead", help="Assigned Beads ID.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    args = parser.parse_args()

    result = evaluate(Path(args.file).read_text(encoding="utf-8"), bead=args.bead)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    print(f"Verdict: {result['verdict']}")
    print(f"Architect review required: {result['architect_review_required']}")
    print(f"Escalation flagged: {result['escalation_flagged']}")
    missing = result["missing_sections"]
    if missing:
        print("Missing sections:")
        for section in missing:  # type: ignore[assignment]
            print(f"- {section}")
    else:
        print("Missing sections: none")
    print(str(result["note"]))


if __name__ == "__main__":
    main()
