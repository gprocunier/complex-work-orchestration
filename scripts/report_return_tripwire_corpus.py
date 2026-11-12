#!/usr/bin/env python3
"""Counts-only return-tripwire qualification report using the original return evaluator."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

from cwo_core.returns import make_acceptance_decision

ROOT = Path(__file__).resolve().parents[1]
CORPUS = "tests/fixtures/return_tripwires/corpus.json"
SAMPLE = "examples/sample-contractor-return.md"
LABELS = ("hostile", "benign", "ambiguous")
METRICS = ("accepted_for_use", "held", "tripwire_hit", "held_without_tripwire",
           "non_tripwire_hold_reason")


def placements(sample: str, clause: str) -> tuple[tuple[str, str], ...]:
    if "Evidence:\n" not in sample:
        raise ValueError("sample must contain the actual Evidence section")
    return (("appended", sample + "\n" + clause + "\n"),
            ("evidence", sample.replace("Evidence:\n", "Evidence:\n- " +
                                       clause.replace("\n", "\n  ") + "\n", 1)))


def summarize(decisions: list[dict]) -> dict:
    total = len(decisions)
    counts = Counter({metric: 0 for metric in METRICS})
    for decision in decisions:
        held = bool(decision["evidence_use_hold"])
        hit = bool(decision["tripwire_hits"])
        counts.update({"accepted_for_use": bool(decision["accepted_for_use"]),
                       "held": held, "tripwire_hit": hit,
                       "held_without_tripwire": held and not hit,
                       "non_tripwire_hold_reason": any(
                           not reason.startswith("return-tripwire:")
                           for reason in decision["hold_reasons"])})
    return {"evaluations": total, "counts": dict(counts),
            "rates": {key: value / total if total else None for key, value in counts.items()},
            "verdicts": outcome_rates(decisions, "verdict"),
            "dispositions": outcome_rates(decisions, "recommended_disposition")}


def outcome_rates(decisions: list[dict], field: str) -> dict:
    counts = Counter(decision[field] for decision in decisions)
    return {key: {"count": value, "rate": value / len(decisions)}
            for key, value in sorted(counts.items())}


def grouped(decisions: list[tuple[str, dict]]) -> dict:
    # The declared corpus has only binary hostile labels. Do not infer ambiguity.
    return {label: summarize([decision for kind, decision in decisions if kind == label])
            for label in LABELS}


def input_hashes(root: Path) -> dict:
    paths = [CORPUS, SAMPLE, "scripts/report_return_tripwire_corpus.py"]
    paths += sorted(str(path.relative_to(root)) for path in (root / "scripts/cwo_core").glob("*.py"))
    paths += sorted(str(path.relative_to(root)) for path in (root / "policy").glob("*.yaml"))
    paths += sorted(str(path.relative_to(root)) for path in (root / "schemas").glob("*.json"))
    return {path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in paths}


def build_report() -> dict:
    corpus = json.loads((ROOT / CORPUS).read_bytes())
    sample = (ROOT / SAMPLE).read_text(encoding="utf-8")
    buckets: dict[tuple[str, str], list[tuple[str, dict]]] = {}
    totals: dict[str, list[tuple[str, dict]]] = {"appended": [], "evidence": []}
    for case in corpus["cases"]:
        if type(case["hostile"]) is not bool:
            raise ValueError("declared hostile label must be boolean")
        label = "hostile" if case["hostile"] else "benign"
        for placement, text in placements(sample, case["text"]):
            row = (label, make_acceptance_decision(text))
            buckets.setdefault((case["category"], placement), []).append(row)
            totals[placement].append(row)
    return {"schema": "w05-corpus-category-report-v1", "case_count": len(corpus["cases"]),
            "ambiguous_status": "unknown/not separately labelled in declared corpus",
            "input_sha256": input_hashes(ROOT),
            "totals": {placement: grouped(rows) for placement, rows in totals.items()},
            "categories": [{"category": category, "placement": placement, "labels": grouped(rows)}
                           for (category, placement), rows in sorted(buckets.items())]}


def main() -> int:
    report = build_report()
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
    return int(any(row["hostile"]["counts"]["accepted_for_use"] for row in report["totals"].values()))


if __name__ == "__main__":
    raise SystemExit(main())
