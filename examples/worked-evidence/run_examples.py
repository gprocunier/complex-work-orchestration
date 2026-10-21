#!/usr/bin/env python3
"""Deterministic illustrative exercises; no production access or model calls."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile


def retry_observation(method, retry_all):
    attempts = 0
    effects = 0
    for status in (503, 200):
        attempts += 1
        effects += method == "POST"
        if status == 200 or (method != "GET" and not retry_all):
            break
    return {"attempts": attempts, "effects": effects}


def review_example():
    # These are deliberately conflicting authored proposals, not reviewer events.
    unsafe = retry_observation("POST", retry_all=True)
    safe_write = retry_observation("POST", retry_all=False)
    safe_read = retry_observation("GET", retry_all=False)
    assert unsafe == {"attempts": 2, "effects": 2}
    assert safe_write == {"attempts": 1, "effects": 1}
    assert safe_read == {"attempts": 2, "effects": 0}
    return {"evidence_mode": "authored conflict fixture, not real reviewer returns",
            "proposal_a": "retry all transient failures", "proposal_b": "do not retry non-idempotent writes",
            "rejected_post": unsafe, "accepted_post": safe_write, "accepted_get": safe_read,
            "decision": "permit bounded GET retries; surface ambiguous POST failures without replay"}


def lab_example(root):
    active = root / "active.json"
    backup = {"host": "lab.invalid", "port": 8080}
    active.write_text(json.dumps(backup))
    candidate = {"host": "lab.invalid", "port": 8081}
    # Stage is a separate local file, not a production service restart.
    (root / "staged.json").write_text(json.dumps(candidate))
    active.write_text(json.dumps(candidate))
    simulated_health = False
    if not simulated_health:
        active.write_text(json.dumps(backup))
    restored = json.loads(active.read_text()) == backup
    assert restored
    return {"evidence_mode": "local file lab; health failure intentionally simulated",
            "staged_port": candidate["port"], "health": simulated_health,
            "restored_port": json.loads(active.read_text())["port"], "rollback_verified": restored,
            "network_requests": 0, "production_mutations": 0}


def research_example(root):
    notes = [{"id": "N1", "claim": "Consumers need a list of messages per configuration", "status": "requirement"},
             {"id": "N2", "claim": "JSON preserves a nested list on round trip", "status": "checked"},
             {"id": "N3", "claim": "JSON is faster for all clients", "status": "unsupported"}]
    payload = {"errors": ["invalid host", "invalid port"]}
    assert json.loads(json.dumps(payload)) == payload
    sources = {"output shape": ["N1"], "representation": ["N2"], "excluded claim": ["N3"]}
    memo = ("# Decision: JSON error output\n\n"
            "Choose JSON because the required list-of-messages shape survives serialization (N1, N2).\n"
            "Do not claim a universal speed advantage: N3 has no measurement.\n"
            "Human decision: confirm that downstream clients accept JSON before changing the interface.\n"
            "Acceptance: round-trip the required shape and trace every material sentence to a note.\n")
    (root / "decision.md").write_text(memo)
    (root / "claim-sources.json").write_text(json.dumps(sources, indent=2) + "\n")
    return {"evidence_mode": "supplied synthetic source notes, not external research",
            "notes": notes, "claim_sources": sources, "memo": memo,
            "rejected_unsupported_claims": ["N3"]}


def run():
    with tempfile.TemporaryDirectory(prefix="cwo-worked-evidence-") as tmp:
        root = Path(tmp)
        return {"review": review_example(), "lab": lab_example(root), "research": research_example(root)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Run all assertions without retaining generated files")
    parser.parse_args()
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()
