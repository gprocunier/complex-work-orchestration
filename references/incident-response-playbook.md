# Contractor Incident Response Playbook

Use this playbook when an outside contractor, local worker, or peer reviewer
returns output that may be malicious, conflicted, fabricated, boundary-breaking,
or operationally unsafe.

## Trigger Conditions

Treat the return as an incident when any of these occur:

- `scripts/evaluate_return.py` returns `Verdict: quarantine`.
- The sabotage score reaches the quarantine threshold.
- The contractor asks for broader disclosure than the approved share boundary.
- The contractor claims repo mutation without patch-branch authorization.
- The contractor advises suppressing tests, logs, audit records, or review.
- Evidence is fabricated, unverifiable, or conflicts with validation results.
- The contractor exposes or requests secrets, credentials, production access, or
  personal data.

## Immediate Actions

1. Do not create implementation dependencies from the contractor output.
2. Preserve the packet, return text, normalized return bundle, and audit log.
3. Run the return through both normal evaluation and normalization:

   ```bash
   python3 scripts/normalize_contractor_return.py \
     --bead <id> \
     --dispatch-id <dispatch-id> \
     --packet-sha256 <packet-sha256> \
     --file contractor-return.md \
     --output contractor-return-bundle.json

   python3 scripts/evaluate_return.py \
     --bead <id> \
     --dispatch-id <dispatch-id> \
     --share-boundary <boundary> \
     --file contractor-return.md \
     --audit
   ```

4. Verify audit integrity:

   ```bash
   python3 scripts/verify_audit_log.py --json
   ```

5. Add a Beads comment with the verdict, sabotage score, signals, boundary
   status, and recommended containment.

## Containment

Use these Beads labels on any incident follow-up:

```text
quarantine
architect-adjudication
no-implementation
sabotage-review
```

Keep contractor-only and local-worker-only work excluded from normal Codex ready
work:

```bash
bd ready --exclude-label contractor-only --exclude-label local-worker-only --exclude-label no-codex-exec --json
```

If peer review is needed, create a separate peer-review Bead rather than
allowing the suspect return to become an implementation blocker.

## Architect Decision

The architect decides one of these outcomes:

- reject the return and close the contractor Bead with evidence
- ask for clarification without expanding the share boundary
- re-post a narrowed contract to another provider or human specialist
- convert only verified, bounded findings into normal Codex-executable Beads
- escalate to a human operator if secrets, production access, legal, or policy
  concerns are involved

Never let a quarantined return directly authorize implementation, release, tag,
deployment, secret rotation, or dependency changes.

## Provider Conflict Notes

Provider conflict is not proof of sabotage. It is a routing risk that requires
peer review and architect adjudication. When a conflict domain is present, keep
the evidence trail explicit:

- selected provider and executor
- provider conflict domains from route output
- share boundary and disclosure stage
- packet hash
- return bundle hash
- evaluator verdict
- architect disposition
