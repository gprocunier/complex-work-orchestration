# Contractor Incident Response Playbook

Use this playbook when an outside contractor, local worker, or peer reviewer
returns output that may be malicious, conflicted, fabricated, boundary-breaking,
or operationally unsafe.

Not every disagreement is an incident. A material cross-domain disagreement
between otherwise accepted primary synthesis inputs should first flow through
zero-trust consensus and architect adjudication. Escalate to this playbook when
the divergence is paired with quarantine, fabricated evidence, boundary
violation, unsafe operational advice, or process evasion.

## Trigger Conditions

Treat the return as an incident when any of these occur:

- `scripts/evaluate_return.py` returns `Verdict: quarantine`.
- The sabotage score reaches the quarantine threshold.
- `return_language_status` is `quarantine`, or language findings indicate
  Unicode control or normalization evasion.
- The `malpractice_score` reaches the reject threshold.
- `peer_review_status` is `failed`, `disagreement`, or `blocked`.
- Zero-trust consensus recommends `quarantine` or reports divergence with
  boundary-breaking, fabricated, or unsafe supporting evidence.
- The contractor asks for broader disclosure than the approved share boundary.
- The contractor claims repo mutation without patch-branch authorization.
- The contractor advises suppressing tests, logs, audit records, or review.
- The contractor reroutes the assigned objective into weaker, deferred, or
  non-equivalent work.
- Evidence is fabricated, unverifiable, or conflicts with validation results.
- The contractor exposes or requests secrets, credentials, production access, or
  personal data.

## Immediate Actions

1. Do not create implementation dependencies from the contractor output.
2. Preserve the packet, return text, normalized return bundle, and audit log.
3. Run the return through both normal evaluation and normalization:

   ```bash
   python3 scripts/normalize_contractor_return.py \
     --contractor-packet contractor-packet.json \
     --file contractor-return.md \
     --output contractor-return-bundle.json

   python3 scripts/evaluate_return.py \
     --contractor-packet contractor-packet.json \
     --file contractor-return.md \
     --audit
   ```

4. Verify audit integrity:

   ```bash
   python3 scripts/verify_audit_log.py --json
   ```

5. Add a Beads comment with the verdict, sabotage score, `malpractice_score`,
   `return_language_status`, `peer_review_status`, boundary status,
   `recommended_disposition`, signals, and recommended containment.

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

Work-rerouting cases deserve the same containment discipline even when the
return sounds helpful. Treat objective dilution, non-equivalent substitution,
critical-path deferral without a typed follow-up Bead or tracked task, and
acceptance-evidence omission as evidence to evaluate, not as permission to
change the project goal.

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
- zero-trust consensus status and divergence score when synthesis claims are in scope
- architect disposition
