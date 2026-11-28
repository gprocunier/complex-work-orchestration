# Production evaluation and diagnostic inputs

The [evaluation evidence](evaluation-evidence.md) records the observed
single-worker and contained-pool qualifications, the architect prompt check,
the architect real-use trial, and a fixed six-case workshop handoff comparison
with plain Codex fanout.

Production `evaluate_return.py` accepts an audited contractor packet through
`--contractor-packet`. The common `require_production_contractor_packet` rule
checks the packet and the builder-recorded identity/hash in the trusted local
audit store. This retains the existing operator-owned audit-store assumption;
an actor allowed to rewrite that store can forge its provenance. It is not a
qualified hostile-host source or a full return/candidate binding producer.

| Selector or consumer | Production disposition | Nonproduction behavior |
| --- | --- | --- |
| `--contractor-packet` | Common content and production audit-link check | Cannot combine with advisory mode or local-result selector |
| `--local-dispatch-result` | Refused before scoring, acceptance audit and output | Explicit `--advisory --no-audit --waiver-reason REASON` preserves inspection only |
| No selector, with or without ordinary metadata flags | Same production refusal | Same explicit advisory mode |
| Packet plus ordinary metadata flags | Reject any differing value, including an added value absent from packet metadata | Not a bypass of the packet source |
| Normalizer `--contractor-packet --output` | Same common packet rule before writer; refusals preserve an existing output | Its raw normalizer remains a data converter, not production acceptance/provenance |
| Dispatch/browser packet consumers | Common packet rule by default | Existing unlinked waivers retain only their documented limited claims |

Local-result JSON has no reviewed production producer contract. A labelled
rehearsal packet, a stripped/rehashed packet, raw manual prompt, route artifact
or browser dry-run object cannot supply that missing authority. Raw CLI labels
are equally unqualified. Advisory output has an explicit nonproduction class,
an implementation hold and a non-clearable source reason. Existing reject,
quarantine, partial-only and open-risk recommendations are preserved; other
recommendations are held at open-risk. Advisory mode never appends acceptance
audit. No caller class or self-hash changes this result.

Current model policy is checked before native packet construction or receipt
reservation. An exact historical-nonoperative model refuses new creation with
no replacement. Historical inactive-policy fixture construction and historical
packet inspection remain available; dispatchable validation still refuses.

Compatibility: local-result and raw-metadata evaluation commands must explicitly
choose advisory inspection or obtain a genuine production contractor packet.
No preexisting output is silently promoted. Existing packet consumers and scoped
unlinked waivers are unchanged. This is a scoped compatibility change, not full
policy validation completion, producer qualification, risk reduction or route restoration.

Historical Spark supervision/planning fixtures explicitly enter inactive-v3 policy;
their real validators are retained. Inactive historical packet release keeps the
old Spark route shape. Current dispatchable historical-nonoperative packets still
refuse through nonoperative_model_refusal; no replacement or new model authority.

Advisory projection preserves actual screening_eligible and score diagnostics but
sets accepted_for_use=false, evidence_use_hold=true, both adjudication-required
fields true, and execution_permitted=false. Accept/partial/clarify verdicts become
escalate; accepting/clarification dispositions become architect-adjudication.
Existing rejection/quarantine and restricted synthesis-use states are preserved.
A prior no-hold classification becomes nonproduction-advisory; its reason is not
clearable by cooperative adjudication. This does not qualify a producer.

## Evidence and delivery

The human evaluator report and `evaluate_return.py --report-json` show evidence
disposition and delivery readiness. Return prose can support evidence acceptance.
Readiness stays `unknown` when the evaluator has no issued observation against an
independent requirement baseline and candidate. Use `--json` for the existing
hash-bound evaluator payload in file-based peer-review and synthesis handoffs.

The [qualified completion report](run-readiness.md) uses its original observation
to report each criterion as `passed`, `failed`, `unrun`, or `not-applicable`. A
not-applicable criterion carries its reason from the requirement baseline. A
useful return can remain accepted as evidence while failed or unrun required
checks block completion. The completion consumer still rechecks the exact
observation against the final review and its existing acceptance gates.

## Retired three-arm study

The three-arm study for the retired Candidate E prompt never ran and produced
no comparison results. The source repository preserves its frozen design and
18 synthetic rehearsal records at `evaluation/history/three-arm/`, outside the
installed projection. The frozen `operator_codex_rule` specifies the design's
model, service tier and effort ceiling. Its `example-codex-model` label is inert
and records no operator allocation or observed model run. In the historical
fixtures, `excluded-operator-rule` denotes a study-policy mismatch.

The archive preserves the original task and hidden-material digests, the
preregistration digest and the blank analysis template. All 18 synthetic
rehearsal records retain their original lock binding. The
`r09-overhead-readme-full` record deliberately carries a different protocol
digest to exercise `excluded-protocol-mismatch` in offline scoring tests. Both
archived build-freeze slots are unbound.

From a current source checkout, verify the frozen file roster, file digests
and both unbound build slots.

```sh
python3 -B scripts/comparative_evaluation.py --root evaluation/history/three-arm validate
```

The CLI refuses `run` before reading the archive. See the [study archive](../evaluation/history/README.md)
for the full offline verifier and tests at the pinned `v1.33.0` release.
Historical locks bind the original `evaluation/three-arm/` paths and exact
source bytes.
