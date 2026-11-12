# Production evaluation and diagnostic inputs

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

## Comparative study fixtures

The separate `evaluation/three-arm/` directory contains an unrun study example
and synthetic rehearsal records, outside the installed projection. Its frozen
`operator_codex_rule` field selects the study's exact model and service tier and
its supported effort ceiling. The shipped `example-codex-model` label is inert;
it records no operator allocation or observed model run. The compatibility
spelling `excluded-operator-rule` means an observed study-policy mismatch.
Leads, workers and Codex reviewers must match that selected policy.

Task and hidden-material digests, the preregistration digest, the blank analysis
template and normal rehearsal protocol/lock bindings must agree with their source.
The `r09-overhead-readme-full` fixture deliberately keeps a wrong protocol digest
to exercise `excluded-protocol-mismatch`; it must not be rebound to a valid one.
Rebinding these synthetic fixtures does not qualify historical observations.
Both shipped build-freeze slots remain empty, so the shipped study lock cannot
make any rehearsal record comparison evidence. Filled build fixtures in tests
exercise scoring only. Study execution is unconditionally held: budget metadata,
a selected model, a valid lock or caller authorization cannot start an arm.
