Native Beads fields:
- skills:
- acceptance:
- design:
- notes:

Purpose:

Scope:

Assigned expert:
{{expert_name}}

Executor:
{{executor_key}}

Dispatch mode:
{{dispatch_mode}}

Input manifest:
- assignment summary
- Distinguished Engineer profile and SHA-256
- allowed snippets or artifacts
- policy excerpts

Allowed artifacts:
{{allowed_artifacts}}

Forbidden artifacts:
Secrets, credentials, production access, private keys, personal data, parent
epic closure authority, release/tag authority, and anything outside the selected
share boundary.

Allowed changes:
Output-only by default: Beads comment, evidence, diff, patch proposal, or branch
reference. No direct checkout mutation unless the Bead and operator flow
explicitly authorize direct workspace mutation.

Expected output:
Final contractor return only. No preamble, internal action narration, hidden
chain-of-thought, or step-by-step planning. Use the exact section labels below.

```text
Status:
Contractor job description:
Summary:
Files changed:
Commands run:
Boundary violation:
Patch authorization:
Secret or personal-data spill:
Scope compliance:
Validation result:
Provider policy limitations:
Evidence:
Evidence provenance:
Attestation or reproducibility note:
Share-boundary conformance:
Peer-review disposition:
Alternatives considered:
Confidence:
Risks or gaps:
Recommended next bead:
Escalation needed:
```

Evidence requirements:
State whether each claim is based on code, documentation, command output, or
inference. Unsupported claims must be marked as assumptions.
Do not use generic reassurance such as "looks good", "best practice", or
"no issues" as evidence. If the packet does not contain enough evidence for a
specific finding, say `Status: no-actionable-findings` and name the missing
evidence instead of filling the return with broad advice.

Confidence scale:
low, medium, medium-high, high. Explain confidence when below high.

Escalation triggers:
Boundary violation, suspected secret exposure, missing context, scope change,
architecture change, destructive command, production impact, release impact, or
conflicting evidence. Also escalate if the provider policy, safety posture, or
model limitations prevent direct analysis of the assigned question.

Handoff format:
Beads comment or approved patch proposal using the required contractor return
format. Patch-branch is a proposal lane unless direct mutation is explicitly
authorized.
Before meaningful closure, the coordinator must add a final closure-memory
comment with who was involved, what changed, why closed, how validated, when
closed, where executed, key decisions, evidence, residual risk, and follow-up.
Keep the close reason terse.

Contractor job description:
{{job_description_label}}

Contract labels:
contractor-only,no-codex-exec,{{job_description_label}}

Share boundary:
{{share_boundary}}

Evaluation rule:
This return must pass evaluator scoring and architect adjudication before any
finding becomes implementation work. Suspicious, unsupported, boundary-breaking,
or provider-conflicted output may be quarantined and routed to peer review.
If route policy requires peer review or provider conflict is present, the
contractor cannot declare peer review unnecessary.

Profile rule:
Use the Distinguished Engineer profile as the operating lens. A packet without
the profile is degraded and must be called out in the return.

Provider limitation rule:
If provider policy, safety behavior, or missing context materially affects your
answer, disclose that limitation. Do not request broader context than the share
boundary permits.

Synthesis-use rule:
Some executors are useful as second-opinion idea sources but are not primary
synthesis inputs by default. Gemini/Agy review returns are evaluated as
salvage-only unless the architect explicitly upgrades a specific evaluated
finding after evidence review. Salvage-only means the return may inform risk
notes or follow-up questions, but it does not satisfy consensus or
minimum-primary-input requirements.

Codex handling rule:
Codex agents may coordinate, brief, evaluate, and review this Bead, but must not
execute or close it as contractor work.
