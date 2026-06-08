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
No direct repo changes unless the Bead explicitly authorizes `patch-branch`.

Expected output:
Findings, evidence, confidence, risks or gaps, validation result, and
recommended next Beads.

Evidence requirements:
State whether each claim is based on code, documentation, command output, or
inference. Unsupported claims must be marked as assumptions.

Confidence scale:
low, medium, medium-high, high. Explain confidence when below high.

Escalation triggers:
Boundary violation, suspected secret exposure, missing context, scope change,
architecture change, destructive command, production impact, release impact, or
conflicting evidence.

Handoff format:
Beads comment or approved patch branch using the required contractor return
format.

Contractor job description:
{{job_description_label}}

Contract labels:
contractor-only,no-codex-exec,{{job_description_label}}

Share boundary:
{{share_boundary}}

Evaluation rule:
This return must pass evaluator scoring and architect adjudication before any
finding becomes implementation work.

Profile rule:
Use the Distinguished Engineer profile as the operating lens. A packet without
the profile is degraded and must be called out in the return.

Codex handling rule:
Codex agents may coordinate, brief, evaluate, and review this Bead, but must not
execute or close it as contractor work.
