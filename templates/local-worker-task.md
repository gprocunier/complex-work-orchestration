Native Beads fields:
- skills:
- acceptance:
- design:
- notes:

Purpose:
Run a bounded local-worker task that is reversible, low-risk, and easy to
validate.

Scope:

Inputs:

Forbidden inputs:
Secrets, production access, private credentials, full private repo dumps, and
anything outside the local-worker envelope.

Allowed output:
Summary, classification, triage, low-risk draft, or bounded suggestion.

Validation required:
The main thread or evaluator must verify all output before implementation.

Evaluation rule:
Local-worker output requires evaluator scoring and architect adjudication before
it becomes project direction.

Handoff format:
Structured return using the same contractor return sections.
Before meaningful closure, add a final closure-memory comment with who was
involved, what changed, why closed, how validated, when closed, where executed,
evaluator state, evidence, residual risk, and follow-up.
