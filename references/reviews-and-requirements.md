# Reviews, requirements and recorded work

This reference holds the optional detail behind the [README](../README.md):
how specialist findings are used, how requirements survive changes, and which
examples are observed, tested or only proposed.

## Put specialist findings to work

- **Use local models as project reviewers.** CWO prepares a focused request for
  an approved private endpoint, including OpenShift AI vLLM, records it as a
  local envelope and applies the selected route's response checks before
  evaluation. Sending it from CWO (`dispatch_work.py --execute-local`) is
  disabled in this version; writing the envelope and manual export still work.
  [Use a local reviewer](https://gprocunier.github.io/complex-work-orchestration/local-workers.html).
- **Investigate disagreement rather than averaging it away.** Preserve separate
  findings and their evidence. When structured comparison is needed, invoke CWO's
  comparison API with explicit claims, then check the disputed behavior.
  [Inspect the comparison test](https://gprocunier.github.io/complex-work-orchestration/zero-trust-consensus.html#tested-example).
- **Continue from the accepted decision.** Retain requirements, actual checks,
  unresolved risks and the permitted next task alongside the work.
  [Continue in a fresh session](https://gprocunier.github.io/complex-work-orchestration/continue-project.html).

Local review does not make a cloud session offline. Different models may contribute
useful findings, but more models do not guarantee better answers. Structured
cross-return comparison is explicitly invoked; it is not an automatic gate on
every call. [How CWO fits the ecosystem](https://gprocunier.github.io/complex-work-orchestration/explanation.html#ecosystem).

## Preserve the project requirements when work changes

- **Keep evaluations comparable.** Save the test cases, scoring and selection rule
  before comparing approaches. Repair a broken runner without quietly making the
  test easier. CWO's protocol validator checks recorded fields when invoked; it
  cannot detect every unrecorded change in intent.
- **Account for failed attempts.** Preserve the failure, inspect files and cleanup,
  and account for allowance already used. Continue unrelated work only when it is
  still permitted and its own checks pass; do not silently restart an attempt
  that has already ended and used its allowance.

[Use CWO on your project](https://gprocunier.github.io/complex-work-orchestration/workflows.html#operator).

## Check examples against their evidence

Repository component tests use authored inputs.
[Local-response checks](https://gprocunier.github.io/complex-work-orchestration/use-cases.html#local-review-checks)
cover usable and rejected responses.
[Structured claim comparison](https://gprocunier.github.io/complex-work-orchestration/use-cases.html#claim-comparison)
retains conflicting claims without deciding which is true. These are
not live provider conversations or endpoint qualification.

The [configuration-validator tutorial](../examples/first-project/VALIDATION.md)
illustrates preserving validation rules when adding a command-line interface.
The [documentation-command example](../examples/release-readiness/RECORD.md)
illustrates reproducing an encoding failure and checking JSON escaping with a
real subprocess. These examples do not establish native concurrency or
comparative productivity. Use the current pending-acceptance disposition
until delivered work has verified acceptance evidence.

**Designs to adapt, not completed demonstrations:**
[Converter comparison](https://gprocunier.github.io/complex-work-orchestration/use-cases.html#migration-evaluation)
and [duplicate-job prevention](https://gprocunier.github.io/complex-work-orchestration/use-cases.html#retry-decision)
are designs to adapt. Preserve their requirements and define integrated checks
before treating an implementation as demonstrated.
