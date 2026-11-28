# Architecture design

Use the profile when an architecture change needs a durable design before
implementation. Examples include public interfaces, migrations and changes to
ownership or concurrency. Ordinary scaffold runs use the usual architect
framing.

```bash
python3 scripts/scaffold_workgraph.py --title "Version a public interface" \
  --architecture-design --dry-run
```

The option works with direct Beads creation and `--dry-run --format beads-graph`.
It puts the [design lens](../experts/architecture-design.md) and
[package template](../templates/architecture-design-package.md) on the existing
architect Bead. Record the accepted package version and evidence on that Bead
before closing it. Its existing dependency holds implementation until the
architect work is complete.

## Work from the caller contract

Trace how an actual caller reaches the affected code or workflow today. Capture
the source, observed behavior, and assumptions. Write the proposed caller
experience before choosing interfaces or modules. Then record the relevant
types, signatures, state ownership, invariants, validation and failure behavior.
For non-code work, describe the reader, consumer or operator workflow.

Compare the selected design with one concrete alternative. When reversal cost is
high, compare at least two implementable designs with different boundaries or
ownership against the same constraints. Include compatibility, rollout and
rollback for each expensive decision. Use the existing synthesis option when
multi-model exploration is requested. The architect adjudicates the evidence.

## Reframe a design

Record material implementation deviations on the current work Bead with the
accepted design version, the broken assumption, and supporting evidence. Keep
routine corrections in the current work unit under the existing
[closure rules](run-readiness.md#projection-rules).

When two independent deviations show the same broken assumption, pause the
affected implementation. Count distinct observations or implementation
attempts once each. Create a versioned architect reframe Bead that links both
observations and the prior accepted package. Use the existing Beads dependency
to hold the affected work until the architect accepts the replacement. Mark the
prior design superseded for the affected scope and retain its accepted version,
decision, and evidence.
