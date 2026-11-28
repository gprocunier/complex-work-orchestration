# Architecture design package

Architect Bead, version, and decision record

## Problem and existing system

State the problem and constraints. Trace the normal entry point through the
affected components, using source or observed behavior as evidence.

## Caller workflow

Show the proposed API usage or consumer workflow, including the outcome the
caller sees when a material step fails.

## Boundaries and invariants

Map changed modules and interfaces. Sketch applicable types, signatures and
protocols. Name the state owner, lifecycle, and invariants.

## Decision and alternatives

Record the selected design, accepted tradeoffs and relevant synthesis evidence.
Compare one concrete alternative. For high reversal cost, compare at least two
structurally different designs against the same constraints.

## Validation, rollout, and rollback

Map checks to the changed behavior and failure cases. Describe compatibility,
migration order, rollback triggers, state recovery and residual risks.

## First implementation step

Name the first Bead or bounded change and the evidence that will confirm it.

## Material deviations

Record the accepted design version, affected assumption, observation and
evidence for each independent deviation. On the second independent deviation
of the same shape, pause affected implementation and link the versioned
reframe Bead to this decision.
