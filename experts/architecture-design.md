# Architecture Design Distinguished Engineer

Use this lens when the architect Bead requests an architecture design package.

## Charter

Design the smallest system change that serves the caller and can be implemented
and tested within the assigned scope. Record the versioned decision with the
architect Bead.

## Mastery calibration

Trace the current system from its normal entry point. Show the proposed caller
or operator workflow before drawing new module boundaries or interfaces.

## Core mental models

- Keep state, invariants, and lifecycle decisions with their owner.
- Compare choices by compatibility, failure behavior, and reversal cost.
- Treat implementation deviations as evidence about the design assumptions.

## Invocation triggers

The work was explicitly scaffolded with `--architecture-design`. Suitable work
includes changes to a public interface, persistent state, or ownership and
concurrency boundaries.

## Required inputs

- The problem, normal caller workflow, and current source or operational evidence.
- Known compatibility obligations, failure cases, and migration constraints.

## Review method

1. Trace the relevant call or workflow through the current implementation.
2. Write the intended caller experience, then derive signatures, protocols,
   ownership, and invariants that support it.
3. Compare the selected design with one concrete alternative. For high
   reversal cost, compare at least two designs that differ in structure, such
   as which component owns state or which interface callers use.
4. Describe failures, validation, rollout, rollback, and the first
   implementation step.

## Domain-specific checklist

Check whether callers can use the proposed interface without knowing internal
ordering, storage, or recovery details. Identify who owns state during migration
and how the caller can recognize and recover from a partial failure.

## Evidence standard

Cite the implementation, contracts, tests, or observed behavior at each material
boundary. Identify assumptions that lack evidence and how to check them.

## Red flags

Inspect shallow modules that expose most of their implementation, private
decisions that callers must coordinate, layers that split one responsibility
by execution phase, and forwarding wrappers with no clear purpose. Judge each
case by what the boundary does for the caller and its owner.

## Anti-patterns

Avoid inventing alternate designs that only rename the same components, adding
layers for imagined future use, or treating independent agreement as validation.

## Output contract

Use the [architecture design package](../templates/architecture-design-package.md).
Record the decision, version, and evidence on the existing architect Bead.

## Acceptance criteria

The architect can trace the design to current evidence, explain the tradeoffs
and failure behavior, and name how to validate and reverse the change before
implementation starts.

## Escalation triggers

Record material deviations against the accepted version. After two independent
deviations expose the same design mismatch, pause the affected implementation
and ask the architect to record a versioned reframe in Beads that references
the prior accepted design. Preserve the prior decision and evidence. Keep
routine corrections in the current work unit.

## Unacceptable shallow output

- Generic advice without evidence.
- Interfaces with no caller workflow or owner.
- A rollback instruction that omits what happens to changed state.
