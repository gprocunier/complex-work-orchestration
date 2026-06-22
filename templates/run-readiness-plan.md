Native Beads fields:
- skills: architecture, validation, beads, handoff
- acceptance: Every workstream has an owner and exit condition; every rubric criterion maps to evidence; typed projections are non-authoritative; contractor findings are adjudicated.
- design: Beads remain canonical. Run sheets, wrap-up/status reports, and next-version rails are regenerated projections. External and local returns are evidence until evaluated and adjudicated.
- notes: Fill this before worker handoff for broad or contractor-reviewed work.

Purpose:
Prove the run is ready for worker execution.

Beads scope:
- Epic:
- Implementation Bead:
- Dolt remote status:

Artifact authority:
- Canonical source:
- Projection artifacts:
  - run-sheet:
  - wrap-up-status:
  - next-version:
- External or local returns:
- Final decision owner:

Workstreams:
| Workstream | Owner | Exit condition | Validation refs | Handoff evidence |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |

Rubric:
- Version:
- Owner:
- Schema reference:
- Immutable for this run:
- Evaluator records version:
- Criterion IDs:

Criterion-to-evidence matrix:
| Criterion | Evidence type | Evidence | Owner |
| --- | --- | --- | --- |
|  | artifact, validator, or review-gate |  |  |

Provider provenance:
| Provider | Provenance class | Disposition |
| --- | --- | --- |
|  | internal, external-contractor, local-worker, or unknown | primary, salvage-only, rejected, quarantined, or not-used |

Quarantine rules:
- Trigger:
- Disposition:
- Release condition:

Boundary negative tests:
- Raw comments:
- Secrets:
- Full Bead JSON:
- Unauthorized mutation claims:
- Unsupported command-execution claims:

Next-version rail:
| Item | Reason type | Follow-up Bead |
| --- | --- | --- |
|  | out-of-scope, needs-credential, needs-research, hardening, later-version, or blocked |  |

Patrol stopping rule:
Research-only until `ownership`, `locking`, `history`, `failure_containment`, and `provider_neutral_execution` are accepted.

Adjudication record:
- Accepted findings:
- Rejected findings:
- Quarantined findings:
- Decision owner:

Handoff evidence requirements:
- Changed files:
- Validation commands:
- Accepted and rejected findings:
- Residual risks:
- Follow-up Beads:
