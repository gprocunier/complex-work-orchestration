# Security

The authoritative security description for CWO is the [threat model](references/security-threat-model.md).
It explains the assets, trust boundaries, assumptions, controls, and residual
risks behind the claims made by this repository.

## Reporting a vulnerability

Please do not put credentials, private keys, personal data, or an exploitable
proof of concept in a public issue, pull request, or repository file. For a
suspected vulnerability, use the repository's normal local project-maintainer
workflow: prepare a minimal private report for the project maintainer through
an already-established private channel, if one exists. Include the affected
version or commit, the scoped component, reproduction steps that do not expose
secrets, impact, and any suggested mitigation.

This repository does not assert that a dedicated security mailbox, bug-bounty
program, guaranteed response time, or external incident-response service exists.
If no private channel is already available, do not disclose sensitive details
through a public issue; ask a project maintainer how to submit them safely.

Security reports are reviewed by a human maintainer. Automated validation and
audit evidence can support triage, but they are not an external witness and do
not replace human adjudication.
