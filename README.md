# Complex Work Orchestration

**Take complex work from request to checked result.**

CWO is a Codex skill and operating contract for projects with dependent tasks,
reviews, and work that continues across sessions. Keep decisions and progress
in a durable work graph and bring specialist findings into results you can inspect.
You supply the goal, constraints and permission; CWO guides task organization,
evidence checking and handoff.

## See the result first

A real local change added JSON reporting to the documentation-audit CLI while
preserving its human output and exit statuses. Independent review found a Unicode
encoding failure the first tests missed. The lead reproduced it, corrected JSON
escaping, and added an actual subprocess regression. Eleven focused tests passed.

[Inspect the release-readiness work record](examples/release-readiness/RECORD.md)
or [evaluate the case and operating tasks](https://gprocunier.github.io/complex-work-orchestration/workflows.html).

New to project agents? [Build your first project](https://gprocunier.github.io/complex-work-orchestration/get-started.html)
with the self-contained [starter fixture](examples/first-project/). Repair a
checker, inspect its saved decision, then continue in a fresh session.

## Choose your route

- **New to project agents:** [Start here](https://gprocunier.github.io/complex-work-orchestration/get-started.html).
  Prerequisites, one setup path, a useful first task, fresh-session continuation,
  expected results, and removal.
- **Already use an agent:** [Operator guide](https://gprocunier.github.io/complex-work-orchestration/workflows.html).
  Inspect the extra value, operating costs, evidence, and recovery controls.
- **Evaluating adoption:** [Worked examples](https://gprocunier.github.io/complex-work-orchestration/use-cases.html).
  Dependencies, conflicting reviews, safe lab operations, and research-to-artifact work.

## Fit and non-fit

Use CWO when reconstructing a project after restart is costly, changes depend on
accepted prerequisites, reviews disagree, or handoff requires proof of what was
checked. Skip it for short disposable tasks you can finish and verify in one
conversation.

Codex already plans, uses tools, edits files, and can delegate. Beads already
stores task state. CWO adds an operating contract around that machinery:
acceptance criteria, bounded execution, evidence evaluation, owner decisions,
and recovery-quality handoff. Some controls are deterministic checks; some are
instructions the operator must follow. It does not make an unrestricted agent
safe by declaration. [Understand the boundary](https://gprocunier.github.io/complex-work-orchestration/explanation.html).

## Minimum entry path

Use a working authenticated Codex CLI, Python 3, Git, and
[Beads](https://github.com/gastownhall/beads). The canonical
[setup sequence](https://gprocunier.github.io/complex-work-orchestration/get-started.html#install)
separates the CWO source checkout, installed skill, and target project. It installs
and verifies the named operator profile before starting a **fresh** session.
The named profile leaves your default profile settings intact. The installed
CWO skill remains available in ordinary sessions until disabled or removed. Do
not resume an old thread and call that named-profile activation.

CWO does not include model access. Your agent/provider account supplies it and
its quota. Local work records do not mean prompts remain offline. No additional
outside contractor sharing is enabled by default.

## Status and advanced controls

Development-stage public skill package; see [VERSION](VERSION) and
[CHANGELOG](CHANGELOG.md). No Git tag or deployed version is implied.

- CWO uses a system prompt optimized for complex project work rather than the
  default OpenAI system prompt. See the [CWO system prompt](references/cwo-system-prompt.md)
  for its behavior, activation and limits.
- Current native delegation requires exact qualification and uses Luna-first routing, with recorded Terra
  escalation. Historical Spark records do **not** authorize fresh dispatch.
- Fixed-cohort concurrency is a host-qualified preview, not a setup requirement.
- Browser contractors, local inference, and restricted environments are optional
  paths with distinct boundaries—not universal executable integrations.
- [Reference and troubleshooting](https://gprocunier.github.io/complex-work-orchestration/reference.html)
  links precise policy, schema, installation, update, and recovery controls.
- [Security policy](SECURITY.md) and [threat model](references/security-threat-model.md).
- [Documentation maintenance](https://github.com/gprocunier/complex-work-orchestration/blob/main/CONTRIBUTING.md) explains canonical ownership and checks.

Code is licensed under [GPL-3.0](LICENSE). Installation, local readiness,
committing, pushing, and deployment are separate actions; documentation readiness
does not authorize publication or changing a live installation.
