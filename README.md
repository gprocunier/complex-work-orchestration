# Complex Work Orchestration

This skill turns complex work into a controlled operating model with a senior
architect, project-manager coordination, bounded Codex workerbees, optional
outside model contractors, and a Beads-backed work graph.

Use it when a project needs durable state, multiple agents, independent review,
external reasoning, or careful release judgment.

Project site: https://gprocunier.github.io/complex-work-orchestration/

## Installation

Clone the repository and run the guided installer:

```bash
git clone https://github.com/gprocunier/complex-work-orchestration.git
cd complex-work-orchestration
./scripts/install.sh
```

The installer first autodetects your Codex skills directory from:

1. `CODEX_SKILLS_DIR`
2. `CODEX_HOME/skills`
3. `$HOME/.codex/skills`

When running interactively, it shows the detected path and lets you accept it or
type a different skills directory. For automation, pass the target explicitly:

```bash
./scripts/install.sh --skills-dir /path/to/codex/skills --yes
```

You can also point it at a Codex home:

```bash
./scripts/install.sh --codex-home /path/to/.codex --yes
```

The installer copies the skill files directly into the selected skills
directory: `README.md`, `LICENSE`, `SKILL.md`, `AGENTS.md`, `agents/`,
`policy/`, `templates/`, `experts/`, `references/`, `schemas/`, `examples/`,
`docs/`, and `scripts/`. It does not build or require a tarball.

## Invocation

The normal interface is the Codex conversation. When sizing is unclear, start
in Plan mode and ask Codex to use the skill and prompt coach:

```text
/plan Use $complex-work-orchestration prompt coach to size this work:
Plan a multi-session cleanup of installer docs, tests, and handoff notes.
```

Use the explicit scaffold trigger when you already know the work needs the full
architect/PM/worker harness:

```text
Use $complex-work-orchestration to scaffold this project.
```

The prompt coach treats explicit scaffold language as a full-harness request.
Terms such as `PM coordination`, `workerbee`, `epic`, and `contractor lanes`
also size the work toward an architect/PM/workerbee graph. Contractor-lane
language asks for the outside-sharing boundary before any external dispatch.

Advanced operator-shell equivalent:

```bash
python3 scripts/coach_prompt.py \
  "Plan a multi-session cleanup of installer docs, tests, and handoff notes."
```

All work governed by this skill should leave a durable Beads story. A narrow
task can still execute in the current thread, but the minimum tracking shape is
one Beads task with evidence, validation, and handoff notes.
Generated Beads should populate the native Beads fields for `skills`,
`acceptance`, `design`, and `notes`; descriptions remain the human-readable
assignment body.

When creating Beads manually, do not type literal `\n` sequences into text
fields. Use real newlines through a heredoc, `--body-file`, `--design-file`, or
shell command substitution so rendered Beads do not show backslash-n text.

The skill should also be used for requests that mention:

- Mixture of Experts
- architect, project manager, or workerbee roles
- Claude, Opus, Mythos, or another outside contractor model
- Beads work graphs
- durable handoff or multi-session coordination
- broad review, release, lab, production, or publication risk

## Policy Control Plane

The skill is organized as a small control plane over Beads. The Markdown files
teach the operator-facing flow; the JSON-compatible YAML policy files make the
same flow inspectable by helper scripts without adding a Python dependency.

Core policy files:

- `policy/routing-policy.yaml`: route classes, restricted terms, default route,
  and contractor guard labels.
- `policy/executor-registry.yaml`: internal and outside executor capabilities,
  provider bindings, opt-in requirements, and Codex pickup rules.
- `policy/provider-registry.yaml`: provider trust tiers, retention classes,
  conflict-risk domains, and provider-family metadata.
- `policy/expert-registry.yaml`: discipline profiles, trigger terms,
  job-description labels, and expected output lenses.
- `policy/share-boundaries.yaml`: allowed third-party sharing modes and
  never-share categories, including disclosure-stage escalation rules.
- `policy/peer-review-policy.yaml`: when outside or local contract results need
  independent peer review before evaluation.
- `policy/acceptance-policy.yaml`: contractor return sections, sabotage and
  malpractice scoring thresholds, quarantine, and architect review rules.
- `policy/contracting-controls.yaml`: dispatch, audit, and adjudication
  controls for outside or local-worker contracts.

Advanced helper scripts:

These are the implementation tools Codex can run in the workspace and the
operator-shell equivalents for automation or CI. They are not the first-class
public user flow; start with `/plan` plus the skill when working interactively.

- `scripts/coach_prompt.py`: compile a right-sized invocation prompt before
  launching the full harness, including bounded `interactive_questions` that
  Codex can map to selectable Plan-mode prompts and a
  `beads_tracking_required` flag that is always true for skill-governed work.
- `scripts/route_work.py`: classify a request against the policy.
- `scripts/scaffold_workgraph.py`: create a policy-shaped Beads epic and lane
  tasks.
- `scripts/spawn_expert_reviews.py`: create expert-review or contractor-only
  Beads from routing triggers.
- `scripts/build_contractor_packet.py`: generate a gated outside-contractor
  packet for one Bead, with structured opt-in, quota checks, safe snippets,
  default audit recording, and a Distinguished Engineer profile included by
  default.
- `scripts/generate_manual_dispatch_prompt.py`: turn an approved packet into a
  manual prompt for Claude, OpenAI deep research, or another contractor.
- `scripts/dispatch_work.py`: revalidate a contractor packet, record a manual
  dispatch event by default, and produce the prompt without claiming that an
  external model was called automatically. Direct dispatch can use
  `--dispatch-id` so quota checks, output, and audit records share the same
  identity.
- `scripts/evaluate_return.py`: check contractor returns for required sections.
- `scripts/normalize_contractor_return.py`: turn a contractor response into a
  normalized return bundle with evidence items and sabotage scoring.
- `scripts/dispatch_work.py --local-profile openshift-ai-vllm`: prepare a
  local OpenAI-compatible dispatch envelope for OpenShift AI vLLM or another
  named local profile. The envelope shape is documented by
  `schemas/local-dispatch-envelope.schema.json`.
- `scripts/verify_attestation.py`: verify SHA-256 subject attestations for
  packets, return bundles, or other exported artifacts.
- `scripts/verify_audit_log.py`: verify audit event hashes and hash-chain links.
- `scripts/record_audit_event.py`: append a local audit entry for routing,
  packet, dispatch, evaluation, and adjudication events. New entries include a
  previous-event hash when a prior event exists.
- `scripts/summarize_resume_state.py`: print Beads resume commands and current
  graph state.
- `scripts/validate_repository.py`: fail CI when policies, schemas, personas,
  executor controls, or emitted packet artifact names drift apart.

Schemas in `schemas/` describe prompt-coach results, route results, contractor
packets, contractor return bundles, local dispatch envelopes, attestations,
acceptance decisions, Beads metadata, and audit events. `examples/` contains
small sample artifacts that can be used as smoke-test inputs.

Example route check:

```bash
python3 scripts/route_work.py \
  --external-ok \
  --share-boundary redacted-packet \
  "Security review the auth token and shell command handling."
```

## Diagrams

### Harness Structure

```mermaid
flowchart TD
    User[User request] --> Main[Main Codex thread]
    Main --> Architect[Architect role]
    Main --> PM[Project manager role]
    Main --> Beads[(Beads work graph)]

    Architect --> Frame[Decompose work and set acceptance]
    Architect --> Review[Review findings and make final decisions]

    PM --> Hygiene[Maintain graph, dependencies, status, handoffs]
    PM --> Dispatch[Prepare worker and contractor assignments]
    PM --> Beads

    Beads --> WorkerReady[Codex-ready beads]
    Beads --> ContractorReady[Contractor-only beads]

    WorkerReady --> Workerbee[Codex workerbee]
    Workerbee --> Evidence[Patch, validation, evidence]
    Evidence --> Beads

    ContractorReady --> Packet[Contractor packet]
    Packet --> Outside[Outside LLM contractor]
    Outside --> Findings[Findings, risks, confidence, next actions]
    Findings --> Beads

    Beads --> Review
    Review --> Followup[Accepted follow-up beads]
    Followup --> WorkerReady
```

### Policy Routing

```mermaid
flowchart TD
    Request[User request] --> Classifier[route_work.py]
    Classifier --> Routing[policy/routing-policy.yaml]
    Classifier --> Experts[policy/expert-registry.yaml]
    Classifier --> Share[policy/share-boundaries.yaml]
    Classifier --> Executors[policy/executor-registry.yaml]

    Routing --> Decision{Route class}
    Experts --> Decision
    Share --> Gate{External allowed?}
    Executors --> Gate

    Decision -->|internal-worker| Worker[Normal Codex-executable Beads]
    Decision -->|local-worker| Local[Low-risk local worker contract]
    Decision -->|architect-review| Architect[Architect review Beads]
    Decision -->|external-contract| Gate

    Local --> LocalGuard[local-worker-only + no-codex-exec + one job-description label]
    LocalGuard --> Return[evaluate_return.py]
    Gate -->|No| Architect
    Gate -->|Yes| Contract[Contractor-only Bead]
    Contract --> Guard[contractor-only + no-codex-exec + one job-description label]
    Guard --> Packet[build_contractor_packet.py]
    Packet --> Validate[dispatch_work.py packet revalidation]
    Validate --> Outside[Outside model contractor]
    Outside --> Return
    Return --> Architect
```

### Invocation Flow

```mermaid
flowchart TD
    Start[Request arrives] --> Trigger{Skill trigger?}
    Trigger -->|Explicit: Use $complex-work-orchestration| Harness[Use orchestration harness]
    Trigger -->|Mentions MoE, PM, workerbees, Claude, Beads, durable handoff| Harness
    Trigger -->|Unsure how much harness to use| Coach[coach_prompt.py]
    Trigger -->|Narrow single-thread fix| Local[Use current-thread execution]

    Coach --> Sizing{Recommended level}
    Sizing -->|in-thread| BeadsCheck
    Sizing -->|lightweight-beads| BeadsCheck
    Sizing -->|full-harness or contract/local worker| Harness
    Local --> BeadsCheck[Check bd and .beads]
    Harness --> BeadsCheck

    BeadsCheck --> HasBeads{Beads available?}
    HasBeads -->|Yes| InitSync[bd init if needed, then bd sync]
    HasBeads -->|No| Markdown[Create temporary Markdown plan and warn durability is reduced]

    InitSync --> Size{Graph size}
    Markdown --> Size
    Size -->|narrow| SingleTask[Create or update one Beads task]
    Size -->|complex| Scaffold[Create epic and role/lane beads]
    SingleTask --> Packet[Return orchestration packet]
    Scaffold --> Packet[Return orchestration packet]
```

### External Contracting Flow

```mermaid
flowchart TD
    Need[Need independent deep reasoning] --> OptIn{Third-party collaboration allowed?}
    OptIn -->|No outside sharing| Internal[Keep reasoning inside Codex workflow]
    OptIn -->|Allowed| Boundary[Record share boundary]

    Boundary --> JD[Choose one job-description label]
    JD --> General[contract-jd-general-reasoning]
    JD --> Security[contract-jd-security-reasoning]
    JD --> Architecture[contract-jd-architecture-reasoning]
    JD --> Specialist[contract-jd-domain-name]

    General --> Create[Create contractor-only bead]
    Security --> Create
    Architecture --> Create
    Specialist --> Create

    Create --> Guard[Add contractor-only and no-codex-exec labels]
    Guard --> Metadata[Add executor, codex_pickup, discipline, share_boundary metadata]
    Metadata --> PMPacket[PM prepares boundary-gated packet]
    PMPacket --> Validate[Validate packet hash, provider, disclosure stage, opt-in, profile, snippets, exclusions, and artifacts]
    Validate --> Dispatch[Generate manual dispatch prompt and audit event]
    Dispatch --> Outside[Outside model performs assigned review]
    Outside --> Return[Return Beads comment or patch branch]
    Return --> Evaluate[Evaluate return format, evidence, and boundary fit]
    Evaluate --> Architect[Architect accepts, rejects, or escalates]
    Architect --> Accepted{Accepted?}
    Accepted -->|Yes| Followup[Create normal Codex-executable follow-up beads]
    Accepted -->|No| CloseLoop[Record rejected or superseded finding]
```

### Main-Thread PM Dispatch Flow

```mermaid
flowchart TD
    User[User asks in Codex] --> Coach[Codex runs coach_prompt.py]
    Coach --> Plan{Need contractor?}
    Plan -->|No| Graph[Create normal Beads graph]
    Plan -->|Yes| Boundary[Confirm share boundary and opt-in]

    Boundary --> Contract[Create contractor-only Bead]
    Contract --> Packet[build_contractor_packet.py]
    Packet --> Prompt[dispatch_work.py renders manual prompt]

    Prompt --> Choice{Operator dispatch target}
    Choice --> Claude[claude -p prompt]
    Choice --> Agy[agy -p prompt]
    Choice --> Manual[Manual UI paste]

    Claude --> Return[contractor-return.md]
    Agy --> Return
    Manual --> Return

    Return --> Normalize[normalize_contractor_return.py]
    Normalize --> Evaluate[evaluate_return.py]
    Evaluate --> Architect[Architect adjudication]
    Architect --> Followup[Normal Codex-executable follow-up Beads]
```

### Provider Integrity And Quarantine

```mermaid
flowchart TD
    Request[Task text and requested discipline] --> Route[route_work.py]
    Route --> Providers[policy/provider-registry.yaml]
    Route --> Conflicts{Provider conflict terms hit?}
    Route --> Boundary[policy/share-boundaries.yaml]
    Boundary --> Disclosure{Disclosure stage requires escalation?}

    Conflicts -->|Yes| PeerReq[peer_review_required=true]
    Conflicts -->|No| NormalReview[normal evaluator path]
    Disclosure -->|Yes| Escalation[operator must pass --allow-disclosure-escalation]
    Disclosure -->|No| PacketGate[packet gate]
    Escalation --> PacketGate

    PacketGate --> Packet[contractor packet with packet_sha256]
    Packet --> Attest[optional packet attestation sidecar]
    Packet --> Dispatch[manual dispatch and audit event]
    Dispatch --> Return[contractor return]
    Return --> Normalize[normalize_contractor_return.py]
    Normalize --> Score[sabotage and malpractice score]
    Score --> Peer{Peer review required or sabotage review?}
    Peer -->|Yes| PeerLane[peer-review Bead lane]
    Peer -->|No| Eval[evaluate_return.py]
    PeerLane --> Eval
    Eval --> Quarantine{quarantine recommended?}
    Quarantine -->|Yes| Hold[quarantine, no implementation dependency]
    Quarantine -->|No| Architect[architect adjudication]
    Architect --> Followup[normal Codex-executable follow-up beads]
```

### Beads Work Selection

```mermaid
flowchart LR
    Ready[bd ready] --> Filter{Which actor is looking?}
    Filter -->|Codex workerbee| CodexCmd[bd ready --exclude-label contractor-only --exclude-label local-worker-only --exclude-label no-codex-exec --json]
    Filter -->|PM or architect external dispatch| ContractorCmd[bd ready --label contractor-only --json]
    Filter -->|PM or architect local dispatch| LocalCmd[bd ready --label local-worker-only --json]

    CodexCmd --> Normal[Normal implementation, test, docs, validation beads]
    ContractorCmd --> Contracts[External contractor beads only]
    LocalCmd --> LocalContracts[Local-worker review contracts only]

    Contracts --> ContractLabels[contractor-only + no-codex-exec + one contract-jd label]
    LocalContracts --> LocalLabels[local-worker-only + no-codex-exec + one contract-jd label]
    ContractLabels --> Packet[Brief outside model]
    LocalLabels --> LocalEnvelope[Brief local worker]
    Normal --> Execute[Codex may claim and execute]
```

## Operating Flow

1. Decide whether the work is small enough to execute in-thread or needs the
   full orchestration harness. Beads tracking is mandatory either way. If
   unsure, run the prompt coach first:

   ```bash
   python3 scripts/coach_prompt.py "<task text>"
   ```

   The coach returns a recommended orchestration level,
   `beads_tracking_required=true`, missing questions, bounded
   `interactive_questions`, enabled/disabled levers, warnings, and a paste-ready
   launch prompt. In Plan mode, use `interactive_questions` for selectable user
   input when the answer changes execution behavior. In Default mode, ask only
   the required concise question or apply the coach's safe default.
2. Classify non-trivial work against the policy:

   ```bash
   python3 scripts/route_work.py "<task text>"
   ```

3. If outside contracting may help, ask the third-party collaboration question:

   ```text
   Should this project use a third-party model contractor for deep reasoning? If
   yes, what may be shared: redacted packet only, repo read-only, patch branch,
   or no outside sharing?
   ```

4. If the answer permits outside sharing, re-run the route with `--external-ok`
   and the selected `--share-boundary`.
5. If using local inference, pass `--local-ok`; add `--prefer-local` only when
   low-risk local work is the desired route. Local-worker review beads still get
   `local-worker-only` and `no-codex-exec` and require evaluator plus architect
   adjudication before implementation. Use `--local-profile openshift-ai-vllm`
   when the target worker is an OpenShift AI vLLM endpoint.
6. Check Beads and initialize or sync the work graph.
7. Create or update one Beads task for narrow/current-thread work. Escalate to
   an epic when multiple independent work streams, handoffs, contractors, or
   release gates appear.
8. For epic-sized work, create role/lane tasks under the epic: architect framing, PM coordination,
   workerbee work, validation, docs/handoff, and any outside contracts.
9. For outside work, post contractor-only Beads with job-description labels.
   The scaffold wires dispatch, peer review when required, expert review,
   evaluation, and architect adjudication as real Beads dependencies.
10. PM prepares the contractor packet and a manual dispatch prompt. Packet
   build and dispatch both record hash-chained audit events unless `--no-audit`
   is used.
11. Dispatch revalidates the packet hash, executor, boundary, opt-in basis,
   provider binding, disclosure stage, expert profile, and artifact whitelist
   before rendering the prompt.
12. The outside model returns findings through Beads comments or a patch branch.
13. PM normalizes the return into a return bundle and evaluates required
   sections, evidence, confidence, residual risk, explicit safety fields,
   boundary fit, and sabotage or malpractice signals.
14. If peer review is required or the return trips the sabotage review
   threshold, run the peer-review lane before implementation can proceed.
15. If the return trips quarantine, do not convert findings into implementation
   dependencies until the architect explicitly adjudicates the incident.
16. The architect reviews contractor findings before Codex workers implement
   follow-up work or before release decisions are made.
17. PM keeps dependencies, status, blockers, and resume instructions current.

## Beads Requirement

Beads is required for skill-governed work. The full durable workflow uses an
epic and lane tasks, but even narrow current-thread work should create or update
one Beads task. The installer warns if `bd` is missing but does not fail,
because the skill can still be read and used manually.

Use these checks at startup:

```bash
command -v bd
test -d .beads && bd ready --json || true
```

If the repo should own the durable work story and `.beads` is absent:

```bash
bd init
```

When a synced graph exists:

```bash
bd sync
```

If Beads is unavailable, create the same task or graph structure in a temporary
Markdown plan and say that durability is reduced. Do not claim contractor-only
filtering, shared ready-work semantics, or durable external handoff unless
Beads or an equivalent tracker is actually in use.

On Fedora or EPEL-style systems, use your configured Beads package source. If
you do not have one, the installer suggests the public `greg-at-redhat/beads`
COPR. Set `BEADS_COPR=owner/project` before running the installer to point the
hint at a different COPR.

Normal Codex ready-work discovery should exclude outside and local-worker
contracts:

```bash
bd ready --exclude-label contractor-only --exclude-label local-worker-only --exclude-label no-codex-exec --json
```

PM or architect dispatch can inspect contract work explicitly:

```bash
bd ready --label contractor-only --json
bd ready --label local-worker-only --json
bd show <id> --json
```

## External Contracting

Outside models are contractors, not project owners. They receive one explicit
bead at a time. They do not re-plan the project, close parent epics, publish,
release, tag, rotate secrets, or run destructive commands.

External contracting is fail-closed. A contractor packet is only valid when the
user has opted in, the selected share boundary allows outside work, the Bead has
`contractor-only` and `no-codex-exec`, and an architect review is required
before any finding becomes implementation work. Packet building enforces this:
external packets require `--external-ok` or `--opt-in-record`, and unsafe files
are rejected before they can enter the packet. Repo-readonly and patch-branch
boundaries also require `--allow-disclosure-escalation`. Dispatch then
revalidates the packet hash, executor, boundary, disclosure stage, opt-in basis,
expert profile, and artifact whitelist before any manual prompt is rendered.

Provider identity is explicit. Executors are bound to provider profiles in
`policy/provider-registry.yaml`; routing reports provider-conflict domains such
as frontier model work or model-provider competition. A conflict does not make
the contractor unusable by itself, but it forces peer review and architect
adjudication before findings can affect the implementation plan.

Distinguished Engineer profiles are first-class packet artifacts. A normal
contractor packet includes the matched `experts/<discipline>.md` profile and
its SHA-256 so the outside model receives the full operating lens, not just a
job-description label. A packet created with `--no-include-expert-profile` is
degraded, must pass `--degraded-context-justification`, and still requires
`--allow-degraded-packet` at dispatch time.

Use outside contracts for work that benefits from an independent reasoning lens:

- general second-opinion reasoning
- security-focused review
- architecture critique
- reliability or operations review
- performance analysis
- documentation and publishability review
- discipline-specific review such as SELinux, API compatibility, packaging, or compliance

The PM prepares the packet. The architect remains the final decision owner.

## Job Description Labels

Every outside contract gets guard labels:

- `contractor-only`
- `no-codex-exec`

Every outside contract also gets exactly one primary job-description label:

- `contract-jd-general-reasoning`: assumptions, tradeoffs, failure modes,
  alternatives, and independent critique.
- `contract-jd-security-reasoning`: threat model, privilege boundaries,
  input handling, authn/authz, secret exposure, dependencies, and supply-chain
  risk.
- `contract-jd-architecture-reasoning`: system boundaries, coupling,
  migration paths, data flow, maintainability, and reversibility.
- `contract-jd-reliability-reasoning`: operational failure modes, recovery,
  observability, rollout, concurrency, state, and incident risk.
- `contract-jd-performance-reasoning`: scaling behavior, algorithmic cost,
  resource pressure, hot paths, caching, and benchmark gaps.
- `contract-jd-docs-reasoning`: correctness, clarity, audience fit, missing
  warnings, examples, and publishability.
- `contract-jd-peer-review`: independent acceptance gate for contractor or
  local-worker returns when `peer_review_required=true`.
- `contract-jd-sabotage-review`: integrity review for suspicious, conflicted,
  fabricated, or boundary-breaking returns.
- `contract-jd-domain-<name>`: any other discipline-specific contract, such as
  `contract-jd-domain-selinux` or `contract-jd-domain-api-compat`.
- `contract-jd-redhat-<name>`: Red Hat product-focused Distinguished Engineer
  lens, such as OpenShift Platform, OpenShift Application Developer,
  OpenShift AI, RHOSO, RHACM, RHACS, or RHEL.

The job-description label calibrates the outside model. A security contract
should return security findings, not a generic project review.
If work needs multiple disciplines, create multiple contractor Beads so each
packet has exactly one primary job-description label and one matching expert
profile.

## Contractor Bead Template

```text
Purpose:
Scope:
Inputs:
Allowed changes:
Do not touch:
Expected output:
Validation required:
Escalation triggers:
Handoff format:
Contractor job description:
Contract labels:
Share boundary:
Codex handling rule:
```

Example:

```bash
body=$(cat <<'EOF'
Purpose:
Scope:
Inputs:
Allowed changes:
Do not touch:
Expected output:
Validation required:
Escalation triggers:
Handoff format:
Contractor job description:
Contract labels:
Share boundary:
Codex handling rule: Codex agents may coordinate, brief, and review this bead, but must not execute or close it as contractor work.
EOF
)

bd create "Claude Opus review: security-focused reasoning for <scope>" \
  --type task \
  --labels contractor-only,no-codex-exec,contract-jd-security-reasoning \
  --assignee external-claude-opus \
  --skills security,contractor-control,beads \
  --acceptance "Security findings cite evidence, mitigations are testable, and architect review remains required." \
  --design "Apply the security job-description lens within the approved share boundary; do not perform implementation work." \
  --notes "Share boundary: redacted-packet. Codex pickup: forbidden. Return channel: bd-comment." \
  --metadata '{"executor":"external-llm","codex_pickup":"forbidden","job_description":"security-focused reasoning","discipline":"security","share_boundary":"redacted-packet","return_channel":"bd-comment","architect_review_required":true}' \
  --description "$body"
```

## Contractor Packet

Give the outside model:

- the assigned bead ID and `bd show <id> --json` output
- `references/contractor-brief.md`
- the job-description label and discipline lens
- the Distinguished Engineer calibration profile
- allowed files, forbidden files, and sharing boundary
- opt-in basis and quota metadata
- expected output and handoff format
- validation expectations
- escalation triggers

The packet can be generated after the contractor Bead exists:

```bash
python3 scripts/build_contractor_packet.py \
  --bead <id> \
  --executor external_security_reviewer \
  --share-boundary redacted-packet \
  --external-ok \
  --attest-packet \
  --format json \
  --output contractor-packet.json
```

Use `--opt-in-record <path>` instead of `--external-ok` when opt-in is recorded
in a local JSON audit note. The record must include `allowed: true`, a matching
share boundary, `allowed_external_executors`, decision source, timezone-aware
timestamp, scope, and optional expiry; see `examples/sample-opt-in-record.json`.
Legacy records with `allowed_executors` still validate for compatibility. Pass
`--epic <id>` when the contract belongs to a durable epic so quota checks are
scoped to that epic. Without `--epic`, the helper uses the global dispatch
bucket for quota accounting.
Records may also include `allowed_providers` to constrain which provider family
is approved for the packet.

For repo-readonly or patch-branch disclosure, include an explicit escalation:

```bash
python3 scripts/build_contractor_packet.py \
  --bead <id> \
  --executor external_security_reviewer \
  --share-boundary repo-readonly \
  --allow-disclosure-escalation \
  --external-ok \
  --format json \
  --output contractor-packet.json
```

If an expert profile is intentionally omitted, name the reason in the packet:

```bash
python3 scripts/build_contractor_packet.py \
  --bead <id> \
  --executor external_security_reviewer \
  --share-boundary redacted-packet \
  --external-ok \
  --no-include-expert-profile \
  --degraded-context-justification "The reviewer only needs a narrow compatibility check." \
  --format json \
  --output contractor-packet.json
```

Packet validation checks the packet hash, executor, boundary, disclosure stage,
opt-in basis, expert-profile state, mandatory exclusions (`full_bead_json`,
`secrets`, `production_access`), artifact whitelist, snippet shape, snippet line
limits, snippet SHA-256 values, and included-artifact consistency before
dispatch.

Manual dispatch prompts are generated from approved packets:

```bash
python3 scripts/dispatch_work.py \
  --packet contractor-packet.json \
  --mode manual
```

Both packet build and dispatch append audit entries by default. Use
`--no-audit` only for tests or dry operator rehearsals that must not consume
quota.

For a low-risk local worker envelope, start inside Codex and let the coach ask
for explicit local opt-in:

```text
/plan Use $complex-work-orchestration prompt coach to size this work:
Use a local OpenShift AI vLLM worker to review a bounded README command example.
```

After opt-in, Codex may run the local-worker helper path behind the scenes:

```bash
python3 scripts/coach_prompt.py \
  --local-ok \
  --prefer-local \
  --local-profile openshift-ai-vllm \
  --requested-role documentation \
  "Use an OpenShift AI vLLM local worker to review a bounded README command example."

python3 scripts/route_work.py \
  --local-ok \
  --prefer-local \
  --local-profile openshift-ai-vllm \
  --requested-role documentation \
  "Use an OpenShift AI vLLM local worker to review a bounded README command example."
```

Local-worker output is treated like contractor evidence: evaluator scoring and
architect adjudication are still required before follow-up work is implemented.
Local-worker expert review beads are labeled `local-worker-only` and
`no-codex-exec`, and their metadata sets `codex_pickup` to `forbidden`.
The local secure reviewer (`local_secure_review_worker`) is read-only and local:
it can inspect approved repo context for security, peer-review, repo-review, or
sabotage-review work, but it has no web, shell, or repo-write authority.

Direct route dispatch prepares a local dispatch envelope and can carry a stable
dispatch ID:

```bash
python3 scripts/dispatch_work.py \
  --local-ok \
  --prefer-local \
  --local-profile openshift-ai-vllm \
  --dispatch-id dispatch-<bead-id>-<timestamp> \
  --bead <id> \
  --epic <epic-id> \
  --json \
  "Documentation review for public README examples."
```

To call a local OpenAI-compatible endpoint, set the OpenShift AI vLLM endpoint
environment variables and opt in to execution:

```bash
export CWO_OPENSHIFT_AI_VLLM_BASE_URL="https://vllm.example.internal"
export CWO_OPENSHIFT_AI_VLLM_MODEL="vllm-local"

python3 scripts/dispatch_work.py \
  --local-ok \
  --prefer-local \
  --local-profile openshift-ai-vllm \
  --execute-local \
  "Summarize the docs-review risks in this packet."
```

The generated `local_envelope` follows
`schemas/local-dispatch-envelope.schema.json`; `--execute-local` is never
implicit.

Do not ask outside models for raw chain-of-thought. Ask for conclusions,
assumptions, evidence, alternatives considered, risks, confidence, and
recommended next actions.

## Return Format

Contractor results should come back as a Beads comment or a patch branch with a
Beads comment pointing to it:

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

## Return Evaluation

Normalize and evaluate contractor output before converting any finding into
normal Codex work:

```bash
python3 scripts/normalize_contractor_return.py \
  --bead <id> \
  --dispatch-id <dispatch-id> \
  --packet-sha256 <packet-sha256> \
  --file contractor-return.md \
  --output contractor-return-bundle.json

python3 scripts/evaluate_return.py --bead <id> --file contractor-return.md
```

Evaluator output includes `sabotage_score`, `malpractice_score`,
`peer_review_required`, `peer_review_status`, `human_adjudication_required`,
and `recommended_disposition`. If the evaluator reports `Verdict: quarantine`,
a high sabotage score, or a high malpractice score, do not create
implementation dependencies from the contractor output. Keep the return
isolated, run peer review or local secure review as needed, and have the
architect decide whether to reject, narrow, or re-post the contract.

Audit and attestation checks:

```bash
python3 scripts/verify_attestation.py \
  --file contractor-packet.json \
  --attestation contractor-packet.json.attestation.json

python3 scripts/verify_audit_log.py --json
```

## Reference

See `references/prompt-coach.md` for prompt sizing and invocation guidance,
`references/external-contracting.md` for the outside-contractor guide, and
`references/local-inference.md` for OpenShift AI vLLM and other local
OpenAI-compatible workers. See `references/redhat-expert-catalog.md` for the
Red Hat product-focused Distinguished Engineer lenses. Use
`references/contractor-brief.md` as the reusable assignment brief for outside
model contractors. Use `policy/`, `schemas/`, `templates/`, and `experts/` as
the source of truth for route classification, job-description calibration,
validation contracts, and reusable Beads bodies. Use `examples/` for smoke-test
inputs and expected artifact shapes.

## License

This project is licensed under the GNU General Public License v3.0 only
(`GPL-3.0-only`). See `LICENSE`.
