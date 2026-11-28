# CWO security threat model

CWO's supervisor host controls what a registered worker receives, which effects
it can request, and what evidence reaches the lead. The model assumes that a
worker's prompts and output may be hostile. It covers the managed routes
described here and assumes the operator, controller, host OS and selected
executables are trusted. The lead uses its host permissions. The controller
protects specific approvals and review inputs from the lead's writes.
The [claims register](claims-register.md) links claims to implementation and evidence.

## Trust on the supervisor host

| Boundary | What is trusted and what can cross it |
| --- | --- |
| Operator and controller | The operator authorizes the task, budget and disclosure. The controller holds approval keys, current authorization and replay state, worker login custody, dispatch and acceptance evidence, and the link to the selected Beads database. |
| Lead session | The host sandbox and approval settings govern the lead's tool access. CWO relies on the lead to honor the operator's scope and approvals. Check the lead's findings and decisions against evidence. |
| Registered worker | The host treats model responses and tool requests as untrusted. The worker sees the mounted checkout and task data for its assignment. The host keeps signing keys, controller state and acceptance records outside worker-visible roots and validates returned artifacts before use. |
| Provider or external reviewer | Approved data crosses the boundary to the selected service or reviewer. Returned material is evidence. Provider identity, reply digests and review scores describe provenance and evaluation within the workflow. The service's data handling and the truth of its claims remain separate questions. |

The authority host runs under a Unix user ID separate from the unprivileged lead.
The administrator
selects the host code, configuration, socket and state directories in protected
system configuration. The host checks the peer's kernel-reported user ID and
accepts only a supported operation and a reference to a saved operator decision.
It holds outbound opt-in and the reviews and original dispatch records used by
protected synthesis. The lead continues to have the filesystem and tool access
granted to its session, including access to other same-account state.

Controller-signed approvals use a keyed HMAC over the exact approved action.
The verifier checks the action and its parent authorization. Route-specific
checks enforce current scope, expiry and use state before effects. The bindings
cover the relevant task, workspace, provider, budget and operations. This
protects against a sandboxed worker forging an approval, changing its scope
or replaying an already-used authorization. The controller keeps its key and
use state outside the worker's mounts. The lead and other unrestricted
processes running under the controller's Unix account are trusted. They can
access same-account state or bypass the helpers. These signatures establish
authorization under the controller key. Independent proof of who approved the
action would require a separate trust root.
[Signed route contracts](native-live-route-holds.md).

Packet self-hashes and record digests identify exact bytes. The configured host
audit verifies retained events and links against a private head checkpoint and
ordered segment seals. It refuses a changed retained record, broken chain or
missing history inconsistent with that evidence. Legacy diagnostic logs only
check the retained chain and provide no host authority. A same-account writer
can replace and rehash the entire local history and checkpoint. The host audit
has no external anchor and says nothing about unrecorded actions.
[Host audit history](host-audit-history.md).

## Registered worker routes

| Route | Shipped status and evidence | Scope |
| --- | --- | --- |
| Registered single-worker execution | The live qualification completed on 2026-11-24 after using 15 of 20 allowed starts. Every required behavior had a passing witness. The recorded Codex CLI was 0.171.0. Live witnesses through CWO v1.24.0 covered useful output and validation, progress from empty polling without stdin delivery, nonempty input refusal, outside-workspace refusal before spawn, signed exhaustion and charging, archive and cleanup. Production execution has its own enabled source decision, exact OpenAI disclosure and separately provisioned worker authentication. | The pass applies to the recorded finite profile and setup. Generic native launch, unrestricted worker tools and other hosts or configurations need their own evidence. [Production enablement](https://github.com/gprocunier/complex-work-orchestration/pull/149) · [Production requirements](native-live-route-holds.md#registered-single-worker-production) |
| Standing-approved delegation | The local `cwo-codex` foreground approval server retains an eligible assignment when the operator accepts the exact action. The installed `cwo delegate` selects it by project, Beads database, task and baseline, verifies the original admission and budget, and runs one registered worker. The signed custody can reference the full initial checkout snapshot by digest. The controller checks the protected reference and observes the current checkout again before dispatch. | The route writes one preapproved project-relative text output. It binds the exact candidate to the baseline and delivers it for independent hand acceptance. Installation alone supplies neither an approval nor evidence that a fresh host is qualified. [Delegation](https://github.com/gprocunier/complex-work-orchestration/pull/181) · [Checkout custody](https://github.com/gprocunier/complex-work-orchestration/pull/219) · [Hand acceptance](run-readiness.md#accepting-a-delivery-by-hand) |
| Registered contained pool | The trusted host admits the exact approved group of two or three workers, checks each login and the shared allowance, and calibrates the original callbacks before productive work. The v1.45.0 qualification used disposable cohorts. | The claim applies to the registered contained route and its scoped writer. The fixed qualification campaign is retired. [Pool operation](native-supervision-pools.md#start-an-approved-cohort) · [Qualification evidence](evaluation-evidence.md#contained-worker-pool) |

The registered single-worker and contained pool app servers run
with read-only checkout mounts. The single-worker route exposes the approved
finite command and empty polls. In the pool, the original isolated writer may
change only its assigned file. For a bounded unified diff, it rechecks the signed
starting digest before replacing the existing file. Codex's read-only tool
profile adds another layer in the pool: stock tool names can still appear in the
reported catalog. The catalog records what was declared. The containment claim
rests on the host mounts, network isolation, checked profile and authorized writer effects.
Confidential native workloads remain unsupported.
[Registered route](native-live-route-holds.md#registered-single-worker-production) ·
[Contained pool tools](native-supervision-pools.md#contained-pool-execution).

**Provider-only network.** The registered app server uses a host relay for HTTPS
to the allowlisted OpenAI service and authentication destinations. The relay
checks the destination and TLS server name. The finite command, pool writer and
validator run in separate network namespaces without that relay. The encrypted
payload is opaque to the relay. Admission and packet screening govern which
data is approved for disclosure. This network boundary applies to these
registered processes. Desktop, external CLI and ordinary lead traffic use
their own environment's network access.
[Registered provider relay](../scripts/registered_provider_network.py).

**Dedicated worker logins.** The worker sign-in uses a separate owner-private
Codex home under the controller's Unix account. Production, interactive Codex
and qualification use separate login homes. Concurrent pool workers each need
their own. Only the isolated app server receives the projected login.
Its tool profile denies access to that projection, and command and validator
processes run without it. The controller checks custody and holds an exclusive
lease while an app server uses the login. Uncertain cleanup keeps the lease
held for reconciliation. The app server can refresh the credential, and an
unrestricted process under the controller account can access the login home.
[Worker login requirements](native-live-route-holds.md#registered-single-worker-production) ·
[Pool login custody](native-supervision-pools.md#contained-pool-execution).

## Review and synthesis routes

| Route | Available path | Trust limit |
| --- | --- | --- |
| Codex | The policy assigns the architect ownership of synthesis and lists an internal Codex review worker. A live worker still needs the admission and authority of its actual route. | The architect and reviewer roles are instructions. Codex and ChatGPT Pro share the OpenAI provider family. |
| Claude | CWO can export a screened architecture critic packet for separate use with the Claude CLI. | An approved packet, working CLI and authorized login are prerequisites. [External critics](external-contracting.md#dispatch-flow) · [Executor registry](../policy/executor-registry.yaml) |
| Gemini | CWO can export a screened critic packet for Gemini through Antigravity's `agy` CLI. The shipped synthesis policy treats Gemini as salvage-only by default. | An approved packet, working CLI and authorized login are prerequisites. A specific evaluated finding can count as primary only with the architect's recorded approval under synthesis policy. [Executor registry](../policy/executor-registry.yaml) · [Synthesis rules](zero-trust-consensus.md) |
| ChatGPT Pro | The shipped integration prepares the screened request for a Codex architect thread in the ChatGPT desktop app. With the operator present, the thread uses the paired `@Chrome` profile to send the request and capture the reply. The operator reported a successful desktop round trip with matching reply and evaluator digests. | CWO binds the prepared request ID, private reply bytes, sender-confirmed model picker label and evaluation. The sender supplies the browser and model observations. Legacy CDP dispatch and share-link intake remain held. [Desktop integration](https://github.com/gprocunier/complex-work-orchestration/pull/163) · [Desktop workflow](chatgpt-pro-browser.md) |

Managed contractor export checks the host's current opt-in for the checkout,
assignment, destination and disclosure boundary, and screens the exact export.
Packet redaction and its separate residual check look for credentials and
recognizable personal details. Outbound screening also examines bounded hex
and base64 text for sensitive content. These checks can miss sensitive
information, so operators still need to inspect what will be shared.
Direct CLI or network calls use the invoking environment's permissions.
An exported prompt records preparation.
Observed peer-review evidence is still required when policy calls for it.
A required review stays open until the original evidence is available.
[Contractor dispatch](external-contracting.md#dispatch-flow) ·
[Peer review source contract](peer-review-record.md).

Protected synthesis uses the operator's exact panel selection and host-captured
returns from observed dispatches. It checks the corresponding evaluations and
preserves peer-review holds. When an older observed dispatch omits candidate
and scope, the report identifies the operator's selection. Same-family channels
count as one domain. Cross-provider agreement can still reflect shared errors.
File-based reports remain advisory, and synthesis reports support the
architect's adjudication. Protected synthesis evidence is offline.
[Offline synthesis](zero-trust-consensus.md#invocation-boundary)

## Delivery and acceptance

Worker and reviewer output goes through evaluation, checks for harmful changes
and quarantine conditions, any required peer review, and architect adjudication.
A passed structured peer review requires separate recorded dispatches. The
review dispatch must target the original dispatch, exact return and evaluation.
Same dispatch, session or model refuse. Same-provider escalation is accepted
only for a registered stronger model and offers weaker separation. Missing or
ambiguous host provenance refuses. Review leaves quarantine, tripwires and
unrelated holds in place.
[Peer review source contract](peer-review-record.md).

Return screening uses the structure of the review to flag directives and
unsupported claims. The architect can inspect the exact evidence behind each
hold. [Return screening](external-contracting.md#return-screening)

Everyday delegation delivers the exact candidate for hand acceptance from a
separate foreground session. The hand acceptance helper checks the live
candidate, baseline, blockers and children and records the reviewer session and
decision before close. These checks rely on the verified host and protect the
helper-managed path. Unrestricted processes can still edit the audit or operate
directly on Beads. [Hand acceptance](run-readiness.md#accepting-a-delivery-by-hand).

The verified production closure library is enabled. It consumes one original
host acceptance bound to the exact task, requirement baseline, candidate,
dispatch, return, current policy, required clearances and setup-selected Beads
database. A host-selected adjudicator must satisfy the peer-review separation
rules against the executor. Policy-required peer review remains a separate
gate. The original adapter checks blockers and children before writing and
checks again before close. The audit reserves acceptance before the first write.
It records partial persistence and avoids automatic retry after a later
refusal. The embedding host selects the adjudication callable and records its
identity. The record depends on that host's integrity. The shipped original
review-host producer remains held. The narrative CLI records
`pending-acceptance`. Verified production success requires the library. The
retired activation executor's historical pool receipts apply to the original
preview attempt. The current preview validates plans and approvals offline.
[Verified closure library](run-readiness.md#verified-closure-library) ·
[Activation preview refusal](native-live-route-holds.md).

## Instruction-only controls and remaining trust

The architect profile and role prompts ask the lead to delegate where appropriate,
keep within scope, review evidence and honor holds. Host sandbox and approval
settings govern the lead's Codex session. Launching with Codex `--yolo` disables
Codex sandbox and approval checks for the lead. Any separate OS or container
restrictions still apply. CWO's registered worker controls apply on that route.
A lead with direct filesystem or Beads access can bypass a cooperative helper. Advisory
Beads hooks and native supervision reports supply context and observations.
They have no independent enforcement, and hook-based enforcement remains
unsupported. [Architect profile](cwo-system-prompt.md) ·
[Hook enforcement disposition](codex-hook-enforcement-disposition.md) ·
[Native supervision](native-supervision.md).

The model assumes an uncompromised host, account, credentials, software and
trust root. Provider compromise or retention, malicious maintainers, OS and
dependency vulnerabilities, availability and deliberate operator disclosure are
outside its scope.
