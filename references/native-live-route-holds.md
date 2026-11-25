# Native live route holds

`scripts/cwo_core/native_live_availability.py` enables the registered
single-worker production decision. `N1_LIVE_AVAILABLE`, `POOL_LIVE_AVAILABLE`
and `CAMPAIGN_LIVE_AVAILABLE` remain `False`. These decisions come from installed
source. Activation preview retains its independent `LIVE_ACTIVATION_AVAILABLE`
hold in `run_native_pool_activation_preview.py`. Its accepted-child close route
uses pool receipts and would require a separate closure review before claiming
verified acceptance.

| Route | Required source decisions | Enforcement before effects |
| --- | --- | --- |
| Registered single-worker production | `REGISTERED_N1_LIVE_AVAILABLE` | Original signed workflow, exact finite profile, current provider disclosure adoption and configured dedicated worker login before the first claim. The original factory and transport recheck authority at launch and model request writes. |
| Raw native or generic maintenance launch | `N1_LIVE_AVAILABLE` | Raw `AppServer` construction and its adjacent `Popen`, unbound model RPCs, maintenance runtime `prepare` and the admitted v8 loader. |
| N1 host qualification | Signed version 2 qualification permit | The protected controller binds one exact operation, its expiry and the fixed 20-start campaign limit. The factory charges the launch to a private campaign journal before releasing the app-server command. |
| Native surface probe and qualification | `N1_LIVE_AVAILABLE` | `capture_tool_request` refuses before capture binding or listener startup; its CLI refuses before catalog/evidence writes. `observe_qualification` verifies the original opaque operation, then refuses before qualification output/intent creation. |
| Registered pool and retry | `N1_LIVE_AVAILABLE` and `POOL_LIVE_AVAILABLE` | Pool host execute entry and each member, plus approved retry entry and effect. `PoolConfiguration.enabled=True` cannot replace either source decision. |
| Activation preview | Dedicated `LIVE_ACTIVATION_AVAILABLE` plus N1 for `n1-read-only` and `n1-mutable`; additionally pool for `n2-read-only` | Run entry checks the dedicated hold and N1 before loading inputs; the loaded profile is checked before claims, ledger creation, reservation or launch. Server creation, ledger transport RPC entry points, worker-contract allocation and accepted-child closure recheck the dedicated hold and selected profile. |
| Retired campaign | Campaign, pool and N1, in that order | The CLI, pool canary, pool preparation, preclaim, global claim and server entry points check the three decisions and then refuse as retired. They refuse before input reads, claims, evidence writes or worker allocation. |
| Admitted v8 multiworker plan | N1 and pool | The loader checks the actual child count before consuming the verified operation or importing its runtime adapter. The concrete installed maintenance runtime supports exactly one worker child and one precommit session; it does not implement a multiworker maintenance cohort. |

The raw transport's N1 decision is a shared prerequisite because its concrete
constructor launches the real Codex executable. Pool and campaign checks still
apply to adapters configured for the campaign contract. Standalone calibration
allocates one thread and requires N1. The retired launcher remains a refusal when
all three decisions allow.

Structural and authority-only pool validation, activation key generation,
preparation, approval and dry runs remain available. Offline fake-only machinery
does not gain a production exemption: tests patch the necessary source decisions
inside their fixture lifetime while replacing model, process and RPC effects.
`tests/test_f5_native_live_holds.py` proves the default zero-launch refusals,
independent flag combinations, direct library and supplied-server refusals, and
fake positive controls. Registered N1/pool controls use the original factory,
host, ledger, artifact and validation machinery with fake process/OS effects.
`tests/test_r1_activation_preview_hold.py` additionally proves preview refusal
with shared flags on and its dedicated hold off, before input reads, server startup
and closure, plus controls with all required decisions patched on.

The historical transport extraction and archived source fixtures remain
historical records. Raw transport retains its source hold. Additional live
routes require their own qualification and operator decision.

## Historical campaign verification

The offline suite checks the pre-retirement launcher and its mocked refusals
with the matching source and tests at
`d0e2d682659fd724ddb9f50cd50beb6877fb1eda`. It checks the retired validator and
record witnesses at commit `a559a0bb2b9fc4e83b8acbef7b13b48172a47983`
(`v1.37.0`). The Generation 11 source digests are read from
`e7f540654e0ed605e4720bd4d3b670a11cb8f701`.

A full checkout must contain the named public objects. Source archives and
shallow checkouts run the current refusal and neutral Git-fixture checks. Exact
witnesses that need missing public objects are skipped in those checkouts. The
strict private-checkpoint verifier still requires its original objects. Neutral
fixtures only substantiate the observed structure and dispositions. Historical
verification grants no launch authority.

## Explicit launcher binding hold

The activation-preview launcher constructs bare `AppServer()`. The constructor
requires explicit executable and `CODEX_HOME` bindings or a verified capture
binding, in addition to the source holds and qualification requirements. The
legacy campaign launcher refuses before reaching server construction.

## Registered single-worker production

The original signed registered workflow can select `production_live: true`
for one worker and one session. Its operator execution adoption binds the exact
request and OpenAI provider disclosure. The app server uses a read-only checkout,
provider-only HTTPS relay and the original finite-tool profile. The finite command
and validator run in separate network namespaces. The host checks the selected
model, effort and default tier before submitting work.

The host checks the target and worker checkouts with complete inert captures.
Each capture allows up to 64 MiB of worktree data in total and up to 16 MiB per
file. The file count, walked entries, Git metadata, capture time and retained
records have their own limits. An incomplete capture prevents a new invocation.
After the finite command arrives, the registered production host allows 30
seconds for its checkout rechecks, execution and reply.

Call `adopt_execution` with `boundary` set to `provider-only`, `provider` set to
`openai`, and `request_sha256` set to the digest of the original rendered request
bytes. Set `allowed_effects` to `native-worker`, `provider-request` and
`target-publication` in that order. The production selector must agree in the
signed factory specification and the original whole-route admission.

Accept the installer's delegation setup prompt or pass `--setup-delegation`.
For an existing installation, run this command from the installed skill directory.

```bash
python3 scripts/setup_delegation.py
```

Setup uses the account's `.cwo-worker-codex` directory by default. Use
`--worker-home` to choose another dedicated directory and `--codex-home` to
identify a custom main Codex home to keep separate. Setup observes app-server
startup and cleanup in an isolated scratch home before using Codex device
sign-in with the file credential store. For this check put the standalone Codex
release's `bin` directory first on `PATH`. The isolated process mounts the
selected executable and system runtime. A package launcher that needs sibling
files can fail in that environment. The check sends no model task.

Setup checks the worker login permissions and lease, then saves the path as `worker_login_home` in
`../.cwo-host-state/<package>/worker-login.json`, relative to the skill root.

A registered single-worker controller can use the saved setting or supply
`worker_login_home` explicitly alongside its protected settings.

```python
controller = ControllerConfiguration(
    **protected_settings,
    worker_login_home=Path.home() / ".cwo-worker-codex",
)
```

The dedicated home keeps worker credential refreshes separate from interactive
Codex sessions and qualification campaigns. The controller refuses the default
primary home, its active `CODEX_HOME` if set, and all qualification login homes.
The worker home must be canonical, with mode `0700` and a mode `0600` `auth.json`
owned by the controller account. Keep this home dedicated to sign-in so the
operation's signed configuration and rollout paths can be mounted there.

The signed worker `config.toml` must set `cli_auth_credentials_store = "file"`
and include `"/cwo/managed-login" = "deny"` in its filesystem permissions table.
Only the app server receives the projection, and its atomic refresh persists in
the dedicated home. One app server per login can hold the interlock. The login
and the controller's `~/.local/state/cwo/registered-worker-logins` directory must
share an overlay-capable filesystem. Unknown cleanup keeps the lease held for
controller reconciliation.

Launch with `RegisteredN1Workflow.run()` after adopting execution. Missing or
unsafe worker login settings refuse before either signed operation is claimed.
Target publication still requires its original independent evidence and authority.

Live host qualification covered useful output, empty polling with zero stdin
delivery and observed progress, nonempty input refusal, an out-of-workspace
refusal before spawn, signed exhaustion, charges, archive and original cleanup.
Production admission and authentication isolation have offline witnesses.

### Standing-approved delegation

In the local `cwo-codex` session, use `cwo-delegation`'s
`authorize_assignment` tool for an open Bead with a requirement baseline.
Supply the exact task, baseline path, applied amendments in order if any,
and one project-relative output path with its exact UTF-8 text. Codex shows
the assignment, output, provider and budget in its foreground form. An
affirmative choice there allows the controller to retain that exact scope.
A matching retained approval is reused while its admission is current. If it
expires before any dispatch activity, use the same tool to approve a fresh
admission. Original dispatch activity keeps the existing recovery path.

The approval server is a child of the local Codex foreground process and uses
that process's private stdio pipes. The registered worker runs in separate
mount and process namespaces with only the registered finite tool surface.
The worker cannot access controller state or signing keys. Unrestricted
processes running as the controller account are part of the trusted host.

The protected controller retains an already approved `RegisteredN1Workflow`
with `registered_delegation_entry.retain_approved_assignment(workflow)`.
Pass `standing_delegation` as a `delegate_internal_work.StandingDelegation`
and `standing_directive` as the signed operator approval to
`ControllerConfiguration`. The controller signs the action digest from
`StandingDelegation.approval_scope` with `sign_controller_directive`, using
the original mission directive's digest as the parent. The same protected
controller can issue the directive when it accepts the lead's request under
the user's existing standing approval. That scope binds the
Bead, project database, baseline, exact admission, both preapproved operations
and OpenAI disclosure. The eligible route selects one `internal_worker`
assignment without a required pre-dispatch peer review. The controller holds
the signing key outside worker-visible roots and checks the dedicated login
before signing current dispatch authority or launching a worker.

After retention, run `cwo delegate --task <exact task> --baseline <file>
--summary <delivery note>` from the approved project checkout. The command
selects by the checkout, Beads database, Bead, exact task and resolved baseline.
It verifies the retained custody against a separate project key in the private
installation host store and checks the original approval again. It refuses a
missing or changed approval. The dedicated worker login supplies authentication.
The registered profile uses a finite writer bound to the approved output size
and digest.

The call checks the baseline reference on the open Bead, runs the registered
worker's original finite command, and posts its exact validated worktree
candidate for independent hand review. The registered worker receives a
read-only checkout and can invoke only the preapproved command and empty polls.
The host returns the arguments for the existing hand-close command. Keep the
original worker checkout available for review. When that checkout does not
resolve the project's Beads database, set the existing absolute `BEADS_DIR`
selector to the original project database for the host and the reviewer.
After an interrupted delivery write, the host can use `cwo delegate --resume`
with the original task, baseline and summary in the same checkout. The command
reopens the original protected configuration. Use the same CWO build that
prepared the assignment. Resumption requires signed
completed custody and unchanged admission accounting. An expired
dispatch admission permits only this completed-custody replay. An unknown or
unfinished worker attempt requires reconciliation.
[Hand acceptance procedure](run-readiness.md#accepting-a-delivery-by-hand).

## Registered single-worker host qualification

A trusted embedding controller prepares and signs one finite single-worker
operation for a disposable workspace. The qualification model selection binds
all roles in that operation to the same model, effort and service tier. The
factory verifies the exact thread identity before opening the turn and records
actual finite-input observations from the original app-server exchange and owned
tool pipe. The campaign allows 20 total starts. Each exact operation can start
once, and failed or uncertain starts consume the same allowance. Any signed
qualification operation can use an available start. A permit can include an
optional repair digest for provenance. The journal reports initial and recheck
counts alongside the total for audit.

Existing version 1 campaign journals and their prior starts carry forward in
place. Continue using the existing journal without re-enrollment. The controller
must issue version 2 permits before starting any remaining operations. Each
version 2 permit signs the exact operation, expiry, optional repair digest and
fixed campaign limit of 20.

The app server uses a host-owned relay for HTTPS to `api.openai.com` and
`chatgpt.com`. The relay checks the destination and TLS server name and records
rejected requests. TLS passes through encrypted. Finite command and validator
processes run in separate network namespaces. Qualification output stays in
disposable custody and production dispatch continues to require its own source
decision.

The controller can select a dedicated Codex file login by passing
`managed_login=True` to `bind_model_selection` before signing the operation.
Its registered configuration selects `cli_auth_credentials_store = "file"`
and denies tool access to `/cwo/managed-login`. The app server sees that path
as `CODEX_HOME`. It maps to the `.cwo-qual-codex` directory in the controller
account's passwd home, with an owner-private directory and `auth.json`. Codex
reads and refreshes the file in its namespace. The controller checks metadata
and sends no authentication token. The signed config and active and archived
rollouts use the original operation spool. Finite command and validator
namespaces exclude the login. Linux and Bubblewrap must support a writable
overlay on the dedicated login filesystem. Mount setup and verification occur
before the launch is charged. An unresolved mount leaves the private campaign
interlock held for controller reconciliation.

The controller can separately supply a provisioned Codex personal access
token through `RegisteredN1Factory.run(provider_access_token=...)`. The signed
qualification launch delivers it through a private pipe. The app-server
bootstrap closes the pipe before passing the token to Codex as
`CODEX_ACCESS_TOKEN`. The controller supplies and manages that credential.
The provider broker adds `auth.openai.com:443` for either authentication mode,
with matching CONNECT authority and TLS server name. See the
[Codex access token documentation](https://learn.chatgpt.com/docs/enterprise/access-tokens).
