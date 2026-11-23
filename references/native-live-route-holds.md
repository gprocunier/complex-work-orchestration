# Native live route holds

`scripts/cwo_core/native_live_availability.py` supplies three independent source
decisions, all shipped as `False`: `N1_LIVE_AVAILABLE`, `POOL_LIVE_AVAILABLE`,
and `CAMPAIGN_LIVE_AVAILABLE`. They are not read from a plan, environment,
constructor enable switch, approval file or CLI option. The activation preview
also retains its own default-off `LIVE_ACTIVATION_AVAILABLE` decision in
`run_native_pool_activation_preview.py`. Its accepted-child close route uses pool
receipts and is held independently by `LIVE_ACTIVATION_AVAILABLE` and the selected
N1/pool holds. It is not constrained by production verified acceptance today;
restoring N1/pool alone cannot restore the preview. Any future restoration must
resolve that separate closure contract before claiming verified acceptance.
No route is restored or live qualification claimed.

| Route | Required source decisions | Enforcement before effects |
| --- | --- | --- |
| Production N1 | `N1_LIVE_AVAILABLE` | Raw `AppServer` construction and its adjacent `Popen`; registered workflow `run`, factory `run`/`require_effect`, and containment `launch`; maintenance runtime `prepare`; admitted v8 loader before operation claim. |
| N1 host qualification | Signed qualification permit | The protected controller binds one exact operation and expiry. The factory charges the launch to a private campaign journal before releasing the app-server command. |
| Native surface probe and qualification | `N1_LIVE_AVAILABLE` | `capture_tool_request` refuses before capture binding or listener startup; its CLI refuses before catalog/evidence writes. `observe_qualification` verifies the original opaque operation, then refuses before qualification output/intent creation. |
| Registered pool and retry | `N1_LIVE_AVAILABLE` and `POOL_LIVE_AVAILABLE` | Pool host execute entry and each member, plus approved retry entry and effect. `PoolConfiguration.enabled=True` cannot replace either source decision. |
| Activation preview | Dedicated `LIVE_ACTIVATION_AVAILABLE` plus N1 for `n1-read-only` and `n1-mutable`; additionally pool for `n2-read-only` | Run entry checks the dedicated hold and N1 before loading inputs; the loaded profile is checked before claims, ledger creation, reservation or launch. Server creation, ledger transport RPC entry points, worker-contract allocation and accepted-child closure recheck the dedicated hold and selected profile. |
| Campaign | N1, pool and campaign | Main entry, preclaim validation, global claim acquisition, server construction, `build_pool_inputs` and `run_pool_canary`. A supplied server or a pre-move validator tree cannot replace a held source decision. |
| Admitted v8 multiworker plan | N1 and pool | The loader checks the actual child count before consuming the verified operation or importing its runtime adapter. The concrete installed maintenance runtime supports exactly one worker child and one precommit session; it does not implement a multiworker maintenance cohort. |

The raw transport's N1 decision is a shared prerequisite because its concrete
constructor launches the real Codex executable. Pool and campaign checks remain
necessary under a partial future restoration where N1 is available. Standalone
calibration allocates one thread and requires N1; campaign pool helpers require
all three decisions. Existing validator-tree, admission, approval, custody,
configuration and finite resource checks remain additional requirements.

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
historical records. The current raw transport deliberately adds the default-off launch
hold after that extraction; it no longer claims historical byte identity.
Restoration remains an operator decision with the separately required live
qualification and deployment review. These flags themselves do not validate a
live qualification record.

## Explicit launcher binding hold

The activation-preview launcher and campaign launcher still construct bare
`AppServer()`. With explicit launcher binding this always refuses, including when every availability
flag is patched on. Their routes remain unavailable. Any later restoration must
supply explicit executable and `CODEX_HOME` bindings, or a verified capture
binding, through the constructor contract and satisfy all existing source
holds and qualification requirements. This change documents that refusal; it
restores no route.

## Registered single-worker host qualification

A trusted embedding controller prepares and signs one finite single-worker
operation for a disposable workspace. The qualification model selection binds
all roles in that operation to the same model, effort and service tier. The
factory verifies the exact thread identity before opening the turn and records
actual finite-input observations from the original app-server exchange and owned
tool pipe. The private campaign journal allows ten initial starts and up to five
signed rechecks after a repair. Failed starts consume the same allowance.

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
