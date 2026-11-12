# Native live route holds

`scripts/cwo_core/native_live_availability.py` supplies three independent source
decisions, all shipped as `False`: `N1_LIVE_AVAILABLE`, `POOL_LIVE_AVAILABLE`,
and `CAMPAIGN_LIVE_AVAILABLE`. They are not read from a plan, environment,
constructor enable switch, approval file or CLI option. The activation preview
also retains its own default-off `LIVE_ACTIVATION_AVAILABLE` decision in
`run_native_pool_activation_preview.py`. The production closure gate and verified
host acceptance/database identity requirements remain additional constraints;
restoring N1/pool alone cannot restore the preview.
No route is restored or live qualification claimed.

| Route | Required source decisions | Enforcement before effects |
| --- | --- | --- |
| N1 | `N1_LIVE_AVAILABLE` | Raw `AppServer` construction and its adjacent `Popen`; registered workflow `run`, factory `run`/`require_effect`, and each containment `launch`; maintenance runtime `prepare`; admitted v8 loader before operation claim. |
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
