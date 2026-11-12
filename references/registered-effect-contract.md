# Registered worker effect contract

The registered worker must preserve its selected profile after useful work,
ordinary errors and denied effects. Offline tests exercise the direct
`RegisteredN1Factory.run` consumer through `RegisteredN1Factory._effect`,
`OfflineN1Host.run_registered`, `RegisteredServerRequests`, and the registered
transport adapters. They use a fake RPC child and real consumer code.

`FactoryTests.test_original_registered_useful_then_forbidden_effect_matrix` in
`tests/test_registered_n1_factory.py` first produces useful output with a tool
receipt, then sends correlated requests on the same thread, turn, connection
and profile. Each request follows its predecessor's reply.

| Follow-up | Request field | Required response |
| --- | --- | --- |
| Write | `item/fileChange/requestApproval`, `grantRoot` | `decline` |
| Network | `item/permissions/requestApproval`, `permissions.network.enabled=true` | empty `permissions` |
| Process | `item/commandExecution/requestApproval`, different `command` | `decline` |
| Confidential read | command approval for a prohibited read | `decline` |
| Ordinary retry after denied read | same prohibited command and ordinary `reason` | `decline` |
| Explicit escalation | useful command plus `additionalPermissions.fileSystem.read` and a typed read action | `decline` |

The denied read produces an ordinary fake OS error. Retry and escalation use
the same reason text, so typed additional permissions must independently cause
refusal. Tests retain the refusal records and transport observations, and use
positive-control spies to establish that all forbidden effect counters stay
zero. They also check one turn and child, unchanged profile, useful output
bytes, validated artifact, retained charge, and no fallback or second dispatch.

Keep pre-useful denial, standalone effect-runner, and consent/publication
controls separate: they cover distinct entry points and ordering. Fake
transport observations establish cooperative consumer behavior. They do not
qualify provider containment, physical isolation, a live runtime or a
confidentiality profile. Protocol pins alone do not establish containment.
