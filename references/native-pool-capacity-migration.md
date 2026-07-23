# Pool Capacity Naming Migration

`policy/native-worker-execution.yaml` is the only operative source for native
pool capacity. Its `native_supervision_pool.capacity` object separates three
different limits:

| Canonical field | Meaning | Current value |
| --- | --- | --- |
| `default_max_active_workers` | Capacity used without concurrency opt-in | `1` |
| `released_max_active_workers` | Highest capacity an operative launch may use | `2` |
| `hard_max_active_workers` | Highest capacity represented by current schemas and runtime | `3` |

Changing a limit requires one policy edit followed by
`python scripts/sync_native_pool_capacity.py --write`; repository validation
then rejects any schema or active-source drift. Raising the released limit also
requires the separately recorded operator activation. A hard or schema ceiling
never authorizes dispatch by itself.

## Naming inventory

| Retired active name | Canonical replacement | Compatibility status |
| --- | --- | --- |
| `cap_two_enabled_by_default` | `capacity.concurrency_enabled_by_default` | No new writes |
| `cap_two_requires_explicit_opt_in` | `capacity.requires_explicit_opt_in` | No new writes |
| `cap_two_requires_fresh_capability` | `capacity.requires_fresh_capability_receipt` | No new writes |
| `cap_two_operative_release` | `capacity.released_max_active_workers` | Frozen campaign reads only |
| `MAX_ACTIVE_WORKERS` | `load_pool_capacity().hard_max_active_workers` | Removed |
| `nonpreemptive-edf-cap2-v1` | `nonpreemptive-edf-generalized-v2` | Frozen receipt reads only |

Historical capacity-two campaign manifests and callback receipts remain
readable through `native_pool_capacity_compat.py` for one minor-release
deprecation window. They cannot authorize a new pool contract, expand released
capacity, or be emitted as a new operative pool artifact.
