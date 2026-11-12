# Claims register

This register maps CWO's consequential safety claims to the mechanism that backs
them and the limit of that mechanism. Public copy should not claim more than the
"what it does" column. The public-copy validator rejects the retired wordings
listed at the end.

| Claim area | What it does | What it does not do | Evidence |
| --- | --- | --- | --- |
| Helper gates (packet validation, closure checks, dispatch checks) | Refuse when the helper is invoked and its inputs fail | Stop a lead that skips the helper or writes its inputs. These gates are cooperative | Helper source and tests |
| Native supervision checks | Classify the worker's recorded activity when the lead runs the check and acts on its exit code | Poll, interrupt or contain a worker on their own. No shipped component enforces the cadence | `scripts/supervise_native_worker.py` |
| Execution boundary | Whatever sandbox and approval policy the host is configured with | Add a boundary of its own. A lead launched with Codex `--yolo` has Codex sandboxing and approval checks disabled, and CWO supplies no independent boundary in their place; only restrictions imposed outside Codex, such as a container, still apply | Host configuration |
| Content digests and packet `attestation` fields | Identify exact bytes so later changes are visible | Authenticate who produced or approved the bytes. The packet `attestation` value is an unkeyed self-hash | `scripts/cwo_core/packets.py` |
| Audit hash chain (configured host) | Check retained event digests and links against a private head checkpoint and ordered segment seals; refuse missing or truncated history inconsistent with the retained checkpoint | Prevent a same-account writer from erasing state or rewriting and rehashing the chain and checkpoint, authenticate the operator, or supply an external anchor | `scripts/cwo_core/audit.py` (`verify_audit_log`), `host_records.py` (`audit_events`), `audit_segments.py` (`verify_checkpoint`) |
| Custom legacy diagnostic audit logs | Check retained event digests and links when the legacy verifier is invoked | Detect deleted trailing events or an emptied log without an expected head/count; provide host authority, operator authentication or protection against same-writer rewriting | `scripts/cwo_core/audit.py` (non-configured-file branch of `verify_audit_log`) |
| Signed activation-preview approvals | Bind an approval to exact fields with HMAC | Authenticate the operator against the lead: the key is a 0600 file in an owner-private control root that the same Unix user can read | `scripts/cwo_core/native_activation_preview.py` |
| Signed maintenance approvals | Bind an approval to exact fields with HMAC, verified with a key the embedding controller supplies | Establish key custody: no embedding controller ships, so who holds the key, and whether the lead can read it, is undefined | `scripts/cwo_core/maintenance_authority.py` |
| Concurrent native pool contract | Validate artifacts and refuse unavailable execution; maintenance (version 8) also requires explicit capabilities | Enable live execution. Registered single-worker, pool and campaign routes have default-off source holds; ordinary productive plans additionally lack a shipped trusted controller, including for `--validate-only` | `scripts/cwo_core/native_live_availability.py`, `scripts/run_admitted_native_pool_transaction.py` and their tests |
| Stale-agent cleanup | Detect stale registry entries and recognized agent processes, and prune registry records with no live PID (missing, invalid or exited) unless run with `--dry-run` or `--no-prune-state` | Terminate any process. Termination requests report unavailable | `scripts/cleanup_stale_agents.py` |
| Operator prompt qualification | The archived v5 prompt was selected in a local comparison | Qualify the active prompt bytes; no new comparison has been run, and raw traces are not published | `references/candidate-e-qualification-summary.md` |

## Retired wordings

These phrasings overstated a mechanism and must not return to public copy. The
public-copy validator is a heuristic check for them. Besides reading the copy
roughly as a reader sees it, with `details` elements open and closed and with
images loaded and broken, it reads the source with markup replaced by spaces,
attribute values and comments included. It can therefore report a phrase no
reader would see, for example one split across two attribute values; reword the
copy in that case. It also asks for rewording when it finds markup it
recognizes but does not read, for example a hidden element holding other
markup, elements such as `noscript` or `dialog` whose content shows only in
some states, unrecognized attributes or inline styles, a link reference
definition spanning lines, and invisible or look-alike characters. It does not
model all of CommonMark and HTML, and it does not evaluate stylesheets,
scripts, fonts or text drawn inside images, so it can miss a phrase hidden in
ways it does not recognize. Copy must not rely on those to hide or split words.

- "hashes make tampering detectable" (too broad: configured host verification
  also checks retained history against a checkpoint and segment seals, while
  legacy diagnostics lack that checkpoint; same-writer rewriting remains possible)
- "provide tamper-evident detection" (same limits; the term is acceptable only
  when tied to retained digests/checkpoints and the same-writer limitation)
- "Native productive work uses the admitted version-2 pool launcher" (the
  launcher refuses ordinary plans without a trusted controller)
