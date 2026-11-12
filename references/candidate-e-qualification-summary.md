# Candidate E qualification summary

This is the compact publication record for the repository's Candidate E
operator-profile decision. It reports the accepted result and its limits; it
does not publish machine-local traces, private work packets, or raw campaign
state.

## Decision

The final no-retry C/E/F matrix recorded equal completion, safety, recovery,
handoff, and process results for all three arms. Candidate E used the fewest
recorded tokens and the least wall time, so it became the default architect
contract for substantive CWO work. Candidate C remains an opt-in compatibility
profile.

This is a scoped repository decision. It is not a universal model or prompt
ranking, and it does not claim that Candidate E was safer than C or F.

## Bound artifacts

| Artifact | SHA-256 | Status |
| --- | --- | --- |
| `prompts/archive/cwo-sol-operator-e-v5-qualified.md` | `75b3bdf7624d7e3913f2879f4a20306c74805ad8409ce785597da67e1011c3f8` | Exact prompt evaluated in the final v5 matrix |
| `prompts/cwo-sol-operator-e.md` | `78a322fe1b5e72ba7f1d1a4253230f90fef37a372ed1334ec00c1e20647874b8` | Active prompt: post-v5 repair, scoped continuation and issue #44 wording |

Earlier bytes of the active prompt, kept for reference only:

| Revision | SHA-256 |
| --- | --- |
| Post-v5 repair | `ce85010acb60ea9fafd81f84790524a86f685067b65f86c352e07a5d3367ef67` |
| Scoped-continuation update | `82fdd0a53aa188cfa5779950cd32d6f7d7b9fa2c4dac3af1c72480a75548f22d` |

The issue #44 revision rewords two passages so they name the permitted action
directly: an alternative workflow is used only when the applicable CWO contract
already authorizes it, and provider safeguards, security and access gates,
required validation and frozen protocol bindings are not optional. Authority,
security and frozen-protocol boundaries are unchanged. Whether the wording
affects provider safety stops is unknown; no controlled comparison was run.

Automated profile tests bind the archived v5 hash and the active hash.
Installation and verification bind the active prompt bytes to the named
`cwo-sol-operator-e` profile without changing ordinary Codex sessions. An
installed profile from earlier bytes fails verification until it is reinstalled.

## Repair boundary

After v5, an operator substituted a new benchmark for an already-frozen
controller during continuation. The active prompt and the stdlib-only frozen
protocol helper now make benchmark, task-family, controller, and run-shape
bindings explicit; steering cannot replace them. An authorized replacement
requires a new lock.

Deterministic regressions validate that repair. No new model comparison has
qualified the repaired active prompt bytes. The archived v5 prompt therefore
supports the selection decision, while the active prompt is separately labeled
as repaired and deterministically validated.

## Publication boundary

The public baseline includes the two prompt artifacts, named-profile manager,
fresh-session launcher, frozen-protocol schemas and validator, operator guides,
and deterministic tests. Raw evaluation traces and local audit state are not
part of the portable package. Reproduction claims should bind the exact prompt
hash and protocol lock rather than infer equivalence from the Candidate E name.
