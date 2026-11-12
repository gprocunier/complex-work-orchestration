# Compact release route inventory

`policy/release-effect-routes.json` records supported entrypoints, guarded
effects, exact gate statements, refusal assertions and matched positive controls.
An entry names the effect that must remain zero; earlier inspection, lifecycle,
private preparation or containment effects can be legitimate. Generic operator
programs retain their selected arguments, environment and downstream limits.
Native holds do not become universal Beads or operator command authorization.

Shared contracts, source points and witnesses avoid repeating the same data for
entry aliases. Point arrays store a file index plus either symbol/line/raw-body
digest or line/exact source text. These are explicit references, with no inferred
call resolution. A raw declaration digest uses source bytes, with no AST dump ABI.
Existing declaration and line/text points retain their semantics. An exact text
span can additionally select UTF-8 byte columns with `col`, `end_line` and
`end_col`; its compact point is `[file_index, line, text, col, end_line, end_col]`.
This represents assigned, nested and multiline calls without treating an entire
statement or nearby gate as that primitive.
The compact inventory has a finite 512 KiB (524,288 byte) limit. Complete script bindings and individual primitive dispositions share this
capacity; source/file/count bounds and deadlines remain finite. Full traces, graphs and intermediates stay
external; compression is not a substitute for compact authored installed data.

The inventory is authored decision data. Every route has an explicit manual
conclusion and limits. Neither its presence nor a matching source hash approves
that conclusion. Constructors, virtual calls, callbacks, context entry, dynamic
imports and other constructed calls are reviewed against their actual supported
selection. The tracer never marks unknown code safe. It uses conservative
file-local alias unions within declared primitive families; they can produce
false positives and are not whole-program receiver or control-flow resolution.

Every current `scripts/` file must appear in `source_bindings`, including benign
files and the checker itself. Added, removed, changed or unbound scripts refuse.
The bounded Python classifier covers process creation (`subprocess`, `os` exec/
spawn), socket/HTTP constructors and requests, Playwright entry/method candidates,
AppServer constructors/RPC candidates, Beads helpers, and `shutil` copy/move calls.
All copies are candidates; destination safety remains a manual decision. Imported
aliases, simple assigned aliases, literal `importlib` and `getattr` expressions
are resolved within these families. Alias unions preserve possible effects across
reassignments. Declared method candidates survive constructed receivers such as
`page.locator(...).first.click()` and `super().request(...)`. Attribute/call/
subscript wrappers and literal list/tuple/dict value unions conservatively retain
possible declared namespaces; they do not establish a wrapper's actual return
type or choose a runtime key/index. Assigned methods and literal `getattr` use the
same rule. Unknown receivers retain only the explicitly declared method families;
unknown targets outside those families remain external review scope. A missing classifier hit cannot be excused by an exclusion. Resolution retains
the existing eight alias passes and twelve expression levels. A chain
that exceeds the alias budget refuses. Unknown imports/getattr targets and other
unresolved dynamic call candidates require individual named exclusions. This
finite classifier does not detect arbitrary reflection, generated code, arbitrary
wrapper calls or shell command semantics. Shell lines remain lexical evidence for
external review; their files still require complete byte/mode bindings.

`primitive_coverage` uses schema `bounded-primitives-v1`. Each `hits` row is
`[path, line, col, end_line, end_col, family, sha256, disposition]`; its hash binds
the exact UTF-8 call bytes. The observed and authored hit sets must match exactly,
without duplicate, missing, stale or extra rows. A disposition is either
`["route", route_id, point_key]`, selecting an exact effect point of that route,
or `["exclude", exclusion_id]`. Expanded EXAMPLE routes may supply the effect
point dict directly. Mapped points must equal the complete classified call span.
Each exclusion is used once and supplies a nonempty `reason` and `conclusion`,
optionally naming an existing route. Thus its name and decision bind one specific
source span, never a file-wide exemption. Orphan/duplicate/unknown exclusions
refuse. Dynamic-family candidates can only be excluded individually; a route name
does not resolve their unknown target. These manual dispositions remain review
trust, not evidence that an effect is unreachable or authorized.

Gate points are checked against the complete bounded Python AST. They must
anchor a conditional header/predicate, a Raise statement, or an exact reviewed
guard/validator call. Direct assigned validator results are supported; ordinary
assignments, declarations, message fragments, context/lock entry and constructor
keywords are not guards. The finite dotted-callee list is in the checker; a
`require_*` suffix or caller-authored policy cannot add a guard family. Literal
constant conditions refuse. Existing line/prefix points bind the complete AST
payload, while exact column points can select a full conditional predicate.

Canonical guard/effect intervals use UTF-8 byte offsets with an excluded end.
Conditional suites are outside their header interval. Explicit effect columns
stay exact; line/prefix effect points resolve to their enclosing call span where
present. Any nonempty intersection with an authored effect point (even another
key/route), classified primitive, or the named durable `capability.claim` call
refuses. Claims and reservation/context/read ordering remain distinct manual
facts; an earlier durable effect cannot serve as its own admission gate.

Shell guards use a finite exact set of current installer and Chrome refusal/dry
predicates, anchored to whole source lines. Ordinary/ANSI quoted strings,
here-documents and continued commands cannot present their contents as guards;
unsupported here-document forms refuse. This is bounded lexical context, not a
general Bash parser, expansion evaluator or control-flow proof. Unknown selected
forms refuse; external review still checks the complete shell programme.

These checks establish source form and interval consistency. They cannot prove
predicate correctness, runtime dominance, callback identity or refusal causality.
The named functioning witnesses and independent semantic review remain required.

Release review combines the effect-path trace, milestone assessment, actual
platform gates and semantic fault witnesses. The trace checker alone does not
establish release readiness. A changed guard requires an actual refusal witness,
a matched positive control and restored source; hashes or printed fault names
are not fault catches. Full traces, fault logs and release decisions stay outside
the product. Gate records do not enable held effects.

Milestone assessment: M1a has 62 met, 17 partial, 2 held and 0 unverified clauses;
M1a is incomplete. M2 applies and is incomplete. This inventory does not change
those results.

From the source checkout, generate evidence outside the product:

```sh
python -B scripts/check_release_effect_routes.py --generate-trace --evidence-dir /workspace/evidence/release-routes
python -B scripts/check_release_effect_routes.py --evidence-dir /workspace/evidence/release-routes --review selected-review.json --review-sha256 SELECTED_SHA256
```

The first command is an explicit evidence step. It reads bounded regular source
files without importing inventoried modules, binds exact bytes and modes, and
retains lexical calls/imports, shell lines and classified per-hit dispositions. The full trace and index must stay
outside the product checkout.
The second command regenerates that trace and compares exact source, inventory,
declaration, gate, witness, trace and selected-review identities. Both commands
refuse stale source; no normal product runtime loads the full trace.

The selected review uses `release-route-review-v1`, role `independent-reviewer`,
an explicit reviewer, `ACCEPT`, and exact source, inventory and trace hashes.
Its decisions must cover every inventory route exactly, with matching decision
hashes and a semantic conclusion. Each named witness has a matching body hash,
source hash, the witness kind's semantic selection and selected
receipt/log paths and hashes. Paths are relative to the evidence directory.
The existing recorder's complete zero-exit receipt must match its actual raw log.
Named success records accept verbose unittest output with the description read
from that exact test declaration, including its normal second-line form.
The independent reviewer checks that the named test passed, that the selected
assertion was reached, that the positive worked, and that the receipt really
belongs to this source. The checker does not infer those semantics from a green
exit or a method name. JSON selection is external review trust, not authentication
of people, independent origin or protection from an unrestricted same-user writer.
`zero-effect-refusal`, `matched-positive`, `operator-contract` and
`inspection-only` witnesses retain different credit. A manual programme entry
does not inherit another entry's zero-effect assertion. In particular raw Beads
argv, direct socket helpers, operator launchers and dormant share helpers have
explicit selection or exclusion limits; no universal native hold is invented.

All custody files are re-read after source/review comparison. Files, bytes and
directory entries can still change and revert between observations; this is a
bounded retrospective check, not an atomic snapshot or operating-system sandbox.
The trace is lexical evidence for the manual audit, not full-program resolution
or proof that arbitrary external programs have no additional effects.

`tests.test_release_effect_routes` supplies functioning EXAMPLE-only acceptance,
executed fake-effect refusal/positive pairs and stale/unrelated/missing/mismapped
input cases. Coherently rebound primitive fixtures exercise direct, aliased,
importlib/getattr calls and exact mapped/excluded positives without stale-file
checks masking classifier failures. Capacity tests load valid data above the old
cap and at 512 KiB, then refuse cap+1. No actual author approval is supplied. Without an explicitly
selected independent acceptance the real CLI refuses release trace completion.
Selected bounded completion still leaves milestone, platform and safety-slice
work as separate obligations.

The actual installer copies `check_installed_skill.py --list-files` from
`policy/install-projection.yaml`; its source-tree enumeration excludes Python
caches. Only the compact inventory and small source helpers belong in that
projection. Full trace data, raw evidence, indexes and intermediate artifacts
must never be created inside it. Projection evidence uses harmless disposable
copies and installer dry-run, with no activation.
