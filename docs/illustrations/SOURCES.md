# Diagram and logo sources

`connected-ecosystem.svg` shows planning and review relationships;
`supervised-delegation.svg` expands native task execution. Both are authored
conceptual diagrams, not execution records, model recommendations or grants to
run workers. Native supervision, contractor review and local-model review have
different capability and permission contracts.

Brand marks retain their original bytes, colors and proportions and identify
their respective owners; no endorsement is implied. `sources.json` records each
primary asset URL or source page and its SHA-256 hash, plus the complete diagram
hashes. Marks are embedded so rendering does not contact provider sites.

The supervision content follows `native-supervision.html`, the current native
supervision references and the active policy. Registered single-worker, pool
and campaign live routes have default-off source holds. The diagram describes
the held contract: one worker is the default topology, and concurrent groups
require opt-in, fresh host qualification and a maximum of three. Those contract
requirements cannot restore execution. Instructions and detection are not
guarantees of prevention.

The Review highlight and zero-trust disclosure are HTML/CSS progressive
enhancements. The source SVG geometry remains unchanged; a native disclosure
provides keyboard, touch and no-JavaScript access to the same explanation.

## Light and dark appearance

All diagrams follow the page color scheme, including an explicit theme selection.
The theme generator adds only palette CSS to the two authored illustrations;
it preserves their source geometry, labels, connectors and embedded brand payloads.
Logo tiles retain their original backgrounds so the marks are never inverted.
`original_illustrations` in `sources.json` seals the current unthemed source
bytes, including the live-hold wording; the regular
diagram hashes include the palette styles. Regenerate with
`python scripts/generate_diagram_themes.py --write` and check with `--check`.
The responsive flowcharts use the same mechanism via `generate_diagrams.py`.
