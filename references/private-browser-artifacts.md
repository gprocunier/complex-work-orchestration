# Saved private browser returns

For the current copied-reply workflow, see
[ChatGPT Pro review in desktop Chrome](chatgpt-pro-browser.md). The verification
steps below apply to saved private captures from the earlier CDP browser route.

## Ingest a saved capture

A complete capture binds the packet, frozen screened request, observed
conversation and messages, and exact response bytes. A candidate review also
binds the named candidate and verifies its current repository contents.

The provenance record contains identifiers and digests. The response text
stays in a separate owner-only file. Partial captures remain available for
diagnosis. Ingestion requires a complete capture.

Ingestion needs the current original packet, its saved packet-source digest and
the exact dispatch event hash returned with the private-artifact reference. The
event is read from the configured audit store and pins the raw provenance-file
digest before response content is read. Values copied from the artifact being
checked do not supply independent expectations. A changed packet, source,
candidate, request, conversation, message or response refuses.

For an artifact whose independent references are already available:

```bash
python scripts/ingest_chatgpt_share_return.py \
  --private-artifact private/review.provenance.json \
  --packet private/packet.json \
  --packet-source-sha256 "$PACKET_SOURCE_SHA256" \
  --capture-event "$CAPTURE_EVENT_HASH" \
  --output private/review-return.md --json
```

A candidate-bound packet also requires its private candidate record and current
repository through `--candidate` and `--candidate-root`. Stdout and refusal
diagnostics report metadata. The requested contractor-return file contains the
evidence text for evaluation. Preserve older provenance versions as recorded.

## Evaluate a saved capture

When the host audit store already contains the dispatch and its completed
private capture, evaluate the reply with the original packet and provenance
file.

```bash
python scripts/cwo.py evaluate \
  --private-artifact private/review.provenance.json \
  --contractor-packet private/packet.json --json
```

Evaluation gets the packet-source digest and capture-event hash from the
original dispatch. If you supply either `--packet-source-sha256` or
`--capture-event`, match the value in the host record. The evaluator checks the
screened request and captured turn against that record, then records the response
digest, score and review status.

Verification assumes control of both the artifacts and audit store. A process
with the same user's access can write both. Keep the independently selected
references outside the returned artifact.

## Historical implementation

Release [v1.37.0](https://github.com/gprocunier/complex-work-orchestration/tree/v1.37.0)
contains the retired CDP transport, launcher, share consent and share-reader
code alongside their matching offline tests and fixtures. The current intake
tests load a [saved v5 capture](../tests/fixtures/browser-capture-v5/) generated
with the tagged implementation and a simulated document.
