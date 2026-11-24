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

## Historical share consent fixtures

Separate create-share authorization requires fresh consent from the original
registered parent. Consent binds its frozen source, candidate or packet inputs,
prepared request, intended purpose, document and conversation identity, complete
ordered history including the generated response, and exact final disclosure
bytes. Decoded conversation content and the final representation pass outbound
screening at consent and again before creation. Unknown coverage refuses.

Consent is an opaque, expiring object that can authorize only one original share
ticket. Its lifetime cannot exceed the original action timeout; an earlier
requested expiry still applies. Copies, foreign consent, replay and changed
source, options, document, conversation or content refuse before the next effect.
Sharing consumes a separate one-use execution admission within the original
aggregate budget. Configuration alone cannot grant consent.

Registered offline fixtures can declare complete coverage and exercise the
separate consumer for explicit plaintext disclosures. Unrepresented media,
attachments, embedded documents and rich markup refuse complete coverage.
Plaintext wrappers permit only pre-wrap whitespace formatting; additional inline
style properties refuse coverage.
The supported fixture boundary pins the original document
and its root, checks the current URL and exact disclosure, then clicks once in
one synchronous browser operation. It validates a result URL against an observed
document, conversation and action binding. A known stale result refuses before
creation. A wrong result discovered after creation leaves an unknown outcome
and conservative reservation accounting; it cannot undo that creation. No
legacy share, social or clipboard fallback follows a refusal.

The CDP Send and share routes remain held. These fixtures exercise checks on
saved or simulated browser content.
