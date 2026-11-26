# Saved v5 private browser capture

Generated offline at tag `v1.37.0` (commit
`a559a0bb2b9fc4e83b8acbef7b13b48172a47983`) using a simulated two-message
document and a synthetic packet. The retired capture, response writer and audit
writer produced the original provenance and audit bytes. The original host
store produced the checkpoint and the prepared and observed dispatch records.
The observed dispatch pins the exact capture event independently of the
provenance file.

The tagged functions used were `prepare_browser_packet_request` with the
relative path `packet.json` and request ID of 32 ones, the capture method
`_capture_assistant_response` with a fixed snapshot for `conv-0001`,
`write_private_response` with the names in the provenance, and
`record_browser_dispatch`. The capture used a confirmed model attestation,
a synthetic admission digest of 64 lowercase d characters, and a clock fixed
at 2026-11-14 00:00 UTC.

The response uses base64 to preserve its exact UTF-8 bytes, CRLF and trailing
spaces through Git checkout. Both private-artifact commands consume the
fixture through temporary owner-only files and the ordinary host audit reader.
