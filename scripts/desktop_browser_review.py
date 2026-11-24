#!/usr/bin/env python3
"""Prepare a screened request and receive the reply copied from desktop Chrome."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys

from browser_request import EXECUTOR_KEY, REQUEST_ID_RE, prepare_browser_packet_request
from cwo_core.audit import enforce_contracting_quota
from cwo_core.browser_provenance import candidate_context, packet_subject
from cwo_core.errors import CWOPolicyError
from cwo_core.host_records import DESKTOP_BROWSER_CAPTURE, DESKTOP_BROWSER_HANDOFF, HostRecordError, configured_store
from cwo_core.host_return_intake import MAX_RETURN_BYTES
from cwo_core.outbound_screen import require_clean
from cwo_core.packet_provenance import require_production_contractor_packet
from cwo_core.private_artifact import PrivateArtifactError, PrivateDirectory, sha256_bytes
from generate_manual_dispatch_prompt import load_packet_file


def _is_desktop_preparation(dispatch):
    return dispatch["evaluation_metadata"].get("browser_handoff") == DESKTOP_BROWSER_HANDOFF


def _find_dispatch(store, packet):
    dispatch_id = packet.get("dispatch_id")
    if store.find("dispatch", dispatch_id=dispatch_id):
        return store.require_dispatch(dispatch_id)
    return None


def require_desktop_reply_source(packet):
    if packet.get("executor") == EXECUTOR_KEY:
        dispatch = _find_dispatch(configured_store(), packet)
        if dispatch and _is_desktop_preparation(dispatch):
            raise SystemExit("a prepared desktop browser return requires --browser-reply")


def _resume_request(path, dispatch, request_id):
    metadata = dispatch["evaluation_metadata"]
    if not _is_desktop_preparation(dispatch) or request_id != metadata.get("request_id"):
        raise SystemExit("request ID does not match the recorded browser preparation")
    request = prepare_browser_packet_request(path, request_id=request_id)
    pinned = (dispatch["dispatch_id"], dispatch["packet_sha256"], dispatch["request_sha256"],
              metadata["packet_source_sha256"], metadata["outbound_prepared_sha256"])
    current = (request.metadata["dispatch_id"], request.metadata["packet_sha256"], request.outbound.payload.sha256,
               request.packet_source.sha256, request.outbound.sha256)
    if current != pinned:
        raise SystemExit("packet does not match the recorded browser preparation")
    return request


def prepare_desktop_request(path):
    store = configured_store()
    path = Path(path).expanduser().resolve()
    dispatch = _find_dispatch(store, load_packet_file(str(path)))
    if dispatch:
        request = _resume_request(path, dispatch, dispatch["evaluation_metadata"].get("request_id"))
    else:
        request = prepare_browser_packet_request(path)
        metadata = request.metadata
        enforce_contracting_quota(metadata["epic_id"], EXECUTOR_KEY, "external-contract",
                                  dispatch_id=metadata["dispatch_id"], packet_sha256=metadata["packet_sha256"])
        request.record_dispatch(desktop=True)
    return request.require_unchanged()


def _read_copied_reply(path):
    try:
        descriptor = os.open(Path(path).expanduser(), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise SystemExit("--browser-reply requires a regular file")
            raw = stream.read(MAX_RETURN_BYTES + 1)
        if len(raw) > MAX_RETURN_BYTES or not raw.decode("utf-8").strip():
            raise SystemExit("--browser-reply requires a nonempty UTF-8 reply within the host intake limit")
    except (OSError, UnicodeError):
        raise SystemExit("--browser-reply is unreadable or is not UTF-8") from None
    return raw


def desktop_evaluation_input(args):
    """Match the packet and sender-observed request ID before reading the reply."""
    label = args.model_label.strip() if args.model_label else ""
    if not label or len(label) > 256 or not label.isprintable():
        raise SystemExit("--browser-reply requires a sender-confirmed --model-label from the model picker")
    require_clean(label, surface="ChatGPT model picker label")
    request_id = args.request_id
    if not request_id or not REQUEST_ID_RE.fullmatch(request_id):
        raise SystemExit("--browser-reply requires --request-id from the posted browser request")
    packet = load_packet_file(str(Path(args.contractor_packet).expanduser()))
    require_production_contractor_packet(packet)
    dispatch = configured_store().require_dispatch(packet.get("dispatch_id"))
    metadata = dispatch["evaluation_metadata"]
    if (not _is_desktop_preparation(dispatch) or request_id != metadata.get("request_id")
            or dispatch["packet_sha256"] != packet["packet_sha256"]):
        raise SystemExit("packet or request ID does not match the recorded browser preparation")
    if packet.get("subject") != packet_subject(packet, **candidate_context(args)):
        raise SystemExit("browser return subject does not match the current packet source/candidate")
    return packet, metadata, _read_copied_reply(args.browser_reply)


def _require_same_receipt(store, dispatch_id, digest, metadata):
    receipts = store.find("return-received", dispatch_id=dispatch_id)
    if not receipts:
        return False
    if (len(receipts) != 1 or receipts[0].get("return_sha256") != digest
            or receipts[0].get("desktop_browser") != metadata):
        raise SystemExit("this browser request already has a different reply or model label")
    store.require_return(dispatch_id, digest)
    return True


def _retain_reply(store, name, raw):
    with PrivateDirectory.open(store.state_root / "browser-returns", create=True) as directory:
        if directory.contains(name) is False:
            directory.write(name, raw)
        if directory.read(name, max_bytes=MAX_RETURN_BYTES) != raw:
            raise SystemExit("this browser request already has a different private reply")


def record_desktop_reply(dispatch_id, raw, args):
    """Keep exact reply bytes privately and bind their digest to the audited dispatch."""
    store = configured_store()
    name = f"{args.request_id}.response.txt"
    metadata = {"request_id": args.request_id, "model_label": args.model_label.strip(), "response_file": name}
    digest = sha256_bytes(raw)
    recorded = _require_same_receipt(store, dispatch_id, digest, metadata)
    try:
        _retain_reply(store, name, raw)
    except PrivateArtifactError as exc:
        raise SystemExit(f"could not retain the private browser reply: {exc}") from exc
    if not recorded:
        try:
            store.write_return_received(dispatch_id, digest, capture_provenance=DESKTOP_BROWSER_CAPTURE,
                                        desktop_browser=metadata)
        except HostRecordError:
            if not _require_same_receipt(store, dispatch_id, digest, metadata):
                raise


def main():
    parser = argparse.ArgumentParser(description="Prepare an exact screened packet request for desktop @Chrome.")
    parser.add_argument("--packet", required=True, help="Production ChatGPT browser contractor packet.")
    args = parser.parse_args()
    try:
        sys.stdout.write(prepare_desktop_request(args.packet).decode("utf-8"))
    except CWOPolicyError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
