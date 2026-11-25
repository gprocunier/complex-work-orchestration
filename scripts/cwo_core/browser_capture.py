"""Publish private browser returns from a trusted host observation."""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import re
import secrets
from typing import Any

from .audit import record_audit_event
from .browser_provenance import build_private_provenance, capture_audit_fields
from .paths import REPO_ROOT, cwo_temp_dir
from .private_artifact import (
    PrivateArtifactError,
    PrivateDirectory,
    artifact_path,
    note_present_artifacts,
    note_retained_by_name,
    sha256_bytes,
)
from .telemetry import safe_text_hash, telemetry_fields


def resolve_response_dir(raw: str | None) -> Path:
    """Return the owner-only directory for private responses (outside the repository).

    The path is read the way the artifact writer reads it: absolute, with no
    ``..`` component to normalize away. It must lie outside the repository both
    as written and with symlinks resolved; the writer then refuses any
    symlinked component.
    """
    if not raw:
        return cwo_temp_dir(purpose="chatgpt-browser-returns")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise SystemExit("--response-dir must be an absolute path")
    try:
        path = artifact_path(path)
    except PrivateArtifactError as exc:
        raise SystemExit("--response-dir must not contain a '..' component") from exc
    if path.is_relative_to(REPO_ROOT) or path.resolve().is_relative_to(REPO_ROOT):
        raise SystemExit("--response-dir must live outside the repository")
    return path


def private_response_names(metadata: dict[str, Any]) -> tuple[str, str]:
    """Fresh ``(provenance, response)`` file names for one capture.

    A caller fixes them before anything is written, so that a failure at any
    point afterwards can be checked against these names.
    """
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", str(metadata.get("dispatch_id") or "dispatch")).strip(".-") or "dispatch"
    run_id = f"{stem}-{dt.datetime.now(dt.UTC).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"
    return f"{run_id}.provenance.json", f"{run_id}.response.txt"


def note_present_response_files(exc: BaseException, response_dir: Path, names: tuple[str, ...],
                                published: list[str] | tuple[str, ...] = ()) -> None:
    """Note on ``exc`` each planned private response file that exists (or cannot be checked), and each one known to
    have been published (``published``) even if it is no longer found by name."""
    present = []
    for name in names:
        path = response_dir / name
        try:
            os.lstat(path)
        except FileNotFoundError:
            if any(Path(known).name == name for known in published):
                present.append(f"{path} (published, but no longer at that path)")
            continue
        except OSError:
            present.append(f"{path} (could not be checked)")
            continue
        present.append(str(path))
    if present:
        note = "private response files present after the failure: " + ", ".join(present)
        if note not in getattr(exc, "__notes__", []):
            exc.add_note(note)


def write_private_response(
    response_dir: Path,
    *,
    metadata: dict[str, Any],
    prompt: str,
    browser_result: dict[str, Any],
    retained: list[str] | None = None,
    names: tuple[str, str] | None = None,
) -> dict[str, Any]:
    """Persist the response privately and return a digest reference.

    Pass an owner-private destination selected with resolve_response_dir and
    the observation from the trusted browser host. The response text never
    enters the dispatch result, stdout or the audit log.
    An unverified capture is still stored, marked incomplete, as diagnostic
    material that ingestion refuses as a return. Both files are written through
    one pinned directory descriptor, provenance first: it holds identities and
    the response digest but no response text, and ingest refuses it while the
    response file it names is missing. Nothing is deleted on failure; the error
    (or, for an interruption, an exception note) names any file that was
    published, and every published path is appended to ``retained`` as soon
    as it is known, so a caller can still report it after a later failure.
    """
    text = browser_result.get("response_text")
    if not isinstance(text, str) or not text.strip():
        raise SystemExit("browser response capture is empty; no private response artifact was written")
    response_bytes = text.encode("utf-8")
    provenance_name, response_name = names or private_response_names(metadata)
    provenance = build_private_provenance(
        metadata, prompt, browser_result, response_file=response_name,
        captured_at=dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    response_sha256 = provenance["response_sha256"]
    complete = provenance["capture_complete"]
    provenance_bytes = (json.dumps(provenance, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        directory = PrivateDirectory.open(response_dir, create=True)
    except PrivateArtifactError as exc:
        raise SystemExit(f"could not open the private response directory: {exc}") from exc
    published = retained if retained is not None else []
    try:
        try:
            try:
                provenance_path = directory.write(provenance_name, provenance_bytes)
            except BaseException as exc:
                if getattr(exc, "retained_artifact", None) is not None:
                    published.append(str(exc.retained_artifact))  # type: ignore[attr-defined]
                if isinstance(exc, PrivateArtifactError):
                    raise SystemExit(f"could not write private response provenance: {exc}") from exc
                raise
            published.append(str(provenance_path))
            try:
                response_path = directory.write(response_name, response_bytes)
                published.append(str(response_path))
            except BaseException as exc:
                if getattr(exc, "retained_artifact", None) is not None and str(exc.retained_artifact) not in published:
                    published.append(str(exc.retained_artifact))  # type: ignore[attr-defined]
                present = directory.contains(response_name)
                if present:
                    retained = (f"the provenance {provenance_path} and the response {directory.path / response_name} are both "
                                "retained; ingest accepts the pair only if the response matches its recorded digest")
                elif present is False:
                    retained = f"the provenance {provenance_path} is retained without its response file, and ingest refuses it"
                else:
                    retained = f"the provenance {provenance_path} is retained; whether the response file exists could not be checked"
                if isinstance(exc, PrivateArtifactError):
                    raise SystemExit(f"could not write private response artifact ({exc}); {retained}") from exc
                exc.add_note(retained)
                raise
            reference = {
                "provenance_path": str(provenance_path),
                "response_path": str(response_path),
                "response_sha256": response_sha256,
                "provenance_sha256": sha256_bytes(provenance_bytes),
                "capture_audit_fields": capture_audit_fields(provenance, sha256_bytes(provenance_bytes)),
                "response_chars": len(text),
                "capture_complete": complete,
                "capture_incomplete_reasons": provenance["capture_incomplete_reasons"],
            }
            # The return stays inside the try with the finally, so CPython keeps the
            # closing code it runs on the way out inside the outer handler.
            return reference
        except BaseException as exc:
            # Covers the whole transaction, including the instructions between a
            # publication and its bookkeeping: whatever exists is named.
            for path in note_present_artifacts(exc, directory, [provenance_name, response_name]):
                if path not in published:
                    published.append(path)
            raise
        finally:
            directory.close()
    except BaseException as exc:
        # Also covers closing the directory and the way into that cleanup, after
        # which the descriptor may be gone: check by name.
        for path in note_retained_by_name(exc, [directory.path / provenance_name, directory.path / response_name],
                                          published + directory.published_paths):
            if path not in published:
                published.append(path)
        raise


def record_browser_dispatch(
    result: dict[str, Any],
    *,
    quota_info: dict[str, Any],
    waiver_fields: dict[str, Any] | None = None,
    telemetry_kind: str = "browser_dispatch",
    telemetry_missing_reason: str | None = None,
) -> dict[str, Any]:
    """Persist the existing dispatch event and link its hash to the private artifact.

    The host supplies the dispatch metadata and the artifact reference from
    write_private_response. Intake selects the event from the independent
    audit store and validates the artifact's exact provenance and response.
    """
    attestation = result.get("model_attestation") if isinstance(result.get("model_attestation"), dict) else {}
    live_submission = telemetry_kind == "browser_dispatch"
    response_artifact = result.get("response_artifact") or {}
    waivers = waiver_fields or {}
    share_url = result.get("share_url")
    failure_reason = result.get("failure_reason")
    event = record_audit_event(
        {
            "event_type": "chatgpt_browser_dispatch",
            **response_artifact.get("capture_audit_fields", {}),
            "quota_event_type": quota_info.get("quota_event_type"),
            "quota_stage": "consumed" if quota_info.get("quota_checked") else None,
            "dispatch_id": result["dispatch_id"],
            "bead_id": result["bead_id"],
            "epic_id": result["epic_id"],
            "executor_key": result["executor"],
            "waiver_required": waivers.get("waiver_required", False),
            "waiver_flags": waivers.get("waiver_flags", []),
            "waiver_reason": waivers.get("waiver_reason"),
            "provider_key": result["provider_key"],
            "executor_external": True,
            "dispatch_mode": "browser_automation",
            "share_boundary": result["share_boundary"],
            "packet_sha256": result["packet_sha256"],
            "prompt_sha256": result["prompt_sha256"],
            "quota_remaining": quota_info.get("quota_remaining"),
            "share_url_present": bool(share_url),
            "response_artifact_present": bool(response_artifact),
            "response_sha256": response_artifact.get("response_sha256"),
            "share_link_method": result.get("share_link_method"),
            "model_attestation_present": bool(result.get("model_attestation")),
            "status": result["status"],
            "failure_stage": result.get("failure_stage"),
            **telemetry_fields(
                telemetry_kind=telemetry_kind,
                telemetry_status=result["status"],
                telemetry_missing_reason=telemetry_missing_reason,
                agent_model_calls=1 if live_submission else 0,
                retry_count=0,
                model=result.get("model"),
                model_label=result.get("model_label"),
                reasoning_label=result.get("reasoning_label"),
                provider_family=result.get("provider_family"),
                provider_retention_class=result.get("provider_retention_class"),
                job_description_label=result.get("job_description_label"),
                expert_profile=result.get("expert_profile"),
                elapsed_seconds=result.get("elapsed_seconds") if live_submission else None,
                prompt_chars=result.get("prompt_chars"),
                response_chars=result.get("response_chars"),
                share_url_sha256=safe_text_hash(share_url),
                share_url_chars=len(str(share_url)) if share_url else None,
                failure_reason_sha256=safe_text_hash(failure_reason),
                failure_reason_chars=len(str(failure_reason)) if failure_reason else None,
                model_attestation_status=attestation.get("status"),
                model_attestation_required=attestation.get("required"),
                expected_return_language=result.get("expected_return_language"),
                expected_return_language_source=result.get("expected_return_language_source"),
            ),
        }
    )
    if response_artifact:
        response_artifact["capture_event_hash"] = event["event_hash"]
    return event
