"""One parent-owned fallback attempt after a structured provider refusal.

The worker packet never carries the authorization mark. The parent reads an
owner-private mark file outside every worker and lead write root, then passes
an opaque handle to this controller. Dispatch remains an injected parent
operation, which keeps tests offline and provider-free.
"""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .invocation_ledger import EffectResult, InvocationLedger
from .model_identities import (
    CYBER_FALLBACK_ACCESS_PROGRAM,
    CYBER_FALLBACK_CODEX_CONFIG,
    CYBER_FALLBACK_ROLE,
    CYBER_FALLBACK_SERVICE_TIER,
    bounded_cyber_fallback_effort,
    is_cyber_fallback_model,
)


_BLOCKER_KEY = "provider-safety-policy-refusal"
# Only a cyber-policy refusal triggers recovery; other refusals and errors stop.
_REFUSAL_CATEGORIES = {"cyberPolicy"}
_MARK_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class CyberFallbackError(ValueError):
    """A mark or fallback request failed closed before dispatch."""


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def _pairs(entries: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in entries:
        if key in value:
            raise CyberFallbackError("security-work mark contains a duplicate JSON key")
        value[key] = item
    return value


def _private_bytes(path: Path, expected_sha256: str, maximum_bytes: int = 65536) -> bytes:
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o077
        ):
            raise CyberFallbackError("security-work mark must be an owned private regular file")
        if before.st_size > maximum_bytes:
            raise CyberFallbackError("security-work mark exceeds its byte bound")
        chunks = bytearray()
        while len(chunks) <= maximum_bytes:
            chunk = os.read(descriptor, min(65536, maximum_bytes + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if len(chunks) > maximum_bytes or identity(before) != identity(after):
            raise CyberFallbackError("security-work mark drifted during capture")
        data = bytes(chunks)
        if hashlib.sha256(data).hexdigest() != expected_sha256:
            raise CyberFallbackError("security-work mark raw hash mismatch")
        return data
    except OSError as exc:
        raise CyberFallbackError(f"security-work mark could not be read: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _timestamp(value: Any) -> str:
    if type(value) is not str or not value or len(value) > 128:
        raise CyberFallbackError("security-work mark timestamp is invalid")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CyberFallbackError("security-work mark timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise CyberFallbackError("security-work mark timestamp must include a timezone")
    return value


def _validate_mark_entry(mark: Any) -> dict[str, Any]:
    fields = {"scope", "id", "source", "marked_by", "marked_at"}
    if not isinstance(mark, Mapping) or set(mark) != fields:
        raise CyberFallbackError("security-work mark entry is invalid")
    if mark.get("scope") not in {"project", "work-item"} or not _MARK_ID.fullmatch(str(mark.get("id", ""))):
        raise CyberFallbackError("security-work mark scope or identity is invalid")
    if mark.get("source") != "user":
        raise CyberFallbackError("only an explicit user action can create a security-work mark")
    if type(mark.get("marked_by")) is not str or not mark["marked_by"].strip() or len(mark["marked_by"]) > 256:
        raise CyberFallbackError("security-work mark setter is invalid")
    current = dict(mark)
    current["marked_at"] = _timestamp(mark["marked_at"])
    return current


def _validate_mark_document(value: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, Mapping) or set(value) != {"version", "marks"} or value.get("version") != 1:
        raise CyberFallbackError("security-work mark document is invalid")
    marks = value.get("marks")
    if type(marks) is not list or not marks or len(marks) > 256:
        raise CyberFallbackError("security-work mark list is invalid")
    validated = []
    identities = set()
    for mark in marks:
        current = _validate_mark_entry(mark)
        identity = (current["scope"], current["id"])
        if identity in identities:
            raise CyberFallbackError("security-work mark scope is duplicated")
        identities.add(identity)
        validated.append(current)
    return tuple(validated)


class _VerifiedMark:
    __slots__ = ("_record", "_secret")

    def __init__(self, record: Mapping[str, Any], secret: object, expected: object) -> None:
        if secret is not expected:
            raise CyberFallbackError("verified user marks are issued only by their private store")
        self._record = copy.deepcopy(dict(record))
        self._secret = secret

    __hash__ = object.__hash__


class SecurityMarkStore:
    """Read exact user marks and issue non-serializable handles to the parent."""

    def __init__(
        self,
        path: str | Path,
        expected_sha256: str,
        *,
        prohibited_write_roots: Sequence[str | Path],
    ) -> None:
        self.path = Path(path)
        if (
            not self.path.is_absolute()
            or ".." in self.path.parts
            or any(parent.is_symlink() for parent in (self.path, *self.path.parents))
        ):
            raise CyberFallbackError("security-work mark path must be absolute and non-symlink")
        if type(expected_sha256) is not str or _SHA256.fullmatch(expected_sha256) is None:
            raise CyberFallbackError("security-work mark raw hash is invalid")
        self.expected_sha256 = expected_sha256
        roots = tuple(Path(root) for root in prohibited_write_roots)
        if not roots or any(not root.is_absolute() or root == self.path or root in self.path.parents for root in roots):
            raise CyberFallbackError("security-work mark must stay outside worker and lead write roots")
        self._secret = object()
        self._issued: dict[_VerifiedMark, bool] = {}
        self._marks = self._load()

    def _load(self) -> tuple[dict[str, Any], ...]:
        raw = _private_bytes(self.path, self.expected_sha256)
        try:
            value = json.loads(
                raw,
                object_pairs_hook=_pairs,
                parse_constant=lambda token: (_ for _ in ()).throw(
                    CyberFallbackError(f"security-work mark contains non-finite JSON {token}")
                ),
            )
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise CyberFallbackError("security-work mark is not valid JSON") from exc
        return _validate_mark_document(value)

    def issue(self, *, work_item_id: str, project_id: str | None = None) -> _VerifiedMark | None:
        if not _MARK_ID.fullmatch(work_item_id) or (project_id is not None and not _MARK_ID.fullmatch(project_id)):
            raise CyberFallbackError("security-work identity is invalid")
        if self._load() != self._marks:
            raise CyberFallbackError("security-work marks changed after their private capture")
        match = next((mark for mark in self._marks if mark["scope"] == "work-item" and mark["id"] == work_item_id), None)
        if match is None and project_id is not None:
            match = next((mark for mark in self._marks if mark["scope"] == "project" and mark["id"] == project_id), None)
        if match is None:
            return None
        record = {**match, "config_sha256": self.expected_sha256}
        mark = _VerifiedMark(record, self._secret, self._secret)
        self._issued[mark] = False
        return mark

    def verify(
        self, mark: object, *, work_item_id: str, project_id: str | None, consume: bool = False,
    ) -> dict[str, Any]:
        if type(mark) is not _VerifiedMark or mark not in self._issued or mark._secret is not self._secret:
            raise CyberFallbackError("a verified user mark from the configured private store is required")
        if self._issued[mark]:
            raise CyberFallbackError("the verified user mark handle was already consumed")
        record = copy.deepcopy(mark._record)
        matches = (
            record["scope"] == "work-item" and record["id"] == work_item_id
        ) or (
            record["scope"] == "project" and project_id is not None and record["id"] == project_id
        )
        if not matches:
            raise CyberFallbackError("the verified user mark does not cover this work")
        if self._load() != self._marks:
            raise CyberFallbackError("security-work marks changed after their private capture")
        if consume:
            self._issued[mark] = True
        return record


class CyberFallbackController:
    """Consume one terminal refusal and launch at most one fallback attempt."""

    def __init__(
        self,
        ledger: InvocationLedger,
        mark_store: SecurityMarkStore,
        recorder: Callable[[dict[str, Any]], None],
        *,
        clock: Callable[[], float],
    ) -> None:
        if type(ledger) is not InvocationLedger or type(mark_store) is not SecurityMarkStore or not callable(recorder):
            raise CyberFallbackError("exact parent ledger, mark store and recorder are required")
        self.ledger = ledger
        self.mark_store = mark_store
        self.recorder = recorder
        self.clock = clock

    @staticmethod
    def _classification(result: Any) -> str | None:
        summary = result.get("summary") if isinstance(result, Mapping) else None
        blockers = summary.get("terminal_blockers") if isinstance(summary, Mapping) else None
        category = blockers.get(_BLOCKER_KEY) if isinstance(blockers, Mapping) else None
        return category if category in _REFUSAL_CATEGORIES else None

    def _original(self, attempt: Any, packet: bytes) -> dict[str, Any]:
        if not isinstance(attempt, Mapping) or type(attempt.get("reservation_id")) is not str:
            raise CyberFallbackError("original charged attempt is invalid")
        current = self.ledger.attempt(attempt["reservation_id"])
        if current != dict(attempt):
            raise CyberFallbackError("original charged attempt changed")
        if (
            current["state"] != "terminal"
            or current["outcome"] != "failed"
            or current["charge"] != current["amount"]
            or current["request_sha256"] != hashlib.sha256(packet).hexdigest()
        ):
            raise CyberFallbackError("a known fully charged refusal for the exact packet is required")
        return current

    def _existing_fallback(self, parent_attempt_id: str) -> dict[str, Any] | None:
        with self.ledger._locked() as (_root, document):
            rows = [
                copy.deepcopy(attempt)
                for attempt in document["attempts"].values()
                if attempt["lineage"] == {"kind": "fallback", "parent_attempt_id": parent_attempt_id}
            ]
        if len(rows) > 1:
            raise CyberFallbackError("more than one fallback attempt is recorded for the original")
        return rows[0] if rows else None

    def _record_blocker(
        self, *, original: Mapping[str, Any], classification: str, cause: str,
        mark: Mapping[str, Any] | None = None, role: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        blocker = {"classification": classification, "cause": cause}
        record = {
            "record_type": "cwo-cyber-fallback",
            "version": 1,
            "event": "blocker",
            "reason": "cyber_refusal",
            "parent_attempt_id": original["attempt_id"],
            "blocker": blocker,
        }
        if mark is not None:
            record["mark"] = copy.deepcopy(dict(mark))
        if role is not None:
            record["fallback_role"] = copy.deepcopy(dict(role))
        self.recorder(record)
        return {"status": "blocked", "original_attempt": copy.deepcopy(dict(original)), "blocker": blocker}

    @staticmethod
    def _dispatch_identity(value: Any) -> dict[str, str]:
        fields = {"model", "effort", "service_tier"}
        if not isinstance(value, Mapping) or set(value) != fields or any(
            type(value[field]) is not str or not value[field] for field in fields
        ):
            raise CyberFallbackError("trusted original dispatch identity is invalid")
        return dict(value)

    @staticmethod
    def _available_role(value: Any) -> dict[str, Any] | None:
        required = {"role", "status", "reason", "model", "required_access_program", "codex_config"}
        if not isinstance(value, Mapping) or not required <= set(value) <= required | {"previous", "purpose"}:
            raise CyberFallbackError("fallback role projection is invalid")
        role = copy.deepcopy(dict(value))
        if role["role"] != CYBER_FALLBACK_ROLE:
            raise CyberFallbackError("fallback role projection names another role")
        if role["status"] != "available":
            return None
        if (
            not is_cyber_fallback_model(role["model"])
            or role["required_access_program"] != CYBER_FALLBACK_ACCESS_PROGRAM
            or role["codex_config"] != CYBER_FALLBACK_CODEX_CONFIG
            or role["reason"] != "required-access-program-advertised"
        ):
            raise CyberFallbackError("available fallback must bind the configured Daybreak Blue role")
        return role

    def recover(
        self,
        *,
        packet: bytes,
        work_item_id: str,
        project_id: str | None,
        original_attempt: Mapping[str, Any],
        original_result: Mapping[str, Any],
        original_dispatch: Mapping[str, Any],
        fallback_role: Mapping[str, Any],
        mark: object | None,
        dispatch: Callable[[dict[str, Any]], Mapping[str, Any]],
    ) -> dict[str, Any]:
        if type(packet) is not bytes or not packet or not callable(dispatch):
            raise CyberFallbackError("an immutable packet and parent dispatcher are required")
        original = self._original(original_attempt, packet)
        classification = self._classification(original_result)
        if classification is None:
            return {"status": "unchanged", "original_attempt": copy.deepcopy(original)}
        if original["lineage"]["kind"] == "fallback":
            return self._record_blocker(
                original=original, classification=classification, cause="fallback-refused"
            )
        if mark is None:
            return self._record_blocker(
                original=original, classification=classification, cause="work-not-marked"
            )
        mark_record = self.mark_store.verify(
            mark, work_item_id=work_item_id, project_id=project_id
        )
        role = self._available_role(fallback_role)
        if role is None:
            return self._record_blocker(
                original=original, classification=classification, cause="fallback-role-unavailable",
                mark=mark_record, role=fallback_role,
            )
        if self._existing_fallback(original["attempt_id"]) is not None:
            return self._record_blocker(
                original=original, classification=classification, cause="fallback-already-attempted",
                mark=mark_record, role=role,
            )
        original_identity = self._dispatch_identity(original_dispatch)
        fallback_effort = bounded_cyber_fallback_effort(original_identity["effort"])
        if role["model"] == original_identity["model"]:
            raise CyberFallbackError(
                "available fallback must bind the configured Daybreak Blue role, not the refused model"
            )
        self.mark_store.verify(
            mark, work_item_id=work_item_id, project_id=project_id, consume=True
        )
        packet_sha256 = hashlib.sha256(packet).hexdigest()
        mark_sha256 = _canonical_sha256(mark_record)
        binding = {
            "reason": "cyber_refusal",
            "parent_attempt_id": original["attempt_id"],
            "classification": classification,
            "packet_sha256": packet_sha256,
            "mark_sha256": mark_sha256,
            "mark": mark_record,
            "fallback_role": role,
            "effort": fallback_effort,
            "service_tier": CYBER_FALLBACK_SERVICE_TIER,
        }
        binding_sha256 = _canonical_sha256(binding)
        reservation = self.ledger.reserve(
            budget_id=original["budget_id"],
            request_id="cyber-fallback:" + binding_sha256[:32],
            request_sha256=packet_sha256,
            admission_sha256=binding_sha256,
            amount=original["amount"],
            expires_at=self.clock() + 300,
            lineage={"kind": "fallback", "parent_attempt_id": original["attempt_id"]},
            refuse_while_unresolved=True,
        )
        request = {
            "packet": packet,
            "packet_sha256": packet_sha256,
            "reason": "cyber_refusal",
            "classification": classification,
            "parent_attempt_id": original["attempt_id"],
            "role": role["role"],
            "model": role["model"],
            "codex_config": copy.deepcopy(role["codex_config"]),
            "effort": fallback_effort,
            "service_tier": CYBER_FALLBACK_SERVICE_TIER,
            "mark": copy.deepcopy(mark_record),
        }
        fallback_result: dict[str, Any] = {}

        def observe(observation: dict[str, Any]) -> None:
            event = observation["event"]
            record = {
                "record_type": "cwo-cyber-fallback",
                "version": 1,
                "event": event,
                **binding,
                "attempt": copy.deepcopy(observation["attempt"]),
            }
            if observation["detail"]:
                record["detail"] = copy.deepcopy(observation["detail"])
            if event == "terminal" and fallback_result:
                record["fallback_outcome"] = fallback_result["outcome"]
                record["fallback_classification"] = self._classification(fallback_result)
            self.recorder(record)

        def effect(effect_packet: bytes, _report: Callable[..., None]) -> EffectResult:
            if effect_packet != packet:
                raise CyberFallbackError("fallback dispatcher did not receive the unchanged packet bytes")
            observed = dispatch(request)
            if not isinstance(observed, Mapping) or observed.get("outcome") not in {"completed", "failed"}:
                raise CyberFallbackError("fallback dispatcher returned an invalid result")
            fallback_result.update(copy.deepcopy(dict(observed)))
            return EffectResult(fallback_result["outcome"], fallback_result.get("usage"))

        settled = self.ledger.invoke(
            reservation["reservation_id"], packet, effect, observers=(observe,)
        )
        result = {
            "status": "completed" if settled["outcome"] == "completed" else "blocked",
            "original_attempt": copy.deepcopy(original),
            "fallback_attempt": settled,
            "fallback_result": copy.deepcopy(fallback_result),
        }
        if settled["outcome"] == "failed":
            result["blocker"] = {
                "classification": self._classification(fallback_result),
                "cause": "fallback-refused" if self._classification(fallback_result) else "fallback-failed",
            }
        return result
