"""Record a local delivery and close it after an independent hand review."""
from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import os
import sys
from typing import Any

from . import audit, beads, candidate_identity, host_records, requirement_baseline
from .closure_checks import MAX_PROJECTION, projection, require_closed_prerequisites
from .process_identity import ProcAdapter, parse_proc_stat
from .util import artifact_hash

RECORDED = "manual_delivery_recorded"
ACCEPTED = "manual_delivery_accepted"
CLOSED = "manual_delivery_closed"
_OPEN = ("open", "in_progress")
_AGENT_EXECUTABLES = {"codex", "claude"}
_RECEIPT_LABEL = "Manual delivery receipt "


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _agent_process(proc: ProcAdapter, pid: int, command: str) -> bool:
    if command in _AGENT_EXECUTABLES:
        return True
    try:
        executable = proc.readlink(f"{pid}/exe").removesuffix(" (deleted)")
    except PermissionError:
        return False
    return Path(executable).name in _AGENT_EXECUTABLES


def _process_chain() -> tuple[tuple[str, bool], ...]:
    """Bind parents to kernel process incarnations, independent of environment and Beads actors."""
    proc = ProcAdapter()
    try:
        boot = proc.read_text("sys/kernel/random/boot_id").strip()
        namespace = proc.own_pid_namespace()
        pid = os.getppid()
        chain = []
        while pid > 1:
            parent = parse_proc_stat(proc.read_text(f"{pid}/stat"))
            _need(parent.pid == pid, "the local process ancestry changed")
            token = f"{boot}/{namespace}/{pid}/{parent.start_ticks}"
            chain.append((token, _agent_process(proc, pid, parent.comm)))
            pid = parent.ppid
    except OSError as exc:
        raise ValueError("local process ancestry is unavailable for manual acceptance") from exc
    _need(bool(chain), "a local parent process is required for manual acceptance")
    return tuple(chain)


def delivery_session() -> str:
    chain = _process_chain()
    return next((token for token, agent in chain if agent), chain[0][0])


def reviewer_session() -> tuple[str, tuple[str, ...]]:
    try:
        foreground = sys.stdin.isatty() and os.tcgetpgrp(sys.stdin.fileno()) == os.getpgrp()
    except OSError as exc:
        raise ValueError("manual acceptance requires a foreground terminal") from exc
    _need(foreground, "manual acceptance requires a foreground terminal")
    chain = _process_chain()
    _need(not any(agent for _, agent in chain), "an agent session cannot accept a delivery by hand")
    return f"uid:{os.getuid()}", tuple(token for token, _ in chain)


def _read_record(path: str) -> dict[str, Any]:
    with Path(path).open("rb") as handle:
        raw = handle.read(MAX_PROJECTION + 1)
    _need(len(raw) <= MAX_PROJECTION, f"record is too large: {path}")
    return requirement_baseline.load_record(raw.decode())


def add_delivery_arguments(cli: argparse.ArgumentParser, *, required: bool = False) -> None:
    cli.add_argument("--repo", help="Top of the project working tree (default: current directory).")
    cli.add_argument("--baseline", required=required, help="The initial requirement baseline JSON.")
    cli.add_argument("--amendment", action="append", default=[], help="An applied amendment, in order. Repeatable.")
    cli.add_argument("--candidate", required=required, help="The exact candidate identity JSON.")


@dataclass(frozen=True)
class Delivery:
    bead_id: str
    root: Path
    chain: dict[str, Any]
    candidate: dict[str, Any]

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> Delivery:
        _need(bool(args.baseline and args.candidate), "a bound delivery requires --baseline and --candidate")
        baseline = _read_record(args.baseline)
        chain = requirement_baseline.resolve_chain(baseline, [_read_record(path) for path in args.amendment])
        _need(args.bead == chain["bead_id"], "the baseline belongs to a different Bead")
        return cls(chain["bead_id"], Path(args.repo or ".").resolve(strict=True), chain, _read_record(args.candidate))

    def binding(self, database: str) -> dict[str, Any]:
        return dict(bead_id=self.bead_id, manual_database_sha256=database,
                    baseline_sha256=self.chain["digest"],
                    candidate_sha256=candidate_identity.candidate_digest(self.candidate))

    def task(self, run_bd: Callable[[list[str]], str]) -> dict[str, Any]:
        raw = run_bd(beads.show_bead_args(self.bead_id, include_comments=True))
        task = projection(raw, "Bead")
        if type(task) is list and len(task) == 1:
            task = task[0]
        _need(type(task) is dict and task.get("id") == self.bead_id
              and type(task.get("comments")) is list, "the exact Bead with comments is required")
        return task

    def check(self, task: dict[str, Any]) -> None:
        checked = candidate_identity.check_candidate(self.candidate, root=self.root, chain=self.chain, bead=task)
        _need(checked["valid"], "candidate or baseline refused: " + "; ".join(checked["errors"]))


def _database_identity(storage: Path) -> str:
    info = storage.stat()
    return artifact_hash(f"{storage}\0{info.st_dev}\0{info.st_ino}")


def _database_location(arguments: list[str]) -> tuple[Path, Path]:
    location = projection(beads.run_bd([*arguments, "where", "--json"]), "database")
    _need(type(location) is dict and type(location.get("path")) is str
          and type(location.get("database_path")) is str, "Beads did not identify the project database")
    return Path(location["path"]).resolve(strict=True), Path(location["database_path"]).resolve(strict=True)


def project_beads(root: Path) -> tuple[str, Callable[[list[str]], str]]:
    """Pin Beads' normal project database selection without workspace enrollment."""
    project = ["-C", str(root)]
    beads_dir = os.environ.get("BEADS_DIR")
    selector = ["--db", str((root / beads_dir).resolve(strict=True))] if beads_dir else []
    path, storage = _database_location([*project, *selector])
    pinned = [*project, "--db", str(path)]
    database = _database_identity(storage)
    _need(_database_location(pinned) == (path, storage), "the explicit Beads command selected another database")

    def run_bd(command: list[str]) -> str:
        _need(_database_identity(storage) == database, "the project Beads database changed")
        return beads.run_bd([*pinned, *command])

    return database, run_bd


def _store(delivery: Delivery) -> host_records.HostRecordStore:
    store = host_records.configured_store()
    store.require_outside_worker_roots((delivery.root,))
    return store


def record_delivery(args: argparse.Namespace, summary: str) -> str:
    delivery = Delivery.from_args(args)
    session = delivery_session()
    store = _store(delivery)
    database, run_bd = project_beads(delivery.root)
    task = delivery.task(run_bd)
    delivery.check(task)
    _need(task.get("status") in _OPEN, "only an open Bead can record a delivery")
    binding = delivery.binding(database)
    summary += f"\nCandidate for hand review: {binding['candidate_sha256']}\n"
    receipt = store.record_audit_event(dict(event_type=RECORDED, **binding,
                                            manual_delivery_session=session,
                                            manual_summary_sha256=artifact_hash(summary)))
    comment = f"{summary}\n{_RECEIPT_LABEL}{receipt['event_hash']}"
    run_bd(["comment", "--", delivery.bead_id, comment])
    return comment + "\n"


def _matches(event: dict[str, Any], **fields: Any) -> bool:
    return all(event.get(key) == value for key, value in fields.items())


def _posted_deliveries(events: list[dict[str, Any]], task: dict[str, Any],
                       binding: dict[str, Any]) -> list[dict[str, Any]]:
    recorded = {event["event_hash"]: event for event in events
                if _matches(event, event_type=RECORDED, bead_id=binding["bead_id"],
                            manual_database_sha256=binding["manual_database_sha256"])}
    posted = []
    for comment in task["comments"]:
        text = comment.get("text") if type(comment) is dict else None
        if type(text) is not str:
            continue
        summary, _, last_line = text.rpartition("\n")
        if last_line.startswith(_RECEIPT_LABEL):
            event = recorded.get(last_line.removeprefix(_RECEIPT_LABEL))
            if event and artifact_hash(summary) == event.get("manual_summary_sha256"):
                posted.append(event)
    return posted


def _current_delivery(events: list[dict[str, Any]], task: dict[str, Any],
                      binding: dict[str, Any], ancestry: tuple[str, ...]) -> dict[str, Any]:
    deliveries = _posted_deliveries(events, task, binding)
    _need(bool(deliveries), "no host-recorded delivery comment is available for hand review")
    event = deliveries[-1]
    _need(_matches(event, **binding), "the reviewed candidate and baseline must match the latest delivery")
    _need(not any(_matches(item, **binding) and item.get("manual_delivery_session") in ancestry
                  for item in deliveries), "the delivering session cannot accept its own delivery")
    return event


def _append(store: host_records.HostRecordStore, state: int, lock: int, **event: Any) -> dict[str, Any]:
    return audit.record_audit_event(event, store.audit_file, _directory_fd=state,
                                    _limits=store.limits, _lock_fd=lock)


def _acceptance(events: list[dict[str, Any]], event: dict[str, Any]) -> dict[str, Any] | None:
    return next((entry for entry in reversed(events)
                 if _matches(entry, event_type=ACCEPTED, manual_delivery_event=event["event_hash"])), None)


def _claim(store: host_records.HostRecordStore, task: dict[str, Any], binding: dict[str, Any],
           reviewer: str, ancestry: tuple[str, ...], note: str) -> tuple[dict[str, Any], bool]:
    with store._guarded_state(create=True) as (state, lock):
        events = host_records._audit_snapshot(state, store.limits)
        event = _current_delivery(events, task, binding, ancestry)
        existing = _acceptance(events, event)
        if existing is not None:
            return existing, False
        source = dict(manual_delivery_event=event["event_hash"], **binding)
        _need(task.get("status") in _OPEN, "only an open delivered Bead can be accepted")
        accepted = _append(store, state, lock, event_type=ACCEPTED, **source,
                           manual_reviewer=reviewer, manual_review_session=ancestry[0], manual_review_note=note)
        return accepted, True


def _confirm_close(store: host_records.HostRecordStore, accepted: dict[str, Any],
                   binding: dict[str, Any]) -> dict[str, Any]:
    source = dict(manual_acceptance_event=accepted["event_hash"], **binding)
    with store._guarded_state(create=True) as (state, lock):
        events = host_records._audit_snapshot(state, store.limits)
        for event in reversed(events):
            if _matches(event, event_type=CLOSED, **source):
                return event
        return _append(store, state, lock, event_type=CLOSED, **source)


def _close(run_bd: Callable[[list[str]], str], bead_id: str, reason: str) -> None:
    try:
        run_bd(["close", "--reason", reason, "--", bead_id])
    except SystemExit:
        # The write may have reached Beads before the subprocess failed.
        pass


def accept_delivery(args: argparse.Namespace) -> dict[str, Any]:
    reviewer, ancestry = reviewer_session()
    note = " ".join(args.note.split())
    _need(0 < len(note) <= 240, "enter a review note of 1 to 240 characters")
    delivery = Delivery.from_args(args)
    store = _store(delivery)
    database, run_bd = project_beads(delivery.root)
    binding = delivery.binding(database)
    _need(binding["candidate_sha256"] == args.reviewed_candidate, "the candidate file differs from the reviewed candidate")
    task = delivery.task(run_bd)
    events = store.audit_events()
    pending = _current_delivery(events, task, binding, ancestry)
    accepted, claimed = _acceptance(events, pending), False
    if accepted is None:
        delivery.check(task)
        require_closed_prerequisites(run_bd, delivery.bead_id)
        accepted, claimed = _claim(store, task, binding, reviewer, ancestry, note)
    reason = f"Manual delivery accepted ({accepted['event_hash']})"
    if claimed:
        task = delivery.task(run_bd)
        latest = _current_delivery(store.audit_events(), task, binding, ancestry)
        _need(latest["event_hash"] == accepted["manual_delivery_event"] and task.get("status") in _OPEN,
              "the delivery changed after acceptance was recorded")
        delivery.check(task)
        require_closed_prerequisites(run_bd, delivery.bead_id)
        _close(run_bd, delivery.bead_id, reason)
    current = delivery.task(run_bd)
    _need(current.get("status") == "closed" and current.get("close_reason") == reason,
          "acceptance was recorded, but closure is unconfirmed. A retry only checks for the original close")
    closure = _confirm_close(store, accepted, binding)
    return dict(closed=True, **binding, acceptance_event=accepted["event_hash"], closure_event=closure["event_hash"])
