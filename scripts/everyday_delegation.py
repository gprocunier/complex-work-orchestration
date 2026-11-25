"""Coordinate one original registered workflow and its bound hand delivery."""
from __future__ import annotations

from argparse import ArgumentParser, Namespace
from collections.abc import Sequence
import json
from pathlib import Path
import sys

import everyday_delegation_delivery as delivery_records
import registered_delegation_entry as entry
import registered_n1_workflow as native
from cwo_core import candidate_identity, host_records, manual_delivery, requirement_baseline, workspace_capture
from cwo_core.native_live_availability import NativeLiveUnavailable


def _baseline(baseline, amendments):
    baseline_path = str(Path(baseline).resolve(strict=True))
    amendment_paths = tuple(str(Path(path).resolve(strict=True)) for path in amendments)
    chain = requirement_baseline.resolve_chain(manual_delivery._read_record(baseline_path),
        [manual_delivery._read_record(path) for path in amendment_paths])
    return baseline_path, amendment_paths, chain


def _delivery_inputs(workflow, baseline, amendments):
    if type(workflow) is not native.RegisteredN1Workflow:
        raise ValueError('An original configured registered workflow is required.')
    baseline_path, amendment_paths, chain = _baseline(baseline, amendments)
    standing = workflow.config._standing_delegation
    if (standing is None or chain['digest'] != standing.baseline_sha256
            or chain['bead_id'] != workflow.config.route['parent_id']):
        raise ValueError('The Bead and requirement baseline must match the standing delegation.')
    root = workflow.config.host.worker
    return Namespace(bead=chain['bead_id'], repo=str(root), project=str(workflow.config.project),
                     baseline=baseline_path, amendment=amendment_paths), chain


def _open_task(delivery, run_bd):
    task = delivery.task(run_bd)
    if task.get('status') not in manual_delivery._OPEN:
        raise ValueError('An open Bead is required for registered worker delivery.')
    errors = requirement_baseline.bead_reference_errors(task, delivery.chain)
    if errors:
        raise requirement_baseline.RequirementBaselineError(errors)
    return task


def _save_candidate(store, candidate, digest):
    raw = json.dumps(candidate, sort_keys=True, ensure_ascii=False).encode() + b'\n'
    if len(raw) > manual_delivery.MAX_PROJECTION:
        raise ValueError('The candidate identity exceeds the delivery record limit.')
    name = 'delegated-candidate-' + digest.removeprefix('sha256:') + '.json'
    with store._state(create=True) as directory:
        try:
            host_records._write_at(directory, name, raw, atomic_create=True)
        except FileExistsError:
            if host_records._read_at(directory, name, manual_delivery.MAX_PROJECTION) != raw:
                raise ValueError('The retained delegated candidate identity changed.') from None
    return str(store.state_root / name)


def _reference(delivery, task, run_bd, digest):
    line = candidate_identity.candidate_reference_line(delivery.bead_id, digest)
    if any(comment.get('text') == line for comment in task['comments'] if type(comment) is dict):
        delivery.check(task)
        return
    # Validate the exact proposed reference before posting it. The delivery
    # producer rechecks the actual Bead after this write.
    delivery.check({**task, 'comments': [*task['comments'], {'text': line}]})
    run_bd(['comment', '--', delivery.bead_id, line])


def deliver(workflow, *, baseline: str | Path, amendments: Sequence[str | Path] = (), summary: str) -> dict:
    """Post or resume delivery from the original in-process completed workflow."""
    args, chain = _delivery_inputs(workflow, baseline, amendments)
    root = workflow.config.host.worker
    if workflow._artifact is None:
        raise ValueError('The original completed registered workflow is required for delivery.')
    _host, _token, report, _target, _policy = workflow._artifact
    candidate = candidate_identity.capture_candidate(root, chain=chain,
        base_commit=report['binding']['worker_identity']['head_commit'],
        scope_paths=sorted(entry['path'] for entry in report['artifact']['files']))
    delivery = manual_delivery.Delivery(args.bead, root, chain, candidate, Path(args.project))
    store = host_records.configured_store()
    store.require_outside_worker_roots((root, workflow.config.host.target, delivery.database_root))
    database, run_bd = manual_delivery.project_beads(Path(args.project))
    task = _open_task(delivery, run_bd)
    delivery_records.verify_candidate(workflow, delivery, database=database)
    digest = candidate_identity.candidate_digest(candidate)
    args.candidate = _save_candidate(store, candidate, digest)
    _reference(delivery, task, run_bd, digest)
    comment = delivery_records.record_delivery(workflow, args, summary)
    return {**vars(args), 'candidate_sha256': digest, 'delivery_comment': comment}


def delegate(workflow, task, *, baseline: str | Path,
             amendments: Sequence[str | Path] = (), summary: str, resume: bool = False) -> dict:
    """Deliver a standing-approved assignment or resume delivery from completed custody."""
    args, chain = _delivery_inputs(workflow, baseline, amendments)
    root, project = Path(args.repo), Path(args.project)
    database, run_bd = manual_delivery.project_beads(project)
    _open_task(manual_delivery.Delivery(args.bead, root, chain, {}, project), run_bd)
    if resume:
        workflow.resume_delegation(task, database=database)
    else:
        workflow.delegate(task, database=database)
    return deliver(workflow, baseline=args.baseline, amendments=args.amendment, summary=summary)


def _installed_assignment(args):
    if not args.resume and native.login_config.read_worker_login_home() is None:
        raise ValueError(native.delegation_setup_message())
    _baseline_path, _amendment_paths, chain = _baseline(args.baseline, args.amendment)
    try:
        workflow = entry.open_assignment(args.task, chain)
    except entry.StandingApprovalMissing as exc:
        if args.resume:
            raise
        raise ValueError(f'{exc} Use the cwo-delegation approval tool in the local cwo-codex session.') from None
    if not args.resume and entry.renewable(workflow):
        raise ValueError('The unused delegation admission is expired. Use the cwo-delegation approval tool '
                         'in the local cwo-codex session to approve a fresh admission.')
    return workflow


def main(argv: list[str] | None = None, *, workflow=None) -> int:
    """Run the standing-approved assignment selected from the lead's project."""
    cli = ArgumentParser(description=__doc__)
    cli.add_argument('--task', required=True, help='The original admitted lead assignment.')
    cli.add_argument('--baseline', required=True, type=Path, help='The original requirement baseline JSON.')
    cli.add_argument('--amendment', action='append', default=[], type=Path, help='An applied amendment in order.')
    cli.add_argument('--summary', required=True, help='The delivery note for independent review.')
    cli.add_argument('--resume', action='store_true', help='Resume the same completed assignment without dispatching.')
    args = cli.parse_args(argv)
    try:
        if workflow is None:
            workflow = _installed_assignment(args)
        result = delegate(workflow, args.task, baseline=args.baseline, amendments=args.amendment,
                          summary=args.summary, resume=args.resume)
    except (NativeLiveUnavailable, OSError, ValueError, SystemExit, workspace_capture.WorkspaceDiscoveryError) as exc:
        print(f'delegate: {exc}', file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
