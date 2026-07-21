from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import copy, deepcopy
import hashlib
import json
from pathlib import Path
import pickle
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Barrier, Lock
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.beads import BdCommandResult, run_bd_structured  # noqa: E402
from cwo_core.beads_ready_set import build_ready_set_evidence  # noqa: E402
from cwo_core.native_pool_admission import (  # noqa: E402
    AdmissionCandidate,
    BeadsClaimAdapter,
    FixedCohortAdmissionCapability,
    NativePoolAdmissionError,
    build_admission_child_binding,
    build_dispatch_context,
    canonical_admission_sha256,
    consume_pool_admission,
    reserve_pool_cohort,
    validate_dispatch_receipt,
    validate_reservation_receipt,
)
from cwo_core.native_pool_proportionality import (  # noqa: E402
    pool_proportionality_check,
)
from tests.test_beads_ready_set import ready_item  # noqa: E402
from tests.test_native_pool_proportionality import (  # noqa: E402
    _fixture,
    _set_runtime,
)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _exact_raw(item: dict) -> dict:
    return {
        key: deepcopy(value)
        for key, value in item["raw"].items()
        if not key.startswith("_cwo_")
    }


def _candidate_from(
    readiness: dict,
    estimates: dict[str, dict],
    policy: dict,
    *,
    requested_workers: int,
) -> AdmissionCandidate:
    assessment = pool_proportionality_check(
        readiness,
        estimates,
        requested_workers=requested_workers,
        policy_document=policy,
    )
    selected = assessment["selected_cohort"]
    issue_ids = (
        list(selected["issue_ids"])
        if selected is not None
        else [assessment["fallback_issue_id"]]
    )
    bindings = {
        issue_id: build_admission_child_binding(
            readiness,
            estimates[issue_id],
            bead_id=issue_id,
            child_id=f"child-{issue_id}",
            packet_id=f"packet-{issue_id}",
            packet_sha256=_hash(f"packet:{issue_id}"),
            worktree_identity_sha256=_hash(f"worktree:{issue_id}"),
        )
        for issue_id in issue_ids
    }
    return AdmissionCandidate(readiness, estimates, assessment, bindings)


def _fixture_candidate(size: int) -> tuple[AdmissionCandidate, list[dict], dict]:
    readiness, estimates, items, policy = _fixture([600] * size)
    return (
        _candidate_from(
            readiness,
            estimates,
            policy,
            requested_workers=size,
        ),
        items,
        policy,
    )


class MemoryBdRunner:
    def __init__(self, issues: list[dict], *, actor: str = "admission-actor") -> None:
        self.actor = actor
        self.issues = {item["id"]: _exact_raw(item) for item in issues}
        self.actions: dict[str, list[str]] = {}
        self.claim_order: list[str] = []
        self.calls: list[tuple[str, ...]] = []

    def queue(self, bead_id: str, *actions: str) -> None:
        self.actions.setdefault(bead_id, []).extend(actions)

    def __call__(self, args: tuple[str, ...], **kwargs: object) -> BdCommandResult:
        actor = str(kwargs.get("actor", self.actor))
        self.calls.append(args)
        command = ("bd", *args)
        bead_id = args[1]
        if args[0] == "show":
            return BdCommandResult(
                command=command,
                returncode=0,
                stdout=json.dumps([self.issues[bead_id]]),
                stderr="",
                timed_out=False,
                timeout_seconds=5,
            )
        if args[0] != "update":
            raise AssertionError(args)
        self.claim_order.append(bead_id)
        action = self.actions.get(bead_id, ["success"]).pop(0)
        issue = self.issues[bead_id]
        committed = action in {"success", "timeout-committed", "error-committed"}
        if committed:
            issue.update(
                {
                    "status": "in_progress",
                    "assignee": actor,
                    "updated_at": "2026-07-21T20:00:01Z",
                    "started_at": "2026-07-21T20:00:01Z",
                }
            )
        elif action == "lost":
            issue.update(
                {
                    "status": "in_progress",
                    "assignee": "other-actor",
                    "updated_at": "2026-07-21T20:00:01Z",
                    "started_at": "2026-07-21T20:00:01Z",
                }
            )
        timed_out = action in {"timeout-committed", "timeout-uncommitted"}
        returncode = None if timed_out else (7 if action == "error-committed" else 0)
        stdout = (
            json.dumps({"status": "in_progress", "assignee": actor})
            if action == "spoof-output"
            else "{}"
        )
        return BdCommandResult(
            command=command,
            returncode=returncode,
            stdout=stdout,
            stderr="claim failed" if returncode else "",
            timed_out=timed_out,
            timeout_seconds=5,
        )


def _adapter(runner: MemoryBdRunner) -> BeadsClaimAdapter:
    return BeadsClaimAdapter(
        directory=ROOT,
        database=ROOT / ".beads" / "embeddeddolt",
        actor=runner.actor,
        timeout=5,
        runner=runner,
    )


def _live(binding: dict) -> dict:
    return binding


def _reserve(
    candidate: AdmissionCandidate,
    items: list[dict],
    *,
    runner: MemoryBdRunner | None = None,
    **kwargs: object,
):
    effective = runner or MemoryBdRunner(items)
    result = reserve_pool_cohort(
        candidate,
        claim_adapter=_adapter(effective),
        admission_nonce="admission-nonce-1",
        live_revalidate=_live,
        now="2026-07-21T20:00:02Z",
        **kwargs,
    )
    return result, effective


def _context(receipt: dict) -> dict:
    return build_dispatch_context(
        receipt,
        pool_contract_sha256="a" * 64,
        preflight_request_sha256="b" * 64,
        preflight_result_sha256="c" * 64,
        lease_set_sha256="d" * 64,
    )


class NativePoolAdmissionTests(unittest.TestCase):
    def test_n2_success_is_sorted_claim_backed_and_p1_7_bound(self) -> None:
        candidate, items, _ = _fixture_candidate(2)
        reservation, runner = _reserve(candidate, list(reversed(items)))

        self.assertTrue(reservation.admitted)
        self.assertEqual(runner.claim_order, ["bead-a", "bead-b"])
        self.assertEqual(validate_reservation_receipt(reservation.receipt), [])
        self.assertEqual(
            reservation.receipt["retained_owned_issue_ids"],
            ["bead-a", "bead-b"],
        )
        self.assertNotEqual(reservation.receipt["claim_actor"], runner.actor)
        self.assertEqual(
            reservation.claim_adapter.actor,
            reservation.receipt["claim_actor"],
        )
        self.assertEqual(reservation.capability.state, "available")

    def test_productive_n3_and_forged_n4_reject_before_any_claim(self) -> None:
        candidate, items, _ = _fixture_candidate(3)
        runner = MemoryBdRunner(items)
        with self.assertRaisesRegex(
            NativePoolAdmissionError,
            "productive-cohort-size-three-unreleased",
        ):
            _reserve(candidate, items, runner=runner)
        self.assertEqual(runner.claim_order, [])

        forged_assessment = deepcopy(dict(candidate.proportionality_assessment))
        forged_assessment["selected_cohort"]["issue_ids"].append("bead-d")
        forged = AdmissionCandidate(
            candidate.readiness_evidence,
            candidate.work_estimates,
            forged_assessment,
            candidate.child_bindings,
        )
        with self.assertRaisesRegex(
            NativePoolAdmissionError,
            "cohort-size-four-or-more-forbidden",
        ):
            _reserve(forged, items, runner=runner)
        self.assertEqual(runner.claim_order, [])

    def test_timeout_reconciliation_uses_exact_show_not_command_output(self) -> None:
        _, items, _ = _fixture_candidate(2)
        runner = MemoryBdRunner(items)
        runner.queue("bead-a", "timeout-committed")
        committed = _adapter(runner).claim("bead-a")
        self.assertTrue(committed.owned)
        self.assertEqual(committed.receipt["outcome"], "claimed-after-timeout")

        runner = MemoryBdRunner(items)
        runner.queue("bead-a", "timeout-uncommitted")
        uncommitted = _adapter(runner).claim("bead-a")
        self.assertFalse(uncommitted.owned)
        self.assertEqual(uncommitted.receipt["outcome"], "claim-lost")

        runner = MemoryBdRunner(items)
        runner.queue("bead-a", "spoof-output")
        spoofed = _adapter(runner).claim("bead-a")
        self.assertFalse(spoofed.owned)
        self.assertEqual(spoofed.receipt["outcome"], "claim-lost")

    def test_partial_race_rebuilds_once_and_requires_owned_inclusion(self) -> None:
        _, _, all_items, policy = _fixture([600, 600, 600])
        initial_ready = build_ready_set_evidence(
            all_items[:2],
            epic_id="epic-initial",
            requested_workers=2,
            policy_document=policy,
        )
        replacement_items = [all_items[0], all_items[2]]
        replacement_ready = build_ready_set_evidence(
            replacement_items,
            epic_id="epic-replacement",
            requested_workers=2,
            policy_document=policy,
        )
        all_estimates = {
            item["id"]: item["raw"]["metadata"]["cwo_ready_set_admission"]["work_plan"]
            for item in all_items
        }
        initial = _candidate_from(
            initial_ready,
            {key: all_estimates[key] for key in ("bead-a", "bead-b")},
            policy,
            requested_workers=2,
        )
        replacement = _candidate_from(
            replacement_ready,
            {key: all_estimates[key] for key in ("bead-a", "bead-c")},
            policy,
            requested_workers=2,
        )
        runner = MemoryBdRunner(all_items)
        runner.queue("bead-b", "lost")
        calls: list[tuple[frozenset[str], str]] = []

        def rebuild(
            prior: AdmissionCandidate,
            owned: frozenset[str],
            lost: str,
        ) -> AdmissionCandidate:
            del prior
            calls.append((owned, lost))
            return replacement

        reservation, _ = _reserve(
            initial,
            all_items,
            runner=runner,
            rebuild=rebuild,
        )
        self.assertTrue(reservation.admitted)
        self.assertEqual(calls, [(frozenset({"bead-a"}), "bead-b")])
        self.assertEqual(runner.claim_order, ["bead-a", "bead-b", "bead-c"])
        self.assertEqual(reservation.receipt["recompute_count"], 1)
        self.assertEqual(
            reservation.receipt["retained_owned_issue_ids"],
            ["bead-a", "bead-c"],
        )

        omission_ready = build_ready_set_evidence(
            all_items[1:],
            epic_id="epic-omission",
            requested_workers=2,
            policy_document=policy,
        )
        omission = _candidate_from(
            omission_ready,
            {key: all_estimates[key] for key in ("bead-b", "bead-c")},
            policy,
            requested_workers=2,
        )
        runner = MemoryBdRunner(all_items)
        runner.queue("bead-b", "lost")
        with self.assertRaisesRegex(
            NativePoolAdmissionError,
            "rebuild-omitted-retained-owned-claim",
        ):
            _reserve(
                initial,
                all_items,
                runner=runner,
                rebuild=lambda *_: omission,
            )

    def test_second_loss_stops_without_refill(self) -> None:
        _, _, all_items, policy = _fixture([600, 600, 600])
        estimates = {
            item["id"]: item["raw"]["metadata"]["cwo_ready_set_admission"]["work_plan"]
            for item in all_items
        }
        initial_ready = build_ready_set_evidence(
            all_items[:2],
            epic_id="epic-first",
            requested_workers=2,
            policy_document=policy,
        )
        replacement_ready = build_ready_set_evidence(
            [all_items[0], all_items[2]],
            epic_id="epic-second",
            requested_workers=2,
            policy_document=policy,
        )
        initial = _candidate_from(
            initial_ready,
            {key: estimates[key] for key in ("bead-a", "bead-b")},
            policy,
            requested_workers=2,
        )
        replacement = _candidate_from(
            replacement_ready,
            {key: estimates[key] for key in ("bead-a", "bead-c")},
            policy,
            requested_workers=2,
        )
        runner = MemoryBdRunner(all_items)
        runner.queue("bead-b", "lost")
        runner.queue("bead-c", "lost")
        rebuild_count = 0

        def rebuild(*_: object) -> AdmissionCandidate:
            nonlocal rebuild_count
            rebuild_count += 1
            return replacement

        reservation, _ = _reserve(
            initial,
            all_items,
            runner=runner,
            rebuild=rebuild,
        )
        self.assertFalse(reservation.admitted)
        self.assertIsNone(reservation.capability)
        self.assertEqual(rebuild_count, 1)
        self.assertEqual(runner.claim_order, ["bead-a", "bead-b", "bead-c"])
        self.assertEqual(reservation.receipt["status"], "claim-lost")

    def test_live_binding_drift_fails_closed_after_claims(self) -> None:
        candidate, items, _ = _fixture_candidate(2)
        runner = MemoryBdRunner(items)

        def drift(binding: dict) -> dict:
            binding["packet_sha256"] = "f" * 64
            return binding

        with self.assertRaisesRegex(
            NativePoolAdmissionError,
            "live-revalidation-binding-drift",
        ):
            reserve_pool_cohort(
                candidate,
                claim_adapter=_adapter(runner),
                admission_nonce="drift-nonce",
                live_revalidate=drift,
                now="2026-07-21T20:00:02Z",
            )
        self.assertEqual(runner.claim_order, ["bead-a", "bead-b"])

    def test_capability_blocks_construction_copy_pickle_and_subclass(self) -> None:
        candidate, items, _ = _fixture_candidate(2)
        reservation, _ = _reserve(candidate, items)
        capability = reservation.capability
        self.assertIsNotNone(capability)
        assert capability is not None

        with self.assertRaisesRegex(
            NativePoolAdmissionError,
            "construction-forbidden",
        ):
            FixedCohortAdmissionCapability(
                reservation_sha256="a" * 64,
                fixed_cohort_sha256_value="b" * 64,
                child_bindings_sha256="c" * 64,
                token=object(),
            )
        with self.assertRaises(TypeError):
            copy(capability)
        with self.assertRaises(TypeError):
            deepcopy(capability)
        with self.assertRaises(TypeError):
            pickle.dumps(capability)
        with self.assertRaisesRegex(TypeError, "subclass-forbidden"):

            class ForgedCapability(FixedCohortAdmissionCapability):
                pass

    def test_receipt_tamper_and_reseal_cannot_grant_authority(self) -> None:
        candidate, items, _ = _fixture_candidate(2)
        reservation, _ = _reserve(candidate, items)
        capability = reservation.capability
        assert capability is not None
        tampered = deepcopy(dict(reservation.receipt))
        tampered["admission_nonce"] = "attacker-resealed"
        unsigned = dict(tampered)
        unsigned.pop("reservation_sha256")
        tampered["reservation_sha256"] = canonical_admission_sha256(unsigned)
        self.assertEqual(validate_reservation_receipt(tampered), [])
        with self.assertRaisesRegex(
            NativePoolAdmissionError,
            "dispatch-capability-binding-mismatch",
        ):
            consume_pool_admission(
                capability,
                tampered,
                _context(tampered),
                claim_adapter=reservation.claim_adapter,
                live_revalidate=_live,
                commit=lambda _: None,
                now="2026-07-21T20:00:03Z",
            )
        self.assertEqual(capability.state, "available")

    def test_concurrent_duplicate_consume_has_one_winner(self) -> None:
        candidate, items, _ = _fixture_candidate(2)
        reservation, _ = _reserve(candidate, items)
        capability = reservation.capability
        assert capability is not None
        barrier = Barrier(2)
        commits: list[str] = []
        commit_lock = Lock()

        def attempt() -> str:
            barrier.wait()
            try:
                receipt = consume_pool_admission(
                    capability,
                    reservation.receipt,
                    _context(dict(reservation.receipt)),
                    claim_adapter=reservation.claim_adapter,
                    live_revalidate=_live,
                    commit=lambda value: (
                        commit_lock.acquire(),
                        commits.append(value["dispatch_sha256"]),
                        commit_lock.release(),
                    ),
                    now="2026-07-21T20:00:03Z",
                )
            except NativePoolAdmissionError:
                return "rejected"
            self.assertEqual(validate_dispatch_receipt(receipt), [])
            return "committed"

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda _: attempt(), range(2)))
        self.assertEqual(sorted(outcomes), ["committed", "rejected"])
        self.assertEqual(len(commits), 1)
        self.assertEqual(capability.state, "retired")

    def test_precommit_failure_releases_but_commit_and_postcommit_failures_retire(self) -> None:
        candidate, items, _ = _fixture_candidate(2)
        reservation, _ = _reserve(candidate, items)
        capability = reservation.capability
        assert capability is not None

        def fail(_: object) -> None:
            raise RuntimeError("boom")

        with self.assertRaisesRegex(RuntimeError, "boom"):
            consume_pool_admission(
                capability,
                reservation.receipt,
                _context(dict(reservation.receipt)),
                claim_adapter=reservation.claim_adapter,
                live_revalidate=_live,
                precommit=fail,
                commit=lambda _: None,
            )
        self.assertEqual(capability.state, "available")
        with self.assertRaisesRegex(RuntimeError, "boom"):
            consume_pool_admission(
                capability,
                reservation.receipt,
                _context(dict(reservation.receipt)),
                claim_adapter=reservation.claim_adapter,
                live_revalidate=_live,
                commit=fail,
            )
        self.assertEqual(capability.state, "retired")

        reservation, _ = _reserve(candidate, items)
        capability = reservation.capability
        assert capability is not None
        with self.assertRaisesRegex(RuntimeError, "boom"):
            consume_pool_admission(
                capability,
                reservation.receipt,
                _context(dict(reservation.receipt)),
                claim_adapter=reservation.claim_adapter,
                live_revalidate=_live,
                commit=lambda _: None,
                postcommit=fail,
            )
        self.assertEqual(capability.state, "retired")

    def test_fixed_cohort_context_mismatch_releases_without_commit(self) -> None:
        candidate, items, _ = _fixture_candidate(2)
        reservation, _ = _reserve(candidate, items)
        capability = reservation.capability
        assert capability is not None
        context = _context(dict(reservation.receipt))
        context["fixed_cohort_sha256"] = "f" * 64
        commits: list[dict] = []
        with self.assertRaisesRegex(
            NativePoolAdmissionError,
            "dispatch-context-binding-mismatch",
        ):
            consume_pool_admission(
                capability,
                reservation.receipt,
                context,
                claim_adapter=reservation.claim_adapter,
                live_revalidate=_live,
                commit=commits.append,
            )
        self.assertEqual(commits, [])
        self.assertEqual(capability.state, "available")

    def test_public_consumer_revalidates_claims_under_capability_lock(self) -> None:
        candidate, items, _ = _fixture_candidate(2)
        reservation, runner = _reserve(candidate, items)
        capability = reservation.capability
        assert capability is not None
        bead_id = reservation.receipt["issue_ids"][0]
        runner.issues[bead_id]["title"] += " drift"
        commits: list[dict] = []

        with self.assertRaisesRegex(
            NativePoolAdmissionError,
            "live-revalidation-claim-drift",
        ):
            consume_pool_admission(
                capability,
                reservation.receipt,
                _context(dict(reservation.receipt)),
                claim_adapter=reservation.claim_adapter,
                live_revalidate=_live,
                commit=commits.append,
            )
        self.assertEqual(commits, [])
        self.assertEqual(capability.state, "available")

    def test_real_temporary_beads_claim_has_exact_started_at_transition(self) -> None:
        with TemporaryDirectory(prefix="cwo-p113b-beads-") as directory:
            subprocess.run(
                ["bd", "init", "--prefix", "p13", "--quiet"],
                cwd=directory,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            created = subprocess.run(
                ["bd", "create", "claim target", "--type", "task", "--json"],
                cwd=directory,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            issue_id = json.loads(created.stdout)["id"]
            adapter = BeadsClaimAdapter(
                directory=directory,
                database=Path(directory) / ".beads" / "embeddeddolt",
                actor="admission-real-test",
                timeout=20,
            )
            transition = adapter.claim(issue_id)
            self.assertTrue(transition.owned)
            self.assertEqual(transition.receipt["outcome"], "claimed")
            self.assertEqual(transition.post_issue["status"], "in_progress")
            self.assertEqual(
                transition.post_issue["assignee"],
                "admission-real-test",
            )
            self.assertTrue(transition.post_issue["started_at"])

    def test_real_concurrent_same_base_actor_allows_one_admission_commit(self) -> None:
        with TemporaryDirectory(prefix="cwo-p113b-real-race-") as directory:
            subprocess.run(
                ["bd", "init", "--prefix", "race", "--quiet"],
                cwd=directory,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            created = subprocess.run(
                ["bd", "create", "race target", "--type", "task", "--json"],
                cwd=directory,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            issue_id = json.loads(created.stdout)["id"]
            _, _, _, policy = _fixture([600])
            template = _set_runtime(ready_item(issue_id), 600, policy=policy)
            subprocess.run(
                [
                    "bd",
                    "update",
                    issue_id,
                    "--title",
                    issue_id,
                    "--priority",
                    "1",
                    "--set-labels",
                    "implementation",
                    "--metadata",
                    json.dumps(template["raw"]["metadata"]),
                    "--json",
                ],
                cwd=directory,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            shown = subprocess.run(
                ["bd", "show", issue_id, "--json"],
                cwd=directory,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            raw = json.loads(shown.stdout)[0]
            item = {
                "id": issue_id,
                "title": raw["title"],
                "type": raw["issue_type"],
                "status": raw["status"],
                "priority": raw["priority"],
                "labels": raw["labels"],
                "dependencies": [],
                "raw": {**raw, "_cwo_executable_leaf": True},
            }
            readiness = build_ready_set_evidence(
                [item],
                epic_id="real-race-epic",
                requested_workers=1,
                policy_document=policy,
            )
            estimates = {
                issue_id: raw["metadata"]["cwo_ready_set_admission"]["work_plan"]
            }
            candidate = _candidate_from(
                readiness,
                estimates,
                policy,
                requested_workers=1,
            )
            update_barrier = Barrier(2)

            def race_runner(args: tuple[str, ...], **kwargs: object) -> BdCommandResult:
                if args[0] == "update":
                    update_barrier.wait(timeout=20)
                return run_bd_structured(args, **kwargs)

            base_adapter = BeadsClaimAdapter(
                directory=directory,
                database=Path(directory) / ".beads" / "embeddeddolt",
                actor="shared-admission-base",
                timeout=20,
                runner=race_runner,
            )

            def attempt() -> object:
                try:
                    return reserve_pool_cohort(
                        candidate,
                        claim_adapter=base_adapter,
                        admission_nonce="shared-race-nonce",
                        live_revalidate=_live,
                        now="2026-07-21T20:00:02Z",
                    )
                except NativePoolAdmissionError as error:
                    return error

            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = list(executor.map(lambda _: attempt(), range(2)))
            admitted = [
                outcome
                for outcome in outcomes
                if not isinstance(outcome, BaseException) and outcome.admitted
            ]
            self.assertEqual(len(admitted), 1, outcomes)
            winner = admitted[0]
            self.assertNotEqual(
                winner.receipt["claim_actor"],
                base_adapter.actor,
            )
            final_show = json.loads(
                subprocess.run(
                    ["bd", "show", issue_id, "--json"],
                    cwd=directory,
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).stdout
            )[0]
            self.assertEqual(final_show["assignee"], winner.receipt["claim_actor"])
            commits: list[str] = []
            dispatch = consume_pool_admission(
                winner.capability,
                winner.receipt,
                _context(dict(winner.receipt)),
                claim_adapter=winner.claim_adapter,
                live_revalidate=_live,
                commit=lambda receipt: commits.append(receipt["dispatch_sha256"]),
            )
            self.assertEqual(commits, [dispatch["dispatch_sha256"]])


if __name__ == "__main__":
    unittest.main()
