from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from continue_sprint import build_continuation_brief, load_beads_items  # noqa: E402
from cwo_core.beads import BdCommandResult, run_bd_structured  # noqa: E402
from cwo_core.beads_ready_set import build_ready_set_evidence  # noqa: E402
from cwo_core.native_pool_admission import (  # noqa: E402
    AdmissionCandidate,
    BeadsClaimAdapter,
    NativePoolAdmissionError,
    build_dispatch_context,
    consume_pool_admission,
    reserve_pool_cohort,
)
from cwo_core.native_pool_admitted import run_admitted_native_pool  # noqa: E402
from cwo_core.native_pool_leases import PoolLeaseRegistry  # noqa: E402
from cwo_core.native_pool_preflight import run_pool_preflight  # noqa: E402
from cwo_core.native_pool_proportionality import (  # noqa: E402
    pool_proportionality_check,
)
from cwo_core.policy import load_policy  # noqa: E402
from tests.test_beads_ready_set import (  # noqa: E402
    ready_item,
    released_three_policy,
)
from tests.test_native_pool import FakeClock, PoolHarness  # noqa: E402
from tests.test_native_pool_admission import _candidate_from, _live  # noqa: E402
from tests.test_native_pool_admission_contracts import (  # noqa: E402
    _admitted_artifacts,
    _execution_inputs,
)
from tests.test_native_pool_proportionality import _set_runtime  # noqa: E402


BD_PATH = shutil.which("bd")


class TemporaryBeadsPoolGraph:
    def __init__(self, root: Path, *, leaf_count: int, policy: dict) -> None:
        self.root = root
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(
            [
                BD_PATH or "bd",
                "init",
                "--non-interactive",
                "--skip-agents",
                "--skip-hooks",
                "-p",
                "p16",
            ],
            cwd=root,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        self.epic = self.bd(
            "create",
            "P1-6 temporary graph",
            "--type",
            "epic",
            "--priority",
            "1",
            "--labels",
            "orchestration",
            "--silent",
        )
        self.package = self.bd(
            "create",
            "Open publication parent",
            "--type",
            "feature",
            "--parent",
            self.epic,
            "--priority",
            "1",
            "--labels",
            "publication-parent",
            "--silent",
        )
        self.leaf_ids: list[str] = []
        self.estimates: dict[str, dict] = {}
        for index in range(leaf_count):
            bead_id = self.bd(
                "create",
                f"Ready leaf {index}",
                "--type",
                "task",
                "--parent",
                self.package,
                "--priority",
                str(index + 1),
                "--labels",
                "implementation",
                "--silent",
            )
            fixture = _set_runtime(
                ready_item(
                    bead_id,
                    write_paths=[f"scripts/p1-6-{index}.py"],
                ),
                600,
                policy=policy,
            )
            metadata = fixture["raw"]["metadata"]
            self.bd(
                "update",
                bead_id,
                "--metadata",
                json.dumps(metadata),
                "--json",
            )
            self.leaf_ids.append(bead_id)
            self.estimates[bead_id] = metadata["cwo_ready_set_admission"][
                "work_plan"
            ]

    @property
    def database(self) -> Path:
        return self.root / ".beads" / "embeddeddolt"

    def bd(self, *args: str) -> str:
        return subprocess.check_output(
            [BD_PATH or "bd", *args],
            cwd=self.root,
            text=True,
        ).strip()

    def continuation(
        self,
        policy: dict,
        *,
        requested_workers: int = 3,
    ) -> tuple[list[dict], dict]:
        with mock.patch.dict(
            os.environ,
            {"BEADS_DIR": str(self.root / ".beads")},
        ):
            items = load_beads_items(self.epic)
        return items, build_continuation_brief(
            items,
            epic_id=self.epic,
            source="beads",
            requested_workers=requested_workers,
            policy_document=policy,
        )

    def show(self, *issue_ids: str) -> list[dict]:
        return json.loads(self.bd("show", *issue_ids, "--json"))


class RecordingBdRunner:
    def __init__(
        self,
        *,
        preempt_issue_id: str | None = None,
        drift_issue_id: str | None = None,
    ) -> None:
        self.preempt_issue_id = preempt_issue_id
        self.drift_issue_id = drift_issue_id
        self.preempted = False
        self.drifted = False
        self._show_counts: dict[str, int] = {}
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, args: tuple[str, ...], **kwargs: object) -> BdCommandResult:
        self.calls.append(args)
        if args[:1] == ("show",) and len(args) >= 2:
            issue_id = args[1]
            self._show_counts[issue_id] = self._show_counts.get(issue_id, 0) + 1
            if (
                issue_id == self.drift_issue_id
                and self._show_counts[issue_id] == 2
            ):
                drift = run_bd_structured(
                    ("update", issue_id, "--title", "drifted before claim", "--json"),
                    directory=kwargs["directory"],
                    database=kwargs["database"],
                    actor="p1-6-drift-actor",
                    timeout=kwargs.get("timeout"),
                )
                if not drift.succeeded:
                    raise AssertionError(drift)
                self.drifted = True
        if (
            self.preempt_issue_id is not None
            and not self.preempted
            and args[:2] == ("update", self.preempt_issue_id)
            and "--claim" in args
        ):
            competitor = run_bd_structured(
                args,
                directory=kwargs["directory"],
                database=kwargs["database"],
                actor="p1-6-competing-claim",
                timeout=kwargs.get("timeout"),
            )
            if not competitor.succeeded:
                raise AssertionError(competitor)
            self.preempted = True
        return run_bd_structured(args, **kwargs)


def claim_adapter(
    graph: TemporaryBeadsPoolGraph,
    runner: RecordingBdRunner,
) -> BeadsClaimAdapter:
    return BeadsClaimAdapter(
        directory=graph.root,
        database=graph.database,
        actor="p1-6-admission",
        timeout=20,
        runner=runner,
    )


def dispatch_context(reservation: dict) -> dict:
    return build_dispatch_context(
        reservation,
        pool_contract_sha256="a" * 64,
        preflight_request_sha256="b" * 64,
        preflight_result_sha256="c" * 64,
        lease_set_sha256="d" * 64,
    )


@unittest.skipUnless(BD_PATH, "bd CLI not available")
class NativePoolPhase1TemporaryBeadsTests(unittest.TestCase):
    def test_real_n1_fallback_and_n2_pool_preserve_open_parents(self) -> None:
        policy = load_policy("native-worker-execution")
        for size in (1, 2):
            with (
                self.subTest(size=size),
                tempfile.TemporaryDirectory(
                    prefix=f"cwo-p1-6-n{size}-"
                ) as temporary,
            ):
                graph = TemporaryBeadsPoolGraph(
                    Path(temporary),
                    leaf_count=size,
                    policy=policy,
                )
                items, readiness = graph.continuation(
                    policy,
                    requested_workers=size,
                )
                runner = RecordingBdRunner()
                if size == 1:
                    assessment = pool_proportionality_check(
                        readiness,
                        graph.estimates,
                        requested_workers=1,
                        policy_document=policy,
                    )
                    self.assertEqual(assessment["decision"], "single")
                    self.assertEqual(
                        assessment["fallback_issue_id"],
                        graph.leaf_ids[0],
                    )
                    self.assertIsNone(assessment["selected_cohort"])
                    self.assertEqual(runner.calls, [])
                    parents = {
                        item["id"]: item
                        for item in graph.show(graph.package, graph.epic)
                    }
                    self.assertEqual(parents[graph.package]["status"], "open")
                    self.assertEqual(parents[graph.epic]["status"], "open")
                    continue
                launch_root = Path(temporary) / "launch"
                launch_root.mkdir()
                fixture, reservation, contract, request = _admitted_artifacts(
                    launch_root,
                    size=size,
                    admission_fixture=(
                        readiness,
                        graph.estimates,
                        items,
                        policy,
                    ),
                    claim_adapter_override=claim_adapter(graph, runner),
                    claim_runner_override=runner,
                )
                preflight = run_pool_preflight(
                    request,
                    policy_document=policy,
                )
                self.assertTrue(preflight["accepted"], preflight["findings"])
                (
                    child_contracts,
                    tasks,
                    child_callbacks,
                    adapters,
                    pool_callbacks,
                    _clock,
                ) = _execution_inputs(fixture, contract)
                for child_adapter in adapters.values():
                    child_adapter.decisions = ["continue", "complete"]
                launched = run_admitted_native_pool(
                    reservation,
                    fixture.admission_capability,
                    contract,
                    request,
                    preflight,
                    child_contracts,
                    tasks,
                    child_callbacks,
                    claim_adapter=fixture.claim_adapter,
                    live_revalidate=_live,
                    pool_callbacks=pool_callbacks,
                    lease_registry=PoolLeaseRegistry(
                        launch_root / "leases.json",
                        owner_alive=lambda _owner: True,
                        now=FakeClock.now_utc,
                    ),
                    capability_receipt=fixture.pool_capability_receipt,
                    policy_document=policy,
                )

                receipt = launched["pool_receipt"]
                self.assertTrue(receipt["accepting"])
                self.assertEqual(reservation["issue_ids"], graph.leaf_ids)
                self.assertEqual(
                    [item["bead_id"] for item in receipt["child_dispositions"]],
                    graph.leaf_ids,
                )
                parents = {
                    item["id"]: item
                    for item in graph.show(graph.package, graph.epic)
                }
                self.assertEqual(parents[graph.package]["status"], "open")
                self.assertEqual(parents[graph.epic]["status"], "open")

    def test_n2_rejects_same_graph_before_claim_and_activation_fixture_runs_n3(
        self,
    ) -> None:
        default_policy = load_policy("native-worker-execution")
        activated_policy = released_three_policy()
        with tempfile.TemporaryDirectory(prefix="cwo-p1-6-e2e-") as temporary:
            graph = TemporaryBeadsPoolGraph(
                Path(temporary),
                leaf_count=3,
                policy=activated_policy,
            )
            _items, released_readiness = graph.continuation(default_policy)
            self.assertEqual(
                [item["id"] for item in released_readiness["recommended_ready_set"]],
                graph.leaf_ids,
            )
            self.assertFalse(released_readiness["dispatch_authorized"])
            released_candidate = _candidate_from(
                released_readiness,
                graph.estimates,
                default_policy,
                requested_workers=3,
            )
            rejected_runner = RecordingBdRunner()
            with self.assertRaisesRegex(
                NativePoolAdmissionError,
                "productive-cohort-size-three-unreleased",
            ):
                reserve_pool_cohort(
                    released_candidate,
                    claim_adapter=claim_adapter(graph, rejected_runner),
                    admission_nonce="released-n2-rejection",
                    live_revalidate=_live,
                    policy_document=default_policy,
                )
            self.assertEqual(
                [call for call in rejected_runner.calls if call[0] == "update"],
                [],
            )

            activated_items, activated_readiness = graph.continuation(
                activated_policy
            )
            runner = RecordingBdRunner()
            adapter = claim_adapter(graph, runner)
            launch_root = Path(temporary) / "launch"
            launch_root.mkdir()
            with mock.patch(
                "cwo_core.native_pool_capacity.load_policy",
                return_value=activated_policy,
            ):
                fixture, reservation, contract, request = _admitted_artifacts(
                    launch_root,
                    size=3,
                    admission_fixture=(
                        activated_readiness,
                        graph.estimates,
                        activated_items,
                        activated_policy,
                    ),
                    claim_adapter_override=adapter,
                    claim_runner_override=runner,
                )
                preflight = run_pool_preflight(
                    request,
                    policy_document=activated_policy,
                )
                self.assertTrue(preflight["accepted"], preflight["findings"])
                (
                    child_contracts,
                    tasks,
                    child_callbacks,
                    adapters,
                    pool_callbacks,
                    _clock,
                ) = _execution_inputs(fixture, contract)
                for child_adapter in adapters.values():
                    child_adapter.decisions = ["continue", "complete"]
                launched = run_admitted_native_pool(
                    reservation,
                    fixture.admission_capability,
                    contract,
                    request,
                    preflight,
                    child_contracts,
                    tasks,
                    child_callbacks,
                    claim_adapter=fixture.claim_adapter,
                    live_revalidate=_live,
                    pool_callbacks=pool_callbacks,
                    lease_registry=PoolLeaseRegistry(
                        launch_root / "leases.json",
                        owner_alive=lambda _owner: True,
                        now=FakeClock.now_utc,
                    ),
                    capability_receipt=fixture.pool_capability_receipt,
                    policy_document=activated_policy,
                )

            receipt = launched["pool_receipt"]
            self.assertTrue(receipt["accepting"])
            self.assertEqual(reservation["candidate_mode"], "released-capacity")
            self.assertEqual(
                [item["bead_id"] for item in receipt["child_dispositions"]],
                reservation["issue_ids"],
            )
            self.assertTrue(
                all(
                    item["implementation_bead_close_authorized"]
                    and not item["parent_close_authorized"]
                    and not item["publication_close_authorized"]
                    for item in receipt["child_dispositions"]
                )
            )
            claimed = {item["id"]: item for item in graph.show(*graph.leaf_ids)}
            self.assertTrue(
                all(
                    claimed[bead_id]["assignee"] == reservation["claim_actor"]
                    for bead_id in reservation["issue_ids"]
                )
            )
            parents = {item["id"]: item for item in graph.show(graph.package, graph.epic)}
            self.assertEqual(parents[graph.package]["status"], "open")
            self.assertEqual(parents[graph.epic]["status"], "open")

    def test_lost_real_claim_recomputes_once_and_dispatches_one_exact_cohort(
        self,
    ) -> None:
        activated_policy = released_three_policy()
        with tempfile.TemporaryDirectory(prefix="cwo-p1-6-race-") as temporary:
            graph = TemporaryBeadsPoolGraph(
                Path(temporary),
                leaf_count=4,
                policy=activated_policy,
            )
            requested_four = graph.continuation(
                activated_policy,
                requested_workers=4,
            )[1]
            self.assertEqual(
                len(requested_four["recommended_ready_set"]),
                3,
            )
            self.assertIn(
                "phase1-candidate-ceiling-applied",
                {reason["code"] for reason in requested_four["fanout_reasons"]},
            )
            items, readiness = graph.continuation(activated_policy)
            initial = _candidate_from(
                readiness,
                graph.estimates,
                activated_policy,
                requested_workers=3,
            )
            initial_ids = list(
                initial.proportionality_assessment["selected_cohort"]["issue_ids"]
            )
            lost_issue_id = sorted(initial_ids)[1]
            replacement_ids = [
                bead_id for bead_id in graph.leaf_ids if bead_id != lost_issue_id
            ]
            items_by_id = {item["id"]: item for item in items}
            replacement_items = [items_by_id[bead_id] for bead_id in replacement_ids]
            replacement_readiness = build_ready_set_evidence(
                replacement_items,
                epic_id=graph.epic,
                requested_workers=3,
                policy_document=activated_policy,
                scope_items=replacement_items,
            )
            replacement = _candidate_from(
                replacement_readiness,
                {
                    bead_id: graph.estimates[bead_id]
                    for bead_id in replacement_ids
                },
                activated_policy,
                requested_workers=3,
            )

            forged_assessment = deepcopy(initial.proportionality_assessment)
            forged_assessment["selected_cohort"]["issue_ids"].append(
                next(bead_id for bead_id in graph.leaf_ids if bead_id not in initial_ids)
            )
            forged = AdmissionCandidate(
                initial.readiness_evidence,
                initial.work_estimates,
                forged_assessment,
                initial.child_bindings,
            )
            rejected_runner = RecordingBdRunner()
            with self.assertRaisesRegex(
                NativePoolAdmissionError,
                "cohort-size-four-or-more-forbidden",
            ):
                reserve_pool_cohort(
                    forged,
                    claim_adapter=claim_adapter(graph, rejected_runner),
                    admission_nonce="forged-n4",
                    live_revalidate=_live,
                    policy_document=activated_policy,
                )
            self.assertEqual(rejected_runner.calls, [])

            runner = RecordingBdRunner(preempt_issue_id=lost_issue_id)
            adapter = claim_adapter(graph, runner)
            rebuild_calls: list[tuple[frozenset[str], str]] = []

            def rebuild(
                _prior: AdmissionCandidate,
                owned: frozenset[str],
                lost: str,
            ) -> AdmissionCandidate:
                rebuild_calls.append((owned, lost))
                return replacement

            with mock.patch(
                "cwo_core.native_pool_capacity.load_policy",
                return_value=activated_policy,
            ):
                reserved = reserve_pool_cohort(
                    initial,
                    claim_adapter=adapter,
                    admission_nonce="real-race-recompute",
                    live_revalidate=_live,
                    rebuild=rebuild,
                    policy_document=activated_policy,
                )
                commits: list[str] = []
                dispatch = consume_pool_admission(
                    reserved.capability,
                    reserved.receipt,
                    dispatch_context(reserved.receipt),
                    claim_adapter=reserved.claim_adapter,
                    live_revalidate=_live,
                    commit=lambda receipt: commits.append(receipt["dispatch_sha256"]),
                )
                with self.assertRaisesRegex(
                    NativePoolAdmissionError,
                    "admission-capability-not-available:retired",
                ):
                    consume_pool_admission(
                        reserved.capability,
                        reserved.receipt,
                        dispatch_context(reserved.receipt),
                        claim_adapter=reserved.claim_adapter,
                        live_revalidate=_live,
                        commit=lambda receipt: commits.append(
                            receipt["dispatch_sha256"]
                        ),
                    )

            self.assertTrue(runner.preempted)
            self.assertEqual(len(rebuild_calls), 1)
            self.assertEqual(rebuild_calls[0][1], lost_issue_id)
            self.assertEqual(reserved.receipt["recompute_count"], 1)
            self.assertEqual(reserved.receipt["issue_ids"], replacement_ids)
            self.assertEqual(commits, [dispatch["dispatch_sha256"]])

    def test_real_postclaim_drift_blocks_dispatch_commit(self) -> None:
        activated_policy = released_three_policy()
        with tempfile.TemporaryDirectory(prefix="cwo-p1-6-drift-") as temporary:
            graph = TemporaryBeadsPoolGraph(
                Path(temporary),
                leaf_count=3,
                policy=activated_policy,
            )
            _items, readiness = graph.continuation(activated_policy)
            candidate = _candidate_from(
                readiness,
                graph.estimates,
                activated_policy,
                requested_workers=3,
            )
            runner = RecordingBdRunner()
            with mock.patch(
                "cwo_core.native_pool_capacity.load_policy",
                return_value=activated_policy,
            ):
                reserved = reserve_pool_cohort(
                    candidate,
                    claim_adapter=claim_adapter(graph, runner),
                    admission_nonce="real-drift",
                    live_revalidate=_live,
                    policy_document=activated_policy,
                )
                graph.bd(
                    "update",
                    reserved.receipt["issue_ids"][0],
                    "--title",
                    "drifted after claim",
                    "--json",
                )
                commits: list[str] = []
                with self.assertRaisesRegex(
                    NativePoolAdmissionError,
                    "live-revalidation-claim-drift",
                ):
                    consume_pool_admission(
                        reserved.capability,
                        reserved.receipt,
                        dispatch_context(reserved.receipt),
                        claim_adapter=reserved.claim_adapter,
                        live_revalidate=_live,
                        commit=lambda receipt: commits.append(
                            receipt["dispatch_sha256"]
                        ),
                    )
            self.assertEqual(commits, [])
            self.assertEqual(reserved.capability.state, "available")

    def test_real_drift_between_cohort_precheck_and_claim_never_claims_or_dispatches(
        self,
    ) -> None:
        policy = load_policy("native-worker-execution")
        with tempfile.TemporaryDirectory(prefix="cwo-p1-6-preclaim-drift-") as temporary:
            graph = TemporaryBeadsPoolGraph(
                Path(temporary),
                leaf_count=2,
                policy=policy,
            )
            _items, readiness = graph.continuation(policy, requested_workers=2)
            candidate = _candidate_from(
                readiness,
                graph.estimates,
                policy,
                requested_workers=2,
            )
            drift_issue_id = candidate.proportionality_assessment[
                "selected_cohort"
            ]["issue_ids"][0]
            runner = RecordingBdRunner(drift_issue_id=drift_issue_id)
            reserved = reserve_pool_cohort(
                candidate,
                claim_adapter=claim_adapter(graph, runner),
                admission_nonce="real-preclaim-drift",
                live_revalidate=_live,
                policy_document=policy,
            )

            self.assertTrue(runner.drifted)
            self.assertFalse(reserved.admitted)
            self.assertIsNone(reserved.capability)
            self.assertEqual(reserved.receipt["status"], "claim-lost")
            self.assertEqual(reserved.receipt["claims"][0]["outcome"], "claim-lost")
            self.assertEqual(
                [
                    call
                    for call in runner.calls
                    if call[:2] == ("update", drift_issue_id)
                    and "--claim" in call
                ],
                [],
            )
            issue = graph.show(drift_issue_id)[0]
            self.assertEqual(issue["status"], "open")
            self.assertIn(issue.get("assignee"), (None, ""))


class NativePoolPhase1InterleavingTests(unittest.TestCase):
    def test_seeded_n3_lifecycle_and_failure_interleavings_are_bounded(self) -> None:
        policy = released_three_policy()
        generator = random.Random(0xC0DE)
        for case in range(24):
            continuation_counts = [generator.randrange(3) for _ in range(3)]
            decisions = [
                ["continue"] * count + ["complete"]
                for count in continuation_counts
            ]
            fail = (
                (generator.randrange(3), "check")
                if case % 3 == 0
                else None
            )
            with self.subTest(case=case, counts=continuation_counts, fail=fail):
                with tempfile.TemporaryDirectory() as temporary:
                    harness = PoolHarness(
                        temporary,
                        cap=3,
                        decisions=decisions,
                        fail=fail,
                        policy_document=policy,
                    )
                    progress = harness.coordinator.progress()
                    for _ in range(256):
                        if progress["status"] in {"closed", "control-failed"}:
                            break
                        before = sum(
                            len(adapter.calls)
                            for adapter in harness.adapters.values()
                        )
                        progress = harness.coordinator.step()
                        after = sum(
                            len(adapter.calls)
                            for adapter in harness.adapters.values()
                        )
                        self.assertLessEqual(after - before, 1)
                        if progress["wait_required"]:
                            harness.clock.sleep(seconds=progress["wait_seconds"])
                    else:
                        self.fail("seeded N3 interleaving did not terminate")
                    receipt = progress.get("receipt") or harness.coordinator.run()
                    self.assertEqual(
                        len(receipt["terminal_order"]),
                        len(set(receipt["terminal_order"])),
                    )
                    self.assertEqual(
                        {item["child_id"] for item in receipt["child_dispositions"]},
                        {"child-0", "child-1", "child-2"},
                    )
                    self.assertEqual(
                        [child["child_id"] for child in harness.coordinator.children],
                        ["child-0", "child-1", "child-2"],
                    )
                    if fail is None:
                        self.assertTrue(receipt["accepting"])
                    else:
                        self.assertFalse(receipt["accepting"])


if __name__ == "__main__":
    unittest.main()
