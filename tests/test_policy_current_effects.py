"""Current entry points refuse malformed current policy with zero effects; historical records stay historical.

Evidence for current-policy affected-contract compatibility. Every test drives a real
current entry point (a CLI ``main`` in process, or the native release builder) and wraps
its effect boundaries in spies:

- dispatch: ``dispatch_work.execute_local_envelope`` and the dispatch or route artifact on stdout;
- persistence: ``record_audit_event`` in each caller's namespace and in ``cwo_core.audit``,
  the audit file itself, and ``build_contractor_packet.atomic_write_text`` (packet files);
- promotion: ``native_release._register_canary`` (release registry) and ``write_release_evidence``;
- acceptance: verdicts returned by ``evaluate_return.make_acceptance_decision``.

Each refusal has a positive control: the same invocation with the shipped policy. The
positive controls reach the stdout artifacts, ``record_audit_event`` in ``dispatch_work``,
``build_contractor_packet`` and ``evaluate_return``, ``atomic_write_text``, the acceptance
verdicts and (historical policy only) ``native_release._register_canary``, so a zero count on
those means the effect was prevented, not that the spy was unwired. Three spies are additional
guards that no positive control reaches, so their zero counts show nothing by themselves:
``dispatch_work.execute_local_envelope`` (local invocation is unavailable), ``write_release_evidence``
(only the manage_native_release CLI writes evidence; the tests call the builders, which return it) and
``cwo_core.audit.record_audit_event``
(each CLI imports ``record_audit_event`` by name, so its calls reach the caller's spy instead).
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable, Iterator
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_contractor_packet  # noqa: E402
import dispatch_work  # noqa: E402
import evaluate_return  # noqa: E402
import route_work  # noqa: E402
from cwo_core import audit, native_release, operative_routing, packets, policy, return_risk  # noqa: E402
from cwo_core.errors import CWOError  # noqa: E402
from cwo_core.paths import cwo_temp_dir  # noqa: E402
from cwo_core.host_records import HostRecordStore, using_test_store  # noqa: E402

import tests.test_native_release as release_tests  # noqa: E402  (module import: its test classes are not collected here)
import tests.test_operative_routing as routing_tests  # noqa: E402
from tests.historical_policy_fixtures import historical_v2_policy  # noqa: E402

RETURN_TEXT = """## Summary
Reviewed the README examples for accuracy.

## Findings
- The install example uses the documented script path.

## Evidence
- README.md lines 10-20 were read.

## Risks
- None found beyond the documented limits.
"""

# Digests of unchanged historical policy inputs; the fixed v2 and v3 route
# compatibility records bind to these exact policy bytes.
BASE_OPERATIVE_POLICY_SHA256 = "c3e1db87e8ddf2417f30ca68065c416091f4accdd8d839d97b943e081ecf7f22"
BASE_TASK_SELECTED_POLICY_SHA256 = "26257b1b997ada4a9583c0ed7cd09c99ecff4923aff84d2486ab0587c6e9902a"

HISTORICAL_V2_REFUSAL = "historical v2 route is parseable but cannot authorize new dispatch"


def _read(name: str) -> dict[str, Any]:
    return json.loads((ROOT / "policy" / f"{name}.yaml").read_text(encoding="utf-8"))


@contextlib.contextmanager
def current_policy(name: str | None = None, mutate: Callable[[dict[str, Any]], None] | None = None,
                   raw: str | None = None, location: str = "") -> Iterator[Path]:
    """A copy of the shipped policy directory, optionally with one document changed, and a fresh audit file.

    ``location`` places the policy directory under that relative path of the temporary directory.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        policy_dir = Path(tmpdir) / location / "policy"
        shutil.copytree(ROOT / "policy", policy_dir)
        if name is not None:
            text = raw
            if text is None:
                document = _read(name)
                if mutate is not None:
                    mutate(document)
                text = json.dumps(document, indent=2)
            (policy_dir / f"{name}.yaml").write_text(text, encoding="utf-8")
        policy.clear_policy_cache()
        try:
            with mock.patch.object(policy, "POLICY_DIR", policy_dir), \
                    mock.patch.object(audit, "AUDIT_LOG", Path(tmpdir) / "audit" / "audit.jsonl"), \
                    mock.patch.object(audit, "HOST_AUDIT_LOG", Path(tmpdir) / "audit" / "audit.jsonl"), \
                    using_test_store(HostRecordStore.for_tests(Path(tmpdir) / "audit")):
                yield Path(tmpdir)
        finally:
            policy.clear_policy_cache()


def _raw_replace(name: str, old: str, new: str) -> str:
    text = (ROOT / "policy" / f"{name}.yaml").read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"{old!r} not found in policy/{name}.yaml")
    return text.replace(old, new, 1)


class EffectSpies:
    """Counting spies that wrap (not replace) every effect boundary of the entry points under test."""

    BOUNDARIES = {
        "dispatch: dispatch_work.execute_local_envelope": (dispatch_work, "execute_local_envelope"),
        "persistence: dispatch_work.record_audit_event": (dispatch_work, "record_audit_event"),
        "persistence: build_contractor_packet.record_audit_event": (build_contractor_packet, "record_audit_event"),
        "persistence: build_contractor_packet.atomic_write_text": (build_contractor_packet, "atomic_write_text"),
        "persistence: evaluate_return.record_audit_event": (evaluate_return, "record_audit_event"),
        "persistence: cwo_core.audit.record_audit_event": (audit, "record_audit_event"),
        "promotion: native_release._register_canary": (native_release, "_register_canary"),
        "promotion: native_release.write_release_evidence": (native_release, "write_release_evidence"),
    }
    ACCEPTANCE = "acceptance: evaluate_return.make_acceptance_decision verdicts"

    def __enter__(self) -> "EffectSpies":
        self._stack = contextlib.ExitStack()
        self.mocks = {
            label: self._stack.enter_context(mock.patch.object(module, attribute, wraps=getattr(module, attribute)))
            for label, (module, attribute) in self.BOUNDARIES.items()
        }
        self.verdicts: list[Any] = []
        real_decision = evaluate_return.make_acceptance_decision

        def decision(*args: Any, **kwargs: Any) -> Any:
            result = real_decision(*args, **kwargs)
            self.verdicts.append(result)
            return result

        self._stack.enter_context(mock.patch.object(evaluate_return, "make_acceptance_decision", side_effect=decision))
        self.stdout = io.StringIO()
        self._stack.enter_context(contextlib.redirect_stdout(self.stdout))
        return self

    def __exit__(self, *exc: Any) -> None:
        self._stack.close()

    def counts(self) -> dict[str, int]:
        counts = {label: spy.call_count for label, spy in self.mocks.items()}
        counts[self.ACCEPTANCE] = len(self.verdicts)
        return counts

    def total(self) -> int:
        return sum(self.counts().values())


def run_main(module: Any, argv: list[str]) -> tuple[EffectSpies, BaseException | None]:
    """Run ``module.main()`` with ``argv`` under effect spies; return the spies and any exit raised."""
    raised: BaseException | None = None
    with mock.patch.object(sys, "argv", argv), EffectSpies() as spies:
        try:
            module.main()
        except SystemExit as exc:
            raised = exc
    return spies, raised


class RefusalAssertions(unittest.TestCase):
    def tearDown(self) -> None:
        policy.clear_policy_cache()

    def assert_refused_without_effects(self, spies: EffectSpies, raised: BaseException | None, home: Path,
                                       *fragments: str, audit_before: bytes | None = None) -> None:
        from cwo_core.policy_schema import PolicySchemaError

        self.assertIsNotNone(raised, f"malformed policy was accepted; effects {spies.counts()}")
        message = str(raised)
        for fragment in fragments:
            self.assertIn(fragment, message)
        # The refusal is the loader's, not a later consumer check, and it is a SystemExit (not a CWOError).
        self.assertTrue(isinstance(raised, PolicySchemaError) or "is not JSON-compatible YAML" in message, message)
        self.assertNotIsInstance(raised, CWOError)
        self.assertEqual(spies.counts(), {label: 0 for label in spies.counts()})
        self.assertEqual(spies.stdout.getvalue(), "")
        if audit_before is None:
            self.assertFalse((home / "audit" / "audit.jsonl").exists())
        else:
            self.assertEqual((home / "audit" / "audit.jsonl").read_bytes(), audit_before)


# Malformed current documents, each one a value the base coerced or accepted.
ROUTING_CASES = {
    "routing-policy: empty local-worker allowlist": (
        "routing-policy", lambda d: d["local_worker"].update(allowed_task_classes=[]), None, "allowed_task_classes"),
    "routing-policy: unknown default risk level": (
        "routing-policy", lambda d: d["defaults"].update(risk_level="lowest"), None, "defaults.risk_level"),
}
PEER_REVIEW_CASES = {
    "peer-review-policy: boolean minimum_peer_reviews": (
        "peer-review-policy", lambda d: d["defaults"].update(minimum_peer_reviews=False), None, "minimum_peer_reviews"),
    "peer-review-policy: misspelled required_for_risk_levels": (
        "peer-review-policy",
        lambda d: d.update(required_for_risk_level=d.pop("required_for_risk_levels")), None, "required_for_risk_levels"),
}
CONTROLS_CASES = {
    "contracting-controls: boolean sabotage weight": (
        "contracting-controls", lambda d: d["sabotage_policy"]["signal_weights"].update(prompt_injection=True), None,
        "prompt_injection"),
    "contracting-controls: string external quota": (
        "contracting-controls", lambda d: d["quota_policy"].update(external_manual_dispatches_per_epic="100000"), None,
        "external_manual_dispatches_per_epic"),
    "contracting-controls: empty external executor allowlist": (
        "contracting-controls", lambda d: d.update(allowed_external_executors=[]), None, "allowed_external_executors"),
    "contracting-controls: NaN language ratio": (
        "contracting-controls", None,
        _raw_replace("contracting-controls", '"unexpected_script_ratio": 0.2', '"unexpected_script_ratio": NaN'),
        "non-finite number NaN"),
    "contracting-controls: overflowing language ratio": (
        "contracting-controls", None,
        _raw_replace("contracting-controls", '"unexpected_script_ratio": 0.2', '"unexpected_script_ratio": 1e309'),
        "overflows to a non-finite value"),
}
THRESHOLD_CASE = {
    # Boolean quarantine thresholds must stop processing through return_risk._policy_thresholds.
    "contracting-controls: boolean quarantine threshold": (
        "contracting-controls", lambda d: d["sabotage_policy"]["thresholds"].update(quarantine=True), None,
        "quarantine"),
}


class CurrentEntryPointRefusalTests(RefusalAssertions):
    """Malformed current policy stops each current consumer before any effect."""

    ROUTE_ARGV = ["route_work.py", "Documentation review for public README examples.", "--json"]
    DISPATCH_ARGV = [
        "dispatch_work.py", "Documentation review for public README examples.", "--local-ok", "--prefer-local",
        "--share-boundary", "no-outside-sharing", "--requested-role", "documentation", "--bead", "bead-1",
        "--epic", "epic-1", "--dispatch-id", "dispatch-w10-effects", "--json",
    ]

    def packet_argv(self, output: Path) -> list[str]:
        return [
            "build_contractor_packet.py", "--bead", "complex-work-orchestration-example",
            "--bead-json-file", str(ROOT / "examples" / "sample-bead.json"), "--executor", "claude_code_manual",
            "--share-boundary", "redacted-packet", "--external-ok", "--epic", "epic-1",
            "--dispatch-id", "dispatch-w10-packet", "--format", "json", "--output", str(output),
        ]

    def evaluate_argv(self, home: Path) -> list[str]:
        path = home / "return.md"
        path.write_text(RETURN_TEXT, encoding="utf-8")
        packet = home / "evaluator-packet.json"
        with mock.patch.object(sys, "argv", self.packet_argv(packet)), contextlib.redirect_stdout(io.StringIO()):
            build_contractor_packet.main()
        return ["evaluate_return.py", "--file", str(path), "--contractor-packet", str(packet), "--json"]

    def test_route_work_refuses_malformed_routing_and_peer_review_policy(self) -> None:
        with current_policy() as home:
            spies, raised = run_main(route_work, self.ROUTE_ARGV)
            self.assertIsNone(raised)
            route = json.loads(spies.stdout.getvalue())
            self.assertIn("peer_review_count", route)
            self.assertFalse((home / "audit" / "audit.jsonl").exists())
        for label, (name, mutate, raw, fragment) in {**ROUTING_CASES, **PEER_REVIEW_CASES}.items():
            with self.subTest(case=label), current_policy(name, mutate, raw) as home:
                spies, raised = run_main(route_work, self.ROUTE_ARGV)
                self.assert_refused_without_effects(spies, raised, home, f"policy/{name}.yaml", fragment)

    def test_dispatch_work_refuses_malformed_policy_before_dispatch_or_audit(self) -> None:
        with current_policy() as home:
            spies, raised = run_main(dispatch_work, self.DISPATCH_ARGV)
            self.assertIsNone(raised)
            self.assertEqual(json.loads(spies.stdout.getvalue())["dispatch_id"], "dispatch-w10-effects")
            self.assertEqual(spies.mocks["persistence: dispatch_work.record_audit_event"].call_count, 1)
            self.assertTrue((home / "audit" / "audit.jsonl").exists())
        cases = {**ROUTING_CASES, **PEER_REVIEW_CASES, **CONTROLS_CASES}
        for label, (name, mutate, raw, fragment) in cases.items():
            with self.subTest(case=label), current_policy(name, mutate, raw) as home:
                spies, raised = run_main(dispatch_work, self.DISPATCH_ARGV)
                self.assert_refused_without_effects(spies, raised, home, f"{name}.yaml", fragment)

    def test_parse_refusals_name_the_policy_and_not_its_location(self) -> None:
        # A location like the per-shard temporary directories of run_parallel_unittest.py. The outbound
        # screen reads it as a high-entropy token, so a parse refusal that rendered the absolute path of
        # the policy file would be withheld by dispatch_work, depending on where the policy directory is.
        from cwo_core.outbound_screen import screen_outbound

        location = "cwo-worker-06-4koxusze/tmp_34ki81x/run-7d2qk9vx"
        self.assertEqual({finding.rule for finding in screen_outbound(location, surface="location").findings},
                         {"entropy"})
        parse_cases = {label: case for label, case in CONTROLS_CASES.items() if case[2] is not None}
        self.assertEqual(len(parse_cases), 2)
        for label, (name, mutate, raw, fragment) in parse_cases.items():
            with self.subTest(case=label), current_policy(name, mutate, raw, location=location) as home:
                spies, raised = run_main(dispatch_work, self.DISPATCH_ARGV)
                self.assert_refused_without_effects(
                    spies, raised, home, f"policy/{name}.yaml is not JSON-compatible YAML", fragment)
                self.assertNotIn("withheld", str(raised))
                self.assertNotIn(str(home), str(raised))

    def test_build_contractor_packet_refuses_malformed_contracting_controls(self) -> None:
        with current_policy() as home:
            output = home / "packet.json"
            spies, raised = run_main(build_contractor_packet, self.packet_argv(output))
            self.assertIsNone(raised)
            self.assertEqual(spies.mocks["persistence: build_contractor_packet.record_audit_event"].call_count, 1)
            self.assertEqual(spies.mocks["persistence: build_contractor_packet.atomic_write_text"].call_count, 1)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["executor"], "claude_code_manual")
        for label, (name, mutate, raw, fragment) in CONTROLS_CASES.items():
            with self.subTest(case=label), current_policy(name, mutate, raw) as home:
                output = home / "packet.json"
                spies, raised = run_main(build_contractor_packet, self.packet_argv(output))
                self.assert_refused_without_effects(spies, raised, home, f"{name}.yaml", fragment)
                self.assertFalse(output.exists())

    def test_dispatch_of_a_valid_packet_refuses_malformed_contracting_controls(self) -> None:
        for label, (name, mutate, raw, fragment) in {"positive control": (None, None, None, None), **CONTROLS_CASES}.items():
            with self.subTest(case=label), current_policy() as home:
                # The packet and its packet_built audit record are produced under the shipped policy.
                packet_path = home / "packet.json"
                _, raised = run_main(build_contractor_packet, self.packet_argv(packet_path))
                self.assertIsNone(raised)
                audit_before = (home / "audit" / "audit.jsonl").read_bytes()
                if name is not None:
                    document = raw if raw is not None else None
                    if document is None:
                        changed = _read(name)
                        mutate(changed)
                        document = json.dumps(changed, indent=2)
                    (policy.POLICY_DIR / f"{name}.yaml").write_text(document, encoding="utf-8")
                policy.clear_policy_cache()
                spies, raised = run_main(dispatch_work, ["dispatch_work.py", "--packet", str(packet_path), "--json"])
                if name is None:
                    self.assertIsNone(raised)
                    self.assertEqual(spies.mocks["persistence: dispatch_work.record_audit_event"].call_count, 1)
                    self.assertEqual(json.loads(spies.stdout.getvalue())["dispatch_id"], "dispatch-w10-packet")
                    continue
                self.assertIsNotNone(raised, f"malformed policy was accepted; effects {spies.counts()}")
                self.assertIn(fragment, str(raised))
                self.assertNotIsInstance(raised, CWOError)
                self.assertEqual(spies.total(), 0, spies.counts())
                self.assertEqual(spies.stdout.getvalue(), "")
                self.assertEqual((home / "audit" / "audit.jsonl").read_bytes(), audit_before)

    def test_evaluate_return_refuses_malformed_contracting_controls_without_acceptance(self) -> None:
        with current_policy() as home:
            spies, raised = run_main(evaluate_return, self.evaluate_argv(home))
            self.assertIsNone(raised)
            self.assertEqual(len(spies.verdicts), 1)
            self.assertEqual(spies.mocks["persistence: evaluate_return.record_audit_event"].call_count, 1)
            self.assertIn("verdict", json.loads(spies.stdout.getvalue()))
        for label, (name, mutate, raw, fragment) in {**CONTROLS_CASES, **THRESHOLD_CASE}.items():
            with self.subTest(case=label), current_policy() as home:
                argv = self.evaluate_argv(home)
                audit_before = (home / "audit" / "audit.jsonl").read_bytes()
                if raw is None:
                    changed = _read(name)
                    mutate(changed)
                    document = json.dumps(changed, indent=2)
                else:
                    document = raw
                (policy.POLICY_DIR / f"{name}.yaml").write_text(document, encoding="utf-8")
                policy.clear_policy_cache()
                spies, raised = run_main(evaluate_return, argv)
                self.assert_refused_without_effects(spies, raised, home, f"{name}.yaml", fragment,
                                                    audit_before=audit_before)


class ExceptionTypeChangeTests(RefusalAssertions):
    """Callers that caught only CWOPolicyError around a covered reader cannot turn the refusal into an answer."""

    def test_return_risk_threshold_refusal_is_now_a_system_exit_that_escapes_cwo_error_handlers(self) -> None:
        name, mutate, _, fragment = THRESHOLD_CASE["contracting-controls: boolean quarantine threshold"]
        with current_policy(name, mutate):
            for call in (return_risk.sabotage_thresholds, return_risk.malpractice_thresholds):
                with self.subTest(call=call.__name__):
                    with self.assertRaises(SystemExit) as raised:
                        try:
                            call()
                        except CWOError:  # Exercise a caller that catches only the domain error.
                            self.fail("refusal was a CWOError a caller could catch and continue past")
                    self.assertIn(fragment, str(raised.exception))

    def test_packet_validation_does_not_fold_the_refusal_into_its_error_list(self) -> None:
        # validate_contractor_packet catches CWOPolicyError around language checks and returns errors;
        # a malformed policy must stop it instead of producing a list a caller might filter.
        with current_policy() as home:
            packet_path = home / "packet.json"
            _, raised = run_main(build_contractor_packet, self.packet_argv(packet_path))
            self.assertIsNone(raised)
            packet = json.loads(packet_path.read_text(encoding="utf-8"))
            self.assertEqual(packets.validate_contractor_packet(packet), [])
            for label, (name, mutate, raw, fragment) in CONTROLS_CASES.items():
                with self.subTest(case=label):
                    if raw is None:
                        changed = _read(name)
                        mutate(changed)
                        raw = json.dumps(changed, indent=2)
                    (policy.POLICY_DIR / f"{name}.yaml").write_text(raw, encoding="utf-8")
                    policy.clear_policy_cache()
                    with self.assertRaises(SystemExit) as raised:
                        result = packets.validate_contractor_packet(packet)
                        self.fail(f"validation returned {result!r}")
                    self.assertIn(fragment, str(raised.exception))
                    self.assertNotIsInstance(raised.exception, CWOError)

    def test_local_dispatch_language_handler_does_not_catch_the_refusal(self) -> None:
        # evaluate_return._load_local_dispatch_metadata converts CWOPolicyError from the language
        # metadata into its own message; the schema refusal reaches the caller unchanged.
        name, mutate, raw, fragment = CONTROLS_CASES["contracting-controls: NaN language ratio"]
        with current_policy(name, mutate, raw) as home:
            artifact = home / "dispatch.json"
            artifact.write_text(json.dumps({
                "route": {"recommended_executor": "local_secure_review_worker", "selected_executor": {}},
                "local_envelope": {"expected_return_language": "en", "expected_return_language_source": "packet-v2"},
                "local_response": {},
            }), encoding="utf-8")
            with self.assertRaises(SystemExit) as raised:
                evaluate_return._load_local_dispatch_metadata(artifact)
            self.assertIn(fragment, str(raised.exception))
            self.assertNotIn("Invalid local dispatch language metadata", str(raised.exception))

    packet_argv = CurrentEntryPointRefusalTests.packet_argv


class HistoricalRecordTests(RefusalAssertions):
    """A historical-valid record stays readable and valid historically and grants nothing current."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="cwo-w10-historical-")
        self.addCleanup(self.temp.cleanup)
        environment = mock.patch.dict(os.environ, {
            "CWO_TEMP_ROOT": self.temp.name, "CWO_SESSION_ID": "w10-historical-session",
        })
        environment.start()
        self.addCleanup(environment.stop)
        self.root = cwo_temp_dir(scope="session")
        registries = mock.patch.dict(os.environ, {
            "CWO_NATIVE_RELEASE_REGISTRY_ROOT": str(self.root / "registry"),
            "CWO_PRECOMMIT_REGISTRY_ROOT": str(self.root / "precommit-registry"),
        })
        registries.start()
        self.addCleanup(registries.stop)
        clock = mock.patch.object(operative_routing, "_now_iso", new=lambda: routing_tests.NOW)
        clock.start()
        self.addCleanup(clock.stop)

    def v2_record(self) -> tuple[dict[str, Any], dict[str, Any]]:
        """A genuine v2 fallback route record, produced under the historical (inactive v3) policy."""
        with historical_v2_policy():
            plan, route, _ = release_tests.NativeReleaseTests.fallback_canary_bundle(self)
        return plan, route

    def promote(self, plan: dict[str, Any], route: dict[str, Any], packet_id: str) -> dict[str, Any]:
        return native_release.build_canary_release_evidence(
            packet_id=packet_id, attempt_nonce=f"{packet_id}-attempt", work_plan=plan, workdir=self.root,
            operative_routing=route, now=routing_tests.NOW,
        )

    def test_policy_digests_bound_by_records_are_unchanged(self) -> None:
        policy.clear_policy_cache()
        self.assertEqual(operative_routing.operative_policy_sha256("connected-codex"), BASE_OPERATIVE_POLICY_SHA256)
        self.assertEqual(operative_routing.task_selected_policy_sha256("connected-codex"), BASE_TASK_SELECTED_POLICY_SHA256)

    def test_v2_record_is_historically_valid_and_promotable_only_under_its_historical_policy(self) -> None:
        plan, route = self.v2_record()
        self.assertEqual(route["version"], 2)
        with historical_v2_policy():
            self.assertEqual(operative_routing.validate_operative_route_for_model(
                route, operative_routing.LUNA_MODEL, work_estimate=plan, now=routing_tests.NOW,
                historical_parse=True), [])
            with EffectSpies() as spies:
                evidence = self.promote(plan, route, "w10-historical-control")
            self.assertEqual(spies.mocks["promotion: native_release._register_canary"].call_count, 1)
            self.assertEqual(evidence["requested_model"], operative_routing.LUNA_MODEL)
        # Readable and valid as history under the current policy too.
        self.assertEqual(operative_routing.validate_operative_route_for_model(
            route, operative_routing.LUNA_MODEL, work_estimate=plan, now=routing_tests.NOW, historical_parse=True), [])

    def test_v2_record_cannot_authorize_current_dispatch_or_promotion(self) -> None:
        plan, route = self.v2_record()
        policy.clear_policy_cache()
        self.assertEqual(operative_routing.validate_operative_route_for_model(
            route, operative_routing.LUNA_MODEL, work_estimate=plan, now=routing_tests.NOW), [HISTORICAL_V2_REFUSAL])
        with EffectSpies() as spies:
            with self.assertRaises(ValueError) as raised:
                self.promote(plan, route, "w10-historical-current")
        self.assertIn(HISTORICAL_V2_REFUSAL, str(raised.exception))
        self.assertEqual(spies.total(), 0, spies.counts())
        self.assertFalse((self.root / "registry" / "issued-canaries.json").exists())

    def test_relabelled_v2_record_is_refused_currently_and_historically(self) -> None:
        plan, route = self.v2_record()
        relabels: dict[str, Callable[[dict[str, Any]], None]] = {
            "version relabelled to 3": lambda r: r.update(version=3),
            "version relabelled to legacy 1": lambda r: r.update(version=1),
            "rebound to the current task-selected digest": lambda r: r.update(
                policy_sha256=operative_routing.task_selected_policy_sha256("connected-codex")),
        }
        for index, (label, relabel) in enumerate(relabels.items()):
            forged = copy.deepcopy(route)
            relabel(forged)
            with self.subTest(relabel=label):
                policy.clear_policy_cache()
                self.assertTrue(operative_routing.validate_operative_route_for_model(
                    forged, operative_routing.LUNA_MODEL, work_estimate=plan, now=routing_tests.NOW))
                with historical_v2_policy():
                    self.assertTrue(operative_routing.validate_operative_route_for_model(
                        forged, operative_routing.LUNA_MODEL, work_estimate=plan, now=routing_tests.NOW,
                        historical_parse=True))
                for scope, context in (("current", contextlib.nullcontext()), ("historical", historical_v2_policy())):
                    with context, EffectSpies() as spies:
                        with self.assertRaises(ValueError):
                            self.promote(plan, forged, f"w10-relabel-{scope}-{index}")
                    self.assertEqual(spies.total(), 0, (scope, spies.counts()))

    def test_stale_peer_review_thresholds_stay_readable_and_never_reach_acceptance(self) -> None:
        # peer-review-policy keeps the retired 30/60 block byte for byte; acceptance reads only 20/35/50.
        policy.clear_policy_cache()
        self.assertEqual(policy.peer_review_policy()["sabotage_thresholds"], {"review": 30, "quarantine": 60})
        self.assertEqual(return_risk.sabotage_thresholds(), {"review": 20, "architect_escalation": 35, "quarantine": 50})
        changed = _read("peer-review-policy")
        changed["sabotage_thresholds"] = {"review": 99, "quarantine": 100}
        with current_policy("peer-review-policy", lambda d: d.update(sabotage_thresholds=changed["sabotage_thresholds"])):
            self.assertEqual(return_risk.sabotage_thresholds(), {"review": 20, "architect_escalation": 35, "quarantine": 50})


if __name__ == "__main__":
    unittest.main()
