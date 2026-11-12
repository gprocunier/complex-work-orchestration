"""Synthetic offline metadata fixtures; no live canary, model or dispatch."""
from __future__ import annotations

import copy
import datetime as dt
import json
from pathlib import Path
import re
import sys
from types import MappingProxyType
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import native_release as release  # noqa: E402
from cwo_core.native_containment import containment_error  # noqa: E402
from cwo_core.policy import load_policy  # noqa: E402
from tests import test_maintenance_release as maintenance_fixture  # noqa: E402
from tests import test_native_release as release_fixture  # noqa: E402
from tests.historical_policy_fixtures import historical_v2_policy  # noqa: E402


BOOLEAN_POLICY_FIELDS = (
    ("canary_repository_work_authorized", False),
    ("canary_source_mutation_authorized", False),
    ("operative_release_enabled", True),
    ("fallback_requires_operative_routing", True),
)


def rebound(evidence: dict) -> dict:
    value = copy.deepcopy(evidence)
    value["evidence_sha256"] = release._evidence_hash(value)
    return value


class NativeReleaseLiteralTypesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = release_fixture.NativeReleaseTests(
            "test_canary_evidence_is_strict_bounded_and_nonoperative"
        )
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.source = load_policy("native-worker-execution")
        self.good = self.fixture.build()
        self.assertEqual(
            release.validate_native_release_evidence(
                self.good, policy=self.source, now=self.fixture.now_dt
            ),
            [],
        )

    def reject_policy(self, source: dict, message: str) -> None:
        with self.assertRaisesRegex(ValueError, re.escape(message)):
            release._policy(source)
        errors = release.validate_native_release_evidence(
            self.good, policy=source, now=self.fixture.now_dt
        )
        self.assertTrue(errors)
        self.assertIn(message, "; ".join(errors))
        self.assertIn(
            message,
            containment_error(
                "supervised-worker-fit-request", source, release_evidence=self.good
            ),
        )
        with mock.patch.object(release, "_register_canary") as register:
            with self.assertRaisesRegex(ValueError, re.escape(message)):
                self.fixture.build(policy=source)
            register.assert_not_called()
        for builder in (
            release.build_operative_release_evidence,
            release.authorize_operative_packet,
        ):
            with self.subTest(builder=builder.__name__):
                with self.assertRaisesRegex(ValueError, re.escape(message)):
                    builder(
                        candidate_packet=release_fixture.candidate_packet(self.fixture.root),
                        adjudication={},
                        canary_receipt={},
                        policy=source,
                    )
        path = self.fixture.root / "rejected-policy.json"
        with mock.patch.object(release, "load_policy", return_value=source):
            with self.assertRaisesRegex(ValueError, re.escape(message)):
                release.write_release_evidence(path, self.good)
        self.assertFalse(path.exists())

    def reject_evidence(self, evidence: dict, message: str) -> None:
        errors = release.validate_native_release_evidence(
            evidence, policy=self.source, now=self.fixture.now_dt
        )
        self.assertTrue(errors)
        self.assertIn(message, "; ".join(errors))
        self.assertIn(
            message,
            containment_error(
                "supervised-worker-fit-request", self.source, release_evidence=evidence
            ),
        )
        path = self.fixture.root / "rejected-evidence.json"
        with self.assertRaisesRegex(ValueError, re.escape(message)):
            release.write_release_evidence(path, evidence)
        self.assertFalse(path.exists())

    def test_policy_boolean_literals_require_actual_booleans(self) -> None:
        for field, expected in BOOLEAN_POLICY_FIELDS:
            with self.subTest(field=field):
                self.assertIs(self.source["native_release_evidence"][field], expected)
            for bad in (0, 1, 0.0, 1.0, not expected):
                with self.subTest(field=field, bad=repr(bad)):
                    source = copy.deepcopy(self.source)
                    source["native_release_evidence"][field] = bad
                    self.reject_policy(source, f"native_release_evidence.{field} must equal")

    def test_policy_version_requires_integer_one(self) -> None:
        for bad in (True, False, 1.0, 0.0, "1", None, 0, 3):
            with self.subTest(bad=repr(bad)):
                source = copy.deepcopy(self.source)
                source["native_release_evidence"]["version"] = bad
                self.reject_policy(source, "native_release_evidence.version must equal")

    def test_evidence_version_requires_integer_one_even_when_rebound(self) -> None:
        for bad in (True, False, 1.0, 0.0, "1", None, 0, 3):
            with self.subTest(bad=repr(bad)):
                evidence = copy.deepcopy(self.good)
                evidence["version"] = bad
                self.reject_evidence(
                    rebound(evidence), "native release evidence version must equal"
                )

    def test_boolean_evidence_fields_keep_their_existing_refusals(self) -> None:
        for field in ("repository_work_authorized", "source_mutation_authorized"):
            for bad in (0, 1, 0.0, 1.0):
                with self.subTest(field=field, bad=repr(bad)):
                    evidence = copy.deepcopy(self.good)
                    evidence[field] = bad
                    self.reject_evidence(rebound(evidence), f"{field} must be boolean")
            evidence = copy.deepcopy(self.good)
            evidence[field] = True
            self.reject_evidence(
                rebound(evidence),
                "canary release evidence cannot authorize repository work or source mutation",
            )

    def test_missing_unknown_and_wrong_literals_remain_invalid(self) -> None:
        for kind in ("missing", "unknown", "wrong-string"):
            with self.subTest(kind=kind):
                source = copy.deepcopy(self.source)
                evidence = copy.deepcopy(self.good)
                if kind == "missing":
                    del source["native_release_evidence"]["authority"]
                    del evidence["authority"]
                    policy_message = "native_release_evidence policy fields are invalid"
                    evidence_message = "native release evidence fields are invalid"
                elif kind == "unknown":
                    source["native_release_evidence"]["unexpected"] = True
                    evidence["unexpected"] = True
                    policy_message = "native_release_evidence policy fields are invalid"
                    evidence_message = "native release evidence fields are invalid"
                else:
                    source["native_release_evidence"]["authority"] = "unexpected"
                    evidence["authority"] = "unexpected"
                    policy_message = "native_release_evidence.authority must equal"
                    evidence_message = "native release evidence authority must equal"
                self.reject_policy(source, policy_message)
                self.reject_evidence(rebound(evidence), evidence_message)

    def test_valid_mapping_inputs_registration_and_write_remain_possible(self) -> None:
        source = copy.deepcopy(self.source)
        source["native_release_evidence"] = MappingProxyType(source["native_release_evidence"])
        self.assertEqual(
            release._policy(MappingProxyType(source)),
            self.source["native_release_evidence"],
        )
        self.assertEqual(
            release.validate_native_release_evidence(
                MappingProxyType(self.good), policy=MappingProxyType(source), now=self.fixture.now_dt
            ),
            [],
        )
        registry = json.loads((self.fixture.registry / "issued-canaries.json").read_text(encoding="utf-8"))
        self.assertIn(self.good["evidence_id"], registry["evidence_ids"])
        path = release.write_release_evidence(self.fixture.root / "valid.json", self.good)
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), self.good)
        with self.assertRaisesRegex(ValueError, "duplicate native release packet_id"):
            self.fixture.build(attempt_nonce="different-offline-attempt")

    def test_hash_lifetime_binding_and_nonoperative_controls_remain(self) -> None:
        evidence = copy.deepcopy(self.good)
        evidence["packet_id"] = "synthetic-unrebound-change"
        self.reject_evidence(evidence, "canonical hash mismatch")
        expired = self.fixture.now_dt + dt.timedelta(hours=1)
        self.assertTrue(release.validate_native_release_evidence(self.good, now=expired))
        self.assertTrue(
            release.validate_native_release_evidence(
                self.good, now=self.fixture.now_dt, operation="native-dispatch"
            )
        )
        self.assertTrue(
            release.validate_native_release_evidence(
                self.good, now=self.fixture.now_dt, expected_packet_id="unbound"
            )
        )
        evidence = copy.deepcopy(self.good)
        evidence["precommit_receipt_sha256"] = "1" * 64
        self.reject_evidence(
            rebound(evidence), "canary release evidence cannot claim post-canary or adjudication receipts"
        )

    def test_genuine_offline_operative_builder_and_candidate_version_guard(self) -> None:
        with historical_v2_policy():
            canary = self.fixture.accepting_canary_receipt()
            candidate = release_fixture.candidate_packet(self.fixture.root)
            adjudication = release_fixture.operative_adjudication(canary["receipt_sha256"])
            evidence = release.build_operative_release_evidence(
                candidate_packet=candidate, adjudication=adjudication,
                canary_receipt=canary, now=self.fixture.now,
            )
            self.assertEqual(release.validate_native_release_evidence(evidence, now=self.fixture.now_dt), [])
            for version in (True, False, 2.0):
                with self.subTest(version=repr(version)):
                    invalid = copy.deepcopy(candidate)
                    invalid["version"] = version
                    with self.assertRaisesRegex(ValueError, "candidate packet version must be integer 2"):
                        release.authorize_operative_packet(
                            candidate_packet=invalid, adjudication=adjudication,
                            canary_receipt=canary, now=self.fixture.now,
                        )

    def test_maintenance_delegation_retains_real_scoped_authority_checks(self) -> None:
        fixture = maintenance_fixture.MaintenanceReleaseTests(
            "test_live_owner_bound_shape_is_valid_not_product_acceptance"
        )
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        kwargs = {
            "maintenance_operation": fixture.cap,
            "maintenance_verifier": fixture.f.verifier,
            "now": fixture.now,
            "operation": "native-dispatch",
        }
        self.assertEqual(release.validate_native_release_evidence(fixture.value, **kwargs), [])
        self.assertTrue(release.validate_native_release_evidence(fixture.value, now=fixture.now))
        for version in (True, False, 2.0):
            with self.subTest(version=repr(version)):
                evidence = copy.deepcopy(fixture.value)
                evidence["version"] = version
                evidence = rebound(evidence)
                self.assertTrue(fixture.errors(evidence, operation="native-dispatch"))
                self.assertTrue(release.validate_native_release_evidence(evidence, **kwargs))
        fixture.f.store.settle(
            fixture.scope["operation_id"], fixture.cap.operation_sha256, outcome="accepted"
        )
        self.assertTrue(release.validate_native_release_evidence(fixture.value, **kwargs))


if __name__ == "__main__":
    unittest.main()
