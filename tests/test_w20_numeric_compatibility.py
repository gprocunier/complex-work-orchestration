"""Bounded predecessor compatibility; no historical artifact grants authority."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_progress import (  # noqa: E402
    evaluate_worker_progress,
    validate_progress_decision_for_productive_use,
)
from cwo_core.native_pool_proportionality import (  # noqa: E402
    pool_proportionality_check,
    validate_pool_proportionality_assessment,
)
from cwo_core.work_sizing import (  # noqa: E402
    canonical_work_estimate_sha256,
    evaluate_work_estimate,
    validate_work_estimate,
    validate_worker_commitment,
)

FIXTURE = ROOT / "tests" / "fixtures" / "w20_numeric_predecessor_v1.json"
BASELINE_COMMIT = "55d99e2666556d949eba33dc590f53a2e1bccad9"
BASELINE_TREE = "fdbf3ea5117beb0cd4fc56ed976e4ca110d963e3"
HISTORICAL_REFUSAL = [
    "commitment version 1 is historical-inspection-only and dispatch-forbidden"
]
CAPTURES = {
    "progress": {
        "ordinary": "ed2c3fa88e6b361e35f69b51fec1087ba6c70cf5cc73c62616010dba58c58c19",
        "warning": "20de72f42b8b2a21952c67ff78b88d81dd2ea8a23c174fdf66193f0ca5624d78",
        "budget-stop": "2f64d653348f306d6cec31963d5ad8520924fecc07f3a839801b9e30ebccfd3e",
        "authority-stop": "f5b135ce551dddf16ec5e74d56756c4ac743bf105327df5cb52dd3c4fddd24fd",
    },
    "work_sizing": {
        "semantic": "8b4a6624406ded95c005989c8c2570a2d41c7fe1b1c82d08d1e9e29c2fe7ee63",
        "literal": "0a56f7a16cca4f4599f3408d03ac4a7391b145f047f385284959f8752026c27c",
        "narrow": "7d77aecca9b53c1d1f9744bc8e0a66a7a7752f5dd0dc875dbe97e5cea07afc98",
    },
    "proportionality": {
        "economically-eligible": "c9483bd0005af77af61bb6b63e4820dd43406cd22af88b2f78025cb1c7a9f9e7",
        "economically-rejected": "b58274ea230b2e9fdd71add85746472a8c5bd30d7c01f484e843bb354d27318b",
    },
}


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _validate_fixture(document):
    _require(type(document) is dict, "fixture must be an object")
    _require(type(document.get("version")) is int, "fixture version must be integer")
    _require(document.get("version") == 1, "unsupported fixture version")
    _require(document.get("effect_authority") is False, "fixture is historical only")
    _require(document.get("baseline_commit") == BASELINE_COMMIT, "baseline commit mismatch")
    _require(document.get("baseline_tree") == BASELINE_TREE, "baseline tree mismatch")
    _require(
        document.get("fixture_type") == "w20-numeric-predecessor-goldens",
        "fixture type mismatch",
    )
    for group, captures in CAPTURES.items():
        cases = document.get(group)
        _require(type(cases) is list, f"{group} must be an array")
        _require(
            [case.get("name") for case in cases if type(case) is dict]
            == list(captures) and len(cases) == len(captures),
            f"{group} capture inventory mismatch",
        )
        for case in cases:
            digest = captures[case["name"]]
            _require(case.get("canonical_sha256") == digest, "capture SHA mismatch")
            _require(_sha(case["expected"]) == digest, "expected body SHA mismatch")
    for case in document["work_sizing"]:
        _require(case["work_estimate_sha256"] == case["canonical_sha256"],
                 "work estimate binding mismatch")
        _require(case["legacy_v1_commitment"]["version"] == 1,
                 "historical commitment version mismatch")
        _require(case["legacy_inspection_errors"] == [], "historical inspection mismatch")
        _require(case["legacy_current_dispatch_errors"] == HISTORICAL_REFUSAL,
                 "historical dispatch refusal mismatch")
    return document


class W20NumericCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_bytes = FIXTURE.read_bytes()
        cls.fixture = _validate_fixture(json.loads(cls.original_bytes))

    @classmethod
    def tearDownClass(cls):
        if FIXTURE.read_bytes() != cls.original_bytes:
            raise AssertionError("historical fixture bytes changed")

    def assertGolden(self, group, case, current):
        digest = CAPTURES[group][case["name"]]
        self.assertEqual(case["canonical_sha256"], digest)
        self.assertEqual(_sha(case["expected"]), digest)
        self.assertEqual(_canonical(current), _canonical(case["expected"]))
        self.assertEqual(_sha(current), digest)

    def test_progress_default_policy_outputs(self):
        for case in self.fixture["progress"]:
            with self.subTest(case=case["name"]):
                before = _canonical(case)
                current = evaluate_worker_progress(**deepcopy(case["input"]))
                self.assertGolden("progress", case, current)
                for decision in (case["expected"], current):
                    self.assertIs(decision["dispatch_authorized"], False)
                    self.assertIsNone(validate_progress_decision_for_productive_use(decision))
                self.assertEqual(_canonical(case), before)

    def test_work_estimates_and_historical_only_commitments(self):
        for case in self.fixture["work_sizing"]:
            with self.subTest(case=case["name"]):
                before = _canonical(case)
                current = evaluate_work_estimate(deepcopy(case["input"]))
                self.assertGolden("work_sizing", case, current)
                for estimate in (case["expected"], current):
                    self.assertEqual(validate_work_estimate(estimate), [])
                    self.assertEqual(
                        canonical_work_estimate_sha256(estimate), case["work_estimate_sha256"]
                    )
                legacy = deepcopy(case["legacy_v1_commitment"])
                self.assertEqual(legacy["work_estimate_sha256"], case["work_estimate_sha256"])
                self.assertEqual(validate_worker_commitment(legacy, current), [])
                self.assertEqual(
                    validate_worker_commitment(legacy, current, dispatchable=False), []
                )
                self.assertEqual(
                    validate_worker_commitment(legacy, current, dispatchable=True),
                    HISTORICAL_REFUSAL,
                )
                self.assertEqual(_canonical(case), before)

    def test_proportionality_captured_policy_is_read_only_input(self):
        for case in self.fixture["proportionality"]:
            with self.subTest(case=case["name"]):
                policy = deepcopy(self.fixture["proportionality_policy"])
                before = _canonical(policy)
                inputs = deepcopy(case["input"])
                current = pool_proportionality_check(**inputs, policy_document=policy)
                self.assertGolden("proportionality", case, current)
                for assessment in (case["expected"], current):
                    self.assertEqual(
                        validate_pool_proportionality_assessment(
                            assessment, policy_document=policy
                        ), []
                    )
                    self.assertIs(assessment["dispatch_authorized"], False)
                    self.assertEqual(assessment["authority"], "candidate-evidence-only")
                self.assertIs(current["accepted"], case["name"] == "economically-eligible")
                self.assertEqual(_canonical(policy), before)

    def test_fixture_header_and_inventory_tampering_is_rejected(self):
        for field, value in (
            ("version", True), ("version", 1.0), ("version", 2),
            ("baseline_commit", "0" * 40), ("baseline_tree", "0" * 40),
            ("effect_authority", 0), ("effect_authority", True),
        ):
            with self.subTest(field=field, value=value):
                changed = deepcopy(self.fixture)
                changed[field] = value
                with self.assertRaises(ValueError):
                    _validate_fixture(changed)
        for group in CAPTURES:
            changed = deepcopy(self.fixture)
            changed[group].pop()
            with self.subTest(group=group), self.assertRaises(ValueError):
                _validate_fixture(changed)

    def test_expected_sha_and_boolean_integer_tampering_is_rejected(self):
        changed = deepcopy(self.fixture)
        changed["progress"][0]["canonical_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "capture SHA mismatch"):
            _validate_fixture(changed)
        for reseal in (False, True):
            with self.subTest(reseal=reseal):
                changed = deepcopy(self.fixture)
                case = changed["progress"][0]
                case["expected"]["actual"]["validation_complete"] = 0
                self.assertNotEqual(_canonical(case["expected"]),
                                    _canonical(self.fixture["progress"][0]["expected"]))
                if reseal:
                    case["canonical_sha256"] = _sha(case["expected"])
                with self.assertRaises(ValueError):
                    _validate_fixture(changed)

    def test_current_validator_rejects_legacy_binding_and_identity_tampering(self):
        for case in self.fixture["work_sizing"]:
            current = evaluate_work_estimate(deepcopy(case["input"]))
            legacy = case["legacy_v1_commitment"]
            for field, value, error in (
                ("work_estimate_sha256", "0" * 64,
                 "commitment.work_estimate_sha256 does not match evaluated work estimate payload"),
                ("work_unit_id", "relabelled",
                 "commitment.work_unit_id must match work_estimate.work_unit_id"),
                ("bead_id", "relabelled",
                 "commitment.bead_id must match work_estimate.bead_id"),
                ("attestation_source", "trusted-control-plane-session-metadata",
                 "historical commitment.attestation_source must equal trusted-session-jsonl"),
            ):
                with self.subTest(case=case["name"], field=field):
                    forged = deepcopy(legacy)
                    forged[field] = value
                    self.assertEqual(validate_worker_commitment(forged, current), [error])
            forged = deepcopy(legacy)
            forged["requested_model"] = forged["attested_model"] = "gpt-5.6-luna"
            self.assertEqual(
                validate_worker_commitment(forged, current),
                ["commitment.requested_model must match work_estimate.requested_model"],
            )
            changed_input = deepcopy(case["input"])
            changed_input["primary_outcome"] += " altered"
            changed_estimate = evaluate_work_estimate(changed_input)
            self.assertEqual(validate_work_estimate(changed_estimate), [])
            self.assertEqual(
                validate_worker_commitment(legacy, changed_estimate),
                ["commitment.work_estimate_sha256 does not match evaluated work estimate payload"],
            )

    def test_cross_version_relabelling_does_not_supply_a_current_receipt(self):
        for case in self.fixture["work_sizing"]:
            with self.subTest(case=case["name"]):
                current = evaluate_work_estimate(deepcopy(case["input"]))
                forged = deepcopy(case["legacy_v1_commitment"])
                forged["version"] = 2
                self.assertTrue(validate_worker_commitment(forged, current, dispatchable=True))
                for field in (
                    "confidence", "tool_calls_before_commitment",
                    "context_compactions_before_commitment", "reason",
                ):
                    forged.pop(field)
                forged.update(
                    packet_id="historical-relabel-test", attempt_nonce="historical-relabel-test",
                    agent_id="historical-relabel-test", precommit_receipt_sha256="0" * 64,
                )
                self.assertEqual(
                    validate_worker_commitment(forged, current, dispatchable=True),
                    ["commitment version 2 requires the bound precommit receipt"],
                )


if __name__ == "__main__":
    unittest.main()
