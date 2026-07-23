from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_pool_capacity import (  # noqa: E402
    NativePoolCapacityPolicyError,
    capacity_schema_errors,
    load_pool_capacity,
)


def policy_document() -> dict:
    return json.loads(
        (ROOT / "policy" / "native-worker-execution.yaml").read_text(encoding="utf-8")
    )


class NativePoolCapacityTests(unittest.TestCase):
    def test_canonical_policy_separates_hard_and_released_capacity(self) -> None:
        document = policy_document()
        limits = load_pool_capacity(document)
        self.assertEqual(limits.default_max_active_workers, 1)
        self.assertEqual(limits.released_max_active_workers, 2)
        self.assertEqual(limits.hard_max_active_workers, 3)
        self.assertEqual(limits.supported_capacities, (1, 2, 3))
        for requested in (1, 2, 3):
            with self.subTest(requested=requested):
                self.assertTrue(limits.validates_requested_capacity(requested))
        for requested in (0, 4, True, "3"):
            with self.subTest(requested=requested):
                self.assertFalse(limits.validates_requested_capacity(requested))
        self.assertTrue(limits.is_released(2))
        self.assertFalse(limits.is_released(3))
        self.assertFalse(limits.requires_capability_receipt(1))
        self.assertTrue(limits.requires_capability_receipt(2))
        self.assertTrue(limits.requires_capability_receipt(3))

    def test_policy_rejects_unknown_weakened_and_misordered_limits(self) -> None:
        cases: list[tuple[str, object]] = [
            ("unknown", True),
            ("requires_explicit_opt_in", False),
            ("requires_fresh_capability_receipt", False),
            ("operator_activation_required_for_increase", False),
            ("concurrency_enabled_by_default", True),
        ]
        for field, value in cases:
            with self.subTest(field=field):
                document = policy_document()
                document["native_supervision_pool"]["capacity"][field] = value
                with self.assertRaises(NativePoolCapacityPolicyError):
                    load_pool_capacity(document)

        document = policy_document()
        document["native_supervision_pool"]["capacity"][
            "released_max_active_workers"
        ] = 4
        with self.assertRaisesRegex(
            NativePoolCapacityPolicyError,
            "order-invalid",
        ):
            load_pool_capacity(document)

    def test_all_capacity_bound_schemas_match_policy(self) -> None:
        self.assertEqual(capacity_schema_errors(), [])

    def test_schema_drift_is_detected_without_touching_source_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "schemas", root / "schemas")
            schema_path = root / "schemas/native-supervision-pool-state.schema.json"
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            schema["properties"]["children"]["maxItems"] = 99
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            self.assertEqual(
                capacity_schema_errors(repo_root=root),
                [
                    "pool-capacity-schema-drift:"
                    "schemas/native-supervision-pool-state.schema.json"
                ],
            )

    def test_policy_copy_can_release_three_without_changing_hard_limit(self) -> None:
        document = copy.deepcopy(policy_document())
        document["native_supervision_pool"]["capacity"][
            "released_max_active_workers"
        ] = 3
        limits = load_pool_capacity(document)
        self.assertTrue(limits.is_released(3))
        self.assertFalse(limits.validates_requested_capacity(4))


if __name__ == "__main__":
    unittest.main()
