from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_control import build_control_turn_contract  # noqa: E402
from cwo_core.native_pool_config import (  # noqa: E402
    NativePoolConfigError,
    RENDER_REQUEST_SCHEMA,
    RENDER_REQUEST_TYPE,
    build_live_canary_pool_contract,
    build_pool_contract,
    seal_bound_manifest_validation,
    validate_pool_render_request,
)
from cwo_core.native_pool_contracts import canonical_sha256, seal_artifact, validate_pool_contract, write_private_artifact  # noqa: E402
from cwo_core.native_pool_leases import capture_owner_identity  # noqa: E402
from tests.test_native_pool_contracts import capability_payload, sha  # noqa: E402
from tests import test_run_native_pool_live_canaries as live_test_helpers  # noqa: E402


def git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


class RenderFixture:
    def __init__(self, root: Path, cap: int) -> None:
        self.root = root
        self.integration = root / "integration"
        self.integration.mkdir()
        git("init", "-q", cwd=self.integration)
        (self.integration / "scripts").mkdir()
        for index in range(cap):
            (self.integration / "scripts" / f"child_{index}.py").write_text(
                f"VALUE = {index}\n", encoding="utf-8"
            )
        git("add", ".", cwd=self.integration)
        git(
            "-c",
            "user.name=CWO Test",
            "-c",
            "user.email=cwo@example.invalid",
            "commit",
            "-qm",
            "baseline",
            cwd=self.integration,
        )
        self.worktrees: list[Path] = []
        self.children: list[dict] = []
        for index in range(cap):
            worktree = root / f"worker-{index}"
            git(
                "worktree",
                "add",
                "-q",
                "-b",
                f"pool-config-worker-{index}",
                str(worktree),
                "HEAD",
                cwd=self.integration,
            )
            self.worktrees.append(worktree)
            state_file = root / f"worker-state-{index}.json"
            control_file = root / f"control-{index}.json"
            packet_sha256 = sha(f"render-packet:{index}")
            control = build_control_turn_contract(
                state_file=str(state_file),
                agent_id=f"agent-{index}",
                control_turn_id=f"child-turn-{index}",
                task_sha256=hashlib.sha256(f"task-{index}".encode("utf-8")).hexdigest(),
                poll_interval_ms=1000,
            )
            state = {
                "result_type": "cwo-native-supervision-state",
                "version": 1,
                "schema": "schemas/native-supervision-state.schema.json",
                "packet_id": f"packet-{index}",
                "packet_sha256": packet_sha256,
                "agent_id": f"agent-{index}",
                "session_id": f"session-{index}",
                "status": "created",
                "control_turn_id": None,
                "poll_interval_ms": 1000,
                "control_adapter": "native-multi-agent-v1",
                "required_capabilities": ["interrupt", "close", "wait"],
            }
            write_private_artifact(control_file, control)
            write_private_artifact(state_file, state)
            self.children.append(
                {
                    "child_id": f"child-{index}",
                    "packet_id": f"packet-{index}",
                    "attempt_nonce": f"attempt-{index}",
                    "session_id": f"session-{index}",
                    "agent_id": f"agent-{index}",
                    "control_turn_id": f"child-turn-{index}",
                    "packet_sha256": packet_sha256,
                    "control_contract_file": str(control_file),
                    "state_file": str(state_file),
                    "worktree": str(worktree),
                    "isolation_class": "mutable-isolated",
                    "declared_write_paths": [f"scripts/child_{index}.py"],
                    "integration_target_paths": [f"scripts/child_{index}.py"],
                    "lease_id": f"lease-{index}",
                }
            )
        self.request = {
            "request_type": RENDER_REQUEST_TYPE,
            "version": 1,
            "schema": RENDER_REQUEST_SCHEMA,
            "pool_id": "pool-render",
            "pool_epoch": "epoch-render",
            "control_turn_id": "pool-turn",
            "created_at": "2026-07-16T00:00:00Z",
            "max_active_workers": cap,
            "aggregate_hard_budget": {
                "tool_calls": 40,
                "runtime_seconds": 1200,
                "compactions": 0,
                "full_suite_runs": 0,
                "mutations": cap,
            },
            "integration_root": str(self.integration),
            "children": self.children,
        }


class NativePoolConfigTests(unittest.TestCase):
    def test_cap_one_render_derives_live_identity_and_strict_child_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RenderFixture(Path(temporary), 1)
            self.assertEqual(validate_pool_render_request(fixture.request), [])
            contract = build_pool_contract(fixture.request)
            self.assertEqual(validate_pool_contract(contract), [])
            self.assertEqual(contract["max_active_workers"], 1)
            self.assertIsNone(contract["capability_receipt_sha256"])
            self.assertEqual(
                contract["children"][0]["state_file"],
                fixture.children[0]["state_file"],
            )

    def test_render_request_rejects_unknown_fields_and_duplicate_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RenderFixture(Path(temporary), 2)
            request = copy.deepcopy(fixture.request)
            request["unknown"] = True
            request["children"][1]["attempt_nonce"] = request["children"][0]["attempt_nonce"]
            errors = validate_pool_render_request(request)
            self.assertTrue(any("unknown-fields" in error for error in errors))
            self.assertIn("duplicate-child-attempt-nonce", errors)

    def test_cap_two_requires_explicit_opt_in_and_fresh_exact_capability(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RenderFixture(Path(temporary), 2)
            owner = capture_owner_identity()
            payload = capability_payload()
            payload["host_identity"] = owner
            capability = seal_artifact(payload, "receipt_sha256")
            now = dt.datetime(2026, 7, 16, 0, 10, tzinfo=dt.timezone.utc)
            with self.assertRaisesRegex(NativePoolConfigError, "explicit-enable-concurrency"):
                build_pool_contract(
                    fixture.request,
                    capability_receipt=capability,
                    now=now,
                )
            with self.assertRaisesRegex(NativePoolConfigError, "operative-release-required"):
                build_pool_contract(
                    fixture.request,
                    capability_receipt=capability,
                    enable_concurrency=True,
                    owner_pid=owner["pid"],
                    now=now,
                )
            policy_document = json.loads(
                (ROOT / "policy" / "native-worker-execution.yaml").read_text(
                    encoding="utf-8"
                )
            )
            policy_document["native_supervision_pool"]["status"] = "operative-authorized"
            policy_document["native_supervision_pool"][
                "cap_two_operative_release"
            ] = True
            contract = build_pool_contract(
                fixture.request,
                capability_receipt=capability,
                enable_concurrency=True,
                owner_pid=owner["pid"],
                now=now,
                policy_document=policy_document,
            )
            self.assertEqual(validate_pool_contract(contract), [])
            self.assertEqual(contract["owner"], owner)
            self.assertEqual(contract["scheduler"]["certified_max_check_ms"], 200)
            mismatched = copy.deepcopy(capability)
            mismatched["certification"]["policy_sha256"] = sha("other-policy")
            mismatched = seal_artifact(mismatched, "receipt_sha256")
            with self.assertRaisesRegex(
                NativePoolConfigError, "capability-certification-policy-mismatch"
            ):
                build_pool_contract(
                    fixture.request,
                    capability_receipt=mismatched,
                    enable_concurrency=True,
                    owner_pid=owner["pid"],
                    now=now,
                    policy_document=policy_document,
                )

    def test_worker_state_identity_or_status_mismatch_fails_before_render(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RenderFixture(Path(temporary), 1)
            state_path = Path(fixture.children[0]["state_file"])
            state = json.loads(state_path.read_text(encoding="utf-8"))
            state["status"] = "armed"
            write_private_artifact(state_path, state)
            with self.assertRaisesRegex(NativePoolConfigError, "worker-state-not-newly-created"):
                build_pool_contract(fixture.request)

    def test_historical_manifest_versions_are_not_live_renderable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = RenderFixture(root, 2)
            authority_root = root / "authority"
            authority_root.mkdir()
            helper = live_test_helpers.FullAutoAuthorizationLauncherTests()
            head, _orphan = helper.make_repo(authority_root)
            authorization = helper.authorization(authority_root, head)
            manifest = helper.manifest(
                authorization,
                head,
                subprocess.run(
                    ["git", "rev-parse", "HEAD^{tree}"],
                    cwd=authority_root,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip(),
            )
            fixture.request["control_turn_id"] = manifest["control_turn_id"]
            owner = capture_owner_identity()
            payload = capability_payload()
            payload["host_identity"] = owner
            payload["control_turn_id"] = manifest["control_turn_id"]
            capability = seal_artifact(payload, "receipt_sha256")
            now = dt.datetime(2026, 7, 16, 0, 10, tzinfo=dt.timezone.utc)
            with self.assertRaisesRegex(
                NativePoolConfigError, "manifest-version-historical-only"
            ):
                build_live_canary_pool_contract(
                    fixture.request,
                    campaign_manifest=manifest,
                    capability_receipt=capability,
                    owner_pid=owner["pid"],
                    now=now,
                )
            manifest["version"] = 3
            manifest["schema"] = "schemas/native-live-campaign-manifest-v3.schema.json"
            manifest.pop("manifest_sha256", None)
            manifest["manifest_sha256"] = canonical_sha256(manifest)
            with self.assertRaisesRegex(
                NativePoolConfigError, "manifest-version-historical-only"
            ):
                build_live_canary_pool_contract(
                    fixture.request,
                    campaign_manifest=manifest,
                    capability_receipt=capability,
                    owner_pid=owner["pid"],
                    now=now,
                )

    def test_v4_manifest_requires_exact_full_binding_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = RenderFixture(root, 2)
            authority_root = root / "authority"
            authority_root.mkdir()
            helper = live_test_helpers.FullAutoAuthorizationLauncherTests()
            head, _orphan = helper.make_repo(authority_root)
            authorization = helper.authorization(authority_root, head)
            manifest = helper.manifest(
                authorization,
                head,
                subprocess.run(
                    ["git", "rev-parse", "HEAD^{tree}"],
                    cwd=authority_root,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip(),
            )
            manifest["version"] = 4
            manifest["schema"] = "schemas/native-live-campaign-manifest-v4.schema.json"
            manifest.pop("manifest_sha256", None)
            manifest["manifest_sha256"] = canonical_sha256(manifest)
            fixture.request["control_turn_id"] = manifest["control_turn_id"]
            owner = capture_owner_identity()
            payload = capability_payload()
            payload["host_identity"] = owner
            payload["control_turn_id"] = manifest["control_turn_id"]
            capability = seal_artifact(payload, "receipt_sha256")
            bindings = {
                "manifest_sha256": manifest["manifest_sha256"],
                "launch_claim_sha256": sha("launch-claim"),
                "candidate_commit": manifest["candidate"]["commit"],
            }
            bound = seal_bound_manifest_validation(manifest, bindings)
            now = dt.datetime(2026, 7, 16, 0, 10, tzinfo=dt.timezone.utc)

            with self.assertRaisesRegex(
                NativePoolConfigError, "bound-validation-invalid"
            ):
                build_live_canary_pool_contract(
                    fixture.request,
                    campaign_manifest=manifest,
                    capability_receipt=capability,
                    owner_pid=owner["pid"],
                    now=now,
                )

            contract = build_live_canary_pool_contract(
                fixture.request,
                campaign_manifest=manifest,
                capability_receipt=capability,
                bound_manifest_validation=bound,
                expected_bound_manifest_validation=bound,
                owner_pid=owner["pid"],
                now=now,
            )
            self.assertEqual(validate_pool_contract(contract), [])

            for field, replacement in (
                ("manifest_sha256", sha("stale-manifest")),
                ("launch_claim_sha256", sha("stale-claim")),
                ("artifact_bindings_sha256", sha("stale-bindings")),
            ):
                stale = copy.deepcopy(bound)
                stale[field] = replacement
                stale["validation_sha256"] = canonical_sha256(
                    {
                        key: value
                        for key, value in stale.items()
                        if key != "validation_sha256"
                    }
                )
                with self.subTest(field=field), self.assertRaisesRegex(
                    NativePoolConfigError, "bound-validation-invalid"
                ):
                    build_live_canary_pool_contract(
                        fixture.request,
                        campaign_manifest=manifest,
                        capability_receipt=capability,
                        bound_manifest_validation=stale,
                        expected_bound_manifest_validation=bound,
                        owner_pid=owner["pid"],
                        now=now,
                    )

            changed_manifest = copy.deepcopy(manifest)
            changed_manifest["candidate"]["tree"] = sha("changed-tree")[:40]
            changed_manifest.pop("manifest_sha256")
            changed_manifest["manifest_sha256"] = canonical_sha256(changed_manifest)
            with self.assertRaisesRegex(
                NativePoolConfigError, "bound-validation-invalid"
            ):
                build_live_canary_pool_contract(
                    fixture.request,
                    campaign_manifest=changed_manifest,
                    capability_receipt=capability,
                    bound_manifest_validation=bound,
                    expected_bound_manifest_validation=bound,
                    owner_pid=owner["pid"],
                    now=now,
                )

    def test_cli_renders_mode_0600_contract_and_requires_no_task_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RenderFixture(Path(temporary), 1)
            request_path = Path(temporary) / "request.json"
            output_path = Path(temporary) / "contract.json"
            write_private_artifact(request_path, fixture.request)
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "supervise_native_pool.py"),
                    "render",
                    "--request",
                    str(request_path),
                    "--output",
                    str(output_path),
                    "--owner-pid",
                    str(os.getpid()),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            contract = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(validate_pool_contract(contract), [])
            self.assertEqual(output_path.stat().st_mode & 0o777, 0o600)
            serialized = json.dumps(contract)
            self.assertNotIn("task-0", serialized)
            self.assertNotIn(str(fixture.integration), serialized)


if __name__ == "__main__":
    unittest.main()
