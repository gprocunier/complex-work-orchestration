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
    build_pool_contract,
    validate_pool_render_request,
)
from cwo_core.native_pool_contracts import seal_artifact, validate_pool_contract, write_private_artifact  # noqa: E402
from cwo_core.native_pool_leases import capture_owner_identity  # noqa: E402
from tests.test_native_pool_contracts import capability_payload, sha  # noqa: E402


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
            contract = build_pool_contract(
                fixture.request,
                capability_receipt=capability,
                enable_concurrency=True,
                owner_pid=owner["pid"],
                now=now,
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
