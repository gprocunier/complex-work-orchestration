"""Normal pool ingress keeps authority in the protected producer."""

from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import tomllib
from types import MethodType
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import registered_native_pool_client as client
import registered_contained_pool_host as contained
import registered_contained_pool_preparation as preparation
import registered_delegation_foreground as foreground
from registered_native_pool_host import RegisteredNativePoolHost
import registered_pool_configuration as pool_config
import run_admitted_native_pool_transaction as launcher
from cwo_core.maintenance_authority import sign_controller_directive
from cwo_core.native_authority import canonical_authority_sha256
from cwo_core import native_live_availability as availability
from cwo_core.outbound_screen import OutboundRefused
from cwo_core.private_artifact import PrivateDirectory
from cwo_core.supervision.transport.app_server import _prepare_native_frame
from tests import test_ordinary_pool_hosted_e2e as hosted


def request(mode="execute"):
    return {"version": 1, "mode": mode, "pool_id": "ordinary", "workers": ["one", "two"]}


class OrdinaryPoolIngressTests(unittest.TestCase):
    def test_original_function_on_another_host_cannot_cross_ingress(self):
        host, other = (object.__new__(RegisteredNativePoolHost) for _ in range(2))
        host.run = MethodType(RegisteredNativePoolHost.run, other)
        with self.assertRaisesRegex(ValueError, "original bound pool host method"):
            client.submit(request(), host=host)

    def test_hostless_execute_stays_lazy_and_validate_has_no_authority(self):
        self.assertEqual(client.submit(request("validate-only"))["authority_validated"], False)
        with self.assertRaisesRegex(ValueError, "registered-pool-host-required"):
            client.submit(request())

    def test_settled_contained_refusal_exits_two_and_retains_the_report(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "request.json"
            path.write_text(json.dumps(request()), encoding="utf-8")
            observed = {"execution_route": "registered-contained-pool", "accepted": False,
                        "state": "CONTAINED"}
            stdout, stderr = StringIO(), StringIO()
            with patch.object(client, "submit", return_value=observed), redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(launcher.main(["--pool-request", str(path)], host=object()), 2)
            self.assertEqual(json.loads(stdout.getvalue()), observed)
            self.assertEqual(stderr.getvalue(), "")

    def test_unsupported_model_refuses_before_project_and_beads(self):
        proposal = {"epic_id": "epic", "model": "gpt-6-luna", "effort": "high", "service_tier": "default",
                    "assignments": [{}, {}]}
        with (patch.object(availability, "REGISTERED_CONTAINED_POOL_LIVE_AVAILABLE", True),
              patch.object(contained, "project_root") as discovery):
            with self.assertRaisesRegex(ValueError, "model, effort and tier are unavailable"):
                with preparation.prepare_pool(Path.cwd(), proposal):
                    self.fail("unsupported selection reached approval")
            discovery.assert_not_called()

    def test_signed_scope_drift_refuses_before_constructing_the_ledger_or_claims(self):
        with TemporaryDirectory() as directory:
            project = Path(directory)
            store = SimpleNamespace(state_root=project / "controller")
            root = contained.pool_state(store) / request()["pool_id"]
            database = {"selector": str(project), "storage": str(project), "sha256": "test-database"}
            manifest = dict.fromkeys(contained._SCOPE_FIELDS)
            manifest.update(scope=contained.APPROVAL_SCOPE, pool_id=root.name, project=str(project), database=database,
                            provider="openai", disclosure="provider-only", selection=list(contained.SUPPORTED_SELECTION),
                            expires_at=int(datetime.now(timezone.utc).timestamp()) + 600)
            key = b"ordinary-pool-test-directive-key"
            directive = sign_controller_directive(
                verification_key=key, actor_id=contained.actor(), identity_source=contained.IDENTITY_SOURCE,
                action_sha256=canonical_authority_sha256(manifest), directive_id="inert-original-approval",
            )
            manifest["selection"][0] = "gpt-6-luna"
            with PrivateDirectory.open(root, create=True) as handle:
                handle.write(contained.APPROVAL_FILE, contained.encode({"manifest": manifest, "directive": directive}))
            ledger = Mock(side_effect=AssertionError("invalid signature reached ledger construction"))
            with (patch.object(availability, "REGISTERED_CONTAINED_POOL_LIVE_AVAILABLE", True),
                  patch.object(contained, "project_root", return_value=project),
                  patch.object(contained, "database_coordinates", return_value=database),
                  patch.object(contained, "_protected_store", return_value=store),
                  patch.object(contained, "_read_key", return_value=key),
                  patch.object(contained, "InvocationLedger", ledger)):
                with self.assertRaisesRegex(ValueError, "operator-directive-action-mismatch"):
                    contained.open_approved_pool(project, root.name)
            ledger.assert_not_called()

    def test_generated_pool_checkout_coordinate_passes_original_outbound_screen(self):
        proposal = {"epic_id": "epic", "model": "gpt-6.2-sol", "effort": "xhigh", "service_tier": "default",
                    "assignments": [{}, {}]}
        budget = {"aggregate_hard_budget": {"tool_calls": 2, "runtime_seconds": 180}}
        assignments = [({"bead_id": "a", "write_path": "a.txt"}, budget),
                       ({"bead_id": "b", "write_path": "b.txt"}, budget)]

        def planned(root, *_args):
            return {"cwd": str(root / "workspaces" / "worker-1")}

        with hosted._pool_test_directory() as directory:
            project = Path(directory)
            store = SimpleNamespace(state_root=project / "controller")
            database = {"selector": str(project), "sha256": "test-database"}
            with (patch.object(availability, "REGISTERED_CONTAINED_POOL_LIVE_AVAILABLE", True),
                  patch.object(contained, "project_root", return_value=project),
                  patch.object(contained, "database_coordinates", return_value=database),
                  patch.object(contained, "_protected_store", return_value=store),
                  patch.object(contained.manual_delivery, "project_beads", return_value=("test-database", Mock())),
                  patch.object(preparation, "_assignment", side_effect=assignments),
                  patch.object(preparation, "_mounts", return_value=()),
                  patch.object(preparation, "_manifest", side_effect=planned)):
                with preparation.prepare_pool(project, proposal) as pending:
                    checkout = Path(json.loads(pending.manifest)["cwd"])
                    self.assertRegex(pending.root.name, r"^pool-[0-9]{12}-[0-9]{12}$")
                    frame, _ = _prepare_native_frame(self._thread_start(checkout), "thread/start")
                    params = json.loads(frame)["params"]
                    self.assertEqual((params["cwd"], params["runtimeWorkspaceRoots"]), (str(checkout), [str(checkout)]))
                    old_checkout = pending.root.with_name("pool-ed8fcfb18caa453b9794fb22c8cb2c64")
                    # Reproduce the worker shard's ambient TMPDIR token independently of its random suffixes.
                    shard_parent = Path("/disk/tmp/cwo-worker-02-a1b2c3d4/tmpq9w8e7r6/controller.pool")
                    for root in (old_checkout, shard_parent / pending.root.name):
                        with self.subTest(root=root), self.assertRaisesRegex(OutboundRefused, "entropy.*json view"):
                            path = root / "workspaces" / "worker-1"
                            _prepare_native_frame(self._thread_start(path), "thread/start")

    @staticmethod
    def _thread_start(checkout):
        return {"id": 2, "method": "thread/start", "params": pool_config.thread_start_selectors(checkout)}

    def test_authorize_pool_foreground_declines_or_retains_original_cohort(self):
        with hosted._pool_test_directory() as directory, ExitStack() as stack:
            # The foreground only prepares and signs. Use an inert launcher pin even on hosts
            # that lack Bubblewrap so this authority witness always runs.
            stack.enter_context(patch.object(hosted, "_LAUNCHER", Path("/usr/bin/true")))
            fixture = hosted._HostedPoolFixture(directory, 2, stack)
            pool_root = fixture.approval.parent.parent
            existing = set(pool_root.iterdir())
            root_snapshots = {root: (root / contained.APPROVAL_FILE).read_bytes() for root in existing}

            declined = self._foreground_pool_decision(fixture, {"action": "decline"})
            self.assertTrue(declined["isError"])
            self.assertEqual(set(pool_root.iterdir()), existing)

            approved = self._foreground_pool_decision(fixture, {"action": "accept", "content": {"approve": True}})
            self.assertFalse(approved["isError"])
            retained, = set(pool_root.iterdir()) - existing
            request_path = retained / contained.REQUEST_FILE
            self.assertIn(str(request_path), approved["content"][0]["text"])
            pool_request = json.loads(request_path.read_bytes())
            self.assertEqual(pool_request, {"version": 1, "mode": "execute", "pool_id": retained.name,
                                            "workers": ["worker-1", "worker-2"]})
            original = contained.open_approved_pool(fixture.project, pool_request["pool_id"])
            self.assertTrue(client.submit(dict(pool_request, mode="validate-only"), host=original)["authority_validated"])
            manifest = json.loads((retained / contained.APPROVAL_FILE).read_bytes())["manifest"]
            self.assertEqual(
                [(row["bead_id"], row["task"], row["write_path"], row["expected_utf8"]) for row in manifest["children"]],
                [(f"pool-task-{index}", row["task"], row["output_path"], row["output_text"])
                 for index, row in enumerate(fixture.args["assignments"], 1)],
            )
            self.assertEqual({root: (root / contained.APPROVAL_FILE).read_bytes() for root in existing}, root_snapshots)
            self.assertEqual(fixture.database.commands.claim_order, [])
            self.assertFalse(fixture.login_state.exists())
            self.assertFalse((retained / "ledger").exists())

    def _foreground_pool_decision(self, fixture, decision):
        elicitation_id = "cwo-standing-pool-test"
        messages = [
            {"id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25",
                "capabilities": {"elicitation": {"form": {}}}}},
            {"method": "notifications/initialized"},
            {"id": 2, "method": "tools/list"},
            {"id": 3, "method": "tools/call", "params": {"name": "authorize_pool", "arguments": fixture.args}},
            {"id": elicitation_id, "result": decision},
        ]
        source = StringIO("".join(json.dumps({"jsonrpc": "2.0", **row}) + "\n" for row in messages))
        sink = StringIO()
        with patch.object(foreground, "uuid4", return_value=SimpleNamespace(hex="pool-test")):
            foreground.serve(source, sink, fixture.project)
        initialized, tools, question, returned = map(json.loads, sink.getvalue().splitlines())
        self.assertEqual(initialized["result"]["serverInfo"]["name"], "cwo-delegation")
        self.assertIn("authorize_pool", {tool["name"] for tool in tools["result"]["tools"]})
        self.assertEqual((question["id"], question["method"]), (elicitation_id, "elicitation/create"))
        self.assertIs(question["params"]["_meta"]["codex_requires_user_input"], True)
        for assignment in fixture.args["assignments"]:
            for field in ("task", "output_path", "output_text"):
                self.assertIn(json.dumps(assignment[field]), question["params"]["message"])
        self.assertEqual(returned["id"], 3)
        return returned["result"]

    def test_fixed_offline_bundled_catalog_and_stock_fallback(self):
        host = {"launcher": "/fixture/bwrap", "executable": "/fixture/codex"}
        command = ["/fixture/bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
                   "--clearenv", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib64", "/lib64",
                   "--symlink", "usr/lib", "/lib", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/offline",
                   "--ro-bind", "/fixture/codex", "/offline/codex", "--setenv", "HOME", "/offline",
                   "--setenv", "CODEX_HOME", "/offline", "--chdir", "/offline", "--", "/offline/codex",
                   "debug", "models", "--bundled"]
        inert = contained.encode({"models": [
            {"slug": "gpt-6.2-sol", "tool_mode": "code_mode_only", "experimental_supported_tools": ["clock"]},
            {"slug": "unselected-model"},
        ]})
        replies = [subprocess.CompletedProcess(command, 0, stdout=inert),
                   subprocess.CalledProcessError(1, command)]
        with patch.object(preparation.subprocess, "run", side_effect=replies) as export:
            catalog = preparation._bundled_catalog(host)
            fallback = preparation._bundled_catalog(host)
        invocation = call(command, stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=30)
        self.assertEqual(export.call_args_list, [invocation, invocation])
        self.assertEqual(json.loads(catalog), {"models": [{"slug": "gpt-6.2-sol", "tool_mode": "direct",
                                                           "experimental_supported_tools": [],
                                                           "supports_search_tool": False}]})
        self.assertIsNone(fallback)
        worker, spool = Path("/fixture/worker"), Path("/fixture/spool")
        selected = pool_config.configuration_files(worker, spool, catalog=catalog)
        stock = pool_config.configuration_files(worker, spool, catalog=fallback)
        self.assertEqual(selected[pool_config.CATALOG_NAME], catalog)
        self.assertNotIn(pool_config.CATALOG_NAME, stock)
        self.assertTrue(tomllib.loads(stock["config.toml"].decode())["features"]["code_mode"]["enabled"])
