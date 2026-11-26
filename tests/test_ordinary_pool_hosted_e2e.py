"""Exercise signed ordinary pools with inert app servers and actual host custody."""

from contextlib import ExitStack, chdir, redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
from types import MethodType
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import cwo
import registered_contained_pool_host as producer
import registered_contained_pool_preparation as prepare
import registered_n1_qualification as login
import registered_native_pool_client as client
from registered_native_pool_host import RegisteredNativePoolHost
import registered_pool_containment as containment
import registered_worker_login_config as login_config
from cwo_core import beads, host_records, native_live_availability as availability, requirement_baseline as baseline
from cwo_core.policy import load_policy
from tests import test_registered_pool_containment as containment_fixture
from tests.real_beads_fixture import configure_git_fixture
from tests.test_beads_ready_set import ready_item
from tests.test_native_pool_admission import MemoryBdRunner
from tests.test_native_pool_proportionality import _set_runtime
from tests.test_registered_pool_qualification import _PEER, _pool_test_directory


_EPIC = "epic-ordinary-pool"
_LAUNCHER = Path("/usr/bin/bwrap")
_PYTHON = Path("/usr/bin/python3").resolve()
_PEER_ENTRY = r"""
import errno
import json
import os
from pathlib import Path
import sys

worktree = Path.cwd()
slot = int(worktree.name.rsplit('-', 1)[1])
login = Path(os.environ['CODEX_HOME'])
assert (login / 'auth.json').read_text() == f'synthetic pool login {slot}\n'
try:
    (worktree / 'prohibited-direct-write.txt').write_text('prohibited')
except OSError as error:
    assert error.errno == errno.EROFS
else:
    raise AssertionError('App-server checkout permitted a direct write')
calibration = '/calibration-spool-' in os.environ['CODEX_SQLITE_HOME']
sys.argv[1] = json.dumps({'home': str(login), 'login': str(login), 'worktree': str(worktree),
    'worker': worktree.name, 'marker': f'CWO_POOL_WORKER_{slot}_DONE',
    'existing': slot == 2, 'behavior': 'calibration' if calibration else '',
    'namespace': 'cwo_finite', 'tool': 'write_selected_fixture', 'effort': 'xhigh'})
"""


class _DisposableBeads:
    """Replace only the Beads subprocess when it names the exact test project and database."""

    def __init__(self, project, items):
        self.project = project
        self.database = project / ".beads"
        self.database.mkdir(mode=0o700)
        self.storage = self.database / "test.db"
        self.storage.touch()
        self.commands = MemoryBdRunner(items)
        self.original = subprocess.run

    def run(self, command, *args, **kwargs):
        if command[0] != "bd":
            return self.original(command, *args, **kwargs)
        if list(command[1:3]) != ["-C", str(self.project)]:
            raise AssertionError("Unexpected Beads project for disposable pool")
        options = command[3:]
        if options[0] == "--db":
            if options[1] != str(self.database):
                raise AssertionError("Unexpected Beads database for disposable pool")
            options = options[2:]
        if options[0] == "where":
            payload = {"path": str(self.database), "database_path": str(self.storage)}
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if options[0] == "ready":
            if list(options) != ["ready", "--json", "--parent", _EPIC, "--unassigned", "--limit", "0"]:
                raise AssertionError("Unexpected Beads ready query for disposable pool")
            return subprocess.CompletedProcess(command, 0, json.dumps(list(self.commands.issues.values())), "")
        if list(options[:3]) == ["show", "--json", "--include-comments"]:
            return subprocess.CompletedProcess(command, 0, json.dumps([self.commands.issues[options[-1]]]), "")
        if options[0] != "--actor" or options[2] not in {"show", "update", "close"}:
            raise AssertionError("Unexpected Beads operation for disposable pool")
        result = self.commands(tuple(options[2:]), actor=options[1])
        return subprocess.CompletedProcess(command, result.returncode, result.stdout, result.stderr)


class _HostedPoolFixture:
    def __init__(self, root, size, stack):
        self.root = Path(root)
        self.project = self.root / "project"
        self.project.mkdir(mode=0o700)
        self._git("init", "--quiet")
        configure_git_fixture(self.project)
        self._git("commit", "--quiet", "--allow-empty", "-m", "Initialize disposable pool checkout")
        self.store = host_records.HostRecordStore.for_tests(self.root / "controller")
        self.login_state = self.root / "login-state"
        self.homes = tuple(self.root / f"login-{slot}" for slot in range(1, size + 1))
        for slot, home in enumerate(self.homes, 1):
            home.mkdir(mode=0o700)
            auth = home / "auth.json"
            auth.write_text(f"synthetic pool login {slot}\n", encoding="utf-8")
            auth.chmod(0o600)
        self.args, items = self._assignments(size)
        self.database = _DisposableBeads(self.project, items)
        self.executable = self._inert_appserver()
        self._replace_host_boundaries(stack)
        login_config.write_pool_worker_login_homes(self.homes)
        with prepare.prepare_pool(self.project, self.args) as pending:
            self.request_path = prepare.retain_approved_pool(pending, "ordinary-pool-test-adoption")
        self.request = json.loads(self.request_path.read_bytes())
        self.approval = self.request_path.parent / producer.APPROVAL_FILE
        self.scope = json.loads(self.approval.read_bytes())["manifest"]

    def _git(self, *args):
        subprocess.run(["git", "-C", str(self.project), *args], check=True, timeout=10,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def _assignments(self, size):
        assignments, items = [], []
        policy = load_policy("native-worker-execution")
        model, effort, tier = producer.SUPPORTED_SELECTION
        for slot in range(1, size + 1):
            bead_id = f"pool-task-{slot}"
            task = f"Create the exact agreed document for ordinary assignment {slot}."
            output = f"ordinary-{slot}.txt"
            requirement = {"record_type": "cwo-requirement-baseline", "version": 1, "bead_id": bead_id,
                "baseline_version": 1, "criteria": [{"id": "result", "requirement": task, "reference": bead_id,
                    "expected_outcome": "The file holds the approved exact UTF-8 text.",
                    "applicability": "required", "evidence_kind": "artifact"}]}
            baseline_name = f"baseline-{slot}.json"
            (self.project / baseline_name).write_text(json.dumps(requirement), encoding="utf-8")
            digest = baseline.resolve_chain(requirement)["digest"]
            item = _set_runtime(ready_item(bead_id, write_paths=[output], requested_model=model), 600, policy=policy)
            item["raw"]["comments"] = [{"text": baseline.reference_line(bead_id, 1, digest)}]
            item["raw"]["metadata"]["cwo_ready_set_admission"]["aggregate_hard_budget"] = {
                "tool_calls": 60, "runtime_seconds": 2700, "compactions": 3, "full_suite_runs": 3, "mutations": 6,
            }
            items.append(item)
            assignments.append({"task": task, "baseline": baseline_name, "output_path": output,
                                "output_text": f"Approved result for witness {slot}.\n"})
        return {"epic_id": _EPIC, "model": model, "effort": effort, "service_tier": tier,
                "assignments": assignments}, items

    def _inert_appserver(self):
        executable = self.root / "inert-appserver"
        check_prompt = """
        prompt = params['input'][0]['text']
        assert f'ordinary assignment {slot}.' in prompt
        assert f'ordinary-{slot}.txt' in prompt and marker in prompt
"""
        peer = _PEER.replace("        assert 'permissions' not in params",
                             "        assert 'permissions' not in params\n" + check_prompt)
        executable.write_text(f"#!{_PYTHON}\n" + _PEER_ENTRY + peer, encoding="utf-8")
        executable.chmod(0o700)
        return executable

    def _host_inputs(self, _root):
        inputs = {}
        for key, path in (("executable", self.executable), ("launcher", _LAUNCHER), ("validator", _PYTHON)):
            inputs[key], inputs[key + "_sha256"], _ = containment.n1._file(path.resolve(strict=True))
        return inputs

    def _replace_host_boundaries(self, stack):
        stack.enter_context(patch.object(host_records, "configured_store", return_value=self.store))
        stack.enter_context(patch.object(containment, "configured_store", return_value=self.store))
        for module in (login, prepare, producer):
            stack.enter_context(patch.object(module, "worker_login_state", return_value=self.login_state))
        stack.enter_context(patch.object(availability, "REGISTERED_CONTAINED_POOL_LIVE_AVAILABLE", True))
        stack.enter_context(patch.object(beads, "require_bd"))
        stack.enter_context(patch.object(beads.subprocess, "run", self.database.run))
        stack.enter_context(patch.dict(os.environ))
        os.environ.pop("BEADS_DIR", None)
        os.environ.pop("CODEX_HOME", None)
        stack.enter_context(patch.object(prepare, "_host_inputs", self._host_inputs))
        stack.enter_context(patch.object(login, "require_executable_schema"))
        lifetime = containment._PoolLifetime
        fixture = containment_fixture.PoolWorkerContainmentTests
        stack.enter_context(patch.object(lifetime, "_provider_network_fds", fixture._inert_network))
        stack.enter_context(patch.object(lifetime, "_bootstrap_command", fixture._inert_bootstrap))
        stack.enter_context(patch.object(lifetime, "_provider_network_mounts", return_value=[]))
        stack.enter_context(patch.object(lifetime, "_release_provider_descriptor"))

    def submit(self, *args):
        stdout, stderr = StringIO(), StringIO()
        with (chdir(self.project), patch.object(sys, "argv", []), redirect_stdout(stdout), redirect_stderr(stderr)):
            try:
                cwo.main(["delegate-pool", "--pool-request", str(self.request_path), *args])
            except SystemExit as exit:
                return exit.code, stdout.getvalue(), stderr.getvalue()
        raise AssertionError("The registered pool CLI failed to report its exit code")


@unittest.skipUnless(_LAUNCHER.is_file(), "Bubblewrap is required for the registered hosted pool witness")
class HostedOrdinaryPoolTests(unittest.TestCase):
    def test_signed_n2_settles_exact_writes_and_shared_accounting(self):
        self._exercise_cohort(2)

    def test_signed_n3_settles_exact_writes_and_shared_accounting(self):
        self._exercise_cohort(3)

    def _exercise_cohort(self, size):
        with _pool_test_directory() as scratch, ExitStack() as stack:
            fixture = _HostedPoolFixture(scratch, size, stack)
            exit_code, raw, errors = fixture.submit()
            self.assertEqual(exit_code, 0, (raw, errors))
            self.assertEqual(errors, "")
            self._assert_settled(fixture, size, json.loads(raw))

    def test_writer_gate_refusal_retains_peer_output_and_full_charge(self):
        with _pool_test_directory() as scratch, ExitStack() as stack:
            fixture = _HostedPoolFixture(scratch, 2, stack)
            target, peer = fixture.scope["children"]
            open_gate = containment._PoolLifetime._open_gate

            def refuse_selected_writer(lifetime):
                if lifetime.role == "tool" and lifetime.factory.operation_id == target["worker_id"]:
                    raise containment.config.PoolContainmentError("Synthetic local writer gate refusal.")
                return open_gate(lifetime)

            stack.enter_context(patch.object(containment._PoolLifetime, "_open_gate", refuse_selected_writer))
            status, raw, errors = fixture.submit()
            self.assertEqual((status, errors), (2, ""), (raw, errors))
            report = json.loads(raw)
            self._assert_refused_writer(fixture, report, target, peer)

    def _assert_refused_writer(self, fixture, report, target, peer):
        self.assertEqual((report["state"], report["accepted"]), ("CONTAINED", False))
        self.assertFalse((Path(target["worktree"]) / target["write_path"]).exists())
        self.assertEqual((Path(peer["worktree"]) / peer["write_path"]).read_text(encoding="utf-8"), peer["expected_utf8"])
        accounting = report["ordinary_pool_accounting"]
        calibration, productive = accounting["calibration"], accounting["productive"]
        self.assertEqual((calibration["state"], calibration["outcome"]), ("terminal", "completed"))
        self.assertEqual((productive["state"], productive["outcome"]), ("reconciliation-required", None))
        self.assertEqual(accounting["aggregate"]["charged"], {
            key: calibration["charge"][key] + productive["charge"][key] for key in productive["charge"]
        })
        events = [json.loads(line) for line in Path(productive["effect_journal_path"]).read_text().splitlines()]
        observed = {kind: [event for event in events if event["event_type"] == "qualification-" + kind]
                    for kind in ("provisional-turn-proof", "tool-debit", "writer-release", "tool-ack")}
        self.assertEqual([len(rows) for rows in observed.values()], [2, 2, 2, 1])
        self.assertLess(max(event["sequence"] for event in observed["tool-debit"]),
                        min(event["sequence"] for event in observed["writer-release"]))
        self.assertEqual(observed["tool-ack"][0]["details"]["child_id"], peer["worker_id"])
        self.assertTrue(events[-1]["details"]["cleanup_confirmed"])
        self.assertFalse(list(fixture.login_state.glob("login-*.lock")))

    def test_validate_only_and_signed_scope_refusals_precede_productive_effects(self):
        with _pool_test_directory() as scratch, ExitStack() as stack:
            fixture = _HostedPoolFixture(scratch, 2, stack)
            launch = stack.enter_context(patch.object(containment._PoolLifetime, "launch",
                side_effect=AssertionError("validation or refused scope started a worker")))
            outcome, raw, errors = fixture.submit("--validate-only")
            self.assertEqual((outcome, errors), (0, ""))
            self.assertEqual(json.loads(raw), {"structurally_valid": True, "authority_validated": True,
                                              "model_calls": 0, "dispatch_authorized": False})
            self._assert_no_effects(fixture)

            original = fixture.approval.read_bytes()
            edited = json.loads(original)
            edited["manifest"]["children"][0]["expected_utf8"] = "unsigned changed output"
            fixture.approval.write_bytes(producer.encode(edited))
            outcome, raw, errors = fixture.submit()
            self.assertEqual((outcome, raw), (2, ""))
            self.assertIn("action", errors)
            self._assert_no_effects(fixture)

            fixture.approval.unlink()
            outcome, raw, errors = fixture.submit()
            self.assertEqual((outcome, raw), (2, ""))
            self.assertIn("approval.json", errors)
            self._assert_no_effects(fixture)
            launch.assert_not_called()

    def test_substituted_host_and_held_generic_route_are_refused(self):
        with _pool_test_directory() as scratch, ExitStack() as stack:
            fixture = _HostedPoolFixture(scratch, 2, stack)
            pool_id = fixture.request["pool_id"]
            original, other = (producer.open_approved_pool(fixture.project, pool_id) for _ in (1, 2))
            original.run = MethodType(type(original).run, other)
            with self.assertRaisesRegex(ValueError, "original bound pool host method"):
                client.submit(fixture.request, host=original)
            generic = object.__new__(RegisteredNativePoolHost)
            with self.assertRaisesRegex(availability.NativeLiveUnavailable, "native-pool-live-unavailable"):
                client.submit(fixture.request, host=generic)
            self._assert_no_effects(fixture)

    def test_missing_or_changed_configured_logins_precede_productive_effects(self):
        with _pool_test_directory() as scratch, ExitStack() as stack:
            fixture = _HostedPoolFixture(scratch, 2, stack)
            launch = stack.enter_context(patch.object(containment._PoolLifetime, "launch",
                side_effect=AssertionError("a refused pool login started a worker")))
            login_config.write_pool_worker_login_homes(fixture.homes[::-1])
            outcome, raw, errors = fixture.submit()
            self.assertEqual((outcome, raw), (2, ""))
            self.assertIn("worker logins changed", errors)
            self._assert_no_effects(fixture)

            login_config.write_pool_worker_login_homes(fixture.homes)
            (fixture.homes[0] / "auth.json").rename(fixture.homes[0] / "missing-auth.json")
            outcome, raw, errors = fixture.submit()
            self.assertEqual((outcome, raw), (2, ""))
            self.assertIn("private authentication file", errors)
            self._assert_no_effects(fixture)
            launch.assert_not_called()

    def _assert_no_effects(self, fixture):
        root = fixture.approval.parent
        self.assertEqual(fixture.database.commands.claim_order, [])
        self.assertFalse(fixture.login_state.exists())
        for name in ("execution-intent.json", "admission.json", "callback-calibration", "ordinary", "ledger"):
            self.assertFalse((root / name).exists(), name)
        for child in fixture.scope["children"]:
            self.assertFalse((Path(child["worktree"]) / child["write_path"]).exists())
            for phase in ("calibration", "productive"):
                self.assertEqual(list(Path(child[phase + "_spool"]).iterdir()), [])

    def _assert_settled(self, fixture, size, report):
        self.assertEqual(report["execution_route"], "registered-contained-pool")
        self.assertEqual(report["state"], "ACCEPTED")
        self.assertTrue(report["accepted"])
        settlement = report["validation"]["qualification_settlement"]
        self.assertEqual(settlement["outcome"], "verified")
        self.assertEqual(len(settlement["released_lease_sha256s"]), size)
        workers = report["validation"]["worker_observations"]
        self.assertEqual(len(workers), size)
        self.assertTrue(all(row["tools"]["unexpected"] == ["apply_patch"] for row in workers.values()))
        accounting = report["ordinary_pool_accounting"]
        phases = [accounting["calibration"], accounting["productive"]]
        self.assertEqual({row["budget_id"] for row in phases}, {phases[0]["budget_id"]})
        self.assertNotEqual(phases[0]["reservation_id"], phases[1]["reservation_id"])
        for phase in phases:
            self.assertEqual((phase["state"], phase["outcome"], phase["charge"]["sessions"]),
                             ("terminal", "completed", size))
        self.assertEqual(accounting["aggregate"]["charged"], {
            key: sum(phase["charge"][key] for phase in phases) for key in phases[0]["charge"]
        })
        self._assert_writer_release_order(accounting["productive"], size)
        self.assertFalse(list(fixture.login_state.glob("login-*.lock")))
        self.assertCountEqual(fixture.database.commands.claim_order, [child["bead_id"] for child in fixture.scope["children"]])
        for child in fixture.scope["children"]:
            checkout = Path(child["worktree"])
            output = child["write_path"]
            self.assertEqual((checkout / output).read_text(encoding="utf-8"), child["expected_utf8"])
            self.assertEqual({path.name for path in checkout.glob("ordinary-*.txt")}, {output})
            self.assertFalse((checkout / "prohibited-direct-write.txt").exists())
            self.assertFalse((fixture.project / output).exists())
            self.assertEqual({path.name for path in Path(child["login_home"]).iterdir()}, {"auth.json"})
            for phase in ("calibration", "productive"):
                self._assert_login_and_writer_receipts(child, phase)

    def _assert_login_and_writer_receipts(self, child, phase):
        receipts = Path(child[phase + "_spool"]).parent / "containment-receipts"
        rows = [json.loads(record.read_bytes()) for record in sorted(receipts.glob("*.json"))]
        observations = {row["stage"]: row["observation"] for row in rows}
        appserver = observations["appserver-contained"]
        self.assertTrue(appserver["worktree_readonly"] and appserver["managed_login_projection"])
        self.assertEqual(appserver["network"], "registered-provider-tunnel")
        self.assertIn("appserver-terminated", observations)
        self.assertIn("login-released", observations)
        self.assertEqual(sum(row["stage"] == "writer-output" for row in rows), int(phase == "productive"))
        if phase == "productive":
            writer = observations["tool-contained"]
            self.assertEqual(writer["network"], "isolated")
            self.assertFalse(writer["managed_login_projection"])

    def _assert_writer_release_order(self, accounting, size):
        rows = [json.loads(line) for line in Path(accounting["effect_journal_path"]).read_text().splitlines()]
        events = {kind: [row["sequence"] for row in rows if row["event_type"] == "qualification-" + kind]
                  for kind in ("provisional-turn-proof", "tool-debit", "writer-release", "tool-ack")}
        self.assertTrue(all(len(rows) == size for rows in events.values()), events)
        self.assertLess(max(events["provisional-turn-proof"]), min(events["tool-debit"]))
        self.assertLess(max(events["tool-debit"]), min(events["writer-release"]))
