"""Validator receipt preparation with real producers, disposable repositories and watched effects."""
from __future__ import annotations

import builtins
import contextlib
import copy
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import close_bead_with_summary as closure  # noqa: E402
import prepare_validator_receipts as preparation  # noqa: E402
from cwo_core import beads  # noqa: E402
from cwo_core import candidate_identity as ci  # noqa: E402
from cwo_core import checked_command as cc  # noqa: E402
from cwo_core import requirement_baseline as rb  # noqa: E402
from cwo_core import stage_completion  # noqa: E402
from cwo_core import workspace_capture  # noqa: E402
from tests.real_beads_fixture import configure_git_fixture

OUTPUT = b"EXAMPLE validator output\n"
BEFORE = b"EXAMPLE before\n"
AFTER = b"EXAMPLE after\n"
ORIGINAL_OPEN = io.open
ENV = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
ENV.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, LC_ALL="C")


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def spec_hash(value: dict) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha(payload.encode("utf-8"))


def spec(root: Path, command_id: str, source: str) -> dict:
    return {
        "spec_type": cc.SPEC_TYPE, "version": 1, "command_id": command_id,
        "mode": "python-source", "argv": [], "cwd": str(root),
        "env": {}, "inherit_environment": False, "stdin": None,
        "source": source, "preflights": [],
        "mutation_intent": "none", "allowed_paths": [], "timeout_seconds": 10,
    }


def criterion(name: str, outcome: str, kind: str = "validator") -> dict:
    return {
        "id": name, "requirement": "EXAMPLE independently specified obligation " + name,
        "reference": "EXAMPLE-contract/" + name,
        "expected_outcome": outcome, "applicability": "required", "evidence_kind": kind,
    }


def validator(name: str, command: dict, stdout: bytes) -> dict:
    normalized = cc.normalize_command_spec(command)
    contract = {"command_id": command["command_id"], "spec_sha256": spec_hash(normalized), "stdout_sha256": sha(stdout)}
    return criterion(name, preparation.PREFIX + json.dumps(contract))


def amendment(prior: dict, new: dict) -> dict:
    before = {item["id"]: item for item in prior["criteria"]}
    after = {item["id"]: item for item in new["criteria"]}
    return {
        "record_type": rb.AMENDMENT_RECORD_TYPE, "version": 1, "bead_id": prior["bead_id"],
        "amendment_id": f"EXAMPLE-addition-{new['baseline_version']}", "prior_digest": rb.record_digest(prior),
        "prior_baseline_version": prior["baseline_version"],
        "added_criterion_ids": sorted(set(after) - set(before)),
        "removed_criterion_ids": sorted(set(before) - set(after)),
        "changed_criterion_ids": sorted(key for key in set(before) & set(after) if before[key] != after[key]),
        "rationale": "EXAMPLE independent scope addition", "authority": {"role": "EXAMPLE", "reference": "EXAMPLE-decision"},
        "baseline": new,
    }


def external_edit(path: Path, data: bytes) -> None:
    """Simulate an outside edit through the saved real writer; Python watches are not containment."""
    with ORIGINAL_OPEN(path, "wb") as handle:
        handle.write(data)


class TempGit:
    def __init__(self, case: unittest.TestCase) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="EXAMPLE-TempGit-")
        case.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "repo"
        self.root.mkdir()
        (self.root / "src").mkdir()
        (self.root / "src/item.txt").write_bytes(BEFORE)
        self.git("init", "-q")
        configure_git_fixture(self.root)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "EXAMPLE baseline content")
        self.base = self.git("rev-parse", "HEAD")

    def git(self, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(self.root), "-c", "user.name=EXAMPLE", "-c", "user.email=EXAMPLE@example.invalid",
             "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
            check=True, capture_output=True, text=True, env=ENV,
        )
        return completed.stdout.strip()


class EffectWatch:
    """Watch named Python boundaries while allowing existing private candidate capture work."""
    def __init__(self, case: unittest.TestCase, repo: Path, command: dict) -> None:
        self.case = case
        self.repo = repo
        self.command = command
        self.depth = 0
        self.capture_calls = 0
        self.hits: list[str] = []
        self.capture = workspace_capture.capture

    def _capture(self, *args, **kwargs):
        self.capture_calls += 1
        self.depth += 1
        try:
            return self.capture(*args, **kwargs)
        finally:
            self.depth -= 1

    def _effect(self, kind: str, args: tuple, kwargs: dict) -> bool:
        if kind == "text":
            mode = args[1] if len(args) > 1 else kwargs.get("mode", "r")
            return any(flag in mode for flag in "wax+")
        if kind == "flags":
            flags = args[1] if len(args) > 1 else kwargs["flags"]
            return bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        return True

    def _allowed(self, kind: str, args: tuple) -> bool:
        if not self.depth or kind == "boundary":
            return False
        if kind == "process":
            return True
        for value in args[:2]:
            if isinstance(value, (str, os.PathLike)):
                path = os.path.abspath(value)
                if path == str(self.repo) or path.startswith(str(self.repo) + os.sep):
                    return False
        return True

    def _wrapper(self, name: str, original, kind: str):
        def watched(*args, **kwargs):
            if not self._effect(kind, args, kwargs):
                return original(*args, **kwargs)
            if self._allowed(kind, args):
                return original(*args, **kwargs)
            self.hits.append(name)
            raise AssertionError("EXAMPLE blocked effect boundary: " + name)
        return watched

    def _targets(self) -> list:
        path = str(self.repo / "src/item.txt")
        rows = [
            (builtins, "open", "text", (path, "w"), {}),
            (io, "open", "text", (path, "w"), {}),
            (os, "open", "flags", (path, os.O_WRONLY), {}),
            (subprocess, "run", "process", (["EXAMPLE-process-unavailable"],), {}),
            (subprocess, "Popen", "process", (["EXAMPLE-process-unavailable"],), {}),
            (os, "system", "process", ("EXAMPLE-process-unavailable",), {}),
            (os, "popen", "process", ("EXAMPLE-process-unavailable",), {}),
            (socket, "socket", "boundary", (socket.AF_INET, socket.SOCK_STREAM), {}),
            (socket, "create_connection", "boundary", (("example.invalid", 9),), {}),
            (beads, "run_bd", "boundary", (["comment", "EXAMPLE-bead", "EXAMPLE note"],), {}),
            (beads, "run_bd_structured", "boundary", (["show", "EXAMPLE-bead"],), {}),
            (closure, "run_bd", "boundary", (["close", "EXAMPLE-bead"],), {}),
            (closure, "execute", "boundary", (SimpleNamespace(),), {}),
            (cc, "execute_checked_command", "boundary", (self.command,), {}),
            (stage_completion, "consume", "boundary", (None, None, "EXAMPLE-unit", {}), {}),
        ]
        for name, arguments in (
            ("mkdir", (str(self.repo / "EXAMPLE-directory"),)),
            ("unlink", (path,)),
            ("rmdir", (str(self.repo / "EXAMPLE-directory"),)),
            ("rename", (path, str(self.repo / "EXAMPLE-renamed"))),
            ("replace", (path, str(self.repo / "EXAMPLE-replaced"))),
            ("chmod", (path, 0o600)),
            ("utime", (path, None)),
            ("symlink", ("EXAMPLE-target", str(self.repo / "EXAMPLE-link"))),
            ("link", (path, str(self.repo / "EXAMPLE-hard-link"))),
            ("write", (0, b"EXAMPLE")),
            ("ftruncate", (0, 0)),
        ):
            rows.append((os, name, "write", arguments, {}))
        for name, arguments in (
            ("fork", ()),
            ("execv", ("/EXAMPLE-unavailable", ["EXAMPLE-unavailable"])),
            ("execve", ("/EXAMPLE-unavailable", ["EXAMPLE-unavailable"], {})),
            ("posix_spawn", ("/EXAMPLE-unavailable", ["EXAMPLE-unavailable"], {})),
            ("posix_spawnp", ("EXAMPLE-unavailable", ["EXAMPLE-unavailable"], {})),
        ):
            if hasattr(os, name):
                rows.append((os, name, "process", arguments, {}))
        return rows

    @contextlib.contextmanager
    def installed(self, *, require_capture: bool = True):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(workspace_capture, "capture", side_effect=self._capture))
            probes = []
            for module, name, kind, arguments, keywords in self._targets():
                original = getattr(module, name)
                watched = stack.enter_context(patch.object(module, name, side_effect=self._wrapper(module.__name__ + "." + name, original, kind)))
                probes.append((module.__name__ + "." + name, watched, arguments, keywords))
            yield
            self.case.assertEqual(self.hits, [])
            if require_capture:
                self.case.assertGreaterEqual(self.capture_calls, 2)
            for name, watched, arguments, keywords in probes:
                with self.case.subTest(boundary=name), self.case.assertRaises(AssertionError):
                    watched(*arguments, **keywords)
                self.case.assertEqual(self.hits[-1], name)


class ValidatorReceiptPreparationTests(unittest.TestCase):
    def begin(self, variant: str = "passed", *, extra=(), additive: bool = False) -> None:
        self.workspace = TempGit(self)
        self.repo = self.workspace.root
        self.specs = {
            "passed": spec(self.repo, "EXAMPLE-command", "print('EXAMPLE validator output')\n# EXAMPLE café label\n"),
            "failed": spec(self.repo, "EXAMPLE-failed", "raise SystemExit(7)\n"),
            "refused": spec(self.repo, "EXAMPLE-refused", "def EXAMPLE_invalid(:\n"),
            "additional": spec(self.repo, "EXAMPLE-additional", "print('EXAMPLE validator output')\n# EXAMPLE additional check\n"),
        }
        chosen = self.specs[variant]
        expected = OUTPUT if variant == "passed" else b""
        self.initial = {
            "record_type": rb.BASELINE_RECORD_TYPE, "version": 1,
            "bead_id": "EXAMPLE-bead", "baseline_version": 1, "criteria": [validator("EXAMPLE-validator", chosen, expected), *extra],
        }
        self.amendments = []
        if additive:
            new = copy.deepcopy(self.initial)
            new["baseline_version"] = 2
            new["criteria"].append(validator("EXAMPLE-added", self.specs["additional"], OUTPUT))
            self.amendments.append(amendment(self.initial, new))
        self.chain = rb.resolve_chain(self.initial, self.amendments)
        self.bead = {
            "id": self.chain["bead_id"], "comments": [
                {"text": rb.reference_line(self.chain["bead_id"], entry["version"], entry["digest"])}
                for entry in self.chain["baselines"]],
        }
        # Baseline obligations and projection exist before implementation content changes.
        (self.repo / "src/item.txt").write_bytes(AFTER)
        (self.repo / "src/EXAMPLE-added.txt").write_bytes(b"EXAMPLE untracked delivery\n")
        self.candidate = ci.capture_candidate(
            self.repo, chain=self.chain, base_commit=self.workspace.base, scope_paths=["src"])
        self.bead["comments"].append({"text": ci.candidate_reference_line(
            self.chain["bead_id"], ci.candidate_digest(self.candidate))})
        # Receipt production happens only in parent fixture setup, before effect watches.
        self.receipts = {key: cc.execute_checked_command(value) for key, value in self.specs.items()}
        self.evidence = [self.wrapper("EXAMPLE-validator", variant)]
        if additive:
            self.evidence.append(self.wrapper("EXAMPLE-added", "additional"))

    def wrapper(self, criterion_id: str, key: str) -> dict:
        return {
            "record_type": preparation.EVIDENCE_TYPE, "version": 1, "criterion_id": criterion_id,
            "baseline_digest": self.chain["digest"], "candidate_digest": ci.candidate_digest(self.candidate),
            "spec": copy.deepcopy(self.specs[key]),
            "result": copy.deepcopy(self.receipts[key]),
        }

    def assess(self, **changes) -> dict:
        arguments = {
            "root": str(self.repo), "initial": self.initial, "candidate": self.candidate, "bead": self.bead,
            "validator_evidence": self.evidence, "amendments": self.amendments,
        }
        arguments.update(changes)
        with EffectWatch(self, self.repo, self.specs["passed"]).installed():
            result = preparation.prepare(**arguments)
        for key in preparation.AUTHORITY_FIELDS:
            self.assertIs(result[key], False)
        return result

    def states(self, result: dict) -> dict:
        return {entry["id"]: entry["state"] for entry in result["criteria"]}

    def test_real_passing_receipt_has_consistent_observations_without_authority(self) -> None:
        self.begin()
        self.assertEqual(self.receipts["passed"]["execution_status"], "passed")
        self.assertEqual(self.receipts["failed"]["execution_status"], "failed")
        self.assertEqual(self.receipts["refused"]["preflight_status"], "failed")
        result = self.assess()
        self.assertEqual(result["state"], "OBSERVED_CONSISTENT")
        self.assertTrue(result["observations_complete"])
        self.assertEqual(result["candidate_checks"], {"before": [], "after": []})
        self.assertEqual(result["validator_evidence"], self.evidence)
        self.assertEqual(result["criteria"][0]["observation"]["normalized_spec_sha256"], spec_hash(cc.normalize_command_spec(self.specs["passed"])))
        self.assertEqual(result["criteria"][0]["observation"]["stdout_sha256"], sha(OUTPUT))
        body = {key: value for key, value in result.items() if key != "report_digest"}
        self.assertEqual(result["report_digest"], rb.record_digest(body))

    def test_real_failed_and_preflight_refused_receipts_do_not_complete(self) -> None:
        for variant in ("failed", "refused"):
            with self.subTest(variant=variant):
                self.begin(variant)
                result = self.assess()
                self.assertFalse(result["observations_complete"])
                self.assertEqual(self.states(result)["EXAMPLE-validator"], "INCONSISTENT")

    def test_unrelated_real_success_with_the_same_stdout_does_not_complete(self) -> None:
        self.begin()
        evidence = [self.wrapper("EXAMPLE-validator", "additional")]
        self.assertEqual(self.receipts["additional"]["execution_status"], "passed")
        result = self.assess(validator_evidence=evidence)
        self.assertFalse(result["observations_complete"])
        self.assertEqual(self.states(result)["EXAMPLE-validator"], "INCONSISTENT")

    def test_mutated_receipt_copies_refuse_exact_join_and_source_mismatches(self) -> None:
        self.begin()
        changes = (
            ("baseline_digest", "sha256:" + "0" * 64),
            ("candidate_digest", "sha256:" + "1" * 64),
            ("result.result_type", "EXAMPLE-result"),
            ("result.version", 2),
            ("result.command_id", "EXAMPLE-unrelated"),
            ("result.spec_sha256", "0" * 64),
            ("result.mode", "shell-source"),
            ("result.linted_sha256", "0" * 64),
            ("result.executed_sha256", "0" * 64),
            ("result.diagnostics.stdout", "EXAMPLE unrelated output\n"),
            ("result.failure_class", "EXAMPLE-failure"),
            ("result.mutated_paths", ["EXAMPLE-path"]),
            ("spec.source", "print('EXAMPLE unrelated')\n"),
        )
        for field, value in changes:
            with self.subTest(field=field):
                evidence = copy.deepcopy(self.evidence)
                target = evidence[0]
                parts = field.split(".")
                for part in parts[:-1]:
                    target = target[part]
                target[parts[-1]] = value
                self.assertFalse(self.assess(validator_evidence=evidence)["observations_complete"])

    def test_mutated_copies_refuse_boolean_integer_substitutions(self) -> None:
        self.begin()
        for field, value in (
            ("version", True), ("exit_code", False), ("execution_started", 1),
            ("hash_match", 1), ("quarantine_required", 0), ("mutation_started", 0),
            ("avoided_retry_cycles", False), ("quoting_error_prevented", 0),
        ):
            with self.subTest(field=field):
                evidence = copy.deepcopy(self.evidence)
                evidence[0]["result"][field] = value
                self.assertFalse(self.assess(validator_evidence=evidence)["observations_complete"])
        evidence = copy.deepcopy(self.evidence)
        evidence[0]["result"]["complexity"]["score"] = True
        self.assertFalse(self.assess(validator_evidence=evidence)["observations_complete"])
        evidence[0]["spec"]["version"] = True
        self.assertFalse(self.assess(validator_evidence=evidence)["observations_complete"])

    def test_missing_extra_and_duplicate_evidence_mappings_do_not_complete(self) -> None:
        self.begin(additive=True)
        missing = self.assess(validator_evidence=self.evidence[:1])
        self.assertEqual(self.states(missing)["EXAMPLE-added"], "UNASSESSABLE")
        extra = copy.deepcopy(self.evidence)
        extra[0]["criterion_id"] = "EXAMPLE-unknown"
        duplicate_receipt = copy.deepcopy(self.evidence)
        duplicate_receipt[1] = copy.deepcopy(self.evidence[0])
        duplicate_receipt[1]["criterion_id"] = "EXAMPLE-added"
        for collection in ([], extra, self.evidence + [copy.deepcopy(self.evidence[0])], duplicate_receipt):
            with self.subTest(count=len(collection)):
                self.assertFalse(self.assess(validator_evidence=collection)["observations_complete"])

    def test_mixed_obligations_remain_present_and_unsupported_kinds_stay_unassessable(self) -> None:
        outcomes = (
            criterion("EXAMPLE-artifact", "cwo-artifact-v1:" + json.dumps({"op": "regular-file-sha256", "path": "src/item.txt", "sha256": sha(AFTER)}), "artifact"),
            criterion("EXAMPLE-review", "EXAMPLE final review has no blockers.", "review-gate"),
            criterion("EXAMPLE-service", "EXAMPLE service is stopped and its recreating service is disabled."),
            criterion("EXAMPLE-prose", "EXAMPLE validation has been considered."),
            criterion("EXAMPLE-unsupported", preparation.PREFIX + json.dumps({"op": "EXAMPLE-unsupported"})),
        )
        self.begin(extra=outcomes)
        result = self.assess()
        self.assertEqual(self.states(result)["EXAMPLE-validator"], "OBSERVED_CONSISTENT")
        for item in outcomes:
            self.assertEqual(self.states(result)[item["id"]], "UNASSESSABLE")
        self.assertEqual(set(result["required_criterion_ids"]), set(self.states(result)))
        self.assertFalse(result["observations_complete"])

    def test_unsupported_closed_outcomes_never_become_passes(self) -> None:
        for contract in (
            {"command_id": "EXAMPLE-validator", "spec_sha256": "0" * 64},
            {"command_id": True, "spec_sha256": "0" * 64, "stdout_sha256": "0" * 64},
            {"command_id": "EXAMPLE-validator", "spec_sha256": "F" * 64, "stdout_sha256": "0" * 64},
            {"command_id": "EXAMPLE-validator", "spec_sha256": "0" * 64, "stdout_sha256": "0" * 64, "extra": True},
        ):
            with self.subTest(fields=sorted(contract)):
                extra = criterion("EXAMPLE-unsupported", preparation.PREFIX + json.dumps(contract))
                self.begin(extra=[extra])
                result = self.assess()
                self.assertEqual(self.states(result)["EXAMPLE-unsupported"], "UNASSESSABLE")
                self.assertFalse(result["observations_complete"])

    def test_additive_chain_is_consumed_and_stale_or_weakening_records_refuse(self) -> None:
        self.begin(additive=True)
        with patch.object(preparation, "_observe", wraps=preparation._observe) as observe:
            observed = self.assess()
            observe.assert_called_once()
        self.assertEqual(observed["state"], "OBSERVED_CONSISTENT")
        self.assertTrue(observed["observations_complete"])
        stale = copy.deepcopy(self.candidate)
        stale["baseline"] = {"version": 1, "digest": rb.record_digest(self.initial)}
        self.assertFalse(self.assess(candidate=stale)["observations_complete"])
        weakened = copy.deepcopy(self.chain["baseline"])
        weakened["baseline_version"] = 3
        weakened["criteria"].pop(0)
        changes = self.amendments + [amendment(self.chain["baseline"], weakened)]
        watch = EffectWatch(self, self.repo, self.specs["passed"])
        with watch.installed(require_capture=False), \
                patch.object(preparation, "_observe", wraps=preparation._observe) as observe, \
                patch.object(ci, "check_candidate", wraps=ci.check_candidate) as check:
            result = preparation.prepare(
                str(self.repo), self.initial, self.candidate, self.bead, self.evidence, changes)
            observe.assert_not_called()
            check.assert_not_called()
            self.assertEqual(watch.capture_calls, 0)
        self.assertEqual(result["state"], "INCONSISTENT")
        self.assertFalse(result["observations_complete"])
        self.assertEqual(result["candidate_checks"], {"before": [], "after": []})
        for key in preparation.AUTHORITY_FIELDS:
            self.assertIs(result[key], False)
        self.assertIn("only amendments that add criteria", " ".join(result["errors"]))

    def test_dirty_untracked_and_permission_edits_invalidate_the_exact_candidate(self) -> None:
        self.begin()
        path = self.repo / "src/item.txt"
        mode = path.stat().st_mode & 0o7777
        for mutate, restore in (
            (lambda: external_edit(path, b"EXAMPLE drift\n"), lambda: external_edit(path, AFTER)),
            (lambda: (self.repo / "src/EXAMPLE-extra").write_bytes(b"EXAMPLE"), lambda: (self.repo / "src/EXAMPLE-extra").unlink()),
            (lambda: path.chmod(mode ^ 0o020), lambda: path.chmod(mode)),
        ):
            mutate()
            try:
                result = self.assess()
                self.assertFalse(result["observations_complete"])
                self.assertTrue(result["candidate_checks"]["before"])
            finally:
                restore()

    def test_post_observation_outside_edit_invalidates_consistent_entries(self) -> None:
        self.begin()
        observe = preparation._observe
        def drift(*args):
            observe(*args)
            external_edit(self.repo / "src/item.txt", b"EXAMPLE later\n")
        with patch.object(preparation, "_observe", side_effect=drift):
            result = self.assess()
        self.assertFalse(result["observations_complete"])
        self.assertTrue(result["candidate_checks"]["after"])
        self.assertEqual(self.states(result)["EXAMPLE-validator"], "INCONSISTENT")

    def test_reentrant_caller_mutation_cannot_change_the_private_input_snapshot(self) -> None:
        self.begin(additive=True)
        saved = copy.deepcopy((self.initial, self.candidate, self.bead, self.evidence, self.amendments))
        resolve = rb.resolve_chain
        def reentrant(*args):
            chain = resolve(*args)
            self.initial["criteria"].clear()
            self.candidate["commit"] = "0" * 40
            self.bead["comments"].clear()
            self.evidence[0]["result"]["diagnostics"]["stdout"] = "EXAMPLE changed"
            self.amendments.clear()
            return chain
        with patch.object(rb, "resolve_chain", side_effect=reentrant):
            result = self.assess()
        self.assertTrue(result["observations_complete"])
        self.assertEqual(result["bindings"]["candidate"], saved[1])
        self.assertEqual(result["validator_evidence"], saved[3])
        self.assertEqual(result["bindings"]["resolved_baseline"]["baseline"], saved[4][-1]["baseline"])

    def test_cwd_and_mutation_refusals_precede_real_normalization(self) -> None:
        self.begin()
        for update in (
            {"cwd": str(self.repo.parent)}, {"cwd": "~"}, {"cwd": str(self.repo) + "/../EXAMPLE-outside"},
            {"mutation_intent": "workspace-scoped", "allowed_paths": ["EXAMPLE-path"]},
            {"version": True},
        ):
            evidence = copy.deepcopy(self.evidence)
            evidence[0]["spec"].update(update)
            with patch.object(cc, "normalize_command_spec", wraps=cc.normalize_command_spec) as normalizer:
                self.assertFalse(self.assess(validator_evidence=evidence)["observations_complete"])
                normalizer.assert_not_called()

    def test_mutated_incomplete_result_and_status_only_records_do_not_pass(self) -> None:
        self.begin()
        for receipt in ({"execution_status": "passed"},):
            evidence = copy.deepcopy(self.evidence)
            evidence[0]["result"] = receipt
            self.assertFalse(self.assess(validator_evidence=evidence)["observations_complete"])
        evidence = copy.deepcopy(self.evidence)
        del evidence[0]["result"]["diagnostics"]
        self.assertFalse(self.assess(validator_evidence=evidence)["observations_complete"])

    def test_unrelated_implementation_errors_remain_visible(self) -> None:
        self.begin()
        for error_type in (RuntimeError, TypeError, ValueError):
            with self.subTest(error=error_type.__name__):
                failure = error_type("EXAMPLE implementation failure")
                with patch.object(preparation, "_observe", side_effect=failure):
                    with self.assertRaisesRegex(error_type, "EXAMPLE implementation failure") as caught:
                        self.assess()
                self.assertIs(caught.exception, failure)

    def cli(self, data: bytes, *, args=()) -> tuple[int, dict]:
        stdout = io.StringIO()
        stdin = SimpleNamespace(buffer=io.BytesIO(data))
        with patch.object(sys, "stdin", stdin), contextlib.redirect_stdout(stdout), \
                EffectWatch(self, self.repo, self.specs["passed"]).installed(require_capture=False):
            code = preparation.main(list(args))
        return code, json.loads(stdout.getvalue())

    def document(self) -> dict:
        return {
            "record_type": preparation.INPUT_TYPE, "version": 1, "root": str(self.repo),
            "baseline": self.initial, "amendments": self.amendments,
            "candidate": self.candidate, "bead": self.bead, "validator_evidence": self.evidence,
        }

    def non_object_projections(self) -> tuple:
        return (
            ("null", None), ("false", False), ("true", True), ("zero", 0), ("integer", 1),
            ("empty text", ""), ("text", "EXAMPLE projection"),
            ("empty array", []), ("text array", ["EXAMPLE projection"]),
            ("object array", [copy.deepcopy(self.bead)]),
            ("mapping array", [[key, copy.deepcopy(value)] for key, value in self.bead.items()]),
        )

    def assert_projection_refusal(self, invoke) -> None:
        watch = EffectWatch(self, self.repo, self.specs["passed"])
        with watch.installed(require_capture=False), \
                patch.object(preparation, "_observe", wraps=preparation._observe) as observe, \
                patch.object(ci, "check_candidate", wraps=ci.check_candidate) as check, \
                patch.object(cc, "normalize_command_spec", wraps=cc.normalize_command_spec) as normalizer, \
                patch.object(rb, "record_digest", wraps=rb.record_digest) as digest:
            result = invoke()
            observe.assert_not_called()
            check.assert_not_called()
            normalizer.assert_not_called()
            self.assertEqual(watch.capture_calls, 0)
            body = {key: value for key, value in result.items() if key != "report_digest"}
            digest.assert_called_once_with(body)
        self.assertEqual(result["state"], "INCONSISTENT")
        self.assertIs(result["observations_complete"], False)
        self.assertEqual(result["errors"], ["preparation refused: the Bead projection must be an object"])
        self.assertEqual(result["candidate_checks"], {"before": [], "after": []})
        self.assertEqual(result["bindings"], {})
        self.assertEqual(result["criteria"], [])
        self.assertEqual(result["report_digest"], rb.record_digest(body))
        for key in preparation.AUTHORITY_FIELDS:
            self.assertIs(result[key], False)

    def test_non_object_projections_refuse_document_before_observation(self) -> None:
        self.begin()
        for name, bead in self.non_object_projections():
            with self.subTest(shape=name):
                document = copy.deepcopy(self.document())
                document["bead"] = bead
                self.assert_projection_refusal(lambda: preparation.prepare_document(document))

    def test_non_object_projections_refuse_prepare_before_observation(self) -> None:
        self.begin()
        for name, bead in self.non_object_projections():
            with self.subTest(shape=name):
                self.assert_projection_refusal(lambda: preparation.prepare(
                    str(self.repo), self.initial, self.candidate, bead, self.evidence, self.amendments))

    def test_non_object_projections_refuse_cli_before_observation(self) -> None:
        self.begin()
        for name, bead in self.non_object_projections():
            with self.subTest(shape=name):
                document = copy.deepcopy(self.document())
                document["bead"] = bead
                data = json.dumps(document).encode("utf-8")

                def invoke() -> dict:
                    stdout, stderr = io.StringIO(), io.StringIO()
                    stdin = SimpleNamespace(buffer=io.BytesIO(data))
                    with patch.object(sys, "stdin", stdin), contextlib.redirect_stdout(stdout), \
                            contextlib.redirect_stderr(stderr):
                        code = preparation.main([])
                    self.assertEqual(code, 1)
                    self.assertEqual(stderr.getvalue(), "")
                    return json.loads(stdout.getvalue())

                self.assert_projection_refusal(invoke)

    def test_cli_uses_one_stdin_document_and_refuses_file_arguments(self) -> None:
        self.begin()
        code, result = self.cli(json.dumps(self.document()).encode("utf-8"))
        self.assertEqual(code, 0)
        self.assertTrue(result["observations_complete"])
        code, result = self.cli(b"{}", args=["--candidate", "EXAMPLE-file.json"])
        self.assertEqual(code, 1)
        self.assertFalse(result["observations_complete"])

    def test_cli_parser_errors_are_structured_and_leave_parser_globals_unchanged(self) -> None:
        self.begin()
        previous = sys.get_int_max_str_digits()
        for raw in (
            b'{"x":1,"x":2}', b"\xff", b'{"x":"\\ud800"}', b'{"x":1.0}', b'{"x":NaN}',
            b'{"x":9223372036854775808}', b'{"x":' + b"9" * 4400 + b"}",
            b'{"x":' + b"[" * 40 + b"0" + b"]" * 40 + b"}", b"[]", b"{",
            b" " * (preparation.MAX_INPUT + 1),
        ):
            with self.subTest(size=len(raw)):
                code, result = self.cli(raw)
                self.assertEqual(code, 1)
                self.assertFalse(result["observations_complete"])
                self.assertTrue(result["errors"])
        self.assertEqual(sys.get_int_max_str_digits(), previous)

    def test_byte_depth_and_token_bounds_precede_json_construction(self) -> None:
        for raw, overrides in (
            (b" " * 33, {"MAX_INPUT": 32}),
            (b'{"x":[[0]]}', {"MAX_DEPTH": 2}),
            (b'{"x":[0,0,0,0]}', {"MAX_NODES": 4}),
        ):
            with self.subTest(limits=overrides), contextlib.ExitStack() as stack:
                for name, value in overrides.items():
                    stack.enter_context(patch.object(preparation, name, value))
                with patch.object(preparation.json, "loads", wraps=json.loads) as loads:
                    with self.assertRaises(preparation.PreparationError):
                        preparation._decode(raw)
                    loads.assert_not_called()


if __name__ == "__main__":
    unittest.main()
