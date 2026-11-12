"""Issue #41 coverage at original offline admission and denied live boundaries.

EXAMPLE review execution is entirely synthetic. Its deadline and output units
are fake-engine controls, not provider latency, tokenization or billing facts.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import chatgpt_browser_review as browser  # noqa: E402
import dispatch_work as dispatch  # noqa: E402
import prepare_local_admission as admission  # noqa: E402
from test_route_feasibility_preparation import bind, record  # noqa: E402

planner = admission.planner
ledger_api = admission.ledger_api


class ExampleClock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


class ExampleOwners:
    """A synthetic always-live owner probe, never real process authority."""

    def current(self):
        return {"pid": 4242, "start_ticks": 7,
                "boot_id_sha256": hashlib.sha256(b"EXAMPLE-boot").hexdigest()}

    def status(self, _owner):
        return "alive"


def example_review_route(*, tiny):
    """Use the original route fixture and real planner, with exact total limits."""
    route = record(tiny=tiny, alternatives=not tiny)
    route["aggregate_id"] = "EXAMPLE-issue41-aggregate"
    route["run_id"] = "EXAMPLE-issue41-run"
    for node in route["nodes"]:
        node["execution"]["options"] = {"temperature": 0}
        node["rendered_request"] = planner.render_request(node)
    bind(route)
    planned = planner.prepare(route)
    if planned["status"] != "within-declared-limits":
        raise AssertionError("The original EXAMPLE route must be feasible.")
    route["limits"] = dict(planned["totals"])
    return bind(route)


class ExampleReviewEffect:
    """A test-only final adapter applying the original consumer's allowance."""

    def __init__(self, clock, *, cutoff=False):
        self.clock, self.cutoff = clock, cutoff
        self.calls, self.partial, self.final = [], [], None
        self.telemetry = dict.fromkeys(("tokens", "remote_billing", "remote_cancelled", "latency"))

    def __call__(self, request, execution, allowance, report):
        # No independently typed timeout or model default: these actual engine
        # arguments come only from the accepting original admission consumer.
        return self.review(
            request=request, model=execution["model"], effort=execution["effort"],
            options=execution["options"], output_units=execution["output_tokens_upper"],
            timeout=allowance["runtime_seconds"], reservation=allowance, report=report,
        )

    def review(self, *, request, model, effort, options, output_units, timeout, reservation, report):
        self.calls.append({
            "request": request, "model": model, "effort": effort, "options": copy.deepcopy(options),
            "output_units": output_units, "timeout": timeout, "reservation": dict(reservation),
        })
        deadline = self.clock.now + timeout
        rendered = json.loads(request)
        sizes = [len(source["text"].encode("utf-8")) for source in rendered["sources"]]
        self.partial.append("EXAMPLE: inspected the selected source bytes.")
        report("EXAMPLE-partial", {"source_bytes": sizes, "substantive_final": False})
        if self.cutoff:
            self.clock.now = deadline
        if self.clock.now >= deadline:
            raise ledger_api.InvocationTimeout("EXAMPLE operator/local cutoff; partial is not a final review.")
        words = f"EXAMPLE review: {len(sizes)} selected source; {sum(sizes)} UTF-8 bytes; check the declared acceptance."
        self.final = " ".join(words.split()[:output_units])
        return ledger_api.EffectResult("completed")


class Issue41DispatchMatrixTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="EXAMPLE-issue41-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def case(self, label, *, tiny=False):
        route = example_review_route(tiny=tiny)
        clock, owners = ExampleClock(), ExampleOwners()
        ledger = ledger_api.InvocationLedger(self.root / label, clock=clock, owner_probe=owners)
        receipt = admission.prepare(route, "plan", now=clock.now, expires_at=clock.now + 60)
        return SimpleNamespace(route=route, clock=clock, ledger=ledger, receipt=receipt,
                               effect=ExampleReviewEffect(clock))

    def invoke(self, case, *, receipt=None, route=None, node_id="plan", observer=None, mapping=None):
        return admission.invoke_offline(
            case.receipt if receipt is None else receipt,
            case.route if route is None else route, node_id,
            ledger=case.ledger, effect=case.effect, observer=observer, node_attempts=mapping,
        )

    def test_valid_review_applies_exact_admitted_arguments_once(self):
        case = self.case("EXAMPLE-positive")
        events, reentrant = [], []

        def observer(event):
            stored = case.ledger.attempt(event["attempt"]["reservation_id"])
            self.assertEqual(stored, event["attempt"])
            self.assertEqual(stored["observers"], [observer.__qualname__])
            events.append(event["event"])
            if event["event"] == "invocation-intent":
                self.assertEqual(case.effect.calls, [])
            if event["event"] == "EXAMPLE-partial":
                with self.assertRaises(ledger_api.InvocationLedgerError):
                    self.invoke(case)
                reentrant.append(True)

        result = self.invoke(case, observer=observer)
        execution = json.loads(case.receipt.execution_bytes)
        amount = json.loads(case.receipt.amounts_bytes)
        self.assertEqual(case.effect.calls, [{
            "request": case.receipt.request_bytes, "model": execution["model"],
            "effort": execution["effort"], "options": execution["options"],
            "output_units": execution["output_tokens_upper"], "timeout": amount["runtime_seconds"],
            "reservation": amount,
        }])
        self.assertEqual(reentrant, [True])
        self.assertEqual(events, ["invocation-intent", "EXAMPLE-partial", "terminal"])
        self.assertIn("1 selected source; 3 UTF-8 bytes", case.effect.final)
        self.assertLessEqual(len(case.effect.final.split()), execution["output_tokens_upper"])
        self.assertEqual(result["attempt"]["charge"], amount)
        self.assertIsNone(result["attempt"]["observed_usage"])
        self.assertEqual(case.effect.telemetry, dict.fromkeys(case.effect.telemetry))
        for name in admission.FALSE_FIELDS:
            self.assertIs(result[name], False)

    def test_missing_number_only_forged_and_stale_records_never_reach_review(self):
        case = self.case("EXAMPLE-invalid")
        forged = replace(case.receipt, request_bytes=b"EXAMPLE-forged-input")
        candidates = (None, 600, {"ready": True, "timeout": 600}, forged,
                      replace(case.receipt, amounts_bytes=b"600"))
        for receipt in candidates:
            with self.subTest(kind=type(receipt).__name__):
                with self.assertRaises(admission.AdmissionError):
                    admission.invoke_offline(receipt, case.route, "plan", ledger=case.ledger, effect=case.effect)
        case.clock.now = case.receipt.expires_at
        with self.assertRaisesRegex(admission.AdmissionError, "expired"):
            self.invoke(case)
        self.assertEqual(case.effect.calls, [])
        self.assertFalse(case.ledger.root.exists())

    def test_feasible_model_effort_wrapper_attachment_and_output_drift_are_bound(self):
        case = self.case("EXAMPLE-drift")
        for field in ("model", "effort", "options", "output_tokens_upper", "prompt", "wrappers", "attachments"):
            with self.subTest(field=field):
                changed = copy.deepcopy(case.route)
                node = changed["nodes"][0]
                if field == "model":
                    node["execution"][field] = "gpt-6.1-sol"
                    node["estimate_source"]["requested_model"] = node["execution"][field]
                    node["source_sha256"] = planner.work_sizing.canonical_work_estimate_sha256(node["estimate_source"])
                    node["unit_estimate"] = planner.work_sizing.evaluate_work_estimate(
                        node["estimate_source"], policy=changed["policy"])
                    node["unit_sha256"] = planner.work_sizing.canonical_work_estimate_sha256(node["unit_estimate"])
                elif field == "effort":
                    node["execution"][field] = "low"
                elif field == "options":
                    node["execution"][field]["temperature"] = 1
                elif field == "output_tokens_upper":
                    node["execution"][field] -= 1
                elif field == "prompt":
                    node[field] = "EXAMPLE other note."
                else:
                    node[field][0]["text"] = "EXAMPLE changed."
                node["rendered_request"] = planner.render_request(node)
                bind(changed)
                self.assertEqual(changed["limits"], case.route["limits"])
                self.assertEqual(planner.prepare(changed)["status"], "within-declared-limits")
                with self.assertRaisesRegex(admission.AdmissionError, "bindings differ"):
                    self.invoke(case, route=changed)
        self.assertEqual(case.effect.calls, [])
        self.assertFalse(case.ledger.root.exists())

    def test_text_attachment_hash_is_the_actual_rendered_hash_and_binary_is_denied(self):
        case = self.case("EXAMPLE-attachment", tiny=True)
        planned = planner.prepare(case.route)
        actual = case.route["nodes"][0]["attachments"][0]["text"].encode("utf-8")
        measured = planned["nodes"][0]["measurements"]["attachments"][0]
        self.assertEqual(measured["sha256"], hashlib.sha256(actual).hexdigest())
        self.invoke(case)
        rendered = json.loads(case.effect.calls[0]["request"])
        self.assertEqual(rendered["attachments"], case.route["nodes"][0]["attachments"])
        unsupported = copy.deepcopy(case.route)
        unsupported["nodes"][0]["attachments"][0] = {"id": "EXAMPLE-image", "image_bytes": [1, 2, 3]}
        bind(unsupported)
        with self.assertRaises(admission.AdmissionError):
            admission.prepare(unsupported, "plan", now=case.clock.now, expires_at=case.clock.now + 60)
        self.assertEqual(len(case.effect.calls), 1)

    def test_cutoff_keeps_partial_nonfinal_and_terminal_dependent_held(self):
        case = self.case("EXAMPLE-cutoff")
        case.effect.cutoff = True
        with self.assertRaisesRegex(ledger_api.InvocationTimeout, "operator/local cutoff"):
            self.invoke(case)
        self.assertTrue(case.effect.partial)
        self.assertIsNone(case.effect.final)
        attempt = next(iter(json.loads((case.ledger.root / ledger_api.LEDGER_FILE).read_bytes())["attempts"].values()))
        self.assertEqual((attempt["state"], attempt["outcome"]), ("terminal", "timeout"))
        self.assertEqual(attempt["charge"], json.loads(case.receipt.amounts_bytes))
        self.assertIsNone(attempt["observed_usage"])
        # A new receipt/larger expiry cannot restart the spent node. Its real
        # timeout cannot become a completed dependency or a failed retry parent.
        for node_id in ("plan", "review", "retry", "fallback", "sibling"):
            receipt = admission.prepare(case.route, node_id, now=case.clock.now, expires_at=case.clock.now + 120)
            mapping = {} if node_id == "plan" else {"plan": attempt["attempt_id"]}
            with self.assertRaises((admission.AdmissionError, ledger_api.InvocationLedgerError)):
                self.invoke(case, receipt=receipt, node_id=node_id, mapping=mapping)
        self.assertEqual(len(case.effect.calls), 1)
        self.assertEqual(case.ledger.attempt(attempt["reservation_id"]), attempt)
        independent = self.case("EXAMPLE-independent", tiny=True)
        self.assertEqual(self.invoke(independent)["attempt"]["outcome"], "completed")
        self.assertEqual(len(independent.effect.calls), 1)

    def test_unknown_projection_cannot_be_converted_into_a_zero_allowance(self):
        for unknown in ("billing", "output", "latency"):
            with self.subTest(unknown=unknown):
                case = self.case("EXAMPLE-unknown-" + unknown, tiny=True)
                changed = copy.deepcopy(case.route)
                if unknown == "billing":
                    changed["projection_policy"]["billing"] = None
                elif unknown == "output":
                    changed["nodes"][0]["execution"]["output_tokens_upper"] = None
                    changed["nodes"][0]["rendered_request"] = planner.render_request(changed["nodes"][0])
                else:
                    changed["nodes"][0]["uncertainty"]["status"] = "unresolved"
                bind(changed)
                self.assertEqual(planner.prepare(changed)["status"], "unassessable")
                with self.assertRaises(admission.AdmissionError):
                    admission.prepare(changed, "plan", now=case.clock.now, expires_at=case.clock.now + 60)
                self.assertEqual(case.effect.calls, [])
                self.assertFalse(case.ledger.root.exists())

    def test_direct_custom_local_and_browser_modes_cannot_bypass_shipped_denials(self):
        self.assertIs(dispatch.LOCAL_INVOCATION_AVAILABLE, False)
        self.assertIs(browser.BROWSER_DISPATCH_AVAILABLE, False)
        with patch.object(dispatch.request, "build_opener") as http:
            with self.assertRaises(SystemExit) as raised:
                dispatch.execute_local_envelope({"ready": True, "timeout_seconds": 600}, {}, None)
            self.assertEqual(str(raised.exception), dispatch.LOCAL_INVOCATION_UNAVAILABLE)
        http.assert_not_called()
        for mode in ("cdp", "profile"):
            for entry in ("run", "_run", "confirm_model_only"):
                with self.subTest(mode=mode, entry=entry):
                    self.assert_browser_hold(mode, entry)
        for entry in ("run", "_run", "confirm_model_only"):
            self.assert_browser_source_controls(entry)

    def assert_browser_source_controls(self, entry):
        # Empty CDP contexts/pages reach the actual new-context/new-page and
        # label/confirmation helpers. Only effects and response capture are fake.
        for observed, refused in (("Pro Extended", False), ("Instant", True)):
            with self.subTest(entry=entry, observed=observed):
                effects = Mock()
                locator = Mock()
                locator.first = locator.last = locator
                locator.inner_text.return_value = observed
                locator.get_attribute.return_value = None
                page = Mock(url="https://chatgpt.com/c/EXAMPLE")
                page.locator.return_value = locator
                context = SimpleNamespace(pages=[], new_page=Mock(return_value=page))
                connection = SimpleNamespace(contexts=[], new_context=Mock(return_value=context))
                playwright = SimpleNamespace(chromium=SimpleNamespace(
                    connect_over_cdp=Mock(return_value=connection)), stop=Mock())
                manager = SimpleNamespace(start=Mock(return_value=playwright))
                api = ModuleType("playwright.sync_api")
                api.TimeoutError = TimeoutError
                api.sync_playwright = Mock(return_value=manager)
                runner = browser.PlaywrightChatGPTRunner({
                    "connect_over_cdp_url": "http://127.0.0.1:9222",
                    "chatgpt_url": "https://chatgpt.com/",
                    "model_label": "Pro", "reasoning_label": "Extended",
                    "require_model_confirmation": True,
                    "selectors": {"model_label_selector": "model-option",
                        "reasoning_label_selector": "reasoning-option",
                        "model_label_confirmation_selector": "model-status",
                        "reasoning_label_confirmation_selector": "reasoning-status"},
                })
                with patch.dict(sys.modules, {"playwright": ModuleType("playwright"),
                                             "playwright.sync_api": api}), \
                        patch.object(browser, "BROWSER_DISPATCH_AVAILABLE", True), \
                        patch.object(runner, "_conversation_text", return_value="before"), \
                        patch.object(runner, "_message_snapshot", return_value={"available": True}), \
                        patch.object(runner, "_submit_prompt", effects.send), \
                        patch.object(runner, "_pin_conversation"), \
                        patch.object(runner, "_wait_for_stable_response", return_value="reply"), \
                        patch.object(runner, "_capture_assistant_response", return_value={
                            "text": "reply", "extraction": "EXAMPLE", "message_id": "1",
                            "conversation_url": page.url, "conversation_id": "EXAMPLE"}):
                    args = () if entry == "confirm_model_only" else ("EXAMPLE review",)
                    if refused:
                        # Effect assertion comes first so a bypass is attributed
                        # to fake Send, not merely a changed diagnostic/refusal.
                        failure = None
                        try:
                            getattr(runner, entry)(*args)
                        except (SystemExit, browser.ChatGPTBrowserReviewError) as exc:
                            failure = exc
                        self.assertEqual(effects.send.call_count, 0)
                        self.assertIsNotNone(failure)
                    else:
                        result = getattr(runner, entry)(*args)
                        self.assertEqual(effects.send.call_count, int(entry != "confirm_model_only"))
                        self.assertEqual(result["model_attestation"]["status"], "confirmed")
                api.sync_playwright.assert_called_once_with()
                manager.start.assert_called_once_with()
                connection.new_context.assert_called_once_with()
                context.new_page.assert_called_once_with()
                page.goto.assert_called_once()
                locator.click.assert_any_call(timeout=30000)
                self.assertGreaterEqual(locator.click.call_count, 2)
                self.assertIn(unittest.mock.call("model-status"), page.locator.call_args_list)
                if not refused:
                    self.assertIn(unittest.mock.call("reasoning-status"), page.locator.call_args_list)

    def assert_browser_hold(self, mode, entry):
        runner = browser.PlaywrightChatGPTRunner({
            "selectors": {}, "chrome_user_data_dir": "/EXAMPLE-profile",
            "chatgpt_url": "https://chatgpt.com/",
            **({"connect_over_cdp_url": "http://127.0.0.1:9222"} if mode == "cdp" else {}),
        })
        effects = Mock()
        page = Mock(url="https://chatgpt.com/c/EXAMPLE")
        effects.attach_mock(page.goto, "navigate")
        context = Mock()
        effects.connect.return_value.contexts = [context]
        effects.launch.return_value = context
        playwright = SimpleNamespace(chromium=SimpleNamespace(
            connect_over_cdp=effects.connect, launch_persistent_context=effects.launch), stop=Mock())
        effects.start.return_value = playwright
        effects.factory.return_value = SimpleNamespace(start=effects.start)
        api = ModuleType("playwright.sync_api")
        api.TimeoutError = TimeoutError
        api.sync_playwright = effects.factory
        with patch.dict(sys.modules, {"playwright": ModuleType("playwright"), "playwright.sync_api": api}), \
                patch.object(runner, "_select_page", return_value=page) as held_select_page, \
                patch.object(runner, "_wait_for_prompt"), patch.object(runner, "_select_configured_labels"), \
                patch.object(runner, "_confirm_configured_labels", return_value={"status": "confirmed"}), \
                patch.object(runner, "_conversation_text", return_value="before"), \
                patch.object(runner, "_message_snapshot", return_value={"available": True, "messages": []}), \
                patch.object(runner, "_submit_prompt", effects.send), \
                patch.object(runner, "_pin_conversation"), patch.object(runner, "_wait_for_stable_response", return_value="reply"), \
                patch.object(runner, "_capture_assistant_response", return_value={
                    "text": "reply", "extraction": "EXAMPLE", "message_id": "1",
                    "conversation_url": page.url, "conversation_id": "EXAMPLE",
                }):
            args = () if entry == "confirm_model_only" else ("EXAMPLE custom/manual prompt",)
            with self.assertRaises(SystemExit) as raised:
                getattr(runner, entry)(*args)
            self.assertEqual(str(raised.exception), browser.BROWSER_DISPATCH_UNAVAILABLE)
            self.assertEqual(effects.mock_calls, [], "held entry reached a browser effect")
            held_select_page.assert_not_called()
            with patch.object(browser, "BROWSER_DISPATCH_AVAILABLE", True):
                getattr(runner, entry)(*args)
            effects.factory.assert_called_once_with()
            effects.start.assert_called_once_with()
            (effects.connect if mode == "cdp" else effects.launch).assert_called_once()
            (effects.launch if mode == "cdp" else effects.connect).assert_not_called()
            page.goto.assert_called_once()
            self.assertEqual(effects.send.call_count, int(entry != "confirm_model_only"))

    def test_chrome_launcher_dry_run_and_operator_actions_use_only_expected_effects(self):
        rows = (
            ("dry", ["--dry-run"], [], False, False),
            ("dry-config", ["--dry-run", "--write-config"], [], False, False),
            ("dry-replace", ["--dry-run", "--replace"], [], False, False),
            ("dry-combined", ["--dry-run", "--replace", "--write-config"], [], False, False),
            ("dry-stop", ["--dry-run", "--stop"], [], False, False),
            ("dry-print-config", ["--dry-run", "--print-chrome-command", "--write-config"], [], False, False),
            ("print", ["--print-chrome-command"], [], False, False),
            ("stop", ["--stop"], ["systemctl --user stop EXAMPLE.service"], False, False),
            ("status", ["--status"], [], False, False),
            ("dry-status", ["--dry-run", "--status"], [], False, False),
            ("config-print", ["--write-config", "--print-chrome-command"], [], True, False),
            ("launch", ["--replace", "--write-config"], ["systemctl --user stop EXAMPLE.service", "launch"], True, True),
        )
        for name, args, expected, config_written, profile_created in rows:
            for existing_config in (False, True):
                with self.subTest(row=name, existing_config=existing_config), tempfile.TemporaryDirectory() as directory:
                    self.assert_chrome_actions(Path(directory), args, expected, config_written, profile_created, existing_config)

    def assert_chrome_actions(self, root, args, expected, config_written, profile_created, existing_config):
        bin_dir = root / "bin"
        bin_dir.mkdir()
        log = root / "effects"
        reads = root / "reads"
        for name, body in {
            "systemctl": 'case "$*" in *is-active*) echo "$*" >>"$READS"; exit 1;; *status*) echo "$*" >>"$READS";; *) echo "systemctl $*" >>"$EFFECTS";; esac',
            "ss": 'echo "$*" >>"$READS"',
            "systemd-run": 'echo launch >>"$EFFECTS"',
            "chrome": 'echo unexpected-chrome >>"$EFFECTS"',
        }.items():
            script = bin_dir / name
            script.write_text("#!/bin/bash\n" + body + "\n")
            script.chmod(0o700)
        profile = root / "absent-profile"
        config = root / "config.json"
        if existing_config:
            config.write_bytes(b"EXAMPLE existing config\n")
            config.chmod(0o640)
        before = (config.read_bytes(), config.stat().st_mode) if existing_config else None
        result = subprocess.run([
            "/bin/bash", str(ROOT / "scripts/launch_chatgpt_cdp_chrome.sh"),
            "--chrome", str(bin_dir / "chrome"), "--unit", "EXAMPLE", "--profile", str(profile),
            "--config", str(config), *args,
        ], env={**os.environ, "PATH": f"{bin_dir}:/usr/bin:/bin", "EFFECTS": str(log), "READS": str(reads),
                "HOME": str(root), "XDG_RUNTIME_DIR": str(root), "XAUTHORITY": str(root / "xauth")},
            text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(log.read_text().splitlines() if log.exists() else [], expected)
        self.assertEqual(profile.exists(), profile_created)
        if config_written:
            self.assertEqual(json.loads(config.read_text())["connect_over_cdp_url"], "http://127.0.0.1:9222")
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        else:
            self.assertEqual((config.read_bytes(), config.stat().st_mode) if config.exists() else None, before)
        if "--status" in args:
            self.assertIn("status EXAMPLE.service", reads.read_text())
        elif "--dry-run" in args or "--print-chrome-command" in args:
            self.assertIn("Config path:" if "--stop" not in args else "systemctl", result.stdout)

    def test_tiny_work_keeps_one_role_and_no_extra_model_or_timeout_parameters(self):
        case = self.case("EXAMPLE-tiny", tiny=True)
        self.assertEqual([node["role"] for node in case.route["nodes"]], ["planning"])
        with self.assertRaises(TypeError):
            admission.invoke_offline(case.receipt, case.route, "plan", ledger=case.ledger,
                                     effect=case.effect, timeout=600)
        self.assertEqual(case.effect.calls, [])
        result = self.invoke(case)
        self.assertEqual(result["attempt"]["outcome"], "completed")
        self.assertEqual(len(case.effect.calls), 1)
        self.assertEqual(case.ledger.summary(case.receipt.budget_id)["attempts_by_state"]["terminal"], 1)


if __name__ == "__main__":
    unittest.main()
