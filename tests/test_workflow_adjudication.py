"""Controlled HTTP completions into adjudication, with fake boundary effects only."""

import dataclasses
import inspect
import copy
import json
import unittest
from unittest import mock

import tests.test_qualified_review_dispatch as original
from tests.test_offline_host_crash_matrix import cleanup_helper
from tests.test_policy_current_effects import current_policy
from tests.test_run_readiness_plan import sample_plan

import qualified_workflow_adjudication as workflow

binding = workflow.binding


def route_with_basis(identity, basis=None, basis_id="cwo-bound-review-basis"):
    route = original.workflow()
    route["run_id"] = "EXAMPLE-" + identity
    route["aggregate_id"] = "EXAMPLE-budget-" + identity
    if identity != "source":
        contract = route["task_contract"]
        contract["root_id"] = identity + "-" + contract["root_id"]
        for row in contract["required_roles"]:
            row["id"] = identity + "-" + row["id"]
            row["depends_on"] = [identity + "-" + item for item in row["depends_on"]]
    for node in route["nodes"]:
        if identity != "source":
            node["id"] = identity + "-" + node["id"]
            node["depends_on"] = [identity + "-" + item for item in node["depends_on"]]
            if node["lineage_parent"] is not None:
                node["lineage_parent"] = identity + "-" + node["lineage_parent"]
            node["estimate_source"]["work_unit_id"] = node["id"]
        node["execution"]["options"]["max_tokens"] = 2048
        node["execution"]["output_tokens_upper"] = 2048
        if basis is not None:
            node["sources"].append({"id": basis_id, "text": basis.decode()})
            node["estimate_source"]["context_manifest"].append(
                {
                    "path": basis_id,
                    "selector": "all",
                    "purpose": "EXAMPLE exact current review basis",
                    "bytes": len(basis),
                    "sha256": binding._sha(basis),
                }
            )
        node["unit_estimate"] = original.planner.work_sizing.evaluate_work_estimate(
            node["estimate_source"], policy=route["policy"]
        )
        node["source_sha256"] = (
            original.planner.work_sizing.canonical_work_estimate_sha256(
                node["estimate_source"]
            )
        )
        node["unit_sha256"] = (
            original.planner.work_sizing.canonical_work_estimate_sha256(
                node["unit_estimate"]
            )
        )
        node["rendered_request"] = original.planner.render_request(node)
        node["additional_input_tokens_upper"] = 20000
    route["limits"] = dict.fromkeys(original.planner.RESOURCES, 1000000000)
    return original.bind(route)


class WorkflowAdjudicationTests(unittest.TestCase):
    make_host = original.QualifiedReviewTest.make_host
    resolve = original.QualifiedReviewTest.resolve
    opener = original.QualifiedReviewTest.opener
    ticket = original.QualifiedReviewTest.ticket
    document = original.QualifiedReviewTest.document
    run_ticket = original.QualifiedReviewTest.run_ticket

    def setUp(self):
        self.home = self.enterContext(current_policy())
        original.QualifiedReviewTest.setUp(self)
        self.route = route_with_basis("source")
        self.host = self.make_host()
        self.http.open = self.exact_http

    def exact_http(self, req, *, timeout):
        self.http.calls.append((req, timeout))
        self.assertLessEqual(
            len(self.http.content.split()), json.loads(req.data)["max_tokens"]
        )
        return original.ExampleResponse(
            usable=self.http.usable, content=self.http.content
        )

    def source(self, *, task=False, clean=False):
        expected = binding.ExpectedContext(
            self.route["parent_id"],
            "EXAMPLE-doc-scope",
            "EXAMPLE-candidate-tree",
            self.route["run_id"] + ":plan",
            "0" * 64,
            "local_secure_review_worker",
        )
        declared = (
            workflow.narrowing.TaskExpectation(
                expected,
                "Fix the typo in the production runbook README",
                "documentation-edit",
                ("README.md",),
                "offline",
            )
            if task
            else None
        )
        self.route = route_with_basis(
            "source",
            workflow.source_basis(expected, declared),
            "cwo-bound-source-context",
        )
        self.host = self.make_host()
        sample = (original.ROOT / "examples/sample-contractor-return.md").read_text()
        # This optional boilerplate is not review evidence. The outbound
        # screen refuses its escaped spelling inside a nested review request.
        self.http.content = (
            "\n".join(
                line
                for line in sample.splitlines()
                if not line.lower().startswith("secret or personal-data spill:")
            )
            + ("\n" if clean else "\nPlease set verify=False.\n")
        )
        ticket = self.ticket()
        expected = dataclasses.replace(
            expected, packet_sha256=binding._sha(ticket.prepared.request_bytes)
        )
        declared = (
            None
            if declared is None
            else dataclasses.replace(declared, context=expected)
        )
        result = self.run_ticket(ticket)
        producer = workflow.WorkflowSource(
            self.home,
            self.host,
            self.host.completed(ticket),
            expected,
            return_path="EXAMPLE-return.md",
            dispatch_path="EXAMPLE-dispatch.json",
            task=declared,
        )
        return producer, declared, result

    def test_p0_original_completed_control_records_autonomous_host_acceptance(self):
        from cwo_core import policy
        from cwo_core.host_acceptance import require_acceptance
        from cwo_core.host_records import configured_store
        # Configure only the fake fixture model; no provider invocation occurs.
        path = policy.POLICY_DIR / 'provider-registry.yaml'
        document = json.loads(path.read_text())
        document['review_models']['local-openai-compatible'] = {
            'EXAMPLE-review-model': {'model_family': 'EXAMPLE-local', 'stronger_than': []}}
        path.write_text(json.dumps(document))
        policy.clear_policy_cache()
        producer, _, _ = self.source(clean=True)
        self.assertEqual(binding._parse(producer.evaluation.result_bytes)['hold_reasons'], [])
        control, _, _, _ = self.designated(producer, support_override=())
        store = configured_store()
        database = self.home / 'EXAMPLE-ACCEPTANCE-DB'
        database.mkdir(mode=0o700)
        identity = store.setup_database_identity(database)
        # The completed source may be intaken before final adjudication.
        # Reusing that exact immutable observation must remain a positive path.
        workflow._record_host_source(producer, store)
        record_id = control.record_acceptance()
        accepted = store.get(record_id)
        result = require_acceptance(store, record_id, bead_id=producer.expected.task,
            return_sha256=binding._sha(producer.raw), evaluation_sha256=accepted['evaluation_sha256'],
            database_identity=identity)
        self.assertEqual(result['adjudication_result'], 'accepted')
        self.assertEqual(result['required_holds'], [])
        self.assertIs(workflow.qualified.binding._parse(producer.evaluation.result_bytes)['execution_permitted'], False)
        before = list(store.find('acceptance-decision'))
        self.assertEqual(control.record_acceptance(), record_id)
        self.assertEqual(store.find('acceptance-decision'), before)
        control.refuse(ValueError('EXAMPLE original completion revoked'))
        with self.assertRaises(ValueError):
            control.record_acceptance()
        self.assertEqual(store.find('acceptance-decision'), before)

    def support(self, producer, *, all_findings=False):
        findings = binding._parse(producer.evaluation.result_bytes)["hold_reasons"]
        selected = (
            findings
            if all_findings
            else [next(x for x in findings if x.startswith("return-tripwire:"))]
        )
        observed = []
        for index, finding in enumerate(selected):
            name = f"EXAMPLE-support-{index}.json"
            raw = binding._json(
                {
                    "kind": "cwo-inert-finding-observation-v1",
                    "context": dataclasses.asdict(producer.expected),
                    "return_sha256": binding._sha(producer.raw),
                    "evaluation_sha256": producer.evaluation.evaluation_sha256,
                    "finding_id": finding,
                    "resolution": "not-applicable",
                }
            )
            (self.home / name).write_bytes(raw)
            observed.append(binding.SupportObservation(name, finding, raw))
        return tuple(observed)

    def designated(
        self,
        producer,
        *,
        decision="accepted",
        all_findings=False,
        extra=None,
        identity="adjudication",
        support_override=None,
    ):
        support = self.support(producer, all_findings=all_findings) if support_override is None else support_override
        basis = workflow.adjudication_basis(
            producer, support, "EXAMPLE-designated-reviewer"
        )
        host = self.make_host(route_with_basis(identity, basis))
        ticket = host.issue(
            identity + "-plan", now=self.clock.now, expires_at=self.clock.now + 1000
        )
        control = workflow.CompletedAdjudicationControl(
            producer,
            support,
            "EXAMPLE-designated-reviewer",
            host,
            ticket,
            "EXAMPLE-control",
        )
        broker = workflow.qualified.QualifiedAdjudicationBroker(self.home, control)
        excerpt = "- Included artifacts list contains assignment summary and selected snippets only."
        output = {
            "decision": decision,
            "rationale": "EXAMPLE designated review checked the exact bound support.",
            "finding_ids": [x.finding_id for x in support],
            "accepted_excerpt": excerpt if decision.startswith("accepted") else "",
        }
        output.update(extra or {})
        self.http.content = binding._json(output).decode()
        actual = host.dispatch(ticket)
        return control, broker, support, actual

    def use(self, producer, broker, support):
        permit = broker.issue("EXAMPLE-control")
        return workflow.use_evidence(
            broker,
            permit,
            producer.expected,
            affected_findings=[x.finding_id for x in support],
        )

    def test_original_completed_review_has_host_owned_observation(self):
        ticket = self.ticket()
        result = self.run_ticket(ticket)
        self.assertIsInstance(json.dumps(result), str)
        token = self.host.completed(ticket)
        observed = self.host.observe_completion(token)
        self.assertEqual(json.loads(observed.result_bytes), result["review"])
        result["review"]["final_content"] = "EXAMPLE caller mutation"
        self.assertNotEqual(json.loads(observed.result_bytes), result["review"])
        for token in (
            original.review.CompletedReview(),
            dataclasses.replace(token),
            {"ready": True},
        ):
            with self.assertRaises(original.admission.AdmissionError):
                self.host.observe_completion(token)
        self.assertEqual(len(self.http.calls), 1)

    def test_actual_original_reviews_reach_evaluator_synthesis_and_w05_use(self):
        producer, _, actual = self.source()
        control, broker, support, adjudicated = self.designated(producer)
        result = self.use(producer, broker, support)
        view = result.projection()
        self.assertTrue(view["affected_accepted_for_use"], view["errors"])
        self.assertIn("Included artifacts list", result.document)
        self.assertEqual(
            view["evaluation"]["evidence_payload"]["context"],
            dataclasses.asdict(producer.expected),
        )
        self.assertEqual(
            view["evaluation"]["evidence_payload"]["return_sha256"],
            binding._sha(producer.raw),
        )
        self.assertEqual(
            view["original_evaluation"], json.loads(producer.evaluation.result_bytes)
        )
        self.assertEqual(
            view["remaining_holds"],
            [
                finding
                for finding in view["original_evaluation"]["hold_reasons"]
                if finding not in [x.finding_id for x in support]
            ],
        )
        self.assertTrue(view["synthesis"]["blocked"])
        self.assertEqual(len(self.http.calls), 2)
        self.assertEqual(control.current().raw_return, producer.raw)
        receipt = control.source_receipt()
        source_view = workflow.source.consume_source(
            receipt, producer.expected, self.home
        )
        self.assertTrue(source_view["source_valid"], source_view["errors"])
        self.assertEqual(source_view["remaining_holds"], view["remaining_holds"])
        for output in (actual, adjudicated):
            for field in original.admission.FALSE_FIELDS:
                self.assertFalse(output[field])
        for field in (
            "execution_permitted",
            "dispatch_permitted",
            "completion_permitted",
            "live_activation",
        ):
            self.assertFalse(view[field])

    def test_restrictive_completed_decisions_preserve_holds_and_independent_work(self):
        producer, _, original_result = self.source()
        control, broker, support, _ = self.designated(producer, decision="quarantined")
        result = self.use(producer, broker, support)
        view = result.projection()
        self.assertFalse(view["affected_accepted_for_use"])
        self.assertEqual(
            view["remaining_holds"],
            json.loads(producer.evaluation.result_bytes)["hold_reasons"],
        )
        self.assertEqual(result.document, "")
        self.http.content = original.EXAMPLE_FINAL
        sibling = self.host.dispatch(
            self.ticket("sibling"),
            node_attempts={"plan": original_result["attempt"]["attempt_id"]},
        )
        self.assertEqual(sibling["review"]["final_content"], original.EXAMPLE_FINAL)
        self.assertEqual(control.current().context, producer.expected)

    def test_worker_authority_assertions_cannot_issue(self):
        producer, _, _ = self.source()
        _, broker, _, _ = self.designated(producer, extra={"role": "architect"})
        with self.assertRaisesRegex(ValueError, "authority-asserting"):
            broker.issue("EXAMPLE-control")
        with self.assertRaisesRegex(ValueError, "already attempted"):
            broker.issue("EXAMPLE-control")
        self.assertEqual(len(self.http.calls), 2)

    def test_original_completion_refusal_is_terminal_after_policy_recovery(self):
        initial_ticket = self.ticket()
        initial = self.run_ticket(initial_ticket)
        for access, node in (("direct", "plan"), ("lookup", "sibling")):
            with self.subTest(access=access):
                ticket = initial_ticket if node == "plan" else self.ticket(node)
                if node != "plan":
                    self.host.dispatch(
                        ticket, node_attempts={"plan": initial["attempt"]["attempt_id"]}
                    )
                token = self.host.completed(ticket)
                with mock.patch.object(original.review, "_policies", return_value=()):
                    with self.assertRaises(original.admission.AdmissionError):
                        if access == "lookup":
                            self.host.completed(ticket)
                        else:
                            self.host.observe_completion(token)
                with self.assertRaises(original.admission.AdmissionError):
                    self.host.completed(ticket)
                with self.assertRaisesRegex(
                    original.admission.AdmissionError, "Unissued"
                ):
                    self.host.observe_completion(token)
        self.assertEqual(len(self.http.calls), 2)

    def test_review_designation_refuses_inflight_and_terminal_observer_enrollment(self):
        producer, _, _ = self.source()
        support = self.support(producer)
        basis = workflow.adjudication_basis(
            producer, support, "EXAMPLE-designated-reviewer"
        )
        for stage in ("invocation-intent", "terminal"):
            with self.subTest(stage=stage):
                identity = "late-" + stage
                host = self.make_host(route_with_basis(identity, basis))
                ticket = host.issue(
                    identity + "-plan",
                    now=self.clock.now,
                    expires_at=self.clock.now + 1000,
                )
                attempts = []

                def observer(event):
                    if event["event"] == stage:
                        with self.assertRaisesRegex(
                            original.admission.AdmissionError,
                            "before controlled submission",
                        ):
                            workflow.CompletedAdjudicationControl(
                                producer,
                                support,
                                "EXAMPLE-designated-reviewer",
                                host,
                                ticket,
                                "EXAMPLE-control",
                            )
                        attempts.append(stage)

                self.http.content = original.EXAMPLE_FINAL
                host.dispatch(ticket, observer=observer)
                self.assertEqual(attempts, [stage])
                with self.assertRaisesRegex(
                    original.admission.AdmissionError, "before controlled submission"
                ):
                    workflow.CompletedAdjudicationControl(
                        producer,
                        support,
                        "EXAMPLE-designated-reviewer",
                        host,
                        ticket,
                        "EXAMPLE-control",
                    )
        self.assertEqual(len(self.http.calls), 3)

    def test_shared_adjudication_refusal_is_irreversible_and_preserves_primary(self):
        """Original I7 consumer veto shares the actual control's terminal lifecycle."""
        producer, _, _ = self.source()
        control, broker, _support, _ = self.designated(producer, all_findings=True)
        self.assertEqual(binding._parse(control.current().record_bytes)['decision'], 'accepted')
        primary = KeyboardInterrupt('EXAMPLE original eligibility interruption')
        control.refuse(primary)
        control.refuse(ValueError('EXAMPLE later refusal'))
        self.assertIs(control._refusal, primary)
        for action in (control.current, control.require_active, control.source_receipt):
            with self.assertRaisesRegex(ValueError, 'terminal'):
                action()
        with self.assertRaisesRegex(ValueError, 'terminal'):
            broker.issue('EXAMPLE-control')
        other, _broker, _support, _ = self.designated(producer, all_findings=True, identity='identity')
        other.producer = object()
        with self.assertRaisesRegex(ValueError, 'identity'):
            other.current()
        other.producer = producer
        with self.assertRaisesRegex(ValueError, 'terminal'):
            other.current()

    def test_source_drift_after_original_synthesis_refuses_terminal_use(self):
        producer, _, _ = self.source()
        _, broker, support, _ = self.designated(producer)
        permit = broker.issue("EXAMPLE-control")
        import evidence_use

        original_synthesis = evidence_use.evaluate_synthesis_inputs

        def changed(*args, **kwargs):
            result = original_synthesis(*args, **kwargs)
            (self.home / producer.return_path).chmod(0o600)
            (self.home / producer.return_path).write_bytes(b"EXAMPLE changed return")
            return result

        with mock.patch.object(
            evidence_use, "evaluate_synthesis_inputs", side_effect=changed
        ):
            result = workflow.use_evidence(
                broker,
                permit,
                producer.expected,
                affected_findings=[x.finding_id for x in support],
            )
        self.assertEqual(result.document, "")
        self.assertEqual(result.projection()["resolved_findings"], [])
        (self.home / producer.return_path).write_bytes(producer.raw)
        again = workflow.use_evidence(
            broker,
            permit,
            producer.expected,
            affected_findings=[x.finding_id for x in support],
        )
        self.assertFalse(again.projection()["affected_accepted_for_use"])
        with self.assertRaisesRegex(ValueError, "terminal"):
            producer.current()

    def test_same_bound_source_reaches_original_current_readiness(self):
        producer, _, _ = self.source()
        control, broker, support, _ = self.designated(producer, all_findings=True)
        permit = broker.issue("EXAMPLE-control")
        plan = self.current_plan(control, broker, permit)
        result = workflow.current_readiness(
            plan,
            broker,
            permit,
            producer.expected,
            affected_findings=[x.finding_id for x in support],
        )
        self.assertTrue(result["current_evidence_ready"], result["errors"])
        self.assertFalse(result["execution_permitted"])
        self.assertFalse(result["completion_permitted"])
        # Informational history remains readable, but cannot import a spent grant.
        self.assertEqual(workflow.readiness.validate_plan(plan), [])
        again = workflow.current_readiness(
            plan,
            broker,
            permit,
            producer.expected,
            affected_findings=[x.finding_id for x in support],
        )
        self.assertFalse(again["current_evidence_ready"])

    def current_plan(self, control, broker, permit):
        plan = sample_plan()
        record = binding._parse(control.current().record_bytes)
        plan["adjudication_record"].update(
            accepted_findings=record["finding_ids"],
            rejected_findings=[],
            quarantined_findings=[],
            evidence_refs=record["supporting_evidence"],
            current_source=workflow._readiness_binding(broker._issued[permit]),
        )
        return plan

    def test_historical_readiness_role_labels_cannot_replace_current_source_bindings(
        self,
    ):
        producer, _, _ = self.source()
        control, broker, support, _ = self.designated(producer, all_findings=True)
        permit = broker.issue("EXAMPLE-control")
        plan = self.current_plan(control, broker, permit)
        plan["adjudication_record"]["current_source"]["context"]["candidate"] = (
            "EXAMPLE-other-candidate"
        )
        plan["adjudication_record"]["evidence_refs"][0]["sha256"] = "f" * 64
        self.assertEqual(workflow.readiness.validate_plan(plan), [])
        result = workflow.current_readiness(
            plan,
            broker,
            permit,
            producer.expected,
            affected_findings=[x.finding_id for x in support],
        )
        self.assertFalse(result["current_evidence_ready"])
        self.assertTrue(
            any("exact original current" in error for error in result["errors"])
        )
        self.assertFalse(result["evidence"]["affected_accepted_for_use"])
        self.assertEqual(
            result["evidence"]["remaining_holds"],
            result["evidence"]["original_evaluation"]["hold_reasons"],
        )
        self.assertEqual(len(self.http.calls), 2)

    def test_malformed_readiness_refusal_spends_permit_and_preserves_original_holds(
        self,
    ):
        producer, _, _ = self.source()
        for index, malformed in enumerate(("root", "projection-type")):
            with self.subTest(malformed=malformed):
                control, broker, support, _ = self.designated(
                    producer, all_findings=True, identity="malformed-" + str(index)
                )
                permit = broker.issue("EXAMPLE-control")
                plan = self.current_plan(control, broker, permit)
                bad = [None] if malformed == "root" else copy.deepcopy(plan)
                if malformed == "projection-type":
                    bad["artifact_authority"]["projections"][0]["type"] = []
                refused = workflow.current_readiness(
                    bad,
                    broker,
                    permit,
                    producer.expected,
                    affected_findings=[x.finding_id for x in support],
                )
                self.assertFalse(refused["current_evidence_ready"])
                view = refused["evidence"]
                self.assertFalse(view["affected_accepted_for_use"])
                self.assertEqual(
                    view["remaining_holds"], view["original_evaluation"]["hold_reasons"]
                )
                self.assertEqual(view["resolved_findings"], [])
                self.assertIsNone(view["synthesis"])
                for attempted in (permit, {}, []):
                    recovered = workflow.current_readiness(
                        plan,
                        broker,
                        attempted,
                        producer.expected,
                        affected_findings=[x.finding_id for x in support],
                    )
                    self.assertFalse(recovered["current_evidence_ready"])
        self.assertEqual(len(self.http.calls), 3)

    def risk_case(self):
        producer, task, _ = self.source(task=True)
        control, broker, support, _ = self.designated(producer, all_findings=True)
        self.assertTrue(
            self.use(producer, broker, support).projection()[
                "affected_accepted_for_use"
            ]
        )
        receipt = control.source_receipt()
        record = control.current().record_bytes
        workflow._publish(self.home, "EXAMPLE-source-adjudication.json", record)
        (self.home / "README.md").write_text(
            "# EXAMPLE production runbook\n\nOffline spelling example.\n"
        )
        value = workflow.narrowing.scope_evidence(
            self.home,
            receipt,
            task,
            ("environment:production",),
            observed_support=support,
        )
        workflow._publish(self.home, "EXAMPLE-scope.json", binding._json(value))
        scope = workflow.narrowing.observe_scope(
            self.home, "EXAMPLE-scope.json", receipt, task, observed_support=support
        )
        registered = workflow.risk_use.TaskRiskRegistration(
            task,
            receipt,
            scope,
            support,
            producer.return_path,
            "EXAMPLE-source-adjudication.json",
            record,
            "EXAMPLE-risk-decision.json",
            "EXAMPLE-separate-task-risk-reviewer",
        )
        basis = workflow.task_risk_basis(self.home, registered)
        host = self.make_host(route_with_basis("task-risk", basis))
        ticket = host.issue(
            "task-risk-plan", now=self.clock.now, expires_at=self.clock.now + 1000
        )
        risk_control = workflow.CompletedTaskRiskControl(
            self.home, registered, host, ticket, "EXAMPLE-risk", adjudication=control
        )
        risk_host = workflow.risk_use.TaskRiskHost(
            self.home, {"EXAMPLE-risk": registered}, risk_control
        )
        self.http.content = binding._json(
            {
                "decision": "accepted",
                "rationale": "EXAMPLE checked production is a documentation reference only.",
            }
        ).decode()
        host.dispatch(ticket)
        risk_control.publish()
        return producer, risk_host

    def test_separate_actual_task_risk_review_reaches_original_task_risk_host(self):
        _, risk_host = self.risk_case()
        result = risk_host.plan("EXAMPLE-risk")
        self.assertTrue(result["controlled_plan_ready"], result["errors"])
        self.assertEqual(result["plan"]["risk_level"], "low")
        self.assertEqual(result["original_assessment"]["floor"], "medium")
        self.assertIsNone(result["effective_assessment"]["floor"])
        self.assertFalse(result["effect_authority"])
        self.assertTrue(result["plan"]["architect_adjudication_required"])
        self.assertEqual(len(self.http.calls), 3)
        self.assertFalse(risk_host.plan("EXAMPLE-risk")["controlled_plan_ready"])

    def test_original_task_risk_callout_cannot_erase_completed_source_refusal(self):
        producer, risk_host = self.risk_case()
        original_router = workflow.risk_use.classify_work

        def changed(*args, **kwargs):
            result = original_router(*args, **kwargs)
            path = self.home / producer.return_path
            path.chmod(0o600)
            path.write_bytes(b"EXAMPLE changed controlled source after router callout")
            return result

        with mock.patch.object(workflow.risk_use, "classify_work", side_effect=changed):
            result = risk_host.plan("EXAMPLE-risk")
        self.assertFalse(result["controlled_plan_ready"])
        self.assertIsNone(result["plan"])
        self.assertEqual(result["effective_assessment"], result["original_assessment"])
        (self.home / producer.return_path).write_bytes(producer.raw)
        self.assertFalse(risk_host.plan("EXAMPLE-risk")["controlled_plan_ready"])
        self.assertEqual(len(self.http.calls), 3)

    def test_actual_source_context_and_missing_review_basis_refuse_before_extra_http(
        self,
    ):
        producer, _, _ = self.source()
        for field, replacement in (
            ("candidate", "EXAMPLE-other-candidate"),
            ("scope", "EXAMPLE-other-scope"),
            ("packet_sha256", "f" * 64),
        ):
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValueError, "actual original|submitted source"),
            ):
                workflow.WorkflowSource(
                    self.home,
                    self.host,
                    producer.completion,
                    dataclasses.replace(producer.expected, **{field: replacement}),
                    return_path="EXAMPLE-unpublished-return.md",
                    dispatch_path="EXAMPLE-unpublished-dispatch.json",
                )
        host = self.make_host(route_with_basis("missing-basis"))
        ticket = host.issue(
            "missing-basis-plan", now=self.clock.now, expires_at=self.clock.now + 1000
        )
        with self.assertRaisesRegex(ValueError, "exact current bound basis"):
            workflow.CompletedAdjudicationControl(
                producer,
                self.support(producer),
                "EXAMPLE-designated-reviewer",
                host,
                ticket,
                "EXAMPLE-control",
            )
        self.assertEqual(len(self.http.calls), 1)


class TerminalPulse(unittest.TestCase):
    def setUp(self):
        self.f = WorkflowAdjudicationTests()
        self.f.setUp()
        self.addCleanup(cleanup_helper, self, self.f)

    def pulse(self, producer):
        path = self.f.home / producer.return_path
        path.chmod(0o600)
        path.write_bytes(b"EXAMPLE temporary source mismatch")
        try:
            with self.assertRaises(ValueError):
                producer.current()
        finally:
            path.write_bytes(producer.raw)

    def frames(self):
        frame = inspect.currentframe().f_back
        result = []
        while frame is not None:
            result.append((frame.f_code, dict(frame.f_locals)))
            frame = frame.f_back
        return result

    def use_case(self, kind):
        producer, _, _ = self.f.source()
        control, broker, support, _ = self.f.designated(producer, all_findings=True)
        permit = broker.issue("EXAMPLE-control")
        plan = self.f.current_plan(control, broker, permit)
        seen = []
        real = workflow.qualified.make_acceptance_decision

        def evaluated(*args, **kwargs):
            result = real(*args, **kwargs)
            if any(
                code is workflow.qualified._observe.__code__
                for code, local in self.frames()
            ):
                seen.append("broker-validation")
                if len(seen) == 2:
                    self.pulse(producer)
            return result

        with mock.patch.object(
            workflow.qualified, "make_acceptance_decision", side_effect=evaluated
        ):
            result = (
                workflow.use_evidence(
                    broker,
                    permit,
                    producer.expected,
                    affected_findings=[row.finding_id for row in support],
                )
                if kind == "advice"
                else workflow.current_readiness(
                    plan,
                    broker,
                    permit,
                    producer.expected,
                    affected_findings=[row.finding_id for row in support],
                )
            )
        self.assertEqual(len(seen), 2)
        accepted = (
            result.projection()["affected_accepted_for_use"]
            if kind == "advice"
            else result["current_evidence_ready"]
        )
        self.assertFalse(
            accepted,
            "Detected terminal source refusal disappeared after final evaluator restored bytes",
        )

    def test_final_w05_validation_preserves_terminal_source_refusal(self):
        self.use_case("advice")

    def test_final_readiness_validation_preserves_terminal_source_refusal(self):
        self.use_case("readiness")

    def test_source_current_checks_terminal_state_on_exit(self):
        producer, _, _ = self.f.source()
        real = workflow.qualified.make_acceptance_decision
        seen = []

        def evaluated(*args, **kwargs):
            result = real(*args, **kwargs)
            if not seen:
                seen.append("pulse")
                self.pulse(producer)
            return result

        accepted = True
        with mock.patch.object(
            workflow.qualified, "make_acceptance_decision", side_effect=evaluated
        ):
            try:
                producer.current()
            except ValueError:
                accepted = False
        self.assertFalse(
            accepted, "Outer current source observation lost reentrant terminal refusal"
        )

    def test_final_task_risk_validation_preserves_terminal_source_refusal(self):
        producer, host = self.f.risk_case()
        real = workflow.risk_use.produce_disposition
        seen = []

        def produced(*args, **kwargs):
            result = real(*args, **kwargs)
            frames = self.frames()
            if (
                not seen
                and any(
                    code is workflow.risk_use._validate.__code__
                    for code, local in frames
                )
                and any(
                    code is workflow.risk_use.TaskRiskHost._plan.__code__
                    and "plan" in local
                    for code, local in frames
                )
            ):
                seen.append("final-risk-validation")
                self.pulse(producer)
            return result

        with mock.patch.object(
            workflow.risk_use, "produce_disposition", side_effect=produced
        ):
            result = host.plan("EXAMPLE-risk")
        self.assertEqual(seen, ["final-risk-validation"])
        self.assertFalse(
            result["controlled_plan_ready"],
            "Detected terminal source refusal disappeared after final task-risk validator restored bytes",
        )


if __name__ == "__main__":
    unittest.main()
