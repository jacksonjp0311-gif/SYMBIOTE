"""Synthetic consumer/containment fixtures, never the registered native cohort."""
import copy
import json
import tempfile
import types
from pathlib import Path
import unittest
from unittest import mock

import reciprocal_engineering as r


class IndependentMeasurementTests(unittest.TestCase):
    def setUp(self):
        self.schema,self.costs=r.graph_fixture(1,[1,2])
        self.price=100000;self.target=4

    def test_generic_two_branch_control_and_partial_certificate_are_independently_derived(self):
        measurement=r.simulate_measurement(self.schema,self.costs,[self.target],self.price)
        self.assertEqual([row["edge_id"] for row in measurement["lookups"]],[0,2,3,4])
        self.assertEqual(measurement["predictions"],[[self.target,3]])
        self.assertEqual(measurement["provider_checks"],5)
        r.verify_measurement(measurement,self.schema,self.costs,[self.target],self.price)
        partial=dict(lookups=[dict(provider_sha256=r.safety.digest(dict(schema=self.schema,costs=self.costs)),sequence=i,edge_id=edge,cost=1) for i,edge in enumerate([2,3,4])],
                     provider_checks=5,model_work=3+r.assess(self.schema,{2:1,3:1,4:1},0,4)[1],predictions=[[4,3]],complete=True)
        r.verify_partial_measurement(partial,self.schema,self.costs,[dict(edge_id=i,cost=1) for i in [2,3,4]],[4])

    def test_changed_cost_or_work_cannot_pass_with_a_producer_complete_flag(self):
        original=r.simulate_measurement(self.schema,self.costs,[self.target],self.price)
        for key in ("model_work","provider_checks","lookup_cost","prediction","missing_trace"):
            bad=copy.deepcopy(original)
            if key in ("model_work","provider_checks"):bad[key]+=1
            if key=="lookup_cost":bad["lookups"][0]["cost"]=1
            if key=="prediction":bad["predictions"][0][1]=2
            if key=="missing_trace":bad["lookups"].pop()
            with self.subTest(key=key),self.assertRaises(RuntimeError):
                r.verify_measurement(bad,self.schema,self.costs,[self.target],self.price)

    def test_unknown_edges_remain_unknown_and_wrong_map_is_rejected(self):
        route,_=r.shortest(self.schema,{2:1,3:1},0,4)
        self.assertFalse(route["certified"])
        with self.assertRaisesRegex(RuntimeError,"wrong or duplicate"):
            r.verify_partial_measurement({},self.schema,self.costs,[dict(edge_id=0,cost=1)],[4])

    def test_control_budget_is_not_silently_increased(self):
        unrestricted=r.simulate_measurement(self.schema,self.costs,[self.target],self.price)
        cheap=r.simulate_measurement(self.schema,self.costs,[self.target],self.price,budget=100)
        self.assertFalse(cheap["complete"])
        self.assertLess(len(cheap["lookups"]),len(unrestricted["lookups"]))
        self.assertLessEqual(cheap["model_work"]+cheap["provider_checks"],100)

    def test_missing_empty_or_relearned_restart_is_not_retained_learning(self):
        first=dict(schema="symbiote.cognition-summary/1",status="STOPPED",identity="private-a",fresh_promotions=2,active_models=2,final_knowledge_anchor=dict(records=3,head_sha256="a"*64))
        again=dict(schema=first["schema"],status="STOPPED",identity="private-a",fresh_promotions=0,active_models=2,initial_knowledge_anchor=first["final_knowledge_anchor"],final_knowledge_anchor=first["final_knowledge_anchor"])
        r.verify_restart(first,again)
        for change in ("empty","relearned","foreign","missing"):
            bad=copy.deepcopy(again)
            if change=="empty":bad["active_models"]=0
            if change=="relearned":bad["fresh_promotions"]=1
            if change=="foreign":bad["identity"]="other"
            if change=="missing":bad.pop("initial_knowledge_anchor")
            with self.subTest(change=change),self.assertRaises((RuntimeError,KeyError)):r.verify_restart(first,bad)

    def test_identical_pid_or_foreign_owner_does_not_establish_os_restart(self):
        before=dict(identity="owner",pid=101);after=dict(identity="owner",pid=202)
        r.verify_process_restart(before,after,"owner")
        for changed in [dict(identity="owner",pid=101),dict(identity="foreign",pid=202),dict(identity="owner",pid=True)]:
            with self.assertRaises(RuntimeError):r.verify_process_restart(before,changed,"owner")

    def test_timing_is_diagnostic_and_missing_phase_work_cannot_be_claimed(self):
        names=["compute","lock_wait","io","evaluation","replay","shutdown"]
        report=dict(schema="symbiote.stage-timing/1",pid=22,logical_cost_or_reward_input=False,
                    overlapping_totals_are_additive=False,deterministic_or_exclusive_cpu_time=False,
                    stages=[dict(stage=name,started=1,completed=1,in_flight=0,monotonic_elapsed_ns=100,
                            max_monotonic_elapsed_ns=100,wall_elapsed_ns=100,min_started_wall_unix_ns=1000,
                            max_completed_wall_unix_ns=1100,saturated=False,wall_clock_regressions=0,wall_clock_unavailable=0) for name in names])
        r.verify_timing(report,22,names)
        for key in ("reward","missing_work","wrong_process"):
            changed=copy.deepcopy(report)
            if key=="reward":changed["logical_cost_or_reward_input"]=True
            if key=="missing_work":changed["stages"][0]["monotonic_elapsed_ns"]=0
            if key=="wrong_process":changed["pid"]=99
            with self.subTest(key=key),self.assertRaises(RuntimeError):r.verify_timing(changed,22,names)

    def test_boolean_does_not_equal_integer_measurement(self):
        with self.assertRaises(RuntimeError):r.integer(True)
        with self.assertRaises(RuntimeError):r.equal(True,1,"typed integer")


class OnceOnlyContainmentTests(unittest.TestCase):
    def test_guard_exit_failure_is_hold_and_preserves_returned_native_process_receipt(self):
        with tempfile.TemporaryDirectory(prefix="reciprocal-consumer-fixture-") as temporary:
            root=Path(temporary)
            registration=dict(artifact_directory=str(root),source_commit="a"*40,
                              binaries=dict(service_tests=dict(path=str(root/"synthetic-never-executed.exe"))))
            path=root/"registration.json";r.write_new(path,registration)
            process=dict(process_receipt="synthetic.process.json",exit_code=0,outcome="completed",cleanup_verified=True)
            r.write_new(root/process["process_receipt"],process)
            class FailedGuard:
                report=dict(released=True,max_observed_suspension_ms=30000)
                def __enter__(self):return self
                def check(self):pass
                def __exit__(self,*_):raise RuntimeError("Host suspension interrupted qualification")
            with mock.patch.object(r,"source_check"),mock.patch.object(r,"QualificationAwake",return_value=FailedGuard()), \
                    mock.patch.object(r.safety,"execute",return_value=process),mock.patch.object(r.safety,"check_exit"), \
                    mock.patch.object(r.safety,"check_native_test"),mock.patch.object(r.safety,"output",return_value="synthetic test output"), \
                    mock.patch.object(r,"verify_cohort",return_value=dict(status="PASS_OPERATIONAL_RECIPROCITY")):
                result=r.run(path,r.sha(path))
                self.assertEqual(result["status"],"HOLD")
                self.assertEqual(result["process"],process)
                self.assertTrue((root/process["process_receipt"]).exists())
                self.assertIn("suspension",result["failure"])
                with self.assertRaises(FileExistsError):r.run(path,r.sha(path))
            self.assertEqual(r.load(root/"reciprocal-report.json")["status"],"HOLD")


class PreservedExecutableTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix="reciprocal-snapshot-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.parent=Path(self.temporary.name).resolve();self.root=self.parent/"artifacts"
        (self.root/"executables").mkdir(parents=True)
        self.original=self.parent/"original-native.exe";self.original.write_bytes(b"synthetic-native-not-executed\0-----BEGIN PRIVATE KEY-----\0compiled parser literal")
        self.tests=self.parent/"original-tests.exe";self.tests.write_bytes(b"synthetic-tests-not-executed\0-----BEGIN RSA PRIVATE KEY-----\0compiled rejection literal")
        self.native_sha=r.sha(self.original);self.test_sha=r.sha(self.tests)
        self.snapshot=self.root/"executables/symbiote.exe";self.snapshot.write_bytes(self.original.read_bytes())
        self.test_snapshot=self.root/"executables/service-tests.exe";self.test_snapshot.write_bytes(self.tests.read_bytes())
        self.manifest=dict(schema="symbiote.partial-graph-native-artifacts/1",private_keys_copied=False,
                           native_binary=str(self.snapshot),native_binary_sha256=self.native_sha,
                           service_tests=str(self.test_snapshot),service_tests_sha256=self.test_sha,
                           files=[dict(path=p.relative_to(self.root).as_posix(),bytes=p.stat().st_size,sha256=r.sha(p))
                                  for p in (self.snapshot,self.test_snapshot)],report={})
        self.save()

    def save(self):
        (self.root/"artifact-manifest.json").write_text(json.dumps(self.manifest),encoding="utf-8")

    def verify(self):
        return r.verify_manifest(self.root,self.original,self.native_sha,
                                 dict(path=str(self.tests),sha256=self.test_sha))

    def test_exact_censused_snapshots_survive_original_build_replacement_and_removal(self):
        self.verify()
        self.original.write_bytes(b"later-build-must-not-be-substituted")
        self.tests.unlink()
        self.verify()

    def test_same_bytes_at_an_unregistered_external_path_do_not_reassign_provenance(self):
        external=self.parent/"unregistered-native.exe";external.write_bytes(self.snapshot.read_bytes())
        self.manifest["native_binary"]=str(external);self.save()
        with self.assertRaisesRegex(RuntimeError,"outside the artifact snapshot"):self.verify()

    def test_changed_snapshot_cannot_replace_the_registered_hash_even_with_a_rehashed_manifest(self):
        self.snapshot.write_bytes(b"different-claimed-native")
        self.manifest["native_binary_sha256"]=r.sha(self.snapshot)
        self.manifest["files"][0].update(bytes=self.snapshot.stat().st_size,sha256=r.sha(self.snapshot));self.save()
        with self.assertRaisesRegex(RuntimeError,"provenance differs"):self.verify()

    def test_service_test_copy_must_match_its_independent_registration_pin(self):
        self.test_snapshot.write_bytes(b"different-tests")
        self.manifest["service_tests_sha256"]=r.sha(self.test_snapshot)
        self.manifest["files"][1].update(bytes=self.test_snapshot.stat().st_size,sha256=r.sha(self.test_snapshot));self.save()
        with self.assertRaisesRegex(RuntimeError,"registered executable SHA differs"):self.verify()

    def test_unregistered_executable_and_unpinned_test_copy_receive_no_pem_exception(self):
        with self.assertRaisesRegex(RuntimeError,"independent exact SHA pin"):
            r.verify_manifest(self.root,self.original,self.native_sha)
        extra=self.root/"unregistered.exe";extra.write_bytes(b"-----BEGIN PRIVATE KEY-----\noperator secret")
        self.manifest["files"].append(dict(path="unregistered.exe",bytes=extra.stat().st_size,sha256=r.sha(extra)));self.save()
        with self.assertRaisesRegex(RuntimeError,"private key in public artifacts"):self.verify()

    def test_extra_snapshot_file_and_snapshot_reassignment_both_fail_the_census_contract(self):
        (self.root/"extra.exe").write_bytes(self.snapshot.read_bytes())
        with self.assertRaisesRegex(RuntimeError,"file census"):self.verify()
        (self.root/"extra.exe").unlink()
        other=self.root/"executables/other.exe";self.snapshot.rename(other)
        self.manifest["native_binary"]=str(other);self.manifest["files"][0]["path"]="executables/other.exe";self.save()
        with self.assertRaisesRegex(RuntimeError,"bounded censused executable snapshot"):self.verify()

    def test_manifest_reparse_member_is_refused_before_json_is_loaded(self):
        manifest=self.root/"artifact-manifest.json";original=Path.lstat
        def reparse(path,*args,**kwargs):
            actual=original(path,*args,**kwargs)
            return types.SimpleNamespace(st_file_attributes=0x400,st_mode=actual.st_mode) if path==manifest else actual
        with mock.patch.object(Path,"lstat",autospec=True,side_effect=reparse):
            with self.assertRaisesRegex(RuntimeError,"linked/reparse artifact refused"):self.verify()


class FiniteFeedbackTests(unittest.TestCase):
    def test_distinct_exchange_ids_cannot_credit_one_scope_promotion_candidate_or_sense_twice(self):
        credits=[dict(scope=scope,promotion_sha256=letter*64,candidate_id=letter*64,sense_decision_id="sense-"+letter)
                 for scope,letter in zip(r.SCOPES,("a","b"))]
        r.verify_normal_credits(credits)
        for field in ("scope","promotion_sha256","candidate_id","sense_decision_id"):
            changed=copy.deepcopy(credits);changed[1][field]=changed[0][field]
            with self.subTest(field=field),self.assertRaises(RuntimeError):r.verify_normal_credits(changed)
        with self.assertRaises(RuntimeError):r.verify_normal_credits(credits[:1])

    def test_unrecognized_feedback_versions_cannot_disappear_from_the_independent_history(self):
        row=dict(event="partner_decision_recorded",decision=dict(details=dict(schema="symbiote.learning-feedback/2",event={})))
        with self.assertRaisesRegex(RuntimeError,"unsupported learning feedback namespace"):
            r.feedback_groups([row])

    def test_measured_task_arithmetic_separates_positive_harmful_and_unavailable_costs(self):
        baseline=dict(kind="measured",units=1000,evidence_sha256="a"*64)
        measurement=dict(before=dict(graph_forecast_work=100),after=dict(graph_forecast_work=277),
                         costs=dict(unit_model="received-graph-task-sense-through-first-use/1",acquisition=0,adoption=1,
                                    validation=300,prediction=38,wire=50,replay=139))
        outcome=r.scoped_outcome(measurement,300,baseline,38,50)
        self.assertEqual(outcome["candidate_cost"],528);self.assertEqual(outcome["measured_net"],472)
        self.assertTrue(outcome["verified_benefit"])
        harmful=r.scoped_outcome(measurement,300,dict(baseline,units=1),38,50)
        self.assertEqual(harmful["measured_net"],-527);self.assertFalse(harmful["verified_benefit"])
        for changed in (dict(measurement,costs=dict(measurement["costs"],wire=0)),
                        dict(measurement,after=dict(graph_forecast_work=101))):
            with self.assertRaises(RuntimeError):r.scoped_outcome(changed,300,baseline,38,50)
        for claimed in (dict(outcome,measured_net=473),dict(outcome,candidate_cost=0),dict(harmful,verified_benefit=True)):
            with self.assertRaises(RuntimeError):r.equal(claimed,outcome if claimed["measured_net"]>0 else harmful,"actual outcome")

    def test_public_receipt_recomputation_cannot_swap_bindings_measurements_or_duplicate_credit(self):
        results=[dict(binding=dict(exchange_id=letter*64,request_sha256=letter*64,scope="scope-"+letter),
                      measurement_sha256=letter*64,outcome=dict(verified_benefit=True)) for letter in ("a","b")]
        receipts=[dict(binding=copy.deepcopy(item["binding"]),measurement_sha256=item["measurement_sha256"],verified_scoped_benefit=True) for item in results]
        r.verify_bound_receipts(receipts,results)
        for change in ("binding","measurement","duplicate","benefit"):
            bad=copy.deepcopy(receipts)
            if change=="binding":bad[0]["binding"]["request_sha256"]="c"*64
            if change=="measurement":bad[0]["measurement_sha256"]=bad[1]["measurement_sha256"]
            if change=="duplicate":bad[1]=copy.deepcopy(bad[0])
            if change=="benefit":bad[0]["verified_scoped_benefit"]=False
            with self.subTest(change=change),self.assertRaises(RuntimeError):r.verify_bound_receipts(bad,results)

    def test_changed_typed_feedback_body_requires_both_carrier_and_ledger_revalidation(self):
        envelope=dict(schema="symbiote.learning-feedback/1",scope="scope",event=dict(phase="decision",
                      binding=dict(origin="native_learning_intent",exchange_id="a"*64,decision_id="learn",sender_id="sender",receiver_id="receiver",scope="scope",
                                   schema_fingerprint="b"*64,request_sha256="c"*64,candidate_id="d"*64,offered_record_sha256="e"*64,policy_sha256="f"*64,fixture_sha256="0"*64),
                      before=dict(identity="receiver",records=1,head_sha256="1"*64),baseline=dict(kind="unknown",reason="not measured")))
        original=r.feedback_carrier_digest(envelope)
        changed=copy.deepcopy(envelope);changed["event"]["binding"]["request_sha256"]="9"*64
        self.assertNotEqual(original,r.feedback_carrier_digest(changed))
        decision=dict(context="scope",decision_id="feedback-"+original,selected_peer=None,frontier_edge=None,details=changed)
        with self.assertRaisesRegex(RuntimeError,"carrier digest"):
            r.feedback_groups([dict(event="partner_decision_recorded",decision=decision)])


if __name__=="__main__":unittest.main()
