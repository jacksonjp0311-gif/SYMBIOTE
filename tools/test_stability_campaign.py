"""Campaign safety tests; no campaign or research cohort is started here."""
import importlib.util
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("campaign",ROOT/"tools/stability_campaign.py")
c=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class SafetyTests(unittest.TestCase):
    def test_real_timeout_contains_and_terminates_an_actual_descendant(self):
        with tempfile.TemporaryDirectory(prefix="symbiote-campaign-tree-test-") as temp:
            code="import subprocess,sys,json,time;p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);print(json.dumps({'child':p.pid}),flush=True);time.sleep(30)"
            result=c.execute([sys.executable,"-c",code],Path(temp),"tree",timeout=2)
            self.assertEqual(result["outcome"],"timeout")
            self.assertTrue(result["cleanup_verified"])
            self.assertGreater(json.loads(c.output(result,temp))["child"],0)
            self.assertTrue((Path(temp)/result["process_receipt"]).is_file())
            self.assertLess(result["elapsed_seconds"],2+c.BOUNDS["cleanup_seconds"]+2)

    def test_real_cancellation_and_output_ceiling_preserve_failure_receipts(self):
        with tempfile.TemporaryDirectory(prefix="symbiote-campaign-cancel-test-") as temp:
            start=time.monotonic()
            cancelled=c.execute([sys.executable,"-c","import time;time.sleep(30)"],Path(temp),"cancel",timeout=5,cancelled=lambda:time.monotonic()-start>0.2)
            self.assertEqual(cancelled["outcome"],"cancelled")
            self.assertTrue(cancelled["cleanup_verified"])
            code="import sys,time;sys.stdout.buffer.write(b'x'*3000000);sys.stdout.flush();time.sleep(30)"
            overflow=c.execute([sys.executable,"-c",code],Path(temp),"overflow",timeout=5)
            self.assertEqual(overflow["outcome"],"output-budget")
            self.assertTrue(overflow["output_truncated"])
            self.assertLessEqual(overflow["stdout_bytes"]+overflow["stderr_bytes"],c.BOUNDS["output_bytes_per_process"])
            self.assertTrue(overflow["cleanup_verified"])

    def test_missing_executable_failure_is_recorded_and_never_counts_as_pass(self):
        with tempfile.TemporaryDirectory(prefix="symbiote-campaign-start-test-") as temp:
            result=c.execute([str(Path(temp)/"missing")],Path(temp),"missing",timeout=1)
            self.assertEqual(result["outcome"],"execution-error")
            self.assertTrue((Path(temp)/result["process_receipt"]).exists())
            with self.assertRaises(RuntimeError):c.check_exit(result)

    def test_actual_namespaced_unsafe_long_and_reserved_labels_use_safe_unique_artifacts(self):
        labels=["65-endurance::mixed_family_24_cycle_local_campaign","CON","NUL.txt","../outside/\\unsafe:*?\"<>|. ",
                "a/b","a:b","a\\b","same-prefix-"+"x"*1000+"A","same-prefix-"+"x"*1000+"B","\u03bb/\u5b9e\u9a8c"]
        with tempfile.TemporaryDirectory(prefix="symbiote-campaign-labels-") as temp:
            root=Path(temp);names=set()
            code="import json,sys;print(json.dumps(sys.argv[1:]));print('captured-stderr',file=sys.stderr)"
            for label in labels:
                arguments=[sys.executable,"-c",code,"original::argument",label]
                result=c.execute(arguments,root,label,timeout=10)
                c.check_exit(result)
                self.assertEqual(result["label"],label)
                self.assertEqual(result["argv"],arguments)
                self.assertEqual(json.loads(c.output(result,root)),arguments[3:])
                self.assertEqual((root/result["stderr"]).read_text(encoding="utf-8").strip(),"captured-stderr")
                self.assertEqual(c.load(root/result["process_receipt"]),result)
                for field in ("stdout","stderr","process_receipt"):
                    name=result[field]
                    self.assertRegex(name,r"^p-[A-Za-z0-9_-]{1,12}-[0-9a-f]{64}\.(stdout|stderr|process\.json)$")
                    self.assertLessEqual(len(name),92)
                    self.assertEqual((root/name).resolve().parent,root.resolve())
                    self.assertNotIn(name,names)
                    names.add(name)
                    self.assertTrue(name.startswith(c.artifact_stem(label)+"."))
            self.assertEqual(len(names),3*len(labels))
            self.assertEqual({path.name for path in root.iterdir()},names)
            self.assertEqual(c.artifact_stem(labels[0]),c.artifact_stem(labels[0]))
            self.assertNotEqual(c.artifact_stem("a/b"),c.artifact_stem("a:b"))
            # Equal readable prefixes still retain the full original-label hash.
            self.assertNotEqual(c.artifact_stem(labels[-3]),c.artifact_stem(labels[-2]))

    def test_exact_regression_cannot_accept_zero_tests_or_failed_tests(self):
        c.check_native_test("running 1 test\ntest result: ok. 1 passed; 0 failed; 80 filtered out;")
        for text in ("test result: ok. 0 passed; 0 failed;", "test result: FAILED. 0 passed; 1 failed;", "1 passed"):
            with self.assertRaises(RuntimeError):c.check_native_test(text)

    def test_prediction_schema_and_duplicate_artifacts_fail_closed(self):
        self.assertEqual(c.prediction_revisions(dict(predictions=[dict(artifact="alpha-table",revision=2)]))["alpha-table"]["revision"],2)
        for rows in ([dict(id="alpha-table",revision=2)],[dict(artifact="alpha-table",revision=True)],[dict(artifact="a",revision=1),dict(artifact="a",revision=2)]):
            with self.assertRaises(RuntimeError):c.prediction_revisions(dict(predictions=rows))
        with self.assertRaises(RuntimeError):c.assert_predictions(dict(identity="owner",active_artifacts=True,network_requests=0),"owner",1)

    def test_complete_genesis_tables_not_just_counts_and_revisions_are_required(self):
        expected={"alpha-table":1,"beta-table":1}
        valid=dict(schema="symbiote.retained/1",status="PASS",identity="owner",active_artifacts=2,network_requests=0,
                   genesis_artifacts=2,structural_artifacts=0,structural_knowledge=[],predictions=[
                       dict(artifact="alpha-table",partner="alpha",scope="finite-boolean-v1",revision=1,predictions=[0,1,1,0]),
                       dict(artifact="beta-table",partner="beta",scope="finite-boolean-v1",revision=1,predictions=[0,1,0,1])])
        c.genesis_predictions(valid,"owner",expected)
        import copy
        for kind in ("missing","empty","wrong","bool","source","scope"):
            invalid=copy.deepcopy(valid)
            if kind=="missing":del invalid["predictions"]
            elif kind=="source":invalid["predictions"][0]["partner"]="other"
            elif kind=="scope":invalid["predictions"][0]["scope"]="other"
            else:invalid["predictions"][0]["predictions"]={"empty":[],"wrong":[1,1,1,0],"bool":[False,1,1,0]}[kind]
            with self.assertRaises((RuntimeError,KeyError),msg=kind):c.genesis_predictions(invalid,"owner",expected)

    def test_final_cancel_deadline_and_report_space_cannot_become_pass(self):
        c.final_acceptance(False,1,100,100)
        for args in ((True,1,0,0),(False,601,0,0),(False,1,c.BOUNDS["evidence_bytes"],1),
                     (False,1,0,c.BOUNDS["final_report_reserve_bytes"]+1)):
            with self.assertRaises(RuntimeError):c.final_acceptance(*args)

    def test_actual_affine_outputs_must_match_the_committed_strategy(self):
        record=dict(id="model",source="peer",scope="manual/v1",revision=1,schema_fingerprint="a"*64,
                    payload=dict(kind="affine",width=4,coefficients=3,bias=False))
        model={key:record[key] for key in ("id","source","scope","revision","schema_fingerprint")}
        model.update(model=record["payload"],sample_predictions=[dict(input=i,output=(i&3).bit_count()%2) for i in range(8)])
        report=dict(identity="owner",network_requests=0,active_artifacts=1,genesis_artifacts=0,predictions=[],structural_artifacts=1,structural_knowledge=[model])
        c.structural_affine_predictions(report,"owner",record)
        for value in (None,2,True):
            model["sample_predictions"][0]["output"]=value
            with self.assertRaises(RuntimeError):c.structural_affine_predictions(report,"owner",record)

    def test_started_marker_is_exclusive_and_original_receipt_survives(self):
        with tempfile.TemporaryDirectory(prefix="symbiote-campaign-once-test-") as temp:
            path=Path(temp)/"campaign-started.json"
            c.write_new(path,dict(registration_sha256="first"))
            with self.assertRaises(FileExistsError):c.write_new(path,dict(registration_sha256="replacement"))
            self.assertEqual(c.load(path)["registration_sha256"],"first")

    def test_endurance_tls_math_receipts_must_equal_preserved_native_stdout(self):
        with tempfile.TemporaryDirectory(prefix="symbiote-campaign-wire-binding-") as temp:
            root=Path(temp)
            request=dict(scope="affine-context/v1",request_id="manual",body=dict(operation="knowledge.predict",artifact="manual-affine",input=0))
            response=dict(prediction=0,conditional=True,physical_certificate_authorized=False)
            c.write_new(root/"reply.stdout",response)
            (root/"reply.stderr").write_bytes(b"")
            native=dict(label="cycle-1-0-predict",success=True,exit_code=0,stdout="reply.stdout",stdout_sha256=c.sha(root/"reply.stdout"),stderr="reply.stderr",stderr_sha256=c.sha(root/"reply.stderr"))
            events=[dict(kind="native-command",data=native),
                    dict(kind="tls-request",data=dict(label=native["label"],request=request,explicit_duplicate=False)),
                    dict(kind="tls-response",data=dict(label=native["label"],response=response))]
            _,parsed,requests,responses=c.endurance_outputs(root,events)
            c.bound_tls_pair(parsed,requests,responses,native["label"],request,response)
            changed=copy.deepcopy(response);changed["prediction"]=1
            with self.assertRaises(RuntimeError):c.bound_tls_pair(parsed,requests,responses,native["label"],request,changed)
            altered=copy.deepcopy(events);altered[-1]["data"]["response"]=changed
            with self.assertRaises(RuntimeError):c.endurance_outputs(root,altered)
            with self.assertRaises(RuntimeError):c.endurance_outputs(root,events+[events[0]])
            with self.assertRaises(RuntimeError):c.endurance_outputs(root,events[:-1])
            changed_request=copy.deepcopy(request);changed_request["body"]["input"]=1
            with self.assertRaises(RuntimeError):c.bound_tls_pair(parsed,requests,responses,native["label"],changed_request,response)
            with self.assertRaises(RuntimeError):c.bound_tls_pair(parsed,requests,responses,native["label"],request,response,True)
            (root/"reply.stdout").write_text('{"prediction":1}',encoding="utf-8")
            with self.assertRaises(RuntimeError):c.endurance_outputs(root,events)

    def test_lost_reply_is_bound_to_actual_quarantine_body_owner_key_and_response(self):
        request=dict(schema="symbiote.service-request/1",scope="affine-context/v1",request_id="manual-lost",body=dict(operation="candidate.submit",offer=dict(inert="manual-fixture")))
        body=c.digest(request)
        candidate=c.digest(dict(authenticated_sender="client",canonical_body_sha256=body))
        response=dict(schema="symbiote.service-quarantine/1",status="QUARANTINED",candidate=candidate,promoted=False)
        row=dict(key=dict(peer_id="client",operation="candidate.submit",scope=request["scope"],request_id=request["request_id"]),
                 candidate_id=candidate,body_sha256=body,body=request,response=response)
        c.bound_quarantine(row,request,response,"client")
        for field in ("body","body_sha256","key","response","candidate_id"):
            changed=copy.deepcopy(row)
            if field=="body":changed[field]["request_id"]="other"
            elif field=="key":changed[field]["peer_id"]="other"
            elif field=="response":changed[field]["promoted"]=True
            else:changed[field]="0"*64
            with self.assertRaises(RuntimeError,msg=field):c.bound_quarantine(changed,request,response,"client")
        with self.assertRaises(RuntimeError):c.bound_quarantine(row,request,response,"foreign-owner")
        numeric=copy.deepcopy(response);numeric["promoted"]=0
        with self.assertRaises(RuntimeError):c.bound_quarantine(row,request,numeric,"client")

    def test_registration_rejects_non_temp_destination_before_creating_or_launching(self):
        destination=ROOT/"uncreated-campaign-registration-contract"
        self.assertFalse(destination.exists())
        with self.assertRaisesRegex(RuntimeError,"OS temporary"):
            c.register("missing-native","missing-cli","missing-service",destination,"a"*40)
        self.assertFalse(destination.exists())

    def test_activation_guard_classification_requires_exact_causal_error_and_exit(self):
        blocked=dict(success=False,exit_code=1)
        for changed,message,kind in ((True,c.POLICY_ACTIVATION_HOLD,"POLICY_CHANGE_HOLD"),(False,c.RESTORE_ACTIVATION_HOLD,"UNREVIEWED_RESTORE_HOLD")):
            for ending in ("\n","\r\n"):
                self.assertEqual(c.activation_guard_kind(blocked,b"",(message+ending).encode(),changed),kind)
            for error in (message,"prefix "+message+"\n",message+" extra\n",message+"\n\n",
                          "SYMBIOTE failure: unknown flag --restore\n","SYMBIOTE failure: cannot open configured service file\n",
                          "SYMBIOTE failure: service configuration does not match a prepared persistent identity\n",
                          (c.RESTORE_ACTIVATION_HOLD if changed else c.POLICY_ACTIVATION_HOLD)+"\n"):
                with self.assertRaises(RuntimeError):c.activation_guard_kind(blocked,b"",error.encode(),changed)
            for status,stdout in ((dict(success=True,exit_code=1),b""),(dict(success=False,exit_code=True),b""),
                                  (dict(success=False,exit_code=2),b""),(blocked,b"{}\n")):
                with self.assertRaises(RuntimeError):c.activation_guard_kind(status,stdout,(message+"\n").encode(),changed)

    def test_frozen_plan_has_one_host_and_no_research_cohort_entry_points(self):
        plan=c.plan_descriptor()
        self.assertEqual(plan["two_host_validation"],"OPEN_UNAVAILABLE")
        self.assertEqual(c.BOUNDS["root_launches"],96)
        self.assertEqual(c.BOUNDS["campaign_seconds"],600)
        for case in c.SERVICE_CASES+c.CLI_CASES:
            self.assertNotIn("cohort",case)
        sources=c.source_files(ROOT)
        self.assertIn("tools/stability_campaign.py",sources)
        self.assertIn(c.PROTOCOL_FILE,sources)


class NativeContractTests(unittest.TestCase):
    def test_actual_native_restored_owner_hits_policy_or_restore_guard_without_mutation(self):
        binary=Path(os.environ.get("SYMBIOTE_TEST_BINARY",ROOT/"target/debug"/("symbiote.exe" if os.name=="nt" else "symbiote")))
        if not binary.is_file():self.skipTest("build native candidate before running the actual contract calibration")
        for changed in (True,False):
            with self.subTest(policy_changed=changed),tempfile.TemporaryDirectory(prefix="symbiote-native-activation-guard-") as temp:
                root=Path(temp);old=root/"original";new=root/"restored"
                old.mkdir();new.mkdir()
                def command(label,*args,expected=0):
                    result=c.execute([binary,*args,"--json"],root,label,timeout=10)
                    c.check_exit(result,expected)
                    return result
                prepared=json.loads(c.output(command("prepare","prepare-service","--state",old/"owner"),root))
                owner=prepared["identity"]
                # These offline public-only operations need neither credentials
                # nor a listener. The CA bytes are nevertheless policy-pinned.
                ca=b"manual offline public CA placeholder\n"
                for directory in (old,new):(directory/"ca.pem").write_bytes(ca)
                manifest=dict(schema="symbiote.service-config/1",state=str(old/"owner") if changed else "owner",identity=owner,
                              certificate="missing.pem",private_key="missing.key",certificate_sha256="a"*64,ca_certificate="ca.pem",bind_address="127.0.0.1:30001",
                              peers=[dict(alias="partner",id="manual-peer",address="127.0.0.1:30002",server_name="manual.symbiote.test",certificate_sha256="b"*64,
                                          access=[dict(scope="manual/v1",operations=["knowledge.read"],artifacts=["*"])])],
                              contexts=[dict(scope="manual/v1",schema_fingerprint="c"*64,truth_fixture=None,truth_sha256=None)],
                              limits=dict(max_requests=8,max_connections=8,max_frame_bytes=4096,timeout_ms=100,lifetime_ms=1000,per_peer_requests=8,max_offers=1,max_offer_bytes=1024,model_work=1024))
                c.write_new(old/"service.json",manifest)
                command("register","peer-revoke","--config",old/"service.json","--peer","manual-peer","--reason","offline fixture registration")
                backup=json.loads(c.output(command("backup","backup-state","--state",old/"owner","--backup",root/"backup"),root))
                command("restore","restore-state","--backup",root/"backup","--manifest-sha256",backup["manifest_sha256"],"--state",new/"owner")
                following=copy.deepcopy(manifest)
                if changed:following["state"]=str(new/"owner")
                c.write_new(new/"service.json",following)
                old_digest=c.digest(dict(manifest=manifest,ca_sha256=c.sha(old/"ca.pem")))
                new_digest=c.digest(dict(manifest=following,ca_sha256=c.sha(new/"ca.pem")))
                self.assertEqual(old_digest!=new_digest,changed)
                _,history=c.operational_chain(new/"owner/operations.jsonl",owner)
                self.assertEqual(history[0]["payload"]["policy_digest"],old_digest)
                names=("ledger.jsonl","knowledge.jsonl","operations.jsonl","operations-owner.json")
                preserved={name:(new/"owner"/name).read_bytes() for name in names}
                blocked=command("activation","peer-revoke","--config",new/"service.json","--peer","manual-peer","--reason","must not mutate before review",expected=1)
                outcome=dict(success=False,exit_code=blocked["exit_code"])
                stdout=(root/blocked["stdout"]).read_bytes();stderr=(root/blocked["stderr"]).read_bytes()
                self.assertEqual(c.activation_guard_kind(outcome,stdout,stderr,changed),"POLICY_CHANGE_HOLD" if changed else "UNREVIEWED_RESTORE_HOLD")
                self.assertEqual(preserved,{name:(new/"owner"/name).read_bytes() for name in names})
                for label,args,exit_code in (("parser",["peers","--config",new/"service.json","--unknown-restore-flag"],2),
                                             ("credential",["peers","--config",new/"service.json"],1)):
                    failed=command(label,*args,expected=exit_code)
                    with self.assertRaises(RuntimeError):c.activation_guard_kind(dict(success=False,exit_code=failed["exit_code"]),(root/failed["stdout"]).read_bytes(),(root/failed["stderr"]).read_bytes(),changed)
                foreign=copy.deepcopy(following);foreign["identity"]="foreign-owner"
                c.write_new(new/"foreign.json",foreign)
                failed=command("foreign","peer-revoke","--config",new/"foreign.json","--peer","manual-peer","--reason","foreign owner rejected",expected=1)
                with self.assertRaises(RuntimeError):c.activation_guard_kind(dict(success=False,exit_code=failed["exit_code"]),(root/failed["stdout"]).read_bytes(),(root/failed["stderr"]).read_bytes(),changed)
                self.assertEqual(preserved,{name:(new/"owner"/name).read_bytes() for name in names})

    def test_actual_demo_prediction_fields_and_dead_lock_inspection_exit(self):
        binary=Path(os.environ.get("SYMBIOTE_TEST_BINARY",ROOT/"target/debug"/("symbiote.exe" if os.name=="nt" else "symbiote")))
        if not binary.is_file():self.skipTest("build native candidate before running the actual contract calibration")
        with tempfile.TemporaryDirectory(prefix="symbiote-campaign-native-contract-") as temp:
            root=Path(temp);state=root/"owner"
            version=c.execute([binary,"version","--json"],root,"version",timeout=10)
            c.check_exit(version)
            metadata=json.loads(c.output(version,root))
            self.assertEqual(metadata["name"],"SYMBIOTE")
            self.assertEqual(metadata["version"],"0.5.1")
            self.assertIsInstance(metadata["build_source_commit"],str)
            first=c.execute([binary,"demo","--state",state,"--receipts",root/"demo.json","--json"],root,"demo",timeout=30)
            c.check_exit(first)
            learned=json.loads(c.output(first,root))
            prediction=c.execute([binary,"predict","--state",state,"--json"],root,"predict",timeout=10)
            c.check_exit(prediction)
            actual=json.loads(c.output(prediction,root))
            c.genesis_predictions(actual,learned["identity"],{"alpha-table":1,"beta-table":1})
            self.assertEqual(set(c.prediction_revisions(actual)),{"alpha-table","beta-table"})
            _,raw=c.identity_chain(state/"ledger.jsonl")
            self.assertEqual(raw[0]["payload"]["identity"],learned["identity"])
            # The child was positively waited/reaped by execute. Only its PID
            # is written to our own temporary state; no process is killed here.
            (state/"writer.lock").write_text(f"process={prediction['pid']}\n")
            inspection=c.execute([binary,"inspect-state","--state",state,"--json"],root,"inspect",timeout=10)
            c.check_exit(inspection)
            report=json.loads(c.output(inspection,root))
            self.assertEqual(report["status"],"ATTENTION")
            self.assertEqual(next(lock for lock in report["locks"] if lock["name"]=="writer.lock")["process"],prediction["pid"])
            self.assertIn(next(lock for lock in report["locks"] if lock["name"]=="writer.lock")["state"],("dead","live"))
            # PID reuse may make this conservative liveness check live, but it
            # must never silently initialize/reset or remove that lock.
            self.assertTrue((state/"writer.lock").is_file())


if __name__=="__main__":unittest.main()
