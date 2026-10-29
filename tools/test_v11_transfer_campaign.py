"""Offline preregistration/barrier/measurement rejection fixtures, no targets."""
import copy
import ctypes
import hashlib
import io
import importlib.util
import marshal
import json
import os
import struct
import sys
from pathlib import Path
import tempfile
import time
import types
import unittest
from unittest import mock

import v11_transfer_campaign as campaign


def fixture_spec():
    cases = []
    for index in range(2):
        case = {}
        for role in ("a", "b"):
            raw = hashlib.sha256(f"{campaign.PROTOCOL}/case/{index}/{role}".encode()).digest()
            case[role] = dict(mask=1+raw[0] % 255, bias=raw[1] & 1)
        cases.append(case)
    return dict(schema="symbiote.v11-transfer-spec/1", protocol=campaign.PROTOCOL, cases=cases, width=8,
                fresh_inputs=32, horizons=[1, 16, 32], query_policy="rank-basis-min/v1", max_queries_per_source=16,
                max_gf2_per_episode=1_000_000, bounds=dict(seconds=600, evidence_bytes=134217728))


class TransferContractTests(unittest.TestCase):
    def test_task_bounds_seed_and_policy_cannot_silently_change(self):
        original = fixture_spec(); campaign.spec_check(original)
        for field, value in (("fresh_inputs", 16), ("width", 7), ("horizons", [1, 32]), ("max_queries_per_source", 32),
                             ("query_policy", "finite-domain-scan/v1"), ("bounds", dict(seconds=601, evidence_bytes=134217728))):
            altered = copy.deepcopy(original); altered[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): campaign.spec_check(altered)
        altered = copy.deepcopy(original); altered["cases"][0]["a"]["mask"] ^= 1
        with self.assertRaisesRegex(ValueError, "deterministic pair"): campaign.spec_check(altered)

    def test_revealed_inputs_are_deterministic_unique_disjoint(self):
        observed = {0, 1, 2, 4, 8, 16, 32, 64, 128, 3}
        first = campaign.fresh_inputs(99, observed)
        self.assertEqual(first, campaign.fresh_inputs(99, observed))
        self.assertEqual(len(set(first)), 32)
        self.assertFalse(observed.intersection(first))
        with self.assertRaisesRegex(ValueError, "not enough"): campaign.fresh_inputs(99, set(range(256)))

    def test_external_grader_derives_labels_and_preserves_cache_abstention(self):
        inputs = list(range(32, 64)); wiring = dict(mask=199, bias=1)
        predictions = [dict(input=value, answer=((value & 199).bit_count() % 2) ^ 1) for value in inputs]
        grades = campaign.grade_predictions(inputs, predictions, wiring)
        self.assertEqual([row["correct"] for row in grades], [1, 16, 32])
        self.assertEqual(campaign.grade_predictions(inputs, [dict(input=value, answer=None) for value in inputs], wiring)[-1],
                         dict(horizon=32, correct=0, abstentions=32))
        altered = copy.deepcopy(predictions); altered[0]["answer"] ^= 1
        self.assertEqual(campaign.grade_predictions(inputs, altered, wiring)[0]["correct"], 0)
        for altered in (predictions[:-1], list(reversed(predictions)), [dict(row, answer=False) for row in predictions]):
            with self.subTest(altered=altered), self.assertRaises(ValueError): campaign.grade_predictions(inputs, altered, wiring)

    def test_swapped_artifact_knowledge_mutation_and_fabricated_zero_rejected(self):
        freeze = dict(arm="transfer", artifacts=[dict(record_sha256="a"*64), dict(record_sha256="b"*64)],
                      inspections=[dict(knowledge="anchor-a"), dict(knowledge="anchor-b")], acquisition=dict(received=[{}, {}]))
        report = dict(status="PREDICTIONS_COMMITTED", source_calls=0, source_contact_attempts=0,
                      learning_during_evaluation=False, labels_received=False,
                      predictions=[[dict(record_sha256="a"*64)], [dict(record_sha256="b"*64)]],
                      before=[dict(knowledge="anchor-a"), dict(knowledge="anchor-b")],
                      after=[dict(knowledge="anchor-a"), dict(knowledge="anchor-b")])
        campaign.prediction_binding(report, freeze)
        variants=[]
        row=copy.deepcopy(report);row["predictions"][0][0]["record_sha256"]="b"*64;variants.append(row)
        row=copy.deepcopy(report);row["after"][0]["knowledge"]="changed";variants.append(row)
        row=copy.deepcopy(report);row["source_contact_attempts"]=1;variants.append(row)
        row=copy.deepcopy(report);row["source_calls"]=False;variants.append(row)
        for altered in variants:
            with self.subTest(altered=altered), self.assertRaises(ValueError): campaign.prediction_binding(altered, freeze)

    def test_worker_cannot_open_targets_without_outer_once_only_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); registration=root/"registration.json"
            campaign.write(registration,dict(artifacts=str(root)))
            campaign.write(root/"EXECUTION-STARTED.json",dict(registration_sha256=campaign.sha(registration),admission_sha256="a"*64))
            args=types.SimpleNamespace(registration=registration,registration_sha256=campaign.sha(registration))
            with mock.patch.object(campaign,"validate"),mock.patch.dict(os.environ,{"SYMBIOTE_V11_TRANSFER_ADMISSION":""}), \
                    mock.patch.object(campaign,"one_case",side_effect=AssertionError("target must stay closed")), \
                    self.assertRaisesRegex(ValueError,"once-only admission"):
                campaign.worker(args)
            self.assertFalse((root/"cases").exists())

    def test_existing_execution_marker_prevents_retry_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();registration=root/"registration.json"
            campaign.write(registration,dict(artifacts=str(root)))
            marker=root/"EXECUTION-STARTED.json";marker.write_bytes(b"preserved original failure\n")
            args=types.SimpleNamespace(registration=registration,registration_sha256=campaign.sha(registration))
            with mock.patch.object(campaign,"validate"),mock.patch.object(campaign.safety,"execute",side_effect=AssertionError("no repeat")), \
                    self.assertRaises(FileExistsError):campaign.run(args)
            self.assertEqual(marker.read_bytes(),b"preserved original failure\n")

    def test_peak_measurement_uses_owned_job_commit_units_and_closes_on_failure(self):
        class Accounting(ctypes.Structure):
            _fields_=[("user",ctypes.c_longlong),("kernel",ctypes.c_longlong)]
        class Kernel:
            def QueryInformationJobObject(self,handle,kind,pointer,size,unused):
                if kind==9:pointer._obj.peak_process=111;pointer._obj.peak_job=222
                elif kind==8:pointer._obj.basic.user=333;pointer._obj.basic.kernel=444;pointer._obj.io.read_bytes=555
                else:raise AssertionError("actual CPU/I/O must use accounting class8")
                return 1
        class Job:
            def __init__(self):self.handle=123;self.attached=True;self.kernel=Kernel();self.accounting=Accounting
            def close(self):self.handle=None
        observations=[]
        with mock.patch.object(campaign.safety,"WindowsJob",Job):
            selected=campaign.measured_job_class(observations)();selected.close()
        self.assertIsNone(selected.handle)
        self.assertEqual(observations[0]["peak_job_bytes"],222)
        self.assertEqual(observations[0]["cpu_user_100ns"],333)
        self.assertEqual(observations[0]["io"]["read_bytes"],555)
        self.assertEqual(observations[0]["io_information_class"],8)
        self.assertEqual(observations[0]["kind"],"windows-job-peak-committed-bytes-not-RSS")
        with mock.patch.object(campaign.safety,"WindowsJob",Job):
            selected=campaign.measured_job_class([])()
            selected.kernel.QueryInformationJobObject=lambda *_:0
            with self.assertRaisesRegex(ValueError,"peak-memory query failed"):selected.close()
            self.assertIsNone(selected.handle)

    def test_interruption_kills_only_owned_child_after_exact_prediction_commit(self):
        class Child:
            pid=777
            def __init__(self):self.returncode=None;self.stdout=io.BytesIO(b"native fixture stream\n");self.stderr=io.BytesIO(b"");self.killed=False
            def poll(self):return self.returncode
            def kill(self):self.killed=True;self.returncode=-9
            def wait(self,timeout=None):return self.returncode
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();prediction=root/"predictions.json";prediction.write_bytes(b'{"actual":"commit"}\n')
            for role in ("a","b"):
                owner=root/"state"/role;owner.mkdir(parents=True)
                for name in ("writer.lock","knowledge.writer.lock"):(owner/name).write_bytes(b"process=777\nnonce=synthetic\n")
            marker=prediction.with_name(prediction.name+".interruption-ready.json")
            campaign.write(marker,dict(schema="symbiote.transfer-interruption-ready/1",pid=777,prediction_receipt_sha256=campaign.sha(prediction)))
            child=Child()
            with mock.patch.object(campaign.subprocess,"Popen",return_value=child):
                receipt=campaign.phase_call(["synthetic-not-executed"],root,"owned-interruption",time.monotonic()+3,interrupt_after=prediction)
            self.assertTrue(child.killed)
            self.assertTrue(receipt["interrupted_after_commit"])
            self.assertTrue(receipt["cleanup_verified"])
            self.assertEqual(receipt["exit_code"],-9)
            self.assertEqual(receipt["pid"],777)
            self.assertEqual(len(receipt["observed_owner_lock_bindings"]),4)
            marker.unlink();campaign.write(marker,dict(schema="symbiote.transfer-interruption-ready/1",pid=999,prediction_receipt_sha256=campaign.sha(prediction)))
            child=Child()
            with mock.patch.object(campaign.subprocess,"Popen",return_value=child),self.assertRaisesRegex(ValueError,"native phase failed"):
                campaign.phase_call(["synthetic-not-executed"],root,"foreign-marker",time.monotonic()+3,interrupt_after=prediction)
            failed=campaign.load(root/"foreign-marker.process.json")
            self.assertEqual(failed["outcome"],"HOLD")
            self.assertFalse(failed["interrupted_after_commit"])
            self.assertEqual(failed["pid"],777)
            self.assertIn("interruption binding",failed["failure"])

    def test_launch_error_preserves_empty_streams_and_hold_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            with mock.patch.object(campaign.subprocess,"Popen",side_effect=OSError("unit fixture launch unavailable")), \
                    self.assertRaisesRegex(ValueError,"native phase failed"):
                campaign.phase_call(["synthetic-not-executed"],root,"failed-launch",time.monotonic()+3)
            receipt=campaign.load(root/"failed-launch.process.json")
            self.assertEqual(receipt["outcome"],"HOLD")
            self.assertIsNone(receipt["pid"])
            self.assertIn("launch unavailable",receipt["failure"])

    def test_helper_bytecache_cannot_substitute_unpinned_python(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();tools=root/"tools";tools.mkdir();source=tools/"fixture.py"
            source.write_bytes(b"value = 'checked source'\n");details=source.stat()
            cached=Path(importlib.util.cache_from_source(str(source)));cached.parent.mkdir()
            raw=(importlib.util.MAGIC_NUMBER+struct.pack("<III",0,int(details.st_mtime),details.st_size)
                 +marshal.dumps(compile("raise RuntimeError('POISONED_BYTECODE_EXECUTED')",str(source),"exec")))
            cached.write_bytes(raw);before=dict(campaign.LOADED_HELPERS);old=sys.modules.get("fixture")
            try:
                with mock.patch.object(campaign,"ROOT",root):selected=campaign.source_module("fixture")
                self.assertEqual(selected.value,"checked source")
                self.assertEqual(cached.read_bytes(),raw)
                self.assertEqual(campaign.LOADED_HELPERS["fixture"],hashlib.sha256(source.read_bytes()).hexdigest())
            finally:
                campaign.LOADED_HELPERS.clear();campaign.LOADED_HELPERS.update(before)
                if old is None:sys.modules.pop("fixture",None)
                else:sys.modules["fixture"]=old


if __name__ == "__main__":unittest.main()
