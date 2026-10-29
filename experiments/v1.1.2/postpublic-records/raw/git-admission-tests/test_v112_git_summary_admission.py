"""Owned tiny fixtures only; no archive, original corpus, native or Git process."""
from pathlib import Path
import hashlib,json,os,tempfile,types,unittest
from unittest import mock
HERE=Path(__file__).parent
wrapper=types.ModuleType('git_admission_fixture');wrapper.__file__=str(HERE/'v112_git_summary_admission.py');exec(compile(Path(wrapper.__file__).read_bytes(),wrapper.__file__,'exec'),wrapper.__dict__)
raw=wrapper.ADAPTER.read_bytes();assert hashlib.sha256(raw).hexdigest()==wrapper.ADAPTER_PIN
adapter=types.ModuleType('frozen_adapter_fixture');adapter.__file__=str(wrapper.ADAPTER);exec(compile(raw,str(wrapper.ADAPTER),'exec'),adapter.__dict__);base=adapter.base
class ExactGitSummary(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='v112-git-format-fixture-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.f=self.root/'8.stdout';self.f.write_bytes(wrapper.LITERAL)
    def fingerprint(self):return wrapper.git_fingerprint(base,self.f,self.f)
    def docs(self):return dict(source_commit=wrapper.SOURCE,status='PASS_BYTE_SELECTION_ONLY',payloads=[dict(path='p/02469/8.stdout',sha256=wrapper.PIN,bytes=177,origins=[dict(source='proofs',path='source-freeze/8.stdout')])]),dict(files=[dict(path='source-freeze/8.stdout',sha256=wrapper.PIN,bytes=177,original_source_commit=wrapper.SOURCE,original_path=str(Path(os.environ['TEMP'])/'v112-freeze-001/8.stdout'))])
    def test_exact_literal_and_origin_allowed(self):
        before=self.f.read_bytes();self.assertEqual(self.fingerprint()['sha256'],wrapper.PIN);wrapper.origin_documents(*self.docs());self.assertEqual(self.f.read_bytes(),before)
    def test_wrong_path_denied(self):
        with self.assertRaises(ValueError):wrapper.git_fingerprint(base,self.f,self.root/'other.stdout')
    def test_changed_same_length_pin_denied(self):
        self.f.write_bytes(wrapper.LITERAL.replace(b'475',b'476'))
        with self.assertRaises(ValueError):self.fingerprint()
    def test_missing_or_extra_bytes_denied(self):
        for raw in[wrapper.LITERAL[:-1],wrapper.LITERAL+b'\n']:
            self.f.write_bytes(raw)
            with self.assertRaises(ValueError):self.fingerprint()
    def test_crlf_normalization_not_admitted(self):
        self.f.write_bytes(wrapper.LITERAL.replace(b'\n',b'\r\n'))
        with self.assertRaises(ValueError):self.fingerprint()
    def test_unclassified_json_heuristic_still_rejects_git_text(self):
        other=self.root/'unregistered.stdout';other.write_bytes(wrapper.LITERAL)
        with self.assertRaises(json.JSONDecodeError):wrapper.dispatch(base,adapter.ORIGINAL_FINGERPRINT,other,self.f)
    def test_other_json_keeps_original_fingerprint(self):
        other=self.root/'other.json';other.write_bytes(b'{"status":"HOLD"}\n');self.assertEqual(wrapper.dispatch(base,adapter.ORIGINAL_FINGERPRINT,other,self.f),adapter.ORIGINAL_FINGERPRINT(other))
    def test_raw_credential_rejection_is_never_swallowed(self):
        with mock.patch.object(base,'scan_bytes',side_effect=ValueError('raw credential rejected')):
            with self.assertRaisesRegex(ValueError,'raw credential'):self.fingerprint()
    def test_decoded_credential_rejection_is_never_swallowed(self):
        with mock.patch.object(base,'scan_json',side_effect=ValueError('decoded credential rejected')):
            with self.assertRaisesRegex(ValueError,'decoded credential'):self.fingerprint()
    def test_whole_raw_and_all_decoded_lines_are_scanned(self):
        with mock.patch.object(base,'scan_bytes',wraps=base.scan_bytes)as raw_scan,mock.patch.object(base,'scan_json',wraps=base.scan_json)as decoded:
            self.fingerprint();self.assertTrue(any(x.args[0]==wrapper.LITERAL for x in raw_scan.call_args_list));values=[x.args[0]for x in decoded.call_args_list];self.assertIn(wrapper.LITERAL.decode(),values)
            for line in wrapper.LITERAL.decode().splitlines():self.assertIn(line,values)
    def test_late_mutation_denied(self):
        original=base.scan_json;changed=[False]
        def mutate(*args,**kwargs):
            result=original(*args,**kwargs)
            if not changed[0]:changed[0]=True;self.f.write_bytes(wrapper.LITERAL+b'x')
            return result
        with mock.patch.object(base,'scan_json',side_effect=mutate):
            with self.assertRaisesRegex(ValueError,'changed'):self.fingerprint()
    def test_wrong_logical_origin_or_original_source_denied(self):
        for field,value in[('bytes',178),('sha256','0'*64),('original_source_commit','0'*40),('original_path',str(self.root/'elsewhere'))]:
            a,b=self.docs();b['files'][0][field]=value
            with self.assertRaises(ValueError):wrapper.origin_documents(a,b)
        a,b=self.docs();a['payloads'][0]['origins'][0]['path']='other/8.stdout'
        with self.assertRaises(ValueError):wrapper.origin_documents(a,b)
if __name__=='__main__':unittest.main()
