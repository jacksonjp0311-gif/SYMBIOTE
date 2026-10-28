"""Disposable byte-only relocation tests; synthetic executable bytes never run."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('portable',HERE/'portable_evidence_replay.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
TOOLS=HERE.parent
CONSUMER_SHA='40b4e51e3d08aab461dec395d47983f9faa0ff758a233ebc397eb141f5ed4a54'


class PortableContracts(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='portable-unit-');self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();(self.root/'normal/executables').mkdir(parents=True);(self.root/'tools').mkdir()
        self.native=self.root/'normal/executables/symbiote.exe';self.native.write_bytes(b'MZ synthetic native; never executed\0-----BEGIN PRIVATE KEY-----')
        self.tests=self.root/'normal/executables/service-tests.exe';self.tests.write_bytes(b'MZ synthetic test; never executed')
        self.nsha=p.sha(self.native);self.tsha=p.sha(self.tests)
        self.raw=dict(schema='symbiote.partial-graph-native-artifacts/1',private_keys_copied=False,
            native_binary=r'C:\old\study\executables\symbiote.exe',native_binary_sha256=self.nsha,
            service_tests=r'C:\old\study\executables\service-tests.exe',service_tests_sha256=self.tsha,
            files=[dict(path='executables/'+path.name,bytes=path.stat().st_size,sha256=p.sha(path)) for path in (self.native,self.tests)],report={})
        self.dump('normal/artifact-manifest.json',self.raw)
        self.dump('build.json',dict(schema='synthetic-build/1',source_commit='a'*40,native_sha=self.nsha,test_sha=self.tsha))
        for name in p.MODULES:(self.root/'tools'/f'{name}.py').write_bytes((TOOLS/f'{name}.py').read_bytes())
        self.manifest=dict(schema='symbiote.v1-evidence-manifest/2',source_commit='a'*40,
            collections=[dict(name='normal',path=r'C:\old\study',archive_prefix='normal')],
            anchors=[dict(id='build',path=r'C:\old\build.json',sha256=p.sha(self.root/'build.json'),expect=[dict(pointer='/schema',value='synthetic-build/1')],source_commit_pointer='/source_commit',source_commit='a'*40)],
            registered_executables=[dict(role=role,archive_path='normal/executables/'+path.name,sha256=pin,anchor='build',digest_pointer=pointer)
                for role,path,pin,pointer in [('final-build-native',self.native,self.nsha,'/native_sha'),('final-build-service-tests',self.tests,self.tsha,'/test_sha')]],entries=[])
        self.reseal()

    def dump(self,name,value):
        (self.root/name).write_text(json.dumps(value),encoding='utf-8')

    def reseal(self):
        rows=[]
        for path in sorted(self.root.rglob('*')):
            if not path.is_file() or path.name=='MANIFEST.json':continue
            relative=path.relative_to(self.root).as_posix()
            if relative.startswith('normal/'):origin='C:\\old\\study\\'+relative.removeprefix('normal/').replace('/','\\')
            elif relative=='build.json':origin=r'C:\old\build.json'
            else:origin='C:\\old\\'+relative.replace('/','\\')
            rows.append(dict(path=relative,bytes=path.stat().st_size,sha256=p.sha(path),sources=[origin]))
        self.manifest['entries']=rows;self.dump('MANIFEST.json',self.manifest);self.pin=p.sha(self.root/'MANIFEST.json')

    def verify(self):
        archive=p.Archive(self.root,self.pin);native=archive.binding('final-build-native');tests=archive.binding('final-build-service-tests')
        with p.consumers(archive,'tools',CONSUMER_SHA,native,tests) as (r,_):
            return r.verify_manifest(self.root/'normal',r'C:\old\target\symbiote.exe',self.nsha,
                                     dict(path=r'C:\old\target\service.exe',sha256=self.tsha))

    def test_raw_absolute_claims_replay_without_any_original_host_file_read(self):
        old_open=Path.open;attempts=[]
        def guarded(path,*args,**kwargs):
            if str(path).lower().startswith('c:\\old'):
                attempts.append(str(path));raise AssertionError('original host path read')
            return old_open(path,*args,**kwargs)
        before=(self.root/'normal/artifact-manifest.json').read_bytes()
        with mock.patch.object(Path,'open',autospec=True,side_effect=guarded):self.verify()
        self.assertEqual(attempts,[]);self.assertEqual((self.root/'normal/artifact-manifest.json').read_bytes(),before)
        self.assertFalse(any(path.name=='__pycache__' for path in self.root.rglob('*')))

    def test_escaped_role_is_rejected_even_after_manifest_and_member_hashes_are_recomputed(self):
        self.raw['native_binary']=r'C:\old\study\executables\..\..\outside.exe'
        self.dump('normal/artifact-manifest.json',self.raw);self.reseal()
        with self.assertRaisesRegex(RuntimeError,'escaped original'):self.verify()

    def test_changed_role_sha_cannot_override_the_independent_build_pin(self):
        self.raw['native_binary_sha256']='f'*64;self.dump('normal/artifact-manifest.json',self.raw);self.reseal()
        with self.assertRaises(RuntimeError):self.verify()

    def test_missing_snapshot_from_original_raw_census_is_not_healed_by_archive_membership(self):
        self.raw['files'].pop();self.dump('normal/artifact-manifest.json',self.raw);self.reseal()
        with self.assertRaisesRegex(RuntimeError,'file census'):self.verify()

    def test_same_hash_at_an_unmapped_original_path_is_never_a_fallback(self):
        self.raw['native_binary']=r'C:\old\target\symbiote.exe';self.dump('normal/artifact-manifest.json',self.raw);self.reseal()
        with self.assertRaisesRegex(RuntimeError,'not selected'):self.verify()

    def test_unlisted_local_file_and_wrong_external_manifest_pin_fail_closed(self):
        with self.assertRaisesRegex(RuntimeError,'external pin'):p.Archive(self.root,'0'*64)
        (self.root/'unlisted.txt').write_bytes(b'not selected')
        with self.assertRaisesRegex(RuntimeError,'census differs'):p.Archive(self.root,self.pin)

    def test_timestamp_valid_unpinned_bytecode_never_executes_instead_of_pinned_source(self):
        import importlib._bootstrap_external
        source=self.root/'tools/source_fingerprint.py';source_pin=p.sha(source)
        cache=Path(importlib.util.cache_from_source(str(source)));cache.parent.mkdir()
        code=compile("raise RuntimeError('UNPINNED_BYTECODE_EXECUTED')",str(source),'exec')
        payload=importlib._bootstrap_external._code_to_timestamp_pyc(code,int(source.stat().st_mtime),source.stat().st_size)
        cache.write_bytes(payload);self.reseal()
        self.verify()
        self.assertEqual(p.sha(source),source_pin)
        self.assertEqual(cache.read_bytes(),payload)

    def test_wrong_consumer_source_is_not_executed_even_with_resealed_archive(self):
        (self.root/'tools/reciprocal_engineering.py').write_bytes(b'raise AssertionError("must never execute")')
        self.reseal()
        with self.assertRaisesRegex(RuntimeError,'consumer source pin differs'):self.verify()


if __name__=='__main__':
    if '--tools' in sys.argv:
        index=sys.argv.index('--tools');TOOLS=Path(sys.argv[index+1]);del sys.argv[index:index+2]
    unittest.main()
