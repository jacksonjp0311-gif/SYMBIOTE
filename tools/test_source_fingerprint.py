import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
import source_fingerprint as source


class SourceManifestTests(unittest.TestCase):
    def test_input_order_case_and_unicode_names_preserve_exact_framed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            values={'Z.rs':b'first\n','a.rs':b'second\r\n','café.rs':b'\x00exact|bytes'}
            for name,data in values.items():
                (root/name).write_bytes(data)
            result=source.manifest(root,list(reversed(values)))
            self.assertEqual([row['path'] for row in result['files']],['Z.rs','a.rs','café.rs'])
            for row in result['files']:
                self.assertEqual(row['sha256'],hashlib.sha256(values[row['path']]).hexdigest())
            self.assertEqual(result,source.manifest(root,list(values)))
            source.verify(root,result)
            (root/'a.rs').write_bytes(b'second\n')
            with self.assertRaises(ValueError): source.verify(root,result)

    def test_source_path_set_digest_and_metadata_tampering_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'one.rs').write_bytes(b'one')
            result=source.manifest(root,['one.rs'])
            for field,value in [('sha256','0'*64),('total_bytes',0),('schema','symbiote.software-verification/1')]:
                altered=copy.deepcopy(result);altered[field]=value
                with self.assertRaises(ValueError): source.verify(root,altered)
            for names in [['one.rs','one.rs'],['../one.rs'],['/one.rs'],['C:/one.rs'],['./one.rs'],['one.rs/../one.rs'],['one.rs','ONE.rs']]:
                with self.assertRaises((ValueError,FileNotFoundError)): source.manifest(root,names)

    def test_whole_source_tree_verification_detects_new_operational_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ['Cargo.toml','Cargo.lock','SYMBIOTE-All-One.ps1']:
                (root/name).write_bytes(b'fixture')
            (root/'tools').mkdir()
            saved=source.manifest(root)
            (root/'tools/new_runtime_plugin.py').write_bytes(b'changed operational source')
            with self.assertRaises(ValueError): source.verify(root,saved)


if __name__=='__main__': unittest.main()
