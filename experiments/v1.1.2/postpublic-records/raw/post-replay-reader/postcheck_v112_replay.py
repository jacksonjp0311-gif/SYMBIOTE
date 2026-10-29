"""Full byte census after data-only replay; original inputs are never opened."""
from pathlib import Path
import os,json,hashlib,stat
p=Path(os.environ['TEMP']);root=p/'vz112/zip-extracted/corpus';zip_path=p/'vz112/EVIDENCE.zip';MF='daafc48c29ffad69a9d0ec76209e523757d6446a4b7939b18a72d9fd25f6d069';ZIP='07d2ea383c4dc2ac9fd34b95d5db4915edfab5151c9b921cff1f707dfd5d513a'
def sha(f):
 h=hashlib.sha256();a=f.stat()
 with f.open('rb')as s:
  while True:
   b=s.read(1048576)
   if not b:break
   h.update(b)
 z=f.stat();assert(a.st_size,a.st_mtime_ns,a.st_ino)==(z.st_size,z.st_mtime_ns,z.st_ino);return h.hexdigest()
assert sha(root/'MANIFEST.json')==MF;v=json.loads((root/'MANIFEST.json').read_bytes());wanted={'MANIFEST.json':(root/'MANIFEST.json').stat().st_size};rows=[]
for e in v['entries']:
 f=root/e['path'];assert f.is_file()and not f.is_symlink()and f.stat().st_size==e['bytes']and sha(f)==e['sha256'];wanted[e['path']]=e['bytes'];rows.append(dict(path=e['path'],bytes=e['bytes'],sha256=e['sha256']))
actual={f.relative_to(root).as_posix():f.stat().st_size for f in root.rglob('*')if f.is_file()};assert actual==wanted;assert sha(zip_path)==ZIP
replay=json.loads((p/'vr112/replay-receipt.json').read_bytes());assert replay['status']=='PASS_ARCHIVED_HOUR_AND_E3_DATA_REPLAY'and replay['original_host_read_attempts']==[]and replay['native_executions']==replay['subprocesses']==replay['network_calls']==0
result=dict(schema='symbiote.v112-post-replay-byte-guard/1',status='PASS_ALL_ARCHIVED_BYTES_UNCHANGED',source_commit=v['source_commit'],zip_sha256=ZIP,zip_bytes=zip_path.stat().st_size,manifest_sha256=MF,members_including_manifest=len(actual),total_bytes=sum(actual.values()),entry_census_sha256=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest(),replay_receipt_sha256=sha(p/'vr112/replay-receipt.json'),mapper_source_sha256='5c70f914eb6f26cd89414aa1aacccf215ea1866e6430f81e41836a063546a845',native_executions=0,original_host_roots_read=False,reader_sha256=sha(Path(__file__)))
with(p/'vr112/post-replay-recheck.json').open('xb')as f:f.write((json.dumps(result,indent=2)+'\n').encode())
print(json.dumps(dict(status=result['status'],receipt_sha256=sha(p/'vr112/post-replay-recheck.json'),members=len(actual),total_bytes=result['total_bytes'])))
