"""Seal already closed public evidence; read-only artifact checks, no native/network."""
import hashlib,json,os,stat,time
from pathlib import Path
T=Path(os.environ['TEMP']).resolve(strict=True)
R=T/'pub112'
SOURCE='8aa5f4c6ab26f7ccad53935a70414ae1765b57c6'
def need(v,m):
    if not v: raise ValueError(m)
def digest(p):
    before=p.stat(); h=hashlib.sha256(); count=0
    with p.open('rb') as f:
        for b in iter(lambda:f.read(65536),b''): h.update(b);count+=len(b)
    after=p.stat();need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)and count==before.st_size,'file changed')
    return dict(bytes=count,sha256=h.hexdigest())
def write(p,v):
    with p.open('xb') as f:f.write(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()+b'\n')
def inventory():
    rows=[]
    for d,ds,fs in os.walk(R,followlinks=False):
        for name in ds+fs:
            p=Path(d)/name;s=p.lstat();need(not stat.S_ISLNK(s.st_mode)and not getattr(s,'st_file_attributes',0)&0x400,'linked corpus member')
            if p.is_file():rows.append(dict(path=p.relative_to(R).as_posix(),**digest(p)))
    return sorted(rows,key=lambda r:r['path'].encode())
copies=[];helpers=R/'helpers';helpers.mkdir()
for name in ['v112_public_artifact_fetch_40967471449.py','v112_public_artifact_stdin_40967471449.py','v112-public-fetch-first-run-binding.json','v112-public-fetch-first-run-binding.diff','public112-owned-download-closures.json','preserve_public112_metadata.py','seal_public112.py']:
    p=T/name;raw=p.read_bytes();before=digest(p);need(hashlib.sha256(raw).hexdigest()==before['sha256'],'copy changed')
    out=helpers/name
    with out.open('xb')as f:f.write(raw)
    need(digest(out)==before and digest(p)==before,'copy witness differs');copies.append(dict(original=str(p),selected=out.relative_to(R).as_posix(),**before))
write(R/'HELPER-COPY-CENSUS.json',dict(schema='symbiote.public-evidence-helper-copies/1',source_commit=SOURCE,copies=copies,raw_bytes_unchanged=True))
platforms=[]
for key in ['w','l','a','i']:
    root=R/key;receipt=root/'download.json';v=json.loads(receipt.read_bytes())
    need(v['status']=='PASS_API_DIGEST_BOUND_ARTIFACT_BYTES'and v['source_commit']==SOURCE and v['public_workflow_run_id']==40967471449,'download admission differs')
    need(digest(root/'artifact.zip')==dict(bytes=v['original_artifact_bytes'],sha256=v['original_artifact_sha256']),'API artifact differs')
    actual=[]
    for p in (root/'data').rglob('*'):
        if p.is_file():actual.append(dict(path=p.relative_to(root/'data').as_posix(),**digest(p)))
    need(sorted(actual,key=lambda r:r['path'].encode())==v['files'],'actual extraction differs')
    platforms.append(dict(key=key,artifact_id=v['artifact_id'],artifact_name=v['artifact_name'],api_zip_sha256=v['original_artifact_sha256'],api_zip_bytes=v['original_artifact_bytes'],download_receipt=digest(receipt),members=len(actual),extracted_bytes=sum(r['bytes']for r in actual),parent_report=key+'/data/public-acceptance.json',native_report=key+'/data/native/acceptance.json',embedding_report=key+'/data/embedding/embedding-acceptance.json'))
rows=inventory()
value=dict(schema='symbiote.closed-public-workflow-evidence/1',status='CLOSED_API_DIGEST_BOUND_PRESERVATION_ONLY',source_commit=SOURCE,version='v1.1.2',public_workflow_run_id=40967471449,attempt=1,release_id=428461777,publication_plan_sha256='e974dd7ecef3d2fc7356dfd090bdc32e086f00b4b51ae1efa7a823d474694b5d',platforms=platforms,files=rows,file_count=len(rows),total_bytes=sum(r['bytes']for r in rows),artifact_data_writers_stopped=True,temporary_download_urls_saved=False,native_executions_by_preserver=0,exclusions=[dict(path='CORPUS-MANIFEST.json',reason='self census is externally SHA pinned')],interpretation='Full original API ZIPs plus byte-exact safe extractions, official metadata and decoded connector logs are preserved; preservation alone does not grant public/stable release approval.')
need(inventory()==rows,'corpus changed before seal')
write(R/'CORPUS-MANIFEST.json',value)
print(json.dumps(dict(status=value['status'],manifest=str(R/'CORPUS-MANIFEST.json'),**digest(R/'CORPUS-MANIFEST.json'),file_count=len(rows),total_bytes=value['total_bytes'],platforms=platforms)))
