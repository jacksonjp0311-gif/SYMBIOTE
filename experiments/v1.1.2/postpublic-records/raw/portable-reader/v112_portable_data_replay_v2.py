"""Data-only archived112 hour/E3 replay; original source/evidence paths denied."""
import argparse,builtins,hashlib,io,json,os,re,socket,subprocess,sys,types
from pathlib import Path
sys.dont_write_bytecode=True
SOURCE='8aa5f4c6ab26f7ccad53935a70414ae1765b57c6';MF=None;SELECTION='df529992e1b0e08619701c1514f01aee813ca42b64d79b01895807bf3708f261';SELECTOR='9b529e5cc1db05fd381cf8480b0ff8892b064e2353acaa88533e23a23447fe11'
def need(v,m):
 if not v:raise ValueError(m)
def digest(b):return hashlib.sha256(b).hexdigest()
def file_sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb')as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def write(p,v):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('xb')as f:f.write((json.dumps(v,sort_keys=True,indent=2)+'\n').encode())
def main():
 a=argparse.ArgumentParser();a.add_argument('--zip',type=Path,required=True);a.add_argument('--zip-sha256',required=True);a.add_argument('--corpus',type=Path,required=True);a.add_argument('--export',dest='exported',type=Path,required=True);a.add_argument('--out',type=Path,required=True);a.add_argument('--manifest-sha256',required=True);args=a.parse_args();out=args.out;MF=args.manifest_sha256;need(re.fullmatch(r'[0-9a-f]{64}',MF)and MF!='0'*64,'actual external qualified manifest pin required')
 need(not out.exists(),'fresh outside-corpus replay root');out.mkdir();corpus=args.corpus;exported=args.exported
 need(file_sha(corpus/'MANIFEST.json')==MF and file_sha(exported/'selection.json')==SELECTION,'external manifest/selection pins')
 selection=json.loads((exported/'selection.json').read_bytes());need(selection['source_commit']==SOURCE,'exact112 source context');mapping={(o['source'],o['path']):r for r in selection['payloads']for o in r['origins']}
 def member(source,name):
  r=mapping[source,name];path=exported/r['path'];need(file_sha(path)==r['sha256']and path.stat().st_size==r['bytes'],'archived payload pin differs');return path
 consolidation=json.loads(member('proofs','COPY-CENSUS.json').read_bytes());need(file_sha(member('proofs','COPY-CENSUS.json'))=='ad03f45cf2556e255dfe95222c78d2b670d4c08b37a333ad666530d1226c3def','closed explicit proof copy census')
 primary_copies=json.loads(member('build-primary','COPY-CENSUS.json').read_bytes())
 proof_paths={'source-equivalence':'source-independent/source-equivalence.json','build-independent':'loose/v112-build-independent-8aa.json','e3-reader':'loose/v112-e3-cost-audit-repro-8aa.py','hour-reader':'hour-independent/audit_hour.py','source-tools/stability_campaign.py':'source-snapshots/tools/stability_campaign.py','source-tools/soak_campaign.py':'source-snapshots/tools/soak_campaign.py'}
 def proof(label,relative=None):return member('proofs',proof_paths[label])
 denied=[Path(s['path'])for s in selection['sources']]+[Path(r['original_path'])for r in consolidation['files']]+[Path(r['original_path'])for r in primary_copies['files']]
 temp=Path(os.environ['TEMP']);denied += [temp/'vx112',temp/'ve112',temp/'ve112b',temp/'vt112b',temp/'vo112b',temp/'v1z69',temp/'v1x69',temp/'v1e69',temp/'public-failed111',temp/'v11-e3-primary-b46',temp/'v11-build-b46ec34',temp/'v111-e3-repro-69d',temp/'v111-build-69d0bdf',Path(r'C:\Users\jacks\Documents\Codex\2026-10-26\codex-master-directive-symbiote-symbiotic-adaptive')]
 def lexical(p):return os.path.normcase(os.path.abspath(os.fsdecode(os.fspath(p))))
 boundaries=[lexical(p)for p in denied];attempted=[];count=[0];process_attempts=[]
 def check(p):
  if isinstance(p,int):return
  v=lexical(p)
  if any(v==b or v.startswith(b+os.sep)for b in boundaries):attempted.append(v);raise PermissionError('original host evidence/source access denied')
  count[0]+=1
 def prohibited(*x,**y):process_attempts.append('process-or-network');raise RuntimeError('data-only replay prohibited process/network')
 old_io,old_builtin,old_scan,old_stat,old_lstat,old_osopen=io.open,builtins.open,os.scandir,os.stat,os.lstat,os.open
 saved=subprocess.run,subprocess.Popen,socket.socket,os.system
 def guarded_io(p,mode='r',*x,**y):
  if 'r'in mode or '+'in mode:check(p)
  return old_io(p,mode,*x,**y)
 def guarded_builtin(p,mode='r',*x,**y):
  if 'r'in mode or '+'in mode:check(p)
  return old_builtin(p,mode,*x,**y)
 def guarded_scan(p='.'):check(p);return old_scan(p)
 def guarded_stat(p,*x,**y):check(p);return old_stat(p,*x,**y)
 def guarded_lstat(p,*x,**y):check(p);return old_lstat(p,*x,**y)
 def guarded_osopen(p,flags,*x,**y):check(p);return old_osopen(p,flags,*x,**y)
 def copy_selected(source,expected,target):
  raw=source.read_bytes();need(digest(raw)==expected,'archived reader/control exact SHA');target.parent.mkdir(parents=True,exist_ok=True)
  with target.open('xb')as f:f.write(raw)
  return target
 def rawmodule(path,pin,name):
  raw=path.read_bytes();need(digest(raw)==pin,'archived reader source pin');m=types.ModuleType(name);m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__);return m
 io.open=guarded_io;builtins.open=guarded_builtin;os.scandir=guarded_scan;os.stat=guarded_stat;os.lstat=guarded_lstat;os.open=guarded_osopen;subprocess.run=prohibited;subprocess.Popen=prohibited;socket.socket=prohibited;os.system=prohibited
 try:
  selector=rawmodule(exported/'selector.py',SELECTOR,'archived_selector');recon=[]
  for source,name in [('hour','h'),('e3-reproduction','e')]:
   result=selector.reconstruct(exported,SELECTION,source,out/name);write(out/(name+'-reconstruction.json'),result);recon.append(result)
  # Restore only explicitly selected relative reader dependencies; original
  # absolute provenance coordinates are never resolved or used as fallbacks.
  copy_selected(proof('source-equivalence'),'23839d7ccec31d5c8e798694470bd3ead2329c2066871bfa59a0b7e3f24adce6',out/'v112-source-independent-8aa-v2/source-equivalence.json')
  copy_selected(proof('build-independent'),'e013503b083a0aa4a4746b1d39995fa3d5f0cc1c104a30dc2ad99e1e90a792b2',out/'v112-build-independent-8aa.json')
  ep=copy_selected(proof('e3-reader'),'2809c291d126b7b7012dfba5f17e109135b71c95ec1379571875b58779655df0',out/'e3-reader.py');e3=rawmodule(ep,'2809c291d126b7b7012dfba5f17e109135b71c95ec1379571875b58779655df0','archived_e3')
  sys.argv=[str(ep),'--root',str(out/'e'),'--output',str(out/'e3-audit.json'),'--build-proof',str(member('build-final','build-proof.json')),'--prior-registration',str(member('build-primary','registration.json'))];e3.main()
  hp=copy_selected(proof('hour-reader'),'fca72be8622b01aa069726bdf017ab9e036baf114cd1a1fff088f74670b34f31',out/'hour-reader.py')
  for name,pin in [('stability_campaign.py','bb17621588730bf2dd1cebdeb0ded28534d2815ee130e86be1fd11e1b1d7daae'),('soak_campaign.py','f51696c58ade4a7068a1ddf0229dac102ed83159193677b08ada91acc8e7a475')]:copy_selected(proof('source-tools/'+name),pin,out/'reference'/name)
  hour=rawmodule(hp,'fca72be8622b01aa069726bdf017ab9e036baf114cd1a1fff088f74670b34f31','archived_hour');sys.argv=[str(hp),'--root',str(out/'h'),'--out',str(out/'hour-audit/audit.json'),'--registration-sha256','91d726d4d0f52a0dd99c2caa1fa1406abb6afb02f7e50c3481ac62bd4e51e5f9','--report-sha256','2989c31eb51d807e8cde8389b47299e0253144f2824a5c7d360b83e030826987','--native-report-sha256','51c083c0e18e138bc75db230e582d218f4ad1ad788a2f2dece7b9d6497aa37aa','--native-sha256','0f081d8ed4f5b8e4f5b33b9d6eaff53416203f7cfeeebf99ee6511b6751d00dc'];hour.main()
  images={}
  for role,pin in [('staged-hour-native','0f081d8ed4f5b8e4f5b33b9d6eaff53416203f7cfeeebf99ee6511b6751d00dc'),('hour-driver','e442b2ec8c18dbe62235c5692fc396348ea3a30417428240251173e336292aa2'),('e3-consumer','82a97759eb475fe022c96b5a082c994c2cb9645ba0250f4f4c8a975664d88675')]:
   row=next(r for r in selection['payloads']if r['sha256']==pin);need(file_sha(exported/row['path'])==pin,'actual archived image binding');images[role]=dict(sha256=pin,archive_payload=row['path'])
  need(not attempted and not process_attempts,'original source/process/network attempted');need(file_sha(args.zip)==args.zip_sha256 and file_sha(corpus/'MANIFEST.json')==MF and file_sha(exported/'selection.json')==SELECTION,'postreplay archive controls unchanged')
  result=dict(schema='symbiote.v112-portable-data-replay/1',status='PASS_ARCHIVED_HOUR_AND_E3_DATA_REPLAY',source_commit=SOURCE,zip_sha256=args.zip_sha256,inner_manifest_sha256=MF,selection_sha256=SELECTION,reader_sha256=file_sha(Path(__file__)),archived_selector_sha256=SELECTOR,reconstructed=recon,images=images,hour_receipt_sha256=file_sha(out/'hour-audit/audit.json'),e3_receipt_sha256=file_sha(out/'e3-audit.json'),original_host_read_attempts=attempted,guarded_read_stat_and_scan_operations=count[0],native_executions=0,subprocesses=0,network_calls=0,scientific_samples=0,not_replayed='Original155-file checkout/source-tree and original-location native execution checks are NOT_REPLAYED; their original independent actual-source/image audit records remain preserved. This is archived data/reference/counter replay only; no old gate is relabelled.')
  write(out/'replay-receipt.json',result);print(json.dumps({'status':result['status'],'receipt_sha256':file_sha(out/'replay-receipt.json'),'hour_sha256':result['hour_receipt_sha256'],'e3_sha256':result['e3_receipt_sha256'],'original_host_attempts':attempted}))
 finally:
  io.open=old_io;builtins.open=old_builtin;os.scandir=old_scan;os.stat=old_stat;os.lstat=old_lstat;os.open=old_osopen;subprocess.run,subprocess.Popen,socket.socket,os.system=saved
if __name__=='__main__':main()
