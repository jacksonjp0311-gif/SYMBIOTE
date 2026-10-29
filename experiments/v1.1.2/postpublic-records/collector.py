"""Copy explicitly pinned closed release-sidecar files; never publish or qualify.
Unknown public/stage/finalize results stay pending. Exact bytes are copied;
originals and the immutable evidence archive are never modified.
"""
import argparse,hashlib,json,re,sys,tempfile,types
from pathlib import Path
from urllib.parse import urlsplit,parse_qsl
SOURCE='8aa5f4c6ab26f7ccad53935a70414ae1765b57c6'
QUALIFIED='301bf6030271c38f43902631c35ac852c87455ab2f2bd3118a74c5b879a26ffc'
LIMITS=dict(files=256,file_bytes=1048576,total_bytes=8388608,console_bytes=65536,path=240)
ALLOWED={'.json','.jsonl','.py','.md','.txt','.stdout','.stderr','.log','.diff','.toml','.lock','.sha256'}
FORBIDDEN={'.exe','.dll','.pdb','.so','.dylib','.zip','.gz','.tar','.7z','.key','.pfx','.p12'}
def need(v,m):
 if not v:raise ValueError(m)
def digest(b):return hashlib.sha256(b).hexdigest()
def load_primitives(path):
 raw=Path(path).read_bytes();need(digest(raw)==QUALIFIED,'qualified scanner adapter SHA differs');m=types.ModuleType('qualified_sidecar_scanner');m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__);return m.base

def public_urls(value):
 if isinstance(value,dict):
  for k,v in value.items():public_urls(k);public_urls(v)
 elif isinstance(value,list):
  for v in value:public_urls(v)
 elif isinstance(value,str):
  for match in re.findall(r'https?://[^\s<>"\\]+',value):
   u=urlsplit(match.rstrip(').,;'));need(u.username is None and u.password is None,'URL user credentials refused')
   keys=[k.lower()for k,v in parse_qsl(u.query,keep_blank_values=True)]
   need(not any(k in {'token','access_token','auth','password','signature','sig','credential'}or k.startswith(('x-amz-','x-goog-'))for k in keys),'signed or credential URL refused')

def read_file(base,item):
 base.fields(item,('id','path','sha256','bytes','purpose','scope'));need(re.fullmatch('[a-z0-9-]{1,48}',item['id'])and isinstance(item['purpose'],str)and isinstance(item['scope'],str),'explicit bounded selection purpose/id/scope')
 p=base.plain(item['path'],False);temp=Path(tempfile.gettempdir()).resolve(strict=True);need(temp in p.parents,'only explicitly selected Temp proof files')
 before=base.signature(p);need(type(item['bytes'])is int and 0<=item['bytes']==before[2]<=LIMITS['file_bytes'],'pre-read individual bound/exact length')
 need(p.suffix.lower()in ALLOWED and p.suffix.lower()not in FORBIDDEN,'only small declared text formats; native/archive/private files excluded')
 if p.suffix.lower()in {'.stdout','.stderr','.txt','.log'}:need(before[2]<=LIMITS['console_bytes'],'large logs belong in external evidence')
 raw=base.read_bounded(p,LIMITS['file_bytes']);need(len(raw)==item['bytes']and digest(raw)==base.pin(item['sha256'])and base.signature(p)==before,'source byte/stat pin changed')
 need(not raw.startswith((b'MZ',b'\x7fELF',b'\xcf\xfa\xed\xfe',b'\xfe\xed\xfa\xcf',b'\xca\xfe\xba\xbe')),'native image magic refused')
 tail=b''
 for offset in range(0,len(raw),base.BLOCK):
  block=raw[offset:offset+base.BLOCK];base.scan_bytes(tail+block,str(p));tail=(tail+block)[-base.PEM_OVERLAP:]
 text=raw.decode('utf-8-sig',errors='strict');public_urls(text)
 if p.suffix.lower()in {'.stdout','.stderr','.txt','.log'} and text.lstrip().startswith(('{','[','\"')):
  document=base.parse(raw);base.scan_json(document,str(p));public_urls(document)
 if p.suffix.lower()in {'.json','.jsonl'}:
  if p.suffix.lower()=='.json':document=base.parse(raw);base.scan_json(document,str(p));public_urls(document)
  else:
   for line in raw.splitlines():
    if line.strip():document=base.parse(line);base.scan_json(document,str(p));public_urls(document)
 return raw

def inspect(base,spec_path):
 spec_path=base.plain(spec_path,False);raw=base.read_bounded(spec_path,1048576);spec=base.parse(raw);base.scan_bytes(raw,str(spec_path));base.scan_json(spec,str(spec_path));public_urls(spec)
 base.fields(spec,('schema','source_commit','version','status','goal_bytes','files','references','pending','index_template'))
 need(spec['schema']=='symbiote.v112-sidecar-selection/1'and spec['source_commit']==SOURCE and spec['version']=='v1.1.2','exact source/version sidecar context')
 need(spec['status']in {'PREPARATION_ONLY_PUBLIC_RESULTS_PENDING','CLOSED_SELECTED_RECORDS_FOR_REVIEW'}and type(spec['goal_bytes'])is int and spec['goal_bytes']==1048576,'sidecar selection remains copying only, never public qualification')
 need(isinstance(spec['files'],list)and 0<len(spec['files'])<=LIMITS['files']and len({i['id']for i in spec['files']})==len(spec['files']),'bounded explicit distinct files')
 need(isinstance(spec['pending'],dict)and all(v=='PENDING_ACTUAL_RECORD'for v in spec['pending'].values()),'unknown publication fields remain pending')
 need(isinstance(spec['references'],list)and len(spec['references'])<=64 and isinstance(spec['index_template'],dict),'explicit references and template')
 if spec['status']=='CLOSED_SELECTED_RECORDS_FOR_REVIEW':
  need(not spec['pending']and 'PENDING_ACTUAL_RECORD'not in json.dumps(spec['index_template'])and '{{'not in json.dumps(spec['index_template']),'closed index must resolve placeholders explicitly; no inferred status')
 total=0;rows=[]
 for item in spec['files']:
  data=read_file(base,item);total+=len(data);need(total<=LIMITS['total_bytes'],'bounded compact sidecar; external references for large proof trees');rows.append(dict(item,selected_relative_path='raw/'+item['id']+'/'+Path(item['path']).name))
 return spec,rows,total,digest(raw)

def capture(base,spec_path,out):
 spec,rows,total,spec_sha=inspect(base,spec_path);temp=Path(tempfile.gettempdir()).resolve(strict=True);need(out.is_absolute()and temp in out.parents and not out.exists(),'fresh dedicated Temp capture output');base.plain(out.parent,True)
 roots=[Path(i['path'])for i in rows];need(all(out!=r and r not in out.parents and out not in r.parents for r in roots),'capture cannot overlap selected originals');out.mkdir()
 for item in rows:
  data=read_file(base,{k:item[k]for k in ('id','path','sha256','bytes','purpose','scope')});target=out/item['selected_relative_path'];need(len(str(target))<=LIMITS['path'],'compact copied path bound');target.parent.mkdir(parents=True,exist_ok=True)
  with target.open('xb')as f:f.write(data)
  need(digest(target.read_bytes())==item['sha256'],'sidecar copy differs')
 for item in spec['files']:read_file(base,item)
 (out/'SELECTION.json').write_bytes(base.read_bounded(spec_path,1048576));(out/'INDEX.PENDING.json').write_bytes((json.dumps(spec['index_template'],sort_keys=True,indent=2)+'\n').encode());(out/'collector.py').write_bytes(Path(__file__).read_bytes())
 result=dict(schema='symbiote.v112-sidecar-capture/1',status='PASS_SELECTED_CLOSED_BYTE_COPY_ONLY',source_commit=SOURCE,version='v1.1.2',selection_sha256=spec_sha,collector_sha256=digest(Path(__file__).read_bytes()),qualified_scanner_sha256=QUALIFIED,files=rows,selected_file_bytes=total,goal_bytes=spec['goal_bytes'],within_goal=total<=spec['goal_bytes'],limits=LIMITS,pending=spec['pending'],references=spec['references'],source_bytes_unchanged=True,native_or_archive_files_copied=0,public_qualification_inferred=False,scientific_samples=0,git_note='Raw copies are exact here. Git eol normalization must be separately recorded by comparing original SHA with indexed blob bytes before claiming byte-identical committed copies.')
 with(out/'CAPTURE.json').open('xb')as f:f.write((json.dumps(result,sort_keys=True,indent=2)+'\n').encode())
 return result

def main():
 sys.dont_write_bytecode=True;p=argparse.ArgumentParser(description=__doc__);p.add_argument('--qualified-adapter',type=Path,required=True);p.add_argument('--spec',type=Path,required=True);p.add_argument('--out',type=Path);a=p.parse_args();base=load_primitives(a.qualified_adapter)
 if a.out:
  r=capture(base,a.spec,a.out);print(json.dumps(dict(status=r['status'],files=len(r['files']),bytes=r['selected_file_bytes'],capture_sha256=digest((a.out/'CAPTURE.json').read_bytes()),public_pending=r['pending'])))
 else:
  spec,rows,total,pin=inspect(base,a.spec);print(json.dumps(dict(status='PLAN_SELECTED_CLOSED_BYTES_ONLY',selection_sha256=pin,files=len(rows),bytes=total,pending=spec['pending'])))
if __name__=='__main__':
 try:main()
 except (ValueError,OSError,KeyError,TypeError)as e:print(json.dumps(dict(status='HOLD_CAPTURE_NOT_PUBLIC_QUALIFICATION',failure=type(e).__name__+': '+str(e))),file=sys.stderr);sys.exit(1)
