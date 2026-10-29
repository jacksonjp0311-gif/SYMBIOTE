"""Exact one-file Git-summary admission; frozen 301bf/9a raw and decoded scanners stay authoritative.

This operator-prepared dispatch is explicitly additional to the two Cargo formats.
It is not a production source change or a general human-text/JSON-prefix bypass.
"""
from pathlib import Path
import hashlib,json,os,re,sys,types
SOURCE='8aa5f4c6ab26f7ccad53935a70414ae1765b57c6'
ROOT=Path(os.environ['TEMP'])/'vx112';TARGET=ROOT/'p/02469/8.stdout'
PIN='41bc1bb4e077def3cf33faaacc257bbe21bc433ffd0172d92b0cc0f0a062cfc0'
SELECTION='df529992e1b0e08619701c1514f01aee813ca42b64d79b01895807bf3708f261'
COPIES='ad03f45cf2556e255dfe95222c78d2b670d4c08b37a333ad666530d1226c3def'
LITERAL=b'[main 8aa5f4c] fix: scope public metadata auth for v1.1.2 qualification\n 14 files changed, 475 insertions(+), 55 deletions(-)\n create mode 100644 docs/CORRECTIVE_RELEASE_112.md\n'
ADAPTER=Path(r'C:\Users\jacks\Documents\Codex\2026-10-26\codex-master-directive-symbiote-symbiotic-adaptive\tools\release\package_v1_evidence_v4.py')
ADAPTER_PIN='301bf6030271c38f43902631c35ac852c87455ab2f2bd3118a74c5b879a26ffc'
def need(ok,message):
    if not ok:raise ValueError(message)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def origin_documents(selection,copies):
    need(selection['source_commit']==SOURCE and selection['status']=='PASS_BYTE_SELECTION_ONLY','exact source-bound completed byte export')
    row=next(r for r in selection['payloads']if r['path']=='p/02469/8.stdout')
    need(row['sha256']==PIN and row['bytes']==177 and row['origins']==[dict(source='proofs',path='source-freeze/8.stdout')],'exact logical Git-summary origin')
    copy=next(r for r in copies['files']if r['path']=='source-freeze/8.stdout')
    need(copy['sha256']==PIN and copy['bytes']==177 and copy['original_source_commit']==SOURCE and copy['original_path']==str(Path(os.environ['TEMP'])/'v112-freeze-001/8.stdout'),'exact original source-freeze byte copy')
def pinned_document(base,path,pin):
    path=base.plain(path,False);before=base.signature(path);need(before[2]<=32*1024*1024,'pre-read provenance bound');raw=base.read_bounded(path,32*1024*1024)
    need(digest(raw)==pin and base.signature(path)==before,'provenance pin/stability');base.scan_bytes(raw,str(path));value=base.parse(raw);base.scan_json(value,str(path));return value
def validate_origin(base):
    selection=pinned_document(base,ROOT/'selection.json',SELECTION)
    copied=next(r for r in selection['payloads']if any(o==dict(source='proofs',path='COPY-CENSUS.json')for o in r['origins']))
    need(copied['sha256']==COPIES and re.fullmatch(r'p/[0-9]{5}/COPY-CENSUS[.]json',copied['path']),'pinned contained copy-census member')
    copies=pinned_document(base,ROOT/copied['path'],COPIES);origin_documents(selection,copies)
def git_fingerprint(base,path,expected_path=TARGET):
    path=base.plain(path,False);need(path==expected_path,'only exact registered Git-summary path')
    before=base.signature(path);need(before[2]==177 and path.suffix=='.stdout','exact registered Git-summary size/extension')
    hashed=hashlib.sha256();tail=b'';chunks=[];count=0
    with path.open('rb')as stream:
        while True:
            block=stream.read(base.BLOCK)
            if not block:break
            count+=len(block);need(count<=177,'Git-summary grew');hashed.update(block)
            # Identical continuous block and PEM-overlap primitive to base9a.
            base.scan_bytes(tail+block,str(path));tail=(tail+block)[-base.PEM_OVERLAP:];chunks.append(block)
    raw=b''.join(chunks);need(count==177 and hashed.hexdigest()==PIN and raw==LITERAL,'exact Git-summary bytes/SHA/literal')
    text=raw.decode('utf-8','strict');need(len(text.splitlines())==3 and text.endswith('\n'),'exact three UTF8 lines')
    base.scan_json(text,str(path))
    for line in text.splitlines():base.scan_json(line,str(path))
    need(base.signature(path)==before,'Git-summary changed during raw/decoded scan')
    return dict(bytes=177,sha256=PIN,signature=before)
def dispatch(base,fallback,path,target=TARGET):
    # All unclassified and Cargo paths retain the original frozen dispatch.
    return git_fingerprint(base,path,target)if Path(path)==target else fallback(path)
def load_adapter():
    raw=ADAPTER.read_bytes();need(digest(raw)==ADAPTER_PIN,'exact frozen qualified adapter')
    m=types.ModuleType('qualified_v112_with_declared_git_summary');m.__file__=str(ADAPTER);exec(compile(raw,str(ADAPTER),'exec'),m.__dict__)
    validate_origin(m.base);fallback=m.ORIGINAL_FINGERPRINT
    m.ORIGINAL_FINGERPRINT=lambda path:dispatch(m.base,fallback,path)
    return m
if __name__=='__main__':
    try:load_adapter().main()
    except Exception as error:
        print(json.dumps(dict(status='HOLD_EXACT_GIT_SUMMARY_ADMISSION',failure=type(error).__name__+': '+str(error))),file=sys.stderr);raise SystemExit(1)
