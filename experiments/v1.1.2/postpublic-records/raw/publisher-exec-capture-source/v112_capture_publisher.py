"""Capture one explicitly requested frozen publisher operation, with raw streams."""
import argparse,hashlib,json,os,subprocess,sys,time
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(r'C:\Users\jacks\Documents\Codex\2026-10-26\codex-master-directive-symbiote-symbiotic-adaptive')
TMP=Path(r'C:\Users\jacks\AppData\Local\Temp')
SOURCE='8aa5f4c6ab26f7ccad53935a70414ae1765b57c6'
PUBLISHER='f1bd6913a3264b013bf077f975d7325b8e38a275af6e01a2abb728fabdf5c297'
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--mode',choices=['stage','provisional','finalize','flag-failed'],required=True);p.add_argument('--plan',type=Path,required=True);p.add_argument('--plan-sha256',required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--public-acceptance',type=Path);p.add_argument('--public-acceptance-sha256');p.add_argument('--failed-public-run',type=int);a=p.parse_args()
    publisher=ROOT/'tools/release/v11_publish.py'
    assert sha(publisher)==PUBLISHER and sha(a.plan)==a.plan_sha256
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()==SOURCE
    assert not subprocess.check_output(['git','status','--porcelain=v1','--untracked-files=all'],cwd=ROOT)
    assert a.out.is_absolute() and a.out.parent==TMP and not a.out.exists()
    stdout=a.out.with_suffix('.stdout');stderr=a.out.with_suffix('.stderr');capture=a.out.with_suffix('.capture.json')
    assert all(not path.exists() for path in [stdout,stderr,capture])
    command=[sys.executable,'-B',str(publisher),a.mode,'--plan',str(a.plan),'--plan-sha256',a.plan_sha256,'--out',str(a.out)]
    if a.public_acceptance is not None:command.extend(['--public-acceptance',str(a.public_acceptance),'--public-acceptance-sha256',a.public_acceptance_sha256])
    if a.failed_public_run is not None:command.extend(['--failed-public-run',str(a.failed_public_run)])
    before=datetime.now(timezone.utc).isoformat();start=time.monotonic()
    with stdout.open('xb') as out,stderr.open('xb') as err:
        process=subprocess.run(command,cwd=ROOT,stdout=out,stderr=err,check=False,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    receipt=dict(schema='symbiote.v112-owned-publisher-capture/1',source_commit=SOURCE,publisher_sha256=PUBLISHER,mode=a.mode,command=command,started_utc=before,finished_utc=datetime.now(timezone.utc).isoformat(),elapsed_seconds=time.monotonic()-start,exit_code=process.returncode,streams={name:dict(path=str(path),bytes=path.stat().st_size,sha256=sha(path)) for name,path in [('stdout',stdout),('stderr',stderr)]},credentials_logged=False,operator_sha256=sha(__file__))
    with capture.open('xb') as f:f.write(json.dumps(receipt,indent=2).encode()+b'\n')
    result=json.loads((a.out/'operation.json').read_bytes()) if (a.out/'operation.json').is_file() else {}
    print(json.dumps(dict(exit_code=process.returncode,status=result.get('status'),reason=result.get('reason'),capture=str(capture),capture_sha256=sha(capture),operation=str(a.out/'operation.json'),operation_sha256=sha(a.out/'operation.json') if result else None)))
    return process.returncode
if __name__=='__main__':raise SystemExit(main())
