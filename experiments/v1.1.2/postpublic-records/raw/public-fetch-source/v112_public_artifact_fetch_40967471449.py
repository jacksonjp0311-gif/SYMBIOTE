"""Bounded API-digest artifact fetch. URL is read once from stdin, never saved/logged."""
import argparse,hashlib,json,os,re,stat,sys,tempfile,time,urllib.request,zipfile
from pathlib import Path,PurePosixPath
from urllib.parse import urlsplit
SOURCE="8aa5f4c6ab26f7ccad53935a70414ae1765b57c6";RUN=40967471449  # Actual FIRST public workflow; source-pinned8aa, root supplied.
LIMITS=dict(zip_bytes=32*1024*1024,descriptor_bytes=2*1024*1024,files=4096,file_bytes=64*1024*1024,total_bytes=128*1024*1024,path_characters=240,socket_seconds=20,network_seconds=120)
TARGETS={"x86_64-pc-windows-msvc","x86_64-unknown-linux-gnu","aarch64-apple-darwin","x86_64-apple-darwin"}
def need(ok,message):
    if not ok:raise ValueError(message)
def h(raw):return hashlib.sha256(raw).hexdigest()
def encode(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()+b"\n"
def write(path,raw):
    with path.open("xb")as f:f.write(raw)
def plain(path,directory=False):
    path=Path(path);need(path.is_absolute()and".."not in path.parts,"absolute ordinary path required")
    cursor=Path(path.anchor)
    for part in path.parts[1:]:
        cursor=cursor/part;s=cursor.lstat();need(not cursor.is_symlink()and not getattr(s,"st_file_attributes",0)&0x400,"linked/reparse path refused")
    need(path.is_dir()if directory else path.is_file(),"input type differs");return path.resolve(strict=True)
def descriptor(path,pin):
    path=plain(path);before=path.stat();need(before.st_size<=LIMITS["descriptor_bytes"],"descriptor pre-read bound")
    with path.open("rb")as f:raw=f.read(LIMITS["descriptor_bytes"]+1)
    after=path.stat();need(len(raw)==before.st_size and h(raw)==pin and(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),"descriptor pin/stability differs")
    value=json.loads(raw);workflow=value["workflow_run"]
    need(workflow["id"]==RUN and workflow["head_sha"]==SOURCE and value["expired"]is False,"API artifact source/run/expiry differs")
    need(type(value["id"])is int and value["id"]>0 and type(value["size_in_bytes"])is int and 0<value["size_in_bytes"]<=LIMITS["zip_bytes"],"API artifact identity/size exceeds bound")
    need(value["name"]in{"v11-public-"+target for target in TARGETS},"unexpected public-platform artifact name")
    need(isinstance(value["digest"],str)and re.fullmatch(r"sha256:[0-9a-f]{64}",value["digest"]),"actual API SHA256 digest required")
    return value,raw
class HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,msg,headers,url):
        parsed=urlsplit(url);need(parsed.scheme=="https"and parsed.hostname and parsed.username is None and parsed.password is None,"unsafe download redirect")
        return super().redirect_request(request,fp,code,msg,headers,url)
def extract(archive,data):
    data.mkdir();seen=set();members=[];total=0
    with zipfile.ZipFile(archive)as z:
        infos=z.infolist();need(0<len(infos)<=LIMITS["files"],"ZIP member count exceeds bound")
        for entry in infos:
            name=entry.filename;directory=entry.is_dir();relative=name[:-1]if directory else name
            path=PurePosixPath(relative);mode=(entry.external_attr>>16)&0o170000
            need(entry.orig_filename==name and relative and not path.is_absolute()and path.as_posix()==relative and all(part not in {".",".."}and":"not in part and"\\"not in part and not part.endswith((" ","."))for part in path.parts),"unsafe ZIP member path")
            need(not entry.flag_bits&1 and mode in {0,stat.S_IFREG,stat.S_IFDIR}and not(mode==stat.S_IFDIR and not directory),"encrypted/special ZIP member refused")
            key=relative.casefold();need(key not in seen,"duplicate/case-alias ZIP member");seen.add(key)
            need(all(part.split(".")[0].upper()not in {"CON","PRN","AUX","NUL",*["COM"+str(i)for i in range(1,10)],*["LPT"+str(i)for i in range(1,10)]}for part in path.parts),"reserved Windows member refused")
            target=data.joinpath(*path.parts);need(len(str(target))<=LIMITS["path_characters"],"extraction path exceeds bound")
            if directory:need(entry.file_size==0,"directory has file bytes");target.mkdir(parents=True,exist_ok=True);continue
            need(0<=entry.file_size<=LIMITS["file_bytes"]and total+entry.file_size<=LIMITS["total_bytes"],"ZIP expanded byte bound")
            target.parent.mkdir(parents=True,exist_ok=True);hasher=hashlib.sha256();count=0
            with z.open(entry)as source,target.open("xb")as output:
                while True:
                    block=source.read(65536)
                    if not block:break
                    count+=len(block);need(count<=entry.file_size,"ZIP member expanded beyond declared size");output.write(block);hasher.update(block)
            need(count==entry.file_size,"ZIP member truncated");total+=count
            members.append(dict(path=path.as_posix(),bytes=count,sha256=hasher.hexdigest()))
    actual={p.relative_to(data).as_posix()for p in data.rglob("*")if p.is_file()};need(actual=={r["path"]for r in members},"extracted census differs")
    return sorted(members,key=lambda r:r["path"].encode()),total

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--descriptor",type=Path,required=True);p.add_argument("--descriptor-sha256",required=True);p.add_argument("--out",type=Path,required=True);a=p.parse_args();out=None;started=time.monotonic();artifact=None
    try:
        need(type(RUN)is int and RUN>0,"actual public workflow id has not been bound")
        need(re.fullmatch(r"[0-9a-f]{64}",a.descriptor_sha256),"descriptor SHA256 required")
        artifact,descriptor_raw=descriptor(a.descriptor,a.descriptor_sha256)
        url=sys.stdin.buffer.readline(8193).decode("ascii").strip();parts=urlsplit(url);need(len(url)<=8192 and parts.scheme=="https"and parts.hostname and parts.username is None and parts.password is None,"one bounded HTTPS connector URL required")
        out=a.out;temporary=Path(tempfile.gettempdir()).resolve(strict=True);need(out.is_absolute()and temporary in out.parents and not out.exists()and len(str(out))<=110,"fresh short OS Temp output required");plain(out.parent,True);out.mkdir()
        archive=out/"artifact.zip";hasher=hashlib.sha256();count=0;opener=urllib.request.build_opener(HttpsOnly())
        with opener.open(urllib.request.Request(url,headers={"User-Agent":"SYMBIOTE-evidence-fetch/1"}),timeout=LIMITS["socket_seconds"])as response,archive.open("xb")as output:
            need(urlsplit(response.geturl()).scheme=="https","non-HTTPS final download refused")
            while True:
                need(time.monotonic()-started<=LIMITS["network_seconds"],"download observed deadline exhausted")
                block=response.read(65536)
                if not block:break
                count+=len(block);need(count<=artifact["size_in_bytes"]and count<=LIMITS["zip_bytes"],"download exceeds API/byte bound");output.write(block);hasher.update(block)
        need(count==artifact["size_in_bytes"]and hasher.hexdigest()==artifact["digest"][7:],"download differs from actual API size/SHA256")
        members,total=extract(archive,out/"data")
        result=dict(schema="symbiote.artifact-source-download/1",status="PASS_API_DIGEST_BOUND_ARTIFACT_BYTES",source_commit=SOURCE,public_workflow_run_id=RUN,artifact_id=artifact["id"],artifact_name=artifact["name"],descriptor_sha256=a.descriptor_sha256,original_artifact_sha256=hasher.hexdigest(),original_artifact_bytes=count,extracted_bytes=total,files=members,limits=LIMITS,elapsed_seconds=time.monotonic()-started,helper_sha256=h(Path(__file__).read_bytes()),download_url_saved=False,authorization_headers_used=False,native_executions=0,interpretation="Actual public-workflow byte preservation only; no global public qualification is inferred from individual component reports.")
        write(out/"download.json",encode(result));print(json.dumps(dict(status=result["status"],artifact_id=result["artifact_id"],bytes=count,sha256=result["original_artifact_sha256"],members=len(members),receipt_sha256=h((out/"download.json").read_bytes()))))
    except BaseException as error:
        failure=dict(status="HOLD_ARTIFACT_DOWNLOAD_OR_EXTRACTION",source_commit=SOURCE,public_workflow_run_id=RUN,artifact_id=artifact.get("id")if artifact else None,failure_category=type(error).__name__,http_status=getattr(error,"code",None)if type(getattr(error,"code",None))is int else None,url_or_credentials_saved=False,elapsed_seconds=time.monotonic()-started)
        if out is not None and out.is_dir()and not(out/"download.json").exists():write(out/"download.json",encode(failure))
        print(json.dumps(failure));raise SystemExit(1)
if __name__=="__main__":main()