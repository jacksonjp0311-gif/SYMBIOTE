"""Derive a public ZIP from externally pinned, already verified evidence bytes.

No source discovery, native program, grader, campaign, publication or redaction.
The original tar, manifest, extracted files and verification receipt are read
only. This separately reviewed operator helper is not the frozen tar writer.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import tempfile
import zipfile

LIMITS=dict(files=20001,member_bytes=256*1024*1024,total_bytes=1024*1024*1024,zip_bytes=128*1024*1024)
BASE_SHA="9a2df3fc679ce154469013e02575551d9572e7cee4d2a0eca585e7fc3a780962"


def need(value,message):
    if not value:raise ValueError(message)


def pin(value):
    need(isinstance(value,str) and re.fullmatch("[0-9a-f]{64}",value),"external SHA256 required")
    return value


def encoded(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,allow_nan=False,separators=(",",":")).encode()+b"\n"


def pairs(items):
    result={}
    for key,value in items:
        need(key not in result,"duplicate JSON key")
        result[key]=value
    return result


def parse(raw):
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda value:need(False,"nonfinite JSON"))


def plain(path,directory=False):
    path=Path(path)
    need(path.is_absolute() and ".."not in path.parts,"absolute nonescaping path required")
    for selected in [path,*path.parents]:
        info=selected.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info,"st_file_attributes",0)&0x400,"linked/reparse path refused")
    need(path.is_dir()if directory else path.is_file(),"wrong selected file type")
    return path


def signature(path):
    info=plain(path).stat()
    return info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns


def fingerprint(path,maximum=LIMITS["member_bytes"]):
    before=signature(path);need(before[2]<=maximum,"file byte bound")
    hashed=hashlib.sha256();count=0
    with path.open("rb")as source:
        while True:
            block=source.read(1024*1024)
            if not block:break
            count+=len(block);need(count<=maximum,"file grew beyond bound");hashed.update(block)
    need(signature(path)==before and count==before[2],"file changed while hashing")
    return dict(bytes=count,sha256=hashed.hexdigest())


def read(path,maximum=32*1024*1024):
    before=signature(path);need(before[2]<=maximum,"JSON byte bound")
    raw=path.read_bytes()
    need(signature(path)==before and len(raw)==before[2],"file changed while reading")
    return raw


def member(name):
    need(isinstance(name,str) and name and "\\"not in name and ":"not in name,"portable member path required")
    selected=PurePosixPath(name)
    need(not selected.is_absolute() and selected.as_posix()==name and all(part not in {".",".."}for part in selected.parts),"escaping member refused")
    return selected


def census(root):
    plain(root,True);rows={};names=set();total=0
    def fail(error):raise error
    for current,directories,files in os.walk(root,followlinks=False,onerror=fail):
        plain(Path(current),True)
        for name in directories:plain(Path(current)/name,True)
        for name in files:
            path=plain(Path(current)/name);relative=path.relative_to(root).as_posix();member(relative)
            need(relative.casefold()not in names,"case alias refused");names.add(relative.casefold())
            row=fingerprint(path);total+=row["bytes"];rows[relative]=row
            need(len(rows)<=LIMITS["files"] and total<=LIMITS["total_bytes"],"bounded evidence census required")
    return dict(sorted(rows.items()))


def hash_stream(source,maximum):
    hashed=hashlib.sha256();count=0
    while True:
        block=source.read(1024*1024)
        if not block:break
        count+=len(block);need(count<=maximum,"member stream exceeded declared bound");hashed.update(block)
    return dict(bytes=count,sha256=hashed.hexdigest())


class BoundedOutput:
    """Bound actual compressed ZIP bytes, including header rewrites/directory."""
    def __init__(self,path,maximum):self.stream=path.open("xb+");self.maximum=maximum
    def write(self,value):
        need(self.stream.tell()+len(value)<=self.maximum,"compressed ZIP execution byte cap")
        return self.stream.write(value)
    def tell(self):return self.stream.tell()
    def seek(self,*args):
        position=self.stream.seek(*args);need(0<=position<=self.maximum,"ZIP output seek exceeds byte cap");return position
    def flush(self):return self.stream.flush()
    def __enter__(self):return self
    def __exit__(self,*args):self.stream.close()


def verify_tar(path,expected):
    rows={}
    with tarfile.open(path,"r:gz")as archive:
        for selected in archive:
            name=member(selected.name).as_posix()
            need(selected.isfile() and name not in rows and name in expected,"unexpected tar member/type")
            need(selected.size==expected[name]["bytes"],"tar declared size differs")
            with archive.extractfile(selected)as source:rows[name]=hash_stream(source,selected.size)
    need(rows==expected,"original tar differs from complete extracted bytes")


def verify_zip(path,expected,destination=None):
    rows={}
    if destination is not None:destination.mkdir()
    with zipfile.ZipFile(path)as archive:
        for selected in archive.infolist():
            name=member(selected.filename).as_posix()
            need(not selected.is_dir() and name not in rows and name in expected,"unexpected ZIP member")
            need(stat.S_IFMT(selected.external_attr>>16)==stat.S_IFREG and not selected.flag_bits&1,"linked/encrypted ZIP member refused")
            need(selected.file_size==expected[name]["bytes"],"ZIP declared size differs")
            if destination is None:
                with archive.open(selected)as source:rows[name]=hash_stream(source,selected.file_size)
            else:
                target=destination.joinpath(*member(name).parts);target.parent.mkdir(parents=True,exist_ok=True)
                with archive.open(selected)as source,target.open("xb")as output:
                    hashed=hashlib.sha256();count=0
                    while True:
                        block=source.read(1024*1024)
                        if not block:break
                        count+=len(block);need(count<=selected.file_size,"ZIP extraction exceeded declared size")
                        hashed.update(block);output.write(block)
                    rows[name]=dict(bytes=count,sha256=hashed.hexdigest())
    need(rows==expected,"ZIP byte census differs")
    if destination is not None:need(census(destination)==expected,"fresh ZIP extraction differs")


def derive(args):
    source=plain(args.extracted_root,True);tar=plain(args.tar);verification=plain(args.verification)
    for value in (args.manifest_sha256,args.tar_sha256,args.verification_sha256):pin(value)
    tar_initial=fingerprint(tar,LIMITS["total_bytes"])
    need(tar_initial["sha256"]==args.tar_sha256,"original tar external pin differs")
    verification_raw=read(verification)
    need(hashlib.sha256(verification_raw).hexdigest()==args.verification_sha256,"packaging verification external pin differs")
    receipt=parse(verification_raw)
    need(receipt["schema"]=="symbiote.v1-evidence-packaging/4" and receipt["status"]=="PASS"
         and receipt["archive_sha256"]==args.tar_sha256 and receipt["archive_bytes"]==tar_initial["bytes"]
         and receipt["evidence_plan"]["manifest_sha256"]==args.manifest_sha256
         and all(receipt[field]is True for field in ("full_tree_membership_rechecked","final_archive_bytes_rechecked","final_hardlink_identity_rechecked")),
         "completed exact tar/extraction verification required")
    manifest_raw=read(source/"MANIFEST.json",16*1024*1024)
    need(hashlib.sha256(manifest_raw).hexdigest()==args.manifest_sha256,"inner manifest external pin differs")
    manifest=parse(manifest_raw)
    need(manifest["schema"]=="symbiote.v1-evidence-manifest/2" and manifest["packager_base"]["sha256"]==BASE_SHA,"qualified inner manifest required")
    expected={"MANIFEST.json":dict(bytes=len(manifest_raw),sha256=args.manifest_sha256)}
    for row in manifest["entries"]:
        name=member(row["path"]).as_posix();need(name not in expected,"duplicate inner manifest member")
        need(type(row["bytes"])is int and row["bytes"]>=0,"inner member size must be an integer")
        expected[name]=dict(bytes=row["bytes"],sha256=pin(row["sha256"]))
    need(census(source)==expected,"extracted census differs from qualified inner manifest")
    verify_tar(tar,expected)
    output=Path(args.out);temporary=Path(tempfile.gettempdir()).resolve(strict=True)
    need(output.is_absolute() and temporary in output.parents and not output.exists(),"fresh OS Temp output required")
    plain(output.parent,True)
    need(not(source==output or source in output.parents or output in source.parents),"ZIP output overlaps original corpus")
    output.mkdir()
    derivation=dict(schema="symbiote.evidence-zip-derivation/1",source_commit=manifest["source_commit"],
        original_tar=tar_initial,original_manifest_sha256=args.manifest_sha256,original_verification_sha256=args.verification_sha256,
        helper_sha256=fingerprint(Path(__file__))["sha256"],inner_prefix="corpus/",inner_members=expected,
        policy="unchanged original corpus bytes; separate ZIP serialization and derivation only; no new qualification or grading",
        reproducibility="fixed member order, metadata and compression level; no cross-zlib identity claim",
        self_reference="DERIVATION.json is excluded from inner_members; final external ZIP verification pins this descriptor")
    derivation_raw=encoded(derivation)
    zip_expected={"corpus/"+name:row for name,row in expected.items()}
    zip_expected["DERIVATION.json"]=dict(bytes=len(derivation_raw),sha256=hashlib.sha256(derivation_raw).hexdigest())
    partial=output/"EVIDENCE.zip.partial"
    with BoundedOutput(partial,LIMITS["zip_bytes"])as bounded,zipfile.ZipFile(bounded,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=6,allowZip64=True)as archive:
        for name in sorted(zip_expected,key=lambda value:value.encode()):
            info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0));info.create_system=3
            info.external_attr=(stat.S_IFREG|0o644)<<16;info.compress_type=zipfile.ZIP_DEFLATED
            with archive.open(info,"w")as target:
                if name=="DERIVATION.json":target.write(derivation_raw)
                else:
                    with source.joinpath(*member(name.removeprefix("corpus/")).parts).open("rb")as selected:
                        while True:
                            block=selected.read(1024*1024)
                            if not block:break
                            target.write(block)
    zipped=fingerprint(partial,LIMITS["zip_bytes"])
    verify_zip(partial,zip_expected)
    verify_zip(partial,zip_expected,output/"zip-extracted")
    need(fingerprint(tar,LIMITS["total_bytes"])==tar_initial
         and hashlib.sha256(read(verification)).hexdigest()==args.verification_sha256,"original inputs changed during ZIP derivation")
    need(fingerprint(partial,LIMITS["zip_bytes"])==zipped,"staged ZIP changed after verification")
    partial_identity=signature(partial)[:2]
    # This final full census follows every potentially long input/output hash.
    need(census(source)==expected,"original corpus changed immediately before publication")
    final=output/"EVIDENCE.zip";os.link(partial,final)
    try:
        need(signature(final)[:2]==partial_identity and fingerprint(final,LIMITS["zip_bytes"])==zipped,
             "final ZIP differs after exclusive publication")
    except BaseException:
        if final.exists()and signature(final)[:2]==partial_identity:final.unlink()
        raise
    result=dict(schema="symbiote.evidence-zip-verification/1",status="PASS_BYTE_DERIVATION_ONLY",source_commit=manifest["source_commit"],
        archive=str(final),**zipped,inner_manifest_sha256=args.manifest_sha256,original_tar=tar_initial,
        derivation_sha256=zip_expected["DERIVATION.json"]["sha256"],members=len(zip_expected),
        tar_to_original_extraction=True,zip_member_bytes_verified=True,fresh_zip_extraction_verified=True,original_inputs_unchanged=True,
        original_tar_preserved=True,independent_scientific_samples=0,qualification="no new native execution, experiment or release gate")
    with (output/"zip-verification.json").open("xb")as target:target.write(encoded(result))
    with (output/"EVIDENCE_SHA256SUMS").open("x",encoding="ascii",newline="\n")as target:target.write(zipped["sha256"]+"  EVIDENCE.zip\n")
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("extracted-root","tar","verification","out"):parser.add_argument("--"+name,type=Path,required=True)
    for name in ("manifest-sha256","tar-sha256","verification-sha256"):parser.add_argument("--"+name,required=True)
    args=parser.parse_args()
    try:print(json.dumps(derive(args),indent=2))
    except Exception as error:
        print(json.dumps(dict(status="HOLD_PRESERVE_PARTIAL_ZIP",reason=type(error).__name__+": "+str(error))));raise SystemExit(1)


if __name__=="__main__":main()
