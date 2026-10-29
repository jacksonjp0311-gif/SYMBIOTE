"""Offline fixtures only: no credentials, network, native execution or release."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import time
import types
import unittest
from unittest import mock
import zipfile

SOURCE=Path(__file__).with_name("v11_publish.py")
m=types.ModuleType("v11_publisher_offline")
m.__file__=str(SOURCE)
with mock.patch("subprocess.run",side_effect=AssertionError("import must not execute")),mock.patch("http.client.HTTPSConnection",side_effect=AssertionError("import must not connect")):
    exec(compile(SOURCE.read_bytes(),str(SOURCE),"exec"),m.__dict__)


def file_pin(path,name=None):
    raw=path.read_bytes(); result=dict(path=str(path),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    if name is not None:result["name"]=name
    return result


def signed_result(subject="b"*64,commit="a"*40,run=123,predicate=None):
    return [{"verificationResult":{"signature":{"certificate":{"sourceRepositoryDigest":commit,"buildSignerDigest":commit,
        "sourceRepositoryIdentifier":"777","runInvocationURI":f"https://github.com/{m.REPO}/actions/runs/{run}/attempts/1"}},
        "statement":{"predicateType":predicate or m.PREDICATES[0],"subject":[{"digest":{"sha256":subject}}]},
        "verifiedTimestamps":[{"type":"Tlog","timestamp":"offline-controlled-fixture"}]}}]


class Fixture:
    def __init__(self,root):
        self.root=root;self.assets={};self.plan={"schema":"symbiote.v11-publication-plan/1","repository":m.REPO,"version":m.TAG,
            "candidate_commit":"a"*40,"candidate_run_id":123,"source_ci_run_id":124,"publisher_sha256":m.sha(SOURCE),
            "transport_sha256":m.LOADED_TRANSPORT_SHA256,"cargo_lock_sha256":"c"*64,"platforms":{},"gates":[]}
        gh=root/"gh-offline-fixture";gh.write_bytes(b"not a real executable, never run");self.plan["gh"]=file_pin(gh)
        body=root/"release-body.md";body.write_text("Bounded software; scientific efficiency not demonstrated.\n",encoding="utf-8");self.plan["body"]=file_pin(body)
        for target in m.TARGETS:
            name=m.prefix(target);kind,machine,binary=m.transport.TARGETS[target]
            image=bytearray(128)
            if kind=="pe":image[:2]=b"MZ";struct.pack_into("<I",image,60,64);image[64:68]=b"PE\0\0";struct.pack_into("<H",image,68,machine)
            elif kind=="elf":image[:6]=b"\x7fELF\x02\x01";struct.pack_into("<HH",image,16,2,machine)
            else:image[:4]=b"\xcf\xfa\xed\xfe";struct.pack_into("<I",image,4,machine);struct.pack_into("<I",image,12,2)
            native=hashlib.sha256(image).hexdigest();self.plan["platforms"][target]=dict(native_sha256=native,embedding_sha256="d"*64,driver_sha256="e"*64)
            archive=root/(name+".zip")
            with zipfile.ZipFile(archive,"w") as output:
                output.writestr(binary,image);output.writestr("README.md",f"https://github.com/{m.REPO}/tree/{m.TAG}\n");output.writestr("LICENSE","controlled fixture")
            self.assets[archive.name]=file_pin(archive,archive.name)
            for suffix in m.SUFFIXES[2:]:self.add(name+suffix,{"fixture":"not actual cryptographic evidence"})
            build=dict(schema="symbiote.release-build/1",status="PASS_STAGED_BUILD_METADATA",source_commit="a"*40,target=target,
                       version=m.TAG,compiler_locked="1.98.1",cargo_lock_sha256="c"*64,compiler_flags=[],build_profile="release",
                       binary={"sha256":native},bundle={"sha256":self.assets[name+".zip"]["sha256"]},sbom={"sha256":self.assets[name+".cdx.json"]["sha256"]})
            self.add(name+".build.json",build)
            self.sums("STAGED_SHA256SUMS-"+target,{name+suffix:self.assets[name+suffix]["sha256"] for suffix in m.SUFFIXES})
        self.sums("SHA256SUMS",{m.prefix(target)+".zip":self.assets[m.prefix(target)+".zip"]["sha256"] for target in m.TARGETS})
        self.plan["assets"]=list(self.assets.values())
        for role in sorted(m.PRE_ROLES):self.plan["gates"].append(self.gate(role))
        self.path=root/"plan.json";self.seal()
    def add(self,name,value):
        path=self.root/name;path.write_bytes(m.encode(value));self.assets[name]=file_pin(path,name)
    def sums(self,name,rows):
        path=self.root/name;path.write_text("".join(f"{value}  {key}\n" for key,value in sorted(rows.items())),encoding="ascii")
        self.assets[name]=file_pin(path,name)
    def gate(self,role,public=None):
        target=role.partition(":")[2]; evidence=[];subject="f"*64
        def evidence_json(name,value):
            path=self.root/(role.replace(":","-")+"-"+name+".json");path.write_bytes(m.encode(value));evidence.append(file_pin(path,name))
        if role.startswith(("candidate-native:","public-native:")):
            platform=self.plan["platforms"][target];subject=platform["native_sha256"]
            evidence_json("native-acceptance",dict(schema="symbiote.installed-platform-acceptance/1",status="PASS_INSTALLED_NATIVE_LIFECYCLE",
                source_commit="a"*40,target=target,installed_binary_sha256=subject,service_test_driver_sha256=platform["driver_sha256"],typed_engine_lifecycle={"actual_fixture":"offline not qualification"}))
        if role.startswith(("candidate-embedding:","public-native:")):
            platform=self.plan["platforms"][target]
            if role.startswith("candidate-embedding:"):subject=platform["embedding_sha256"]
            evidence_json("embedding-acceptance",dict(schema="symbiote.embedding-platform-acceptance/1",status="PASS_INDEPENDENT_EMBEDDING_LIFECYCLE",
                source_commit="a"*40,target=target,binary_sha256=platform["embedding_sha256"]))
        if role=="linux-enospc":
            evidence_json("enospc-native",dict(schema="symbiote.engine-enospc/1",status="PASS_ACTUAL_ENOSPC",source_commit="a"*40,
                version="1.1.0",test_executable_sha256=subject,raw_errno=28,filesystem_capacity_bytes=1048576,retain_error_kind="storage",reopen_error_kind="hold",
                committed_ledgers_unchanged=True,fill_file_removed=True,native_mount_or_unmount_performed=False))
        if not evidence:evidence_json("raw-fixture",{"controlled":"offline gate, no actual run claimed"})
        if public is not None:
            native=m.checked_json(next(item for item in evidence if item["name"]=="native-acceptance"))
            embedded=m.checked_json(next(item for item in evidence if item["name"]=="embedding-acceptance"))
            evidence_json("public-platform",dict(schema="symbiote.public-platform-acceptance/1",status="PASS_PUBLIC_PLATFORM_LIFECYCLE",
                source_commit="a"*40,target=target,tag=m.TAG,candidate_run_id=123,public_workflow_run_id=125,
                publication_plan_sha256=public["publication_plan_sha256"],release_id=public["release_id"],
                bundle_sha256=self.assets[m.prefix(target)+".zip"]["sha256"],installed_binary_sha256=self.plan["platforms"][target]["native_sha256"],
                driver_sha256=self.plan["platforms"][target]["driver_sha256"],consumer_sha256=self.plan["platforms"][target]["embedding_sha256"],
                native_acceptance=native,embedding_acceptance=embedded))
        value=dict(schema="symbiote.v11-release-gate/1",role=role,source_commit="a"*40,candidate_run_id=123,subject_sha256=subject,status="PASS",
            started_unix_ns=1,finished_unix_ns=2,evidence=evidence,
            operator_review=dict(reviewer="offline-test-only",decision="ACCEPT",evidence_digest=m.digest(evidence),scope="controlled software fixture; not release evidence"))
        if public is not None:value["public_binding"]=public
        path=self.root/(role.replace(":","-")+"-gate.json");path.write_bytes(m.encode(value))
        return dict(role=role,subject_sha256=subject,**file_pin(path))
    def seal(self):self.path.write_bytes(m.encode(self.plan));self.pin=m.sha(self.path)


class OfflinePublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.f=Fixture(self.root)
    def tearDown(self):self.temp.cleanup()
    def test_exact_complete_four_target_plan_accepts_only_reviewed_bytes(self):
        plan,assets=m.load_plan(self.f.path,self.f.pin);self.assertEqual(len(assets),33);self.assertEqual(len(plan["gates"]),12)
    def test_missing_duplicate_extra_asset_and_altered_size_fail_closed(self):
        for mutate in (lambda p:p["assets"].pop(),lambda p:p["assets"].append(p["assets"][0]),
                       lambda p:p["assets"][0].update(bytes=p["assets"][0]["bytes"]+1)):
            with self.subTest(mutate=mutate):
                original=copy.deepcopy(self.f.plan);mutate(self.f.plan);self.f.seal()
                with self.assertRaises(m.transport.ReleaseError):m.load_plan(self.f.path,self.f.pin)
                self.f.plan=original;self.f.seal()
    def test_wrong_source_compiler_lock_native_and_no_source_ci_gate_are_rejected(self):
        for key,value in (("source_commit","b"*40),("compiler_locked","stable"),("cargo_lock_sha256","0"*64)):
            path=Path(self.f.assets[m.prefix(m.TARGETS[0])+".build.json"]["path"]);original=path.read_bytes();build=m.parse(original);build[key]=value;path.write_bytes(m.encode(build))
            with self.assertRaises(m.transport.ReleaseError):m.load_plan(self.f.path,self.f.pin)
            path.write_bytes(original)
        self.f.plan["gates"]=[item for item in self.f.plan["gates"] if item["role"]!="source-ci"];self.f.seal()
        with self.assertRaises(m.transport.ReleaseError):m.load_plan(self.f.path,self.f.pin)
    def test_changed_plan_or_executed_transport_is_rejected(self):
        with self.assertRaises(m.transport.ReleaseError):m.load_plan(self.f.path,"0"*64)
        with mock.patch.object(m,"LOADED_TRANSPORT_SHA256","0"*64):
            with self.assertRaises(m.transport.ReleaseError):m.load_plan(self.f.path,self.f.pin)
    def test_gate_requires_actual_evidence_review_and_matching_components(self):
        entry=self.f.plan["gates"][0];value=m.checked_json({k:entry[k] for k in ("path","sha256","bytes")})
        for key,replacement in (("evidence",[]),("subject_sha256","0"*64),("source_commit","b"*40),("finished_unix_ns",time.time_ns()+999_000_000_000)):
            bad=copy.deepcopy(value);bad[key]=replacement;Path(entry["path"]).write_bytes(m.encode(bad));new=dict(role=entry["role"],subject_sha256=entry["subject_sha256"],**file_pin(Path(entry["path"])))
            with self.assertRaises(m.transport.ReleaseError):m.gate(new,self.f.plan)
        Path(entry["path"]).write_bytes(m.encode(value))
    def test_signed_fields_not_predicate_or_saved_booleans_authorize_source(self):
        self.assertTrue(m.verified_attestation(signed_result(),"b"*64,"a"*40,123,m.PREDICATES[0],777))
        for section,key,value in (("certificate","sourceRepositoryDigest","c"*40),("certificate","buildSignerDigest","c"*40),
                ("certificate","sourceRepositoryIdentifier","778"),("certificate","runInvocationURI",f"https://github.com/{m.REPO}/actions/runs/124/attempts/1"),
                ("statement","predicateType",m.PREDICATES[1])):
            result=signed_result();root=result[0]["verificationResult"];target=root["signature"]["certificate"] if section=="certificate" else root["statement"];target[key]=value
            root["statement"]["predicate"]={"producer_pass":True,"claimed_source":"a"*40}
            with self.assertRaises(m.transport.ReleaseError):m.verified_attestation(result,"b"*64,"a"*40,123,m.PREDICATES[0],777)
    def test_cryptographic_verifier_is_run_fresh_for_all_signed_subjects(self):
        out=self.root/"crypto";out.mkdir()
        def verify(command,**kwargs):
            self.assertIn("--bundle",command);self.assertIn("--deny-self-hosted-runners",command)
            subject=m.sha(command[3]);predicate=command[command.index("--predicate-type")+1]
            return types.SimpleNamespace(returncode=0,stdout=m.encode(signed_result(subject,predicate=predicate)),stderr=b"")
        with mock.patch.object(m.subprocess,"run",side_effect=verify) as command:
            actual=m.cryptographic_checks(self.f.plan,self.f.assets,out,777)
        self.assertEqual(command.call_count,16);self.assertEqual(len(actual),16)
    def test_failed_cryptographic_process_cannot_be_replaced_by_saved_pass_json(self):
        out=self.root/"crypto-failed";out.mkdir()
        with mock.patch.object(m.subprocess,"run",return_value=types.SimpleNamespace(returncode=1,stdout=m.encode(signed_result()),stderr=b"controlled failure")):
            with self.assertRaises(m.transport.ReleaseError):m.cryptographic_checks(self.f.plan,self.f.assets,out,777)
    def test_complete_official_job_census_is_required(self):
        run=dict(id=123,repository=dict(full_name=m.REPO,id=777),head_sha="a"*40,path=m.WORKFLOW,event="workflow_dispatch",status="completed",conclusion="success")
        for jobs in (dict(total_count=2,jobs=[dict(status="completed",conclusion="success")]),dict(total_count=1,jobs=[dict(status="completed",conclusion="skipped")])):
            with mock.patch.object(m.transport,"metadata",side_effect=[run,jobs]):
                with self.assertRaises(m.transport.ReleaseError):m.check_run(123,"a"*40,m.WORKFLOW,"workflow_dispatch")
    def test_existing_asset_requires_exact_server_digest_not_replacement(self):
        release=dict(tag_name=m.TAG,target_commitish="a"*40,id=9,assets=[])
        for item in self.f.assets.values():release["assets"].append(dict(name=item["name"],id=len(release["assets"])+1,size=item["bytes"],digest="sha256:"+item["sha256"]))
        self.assertEqual(len(m.release_assets(release,self.f.plan,self.f.assets)),33)
        release["assets"][0]["digest"]="sha256:"+"0"*64
        with self.assertRaises(m.transport.ReleaseError):m.release_assets(release,self.f.plan,self.f.assets,True)
    def test_new_transport_refuses_other_routes_and_final_creation_before_network(self):
        with mock.patch.object(m.http.client,"HTTPSConnection",side_effect=AssertionError("network forbidden")):
            for method,suffix,body in (("DELETE","/9",None),("GET","/tags/v1.0.1",None),("POST","",dict(tag_name=m.TAG))):
                with self.assertRaises(m.transport.ReleaseError):m.authenticated_release(method,suffix,body,"offline-never-send")
    def test_public_gates_bind_release_assets_and_include_both_real_component_receipts(self):
        self.f.plan["_plan_sha256"]=self.f.pin
        binding=dict(release_id=9,publication_plan_sha256=self.f.pin,asset_digest="9"*64)
        gates=[self.f.gate(role,binding) for role in sorted(m.PUBLIC_ROLES)]
        path=self.root/"public.json";value=dict(schema="symbiote.v11-public-acceptance/1",candidate_commit="a"*40,public_run_id=125,**binding,gates=gates)
        path.write_bytes(m.encode(value));self.assertEqual(m.public_gates(path,m.sha(path),self.f.plan,binding)["release_id"],9)
        value["release_id"]=10;path.write_bytes(m.encode(value))
        with self.assertRaises(m.transport.ReleaseError):m.public_gates(path,m.sha(path),self.f.plan,binding)
    def test_stage_provisional_final_are_separate_and_public_failure_cannot_promote(self):
        self.f.plan["_plan_sha256"]=self.f.pin
        remote={"release":None,"latest":m.PREVIOUS};mutations=[]
        def release_request(method,suffix,body,token):
            self.assertEqual(token,"offline-not-secret")
            if method=="GET":return copy.deepcopy(remote["release"])
            self.assertEqual((method,suffix),("POST",""));self.assertIs(body["draft"],True);self.assertEqual(body["make_latest"],"false")
            remote["release"]=dict(id=9,assets=[],**copy.deepcopy(body));mutations.append(("CREATE",True));return copy.deepcopy(remote["release"])
        def authenticated(url,method,body,token,**kwargs):
            if method=="POST":
                name=m.urllib.parse.parse_qs(m.urllib.parse.urlsplit(url).query)["name"][0]
                raw=b""
                while True:
                    block=body.read()
                    if not block:break
                    raw+=block
                item=dict(id=len(remote["release"]["assets"])+1,name=name,size=len(raw),digest="sha256:"+hashlib.sha256(raw).hexdigest(),
                    browser_download_url=f"https://github.com/{m.REPO}/releases/download/{m.TAG}/{name}")
                remote["release"]["assets"].append(item);return copy.deepcopy(item)
            self.assertEqual(method,"PATCH");mutations.append(("PATCH",copy.deepcopy(body)))
            remote["release"].update({key:value for key,value in body.items() if key!="make_latest"})
            if body["make_latest"]=="true":remote["latest"]=m.TAG
            return copy.deepcopy(remote["release"])
        def anonymous(url,path,size,expected):
            name=m.urllib.parse.unquote(m.urllib.parse.urlsplit(url).path.rsplit("/",1)[1]);raw=Path(self.f.assets[name]["path"]).read_bytes()
            self.assertEqual(len(raw),size);self.assertEqual(hashlib.sha256(raw).hexdigest(),expected);m.write_new(path,raw)
        def output(name):path=self.root/name;path.mkdir();return path
        run={"run":{"repository":{"id":777}}}
        with mock.patch.object(m.transport,"resolve_tag"),mock.patch.object(m,"check_run",return_value=run),\
             mock.patch.object(m,"cryptographic_checks",return_value=[]),mock.patch.object(m.transport,"credential",return_value="offline-not-secret"),\
             mock.patch.object(m,"authenticated_release",side_effect=release_request),mock.patch.object(m.transport,"authenticated",side_effect=authenticated),\
             mock.patch.object(m.transport,"metadata",side_effect=lambda path:{"tag_name":remote["latest"]}),mock.patch.object(m.transport,"download",side_effect=anonymous):
            staged=m.operate("stage",self.f.plan,self.f.assets,output("stage"))
            self.assertEqual(staged["status"],"PASS_EXACT_DRAFT_STAGED");self.assertIs(remote["release"]["draft"],True)
            self.assertEqual(remote["latest"],m.PREVIOUS);self.assertEqual(len(remote["release"]["assets"]),33)
            resumed=m.operate("stage",self.f.plan,self.f.assets,output("resumed"));self.assertEqual(resumed["status"],staged["status"])
            self.assertEqual(sum(kind=="CREATE" for kind,_ in mutations),1)
            provisional=m.operate("provisional",self.f.plan,self.f.assets,output("provisional"))
            self.assertEqual(provisional["status"],"PASS_PROVISIONAL_NOT_LATEST");self.assertIs(remote["release"]["draft"],False)
            self.assertIs(remote["release"]["prerelease"],True);self.assertEqual(remote["latest"],m.PREVIOUS)
            with self.assertRaises(m.transport.ReleaseError):m.operate("finalize",self.f.plan,self.f.assets,output("no-public-gates"))
            self.assertEqual(remote["latest"],m.PREVIOUS)
            binding=provisional["public_binding"];gates=[self.f.gate(role,binding) for role in sorted(m.PUBLIC_ROLES)]
            final=dict(schema="symbiote.v11-public-acceptance/1",candidate_commit="a"*40,public_run_id=125,**binding,gates=gates)
            path=self.root/"accepted-public.json";path.write_bytes(m.encode(final))
            good=m.operate("finalize",self.f.plan,self.f.assets,output("final"),path,m.sha(path))
            self.assertEqual(good["status"],"PASS_FINAL_PUBLIC_LATEST");self.assertEqual(remote["latest"],m.TAG)
            self.assertIs(remote["release"]["prerelease"],False)
    def test_body_change_after_initial_validation_is_rejected_before_authentication(self):
        self.f.plan["_plan_sha256"]=self.f.pin
        out=self.root/"changed-body";out.mkdir()
        def cryptographic_change(*args):Path(self.f.plan["body"]["path"]).write_text("unreviewed replacement",encoding="utf-8");return []
        with mock.patch.object(m.transport,"resolve_tag"),mock.patch.object(m,"check_run",return_value={"run":{"repository":{"id":777}}}),\
             mock.patch.object(m,"cryptographic_checks",side_effect=cryptographic_change),\
             mock.patch.object(m.transport,"credential",side_effect=AssertionError("no credential or mutation allowed")):
            with self.assertRaises(m.transport.ReleaseError):m.operate("stage",self.f.plan,self.f.assets,out)
    def test_candidate_receipts_cannot_be_relabeled_as_public_and_child_swaps_fail(self):
        self.f.plan["_plan_sha256"]=self.f.pin
        binding=dict(release_id=9,publication_plan_sha256=self.f.pin,asset_digest="9"*64)
        role="public-native:"+m.TARGETS[0]
        original=self.f.gate(role,binding)
        def changed(transform):
            item=copy.deepcopy(original);value=m.checked_json({key:item[key] for key in ("path","bytes","sha256")})
            transform(value)
            value["operator_review"]["evidence_digest"]=m.digest(value["evidence"])
            Path(item["path"]).write_bytes(m.encode(value));item.update(file_pin(Path(item["path"])))
            return item
        entry=changed(lambda value:value.update(evidence=[row for row in value["evidence"] if row.get("name")!="public-platform"]))
        with self.assertRaises(m.transport.ReleaseError):m.gate(entry,self.f.plan,binding,125)
        for key,replacement in (("publication_plan_sha256","0"*64),("public_workflow_run_id",126),("native_acceptance",{"schema":"swapped"})):
            original=self.f.gate(role,binding)
            def transform(value,key=key,replacement=replacement):
                row=next(row for row in value["evidence"] if row.get("name")=="public-platform")
                actual=m.checked_json(row);actual[key]=replacement;Path(row["path"]).write_bytes(m.encode(actual));row.update(file_pin(Path(row["path"])))
            entry=changed(transform)
            with self.assertRaises(m.transport.ReleaseError):m.gate(entry,self.f.plan,binding,125)
    def test_only_actual_failed_public_workflow_can_flag_immutable_release(self):
        self.f.plan["_plan_sha256"]=self.f.pin
        body=Path(self.f.plan["body"]["path"]).read_bytes().decode("utf-8")+f"\n\nPublication plan SHA256: {self.f.pin}\n"
        release=dict(id=9,tag_name=m.TAG,target_commitish="a"*40,draft=False,prerelease=True,body=body,assets=[])
        for asset in self.f.assets.values():release["assets"].append(dict(id=len(release["assets"])+1,name=asset["name"],size=asset["bytes"],digest="sha256:"+asset["sha256"]))
        original_assets=copy.deepcopy(release["assets"]);patches=[]
        failed=dict(id=999,repository=dict(full_name=m.REPO),head_sha="a"*40,path=".github/workflows/v11-public-accept.yml",event="workflow_dispatch",status="completed",conclusion="failure")
        def metadata(path):
            if path.endswith("/latest"):return {"tag_name":m.PREVIOUS}
            if path.endswith("/jobs"):return dict(total_count=1,jobs=[dict(conclusion="failure")])
            return copy.deepcopy(failed)
        def patch(url,method,value,token,**kwargs):
            self.assertEqual(method,"PATCH");self.assertEqual(value["make_latest"],"false");self.assertIs(value["prerelease"],True)
            patches.append(copy.deepcopy(value));release.update({k:v for k,v in value.items() if k!="make_latest"});return copy.deepcopy(release)
        def out(name):path=self.root/name;path.mkdir();return path
        with mock.patch.object(m.transport,"resolve_tag"),mock.patch.object(m,"check_run",return_value={"run":{"repository":{"id":777}}}),\
             mock.patch.object(m,"cryptographic_checks",return_value=[]),mock.patch.object(m.transport,"credential",return_value="offline"),\
             mock.patch.object(m,"authenticated_release",side_effect=lambda *args:copy.deepcopy(release)),\
             mock.patch.object(m.transport,"metadata",side_effect=metadata),mock.patch.object(m.transport,"authenticated",side_effect=patch):
            failed["conclusion"]="success"
            with self.assertRaises(m.transport.ReleaseError):m.operate("flag-failed",self.f.plan,self.f.assets,out("not-failed"),failed_public_run_id=999)
            self.assertEqual(patches,[])
            failed["conclusion"]="failure";failed["head_sha"]="b"*40
            with self.assertRaises(m.transport.ReleaseError):m.operate("flag-failed",self.f.plan,self.f.assets,out("wrong-source-failed"),failed_public_run_id=999)
            self.assertEqual(patches,[])
            failed["head_sha"]="a"*40
            result=m.operate("flag-failed",self.f.plan,self.f.assets,out("flagged"),failed_public_run_id=999)
            self.assertEqual(result["status"],"PASS_PUBLIC_FAILURE_FLAGGED");self.assertEqual(release["assets"],original_assets)
            self.assertEqual(release["target_commitish"],"a"*40);self.assertIn("FAILED PUBLIC ACCEPTANCE",release["body"])
            m.operate("flag-failed",self.f.plan,self.f.assets,out("already-flagged"),failed_public_run_id=999)
            self.assertEqual(len(patches),1)
            for mode in ("stage","provisional","finalize"):
                with self.assertRaises(m.transport.ReleaseError):m.operate(mode,self.f.plan,self.f.assets,out("blocked-"+mode))
            self.assertEqual(len(patches),1)
    def test_public_workflow_has_no_windows_heredoc_or_credential_child_leak(self):
        workflow=SOURCE.parents[2]/".github/workflows/v11-public-accept.yml"
        raw=workflow.read_text(encoding="utf-8")
        self.assertIn("shell: bash",raw);self.assertIn("Path(tempfile.gettempdir()).resolve(strict=True)",raw)
        self.assertIn("actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",raw)
        public=raw.split("name: Anonymous public bytes",1)[1]
        self.assertNotIn("GH_TOKEN:",public);self.assertIn("--candidate-run-id",public)
        self.assertNotIn("cargo build",raw);self.assertNotIn("contents: write",raw)
        chunks=raw.split("python -B - <<'PY'\n")[1:]
        self.assertEqual(len(chunks),2)
        import textwrap
        for chunk in chunks:compile(textwrap.dedent(chunk.split("\n          PY",1)[0]),str(workflow),"exec")


if __name__=="__main__":unittest.main(verbosity=2)
