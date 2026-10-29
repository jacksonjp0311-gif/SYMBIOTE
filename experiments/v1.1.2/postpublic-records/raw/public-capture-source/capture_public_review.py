"""TEMP actual four-public evidence capture. No ACCEPT, gates, network or native execution."""

import argparse,copy,hashlib,json,sys,time,types

from pathlib import Path

sys.dont_write_bytecode=True

BASE=Path(__file__).parent

SOURCE="8aa5f4c6ab26f7ccad53935a70414ae1765b57c6"

def check(v,s):

 if not v: raise ValueError(s)

def coordinate(p,name=None):

 p=Path(p); check(p.is_absolute() and p.is_file() and not p.is_symlink(),"ordinary exact file required")

 raw=p.read_bytes(); check(len(raw)<=128*1024*1024,"capture file bound")

 d=dict(path=str(p),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

 if name:d["name"]=name

 return d,raw

def load_module(p,sha):

 c,raw=coordinate(p);check(c["sha256"]==sha,"frozen helper differs")

 m=types.ModuleType(p.stem);m.__file__=str(p);exec(compile(raw,str(p),"exec"),m.__dict__);return m

def save(p,j):

 check(not p.exists(),"fresh output required");p.write_text(json.dumps(j,indent=2,allow_nan=False)+"\n",encoding="utf-8");return coordinate(p)[0]

def run(roots_path,root_sha):

 rc,raw=coordinate(roots_path);check(rc["sha256"]==root_sha,"external actual root mapping differs");roots=json.loads(raw)

 a=load_module(BASE/"build_reviewed_plan.v2.py","e418c7c07526729c2c2e3e49d4019130d0eb264b30b28b645ca38a8281d469f1")

 pub=load_module(BASE/"assemble_public_assessment.py","c9e8eefdb00f8c0910923c715e0a7c0917c4d085c43b20ebb7e5973f61644c20")

 request=json.loads((BASE/"reviewed-public-inputs.ACTUAL-OPERATIONS-PUBLIC-ARTIFACTS-PENDING.json").read_bytes())

 plan=a.checked_json(request["publication_plan"]);op=a.checked_json(request["provisional_operation"])

 check(request["publication_plan"]["sha256"]=="e974dd7ecef3d2fc7356dfd090bdc32e086f00b4b51ae1efa7a823d474694b5d","actual plan differs")

 check(op["status"]=="PASS_PROVISIONAL_NOT_LATEST" and op["mode"]=="provisional" and op["candidate_commit"]==SOURCE,"actual provisional differs")

 binding={"release_id":428461777,"publication_plan_sha256":request["publication_plan"]["sha256"],"asset_digest":"cf8d5c03f1c8628ed4e9c5f4f0772dfce4be64bb10d5f7de5f33d54547eff9f2"}

 check(op["public_binding"]==binding and op["release"]["draft"] is False and op["release"]["prerelease"] is True,"actual provisional release differs")

 check(a.canonical_digest({x["name"]:x["sha256"] for x in plan["assets"]})==binding["asset_digest"],"asset digest differs")

 run_id,jobs=pub.official_public(a,request["official_public_run"]);check(run_id==40967471449,"wrong first public run")

 check(set(roots)==set(a.TARGETS),"exact four closed roots required")

 assets={x["name"]:x for x in plan["assets"]};captures=[]

 for gate in request["gates"]:

  started=time.time_ns();mono=time.monotonic_ns();target=gate["role"].partition(":")[2];root=Path(roots[target]);named={}

  for name,path in (("public-platform",root/"public-acceptance.json"),("native-acceptance",root/"native/acceptance.json"),("embedding-acceptance",root/"embedding/embedding-acceptance.json")):

   c,b=coordinate(path,name);named[name]=(c,json.loads(b))

  delivered=named["public-platform"][1];native=named["native-acceptance"][1];embedded=named["embedding-acceptance"][1];platform=plan["platforms"][target]

  check(delivered["schema"]=="symbiote.public-platform-acceptance/1" and delivered["status"]=="PASS_PUBLIC_PLATFORM_LIFECYCLE","actual parent did not pass")

  check(delivered["source_commit"]==SOURCE and delivered["target"]==target and delivered["tag"]=="v1.1.2" and delivered["candidate_run_id"]==40945405929 and delivered["public_workflow_run_id"]==run_id,"public source/version/candidate/run mismatch")

  check(delivered["release_id"]==binding["release_id"] and delivered["publication_plan_sha256"]==binding["publication_plan_sha256"],"public release/plan mismatch")

  prefix="symbiote-v1.1.2-"+target;check(delivered["bundle_sha256"]==assets[prefix+".zip"]["sha256"],"public ZIP differs")

  check(delivered["native_acceptance"]==native and delivered["embedding_acceptance"]==embedded,"parent/child receipts differ")

  check(native["status"]=="PASS_INSTALLED_NATIVE_LIFECYCLE" and embedded["status"]=="PASS_INDEPENDENT_EMBEDDING_LIFECYCLE" and native["source_commit"]==embedded["source_commit"]==SOURCE and native["target"]==embedded["target"]==target,"child source/status/target differs")

  check(gate["subject_sha256"]==delivered["installed_binary_sha256"]==native["installed_binary_sha256"]==platform["native_sha256"] and delivered["driver_sha256"]==native["service_test_driver_sha256"]==platform["driver_sha256"] and delivered["consumer_sha256"]==embedded["binary_sha256"]==platform["embedding_sha256"],"component image mismatch")

  downloads=delivered["anonymous_downloads"];check(len(downloads)==9 and len({d["name"] for d in downloads})==9,"nine unique actual anonymous assets required")

  expected_names={prefix+s for s in (".zip",".build.json",".cdx.json",".provenance.sigstore.json",".provenance-verification.json",".sbom.sigstore.json",".sbom-verification.json")}|{"STAGED_SHA256SUMS-"+target,"SHA256SUMS"}

  check({d["name"] for d in downloads}==expected_names,"nine exact public assets differ")

  for d in downloads:check(d["sha256"]==assets[d["name"]]["sha256"] and d["bytes"]==assets[d["name"]]["bytes"] and type(d["asset_id"]) is int and d["asset_id"]>0,"actual anonymous bytes differ from plan")

  check(native.get("typed_engine_lifecycle"),"typed installed engine lifecycle missing")

  gate["evidence"]=[named[n][0] for n in ("public-platform","native-acceptance","embedding-acceptance")]+[dict(request["official_public_run"],name="official-public-run"),dict(request["provisional_operation"],name="provisional-operation")]

  gate["review"]={"reviewer":"PENDING_ROOT_PUBLIC_REVIEW","decision":"REVIEW_REQUIRED","scope":"Actual first-attempt four-target anonymous public lifecycle; exact source/version/candidate/public-run/release/plan/ZIP/native/driver/consumer and nested raw receipts. Nine anonymous byte downloads per target; source-matched installed typed engine and independent embedding. No reciprocal efficiency or broader-host claim."}

  job,start,finish=jobs[target];finished=time.time_ns();check(finished>=started,"review clock regression")

  captures.append({"role":gate["role"],"status":"CAPTURED_AWAITING_ROOT_ACCEPT","started_unix_ns":started,"finished_unix_ns":finished,"monotonic_elapsed_ns":time.monotonic_ns()-mono,"clock_scope":"actual local completed-evidence review only","job_id":job["id"],"official_job_started_unix_ns":start,"official_job_finished_unix_ns":finish,"anonymous_downloads":downloads,"metadata_access":delivered.get("metadata_access"),"native_sha256":platform["native_sha256"],"driver_sha256":platform["driver_sha256"],"consumer_sha256":platform["embedding_sha256"]})

 req=save(BASE/"reviewed-public-inputs.CAPTURED-REVIEW-REQUIRED.json",request)

 report={"schema":"symbiote.v112-public-evidence-captures/1","status":"CAPTURED_AWAITING_ROOT_AND_INDEPENDENT_REVIEW","source_commit":SOURCE,"public_workflow_run_id":run_id,"public_binding":binding,"reviewed_input":req,"actual_roots_mapping":rc,"captures":captures,"native_executions":0,"network_calls":0,"publication_mutations":0,"pass_gates_created":0}

 print(json.dumps(save(BASE/"FOUR-PUBLIC-CAPTURE-REPORT.json",report)))

if __name__=="__main__":

 p=argparse.ArgumentParser();p.add_argument("--roots",required=True);p.add_argument("--roots-sha256",required=True);x=p.parse_args();run(x.roots,x.roots_sha256)

