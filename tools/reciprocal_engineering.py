"""Once-only, source-pinned reciprocal engineering runner and independent consumer.

Registration enumerates the finite family before any target is opened. A passed
operational check is separate from fixed/matched-control utility conclusions.
"""
import argparse
import hashlib
import heapq
import itertools
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time

import source_fingerprint
import stability_campaign as safety
from qualification_awake import QualificationAwake
from transfer_campaign import canonical_path, clean

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = "SYMBIOTE-RECIPROCAL-ENGINEERING-001"
PROTOCOL_FILE = ROOT / "docs/RECIPROCAL_ENGINEERING_PROTOCOL_001.md"
PROTOCOL_SHA256 = "f4c35271c3211ca8023d8e4b35422e9fc19459c3cd964912d4aa1c97f8ad5e9a"
REGISTRATION_SCHEMA = "symbiote.reciprocal-engineering-registration/1"
COHORT = dict(cell_count=64,labelings=[[1,2,3,4],[3,1,4,2]],oracle_prices=[1,100000],
              fixed_branch_orders=24,deadline_seconds=1200,receipt_bytes=134217728)
TEST = "cognitive::graph_reciprocal::registered_partial_graph_reciprocal_cohort"
SMOKE_TEST = "cognitive::graph_reciprocal::partial_graph_native_reciprocity_smoke"
BOUNDS = dict(seconds=1200,evidence_bytes=128*1024*1024,source_check_seconds=15,
              cleanup_seconds=10,report_reserve_bytes=1024*1024)
require = safety.require
write_new = safety.write_new
pairs = safety.pairs
load = safety.load
sha = safety.sha


def integer(value, low=0, high=10**12):
    require(type(value) is int and low <= value <= high,"bounded integer required")
    return value


def equal(actual,expected,label):
    require(safety.encode(actual)==safety.encode(expected),label+" differs from independent recomputation")


def fresh_directory(path):
    path=canonical_path(path);temporary=canonical_path(tempfile.gettempdir())
    require(path.parent.is_dir() and temporary in path.parents and not path.exists()
            and len(str(path))<=80 and ROOT not in path.parents,"fresh short OS-temp artifact directory required")
    path.mkdir();return path


def source_check(registration):
    clean(registration["source_commit"])
    source_fingerprint.verify(ROOT,registration["source_manifest"])
    require(sha(PROTOCOL_FILE)==PROTOCOL_SHA256==registration["protocol_sha256"],"frozen protocol changed")
    require(registration["schema"]==REGISTRATION_SCHEMA and registration["protocol"]==PROTOCOL
            and registration["cohort"]==COHORT and registration["bounds"]==BOUNDS,
            "registration schema, cohort or bounds changed")
    for value in registration["binaries"].values():
        require(sha(value["path"])==value["sha256"],"registered executable changed")


def register(native,test,artifacts,commit):
    clean(commit);require(sha(PROTOCOL_FILE)==PROTOCOL_SHA256,"frozen protocol differs")
    native=canonical_path(native);test=canonical_path(test)
    require(native.is_file() and test.is_file() and test.parent==native.parent/"deps",
            "same-profile native and test executables required")
    before=source_fingerprint.manifest(ROOT)
    pins={role:dict(path=str(path),sha256=sha(path)) for role,path in (("native",native),("service_tests",test))}
    directory=fresh_directory(artifacts);processes=[]
    try:
        for label,args in (("native-version",[native,"version","--json"]),
                           ("test-list",[test,"--list","--format","terse"])):
            receipt=safety.execute(args,directory,label,timeout=30)
            processes.append(receipt);safety.check_exit(receipt)
            text=safety.output(receipt,directory)
            if label=="native-version":
                value=json.loads(text,object_pairs_hook=pairs)
                require(value["name"]=="SYMBIOTE" and value["build_source_commit"]==commit,"native source stamp differs")
            else:
                names={line.removesuffix(": test") for line in text.splitlines() if line.endswith(": test")}
                require({TEST,SMOKE_TEST}<=names,"compiled exact cohort and separate smoke cases required")
        registration=dict(schema=REGISTRATION_SCHEMA,protocol=PROTOCOL,protocol_sha256=PROTOCOL_SHA256,
                          source_commit=commit,source_manifest=before,binaries=pins,cohort=COHORT,bounds=BOUNDS,
                          artifact_directory=str(directory),preflight=processes,target_truth_opened=False,
                          scientific_samples=0,independent_host_validation="OPEN_UNAVAILABLE")
        source_check(registration)
        path=directory/"reciprocal-registration.json";write_new(path,registration)
        return dict(status="REGISTERED_NOT_RUN",registration=str(path),registration_sha256=sha(path))
    except Exception as failure:
        write_new(directory/"registration-failure.json",dict(status="HOLD",failure=str(failure),processes=processes))
        raise


def run(path,external_sha):
    path=canonical_path(path)
    require(re.fullmatch("[0-9a-f]{64}",external_sha) and sha(path)==external_sha,"registration external SHA differs")
    registration=load(path);source_check(registration)
    directory=canonical_path(registration["artifact_directory"])
    require(directory==path.parent and not (directory/"native").exists(),"registered artifact paths changed or native run already exists")
    write_new(directory/"reciprocal-started.json",dict(protocol=PROTOCOL,registration_sha256=external_sha))
    cancel=threading.Event();done=threading.Event();errors=[];old={};awake=QualificationAwake()
    started=time.monotonic()
    report=dict(schema="symbiote.reciprocal-engineering-campaign/1",status="HOLD",protocol=PROTOCOL,
                registration_sha256=external_sha,source_commit=registration["source_commit"],
                scientific_samples=0,independent_host_validation="OPEN_UNAVAILABLE")
    def check_live():
        source_check(registration)
        require(safety.evidence_size(directory)<=BOUNDS["evidence_bytes"],"whole-cohort evidence budget exceeded")
    def watch():
        while not done.wait(BOUNDS["source_check_seconds"]):
            try:check_live();awake.check()
            except Exception as failure:errors.append(str(failure));cancel.set();return
    observer=threading.Thread(target=watch,daemon=True)
    for sig in (signal.SIGINT,signal.SIGTERM):old[sig]=signal.signal(sig,lambda *_:cancel.set())
    try:
        check_live()
        with awake:
            observer.start()
            process=safety.execute([registration["binaries"]["service_tests"]["path"],TEST,"--ignored","--exact","--test-threads=1"],
                                   directory,"native-reciprocal-cohort",timeout=max(1,BOUNDS["seconds"]-(time.monotonic()-started)),
                                   cancelled=cancel.is_set,environment={"SYMBIOTE_GRAPH_RECIPROCAL_REGISTRATION":str(path),
                                   "SYMBIOTE_GRAPH_RECIPROCAL_REGISTRATION_SHA256":external_sha,
                                   "SYMBIOTE_GRAPH_RECIPROCAL_ARTIFACTS":str(directory/"native")})
            report["process"]=process
            safety.check_exit(process);safety.check_native_test(safety.output(process,directory))
            require(not cancel.is_set() and not errors,"cohort cancelled or source watch failed")
            verification=verify_cohort(directory/"native",registration)
            write_new(directory/"independent-verification.json",verification)
            report.update(status="PASS_OPERATIONAL_RECIPROCITY",verification=verification,
                          verification_sha256=sha(directory/"independent-verification.json"))
            check_live();awake.check()
    except Exception as failure:report.update(status="HOLD",failure=str(failure))
    finally:
        done.set()
        if observer.ident is not None:observer.join(timeout=2)
        for sig,handler in old.items():signal.signal(sig,handler)
        report.update(elapsed_seconds=time.monotonic()-started,source_watch_failures=errors,host_awake_guard=awake.report)
        if cancel.is_set() or errors or observer.is_alive() or report["elapsed_seconds"]>BOUNDS["seconds"]:
            report.update(status="HOLD",failure=report.get("failure","cancelled, changed source, unfinished monitor or whole-cohort deadline"))
        if safety.evidence_size(directory)+len(safety.encode(report))>BOUNDS["evidence_bytes"]:
            report.update(status="HOLD",failure="final whole-cohort receipt budget exceeded")
        write_new(directory/"reciprocal-report.json",report)
    return report


def graph_fixture(cheap,labels):
    count=len(labels)
    require(count in (2,3,4) and sorted(labels)==list(range(1,count+1))
            and type(cheap) is int and cheap in range(count),"declared graph generator input")
    edges=[];costs=[];goal=count+1;relay=count+2
    for branch,node in enumerate(labels):
        edges.extend([dict(**{"from":0,"to":node},lower=1,upper=9),dict(**{"from":node,"to":goal},lower=1,upper=9)])
        costs.extend([1 if branch==cheap else 9,1])
    edges.append(dict(**{"from":goal,"to":relay},lower=1,upper=9));costs.append(1)
    return dict(nodes=count+3,edges=edges),costs


def shortest(schema,observed,start,goal,observed_only=False):
    distances={start:0};previous={};queue=[(0,start)];work=0
    while queue:
        distance,node=heapq.heappop(queue)
        if distance!=distances[node]:continue
        if node==goal:break
        for edge_id,edge in enumerate(schema["edges"]):
            work+=1
            if edge["from"]!=node or (observed_only and edge_id not in observed):continue
            proposed=distance+observed.get(edge_id,edge["lower"])
            if proposed<distances.get(edge["to"],10**30):
                distances[edge["to"]]=proposed;previous[edge["to"]]=edge_id
                heapq.heappush(queue,(proposed,edge["to"]))
    if goal not in distances:return None,work
    route=[];cursor=goal
    while cursor!=start:
        edge_id=previous[cursor];route.append(edge_id);cursor=schema["edges"][edge_id]["from"]
    route.reverse()
    return dict(edges=route,cost=distances[goal],certified=all(edge in observed for edge in route)),work



def assess(schema,observed,start,goal):
    optimistic,work=shortest(schema,observed,start,goal)
    if optimistic is None or optimistic["certified"]:return optimistic,work
    known,extra=shortest(schema,observed,start,goal,observed_only=True)
    work+=extra
    if known is not None and known["cost"]==optimistic["cost"]:
        return known,work
    return optimistic,work


def simulate_measurement(schema,costs,targets,price,order=None,budget=None,compress_source=False,query_limit=None):
    """Independent exact Dijkstra replay, including scans and update work."""
    observed={};lookups=[];predictions=[];work=0
    provider=safety.digest(dict(schema=schema,costs=costs))
    checks=len(costs)
    def result(complete):
        return dict(lookups=lookups,model_work=work,provider_checks=checks,predictions=predictions,complete=complete)
    for target in targets:
        start,goal=divmod(target,schema["nodes"])
        while True:
            ceiling=100000 if budget is None else min(max(budget-len(lookups)*price-checks,0),100000)
            require(ceiling>=work,"independent control exceeded admitted work ceiling")
            route,used=assess(schema,observed,start,goal)
            if work+used>ceiling:
                work=ceiling;return result(False)
            work+=used
            require(route is not None,"declared control graph unexpectedly unreachable")
            if route["certified"]:
                predictions.append([target,route["cost"]]);break
            if query_limit is not None and len(lookups)>=query_limit:return result(False)
            edge=next(e for e in route["edges"] if e not in observed)
            if order is not None and start==0:
                options=[]
                for rank,branch in enumerate(order):
                    ids=[i for i,e in enumerate(schema["edges"]) if (e["from"]==0 and e["to"]==branch) or e["from"]==branch]
                    options.append((sum(observed.get(i,schema["edges"][i]["lower"]) for i in ids),rank,ids))
                ids=min(options)[2]
                edge=next((i for i in ids if i not in observed),edge)
            projected=(len(lookups)+1)*price+work+checks+1
            if budget is not None and projected>budget:return result(False)
            require(edge not in observed,"control repeated an already known edge")
            lookups.append(dict(provider_sha256=provider,sequence=len(lookups),edge_id=edge,cost=costs[edge]))
            require(work<ceiling,"model update exceeded work admission")
            work+=1;observed[edge]=costs[edge]
    if compress_source:
        # The source reconstructs its candidate map and certifies both training
        # routes, discarding non-route edge observations only from the map.
        work+=len(observed)
        for target in targets:
            route,used=assess(schema,observed,*divmod(target,schema["nodes"]))
            require(route is not None and route["certified"],"source certificate absent")
            work+=used
    return result(True)


def verify_measurement(measurement,schema,costs,targets,price,order=None,budget=None,source=False,query_limit=None):
    expected=simulate_measurement(schema,costs,targets,price,order,budget,source,query_limit)
    equal(measurement,expected,"exact independent lookup/work/certificate trace")
    return len(expected["lookups"])*price+expected["model_work"]+expected["provider_checks"]


def verify_partial_measurement(measurement,schema,costs,observations,targets):
    observed={};lookups=[];work=0;predictions=[]
    provider=safety.digest(dict(schema=schema,costs=costs))
    for item in observations:
        edge=integer(item["edge_id"],0,len(costs)-1)
        require(edge not in observed and item["cost"]==costs[edge],"wrong or duplicate transferred graph observation")
        lookups.append(dict(provider_sha256=provider,sequence=len(lookups),edge_id=edge,cost=costs[edge]))
        observed[edge]=costs[edge];work+=1
    for target in targets:
        route,used=assess(schema,observed,*divmod(target,schema["nodes"]))
        require(route and route["certified"],"partial graph did not independently certify held-out target")
        work+=used;predictions.append([target,route["cost"]])
    equal(measurement,dict(lookups=lookups,model_work=work,provider_checks=len(costs),predictions=predictions,complete=True),
          "partial map independent verification measurement")
    return work


def checked_member(root,relative):
    require(type(relative) is str and relative and "\\" not in relative and ":" not in relative,
            "portable artifact path required")
    parts=relative.split("/")
    require(all(part not in ("",".","..") for part in parts),"artifact escaped its declared root")
    cursor=Path(root)
    for part in parts:
        cursor=cursor/part;details=cursor.lstat()
        require(not cursor.is_symlink() and not getattr(details,"st_file_attributes",0)&0x400,
                "linked/reparse artifact refused")
    require(cursor.is_file(),"artifact is not a regular file")
    return cursor


def verify_executable(root,manifest,selected,role,original,expected_sha):
    """Bind exact registered bytes, accepting only a censused executable snapshot.

    A later build can replace the original path. It cannot change the registration
    hash or authorize a different external executable path in this evidence.
    """
    require(type(expected_sha) is str and re.fullmatch(r"[0-9a-f]{64}",expected_sha)
            and manifest[role+"_sha256"]==expected_sha,"registered executable SHA differs")
    declared=Path(manifest[role]);original=canonical_path(original)
    require(declared.is_absolute(),"absolute executable provenance required")
    actual=canonical_path(declared)
    if actual==original and root not in actual.parents:
        require(actual.is_file() and sha(actual)==expected_sha,"original executable bytes differ")
        return None
    try:relative=declared.relative_to(root).as_posix()
    except ValueError:raise RuntimeError("executable reassigned outside the artifact snapshot") from None
    parts=relative.split("/")
    names=("symbiote","symbiote.exe") if role=="native_binary" else ("service-tests","service-tests.exe")
    require(len(parts)==2 and parts[0]=="executables" and parts[1] in names and relative in selected,
            "bounded censused executable snapshot required")
    snapshot=checked_member(root,relative)
    require(canonical_path(snapshot)==actual and sha(snapshot)==expected_sha,
            "preserved executable differs from registered bytes")
    return relative


def verify_manifest(root,native,native_sha,service_tests=None):
    root=canonical_path(root);native=canonical_path(native)
    require(root.is_dir(),"artifact directory absent")
    manifest=load(checked_member(root,"artifact-manifest.json"))
    require(manifest["schema"]=="symbiote.partial-graph-native-artifacts/1"
            and manifest["private_keys_copied"] is False
            and manifest["native_binary_sha256"]==native_sha,"native artifact provenance differs")
    files=manifest["files"];require(type(files) is list and 1<=len(files)<=20000,"bounded complete artifact inventory required")
    selected=set();total=0;paths={}
    for row in files:
        relative=row["path"].replace("\\","/")
        require(relative not in selected,"duplicate artifact member")
        selected.add(relative);path=checked_member(root,relative)
        count=integer(row["bytes"],0,BOUNDS["evidence_bytes"]);total+=count
        require(total<=BOUNDS["evidence_bytes"] and path.stat().st_size==count and sha(path)==row["sha256"],
                "artifact byte inventory differs")
        require(path.suffix.lower() not in {".key",".pfx",".p12"},"private credential file in public artifacts")
        paths[relative]=path
    actual=set()
    for directory,directories,names in os.walk(root,followlinks=False):
        for name in directories:
            details=(Path(directory)/name).lstat()
            require(not (Path(directory)/name).is_symlink() and not getattr(details,"st_file_attributes",0)&0x400,
                    "linked artifact directory refused")
        for name in names:actual.add((Path(directory)/name).relative_to(root).as_posix())
    equal(sorted(actual),sorted(selected|{"artifact-manifest.json"}),"full artifact file census")
    executable_members={verify_executable(root,manifest,selected,"native_binary",native,native_sha)}
    if service_tests is not None:
        executable_members.add(verify_executable(root,manifest,selected,"service_tests",service_tests["path"],service_tests["sha256"]))
    for relative,path in paths.items():
        # Only exact independently pinned executable bytes may contain their
        # compiled PEM scanner/rejection literals. This is no .exe-wide waiver.
        if relative in executable_members:continue
        raw=path.read_bytes()
        require(not any(marker in raw for marker in (b"-----BEGIN PRIVATE KEY-----",b"-----BEGIN RSA PRIVATE KEY-----",b"-----BEGIN EC PRIVATE KEY-----")),
                "private key in public artifacts (executable copies require an independent exact SHA pin)")
    return manifest



def verify_restart(first,again):
    require(first["schema"]==again["schema"]=="symbiote.cognition-summary/1"
            and first["status"]==again["status"]=="STOPPED","actual native run/restart summaries required")
    require(integer(first["fresh_promotions"])==2 and integer(again["fresh_promotions"])==0
            and integer(first["active_models"])==integer(again["active_models"])==2,
            "restart must retain nonempty knowledge without a new promotion")
    require(first["identity"]==again["identity"] and first["identity"],"restart identity changed")
    equal(again["initial_knowledge_anchor"],first["final_knowledge_anchor"],"actual restart initial retained anchor")
    equal(again["final_knowledge_anchor"],again["initial_knowledge_anchor"],"restart must not rewrite learned knowledge")


def verify_process_restart(before,after,owner):
    equal(before["identity"],owner,"initial actual process owner")
    equal(after["identity"],owner,"restarted actual process owner")
    require(integer(before["pid"],1)!=integer(after["pid"],1),"native process was not actually restarted")


def knowledge_records(root,role,worlds,expected_owner=None):
    state=Path(root)/(role+"-state")
    _,identity=safety.identity_chain(state/"ledger.jsonl")
    owner=identity[0]["payload"]["identity"]
    if expected_owner is not None:equal(owner,expected_owner,"persistent actual owner")
    _,knowledge=safety.knowledge_chain(state/"knowledge.jsonl")
    require(knowledge[0]["payload"]["identity"]==owner,"knowledge/identity owner mismatch")
    promotions=[row["payload"] for row in knowledge if row["payload"]["event"]=="promote_graph"]
    require(len(knowledge)==3 and len(promotions)==2,"two active nonempty graph models required; no hidden revocation")
    models={row["record"]["scope"]:row for row in promotions}
    equal(sorted(models),sorted(worlds),"both declared graph scopes retained")
    for scope,promotion in models.items():
        world=worlds[scope];record=promotion["record"];payload=record["payload"]
        equal(payload,dict(kind="graph-map",**world["source_map"]),"retained exact partial graph payload")
        equal(record["schema_fingerprint"],safety.digest(dict(kind="finite-positive-cost-directed-graph",version=1,
              query_encoding="start*nodes+goal",schema=payload["schema"])),"retained graph schema fingerprint")
        assessment=promotion["assessment"];evidence=assessment["evidence"]
        training=[row["input"] for row in evidence["training_tasks"]]
        goal=payload["schema"]["nodes"]-2;relay=goal+1;n=payload["schema"]["nodes"]
        equal(training,[goal,goal*n+relay],"disjoint source training task contract")
        require([case["input"] for case in evidence["cases"]]==[relay],"nonempty distinct held-out task required")
        for case in evidence["cases"]:
            equal(case["expected"],3,"finite held-out truth")
            equal(case["candidate"],3,"correct retained held-out certificate")
        observations=payload["observations"]
        require(len(evidence["acquisitions"])==len(observations)==3,"exact independently observed partial map proof required")
        for sequence,(acquisition,observation) in enumerate(zip(evidence["acquisitions"],observations)):
            equal(acquisition["edge_id"],observation["edge_id"],"acquisition edge binding")
            equal(acquisition["cost"],observation["cost"],"acquisition cost binding")
            envelope=acquisition["receipt"]
            equal(envelope["observer_identity"],owner,"independent local observer")
            equal(envelope["sequence"],sequence,"local acquisition order")
            equal(acquisition["receipt_sha256"],safety.digest(envelope),"complete acquisition envelope hash")
            require(envelope["context"]==scope and envelope["schema_fingerprint"]==record["schema_fingerprint"],"acquisition applicability binding")
    _,operations=safety.operational_chain(state/"operations.jsonl",owner)
    return owner,models,operations


TRAFFIC_FIELDS=("rpc_sent_bytes","rpc_received_bytes","negotiation_sent_bytes","negotiation_received_bytes")
SCOPES=("reciprocal-x/v1","reciprocal-y/v1")


def traffic(value):
    require(type(value) is dict,"actual plaintext traffic snapshot required")
    return sum(integer(value[field],0,BOUNDS["evidence_bytes"]) for field in TRAFFIC_FIELDS)


def traffic_pair(client,server):
    for left,right in (("rpc_sent_bytes","rpc_received_bytes"),("rpc_received_bytes","rpc_sent_bytes"),
                       ("negotiation_sent_bytes","negotiation_received_bytes"),("negotiation_received_bytes","negotiation_sent_bytes")):
        equal(integer(client[left]),integer(server[right]),"endpoint plaintext byte conservation")


def traffic_sum(rows):
    return {field:sum(integer(row[field]) for row in rows) for field in TRAFFIC_FIELDS}


def execution(value,price,worlds):
    require(value["schema"]=="symbiote.graph-execution/1","actual global execution meter required")
    known={safety.digest(dict(schema=w["source_map"]["schema"],costs=w["costs"])):w["costs"] for w in worlds.values()}
    previous={}
    for row in value["lookups"]:
        require(row["provider_sha256"] in known,"unregistered private oracle in execution trace")
        costs=known[row["provider_sha256"]];edge=integer(row["edge_id"],0,len(costs)-1)
        equal(row["cost"],costs[edge],"actual metered local truth lookup")
        sequence=integer(row["sequence"],0,32767);prior=previous.get(row["provider_sha256"])
        require(sequence==0 or prior is not None and sequence==prior+1,"oracle instance sequence has a gap")
        previous[row["provider_sha256"]]=sequence
    return len(value["lookups"])*price+integer(value["provider_checks"])+integer(value["direct_model_work"])+integer(value["graph_forecast_work"])


def stop_units(value):
    return traffic(value["plaintext_traffic"])+integer(value["graph_forecast_work"])


def client_units(value):
    meter=value["client_execution"]
    return traffic(meter["plaintext_traffic"])+integer(meter["graph_forecast_work"])


def actor_units(value,price,worlds):
    return execution(value["graph_execution"],price,worlds)+traffic(value["outbound_plaintext_traffic"])+traffic(value["inbound_plaintext_traffic"])+integer(value["inbound_graph_forecast_work"])+integer(value["fresh_promotions"])


def scoped_measurements(value,world,price):
    map_=world["source_map"];n=map_["schema"]["nodes"]
    measured=value["graph_measurement"]
    verify_partial_measurement(measured,map_["schema"],world["costs"],map_["observations"],[n-1])
    record=value["evaluation_record"]
    require(record["schema"]=="symbiote.scoped-evaluation/1","explicit scoped candidate/control evidence required")
    equal(record["oracle_price"],price,"registered local oracle price")
    equal(record["candidate_measurement"],measured,"candidate measurement envelope")
    baseline=record["measured_task_baseline"]
    baseline_units=verify_measurement(baseline["measurement"],map_["schema"],world["costs"],[n-1],price)
    equal(baseline["units"],baseline_units,"actual private isolated baseline cost")
    equal(baseline["evidence_sha256"],safety.digest(baseline["measurement"]),"actual private baseline evidence binding")
    require(value["feedback_baseline"]["kind"]=="unknown" and record["unavailable_cost_components"],
            "a task-only measured control cannot fabricate a whole-process matched baseline")
    validation=len(measured["lookups"])*price+measured["model_work"]+measured["provider_checks"]
    equal(record["candidate_local_costs"]["validation"],validation,"independent candidate local validation cost")
    require(record["control_execution_in_candidate_process_meter"] is True,"actual private baseline compute must remain charged")
    return measured,baseline["measurement"]


def verify_evaluation(value,world,price,worlds):
    require(value["status"]=="PROMOTED" and value["promoted"] is True,"receiver independently adopted no useful graph model")
    measured,baseline=scoped_measurements(value,world,price)
    meter=value["execution_meter"]
    equal(meter["lookups"],[*measured["lookups"],*baseline["lookups"]],"all actual receiver candidate/control oracle queries")
    equal(meter["direct_model_work"],measured["model_work"]+baseline["model_work"],"all actual receiver candidate/control reasoning work")
    equal(meter["provider_checks"],measured["provider_checks"]+baseline["provider_checks"],"candidate and private control provider initialization checks")
    verify_timing(value["stage_timing"],required=("compute","io","evaluation","replay"))
    return execution(meter,price,worlds)+1


def verify_timing(report,pid=None,required=()):
    require(report["schema"]=="symbiote.stage-timing/1" and report["logical_cost_or_reward_input"] is False
            and report["overlapping_totals_are_additive"] is False
            and report["deterministic_or_exclusive_cpu_time"] is False,"stage diagnostics must remain separate from logical costs/rewards")
    if pid is not None:equal(report["pid"],pid,"stage diagnostics process identity")
    names=["compute","lock_wait","io","evaluation","replay","shutdown"]
    equal(sorted(row["stage"] for row in report["stages"]),sorted(names),"bounded fixed timing stages")
    observed={};warnings=[]
    for row in report["stages"]:
        stage=row["stage"];started=integer(row["started"]);completed=integer(row["completed"])
        require(completed<=started,"completed stage count exceeds started operations")
        equal(row["in_flight"],started-completed,"reported timing span lifecycle")
        elapsed=integer(row["monotonic_elapsed_ns"],0,2**64-1)
        maximum=integer(row["max_monotonic_elapsed_ns"],0,2**64-1)
        require(maximum<=elapsed,"maximum span exceeds cumulative inclusive time")
        integer(row["wall_elapsed_ns"],0,2**64-1)
        for field in ("min_started_wall_unix_ns","max_completed_wall_unix_ns"):
            if row[field] is not None:integer(row[field],1,2**64-1)
        if row["saturated"] or row["wall_clock_regressions"] or row["wall_clock_unavailable"]:warnings.append(stage)
        observed[stage]=dict(completed=completed,monotonic_elapsed_ns=elapsed)
    for stage in required:
        require(observed[stage]["completed"]>0 and observed[stage]["monotonic_elapsed_ns"]>0,
                "required actual stage diagnostics missing: "+stage)
    return dict(stages=observed,clock_or_saturation_warnings=warnings,
                interpretation="inclusive overlapping hardware diagnostics; never added to declared logical task costs")


def verify_run_files(root,prefix,summary):
    equal(load(root/prefix/"summary.json"),summary,"native summary raw receipt")
    events=[json.loads(line,object_pairs_hook=pairs) for line in (root/prefix/"events.jsonl").read_bytes().splitlines()]
    stdout=[json.loads(line,object_pairs_hook=pairs) for line in (root/(prefix+"-stdout.jsonl")).read_bytes().splitlines()]
    equal(stdout,[*events,summary],"actual native stdout/events/summary binding")
    equal([event["sequence"] for event in events],list(range(len(events))),"ordered native cognitive cycle")
    require(not any(event["phase"]=="HOLD" for event in events),"native cognitive run reported HOLD")
    return events


def verify_cell(root,cell,cohort_cell=None,normal=False):
    root=Path(root);require(cell["schema"]=="symbiote.partial-graph-cell/1","cell schema differs")
    if normal:require(cell["mode"]=="normal_capability_goal","normal policy receipt required")
    price=integer(cell["oracle_price"],1,100000);require(price in COHORT["oracle_prices"],"unregistered oracle price")
    labels=cell["labels"];cheap=cell["cheap_indices"]
    require(len(cheap)==2 and len(cell["worlds"])==len(cell["sources"])==2,"exactly two independent task contexts required")
    if cohort_cell is not None:equal([price,labels,cheap],list(cohort_cell),"prospective cell enumeration")
    worlds={};greedy_units={};fixed_units={};equal_query_complete={};control_execution_units=0
    for index,world in enumerate(cell["worlds"]):
        scope=SCOPES[index];equal(world["scope"],scope,"declared context order")
        equal(world["cheap_index"],cheap[index],"fixed cheap branch position");equal(world["labels"],labels,"fixed branch labels")
        schema,costs=graph_fixture(cheap[index],labels);n=schema["nodes"];goal=n-2;target=n-1
        source=cell["sources"][index];equal(source["scope"],scope,"source context applicability")
        observations=[dict(edge_id=i,cost=1) for i in [2*cheap[index],2*cheap[index]+1,len(costs)-1]]
        expected_map=dict(schema=schema,observations=observations)
        equal(source["source_map"],expected_map,"exact partial source map with unknown intervals retained")
        fixture=load(root/("partial-"+str(index)+".json"))
        equal(fixture["schema"],"symbiote.local-truth/2","operator local truth schema")
        equal(fixture["scope"],scope,"operator local truth context")
        equal(fixture["family"],dict(kind="graph",schema=schema,costs=costs),"finite predeclared graph truth")
        equal(fixture["task_contract"],dict(schema="symbiote.partial-graph-task/1",training_inputs=[goal,goal*n+target],heldout_inputs=[target],oracle_price=price,experiment_authorized=not normal,max_experimental_offers=0 if normal else 1),"explicit finite task authorization")
        source_units=verify_measurement(source["source_discovery"],schema,costs,[goal,goal*n+target],price,source=True)
        controls=world["controls"]
        greedy_units[scope]=verify_measurement(controls["greedy"],schema,costs,[target],price)
        orders=list(itertools.permutations(labels));require(len(controls["fixed_orders"])==len(orders),"complete fixed-order controls required")
        fixed_units[scope]=[]
        for order,row in zip(orders,controls["fixed_orders"]):
            equal(row["order"],list(order),"fixed strategy enumeration before truth")
            fixed_units[scope].append(verify_measurement(row["measurement"],schema,costs,[target],price,order=list(order)))
        equal(controls["equal_query"]["query_limit"],3,"matched query limit")
        equal_units=verify_measurement(controls["equal_query"]["measurement"],schema,costs,[target],price,query_limit=3)
        control_execution_units+=greedy_units[scope]+sum(fixed_units[scope])+equal_units
        equal_query_complete[scope]=controls["equal_query"]["measurement"]["complete"]
        worlds[scope]=dict(source_map=expected_map,costs=costs,source_units=source_units)
    owners={};models={};operations={}
    for role in ("actor","server","client"):
        owners[role],models[role],operations[role]=knowledge_records(root,role,worlds)
        config=load(root/(role+".json"));equal(config["identity"],owners[role],"configured private owner")
        for context in config["contexts"]:
            idx=SCOPES.index(context["scope"])
            equal(context["truth_sha256"],sha(root/("partial-"+str(idx)+".json")),"explicit local truth pin")
        if role=="actor":
            require({peer["id"] for peer in config["peers"]}=={cell["partner_identities"][0],cell["partner_identities"][1]},"explicit authorized endpoint discovery")
    require(len(set(owners.values()))==3,"three private independent owner identities required")
    equal([owners["server"],owners["client"]],cell["partner_identities"],"private partner identities")
    equal(owners["actor"],cell["identity"],"central actual identity")
    first,again=cell["native_first"],cell["native_restart"]
    verify_restart(first,again);equal(first["identity"],owners["actor"],"actor learning owner")
    equal(first["quarantined_contributions"],2,"actual two-way native return payloads")
    equal(again["quarantined_contributions"],0,"restart cannot duplicate experimental offers")
    equal(again["graph_execution"]["lookups"],[],"retained central replay must make zero oracle queries")
    events=verify_run_files(root,"native-first",first);restart_events=verify_run_files(root,"native-restart",again)
    require(events and restart_events and events[0]["phase"]==restart_events[0]["phase"]=="READY",
            "actual native process readiness receipts required")
    verify_process_restart(events[0]["details"],restart_events[0]["details"],owners["actor"])
    timing_first=verify_timing(first["stage_timing"],events[0]["details"]["pid"],("compute","lock_wait","io","evaluation","replay","shutdown"))
    timing_restart=verify_timing(again["stage_timing"],restart_events[0]["details"]["pid"],("compute","lock_wait","io","replay","shutdown"))
    for ready in (events[0]["details"],restart_events[0]["details"]):
        equal(ready["identity"],owners["actor"],"restarted central owner")
        require(ready["language_model_required"] is False,"native operational proof requires no language model")
    _,actor_history=safety.knowledge_chain(root/"actor-state/knowledge.jsonl")
    equal(first["final_knowledge_anchor"],dict(identity=owners["actor"],records=len(actor_history),head_sha256=actor_history[-1]["sha256"]),"native retained anchor binds actual owner history")
    for index,scope in enumerate(SCOPES):
        equal(models["actor"][scope]["record"]["source"],owners["server" if index==0 else "client"],"authenticated acquired source owner")
    expected_lookups=[];expected_work=expected_checks=0
    verification_events=[event for event in events if event["phase"]=="VERIFY"]
    equal(sorted(event["details"]["scope"] for event in verification_events),sorted(SCOPES),"two distinct independently evaluated central contexts")
    for event in verification_events:
        scope=event["details"]["scope"]
        source=cell["sources"][SCOPES.index(scope)]
        measured,baseline=scoped_measurements(source["evaluation"],worlds[scope],price)
        expected_lookups.extend([*measured["lookups"],*baseline["lookups"]])
        expected_work+=measured["model_work"]+baseline["model_work"]
        expected_checks+=measured["provider_checks"]+baseline["provider_checks"]
    equal(first["graph_execution"]["lookups"],expected_lookups,"all actual central candidate/control queries")
    equal(first["graph_execution"]["direct_model_work"],expected_work,"all actual central candidate/control reasoning work")
    equal(first["graph_execution"]["provider_checks"],expected_checks,"all central candidate/control provider initialization checks")
    experiments=[event for event in events if event["phase"]=="EXPERIMENT"]
    offers=[event for event in events if event["phase"]=="CONTRIBUTE" and event["details"].get("quarantined_offer") is True]
    if normal:
        policy=load(root/"run-policy.json");require(policy["capability_contributions"] is True,"normal capability objective requires explicit operator opt-in")
        opportunities=[event for event in events if event["phase"]=="CAPABILITY_OPPORTUNITY"]
        require(not experiments and len(opportunities)==len(offers)==2,"normal quality goals cannot use experimental override")
        for offer in offers:
            require(offer["details"]["capability_objective"] is True and offer["details"]["experimental_override"] is False,
                    "normal return payload must use the declared capability goal")
            matches=[event for event in opportunities if event["sequence"]<offer["sequence"] and event["details"]["scope"]==offer["details"]["scope"] and event["details"]["peer"]==offer["details"]["peer"]]
            require(len(matches)==1,"one prior exact capability opportunity required")
            opportunity=matches[0]["details"];goal=opportunity["opportunity"]["goal"];scope=goal["scope"];index=SCOPES.index(scope)
            equal(goal,dict(schema="symbiote.public-task-contract/1",scope=scope,schema_fingerprint=models["actor"][scope]["record"]["schema_fingerprint"],
                           fixture_sha256=sha(root/("partial-"+str(index)+".json")),heldout_inputs=[worlds[scope]["source_map"]["schema"]["nodes"]-1]),"normal pinned public goal")
            equal(opportunity["opportunity"]["contract_sha256"],safety.digest(goal),"public goal exact binding")
            equal(opportunity["opportunity"]["receiver_union"],dict(schema=worlds[scope]["source_map"]["schema"],observations=[]),"fixture receiver previously lacks the scoped facts")
            equal(opportunity["opportunity"]["inventory_record_sha256"],[],"fixture receiver initially has no scoped model")
            equal(opportunity["opportunity"]["certified_new_inputs"],[[goal["heldout_inputs"][0],3]],"new held-out certificate")
            require(opportunity["cost_benefit_verified"] is False and opportunity["local_monetary_utility"] is None and opportunity["remote_monetary_utility"] is None,
                    "capability authorization cannot fabricate bilateral economic utility")
    else:
        require(len(experiments)==len(offers)==2 and all(event["details"]["gain_qualified"] is False for event in experiments),"explicit uncertain-value experimental decisions required")
        for offer in offers:
            require(any(event["sequence"]<offer["sequence"] and event["details"].get("scope")==offer["details"]["scope"] for event in experiments),"experimental budget/decision must precede its payload")
    traffic_pair(first["outbound_plaintext_traffic"],traffic_sum([row["plaintext_traffic"] for row in cell["first_stops"]]))
    traffic_pair(again["outbound_plaintext_traffic"],traffic_sum([row["plaintext_traffic"] for row in cell["restart_stops"]]))
    common=[0,0,0]
    for index,source in enumerate(cell["sources"]):
        role="server" if index==0 else "client";caller=2 if index==0 else 1
        equal(source["role"],role,"source discovery owner")
        traffic_pair(source["submit"]["client_execution"]["plaintext_traffic"],source["service_stop"]["plaintext_traffic"])
        common[index+1]+=worlds[SCOPES[index]]["source_units"]+verify_evaluation(source["evaluation"],worlds[SCOPES[index]],price,worlds)+stop_units(source["service_stop"])
        common[caller]+=client_units(source["submit"])
    exchanged=list(common);exchanged[0]+=actor_units(first,price,worlds)+actor_units(again,price,worlds)
    for index in range(2):exchanged[index+1]+=stop_units(cell["first_stops"][index])+stop_units(cell["restart_stops"][index])
    require(len(cell["return_evaluations"])==len(cell["retained_predictions"])==2,"two adopted and restarted receiver contributions required")
    equal(sorted(row["role"] for row in cell["return_evaluations"]),["client","server"],"independent adoption by each distinct partner")
    equal(sorted(row["role"] for row in cell["retained_predictions"]),["client","server"],"actual restart of each distinct receiver")
    for returned in cell["return_evaluations"]:
        role=returned["role"];index=1 if role=="server" else 2
        require(role in ("server","client"),"return receiver role")
        scope=SCOPES[1] if role=="server" else SCOPES[0]
        equal(returned["scope"],scope,"cross-scope reciprocal capability extension")
        exchanged[index]+=verify_evaluation(returned["evaluation"],worlds[scope],price,worlds)
        promotion=models[role][scope];equal(promotion["record"]["source"],owners["actor"],"actual return source identity")
        equal(returned["evaluation"]["artifact"],promotion["record"]["id"],"receiver evaluation binds actual promoted artifact")
        equal(returned["evaluation"]["record_sha256"],safety.record_digest(promotion["record"]),"receiver evaluation binds actual promoted record bytes")
        # The completed event's record digest is the canonical ledger model.
        require(any(row["payload"]["event"]=="evaluation_completed" and row["payload"]["record_sha256"]==safety.record_digest(promotion["record"]) for row in operations[role]),"return adoption lacks a durable operational completion")
    for retained in cell["retained_predictions"]:
        role=retained["role"];index=1 if role=="server" else 2;caller=2 if index==1 else 1
        verify_process_restart(cell["first_ready"][index-1],retained["ready"],owners[role])
        scope=SCOPES[1] if role=="server" else SCOPES[0]
        equal(retained["scope"],scope,"retained reciprocal applicability")
        equal(retained["ready"]["identity"],owners[role],"receiver restart retains actual owner identity")
        equal(cell["first_ready"][index-1]["identity"],owners[role],"receiver initial actual owner identity")
        prediction=retained["prediction"];record=models[role][scope]["record"]
        equal(prediction["artifact"],record["id"],"retained prediction uses actual adopted return")
        equal(prediction["record_sha256"],safety.record_digest(record),"retained prediction binds exact return record")
        world=worlds[scope];observed={item["edge_id"]:item["cost"] for item in world["source_map"]["observations"]}
        route,_=assess(world["source_map"]["schema"],observed,0,world["source_map"]["schema"]["nodes"]-1)
        equal(prediction["route"]["edges"],route["edges"],"retained exact route certificate")
        require(prediction["prediction"]==3 and type(prediction["prediction"]) is int and prediction["conditional"] is True,"nonempty correct retained conditional prediction required")
        traffic_pair(prediction["client_execution"]["plaintext_traffic"],retained["service_stop"]["plaintext_traffic"])
        exchanged[index]+=stop_units(retained["service_stop"]);exchanged[caller]+=client_units(prediction)
    wrong=cell["wrong_control"];require(wrong["evaluation"]["status"]=="REJECTED" and wrong["evaluation"]["promoted"] is False,"actual wrong-map rejection control required")
    equal(len(wrong["evaluation"]["execution_meter"]["lookups"]),1,"wrong map rejection must independently observe its contradictory edge")
    wrong_units=execution(wrong["evaluation"]["execution_meter"],price,worlds)+stop_units(wrong["service_stop"])+client_units(wrong["submit"])
    participants=[];matched_execution_units=0;require(len(cell["participants"])==3,"all participant cost accounts required")
    for index,(role,targets,row) in enumerate(zip(("actor","server","client"),((SCOPES[0],SCOPES[1]),(SCOPES[1],),(SCOPES[0],)),cell["participants"])):
        equal(row["role"],role,"participant cost owner");equal(row["target_scopes"],list(targets),"participant independent targets")
        equal(row["common_source_units"],common[index],"actual source/replay/wire common costs")
        equal(row["exchange_units"],exchanged[index],"all actual exchange/replay/wire/adoption costs")
        greedy=common[index]+sum(greedy_units[scope] for scope in targets)
        fixed=[common[index]+sum(fixed_units[scope][order] for scope in targets) for order in range(len(next(iter(fixed_units.values()))))]
        equal(row["greedy_units"],greedy,"independent isolated full task costs");equal(row["fixed_units"],fixed,"independent all-fixed task costs")
        remaining=exchanged[index]-common[index];equal(row["matched_resource_budget"],remaining,"identical exchange task resource ceiling")
        require(len(row["matched_resource"])==len(targets),"all matched-resource target controls required")
        matched_complete=True;matched_units=common[index]
        for scope,control in zip(targets,row["matched_resource"]):
            equal(control["scope"],scope,"matched-resource target scope");equal(control["budget"],remaining,"sequential matched-total-resource budget")
            world=worlds[scope];units=verify_measurement(control["measurement"],world["source_map"]["schema"],world["costs"],[world["source_map"]["schema"]["nodes"]-1],price,budget=remaining)
            require(units<=remaining,"matched control overspent declared ceiling")
            remaining-=units;matched_units+=units;matched_execution_units+=units;matched_complete &= control["measurement"]["complete"]
        participants.append(dict(role=role,baseline_kind="measured",exchange_units=exchanged[index],greedy_units=greedy,fixed_units=fixed,
                                 matched_resource_units=matched_units,matched_resource_complete=matched_complete,
                                 conditional_saving_vs_greedy=greedy-exchanged[index]))
    return dict(status="PASS_OPERATIONAL_RECIPROCITY",oracle_price=price,labels=labels,cheap_indices=cheap,
                participants=participants,equal_query_complete=equal_query_complete,wrong_control_units=wrong_units,
                stage_timing=dict(first=timing_first,restart=timing_restart),
                control_execution_units=control_execution_units,matched_control_execution_units=matched_execution_units,
                total_native_engineering_execution_units=sum(exchanged)+wrong_units+control_execution_units+matched_execution_units,
                scientific_samples=0,independent_host_validation="OPEN_UNAVAILABLE")


def verify_cohort(root,registration):
    root=canonical_path(root);native=registration["binaries"]["native"]
    manifest=verify_manifest(root,native["path"],native["sha256"],registration["binaries"]["service_tests"])
    report=load(root/"cohort.json");equal(manifest["report"],report,"actual native cohort report")
    require(report["schema"]=="symbiote.partial-graph-cohort/1" and report["completed"]==64 and len(report["cells"])==64,"complete registered cohort required")
    equal(report["registration_sha256"],sha(root/"registration.json"),"native external registration bytes")
    equal(load(root/"registration.json"),registration,"registered final source/binary/cohort contract")
    expected=[(price,labels,[x,y]) for price in COHORT["oracle_prices"] for labels in COHORT["labelings"] for x in range(4) for y in range(4)]
    cells=[]
    for index,(entry,parameters) in enumerate(zip(report["cells"],expected)):
        equal(entry["path"],f"cell-{index:03}/cell.json","complete original prospective cell order")
        path=checked_member(root,entry["path"]);equal(sha(path),entry["sha256"],"actual per-cell raw receipt")
        cells.append(verify_cell(path.parent,load(path),parameters))
    result=aggregate(cells,"REGISTERED_FINITE_ENGINEERING_COHORT")
    result.update(native_binary_sha256=native["sha256"],artifact_manifest_sha256=sha(root/"artifact-manifest.json"),
                  consumer_source_sha256=sha(Path(__file__)),protocol_sha256=PROTOCOL_SHA256,
                  registration_sha256=report["registration_sha256"])
    return result


def aggregate(cells,classification):
    roles={}
    for role in ("actor","server","client"):
        rows=[p for cell in cells for p in cell["participants"] if p["role"]==role]
        total_exchange=sum(row["exchange_units"] for row in rows)
        fixed=[sum(row["fixed_units"][i] for row in rows) for i in range(len(rows[0]["fixed_units"]))]
        matched_explains=all(row["matched_resource_complete"] and row["matched_resource_units"]<=row["exchange_units"] for row in rows)
        roles[role]=dict(baseline_kind="measured",exchange_units=total_exchange,greedy_units=sum(row["greedy_units"] for row in rows),
                         each_fixed_order_units=fixed,
                         efficiency_vs_all_fixed_orders="CONDITIONAL_AGGREGATE_GAIN" if total_exchange<min(fixed) else "NOT_DEMONSTRATED",
                         matched_resource_explains_all=matched_explains,
                         efficiency_vs_matched_resource="NOT_DEMONSTRATED" if matched_explains else "NOT_ESTABLISHED_BY_THIS_AGGREGATE")
    return dict(schema="symbiote.reciprocal-engineering-independent/1",status="PASS_OPERATIONAL_RECIPROCITY",
                classification=classification,cells=len(cells),participants=roles,cell_results=cells,
                total_native_engineering_execution_units=sum(cell["total_native_engineering_execution_units"] for cell in cells),
                scientific_samples=0,independent_host_validation="OPEN_UNAVAILABLE",
                limitations=["finite related controls, not independent samples","local truth and instrumented counters are trusted within this same-host engineering envelope",
                             "plaintext counters are checked across both endpoints; cryptographic framing and hardware cost are separate diagnostics",
                             "observed capability extension does not imply net research-campaign profit or generalized efficiency",
                             "total native declared units include all separately executed controls and negative tests; Python audit/hardware/cryptographic work is not converted into those units"])


def feedback_carrier_digest(envelope):
    # Carrier IDs were serialized from typed Rust structs (declaration order),
    # unlike the sorted JSON Values used by journal/payload SHA bindings.
    def ordered(value):
        if isinstance(value,list):return [ordered(item) for item in value]
        if not isinstance(value,dict):return value
        if "phase" in value:
            variants={"decision":"binding before baseline","promoted":"exchange_id record_sha256 before after evidence_sha256 promotion_sha256 costs baseline",
                      "store_use":"exchange_id record_sha256 knowledge_at input output model_work sequence basis",
                      "cost_observation":"exchange_id measurement","outcome":"exchange_id knowledge_at outcome"}
            require(value["phase"] in variants,"unknown normal feedback phase")
            keys=["phase",*variants[value["phase"]].split()]
        elif value.get("schema")=="symbiote.learning-feedback/1":keys="schema scope event".split()
        elif value.get("schema")=="symbiote.received-task-cost/1":keys="schema scope sender boundary evaluation_sha256 acquisition_sha256 before after lookups baseline costs private_control_audit_units accounting_boundary".split()
        elif "origin" in value:keys="origin exchange_id decision_id sender_id receiver_id scope schema_fingerprint request_sha256 candidate_id offered_record_sha256 policy_sha256 fixture_sha256".split()
        elif "identity" in value:keys="identity records head_sha256".split()
        elif "graph_forecast_work" in value:keys="lookups provider_checks direct_model_work graph_forecast_work".split()
        elif "prefix_sha256" in value:keys="owner events prefix_sha256".split()
        elif "quality" in value:keys="quality baseline candidate_cost measured_net verified_benefit uses unit_model".split()
        elif "unit_model" in value:keys="unit_model acquisition validation adoption prediction wire replay".split()
        elif "provider_sha256" in value:keys="provider_sha256 sequence edge_id cost".split()
        elif "kind" in value:
            variants={"measured":"units evidence_sha256","estimate":"units basis","unknown":"reason","retained_evaluation":"evidence_sha256","conditional_family":"family"}
            require(value["kind"] in variants,"unknown typed baseline/use basis")
            keys=["kind",*variants[value["kind"]].split()]
        else:raise RuntimeError("unknown typed feedback object")
        equal(sorted(value),sorted(keys),"closed typed feedback fields")
        return {key:ordered(value[key]) for key in keys}
    return hashlib.sha256(json.dumps(ordered(envelope),ensure_ascii=False,separators=(",",":")).encode()).hexdigest()


def feedback_groups(rows):
    groups={}
    for position,row in enumerate(rows):
        if row.get("event")!="partner_decision_recorded":continue
        decision=row["decision"];envelope=decision["details"]
        schema=envelope.get("schema","")
        if type(schema) is str and schema.startswith("symbiote.learning-feedback/"):
            require(schema=="symbiote.learning-feedback/1","unsupported learning feedback namespace version")
        if schema!="symbiote.learning-feedback/1":continue
        event=envelope["event"];phase=event["phase"]
        exchange=event["binding"]["exchange_id"] if phase=="decision" else event["exchange_id"]
        require(re.fullmatch(r"[0-9a-f]{64}",exchange) and decision["selected_peer"] is None and decision["frontier_edge"] is None,
                "feedback carrier participant binding differs")
        equal(decision["decision_id"],"feedback-"+feedback_carrier_digest(envelope),"typed feedback carrier digest")
        equal(decision["context"],envelope["scope"],"feedback carrier scope")
        group=groups.setdefault(exchange,[]);expected=("decision","promoted","store_use","cost_observation","outcome")
        require(len(group)<len(expected) and phase==expected[len(group)],"feedback phase missing, swapped or duplicated credit")
        if group:equal(envelope["scope"],group[0][1]["binding"]["scope"],"exchange feedback applicability")
        group.append((position,event))
    require(len(groups)==2 and all(len(group)==5 for group in groups.values()),"both complete actual causal feedback chains required")
    return groups


def scoped_outcome(measurement,validation,baseline,prediction_work,wire):
    """Recompute finite-window arithmetic without accepting producer benefit/net."""
    before,after=measurement["before"],measurement["after"]
    delta_forecast=integer(after["graph_forecast_work"])-integer(before["graph_forecast_work"])
    require(delta_forecast>=prediction_work,"task forecast meter regressed or excludes actual use")
    costs=dict(unit_model="received-graph-task-sense-through-first-use/1",acquisition=0,adoption=1,
               validation=validation,prediction=prediction_work,wire=wire,replay=delta_forecast-prediction_work)
    equal(measurement["costs"],costs,"scoped candidate cost decomposition")
    total=sum(integer(costs[field],0,10**9) for field in ("acquisition","adoption","validation","prediction","wire","replay"))
    require(total<=10**9,"finite task cost exceeds bounded units")
    net=integer(baseline["units"],0,10**9)-total
    return dict(quality="capability_extended",baseline=baseline,candidate_cost=total,measured_net=net,
                verified_benefit=net>0,uses=1,unit_model=costs["unit_model"])


def verify_bound_receipts(receipts,results):
    require(len(receipts)==2 and len({r["binding"]["exchange_id"] for r in receipts})==2,"exact distinct public scoped verifier receipts required")
    for receipt in receipts:
        matches=[item for item in results if item["binding"]==receipt["binding"]]
        require(len(matches)==1,"public verifier receipt binding was swapped")
        equal(receipt["measurement_sha256"],matches[0]["measurement_sha256"],"public verifier exact cost receipt")
        equal(receipt["verified_scoped_benefit"],matches[0]["outcome"]["verified_benefit"],"public verifier agrees with independently derived scoped outcome")


def verify_normal_feedback(root,cell):
    root=Path(root);owner=cell["identity"];price=cell["oracle_price"]
    _,raw=safety.operational_chain(root/"actor-state/operations.jsonl",owner)
    equal(cell["feedback_events"],[row for row in raw if row["payload"].get("decision",{}).get("details",{}).get("schema")=="symbiote.learning-feedback/1"],
          "reported feedback is the exact censused actual operational history")
    rows=[row["payload"] for row in raw[1:]];groups=feedback_groups(rows)
    _,history=safety.knowledge_chain(root/"actor-state/knowledge.jsonl")
    first_events=verify_run_files(root,"native-first",cell["native_first"])
    restart_events=verify_run_files(root,"native-restart",cell["native_restart"])
    policy=load(root/"run-policy.json");config=load(root/"actor.json");results=[]
    def one(predicate,before,label):
        matches=[(i,row) for i,row in enumerate(rows[:before]) if predicate(row)]
        require(len(matches)==1,"one exact prior "+label+" required")
        return matches[0]
    def anchor(value):
        n=integer(value["records"],1,len(history));equal(value,dict(identity=owner,records=n,head_sha256=history[n-1]["sha256"]),"actual knowledge prefix anchor")
        return n
    last_lookup=0;last_direct=last_checks=last_forecast=0
    for exchange,group in groups.items():
        (decision_position,decision),(promoted_position,promoted),(use_position,use),(cost_position,cost),(_,closed)=group
        binding=decision["binding"];scope=binding["scope"];index=SCOPES.index(scope)
        _,original=one(lambda row:row.get("decision",{}).get("decision_id")==binding["decision_id"],decision_position,"native learning decision")
        learning=original["decision"];details=learning["details"];request=details["request"];offered=request["body"]["offer"]["record"]
        request_sha=safety.digest(request);sender=cell["partner_identities"][index]
        expected=dict(origin="native_learning_intent",exchange_id=exchange,decision_id=learning["decision_id"],sender_id=sender,receiver_id=owner,
                      scope=scope,schema_fingerprint=offered["schema_fingerprint"],request_sha256=request_sha,
                      candidate_id=safety.digest(dict(authenticated_sender=sender,canonical_body_sha256=request_sha)),
                      offered_record_sha256=safety.record_digest(offered),policy_sha256=policy["service_policy_sha256"],
                      fixture_sha256=sha(root/("partial-"+str(index)+".json")))
        expected["exchange_id"]=safety.digest(dict(decision=expected["decision_id"],sender=sender,receiver=owner,request=request_sha,
                candidate=expected["candidate_id"],scope=scope,schema=expected["schema_fingerprint"],policy=expected["policy_sha256"],fixture=expected["fixture_sha256"]))
        equal(binding,expected,"exact causal decision/request/artifact binding")
        require(details["schema"]=="symbiote.cognition-decision/1" and details["phase"]=="learn" and learning["selected_peer"]==sender and learning["context"]==scope,
                "causal origin is not the actual native learning decision")
        equal(details["candidate_id"],binding["candidate_id"],"learning candidate identity")
        equal(details["knowledge_before"],decision["before"],"learning prior knowledge boundary")
        equal(details["policy"],policy,"actual learning owner policy")
        before=anchor(decision["before"]);after=anchor(promoted["after"])
        equal(promoted["before"],decision["before"],"promotion starts at exact decision knowledge")
        require(after==before+1,"one exact fresh knowledge promotion per exchange")
        promotion=history[after-1];record=promotion["payload"]["record"];evidence=promotion["payload"]["assessment"]["evidence"]
        equal(promoted["promotion_sha256"],promotion["sha256"],"exact actual promotion row")
        equal(promoted["record_sha256"],safety.record_digest(record),"exact localized model")
        equal(promoted["evidence_sha256"],safety.digest(evidence),"exact stored local assessment")
        equal(record["payload"],offered["payload"],"received artifact is the evaluated local model")
        require(record["scope"]==scope and record["source"]==sender,"localized model source/applicability changed")
        require(not any(row["payload"].get("record",{}).get("scope")==scope for row in history[1:before]),"normal fixture did not extend prior scoped capability")
        quarantine_position,quarantine=one(lambda row:row.get("event")=="quarantined" and row["candidate_id"]==binding["candidate_id"],promoted_position,"authenticated quarantine")
        require(quarantine_position>decision_position and quarantine["key"]["peer_id"]==sender and quarantine["key"]["scope"]==scope,"quarantine chronology/identity differs")
        equal(quarantine["body"],request,"actual authenticated request bytes")
        equal(quarantine["body_sha256"],request_sha,"actual authenticated request digest")
        prepared_position,prepared=one(lambda row:row.get("event")=="evaluation_prepared" and row["candidate_id"]==binding["candidate_id"],promoted_position,"local evaluation intent")
        completed_position,completed=one(lambda row:row.get("event")=="evaluation_completed" and row["candidate_id"]==binding["candidate_id"],promoted_position,"local evaluation completion")
        require(quarantine_position<prepared_position<completed_position<promoted_position,"local promotion chronology differs")
        equal(prepared["record"],record,"durable intent evaluates exact promoted record")
        equal(prepared["fixture_sha256"],binding["fixture_sha256"],"exact pinned local truth")
        equal(prepared["response"],completed["response"],"durable evaluation intent/commit identity")
        response=completed["response"];evaluation=response["evaluation_record"]
        source=cell["sources"][index];world=dict(source_map=source["source_map"],costs=graph_fixture(1,[1,2])[1])
        candidate,control=scoped_measurements(response,world,price)
        equal(promoted["costs"],evaluation["candidate_local_costs"],"promotion fee provenance")
        require(promoted["baseline"]["kind"]==decision["baseline"]["kind"]=="unknown","legacy unknown must remain distinct from scoped measurement")
        map_=world["source_map"];target=map_["schema"]["nodes"]-1
        route,work=assess(map_["schema"],{o["edge_id"]:o["cost"] for o in map_["observations"]},0,target)
        work+=len(map_["observations"])  # actual retained learner observation updates
        equal(use,dict(phase="store_use",exchange_id=exchange,record_sha256=safety.record_digest(record),knowledge_at=promoted["after"],
                      input=target,output=route["cost"],model_work=work,sequence=0,basis=dict(kind="retained_evaluation",evidence_sha256=safety.digest(evidence))),"actual independently certified retained use")
        equal(closed["knowledge_at"],promoted["after"],"outcome knowledge identity")
        m=cost["measurement"];acquisition=details["acquisition"]
        require(m["schema"]=="symbiote.received-task-cost/1" and m["scope"]==scope and m["sender"]==sender,"scoped cost receipt context differs")
        boundary=m["boundary"];n=integer(boundary["events"],0,len(rows)-1)
        equal(boundary,dict(owner=owner,events=n,prefix_sha256=safety.digest(rows[:n])),"actual SENSE start journal prefix")
        sense=rows[n]["decision"]
        require(n<decision_position and sense["decision_id"]==acquisition["sense_decision_id"] and sense["selected_peer"]==sender and sense["context"]==scope
                and sense["details"]["schema"]=="symbiote.cognition-decision/1" and sense["details"]["phase"]=="sense","captured start is not immediately before the exact prior SENSE")
        require(acquisition["schema"]=="symbiote.sense-acquisition/1" and acquisition["unit_model"]=="application-plaintext-bytes/1"
                and acquisition["source_record_sha256"]==binding["offered_record_sha256"],"one-offer acquisition receipt differs")
        wire=integer(acquisition["sent_bytes"])+integer(acquisition["received_bytes"])
        matching=[row["outcome"] for row in rows[n+1:decision_position] if row.get("event")=="partner_outcome_recorded" and row["outcome"]["interaction_id"]==sense["decision_id"]]
        equal(matching,[dict(interaction_id=sense["decision_id"],peer_id=sender,scope=scope,kind="received",receipt_sha256=binding["offered_record_sha256"],
                             resource_units=(acquisition["sent_bytes"]+1023)//1024+(acquisition["received_bytes"]+1023)//1024)],"actual unique SENSE receipt/bytes")
        equal(m["acquisition_sha256"],safety.digest(acquisition),"exact scoped acquisition digest")
        equal(m["evaluation_sha256"],safety.digest(evaluation),"exact measured local control digest")
        expected_lookups=[*candidate["lookups"],*control["lookups"]]
        equal(m["lookups"],expected_lookups,"all scoped candidate and separately charged control lookups")
        b,a=m["before"],m["after"]
        equal(b["lookups"],last_lookup,"non-overlapping actual candidate/control windows")
        equal(b["direct_model_work"],last_direct,"direct native work window prefix")
        equal(b["provider_checks"],last_checks,"provider check window prefix")
        require(integer(b["graph_forecast_work"])>=last_forecast,"native scoped windows overlap/regress")
        equal(a["lookups"]-b["lookups"],len(expected_lookups),"scoped oracle counter delta")
        equal(cell["native_first"]["graph_execution"]["lookups"][b["lookups"]:a["lookups"]],expected_lookups,"scoped lookups are an exact actual process-meter slice")
        equal(a["direct_model_work"]-b["direct_model_work"],candidate["model_work"]+control["model_work"],"scoped direct-work delta")
        equal(a["provider_checks"]-b["provider_checks"],candidate["provider_checks"]+control["provider_checks"],"scoped provider-check delta")
        require(integer(a["graph_forecast_work"])<=cell["native_first"]["graph_execution"]["graph_forecast_work"],"window exceeds whole native process forecast work")
        baseline=dict(kind="measured",units=verify_measurement(control,map_["schema"],world["costs"],[target],price),evidence_sha256=safety.digest(control))
        equal(m["baseline"],baseline,"measured independent isolated task baseline")
        equal(m["private_control_audit_units"],baseline["units"],"private control execution is separate audit work")
        validation=len(candidate["lookups"])*price+candidate["model_work"]+candidate["provider_checks"]
        outcome=scoped_outcome(m,validation,baseline,work,wire);equal(closed["outcome"],outcome,"independently derived actual outcome/net")
        require((outcome["measured_net"]>0)==(price==100000),"declared useful/harmful fixture criterion failed")
        matches=[event["details"] for event in first_events if event["phase"]=="FEEDBACK" and event["details"]["exchange_id"]==exchange]
        require(len(matches)==1,"one actual stdout feedback completion required")
        equal(matches[0]["actual_use"],use,"actual stdout use receipt");equal(matches[0]["measurement"],m,"actual stdout cost receipt");equal(matches[0]["outcome"],outcome,"actual stdout outcome")
        results.append(dict(binding=binding,measurement_sha256=safety.digest(m),outcome=outcome,closed_position=group[-1][0]))
        last_lookup,last_direct,last_checks,last_forecast=(a[field] for field in ("lookups","direct_model_work","provider_checks","graph_forecast_work"))
    verify_bound_receipts(cell["bound_verification"]["receipts"],results)
    first_sense=next(event for event in restart_events if event["phase"]=="SENSE")
    equal(cell["restart_first_sense"],first_sense,"actual restarted first choice")
    position,entry=one(lambda row:row.get("decision",{}).get("decision_id")==first_sense["details"]["decision"],len(rows),"restarted source decision")
    prior=rows[:position];profiles=[]
    for peer in config["peers"]:
        for scope in policy["scopes"]:
            p=dict(peer=peer["id"],scope=scope,visits=0,failures=0,verified_novel=0,resource_units=0)
            for row in prior:
                d=row.get("decision",{});details=d.get("details",{})
                if details.get("schema")=="symbiote.cognition-decision/1" and details["phase"]=="sense" and d["selected_peer"]==peer["id"] and d["context"]==scope:p["visits"]+=1
                o=row.get("outcome") if row.get("event")=="partner_outcome_recorded" else None
                if o is not None and o["peer_id"]==peer["id"] and o["scope"]==scope:
                    p["failures"]+=o["kind"] in ("failed","rejected");p["resource_units"]+=integer(o["resource_units"])
                i=row.get("interaction") if row.get("event")=="partner_interaction_completed" else None
                if i is not None and i["peer_id"]==peer["id"] and i["context"]==scope:
                    p["verified_novel"]+=i["outcome"]=="verified_novel";p["failures"]+=i["outcome"] in ("verification_failed","transport_failed");p["resource_units"]+=integer(i["resource_units"])
            for item in results:
                if item["closed_position"]<position and item["binding"]["sender_id"]==peer["id"] and item["binding"]["scope"]==scope:
                    key="feedback_prefer" if item["outcome"]["verified_benefit"] else "feedback_defer";p[key]=p.get(key,0)+1
            profiles.append(p)
    def priority(p,feedback=True):
        return (p["visits"]+2*min(p.get("feedback_defer",0),3) if feedback else p["visits"],p["failures"],
                -p.get("feedback_prefer",0) if feedback else 0,-p["verified_novel"],p["resource_units"],p["peer"],p["scope"])
    profiles.sort(key=priority);equal(entry["decision"]["details"]["profiles"],profiles,"restart profiles rebuilt from actual preceding outcomes")
    equal(first_sense["details"]["profile"],profiles[0],"actual evidence-conditioned source choice")
    if price==100000:require(profiles[0].get("feedback_prefer",0)>0,"favorable experience was not retained in actual next choice")
    else:require(profiles[0].get("feedback_defer",0)==0 and any(p.get("feedback_defer",0)>0 for p in profiles),"harmful experience did not delay the costly contexts")
    without=min(profiles,key=lambda p:priority(p,False))
    return dict(status="PASS_INDEPENDENT_FINITE_TASK_FEEDBACK",exchanges=results,restart_choice=profiles[0],choice_without_feedback=without,
                selection_changed_by_feedback=(profiles[0]["peer"],profiles[0]["scope"])!=(without["peer"],without["scope"]),
                accounting_limit="Window forecast/byte counters are native instrumented receipts checked against chains/global bounds; closure, independent controls and host audit remain separately charged, not lifetime profit")


def verify_normal(root,native,native_sha,service_tests):
    root=canonical_path(root);manifest=verify_manifest(root,native,native_sha,service_tests)
    report=manifest["report"];require(report["schema"]=="symbiote.normal-capability-smoke/1" and len(report["cases"])==2,"two-case normal acceptance fixture required")
    results=[]
    for index,(price,cell) in enumerate(zip((100000,1),report["cases"])):
        cell_root=root/f"cell-{index:03}";equal(load(cell_root/"cell.json"),cell,"actual normal raw cell receipt")
        equal([cell["oracle_price"],cell["labels"],cell["cheap_indices"]],[price,[1,2],[1,1]],"separate fixed normal quality/harm cases")
        result=verify_cell(cell_root,cell,normal=True);result["feedback"]=verify_normal_feedback(cell_root,cell);results.append(result)
    result=aggregate(results,"NORMAL_QUALITY_GOAL_AND_HARM_FIXTURES_NOT_REGISTERED_COHORT")
    result.update(schema="symbiote.normal-feedback-independent/1",native_binary_sha256=native_sha,
                  service_test_executable_sha256=service_tests["sha256"],artifact_manifest_sha256=sha(root/"artifact-manifest.json"),consumer_source_sha256=sha(Path(__file__)))
    return result


def verify_smoke(root,native,native_sha,service_tests=None):
    root=canonical_path(root);manifest=verify_manifest(root,native,native_sha,service_tests)
    cell=load(root/"cell-000/cell.json");equal(manifest["report"],cell,"generic smoke raw receipt")
    require(cell["labels"]==[1,2] and cell["cheap_indices"]==[1,0] and cell["oracle_price"]==100000,
            "separate declared two-branch engineering fixture required")
    result=aggregate([verify_cell(root/"cell-000",cell)],"GENERIC_TWO_BRANCH_SMOKE_NOT_REGISTERED_COHORT")
    result.update(native_binary_sha256=native_sha,artifact_manifest_sha256=sha(root/"artifact-manifest.json"),
                  consumer_source_sha256=sha(Path(__file__)),protocol_sha256=PROTOCOL_SHA256)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest="command",required=True)
    setup=commands.add_parser("register")
    for name in ("binary","service-tests","artifacts"):setup.add_argument("--"+name,type=Path,required=True)
    setup.add_argument("--source-commit",required=True)
    launch=commands.add_parser("run");launch.add_argument("--registration",type=Path,required=True);launch.add_argument("--registration-sha256",required=True)
    for name in ("verify-smoke","verify-normal"):
        smoke=commands.add_parser(name);smoke.add_argument("--artifacts",type=Path,required=True);smoke.add_argument("--native",type=Path,required=True);smoke.add_argument("--native-sha256",required=True);smoke.add_argument("--output",type=Path,required=True)
        smoke.add_argument("--service-tests",type=Path,required=name=="verify-normal");smoke.add_argument("--service-tests-sha256",required=name=="verify-normal")
    args=parser.parse_args()
    if args.command=="register":result=register(args.binary,args.service_tests,args.artifacts,args.source_commit)
    elif args.command=="run":result=run(args.registration,args.registration_sha256)
    else:
        require((args.service_tests is None)==(args.service_tests_sha256 is None),"service executable needs its independent path and SHA together")
        tests=dict(path=args.service_tests,sha256=args.service_tests_sha256) if args.service_tests is not None else None
        verify=verify_normal if args.command=="verify-normal" else verify_smoke
        result=verify(args.artifacts,args.native,args.native_sha256,tests);write_new(args.output,result)
    print(json.dumps(result,indent=2));return 1 if result["status"]=="HOLD" else 0


if __name__=="__main__":
    try:raise SystemExit(main())
    except (RuntimeError,OSError,ValueError,KeyError,TypeError,IndexError,subprocess.SubprocessError) as failure:
        print(json.dumps(dict(status="HOLD",failure=str(failure))),file=sys.stderr);raise SystemExit(1)
