"""Once-only local hour soak and a separately labelled short engineering fixture."""
import argparse
import hashlib
import json
import ntpath
import os
import re
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time

import stability_campaign as safety
import source_fingerprint
from qualification_awake import QualificationAwake

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = "SYMBIOTE-LOCAL-SOAK-001"
PROTOCOL_FILE = "docs/SOAK_CAMPAIGN_PROTOCOL.md"
HOUR_TEST = "soak::hour_120_cycle_local_soak"
FIXTURE_TEST = "soak::short_local_soak_fixture"
BOUNDS = dict(hour_seconds=3900, fixture_seconds=180, cleanup_seconds=10,
              evidence_bytes=64*1024*1024, source_check_seconds=30,
              root_output_bytes=2*1024*1024, native_command_bytes=256*1024,
              windows_job_processes=8, windows_job_memory_bytes=256*1024*1024)

# Inert checked I/O/hash/math helpers; importing does not start an old campaign.
for _name in ("require","sha","encode","digest","pairs","load","write_new","identity_chain","knowledge_chain",
              "record_digest","operational_chain","artifact_file","endurance_outputs","bound_native_receipt",
              "bound_tls_pair","bound_quarantine","activation_guard_kind"):
    globals()[_name] = getattr(safety,_name)


def mode(qualification):
    return (dict(name="HOUR_QUALIFICATION",cycles=120,keys=483,spacing_ms=30000,window_ms=3600000,
                 rotations=[18,38,78,101],denials=[30,90],lost=50,restore=60)
            if qualification else dict(name="ENGINEERING_FIXTURE_NOT_HOUR_QUALIFICATION",cycles=12,keys=51,
                 spacing_ms=0,window_ms=0,rotations=[2,4,8,10],denials=[3,9],lost=5,restore=6))


def source_files(root=ROOT):
    root=Path(root)
    return dict(manifest=source_fingerprint.manifest(root),protocol_sha256=sha(root/PROTOCOL_FILE))


def check_timing(report,events,selected):
    require(report["mode"]==selected["name"],"fixture/hour mode mismatch")
    expected=dict(spacing_ms=selected["spacing_ms"],window_ms=selected["window_ms"],rotations=selected["rotations"],
                  denials=selected["denials"],lost_cycle=selected["lost"],restore_after=selected["restore"],
                  late_limit_ms=5000,maintenance_gap_limit_ms=20000)
    require(report["schedule"]==expected,"fixed schedule was changed")
    require(events and [event["sequence"] for event in events]==list(range(len(events))),"ordered raw timing events required")
    require(all(type(event["elapsed_ms"]) is int and event["elapsed_ms"]>=0 for event in events),"integer observed event clocks required")
    require([e["elapsed_ms"] for e in events]==sorted(e["elapsed_ms"] for e in events),"raw event clocks went backwards")
    active=None;sessions=[];gaps=[];origin=None;last_end=None
    indexed={};alive={}
    for event in events:
        kind=event["kind"];data=event["data"];label=data.get("label")
        if kind in ("tls-request","native-command","tls-response"):
            key=(kind,label);require(key not in indexed,"duplicate timing label");indexed[key]=event
        if kind=="listener-alive":
            require(type(data["cycle"]) is int and type(data["pid"]) is int,"owned liveness event binding")
            alive.setdefault(data["cycle"],[]).append(event)
        if kind=="owned-listener-started" and label!="bootstrap":
            require(active is None,"overlapping main listener spans")
            active=dict(start=event,end=None,pid=data["ready"]["pid"])
            if origin is None:
                require(label=="main-initial","measurement must start at actual first main readiness")
                origin=event["elapsed_ms"]
            else:
                end=last_end;require(end is not None,"missing preceding positive stop")
                cycle=end["data"]["cycle"] if end["kind"]=="owned-listener-killed-and-joined" else int(end["data"]["label"].removeprefix("maintenance-"))
                gap=event["elapsed_ms"]-end["elapsed_ms"]
                require(0<=gap<=20000,"observed maintenance gap exceeded bound")
                gaps.append(dict(after_cycle=cycle,elapsed_ms=gap))
        if kind in ("owned-listener-stopped","owned-listener-killed-and-joined") and data["main_listener"]:
            require(active is not None and data["pid"]==active["pid"],"positive stop must match ordered actual main readiness")
            span=event["elapsed_ms"]-active["start"]["elapsed_ms"]
            require(type(data["ready_to_wait_ms"]) is int and data["ready_to_wait_ms"]==span,"listener span differs from raw start/stop clocks")
            active["end"]=event;sessions.append(active);active=None;last_end=event
    require(origin is not None and active is None and len(sessions)==9 and last_end["data"]["label"]=="measurement-final","complete actual main listener lifecycle")
    require(type(report["measurement_started_elapsed_ms"]) is int and report["measurement_started_elapsed_ms"]==origin,"measurement origin differs from actual main-initial event")
    measured=last_end["elapsed_ms"]-origin
    require(type(report["measurement_elapsed_ms"]) is int and report["measurement_elapsed_ms"]==measured,"measurement end differs from actual final positive stop")
    observed_spans=sum(session["end"]["elapsed_ms"]-session["start"]["elapsed_ms"] for session in sessions)
    require(type(report["main_listener_span_ms"]) is int and report["main_listener_span_ms"]==observed_spans,"live-span summary differs from observed event intervals")
    expected_points=sorted([*selected["rotations"],*selected["denials"],selected["lost"],selected["restore"]])
    require([row["after_cycle"] for row in gaps]==expected_points,"actual maintenance cutpoints differ")
    declared=report["maintenance_gaps"]
    require(len(declared)==len(gaps) and all(type(row["elapsed_ms"]) is int and row["after_cycle"]==actual["after_cycle"] and row["elapsed_ms"]==actual["elapsed_ms"] for row,actual in zip(declared,gaps)),"maintenance gap metadata differs from raw stop/ready events")
    cycles=report["cycles"]
    require(len(cycles)==selected["cycles"] and [row["cycle"] for row in cycles]==list(range(1,selected["cycles"]+1)),"every scheduled slot appears exactly once")
    require(set(alive)==set(range(1,selected["cycles"]+1)),"raw positive idle observations required for every slot")
    previous_finish=None;max_idle=0
    for index,cycle in enumerate(cycles,1):
        due=index*selected["spacing_ms"]
        require(type(cycle["due_ms"]) is int and cycle["due_ms"]==due,"fixed due time differs")
        triples=[]
        for number,operation in ((0,"read"),(0,"predict"),(1,"read"),(1,"predict")):
            label=f"cycle-{index}-{number}-{operation}"
            triple=[indexed[(kind,label)] for kind in ("tls-request","native-command","tls-response")]
            require(triple[0]["sequence"]<triple[1]["sequence"]<triple[2]["sequence"],"request/output/reply event order")
            if triples:require(triples[-1][-1]["sequence"]<triple[0]["sequence"],"cycle requests overlap or were reordered")
            triples.append(triple)
        first,last=triples[0][0],triples[-1][-1]
        matching=[session for session in sessions if session["start"]["sequence"]<first["sequence"]<last["sequence"]<session["end"]["sequence"] and session["pid"]==cycle["ready"]["pid"]]
        require(len(matching)==1,"all four cycle attempts must lie in the same observed live session")
        session=matching[0]
        require(type(cycle["started_ms"]) is int and type(cycle["finished_ms"]) is int
                and cycle["started_ms"]==first["elapsed_ms"]-origin and cycle["finished_ms"]==last["elapsed_ms"]-origin,"cycle metadata differs from actual request/reply clocks")
        if selected["window_ms"]:
            require(origin+due<=first["elapsed_ms"]<=origin+due+5000,"actual first attempt missed fixed slot; no catchup")
            require(all(origin+due<=event["elapsed_ms"]<=origin+due+selected["spacing_ms"] for triple in triples for event in triple),"raw request/output/reply outside scheduled cycle interval")
        probes=alive[index]
        require(all(session["start"]["sequence"]<event["sequence"]<first["sequence"] and event["data"]["pid"]==session["pid"] for event in probes),"idle observations do not bind the active cycle listener")
        boundary=max(session["start"]["elapsed_ms"],previous_finish["elapsed_ms"] if previous_finish else origin)
        times=[boundary,*[event["elapsed_ms"] for event in probes],first["elapsed_ms"]]
        require(times==sorted(times),"idle observation timing went backwards")
        observed=max(b-a for a,b in zip(times,times[1:]));max_idle=max(max_idle,observed)
        require(observed<=5000,"observed idle-liveness event gap exceeded bound")
        require(type(cycle["idle_poll_count"]) is int and cycle["idle_poll_count"]>=len(probes)
                and type(cycle["max_idle_poll_gap_ms"]) is int and 0<=cycle["max_idle_poll_gap_ms"]<=5000,"native fine-grained poll diagnostics")
        previous_finish=last
    require(report["max_idle_poll_gap_ms"]==max(row["max_idle_poll_gap_ms"] for row in cycles)
            and report["idle_poll_count"]==sum(row["idle_poll_count"] for row in cycles),"fine-grained poll diagnostic totals")
    require(report["stale_tls_probe_attempts"]==4,"four separate stale TLS negotiation probes")
    if selected["window_ms"]:
        require(report["qualification"]=="ONE_HOST_BOUNDED_HOUR" and measured>=3600000 and observed_spans>=3540000,"event-derived full hour and live spans required")
    else:require(report["qualification"]=="NOT_HOUR_QUALIFIED","short fixture cannot qualify the hour")
    return dict(measurement_origin_ms=origin,measurement_elapsed_ms=measured,main_listener_span_ms=observed_spans,
                max_maintenance_gap_ms=max(row["elapsed_ms"] for row in gaps),max_observed_idle_gap_ms=max_idle,
                timing_basis="ordered raw main readiness/positive stops, idle liveness and actual request/output/reply events")


def final_checks(cancelled,elapsed,qualification,evidence_bytes,report_bytes):
    require(not cancelled,"cancelled before final report")
    require(elapsed<=(BOUNDS["hour_seconds"] if qualification else BOUNDS["fixture_seconds"]),"final total deadline")
    require(report_bytes<=1024*1024 and evidence_bytes+report_bytes<=BOUNDS["evidence_bytes"],"final evidence/receipt budget")


def new_directory(path):
    path=Path(path).resolve()
    require(not path.exists() and path.parent.is_dir() and Path(tempfile.gettempdir()).resolve() in path.parents
            and ROOT not in path.parents and len(str(path))<=80,"fresh short OS-temp artifact directory required (maximum80characters)")
    path.mkdir()
    return path


def binaries(native,test):
    result={name:dict(path=str(Path(path).resolve(strict=True)),sha256=sha(path)) for name,path in (("native",native),("service_tests",test))}
    require(Path(result["service_tests"]["path"]).parent==Path(result["native"]["path"]).parent/"deps","fresh same-profile Cargo test executable required; location alone does not authenticate embedded binary")
    return result


def metadata(directory,label,argv):
    record=safety.execute(argv,directory,label,timeout=30)
    safety.check_exit(record)
    return record,safety.output(record,directory)


def register(native,test,artifacts,commit):
    require(isinstance(commit,str) and len(commit)==40 and all(c in "0123456789abcdef" for c in commit),"selected immutable source commit required")
    directory=new_directory(artifacts);before=source_files();pins=binaries(native,test);preflight=[]
    for label,args in (("git-head",["git","rev-parse","HEAD"]),("git-clean",["git","status","--porcelain=v1","--untracked-files=all"]),
                       ("native-version",[pins["native"]["path"],"version","--json"]),
                       ("service-list",[pins["service_tests"]["path"],"--list","--format","terse"])):
        receipt,text=metadata(directory,label,args);preflight.append(receipt)
        if label=="git-head":require(text.strip()==commit,"HEAD differs from selected commit")
        if label=="git-clean":require(not text.strip(),"registration requires clean committed source")
        if label=="native-version":
            version=json.loads(text,object_pairs_hook=pairs)
            require(version["name"]=="SYMBIOTE" and version["build_source_commit"]==commit,"native source stamp differs from clean committed candidate")
        if label=="service-list":
            names={line.removesuffix(": test") for line in text.splitlines() if line.endswith(": test")}
            require({HOUR_TEST,FIXTURE_TEST}<=names,"compiled exact hour and separate fixture cases must exist")
    require(source_files()==before,"source changed during registration")
    registration=dict(schema="symbiote.soak-registration/1",protocol=PROTOCOL,protocol_sha256=sha(ROOT/PROTOCOL_FILE),
                      source_commit=commit,source_order=source_fingerprint.ALGORITHM,source_manifest=before["manifest"],source_sha256=before["manifest"]["sha256"],
                      binaries=pins,bounds=BOUNDS,mode=mode(True),artifact_directory=str(directory),preflight=preflight,
                      independent_host_validation="OPEN_UNAVAILABLE",scientific_samples=0)
    path=directory/"soak-registration.json";write_new(path,registration)
    return dict(status="REGISTERED_NOT_RUN",registration=str(path),registration_sha256=sha(path))


def pins_unchanged(pins,sources):
    require(source_files()==sources,"source changed while registered soak was active")
    require(all(sha(value["path"])==value["sha256"] for value in pins.values()),"registered executable changed")


def git_unchanged(commit):
    for args,expected in ((["rev-parse","HEAD"],commit),(["status","--porcelain=v1","--untracked-files=all"],"")):
        result=subprocess.run(["git",*args],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,text=True,check=False)
        require(result.returncode==0 and len(result.stdout)+len(result.stderr)<=2*1024*1024 and result.stdout.strip()==expected,"clean committed candidate changed")


def live_candidate_check(directory,pins,sources,qualification,commit):
    pins_unchanged(pins,sources)
    if qualification:git_unchanged(commit)
    require(safety.evidence_size(directory)<=BOUNDS["evidence_bytes"],"evidence byte budget")


def launch(directory,pins,sources,qualification,registration_pin=None,commit=None):
    selected=mode(qualification);cancel=threading.Event();done=threading.Event();errors=[]
    awake=QualificationAwake()
    def watch():
        while not done.wait(BOUNDS["source_check_seconds"]):
            try:
                live_candidate_check(directory,pins,sources,qualification,commit)
                awake.check()
            except Exception as failure:errors.append(str(failure));cancel.set();return
    observer=threading.Thread(target=watch,daemon=True);old={}
    for signum in (signal.SIGINT,signal.SIGTERM):old[signum]=signal.signal(signum,lambda *_:cancel.set())
    report=dict(schema="symbiote.local-soak-campaign/1",protocol=PROTOCOL,status="HOLD",mode=selected["name"],
                registration_sha256=registration_pin,independent_host_validation="OPEN_UNAVAILABLE",scientific_samples=0)
    started=time.monotonic()
    try:
        pins_unchanged(pins,sources)
        if qualification:git_unchanged(commit)
        native=directory/"native";require(not native.exists(),"native evidence must be new")
        case=HOUR_TEST if qualification else FIXTURE_TEST
        with awake:
            observer.start()
            process=safety.execute([pins["service_tests"]["path"],case,"--ignored","--exact","--test-threads=1"],directory,
                                   "hour-soak" if qualification else "short-soak-fixture",
                                   timeout=BOUNDS["hour_seconds"] if qualification else BOUNDS["fixture_seconds"],
                                   cancelled=cancel.is_set,environment={"SYMBIOTE_SOAK_ARTIFACTS":str(native)})
            report['process']=process
        report["process"]=process;safety.check_exit(process);safety.check_native_test(safety.output(process,directory))
        require(not cancel.is_set() and not errors,"soak cancelled or source watch failed")
        report["verification"]=verify_soak(native,pins,selected)
        pins_unchanged(pins,sources)
        if qualification:git_unchanged(commit)
        elapsed=time.monotonic()-started
        require(elapsed<=(BOUNDS["hour_seconds"] if qualification else BOUNDS["fixture_seconds"]),"final total deadline")
        if qualification:require(process["elapsed_seconds"]>=3600,"root-observed actual hour required")
        require(safety.evidence_size(directory)+1024*1024<=BOUNDS["evidence_bytes"],"final receipt reserve")
        report["status"]="PASS_LOCAL_HOUR" if qualification else "PASS_ENGINEERING_FIXTURE_NOT_HOUR_QUALIFICATION"
    except Exception as failure:report["failure"]=str(failure)
    finally:
        done.set()
        if observer.ident is not None:observer.join(timeout=2)
        report['host_awake_guard']=awake.report
        for signum,handler in old.items():signal.signal(signum,handler)
        report["elapsed_seconds"]=time.monotonic()-started;report["source_watch_failures"]=errors
        if cancel.is_set() or errors or observer.is_alive():report["status"]="HOLD";report.setdefault("failure","cancelled or source monitor incomplete")
        if report["status"]!="HOLD":
            try:final_checks(cancel.is_set(),time.monotonic()-started,qualification,safety.evidence_size(directory),len(json.dumps(report,indent=2).encode())+1)
            except RuntimeError as failure:report["status"]="HOLD";report["failure"]=str(failure)
        write_new(directory/"soak-report.json",report)
    return report


def run(path,pin):
    path=Path(path).resolve(strict=True);require(sha(path)==pin,"registration external SHA differs")
    registered=load(path)
    require(registered["schema"]=="symbiote.soak-registration/1" and registered["protocol"]==PROTOCOL
            and registered["protocol_sha256"]==sha(ROOT/PROTOCOL_FILE) and registered["mode"]==mode(True)
            and registered["bounds"]==BOUNDS and registered["source_order"]==source_fingerprint.ALGORITHM
            and registered["source_sha256"]==registered["source_manifest"]["sha256"],"unsupported or changed frozen registration")
    directory=Path(registered["artifact_directory"]);require(directory.resolve()==path.parent,"registered path changed")
    sources=dict(manifest=registered["source_manifest"],protocol_sha256=registered["protocol_sha256"])
    pins_unchanged(registered["binaries"],sources);git_unchanged(registered["source_commit"])
    write_new(directory/"soak-started.json",dict(registration_sha256=pin,protocol=PROTOCOL))
    return launch(directory,registered["binaries"],sources,True,pin,registered["source_commit"])


def fixture(native,test,artifacts):
    directory=new_directory(artifacts);pins=binaries(native,test);sources=source_files()
    write_new(directory/"fixture-only.json",dict(schema="symbiote.soak-fixture/1",classification=mode(False)["name"],binaries=pins,source_sha256=digest(sources)))
    return launch(directory,pins,sources,False)


def main():
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest="command",required=True)
    for name in ("register","fixture"):
        sub=commands.add_parser(name)
        for field in ("binary","service-tests","artifacts"):sub.add_argument("--"+field,type=Path,required=True)
        if name=="register":sub.add_argument("--source-commit",required=True)
    sub=commands.add_parser("run");sub.add_argument("--registration",type=Path,required=True);sub.add_argument("--registration-sha256",required=True)
    args=parser.parse_args()
    if args.command=="register":result=register(args.binary,args.service_tests,args.artifacts,args.source_commit)
    elif args.command=="fixture":result=fixture(args.binary,args.service_tests,args.artifacts)
    else:result=run(args.registration,args.registration_sha256)
    print(json.dumps(result,indent=2));return 1 if result["status"]=="HOLD" else 0


def verify_soak(root,binaries,selected):
    """Independent fixed-fixture continuity checks on preserved native evidence."""
    root=Path(root).resolve(strict=True)
    report=load(root/"soak-report.json")
    require(report["schema"]=="symbiote.local-soak/1" and report["status"]=="PASS" and report["first_failure"] is None,"native continuity report completed without a hidden failure")
    for key,value in (("cycles_expected",selected["cycles"]),("cycles_completed",selected["cycles"]),("request_keys_expected",selected["keys"]),("request_keys_recorded",selected["keys"]),
                      ("service_starts_expected",10),("service_starts",10),("owned_stops",10),("models_retained",2)):
        require(type(report[key]) is int and report[key]==value,"actual continuity count "+key)
    require(report["native_binary_sha256"]==binaries["native"]["sha256"] and report["test_binary_sha256"]==binaries["service_tests"]["sha256"],"continuity uses exactly the registered native/test executables")
    require(report["current_server_state"]=="owners/server-restored" and report["client_state"]=="owners/client","declared final owner paths")
    owners=report["owner_identities"]
    require(len(owners)==2 and len(set(owners))==2,"two distinct persistent owner identities")
    server=root/report["current_server_state"];client=root/report["client_state"]
    owner_raw=[]
    for directory,owner in ((server,owners[0]),(client,owners[1])):
        raw,identity=identity_chain(directory/"ledger.jsonl")
        require(identity[0]["payload"]["identity"]==owner,"continuity identity equals actual owner genesis")
        owner_raw.append(raw)
    knowledge,rows=knowledge_chain(server/"knowledge.jsonl")
    require(rows[0]["payload"]["identity"]==owners[0],"actual retained knowledge owner")
    models=[row["payload"]["record"] for row in rows if row["payload"]["event"] in ("promote","promote_graph")]
    require(len(models)==2 and not any(row["payload"]["event"]=="revoke" for row in rows),"exactly two initial retained models, no hidden replacement")
    model_hashes={record_digest(record) for record in models}
    require(len(model_hashes)==2 and set(report["model_digests"])==model_hashes,"both actual complete model digests")
    by_scope={record["scope"]:record for record in models}
    require(set(by_scope)=={"affine-context/v1","graph-context/v1"} and all(record["source"]==owners[1] for record in models),"authenticated source and fixed two-context applicability")
    require(by_scope["affine-context/v1"]["payload"]==dict(kind="affine",width=3,coefficients=3,bias=False),"known manual affine strategy")
    graph=by_scope["graph-context/v1"]["payload"]
    expected_graph=dict(nodes=3,edges=[dict(zip(("from","to","lower","upper"),edge)) for edge in ((0,1,1,9),(1,2,1,9),(0,2,1,9))])
    require(graph==dict(kind="graph-map",schema=expected_graph,observations=[dict(edge_id=i,cost=cost) for i,cost in enumerate((1,2,5))]),"known complete manual graph observations")
    operations,ops=operational_chain(server/"operations.jsonl",owners[0])
    client_ops,client_rows=operational_chain(client/"operations.jsonl",owners[1])
    _,client_knowledge=knowledge_chain(client/"knowledge.jsonl")
    require(len(client_knowledge)==1 and client_knowledge[0]["payload"]["identity"]==owners[1],"client has its own unchanged nonlearning knowledge genesis")
    events=[json.loads(line,object_pairs_hook=pairs) for line in artifact_file(root,report["events_file"]).read_bytes().splitlines()]
    require(len(events)<10000 and [event["sequence"] for event in events]==list(range(len(events)))
            and sha(root/report["events_file"])==report["events_sha256"],"complete bounded event sequence and exact bytes")
    require([event["elapsed_ms"] for event in events]==sorted(event["elapsed_ms"] for event in events),"actual monotonic event order")
    require(all(event["data"]["outcome"]=="completed" for event in events if event["kind"]=="native-command"),"no native deadline or output-limit failure may masquerade as an expected negative")
    native,parsed,requests,tls_responses=endurance_outputs(root,events)
    attempts=[];active={};ready_events={};stop_events={};sessions=[];starts=stops=killed=0
    for event in events:
        data=event["data"];kind=event["kind"]
        if kind=="tls-request":attempts.append((data["request"],data["explicit_duplicate"]))
        elif kind=="lost-reply-request":attempts.append((data,False))
        elif kind=="owned-listener-started":
            ready=data["ready"];pid=ready["pid"]
            require(ready["identity"]==owners[0] and type(pid) is int and pid>0 and pid not in active,"owned ready instance identity/PID timeline")
            starts+=1;require(data["spawn_ordinal"]==starts,"actual owned spawn ordinal")
            require(data["label"] not in ready_events,"duplicate listener start label")
            ready_events[data["label"]]=ready
            active[pid]=dict(ready=ready,start=event["sequence"],end=None)
        elif kind in ("owned-listener-stopped","owned-listener-killed-and-joined"):
            pid=data["pid"];require(pid in active,"only a positively owned active listener can stop")
            session=active.pop(pid);session["end"]=event["sequence"];sessions.append(session);stops+=1
            if kind=="owned-listener-killed-and-joined":killed+=1;require(data["joined"] is True and data["exit_code"]!=0,"real killed child was waited and unsuccessful")
            else:
                require(data["exit_code"]==0 and data["stop"]["identity"]==owners[0],"real graceful native shutdown")
                require(data["label"] not in stop_events,"duplicate listener stop label")
                stop_events[data["label"]]=data["stop"]
    require(starts==stops==10 and killed==1 and not active,"all ten owned listeners stopped, one actual killed-service crash")
    keys={};duplicates=0
    for request,duplicate in attempts:
        key=(request["scope"],request["request_id"])
        if duplicate:
            require(key in keys and encode(request)==encode(keys[key]),"idempotent retry repeats the exact earlier wire request")
            duplicates+=1
        else:require(key not in keys,"fresh on-wire request key reused");keys[key]=request
    require(len(attempts)==selected["keys"]+1 and len(keys)==selected["keys"] and duplicates==1
            and set(keys)=={(row["scope"],row["request_id"]) for row in report["request_keys"]},"99 unique wire keys and one exact retry; no 99-key durable-cache claim")
    cycles=report["cycles"]
    require(len(cycles)==selected["cycles"] and [row["cycle"] for row in cycles]==list(range(1,selected["cycles"]+1)),"every fixed continuity cycle appears once")
    server_prefixes={};client_prefixes={}
    for raw,table in ((operations,server_prefixes),(client_ops,client_prefixes)):
        hasher=hashlib.sha256()
        for count,line in enumerate(raw.splitlines(keepends=True),1):
            hasher.update(line);table[hasher.hexdigest()]=count
    previous_server=previous_client=0
    for cycle in cycles:
        n=cycle["cycle"];responses=cycle["responses"]
        require(len(responses)==4 and cycle["ready"]["identity"]==owners[0],"four actual replies from same owned listener")
        first_label=f"cycle-{n}-0-read"
        position=next(event["sequence"] for event in events if event["kind"]=="tls-request" and event["data"]["label"]==first_label)
        require(sum(session["start"]<position<session["end"] and encode(session["ready"])==encode(cycle["ready"]) for session in sessions)==1,"cycle binds an actually live owned listener session")
        expected_ops=[]
        for scope in ("affine-context/v1","graph-context/v1"):
            expected_ops.extend((scope,operation) for operation in ("knowledge.read","knowledge.predict"))
        require([(row["request"]["scope"],row["request"]["body"]["operation"]) for row in responses]==expected_ops,"fixed manual read/predict operation order")
        for index,pair in enumerate(responses):
            request,reply=pair["request"],pair["response"];scope=request["scope"];record=by_scope[scope]
            label=f"cycle-{n}-{index//2}-{'read' if index%2==0 else 'predict'}"
            bound_tls_pair(parsed,requests,tls_responses,label,request,reply)
            require(encode(keys[(scope,request["request_id"])])==encode(request) and request["body"]["artifact"]==record["id"],"actual current model and unique wire request binding")
            if request["body"]["operation"]=="knowledge.read":
                require(reply["sender"]==owners[0] and reply["record_sha256"]==record_digest(reply["record"])==record_digest(record),"real read returns the unchanged retained record")
            else:
                query=(n-1)%8 if scope=="affine-context/v1" else (1,2,5)[(n-1)%3]
                expected=(query&3).bit_count()%2 if scope=="affine-context/v1" else {1:1,2:3,5:2}[query]
                require(request["body"]["input"]==query and reply["input"]==query and type(reply["prediction"]) is int
                        and reply["prediction"]==expected and reply["conditional"] is True and reply["physical_certificate_authorized"] is False
                        and reply["record_sha256"]==record_digest(record),"independently recomputed actual finite prediction")
                if scope=="graph-context/v1":
                    route=reply["route"];nodes,edges={1:([0,1],[0]),2:([0,1,2],[0,1]),5:([1,2],[1])}[query]
                    require(route["cost"]==expected and route["nodes"]==nodes and route["edges"]==edges and route["conditional"] is True,"actual exact shortest graph path certificate")
        witness=cycle["continuity"]
        require(witness["server_owner_sha256"]==hashlib.sha256(owner_raw[0]).hexdigest() and witness["client_owner_sha256"]==hashlib.sha256(owner_raw[1]).hexdigest()
                and witness["knowledge_sha256"]==hashlib.sha256(knowledge).hexdigest() and set(witness["model_digests"])==model_hashes and witness["models_retained"]==2,"nonvacuous owner/model continuity at every cycle")
        server_count=server_prefixes.get(witness["server_operations_sha256"],-1)
        client_count=client_prefixes.get(witness["client_operations_sha256"],-1)
        require(server_count>=previous_server and client_count>=previous_client
                and server_count==witness["server_operation_records"],"each cycle preserves an exact chronological prefix of actual operational history")
        previous_server,previous_client=server_count,client_count
    require([row["after_cycle"] for row in report["credential_rotations"]]==selected["rotations"],"four explicitly scheduled leaf rotations")
    for row in report["credential_rotations"]:
        after=row["after_cycle"]
        bound_native_receipt(parsed,f"rotation-{after}-server",row["server_transition"])
        bound_native_receipt(parsed,f"rotation-{after}-client",row["client_transition"])
        require(row["previous_pin"]!=row["current_pin"] and row["stale_pin_rejection"]["application_mutation"] is False
                and row["stale_pin_rejection"]["error"] and row["stale_pin_rejection"]["before_cycle"]==row["after_cycle"]+1,"actual prior leaf pin rejection without application mutation")
    require([row["after_cycle"] for row in report["denials"]]==selected["denials"],"two scheduled denials/regrants")
    for row in report["denials"]:
        after=row["after_cycle"]
        for label,key in ((f"denial-{after}","denial"),(f"denied-serve-{after}","denied_service"),(f"regrant-{after}","regrant")):
            bound_native_receipt(parsed,label,row[key])
        stopped=row["denied_service"]
        require(row["denial"]["peer"]==row["regrant"]["peer"]==owners[1] and row["denial"]["denied"] is True and row["regrant"]["denied"] is False
                and stopped["schema"]=="symbiote.service-stop/1" and stopped["status"]=="STOPPED" and stopped["reason"]=="no-authorized-peers"
                and stopped["listener_opened"] is False and stopped["requests"]==stopped["connections"]==0,"denied serve opens no listener; generic success is insufficient")
    payloads=[row["payload"] for row in ops]
    require(sum(row["event"]=="policy_transitioned" for row in payloads)==5
            and sum(row["payload"]["event"]=="policy_transitioned" for row in client_rows)==4
            and sum(row["event"]=="peer_denied" for row in payloads)==sum(row["event"]=="peer_restored" for row in payloads)==2,
            "actual durable rotation/relocation/denial/regrant history")
    quarantined=[row for row in payloads if row["event"]=="quarantined"]
    require(len(quarantined)==3 and len({(row["key"]["peer_id"],row["key"]["operation"],row["key"]["scope"],row["key"]["request_id"]) for row in quarantined})==3,"only three durable candidate keys, not all read/predict requests")
    for label in ("submit-affine","submit-graph"):
        require(label in requests and label in tls_responses,"actual initial submission evidence")
        request=requests[label]["request"];response=tls_responses[label]["response"]
        matching=[row for row in quarantined if row["candidate_id"]==response["candidate"]]
        require(len(matching)==1,"initial submission has one actual quarantine")
        bound_quarantine(matching[0],request,response,owners[1])
    completed=[row for row in payloads if row["event"]=="evaluation_completed"]
    prepared_rows=[row for row in payloads if row["event"]=="evaluation_prepared"]
    prepared={row["candidate_id"]:row for row in prepared_rows}
    require(len(completed)==len(prepared_rows)==len(prepared)==2
            and all(row["record_sha256"]==record_digest(prepared[row["candidate_id"]]["record"]) and row["record_sha256"] in model_hashes
                    and encode(row["response"])==encode(prepared[row["candidate_id"]]["response"]) for row in completed),
            "exact completed operational history anchors both actual historical promotions and prepared receipts")
    for index,label in enumerate(("submit-affine","submit-graph")):
        candidate=tls_responses[label]["response"]["candidate"]
        matching=[row for row in completed if row["candidate_id"]==candidate]
        require(len(matching)==1,"initial candidate completed exactly once")
        bound_native_receipt(parsed,f"initial-evaluation-{index}",matching[0]["response"])
    lost=report["lost_reply"]
    matches=[row for row in quarantined if row["candidate_id"]==lost["candidate"]]
    require(lost["cycle"]==selected["lost"] and lost["quarantine_rows"]==1 and len(matches)==1 and lost["candidate_evaluated"] is False
            and lost["committed_response"]["status"]=="QUARANTINED" and lost["committed_response"]["promoted"] is False
            and encode(lost["retry_response"])==encode(lost["committed_response"]) and lost["first_call_error"]
            and lost["owned_crash"]["joined"] is True and lost["owned_crash"]["exit_code"]!=0
            and lost["journal_sha256_before_crash"]==lost["journal_sha256_after_retry"],"genuine committed lost reply, one owned killed service, exact idempotent replay without mutation")
    bound_quarantine(matches[0],lost["request"],lost["committed_response"],owners[1])
    bound_tls_pair(parsed,requests,tls_responses,"lost-submit-exact-retry",lost["request"],lost["retry_response"],True)
    bound_native_receipt(parsed,"recover-owned-crash",lost["recovery"])
    require(lost["recovery"]["processes_terminated"]==0 and lost["recovery"]["ledgers_modified"] is False,"crash recovery removes only proven-dead locks without learning edits or killing other processes")
    require([event["data"] for event in events if event["kind"]=="lost-reply-request"]==[lost["request"]],"lost direct TLS request is the preserved exact quarantine request")
    crashes=[event["data"] for event in events if event["kind"]=="owned-listener-killed-and-joined"]
    require(len(crashes)==1 and all(crashes[0][key]==lost["owned_crash"][key] for key in ("pid","exit_code","joined"))
            and crashes[0]["cycle"]==selected["lost"],"lost response references the actual killed and waited service")
    midpoint=report["midpoint_restore"]
    require(midpoint["after_cycle"]==selected["restore"] and midpoint["old_source_absent"] is True and midpoint["new_learning_promotions"]==0
            and midpoint["pending_lost_candidate_rejected"]==lost["candidate"],"fixed midpoint relocation settles, never learns from, pending lost candidate")
    require(sum(row["event"]=="evaluation_rejected" and row["candidate_id"]==lost["candidate"] for row in payloads)==1,"pending quarantine rejected exactly once")
    require(midpoint["backup"]["manifest_sha256"]==midpoint["verification"]["manifest_sha256"]==midpoint["restore"]["manifest_sha256"]
            and midpoint["restore"]["network_started"] is False and midpoint["activation"]["relocation"]["restore_mapping_sha256"]==midpoint["restore"]["restore_mapping_sha256"],"verified backup and explicit restore-review mapping binding")
    for label,key in (("midpoint-backup","backup"),("midpoint-verify","verification"),("midpoint-restore","restore"),("midpoint-reviewed-relocation","activation")):
        bound_native_receipt(parsed,label,midpoint[key])
    blocked=midpoint["unreviewed_activation"]
    require(encode(native.get("midpoint-unreviewed-peers"))==encode(blocked),"unreviewed activation is the actual preserved failed native command")
    activation_guard=verify_soak_midpoint_guard(root,midpoint,owners[0],selected)
    final=report["final_continuity"]
    require(encode(final)==encode(cycles[-1]["continuity"]) and report["identity_and_model_continuity"] is True
            and final["server_operations_sha256"]==hashlib.sha256(operations).hexdigest()
            and final["client_operations_sha256"]==hashlib.sha256(client_ops).hexdigest()
            and final["server_operation_records"]==len(ops),"final continuity binds actual surviving owner history")
    files=report["owner_files"];listed=set()
    for item in files:
        path=artifact_file(root,item["path"]);require(item["path"] not in listed,"duplicate preserved owner file")
        listed.add(item["path"])
        require(path.stat().st_size==item["bytes"] and sha(path)==item["sha256"],"exact preserved owner/backup bytes")
    actual={path.relative_to(root).as_posix() for prefix in ("owners","midpoint-backup") for path in (root/prefix).rglob("*") if path.is_file()}
    require(listed==actual,"no silent omission from final owner/backup inventory")
    for path in root.rglob("*"):
        require(not path.is_symlink(),"continuity evidence contains a link")
        if path.is_file():
            require(path.suffix.lower() not in (".key",".pfx",".p12"),"private credential file in continuity evidence")
            data=path.read_bytes()
            require(not any(marker in data for marker in (b"-----BEGIN PRIVATE KEY-----",b"-----BEGIN EC PRIVATE KEY-----",b"-----BEGIN RSA PRIVATE KEY-----")),"private key material in continuity evidence")
    timing=check_timing(report,events,selected)
    return dict(status="PASS",classification=selected["name"],cycles=selected["cycles"],owners=owners,wire_keys=selected["keys"],durable_candidate_keys=3,
                service_starts=10,owned_stops=10,retained_models=2,model_digests=sorted(model_hashes),events_sha256=report["events_sha256"],
                independent_host_validation="OPEN_UNAVAILABLE",scientific_samples=0,report_sha256=sha(root/"soak-report.json"),unreviewed_activation_guard=activation_guard,timing_observations=timing)


def verify_soak_midpoint_guard(root,midpoint,owner,selected):
    """Prove the fixed midpoint's owner/history and state-only policy change."""
    root=Path(root)
    blocked=midpoint["unreviewed_activation"]
    streams={name:artifact_file(root,blocked[name]).read_bytes() for name in ("stdout","stderr")}
    require(all(hashlib.sha256(data).hexdigest()==blocked[name+"_sha256"] for name,data in streams.items()),
            "blocked activation raw output differs from its preserved hashes")
    old=root/"owners/server-pre-restore";current=root/"owners/server-restored"
    old_identity,_=identity_chain(old/"ledger.jsonl")
    current_identity,current_rows=identity_chain(current/"ledger.jsonl")
    require(old_identity==current_identity and current_rows[0]["payload"]["identity"]==owner,
            "blocked activation must preserve the same real owner identity")
    old_knowledge,_=knowledge_chain(old/"knowledge.jsonl")
    current_knowledge,_=knowledge_chain(current/"knowledge.jsonl")
    require(old_knowledge==current_knowledge,"blocked activation cannot replace retained knowledge")
    before,prior=operational_chain(old/"operations.jsonl",owner)
    after,later=operational_chain(current/"operations.jsonl",owner)
    require(after.startswith(before),"restored operational history must retain its exact old prefix")
    backup=root/"midpoint-backup"
    manifest=load(backup/"backup-manifest.json")
    pin=sha(backup/"backup-manifest.json")
    require(manifest["schema"]=="symbiote.owner-backup/1" and manifest["identity"]==owner
            and all(midpoint[key]["identity"]==owner and midpoint[key]["manifest_sha256"]==pin for key in ("backup","verification","restore")),
            "blocked activation must concern the actual verified same-owner backup")
    for name in ("ledger.jsonl","knowledge.jsonl","operations.jsonl","operations-owner.json"):
        saved=artifact_file(root,"midpoint-backup/files/"+name).read_bytes()
        expected=artifact_file(root,"owners/server-pre-restore/"+name).read_bytes()
        require(saved==expected and manifest["files"][name]==dict(bytes=len(saved),sha256=hashlib.sha256(saved).hexdigest()),
                "backup and pre-restore owner/history bytes must agree")
    last_rotation=max(cycle for cycle in selected["rotations"] if cycle<selected["restore"])
    old_manifest=load(artifact_file(root,f"public-policies/rotation-{last_rotation}-server.json"))
    new_manifest=load(artifact_file(root,"public-policies/midpoint-restored-server.json"))
    require(old_manifest["identity"]==new_manifest["identity"]==owner
            and old_manifest["schema"]==new_manifest["schema"]=="symbiote.service-config/1"
            and {k:v for k,v in old_manifest.items() if k!="state"}=={k:v for k,v in new_manifest.items() if k!="state"},
            "midpoint public policy may change only its state path")
    ca=sha(artifact_file(root,"public-certificates/ca.pem"))
    previous=dict(manifest=old_manifest,ca_sha256=ca);following=dict(manifest=new_manifest,ca_sha256=ca)
    old_policy=digest(previous);new_policy=digest(following)
    latest=next((row["payload"]["policy_digest"] for row in reversed(prior) if row["payload"]["event"]=="policy_transitioned"),prior[0]["payload"]["policy_digest"])
    require(old_policy==latest==manifest["operational_policy_sha256"]
            and prior[-1]["sha256"]==manifest["operational_head_sha256"],"copied old public policy must match the real backup epoch/head")
    activation=midpoint["activation"]
    require(activation["identity"]==owner and activation["previous_policy_sha256"]==old_policy
            and activation["policy_sha256"]==new_policy,"reviewed relocation must bind both recomputed public policy digests")
    mapping_pin=midpoint["restore"]["restore_mapping_sha256"]
    require(isinstance(mapping_pin,str) and re.fullmatch(r"[0-9a-f]{64}",mapping_pin) is not None,"bounded restore mapping digest")
    mapping_file=artifact_file(root,"owners/server-restored/restored-owner-"+mapping_pin+".json")
    mapping=load(mapping_file)
    require(sha(mapping_file)==mapping_pin and mapping["schema"]=="symbiote.restored-owner/1"
            and mapping["identity"]==owner and mapping["manifest_sha256"]==pin
            and mapping["manifest_json"].encode()==(backup/"backup-manifest.json").read_bytes(),"restore mapping binds the exact verified backup and owner")
    def location(value):
        require(isinstance(value,str) and bool(value),"public policy state path is required")
        if manifest["operating_system"]=="windows":return ntpath.normcase(ntpath.normpath(value.removeprefix("\\\\?\\")))
        return os.path.normpath(value)
    require(location(old_manifest["state"])==location(manifest["source_state"])==location(mapping["source_state"])==location(activation["relocation"]["prior_state"])
            and location(new_manifest["state"])==location(mapping["restored_state"])==location(activation["relocation"]["restored_state"])
            and activation["relocation"]["restore_mapping_sha256"]==mapping_pin,"copied policy paths must bind the actual source and reviewed restore mapping")
    transitions=[row["payload"] for row in later[len(prior):] if row["payload"]["event"]=="policy_transitioned"
                 and row["payload"]["relocation"] is not None]
    require(len(transitions)==1 and transitions[0]["previous_policy"]==previous and transitions[0]["policy"]==following
            and transitions[0]["previous_policy_digest"]==old_policy and transitions[0]["policy_digest"]==new_policy
            and transitions[0]["relocation"]==activation["relocation"],"actual policy transition must anchor the copied snapshots and relocation")
    return activation_guard_kind(blocked,streams["stdout"],streams["stderr"],old_policy!=new_policy)

if __name__=="__main__":
    try:raise SystemExit(main())
    except (RuntimeError,OSError,ValueError,KeyError,subprocess.SubprocessError) as failure:
        print(json.dumps(dict(status="HOLD",failure=str(failure))));raise SystemExit(1)
