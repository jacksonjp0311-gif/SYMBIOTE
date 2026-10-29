"""Once-only, externally pinned local API-transfer experiment supervisor.

Native phase children inherit the worker's owned process group/job; no nested
session can survive an enclosing cancellation. This file does not run at import.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import types

ROOT = Path(__file__).resolve().parents[1]
LOADED_HELPERS = {}
sys.dont_write_bytecode = True


def source_module(name):
    path = ROOT / "tools" / (name + ".py")
    before = path.stat()
    if path.is_symlink() or before.st_size > 4 * 1024 * 1024:
        raise ValueError("linked or oversized source helper")
    raw = path.read_bytes(); after = path.stat()
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or len(raw) != before.st_size):
        raise ValueError("source helper changed while reading")
    selected = types.ModuleType(name); selected.__file__ = str(path)
    # Qualified dependencies resolve to the already checked source modules below.
    sys.modules[name] = selected
    exec(compile(raw, str(path), "exec"), selected.__dict__)
    LOADED_HELPERS[name] = hashlib.sha256(raw).hexdigest()
    return selected


_helper_names = ("source_fingerprint", "stability_campaign", "qualification_awake", "engine_evolution")
_previous_modules = {name: sys.modules.get(name) for name in _helper_names}
try:
    source_fingerprint = source_module("source_fingerprint")
    safety = source_module("stability_campaign")
    QualificationAwake = source_module("qualification_awake").QualificationAwake
    _callback_helpers = source_module("engine_evolution")
    cache_observe, read_line = _callback_helpers.cache_observe, _callback_helpers.read_line
finally:
    for _name, _previous in _previous_modules.items():
        if _previous is None: sys.modules.pop(_name, None)
        else: sys.modules[_name] = _previous

PROTOCOL = "SYMBIOTE-V11-TRANSFER-001"
PROTOCOL_FILE = ROOT / "docs/V11_TRANSFER_PROTOCOL_001.md"
SPEC_FILE = ROOT / "docs/V11_TRANSFER_PROTOCOL_001.json"
SECONDS = 600
BYTES = 128 * 1024 * 1024
ARMS = ("transfer", "isolated", "equal", "cache")
ROLES = ("a-own", "b-own", "a-foreign", "b-foreign")


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    return safety.sha(path)


def load(path):
    return safety.load(path)


def write(path, value):
    safety.write_new(path, value)


def canonical(value):
    return safety.encode(value)


def clean_source():
    need(not subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT), "clean committed source required")
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()


def spec_check(spec):
    need(spec["schema"] == "symbiote.v11-transfer-spec/1" and spec["protocol"] == PROTOCOL,
         "prospective machine task contract identity")
    need(spec["width"] == 8 and spec["fresh_inputs"] == 32 and spec["horizons"] == [1, 16, 32]
         and spec["query_policy"] == "rank-basis-min/v1" and spec["max_queries_per_source"] == 16
         and spec["max_gf2_per_episode"] == 1_000_000
         and spec["bounds"] == {"seconds": SECONDS, "evidence_bytes": BYTES}, "fixed task/bounds contract")
    need(len(spec["cases"]) == 2, "exactly two prospective task pairs")
    for index, case in enumerate(spec["cases"]):
        need(set(case) == {"a", "b"}, "two independent private wirings")
        for wiring in case.values():
            need(set(wiring) == {"mask", "bias"} and type(wiring["mask"]) is int
                 and 0 <= wiring["mask"] < 256 and type(wiring["bias"]) is int and wiring["bias"] in (0, 1), "wiring schema")
        for role in ("a", "b"):
            seed = hashlib.sha256(f"{PROTOCOL}/case/{index}/{role}".encode("utf-8")).digest()
            need(case[role] == dict(mask=1+seed[0] % 255, bias=seed[1] & 1), "registered deterministic pair differs")


def fresh(path):
    path = Path(path)
    need(path.is_absolute() and not path.exists(), "fresh absolute evidence root")
    base = Path(tempfile.gettempdir()).resolve(strict=True)
    need(base in path.parents and path.parent.resolve(strict=True) == path.parent and len(str(path)) <= 110,
         "short canonical OS Temp evidence root")
    path.mkdir()
    return path


def register(args):
    need(os.name == "nt", "this prospective measured study requires this Windows PC; other-host qualification is separate")
    commit = clean_source()
    spec = load(SPEC_FILE); spec_check(spec)
    root = fresh(args.out)
    consumer = Path(args.consumer).resolve(strict=True)
    version_call = safety.execute([consumer, "--version"], root, "consumer-admission", timeout=10)
    safety.check_exit(version_call)
    version = json.loads(safety.output(version_call, root))
    need(version["schema"] == "symbiote.transfer-consumer-version/1" and version["build_source_commit"] == commit,
         "consumer compiled source stamp must match clean candidate")
    proof = Path(args.build_proof).resolve(strict=True)
    need(load(proof)["source_commit"] == commit, "build proof source differs")
    value = dict(schema="symbiote.v11-transfer-registration/1", protocol=PROTOCOL, source_commit=commit,
                 source_manifest=source_fingerprint.manifest(ROOT), protocol_sha256=sha(PROTOCOL_FILE),
                 spec_sha256=sha(SPEC_FILE), spec=spec, artifacts=str(root), consumer=dict(path=str(consumer), sha256=sha(consumer)),
                 build_proof=dict(path=str(proof), sha256=sha(proof)), version=version,
                 adapter_sha256=sha(ROOT / "adapters/switchbox_source.py"),
                 supervisor_sha256=sha(Path(__file__)), callback_helper_sha256=sha(ROOT / "tools/engine_evolution.py"),
                 executed_helper_sha256=dict(LOADED_HELPERS),
                 interruption="owned-actual-process-kill-after-all-predictions-before-outcome; explicit verified-dead recovery",
                 automatic_retry=False, scientific_samples=0)
    path = root / "registration.json"; write(path, value)
    print(json.dumps(dict(status="REGISTERED_NOT_RUN", registration=str(path), sha256=sha(path))))


def validate(registration):
    need(registration["schema"] == "symbiote.v11-transfer-registration/1" and registration["protocol"] == PROTOCOL,
         "registration identity")
    root=Path(registration["artifacts"])
    need(root.is_absolute() and root.resolve(strict=True)==root and Path(tempfile.gettempdir()).resolve(strict=True) in root.parents,
         "registered evidence root must stay within canonical OS Temp")
    spec_check(registration["spec"])
    need(registration["executed_helper_sha256"] == LOADED_HELPERS
         and all(sha(ROOT / "tools" / (name + ".py")) == expected for name, expected in LOADED_HELPERS.items()),
         "executed source helpers differ from original registered bytes")
    need(clean_source() == registration["source_commit"] and sha(PROTOCOL_FILE) == registration["protocol_sha256"]
         and sha(SPEC_FILE) == registration["spec_sha256"] and load(SPEC_FILE) == registration["spec"], "source/protocol/task changed")
    source_fingerprint.verify(ROOT, registration["source_manifest"])
    for name in ("consumer", "build_proof"):
        need(sha(registration[name]["path"]) == registration[name]["sha256"], "registered executable/build bytes changed")
    for path, key in ((ROOT / "adapters/switchbox_source.py", "adapter_sha256"),
                      (Path(__file__), "supervisor_sha256"), (ROOT / "tools/engine_evolution.py", "callback_helper_sha256")):
        need(sha(path) == registration[key], "registered supervisor/source helper changed")


def phase_call(argv, root, label, deadline, interrupt_after=None):
    """No new session: the enclosing supervisor retains all descendant ownership."""
    need(time.monotonic() < deadline, "phase deadline before launch")
    paths = [root / (label + suffix) for suffix in (".stdout", ".stderr")]
    started = time.monotonic(); overflow = threading.Event(); lock = threading.Lock(); count = [0]
    process = None; threads = []; status = "HOLD"; interrupted = False; interruption_marker = None
    timed_out = False; failure = None; lock_bindings=[]
    with paths[0].open("xb") as stdout, paths[1].open("xb") as stderr:
        def drain(pipe, target):
            try:
                while True:
                    raw = pipe.read(65536)
                    if not raw: break
                    with lock:
                        keep = min(len(raw), max(0, 2 * 1024 * 1024-count[0]))
                        target.write(raw[:keep]); count[0] += keep
                        if keep != len(raw): overflow.set()
            except (OSError,ValueError):
                overflow.set()
            finally:
                pipe.close()
        try:
            process = subprocess.Popen([str(item) for item in argv], cwd=ROOT, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=0x08000000 if os.name=="nt" else 0)
            for pipe, target in ((process.stdout, stdout), (process.stderr, stderr)):
                thread = threading.Thread(target=drain, args=(pipe, target), daemon=True); thread.start(); threads.append(thread)
            while process.poll() is None and time.monotonic() < min(deadline, started+45) and not overflow.is_set():
                if interrupt_after is not None:
                    marker = interrupt_after.with_name(interrupt_after.name + ".interruption-ready.json")
                    if marker.exists():
                        interruption_marker = load(marker)
                        need(interruption_marker["schema"] == "symbiote.transfer-interruption-ready/1"
                             and type(interruption_marker["pid"]) is int and interruption_marker["pid"] == process.pid
                             and interruption_marker["prediction_receipt_sha256"] == sha(interrupt_after),
                             "actual owned process interruption binding")
                        lock_bindings=owned_lock_bindings(interrupt_after.parent/"state",process.pid)
                        process.kill(); interrupted = True
                        break
                time.sleep(0.02)
            timed_out = time.monotonic() >= min(deadline, started+45)
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
        except BaseException as error:
            failure = type(error).__name__ + ": " + str(error)
        finally:
            try:
                if process is not None and process.poll() is None: process.kill(); process.wait(timeout=3)
            except BaseException as error:
                failure = (failure or "") + "; cleanup: " + str(error)
            for thread in threads: thread.join(timeout=2)
    exited = process is not None and process.poll() is not None
    expected_exit = (process.returncode != 0 and interrupted if interrupt_after is not None else process.returncode == 0) if exited else False
    cleanup_verified = (process is None or exited) and all(not thread.is_alive() for thread in threads)
    status = "completed" if expected_exit and cleanup_verified and failure is None and not timed_out and not overflow.is_set() else "HOLD"
    receipt = dict(schema="symbiote.v11-transfer-phase-process/1", label=label, argv=[str(value) for value in argv],
                   pid=process.pid if process else None, exit_code=process.returncode if process else None,
                   outcome=status, failure=failure, cleanup_verified=cleanup_verified, elapsed_seconds=time.monotonic()-started,
                   stdout_sha256=sha(paths[0]), stderr_sha256=sha(paths[1]), output_truncated=overflow.is_set(),
                   timeout=timed_out,
                   interrupted_after_commit=interrupted, interruption_marker=interruption_marker,
                   observed_owner_lock_bindings=lock_bindings,
                   observed_exited=exited, containment="inherits enclosing worker owned group/job",
                   peak_memory=dict(kind="unknown per phase; enclosing process containment and full wall time retained", bytes=None))
    write(root / (label + ".process.json"), receipt)
    need(status == "completed" and time.monotonic() <= deadline, "native phase failed; original streams/receipt preserved: " + label)
    return receipt


def owned_lock_bindings(state, pid):
    bindings=[]
    for role in ("a","b"):
        for name in ("writer.lock","knowledge.writer.lock"):
            path=state/role/name
            need(path.is_file() and not path.is_symlink() and path.stat().st_size<=4096,"actual live owner lock witness required")
            raw=path.read_bytes()
            need(raw.startswith(f"process={pid}\n".encode("ascii")),"owner lock does not belong to exact child being interrupted")
            bindings.append(dict(owner_role=role,name=name,pid=pid,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
    return bindings


class Sources:
    def __init__(self, descriptors, wirings, private, root):
        self.children = []; self.endpoints = {}; self.private = private; self.root = root
        try:
            for role in ROLES:
                concept = "a" if role in ("a-own", "b-foreign") else "b"
                secret = private / role; secret.mkdir()
                token = secrets.token_hex(32); (secret / "token").write_text(token, encoding="ascii"); (secret / "token").chmod(0o600)
                descriptor = descriptors[concept]
                config = dict(**descriptor, **wirings[concept], token_file="token", max_queries=16, lifetime_ms=60000)
                write(secret / "source.json", config)
                stderr = (root / (role + ".source.stderr")).open("xb")
                child = subprocess.Popen([sys.executable, "-B", ROOT / "adapters/switchbox_source.py", "--config", secret / "source.json",
                                          "--transcript", root / (role + ".source.jsonl")], cwd=ROOT, stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=stderr, creationflags=0x08000000 if os.name=="nt" else 0)
                self.children.append((role, child, stderr, time.monotonic()))
                ready = read_line(child.stdout, 3)
                need(ready["schema"] == "symbiote.switchbox-ready/1" and all(ready[key] == value for key, value in descriptor.items()), "authorized source readiness differs")
                self.endpoints[role] = dict(source=descriptor, address=ready["address"], token_file=str(secret / "token"))
                write(root / (role + ".source-ready.json"), ready)
        except BaseException:
            self.close(); raise

    def close(self):
        failures = []
        for role, child, stderr, started in self.children:
            error_text = None
            try:
                if child.stdin:
                    child.stdin.close(); child.stdin = None
                summary = read_line(child.stdout, 3)
                child.wait(timeout=3)
                need(child.returncode == 0 and summary["owner_stopped"] is True and summary["denied_requests"] == 0,
                     "owned source failed or denied a query")
                write(self.root / (role + ".source-summary.json"), summary)
            except BaseException as error:
                failures.append(str(error))
                error_text = str(error)
            finally:
                if child.poll() is None: child.kill(); child.wait(timeout=3)
                stderr.close()
                write(self.root / (role + ".source-process.json"), dict(schema="symbiote.v11-owned-source-process/1",
                    pid=child.pid, exit_code=child.returncode, observed_exited=child.poll() is not None,
                    owner_pipe_closed=True, elapsed_seconds=time.monotonic()-started, failure=error_text,
                    stderr_sha256=sha(self.root / (role + ".source.stderr")),
                    containment="inherits enclosing worker owned group/job"))
        self.children.clear()
        need(not failures, "source cleanup/summary failed: " + "; ".join(failures))


def fresh_inputs(index, observed):
    domain = sorted(range(256), key=lambda value: hashlib.sha256(f"{PROTOCOL}/case/{index}/input/{value}".encode()).digest())
    selected = [value for value in domain if value not in observed][:32]
    need(len(selected) == 32, "not enough disjoint fresh tasks")
    return selected


def grade_predictions(inputs, predictions, wiring):
    need(len(inputs) == 32 and len(set(inputs)) == 32 and all(type(value) is int and 0 <= value < 256 for value in inputs),
         "complete bounded fresh task list")
    need(len(predictions) == 32 and [row["input"] for row in predictions] == inputs,
         "complete ordered predictions before grade")
    need(all(type(row["input"]) is int and (row["answer"] is None or type(row["answer"]) is int and row["answer"] in (0, 1))
             for row in predictions), "prediction answers must be binary integers or explicit abstentions")
    truth = [((value & wiring["mask"]).bit_count() % 2) ^ wiring["bias"] for value in inputs]
    return [dict(horizon=h, correct=sum(row["answer"] == expected for row, expected in zip(predictions[:h], truth[:h])),
                 abstentions=sum(row["answer"] is None for row in predictions[:h])) for h in (1, 16, 32)]


def prediction_binding(report, freeze):
    need(report["status"] == "PREDICTIONS_COMMITTED" and report["source_calls"] == 0
         and report["source_contact_attempts"] == 0 and report["learning_during_evaluation"] is False
         and report["labels_received"] is False, "native evaluation must remain source-off and label-free")
    need(type(report["source_calls"]) is int and type(report["source_contact_attempts"]) is int
         and len(report["predictions"]) == 2, "strict complete native evaluation counters/owners")
    for index in range(2):
        received = freeze["acquisition"]["received"][index]
        record_sha = freeze["artifacts"][index]["record_sha256"] if freeze["arm"] == "transfer" else received["record_sha256"]
        need(all(row["record_sha256"] == record_sha for row in report["predictions"][index]), "fresh use did not use exact frozen artifact")
        need(report["before"][index]["knowledge"] == report["after"][index]["knowledge"] == freeze["inspections"][index]["knowledge"],
             "frozen knowledge changed during evaluation")


def state_vector(path):
    return {role: sum(item.stat().st_size for item in (path / role).rglob("*") if item.is_file()) for role in ("a", "b")}


def committed_hashes(path):
    return {role+"/"+name:sha(path/role/name) for role in ("a","b")
            for name in ("ledger.jsonl","knowledge.jsonl","operations.jsonl","operations-owner.json")}


def acquisition_vector(freeze):
    result = []
    for index, owner in enumerate(("a", "b")):
        own = freeze["acquisition"]["own_learning"][index]
        received = freeze["acquisition"]["received"][index]
        learning = received["learning"] if freeze["arm"] == "transfer" else received
        traces = [freeze["acquisition"]["source_traces"][owner + suffix] for suffix in ("-own", "-foreign")]
        result.append(dict(owner=freeze["owners"][index], source_calls=sum(len(trace["observations"]) for trace in traces),
                           inference_validation_gf2=own["usage"]["gf2_work_units"] + learning["usage"]["gf2_work_units"],
                           source_plaintext_bytes=sum(trace["io"]["request_bytes"] + trace["io"]["response_bytes"] for trace in traces),
                           independent_evaluation_cases=own["usage"]["evaluation_cases"] + learning["usage"]["evaluation_cases"],
                           unknown_compute=["evaluator internals", "cold replay", "proof validation", "ledger publication CPU"],
                           no_scalar_conversion=True))
    return result


def one_case(index, wirings, root, private, executable, deadline):
    root.mkdir(); openings = {}; descriptors = {}
    for concept in ("a", "b"):
        openings[concept] = dict(width=8, **wirings[concept], salt=secrets.token_hex(32))
        descriptors[concept] = dict(source_id=f"transfer-authority-{index}-{concept}", scope=f"v11-transfer/{index}/{concept}",
                                    epoch="stationary-1", commitment=hashlib.sha256(canonical(openings[concept])).hexdigest(), width=8)
    observed = set(); acquired = {}
    for arm in ARMS:
        target = root / arm; target.mkdir()
        secret = private / arm; secret.mkdir()
        source_set = Sources(descriptors, wirings, secret, target)
        try:
            if arm != "cache":
                client = secret / "consumer.json"
                write(client, dict(schema="symbiote.transfer-source-config/1", sources=list(descriptors.values()), endpoints=source_set.endpoints))
                phase_call([executable, "acquire", "--config", client, "--arm", arm, "--out", target / "state"], target, "acquire", deadline)
                freeze = load(target / "state/freeze.json")
                for trace in freeze["acquisition"]["source_traces"].values():
                    observed.update(item["input"] for item in trace["observations"])
                acquired[arm] = dict(freeze_sha256=sha(target / "state/freeze.json"), vector=acquisition_vector(freeze),
                                     state_bytes=state_vector(target / "state"))
            else:
                caches = {}
                for role, endpoint in source_set.endpoints.items():
                    descriptor = endpoint["source"]
                    token = Path(endpoint["token_file"]).read_text(encoding="ascii")
                    observations = []
                    for sequence, input_value in enumerate([0, 1, 2, 4, 8, 16, 32, 64, 128, 3]):
                        output, wire = cache_observe(endpoint["address"], descriptor, token, sequence, input_value)
                        observations.append(dict(input=input_value, output=output, plaintext_bytes=wire)); observed.add(input_value)
                    caches[role] = observations
                write(target / "freeze.json", dict(schema="symbiote.transfer-cache-freeze/1", caches=caches, model_constructed=False))
                acquired[arm] = dict(freeze_sha256=sha(target / "freeze.json"), cache_bytes=(target / "freeze.json").stat().st_size)
        finally:
            source_set.close()
    # All sources stopped, all native owners closed, before revealing any task.
    cache=load(root/"cache/freeze.json")["caches"]
    for arm in ("transfer","isolated","equal"):
        frozen=load(root/arm/"state/freeze.json")
        for role in ROLES:
            actual=[dict(input=row["input"],output=row["output"]) for row in frozen["acquisition"]["source_traces"][role]["observations"]]
            need(actual==[dict(input=row["input"],output=row["output"]) for row in cache[role]],"controls received different actual source observations")
    inputs = fresh_inputs(index, observed)
    write(root / "fresh-input-reveal.json", dict(schema="symbiote.transfer-reveal/1", inputs=inputs, observed_inputs=sorted(observed), frozen=acquired))
    committed = []
    for arm in ARMS:
        target = root / arm
        if arm != "cache":
            write(target / "inputs.json", dict(schema="symbiote.transfer-fresh-inputs/1", freeze_sha256=acquired[arm]["freeze_sha256"], inputs=inputs))
            argv=[executable, "predict", "--state", target / "state", "--inputs", target / "inputs.json", "--out", target / "predictions.json"]
            if arm=="transfer":argv.append("--hold-after-commit")
            phase_call(argv,target,"predict",deadline,interrupt_after=target/"predictions.json" if arm=="transfer" else None)
        else:
            cache = load(target / "freeze.json")["caches"]
            predictions = []
            for owner in ("a", "b"):
                table = {row["input"]: row["output"] for row in cache[owner + "-foreign"]}
                predictions.append([dict(input=value, answer=table.get(value), basis="exact observed answers only") for value in inputs])
            write(target / "predictions.json", dict(schema="symbiote.transfer-cache-predictions/1", status="PREDICTIONS_COMMITTED", predictions=predictions))
        committed.append(dict(arm=arm, path=f"{arm}/predictions.json", sha256=sha(target / "predictions.json")))
    write(root / "predictions-committed.json", dict(schema="symbiote.transfer-all-predictions/1", predictions=committed))
    # Private commitment openings and labels appear only after every receipt is committed.
    write(root / "openings-after-commit.json", dict(predictions_commit_sha256=sha(root / "predictions-committed.json"), openings=openings))
    graded = []
    for item in committed:
        value = load(root / item["path"])
        rows = []
        for owner_index, concept in enumerate(("b", "a")):
            actual = value["predictions"][owner_index]
            rows.append(dict(owner_index=owner_index, horizons=grade_predictions(inputs, actual, wirings[concept])))
        graded.append(dict(arm=item["arm"], owners=rows, predictions_sha256=item["sha256"]))
    grade = root / "grade-after-commit.json"
    write(grade, dict(schema="symbiote.transfer-external-grade/1", predictions_commit_sha256=sha(root / "predictions-committed.json"), grades=graded))
    transfer = root / "transfer"
    phase_call([executable,"recover","--state",transfer/"state","--out",transfer/"recovery.json"],transfer,"explicit-verified-dead-recovery",deadline)
    recovered=load(transfer/"recovery.json")
    need(all(row["ledgers_modified"] is False and row["processes_terminated"]==0
             and set(row["recovered_locks"])=={"writer.lock","knowledge.writer.lock"} for row in recovered["recovery"]),
         "actual interrupted-owner locks must be explicitly recovered without changing history")
    phase_call([executable, "complete", "--state", transfer / "state", "--predictions", transfer / "predictions.json",
                "--grade-commit", sha(grade), "--out", transfer / "outcomes.json"], transfer, "complete", deadline)
    before_repeat=committed_hashes(transfer/"state")
    phase_call([executable, "reconcile", "--state", transfer / "state", "--predictions", transfer / "predictions.json",
                "--grade-commit", sha(grade), "--out", transfer / "reconciliation-restart.json"], transfer, "reconcile", deadline)
    need(committed_hashes(transfer/"state")==before_repeat,"repeated reconciliation appended credit or changed committed journals")
    outcomes = load(transfer / "outcomes.json"); repeat = load(transfer / "reconciliation-restart.json")
    need(all(row["newly_reconciled"] is True for row in outcomes["reconciliations"])
         and all(row["newly_reconciled"] is False for row in repeat["reconciliations"]), "exactly-once causal reconciliation across OS-process restart")
    for result in outcomes["outcomes"]:
        value=result["outcome"]
        need(value["quality"]=="conditional" and value["uses"]==32 and value["baseline"]["kind"]=="unknown"
             and value["verified_benefit"] is False and value["measured_net"] is None,
             "external fresh labels must not become native known-use or measured-benefit flags")
    for arm in ("transfer", "isolated", "equal"):
        report = load(root / arm / "predictions.json")
        prediction_binding(report, load(root / arm / "state/freeze.json"))
        for row in next(value for value in graded if value["arm"] == arm)["owners"]:
            need(row["horizons"][-1]["correct"] == 32, "conditional structural fresh correctness")
        need(all(row["source_calls"] == 20 for row in acquired[arm]["vector"]), "same per-owner independent source-query horizon")
    for owner_index in range(2):
        need(acquired["equal"]["vector"][owner_index]["inference_validation_gf2"] <= acquired["transfer"]["vector"][owner_index]["inference_validation_gf2"],
             "equal-query/GF2 control exceeded measured transfer inference allowance")
    components={}
    for arm in ("transfer","isolated","equal"):
        freeze=load(root/arm/"state/freeze.json");prediction=load(root/arm/"predictions.json")
        components[arm]=dict(acquisition_native_resources=freeze["acquisition"]["resource_end"],
            cold_use_native_resources=prediction["resource_end"],horizons=prediction["horizons"],
            state_before_use_bytes=prediction["state_before_bytes"],state_after_use_bytes=prediction["state_after_bytes"],
            artifact_boundary_json_bytes=sum((root/arm/"state"/name).stat().st_size for name in ("artifact-a.json","artifact-b.json")) if arm=="transfer" else 0,
            local_exchange_network_bytes=0,local_exchange_boundary="explicit host-owned in-memory API; serialized artifacts are evidence bytes, not invented network traffic",
            unknown_components=["unattributed primitive CPU", "identity-ledger setup CPU", "host callback bookkeeping"],
            byte_counter_policy="per-instance totals include cold opening; categories overlap and must not be summed")
    components["transfer"].update(outcome_closure_resources=outcomes["resource_end"],restart_reconciliation_resources=repeat["resource_end"])
    report = dict(schema="symbiote.v11-transfer-case/1", index=index, acquisitions=acquired, graded=graded,component_vectors=components,
                  actual_bilateral_outcome=outcomes, restarted_reconciliation=repeat,
                  unchanged_repeat_committed_hashes=before_repeat,
                  whole_operation_costs="component vectors/time/state deltas retained; uninstrumented work unknown, no scalar cost claim",
                  reciprocal_efficiency="NOT_DEMONSTRATED", reason="optimized isolated structural control also answers every fresh task; transfer does not reduce source calls",
                  scientific_samples=0, fresh_case_input_pairs=64)
    write(root / "case-report.json", report)
    return report


def worker(args):
    registration = load(args.registration); need(sha(args.registration) == args.registration_sha256, "external registration pin")
    validate(registration)
    root = Path(registration["artifacts"])
    admission = os.environ.get("SYMBIOTE_V11_TRANSFER_ADMISSION", "")
    marker = load(root / "EXECUTION-STARTED.json")
    need(len(admission) == 64 and hashlib.sha256(admission.encode()).hexdigest() == marker["admission_sha256"]
         and marker["registration_sha256"] == args.registration_sha256, "worker requires enclosing once-only admission")
    public = root / "cases"; public.mkdir()
    private_object = tempfile.TemporaryDirectory(prefix="symbiote-v11-transfer-private-")
    private = Path(private_object.name).resolve()
    report = dict(schema="symbiote.v11-transfer-worker/1", status="HOLD", cases=[], scientific_samples=0)
    started = time.monotonic()
    try:
        for index, pair in enumerate(registration["spec"]["cases"]):
            secret = private / f"case-{index}"; secret.mkdir()
            report["cases"].append(one_case(index, pair, public / f"case-{index}", secret,
                                            registration["consumer"]["path"], started+SECONDS-15))
            need(safety.evidence_size(root) <= BYTES-1024*1024, "evidence budget reserve")
        report["status"] = "PASS_CONDITIONAL_BILATERAL_API_TRANSFER"
    except BaseException as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        report["elapsed_seconds"] = time.monotonic()-started
        write(root / "worker-report.json", report)
        need(private.parent == Path(tempfile.gettempdir()).resolve() and private.name.startswith("symbiote-v11-transfer-private-"), "private cleanup boundary")
        private_object.cleanup()


def measured_job_class(observations):
    """Read the original bounded owned job immediately before its handle closes."""
    parent = safety.WindowsJob
    class MeasuredJob(parent):
        def close(self):
            try:
                if self.handle and self.attached:
                    from ctypes import wintypes as w
                    class Basic(ctypes.Structure):
                        _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                            ("flags", w.DWORD), ("minimum_ws", ctypes.c_size_t), ("maximum_ws", ctypes.c_size_t),
                            ("active_limit", w.DWORD), ("affinity", ctypes.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]
                    class Io(ctypes.Structure):
                        _fields_ = [(name, ctypes.c_ulonglong) for name in ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]
                    class Extended(ctypes.Structure):
                        _fields_ = [("basic", Basic), ("io", Io), ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                                    ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
                    class AccountingAndIo(ctypes.Structure):
                        _fields_=[("basic",self.accounting),("io",Io)]
                    started = time.perf_counter_ns(); info = Extended(); accounting = AccountingAndIo()
                    need(self.kernel.QueryInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info), None), "owned job peak-memory query failed")
                    # ExtendedLimitInformation.IoInfo is reserved. Actual job I/O
                    # comes only from BasicAndIoAccountingInformation, class 8.
                    need(self.kernel.QueryInformationJobObject(self.handle, 8, ctypes.byref(accounting), ctypes.sizeof(accounting), None), "owned job CPU/I/O accounting query failed")
                    need(info.peak_process > 0 and info.peak_job > 0, "actual owned job committed-memory peak required")
                    observations.append(dict(kind="windows-job-peak-committed-bytes-not-RSS", peak_process_bytes=info.peak_process,
                        peak_job_bytes=info.peak_job, cpu_user_100ns=accounting.basic.user, cpu_kernel_100ns=accounting.basic.kernel,
                        io={name: getattr(accounting.io, name) for name, _ in Io._fields_},
                        io_information_class=8,io_scope="all owned job processes; OS operation counters, not physical disk or plaintext transport bytes",
                        query_seconds=(time.perf_counter_ns()-started)/1e9,
                        scope="whole worker, native owners, independent sources, controls and grading; not participant-attributed",
                        limits_unchanged=True))
            finally:
                super().close()
    return MeasuredJob


def run(args):
    registration = load(args.registration); need(sha(args.registration) == args.registration_sha256, "external registration pin")
    validate(registration)
    root = Path(registration["artifacts"]); admission = secrets.token_hex(32)
    write(root / "EXECUTION-STARTED.json", dict(registration_sha256=args.registration_sha256,
        admission_sha256=hashlib.sha256(admission.encode()).hexdigest(), automatic_retry=False, started_at_unix=time.time()))
    processes = root / "processes"; processes.mkdir()
    cancelled = threading.Event(); awake = QualificationAwake(); started = time.monotonic(); previous = {}
    report = dict(schema="symbiote.v11-transfer-result/1", status="HOLD", source_commit=registration["source_commit"],
                  registration_sha256=args.registration_sha256, scientific_samples=0)
    need(os.name == "nt", "registered measured study is Windows-PC only")
    job_measurements = []; original_job = safety.WindowsJob
    safety.WindowsJob = measured_job_class(job_measurements)
    guard_measurement = dict(calls=0, inclusive_seconds=0.0, subtracted_from_elapsed=False)
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.signal(signum, lambda *_: cancelled.set())
    next_watch = [started]
    def check():
        guard_start = time.monotonic()
        try:
            awake.check()
            if time.monotonic() >= next_watch[0]:
                validate(registration); next_watch[0] = time.monotonic()+30
        except BaseException as error:
            report["guard_failure"] = str(error); cancelled.set()
        finally:
            guard_measurement["calls"] += 1
            guard_measurement["inclusive_seconds"] += time.monotonic()-guard_start
        return cancelled.is_set()
    try:
        with awake:
            record = safety.execute([sys.executable, "-B", Path(__file__).resolve(), "worker", "--registration", Path(args.registration).resolve(),
                                     "--registration-sha256", args.registration_sha256], processes, "registered-v11-transfer-worker",
                                     timeout=SECONDS-10, cancelled=check, environment={"SYMBIOTE_V11_TRANSFER_ADMISSION": admission})
            report["process"] = record; safety.check_exit(record)
            need(len(job_measurements) == 1, "one actual complete owned-job measurement required")
            worker_result = load(root / "worker-report.json")
            need(worker_result["status"] == "PASS_CONDITIONAL_BILATERAL_API_TRANSFER", "actual transfer worker did not close")
            validate(registration)
            need(not check() and time.monotonic()-started <= SECONDS, "final cancellation/deadline")
            report.update(status="PASS_ENGINEERING_ONLY", worker=worker_result, reciprocal_efficiency="NOT_DEMONSTRATED")
    except BaseException as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
    finally:
        safety.WindowsJob = original_job
        for signum, handler in previous.items(): signal.signal(signum, handler)
        report.update(elapsed_seconds=time.monotonic()-started, awake=awake.report,
                      whole_worker_resources=job_measurements, guard_instrumentation=guard_measurement)
        if cancelled.is_set() or report["elapsed_seconds"] > SECONDS: report["status"] = "HOLD"
        need(safety.evidence_size(root)+len(canonical(report)) <= BYTES, "final evidence budget")
        write(root / "transfer-report.json", report)
    print(json.dumps(dict(status=report["status"], report=str(root / "transfer-report.json"), sha256=sha(root / "transfer-report.json"))))
    return 0 if report["status"] == "PASS_ENGINEERING_ONLY" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__); subs = parser.add_subparsers(dest="mode", required=True)
    registered = subs.add_parser("register"); registered.add_argument("--consumer", type=Path, required=True)
    registered.add_argument("--build-proof", type=Path, required=True); registered.add_argument("--out", type=Path, required=True)
    for name in ("run", "worker"):
        phase = subs.add_parser(name); phase.add_argument("--registration", type=Path, required=True); phase.add_argument("--registration-sha256", required=True)
    args = parser.parse_args()
    if args.mode == "register": register(args); return
    if args.mode == "worker": worker(args); return
    raise SystemExit(run(args))


if __name__ == "__main__":
    main()
