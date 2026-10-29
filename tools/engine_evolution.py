"""Source-pinned engineering iteration; studies and software fixtures are distinct.

The supervisor owns private wiring and grading. The Rust observer receives only
an approved endpoint/descriptor. Fresh labels are computed after every model has
committed its predictions. Registration is required before the four-case run.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

import source_fingerprint
import stability_campaign as safety
from qualification_awake import QualificationAwake

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = "SYMBIOTE-ENGINE-EVOLUTION-002"
PROTOCOL_FILE = ROOT / "docs/ENGINE_EVOLUTION_PROTOCOL_002.md"
BASELINE = "0616f9a6dc6788078c623a3c2ed2ef237ae11de6"
CASES = [(37, 0), (232, 1), (146, 1), (86, 0)]
MEMORY_TEST = "operational::prefix_index_tests::registered_engine_evolution_002_prefix_profile"
OUTCOME_TEST = "outcomes::two_native_agents_reconcile_receiver_owned_outcome_and_restart"
LIMIT_SECONDS = 600
LIMIT_BYTES = 128 * 1024**2


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def load(path):
    return safety.load(Path(path))


def write(path, value):
    safety.write_new(Path(path), value)


def fresh(path):
    path = Path(path).resolve()
    temporary = Path(tempfile.gettempdir()).resolve()
    need(temporary in path.parents and len(str(path)) <= 100 and not path.exists(),
         "fresh short dedicated OS-temp output required")
    path.mkdir()
    return path


def git_source():
    need(not subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT), "clean source required")
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()


def register(args):
    commit = git_source()
    root = fresh(args.out)
    checked_call([args.native, "--version", "--json"], root, "native-version", time.monotonic()+5)
    checked_call([args.observer, "--version"], root, "observer-version", time.monotonic()+5)
    versions = dict(native=load(root / "native-version.stdout"), observer=load(root / "observer-version.stdout"))
    need(all(value["build_source_commit"] == commit for value in versions.values()),
         "native/observer executable source stamp differs from registered clean source")
    pins = {name: dict(path=str(Path(getattr(args, name)).resolve(strict=True)),
                       sha256=sha(getattr(args, name)))
            for name in ("native", "observer", "memory_test", "service_test")}
    registration = dict(schema="symbiote.engine-evolution-registration/1", protocol=PROTOCOL,
                        baseline_source=BASELINE, source_commit=commit,
                        source_manifest=source_fingerprint.manifest(ROOT), protocol_sha256=sha(PROTOCOL_FILE),
                        artifacts=str(root), **pins,
                        versions=versions,
                        source_adapter=dict(path=str(ROOT / "adapters/switchbox_source.py"),
                                            sha256=sha(ROOT / "adapters/switchbox_source.py")),
                        prefix_profile=dict(histories=[0, 16, 64, 256], captures=32),
                        cases=[dict(width=8, mask=m, bias=b) for m, b in CASES], fresh_inputs=32,
                        bounds=dict(seconds=LIMIT_SECONDS, evidence_bytes=LIMIT_BYTES),
                        scientific_samples=0, automatic_retry=False)
    path = root / "registration.json"
    write(path, registration)
    print(json.dumps(dict(registration=str(path), sha256=sha(path), status="REGISTERED_NOT_RUN")))


def read_line(stream, timeout):
    result = []
    done = threading.Event()

    def read():
        try:
            result.append(stream.readline(8193))
        finally:
            done.set()

    threading.Thread(target=read, daemon=True).start()
    need(done.wait(timeout), "owned source readiness deadline")
    need(result and result[0].endswith(b"\n") and len(result[0]) <= 8192, "owned source readiness frame")
    return json.loads(result[0])


def checked_call(argv, root, label, deadline):
    need(time.monotonic() < deadline, "whole workload deadline")
    started = time.monotonic()
    record = safety.execute(argv, root, label, timeout=min(30, max(0.001, deadline-time.monotonic())),
                            cancelled=lambda: time.monotonic() >= deadline)
    # Bounded original streams/process receipts survive timeout and failure.
    for name in ("stdout", "stderr"):
        (root / (label + "." + name)).write_bytes((root / record[name]).read_bytes())
    need(record["exit_code"] == 0 and record["outcome"] == "completed"
         and record["cleanup_verified"] and not record["output_truncated"], "owned child failed: " + label)
    return record


def state_hashes(state):
    return {p.name: sha(p) for p in Path(state).iterdir() if p.is_file() and p.name != "writer.lock"}


def fresh_inputs(index, observed, count=32):
    order = sorted(range(256), key=lambda value: hashlib.sha256(
        f"{PROTOCOL}/case/{index}/input/{value}".encode("utf-8")).digest())
    return [value for value in order if value not in observed][:count]


def cache_observe(address, config, token, sequence, input_value):
    host, port = address.split(":")
    request = dict(schema="symbiote.switchbox-request/1", source_id=config["source_id"],
                   scope=config["scope"], epoch=config["epoch"], sequence=sequence,
                   input=input_value, token=token)
    wire = json.dumps(request, separators=(",", ":")).encode() + b"\n"
    with socket.create_connection((host, int(port)), timeout=1) as stream:
        stream.sendall(wire)
        raw = stream.makefile("rb").readline(4097)
    need(len(raw) <= 4096 and raw.endswith(b"\n"), "cache source frame")
    reply = json.loads(raw)
    need(reply == dict(schema="symbiote.switchbox-response/1",
                       **{k: config[k] for k in ("source_id", "scope", "epoch", "commitment", "width")},
                       sequence=sequence, input=input_value, output=reply.get("output")), "cache source binding")
    need(type(reply["output"]) is int and reply["output"] in (0, 1), "cache source output")
    return reply["output"], len(wire) + len(raw)


def one_case(index, mask, bias, root, private, native, observer, deadline, expected_source=None):
    root.mkdir()
    rows = []
    scope = f"independent-affine/case-{index}"
    epoch = "stationary-epoch-1"
    opening = dict(width=8, mask=mask, bias=bias, salt=secrets.token_hex(32))
    commitment = hashlib.sha256(safety.encode(opening)).hexdigest()
    for arm in ("reference", "rank", "isolated", "cache"):
        target = root / arm
        target.mkdir()
        secret_dir = private / f"case-{index}-{arm}"
        secret_dir.mkdir()
        token = secrets.token_hex(32)
        (secret_dir / "token").write_text(token, encoding="ascii")
        (secret_dir / "token").chmod(0o600)
        descriptor = dict(source_id="source-" + secrets.token_hex(12), scope=scope, epoch=epoch,
                          commitment=commitment, width=8)
        source_config = dict(**descriptor, mask=mask, bias=bias, token_file="token",
                             max_queries=16, lifetime_ms=30000)
        write(secret_dir / "private.json", source_config)
        child = subprocess.Popen([sys.executable, "-B", str(ROOT / "adapters/switchbox_source.py"),
                                  "--config", str(secret_dir / "private.json"),
                                  "--transcript", str(target / "source-observations.jsonl")],
                                 cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            ready = read_line(child.stdout, 3)
            need(ready["schema"] == "symbiote.switchbox-ready/1"
                 and all(ready[k] == descriptor[k] for k in descriptor), "source readiness descriptor")
            state = target / "state"
            calls = []
            calls.append(checked_call([native, "prepare-service", "--json", "--state", state],
                                      target, "prepare", deadline))
            owner = json.loads((target / "prepare.stdout").read_bytes())["identity"]
            config = dict(schema="symbiote.independent-source-config/1", owner=owner,
                          **descriptor, address=ready["address"], token_file=str(secret_dir / "token"),
                          timeout_ms=12000, max_queries=16, max_work_units=1000000)
            # The endpoint descriptor is public; bearer material remains outside
            # the complete public evidence root and is never given to the grader.
            write(secret_dir / "client.json", config)
            write(target / "approved-descriptor.json", {k:v for k,v in config.items() if k != "token_file"})
            if arm != "cache":
                policy = "reference" if arm == "reference" else "rank"
                calls.append(checked_call([observer, "learn", "--source-config", secret_dir / "client.json",
                                          "--state", state, "--receipts", target / "freeze.json",
                                          "--query-policy", policy], target, "learn", deadline))
                freeze = load(target / "freeze.json")
                need(freeze["schema"] == "symbiote.independent-observer-freeze/1", "native freeze schema")
                need(expected_source is None or freeze["build_source_commit"] == expected_source,
                     "learner source stamp differs before fresh tasks open")
                observed = freeze["observed_inputs"]
                need(len(observed) == len(set(observed)) == 10 and freeze["source_queries"] == 10,
                     "native actual nine training plus one distinct validation query required")
                before = state_hashes(state)
                # The later predict invocation is a separate, restarted process.
                # It reopens/revalidates this model after its source is stopped.
            else:
                # Strong exact cache: it gets the same public basis and one
                # distinct validation input without paying inference work.
                observed = [0, *[1 << bit for bit in range(8)], 3]
                entries = {}
                wire = 0
                for sequence, input_value in enumerate(observed):
                    output, used = cache_observe(ready["address"], descriptor, token, sequence, input_value)
                    entries[str(input_value)] = output
                    wire += used
                freeze = dict(schema="symbiote.answer-cache-freeze/1", owner=owner,
                              source_queries=10, gf2_work_units=0, observed_inputs=observed,
                              entries=entries, plaintext_bytes=wire)
                write(target / "freeze.json", freeze)
                before = state_hashes(state)
            child.stdin.write(b'{"command":"shutdown"}\n')
            child.stdin.flush()
            child.wait(timeout=3)
            summary = json.loads(child.stdout.read())
            errors = child.stderr.read()
            (target / "source.stderr").write_bytes(errors)
            write(target / "source-summary.json", summary)
            need(child.returncode == 0 and summary["source_calls"] == 10 and summary["owner_stopped"],
                 "source call/owned shutdown evidence")
            rows.append(dict(arm=arm, path=target, state=state, config=secret_dir / "client.json",
                             freeze=freeze, freeze_sha256=sha(target / "freeze.json"),
                             observed=set(observed), state_before=before, calls=calls))
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
            for stream in (child.stdin, child.stdout, child.stderr): stream.close()
    observed = set().union(*(row["observed"] for row in rows))
    inputs = fresh_inputs(index, observed)
    need(len(inputs) == 32 and not set(inputs) & observed, "fresh task disjointness")
    # Reveal only after every arm has durable frozen knowledge. All sources are
    # stopped before inference-only evaluation; no source reply can leak labels.
    write(root / "evaluation-reveal.json", dict(schema="symbiote.fresh-reveal/1", inputs=inputs,
                                               freezes={r["arm"]:r["freeze_sha256"] for r in rows}))
    predictions = []
    for row in rows:
        target = row["path"]
        if row["arm"] == "cache":
            value = dict(schema="symbiote.answer-cache-predictions/1", freeze_sha256=row["freeze_sha256"],
                         predictions=[dict(input=i, prediction=row["freeze"]["entries"].get(str(i))) for i in inputs])
            write(target / "predictions.json", value)
        else:
            write(target / "inputs.json", dict(schema="symbiote.independent-observer-inputs/1",
                                              freeze_sha256=row["freeze_sha256"], inputs=inputs))
            row["calls"].append(checked_call([observer, "predict", "--state", row["state"],
                                               "--source-config", row["config"], "--inputs", target / "inputs.json",
                                               "--receipts", target / "predictions.json"], target, "predict", deadline))
            value = load(target / "predictions.json")
            need(expected_source is None or value["build_source_commit"] == expected_source,
                 "predictor source stamp differs before grading")
            need(value["source_queries"] == 0 and value["source_contact_attempts"] == 0
                 and value["learning_during_evaluation"] is False and value["labels_received"] is False,
                 "restarted prediction must not contact a source, learn or receive labels")
            need(state_hashes(row["state"]) == row["state_before"], "evaluation must not update retained learning")
        need([v["input"] for v in value["predictions"]] == inputs, "all predictions committed in task order")
        predictions.append(dict(arm=row["arm"], path=str(target / "predictions.json"),
                                sha256=sha(target / "predictions.json")))
    write(root / "predictions-committed.json", dict(schema="symbiote.predictions-committed/1", predictions=predictions))
    need(hashlib.sha256(safety.encode(opening)).hexdigest() == commitment, "source commitment opening")
    write(root / "source-opening-after-predictions.json", dict(commitment=commitment, opening=opening,
                                                               predictions_committed_sha256=sha(root / "predictions-committed.json")))
    # Independent arithmetic grader, deliberately after all prediction commits.
    truths = {value: (bin(value & mask).count("1") % 2) ^ bias for value in inputs}
    results = []
    for row, commitment_row in zip(rows, predictions):
        need(sha(commitment_row["path"]) == commitment_row["sha256"], "prediction changed before grading")
        value = load(commitment_row["path"])
        answers = value["predictions"]
        correct = sum(type(v["prediction"]) is int and v["prediction"] == truths[v["input"]] for v in answers)
        abstentions = sum(v["prediction"] is None for v in answers)
        need((correct, abstentions) == ((0, 32) if row["arm"] == "cache" else (32, 0)), "fresh conditional predictions")
        source_io = row["freeze"].get("source_io", {})
        candidate_wire = (source_io.get("request_bytes", 0) + source_io.get("response_bytes", 0)
                          if row["arm"] != "cache" else row["freeze"]["plaintext_bytes"])
        vector = dict(source_calls=10, training_source_calls=9, validation_source_calls=1,
                      inference_and_validation_gf2=row["freeze"]["gf2_work_units"],
                      reopen_and_prediction_gf2=value.get("gf2_work_units", 0), prediction_calls=32,
                      plaintext_bytes=candidate_wire,
                      retained_state_bytes=sum(p.stat().st_size for p in row["state"].iterdir() if p.is_file()),
                      cache_bytes=(row["path"] / "freeze.json").stat().st_size if row["arm"] == "cache" else 0,
                      source_audit_bytes=(row["path"] / "source-observations.jsonl").stat().st_size,
                      operational_ledger_replay="not used in this narrow observation embedding",
                      feedback_closure="external grader; no engine benefit credit",
                      unit_policy="separate actual counters and bytes; never summed as equivalent units")
        results.append(dict(arm=row["arm"], correct=correct, abstentions=abstentions, task_count=32,
                            source_queries=row["freeze"]["source_queries"],
                            gf2_work_units=row["freeze"]["gf2_work_units"],
                            complete_operation=vector,
                            evaluation_window=dict(source_calls=0, predictions=32, learning=False),
                            process_calls=row["calls"], freeze_sha256=row["freeze_sha256"],
                            predictions_sha256=commitment_row["sha256"]))
    report = dict(schema="symbiote.fresh-engineering-case/1", index=index, width=8,
                  wiring_revealed_after_predictions=dict(mask=mask,bias=bias), inputs=inputs,
                  observed_inputs=sorted(observed), arms=results, scientific_samples=0,
                  isolated_structural_result="TIE; same supported reasoning family",
                  cache_result="abstains on all new inputs; coverage is not whole-cost benefit",
                  accounting="Source learning, validation, ledger bytes and cold replay are retained per arm. Supervisor/control/source provisioning and grading are separate experimental overhead, not a fabricated zero-cost participant.",
                  harness=dict(graded_answers=128, source_processes=4, source_grades_computed_after_all_predictions=True),
                  exchange_benefit="NOT_TESTED in this observation-source workload; native receiver exchange has a separate component proof")
    write(root / "graded-result.json", report)
    return report


def worker(args):
    registration = load(args.registration)
    need(sha(args.registration) == args.registration_sha256, "external registration pin")
    validate_registration(registration)
    admission = os.environ.get("SYMBIOTE_ENGINE_EVOLUTION_ADMISSION", "")
    marker = load(Path(registration["artifacts"]) / "EXECUTION-STARTED.json")
    need(len(admission) == 64 and marker["registration_sha256"] == args.registration_sha256
         and hashlib.sha256(admission.encode("ascii")).hexdigest() == marker["worker_admission_sha256"],
         "worker requires the enclosing bounded run admission")
    root = Path(registration["artifacts"]) / "fresh-tasks"
    root.mkdir()
    report = dict(schema="symbiote.engine-evolution-fresh/1", status="HOLD", cases=[],
                  scientific_samples=0, independent_host_validation="OPEN_UNAVAILABLE")
    started = time.monotonic()
    private_object = tempfile.TemporaryDirectory(prefix="symbiote-evolution-private-")
    private = Path(private_object.name).resolve()
    try:
        for index, pair in enumerate(CASES):
            report["cases"].append(one_case(index, *pair, root / f"case-{index}", private,
                registration["native"]["path"], registration["observer"]["path"], started+LIMIT_SECONDS-10,
                registration["source_commit"]))
            for row in report["cases"][-1]["arms"]:
                if row["arm"] != "cache":
                    frozen = load(root / f"case-{index}" / row["arm"] / "freeze.json")
                    predicted = load(root / f"case-{index}" / row["arm"] / "predictions.json")
                    need(frozen["build_source_commit"] == predicted["build_source_commit"] == registration["source_commit"],
                         "runtime source stamp changed across learning/frozen prediction")
        report["status"] = "PASS_CONDITIONAL_FRESH_REUSE"
    except BaseException as error:
        report.update(failure=type(error).__name__ + ": " + str(error))
        raise
    finally:
        report["elapsed_seconds"] = time.monotonic()-started
        write(root / "fresh-task-report.json", report)
        # Only the freshly generated, explicitly resolved secrets directory is
        # removed. Raw public outcomes and failed evidence remain untouched.
        need(private.parent == Path(tempfile.gettempdir()).resolve()
             and private.name.startswith("symbiote-evolution-private-"), "private cleanup boundary")
        private_object.cleanup()


def validate_registration(registration):
    need(registration["schema"] == "symbiote.engine-evolution-registration/1"
         and registration["protocol"] == PROTOCOL and registration["baseline_source"] == BASELINE,
         "registered workload identity")
    need(registration["cases"] == [dict(width=8, mask=m, bias=b) for m, b in CASES]
         and registration["prefix_profile"] == dict(histories=[0,16,64,256],captures=32)
         and registration["fresh_inputs"] == 32
         and registration["bounds"] == dict(seconds=LIMIT_SECONDS,evidence_bytes=LIMIT_BYTES),
         "registered workload or budget changed")
    need(git_source() == registration["source_commit"] and sha(PROTOCOL_FILE) == registration["protocol_sha256"],
         "registered clean source/protocol changed")
    source_fingerprint.verify(ROOT, registration["source_manifest"])
    for key in ("native", "observer", "memory_test", "service_test"):
        need(sha(registration[key]["path"]) == registration[key]["sha256"], "registered executable changed")
    need(registration["source_adapter"]["path"] == str(ROOT / "adapters/switchbox_source.py")
         and sha(ROOT / "adapters/switchbox_source.py") == registration["source_adapter"]["sha256"],
         "independent adapter source changed")


def run(args):
    registration = load(args.registration)
    need(sha(args.registration) == args.registration_sha256, "external registration pin")
    validate_registration(registration)
    root = Path(registration["artifacts"])
    admission = secrets.token_hex(32)
    write(root / "EXECUTION-STARTED.json", dict(registration_sha256=args.registration_sha256,
                                               worker_admission_sha256=hashlib.sha256(admission.encode("ascii")).hexdigest(),
                                               automatic_retry=False, started_at_unix=time.time()))
    process_root = root / "processes"
    process_root.mkdir()
    start = time.monotonic()
    cancel = threading.Event()
    awake = QualificationAwake()
    report = dict(schema="symbiote.engine-evolution-result/1", status="HOLD", source_commit=registration["source_commit"],
                  registration_sha256=args.registration_sha256, process_calls=[], scientific_samples=0,
                  broader_stable_qualification="HOLD", automatic_retry=False)
    def cancelled():
        try:
            awake.check()
        except RuntimeError as failure:
            report["awake_failure"] = str(failure)
            cancel.set()
        return cancel.is_set()
    try:
        with awake:
            commands = [
                ("prefix-profile", [registration["memory_test"]["path"], MEMORY_TEST, "--exact", "--ignored", "--nocapture", "--test-threads=1"],
                 {"SYMBIOTE_ENGINE_EVOLUTION_REGISTRATION":str(Path(args.registration).resolve()),
                  "SYMBIOTE_ENGINE_EVOLUTION_REGISTRATION_SHA256":args.registration_sha256,
                  "SYMBIOTE_PREFIX_PROFILE_ARTIFACTS":str(root / "prefix-profile")}),
                ("fresh-tasks", [sys.executable, "-B", str(Path(__file__).resolve()), "worker",
                                  "--registration", str(Path(args.registration).resolve()),
                                  "--registration-sha256", args.registration_sha256],
                 {"SYMBIOTE_ENGINE_EVOLUTION_ADMISSION":admission}),
                ("receiver-outcomes", [registration["service_test"]["path"], OUTCOME_TEST, "--exact", "--nocapture", "--test-threads=1"],
                 {"SYMBIOTE_OUTCOME_ARTIFACTS":str(root / "receiver-outcomes"),
                  "SYMBIOTE_COGNITION_TEST_BINARY":registration["native"]["path"]}),
            ]
            for label, argv, environment in commands:
                remaining = LIMIT_SECONDS-(time.monotonic()-start)-10
                need(remaining > 0, "whole workload budget")
                record = safety.execute(argv, process_root, label, timeout=remaining,
                                        cancelled=cancelled, environment=environment)
                report["process_calls"].append(record)
                need(record["exit_code"] == 0 and record["outcome"] == "completed"
                     and record["cleanup_verified"] and not record["output_truncated"], "owned workload process failed")
                if label != "fresh-tasks": safety.check_native_test(safety.output(record, process_root))
                need(sum(p.stat().st_size for p in root.rglob("*") if p.is_file()) <= LIMIT_BYTES-1024*1024,
                     "complete evidence budget")
                source_fingerprint.verify(ROOT, registration["source_manifest"])
                for key in ("native", "observer", "memory_test", "service_test"):
                    need(sha(registration[key]["path"]) == registration[key]["sha256"], "registered executable changed during run")
                need(sha(ROOT / "adapters/switchbox_source.py") == registration["source_adapter"]["sha256"],
                     "independent adapter changed during run")
            report["fresh_task_result"] = load(root / "fresh-tasks/fresh-task-report.json")
            need(report["fresh_task_result"]["status"] == "PASS_CONDITIONAL_FRESH_REUSE", "fresh task closure")
            report["status"] = "PASS_ENGINEERING_ONLY"
    except BaseException as error:
        report.update(status="HOLD", failure=type(error).__name__ + ": " + str(error))
    finally:
        report.update(elapsed_seconds=time.monotonic()-start, awake=awake.report,
                      interpretation="Bounded controlled software evolution; no generalized transfer efficiency, host-power-loss or two-host claim.")
        if report["elapsed_seconds"] > LIMIT_SECONDS or cancel.is_set(): report["status"] = "HOLD"
        raw = safety.encode(report)
        need(sum(p.stat().st_size for p in root.rglob("*") if p.is_file())+len(raw) <= LIMIT_BYTES,
             "final report exceeds evidence budget")
        write(root / "evolution-report.json", report)
    print(json.dumps(dict(status=report["status"], report=str(root / "evolution-report.json"), sha256=sha(root / "evolution-report.json"))))
    return 0 if report["status"] == "PASS_ENGINEERING_ONLY" else 1


def smoke(args):
    root = fresh(args.out)
    temporary = tempfile.TemporaryDirectory(prefix="symbiote-evolution-private-")
    path = Path(temporary.name).resolve()
    try:
        result = one_case(0, 199, 1, root / "unit-case", path, args.native, args.observer, time.monotonic()+90)
        write(root / "unregistered-smoke.json", dict(status="PASS_SOFTWARE_SMOKE_ONLY", result=result,
              registered_cohort_executed=False, scientific_samples=0))
        print(json.dumps(dict(status="PASS_SOFTWARE_SMOKE_ONLY", root=str(root))))
    finally:
        need(path.parent == Path(tempfile.gettempdir()).resolve()
             and path.name.startswith("symbiote-evolution-private-"), "private cleanup boundary")
        temporary.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="mode", required=True)
    reg = subs.add_parser("register")
    for name in ("native", "observer", "memory-test", "service-test", "out"):
        reg.add_argument("--"+name, required=True, type=Path)
    for name in ("run", "worker"):
        sub = subs.add_parser(name)
        sub.add_argument("--registration", type=Path, required=True)
        sub.add_argument("--registration-sha256", required=True)
    sub = subs.add_parser("smoke")
    for name in ("native", "observer", "out"): sub.add_argument("--"+name, required=True, type=Path)
    args = parser.parse_args()
    try:
        return {"register":register,"run":run,"worker":worker,"smoke":smoke}[args.mode](args) or 0
    except (ValueError, RuntimeError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps(dict(status="HOLD", failure=type(error).__name__ + ": " + str(error))), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
