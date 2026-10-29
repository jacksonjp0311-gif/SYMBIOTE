"""TEMP offline final four-public-gate assembler; no publication operations.

Requires actual completed anonymous-public receipts, externally pinned original
plan/provisional operation and official successful five-job public workflow.
Chronology uses that platform job's recorded UTC start/end, at second resolution.
Do not execute against pending inputs. All ACCEPT decisions remain explicit root
judgments in the externally pinned request, not producer-success authority.
"""
import argparse
import datetime as dt
import hashlib
import json
import sys
import tempfile
import types
from pathlib import Path

sys.dont_write_bytecode = True


def load_assembler(path, expected):
    path = Path(path)
    raw = path.read_bytes()
    if len(raw) > 128 * 1024 or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("reviewed assembler source differs")
    module = types.ModuleType("reviewed_offline_8aa5f4c_assembler")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def utc_ns(value):
    # GitHub supplies actual UTC timestamps to second precision. Do not invent
    # a more precise native start or derive absolute finish from monotonic time.
    return int(dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp()) * 1_000_000_000


def official_public(a, coordinate):
    raw = a.checked_json(coordinate)
    run, jobs = raw["run"], raw["jobs"]
    a.require(run.get("repository", {}).get("id") == a.REPOSITORY_ID
              and run.get("repository", {}).get("full_name") == a.REPOSITORY
              and run.get("head_repository", {}).get("full_name") == a.REPOSITORY
              and run.get("head_sha") == a.SOURCE and run.get("path") == ".github/workflows/v11-public-accept.yml"
              and run.get("event") == "workflow_dispatch" and run.get("status") == "completed"
              and run.get("conclusion") == "success" and run.get("run_attempt") == 1,
              "actual first-attempt official public workflow must pass; failures are preserved, not retried here")
    run_id = a.positive(run["id"])
    a.require(jobs.get("total_count") == len(jobs.get("jobs", [])) == 5,
              "one bind job plus all four public platform jobs are required")
    for job in jobs["jobs"]:
        a.require(job.get("run_id") == run_id and job.get("head_sha") == a.SOURCE
                  and job.get("run_attempt") == run["run_attempt"] and job.get("status") == "completed"
                  and job.get("conclusion") == "success", "public workflow cannot mix attempts or skipped/failed jobs")
    a.require(sum(job.get("name") == "bind" for job in jobs["jobs"]) == 1, "exact source-binding job required")
    target_jobs = {}
    for target in a.TARGETS:
        matches = [job for job in jobs["jobs"] if target in job.get("name", "")
                   and job.get("name", "").startswith("public-platform (")]
        a.require(len(matches) == 1, "missing/ambiguous actual public platform job")
        job = matches[0]
        steps = {step["name"]: step for step in job["steps"]}
        step = steps.get("Anonymous public bytes, original signed components, actual installed behavior", {})
        a.require(step.get("status") == "completed" and step.get("conclusion") == "success",
                  "actual anonymous-public acceptance step did not pass")
        start, finish = utc_ns(job["started_at"]), utc_ns(job["completed_at"])
        a.require(0 < start <= finish, "actual platform job chronology unavailable")
        target_jobs[target] = (job, start, finish)
    return run_id, target_jobs


def assemble(a, request_path, expected, output):
    a.require_bound_coordinates()
    request_path = a.ordinary_file(request_path)
    request_raw = request_path.read_bytes()
    a.require(len(request_raw) <= 2 * 1024 * 1024 and hashlib.sha256(request_raw).hexdigest() == a.pin(expected),
              "final public assessment inputs differ from external root review")
    request = a.parse(request_raw)
    a.keys(request, {"schema", "publication_plan", "publisher", "transport", "provisional_operation",
                     "official_public_run", "gates"})
    a.require(request["schema"] == "symbiote.v11-reviewed-public-inputs/1", "public assessment input schema differs")
    plan = a.checked_json(request["publication_plan"])
    a.require(plan.get("schema") == "symbiote.v11-publication-plan/1" and plan.get("repository") == a.REPOSITORY
              and plan.get("version") == a.VERSION and plan.get("candidate_commit") == a.SOURCE
              and plan.get("candidate_run_id") == a.CANDIDATE_RUN and plan.get("source_ci_run_id") == a.SOURCE_CI_RUN
              and request["publisher"]["sha256"] == plan["publisher_sha256"]
              and request["transport"]["sha256"] == plan["transport_sha256"], "original immutable publication plan differs")
    publisher = a.load_publisher(request)
    assets = {item["name"]: item for item in plan["assets"]}
    a.require(len(assets) == len(plan["assets"]) and len(assets) in (33, 35), "original complete asset census differs")
    asset_digest = a.canonical_digest({name: item["sha256"] for name, item in assets.items()})
    provisional = a.checked_json(request["provisional_operation"])
    a.require(provisional.get("schema") == "symbiote.v11-publication-operation/1"
              and provisional.get("status") == "PASS_PROVISIONAL_NOT_LATEST" and provisional.get("mode") == "provisional"
              and provisional.get("candidate_commit") == a.SOURCE
              and provisional.get("publication_plan_sha256") == request["publication_plan"]["sha256"],
              "original actual anonymous provisional publication has not passed")
    release = provisional["release"]
    binding = {"release_id": a.positive(release["id"]),
               "publication_plan_sha256": request["publication_plan"]["sha256"], "asset_digest": asset_digest}
    a.require(provisional.get("public_binding") == binding and release.get("draft") is False
              and release.get("prerelease") is True and release.get("tag_name") == a.VERSION,
              "public assessment must refer to the actual immutable provisional release")
    run_id, jobs = official_public(a, request["official_public_run"])
    required_roles = {"public-native:" + target for target in a.TARGETS}
    a.require(isinstance(request["gates"], list) and len(request["gates"]) == 4
              and {item["role"] for item in request["gates"]} == required_roles, "all four explicit public root assessments required")
    values = []
    for item in request["gates"]:
        a.keys(item, {"role", "subject_sha256", "evidence", "review"})
        target = item["role"].partition(":")[2]
        job, start, finish = jobs[target]
        gate = dict(item, started_unix_ns=start, finished_unix_ns=finish)
        a.keys(gate["review"], {"reviewer", "decision", "scope"})
        gate["review"] = dict(gate["review"], chronology_basis=(
            "Actual official public platform job " + str(job["id"]) + " UTC started_at/completed_at (second resolution); "
            "native/embedding monotonic execution spans remain in original child receipts. No absolute native finish invented."))
        review = a.operator_review(gate)
        named = a.named_evidence(gate)
        for name, coordinate in (("official-public-run", request["official_public_run"]),
                                 ("provisional-operation", request["provisional_operation"])):
            a.require(name in named and all(named[name][key] == coordinate[key] for key in ("path", "bytes", "sha256")),
                      "each public gate must preserve exact official run and provisional operation evidence")
        native = a.actual(named, "native-acceptance", "symbiote.installed-platform-acceptance/1", "PASS_INSTALLED_NATIVE_LIFECYCLE")
        embedded = a.actual(named, "embedding-acceptance", "symbiote.embedding-platform-acceptance/1", "PASS_INDEPENDENT_EMBEDDING_LIFECYCLE")
        delivered = a.actual(named, "public-platform", "symbiote.public-platform-acceptance/1", "PASS_PUBLIC_PLATFORM_LIFECYCLE")
        platform = plan["platforms"][target]
        a.require(item["subject_sha256"] == platform["native_sha256"]
                  and delivered.get("source_commit") == a.SOURCE and delivered.get("target") == target
                  and delivered.get("tag") == a.VERSION and delivered.get("candidate_run_id") == a.CANDIDATE_RUN
                  and delivered.get("public_workflow_run_id") == run_id
                  and delivered.get("publication_plan_sha256") == binding["publication_plan_sha256"]
                  and delivered.get("release_id") == binding["release_id"]
                  and delivered.get("bundle_sha256") == assets["symbiote-v1.1.2-" + target + ".zip"]["sha256"]
                  and delivered.get("installed_binary_sha256") == platform["native_sha256"]
                  and delivered.get("driver_sha256") == platform["driver_sha256"]
                  and delivered.get("consumer_sha256") == platform["embedding_sha256"]
                  and delivered.get("native_acceptance") == native and delivered.get("embedding_acceptance") == embedded,
                  "actual public source/run/release/plan/ZIP/components differ")
        a.require(native.get("source_commit") == embedded.get("source_commit") == a.SOURCE
                  and native.get("target") == embedded.get("target") == target
                  and native.get("installed_binary_sha256") == platform["native_sha256"]
                  and native.get("service_test_driver_sha256") == platform["driver_sha256"]
                  and embedded.get("binary_sha256") == platform["embedding_sha256"]
                  and native.get("typed_engine_lifecycle"), "public component receipts are not bound to original images")
        for evidence in item["evidence"]:
            a.checked_raw(evidence, 128 * 1024 * 1024)
        values.append({"schema": "symbiote.v11-release-gate/1", "role": item["role"], "source_commit": a.SOURCE,
                       "candidate_run_id": a.CANDIDATE_RUN, "subject_sha256": item["subject_sha256"], "status": "PASS",
                       "started_unix_ns": start, "finished_unix_ns": finish, "evidence": item["evidence"],
                       "operator_review": review, "public_binding": binding})
    output = Path(output)
    a.require(output.is_absolute() and output.parent.resolve(strict=True) == Path(tempfile.gettempdir()).resolve(strict=True)
              and not output.exists() and len(output.name) <= 80, "fresh direct canonical OS-temp output required")
    output.mkdir()
    (output / "reviewed-public-inputs.json").write_bytes(request_raw)
    coordinates = []
    for index, value in enumerate(sorted(values, key=lambda item: item["role"])):
        coordinate = a.write_new(output / (str(index) + "-public-gate.json"), value)
        coordinate.update(role=value["role"], subject_sha256=value["subject_sha256"])
        coordinates.append(coordinate)
    assessment = {"schema": "symbiote.v11-public-acceptance/1", **binding, "candidate_commit": a.SOURCE,
                  "public_run_id": run_id, "gates": coordinates}
    coordinate = a.write_new(output / "public-acceptance.json", assessment)
    publisher.public_gates(coordinate["path"], coordinate["sha256"], plan, binding)
    result = {"schema": "symbiote.v11-offline-public-assessment-assembly/1", "status": "PREPARED_FOR_SEPARATE_ROOT_REVIEW",
              "source_commit": a.SOURCE, "public_run_id": run_id, "public_assessment": coordinate,
              "publication_plan_sha256": binding["publication_plan_sha256"], "reviewed_input_sha256": expected,
              "native_executions": 0, "network_calls": 0, "publication_mutations": 0,
              "next_action": "Root reviews this exact separate public-assessment pin before any explicit publisher finalize operation."}
    a.write_new(output / "assembly-report.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("assembler", "assembler-sha256", "request", "request-sha256", "out"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        assembler = load_assembler(args.assembler, args.assembler_sha256)
        print(json.dumps(assemble(assembler, args.request, args.request_sha256, args.out)))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"status": "HOLD_NO_ACCEPTED_PUBLIC_ASSESSMENT", "failure": str(error),
                          "preserve_any_partial_preparation": True, "publication_mutations": 0}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
