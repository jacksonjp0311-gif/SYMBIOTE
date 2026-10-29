"""Reviewed staged-byte publication. Importing never performs a remote operation.

Behavioral gate receipts are operator-reviewed assessments with pinned raw
evidence, not cryptographic proofs of science. Build signatures are independently
reverified by a pinned GitHub CLI; saved producer verification booleans are inert.
This tool never creates/moves a Git ref, replaces/deletes assets, rebuilds native
code, executes a native candidate, or silently retries a failed public release.
"""
import argparse
import hashlib
import http.client
import json
import re
import subprocess
import time
import types
import urllib.error
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
_transport_path = HERE / "release_v1_candidate.py"
_transport_before = _transport_path.stat()
_transport_raw = _transport_path.read_bytes()
_transport_after = _transport_path.stat()
if (_transport_before.st_dev, _transport_before.st_ino, _transport_before.st_size, _transport_before.st_mtime_ns) != (
        _transport_after.st_dev, _transport_after.st_ino, _transport_after.st_size, _transport_after.st_mtime_ns):
    raise ValueError("release transport changed during source capture")
LOADED_TRANSPORT_SHA256 = hashlib.sha256(_transport_raw).hexdigest()
transport = types.ModuleType("symbiote_v11_transport")
transport.__file__ = str(_transport_path)
exec(compile(_transport_raw, str(_transport_path), "exec"), transport.__dict__)
REPO = "jacksonjp0311-gif/SYMBIOTE"
TAG = "v1.1.2"
PREVIOUS = "v1.0.1"
WORKFLOW = ".github/workflows/v11-candidate.yml"
TARGETS = tuple(transport.TARGETS)
SUFFIXES = (".zip", ".build.json", ".cdx.json", ".provenance.sigstore.json", ".sbom.sigstore.json",
            ".provenance-verification.json", ".sbom-verification.json")
PREDICATES = ("https://slsa.dev/provenance/v1", "https://cyclonedx.org/bom")
MAX_TOTAL = 512 * 1024 * 1024
PRE_ROLES = {"source-ci", "linux-enospc", "e3", "hour"} | {
    prefix + target for target in TARGETS for prefix in ("candidate-native:", "candidate-embedding:")}
PUBLIC_ROLES = {"public-native:" + target for target in TARGETS}
need = transport.need
parse = transport.parse
encode = transport.encode
pin = transport.pin
sha = transport.sha
plain = transport.plain
write_new = transport.write_new


def fields(value, required, optional=()):
    need(isinstance(value, dict) and set(required) <= set(value) <= set(required) | set(optional),
         "missing or unknown typed publication field")


def integer(value):
    need(type(value) is int and value > 0, "positive integer required")
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def checked_file(item, maximum=128 * 1024 * 1024):
    fields(item, {"path", "sha256", "bytes"}, {"name"})
    path = plain(item["path"])
    need(integer(item["bytes"]) <= maximum and path.stat().st_size == item["bytes"], "file size differs from review")
    need(sha(path, maximum) == pin(item["sha256"]), "file differs from externally pinned bytes")
    return path


def checked_json(item, maximum=8 * 1024 * 1024):
    return parse(transport.read_bounded(checked_file(item, maximum), maximum))


def prefix(target):
    return "symbiote-" + TAG + "-" + target


def core_names():
    return {prefix(target) + suffix for target in TARGETS for suffix in SUFFIXES} | {
        "STAGED_SHA256SUMS-" + target for target in TARGETS} | {"SHA256SUMS"}


def check_sums(path, expected):
    raw = transport.read_bounded(path, 128 * 1024).decode("ascii")
    rows = {}
    for line in raw.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        need(match is not None and match[2] not in rows, "invalid or duplicate checksum member")
        rows[match[2]] = match[1]
    need(rows == expected and raw.endswith("\n"), "checksum census differs from exact reviewed assets")


def gate(item, plan, public=None, public_run_id=None):
    fields(item, {"role", "path", "bytes", "sha256", "subject_sha256"})
    record = {key: item[key] for key in ("path", "bytes", "sha256")}
    value = checked_json(record)
    fields(value, {"schema", "role", "source_commit", "candidate_run_id", "subject_sha256", "status",
                   "started_unix_ns", "finished_unix_ns", "evidence", "operator_review"}, {"public_binding"})
    need(value["schema"] == "symbiote.v11-release-gate/1" and value["role"] == item["role"]
         and value["source_commit"] == plan["candidate_commit"] and value["candidate_run_id"] == plan["candidate_run_id"]
         and value["subject_sha256"] == pin(item["subject_sha256"]) and value["status"] == "PASS",
         "gate belongs to another source/run/subject or has not passed")
    start, end = integer(value["started_unix_ns"]), integer(value["finished_unix_ns"])
    need(start <= end <= time.time_ns() + 300_000_000_000, "invalid actual gate chronology")
    evidence = value["evidence"]
    need(isinstance(evidence, list) and 1 <= len(evidence) <= 128, "actual bounded evidence is required")
    need(len({entry["path"] for entry in evidence}) == len(evidence), "duplicate evidence path")
    for entry in evidence:
        checked_file(entry)
    named = {entry["name"]: entry for entry in evidence if "name" in entry}
    need(len(named) == sum("name" in entry for entry in evidence), "duplicate named behavioral evidence")
    review = value["operator_review"]
    fields(review, {"reviewer", "decision", "evidence_digest", "scope"})
    need(isinstance(review["reviewer"], str) and 1 <= len(review["reviewer"]) <= 128
         and review["decision"] == "ACCEPT" and review["evidence_digest"] == digest(evidence)
         and isinstance(review["scope"], str) and 1 <= len(review["scope"]) <= 1024,
         "externally pinned operator evidence assessment required")
    role = item["role"]
    for kind, key in (("candidate-native:", "native_sha256"), ("candidate-embedding:", "embedding_sha256"),
                      ("public-native:", "native_sha256")):
        if role.startswith(kind):
            target = role.removeprefix(kind)
            need(target in TARGETS and value["subject_sha256"] == plan["platforms"][target][key], "gate native/embedding attribution mismatch")
    target = role.partition(":")[2]
    if role.startswith(("candidate-native:", "public-native:")):
        need("native-acceptance" in named, "actual installed native receipt required")
        native = checked_json(named["native-acceptance"])
        need(native.get("schema") == "symbiote.installed-platform-acceptance/1"
             and native.get("status") == "PASS_INSTALLED_NATIVE_LIFECYCLE" and native.get("source_commit") == plan["candidate_commit"]
             and native.get("target") == target and native.get("installed_binary_sha256") == plan["platforms"][target]["native_sha256"]
             and native.get("service_test_driver_sha256") == plan["platforms"][target]["driver_sha256"]
             and native.get("typed_engine_lifecycle"), "installed receipt source/native/driver/lifecycle mismatch")
    if role.startswith(("candidate-embedding:", "public-native:")):
        need("embedding-acceptance" in named, "actual independent embedding receipt required")
        embedded = checked_json(named["embedding-acceptance"])
        need(embedded.get("schema") == "symbiote.embedding-platform-acceptance/1"
             and embedded.get("status") == "PASS_INDEPENDENT_EMBEDDING_LIFECYCLE"
             and embedded.get("source_commit") == plan["candidate_commit"] and embedded.get("target") == target
             and embedded.get("binary_sha256") == plan["platforms"][target]["embedding_sha256"], "independent embedding receipt source/image mismatch")
    if role == "linux-enospc":
        need("enospc-native" in named,"actual isolated native ENOSPC receipt required")
        actual = checked_json(named["enospc-native"])
        need(actual.get("schema") == "symbiote.engine-enospc/1" and actual.get("status") == "PASS_ACTUAL_ENOSPC"
             and actual.get("source_commit") == plan["candidate_commit"] and actual.get("version") == TAG[1:]
             and actual.get("test_executable_sha256") == value["subject_sha256"]
             and actual.get("raw_errno") == 28 and type(actual.get("filesystem_capacity_bytes")) is int
             and 0 < actual["filesystem_capacity_bytes"] <= 1048576 and actual.get("retain_error_kind") == "storage"
             and actual.get("reopen_error_kind") == "hold" and actual.get("committed_ledgers_unchanged") is True
             and actual.get("fill_file_removed") is True and actual.get("native_mount_or_unmount_performed") is False,
             "ENOSPC receipt did not demonstrate the bounded actual OS fault")
    if public is not None:
        need(value.get("public_binding") == public, "public gate is not bound to the actual provisional release and asset set")
        need("public-platform" in named,"actual anonymous public-platform receipt required; candidate receipts are insufficient")
        delivered=checked_json(named["public-platform"])
        need(delivered.get("schema")=="symbiote.public-platform-acceptance/1" and delivered.get("status")=="PASS_PUBLIC_PLATFORM_LIFECYCLE"
             and delivered.get("source_commit")==plan["candidate_commit"] and delivered.get("target")==target and delivered.get("tag")==TAG
             and delivered.get("candidate_run_id")==plan["candidate_run_id"] and delivered.get("public_workflow_run_id")==integer(public_run_id)
             and delivered.get("publication_plan_sha256")==public["publication_plan_sha256"] and delivered.get("release_id")==public["release_id"]
             and delivered.get("bundle_sha256")==next(asset["sha256"] for asset in plan["assets"] if asset["name"]==prefix(target)+".zip")
             and delivered.get("installed_binary_sha256")==plan["platforms"][target]["native_sha256"]
             and delivered.get("driver_sha256")==plan["platforms"][target]["driver_sha256"]
             and delivered.get("consumer_sha256")==plan["platforms"][target]["embedding_sha256"]
             and delivered.get("native_acceptance")==native and delivered.get("embedding_acceptance")==embedded,
             "actual public receipt run/release/plan/images or nested raw child receipts differ")
    else:
        need("public_binding" not in value, "prepublication gate cannot assert a future public release")
    return value


def load_plan(path, expected):
    raw = transport.read_bounded(plain(path), 8 * 1024 * 1024)
    need(hashlib.sha256(raw).hexdigest() == pin(expected), "publication plan changed after external review")
    plan = parse(raw)
    fields(plan, {"schema", "repository", "version", "candidate_commit", "candidate_run_id", "source_ci_run_id",
                  "publisher_sha256", "transport_sha256", "gh", "cargo_lock_sha256", "assets", "platforms", "gates", "body"})
    need(plan["schema"] == "symbiote.v11-publication-plan/1" and plan["repository"] == REPO and plan["version"] == TAG,
         "only the reviewed v1.1.2 repository publication is supported")
    transport.configure_tag(TAG)
    pin(plan["candidate_commit"], 40); integer(plan["candidate_run_id"]); integer(plan["source_ci_run_id"])
    need(sha(Path(__file__)) == pin(plan["publisher_sha256"]) and sha(HERE / "release_v1_candidate.py") == pin(plan["transport_sha256"])
         and LOADED_TRANSPORT_SHA256 == plan["transport_sha256"],
         "executed release tooling differs from the reviewed plan")
    fields(plan["gh"], {"path", "sha256", "bytes"}); checked_file(plan["gh"])
    pin(plan["cargo_lock_sha256"])
    need(isinstance(plan["assets"], list) and len(plan["assets"]) in (33, 35), "exact bounded candidate asset census required")
    assets = {}
    for entry in plan["assets"]:
        fields(entry, {"name", "path", "bytes", "sha256"})
        name = entry["name"]
        need(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,160}", name) and name not in assets,
             "unsafe or duplicate publication asset")
        checked_file(entry); assets[name] = entry
    optional = {"EVIDENCE.zip", "EVIDENCE_SHA256SUMS"}
    need(set(assets) in (core_names(), core_names() | optional), "unexpected/missing staged publication member")
    need(sum(entry["bytes"] for entry in assets.values()) <= MAX_TOTAL, "total reviewed publication bytes exceed bound")
    need(set(plan["platforms"]) == set(TARGETS), "all four actual target platforms required")
    for target, platform in plan["platforms"].items():
        fields(platform, {"native_sha256", "embedding_sha256", "driver_sha256"})
        for value in platform.values(): pin(value)
        build = checked_json(assets[prefix(target) + ".build.json"])
        need(build.get("schema") == "symbiote.release-build/1" and build.get("status") == "PASS_STAGED_BUILD_METADATA"
             and build.get("source_commit") == plan["candidate_commit"] and build.get("target") == target
             and build.get("version") == TAG and build.get("compiler_locked") == "1.98.1"
             and build.get("cargo_lock_sha256") == plan["cargo_lock_sha256"] and build.get("compiler_flags") == []
             and build.get("build_profile") == "release" and build.get("binary", {}).get("sha256") == platform["native_sha256"]
             and build.get("bundle", {}).get("sha256") == assets[prefix(target) + ".zip"]["sha256"]
             and build.get("sbom", {}).get("sha256") == assets[prefix(target) + ".cdx.json"]["sha256"],
             "staged compiler/source/lock/target/native/SBOM metadata mismatch")
        image = transport.inspect_zip(Path(assets[prefix(target) + ".zip"]["path"]), target)
        need(image["binary_sha256"] == platform["native_sha256"], "actual bundled native bytes differ from expected platform image")
        check_sums(Path(assets["STAGED_SHA256SUMS-" + target]["path"]),
                   {prefix(target) + suffix: assets[prefix(target) + suffix]["sha256"] for suffix in SUFFIXES})
    check_sums(Path(assets["SHA256SUMS"]["path"]), {prefix(target)+".zip":assets[prefix(target)+".zip"]["sha256"] for target in TARGETS})
    if optional <= set(assets): check_sums(Path(assets["EVIDENCE_SHA256SUMS"]["path"]), {"EVIDENCE.zip": assets["EVIDENCE.zip"]["sha256"]})
    need(isinstance(plan["gates"], list) and {item["role"] for item in plan["gates"]} == PRE_ROLES
         and len(plan["gates"]) == len(PRE_ROLES), "all twelve distinct prepublication gates required")
    for item in plan["gates"]: gate(item, plan)
    checked_file(plan["body"], 64 * 1024)
    return plan, assets


def check_run(run_id, commit, workflow, event):
    run = transport.metadata(f"/repos/{REPO}/actions/runs/{integer(run_id)}")
    need(run.get("id") == run_id and run.get("repository", {}).get("full_name") == REPO and run.get("head_sha") == commit
         and run.get("path") == workflow and run.get("event") == event and run.get("status") == "completed"
         and run.get("conclusion") == "success" and (workflow != ".github/workflows/ci.yml" or run.get("head_branch") == "main"),
         "exact-source official workflow has not completed successfully")
    jobs = transport.metadata(f"/repos/{REPO}/actions/runs/{run_id}/jobs")
    need(type(jobs.get("total_count")) is int and 0 < jobs["total_count"] == len(jobs.get("jobs", [])) <= 30,
         "all workflow jobs must fit the complete bounded first page")
    need(all(job.get("status") == "completed" and job.get("conclusion") == "success" for job in jobs["jobs"]), "a required workflow job failed/skipped/is incomplete")
    return {"run": run, "jobs": jobs}


def verified_attestation(result, subject_sha, commit, run_id, predicate, repository_id):
    need(isinstance(result, list) and result, "fresh cryptographic verifier returned no signed evidence")
    for entry in result:
        verified = entry.get("verificationResult", {})
        certificate = verified.get("signature", {}).get("certificate", {})
        cert = {re.sub(r"[^a-z0-9]", "", key.lower()): value for key, value in certificate.items()}
        statement = verified.get("statement", {})
        invocation = cert.get("runinvocationuri", cert.get("buildinvocationuri", ""))
        if (cert.get("sourcerepositorydigest") == commit and cert.get("buildsignerdigest") == commit
                and cert.get("sourcerepositoryidentifier") == str(integer(repository_id))
                and re.fullmatch(r"https://github\.com/" + re.escape(REPO) + r"/actions/runs/" + str(run_id) + r"/attempts/[1-9][0-9]*", invocation)
                and statement.get("predicateType") == predicate and verified.get("verifiedTimestamps")
                and any(subject.get("digest", {}).get("sha256") == subject_sha for subject in statement.get("subject", []))):
            return True
    raise transport.ReleaseError("verified certificate source/signer/run, predicate, timestamp or subject does not match")


def cryptographic_checks(plan, assets, out, repository_id):
    result = []
    for target in TARGETS:
        for suffix, bundle_suffix, predicate in ((".zip", ".provenance.sigstore.json", PREDICATES[0]),
                (".build.json", ".provenance.sigstore.json", PREDICATES[0]), (".cdx.json", ".provenance.sigstore.json", PREDICATES[0]),
                (".zip", ".sbom.sigstore.json", PREDICATES[1])):
            asset = assets[prefix(target) + suffix]
            bundle = assets[prefix(target) + bundle_suffix]
            command = [plan["gh"]["path"], "attestation", "verify", asset["path"], "--bundle", bundle["path"], "--repo", REPO,
                       "--source-digest", plan["candidate_commit"], "--signer-workflow", REPO + "/" + WORKFLOW,
                       "--signer-digest", plan["candidate_commit"], "--deny-self-hosted-runners", "--predicate-type", predicate, "--format", "json"]
            need(sha(plan["gh"]["path"]) == plan["gh"]["sha256"], "pinned GitHub CLI changed")
            checked_file(asset); checked_file(bundle)
            process = subprocess.run(command, capture_output=True, timeout=120, check=False)
            need(process.returncode == 0 and 0 < len(process.stdout) <= 8 * 1024 * 1024
                 and len(process.stderr) <= 128 * 1024, "fresh GitHub cryptographic verification failed")
            verified_attestation(parse(process.stdout), asset["sha256"], plan["candidate_commit"], plan["candidate_run_id"], predicate, repository_id)
            name = f"crypto-{len(result):02d}.json"
            write_new(out / name, process.stdout)
            result.append({"asset":asset["name"],"predicate":predicate,"verification":name,"sha256":hashlib.sha256(process.stdout).hexdigest()})
    return result


def authenticated_release(method, suffix, body, token):
    """Narrow new routes; the legacy release transport's allowlist is unchanged."""
    read_route = (suffix == "/tags/" + TAG or suffix == "?per_page=100&page=1"
                  or re.fullmatch(r"/[1-9][0-9]*", suffix) is not None)
    need((method == "POST" and suffix == "") or (method == "GET" and read_route), "unreviewed authenticated release route")
    if method == "POST":
        fields(body,{"tag_name","target_commitish","name","draft","prerelease","make_latest","body"})
        need(body["tag_name"] == TAG and body["name"] == "SYMBIOTE " + TAG and body["draft"] is True
             and body["prerelease"] is True and body["make_latest"] == "false"
             and isinstance(body["body"],str) and len(body["body"].encode()) <= 64 * 1024,
             "create route accepts only the fixed provisional draft, never a final/latest release")
        pin(body["target_commitish"],40)
    else:
        need(body is None,"authenticated GET has no request body")
    payload = None if method == "GET" else encode(body)
    headers = {"Authorization":"Bearer " + token,"Accept":"application/vnd.github+json","User-Agent":"SYMBIOTE-v11-publication"}
    if payload is not None: headers.update({"Content-Type":"application/json","Content-Length":str(len(payload))})
    connection = http.client.HTTPSConnection("api.github.com", timeout=60)
    try:
        connection.request(method,"/repos/"+REPO+"/releases"+suffix,body=payload,headers=headers)
        response = connection.getresponse()
        raw = response.read(8 * 1024 * 1024 + 1)
        need(len(raw) <= 8 * 1024 * 1024, "release metadata response exceeded limit")
        if response.status == 404 and method == "GET": return None
        need(response.status in (200,201), "authenticated release route failed: HTTP " + str(response.status))
        return parse(raw)
    finally: connection.close()


def release_assets(release, plan, assets, partial=False):
    need(isinstance(release,dict), "release metadata is absent or malformed")
    need(release.get("tag_name") == TAG and release.get("target_commitish") == plan["candidate_commit"]
         and type(release.get("id")) is int and release["id"] > 0, "release does not bind exact reviewed tag/source")
    result = {}
    for item in release.get("assets", []):
        name = item.get("name")
        need(name in assets and name not in result and integer(item.get("id"))
             and item.get("size") == assets[name]["bytes"] and item.get("digest") == "sha256:" + assets[name]["sha256"],
             "existing asset differs; replacement/deletion is forbidden")
        result[name] = item
    need(partial or set(result) == set(assets), "public/staged asset set is incomplete")
    return result


def release_by_id(release_id, plan, assets, token, partial=False):
    """Owner-authenticated read of a known release, never a replacement create."""
    release_id=integer(release_id)
    release=authenticated_release("GET","/"+str(release_id),None,token)
    need(isinstance(release,dict) and release.get("id")==release_id,"known release ID is missing or changed")
    release_assets(release,plan,assets,partial)
    return release


def find_release(plan, assets, expected_body, token):
    """A tag404 does not prove draft absence. Read the bounded owner listing.

    A full first page is HOLD rather than an incomplete absence claim. A unique
    matching draft is re-read by its actual ID, with exact source/body/assets.
    No ambiguous, foreign-source, flagged or mismatched draft grants a new POST.
    """
    release=authenticated_release("GET","/tags/"+TAG,None,token)
    if release is not None:
        release_assets(release,plan,assets,True)
        return release
    listed=authenticated_release("GET","?per_page=100&page=1",None,token)
    need(isinstance(listed,list) and len(listed)<100
         and all(isinstance(item,dict) and isinstance(item.get("tag_name"),str) for item in listed),
         "complete bounded owner release listing required before draft absence")
    matches=[item for item in listed if item["tag_name"]==TAG]
    need(len(matches)<=1,"ambiguous matching drafts; preserve all and resolve explicitly")
    if not matches:return None
    release=release_by_id(matches[0].get("id"),plan,assets,token,True)
    need(release.get("draft") is True and release.get("prerelease") is True
         and release.get("body")==expected_body,
         "tag lookup absent but matching release is not this exact resumable draft")
    return release


def latest(tag):
    need(transport.metadata(f"/repos/{REPO}/releases/latest").get("tag_name") == tag, "latest release changed outside the reviewed transition")


def public_bytes(release, plan, assets, out):
    need(release.get("draft") is False, "public byte verification requires actual publication")
    listed = release_assets(release,plan,assets)
    for name in sorted(assets):
        item=listed[name]
        url=f"https://github.com/{REPO}/releases/download/{TAG}/{name}"
        need(item.get("browser_download_url") == url, "public asset URL changed origin/tag/name")
        transport.download(url,out / name,assets[name]["bytes"],assets[name]["sha256"])
    return {"release_id":release["id"],"publication_plan_sha256":plan["_plan_sha256"],
            "asset_digest":digest({name:item["sha256"] for name,item in assets.items()})}


def public_gates(path, expected, plan, binding):
    raw=transport.read_bounded(plain(path),8*1024*1024)
    need(hashlib.sha256(raw).hexdigest()==pin(expected),"public assessment plan changed after review")
    value=parse(raw)
    fields(value,{"schema","publication_plan_sha256","release_id","candidate_commit","asset_digest","gates","public_run_id"})
    integer(value["public_run_id"])
    need(value["schema"]=="symbiote.v11-public-acceptance/1" and value["publication_plan_sha256"]==binding["publication_plan_sha256"]
         and value["release_id"]==binding["release_id"] and value["candidate_commit"]==plan["candidate_commit"]
         and value["asset_digest"]==binding["asset_digest"],"public gates belong to another delivery")
    need(isinstance(value["gates"],list) and {g["role"] for g in value["gates"]}==PUBLIC_ROLES
         and len(value["gates"])==4,"all four actual public platform assessments required")
    for item in value["gates"]: gate(item,plan,binding,value["public_run_id"])
    return value


def pre_mutation(plan,assets):
    need(sha(Path(__file__))==plan["publisher_sha256"] and sha(HERE/"release_v1_candidate.py")==plan["transport_sha256"]
         and LOADED_TRANSPORT_SHA256==plan["transport_sha256"],"release tooling changed since review")
    checked_file(plan["gh"])
    for asset in assets.values():checked_file(asset)
    for item in plan["gates"]:gate(item,plan)
    raw=transport.read_bounded(checked_file(plan["body"],64*1024),64*1024)
    need(hashlib.sha256(raw).hexdigest()==plan["body"]["sha256"],"release body changed during capture")
    transport.resolve_tag(plan["candidate_commit"])
    check_run(plan["candidate_run_id"],plan["candidate_commit"],WORKFLOW,"workflow_dispatch")
    check_run(plan["source_ci_run_id"],plan["candidate_commit"],".github/workflows/ci.yml","push")
    return raw.decode("utf-8")


def operate(mode, plan, assets, out, acceptance=None, acceptance_sha=None, failed_public_run_id=None):
    transport.configure_tag(TAG)
    transport.resolve_tag(plan["candidate_commit"])  # Root creates the reviewed ref separately; never create/move one here.
    runs={"candidate":check_run(plan["candidate_run_id"],plan["candidate_commit"],WORKFLOW,"workflow_dispatch"),
          "source_ci":check_run(plan["source_ci_run_id"],plan["candidate_commit"],".github/workflows/ci.yml","push")}
    write_new(out/"official-runs.json",encode(runs))
    crypto=cryptographic_checks(plan,assets,out,integer(runs["candidate"]["run"]["repository"]["id"]))
    body=pre_mutation(plan,assets)
    if mode=="verify": return {"status":"PASS_READ_ONLY_PREFLIGHT","crypto":crypto}
    token=transport.credential()
    marker=f"\n\nPublication plan SHA256: {plan['_plan_sha256']}\n"
    release=find_release(plan,assets,body+marker,token)
    write_new(out/"initial-release-state.json",encode(release))
    if mode=="flag-failed":
        run_id=integer(failed_public_run_id)
        failed=transport.metadata(f"/repos/{REPO}/actions/runs/{run_id}")
        jobs=transport.metadata(f"/repos/{REPO}/actions/runs/{run_id}/jobs")
        need(failed.get("id")==run_id and failed.get("repository",{}).get("full_name")==REPO
             and failed.get("head_sha")==plan["candidate_commit"] and failed.get("path")==".github/workflows/v11-public-accept.yml"
             and failed.get("event")=="workflow_dispatch" and failed.get("status")=="completed" and failed.get("conclusion") in {"failure","timed_out"}
             and type(jobs.get("total_count")) is int and 0<jobs["total_count"]==len(jobs.get("jobs",[]))<=30
             and any(job.get("conclusion") in {"failure","timed_out"} for job in jobs["jobs"]),
             "only an actual failed exact-source official public workflow can flag this release")
        write_new(out/"failed-official-public-run.json",encode({"run":failed,"jobs":jobs}))
        notice=f"\nFAILED PUBLIC ACCEPTANCE: https://github.com/{REPO}/actions/runs/{run_id}\nPreserved immutable bytes and tag; any correction requires a new version.\n"
        flagged=body+marker+notice
        need(release is not None and release.get("draft") is False and release.get("body") in {body+marker,flagged},"only this exact already-public reviewed delivery may be flagged")
        need(len(flagged.encode())<=64*1024,"failed-release notice exceeds body limit")
        release_assets(release,plan,assets)
        if release.get("body")!=flagged:
            release=transport.authenticated(f"https://api.github.com/repos/{REPO}/releases/{release['id']}","PATCH",
                {"prerelease":True,"make_latest":"false","name":"FAILED: SYMBIOTE "+TAG,"body":flagged},token)
        write_new(out/"flagged-failed-release.json",encode(release))
        need(release.get("prerelease") is True and release.get("body")==flagged,"failure notice not confirmed")
        release_assets(release,plan,assets);transport.resolve_tag(plan["candidate_commit"]);latest(PREVIOUS)
        return {"status":"PASS_PUBLIC_FAILURE_FLAGGED","release":release,"failed_public_run_id":run_id,"crypto":crypto,
                "policy":"immutable failed version cannot be restaged/finalized; correct under a new version"}
    if mode=="stage":
        latest(PREVIOUS)
        if release is None:
            release=authenticated_release("POST","",{"tag_name":TAG,"target_commitish":plan["candidate_commit"],"name":"SYMBIOTE "+TAG,
                "draft":True,"prerelease":True,"make_latest":"false","body":body+marker},token)
            write_new(out/"created-draft.json",encode(release))
        need(release.get("draft") is True and release.get("prerelease") is True and release.get("body")==body+marker,"existing release is not this exact resumable draft")
        current=release_assets(release,plan,assets,True)
        staged_ids={name:item["id"] for name,item in current.items()}
        for name in sorted(assets):
            if name in current: continue
            item=assets[name]; path=checked_file(item)
            with path.open("rb") as stream:
                upload=transport.PinnedUpload(stream,item["bytes"])
                created=transport.authenticated(f"https://uploads.github.com/repos/{REPO}/releases/{release['id']}/assets?name="+urllib.parse.quote(name),"POST",upload,token,size=item["bytes"])
                need(upload.count==item["bytes"] and upload.hash.hexdigest()==item["sha256"],"upload stream changed; preserve partial draft")
            need(created.get("name")==name and created.get("digest")=="sha256:"+item["sha256"] and created.get("size")==item["bytes"],"uploaded asset differs; no replacement admitted")
            staged_ids[name]=integer(created.get("id"))
            write_new(out/("uploaded-"+name+".json"),encode(created))
        release=release_by_id(release["id"],plan,assets,token)
        need(release.get("draft") is True and release.get("prerelease") is True and release.get("body")==body+marker,
             "staged known release state/body changed")
        actual=release_assets(release,plan,assets)
        need({name:item["id"] for name,item in actual.items()}==staged_ids,"staged upload IDs changed; no replacement permitted")
        latest(PREVIOUS)
        return {"status":"PASS_EXACT_DRAFT_STAGED","release":release,"crypto":crypto}
    need(release is not None and release.get("body")==body+marker,"release draft/body is not from this exact reviewed plan")
    release_assets(release,plan,assets)
    if mode=="provisional":
        latest(PREVIOUS)
        need(release.get("prerelease") is True,"a failed/final release cannot be silently retried as provisional")
        if release.get("draft") is True:
            release=transport.authenticated(f"https://api.github.com/repos/{REPO}/releases/{release['id']}","PATCH",{"draft":False,"prerelease":True,"make_latest":"false"},token)
            write_new(out/"published-provisional.json",encode(release))
        binding=public_bytes(release,plan,assets,out);latest(PREVIOUS)
        return {"status":"PASS_PROVISIONAL_NOT_LATEST","release":release,"public_binding":binding,"crypto":crypto}
    need(mode=="finalize" and acceptance is not None and acceptance_sha is not None,"finalization requires a separate externally pinned four-platform public assessment")
    need(release.get("draft") is False,"draft cannot become stable without anonymous provisional acceptance")
    binding=public_bytes(release,plan,assets,out)
    assessment=public_gates(acceptance,acceptance_sha,plan,binding)
    public_run=check_run(assessment["public_run_id"],plan["candidate_commit"],".github/workflows/v11-public-accept.yml","workflow_dispatch")
    write_new(out/"official-public-run.json",encode(public_run))
    if release.get("prerelease") is True:
        latest(PREVIOUS)
        release=transport.authenticated(f"https://api.github.com/repos/{REPO}/releases/{release['id']}","PATCH",{"draft":False,"prerelease":False,"make_latest":"true"},token)
        write_new(out/"finalized-release.json",encode(release))
    need(release.get("draft") is False and release.get("prerelease") is False,"stable mutation not confirmed")
    release_assets(release,plan,assets);transport.resolve_tag(plan["candidate_commit"]);latest(TAG)
    return {"status":"PASS_FINAL_PUBLIC_LATEST","release":release,"public_binding":binding,"public_assessment_sha256":acceptance_sha,"crypto":crypto,
            "qualification":"bounded operator-reviewed software qualification; no scientific efficiency claim"}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode",choices=("verify","stage","provisional","finalize","flag-failed"))
    parser.add_argument("--plan",required=True,type=Path);parser.add_argument("--plan-sha256",required=True)
    parser.add_argument("--out",required=True,type=Path)
    parser.add_argument("--public-acceptance",type=Path);parser.add_argument("--public-acceptance-sha256")
    parser.add_argument("--failed-public-run",type=int)
    args=parser.parse_args(argv)
    out=transport.new_output(args.out)
    try:
        need((args.mode=="finalize" and args.public_acceptance is not None and args.public_acceptance_sha256 is not None)
             or (args.mode!="finalize" and args.public_acceptance is None and args.public_acceptance_sha256 is None),
             "only finalization accepts paired public evidence inputs")
        need((args.mode=="flag-failed")==bool(args.failed_public_run),"only explicit failure flagging accepts a failed public run ID")
        plan,assets=load_plan(args.plan,args.plan_sha256);plan["_plan_sha256"]=args.plan_sha256
        reviewed=transport.read_bounded(plain(args.plan),8*1024*1024)
        need(hashlib.sha256(reviewed).hexdigest()==args.plan_sha256,"reviewed plan changed before preservation")
        write_new(out/"reviewed-plan.json",reviewed)
        result=operate(args.mode,plan,assets,out,args.public_acceptance,args.public_acceptance_sha256,args.failed_public_run)
        result.update({"schema":"symbiote.v11-publication-operation/1","mode":args.mode,"candidate_commit":plan["candidate_commit"],"publication_plan_sha256":args.plan_sha256})
        write_new(out/"operation.json",encode(result));print(json.dumps(result));return 0
    except Exception as error:
        result={"schema":"symbiote.v11-publication-operation/1","status":"HOLD_PRESERVE_PARTIAL_DELIVERY","mode":args.mode,"publication_plan_sha256":args.plan_sha256,
                "reason":str(error),"policy":"no asset replacement, deletion, ref movement, rebuild or automatic retry; public failures require an explicit failed-release notice and a new corrected version"}
        write_new(out/"operation.json",encode(result));print(json.dumps(result));return 1


if __name__=="__main__": raise SystemExit(main())
