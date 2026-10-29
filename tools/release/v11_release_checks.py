"""Bound installed native acceptance and emit target-specific release provenance.

No publish, tag, study or hour is started here. The SBOM describes Cargo's
target-filtered normal/build dependency closure, not unidentified system code.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
import tomllib
import types
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
sys.dont_write_bytecode = True
LOADED_HELPERS = {}


def load_local(name, path):
    """Execute the source bytes recorded here, never a timestamp-valid .pyc."""
    path = Path(path)
    before = path.stat()
    require_size = 4 * 1024 * 1024
    if path.is_symlink() or before.st_size > require_size:
        raise ValueError("linked or oversized helper")
    raw = path.read_bytes()
    after = path.stat()
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or len(raw) != before.st_size):
        raise ValueError("helper changed while reading")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    LOADED_HELPERS[path.name] = hashlib.sha256(raw).hexdigest()
    return module


bundles = load_local("qualified_bundle_checks", TOOLS / "package_release.py")
source_fingerprint = load_local("qualified_source_manifest", TOOLS / "source_fingerprint.py")
safety = load_local("qualified_process_containment", TOOLS / "stability_campaign.py")

MAX_FILE = 128 * 1024 * 1024
MSRV = "1.98.1"
REPOSITORY="jacksonjp0311-gif/SYMBIOTE"
CHILD_ENVIRONMENT_KEYS={
    "PATH","PATHEXT","SYSTEMROOT","WINDIR","COMSPEC","SYSTEMDRIVE","OS",
    "PROCESSOR_ARCHITECTURE","PROCESSOR_IDENTIFIER","NUMBER_OF_PROCESSORS",
    "TEMP","TMP","TMPDIR","HOME","USERPROFILE","HOMEDRIVE","HOMEPATH",
    "APPDATA","LOCALAPPDATA","PROGRAMDATA","PROGRAMFILES","PROGRAMFILES(X86)",
    "COMMONPROGRAMFILES","COMMONPROGRAMFILES(X86)",
    "LANG","LC_ALL","LC_CTYPE","TZ","TERM","NO_COLOR","CLICOLOR",
    "PYTHONUTF8","PYTHONIOENCODING","PYTHONDONTWRITEBYTECODE","PYTHONHOME",
    "RUST_BACKTRACE","RUST_LIB_BACKTRACE","SDKROOT","LD_LIBRARY_PATH","DYLD_LIBRARY_PATH",
}


def child_execute(*args, **kwargs):
    """Sequential bounded child launch with no inherited CI/authentication state.

    The containment helper merges the parent environment. Limit that parent for
    the duration of its synchronous launch/wait; restore it even on failure.
    Explicit caller-supplied native proof paths remain allowed. No concurrent
    helper launches are supported by this release operator.
    """
    original=dict(os.environ)
    selected={key:value for key,value in original.items() if key.upper() in CHILD_ENVIRONMENT_KEYS}
    try:
        os.environ.clear();os.environ.update(selected)
        return safety.execute(*args,**kwargs)
    finally:
        os.environ.clear();os.environ.update(original)


def require(value, message):
    if not value:
        raise ValueError(message)


def pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: require(False, "nonfinite JSON"))


def canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def plain(path, directory=False):
    path = Path(os.path.abspath(path))
    for current in [path, *path.parents]:
        details = current.lstat()
        require(not current.is_symlink() and not getattr(details, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0), "linked path refused")
    require(path.is_dir() if directory else path.is_file(), "wrong file type")
    return path


def read(path):
    path = plain(path)
    before = path.stat()
    require(before.st_size <= MAX_FILE, "file byte bound")
    raw = path.read_bytes()
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            and len(raw) == before.st_size, "file changed while reading")
    return raw


def sha(path):
    return hashlib.sha256(read(path)).hexdigest()


def write_new(path, value):
    with Path(path).open("xb") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, allow_nan=False,
                                indent=2).encode("utf-8") + b"\n")


def pin(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "SHA256 pin required")
    return value


def fresh(path):
    path = Path(os.path.abspath(path))
    # The OS-owned Temp alias is normalized once; selected evidence paths keep
    # strict no-links checks, including the user-selected fresh destination.
    base = Path(__import__("tempfile").gettempdir()).resolve(strict=True)
    plain(base, True)
    require(not path.exists() and base in path.parents, "fresh OS Temp output required")
    plain(path.parent, True)
    path.mkdir()
    return path


def host_target():
    targets = {("win32", "amd64"): "x86_64-pc-windows-msvc",
               ("win32", "x86_64"): "x86_64-pc-windows-msvc",
               ("linux", "x86_64"): "x86_64-unknown-linux-gnu",
               ("darwin", "arm64"): "aarch64-apple-darwin",
               ("darwin", "x86_64"): "x86_64-apple-darwin"}
    target = targets.get((sys.platform, platform.machine().lower()))
    require(target is not None, "host has no supported native target")
    return target


def normal_closure(metadata, package_name="symbiote-runtime"):
    """Exclude dev edges; metadata must be --filter-platform TARGET output."""
    packages = {item["id"]: item for item in metadata["packages"]}
    nodes = {item["id"]: item for item in metadata["resolve"]["nodes"]}
    roots = [item for item in metadata["workspace_members"] if packages[item]["name"] == package_name]
    require(len(roots) == 1, "one native runtime Cargo package required")
    reached, edges, pending = set(), {}, [roots[0]]
    while pending:
        identity = pending.pop()
        if identity in reached:
            continue
        require(identity in packages and identity in nodes, "incomplete Cargo resolution")
        reached.add(identity)
        dependencies = sorted({item["pkg"] for item in nodes[identity]["deps"]
                               if any(kind["kind"] in (None, "build") for kind in item["dep_kinds"])})
        edges[identity] = dependencies
        pending.extend(dependencies)
    return roots[0], packages, nodes, reached, edges


def cargo_sbom(metadata, lock_bytes, target, binary_sha, source_commit):
    root, packages, nodes, reached, edges = normal_closure(metadata)
    locked = tomllib.loads(lock_bytes.decode("utf-8"))["package"]
    locks = {(item["name"], item["version"], item.get("source")): item for item in locked}
    identities = {}
    for identity in reached:
        item = packages[identity]
        # No host-specific absolute Cargo package IDs appear in the BOM.
        identities[identity] = "cargo:" + item["name"] + "@" + item["version"] + ":" + hashlib.sha256(
            (item.get("source") or "workspace").encode()).hexdigest()[:16]
    require(len(set(identities.values())) == len(identities), "Cargo component reference collision")
    components = []
    for identity in sorted(reached, key=lambda value: identities[value]):
        item = packages[identity]
        source = item.get("source")
        key = (item["name"], item["version"], source)
        require(key in locks, "resolved package missing from Cargo.lock")
        lock = locks[key]
        properties = [{"name": "symbiote:source", "value": source or "workspace"},
                      {"name": "symbiote:resolved-features", "value": ",".join(sorted(nodes[identity]["features"]))}]
        if source and source.startswith("registry+"):
            properties.append({"name": "symbiote:cargo-registry-archive-sha256", "value": pin(lock["checksum"])})
        component = {"type": "application" if identity == root else "library",
                     "bom-ref": identities[identity], "name": item["name"], "version": item["version"],
                     "properties": properties}
        if source and source.startswith("registry+"):
            component["purl"] = "pkg:cargo/" + item["name"] + "@" + item["version"]
        if item.get("license"):
            component["licenses"] = [{"expression": item["license"]}]
        components.append(component)
    application = next(item for item in components if item["bom-ref"] == identities[root])
    application["hashes"] = [{"alg": "SHA-256", "content": pin(binary_sha)}]
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "metadata": {"component": application, "properties": [
               {"name": "symbiote:scope", "value": "Cargo target-filtered normal/build closure; excludes dev-only and system/toolchain libraries"},
               {"name": "symbiote:target", "value": target},
               {"name": "symbiote:source-commit", "value": source_commit},
               {"name": "symbiote:cargo-lock-sha256", "value": hashlib.sha256(lock_bytes).hexdigest()}]},
           "components": [item for item in components if item is not application],
           "dependencies": [{"ref": identities[identity], "dependsOn": sorted(identities[dep] for dep in edges[identity])}
                            for identity in sorted(reached, key=lambda value: identities[value])]}
    # The pinned actions/attest SBOM consumer requires a serialNumber even
    # though the CycloneDX 1.5 schema permits its omission. Derive its UUID from
    # this exact canonical content before adding the identifier itself.
    content_sha=hashlib.sha256(canonical(bom)).hexdigest()
    bom["serialNumber"]=uuid.uuid5(uuid.NAMESPACE_URL,"https://github.com/"+REPOSITORY+"/sbom/v1/"+content_sha).urn
    return bom, sorted(nodes[root]["features"])


def command_text(command, *, native=False):
    options={}
    if native:options["env"]={key:value for key,value in os.environ.items()if key.upper()in CHILD_ENVIRONMENT_KEYS}
    result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=60, check=False,**options)
    require(result.returncode == 0 and len(result.stdout) + len(result.stderr) <= 16 * 1024 * 1024,
            "release metadata command failed or exceeded byte bound")
    return result.stdout.decode("utf-8")


def metadata(args):
    bundles.validate_version(args.version)
    require(re.fullmatch(r"[0-9a-f]{40}", args.commit), "full source commit required")
    require(command_text(["git", "rev-parse", "HEAD"]).strip() == args.commit
            and not command_text(["git", "status", "--porcelain"]).strip(), "clean exact source required")
    source = source_fingerprint.manifest(ROOT)
    binary = plain(args.binary)
    image = read(binary)
    bundles.binary_target(image, args.target)
    binary_sha = hashlib.sha256(image).hexdigest()
    require(bundles.inspect_bundle(plain(args.bundle), args.version) == args.target, "bundle target mismatch")
    with zipfile.ZipFile(args.bundle) as archive:
        require(hashlib.sha256(archive.read(bundles.TARGETS[args.target][2])).hexdigest() == binary_sha,
                "bundle binary does not match build image")
    version = parse(command_text([str(binary), "version", "--json"],native=True))
    require(version["name"] == "SYMBIOTE" and version["version"] == args.version[1:]
            and version["build_source_commit"] == args.commit, "native version/source stamp differs")
    rustc = command_text(["rustc", "-vV"])
    require(re.search(r"^release: " + re.escape(MSRV) + r"$", rustc, re.M), "release compiler must equal locked MSRV")
    cargo = command_text(["cargo", "--version"]).strip()
    require(not os.environ.get("RUSTFLAGS") and not os.environ.get("CARGO_ENCODED_RUSTFLAGS"),
            "undeclared compiler flags refused")
    resolved_raw = command_text(["cargo", "metadata", "--locked", "--offline", "--format-version", "1",
                                 "--filter-platform", args.target])
    resolved = parse(resolved_raw)
    lock = read(ROOT / "Cargo.lock")
    sbom, features = cargo_sbom(resolved, lock, args.target, binary_sha, args.commit)
    proofs = [{"name": plain(path).name, "bytes": len(read(path)), "sha256": sha(path)} for path in args.proof]
    require(len({item["name"] for item in proofs}) == len(proofs), "proof filename collision")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    sbom_path = out / ("symbiote-" + args.version + "-" + args.target + ".cdx.json")
    proof_path = out / ("symbiote-" + args.version + "-" + args.target + ".build.json")
    write_new(sbom_path, sbom)
    receipt = {"schema": "symbiote.release-build/1", "status": "PASS_STAGED_BUILD_METADATA",
               "source_commit": args.commit, "source_manifest": source, "target": args.target,
               "version": args.version, "compiler_locked": MSRV, "rustc_verbose": rustc, "cargo_version": cargo,
               "source_verification_run_id":os.environ.get("SYMBIOTE_VERIFICATION_RUN_ID"),
               "build_profile": "release", "build_command": ["cargo", "build", "--release", "--locked", "-p",
                   "symbiote-runtime", "--bin", "symbiote", "--target", args.target],
               "features": features, "compiler_flags": [], "cargo_lock_sha256": hashlib.sha256(lock).hexdigest(),
               "release_helper_sha256": sha(Path(__file__)),
               "packager_sha256": sha(TOOLS / "package_release.py"),
               "containment_helper_sha256": sha(TOOLS / "stability_campaign.py"),
               "source_manifest_helper_sha256": sha(TOOLS / "source_fingerprint.py"),
               "bundle": {"name": Path(args.bundle).name, "bytes": len(read(args.bundle)), "sha256": sha(args.bundle)},
               "binary": {"name": binary.name, "bytes": len(image), "sha256": binary_sha},
               "sbom": {"name": sbom_path.name, "sha256": sha(sbom_path)}, "proofs": proofs,
               "cargo_metadata_sha256": hashlib.sha256(resolved_raw.encode()).hexdigest(),
               "qualification": "staged metadata only; installed acceptance, final hour and public delivery are separate gates"}
    require(sha(binary) == binary_sha and read(ROOT / "Cargo.lock") == lock
            and source_fingerprint.manifest(ROOT) == source
            and all(sha(TOOLS / name) == expected for name, expected in LOADED_HELPERS.items()),
            "build inputs or executed release helpers changed during metadata capture")
    write_new(proof_path, receipt)
    return receipt


def inspect_prediction(report):
    require(report["schema"] == "symbiote.observation-demo/1" and report["status"] == "PASS"
            and report["network_requests"] == 0 and report["language_model"] is False, "observation proof schema/status")
    # This is the immutable owned legacy fixture in observation_demo.rs, not
    # the separate new Engine-CLI observation source used below.
    source_pin=hashlib.sha256(b"owned-synthetic-affine/3-bit-xor5-bias1/v1").hexdigest()
    need_source=(report["source"]=="explicitly owned deterministic three-bit affine observation source"
                 and report["source_sha256"]==source_pin and report["artifact"]=="standalone-active-affine")
    require(need_source,"owned observation source/provenance differs")
    snapshot=report["snapshot"]
    require(snapshot["family"]=="boolean-affine/v1" and snapshot["width"]==3
            and snapshot["physical_certificate_authorized"] is False
            and snapshot["conditional_strategy"]==dict(kind="affine",width=3,coefficients=5,bias=True),
            "owned observation conditional model differs")
    predictions = report["predictions"]
    require(len(predictions) == 8 and {item["input"] for item in predictions} == set(range(8)), "complete finite prediction domain")
    for item in predictions:
        require(type(item["input"]) is int and type(item["prediction"]) is int
                and item["prediction"] == (((item["input"] & 5).bit_count() % 2) ^ 1), "owned observation prediction differs")


def verify_export(root, filename, schema, native_sha, driver_sha):
    root = plain(root, True)
    manifest = parse(read(root / filename))
    require(manifest["schema"] == schema and manifest["native_sha256"] == native_sha
            and manifest["driver_sha256"] == driver_sha and manifest["private_keys_copied"] is False,
            "native proof source images or schema differ")
    require("status" not in manifest or manifest["status"] == "PASS", "native proof recorded a failed status")
    names, total = set(), 0
    for row in manifest["files"]:
        name = row["path"]
        require(isinstance(name, str) and "\\" not in name and ":" not in name and not name.startswith("/")
                and all(part not in ("", ".", "..") for part in name.split("/"))
                and name not in names, "unsafe or duplicate native proof member")
        path = plain(root.joinpath(*name.split("/")))
        require(path.suffix.lower() not in {".key", ".pfx", ".p12"}, "private credential file refused")
        raw = read(path)
        require(type(row["bytes"]) is int and len(raw) == row["bytes"]
                and hashlib.sha256(raw).hexdigest() == pin(row["sha256"]), "native proof byte census mismatch")
        total += len(raw); names.add(name)
        require(total <= 256 * 1024 * 1024 and len(names) <= 20000, "native proof corpus limit")
    actual = set()
    def listing_error(error):
        raise error
    directories_seen = 0
    for current, directories, files in os.walk(root, followlinks=False, onerror=listing_error):
        plain(current, True)
        directories_seen += len(directories)
        require(directories_seen <= 20000, "native proof directory limit")
        for name in directories:
            plain(Path(current) / name, True)
        for name in files:
            actual.add(plain(Path(current) / name).relative_to(root).as_posix())
    require(actual == names | {filename}, "native proof omitted or invented a file")
    return manifest


def selected_driver(path):
    rows = [parse(line) for line in read(path).splitlines() if line.strip()]
    selected = [row["executable"] for row in rows if row.get("reason") == "compiler-artifact"
                and row.get("target", {}).get("name") == "service"
                and row.get("profile", {}).get("test") is True and row.get("executable")]
    require(len(selected) == 1, "exactly one freshly built service-test image required")
    driver = plain(selected[0])
    require("\n" not in str(driver) and "\r" not in str(driver), "unsafe driver output path")
    return {"path": str(driver), "sha256": sha(driver)}


def seal_stage(args):
    bundles.validate_version(args.version)
    require(args.target in bundles.TARGETS, "unsupported staged target")
    directory = plain(args.out, True)
    prefix = "symbiote-" + args.version + "-" + args.target
    suffixes = (".zip", ".build.json", ".cdx.json", ".provenance.sigstore.json", ".sbom.sigstore.json",
                ".provenance-verification.json", ".sbom-verification.json")
    rows = []
    for suffix in suffixes:
        raw = read(directory / (prefix + suffix))
        rows.append({"name": prefix + suffix, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})
    manifest = directory / ("STAGED_SHA256SUMS-" + args.target)
    with manifest.open("x", encoding="ascii", newline="\n") as output:
        output.write("".join(item["sha256"] + "  " + item["name"] + "\n" for item in rows))
    return {"schema": "symbiote.staged-checksum-set/1", "status": "PASS_EXACT_STAGED_FILES",
            "checksums": manifest.name, "sha256": sha(manifest), "files": rows}


def preserve_attestation(source, destination):
    raw = read(source)
    require(isinstance(parse(raw), dict), "Sigstore bundle JSON required")
    plain(Path(destination).parent, True)
    with Path(destination).open("xb") as output:
        output.write(raw)
    return {"schema": "symbiote.attestation-copy/1", "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def typed_engine_lifecycle(binary, out, call):
    observations=out/"engine-observations.json"
    frames=[dict(sequence=index,input=value,output=(value&5).bit_count()%2) for index,value in enumerate((0,1,2,4,3))]
    write_new(observations,frames)
    config=out/"engine-config.json"
    descriptor=dict(source_id="installed-owned-source",scope="installed-engine/v1",epoch="owned-epoch-1",commitment=sha(observations),width=3)
    write_new(config,dict(schema="symbiote.engine-config/1",authorized_sources=[descriptor],max_queries_per_episode=16,
                          max_gf2_work_per_episode=1000000,max_duration_ms=12000))
    state=out/"engine-owner"
    def invoke(label,command,owner=None,state_path=state,options=(),expected=0):
        argv=[binary,"engine",command,"--state",state_path,"--config",config]
        if owner is not None:argv += ["--owner",owner]
        raw=call("installed-engine-"+label,[*argv,*options],expected=expected)
        value=parse(raw)
        require(value["schema"]=="symbiote.engine-cli/1" and value["status"]==("PASS" if expected==0 else "ERROR"),"typed installed engine result schema/status")
        write_new(out/("engine-"+label+".json"),value)
        return value
    initialized=invoke("init","init");owner=initialized["inspection"]["owner"]
    first=invoke("learn","learn",owner,options=["--source",descriptor["source_id"],"--observations",observations])
    learning=first["result"]["learning"];artifact=learning["artifact"]
    require(learning["usage"]["source_calls"]==5 and first["source_access"]["calls"]==5
            and first["source_access"]["file_opened"] is True and learning["reused"] is False,"actual installed public-API learning required")
    missing=out/"nonexistent-replay-source.json"
    require(not missing.exists(),"source-off test path must be absent")
    again=invoke("reopen","learn",owner,options=["--source",descriptor["source_id"],"--observations",missing])
    require(again["result"]["learning"]["reused"] is True and again["source_access"]==dict(calls=0,read_bytes=0,file_opened=False)
            and again["inspection"]["knowledge"]==first["inspection"]["knowledge"],"retained installed API reuse contacted a missing source or changed knowledge")
    prediction=invoke("predict","predict",owner,options=["--artifact",artifact,"--input","6"])
    require(prediction["result"]["prediction"]["answer"]==1 and prediction["result"]["prediction"]["basis"]=="conditional_affine"
            and prediction["result"]["prediction"]["record_sha256"]==learning["record_sha256"],"exact retained conditional prediction required")
    cancelled_state=out/"engine-cancel-owner"
    cancelled_owner=invoke("cancel-init","init",state_path=cancelled_state)["inspection"]["owner"]
    cancelled=invoke("cancelled","learn",cancelled_owner,state_path=cancelled_state,
                     options=["--source",descriptor["source_id"],"--observations",missing,"--cancelled"],expected=1)
    require(cancelled["error"]["kind"]=="cancelled" and cancelled["source_access"]==dict(calls=0,read_bytes=0,file_opened=False)
            and cancelled["inspection"]["knowledge"]["records"]==1,"pre-cancel must preserve empty knowledge without opening source")
    checkpoint=invoke("checkpoint","checkpoint",owner,options=["--backup",out/"engine-checkpoint"])
    checkpoint_pin=pin(checkpoint["result"]["checkpoint"]["manifest_sha256"])
    restored_state=out/"engine-restored-owner"
    restored=invoke("restore","restore",owner,state_path=restored_state,
                    options=["--checkpoint",out/"engine-checkpoint.json","--manifest-sha256",checkpoint_pin])
    require(restored["result"]["restore"]["network_started"] is False and restored["inspection"]["owner"]==owner
            and restored["inspection"]["knowledge"]==checkpoint["inspection"]["knowledge"],"typed checkpoint/restore changed the owner or retained models")
    restored_prediction=invoke("restored-predict","predict",owner,state_path=restored_state,options=["--artifact",artifact,"--input","6"])
    require(restored_prediction["result"]["prediction"]["answer"]==1
            and restored_prediction["result"]["prediction"]["record_sha256"]==learning["record_sha256"],"restored public-API model differs")
    for name in ("ledger.jsonl","knowledge.jsonl"):
        require(read(state/name)==read(restored_state/name),"typed restore changed committed identity/knowledge bytes")
    require(read(restored_state/"operations.jsonl").startswith(read(state/"operations.jsonl")),"typed restore lost original operational prefix")
    restored_identity=[parse(line)for line in read(restored_state/"ledger.jsonl").splitlines()]
    require(len(restored_identity)>=2 and restored_identity[1]["payload"]==dict(event="engine_owner_registered",
            namespace="embedding-engine/v1",minimum_writer="symbiote-engine-writer/1"),"restored typed owner lost its minimum-writer marker")
    before={name:sha(restored_state/name)for name in ("ledger.jsonl","knowledge.jsonl","operations.jsonl")}
    # This current legacy writer must refuse even after every typed handle has
    # closed; no lock conflict may substitute for namespace admission.
    call("installed-engine-legacy-writer-refused",[binary,"observe-demo","--state",restored_state,
         "--receipts",out/"engine-legacy-refused.json","--json"],expected=1)
    require({name:sha(restored_state/name)for name in before}==before,"legacy writer changed an engine-owned restored ledger")
    invoke("revoke","revoke",owner,options=["--artifact",artifact,"--reason","installed acceptance explicit revocation"])
    revoked=invoke("revoked-predict","predict",owner,options=["--artifact",artifact,"--input","6"],expected=1)
    require(revoked["error"]["kind"]=="revoked","revoked installed artifact must fail through typed API")
    return dict(status="PASS_INSTALLED_TYPED_ENGINE_LIFECYCLE",owner=owner,artifact=artifact,record_sha256=learning["record_sha256"],
                source_commitment=descriptor["commitment"],fresh_source_calls=5,retained_source_access=again["source_access"],
                cancelled_typed=True,revoked_typed=True,checkpoint_manifest_sha256=checkpoint_pin,conditional=True,
                minimum_writer_marker_preserved=True,current_legacy_writer_refused=True,economic_benefit_verified=False)


def acceptance(args):
    require(args.target == host_target(), "installed test target must equal actual host")
    bundles.validate_version(args.version)
    bundle = plain(args.bundle)
    require(bundles.inspect_bundle(bundle, args.version) == args.target, "bundle target mismatch")
    manifest = bundle.parent / "SHA256SUMS"
    bundles.verify_directory(bundle.parent, args.version, require_targets=[args.target])
    bundle_pin, manifest_pin = sha(bundle), sha(manifest)
    driver = plain(args.service_tests)
    driver_sha = pin(args.service_tests_sha256)
    require(sha(driver) == driver_sha, "service-test image does not match admitted hash")
    out = fresh(args.out)
    processes = out / "processes"; processes.mkdir()
    started = time.monotonic()
    calls = []
    report = {"schema": "symbiote.installed-platform-acceptance/1", "status": "HOLD",
              "target": args.target, "source_commit": args.commit, "version": args.version,
              "bundle_sha256": bundle_pin, "calls": calls}

    def call(label, argv, timeout=30, environment=None,expected=0):
        require(time.monotonic() - started < 180, "installed acceptance deadline")
        result = child_execute(argv, processes, label, timeout=min(timeout, max(0.01, 180 - (time.monotonic() - started))),
                                environment=environment)
        calls.append(result)
        safety.check_exit(result,expected)
        return safety.output(result, processes)

    try:
        installed = out / "installed"
        if os.name == "nt":
            shell = shutil.which("pwsh") or shutil.which("powershell.exe")
            require(shell is not None, "PowerShell unavailable")
            command = [shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", ROOT / "tools/install.ps1",
                       "-Version", args.version, "-BundleDirectory", bundle.parent, "-InstallDir", installed]
        else:
            shell = shutil.which("sh"); require(shell is not None, "POSIX shell unavailable")
            command = [shell, ROOT / "tools/install.sh", "--version", args.version, "--bundle-dir", bundle.parent,
                       "--install-dir", installed]
        call("install-local-checked-bundle-no-path", command)
        binary = plain(installed / bundles.TARGETS[args.target][2])
        with zipfile.ZipFile(bundle) as archive:
            require(read(binary) == archive.read(binary.name), "installed image bytes differ from bundle")
        image_pin = sha(binary)
        version = parse(call("installed-source-stamp", [binary, "version", "--json"]))
        require(version["name"] == "SYMBIOTE" and version["version"] == args.version[1:]
                and version["build_source_commit"] == args.commit, "installed native stamp mismatch")
        typed_engine=typed_engine_lifecycle(binary,out,call)
        state = out / "owner"
        first = parse(call("installed-learn", [binary, "observe-demo", "--state", state, "--json", "--receipts", out / "learn.json"]))
        inspect_prediction(first)
        require(first["fresh_promotions"] == 1 and first["source_queries"] == 5, "actual new learning required")
        histories = {name: read(state / name) for name in ("ledger.jsonl", "knowledge.jsonl")}
        again = parse(call("installed-reopen-predict", [binary, "observe-demo", "--state", state, "--json", "--receipts", out / "reopen.json"]))
        inspect_prediction(again)
        require(again["fresh_promotions"] == 0 and again["source_queries"] == 0
                and again["identity"] == first["identity"] and again["record_sha256"] == first["record_sha256"]
                and again["predictions"] == first["predictions"], "reopen must reuse the exact durable model")
        backup = out / "backup"
        saved = parse(call("installed-backup", [binary, "backup-state", "--state", state, "--backup", backup, "--json"]))
        pin(saved["manifest_sha256"])
        verified = parse(call("installed-verify-backup", [binary, "verify-backup", "--backup", backup,
                              "--manifest-sha256", saved["manifest_sha256"], "--json"]))
        restored = out / "restored-owner"
        restored_proof = parse(call("installed-restore", [binary, "restore-state", "--backup", backup,
                                    "--manifest-sha256", saved["manifest_sha256"], "--state", restored, "--json"]))
        restored_use = parse(call("installed-restored-predict", [binary, "observe-demo", "--state", restored, "--json",
                                  "--receipts", out / "restored-predictions.json"]))
        inspect_prediction(restored_use)
        require(restored_use["predictions"] == first["predictions"] and restored_use["source_queries"] == 0
                and restored_use["fresh_promotions"] == 0, "restored model not reused exactly")
        require(all(item["identity"] == first["identity"] and item["manifest_sha256"] == saved["manifest_sha256"]
                    and item["network_started"] is False for item in (saved, verified, restored_proof)), "offline restore proof mismatch")
        require(all(read(state / name) == raw == read(restored / name) for name, raw in histories.items()),
                "learning history changed on reopen/restore")
        cancellation_root = out / "native-cancellation"
        cancellation_case = "cognitive::native_cognition_rejects_wrong_transfer_and_respects_owner_eof_and_rpc_budget"
        cancellation_output = call("installed-native-cancel-eof-budget", [driver, cancellation_case, "--exact", "--nocapture", "--test-threads=1"],
                                   60, {"SYMBIOTE_COGNITION_TEST_BINARY": str(binary),
                                        "SYMBIOTE_CANCELLATION_ARTIFACTS": str(cancellation_root)})
        safety.check_native_test(cancellation_output)
        cancellation = verify_export(cancellation_root, "cancellation-artifacts.json", "symbiote.native-cancellation-proof/1",
                                     image_pin, driver_sha)
        for field, name in (("first", "native-counterexample"), ("eof", "native-eof"), ("bounded", "native-rpc-bound")):
            require(cancellation[field] == parse(read(cancellation_root / name / "summary.json")), "cancellation summary not bound to native raw output")
            exited = parse(read(cancellation_root / name / "process-exit.json"))
            require(exited["schema"] == "symbiote.native-test-process-exit/1" and exited["observed_exited"] is True
                    and exited["exit_code"] == 0 and type(exited["pid"]) is int and exited["pid"] > 0
                    and exited["owner_input_closed"] is (field == "eof") and exited["native_sha256"] == image_pin,
                    "actual installed cancellation child exit proof missing")
        require(cancellation["eof"]["fresh_promotions"] == 0
                and cancellation["eof"]["reason"] in {"owner-eof", "cancelled:before-rpc"}
                and cancellation["bounded"]["budget"]["rpc_attempts"] == 1
                and cancellation["bounded"]["fresh_promotions"] == 0
                and cancellation["bounded"]["reason"] == "budget:global-rpc-or-plaintext", "native cancellation/budget proof differs")
        outcome_root = out / "native-outcomes"
        outcome_case = "outcomes::two_native_agents_reconcile_receiver_owned_outcome_and_restart"
        outcome_output = call("installed-native-receiver-outcome-restart", [driver, outcome_case, "--exact", "--nocapture", "--test-threads=1"],
                              60, {"SYMBIOTE_COGNITION_TEST_BINARY": str(binary), "SYMBIOTE_OUTCOME_ARTIFACTS": str(outcome_root)})
        safety.check_native_test(outcome_output)
        outcomes = verify_export(outcome_root, "outcome-artifacts.json", "symbiote.receiver-outcome-native-proof/1", image_pin, driver_sha)
        for field, name in (("first", "sender-first"), ("restart", "sender-restart"),
                            ("receiver_first", "receiver-first"), ("receiver_restart", "receiver-restart")):
            require(outcomes[field] == parse(read(outcome_root / name / "summary.json")), "outcome summary not bound to native raw output")
        require(len(outcomes["pids"]) == 4 and len(set(outcomes["pids"])) == 4
                and all(type(value) is int and value > 0 for value in outcomes["pids"]), "actual receiver/sender restart PIDs required")
        require(outcomes["first"]["receiver_outcomes_verified"] == 1
                and outcomes["first"]["receiver_capability_outcomes_verified"] == 1
                and outcomes["first"]["partner_benefits_verified"] == 0
                and outcomes["restart"]["receiver_outcomes_verified"] == 0
                and outcomes["restart"]["observation_usage"]["queries"] == 0
                and outcomes["restart"]["fresh_promotions"] == 0, "receiver outcome or duplicate restart credit differs")
        require(sha(binary) == image_pin and sha(bundle) == bundle_pin and sha(manifest) == manifest_pin,
                "installed binary or input bundle changed")
        require(sha(driver) == driver_sha, "native proof driver changed during acceptance")
        require(time.monotonic() - started <= 180, "installed acceptance final deadline")
        report.update(status="PASS_INSTALLED_NATIVE_LIFECYCLE", installed_binary_sha256=image_pin,
                      typed_engine_lifecycle=typed_engine,
                      service_test_driver_sha256=driver_sha,
                      identity=first["identity"], backup_manifest_sha256=saved["manifest_sha256"],
                      fresh_source_queries=5, reopened_source_queries=0, restored_source_queries=0,
                      history_bytes_preserved=True, cancellation="PASS_ACTUAL_INSTALLED_IMAGE_EOF_AND_RPC_BOUND",
                      outcome="PASS_ACTUAL_INSTALLED_IMAGE_RECEIVER_CAPABILITY_OUTCOME",
                      native_outcome_case=outcome_case, native_cancellation_case=cancellation_case,
                      qualification="bounded installed native lifecycle only; embedding, final hour and public delivery are separate gates")
    except (Exception, KeyboardInterrupt) as error:
        report["failure"] = str(error)
    report["elapsed_seconds"] = time.monotonic() - started
    write_new(out / "acceptance.json", report)
    return report


def embedding_acceptance(args):
    binary=plain(args.binary);image_pin=sha(binary)
    bundles.binary_target(read(binary),host_target())
    out=fresh(args.out);processes=out/"processes";processes.mkdir()
    executables=out/"executables";executables.mkdir()
    selected=executables/("embedding-consumer.exe" if os.name=="nt" else "embedding-consumer")
    with selected.open("xb") as output:output.write(read(binary))
    selected.chmod(0o755)
    require(sha(selected)==image_pin,"preserved consumer differs from built bytes")
    binary=selected
    report=dict(schema="symbiote.embedding-platform-acceptance/1",status="HOLD",source_commit=args.commit,
                target=host_target(),binary_sha256=image_pin,calls=[])
    try:
        for label,argv in (("embedding-version",[binary,"--version"]),
                           ("independent-embedding-lifecycle",[binary,"--out",out/"lifecycle"])):
            record=child_execute(argv,processes,label,timeout=60)
            report["calls"].append(record);safety.check_exit(record)
            value=parse(safety.output(record,processes))
            require(value["build_source_commit"]==args.commit,"independent consumer source stamp differs")
            if label=="embedding-version":
                require(value["schema"]=="symbiote.embedding-consumer-version/1" and value["version"]==args.version[1:],"consumer version differs")
            else:
                actual=parse(read(out/"lifecycle/acceptance.json"))
                require(actual==value and value["schema"]=="symbiote.embedding-consumer/1" and value["status"]=="PASS"
                        and value["engine_version"]==args.version[1:] and len(set(value["owners"]))==2
                        and value["retained_source_calls"]==0 and value["economic_benefit_verified"] is False
                        and all(value[field] is True for field in ("cancelled_typed","writer_exclusion","revoked_typed","checkpoint_restore","conditional")),
                        "independent consumer did not complete its public API lifecycle")
                report["native_acceptance_sha256"]=sha(out/"lifecycle/acceptance.json")
        require(sha(binary)==image_pin,"independent consumer executable changed")
        report["status"]="PASS_INDEPENDENT_EMBEDDING_LIFECYCLE"
    except (Exception,KeyboardInterrupt) as error:report["failure"]=str(error)
    write_new(out/"embedding-acceptance.json",report)
    return report


def stage_acceptance(args):
    destination=Path(os.path.abspath(args.out))
    require((ROOT/"dist").resolve(strict=True) in destination.parents and not destination.exists(),"fresh dist-only evidence copy required")
    destination.parent.mkdir(parents=True,exist_ok=True);destination.mkdir()
    copies=[]
    def census(root):
        rows=[];total=0
        def failed(error):raise error
        for current,directories,files in os.walk(root,followlinks=False,onerror=failed):
            plain(current,True)
            for name in directories:plain(Path(current)/name,True)
            for name in files:
                path=plain(Path(current)/name)
                require(path.suffix.lower() not in {".key",".pfx",".p12"},"private credential file refused")
                raw=read(path);total+=len(raw);rows.append(dict(path=path.relative_to(root).as_posix(),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
                require(len(rows)<=20000 and total<=512*1024*1024,"closed evidence copy limit")
        return sorted(rows,key=lambda row:row["path"])
    for name,path in (("installed",args.installed),("embedding",args.embedding)):
        if not path.exists():copies.append(dict(kind=name,status="MISSING_NOT_QUALIFIED"));continue
        source=plain(path,True);before=census(source);target=destination/name;target.mkdir()
        for row in before:
            original=source.joinpath(*row["path"].split("/"));selected=target.joinpath(*row["path"].split("/"))
            selected.parent.mkdir(parents=True,exist_ok=True);raw=read(original)
            require(len(raw)==row["bytes"] and hashlib.sha256(raw).hexdigest()==row["sha256"],"copy source changed after census")
            with selected.open("xb") as output:output.write(raw)
        require(census(source)==before and census(target)==before,"closed evidence changed or copy differs")
        copies.append(dict(kind=name,status="PASS_BYTE_COPY_ONLY",original_root=str(source),files=before))
    receipt=dict(schema="symbiote.platform-evidence-copy/1",copies=copies,qualification="byte copy only; actual acceptance statuses remain authoritative")
    write_new(destination/"copy-witness.json",receipt)
    return receipt


def verify_source_ci(run,jobs,commit,run_id):
    require(re.fullmatch(r"[0-9a-f]{40}",commit) and str(run_id).isdecimal(),"source/run coordinates required")
    require(type(run["id"]) is int and run["id"]==int(run_id) and run["repository"]["full_name"]==REPOSITORY
            and run["head_repository"]["full_name"]==REPOSITORY and run["head_branch"]=="main"
            and run["head_sha"]==commit and run["event"]=="push" and run["path"]==".github/workflows/ci.yml"
            and run["status"]=="completed" and run["conclusion"]=="success","official source CI identity/conclusion differs")
    required={"verify (ubuntu-latest)":{"Run python tools/verify.py","Document the supported API on the minimum compiler"},
              "verify (windows-latest)":{"Run python tools/verify.py","Document the supported API on the minimum compiler"},
              "verify (macos-latest)":{"Run python tools/verify.py","Document the supported API on the minimum compiler"},
              "Current stable compatibility":{"Run cargo test --workspace --all-features --locked",
                  "Run cargo clippy --workspace --all-targets --all-features --locked -- -D warnings"}}
    require(jobs["total_count"]==4 and len(jobs["jobs"])==4 and {job["name"] for job in jobs["jobs"]}==set(required),"exact complete source CI platform/stable job set required")
    for job in jobs["jobs"]:
        require(job["run_id"]==run["id"] and job["head_sha"]==commit and job["run_attempt"]==run["run_attempt"]
                and job["status"]=="completed" and job["conclusion"]=="success","source job belongs to a different run/attempt or failed")
        steps={step["name"]:step for step in job["steps"]}
        require(required[job["name"]]<=steps.keys() and all(steps[name]["status"]=="completed" and steps[name]["conclusion"]=="success"
                for name in required[job["name"]]),"required source gate was skipped or failed")
    return dict(schema="symbiote.source-ci-gate/1",status="PASS_OFFICIAL_SOURCE_CI",source_commit=commit,repository=REPOSITORY,
                run_id=run["id"],run_attempt=run["run_attempt"],workflow=run["path"],compiler_minimum=MSRV,
                jobs=[dict(id=job["id"],name=job["name"],conclusion=job["conclusion"]) for job in jobs["jobs"]],
                interpretation="source software gates only; installed platform images, embedding, ENOSPC, studies and hour remain separate")


def public_verifier():
    publisher_path=Path(__file__).with_name("v11_publish.py");publisher_raw=read(publisher_path)
    publisher=types.ModuleType("qualified_public_verifier");publisher.__file__=str(publisher_path)
    exec(compile(publisher_raw,str(publisher_path),"exec"),publisher.__dict__)
    return publisher,hashlib.sha256(publisher_raw).hexdigest()


def selected_install_input(downloads,out,tag,target,bundle_sha256):
    prefix="symbiote-"+tag+"-"+target
    global_rows={}
    global_raw=read(downloads/"SHA256SUMS")
    for line in global_raw.decode("ascii").splitlines():
        match=re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)",line)
        require(match is not None and match[2] not in global_rows,"malformed public global checksum manifest")
        global_rows[match[2]]=match[1]
    require(global_raw.endswith(b"\n") and set(global_rows)=={"symbiote-"+tag+"-"+item+".zip" for item in bundles.TARGETS}
            and global_rows[prefix+".zip"]==pin(bundle_sha256),"public checksum set or selected subject differs")
    raw=read(downloads/(prefix+".zip"))
    require(hashlib.sha256(raw).hexdigest()==bundle_sha256,"downloaded selected image differs")
    # Preserve the public four-platform checksum file unchanged. The installer's
    # local directory contains only one host image and gets a derived census.
    destination=out/"selected-install-input";destination.mkdir()
    with (destination/(prefix+".zip")).open("xb") as output:output.write(raw)
    with (destination/"SHA256SUMS").open("x",encoding="ascii",newline="\n") as output:
        output.write(bundle_sha256+"  "+prefix+".zip\n")
    write_new(destination/"derivation.json",dict(schema="symbiote.selected-install-manifest/1",
        public_original_sha256=hashlib.sha256(global_raw).hexdigest(),selected_zip_sha256=bundle_sha256,
        selected_zip=prefix+".zip",purpose="derived single-host installer census; original public bytes remain unchanged"))
    return destination


@contextmanager
def public_metadata_access(transport, args):
    """Opt in to token-bearing fixed API GETs; restore before public byte reads.

    The token is never an argument, diagnostic value or child environment option.
    The original transport and its anonymous asset redirect reader are unchanged.
    """
    selected = getattr(args, "metadata_token_env", None)
    diagnostic = {"schema": "symbiote.public-metadata-access/1",
                  "mode": "anonymous" if selected is None else "explicit-metadata-only-token",
                  "requests": [], "token_value_recorded": False}
    if selected is None:
        yield diagnostic
        return
    require(selected == "SYMBIOTE_METADATA_TOKEN", "explicit dedicated metadata token environment required")
    token = os.environ.get(selected, "")
    require(0 < len(token) <= 16384 and all(33 <= ord(char) <= 126 for char in token),
            "selected metadata token is absent or malformed")
    require(transport.REPOSITORY == REPOSITORY and type(args.candidate_run_id) is int
            and args.candidate_run_id > 0 and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.tag),
            "fixed metadata repository/run/tag required")
    prefix = "/repos/" + REPOSITORY + "/"
    fixed = {prefix + "actions/runs/" + str(args.candidate_run_id),
             prefix + "actions/runs/" + str(args.candidate_run_id) + "/jobs",
             prefix + "releases/tags/" + args.tag, prefix + "git/ref/tags/" + args.tag}
    annotated = re.compile(re.escape(prefix) + r"git/tags/[0-9a-f]{40}")
    original = transport.metadata

    def metadata(path):
        # Preserve the legacy guard and narrow the authenticated subset further.
        transport.need(isinstance(path, str) and path.startswith(prefix) and "?" not in path and "#" not in path,
                       "fixed repository API route required")
        transport.need(path in fixed or annotated.fullmatch(path) is not None,
                       "unreviewed authenticated metadata route")
        transport.need(len(diagnostic["requests"]) < 12, "bounded metadata request count exceeded")
        observed = {"method": "GET", "host": "api.github.com", "path": path}
        diagnostic["requests"].append(observed)
        request = transport.urllib.request.Request(
            "https://api.github.com" + path + "?verification_stamp=" + str(time.time_ns()),
            headers={"Authorization": "Bearer " + token, "User-Agent": "SYMBIOTE-public-verification",
                     "Accept": "application/vnd.github+json", "Cache-Control": "no-cache"}, method="GET")
        try:
            with transport.urllib.request.build_opener(transport.NoRedirect()).open(request, timeout=60) as response:
                observed["status_code"] = response.status
                transport.need(response.status == 200, "authenticated metadata returned unexpected status")
                raw = response.read(transport.LIMITS["json_bytes"] + 1)
        except transport.urllib.error.HTTPError as error:
            observed["status_code"] = error.code
            raise
        transport.need(len(raw) <= transport.LIMITS["json_bytes"], "API metadata byte limit")
        return transport.parse(raw)

    transport.metadata = metadata
    try:
        yield diagnostic
    finally:
        transport.metadata = original


def public_acceptance(args):
    require(args.tag=="v1.1.2" and args.target==host_target(),"fixed v1.1.2 matching-host public acceptance required")
    pin(args.bundle_sha256);pin(args.plan_sha256);pin(args.gh_sha256)
    require(re.fullmatch(r"[0-9a-f]{40}",args.commit),"full source commit required")
    require(type(args.candidate_run_id) is int and args.candidate_run_id>0,"candidate workflow ID required")
    public_run=os.environ.get("GITHUB_RUN_ID","")
    require(re.fullmatch(r"[1-9][0-9]*",public_run) and os.environ.get("GITHUB_SHA")==args.commit
            and os.environ.get("GITHUB_REPOSITORY")==REPOSITORY,"actual source-bound public workflow context required")
    candidate=plain(args.candidate_root,True);gh=plain(args.gh)
    require(sha(gh)==args.gh_sha256,"GitHub verifier executable pin differs")
    # Read reviewed repository code directly; no downloaded Python or bytecache.
    publisher,publisher_sha=public_verifier()
    transport=publisher.transport;transport.configure_tag(args.tag)
    out=fresh(args.out);downloads=out/"downloads";downloads.mkdir();processes=out/"processes";processes.mkdir()
    report=dict(schema="symbiote.public-platform-acceptance/1",status="HOLD",source_commit=args.commit,target=args.target,
                tag=args.tag,candidate_run_id=args.candidate_run_id,publication_plan_sha256=args.plan_sha256,
                public_workflow_run_id=int(public_run),
                gh_sha256=args.gh_sha256,publisher_helper_sha256=publisher_sha,anonymous_downloads=[])
    try:
        with public_metadata_access(transport, args) as metadata_access:
            report["metadata_access"] = metadata_access
            candidate_run=publisher.check_run(args.candidate_run_id,args.commit,".github/workflows/v11-candidate.yml","workflow_dispatch")
            repository=candidate_run["run"]["repository"]
            require(isinstance(repository,dict) and repository.get("full_name")==REPOSITORY
                    and type(repository.get("id")) is int and repository["id"]>0,"validated candidate repository identity differs")
            release=transport.metadata("/repos/"+REPOSITORY+"/releases/tags/"+args.tag)
            require(release["tag_name"]==args.tag and release["draft"] is False,"actual public release required")
            transport.resolve_tag(args.commit)
        prefix="symbiote-"+args.tag+"-"+args.target
        names=[prefix+suffix for suffix in publisher.SUFFIXES]+["STAGED_SHA256SUMS-"+args.target,"SHA256SUMS"]
        assets={}
        for asset in release["assets"]:
            name=asset["name"]
            require(name not in assets,"duplicate public release asset")
            assets[name]=asset
        require(set(names)<=assets.keys(),"public target asset set incomplete")
        require(sum(assets[name]["size"] for name in names)<=512*1024*1024,"public target download byte limit")
        for name in names:
            expected=None if name=="SHA256SUMS" else sha(candidate/name)
            asset=assets[name]
            expected_url="https://github.com/"+REPOSITORY+"/releases/download/"+args.tag+"/"+name
            require(asset["browser_download_url"]==expected_url,"public asset origin/tag/name differs")
            actual=transport.download(expected_url,downloads/name,asset["size"],expected)
            transport.check_asset_digest(asset,actual)
            report["anonymous_downloads"].append(dict(name=name,sha256=actual,bytes=asset["size"],asset_id=asset["id"]))
        require(sha(downloads/(prefix+".zip"))==args.bundle_sha256,"public ZIP differs from externally selected subject")
        publisher.check_sums(downloads/("STAGED_SHA256SUMS-"+args.target),
            {prefix+suffix:sha(downloads/(prefix+suffix))for suffix in publisher.SUFFIXES})
        for index,(suffix,bundle_suffix,predicate) in enumerate(((".zip",".provenance.sigstore.json",publisher.PREDICATES[0]),
                (".build.json",".provenance.sigstore.json",publisher.PREDICATES[0]),(".cdx.json",".provenance.sigstore.json",publisher.PREDICATES[0]),
                (".zip",".sbom.sigstore.json",publisher.PREDICATES[1]))):
            require(sha(gh)==args.gh_sha256,"GitHub verifier changed before verification")
            subject=downloads/(prefix+suffix)
            call=child_execute([gh,"attestation","verify",subject,"--bundle",downloads/(prefix+bundle_suffix),"--repo",REPOSITORY,
                "--source-digest",args.commit,"--signer-workflow",REPOSITORY+"/.github/workflows/v11-candidate.yml",
                "--signer-digest",args.commit,"--deny-self-hosted-runners","--predicate-type",predicate,"--format","json"],
                processes,"public-subject-signature-"+str(index),timeout=120,environment={"GH_DEBUG":"","GH_TRACE":""})
            safety.check_exit(call)
            publisher.verified_attestation(parse(safety.output(call,processes)),sha(subject),args.commit,args.candidate_run_id,predicate,repository["id"])
        build=parse(read(downloads/(prefix+".build.json")))
        require(build["source_commit"]==args.commit and build["version"]==args.tag and build["target"]==args.target
                and build["compiler_locked"]==MSRV,"signed build metadata target/source/compiler differs")
        retained=candidate/"acceptance"/args.target
        native_proof=retained/"installed/acceptance.json";embedding_proof=retained/"embedding/embedding-acceptance.json"
        proofs={item["name"]:item["sha256"]for item in build["proofs"]}
        require(len(proofs)==len(build["proofs"]),"duplicate signed proof name")
        require(sha(native_proof)==proofs["acceptance.json"] and sha(embedding_proof)==proofs["embedding-acceptance.json"],"snapshot evidence does not match signed build")
        native=parse(read(native_proof));embedding=parse(read(embedding_proof))
        require(native["status"]=="PASS_INSTALLED_NATIVE_LIFECYCLE" and embedding["status"]=="PASS_INDEPENDENT_EMBEDDING_LIFECYCLE"
                and native["source_commit"]==embedding["source_commit"]==args.commit,"candidate component proof did not pass")
        driver=retained/"installed/native-outcomes/service-tests.exe"
        consumer=retained/"embedding/executables"/("embedding-consumer.exe"if os.name=="nt"else"embedding-consumer")
        require(sha(driver)==native["service_test_driver_sha256"] and sha(consumer)==embedding["binary_sha256"],"driver/consumer bytes differ from signed evidence")
        driver.chmod(0o755);consumer.chmod(0o755)
        install_input=selected_install_input(downloads,out,args.tag,args.target,args.bundle_sha256)
        report["native_acceptance"]=acceptance(types.SimpleNamespace(bundle=install_input/(prefix+".zip"),target=args.target,version=args.tag,
                commit=args.commit,service_tests=driver,service_tests_sha256=native["service_test_driver_sha256"],out=out/"native"))
        require(report["native_acceptance"]["status"]=="PASS_INSTALLED_NATIVE_LIFECYCLE","delivered native lifecycle failed")
        report["embedding_acceptance"]=embedding_acceptance(types.SimpleNamespace(binary=consumer,commit=args.commit,version=args.tag,out=out/"embedding"))
        require(report["embedding_acceptance"]["status"]=="PASS_INDEPENDENT_EMBEDDING_LIFECYCLE","delivered-source embedding lifecycle failed")
        require(sha(gh)==args.gh_sha256,"GitHub verifier changed")
        report.update(status="PASS_PUBLIC_PLATFORM_LIFECYCLE",release_id=release["id"],bundle_sha256=args.bundle_sha256,
                      installed_binary_sha256=report["native_acceptance"]["installed_binary_sha256"],
                      driver_sha256=native["service_test_driver_sha256"],consumer_sha256=embedding["binary_sha256"])
    except (Exception,KeyboardInterrupt) as error:report["failure"]=str(error)
    write_new(out/"public-acceptance.json",report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="mode", required=True)
    driver = subs.add_parser("driver")
    driver.add_argument("--cargo-json", type=Path, required=True)
    seal = subs.add_parser("seal")
    seal.add_argument("--out", type=Path, required=True)
    seal.add_argument("--version", required=True)
    seal.add_argument("--target", choices=sorted(bundles.TARGETS), required=True)
    preserve = subs.add_parser("preserve-attestation")
    preserve.add_argument("--input", type=Path, required=True)
    preserve.add_argument("--out", type=Path, required=True)
    embedding=subs.add_parser("embedding")
    embedding.add_argument("--binary",type=Path,required=True)
    embedding.add_argument("--commit",required=True)
    embedding.add_argument("--version",required=True)
    embedding.add_argument("--out",type=Path,required=True)
    staged=subs.add_parser("stage-acceptance")
    staged.add_argument("--installed",type=Path,required=True)
    staged.add_argument("--embedding",type=Path,required=True)
    staged.add_argument("--out",type=Path,required=True)
    ci=subs.add_parser("verify-source-ci")
    ci.add_argument("--run",type=Path,required=True);ci.add_argument("--jobs",type=Path,required=True)
    ci.add_argument("--source",required=True);ci.add_argument("--run-id",required=True);ci.add_argument("--out",type=Path,required=True)
    public=subs.add_parser("public-accept")
    public.add_argument("--candidate-root",type=Path,required=True);public.add_argument("--target",choices=sorted(bundles.TARGETS),required=True)
    public.add_argument("--tag",required=True);public.add_argument("--commit",required=True);public.add_argument("--bundle-sha256",required=True)
    public.add_argument("--plan-sha256",required=True);public.add_argument("--candidate-run-id",type=int,required=True)
    public.add_argument("--gh",type=Path,required=True);public.add_argument("--gh-sha256",required=True);public.add_argument("--out",type=Path,required=True)
    public.add_argument("--metadata-token-env", choices=("SYMBIOTE_METADATA_TOKEN",),
                        help="Explicit metadata-only API token environment; token excluded from release bytes and child programs")
    for name in ("metadata", "accept"):
        command = subs.add_parser(name)
        command.add_argument("--bundle", type=Path, required=True)
        command.add_argument("--target", choices=sorted(bundles.TARGETS), required=True)
        command.add_argument("--version", required=True)
        command.add_argument("--commit", required=True)
        command.add_argument("--out", type=Path, required=True)
        if name == "metadata":
            command.add_argument("--binary", type=Path, required=True)
            command.add_argument("--proof", type=Path, action="append", default=[])
        if name == "accept":
            command.add_argument("--service-tests", type=Path, required=True)
            command.add_argument("--service-tests-sha256", required=True)
    args = parser.parse_args()
    if args.mode=="public-accept":
        report=public_acceptance(args);print(json.dumps(report,indent=2))
        raise SystemExit(0 if report["status"].startswith("PASS") else 1)
    if args.mode=="verify-source-ci":
        receipt=verify_source_ci(parse(read(args.run)),parse(read(args.jobs)),args.source,args.run_id)
        receipt.update(run_metadata_sha256=sha(args.run),jobs_metadata_sha256=sha(args.jobs))
        write_new(args.out,receipt);print(json.dumps(receipt,indent=2));return
    if args.mode=="stage-acceptance":
        print(json.dumps(stage_acceptance(args),indent=2));return
    if args.mode=="embedding":
        result=embedding_acceptance(args);print(json.dumps(result,indent=2))
        raise SystemExit(0 if result["status"].startswith("PASS") else 1)
    if args.mode == "preserve-attestation":
        print(json.dumps(preserve_attestation(args.input, args.out)))
        return
    if args.mode == "seal":
        print(json.dumps(seal_stage(args), indent=2))
        return
    if args.mode == "driver":
        result = selected_driver(args.cargo_json)
        if "GITHUB_OUTPUT" in os.environ:
            run = os.environ.get("GITHUB_RUN_ID", "")
            attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
            require(run.isdecimal() and attempt.isdecimal(), "numeric workflow run/attempt required")
            base = Path(__import__("tempfile").gettempdir()).resolve(strict=True)
            destination = base / ("symbiote-v11-installed-" + run + "-" + attempt)
            require(not destination.exists(), "installed evidence destination already exists; do not retry over it")
            result["acceptance"] = str(destination)
            with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8", newline="\n") as output:
                output.write("path=" + result["path"] + "\nsha256=" + result["sha256"]
                             + "\nacceptance=" + result["acceptance"] + "\n")
        print(json.dumps(result))
        return
    result = metadata(args) if args.mode == "metadata" else acceptance(args)
    print(json.dumps(result, indent=2))
    if result["status"] == "HOLD":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
