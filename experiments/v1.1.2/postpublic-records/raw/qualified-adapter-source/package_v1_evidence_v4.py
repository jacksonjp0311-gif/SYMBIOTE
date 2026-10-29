"""Explicit multi-source v1 evidence adapter with pinned Cargo transcript classification. Preparing/importing this file packages nothing.

The v4 scanner, traversal, size limits, tar/gzip writer, exclusive publication
and extracted-byte comparison are loaded by their exact qualified code digest.
Only heterogeneous evidence selection/anchor checking is new here. This tool
does not execute a study, discover inputs, grade learning, or promote a HOLD.

Run --plan-only first after all inputs exist, are independently audited and
stopped. Actual archive creation requires a separately reviewed completed plan.
Keep every failed attempt and use a new output directory after a correction.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import types

BASE_NAME = "package_stability_evidence_v4.py"
BASE_SHA256 = "9a2df3fc679ce154469013e02575551d9572e7cee4d2a0eca585e7fc3a780962"
HERE = Path(__file__).resolve().parent
SCHEMA = "symbiote.v1-evidence-config/2"
MAX_PATH = 240
FINAL_SOURCE_LIMITS = dict(references=40033, bytes=2 * 1024 * 1024 * 1024)
LAST_PLAN = {}


def load_base():
    path = HERE / BASE_NAME
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != BASE_SHA256:
        raise ValueError("qualified scanner/writer source pin differs")
    module = types.ModuleType("qualified_v4_evidence_primitives")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


base = load_base()
ORIGINAL_FINGERPRINT = base.fingerprint
CLASSIFICATIONS = {}
PURE_CARGO_FORMAT = "cargo-json-stream/1"
CARGO_REASONS = frozenset({"compiler-artifact", "compiler-message", "build-script-executed", "build-finished"})
HUMAN_CARGO = re.compile(
    rb"(?:running [0-9]+ tests?|test [A-Za-z0-9_:]+ \.\.\. (?:ok|FAILED|ignored(?:, [A-Za-z0-9 .:;()/_-]{1,200})?)|"
    rb"test result: (?:ok|FAILED)\. [0-9]+ passed; [0-9]+ failed; [0-9]+ ignored; [0-9]+ measured; [0-9]+ filtered out; finished in [0-9.]+s)\Z"
)


def scan_json(value, label, depth=0, document_schema=None, location=(), cognition_connect=False, cognition_capability=False):
    base.need(depth <= base.LIMITS["json_depth"], "JSON credential scan nesting limit")
    if document_schema is None:
        document_schema = value.get("schema", "") if isinstance(value, dict) else ""
        cognition_connect = isinstance(value, dict) and value.get("phase") == "CONNECT"
        cognition_capability = isinstance(value, dict) and value.get("phase") == "CAPABILITY_OPPORTUNITY"
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower().replace("-", "_") in base.SECRET_KEYS and isinstance(child, str):
                stripped = child.strip()
                placeholder = stripped.lower().startswith(("redacted", "removed", "example", "not-used", "not_used", "none"))
                public_consent = (key == "authorization" and child == "explicit-local-registry"
                                  and document_schema == "symbiote.demo/1"
                                  and len(location) == 2 and location[0] == "phases" and type(location[1]) is int
                                  and value.get("phase") == "CONNECT" and value.get("protocol") == "symbiote/1"
                                  and value.get("scope") == "finite-boolean-v1")
                cognition_consent = (key == "authorization"
                                     and child == "explicit operator registry and current durable denials"
                                     and document_schema == "symbiote.cognition-event/1"
                                     and cognition_connect and location == ("details",))
                capability_consent = (key == "authorization"
                                      and child == "explicit normal quality-goal policy plus current bilateral operation grants"
                                      and document_schema == "symbiote.cognition-event/1"
                                      and cognition_capability and location == ("details",))
                base.need(len(stripped) < 16 or placeholder or public_consent or cognition_consent or capability_consent, "structured credential field in " + label)
            scan_json(child, label, depth + 1, document_schema, location + (key,), cognition_connect, cognition_capability)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            scan_json(child, label, depth + 1, document_schema, location + (index,), cognition_connect, cognition_capability)
    elif isinstance(value, str):
        base.scan_bytes(value.encode("utf-8"), label + " (decoded JSON string)")
        # A JSON string can itself contain a serialized JSON object/string.
        if value.lstrip().startswith(("{", "[", '"')):
            try:
                nested = base.parse(value)
            except (ValueError, json.JSONDecodeError):
                return
            scan_json(nested, label, depth + 1, None, ())



# Keep the qualified raw scanner; extend only exact public consent semantics.
base.scan_json = scan_json

def cargo_stream_fingerprint(path, item):
    path = base.plain(path, False)
    before = base.signature(path)
    base.need(path.suffix.lower() == ".stdout", "pure Cargo admission requires actual STDOUT suffix")
    base.need(before[2] <= base.LIMITS["file_bytes"], "Cargo stream exceeds individual byte bound")
    expected = base.pin(item["sha256"])
    # Preserve the qualified continuous raw-block scanner and PEM overlap, not
    # merely per-line scans. Decoded JSON scanning occurs in a second pass.
    hashed = hashlib.sha256(); count = 0; tail = b""
    with path.open("rb") as source:
        while True:
            block = source.read(base.BLOCK)
            if not block:
                break
            count += len(block)
            base.need(count <= before[2], "Cargo stream grew during raw scan")
            hashed.update(block)
            base.scan_bytes(tail + block, str(path))
            tail = (tail + block)[-base.PEM_OVERLAP:]
    base.need(count == before[2] and hashed.hexdigest() == expected and base.signature(path) == before,
              "Cargo stream raw bytes/pin changed")
    decoded_hash = hashlib.sha256(); decoded_count = messages = finished = 0; last = None
    with path.open("rb") as source:
        while True:
            line = source.readline(base.LIMITS["json_line_bytes"] + 1)
            if not line:
                break
            decoded_count += len(line); decoded_hash.update(line)
            base.need(decoded_count <= before[2] and len(line) <= base.LIMITS["json_line_bytes"],
                      "Cargo stream line or byte scan bound exceeded")
            if not line.strip():
                continue
            line.decode("utf-8", errors="strict")
            document = base.parse(line)
            base.need(isinstance(document, dict) and document.get("reason") in CARGO_REASONS,
                      "not a pure admitted Cargo JSON message")
            base.need(finished == 0, "Cargo messages appear after build-finished")
            if document["reason"] == "build-finished":
                base.need(type(document.get("success")) is bool, "Cargo finish lacks boolean result")
                finished += 1
            base.scan_json(document, str(path))
            messages += 1; last = document["reason"]
    base.need(messages > 0 and finished == 1 and last == "build-finished", "Cargo final message missing/duplicated")
    base.need(decoded_count == before[2] and decoded_hash.hexdigest() == expected
              and base.signature(path) == before, "Cargo stream changed during decoded scan")
    return dict(bytes=before[2], sha256=expected, signature=before)


def classified_fingerprint(path):
    path = base.plain(path, False)
    classification = CLASSIFICATIONS.get(str(path))
    if classification is None:
        return ORIGINAL_FINGERPRINT(path)
    if classification["format"] == PURE_CARGO_FORMAT:
        return cargo_stream_fingerprint(path, classification)
    before = base.signature(path)
    base.need(path.suffix.lower() == ".jsonl" and before[2] <= base.LIMITS["file_bytes"],
              "Cargo transcript must be an explicitly pinned bounded JSONL-named file")
    hashed = hashlib.sha256(); count = json_lines = human_lines = 0
    # Every original byte is scanned; JSON lines additionally receive decoded
    # credential checks. Human output has a closed grammar, never arbitrary text.
    with path.open("rb") as stream:
        while True:
            line = stream.readline(base.LIMITS["json_line_bytes"] + 1)
            if not line:
                break
            count += len(line)
            base.need(count <= before[2] and len(line) <= base.LIMITS["json_line_bytes"],
                      "Cargo transcript grew or exceeded line scan budget")
            hashed.update(line); base.scan_bytes(line, str(path))
            stripped = line.strip()
            if not stripped:
                continue
            stripped.decode("utf-8", errors="strict")
            if stripped.startswith((b"{", b"[", b'"')):
                document = base.parse(stripped)
                base.need(isinstance(document, dict) and document.get("reason") in
                          {"compiler-artifact", "compiler-message", "build-script-executed", "build-finished"},
                          "classified transcript line is not an admitted Cargo JSON message")
                base.scan_json(document, str(path)); json_lines += 1
            else:
                base.need(HUMAN_CARGO.fullmatch(stripped) is not None,
                          "unexpected human line in classified Cargo transcript")
                human_lines += 1
    actual = hashed.hexdigest()
    base.need(count == before[2] and base.signature(path) == before,
              "Cargo transcript changed during scan")
    base.need(actual == classification["sha256"], "classified transcript differs from explicit byte pin")
    base.need(json_lines > 0 and human_lines > 0, "classification requires actual mixed Cargo/test output")
    return dict(bytes=before[2], sha256=actual, signature=before)


def configure_classifications(items):
    global CLASSIFICATIONS
    CLASSIFICATIONS = {}
    for item in bounded_list(items, 0, 64, "bounded explicit format classifications required"):
        base.fields(item, ("path", "sha256", "format"))
        base.need(item["format"] in {"cargo-json-and-rust-test-output/1", PURE_CARGO_FORMAT},
                  "unsupported explicit scan format")
        path = base.plain(item["path"], False)
        if item["format"] == PURE_CARGO_FORMAT:
            base.need(path.suffix.lower() == ".stdout", "pure Cargo requires STDOUT path")
        base.need(str(path) not in CLASSIFICATIONS, "duplicate format classification")
        base.pin(item["sha256"])
        CLASSIFICATIONS[str(path)] = item
    base.fingerprint = classified_fingerprint



def json_pointer(value, pointer):
    base.need(isinstance(pointer, str) and pointer.startswith("/") and len(pointer) <= 1024,
              "explicit bounded JSON pointer required")
    for token in pointer[1:].split("/"):
        base.need(re.search(r"~(?![01])", token) is None, "noncanonical JSON pointer escape")
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict):
            base.need(token in value, "JSON anchor pointer is absent")
            value = value[token]
        else:
            base.need(isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", token)
                      and int(token) < len(value), "JSON anchor array pointer is absent")
            value = value[int(token)]
    return value


def relative_path(value):
    base.need(isinstance(value, str) and value and "\\" not in value and ":" not in value,
              "explicit portable relative member path required")
    path = PurePosixPath(value)
    base.need(not path.is_absolute() and path.as_posix() == value
              and all(part not in (".", "..") for part in path.parts), "unsafe relative member path")
    return path


def bounded_list(value, minimum, maximum, message):
    base.need(isinstance(value, list) and minimum <= len(value) <= maximum, message)
    return value


def tree_census(root):
    """Full relative path/type snapshot; errors and special/link entries HOLD."""
    root = base.plain(root, True)
    pending = [root]
    rows = [{"path": ".", "type": "directory"}]
    files = directories = 0
    portable = {"."}
    while pending:
        directory = base.plain(pending.pop(), True)
        # scandir errors intentionally propagate; no skipped unreadable subtrees.
        with os.scandir(directory) as listing:
            for entry in listing:
                path = directory / entry.name
                info = path.lstat()
                base.need(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & base.REPARSE,
                          "linked/reparse census entry refused")
                relative = path.relative_to(root).as_posix()
                base.need(relative.casefold() not in portable, "case-alias census paths refused")
                portable.add(relative.casefold())
                if stat.S_ISDIR(info.st_mode):
                    kind = "directory"; directories += 1; pending.append(path)
                else:
                    base.need(stat.S_ISREG(info.st_mode), "special census entry refused")
                    kind = "file"; files += 1
                base.need(files <= base.LIMITS["files"] and directories <= base.LIMITS["directories"],
                          "census path-count bound exceeded")
                rows.append(dict(path=relative, type=kind))
    return sorted(rows, key=lambda row: row["path"].encode("utf-8"))


def check_tree_membership(collector, phase):
    for expected in collector.tree_censuses:
        actual = tree_census(expected["root"])
        base.need(actual == expected["paths"], "tree path/type membership changed " + phase + ": " + expected["root"])


def census_digest(rows):
    return hashlib.sha256(base.encode(rows)).hexdigest()


def source_recheck_budget(collector, config_info):
    references = 1 + sum(len(entry["sources"]) for entry in collector.entries.values())
    byte_count = config_info["bytes"] + sum(entry["bytes"] * len(entry["sources"])
                                           for entry in collector.entries.values())
    base.need(references <= FINAL_SOURCE_LIMITS["references"] and byte_count <= FINAL_SOURCE_LIMITS["bytes"],
              "final source revalidation budget exceeded; aliases cannot be silently omitted")
    return dict(references=references, bytes=byte_count)


def recheck_selected_bytes(collector, config_path, config_info):
    """Rehash every occurrence, including aliased sources, after staged return."""
    budget = source_recheck_budget(collector, config_info)
    checked = dict(references=0, bytes=0)
    for _, entry in sorted(collector.entries.items()):
        for path in entry["sources"]:
            recheck_exact_bytes(path, entry, "selected source changed after staged byte verification")
            checked["references"] += 1
            checked["bytes"] += entry["bytes"]
    recheck_exact_bytes(config_path, config_info, "configuration changed after staged byte verification")
    checked["references"] += 1
    checked["bytes"] += config_info["bytes"]
    base.need(checked == budget, "final source revalidation accounting differs")
    return checked


def recheck_exact_bytes(path, expected, failure):
    """Read at most the planned size plus one sentinel byte; no new trust claim."""
    path = base.plain(path, False)
    before = base.signature(path)
    base.need(before[2] == expected["bytes"], failure + ": " + str(path))
    hashed = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(min(base.BLOCK, expected["bytes"] - count + 1))
            if not block:
                break
            count += len(block)
            base.need(count <= expected["bytes"], failure + ": " + str(path))
            hashed.update(block)
    base.need(count == expected["bytes"] and hashed.hexdigest() == expected["sha256"]
              and base.signature(path) == before, failure + ": " + str(path))


def make_v1_plan(config_path):
    global LAST_PLAN
    base.fingerprint = ORIGINAL_FINGERPRINT
    config_path = base.plain(config_path, False)
    config_info = base.fingerprint(config_path)
    config_pin = config_info["sha256"]
    config = base.json_file(config_path, config_pin)
    base.fields(config, ("schema", "inputs_closed", "source_commit", "archive", "extract_to",
                        "collections", "anchors", "receipt_roots", "receipts", "executables", "history", "format_classifications"))
    base.need(config["schema"] == SCHEMA and config["inputs_closed"] is True,
              "use real completed, stopped inputs; template/preparation mode cannot publish")
    source = config["source_commit"]
    base.need(isinstance(source, str) and re.fullmatch(r"[0-9a-f]{40}", source), "actual frozen source commit required")
    configure_classifications(config["format_classifications"])
    temporary = base.plain(Path(tempfile.gettempdir()).resolve(strict=True), True)
    anchors = {}
    for item in bounded_list(config["anchors"], 1, 128, "bounded explicit JSON anchors required"):
        base.fields(item, ("id", "path", "sha256", "expect", "source_commit_pointer", "source_commit"))
        identity = item["id"]
        base.need(isinstance(identity, str) and re.fullmatch(r"[a-z0-9-]{1,64}", identity)
                  and identity not in anchors, "unique bounded anchor ID required")
        path = base.plain(item["path"], False)
        document = base.json_file(path, item["sha256"])
        expectations = bounded_list(item["expect"], 1, 64, "every anchor needs explicit JSON field assertions")
        for expected in expectations:
            base.fields(expected, ("pointer", "value"))
            base.need(base.encode(json_pointer(document, expected["pointer"])) == base.encode(expected["value"]),
                      "actual JSON differs from its explicit frozen field assertion: " + identity)
        pointer = item["source_commit_pointer"]
        if pointer is not None:
            declared_source = item["source_commit"]
            base.need(isinstance(declared_source, str) and re.fullmatch(r"[0-9a-f]{40}", declared_source),
                      "anchor requires its actual source commit")
            base.need(json_pointer(document, pointer) == declared_source, "anchor belongs to a different declared source commit")
        else:
            base.need(item["source_commit"] is None, "an unbound anchor cannot assert a checked source commit")
        anchors[identity] = dict(item, _document=document, _path=path)
    collector = base.Collector()
    collector.tree_censuses = []
    collector.config_snapshot = config_info
    collections = []; roots = []; names = set()
    for item in bounded_list(config["collections"], 1, 16, "one to sixteen explicit evidence collections required"):
        base.fields(item, ("name", "path", "selection", "files", "binding"))
        name = item["name"]
        base.need(isinstance(name, str) and re.fullmatch(r"[a-z0-9-]{1,32}", name)
                  and name not in names, "unique bounded collection name required")
        names.add(name)
        root = base.plain(item["path"], True)
        base.need(base.inside(root, temporary) and root != HERE and not base.inside(root, HERE)
                  and not (root / ".git").exists(), "dedicated OS-temp evidence root required; never whole Temp/audit/checkout")
        base.need(all(root != other and not base.inside(root, other) and not base.inside(other, root) for other in roots),
                  "overlapping evidence roots refused")
        roots.append(root)
        binding = item["binding"]
        base.fields(binding, ("anchor", "root_pointer"))
        base.need(binding["anchor"] in anchors, "collection has no pinned provenance anchor")
        anchor = anchors[binding["anchor"]]
        if binding["root_pointer"] is None:
            base.need(base.inside(anchor["_path"], root), "collection anchor must be inside its real root")
        else:
            base.need(base.plain(json_pointer(anchor["_document"], binding["root_pointer"]), True) == root,
                      "collection root differs from the pinned registration's declared path")
        prefix = "evidence/" + name + "/" + root.name
        if item["selection"] == "tree":
            base.need(item["files"] == [], "tree selection cannot silently exclude files")
            census = tree_census(root)
            collector.tree(root, prefix)
            base.need(tree_census(root) == census, "tree membership changed during collection")
            expected_files = {prefix + "/" + row["path"] for row in census if row["type"] == "file"}
            collected_files = {name for name in collector.entries if name.startswith(prefix + "/")}
            base.need(collected_files == expected_files, "collection did not preserve the full declared file set")
            collector.tree_censuses.append(dict(root=str(root), paths=census, sha256=census_digest(census)))
        else:
            base.need(item["selection"] == "files", "unsupported evidence selection mode")
            for chosen in bounded_list(item["files"], 1, base.LIMITS["files"], "explicit pinned file selection required"):
                base.fields(chosen, ("path", "sha256"))
                relative = relative_path(chosen["path"])
                collector.add(root.joinpath(*relative.parts), prefix + "/" + chosen["path"], chosen["sha256"])
        collections.append(dict(item, archive_prefix=prefix,
                                coverage="entire declared tree" if item["selection"] == "tree" else "only explicitly selected files; no full-directory completeness claim",
                                direct_source_commit_checked=anchor["source_commit_pointer"] is not None))
    receipt_roots = [base.plain(path, True) for path in bounded_list(config["receipt_roots"], 0, 16, "receipt boundary bound")]
    base.need(len(set(receipt_roots)) == len(receipt_roots), "duplicate receipt boundaries")
    base.need(all(root == HERE or base.inside(root, temporary) for root in receipt_roots), "receipt roots must be explicit Temp children/audit; never whole Temp")
    for item in bounded_list(config["receipts"], 0, base.LIMITS["files"], "individual receipt bound"):
        base.fields(item, ("path", "sha256", "archive_path"))
        path = base.plain(item["path"], False)
        base.need(sum(base.inside(path, root) for root in receipt_roots) == 1, "receipt outside or ambiguous in its explicit boundaries")
        relative_path(item["archive_path"])
        collector.add(path, item["archive_path"], item["sha256"])
    bindings = []
    for item in bounded_list(config["executables"], 1, 32, "exact registered executable files required"):
        base.fields(item, ("role", "path", "sha256", "anchor", "digest_pointer"))
        base.need(item["anchor"] in anchors, "executable lacks a pinned registration/build anchor")
        anchor = anchors[item["anchor"]]
        base.need(anchor["source_commit_pointer"] is not None, "executable anchor must bind this exact frozen source commit")
        image_pin = base.pin(item["sha256"])
        base.need(json_pointer(anchor["_document"], item["digest_pointer"]) == image_pin,
                  "executable digest differs from actual pinned registration/build receipt")
        path = base.plain(item["path"], False)
        member = collector.add(path, "executables/sha256/" + image_pin + "/" + path.name, image_pin)
        bindings.append(dict(item, archive_path=member))
    history = bounded_list(config["history"], 0, 128, "bounded explicit historical outcomes required")
    for item in history:
        base.fields(item, ("label", "anchor", "status_pointer", "expected_status"))
        base.need(item["anchor"] in anchors and
                  base.encode(json_pointer(anchors[item["anchor"]]["_document"], item["status_pointer"])) == base.encode(item["expected_status"]),
                  "historical outcome differs; never relabel a HOLD or infer a missing result")
    selected_sources = {str(base.plain(path, False)) for entry in collector.entries.values() for path in entry["sources"]}
    base.need(set(CLASSIFICATIONS).issubset(selected_sources), "classification names an unselected input")
    for identity, item in anchors.items():
        base.need(str(item["_path"]) in selected_sources, "pinned anchor was not selected into archive: " + identity)
        base.need(base.fingerprint(item["_path"])["sha256"] == item["sha256"], "anchor changed during planning")
    archive = base.owned_new(config["archive"]); extracted = base.owned_new(config["extract_to"])
    base.need(str(archive).endswith(".tar.gz") and archive != extracted and not base.inside(archive, extracted)
              and not base.inside(extracted, archive), "new disjoint archive/extraction paths required")
    protected = roots + [root for root in receipt_roots if root != HERE]
    base.need(all(archive != root and not base.inside(archive, root) and extracted != root and not base.inside(extracted, root)
                  and not base.inside(root, extracted) for root in protected), "outputs overlap input trees/boundaries")
    base.need(all(Path(path) != archive and not base.inside(Path(path), extracted) for path in selected_sources), "outputs overlap selected input files")
    base.need(not (archive.parent / "EVIDENCE_SHA256SUMS").exists(), "use a new evidence output directory; checksums already exist")
    base.need(not (archive.parent / "v1-packaging-receipt.json").exists(), "new packaging receipt path required")
    names = ["MANIFEST.json", *collector.entries]
    maximum = max(len(str(extracted.joinpath(*PurePosixPath(name).parts))) for name in names)
    base.need(maximum <= MAX_PATH, "planned extraction exceeds240characters; choose a shorter new output root")
    outputs = [str(archive) + suffix for suffix in ("", ".partial", ".reservation.json", ".MANIFEST.json", ".verification.json", ".failure.json")]
    outputs.extend(str(archive.parent / name) for name in ("EVIDENCE_SHA256SUMS", "v1-packaging-receipt.json"))
    outputs.extend(str(archive.parent / "attempt" / archive.name) + suffix for suffix in ("", ".partial", ".reservation.json", ".MANIFEST.json", ".verification.json", ".failure.json"))
    base.need(max(map(len, outputs)) <= MAX_PATH, "planned publication sidecar exceeds240characters")
    entries = []
    for _, entry in sorted(collector.entries.items()):
        row = {key: value for key, value in entry.items() if not key.startswith("_")}
        row["sources"] = sorted(set(row["sources"]))
        entries.append(row)
    recheck_budget = source_recheck_budget(collector, config_info)
    manifest = base.encode(dict(schema="symbiote.v1-evidence-manifest/2", source_commit=source,
        format_classifications=config["format_classifications"],
        packager_base=dict(file=BASE_NAME, sha256=BASE_SHA256),
        packager_adapter=dict(file=Path(__file__).name, sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()),
        limits=base.LIMITS,
        collections=collections, anchors=config["anchors"], registered_executables=bindings,
        tree_membership=collector.tree_censuses,
        final_source_revalidation=dict(limits=FINAL_SOURCE_LIMITS, planned=recheck_budget,
                                       includes="every selected source occurrence plus config, including all aliases, anchors and executable bytes"),
        directory_representation="regular file bytes are tar members; complete directory path/types are recorded in this manifest census",
        historical_outcomes=history, entries=entries,
        interpretation="byte preservation and explicit anchor assertions only; existing independent verifiers determine qualifications; no new result inferred",
        self_reference="MANIFEST.json excluded from its own entry list; verification receipt pins it"))
    base.need(len(manifest) <= base.LIMITS["manifest_bytes"], "manifest byte bound")
    base.scan_bytes(manifest, "generated v1 manifest"); base.scan_json(base.parse(manifest), "generated v1 manifest")
    base.need(base.fingerprint(config_path)["sha256"] == config_pin, "config changed during planning")
    LAST_PLAN = dict(source_commit=source, config_sha256=config_pin, members_including_manifest=len(entries)+1,
                     source_bytes=collector.total, max_extracted_path_characters=maximum,
                     manifest_sha256=hashlib.sha256(manifest).hexdigest(),
                     tree_census_sha256=census_digest(collector.tree_censuses),
                     final_source_revalidation=recheck_budget,
                     collections_without_direct_commit_field=[row["name"] for row in collections if not row["direct_source_commit_checked"]])
    return config_path, config_pin, collector, manifest, archive, extracted



def recheck_archive_bytes(path, byte_verification, identity=None):
    """Recheck the writer's exact compressed bytes, not only its source inputs."""
    path = base.plain(path, False)
    before = base.signature(path)
    if identity is not None:
        base.need(before[:2] == identity, "staged/final archive identity changed")
    expected = dict(bytes=byte_verification["archive_bytes"], sha256=byte_verification["archive_sha256"])
    base.need(type(expected["bytes"]) is int and expected["bytes"] > 0,
              "writer returned no bounded archive byte count")
    base.pin(expected["sha256"])
    recheck_exact_bytes(path, expected, "archive changed after staged byte verification")
    base.need(base.signature(path) == before, "archive identity/metadata changed during final check")
    return before


def package_v1(config_path, expected_manifest_sha256):
    """Stage old writer output; publish only after full post-package census."""
    config_path = Path(config_path)
    archive = None
    attempt = None
    try:
        plan = make_v1_plan(config_path)
        config_path, config_pin, collector, manifest, archive, extracted = plan
        base.need(hashlib.sha256(manifest).hexdigest() == base.pin(expected_manifest_sha256),
                  "reviewed manifest differs; do not automatically accept a changed plan")
        check_tree_membership(collector, "immediately before package")
        base.need(base.fingerprint(config_path)["sha256"] == config_pin, "config changed before package")
        attempt = archive.parent / "attempt"
        attempt.mkdir()  # A rejected attempt can never be reused or overwritten.
        staged_archive = attempt / archive.name
        staged_plan = (config_path, config_pin, collector, manifest, staged_archive, extracted)
        previous = base.make_plan
        def pinned_plan(candidate):
            base.need(base.plain(candidate, False) == config_path, "staged config path changed")
            return staged_plan
        base.make_plan = pinned_plan
        try:
            byte_verification = base.package(config_path)
        finally:
            base.make_plan = previous
        check_tree_membership(collector, "after staged byte verification")
        final_sources = recheck_selected_bytes(collector, config_path, collector.config_snapshot)
        # Recheck compressed output too: a successful earlier writer receipt
        # cannot qualify a staged archive modified after that writer returned.
        staged_signature = recheck_archive_bytes(staged_archive, byte_verification)
        check_tree_membership(collector, "immediately before final archive exposure")
        # No qualified final pathname or checksum exists before census/hash gates.
        os.link(staged_archive, archive)
        try:
            final_signature = recheck_archive_bytes(archive, byte_verification, staged_signature[:2])
            recheck_archive_bytes(staged_archive, byte_verification, staged_signature[:2])
            base.need(final_signature == staged_signature, "final hard link differs from checked staged archive")
        except BaseException:
            # Remove only our own newly created hard link, retaining staged bytes
            # and their earlier receipt for the failure audit. Never delete a
            # replacement owned by an unrelated writer.
            if archive.exists() and base.signature(archive)[:2] == staged_signature[:2]:
                archive.unlink()
            raise
        base.write_new(Path(str(archive) + ".MANIFEST.json"), manifest)
        result = dict(schema="symbiote.v1-evidence-packaging/4", status="PASS",
                      archive=str(archive), archive_sha256=byte_verification["archive_sha256"],
                      archive_bytes=byte_verification["archive_bytes"], byte_verification=byte_verification,
                      evidence_plan=LAST_PLAN, full_tree_membership_rechecked=True,
                      final_source_bytes_rechecked=final_sources,
                      final_archive_bytes_rechecked=True, final_hardlink_identity_rechecked=True,
                      online_publication=False)
        base.write_new(Path(str(archive) + ".verification.json"), base.encode(result))
        checksums = archive.parent / "EVIDENCE_SHA256SUMS"
        base.write_new(checksums, (result["archive_sha256"] + "  " + archive.name + "\n").encode("ascii"))
        result["checksums"] = str(checksums)
        result["checksums_sha256"] = hashlib.sha256(checksums.read_bytes()).hexdigest()
        base.write_new(archive.parent / "v1-packaging-receipt.json", base.encode(result))
        return result
    except BaseException as error:
        # A malformed/unvalidated config never grants permission to write a log.
        # The caller preserves stderr when planning fails before output validation.
        if archive is not None:
            rejected = archive.parent / "v1-packaging-receipt.json"
            if not rejected.exists():
                base.write_new(rejected, base.encode(dict(schema="symbiote.v1-evidence-packaging/4", status="HOLD",
                    failure=type(error).__name__ + ": " + str(error), rejected_attempt=str(attempt) if attempt else None,
                    qualified_final_archive_exposed=archive.exists(), online_publication=False)))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--expected-manifest-sha256", help="externally retained digest from the exact independently reviewed plan")
    args = parser.parse_args()
    if args.plan_only:
        make_v1_plan(args.config)
        result = dict(schema="symbiote.v1-evidence-plan/2", status="PASS_PLAN_ONLY_NO_ARCHIVE", **LAST_PLAN)
    else:
        base.need(args.expected_manifest_sha256 is not None, "reviewed manifest digest required before package")
        result = package_v1(args.config, args.expected_manifest_sha256)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, RecursionError, base.tarfile.TarError) as error:
        print(json.dumps(dict(status="HOLD", failure=type(error).__name__ + ": " + str(error))), file=sys.stderr)
        sys.exit(1)
