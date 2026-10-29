"""Explicit, deterministic stability-evidence packaging. No default inputs.

Preparing this script does not execute packaging. Run only after all selected
runs and independent audits have stopped. Usage: python SCRIPT --config FILE

Strict configuration (every SHA is an independently retained lowercase SHA256):
{
  "schema": "symbiote.stability-evidence-config/1",
  "archive": "ABSOLUTE_NEW_ARCHIVE.tar.gz",
  "extract_to": "ABSOLUTE_NEW_VALIDATION_DIRECTORY",
  "runs": [{"name":"s3-hold", "path":"ABSOLUTE_CAMPAIGN_ROOT",
            "registration_sha256":"...", "report_sha256":"...",
            "expected_status":"HOLD"}],
  "receipt_roots": ["ABSOLUTE_GATE_DIRECTORY", "ABSOLUTE_AUDIT_DIRECTORY"],
  "receipts": [{"path":"ABSOLUTE_SELECTED_FILE", "sha256":"..."}],
  "saved_binary_roots": ["ABSOLUTE_SAVED_REGISTERED_BINARIES_DIRECTORY"],
  "executables": [{"path":"ABSOLUTE_REGISTERED_OR_SAVED_EXE", "sha256":"..."}]
}

One to four explicit runs are permitted. HOLD is preserved verbatim; a native
phase PASS is never substituted for the campaign's overall report status.
Receipt and saved-binary roots are permission boundaries, never recursive input
requests. Only individually selected, pinned files are collected from them.
Every registered executable digest across the selected runs must be supplied.
No source tree, whole Temp/audit tree or external PKI directory is discovered.

Outputs are new files only. On failure retain .partial, reservation, extracted
files and a failure receipt where possible. No retry, overwrite, deletion or
input mutation is performed. A completed .verification.json is required before
publication. Determinism means the same config/input bytes and Python/zlib
implementation produce identical tar/gzip bytes; it is not a cross-zlib claim.
"""
import argparse
import base64
import binascii
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import tempfile

SCHEMA = "symbiote.stability-evidence-config/1"
LIMITS = dict(files=20000, file_bytes=256 * 1024 * 1024,
              total_bytes=1024 * 1024 * 1024, json_bytes=32 * 1024 * 1024,
              json_line_bytes=2 * 1024 * 1024, json_depth=128,
              manifest_bytes=16 * 1024 * 1024, directories=20000)
BLOCK = 1024 * 1024
PEM_OVERLAP = 128 * 1024
REPARSE = 0x400
FORBIDDEN_SUFFIXES = {".key", ".pfx", ".p12"}
TEXT_JSON = {".json", ".jsonl"}
PEM = re.compile(rb"-----BEGIN ([A-Z0-9 ]{1,64})-----([\s\S]{0,131072}?)-----END \1-----")
CREDENTIALS = [
    re.compile(rb"\bsk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{24,}\b"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{24,}\b"),
    re.compile(rb"(?i)\bAuthorization\s*[:=]\s*[\"']?Bearer\s+[A-Za-z0-9._~-]{20,}"),
]
SECRET_KEYS = {"api_key", "apikey", "access_token", "refresh_token", "client_secret",
               "aws_secret_access_key", "secret_access_key", "authorization", "password"}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, "non-finite JSON number"))


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode("utf-8") + b"\n"


def pin(value):
    need(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "invalid SHA256 pin")
    return value


def fields(value, expected):
    need(isinstance(value, dict) and set(value) == set(expected), "unsupported/missing config fields")


def plain(path, directory=None):
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts, "input path must be explicit and absolute")
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor = cursor / part
        info = cursor.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & REPARSE,
             "linked/reparse input refused: " + str(cursor))
    path = path.resolve(strict=True)
    if directory is not None:
        need(path.is_dir() if directory else path.is_file(), "wrong input type: " + str(path))
    return path


def inside(path, root):
    return path != root and root in path.parents


def signature(path):
    info = path.stat()
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def read_bounded(path, limit):
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    need(len(raw) <= limit, "bounded control input grew/exceeded limit")
    return raw


def der_item(raw, offset=0):
    need(offset + 2 <= len(raw), "truncated DER")
    tag, length = raw[offset], raw[offset + 1]
    cursor = offset + 2
    if length & 128:
        count = length & 127
        need(1 <= count <= 4 and cursor + count <= len(raw), "invalid DER length")
        need(raw[cursor] != 0, "nonminimal DER length")
        length = int.from_bytes(raw[cursor:cursor + count], "big")
        need(length >= 128, "nonminimal DER long length")
        cursor += count
    need(cursor + length <= len(raw), "DER value exceeds block")
    return tag, raw[cursor:cursor + length], cursor + length


def der_children(raw):
    children = []
    cursor = 0
    while cursor < len(raw):
        tag, body, cursor = der_item(raw, cursor)
        children.append((tag, body))
    return children


def public_certificate(raw):
    """Validate DER/X.509 shape, not a trust chain or live service authority."""
    tag, body, end = der_item(raw)
    need(tag == 0x30 and end == len(raw), "public certificate must be one complete DER sequence")
    certificate = der_children(body)
    need([item[0] for item in certificate] == [0x30, 0x30, 0x03], "invalid X.509 certificate shape")
    tbs = der_children(certificate[0][1])
    if tbs and tbs[0][0] == 0xa0:
        version = der_children(tbs.pop(0)[1])
        need(len(version) == 1 and version[0][0] == 2, "invalid certificate version")
    need(len(tbs) >= 6 and [item[0] for item in tbs[:6]] == [2, 0x30, 0x30, 0x30, 0x30, 0x30],
         "certificate has no public subject/key structure")
    spki = der_children(tbs[5][1])
    need(len(spki) == 2 and [item[0] for item in spki] == [0x30, 3] and len(spki[1][1]) > 1,
         "certificate has no public subject key")
    need(len(certificate[2][1]) > 1, "certificate signature absent")


def scan_bytes(raw, label):
    for pattern in CREDENTIALS:
        need(pattern.search(raw) is None, "provider credential pattern in " + label)
    for match in PEM.finditer(raw):
        kind, body = match.group(1), match.group(2)
        # Parser marker literals in an EXE are not complete base64 key blocks.
        lines = [line.strip() for line in body.splitlines() if line.strip()]
        armored = b"".join(line for line in lines if b":" not in line)
        try:
            decoded = base64.b64decode(armored, validate=True)
        except (ValueError, binascii.Error):
            continue
        if not decoded:
            continue
        need(b"PRIVATE KEY" not in kind and b"OPENSSH" not in kind,
             "complete private-key PEM block in " + label)
        if kind == b"CERTIFICATE":
            public_certificate(decoded)
        else:
            need(kind in (b"PUBLIC KEY", b"RSA PUBLIC KEY"), "unsupported credential PEM block in " + label)
            tag, _, end = der_item(decoded)
            need(tag == 0x30 and end == len(decoded), "invalid public-key DER in " + label)


def scan_json(value, label, depth=0, document_schema=None, location=()):
    need(depth <= LIMITS["json_depth"], "JSON credential scan nesting limit")
    if document_schema is None:
        document_schema = value.get("schema", "") if isinstance(value, dict) else ""
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower().replace("-", "_") in SECRET_KEYS and isinstance(child, str):
                stripped = child.strip()
                placeholder = stripped.lower().startswith(("redacted", "removed", "example", "not-used", "not_used", "none"))
                public_consent = (key == "authorization" and child == "explicit-local-registry"
                                  and document_schema == "symbiote.demo/1"
                                  and len(location) == 2 and location[0] == "phases" and type(location[1]) is int
                                  and value.get("phase") == "CONNECT" and value.get("protocol") == "symbiote/1"
                                  and value.get("scope") == "finite-boolean-v1")
                need(len(stripped) < 16 or placeholder or public_consent, "structured credential field in " + label)
            scan_json(child, label, depth + 1, document_schema, location + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            scan_json(child, label, depth + 1, document_schema, location + (index,))
    elif isinstance(value, str):
        scan_bytes(value.encode("utf-8"), label + " (decoded JSON string)")
        # A JSON string can itself contain a serialized JSON object/string.
        if value.lstrip().startswith(("{", "[", '"')):
            try:
                nested = parse(value)
            except (ValueError, json.JSONDecodeError):
                return
            scan_json(nested, label, depth + 1, None, ())


def fingerprint(path):
    path = plain(path, False)
    need(path.suffix.lower() not in FORBIDDEN_SUFFIXES, "private credential extension: " + str(path))
    before = signature(path)
    need(before[2] <= LIMITS["file_bytes"], "individual evidence file exceeds bound")
    hashed = hashlib.sha256()
    tail = b""; prefix = b""; count = 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(BLOCK)
            if not block:
                break
            count += len(block)
            need(count <= before[2], "input grew during bounded scan")
            if not prefix:
                prefix = block.lstrip()[:256]
            hashed.update(block)
            scan_bytes(tail + block, str(path))
            tail = (tail + block)[-PEM_OVERLAP:]
    json_output = (path.suffix.lower() in {".stdout", ".stderr", ".log", ".txt"}
                   and prefix.startswith((b"{", b"[", b'"')))
    empty_captured_json = (before[2] == 0 and path.name.endswith((".stdout.json", ".stderr.json")))
    if (path.suffix.lower() in TEXT_JSON or json_output) and not empty_captured_json:
        if path.suffix.lower() == ".jsonl":
            json_count = 0
            with path.open("rb") as stream:
                while True:
                    line = stream.readline(LIMITS["json_line_bytes"] + 1)
                    if not line:
                        break
                    json_count += len(line)
                    need(json_count <= before[2], "JSONL grew during bounded scan")
                    need(len(line) <= LIMITS["json_line_bytes"], "JSONL line exceeds scan bound")
                    if line.strip():
                        scan_json(parse(line), str(path))
        else:
            need(before[2] <= LIMITS["json_bytes"], "JSON artifact exceeds decoded credential scan bound")
            scan_json(parse(read_bounded(path, LIMITS["json_bytes"])), str(path))
    need(signature(path) == before, "input changed during credential/hash scan: " + str(path))
    return dict(bytes=before[2], sha256=hashed.hexdigest(), signature=before)


def json_file(path, expected=None):
    info = fingerprint(path)
    if expected is not None:
        need(info["sha256"] == pin(expected), "JSON differs from external pin: " + str(path))
    need(info["bytes"] <= LIMITS["json_bytes"], "JSON control exceeds bound")
    return parse(read_bounded(path, LIMITS["json_bytes"]))


def owned_new(path):
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts and not path.exists(), "output must be a new absolute path")
    parent = plain(path.parent, True)
    return parent / path.name


class Collector:
    def __init__(self):
        self.entries = {}
        self.total = 0
        self.portable_names = set()

    def add(self, path, name, expected=None):
        path = plain(path, False)
        parts = PurePosixPath(name)
        need(not parts.is_absolute() and "\\" not in name and ":" not in name
             and all(part not in ("", ".", "..") for part in parts.parts), "unsafe archive name")
        info = fingerprint(path)
        if expected is not None:
            need(info["sha256"] == pin(expected), "input differs from external pin: " + str(path))
        if name in self.entries:
            entry = self.entries[name]
            need(entry["sha256"] == info["sha256"] and entry["bytes"] == info["bytes"], "archive-path collision")
            entry["sources"].append(str(path))
            return name
        need(len(self.entries) < LIMITS["files"] and self.total + info["bytes"] <= LIMITS["total_bytes"], "evidence collection budget exceeded")
        # Case-fold clashes are refused even when creating the archive on POSIX.
        need(name.casefold() not in self.portable_names, "portable archive-name collision")
        self.portable_names.add(name.casefold())
        self.entries[name] = dict(path=name, bytes=info["bytes"], sha256=info["sha256"], sources=[str(path)], _signature=info["signature"])
        self.total += info["bytes"]
        return name

    def tree(self, root, prefix):
        def fail_walk(error):
            raise error

        directory_count = 0
        for current, directories, files in os.walk(root, followlinks=False, onerror=fail_walk):
            directory_count += 1
            need(directory_count + len(directories) <= LIMITS["directories"], "directory traversal bound exceeded")
            current = plain(current, True)
            for name in directories:
                plain(current / name, True)
            for name in sorted(files):
                path = plain(current / name, False)
                self.add(path, prefix + "/" + path.relative_to(root).as_posix())


def make_plan(config_path):
    config_path = plain(config_path, False)
    config_sha256 = fingerprint(config_path)["sha256"]
    config = json_file(config_path, config_sha256)
    fields(config, ("schema", "archive", "extract_to", "runs", "receipt_roots", "receipts", "saved_binary_roots", "executables"))
    need(config["schema"] == SCHEMA and isinstance(config["runs"], list) and 1 <= len(config["runs"]) <= 4, "one to four explicit pinned runs required")
    need(isinstance(config["receipts"], list) and len(config["receipts"]) <= LIMITS["files"]
         and isinstance(config["executables"], list) and 1 <= len(config["executables"]) <= 12,
         "explicit receipt/executable selection bounds")
    temporary = plain(tempfile.gettempdir(), True)
    audit = plain(Path(__file__).parent, True)
    collector = Collector()
    roots = []; runs = []; bindings = []; registered = {}; names = set()
    for run in config["runs"]:
        fields(run, ("name", "path", "registration_sha256", "report_sha256", "expected_status"))
        need(isinstance(run["name"], str) and re.fullmatch(r"[a-z0-9-]{1,32}", run["name"]) and run["name"] not in names, "unique explicit run names required")
        names.add(run["name"])
        root = plain(run["path"], True)
        need(inside(root, temporary) and root != audit and not inside(root, audit) and root.name.startswith("symbiote-v051-"), "run must be its own dedicated campaign directory, never Temp/audit/PKI")
        need(all(root != other and not inside(root, other) and not inside(other, root) for other in roots), "overlapping run roots")
        roots.append(root)
        registration = json_file(root / "campaign-registration.json", run["registration_sha256"])
        report = json_file(root / "campaign-report.json", run["report_sha256"])
        need(registration["schema"] == "symbiote.stability-registration/1" and report["schema"] == "symbiote.local-stability/1", "not a registered stability run")
        need(plain(registration["artifact_directory"], True) == root and report["registration_sha256"] == run["registration_sha256"], "campaign owner/registration binding differs")
        need(run["expected_status"] in ("HOLD", "PASS") and report["status"] == run["expected_status"], "overall campaign status differs from explicit expected status")
        need(registration["protocol"] == report["protocol"] == "SYMBIOTE-LOCAL-STABILITY-001", "unsupported protocol")
        prefix = "runs/" + root.name
        collector.tree(root, prefix)
        need(collector.entries[prefix + "/campaign-registration.json"]["sha256"] == run["registration_sha256"]
             and collector.entries[prefix + "/campaign-report.json"]["sha256"] == run["report_sha256"],
             "registered control bytes changed during collection")
        runs.append(dict(run, archive_prefix=prefix))
        for role, binary in registration["binaries"].items():
            need(role in ("native", "cli_tests", "service_tests"), "unknown registered executable role")
            binary_sha = pin(binary["sha256"])
            registered.setdefault(binary_sha, set()).add(str(Path(binary["path"]).absolute()))
            bindings.append(dict(run=run["name"], role=role, sha256=binary_sha))
    receipt_roots = [plain(path, True) for path in config["receipt_roots"]]
    need(len(receipt_roots) <= 8 and len(set(receipt_roots)) == len(receipt_roots), "receipt root bound/uniqueness")
    for root in receipt_roots:
        need(root != temporary and (root == audit or inside(root, temporary) and "gates" in root.name), "only explicit gate/audit receipt boundaries permitted")
    for receipt in config["receipts"]:
        fields(receipt, ("path", "sha256"))
        path = plain(receipt["path"], False)
        matches = [root for root in receipt_roots if inside(path, root)]
        need(len(matches) == 1, "selected receipt outside or ambiguously inside its explicit boundaries")
        collector.add(path, "receipts/" + matches[0].name + "/" + path.relative_to(matches[0]).as_posix(), receipt["sha256"])
    saved = [plain(path, True) for path in config["saved_binary_roots"]]
    need(len(saved) <= 4 and len(set(saved)) == len(saved), "saved binary root bound/uniqueness")
    need(all(inside(root, audit) and root.name.endswith("binaries") for root in saved), "saved binary roots must be explicit audit children, never whole audit")
    binaries = {}
    for binary in config["executables"]:
        fields(binary, ("path", "sha256"))
        path = plain(binary["path"], False); binary_sha = pin(binary["sha256"])
        need(path.suffix.lower() == ".exe" and binary_sha in registered, "only registered candidate EXEs may be included")
        need(str(path) in registered[binary_sha] or any(inside(path, root) for root in saved), "EXE path is not registered or explicitly saved")
        name = collector.add(path, "binaries/sha256/" + binary_sha + "/" + path.name, binary_sha)
        binaries.setdefault(binary_sha, []).append(name)
    need(set(binaries) == set(registered), "every registered executable digest must be preserved")
    for binding in bindings:
        binding["archive_paths"] = sorted(set(binaries[binding["sha256"]]))
    archive = owned_new(config["archive"]); extracted = owned_new(config["extract_to"])
    need(str(archive).endswith(".tar.gz"), "archive must have .tar.gz suffix")
    protected = roots + saved + [root for root in receipt_roots if root != audit]
    need(all(archive != root and not inside(archive, root) for root in protected)
         and all(extracted != root and not inside(extracted, root) and not inside(root, extracted) for root in protected),
         "output must not mutate or contain a run/gate/saved-binary input boundary")
    selected_sources = [Path(path) for entry in collector.entries.values() for path in entry["sources"]]
    need(all(path != archive and path != extracted and not inside(path, extracted) for path in selected_sources),
         "output overlaps a selected input file")
    need(archive != extracted and not inside(archive, extracted) and not inside(extracted, archive),
         "overlapping archive/extraction outputs")
    manifest_entries = [{key: value for key, value in entry.items() if not key.startswith("_")} for _, entry in sorted(collector.entries.items())]
    for entry in manifest_entries:
        entry["sources"] = sorted(set(entry["sources"]))
    manifest = encode(dict(schema="symbiote.stability-evidence-manifest/1", hash_algorithm="sha256", limits=LIMITS,
                           runs=runs, registered_executables=bindings, entries=manifest_entries,
                           self_reference="MANIFEST.json is excluded from its own entry list and pinned by the verification receipt"))
    need(len(manifest) <= LIMITS["manifest_bytes"], "manifest bound exceeded")
    scan_bytes(manifest, "generated MANIFEST.json"); scan_json(parse(manifest), "generated MANIFEST.json")
    need(fingerprint(config_path)["sha256"] == config_sha256, "configuration changed during planning")
    return config_path, config_sha256, collector, manifest, archive, extracted


def tar_info(name, size):
    info = tarfile.TarInfo(name)
    info.size = size; info.mode = 0o644; info.uid = info.gid = 0
    info.uname = info.gname = ""; info.mtime = 0
    return info


class CheckedReader:
    def __init__(self, entry):
        self.entry = entry
        self.path = plain(entry["sources"][0], False)
        need(signature(self.path) == entry["_signature"], "input changed before archive read")
        self.stream = self.path.open("rb"); self.hasher = hashlib.sha256(); self.count = 0

    def read(self, size):
        block = self.stream.read(size)
        self.count += len(block); self.hasher.update(block)
        return block

    def close(self):
        try:
            need(not self.stream.read(1) and self.count == self.entry["bytes"] and self.hasher.hexdigest() == self.entry["sha256"]
                 and signature(self.path) == self.entry["_signature"], "input mutated while archiving")
        finally:
            self.stream.close()


def compare_and_extract(archive, directory, collector, manifest):
    directory.mkdir()  # Exclusive publication area; retained even on failure.
    expected = dict(collector.entries)
    expected["MANIFEST.json"] = dict(bytes=len(manifest), sha256=hashlib.sha256(manifest).hexdigest(), sources=[])
    seen = set()
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            need(member.name in expected and member.name not in seen and member.isfile(), "unexpected/duplicate/non-file archive member")
            need(member.mode == 0o644 and member.uid == member.gid == member.mtime == 0
                 and member.uname == member.gname == "" and set(member.pax_headers) <= {"path"}, "non-normalized tar metadata")
            entry = expected[member.name]
            need(member.size == entry["bytes"], "archive member size differs")
            parts = PurePosixPath(member.name)
            need(not parts.is_absolute() and all(part not in ("..", ".") for part in parts.parts), "unsafe extraction path")
            target = directory.joinpath(*parts.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            readers = [open(plain(path, False), "rb") for path in entry["sources"]]
            if not readers:
                readers = [io.BytesIO(manifest)]
            hasher = hashlib.sha256(); count = 0
            try:
                with source.extractfile(member) as body, target.open("xb") as output:
                    while True:
                        block = body.read(BLOCK)
                        if not block:
                            break
                        need(all(reader.read(len(block)) == block for reader in readers), "extracted bytes differ from an original input")
                        output.write(block); hasher.update(block); count += len(block)
                    need(all(not reader.read(1) for reader in readers), "source has additional bytes")
            finally:
                for reader in readers:
                    reader.close()
            need(count == entry["bytes"] and hasher.hexdigest() == entry["sha256"], "full extracted SHA/byte comparison failed")
            seen.add(member.name)
    need(seen == set(expected), "archive silently omitted evidence")
    actual = {path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_file()}
    need(actual == seen, "unexpected extracted file")
    return len(seen)


def write_new(path, raw):
    with Path(path).open("xb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def archive_hash(path):
    limit = LIMITS["total_bytes"] + LIMITS["manifest_bytes"] + LIMITS["files"] * 4096
    need(path.stat().st_size <= limit,
         "archive output exceeds its data/metadata envelope")
    hasher = hashlib.sha256(); count = 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(BLOCK)
            if not block:
                return hasher.hexdigest()
            count += len(block)
            need(count <= limit, "archive output grew beyond envelope")
            hasher.update(block)


def package(config_path):
    config_path, config_sha256, collector, manifest, archive, extracted = make_plan(config_path)
    partial = Path(str(archive) + ".partial")
    reservation = Path(str(archive) + ".reservation.json")
    verification = Path(str(archive) + ".verification.json")
    sidecar = Path(str(archive) + ".MANIFEST.json")
    need(all(not path.exists() for path in (partial, reservation, verification, sidecar)), "output/reservation already exists; do not retry or overwrite")
    write_new(reservation, encode(dict(schema="symbiote.evidence-reservation/1", config_sha256=config_sha256, archive=str(archive), extract_to=str(extracted))))
    try:
        with partial.open("xb") as destination:
            with gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=destination, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as bundle:
                    bundle.addfile(tar_info("MANIFEST.json", len(manifest)), io.BytesIO(manifest))
                    for name, entry in sorted(collector.entries.items()):
                        reader = CheckedReader(entry)
                        try:
                            bundle.addfile(tar_info(name, entry["bytes"]), reader)
                        except BaseException:
                            reader.stream.close()
                            raise
                        else:
                            reader.close()
            destination.flush(); os.fsync(destination.fileno())
        checked = compare_and_extract(partial, extracted, collector, manifest)
        # Rescan every source after comparison; source mutations never become PASS.
        for entry in collector.entries.values():
            for path in entry["sources"]:
                actual = fingerprint(path)
                need(actual["sha256"] == entry["sha256"] and actual["bytes"] == entry["bytes"], "source changed after extracted-byte verification")
        need(fingerprint(config_path)["sha256"] == config_sha256, "configuration changed before publication")
        archive_sha = archive_hash(partial)
        write_new(sidecar, manifest)
        # Atomic exclusive link creation prevents POSIX rename-overwrite races.
        # NTFS/POSIX hard-link support is an explicit publication requirement.
        os.link(partial, archive)
        receipt = dict(schema="symbiote.stability-evidence-verification/1", status="PASS", archive=str(archive),
                       archive_sha256=archive_sha, archive_bytes=archive.stat().st_size,
                       manifest_sha256=hashlib.sha256(manifest).hexdigest(), files_including_manifest=checked,
                       source_bytes=collector.total, config_sha256=config_sha256,
                       extracted_directory=str(extracted), full_extracted_byte_comparison=True,
                       credentials_scanned=True, inputs_unchanged=True,
                       archive_metadata="regular files mode0644 uid/gid0 empty owner names mtime0; gzip filename empty/mtime0",
                       interpretation="byte-preserving evidence packaging; each original campaign status remains authoritative")
        write_new(verification, encode(receipt))
        return receipt
    except BaseException as error:
        failure = Path(str(archive) + ".failure.json")
        if not failure.exists():
            write_new(failure, encode(dict(schema="symbiote.stability-evidence-verification/1", status="HOLD",
                                           failure=type(error).__name__ + ": " + str(error),
                                           partial=str(partial), extracted_directory=str(extracted), inputs_modified=False)))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(package(arguments.config), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, tarfile.TarError, KeyError, TypeError, RecursionError) as error:
        print(json.dumps(dict(status="HOLD", failure=type(error).__name__ + ": " + str(error))), file=sys.stderr)
        sys.exit(1)
