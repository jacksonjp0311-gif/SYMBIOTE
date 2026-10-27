"""External, explicit v1 publication/verification draft; importing does nothing.

This never creates a tag/release or replaces an asset. Use only after Root closes
qualification and CI. Native smoke runs only with --install-windows in verify.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import struct
import subprocess
import tempfile
import threading
import time
import types
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPOSITORY = "jacksonjp0311-gif/SYMBIOTE"
TAG = "v1.0.0"
BASE = "https://api.github.com/repos/" + REPOSITORY
TARGETS = {
    "x86_64-pc-windows-msvc": ("pe", 0x8664, "symbiote.exe"),
    "x86_64-unknown-linux-gnu": ("elf", 62, "symbiote"),
    "aarch64-apple-darwin": ("macho", 0x0100000C, "symbiote"),
    "x86_64-apple-darwin": ("macho", 0x01000007, "symbiote"),
}
ZIP_NAMES = {"symbiote-" + TAG + "-" + target + ".zip" for target in TARGETS}
NATIVE_NAMES = ZIP_NAMES | {"SHA256SUMS"}
CDN_HOSTS = {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
LIMITS = dict(asset_bytes=2 * 1024**3, downloads_bytes=3 * 1024**3,
              binary_bytes=100 * 1024**2, text_bytes=128 * 1024,
              json_bytes=8 * 1024**2, body_bytes=64 * 1024,
              wait_seconds=7200, poll_seconds=60, download_seconds=600)


class ReleaseError(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise ReleaseError(message)


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, "non-finite JSON field"))


def encode(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")


def pin(value, length=64):
    need(isinstance(value, str) and re.fullmatch("[0-9a-f]{" + str(length) + "}", value), "lowercase exact digest required")
    return value


def plain(path, directory=False):
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts, "explicit absolute input path required")
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor = cursor / part
        info = cursor.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
             "linked/reparse input refused")
    path = path.resolve(strict=True)
    need(path.is_dir() if directory else path.is_file(), "input has wrong type")
    return path


def sha(path, limit=LIMITS["asset_bytes"]):
    path = plain(path)
    before = path.stat()
    need(before.st_size <= limit, "file exceeds explicit byte limit")
    hashed = hashlib.sha256(); count = 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(min(1024 * 1024, limit - count + 1))
            if not block:
                break
            count += len(block); need(count <= limit, "file grew beyond byte limit")
            hashed.update(block)
    after = path.stat()
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and count == before.st_size,
         "file changed while hashing")
    return hashed.hexdigest()


def write_new(path, data):
    with Path(path).open("xb") as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())


def read_bounded(path, limit):
    with plain(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    need(len(raw) <= limit, "bounded input grew or exceeded its limit")
    return raw


def new_output(path):
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts and not path.exists(), "fresh absolute output directory required")
    parent = plain(path.parent, True)
    root = plain(tempfile.gettempdir(), True)
    need(parent == root or root in parent.parents, "output must be a fresh OS-temp directory")
    need(len(str(parent / path.name)) <= 100, "choose a short OS-temp output path")
    result = parent / path.name; result.mkdir()
    return result


def same_location(first, second):
    def normalized(path):
        value = str(plain(path))
        if os.name == "nt":
            if value.startswith("\\\\?\\UNC\\"):
                value = "\\\\" + value[8:]
            elif value.startswith("\\\\?\\"):
                value = value[4:]
            value = os.path.normcase(value)
        return value
    return normalized(first) == normalized(second)


def url_parts(url, hosts):
    parsed = urllib.parse.urlsplit(url)
    need(parsed.scheme == "https" and parsed.hostname in hosts and parsed.port in (None, 443)
         and parsed.username is None and parsed.password is None and not parsed.fragment,
         "unexpected HTTPS host, credentials, port or fragment")
    return parsed


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ReleaseError("API metadata redirect refused")


class PublicAssetRedirect(urllib.request.HTTPRedirectHandler):
    """Every hop is anonymous, including GitHub's off-host signed redirects."""
    def __init__(self, hosts):
        super().__init__(); self.hosts = hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url_parts(newurl, self.hosts)
        return urllib.request.Request(newurl, headers={"User-Agent": "SYMBIOTE-public-verification",
                                                       "Cache-Control": "no-cache"}, method="GET")


def metadata(path):
    need(path.startswith("/repos/" + REPOSITORY + "/") and "?" not in path and "#" not in path,
         "fixed repository API route required")
    url = "https://api.github.com" + path + "?verification_stamp=" + str(time.time_ns())
    request = urllib.request.Request(url, headers={"User-Agent": "SYMBIOTE-public-verification",
                                                 "Accept": "application/vnd.github+json", "Cache-Control": "no-cache"})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
        raw = response.read(LIMITS["json_bytes"] + 1)
    need(len(raw) <= LIMITS["json_bytes"], "API metadata byte limit")
    return parse(raw)


def resolve_tag(expected):
    expected = pin(expected, 40)
    item = metadata("/repos/" + REPOSITORY + "/git/ref/tags/" + TAG)["object"]
    for _ in range(8):
        if item["type"] == "commit":
            need(item["sha"] == expected, "release tag does not match the explicitly expected source commit")
            return expected
        need(item["type"] == "tag", "release ref is not a commit or annotated tag")
        item = metadata("/repos/" + REPOSITORY + "/git/tags/" + pin(item["sha"], 40))["object"]
    raise ReleaseError("annotated tag nesting limit")


def asset_map(release):
    need(release["tag_name"] == TAG and release["draft"] is False and release["prerelease"] is False,
         "workflow-created public final-tag release required")
    need(type(release["id"]) is int and release["id"] > 0, "actual release ID required")
    need(release["creator"]["login"] == "github-actions[bot]", "release must be created by the configured GitHub workflow")
    need(release["html_url"] == "https://github.com/" + REPOSITORY + "/releases/tag/" + TAG,
         "release page belongs to another repository/tag")
    assets = release["assets"]
    need(isinstance(assets, list) and len(assets) <= 7, "unexpected release asset count")
    result = {}
    for item in assets:
        name = item["name"]
        need(isinstance(name, str) and re.fullmatch("[A-Za-z0-9._-]{1,160}", name) and name not in result,
             "duplicate or unsafe release asset name")
        need(type(item["id"]) is int and item["id"] > 0 and type(item["size"]) is int
             and 0 < item["size"] <= LIMITS["asset_bytes"], "asset identity/size bound")
        expected = "https://github.com/" + REPOSITORY + "/releases/download/" + TAG + "/" + urllib.parse.quote(name)
        need(item["browser_download_url"] == expected, "asset download URL belongs to another origin/tag/name")
        result[name] = item
    need(NATIVE_NAMES <= set(result), "workflow has not completed the exact four native bundles and SHA256SUMS")
    return result


def wait_release(commit, seconds):
    need(type(seconds) is int and 0 <= seconds <= LIMITS["wait_seconds"], "bounded workflow wait required")
    deadline = time.monotonic() + seconds
    while True:
        try:
            release = metadata("/repos/" + REPOSITORY + "/releases/tags/" + TAG)
        except urllib.error.HTTPError as error:
            need(error.code == 404, "GitHub public metadata request failed: HTTP " + str(error.code))
        else:
            asset_map(release)
            resolve_tag(commit)
            return release
        remaining = deadline - time.monotonic()
        need(remaining > 0, "workflow-created release did not appear within the fixed wait")
        time.sleep(min(LIMITS["poll_seconds"], remaining))


def download(url, path, expected_size, expected_sha=None, *, hosts=CDN_HOSTS):
    url_parts(url, hosts)
    need(type(expected_size) is int and 0 < expected_size <= LIMITS["asset_bytes"], "bounded public asset size required")
    if expected_sha is not None:
        pin(expected_sha)
    request = urllib.request.Request(url, headers={"User-Agent": "SYMBIOTE-public-verification", "Cache-Control": "no-cache"})
    hashed = hashlib.sha256(); count = 0; deadline = time.monotonic() + LIMITS["download_seconds"]
    with urllib.request.build_opener(PublicAssetRedirect(hosts)).open(request, timeout=120) as response, Path(path).open("xb") as stream:
        need(response.status == 200, "public download returned an unexpected HTTP status")
        while True:
            need(time.monotonic() <= deadline, "public download elapsed limit")
            block = response.read(min(1024 * 1024, expected_size - count + 1))
            if not block:
                break
            count += len(block); need(count <= expected_size, "public asset exceeded declared size")
            stream.write(block); hashed.update(block)
        stream.flush(); os.fsync(stream.fileno())
    actual = hashed.hexdigest()
    need(count == expected_size and (expected_sha is None or actual == expected_sha), "public asset size or SHA256 mismatch")
    return actual


def check_asset_digest(asset, actual):
    declared = asset.get("digest")
    need(declared is None or declared == "sha256:" + actual, "GitHub asset digest mismatches downloaded/local bytes")


def credential():
    environment = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="Never")
    result = subprocess.run(["git", "credential", "fill"], input=b"protocol=https\nhost=github.com\n\n",
                            capture_output=True, timeout=30, check=False, env=environment)
    need(result.returncode == 0, "GitHub credential helper failed; credential output is intentionally not logged")
    fields = dict(line.split("=", 1) for line in result.stdout.decode("utf-8").splitlines() if "=" in line)
    token = fields.get("password")
    need(isinstance(token, str) and token and "\n" not in token and "\r" not in token, "GitHub credential is unavailable")
    return token


class PinnedUpload:
    def __init__(self, stream, expected_size):
        self.stream = stream; self.expected = expected_size; self.count = 0; self.hash = hashlib.sha256()

    def read(self, size=1024 * 1024):
        if self.count == self.expected:
            return b""
        block = self.stream.read(min(size, self.expected - self.count))
        need(block, "upload input was truncated")
        self.count += len(block); self.hash.update(block)
        return block


def authenticated(url, method, body, token, *, size=None):
    parsed = url_parts(url, {"api.github.com", "uploads.github.com"})
    prefix = "/repos/" + REPOSITORY + "/releases/"
    need(parsed.path.startswith(prefix), "authenticated request outside fixed release namespace")
    if method == "PATCH":
        need(parsed.hostname == "api.github.com" and re.fullmatch(re.escape(prefix) + r"[1-9][0-9]*", parsed.path)
             and not parsed.query, "unexpected release-edit route")
        payload = encode(body); size = len(payload); content_type = "application/json"
    else:
        need(method == "POST" and parsed.hostname == "uploads.github.com"
             and re.fullmatch(re.escape(prefix) + r"[1-9][0-9]*/assets", parsed.path), "unexpected upload route")
        query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
        need(set(query) == {"name"} and len(query["name"]) == 1, "unexpected upload query")
        payload = body; content_type = "application/octet-stream"
        need(type(size) is int and 0 < size <= LIMITS["asset_bytes"], "bounded upload size required")
    headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
               "Content-Type": content_type, "Content-Length": str(size), "User-Agent": "SYMBIOTE-release"}
    connection = http.client.HTTPSConnection(parsed.hostname, timeout=120)
    try:
        connection.request(method, parsed.path + ("?" + parsed.query if parsed.query else ""), body=payload, headers=headers)
        response = connection.getresponse()
        # http.client never follows redirects. Authentication never leaves this host.
        need(response.status in (200, 201), "authenticated operation failed: HTTP " + str(response.status))
        raw = response.read(LIMITS["json_bytes"] + 1)
        need(len(raw) <= LIMITS["json_bytes"], "authenticated JSON response byte limit")
        return parse(raw)
    finally:
        connection.close()


def native_header(data, target):
    kind, machine, _ = TARGETS[target]; valid = False
    need(32 <= len(data) <= LIMITS["binary_bytes"], "native image size bound")
    if kind == "pe" and len(data) >= 64 and data[:2] == b"MZ":
        offset = struct.unpack_from("<I", data, 60)[0]
        valid = offset + 6 <= len(data) and data[offset:offset + 4] == b"PE\0\0" and struct.unpack_from("<H", data, offset + 4)[0] == machine
    if kind == "elf" and data[:6] == b"\x7fELF\x02\x01":
        valid = struct.unpack_from("<H", data, 16)[0] in (2, 3) and struct.unpack_from("<H", data, 18)[0] == machine
    if kind == "macho" and data[:4] == b"\xcf\xfa\xed\xfe":
        valid = struct.unpack_from("<I", data, 4)[0] == machine and struct.unpack_from("<I", data, 12)[0] == 2
    need(valid, "native format/architecture differs from asset name")


def inspect_zip(path, target):
    binary = TARGETS[target][2]
    with zipfile.ZipFile(path) as bundle:
        items = bundle.infolist()
        need(len(items) == 3 and {item.filename for item in items} == {binary, "LICENSE", "README.md"}, "native ZIP must have exactly three flat files")
        for item in items:
            limit = LIMITS["binary_bytes"] if item.filename == binary else LIMITS["text_bytes"]
            need(0 < item.file_size <= limit and not item.is_dir() and not item.flag_bits & 1
                 and ((item.external_attr >> 16) & 0o170000) != 0o120000, "unsafe or oversized native ZIP entry")
        image = bundle.read(binary); native_header(image, target)
        readme = bundle.read("README.md"); license_bytes = bundle.read("LICENSE")
        need(("https://github.com/" + REPOSITORY + "/tree/" + TAG).encode() in readme,
             "native README does not link to the exact versioned documentation")
    return dict(target=target, binary_sha256=hashlib.sha256(image).hexdigest(), binary_bytes=len(image),
                license_sha256=hashlib.sha256(license_bytes).hexdigest(), readme_sha256=hashlib.sha256(readme).hexdigest())


def checksum_manifest(path, expected):
    path = plain(path); raw = read_bounded(path, LIMITS["text_bytes"])
    rows = {}
    for line in raw.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]{1,160})", line)
        need(match is not None and match[2] not in rows, "invalid/duplicate checksum row")
        rows[match[2]] = match[1]
    need(set(rows) == set(expected), "checksum manifest has missing or unexpected assets")
    for name, expected_sha in rows.items():
        need(sha(path.parent / name) == expected_sha, "downloaded asset differs from its exact checksum manifest")
    return rows


def publish(args, out, release, assets, archive):
    allowed = NATIVE_NAMES | {archive.name, "EVIDENCE_SHA256SUMS"}
    need(set(assets) <= allowed, "unexpected pre-existing asset; never delete or replace it")
    stage = out / "upload-staging"; stage.mkdir()
    staged = stage / archive.name; hashed = hashlib.sha256(); count = 0
    with archive.open("rb") as source, staged.open("xb") as destination:
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            count += len(block); need(count <= LIMITS["asset_bytes"], "archive staging byte limit")
            destination.write(block); hashed.update(block)
        destination.flush(); os.fsync(destination.fileno())
    need(hashed.hexdigest() == args.evidence_sha256 and sha(archive) == args.evidence_sha256, "archive changed during staging")
    checksum = stage / "EVIDENCE_SHA256SUMS"
    write_new(checksum, (args.evidence_sha256 + "  " + archive.name + "\n").encode("ascii"))
    checks = []
    token = None
    for path in (staged, checksum):
        expected = sha(path); size = path.stat().st_size
        if path.name in assets:
            asset = assets[path.name]; need(asset["size"] == size, "existing asset size differs; replacement is forbidden")
            check_asset_digest(asset, expected)
            existing = out / ("existing-" + path.name)
            download(asset["browser_download_url"], existing, size, expected)
            action = "VERIFIED_EXISTING_EXACT_BYTES"
        else:
            if token is None:
                token = credential()
            expected_path = "/repos/" + REPOSITORY + "/releases/" + str(release["id"]) + "/assets"
            upload = release["upload_url"].split("{", 1)[0]
            parsed = url_parts(upload, {"uploads.github.com"})
            need(parsed.path == expected_path and not parsed.query, "release upload URL mismatch")
            with path.open("rb") as stream:
                reader = PinnedUpload(stream, size)
                asset = authenticated(upload + "?name=" + urllib.parse.quote(path.name), "POST", reader, token, size=size)
                need(reader.count == size and reader.hash.hexdigest() == expected and sha(path) == expected, "upload source mismatch")
            need(asset["name"] == path.name and asset["size"] == size, "uploaded asset metadata mismatch")
            check_asset_digest(asset, expected); action = "UPLOADED_WITHOUT_REPLACEMENT"
        checks.append(dict(name=path.name, sha256=expected, bytes=size, action=action))
    fresh = metadata("/repos/" + REPOSITORY + "/releases/tags/" + TAG)
    current = asset_map(fresh)
    need(set(current) == allowed, "fresh public release does not expose exact requested assets")
    need(all((current[name]["id"], current[name]["size"], current[name].get("digest")) ==
             (assets[name]["id"], assets[name]["size"], assets[name].get("digest")) for name in NATIVE_NAMES),
         "native asset changed during evidence publication")
    resolve_tag(args.commit)
    return dict(status="EVIDENCE_UPLOADED_AWAITING_FINAL_PUBLIC_DOWNLOAD_VERIFICATION_AND_BODY", assets=checks,
                release_body_changed=False, no_asset_replacement=True, created_tag_or_release=False)


def verify(args, out, release, assets, archive, body):
    native_only = args.mode == "verify-native"
    expected = NATIVE_NAMES if native_only else NATIVE_NAMES | {archive.name, "EVIDENCE_SHA256SUMS"}
    need(set(assets) == expected, "release asset set is not the exact requested five-native or seven-final set")
    need(sum(item["size"] for item in assets.values()) <= LIMITS["downloads_bytes"], "aggregate public download byte limit")
    destination = out / "downloads"; destination.mkdir()
    rows = []
    for name, asset in sorted(assets.items()):
        if name in {"SHA256SUMS", "EVIDENCE_SHA256SUMS"}:
            need(asset["size"] <= LIMITS["text_bytes"], "checksum asset byte limit")
        if name in ZIP_NAMES:
            need(asset["size"] <= LIMITS["binary_bytes"] + 2 * LIMITS["text_bytes"] + 1024 * 1024,
                 "native ZIP download byte limit")
        expected_sha = args.evidence_sha256 if archive is not None and name == archive.name else None
        actual = download(asset["browser_download_url"], destination / name, asset["size"], expected_sha)
        check_asset_digest(asset, actual)
        rows.append(dict(name=name, asset_id=asset["id"], bytes=asset["size"], sha256=actual, anonymous_public_download=True))
    checksum_manifest(destination / "SHA256SUMS", ZIP_NAMES)
    if not native_only:
        checksum_manifest(destination / "EVIDENCE_SHA256SUMS", {archive.name})
    bundles = [inspect_zip(destination / ("symbiote-" + TAG + "-" + target + ".zip"), target) for target in TARGETS]
    need(len({row["license_sha256"] for row in bundles}) == 1, "platform bundles contain different licenses")
    result = dict(status="PASS_PUBLIC_NATIVE_BYTES" if native_only else "PASS_PUBLIC_FINAL_BYTES", assets=rows, bundles=bundles,
                  exact_asset_count=len(expected), checksum_manifest_sets_exact=True, native_installation="NOT_RUN",
                  release_body_changed=False)
    if args.install_windows:
        result["native_installation"] = windows_smoke(args, out, destination, bundles)
    if args.finalize_body:
        token = credential()
        edited = authenticated(BASE + "/releases/" + str(release["id"]), "PATCH",
                               {"name": "SYMBIOTE " + TAG, "body": body}, token)
        need(edited["tag_name"] == TAG and edited["body"] == body, "edited release body does not match reviewed text")
        result.update(release_body_changed=True, body_sha256=args.body_sha256)
    fresh = metadata("/repos/" + REPOSITORY + "/releases/tags/" + TAG)
    current = asset_map(fresh)
    need(set(current) == expected and (not args.finalize_body or fresh["body"] == body), "fresh body or asset set differs")
    need(all((current[name]["id"], current[name]["size"], current[name].get("digest")) ==
             (assets[name]["id"], assets[name]["size"], assets[name].get("digest")) for name in expected),
         "release asset was replaced during public verification")
    resolve_tag(args.commit)
    return result


def windows_smoke(args, out, downloads, bundles):
    need(os.name == "nt" and platform.machine().lower() in ("amd64", "x86_64"), "Windows x64 host required")
    need(args.installer_sha256 and args.safety_file and args.safety_sha256, "installer and process-containment source pins required")
    safety_path = plain(args.safety_file)
    need(sha(safety_path, LIMITS["json_bytes"]) == pin(args.safety_sha256), "process containment helper source pin differs")
    safety = types.ModuleType("qualified_public_process_containment"); safety.__file__ = str(safety_path)
    safety_source = read_bounded(safety_path, LIMITS["json_bytes"])
    need(hashlib.sha256(safety_source).hexdigest() == args.safety_sha256, "containment source changed before import")
    exec(compile(safety_source, str(safety_path), "exec"), safety.__dict__)
    safety.ROOT = out
    installer_url = "https://raw.githubusercontent.com/" + REPOSITORY + "/" + args.commit + "/tools/install.ps1"
    # The raw source size is not release asset metadata; independently bounded read.
    request = urllib.request.Request(installer_url, headers={"User-Agent": "SYMBIOTE-public-verification", "Cache-Control": "no-cache"})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
        raw = response.read(LIMITS["text_bytes"] + 1)
    need(len(raw) <= LIMITS["text_bytes"] and hashlib.sha256(raw).hexdigest() == pin(args.installer_sha256), "exact committed public installer pin mismatch")
    installer = out / "install.ps1"; write_new(installer, raw)
    cancelled = threading.Event(); calls = []; previous = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.getsignal(signum); signal.signal(signum, lambda *_: cancelled.set())
    def call(label, argv):
        need(not cancelled.is_set(), "public smoke cancelled before admission")
        record = safety.execute(argv, out, label, timeout=90, cancelled=cancelled.is_set)
        calls.append(record); safety.check_exit(record)
        return safety.output(record, out)
    def native(command, state, *options):
        return parse(call(command + "-" + str(len(calls)), [binary, command, "--state", state, "--json", *options]).encode())
    try:
        install = out / "installed"
        call("windows-public-installer-no-path", ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                                 "-File", installer, "-Version", TAG, "-BundleDirectory", downloads, "-InstallDir", install])
        binary = plain(install / "symbiote.exe")
        windows = next(row for row in bundles if row["target"] == "x86_64-pc-windows-msvc")
        need(sha(binary) == windows["binary_sha256"], "installed binary differs from verified Windows ZIP")
        version = parse(call("installed-version", [binary, "version", "--json"]).encode())
        need(version["name"] == "SYMBIOTE" and version["version"] == "1.0.0" and version["build_source_commit"] == args.commit, "installed executable version/source stamp mismatch")
        state = out / "demo-owner"
        doctor = native("doctor", state)
        need(not state.exists() and doctor["network_requests"] == 0 and doctor["state_modified"] is False, "doctor changed new state")
        first = native("demo", state, "--receipts", out / "first-demo.json")
        before = native("predict", state)
        again = native("demo", state, "--receipts", out / "restarted-demo.json")
        need(first["promoted"] == 2 and again["promoted"] == 0 and again["reused"] == 2 and first["identity"] == again["identity"] == before["identity"], "public demo/restart identity or persistent promotion mismatch")
        check_predictions(before)
        _, rows = safety.identity_chain(state / "ledger.jsonl")
        need(rows[0]["payload"]["identity"] == first["identity"], "reported owner differs from actual retained genesis")
        promotions = {row["payload"]["artifact"]["id"]: row["payload"]["artifact"]
                      for row in rows if row["payload"]["event"] == "promote"}
        need(set(promotions) == {"alpha-table", "beta-table"} and len(rows) == 3
             and all(item["revision"] == 1 for item in promotions.values()), "actual first promotions/history are not retained exactly once")
        known = ("ledger.jsonl", "knowledge.jsonl")
        histories = {name: (state / name).read_bytes() for name in known if (state / name).is_file()}
        absent = set(known) - set(histories)
        need("ledger.jsonl" in histories, "nonempty actual identity/model history required")
        backup = out / "owner-backup"
        saved = parse(call("backup-state", [binary, "backup-state", "--state", state, "--backup", backup, "--json"]).encode())
        verified = parse(call("verify-backup", [binary, "verify-backup", "--backup", backup, "--manifest-sha256", saved["manifest_sha256"], "--json"]).encode())
        restored_state = out / "restored-owner"
        restored = parse(call("restore-state", [binary, "restore-state", "--backup", backup, "--manifest-sha256", saved["manifest_sha256"], "--state", restored_state, "--json"]).encode())
        after = native("predict", restored_state); check_predictions(after)
        need(after["identity"] == first["identity"] == saved["identity"] == verified["identity"] == restored["identity"], "backup/restore changed owner identity")
        need(after["predictions"] == before["predictions"], "restored actual prediction tables differ")
        need(saved["manifest_sha256"] == verified["manifest_sha256"] == restored["manifest_sha256"]
             and all(item["network_started"] is False for item in (saved, verified, restored)), "backup proof mismatch or unexpected network activation")
        for name, raw_history in histories.items():
            need((state / name).read_bytes() == raw_history == (restored_state / name).read_bytes(), "source/restored history bytes changed")
        for name in absent:
            need(not (state / name).exists() and not (restored_state / name).exists(), "backup fabricated absent history")
        cognition = dict(status="NOT_REQUESTED", requires="new source-pinned service test executable with the explicit cognition-only binary override")
        if args.cognition_tests is not None:
            tests = plain(args.cognition_tests)
            need(sha(tests) == pin(args.cognition_tests_sha256), "new cognition test executable SHA differs")
            artifacts = out / "public-cognition"
            need(not artifacts.exists(), "fresh cognition evidence path required")
            selected = "cognitive::native_cognition_learns_two_families_cross_contributes_and_restarts_without_relearning"
            record = safety.execute([tests, selected, "--nocapture", "--exact", "--test-threads=1"], out,
                                    "installed-public-binary-configured-cognition", timeout=90, cancelled=cancelled.is_set,
                                    environment={"SYMBIOTE_COGNITION_TEST_BINARY": str(binary),
                                                 "SYMBIOTE_COGNITION_ARTIFACTS": str(artifacts)})
            calls.append(record); safety.check_exit(record); safety.check_native_test(safety.output(record, out))
            cognition = check_cognition_artifacts(artifacts, binary, windows["binary_sha256"], safety)
            need(sha(tests) == args.cognition_tests_sha256, "cognition test executable changed during invocation")
            cognition.update(test_binary=str(tests), test_binary_sha256=args.cognition_tests_sha256,
                             exact_test=selected, process_receipt=record["process_receipt"])
        need(not cancelled.is_set() and sha(binary) == windows["binary_sha256"], "cancelled or changed binary before public smoke completion")
        return dict(status="PASS_WINDOWS_INSTALL_AND_BOUNDED_SMOKE", version=version, binary_sha256=sha(binary),
                    installed_into_temp=True, add_to_path=False, calls=calls, exact_prediction_tables=True,
                    retained_identity=first["identity"], backup_manifest_sha256=saved["manifest_sha256"],
                    offline_exact_history_restore=True,
                    configured_cognition_public_binary=cognition,
                    interpretation="Public Windows binary installation and bounded smoke only; no study rerun, hour qualification or two-host evidence")
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def check_cognition_artifacts(root, binary, binary_sha, safety):
    root = plain(root, True)
    manifest_path = plain(root / "artifact-manifest.json")
    need(manifest_path.stat().st_size <= LIMITS["json_bytes"], "cognition manifest byte bound")
    manifest = parse(read_bounded(manifest_path, LIMITS["json_bytes"]))
    need(manifest["schema"] == "symbiote.cognition-engineering-artifacts/1"
         and manifest["private_keys_copied"] is False and manifest["native_binary_sha256"] == binary_sha
         and same_location(manifest["native_binary"], binary), "cognition evidence is not bound to the installed public executable")
    files = manifest["files"]; need(isinstance(files, list) and 1 <= len(files) <= 20000, "bounded actual cognition file manifest required")
    names = set(); total = 0
    for row in files:
        name = row["path"].replace("\\", "/")
        parts = name.split("/")
        need(name and all(part not in ("", ".", "..") for part in parts) and ":" not in name
             and name not in names, "unsafe or duplicate cognition artifact path")
        names.add(name)
        path = plain(root.joinpath(*parts))
        need(root in path.parents and path.suffix.lower() not in {".key", ".pfx", ".p12"}, "cognition artifact escaped root or contains a private credential file")
        need(type(row["bytes"]) is int and row["bytes"] == path.stat().st_size and 0 <= row["bytes"] <= 64 * 1024**2,
             "cognition file-size mismatch")
        total += row["bytes"]; need(total <= 64 * 1024**2, "cognition aggregate evidence byte cap")
        need(sha(path, 64 * 1024**2) == pin(row["sha256"]), "cognition retained file digest mismatch")
    actual = set()
    def listing_error(error):
        raise error
    for current, directories, filenames in os.walk(root, followlinks=False, onerror=listing_error):
        plain(current, True)
        for name in directories:
            plain(Path(current) / name, True)
        for name in filenames:
            actual.add(plain(Path(current) / name).relative_to(root).as_posix())
    need(actual == names | {"artifact-manifest.json"}, "cognition manifest omitted or invented a retained file")
    summaries = [parse(read_bounded(root / name / "summary.json", LIMITS["json_bytes"])) for name in ("native-first", "native-restart")]
    first, again = summaries
    need(all(row["schema"] == "symbiote.cognition-summary/1" and row["status"] == "STOPPED"
             and all(type(row[field]) is int for field in ("active_models", "partner_benefits_verified", "fresh_promotions", "quarantined_contributions"))
             and row["active_models"] == 2 and row["partner_benefits_verified"] == 0 for row in summaries), "actual cognition summaries/model counts missing")
    need(first["fresh_promotions"] == 2 and first["quarantined_contributions"] == 2
         and again["fresh_promotions"] == 0 and again["quarantined_contributions"] == 0
         and first["identity"] == again["identity"]
         and again["initial_knowledge_anchor"] == again["final_knowledge_anchor"], "actual cognition first/restart behavior mismatch")
    for name, summary in zip(("native-first", "native-restart"), summaries):
        output = read_bounded(root / (name + "-stdout.jsonl"), 64 * 1024**2).splitlines()
        need(output and all(len(line) <= LIMITS["text_bytes"] for line in output), "bounded actual native cognition stdout required")
        parsed = [parse(line) for line in output]
        events = [parse(line) for line in read_bounded(root / name / "events.jsonl", 64 * 1024**2).splitlines()]
        need(parsed[-1] == summary and parsed[:-1] == events, "cognition summary/events differ from preserved native stdout")
    role_models = {}
    for role in ("actor", "server", "client"):
        _, identity = safety.identity_chain(root / (role + "-state") / "ledger.jsonl")
        _, knowledge = safety.knowledge_chain(root / (role + "-state") / "knowledge.jsonl")
        owner = identity[0]["payload"]["identity"]
        need(knowledge[0]["payload"]["identity"] == owner, "cognition private owner/knowledge genesis mismatch")
        models = [row["payload"]["record"] for row in knowledge if row["payload"]["event"] in {"promote", "promote_graph"}]
        need(len(models) == 2 and len(knowledge) == 3 and len({row["id"] for row in models}) == 2,
             "cognition retained nonempty two-model history required")
        need({row["payload"]["kind"] for row in models} == {"affine", "graph-map"}
             and {row["scope"] for row in models} == {"affine-context/v1", "graph-context/v1"},
             "actual retained affine and graph families required")
        if role == "actor":
            need(owner == first["identity"], "cognition reported identity differs from retained actor")
        else:
            evaluation = parse(read_bounded(root / ("peer-evaluation-" + role + ".json"), LIMITS["json_bytes"]))
            need(evaluation["schema"] == "symbiote.service-evaluation/1" and evaluation["status"] == "PROMOTED"
                 and evaluation["promoted"] is True
                 and evaluation["record_sha256"] in {safety.record_digest(model) for model in models},
                 "partner independently promoted receipt is not bound to actual retained history")
        role_models[role] = dict(identity=owner, model_count=len(models), model_sha256=[safety.record_digest(model) for model in models])
    need(len({row["identity"] for row in role_models.values()}) == 3, "three private cognition owners required")
    return dict(status="PASS_INSTALLED_PUBLIC_BINARY_CONFIGURED_COGNITION", manifest_sha256=sha(manifest_path),
                native_binary_sha256=binary_sha, roles=role_models, first_fresh_promotions=2,
                restart_fresh_promotions=0, active_models=2, partner_evaluations="two independently PROMOTED local receipts",
                interpretation="bounded operational integration, not a new scientific cohort or learning-efficiency claim")


def check_predictions(value):
    need(value["schema"] == "symbiote.retained/1" and value["status"] == "PASS"
         and type(value["network_requests"]) is int and value["network_requests"] == 0
         and type(value["active_artifacts"]) is int and value["active_artifacts"] == 2
         and type(value["genesis_artifacts"]) is int and value["genesis_artifacts"] == 2
         and type(value["structural_artifacts"]) is int and value["structural_artifacts"] == 0
         and value["structural_knowledge"] == [], "offline two-model prediction state required")
    rows = value["predictions"]
    need(len(rows) == 2 and {row["artifact"] for row in rows} == {"alpha-table", "beta-table"}, "actual alpha/beta prediction rows required")
    expected = {"alpha-table": ("alpha", [0, 1, 1, 0]), "beta-table": ("beta", [0, 1, 0, 1])}
    for row in rows:
        partner, table = expected[row["artifact"]]
        need(type(row["revision"]) is int and row["revision"] == 1 and row["partner"] == partner
             and row["scope"] == "finite-boolean-v1" and row["predictions"] == table
             and all(type(bit) is int and bit in (0, 1) for bit in row["predictions"]), "actual finite prediction tables/revisions differ")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("status", "verify-native", "publish", "verify"))
    parser.add_argument("--commit", required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--evidence-sha256")
    parser.add_argument("--body", type=Path)
    parser.add_argument("--body-sha256")
    parser.add_argument("--finalize-body", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--wait-seconds", type=int, default=1800)
    parser.add_argument("--install-windows", action="store_true")
    parser.add_argument("--installer-sha256")
    parser.add_argument("--safety-file", type=Path)
    parser.add_argument("--safety-sha256")
    parser.add_argument("--cognition-tests", type=Path)
    parser.add_argument("--cognition-tests-sha256")
    args = parser.parse_args()
    out = None; stage = "validate-explicit-inputs"
    try:
        pin(args.commit, 40)
        archive = None
        if args.mode in {"publish", "verify"}:
            need(args.archive is not None and args.evidence_sha256 is not None, "final archive path and external SHA required")
            pin(args.evidence_sha256); archive = plain(args.archive)
            need(re.fullmatch(r"SYMBIOTE-v1\.0\.0-[A-Za-z0-9._-]{1,100}\.tar\.gz", archive.name), "explicit portable v1 qualification archive name required")
            need(sha(archive) == args.evidence_sha256, "archive differs from externally reviewed evidence digest")
        else:
            need(args.archive is None and args.evidence_sha256 is None, "five-native/status mode does not consume the later evidence archive")
        need(not args.install_windows or args.mode in {"verify", "verify-native"}, "native installation requires explicit verification mode")
        need(not args.finalize_body or args.mode == "verify", "body publication follows complete final seven-asset verification only")
        need((args.cognition_tests is None) == (args.cognition_tests_sha256 is None), "cognition test executable needs its explicit digest")
        need(args.cognition_tests is None or args.install_windows, "cognition test override requires Windows installation smoke")
        if args.install_windows:
            need(os.name == "nt" and platform.machine().lower() in ("amd64", "x86_64"), "Windows x64 installation smoke requires that actual host")
            need(args.installer_sha256 and args.safety_file and args.safety_sha256, "explicit installer and containment source pins required")
            pin(args.installer_sha256)
            need(sha(plain(args.safety_file), LIMITS["json_bytes"]) == pin(args.safety_sha256), "containment source pin differs before network admission")
        if args.cognition_tests is not None:
            need(sha(plain(args.cognition_tests)) == pin(args.cognition_tests_sha256), "new cognition test executable pin differs before network admission")
        body = None
        if args.finalize_body:
            need(args.body is not None and args.body_sha256 is not None, "reviewed body file and digest required for publication")
            body_path = plain(args.body)
            need(sha(body_path, LIMITS["body_bytes"]) == pin(args.body_sha256), "reviewed release body pin mismatch")
            raw_body = read_bounded(body_path, LIMITS["body_bytes"])
            need(hashlib.sha256(raw_body).hexdigest() == args.body_sha256, "release body changed while reading")
            body = raw_body.decode("utf-8")
        else:
            need(args.body is None and args.body_sha256 is None, "release body input is admitted only with final verify --finalize-body")
        out = new_output(args.out)
        write_new(out / "requested-operation.json", encode(dict(schema="symbiote.public-release-request/1", mode=args.mode,
                  repository=REPOSITORY, tag=TAG, expected_tag_commit=args.commit, archive=str(archive) if archive else None,
                  evidence_sha256=args.evidence_sha256, body_sha256=args.body_sha256, install_windows=args.install_windows,
                  installer_sha256=args.installer_sha256, containment_source_sha256=args.safety_sha256,
                  cognition_test_executable_sha256=args.cognition_tests_sha256,
                  creates_tag_or_release=False, replaces_assets=False)))
        stage = "wait-for-workflow-release"
        release = wait_release(args.commit, args.wait_seconds); assets = asset_map(release)
        write_new(out / "public-release-metadata.json", encode(release))
        if args.mode == "status":
            result = dict(status="WORKFLOW_RELEASE_FOUND_NO_MUTATION", assets=sorted(assets))
        elif args.mode == "publish":
            stage = "publish-reviewed-evidence-assets"; result = publish(args, out, release, assets, archive)
        else:
            stage = "verify-public-assets-and-optional-native-install"; result = verify(args, out, release, assets, archive, body)
        result.update(schema="symbiote.public-v1-release-operation/1", repository=REPOSITORY, tag=TAG,
                      source_commit=args.commit, release_url=release["html_url"], completed_at_unix=time.time(),
                      evidence_sha256=args.evidence_sha256)
        write_new(out / "operation-receipt.json", encode(result)); print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        # Never persist credential-helper output, auth headers or signed CDN URLs.
        detail = str(error) if isinstance(error, ReleaseError) else "operation failed; raw exception text suppressed to avoid credential disclosure"
        result = dict(schema="symbiote.public-v1-release-operation/1", status="HOLD", stage=stage,
                      failure_type=type(error).__name__, detail=detail, repository=REPOSITORY, tag=TAG,
                      automatic_retry=False, failure_artifacts_preserved=True)
        if out is not None and not (out / "operation-receipt.json").exists():
            write_new(out / "operation-receipt.json", encode(result))
        print(json.dumps(result), file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
