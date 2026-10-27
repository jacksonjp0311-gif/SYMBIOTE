"""Build and verify flat, architecture-checked release bundles with SHA256SUMS.

Checksums establish release-file integrity. They are not signatures or proof of
publisher identity. Native packaging also executes --version before accepting a
binary; a cross-platform verification reads file headers without executing it.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "x86_64-pc-windows-msvc": ("pe", 0x8664, "symbiote.exe"),
    "x86_64-unknown-linux-gnu": ("elf", 62, "symbiote"),
    "aarch64-apple-darwin": ("macho", 0x0100000C, "symbiote"),
    "x86_64-apple-darwin": ("macho", 0x01000007, "symbiote"),
}
MAX_BINARY = 100 * 1024 * 1024
VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\Z")


def validate_version(version):
    if not VERSION.fullmatch(version):
        raise ValueError("version must be a release tag such as v0.2.0")


def binary_target(data, target):
    """Reject a binary whose native format or CPU disagrees with its asset name."""
    if target not in TARGETS:
        raise ValueError("unsupported release target")
    if len(data) > MAX_BINARY or len(data) < 32:
        raise ValueError("binary is empty, truncated, or exceeds the release limit")
    kind, machine, _ = TARGETS[target]
    valid = False
    if kind == "pe" and len(data) >= 64 and data[:2] == b"MZ":
        offset = struct.unpack_from("<I", data, 60)[0]
        valid = (offset + 6 <= len(data) and data[offset:offset+4] == b"PE\0\0"
                 and struct.unpack_from("<H", data, offset + 4)[0] == machine)
    if kind == "elf" and data[:6] == b"\x7fELF\x02\x01":
        valid = (struct.unpack_from("<H", data, 16)[0] in (2, 3)
                 and struct.unpack_from("<H", data, 18)[0] == machine)
    if kind == "macho" and data[:4] == b"\xcf\xfa\xed\xfe":
        valid = (struct.unpack_from("<I", data, 4)[0] == machine
                 and struct.unpack_from("<I", data, 12)[0] == 2)
    if not valid:
        raise ValueError(f"binary format/CPU does not match {target}")


def digest(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def atomic_text(path, text):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=path.parent, prefix=".symbiote-", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def inspect_bundle(path, version):
    validate_version(version)
    prefix = f"symbiote-{version}-"
    if not path.name.startswith(prefix) or not path.name.endswith(".zip"):
        raise ValueError(f"unexpected bundle name: {path.name}")
    target = path.name[len(prefix):-4]
    if target not in TARGETS:
        raise ValueError(f"unsupported bundle target: {target}")
    binary_name = TARGETS[target][2]
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) != 3 or {entry.filename for entry in entries} != {binary_name, "LICENSE", "README.md"}:
            raise ValueError("release bundle must contain exactly one flat binary, LICENSE and README.md")
        if any(entry.file_size > MAX_BINARY or entry.is_dir() for entry in entries):
            raise ValueError("release archive exceeds limits or contains a directory")
        if any(((entry.external_attr >> 16) & 0o170000) == 0o120000 for entry in entries):
            raise ValueError("symbolic links are forbidden in release archives")
        if archive.testzip() is not None:
            raise ValueError("release archive CRC failure")
        binary_target(archive.read(binary_name), target)
    return target


def verify_directory(directory, version, *, write_manifest=False, require_targets=()):
    validate_version(version)
    bundles = sorted(directory.glob("*.zip"))
    if not bundles:
        raise ValueError("no release ZIP bundles found")
    targets = [inspect_bundle(path, version) for path in bundles]
    if len(targets) != len(set(targets)):
        raise ValueError("duplicate release targets")
    if not set(require_targets).issubset(targets):
        raise ValueError("release is missing a required platform bundle")
    expected = {path.name: digest(path) for path in bundles}
    manifest = directory / "SHA256SUMS"
    if write_manifest:
        atomic_text(manifest, "".join(f"{checksum}  {name}\n" for name, checksum in sorted(expected.items())))
    if not manifest.is_file():
        raise ValueError("SHA256SUMS is missing")
    recorded = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        fields = line.split(maxsplit=1)
        if len(fields) != 2 or not re.fullmatch(r"[0-9a-f]{64}", fields[0]):
            raise ValueError("invalid checksum manifest line")
        name = fields[1]
        if name in recorded or Path(name).name != name:
            raise ValueError("duplicate or unsafe checksum manifest entry")
        recorded[name] = fields[0]
    if recorded != expected:
        raise ValueError("checksum mismatch, missing bundle, or unexpected manifest entry")
    return dict(version=version, targets=targets, bundles=len(bundles), checksums="verified", signatures="not provided")


def native_readme(version):
    """A flat native archive needs instructions independent of checkout files."""
    project = f"https://github.com/jacksonjp0311-gif/SYMBIOTE/tree/{version}"
    return f"""# SYMBIOTE {version}

Symbiotic Adaptive Intelligence — native Rust reasoning and evaluated persistent
knowledge. The local demonstrations need no language model, API key, Rust or
Python installation.

Extract all three files into a writable folder. Open a terminal in that folder.

**Windows PowerShell**

```powershell
.\\symbiote.exe doctor
.\\symbiote.exe demo
.\\symbiote.exe predict
```

**Linux or macOS**

```sh
chmod +x ./symbiote
./symbiote doctor
./symbiote demo
./symbiote predict
```

Run `demo` again to observe retained knowledge being reused. Keep the same working
folder: default state is `state/demo` beneath it. Use `--state PATH` to select a
persistent location explicitly. `predict` uses retained knowledge without network
requests. `--help` lists commands; `--json` provides machine-readable receipts.
`network-research` runs separately supervised local peers.

This is bounded research software. A passing demonstration does not establish
general intelligence, better partner selection or universal transfer efficiency.
External connections require explicit operator-provisioned identities, TLS
credentials, pins and permissions.

[Full project README and original graphic]({project}#readme) ·
[Installation, operations and recovery]({project}/docs/OPERATIONS.md) ·
[Security and trust boundary]({project}/docs/SECURITY.md) ·
[Research roadmap]({project}/docs/ROADMAP.md)

The original release archive is covered by `SHA256SUMS` on the
[release page](https://github.com/jacksonjp0311-gif/SYMBIOTE/releases/tag/{version}).
Keep the included LICENSE. BRUTE ancestry, exact upstream references and the
retained-reference licensing exception are documented in the full repository.
""".encode("utf-8")


def package(binary, target, version, out):
    validate_version(version)
    if target not in TARGETS:
        raise ValueError("unsupported release target")
    if not binary.is_file() or binary.stat().st_size > MAX_BINARY:
        raise ValueError("binary missing or exceeds release size limit")
    data = binary.read_bytes()
    binary_target(data, target)
    try:
        result = subprocess.run([str(binary.resolve()), "--version"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"cannot validate native executable version: {error}") from error
    if result.returncode != 0 or result.stdout.strip() != f"SYMBIOTE {version[1:]}":
        raise ValueError("binary version does not match the release tag")
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"symbiote-{version}-{target}.zip"
    files = [(TARGETS[target][2], data, 0o100755), ("LICENSE", (ROOT / "LICENSE").read_bytes(), 0o100644), ("README.md", native_readme(version), 0o100644)]
    # Exclusive creation prevents a mislabeled or previously published asset
    # from being overwritten by a repeat invocation.
    with path.open("xb") as destination:
        try:
            with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
                for name, contents, mode in files:
                    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    info.create_system = 3
                    info.external_attr = mode << 16
                    archive.writestr(info, contents, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        except BaseException:
            destination.close()
            path.unlink(missing_ok=True)
            raise
    inspect_bundle(path, version)
    verify_directory(out, version, write_manifest=True)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--target", choices=sorted(TARGETS))
    parser.add_argument("--version", required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "experiments" / "local" / "release")
    parser.add_argument("--verify-dir", type=Path)
    parser.add_argument("--write-manifest", action="store_true")
    parser.add_argument("--require-target", action="append", default=[], choices=sorted(TARGETS))
    args = parser.parse_args()
    if args.verify_dir:
        result = verify_directory(args.verify_dir, args.version, write_manifest=args.write_manifest, require_targets=args.require_target)
    else:
        if not args.binary or not args.target:
            parser.error("packaging requires --binary and --target")
        if args.write_manifest or args.require_target:
            parser.error("--write-manifest and --require-target apply to --verify-dir")
        archive = package(args.binary, args.target, args.version, args.out)
        result = dict(archive=str(archive), sha256=digest(archive), **verify_directory(args.out, args.version))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
