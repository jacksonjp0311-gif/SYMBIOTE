"""Release integrity checks: architecture, tag binding, immutable assets and tamper detection."""
import struct
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import package_release as release


def image(target):
    data = bytearray(128)
    kind, machine, _ = release.TARGETS[target]
    if kind == "pe":
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 60, 80)
        data[80:84] = b"PE\0\0"
        struct.pack_into("<H", data, 84, machine)
    if kind == "elf":
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HH", data, 16, 3, machine)
    if kind == "macho":
        data[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<I", data, 4, machine)
        struct.pack_into("<I", data, 12, 2)
    return bytes(data)


class ReleasePackagingTests(unittest.TestCase):
    def test_target_label_cannot_disagree_with_binary_cpu_or_format(self):
        for target in release.TARGETS:
            data = image(target)
            release.binary_target(data, target)
            for other in release.TARGETS:
                if other != target:
                    with self.assertRaisesRegex(ValueError, "format/CPU"):
                        release.binary_target(data, other)
        with self.assertRaises(ValueError):
            release.binary_target(b"truncated", "x86_64-pc-windows-msvc")

    def test_package_validates_native_version_and_refuses_asset_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            binary = base / "binary"
            binary.write_bytes(image("x86_64-pc-windows-msvc"))
            result = subprocess.CompletedProcess([], 0, "SYMBIOTE 0.2.0\n", "")
            with patch.object(release.subprocess, "run", return_value=result):
                path = release.package(binary, "x86_64-pc-windows-msvc", "v0.2.0", base / "release")
                self.assertEqual(release.verify_directory(path.parent, "v0.2.0")["bundles"], 1)
                with zipfile.ZipFile(path) as archive:
                    readme = archive.read("README.md").decode("utf-8")
                    self.assertIn(".\\symbiote.exe demo", readme)
                    self.assertIn("./symbiote demo", readme)
                    self.assertIn("https://github.com/jacksonjp0311-gif/SYMBIOTE/tree/v0.2.0/docs/OPERATIONS.md", readme)
                    self.assertNotIn('src="docs/', readme)
                    self.assertNotIn("](docs/", readme)
                with self.assertRaises(FileExistsError):
                    release.package(binary, "x86_64-pc-windows-msvc", "v0.2.0", base / "release")
            bad_version = subprocess.CompletedProcess([], 0, "SYMBIOTE 9.9.9\n", "")
            with patch.object(release.subprocess, "run", return_value=bad_version):
                with self.assertRaisesRegex(ValueError, "version"):
                    release.package(binary, "x86_64-pc-windows-msvc", "v0.2.0", base / "bad")
            self.assertFalse((base / "bad").exists())

    def test_archive_traversal_duplicate_and_symlink_entries_are_refused(self):
        for unsafe in ["../symbiote", "nested/symbiote", "symbiote"]:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "symbiote-v0.2.0-x86_64-unknown-linux-gnu.zip"
                with zipfile.ZipFile(path, "w") as archive:
                    info = zipfile.ZipInfo(unsafe)
                    if unsafe == "symbiote":
                        info.create_system = 3
                        info.external_attr = 0o120777 << 16
                    archive.writestr(info, image("x86_64-unknown-linux-gnu"))
                    archive.writestr("LICENSE", "license")
                    archive.writestr("README.md", "readme")
                with self.assertRaises(ValueError):
                    release.inspect_bundle(path, "v0.2.0")

    def test_manifest_detects_tampering_missing_platform_and_duplicate_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            path = base / "symbiote-v0.2.0-x86_64-unknown-linux-gnu.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("symbiote", image("x86_64-unknown-linux-gnu"))
                archive.writestr("LICENSE", "license")
                archive.writestr("README.md", "readme")
            release.verify_directory(base, "v0.2.0", write_manifest=True)
            manifest = base / "SHA256SUMS"
            original = manifest.read_text()
            manifest.write_text(original + original)
            with self.assertRaisesRegex(ValueError, "duplicate"):
                release.verify_directory(base, "v0.2.0")
            manifest.write_text(original.replace(original[:64], "0" * 64))
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                release.verify_directory(base, "v0.2.0")
            manifest.write_text(original)
            with self.assertRaisesRegex(ValueError, "missing a required"):
                release.verify_directory(base, "v0.2.0", require_targets=["aarch64-apple-darwin"])


if __name__ == "__main__":
    unittest.main()
