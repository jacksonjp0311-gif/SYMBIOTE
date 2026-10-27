"""Exercise native installation and failure preservation with actual local bundles.

Build the native executable first. No release, network, PATH or administrator
changes are needed: bundles and installed binaries stay in a temporary fixture.
"""
import hashlib
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import package_release as release

ROOT = Path(__file__).resolve().parents[1]


class NativeInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native = (sys.platform, platform.machine().lower())
        targets = {("win32", "amd64"): "x86_64-pc-windows-msvc", ("linux", "x86_64"): "x86_64-unknown-linux-gnu", ("darwin", "arm64"): "aarch64-apple-darwin", ("darwin", "x86_64"): "x86_64-apple-darwin"}
        cls.target = targets.get(native)
        if not cls.target:
            raise unittest.SkipTest("native release bundle is unsupported on this test host")
        cls.executable_name = release.TARGETS[cls.target][2]
        cls.binary = ROOT / "target" / "debug" / cls.executable_name
        if not cls.binary.is_file():
            raise unittest.SkipTest("cargo build --workspace is required before native installer tests")
        output = subprocess.check_output([str(cls.binary), "--version"], text=True).strip()
        cls.version = "v" + output.removeprefix("SYMBIOTE ")
        release.validate_version(cls.version)
        cls.shell = shutil.which("pwsh") or shutil.which("powershell") if sys.platform == "win32" else shutil.which("sh")
        if not cls.shell:
            raise unittest.SkipTest("native installer shell unavailable")

    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory(prefix="symbiote-installer-test-")
        self.base = Path(self.fixture.name)
        self.bundle = self.base / "bundle"
        self.archive = release.package(self.binary, self.target, self.version, self.bundle)
        self.installed = self.base / "installed"

    def tearDown(self):
        self.fixture.cleanup()

    def install(self, version=None):
        if sys.platform == "win32":
            args = [self.shell, "-NoProfile", "-NonInteractive", "-File", str(ROOT / "tools" / "install.ps1"), "-Version", version or self.version, "-BundleDirectory", str(self.bundle), "-InstallDir", str(self.installed)]
        else:
            args = [self.shell, str(ROOT / "tools" / "install.sh"), "--version", version or self.version, "--bundle-dir", str(self.bundle), "--install-dir", str(self.installed)]
        return subprocess.run(args, text=True, capture_output=True, timeout=30, check=False)

    def successful_install(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        binary = self.installed / self.executable_name
        actual = subprocess.check_output([str(binary), "--version"], text=True).strip()
        self.assertEqual(actual, "SYMBIOTE " + self.version[1:])
        return binary.read_bytes()

    def test_native_bundle_installs_without_network_or_path_changes(self):
        self.successful_install()

    def test_checksum_failure_preserves_existing_installation(self):
        before = self.successful_install()
        with self.archive.open("ab") as stream:
            stream.write(b"tampered")
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA256 mismatch", result.stdout + result.stderr)
        self.assertEqual((self.installed / self.executable_name).read_bytes(), before)

    def test_unsafe_zip_entry_is_refused_even_with_matching_checksum(self):
        before = self.successful_install()
        with zipfile.ZipFile(self.archive, "a") as archive:
            archive.writestr("../outside.txt", "must never be extracted")
        (self.bundle / "SHA256SUMS").write_text(f"{release.digest(self.archive)}  {self.archive.name}\n", encoding="utf-8")
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.installed / self.executable_name).read_bytes(), before)
        self.assertFalse((self.base / "outside.txt").exists())

    def test_mislabeled_version_is_rejected_before_replacing_binary(self):
        before = self.successful_install()
        false_version = "v99.99.99"
        renamed = self.bundle / f"symbiote-{false_version}-{self.target}.zip"
        renamed.write_bytes(self.archive.read_bytes())
        (self.bundle / "SHA256SUMS").write_text(f"{hashlib.sha256(renamed.read_bytes()).hexdigest()}  {renamed.name}\n", encoding="utf-8")
        result = self.install(false_version)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("version", (result.stdout + result.stderr).lower())
        self.assertEqual((self.installed / self.executable_name).read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
