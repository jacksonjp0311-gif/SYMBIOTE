"""Offline draft checks only: no real network, credentials or native execution."""
import ast
import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import types
import unittest
from unittest import mock
import urllib.request
import zipfile

HERE = Path(__file__).parent
SOURCE = HERE / "release_v1_candidate.py"
module = types.ModuleType("external_release_v1_draft")
module.__file__ = str(SOURCE)
with mock.patch("subprocess.run", side_effect=AssertionError("no subprocess admitted")), \
        mock.patch("subprocess.Popen", side_effect=AssertionError("no subprocess admitted")), \
        mock.patch("urllib.request.build_opener", side_effect=AssertionError("no network admitted")), \
        mock.patch("http.client.HTTPSConnection", side_effect=AssertionError("no network admitted")):
    exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), module.__dict__)


def release_fixture():
    assets = []
    for index, name in enumerate(sorted(module.NATIVE_NAMES), 1):
        assets.append(dict(id=index, name=name, size=1, digest=None, uploader=dict(login="github-actions[bot]"),
                           browser_download_url="https://github.com/" + module.REPOSITORY + "/releases/download/" + module.TAG + "/" + name))
    return dict(id=77, tag_name=module.TAG, draft=False, prerelease=False,
                author=dict(login="jacksonjp0311-gif"), assets=assets,
                html_url="https://github.com/" + module.REPOSITORY + "/releases/tag/" + module.TAG)


class OfflineDraftTests(unittest.TestCase):
    def test_source_parses_and_import_has_no_operation(self):
        tree = ast.parse(SOURCE.read_bytes())
        self.assertIsInstance(tree, ast.Module)
        self.assertEqual(module.REPOSITORY, "jacksonjp0311-gif/SYMBIOTE")
        self.assertEqual(module.TAG, "v1.0.1")

    def test_public_signed_redirect_drops_auth_and_cookies_and_rejects_other_hosts(self):
        request = urllib.request.Request("https://github.com/example", headers={"Authorization": "synthetic-not-a-real-token", "Cookie": "synthetic=value"})
        redirect = module.PublicAssetRedirect(module.CDN_HOSTS)
        safe = redirect.redirect_request(request, None, 302, "redirect", {}, "https://release-assets.githubusercontent.com/synthetic?public-signature=fixture")
        self.assertFalse(safe.has_header("Authorization"))
        self.assertFalse(safe.has_header("Cookie"))
        for url in ("http://release-assets.githubusercontent.com/file", "https://github.com.attacker.invalid/file",
                    "https://user:password@github.com/file", "https://github.com:444/file"):
            with self.subTest(url=url), self.assertRaises(module.ReleaseError):
                redirect.redirect_request(request, None, 302, "redirect", {}, url)

    def test_authenticated_transport_refuses_other_hosts_routes_and_redirects(self):
        with mock.patch.object(module.http.client, "HTTPSConnection") as connection:
            for url in ("https://release-assets.githubusercontent.com/file", "https://api.github.com/repos/elsewhere/project/releases/1",
                        "https://api.github.com/repos/jacksonjp0311-gif/SYMBIOTE/releases", "http://api.github.com/repos/jacksonjp0311-gif/SYMBIOTE/releases/1"):
                with self.subTest(url=url), self.assertRaises(module.ReleaseError):
                    module.authenticated(url, "PATCH", {}, "synthetic-not-a-real-token")
            connection.assert_not_called()
        connection = mock.MagicMock()
        connection.getresponse.return_value.status = 302
        with mock.patch.object(module.http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaisesRegex(module.ReleaseError, "HTTP 302"):
                module.authenticated(module.BASE + "/releases/77", "PATCH", {"body": "fixture"}, "synthetic-not-a-real-token")
        self.assertEqual(connection.request.call_count, 1)
        connection.close.assert_called_once()
        self.assertEqual(connection.request.call_args.args[0], "PATCH")

    def test_metadata_is_anonymous_cache_busted_and_rejects_redirects(self):
        response = mock.MagicMock(); response.__enter__.return_value = response
        response.read.return_value = b"{}"
        opener = mock.MagicMock(); opener.open.return_value = response
        with mock.patch.object(module.urllib.request, "build_opener", return_value=opener), \
                mock.patch.object(module.time, "time_ns", side_effect=(123, 124)):
            module.metadata("/repos/" + module.REPOSITORY + "/releases/tags/" + module.TAG)
            module.metadata("/repos/" + module.REPOSITORY + "/releases/tags/" + module.TAG)
        requests = [call.args[0] for call in opener.open.call_args_list]
        self.assertNotEqual(requests[0].full_url, requests[1].full_url)
        self.assertTrue(all(not request.has_header("Authorization") for request in requests))
        with self.assertRaises(module.ReleaseError):
            module.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://elsewhere.invalid")

    def test_exact_workflow_native_set_duplicate_and_origin_guards(self):
        release = release_fixture()
        self.assertEqual(set(module.asset_map(release)), module.NATIVE_NAMES)
        for mutation in ("uploader", "draft", "duplicate", "origin"):
            bad = copy.deepcopy(release)
            if mutation == "uploader": bad["assets"][0]["uploader"]["login"] = "manual-fixture"
            if mutation == "draft": bad["draft"] = True
            if mutation == "duplicate": bad["assets"].append(bad["assets"][0])
            if mutation == "origin": bad["assets"][0]["browser_download_url"] = "https://elsewhere.invalid/file"
            with self.subTest(mutation=mutation), self.assertRaises(module.ReleaseError):
                module.asset_map(bad)
        extra = dict(id=99, name="unexpected.txt", size=1, digest=None,
                     browser_download_url="https://github.com/" + module.REPOSITORY + "/releases/download/" + module.TAG + "/unexpected.txt")
        assets = module.asset_map(release); assets["unexpected.txt"] = extra
        with mock.patch.object(module, "download", side_effect=AssertionError("no real or mocked download admission")) as download:
            with self.assertRaisesRegex(module.ReleaseError, "exact requested"):
                module.verify(types.SimpleNamespace(mode="verify-native"), None, release, assets, None, None)
            download.assert_not_called()

    def test_four_synthetic_native_header_shapes_and_flat_zip_contract(self):
        with tempfile.TemporaryDirectory(prefix="rv-static-") as directory:
            root = Path(directory).resolve(strict=True)
            for target, (kind, machine, binary_name) in module.TARGETS.items():
                data = bytearray(80)
                if kind == "pe":
                    data[:2] = b"MZ"; struct.pack_into("<I", data, 60, 64)
                    data[64:68] = b"PE\0\0"; struct.pack_into("<H", data, 68, machine)
                elif kind == "elf":
                    data[:6] = b"\x7fELF\x02\x01"; struct.pack_into("<H", data, 16, 2); struct.pack_into("<H", data, 18, machine)
                else:
                    data[:4] = b"\xcf\xfa\xed\xfe"; struct.pack_into("<I", data, 4, machine); struct.pack_into("<I", data, 12, 2)
                path = root / (target + ".zip")
                with zipfile.ZipFile(path, "x") as bundle:
                    bundle.writestr(binary_name, data)
                    bundle.writestr("LICENSE", "synthetic fixture only")
                    bundle.writestr("README.md", "https://github.com/" + module.REPOSITORY + "/tree/" + module.TAG)
                checked = module.inspect_zip(path, target)
                self.assertEqual(checked["target"], target)
                self.assertEqual(checked["binary_sha256"], hashlib.sha256(data).hexdigest())
                broken = bytearray(data); broken[:4] = b"oops"
                with self.assertRaises(module.ReleaseError):
                    module.native_header(broken, target)

    def test_checksum_sets_and_actual_finite_prediction_contract(self):
        with tempfile.TemporaryDirectory(prefix="rv-check-") as directory:
            root = Path(directory).resolve(strict=True); image = root / "fixture.zip"; image.write_bytes(b"not executed")
            checksum = hashlib.sha256(image.read_bytes()).hexdigest()
            path = root / "SHA256SUMS"; path.write_text(checksum + "  fixture.zip\n", encoding="ascii")
            self.assertEqual(module.checksum_manifest(path, {image.name}), {image.name: checksum})
            path.write_text((checksum + "  fixture.zip\n") * 2, encoding="ascii")
            with self.assertRaises(module.ReleaseError): module.checksum_manifest(path, {image.name})
        value = dict(schema="symbiote.retained/1", status="PASS", network_requests=0, active_artifacts=2,
                     genesis_artifacts=2, structural_artifacts=0, structural_knowledge=[], predictions=[
                         dict(artifact="alpha-table", partner="alpha", revision=1, scope="finite-boolean-v1", predictions=[0, 1, 1, 0]),
                         dict(artifact="beta-table", partner="beta", revision=1, scope="finite-boolean-v1", predictions=[0, 1, 0, 1])])
        module.check_predictions(value)
        for mutation in ("missing", "empty", "wrong", "bool", "count-bool"):
            bad = copy.deepcopy(value)
            if mutation == "missing": bad["predictions"] = []
            if mutation == "empty": bad["predictions"][0]["predictions"] = []
            if mutation == "wrong": bad["predictions"][0]["predictions"][0] = 1
            if mutation == "bool": bad["predictions"][0]["predictions"][0] = False
            if mutation == "count-bool": bad["network_requests"] = False
            with self.subTest(mutation=mutation), self.assertRaises(module.ReleaseError): module.check_predictions(bad)

    @unittest.skipUnless(module.os.name == "nt", "Windows canonical path representation")
    def test_rust_extended_native_path_compares_to_python_installed_path(self):
        with tempfile.TemporaryDirectory(prefix="rv-path-") as directory:
            image = Path(directory).resolve() / "synthetic.exe"; image.write_bytes(b"never executed")
            self.assertTrue(module.same_location(image, "\\\\?\\" + str(image)))


class ReleaseSourceTests(unittest.TestCase):
    def test_windows_installer_module_path_is_child_scoped_and_restored_after_failure(self):
        for initial in (None, "", "C:/Program Files/PowerShell/7/Modules"):
            with self.subTest(initial=initial), mock.patch.dict(module.os.environ, {}, clear=True):
                if initial is not None:
                    module.os.environ["PSModulePath"] = initial
                with self.assertRaisesRegex(RuntimeError, "owned installer failed"):
                    with module.windows_powershell_modules():
                        self.assertNotIn("PSModulePath", module.os.environ)
                        raise RuntimeError("owned installer failed")
                if initial is None:
                    self.assertNotIn("PSModulePath", module.os.environ)
                else:
                    self.assertEqual(module.os.environ["PSModulePath"], initial)

    def test_explicit_tag_changes_all_native_names_and_rejects_unsafe_tags(self):
        try:
            module.configure_tag("v1.2.3")
            self.assertTrue(all("v1.2.3" in name for name in module.ZIP_NAMES))
            for bad in ["main","v1.0.1-rc.1","v1.0.1/other","v1.0.1?x",None]:
                with self.assertRaises(module.ReleaseError):module.configure_tag(bad)
        finally:module.configure_tag("v1.0.1")

    def test_only_successful_matching_tag_source_and_release_workflow_is_admitted(self):
        actual=dict(repository=dict(full_name=module.REPOSITORY),path=".github/workflows/release.yml",
                    head_sha="a"*40,head_branch=module.TAG,event="push",status="completed",conclusion="success",
                    html_url="https://github.com/"+module.REPOSITORY+"/actions/runs/1")
        with mock.patch.object(module,"metadata",return_value=actual):
            self.assertEqual(module.verify_release_workflow(1,"a"*40)["conclusion"],"success")
        for key,value in [("path",".github/workflows/ci.yml"),("head_sha","b"*40),("head_branch","main"),
                          ("conclusion","failure"),("status","in_progress"),("event","pull_request"),("event","workflow_dispatch")]:
            changed={**actual,key:value}
            with self.subTest(key=key),mock.patch.object(module,"metadata",return_value=changed):
                with self.assertRaises(module.ReleaseError):module.verify_release_workflow(1,"a"*40)


if __name__ == "__main__":
    unittest.main(verbosity=2)
