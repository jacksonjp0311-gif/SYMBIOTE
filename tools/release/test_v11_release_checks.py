"""Offline release boundary fixtures; synthetic executables are never run."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
import importlib.util
import marshal
import struct

SOURCE = Path(__file__).with_name("v11_release_checks.py")
m = types.ModuleType("v11_release_fixture")
m.__file__ = str(SOURCE)
exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), m.__dict__)


def cargo_fixture():
    packages = [{"id": name, "name": name, "version": "1.1.0" if name.startswith("symbiote-") else "1.0.0",
                 "source": None if name.startswith("symbiote-") else "registry+https://github.com/rust-lang/crates.io-index",
                 "license": "MIT"} for name in ("symbiote-runtime", "symbiote-memory", "serde", "dev-only", "build-only")]
    nodes = [{"id": item["id"], "features": [], "deps": []} for item in packages]
    nodes[0]["deps"] = [{"pkg": "symbiote-memory", "dep_kinds": [{"kind": None}]},
                        {"pkg": "dev-only", "dep_kinds": [{"kind": "dev"}]},
                        {"pkg": "build-only", "dep_kinds": [{"kind": "build"}]}]
    nodes[1]["deps"] = [{"pkg": "serde", "dep_kinds": [{"kind": None}]}]
    metadata = {"packages": packages, "workspace_members": ["symbiote-runtime", "symbiote-memory"], "resolve": {"nodes": nodes}}
    lock = "version = 4\n"
    for item in packages:
        lock += '\n[[package]]\nname = "' + item["name"] + '"\nversion = "' + item["version"] + '"\n'
        if item["source"]:
            lock += 'source = "' + item["source"] + '"\nchecksum = "' + "a" * 64 + '"\n'
    return metadata, lock.encode()


class MetadataBoundaryTests(unittest.TestCase):
    def test_normal_build_closure_excludes_dev_only_packages(self):
        metadata, lock = cargo_fixture()
        bom, features = m.cargo_sbom(metadata, lock, "x86_64-unknown-linux-gnu", "b" * 64, "c" * 40)
        components = [bom["metadata"]["component"], *bom["components"]]
        self.assertEqual({item["name"] for item in components}, {"symbiote-runtime", "symbiote-memory", "serde", "build-only"})
        self.assertEqual(features, [])
        self.assertNotIn('"name": "dev-only"', json.dumps(bom))
        self.assertEqual(bom["metadata"]["component"]["hashes"], [{"alg": "SHA-256", "content": "b" * 64}])
        self.assertIn("excludes dev-only and system/toolchain", json.dumps(bom))

    def test_sbom_does_not_expose_absolute_host_package_ids(self):
        metadata, lock = cargo_fixture()
        for item in metadata["packages"]:
            item["id"] = "C:\\private-host\\" + item["id"]
        for item in metadata["resolve"]["nodes"]:
            item["id"] = "C:\\private-host\\" + item["id"]
            for edge in item["deps"]:
                edge["pkg"] = "C:\\private-host\\" + edge["pkg"]
        metadata["workspace_members"] = ["C:\\private-host\\" + value for value in metadata["workspace_members"]]
        bom, _ = m.cargo_sbom(metadata, lock, "x86_64-unknown-linux-gnu", "b" * 64, "c" * 40)
        self.assertNotIn("private-host", json.dumps(bom))

    def test_lock_mismatch_missing_resolution_and_bad_registry_checksum_rejected(self):
        metadata, lock = cargo_fixture()
        variants = [lock.replace(b'name = "serde"', b'name = "different"'),
                    lock.replace(b'checksum = "' + b"a" * 64, b'checksum = "short')]
        for altered in variants:
            with self.subTest(lock=altered), self.assertRaises((ValueError, KeyError)):
                m.cargo_sbom(metadata, altered, "target", "b" * 64, "c" * 40)
        metadata["resolve"]["nodes"] = metadata["resolve"]["nodes"][:-1]
        with self.assertRaisesRegex(ValueError, "incomplete"):
            m.normal_closure(metadata)

    def test_duplicate_json_and_nonfinite_numbers_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                m.parse(raw)

    def test_read_refuses_file_changed_during_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "bytes"
            path.write_bytes(b"before")
            original = Path.read_bytes

            def mutate(selected):
                value = original(selected)
                selected.write_bytes(b"changed and larger")
                return value

            with mock.patch.object(Path, "read_bytes", mutate), self.assertRaisesRegex(ValueError, "changed"):
                m.read(path)

    def test_os_temp_alias_normalized_without_weakening_selected_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            destination = base / "new-evidence"
            original = Path.resolve

            def resolve(path, *args, **kwargs):
                if str(path) == "os-owned-temp-alias":
                    return base
                return original(path, *args, **kwargs)

            with mock.patch("tempfile.gettempdir", return_value="os-owned-temp-alias"), mock.patch.object(Path, "resolve", resolve):
                self.assertEqual(m.fresh(destination), destination)
            with self.assertRaisesRegex(ValueError, "fresh"):
                m.fresh(destination)

    def test_source_or_compiler_mismatch_rejected_before_metadata(self):
        args = types.SimpleNamespace(version="v1.1.0", commit="c" * 40)
        with mock.patch.object(m, "command_text", return_value="d" * 40), self.assertRaisesRegex(ValueError, "clean exact"):
            m.metadata(args)

    def test_loaded_helper_uses_checked_source_not_valid_poisoned_bytecache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "helper.py"; source.write_bytes(b"value = 'reviewed source'\n")
            details = source.stat()
            cached = Path(importlib.util.cache_from_source(str(source)))
            cached.parent.mkdir()
            poison = compile("raise RuntimeError('UNPINNED_BYTECODE_EXECUTED')", str(source), "exec")
            raw = (importlib.util.MAGIC_NUMBER + struct.pack("<III", 0, int(details.st_mtime), details.st_size)
                   + marshal.dumps(poison))
            cached.write_bytes(raw)
            helpers_before = dict(m.LOADED_HELPERS)
            try:
                selected = m.load_local("selected_fixture_helper", source)
                self.assertEqual(selected.value, "reviewed source")
                self.assertEqual(m.LOADED_HELPERS[source.name], m.sha(source))
                self.assertEqual(cached.read_bytes(), raw)
            finally:
                m.LOADED_HELPERS.clear(); m.LOADED_HELPERS.update(helpers_before)


class InstalledAcceptanceTests(unittest.TestCase):
    @staticmethod
    def observation():
        return {"schema": "symbiote.observation-demo/1", "status": "PASS", "network_requests": 0, "language_model": False,
                "source":"explicitly owned deterministic three-bit affine observation source",
                "source_sha256":hashlib.sha256(b"owned-synthetic-affine/3-bit-xor5-bias1/v1").hexdigest(),
                "artifact":"standalone-active-affine","snapshot":dict(family="boolean-affine/v1",width=3,
                    physical_certificate_authorized=False,conditional_strategy=dict(kind="affine",width=3,coefficients=5,bias=True)),
                "predictions": [{"input": value, "prediction": ((value & 5).bit_count() % 2)^1} for value in range(8)]}

    def test_actual_owned_finite_domain_checked_not_producer_pass(self):
        report = self.observation()
        m.inspect_prediction(report)
        variants = []
        altered = copy.deepcopy(report); altered["predictions"][3]["prediction"] ^= 1; variants.append(altered)
        altered = copy.deepcopy(report); altered["predictions"].pop(); variants.append(altered)
        altered = copy.deepcopy(report); altered["predictions"][0]["input"] = False; variants.append(altered)
        altered = copy.deepcopy(report); altered["predictions"][0]["prediction"] = False; variants.append(altered)
        altered = copy.deepcopy(report); altered["network_requests"] = 1; variants.append(altered)
        altered = copy.deepcopy(report); altered["source_sha256"] = "a"*64; variants.append(altered)
        altered = copy.deepcopy(report); altered["artifact"] = "different-owner-fixture"; variants.append(altered)
        altered = copy.deepcopy(report); altered["snapshot"]["physical_certificate_authorized"] = True; variants.append(altered)
        altered = copy.deepcopy(report); altered["predictions"] = [{"input":value,"prediction":(value&3).bit_count()%2}for value in range(8)]; variants.append(altered)
        for item in variants:
            with self.subTest(item=item), self.assertRaises(ValueError):
                m.inspect_prediction(item)

    def test_wrong_host_refused_without_running_installer(self):
        args = types.SimpleNamespace(target="different-target")
        with mock.patch.object(m.safety, "execute", side_effect=AssertionError("must not run")), self.assertRaisesRegex(ValueError, "actual host"):
            m.acceptance(args)

    def test_import_starts_no_native_process_or_network(self):
        isolated = types.ModuleType("v11_import_only"); isolated.__file__ = str(SOURCE)
        with mock.patch("subprocess.run", side_effect=AssertionError("no process")), \
                mock.patch("subprocess.Popen", side_effect=AssertionError("no process")):
            exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), isolated.__dict__)
        self.assertTrue(callable(isolated.acceptance))

    def test_export_requires_exact_image_pins_and_closed_byte_census(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            member = root / "raw.json"; member.write_bytes(b'{"actual":"native recorded bytes"}\n')
            manifest = {"schema": "fixture/1", "native_sha256": "a" * 64, "driver_sha256": "b" * 64,
                        "private_keys_copied": False, "files": [{"path": member.name, "bytes": member.stat().st_size, "sha256": m.sha(member)}]}

            def save(value):
                (root / "manifest.json").write_text(json.dumps(value), encoding="utf-8")

            save(manifest)
            m.verify_export(root, "manifest.json", "fixture/1", "a" * 64, "b" * 64)
            for field in ("native_sha256", "driver_sha256"):
                changed = copy.deepcopy(manifest); changed[field] = "c" * 64; save(changed)
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, "source images"):
                    m.verify_export(root, "manifest.json", "fixture/1", "a" * 64, "b" * 64)
            for path in ("../raw.json", "/absolute", "C:/outside", "sub\\member", "./raw.json"):
                changed = copy.deepcopy(manifest); changed["files"][0]["path"] = path; save(changed)
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unsafe"):
                    m.verify_export(root, "manifest.json", "fixture/1", "a" * 64, "b" * 64)
            save(manifest)
            (root / "unlisted.json").write_bytes(b"{}");
            with self.assertRaisesRegex(ValueError, "omitted"):
                m.verify_export(root, "manifest.json", "fixture/1", "a" * 64, "b" * 64)
            (root / "unlisted.json").unlink()
            member.write_bytes(b"tampered same producer status PASS")
            with self.assertRaisesRegex(ValueError, "byte census"):
                m.verify_export(root, "manifest.json", "fixture/1", "a" * 64, "b" * 64)

    def test_driver_selection_distinguishes_native_image_and_test_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            image = root / "service-tests.exe"; image.write_bytes(b"synthetic fixture never executed")
            native = {"reason": "compiler-artifact", "target": {"name": "symbiote"}, "profile": {"test": False}, "executable": str(image)}
            selected = {"reason": "compiler-artifact", "target": {"name": "service"}, "profile": {"test": True}, "executable": str(image)}
            path = root / "cargo.jsonl"
            path.write_text(json.dumps(native) + "\n" + json.dumps(selected) + "\n", encoding="utf-8")
            self.assertEqual(m.selected_driver(path), {"path": str(image), "sha256": m.sha(image)})
            for rows in ([native], [selected, selected]):
                path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
                with self.subTest(rows=rows), self.assertRaisesRegex(ValueError, "exactly one"):
                    m.selected_driver(path)

    def test_stage_seal_preserves_attestation_bytes_and_refuses_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            prefix = "symbiote-v1.1.0-x86_64-unknown-linux-gnu"
            for suffix in (".zip", ".build.json", ".cdx.json", ".provenance-verification.json", ".sbom-verification.json"):
                (root / (prefix + suffix)).write_bytes(b"synthetic selected source bytes")
            raw = b'{"mediaType":"synthetic untouched offline bundle"}\r\n'
            source = root / "attestation.json"; source.write_bytes(raw)
            m.preserve_attestation(source, root / (prefix + ".provenance.sigstore.json"))
            m.preserve_attestation(source, root / (prefix + ".sbom.sigstore.json"))
            with self.assertRaises(FileExistsError):
                m.preserve_attestation(source, root / (prefix + ".provenance.sigstore.json"))
            args = types.SimpleNamespace(out=root, version="v1.1.0", target="x86_64-unknown-linux-gnu")
            receipt = m.seal_stage(args)
            self.assertEqual(len(receipt["files"]), 7)
            self.assertEqual((root / (prefix + ".provenance.sigstore.json")).read_bytes(), raw)
            self.assertEqual((root / (prefix + ".sbom.sigstore.json")).read_bytes(), raw)
            with self.assertRaises(FileExistsError):
                m.seal_stage(args)
            sums = (root / receipt["checksums"]).read_text(encoding="ascii")
            self.assertIn(hashlib.sha256(raw).hexdigest() + "  " + prefix + ".sbom.sigstore.json", sums)

    def test_new_engine_cli_rejects_fabricated_learning_without_source_access(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            def call(label,argv,**kwargs):
                if label.endswith("init"):
                    return json.dumps(dict(schema="symbiote.engine-cli/1",status="PASS",inspection=dict(owner="native-owner")))
                return json.dumps(dict(schema="symbiote.engine-cli/1",status="PASS",result=dict(learning=dict(artifact="model",usage=dict(source_calls=5),reused=False)),
                                       source_access=dict(calls=0,file_opened=False)))
            with self.assertRaisesRegex(ValueError,"actual installed public-API learning"):
                m.typed_engine_lifecycle("synthetic-never-executed",root,call)
            frames=json.loads((root/"engine-observations.json").read_bytes())
            self.assertEqual(len(frames),5)
            self.assertNotIn(6,[row["input"] for row in frames])

    def test_evidence_stage_copy_is_exact_and_rejects_writers(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory).resolve();repo=base/"repo";repo.mkdir();(repo/"dist").mkdir()
            installed=base/"installed";installed.mkdir();member=installed/"acceptance.json";member.write_bytes(b'{"status":"unit"}\r\n')
            embedded=base/"embedding";embedded.mkdir();(embedded/"consumer.exe").write_bytes(b"synthetic never run")
            args=types.SimpleNamespace(installed=installed,embedding=embedded,out=repo/"dist"/"first")
            with mock.patch.object(m,"ROOT",repo):receipt=m.stage_acceptance(args)
            self.assertEqual((args.out/"installed/acceptance.json").read_bytes(),member.read_bytes())
            self.assertEqual(receipt["copies"][0]["status"],"PASS_BYTE_COPY_ONLY")
            original=m.read;calls=[0]
            def mutate(path):
                raw=original(path)
                if Path(path)==member:
                    calls[0]+=1
                    if calls[0]==2:member.write_bytes(b"changed after staged read")
                return raw
            args.out=repo/"dist"/"changed"
            with mock.patch.object(m,"ROOT",repo),mock.patch.object(m,"read",side_effect=mutate),self.assertRaisesRegex(ValueError,"evidence changed"):
                m.stage_acceptance(args)
            self.assertFalse((args.out/"copy-witness.json").exists())


class SourceCiTests(unittest.TestCase):
    @staticmethod
    def fixture():
        run=dict(id=123,repository=dict(full_name=m.REPOSITORY),head_repository=dict(full_name=m.REPOSITORY),head_branch="main",head_sha="a"*40,
                 event="push",path=".github/workflows/ci.yml",status="completed",conclusion="success",run_attempt=1)
        expected={"verify (ubuntu-latest)":["Run python tools/verify.py","Document the supported API on the minimum compiler"],
                  "verify (windows-latest)":["Run python tools/verify.py","Document the supported API on the minimum compiler"],
                  "verify (macos-latest)":["Run python tools/verify.py","Document the supported API on the minimum compiler"],
                  "Current stable compatibility":["Run cargo test --workspace --all-features --locked","Run cargo clippy --workspace --all-targets --all-features --locked -- -D warnings"]}
        jobs=dict(total_count=4,jobs=[dict(id=index+1,name=name,run_id=123,head_sha="a"*40,run_attempt=1,status="completed",conclusion="success",
                                        steps=[dict(name=step,status="completed",conclusion="success") for step in steps])for index,(name,steps)in enumerate(expected.items())])
        return run,jobs

    def test_only_exact_official_push_source_and_complete_successful_jobs_reused(self):
        run,jobs=self.fixture();self.assertEqual(m.verify_source_ci(run,jobs,"a"*40,"123")["status"],"PASS_OFFICIAL_SOURCE_CI")
        for field,value in (("event","workflow_dispatch"),("head_sha","b"*40),("head_branch","feature"),("path",".github/workflows/other.yml"),("conclusion","failure")):
            altered=copy.deepcopy(run);altered[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):m.verify_source_ci(altered,jobs,"a"*40,"123")
        for change in ("missing-platform","wrong-attempt","skipped-verifier","failed-stable"):
            altered=copy.deepcopy(jobs)
            if change=="missing-platform":altered["jobs"].pop()
            if change=="wrong-attempt":altered["jobs"][0]["run_attempt"]=2
            if change=="skipped-verifier":altered["jobs"][0]["steps"][0]["conclusion"]="skipped"
            if change=="failed-stable":altered["jobs"][3]["conclusion"]="failure"
            with self.subTest(change=change),self.assertRaises(ValueError):m.verify_source_ci(run,altered,"a"*40,"123")


class PublicDeliveryTests(unittest.TestCase):
    def fixture(self,root):
        target=m.host_target();prefix="symbiote-v1.1.0-"+target
        candidate=root/"candidate";candidate.mkdir();gh=root/"gh.exe";gh.write_bytes(b"synthetic never executed")
        retained=candidate/"acceptance"/target
        (retained/"installed/native-outcomes").mkdir(parents=True)
        (retained/"embedding/executables").mkdir(parents=True)
        (retained/"installed/native-outcomes/service-tests.exe").write_bytes(b"source-bound synthetic driver")
        consumer=retained/"embedding/executables"/("embedding-consumer.exe"if os.name=="nt"else"embedding-consumer")
        consumer.write_bytes(b"source-bound synthetic consumer")
        native=dict(status="PASS_INSTALLED_NATIVE_LIFECYCLE",source_commit="a"*40,
                    service_test_driver_sha256=m.sha(retained/"installed/native-outcomes/service-tests.exe"))
        embedded=dict(status="PASS_INDEPENDENT_EMBEDDING_LIFECYCLE",source_commit="a"*40,binary_sha256=m.sha(consumer))
        m.write_new(retained/"installed/acceptance.json",native);m.write_new(retained/"embedding/embedding-acceptance.json",embedded)
        build=dict(source_commit="a"*40,version="v1.1.0",target=target,compiler_locked="1.98.1",
            proofs=[dict(name=name,sha256=m.sha(path))for name,path in (("acceptance.json",retained/"installed/acceptance.json"),
                    ("embedding-acceptance.json",retained/"embedding/embedding-acceptance.json"))])
        suffixes=(".zip",".build.json",".cdx.json",".provenance.sigstore.json",".sbom.sigstore.json",
                  ".provenance-verification.json",".sbom-verification.json")
        payloads={prefix+suffix:(m.canonical(build)if suffix==".build.json"else b"synthetic never executed "+suffix.encode())for suffix in suffixes}
        payloads["STAGED_SHA256SUMS-"+target]="".join(hashlib.sha256(payloads[prefix+suffix]).hexdigest()+"  "+prefix+suffix+"\n"for suffix in suffixes).encode()
        for name,raw in payloads.items():(candidate/name).write_bytes(raw)
        bundle_sha=m.sha(candidate/(prefix+".zip"))
        # The public four-target manifest deliberately differs from the one-ZIP
        # candidate manifest. Both original byte streams must remain untouched.
        (candidate/"SHA256SUMS").write_text(bundle_sha+"  "+prefix+".zip\n",encoding="ascii")
        payloads["SHA256SUMS"]="".join((bundle_sha if item==target else "d"*64)+"  symbiote-v1.1.0-"+item+".zip\n"for item in sorted(m.bundles.TARGETS)).encode()
        release=dict(id=123,tag_name="v1.1.0",draft=False,assets=[dict(id=index+1,name=name,size=len(raw),
            browser_download_url="https://github.com/"+m.REPOSITORY+"/releases/download/v1.1.0/"+name,
            expected=hashlib.sha256(raw).hexdigest())for index,(name,raw)in enumerate(payloads.items())])
        trace=[]
        def download(url,path,size,expected):
            name=path.name;raw=payloads[name]
            self.assertEqual(len(raw),size)
            if expected is not None:self.assertEqual(hashlib.sha256(raw).hexdigest(),expected)
            path.write_bytes(raw);return m.sha(path)
        def sums(path,expected):
            actual={line.split("  ")[1]:line.split("  ")[0]for line in path.read_text().splitlines()}
            m.require(actual==expected,"fixture checksum mismatch")
        transport=types.SimpleNamespace(configure_tag=lambda tag:self.assertEqual(tag,"v1.1.0"),
            metadata=lambda path:release if "/releases/"in path else dict(id=456),resolve_tag=lambda commit:self.assertEqual(commit,"a"*40),
            download=download,check_asset_digest=lambda asset,actual:self.assertEqual(asset["expected"],actual))
        def verified(value,subject,commit,run,predicate,repository_id):
            trace.append("signature")
            self.assertEqual((commit,run,repository_id),("a"*40,789,456))
            m.require(value=={"cryptographic_exit_zero":True},"fresh verifier rejected")
        publisher=types.SimpleNamespace(transport=transport,SUFFIXES=suffixes,PREDICATES=("slsa","sbom"),
            check_run=lambda *args:trace.append("official-run"),check_sums=sums,verified_attestation=verified)
        args=types.SimpleNamespace(target=target,tag="v1.1.0",commit="a"*40,bundle_sha256=bundle_sha,plan_sha256="b"*64,
            gh=gh,gh_sha256=m.sha(gh),candidate_run_id=789,candidate_root=candidate,out=root/"public")
        return args,publisher,payloads,trace

    def run_fixture(self,args,publisher,trace,bad_verification=False):
        def execute(*argv,**kwargs):trace.append("gh");return {"expected":"cryptographic subprocess"}
        def native(options):
            trace.append("native")
            self.assertEqual(trace.count("signature"),4)
            self.assertEqual(m.sha(options.bundle),args.bundle_sha256)
            self.assertEqual((options.bundle.parent/"SHA256SUMS").read_text(),args.bundle_sha256+"  "+options.bundle.name+"\n")
            return dict(status="PASS_INSTALLED_NATIVE_LIFECYCLE",installed_binary_sha256="c"*64)
        def embedded(options):trace.append("embedding");return dict(status="PASS_INDEPENDENT_EMBEDDING_LIFECYCLE")
        with mock.patch.dict(os.environ,{"GITHUB_RUN_ID":"125","GITHUB_SHA":"a"*40,"GITHUB_REPOSITORY":m.REPOSITORY}), \
             mock.patch.object(m,"public_verifier",return_value=(publisher,"e"*64)), \
             mock.patch.object(m,"child_execute",side_effect=execute),mock.patch.object(m.safety,"check_exit"), \
             mock.patch.object(m.safety,"output",return_value=json.dumps({"cryptographic_exit_zero":not bad_verification})), \
             mock.patch.object(m,"acceptance",side_effect=native),mock.patch.object(m,"embedding_acceptance",side_effect=embedded):
            return m.public_acceptance(args)

    def test_public_original_global_checksums_and_signed_snapshot_precede_execution(self):
        with tempfile.TemporaryDirectory()as directory:
            args,publisher,payloads,trace=self.fixture(Path(directory).resolve())
            candidate_original=(args.candidate_root/"SHA256SUMS").read_bytes()
            result=self.run_fixture(args,publisher,trace)
            self.assertEqual(result["status"],"PASS_PUBLIC_PLATFORM_LIFECYCLE")
            self.assertEqual(result["public_workflow_run_id"],125)
            self.assertEqual((args.out/"downloads/SHA256SUMS").read_bytes(),payloads["SHA256SUMS"])
            self.assertEqual((args.candidate_root/"SHA256SUMS").read_bytes(),candidate_original)
            self.assertNotEqual(candidate_original,payloads["SHA256SUMS"])
            derived=m.parse(m.read(args.out/"selected-install-input/derivation.json"))
            self.assertEqual(derived["public_original_sha256"],hashlib.sha256(payloads["SHA256SUMS"]).hexdigest())
            self.assertEqual(trace[-2:],["native","embedding"])

    def test_saved_producer_pass_cannot_bypass_failed_fresh_signature_or_changed_driver(self):
        for change in ("failed-fresh-verifier","changed-driver"):
            with self.subTest(change=change),tempfile.TemporaryDirectory()as directory:
                args,publisher,payloads,trace=self.fixture(Path(directory).resolve())
                if change=="changed-driver":
                    (args.candidate_root/"acceptance"/args.target/"installed/native-outcomes/service-tests.exe").write_bytes(b"changed after signed snapshot")
                result=self.run_fixture(args,publisher,trace,bad_verification=change=="failed-fresh-verifier")
                self.assertEqual(result["status"],"HOLD");self.assertNotIn("native",trace);self.assertNotIn("embedding",trace)
                self.assertIn("failure",result)

    def test_global_checksum_census_rejects_extra_missing_duplicate_and_wrong_selected(self):
        for change in ("extra","missing","duplicate","wrong-selected"):
            with self.subTest(change=change),tempfile.TemporaryDirectory()as directory:
                root=Path(directory).resolve();args,publisher,payloads,trace=self.fixture(root)
                lines=payloads["SHA256SUMS"].decode().splitlines()
                if change=="extra":lines.append("d"*64+"  unreviewed.zip")
                if change=="missing":lines.pop()
                if change=="duplicate":lines.append(lines[0])
                if change=="wrong-selected":lines=["d"*64+row[64:]if row.endswith(args.target+".zip")else row for row in lines]
                payloads["SHA256SUMS"]=("\n".join(lines)+"\n").encode()
                asset=next(row for row in publisher.transport.metadata("/releases/test")["assets"]if row["name"]=="SHA256SUMS")
                asset.update(size=len(payloads["SHA256SUMS"]),expected=hashlib.sha256(payloads["SHA256SUMS"]).hexdigest())
                result=self.run_fixture(args,publisher,trace)
                self.assertEqual(result["status"],"HOLD");self.assertNotIn("native",trace)

    def test_children_receive_only_runtime_environment_and_parent_is_restored_on_error(self):
        original=dict(os.environ)
        with mock.patch.dict(os.environ,{"GH_TOKEN":"never pass","GITHUB_TOKEN":"never pass","ACTIONS_RUNTIME_TOKEN":"never pass",
                "UNREVIEWED_SECRET":"never pass","SYMBIOTE_UNSELECTED_STATE":"never pass","PSModulePath":"incompatible parent shell modules"}):
            before=dict(os.environ)
            def execute(*args,**kwargs):
                self.assertFalse(any(key in os.environ for key in ("GH_TOKEN","GITHUB_TOKEN","ACTIONS_RUNTIME_TOKEN","UNREVIEWED_SECRET","SYMBIOTE_UNSELECTED_STATE","PSModulePath")))
                self.assertEqual(os.environ.get("PATH"),before.get("PATH"))
                self.assertEqual(kwargs["environment"],{"SYMBIOTE_COGNITION_TEST_BINARY":"explicit actual image"})
                raise RuntimeError("controlled launch failure")
            with mock.patch.object(m.safety,"execute",side_effect=execute),self.assertRaisesRegex(RuntimeError,"controlled launch"):
                m.child_execute(["synthetic never executed"],environment={"SYMBIOTE_COGNITION_TEST_BINARY":"explicit actual image"})
            self.assertEqual(dict(os.environ),before)
        self.assertEqual(dict(os.environ),original)


if __name__ == "__main__":
    unittest.main()
