"""Disposable byte-only interface fixtures. No real v1 evidence is collected."""
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

HERE = Path(__file__).parent
MODULE = HERE / "package_v1_evidence_v4.py"
adapter = types.ModuleType("external_v1_membership_adapter")
adapter.__file__ = str(MODULE)
exec(compile(MODULE.read_text(encoding="utf-8"), str(MODULE), "exec"), adapter.__dict__)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class MembershipInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vx-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.data = self.root / "data"; self.data.mkdir()
        self.text = self.data / "observation.txt"; self.text.write_bytes(b"synthetic byte-only fixture\n")
        self.image = self.root / "fake-native.exe"; self.image.write_bytes(b"MZ synthetic bytes; never executed\n")
        registration = dict(schema="synthetic.byte-only-registration/1", source_commit="a" * 40, native_sha256=sha(self.image))
        self.registration = self.data / "registration.json"
        self.registration.write_text(json.dumps(registration), encoding="utf-8")

    def config(self, label):
        output = self.root / label; output.mkdir()
        config = dict(schema=adapter.SCHEMA, inputs_closed=True, source_commit="a" * 40,
                      archive=str(output / "bundle.tar.gz"), extract_to=str(output / "x"),
                      collections=[dict(name="synthetic", path=str(self.data), selection="tree", files=[],
                                        binding=dict(anchor="registration", root_pointer=None))],
                      anchors=[dict(id="registration", path=str(self.registration), sha256=sha(self.registration),
                                    expect=[dict(pointer="/schema", value="synthetic.byte-only-registration/1")],
                                    source_commit_pointer="/source_commit", source_commit="a" * 40)],
                      receipt_roots=[], receipts=[], history=[], format_classifications=[],
                      executables=[dict(role="synthetic-not-executed", path=str(self.image), sha256=sha(self.image),
                                        anchor="registration", digest_pointer="/native_sha256")])
        path = output / "config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        return path, output

    def plan_pin(self, config):
        plan = adapter.make_v1_plan(config)
        return hashlib.sha256(plan[3]).hexdigest()

    def no_qualified_publication(self, output):
        self.assertFalse((output / "bundle.tar.gz").exists())
        self.assertFalse((output / "EVIDENCE_SHA256SUMS").exists())
        receipt = json.loads((output / "v1-packaging-receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "HOLD")

    def test_os_owned_temp_alias_is_resolved_before_the_strict_boundary_check(self):
        config,_=self.config("os-temp-alias")
        alias=self.root/"os-owned-temp-alias";real=Path(tempfile.gettempdir()).resolve(strict=True)
        original_resolve=Path.resolve;original_plain=adapter.base.plain
        def resolve(path,*args,**kwargs):
            return real if path==alias else original_resolve(path,*args,**kwargs)
        def plain(path,*args,**kwargs):
            self.assertNotEqual(Path(path),alias,"OS alias must not reach strict no-link input validation")
            return original_plain(path,*args,**kwargs)
        with mock.patch.object(adapter.tempfile,"gettempdir",return_value=str(alias)), \
                mock.patch.object(Path,"resolve",autospec=True,side_effect=resolve), \
                mock.patch.object(adapter.base,"plain",side_effect=plain):
            plan=adapter.make_v1_plan(config)
        self.assertEqual(json.loads(plan[3])["source_commit"],"a"*40)

    def test_late_addition_during_writer_rejects_its_otherwise_successful_byte_receipt(self):
        config, output = self.config("late")
        expected = self.plan_pin(config)
        real_package = adapter.base.package

        def late_member(path):
            (self.data / "late-failure.json").write_text('{"status":"HOLD"}', encoding="utf-8")
            return real_package(path)

        with mock.patch.object(adapter.base, "package", side_effect=late_member):
            with self.assertRaisesRegex(ValueError, "membership changed after staged byte verification"):
                adapter.package_v1(config, expected)
        self.no_qualified_publication(output)
        self.assertTrue((output / "attempt/bundle.tar.gz").is_file())
        staged = json.loads((output / "attempt/bundle.tar.gz.verification.json").read_text(encoding="utf-8"))
        self.assertEqual(staged["status"], "PASS")
        self.assertTrue((self.data / "late-failure.json").is_file())

    def test_deletion_or_type_change_after_byte_comparison_is_not_inputs_unchanged(self):
        for change in ("delete", "type-change"):
            with self.subTest(change=change):
                if not self.text.exists():
                    self.text.write_bytes(b"synthetic byte-only fixture\n")
                config, output = self.config(change)
                expected = self.plan_pin(config)
                real_package = adapter.base.package

                def mutate_after_bytes(path):
                    result = real_package(path)
                    self.text.unlink()  # Only this test's own disposable file.
                    if change == "type-change":
                        self.text.mkdir()
                    return result

                with mock.patch.object(adapter.base, "package", side_effect=mutate_after_bytes):
                    with self.assertRaisesRegex(ValueError, "membership changed after staged byte verification"):
                        adapter.package_v1(config, expected)
                self.no_qualified_publication(output)

    def test_immediate_pre_package_census_refuses_before_calling_writer(self):
        config, output = self.config("before")
        expected = self.plan_pin(config)
        real_check = adapter.check_tree_membership

        def change_before_check(collector, phase):
            (self.data / "late.txt").write_bytes(b"late\n")
            real_check(collector, phase)

        with mock.patch.object(adapter, "check_tree_membership", side_effect=change_before_check), \
                mock.patch.object(adapter.base, "package") as writer:
            with self.assertRaisesRegex(ValueError, "membership changed immediately before package"):
                adapter.package_v1(config, expected)
            writer.assert_not_called()
        self.no_qualified_publication(output)
        self.assertFalse((output / "attempt").exists())

    def test_file_added_between_reviewed_plan_and_creation_changes_manifest_pin(self):
        config, output = self.config("frozen")
        expected = self.plan_pin(config)
        (self.data / "added-after-review.txt").write_bytes(b"new\n")
        with mock.patch.object(adapter.base, "package") as writer:
            with self.assertRaisesRegex(ValueError, "reviewed manifest differs"):
                adapter.package_v1(config, expected)
            writer.assert_not_called()
        self.no_qualified_publication(output)

    def test_collection_census_refuses_a_member_added_while_collecting(self):
        config, output = self.config("collect")
        original = adapter.base.Collector.tree

        def changed_during_collection(collector, root, prefix):
            result = original(collector, root, prefix)
            (self.data / "during-collection.txt").write_bytes(b"late\n")
            return result

        with mock.patch.object(adapter.base.Collector, "tree", changed_during_collection):
            with self.assertRaisesRegex(ValueError, "membership changed during collection"):
                adapter.make_v1_plan(config)
        self.assertFalse((output / "attempt").exists())
        self.assertFalse((output / "bundle.tar.gz").exists())

    def test_new_empty_directory_is_membership_change_even_without_extra_file(self):
        config, output = self.config("empty-directory")
        expected = self.plan_pin(config)
        original = adapter.base.package

        def add_directory_after_verification(path):
            result = original(path)
            (self.data / "new-empty-directory").mkdir()
            return result

        with mock.patch.object(adapter.base, "package", side_effect=add_directory_after_verification):
            with self.assertRaisesRegex(ValueError, "membership changed after staged byte verification"):
                adapter.package_v1(config, expected)
        self.no_qualified_publication(output)

    def test_closed_tree_round_trip_is_deterministic_and_preserves_input_bytes(self):
        before = {p.name: p.read_bytes() for p in self.data.iterdir()}
        hashes = []
        for label in ("positive-one", "positive-two"):
            config, output = self.config(label)
            result = adapter.package_v1(config, self.plan_pin(config))
            self.assertEqual(result["status"], "PASS")
            self.assertTrue(result["full_tree_membership_rechecked"])
            self.assertGreater(result["final_source_bytes_rechecked"]["references"], 1)
            self.assertGreater(result["final_source_bytes_rechecked"]["bytes"], 0)
            self.assertTrue(result["byte_verification"]["full_extracted_byte_comparison"])
            self.assertEqual((output / "EVIDENCE_SHA256SUMS").read_text(encoding="ascii"),
                             result["archive_sha256"] + "  bundle.tar.gz\n")
            hashes.append(sha(output / "bundle.tar.gz"))
        self.assertEqual(hashes[0], hashes[1])
        self.assertEqual({p.name: p.read_bytes() for p in self.data.iterdir()}, before)
        self.assertEqual(sha(HERE / adapter.BASE_NAME), adapter.BASE_SHA256)

    def test_member_added_during_final_byte_hashes_is_detected_before_exposure(self):
        config,output=self.config("late-during-final-hashes")
        expected=self.plan_pin(config)
        original=adapter.recheck_selected_bytes
        def hash_then_add(*args,**kwargs):
            result=original(*args,**kwargs)
            (self.data/"late-failure.json").write_bytes(b'{"status":"HOLD"}')
            return result
        with mock.patch.object(adapter,"recheck_selected_bytes",side_effect=hash_then_add):
            with self.assertRaisesRegex(ValueError,"membership changed immediately before final archive exposure"):
                adapter.package_v1(config,expected)
        self.no_qualified_publication(output)

    def test_staged_archive_mutation_after_verified_writer_return_is_hold(self):
        for kind in ("append", "same-size"):
            config, output = self.config("archive-" + kind)
            expected = self.plan_pin(config)
            original = adapter.base.package
            def tamper_after_writer(path):
                result = original(path)
                staged = Path(result["archive"])
                raw = staged.read_bytes()
                staged.write_bytes(raw + b"changed after staged verification" if kind == "append"
                                   else bytes([raw[0] ^ 1]) + raw[1:])
                return result
            with self.subTest(kind=kind), mock.patch.object(adapter.base,"package",side_effect=tamper_after_writer):
                with self.assertRaisesRegex(ValueError,"archive changed after staged byte verification"):
                    adapter.package_v1(config,expected)
            self.no_qualified_publication(output)
            self.assertTrue((output/"attempt/bundle.tar.gz").is_file())

    def test_mutation_after_final_link_is_detected_and_owned_link_is_removed(self):
        config, output = self.config("archive-after-link")
        expected = self.plan_pin(config)
        original = adapter.os.link
        def link_then_change(source,destination):
            result = original(source,destination)
            if Path(destination) == output/"bundle.tar.gz":
                with Path(source).open("ab") as stream:stream.write(b"changed after link")
            return result
        with mock.patch.object(adapter.os,"link",side_effect=link_then_change):
            with self.assertRaisesRegex(ValueError,"archive changed after staged byte verification"):
                adapter.package_v1(config,expected)
        self.no_qualified_publication(output)
        self.assertTrue((output/"attempt/bundle.tar.gz").exists())

    def post_stage_byte_mutation_is_hold(self, target, label, config=None, mutate=None):
        if config is None:
            config, output = self.config(label)
        else:
            output = config.parent
        expected = self.plan_pin(config)
        original_package = adapter.base.package
        original_bytes = target.read_bytes()
        changed = mutate(original_bytes) if mutate else bytes([original_bytes[0] ^ 1]) + original_bytes[1:]
        self.assertEqual(len(changed), len(original_bytes))
        self.assertNotEqual(changed, original_bytes)

        def mutate_same_path_after_verified_return(path):
            result = original_package(path)
            target.write_bytes(changed)  # Only this test's own disposable source.
            return result

        with mock.patch.object(adapter.base, "package", side_effect=mutate_same_path_after_verified_return):
            with self.assertRaisesRegex(ValueError, "changed after staged byte verification"):
                adapter.package_v1(config, expected)
        self.no_qualified_publication(output)
        self.assertEqual(target.read_bytes(), changed)
        self.assertTrue((output / "attempt/bundle.tar.gz").is_file())
        staged = json.loads((output / "attempt/bundle.tar.gz.verification.json").read_text(encoding="utf-8"))
        self.assertEqual(staged["status"], "PASS")

    def test_post_stage_same_path_same_size_observation_bytes_cannot_publish_pass(self):
        self.post_stage_byte_mutation_is_hold(self.text, "changed-observation")

    def test_post_stage_anchor_bytes_are_rechecked(self):
        self.post_stage_byte_mutation_is_hold(self.registration, "changed-anchor",
                                             mutate=lambda raw: raw.replace(b"synthetic", b"malicious"))

    def test_post_stage_registered_executable_bytes_are_rechecked(self):
        self.post_stage_byte_mutation_is_hold(self.image, "changed-image")

    def test_post_stage_configuration_bytes_are_rechecked(self):
        config, _ = self.config("changed-config")
        self.post_stage_byte_mutation_is_hold(config, "unused", config=config,
                                             mutate=lambda raw: raw.replace(b'"a' + b"a" * 39 + b'"',
                                                                             b'"b' + b"a" * 39 + b'"'))

    def test_post_stage_duplicate_archive_alias_source_cannot_be_skipped(self):
        aliases = self.root / "aliases"; aliases.mkdir()
        alias = aliases / "observation.txt"; alias.write_bytes(self.text.read_bytes())
        config, _ = self.config("changed-alias")
        value = json.loads(config.read_text(encoding="utf-8"))
        value["receipt_roots"] = [str(aliases)]
        value["receipts"] = [dict(path=str(alias), sha256=sha(alias),
                                  archive_path="evidence/synthetic/data/observation.txt")]
        config.write_text(json.dumps(value), encoding="utf-8")
        plan = adapter.make_v1_plan(config)
        self.assertEqual(len(plan[2].entries["evidence/synthetic/data/observation.txt"]["sources"]), 2)
        self.post_stage_byte_mutation_is_hold(alias, "unused", config=config)

    def test_final_revalidation_refuses_excessive_alias_count_and_byte_work(self):
        collector = types.SimpleNamespace(entries={"x": dict(bytes=0,
                    sources=["same"] * adapter.FINAL_SOURCE_LIMITS["references"])})
        with self.assertRaisesRegex(ValueError, "final source revalidation budget exceeded"):
            adapter.source_recheck_budget(collector, dict(bytes=0))
        collector.entries = {"x": dict(bytes=adapter.FINAL_SOURCE_LIMITS["bytes"], sources=["same"])}
        with self.assertRaisesRegex(ValueError, "final source revalidation budget exceeded"):
            adapter.source_recheck_budget(collector, dict(bytes=1))

    def test_listing_failure_cannot_omit_a_subtree(self):
        with mock.patch.object(adapter.os, "scandir", side_effect=PermissionError("synthetic denied listing")):
            with self.assertRaisesRegex(PermissionError, "synthetic denied listing"):
                adapter.tree_census(self.data)


    def rewrite_config(self, path, transform):
        body = json.loads(path.read_text()); transform(body)
        path.write_text(json.dumps(body), encoding="utf-8")

    def transcript(self, raw):
        path = self.data / "release-tests.jsonl"; path.write_bytes(raw)
        return path

    def classification(self, path):
        return dict(path=str(path),sha256=sha(path),format="cargo-json-and-rust-test-output/1")

    def test_mixed_transcript_is_exactly_preserved_only_with_reviewed_classification(self):
        transcript = self.transcript(b'{"reason":"build-finished","success":true}\n\nrunning 1 test\ntest sample::works ... ok\ntest soak::hour ... ignored, registered hour; explicit only\n')
        config, output = self.config("mixed")
        with self.assertRaises(ValueError):adapter.make_v1_plan(config)
        self.rewrite_config(config,lambda body:body.update(format_classifications=[self.classification(transcript)]))
        result=adapter.package_v1(config,self.plan_pin(config))
        self.assertEqual(result["status"],"PASS")
        extracted=output/"x/evidence/synthetic/data/release-tests.jsonl"
        self.assertEqual(extracted.read_bytes(),transcript.read_bytes())
        self.assertEqual(sha(extracted),sha(transcript))

    def test_corrupt_json_unrecognized_human_and_decoded_secret_cannot_be_classified_away(self):
        for name,raw in [
            ("bad-json",b'{"reason":"build-finished"\n running 1 test\n'),
            ("free-text",b'{"reason":"build-finished"}\nnot a Cargo test line\n'),
            ("secret",b'{"reason":"compiler-message","message":{"api_key":"'+b'x'*24+b'"}}\nrunning 1 test\n'),
            ("nested-secret",(json.dumps(dict(reason="compiler-message",message=json.dumps(dict(api_key="x"*24))))+"\nrunning 1 test\n").encode())]:
            with self.subTest(name=name):
                transcript=self.transcript(raw)
                config,_=self.config(name)
                self.rewrite_config(config,lambda body:body.update(format_classifications=[self.classification(transcript)]))
                with self.assertRaises(ValueError):adapter.make_v1_plan(config)

    def test_wrong_pin_and_unused_classification_fail(self):
        transcript=self.transcript(b'{"reason":"build-finished"}\nrunning 1 test\n')
        config,_=self.config("wrong-pin")
        item=self.classification(transcript);item["sha256"]="0"*64
        self.rewrite_config(config,lambda body:body.update(format_classifications=[item]))
        with self.assertRaisesRegex(ValueError,"byte pin"):adapter.make_v1_plan(config)
        unused=self.root/"unused.jsonl";unused.write_bytes(transcript.read_bytes())
        config,_=self.config("unused")
        self.rewrite_config(config,lambda body:body.update(format_classifications=[self.classification(unused),self.classification(transcript)]))
        with self.assertRaisesRegex(ValueError,"unselected"):adapter.make_v1_plan(config)

    def test_public_cognitive_consent_is_narrow_and_does_not_hide_a_secret(self):
        public=dict(schema="symbiote.cognition-event/1",phase="CONNECT",
                    details=dict(authorization="explicit operator registry and current durable denials"))
        adapter.scan_json(public,"synthetic public declaration")
        for change in ["schema","phase","location","text","neighbor-secret"]:
            value=json.loads(json.dumps(public))
            if change=="schema":value["schema"]="unrecognized/1"
            if change=="phase":value["phase"]="SENSE"
            if change=="location":value["other"]=value.pop("details")
            if change=="text":value["details"]["authorization"]+=" changed"
            if change=="neighbor-secret":value["details"]["api_key"]="x"*24
            with self.subTest(change=change),self.assertRaises(ValueError):adapter.scan_json(value,"synthetic rejected declaration")

    def test_actual_anchor_source_can_differ_from_release_but_cannot_be_relabelled(self):
        config,_=self.config("historical-source")
        self.rewrite_config(config,lambda body:body.update(source_commit="b"*40))
        plan=adapter.make_v1_plan(config)
        manifest=json.loads(plan[3]);self.assertEqual(manifest["source_commit"],"b"*40)
        self.assertEqual(manifest["anchors"][0]["source_commit"],"a"*40)
        self.rewrite_config(config,lambda body:body["anchors"][0].update(source_commit="b"*40))
        with self.assertRaisesRegex(ValueError,"different declared source"):adapter.make_v1_plan(config)

    def test_public_normal_capability_authorization_requires_its_exact_event_context(self):
        public=dict(schema="symbiote.cognition-event/1",phase="CAPABILITY_OPPORTUNITY",
                    details=dict(authorization="explicit normal quality-goal policy plus current bilateral operation grants"))
        adapter.scan_json(public,"synthetic normal declaration")
        adapter.scan_json(json.dumps(public),"decoded normal declaration")
        for change in ("schema","phase","location","text","nested-location","neighbor-secret","escaped-secret"):
            value=json.loads(json.dumps(public))
            if change=="schema":value["schema"]="unrecognized/1"
            if change=="phase":value["phase"]="CONNECT"
            if change=="location":value["other"]=value.pop("details")
            if change=="text":value["details"]["authorization"]+=" changed"
            if change=="nested-location":value["details"]={"other":value["details"]}
            if change=="neighbor-secret":value["details"]["api_key"]="x"*24
            if change=="escaped-secret":value["details"]["nested"]=json.dumps({"authorization":"x"*24})
            with self.subTest(change=change),self.assertRaises(ValueError):adapter.scan_json(value,"rejected normal declaration")


    def test_pure_cargo_stdout_round_trip_keeps_explicit_format_and_raw_suffix(self):
        transcript = self.data / "compile.stdout"
        transcript.write_bytes(b'{"reason":"compiler-artifact","package_id":"owned-unit"}\n{"reason":"build-finished","success":true}\n')
        config, output = self.config("pure-cargo")
        with self.assertRaises(json.JSONDecodeError):
            adapter.make_v1_plan(config)
        classification = dict(path=str(transcript), sha256=sha(transcript), format=adapter.PURE_CARGO_FORMAT)
        self.rewrite_config(config, lambda body: body.update(format_classifications=[classification]))
        result = adapter.package_v1(config, self.plan_pin(config))
        self.assertEqual(result["status"], "PASS")
        extracted = output / "x/evidence/synthetic/data/compile.stdout"
        self.assertEqual(extracted.read_bytes(), transcript.read_bytes())
        manifest = json.loads((output / "x/MANIFEST.json").read_bytes())
        self.assertEqual(manifest["format_classifications"], [classification])
        self.assertEqual(manifest["packager_base"]["sha256"], adapter.BASE_SHA256)


def stream(*documents):
    return b"".join(json.dumps(document, separators=(",", ":")).encode() + b"\n" for document in documents)


def valid():
    return stream({"reason": "compiler-artifact", "package_id": "unit-owned"}, {"reason": "build-finished", "success": True})


class PureCargoStreamTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cargo-format-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(strict=True)
        self.module = adapter
        self.path = self.root / "owned.stdout"

    def admit(self, raw, pin=None):
        self.path.write_bytes(raw)
        item = dict(path=str(self.path), sha256=pin or hashlib.sha256(raw).hexdigest(), format=adapter.PURE_CARGO_FORMAT)
        self.module.configure_classifications([item])
        return self.module.base.fingerprint(self.path)

    def test_actual_pure_jsonl_stdout_is_preserved(self):
        raw = valid()
        result = self.admit(raw)
        self.assertEqual(result["bytes"], len(raw))
        self.assertEqual(result["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(self.path.read_bytes(), raw)
        self.assertIn(str(self.path), self.module.CLASSIFICATIONS)

    def test_wrong_sha_rejected(self):
        with self.assertRaisesRegex(ValueError, "pin changed"):
            self.admit(valid(), "0" * 64)

    def test_malformed_json_rejected(self):
        with self.assertRaises(ValueError):
            self.admit(b'{"reason":"compiler-artifact"\n' + valid())

    def test_unknown_reason_and_human_output_rejected(self):
        for raw in (stream({"reason":"invented"}), valid() + b"running 2 tests\n"):
            with self.subTest(raw_size=len(raw)), self.assertRaises(ValueError):
                self.admit(raw)

    def test_decoded_secret_rejected(self):
        secret = "sk" + "-" + "A" * 36
        encoded = "".join("\\u%04x" % ord(character) for character in secret)
        raw = ('{"reason":"compiler-message","message":"' + encoded + '"}\n').encode() + stream({"reason":"build-finished","success":True})
        with self.assertRaisesRegex(ValueError, "credential pattern"):
            self.admit(raw)

    def test_continuous_raw_overlap_rejects_cross_block_secret(self):
        secret = "sk" + "-" + "A" * 36
        raw = stream({"reason":"compiler-message","message":secret}, {"reason":"build-finished","success":True})
        with mock.patch.object(self.module.base, "BLOCK", 16):
            with self.assertRaisesRegex(ValueError, "credential pattern"):
                self.admit(raw)

    def test_unclassified_original_stdout_still_rejected(self):
        self.path.write_bytes(valid())
        self.module.configure_classifications([])
        with self.assertRaises(json.JSONDecodeError):
            self.module.base.fingerprint(self.path)

    def test_change_during_decoded_scan_rejected(self):
        original = self.module.base.scan_json
        changed = False
        def mutate(value, *args, **kwargs):
            nonlocal changed
            original(value, *args, **kwargs)
            if not changed:
                changed = True
                with self.path.open("ab") as output:
                    output.write(b" ")
        with mock.patch.object(self.module.base, "scan_json", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "bound exceeded|changed"):
                self.admit(valid())

    def test_finish_required_unique_and_boolean(self):
        for raw in (stream({"reason":"compiler-artifact"}), valid() + valid(), stream({"reason":"build-finished","success":1})):
            with self.subTest(raw_size=len(raw)), self.assertRaises(ValueError):
                self.admit(raw)
        result = self.admit(stream({"reason":"build-finished","success":False}))
        self.assertGreater(result["bytes"], 0)  # Format admission never upgrades a failed build.

    def test_duplicate_keys_and_oversized_line_rejected(self):
        for raw in (b'{"reason":"build-finished","reason":"compiler-artifact","success":true}\n', valid()):
            with self.subTest(raw_size=len(raw)):
                if raw == valid():
                    with mock.patch.dict(self.module.base.LIMITS, json_line_bytes=16), self.assertRaises(ValueError):
                        self.admit(raw)
                else:
                    with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                        self.admit(raw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
