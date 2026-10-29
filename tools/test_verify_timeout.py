"""Fake TimeoutExpired diagnostics only; no compiler, native test or campaign."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock

SOURCE=Path(__file__).with_name("verify.py")
verify=types.ModuleType("timeout_verifier_fixture");verify.__file__=str(SOURCE)
exec(compile(SOURCE.read_bytes(),str(SOURCE),"exec"),verify.__dict__)


class TimeoutDiagnosticTests(unittest.TestCase):
    def test_partial_raw_capture_is_hashed_exactly_and_only_bounded_tails_are_saved(self):
        stdout=b"old-prefix\n"*10000+b"last-native-case\xff\n"
        stderr=b"compiler-log\n"*7000
        timeout=subprocess.TimeoutExpired(["cargo","test"],300,output=stdout,stderr=stderr)
        with tempfile.TemporaryDirectory() as temporary:
            destination=Path(temporary)/"diagnostics"
            with mock.patch.object(verify,"TIMEOUT_DIAGNOSTICS",destination),mock.patch.object(verify.time,"monotonic",side_effect=[10.0,310.5]),\
                 mock.patch.object(verify.subprocess,"run",side_effect=timeout) as run,mock.patch.object(verify.sys,"stderr",io.StringIO()) as printed:
                with self.assertRaises(subprocess.TimeoutExpired):verify.execute(["cargo","test","--workspace","--locked"])
            run.assert_called_once_with(["cargo","test","--workspace","--locked"],cwd=verify.ROOT,text=True,encoding="utf-8",capture_output=True,timeout=300)
            directories=list(destination.iterdir());self.assertEqual(len(directories),1)
            report=json.loads((directories[0]/"timeout.json").read_bytes())
            self.assertEqual(report["status"],"HOLD_TIMEOUT");self.assertEqual(report["timeout_seconds"],300)
            self.assertEqual(report["elapsed_seconds"],300.5)
            for name,raw in (("stdout",stdout),("stderr",stderr)):
                self.assertEqual(report[name]["captured_bytes"],len(raw));self.assertEqual(report[name]["capture_sha256"],hashlib.sha256(raw).hexdigest())
                self.assertTrue(report[name]["original_pipe_bytes_known"])
                tail=(directories[0]/report[name]["tail_file"]).read_bytes()
                self.assertEqual(tail,raw[-32768:]);self.assertEqual(report[name]["tail_bytes"],len(tail))
            self.assertIn("HOLD_VERIFICATION_TIMEOUT",printed.getvalue())
            self.assertLess(len(printed.getvalue().encode("utf-8")),70000)
    def test_text_capture_and_unavailable_capture_are_not_called_original_pipe_bytes(self):
        with tempfile.TemporaryDirectory() as temporary,mock.patch.object(verify,"TIMEOUT_DIAGNOSTICS",Path(temporary)),\
             mock.patch.object(verify.sys,"stderr",io.StringIO()):
            report=verify.preserve_timeout(["fake"],subprocess.TimeoutExpired(["fake"],300,output="café\n",stderr=None),300)
            self.assertEqual(report["stdout"]["hash_basis"],"UTF-8 reencoding of captured text")
            self.assertFalse(report["stdout"]["original_pipe_bytes_known"])
            self.assertFalse(report["stderr"]["capture_available"]);self.assertIsNone(report["stderr"]["capture_sha256"])
    def test_diagnostic_write_failure_reports_it_and_keeps_original_timeout(self):
        timeout=subprocess.TimeoutExpired(["fake"],300,output=b"partial")
        with tempfile.TemporaryDirectory() as temporary,mock.patch.object(verify.subprocess,"run",side_effect=timeout),\
             mock.patch.object(verify.tempfile,"mkdtemp",side_effect=OSError("controlled diagnostic disk failure")),mock.patch.object(verify,"TIMEOUT_DIAGNOSTICS",Path(temporary)),\
             mock.patch.object(verify.sys,"stderr",io.StringIO()) as printed:
            with self.assertRaises(subprocess.TimeoutExpired):verify.execute(["fake"])
            self.assertIn("diagnostic_save_error",printed.getvalue())
    def test_normal_result_and_nonzero_behavior_remain_unchanged(self):
        result=subprocess.CompletedProcess(["fake"],0,"original output","")
        with tempfile.TemporaryDirectory() as temporary,mock.patch.object(verify,"TIMEOUT_DIAGNOSTICS",Path(temporary)/"unused"),\
             mock.patch.object(verify.subprocess,"run",return_value=result):
            self.assertIs(verify.execute(["fake"]),result);self.assertFalse((Path(temporary)/"unused").exists())
        with mock.patch.object(verify.subprocess,"run",return_value=subprocess.CompletedProcess(["fake"],2,"out","err")):
            with self.assertRaisesRegex(RuntimeError,"fake returned 2"):verify.execute(["fake"])
    def test_intel_boundary_is_compile_only_and_keeps_both_command_bounds(self):
        workflow=SOURCE.parents[1]/".github/workflows/v11-candidate.yml"
        raw=workflow.read_text(encoding="utf-8")
        section=raw.split("name: Measure bounded cold Intel test compilation",1)[1].split("name: Build documented API reference",1)[0]
        self.assertIn("'cargo','test','--workspace','--locked','--no-run','--message-format','json'",section)
        self.assertIn("timeout=300",section);self.assertIn("16 * 1024 * 1024",section)
        self.assertIn("--timeout-diagnostics dist/intel-verify-timeouts",section)
        self.assertNotIn("--test-threads",section);self.assertNotIn("CARGO_BUILD_JOBS",section)
        import textwrap
        code=section.split("python -B - <<'PY'\n",1)[1].split("\n          PY",1)[0]
        compile(textwrap.dedent(code),str(workflow),"exec")


if __name__=="__main__":unittest.main(verbosity=2)
