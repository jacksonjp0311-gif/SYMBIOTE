"""Release gates must remain effective under Python's optimization flag."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
VERIFIERS = ["verify.py", "verify_research.py", "verify_deployed.py", "verify_graph.py"]


class VerificationIntegrityTests(unittest.TestCase):
    def test_recorded_graph_cohort_passes_and_tampered_metrics_or_omissions_fail(self):
        spec = importlib.util.spec_from_file_location("graph_gate_fixture", ROOT / "tools" / "verify_graph.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        recorded = json.loads((ROOT / "experiments/v0.4/graph-exchange.json").read_text(encoding="utf-8"))
        self.assertEqual(len(module.validate(recorded)),2)
        altered = copy.deepcopy(recorded)
        altered["regimes"][0]["cases"][0]["participants"][0]["exchange_cost"] += 1
        with self.assertRaises(RuntimeError):
            module.validate(altered)
        omitted = copy.deepcopy(recorded)
        omitted["regimes"][0]["cases"].pop()
        with self.assertRaises(RuntimeError):
            module.validate(omitted)
        filtered = copy.deepcopy(recorded)
        filtered["regimes"][0]["cases"][0]["participants"][0]["exchange_forecasts"].pop()
        with self.assertRaises(RuntimeError):
            module.validate(filtered)

    def test_native_receipt_output_is_decoded_as_utf8(self):
        spec = importlib.util.spec_from_file_location("verification_utf8_fixture", ROOT / "tools" / "verify.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result = module.execute([sys.executable,"-c","import sys; sys.stdout.buffer.write(bytes.fromhex('31e2869233'))"])
        self.assertEqual(result.stdout,"1\u21923")

    def test_empty_or_zero_test_runs_cannot_pass(self):
        spec = importlib.util.spec_from_file_location("verification_count_fixture", ROOT / "tools" / "verify.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for output in ["", "test result: ok. 0 passed; 0 failed;"]:
            with self.assertRaises(RuntimeError):
                module.count_native_tests(output)
        for output in ["", "Ran 0 tests"]:
            with self.assertRaises(RuntimeError):
                module.count_python_tests(output)
        self.assertEqual(module.count_native_tests("test result: ok. 2 passed;\ntest result: ok. 3 passed;"), 5)
        self.assertEqual(module.count_python_tests("Ran 13 tests in 1.0s"), 13)

    def test_false_release_gate_fails_in_optimized_python(self):
        for name in VERIFIERS:
            path = ROOT / "tools" / name
            script = "import importlib.util; s=importlib.util.spec_from_file_location('gate_fixture'," + repr(str(path)) + "); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); m.require(False,'deliberate-negative-control')"
            result = subprocess.run([sys.executable, "-O", "-c", script], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0, name)
            self.assertIn("deliberate-negative-control", result.stderr)

    def test_acceptance_verifiers_contain_no_optimizable_assert_statements(self):
        for name in VERIFIERS:
            tree = ast.parse((ROOT / "tools" / name).read_text(encoding="utf-8"))
            self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)), name)


if __name__ == "__main__":
    unittest.main()
