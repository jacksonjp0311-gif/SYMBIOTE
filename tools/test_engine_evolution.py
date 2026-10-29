"""Freshness and provenance guards, without opening the registered source cohort."""
import hashlib
from pathlib import Path
import tempfile
import unittest

import engine_evolution as evolution


class FreshWorkloadTests(unittest.TestCase):
    def test_fresh_input_order_is_predeclared_disjoint_and_output_independent(self):
        observed = {0, 1, 2, 4, 8, 16, 32, 64, 128, 3}
        expected = sorted(range(256), key=lambda value: hashlib.sha256(
            f"SYMBIOTE-ENGINE-EVOLUTION-002/case/999/input/{value}".encode()).digest())
        expected = [value for value in expected if value not in observed][:32]
        actual = evolution.fresh_inputs(999, observed)
        self.assertEqual(actual, expected)
        self.assertEqual(len(set(actual)), 32)
        self.assertFalse(set(actual) & observed)
        self.assertEqual(actual, evolution.fresh_inputs(999, observed))

    def test_outputs_require_a_fresh_dedicated_temp_directory(self):
        with tempfile.TemporaryDirectory(prefix="evo-directory-unit-") as directory:
            path = Path(directory).resolve() / "new"
            self.assertEqual(evolution.fresh(path), path)
            with self.assertRaises(ValueError):
                evolution.fresh(path)
            with self.assertRaises(ValueError):
                evolution.fresh(Path.cwd() / "do-not-create-engine-evolution")

    def test_canonical_evidence_rejects_nan_instead_of_changing_accounting(self):
        with self.assertRaises(ValueError):
            evolution.safety.encode({"cost": float("nan")})


if __name__ == "__main__":
    unittest.main()
