#!/usr/bin/env python3
"""Execute unchanged BRUTE and native Rust on identical bounded fixtures.

Python is a development verifier only. The production runtime never invokes it.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import random
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "docs/reference/brute/symbolic.py"
REFERENCE_SHA256 = "878a0ee803dec0e5095b561b3110a1c8bc99f6c664f853b137e19fad0cde92eb"


def load_reference():
    if hashlib.sha256(REFERENCE.read_bytes()).hexdigest() != REFERENCE_SHA256:
        raise RuntimeError("retained BRUTE source hash differs from pinned original")
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("brute_symbolic_reference", REFERENCE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def checkpoint(learner):
    snapshot = learner.snapshot()
    return {
        key: snapshot[key]
        for key in (
            "status", "model_rows", "evidence_count", "max_rows_seen",
            "last_failure", "physical_certificate_authorized",
        )
    } | {
        "support": [learner.predict_support(a) for a in (0, 1)],
        "conditional": [learner.conditional_certificate(a) for a in (0, 1)],
    }


def reference_case(module, case):
    learner = module.SymbolicLearner(case["max_states"], case["max_prefixes"])
    learner.initialize(case["initial"])
    history = [checkpoint(learner)]
    for step in case["steps"]:
        learner.observe(step["action"], step["observation"])
        history.append(checkpoint(learner))
    reconstruction = case.get("reconstruct")
    if reconstruction is not None:
        reconstruction = checkpoint(learner.reconstruct(**reconstruction))
    return {"name": case["name"], "history": history, "reconstruction": reconstruction}


def complete_machine_support(case):
    """Third representation: enumerate every labelled complete 1/2-state model.

    This checks exact support independently of both prefix implementations.
    """
    n = case["max_states"]
    if n not in (1, 2):
        raise ValueError("complete-model verifier is deliberately bounded to n <= 2")

    def compatible(code, observation):
        return all(bit is None or ((code >> (1 - i)) & 1) == bit
                   for i, bit in enumerate(observation))

    models = [(trans, emissions, 0)
              for trans in itertools.product(range(n), repeat=2 * n)
              for emissions in itertools.product(range(4), repeat=n)
              if compatible(emissions[0], case["initial"])]
    history = []
    for step in [None] + case["steps"]:
        if step is not None:
            filtered = []
            for trans, emissions, current in models:
                dest = trans[current * 2 + step["action"]]
                if compatible(emissions[dest], step["observation"]):
                    filtered.append((trans, emissions, dest))
            models = filtered
        history.append([
            sorted({emissions[trans[current * 2 + a]] for trans, emissions, current in models})
            if models else None for a in (0, 1)
        ])
    return history


def generated_cases():
    observations = list(itertools.product((None, 0, 1), repeat=2))
    steps = [(action, observation) for action in (0, 1) for observation in observations]
    # Exhaust every length-two trace, including masked contradictions, for n=1/2.
    for n in (1, 2):
        for initial in observations:
            for index, sequence in enumerate(itertools.product(steps, repeat=2)):
                yield {"name": f"exhaustive-n{n}-{initial}-{index}", "max_states": n,
                       "max_prefixes": 1000, "initial": initial,
                       "steps": [{"action": a, "observation": o} for a, o in sequence]}
    rng = random.Random(20261026)
    for index in range(256):
        n = rng.randrange(1, 5)
        yield {"name": f"seeded-{index}", "max_states": n,
               "max_prefixes": 4 if index % 3 == 0 else 5000,
               "initial": rng.choice(observations),
               "steps": [{"action": rng.randrange(2), "observation": rng.choice(observations)}
                         for _ in range(12)],
               "reconstruct": {"max_states": min(n + 1, 6), "max_prefixes": 20000}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="write an optional JSON verification receipt")
    parser.add_argument("--binary", type=Path, help="use an already built reasoning-fixture binary")
    args = parser.parse_args()
    module = load_reference()
    fixture = json.loads((ROOT / "tests/fixtures/reasoning.json").read_text(encoding="utf-8"))
    cases = fixture["cases"] + list(generated_cases())
    command = [str(args.binary.resolve())] if args.binary else [
        "cargo", "run", "--locked", "--quiet", "-p", "symbiote-reasoning",
        "--bin", "reasoning-fixture",
    ]
    completed = subprocess.run(
        command, cwd=ROOT,
        input=json.dumps({"cases": cases}), capture_output=True, text=True,
        timeout=180, check=True,
    )
    native = json.loads(completed.stdout)
    expected = json.loads(json.dumps([reference_case(module, case) for case in cases]))
    if len(native) != len(expected):
        raise AssertionError(f"native case count {len(native)} != {len(expected)}")
    for actual, reference in zip(native, expected):
        if actual != reference:
            raise AssertionError(json.dumps({"native": actual, "reference": reference}))
    complete_cases = 0
    for case, result in zip(cases, expected):
        if case["name"].startswith("exhaustive-"):
            support = complete_machine_support(case)
            if support != [item["support"] for item in result["history"]]:
                raise AssertionError(f"complete-machine support differs: {case['name']}")
            complete_cases += 1
    receipt = {
        "schema": "symbiote.parity/1", "passed": True,
        "upstream": "jacksonjp0311-gif/Brute",
        "commit": "9edbc035792ca75d3a3333b8454e5bf31c706eb1",
        "reference_sha256": REFERENCE_SHA256,
        "cases": len(cases), "checkpoints": sum(len(item["history"]) for item in native),
        "complete_machine_cases": complete_cases,
        "comparison": ["status", "model_rows", "evidence_count", "max_rows_seen",
                       "support", "conditional", "last_failure", "reconstruction"],
        "excluded_counter": "transitions_examined at budget interruption depends on set iteration order",
        "scope": "Exact finite Moore prefix engine parity; full BRUTE certification policy is not ported.",
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
