"""Reproduce final-tree gates and independent-process learning/restart receipts."""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def execute(args, *, expected=0):
    result = subprocess.run([str(x) for x in args], cwd=ROOT, text=True, capture_output=True, timeout=180)
    if result.returncode != expected:
        raise RuntimeError(f"{args[0]} returned {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-cargo", action="store_true")
    parser.add_argument("--skip-parity", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "experiments" / "genesis-verification.json")
    args = parser.parse_args()
    if not args.skip_cargo:
        for command in [["cargo", "fmt", "--all", "--", "--check"], ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"], ["cargo", "test", "--workspace", "--locked"], ["cargo", "build", "--workspace", "--locked"]]:
            execute(command)
            print("PASS", " ".join(command), flush=True)
    if not args.skip_parity:
        result = execute([sys.executable, ROOT / "tools" / "parity.py", "--output", ROOT / "experiments" / "parity.json"])
        print(result.stdout.strip(), flush=True)
    binary = ROOT / "target" / "debug" / ("symbiote.exe" if sys.platform == "win32" else "symbiote")
    with tempfile.TemporaryDirectory(prefix="symbiote-verification-") as directory:
        base = Path(directory)
        state = base / "learned"

        def run(command, fault=None, state_dir=state, expect=0):
            receipt = base / "latest.json"
            cmd = [binary, command, "--state", state_dir, "--receipts", receipt]
            if fault:
                cmd += ["--fault", fault]
            result = execute(cmd, expected=expect)
            if expect:
                return json.loads(receipt.read_text())
            return json.loads(result.stdout)

        first = run("demo")
        retained = run("predict")
        restart = run("demo")
        assert first["promoted"] == 2 and first["reused"] == 0
        assert restart["promoted"] == 0 and restart["reused"] == 2
        assert first["identity"] == retained["identity"] == restart["identity"]
        assert retained["active_artifacts"] == 2 and retained["network_requests"] == 0
        for participant in first["participants"]:
            s, p = participant["symbiote"], participant["partner_benefit"]
            assert (s["isolated_correct"], s["exchange_correct"], s["matched_probe_control_correct"]) == (16, 32, 32)
            assert (p["baseline_resource_units"], p["strategy_resource_units_including_verification"]) == (176, 72)
        failure = run("demo", "wrong-artifact", base / "rejected", expect=1)
        assert failure["status"] == "REJECTED"
        assert run("predict", state_dir=base / "rejected")["active_artifacts"] == 0
        recovery = run("demo", state_dir=base / "rejected")
        assert recovery["promoted"] == 2
        drift = run("demo", "drift", expect=1)
        assert drift["status"] == "REJECTED"
        after_drift = run("predict")
        assert after_drift["active_artifacts"] == 1
        drift_recovery = run("demo")
        assert drift_recovery["identity"] == first["identity"]
        assert drift_recovery["promoted"] == 1 and drift_recovery["reused"] == 1
        recovered_predictions = run("predict")
        assert recovered_predictions["predictions"][0]["revision"] == 2
        evidence = args.output.parent
        evidence.mkdir(parents=True, exist_ok=True)
        for name, report in [("genesis-first.json", first), ("genesis-retained.json", retained), ("genesis-restart.json", restart), ("genesis-rejected.json", failure), ("genesis-drift.json", drift)]:
            (evidence / name).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        shutil.copyfile(state / "ledger.jsonl", evidence / "genesis-ledger.jsonl")
        report = dict(schema="symbiote.verification/1", status="PASS", process_restart=True, stable_identity=True, first_promoted=2, restart_reused=2, rejected_wrong_transfer=True, failed_candidate_recovery=True, drift_revoked=True, drift_recovery_revision=2, retained_network_requests=0, symbiote=dict(isolated_correct=32, exchanged_correct=64, total=64, matched_probe_control_correct=64, verification_queries=8), partner=dict(baseline_resource_units_each=176, strategy_resource_units_each_including_verification=72), limitations=["four-input deterministic laboratory tasks", "repeated predictions are not independent samples", "same-probe-budget control also achieves complete coverage", "partner resource costs are declared simulation units", "hidden-state reasoning parity is separate from finite-table learning"])
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
