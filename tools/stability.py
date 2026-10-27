"""Bounded repeated-process campaign; software endurance, not new learning samples."""
import argparse
import hashlib
import json
import platform
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise RuntimeError("Stability HOLD: " + message)


def invoke(binary, state, command, *options, success=True):
    result = subprocess.run([str(binary), command, "--state", str(state), "--json", *map(str, options)], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=45)
    require((result.returncode == 0) == success, command + " returned an unexpected status: " + result.stderr[-2000:])
    return json.loads(result.stdout) if success else result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def campaign(binary, cycles):
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="symbiote-stability-") as directory:
        state = Path(directory) / "owned-state"
        identities = None
        ledger_digests = None
        process_instances = set()
        totals = {"observe": 0, "verify": 0, "assess": 0}
        for cycle in range(cycles):
            report = invoke(binary, state, "network-research", "--receipts", Path(directory) / "latest.json")
            require(report["status"] == "PASS" and report["restart_retained_predictions"], "native learning/restart did not pass")
            current = [report["identity"]] + [peer["identity"] for peer in report["participants"]]
            require(len(set(current)) == 3, "private identities are not distinct")
            require(identities is None or current == identities, "identity changed across cycles")
            identities = current
            for peer in report["participants"]:
                for field in ["instance_nonce", "restart_instance_nonce"]:
                    require(peer[field] not in process_instances, "native instance nonce repeated")
                    process_instances.add(peer[field])
                for operation, count in peer["restart_oracle_requests"].items():
                    require(count == 0, "retained prediction contacted an oracle")
                    totals[operation] += count
                require(peer["active_models"] == 1, "retained active model count grew")
                require(peer["promotion"]["promoted"] == (cycle == 0), "duplicate learning was counted as a new promotion")
            private_paths = [state, state / "network/exact", state / "network/linear"]
            paths = [path / name for path in private_paths for name in ["ledger.jsonl", "knowledge.jsonl"] if (path / name).exists()]
            current_digests = {str(path.relative_to(state)): digest(path) for path in paths}
            require(ledger_digests is None or current_digests == ledger_digests, "repeated experiment rewrote or grew retained ledgers")
            ledger_digests = current_digests
            for path in private_paths:
                inspected = invoke(binary, path, "inspect-state")
                require(inspected["status"] == "PASS", "post-cycle integrity or liveness inspection failed")
                require(not any(path.glob("*.lock")), "a completed process left a writer lock")
            print(f"PASS native process cycle {cycle + 1}/{cycles}", flush=True)
        return dict(schema="symbiote.stability/1", status="PASS", platform=platform.system(), architecture=platform.machine(), executable_sha256=digest(binary), cycles=cycles, native_peer_instances=len(process_instances), distinct_durable_identities=len(identities), restart_oracle_requests=totals, retained_ledger_sha256=ledger_digests, repeated_promotions=0, elapsed_seconds=round(time.monotonic() - started, 3), limitations=["bounded supervised affine laboratory workload", "repeated cases are endurance checks, not independent learning samples", "does not establish power-loss durability, hostile-host isolation or long-term production reliability"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug" / ("symbiote.exe" if platform.system() == "Windows" else "symbiote"))
    parser.add_argument("--cycles", type=int, default=12)
    parser.add_argument("--output", type=Path, default=ROOT / "experiments/local/stability.json")
    args = parser.parse_args()
    require(2 <= args.cycles <= 1000, "cycles must be 2..1000")
    report = campaign(args.binary.resolve(strict=True), args.cycles)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
