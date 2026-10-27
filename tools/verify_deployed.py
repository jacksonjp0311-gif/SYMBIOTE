"""Verify native peer separation, observed restart counters and crash recovery."""
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition, description):
    if not condition:
        raise RuntimeError("Acceptance gate failed: " + description)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "experiments/local/deployed-verification.json")
    args = parser.parse_args()
    binary = ROOT / "target/debug" / ("symbiote.exe" if sys.platform == "win32" else "symbiote")
    with tempfile.TemporaryDirectory(prefix="symbiote-deployment-check-") as temp:
        base = Path(temp)

        def run(command, state, fault=None, expected=0):
            cmd = [binary, command, "--json", "--state", state]
            if command == "network-research":
                cmd += ["--receipts", base / "report.json"]
            if fault:
                cmd += ["--fault", fault]
            result = subprocess.run([str(x) for x in cmd], capture_output=True, text=True, cwd=ROOT, timeout=90)
            if result.returncode != expected:
                raise RuntimeError(f"{command}: exit {result.returncode}: {result.stderr}")
            return json.loads(result.stdout) if expected == 0 else result.stderr

        state = base / "normal"
        report = run("network-research", state)
        require(report['status'] == 'PASS', "verify_deployed.py:39: report['status'] == 'PASS'")
        owners = [report["identity"]] + [p["identity"] for p in report["participants"]]
        require(len(set(owners)) == 3, 'verify_deployed.py:41: len(set(owners)) == 3')
        pids = [report["controller_pid"]] + [p["pid"] for p in report["participants"]]
        require(len(set(pids)) == 3, 'verify_deployed.py:43: len(set(pids)) == 3')
        for participant in report["participants"]:
            require(participant['promotion']['correct'] == participant['promotion']['total'] == 11, "verify_deployed.py:45: participant['promotion']['correct'] == participant['promotion']['total'] == 11")
            require(participant['instance_nonce'] != participant['restart_instance_nonce'], "verify_deployed.py:46: participant['instance_nonce'] != participant['restart_instance_nonce']")
            require(all((count == 0 for count in participant['restart_oracle_requests'].values())), "verify_deployed.py:47: all((count == 0 for count in participant['restart_oracle_requests'].values()))")
        for field in ["forged_receipt_rejected", "cross_domain_receipt_rejected", "duplicate_receipt_rejected", "restart_retained_predictions"]:
            require(report[field] is True, 'verify_deployed.py:49: report[field] is True')
        migrations = []
        for role in ["exact", "linear"]:
            directory = state / "network" / role
            before = {name:(directory / name).read_bytes() for name in ["ledger.jsonl", "knowledge.jsonl"]}
            first = run("migrate", directory)
            second = run("migrate", directory)
            require(first['changed'] is True and second['changed'] is False, "verify_deployed.py:56: first['changed'] is True and second['changed'] is False")
            require(first['ledger_bytes_changed'] is False, "verify_deployed.py:57: first['ledger_bytes_changed'] is False")
            for name, content in before.items():
                require((directory / name).read_bytes() == content, 'verify_deployed.py:59: (directory / name).read_bytes() == content')
            migrations.append(first)
        after = run("network-research", state)
        for index, participant in enumerate(after["participants"]):
            require(participant['identity'] == report['participants'][index]['identity'], "verify_deployed.py:63: participant['identity'] == report['participants'][index]['identity']")
            require(participant['promotion']['promoted'] is False, "verify_deployed.py:64: participant['promotion']['promoted'] is False")
        fault_state = base / "crashed"
        run("network-research", fault_state, "crash-after-promotion", expected=1)
        exact = fault_state / "network/exact"
        committed = (exact / "knowledge.jsonl").read_bytes()
        recoveries = []
        for role in ["exact", "linear"]:
            directory = fault_state / "network" / role
            if directory.exists():
                result = run("recover", directory)
                require(result['processes_terminated'] == 0, "verify_deployed.py:74: result['processes_terminated'] == 0")
                require(result['ledgers_modified'] is False, "verify_deployed.py:75: result['ledgers_modified'] is False")
                recoveries.append(result)
        require((exact / 'knowledge.jsonl').read_bytes() == committed, "verify_deployed.py:77: (exact / 'knowledge.jsonl').read_bytes() == committed")
        recovered = run("network-research", fault_state)
        require(recovered['participants'][0]['promotion']['promoted'] is False, "verify_deployed.py:79: recovered['participants'][0]['promotion']['promoted'] is False")
        output = args.output.parent
        output.mkdir(parents=True, exist_ok=True)
        (output / "native-process-exchange.json").write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
        verification = dict(schema="symbiote.deployment-verification/1", status="PASS", three_distinct_processes_and_private_identities=True, private_models_survive_real_restart=True, measured_restart_oracle_requests=dict(observe=report["restart_acquisition_requests"], verify=report["restart_verification_requests"], assess=report["restart_assessment_requests"]), byte_preserving_idempotent_migrations=True, crash_after_commit_retained=True, explicit_recovery_killed_no_processes=True, migrations=migrations, recoveries=recoveries, committed_knowledge_sha256=hashlib.sha256(committed).hexdigest(), performance_claim="none; deployment/persistence experiment only")
        args.output.write_text(json.dumps(verification, indent=2)+"\n", encoding="utf-8")
        print(json.dumps(verification, indent=2))


if __name__ == "__main__":
    main()
