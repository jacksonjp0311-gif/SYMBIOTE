"""Reproduce final-tree gates and independent-process learning/restart receipts."""
import argparse
import json
import hashlib
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TIMEOUT_DIAGNOSTICS = ROOT / "experiments/local/verify-timeouts"
TIMEOUT_TAIL_BYTES = 32 * 1024


def require(condition, description):
    if not condition:
        raise RuntimeError("Acceptance gate failed: " + description)


def count_native_tests(output):
    count = sum(int(value) for value in re.findall(r"test result: ok\. (\d+) passed;", output))
    require(count > 0, "native test output must report executed passing tests")
    return count


def count_python_tests(output):
    match = re.search(r"Ran (\d+) tests", output)
    require(match is not None and int(match.group(1)) > 0, "Python discovery must report executed tests")
    return int(match.group(1))


def preserve_timeout(args, failure, elapsed):
    """Preserve bounded partial tails and original capture hashes; never regrade."""
    report = dict(schema="symbiote.verifier-timeout/1", status="HOLD_TIMEOUT", argv=[str(x) for x in args],
                  timeout_seconds=300, elapsed_seconds=elapsed,
                  scope="partial subprocess capture only; cold compilation versus test execution is not inferred")
    tails = {}
    for name, captured in (("stdout", failure.stdout), ("stderr", failure.stderr)):
        known_bytes = isinstance(captured, bytes)
        raw = captured if known_bytes else (captured.encode("utf-8") if isinstance(captured, str) else b"")
        tail = raw[-TIMEOUT_TAIL_BYTES:]
        tails[name] = tail
        report[name] = dict(capture_available=captured is not None, captured_bytes=len(raw),
                            capture_sha256=hashlib.sha256(raw).hexdigest() if captured is not None else None,
                            hash_basis="original captured bytes" if known_bytes else "UTF-8 reencoding of captured text" if isinstance(captured,str) else "capture unavailable",
                            original_pipe_bytes_known=known_bytes, tail_bytes=len(tail),
                            tail_sha256=hashlib.sha256(tail).hexdigest(), tail_file=name+".tail")
    try:
        TIMEOUT_DIAGNOSTICS.mkdir(parents=True, exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix="timeout-", dir=TIMEOUT_DIAGNOSTICS))
        for name, tail in tails.items():
            with (directory / (name+".tail")).open("xb") as output:
                output.write(tail)
        report["directory"] = str(directory)
        with (directory / "timeout.json").open("x", encoding="utf-8", newline="\n") as output:
            json.dump(report, output, ensure_ascii=False, allow_nan=False, indent=2)
            output.write("\n")
    except OSError as error:
        report["diagnostic_save_error"] = str(error)
    print("HOLD_VERIFICATION_TIMEOUT " + json.dumps(report, ensure_ascii=False), file=sys.stderr, flush=True)
    for name, tail in tails.items():
        if tail:
            print(f"--- captured {name} tail (at most {TIMEOUT_TAIL_BYTES} bytes; UTF-8 rendering) ---", file=sys.stderr)
            print(tail.decode("utf-8", errors="replace"), file=sys.stderr, flush=True)
    return report


def execute(args, *, expected=0):
    started = time.monotonic()
    try:
        result = subprocess.run([str(x) for x in args], cwd=ROOT, text=True, encoding="utf-8", capture_output=True, timeout=300)
    except subprocess.TimeoutExpired as failure:
        preserve_timeout(args, failure, time.monotonic() - started)
        raise
    if result.returncode != expected:
        raise RuntimeError(f"{args[0]} returned {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result


def main():
    global TIMEOUT_DIAGNOSTICS
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-cargo", action="store_true")
    parser.add_argument("--skip-parity", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "experiments/local/genesis-verification.json")
    parser.add_argument("--summary", type=Path, default=ROOT / "experiments/local/software-verification.json")
    parser.add_argument("--timeout-diagnostics", type=Path, default=TIMEOUT_DIAGNOSTICS)
    args = parser.parse_args()
    TIMEOUT_DIAGNOSTICS = args.timeout_diagnostics
    native_tests = None
    if not args.skip_cargo:
        for command in [["cargo", "fmt", "--all", "--", "--check"], ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"], ["cargo", "test", "--workspace", "--locked"], ["cargo", "build", "--workspace", "--locked"], ["cargo", "build", "--release", "--locked", "-p", "symbiote-runtime", "--bin", "symbiote"]]:
            checked = execute(command)
            if command[1] == "test":
                native_tests = count_native_tests(checked.stdout)
            print("PASS", " ".join(command), flush=True)
    if not args.skip_parity:
        result = execute([sys.executable, ROOT / "tools" / "parity.py", "--output", ROOT / "experiments" / "parity.json"])
        print(result.stdout.strip(), flush=True)
    packaged = execute([sys.executable, "-m", "unittest", "discover", "-s", "tools", "-p", "test_*.py"])
    package_tests = count_python_tests(packaged.stderr)
    print("PASS release packaging and native installer integrity tests", flush=True)
    release_tools = execute([sys.executable, "-m", "unittest", "discover", "-s", "tools/release", "-p", "test_*.py"])
    release_tool_tests = count_python_tests(release_tools.stderr)
    print("PASS evidence packaging and release workflow provenance tests", flush=True)
    binary = ROOT / "target" / "debug" / ("symbiote.exe" if sys.platform == "win32" else "symbiote")
    with tempfile.TemporaryDirectory(prefix="symbiote-verification-") as directory:
        base = Path(directory)
        state = base / "learned"

        def run(command, fault=None, state_dir=state, expect=0):
            receipt = base / "latest.json"
            cmd = [binary, command, "--json", "--state", state_dir]
            if command in {"demo", "benchmark", "research"}:
                cmd += ["--receipts", receipt]
            if fault:
                cmd += ["--fault", fault]
            result = execute(cmd, expected=expect)
            if expect:
                return json.loads(receipt.read_text())
            return json.loads(result.stdout)

        first = run("demo")
        retained = run("predict")
        restart = run("demo")
        require(first['promoted'] == 2 and first['reused'] == 0, "verify.py:68: first['promoted'] == 2 and first['reused'] == 0")
        require(restart['promoted'] == 0 and restart['reused'] == 2, "verify.py:69: restart['promoted'] == 0 and restart['reused'] == 2")
        require(first['identity'] == retained['identity'] == restart['identity'], "verify.py:70: first['identity'] == retained['identity'] == restart['identity']")
        require(retained['active_artifacts'] == 2 and retained['network_requests'] == 0, "verify.py:71: retained['active_artifacts'] == 2 and retained['network_requests'] == 0")
        for participant in first["participants"]:
            s, p = participant["symbiote"], participant["partner_benefit"]
            require((s['isolated_correct'], s['exchange_correct'], s['matched_probe_control_correct']) == (16, 32, 32), "verify.py:74: (s['isolated_correct'], s['exchange_correct'], s['matched_probe_control_correct']) == (16, 32, 32)")
            require((p['baseline_resource_units'], p['strategy_resource_units_including_verification']) == (176, 72), "verify.py:75: (p['baseline_resource_units'], p['strategy_resource_units_including_verification']) == (176, 72)")
        failure = run("demo", "wrong-artifact", base / "rejected", expect=1)
        require(failure['status'] == 'REJECTED', "verify.py:77: failure['status'] == 'REJECTED'")
        require(run('predict', state_dir=base / 'rejected')['active_artifacts'] == 0, "verify.py:78: run('predict', state_dir=base / 'rejected')['active_artifacts'] == 0")
        recovery = run("demo", state_dir=base / "rejected")
        require(recovery['promoted'] == 2, "verify.py:80: recovery['promoted'] == 2")
        drift = run("demo", "drift", expect=1)
        require(drift['status'] == 'REJECTED', "verify.py:82: drift['status'] == 'REJECTED'")
        after_drift = run("predict")
        require(after_drift['active_artifacts'] == 1, "verify.py:84: after_drift['active_artifacts'] == 1")
        drift_recovery = run("demo")
        require(drift_recovery['identity'] == first['identity'], "verify.py:86: drift_recovery['identity'] == first['identity']")
        require(drift_recovery['promoted'] == 1 and drift_recovery['reused'] == 1, "verify.py:87: drift_recovery['promoted'] == 1 and drift_recovery['reused'] == 1")
        recovered_predictions = run("predict")
        require(recovered_predictions['predictions'][0]['revision'] == 2, "verify.py:89: recovered_predictions['predictions'][0]['revision'] == 2")
        evidence = args.output.parent
        evidence.mkdir(parents=True, exist_ok=True)
        for name, report in [("genesis-first.json", first), ("genesis-retained.json", retained), ("genesis-restart.json", restart), ("genesis-rejected.json", failure), ("genesis-drift.json", drift)]:
            (evidence / name).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        shutil.copyfile(state / "ledger.jsonl", evidence / "genesis-ledger.jsonl")
        report = dict(schema="symbiote.verification/1", status="PASS", process_restart=True, stable_identity=True, first_promoted=2, restart_reused=2, rejected_wrong_transfer=True, failed_candidate_recovery=True, drift_revoked=True, drift_recovery_revision=2, retained_network_requests=0, symbiote=dict(isolated_correct=32, exchanged_correct=64, total=64, matched_probe_control_correct=64, verification_queries=8), partner=dict(baseline_resource_units_each=176, strategy_resource_units_each_including_verification=72), limitations=["four-input deterministic laboratory tasks", "repeated predictions are not independent samples", "same-probe-budget control also achieves complete coverage", "partner resource costs are declared simulation units", "hidden-state reasoning parity is separate from finite-table learning"])
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
    result = execute([sys.executable, ROOT / "tools/verify_research.py"])
    print(result.stdout.strip(), flush=True)
    deployed = execute([sys.executable, ROOT / "tools/verify_deployed.py"])
    print(deployed.stdout.strip(), flush=True)
    graph = execute([sys.executable, ROOT / "tools/verify_graph.py", "--output", args.output.parent / "graph-verification.json"])
    print(graph.stdout.strip(), flush=True)
    digest = hashlib.sha256()
    sources = sorted(set(ROOT.glob("crates/**/*.rs")) | set(ROOT.glob("crates/**/Cargo.toml")) | set(ROOT.glob("tools/*.py")) | set(ROOT.glob("tools/*.ps1")) | set(ROOT.glob("tools/*.sh")) | {ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "SYMBIOTE-All-One.ps1"})
    for source in sources:
        digest.update(source.relative_to(ROOT).as_posix().encode()+b"\0"+source.read_bytes().replace(b"\r\n",b"\n"))
    summary = dict(schema="symbiote.software-verification/1", status="PASS", source_sha256=digest.hexdigest(), platform=platform.system(), architecture=platform.machine(), native_tests_passed=native_tests, packaging_and_installation_tests_passed=package_tests, release_tool_tests_passed=release_tool_tests, legacy_parity_executed=not args.skip_parity, cargo_gates_executed=not args.skip_cargo, genesis_compatibility=True, structural_exchange=True, deployed_processes_migration_and_recovery=True, graph_exchange_and_retained_routes=True, stable_v1_criteria="remain separate from software gate")
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
