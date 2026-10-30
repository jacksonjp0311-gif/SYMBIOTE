"""Register and run SYMBIOTE-STRUCTURAL-TRANSFER-002.

Registration writes no target truth. The study binary generates tasks only
after the registration digest matches.
"""

import argparse
import hashlib
import json
import secrets
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "docs" / "RESEARCH_V06_PROTOCOL.md"
LEARNER = ROOT / "adapters" / "independent_affine.py"


def sha(path):
    digest = hashlib.sha256()
    digest.update(Path(path).read_bytes())
    return digest.hexdigest()


def clean_commit():
    status = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, check=True, text=True, capture_output=True)
    if status.stdout.strip():
        raise SystemExit("registration requires a clean commit")
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, text=True, capture_output=True)
    return commit.stdout.strip()


def register(executable, python, out):
    out = Path(out)
    if out.exists():
        raise SystemExit("registration requires a new artifact directory")
    commit = clean_commit()
    out.mkdir()
    registration = {
        "schema": "symbiote.structural-transfer-002-registration/1",
        "protocol": "SYMBIOTE-STRUCTURAL-TRANSFER-002",
        "protocol_sha256": sha(PROTOCOL),
        "source_commit": commit,
        "repository": str(ROOT),
        "executable": str(Path(executable).resolve()),
        "executable_sha256": sha(executable),
        "independent_learner": str(LEARNER),
        "independent_learner_sha256": sha(LEARNER),
        "python": str(Path(python).resolve()),
        "seed": secrets.token_hex(8),
        "width": 4,
        "tasks_per_owner": 4,
        "unit": "affine-oracle-check/1",
    }
    path = out / "registration.json"
    path.write_text(json.dumps(registration, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "REGISTERED_NOT_RUN", "registration": str(path), "sha256": sha(path)}))


def run(registration, expected, out):
    path = Path(registration).resolve()
    if sha(path) != expected:
        raise SystemExit("registration digest mismatch")
    registration = json.loads(path.read_text(encoding="utf-8"))
    if registration["protocol_sha256"] != sha(PROTOCOL) or registration["independent_learner_sha256"] != sha(LEARNER):
        raise SystemExit("pinned protocol or learner changed")
    if registration["executable_sha256"] != sha(registration["executable"]) or registration["source_commit"] != clean_commit():
        raise SystemExit("pinned executable or source changed")
    result_dir = Path(out)
    result_dir.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        [registration["executable"], "--registration", str(path), "--registration-sha256", expected, "--out", str(result_dir)],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    report_path = result_dir / "result.json"
    if completed.returncode != 0 or not report_path.exists():
        hold = {"schema": "symbiote.structural-transfer-002-result/1", "status": "HOLD", "returncode": completed.returncode, "stderr": completed.stderr[-2000:]}
        (result_dir / "hold.json").write_text(json.dumps(hold, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": "HOLD"}))
        raise SystemExit(completed.returncode or 2)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    print(json.dumps({"status": report["status"], "result": str(report_path), "sha256": sha(report_path)}))


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    registered = commands.add_parser("register")
    registered.add_argument("--executable", type=Path, required=True)
    registered.add_argument("--python", type=Path, required=True)
    registered.add_argument("--out", type=Path, required=True)
    launched = commands.add_parser("run")
    launched.add_argument("--registration", type=Path, required=True)
    launched.add_argument("--registration-sha256", required=True)
    launched.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "register":
        register(args.executable, args.python, args.out)
    else:
        run(args.registration, args.registration_sha256, args.out)


if __name__ == "__main__":
    main()
