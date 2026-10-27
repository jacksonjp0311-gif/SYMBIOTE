"""Reproduce v0.2 exchange, negative controls, offline retention and both ledgers."""
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
    parser.add_argument("--output", type=Path, default=ROOT / "experiments/local/research-verification.json")
    args = parser.parse_args()
    binary = ROOT / "target/debug" / ("symbiote.exe" if sys.platform == "win32" else "symbiote")
    if not binary.exists():
        raise RuntimeError("Build first: cargo build --workspace --locked")
    with tempfile.TemporaryDirectory(prefix="symbiote-research-check-") as temp:
        state = Path(temp) / "state"
        receipt = Path(temp) / "report.json"

        def run(command, partner=False):
            cmd = [binary, command, "--json", "--state", state / "research-partner" if partner else state]
            if command == "research":
                cmd += ["--receipts", receipt]
            result = subprocess.run([str(x) for x in cmd], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=180)
            if result.returncode:
                raise RuntimeError(f"{command} failed: {result.stderr}")
            return json.loads(result.stdout)

        first = run("research")
        require(first['status'] == 'PASS' and first['cases'] == 24 and (first['promoted'] == 48), "verify_research.py:39: first['status'] == 'PASS' and first['cases'] == 24 and (first['promoted'] == 48)")
        require(all(first['negative_controls'].values()), "verify_research.py:40: all(first['negative_controls'].values())")
        require(first['aggregate']['correct'] == first['aggregate']['heldout_predictions'], "verify_research.py:41: first['aggregate']['correct'] == first['aggregate']['heldout_predictions']")
        for participant in first["participants"]:
            require(participant['correct'] == participant['isolated_correct'] == participant['total'], "verify_research.py:43: participant['correct'] == participant['isolated_correct'] == participant['total']")
            require(participant['exchange_cost'] < participant['isolated_cost'], "verify_research.py:44: participant['exchange_cost'] < participant['isolated_cost']")
            require(participant['own_oracle_queries'] == participant['width'] + 1, "verify_research.py:45: participant['own_oracle_queries'] == participant['width'] + 1")
            parts = participant["cost_breakdown"]
            require(sum(parts.values()) == participant['exchange_cost'], "verify_research.py:47: sum(parts.values()) == participant['exchange_cost']")
        own_bytes = (state / "knowledge.jsonl").read_bytes()
        partner_bytes = (state / "research-partner/knowledge.jsonl").read_bytes()
        own = run("predict")
        partner = run("predict", partner=True)
        require(own['identity'] == first['identity'] and partner['identity'] == first['partner_identity'], "verify_research.py:52: own['identity'] == first['identity'] and partner['identity'] == first['partner_identity']")
        require(own['identity'] != partner['identity'], "verify_research.py:53: own['identity'] != partner['identity']")
        for retained in [own, partner]:
            require(retained['structural_artifacts'] == 24 and retained['network_requests'] == 0, "verify_research.py:55: retained['structural_artifacts'] == 24 and retained['network_requests'] == 0")
        require((state / 'knowledge.jsonl').read_bytes() == own_bytes, "verify_research.py:56: (state / 'knowledge.jsonl').read_bytes() == own_bytes")
        require((state / 'research-partner/knowledge.jsonl').read_bytes() == partner_bytes, "verify_research.py:57: (state / 'research-partner/knowledge.jsonl').read_bytes() == partner_bytes")
        rerun = run("research")
        require(rerun['promoted'] == 0 and rerun['already_retained'] == 48, "verify_research.py:59: rerun['promoted'] == 0 and rerun['already_retained'] == 48")
        require(rerun['aggregate'] == first['aggregate'], "verify_research.py:60: rerun['aggregate'] == first['aggregate']")
        require((state / 'knowledge.jsonl').read_bytes() == own_bytes, "verify_research.py:61: (state / 'knowledge.jsonl').read_bytes() == own_bytes")
        require((state / 'research-partner/knowledge.jsonl').read_bytes() == partner_bytes, "verify_research.py:62: (state / 'research-partner/knowledge.jsonl').read_bytes() == partner_bytes")
        out = args.output.parent
        out.mkdir(parents=True, exist_ok=True)
        (out / "reciprocal-exchange.json").write_text(json.dumps(first, indent=2)+"\n", encoding="utf-8")
        (out / "retained-predictions.json").write_text(json.dumps(own, indent=2)+"\n", encoding="utf-8")
        (out / "symbiote-knowledge.jsonl").write_bytes(own_bytes)
        (out / "partner-knowledge.jsonl").write_bytes(partner_bytes)
        sources = sorted(set(ROOT.glob("crates/**/*.rs")) | set(ROOT.glob("crates/**/Cargo.toml")) | {ROOT / "Cargo.toml", ROOT / "Cargo.lock", Path(__file__).resolve()})
        digest = hashlib.sha256()
        for source in sources:
            digest.update(source.relative_to(ROOT).as_posix().encode()+b"\0"+source.read_bytes().replace(b"\r\n",b"\n"))
        verification = dict(schema="symbiote.research-verification/1", status="PASS", source_sha256=digest.hexdigest(), aggregate=first["aggregate"], negative_controls=first["negative_controls"], separate_persistent_identities=True, offline_predictions_after_restart=True, ledger_unchanged_on_read=True, rerun_reconstructs_fresh_learners=True, rerun_duplicates_not_promoted=True, legacy_gates="required separately by tools/verify.py", scientific_status="Declared affine laboratory and trusted oracle-registry assumptions; stable v1.0 criteria remain open")
        args.output.write_text(json.dumps(verification, indent=2)+"\n", encoding="utf-8")
        print(json.dumps(verification, indent=2))


if __name__ == "__main__":
    main()
