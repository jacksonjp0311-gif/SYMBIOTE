"""Reproduce the fixed routing cohort and independently recompute its receipts."""
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition, description):
    if not condition:
        raise RuntimeError("Graph acceptance HOLD: " + description)


def total(meter, price):
    fields = ["acquisitions", "endpoint_requests", "oracle_requests", "sessions", "sent_bytes", "received_bytes", "verified_receipts", "adopted_edges", "route_queries", "model_work", "exported_bytes"]
    require(set(meter) == set(fields), "unknown or omitted cost category")
    require(all(type(meter[field]) is int and meter[field] >= 0 for field in fields), "invalid measured cost count")
    require(meter["acquisitions"] <= 4 and meter["endpoint_requests"] <= 32 and meter["oracle_requests"] <= 16 and meter["model_work"] <= 10_000 and meter["sent_bytes"] <= 65_536 and meter["received_bytes"] <= 65_536, "predeclared participant budget exceeded")
    kib = lambda count: (count + 1023) // 1024
    return meter["acquisitions"] * price + meter["endpoint_requests"] + meter["oracle_requests"] + 2 * meter["sessions"] + kib(meter["sent_bytes"]) + kib(meter["received_bytes"]) + 2 * meter["verified_receipts"] + meter["adopted_edges"] + meter["route_queries"] + meter["model_work"] + kib(meter["exported_bytes"])


def classify(before, after, old_cost, new_cost):
    if after < before:
        return "lower_coverage"
    if after > before:
        return "improved_coverage"
    if new_cost < old_cost:
        return "equal_coverage_lower_cost"
    if new_cost > old_cost:
        return "equal_coverage_higher_cost"
    return "neutral"


def validate(report):
    protocol = (ROOT / "docs/RESEARCH_V04_PROTOCOL.md").read_bytes().replace(b"\r\n", b"\n")
    require(report["schema"] == "symbiote.graph-research/1" and report["status"] == "PASS", "runtime cohort failed")
    require(report["protocol_sha256"] == hashlib.sha256(protocol).hexdigest(), "compiled protocol differs from the fixed document")
    require(report["endpoint_process_separation"] is False, "graph endpoint process boundary changed without new evidence")
    require(report["incorrect_certificates"] == 0, "a conditional certificate was wrong")
    require(set(report["negative_controls"]) >= {"duplicate", "forged", "previous_authority", "wrong_context", "wrong_source"} and all(value is True for value in report["negative_controls"].values()), "receipt negative control failed")
    require(report["restart_retained_predictions"] is True and report["process_id"] != report["restart_process_id"], "actual offline process replay did not pass")
    require(report["oracle_requests_before_restart"] == report["oracle_requests_after_restart"], "offline forecast contacted the authority")
    require(report["restart_oracle_requests"] == {"observe": 0, "verify": 0}, "measured restart requests were nonzero")
    require(len(report["regimes"]) == 2, "the predeclared price regimes are incomplete")
    summaries = []
    for regime, (name, price) in zip(report["regimes"], [("normal", 100), ("cheap_observation", 1)]):
        require(regime["name"] == name and regime["observation_price"] == price, "price regime was changed")
        require(len(regime["cases"]) == regime["worlds"] == 81, "a world was omitted or duplicated")
        classes = Counter({outcome: 0 for outcome in ["improved_coverage", "equal_coverage_lower_cost", "neutral", "equal_coverage_higher_cost", "lower_coverage"]})
        old_sum = new_sum = bilateral = 0
        for world, case in enumerate(regime["cases"]):
            require(case["world"] == world and case["costs"] == [world // (3 ** edge) % 3 + 1 for edge in range(4)], "world weights differ from the fixed complete enumeration")
            require(len(case["participants"]) == 2, "paired participant missing")
            both = True
            for participant, agent in zip(case["participants"], ["graph-dijkstra", "graph-paths"]):
                require(participant["agent"] == agent and participant["heldout_total"] == 2, "a fixed held-out task or learner was omitted")
                for arm in ["isolated", "exchange"]:
                    correct = 0
                    forecasts = participant[arm + "_forecasts"]
                    require(len(forecasts) == 2, "fixed held-out tasks were filtered")
                    for query, prediction in enumerate(forecasts):
                        if prediction is not None:
                            require(prediction["nodes"] == [query + 1, 3] and prediction["edges"] == [query * 2 + 1] and prediction["cost"] == case["costs"][query * 2 + 1] and prediction["cost_basis"] == "observed_edge_costs" and prediction["conditional"] is True, "held-out certificate does not match the independent edge label")
                            correct += 1
                    require(participant[arm + "_heldout_correct"] == correct and participant[arm + "_abstentions"] == 2 - correct, "coverage or abstention count was misstated")
                old_cost, new_cost = total(participant["isolated"], price), total(participant["exchange"], price)
                require(participant["isolated_cost"] == old_cost and participant["exchange_cost"] == new_cost, "cost total differs from measured categories")
                old_sum += old_cost
                new_sum += new_cost
                before, after = participant["isolated_heldout_correct"], participant["exchange_heldout_correct"]
                outcome = classify(before, after, old_cost, new_cost)
                require(participant["comparison"] == outcome, "utility comparison was mislabeled")
                classes[outcome] += 1
                both = both and after >= before and (after > before or new_cost < old_cost)
                if name == "normal":
                    expected = "promoted" if after == 2 else "withheld_abstention"
                    require(participant["promotion"] == expected, "promotion did not respect both held-out tasks")
            bilateral += int(both)
        require(dict(classes) == regime["classes"] and bilateral == regime["bilateral_benefit_worlds"], "aggregate utility classes differ from the cases")
        require(old_sum == regime["isolated_cost"] and new_sum == regime["exchange_cost"], "aggregate costs differ from the cases")
        summaries.append(dict(name=name, worlds=81, participant_comparisons=162, isolated_cost=old_sum, exchange_cost=new_sum, bilateral_benefit_worlds=bilateral, classes=dict(classes)))
    return summaries


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "experiments/local/graph-verification.json")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    receipt = args.output.with_name("graph-exchange.json")
    binary = ROOT / "target/debug" / ("symbiote.exe" if sys.platform == "win32" else "symbiote")
    with tempfile.TemporaryDirectory(prefix="symbiote-graph-verification-") as directory:
        state = Path(directory) / "state"
        result = subprocess.run([str(binary), "graph-research", "--json", "--state", str(state), "--receipts", str(receipt)], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=120)
        require(result.returncode == 0, result.stderr[-4000:])
        report = json.loads(result.stdout)
        require(report == json.loads(receipt.read_text(encoding="utf-8")), "CLI report and persisted receipt differ")
        summaries = validate(report)
        query = report["example_query"]
        ledger = Path(query["state"]) / "knowledge.jsonl"
        before = ledger.read_bytes()
        retained = subprocess.run([str(binary), "route", "--json", "--state", query["state"], "--artifact", query["artifact"], "--from", "1", "--to", "3"], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=10)
        require(retained.returncode == 0, "public retained-route query failed")
        forecast = json.loads(retained.stdout)
        require(forecast["route"]["nodes"] == [1, 3] and forecast["prediction_status"] == "conditionally-certified" and forecast["network_requests"] == 0, "public query lacked a retained conditional certificate")
        require(ledger.read_bytes() == before, "public query rewrote the ledger")
    verification = dict(schema="symbiote.graph-verification/1", status="PASS", protocol_sha256=report["protocol_sha256"], regimes=summaries, promotions=report["promotions"], negative_controls=report["negative_controls"], actual_offline_restart=True, measured_restart_oracle_requests=report["restart_oracle_requests"], public_route_query=True, retained_ledger_unchanged=True, limitations=report["limitations"], cost_scope=report["cost_scope"])
    args.output.write_text(json.dumps(verification, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(verification, indent=2))


if __name__ == "__main__":
    main()
