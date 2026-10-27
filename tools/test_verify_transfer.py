"""Handcrafted graphs/receipts only: never run a prospective generator or pilot."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import verify_transfer as v


def diamond(context="manual-calibration-a"):
    return {"context": context, "schema": {"nodes": 4, "edges": [
        {"from": a, "to": b, "lower": 1, "upper": 9}
        for a, b in ((0, 1), (1, 3), (0, 2), (2, 3))]},
        "start": 0, "goal": 3, "costs": [1, 9, 1, 1]}


def source_record():
    traces = []
    for context in ("manual-source-a", "manual-source-b"):
        t = diamond(context)
        traces.append({k: t[k] for k in ("context", "schema", "start", "goal")} |
                      {"observations": [{"edge": 0, "cost": 1}, {"edge": 1, "cost": 9}]})
    return {"id": "manual-source-policy", "revision": 1, "source": "symbiote-" + "1" * 24,
            "policy": v.policy(["to-goal", "from-start"]), "training": traces,
            "provenance": "Manual source fixture; no cohort generation"}


def write_strategy(directory, tamper=None):
    identity = "symbiote-" + "1" * 24
    owner_payload = {"event": "genesis", "version": 1, "identity": identity}
    body = {"sequence": 0, "previous": v.ZERO, "payload": owner_payload}
    owner_row = dict(body, sha256=v.sha(v.compact(body)))
    owner_bytes = v.compact(owner_row) + b"\n"
    (directory / "ledger.jsonl").write_bytes(owner_bytes)
    record = source_record()
    calibration = [diamond("manual-calibration-a"), diamond("manual-calibration-b")]
    a = v.assessment(record, calibration, [], None)
    if tamper:
        tamper(a)
    payloads = [{"event": "genesis", "version": 1, "identity": identity,
                 "owner_genesis_sha256": v.sha(owner_bytes)},
                {"event": "considered", "record": record, "calibration": calibration, "assessment": a}]
    rows, previous = [], v.ZERO
    for sequence, payload in enumerate(payloads):
        row = {"sequence": sequence, "previous": previous, "payload": payload,
               "sha256": v.digest([sequence, previous, payload])}
        rows.append(row)
        previous = row["sha256"]
    (directory / "strategy.jsonl").write_bytes(b"".join(v.compact(row) + b"\n" for row in rows))
    (directory / "strategy-owner.json").write_bytes(v.compact({"schema": "symbiote.strategy-owner/1",
        "identity": identity, "owner_genesis_sha256": v.sha(owner_bytes), "strategy_genesis_sha256": rows[0]["sha256"]}))
    return identity, v.sha(owner_bytes)


def manual_graph_promotion():
    task = {"context": "manual-retention", "schema": {"nodes": 5, "edges": [
        {"from": i, "to": i + 1, "lower": 1, "upper": 9} for i in range(4)]},
        "start": 0, "goal": 4, "costs": [1, 2, 1, 1]}
    owner, authority, price = "symbiote-" + "1" * 24, "symbiote-" + "2" * 24, 100
    result = v.trial(task)
    fingerprint = v.graph_fingerprint(task["schema"])
    observations = [{"edge_id": i, "cost": c} for i, c in enumerate(task["costs"])]
    record = {"id": f"retained-{v.digest(task)}", "revision": 1, "source": owner, "scope": task["context"],
              "schema_fingerprint": fingerprint, "payload": {"kind": "graph-map", "schema": task["schema"],
              "observations": observations}, "provenance": "Manual complete positive chain"}
    acquisitions = []
    for i, cost in enumerate(task["costs"]):
        identifier = v.digest([authority, owner, task["context"], fingerprint, i, i, cost])
        envelope = {"schema": "symbiote.graph-observation/1", "authority_id": authority, "context": task["context"],
                    "schema_fingerprint": fingerprint, "observer_identity": owner, "sequence": i,
                    "id": identifier, "edge_id": i, "cost": cost}
        acquisitions.append({"id": identifier, "edge_id": i, "cost": cost,
                             "receipt_sha256": v.digest(envelope), "receipt": envelope})
    evidence = {"evaluator": authority, "acquisitions": acquisitions,
                "training_tasks": [{"id": "main-acquisition-route", "input": 4}],
                "cases": [{"id": "subroute-0", "input": 1, "expected": 1, "baseline": None, "candidate": 1},
                          {"id": "subroute-1", "input": 19, "expected": 1, "baseline": None, "candidate": 1}],
                "costs": {"acquisition": 400, "verification": 860, "adoption": 1, "baseline": 0, "candidate": 1261}}
    assessment = {"heldout_route_queries": 2, "baseline_correct": 0, "candidate_correct": 2, "regressions": 0,
                  "baseline_cost": 0, "candidate_cost": 1261, "coverage_improved": True, "cost_improved": False,
                  "authority_id": authority, "record_digest": v.sha(v.compact(v.typed_record(record))), "evidence": evidence}
    return {"event": "promote_graph", "record": record, "assessment": assessment, "policy_version": 2}, task, result, owner, authority, price


class IndependentVerifierManualTests(unittest.TestCase):
    def test_default_and_role_policy_execute_distinct_real_queries(self):
        task = diamond()
        baseline = v.trial(task)
        candidate = v.trial(task, v.policy(["to-goal", "from-start"]))
        self.assertEqual(baseline["queried_edges"], [0, 1, 2, 3])
        self.assertEqual(candidate["queried_edges"], [1, 3, 2])
        self.assertEqual(candidate["certified_cost"], 2)
        self.assertTrue(v.correct(baseline) and v.correct(candidate))
        self.assertGreater(candidate["policy_work"], 0)

    def test_exact_observed_source_ratio_and_context_separation(self):
        record = source_record()
        prior, work, count = v.derive(record["training"])
        self.assertEqual(prior, record["policy"])
        self.assertEqual((work, count), (12, 4))
        altered = copy.deepcopy(record)
        altered["policy"] = v.policy(["from-start", "to-goal"])
        with self.assertRaises(v.Hold):
            v.validate_record(altered)
        altered = copy.deepcopy(record)
        altered["training"][1]["context"] = altered["training"][0]["context"]
        with self.assertRaises(v.Hold):
            v.validate_record(altered)

    def test_observed_drift_records_rejected_query_but_no_accepted_fact(self):
        task = diamond()
        task["costs"][0] = 10
        result = v.trial(task)
        self.assertEqual(result["status"], "contradicted")
        self.assertEqual(result["queried_edges"], [0])
        self.assertEqual(result["observations"], [])
        self.assertIsNone(result["certified_cost"])
        self.assertEqual(result["model_work"], 12)
        self.assertEqual(result["evaluator_work"], 8)

    def test_query_model_policy_budgets_fail_closed(self):
        task = diamond()
        self.assertEqual(v.trial(task, limits=dict(v.LIMITS, max_queries=0))["status"], "query-budget")
        self.assertEqual(v.trial(task, limits=dict(v.LIMITS, model_work=2))["model_work"], 2)
        result = v.trial(task, v.policy(["to-goal"]), dict(v.LIMITS, policy_work=1))
        self.assertEqual(result["status"], "policy-budget")
        self.assertEqual(result["queried_edges"], [])

    def test_inverted_actual_costs_show_harm_without_family_label(self):
        task = diamond("manual-inverted")
        task["costs"] = [9, 1, 1, 1]
        comparison = v.compare(task, v.policy(["to-goal", "from-start"]))
        self.assertTrue(v.regression(comparison))
        self.assertTrue(v.correct(comparison["candidate"]))

    def test_typed_strategy_hash_owner_and_recomputed_raw_assessment(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            identity, genesis = write_strategy(path)
            result = v.verify_strategy(path, path, identity, genesis)
            self.assertEqual(result["selected"]["id"], "manual-source-policy")
            self.assertEqual(result["rows"][-1]["payload"]["assessment"]["candidate_queries"], 6)
            with self.assertRaises(v.Hold):
                v.verify_strategy(path, path, "symbiote-" + "2" * 24, genesis)

    def test_rehashed_false_metrics_still_fail_independent_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            identity, genesis = write_strategy(path, lambda a: a.update(candidate_queries=0))
            with self.assertRaisesRegex(v.Hold, "assessment"):
                v.verify_strategy(path, path, identity, genesis)

    def test_chain_truncation_changed_previous_and_unknown_fields_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            identity, genesis = write_strategy(path)
            journal = path / "strategy.jsonl"
            raw = journal.read_bytes()
            journal.write_bytes(raw[:-1])
            with self.assertRaises(v.Hold):
                v.verify_strategy(path, path, identity, genesis)
            journal.write_bytes(raw.replace(v.ZERO.encode(), b"f" * 64, 1))
            with self.assertRaises(v.Hold):
                v.verify_strategy(path, path, identity, genesis)
        with self.assertRaises(v.Hold):
            v.decode(b'{"status":"PASS","status":"HOLD"}')
        with self.assertRaises(v.Hold):
            v.equal(True, 1, "bool integer confusion")

    def test_graph_retention_recomputes_real_forecasts_work_and_subroute_truth(self):
        args = manual_graph_promotion()
        result = v.verify_graph_promotion(*args)
        self.assertEqual(result["main_cost"], 5)
        self.assertEqual(result["retention_work"], 92)
        self.assertEqual(result["replay_work"], 52)
        self.assertEqual(len(result["cases"]), 2)

    def test_hash_bound_envelope_cannot_change_observer_or_edge_cost(self):
        args = list(manual_graph_promotion())
        args[0]["assessment"]["evidence"]["acquisitions"][0]["receipt"]["observer_identity"] = "foreign"
        with self.assertRaises(v.Hold):
            v.verify_graph_promotion(*args)
        args = list(manual_graph_promotion())
        args[0]["record"]["payload"]["observations"][0]["cost"] = 2
        with self.assertRaises(v.Hold):
            v.verify_graph_promotion(*args)

    def test_retention_over_63_output_rejected_explicitly(self):
        schema = {"nodes": 12, "edges": [{"from": i, "to": i + 1, "lower": 1, "upper": 9} for i in range(11)]}
        observations = [{"edge_id": i, "cost": 9} for i in range(11)]
        with self.assertRaisesRegex(v.Hold, "cost"):
            v.forecast(schema, observations, 11)
        route, work = v.forecast(schema, [{"edge_id": i, "cost": 1} for i in range(11)], 11)
        self.assertEqual(route["cost"], 11)
        self.assertEqual(work, 132)

    def test_graph_typed_ledger_hash_and_rehashed_false_envelope(self):
        payload, task, result, owner, authority, price = manual_graph_promotion()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            genesis = {"event": "genesis", "version": 1, "identity": owner}
            rows, previous = [], v.ZERO
            for sequence, event in enumerate((genesis, payload)):
                h = v.sha(v.compact([sequence, previous, v.typed_payload(event, "knowledge")]))
                rows.append({"sequence": sequence, "previous": previous, "payload": event, "sha256": h})
                previous = h
            path = root / "knowledge.jsonl"
            path.write_bytes(b"".join(v.compact(row) + b"\n" for row in rows))
            parsed, prefixes, _ = v.chain(path, "knowledge", root)
            self.assertEqual(prefixes[rows[-1]["sha256"]]["rows"], 2)
            v.verify_graph_promotion(parsed[1]["payload"], task, result, owner, authority, price)
            rows[1]["payload"]["assessment"]["evidence"]["cases"][0]["expected"] = 2
            rows[1]["sha256"] = v.sha(v.compact([1, rows[1]["previous"], v.typed_payload(rows[1]["payload"], "knowledge")]))
            path.write_bytes(b"".join(v.compact(row) + b"\n" for row in rows))
            forged, _, _ = v.chain(path, "knowledge", root)
            with self.assertRaises(v.Hold):
                v.verify_graph_promotion(forged[1]["payload"], task, result, owner, authority, price)

    def test_registration_binds_actual_executable_and_protocol_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            native, document = v.sha(b"manual executable bytes; never run"), v.sha(b"manual protocol")
            protocol = {"id": v.PROTOCOL, "family": v.FAMILY, "controls": list(v.ARMS),
                        "targets_used_for_policy_promotion": False, "source_calibration_target_contexts_disjoint": True,
                        "limits": {"seconds": 60, "max_actor_cost": 10_000_000, "trial": v.LIMITS}}
            registration = {"schema": "symbiote.query-transfer-registration/1", "source_commit": "a" * 40,
                            "native_sha256": native, "protocol_document_sha256": document,
                            "state_directory": str(root / "absent-state"), "protocol": protocol,
                            "protocol_sha256": v.digest(protocol), "cohort": v.COHORT, "cohort_sha256": v.digest(v.COHORT)}
            path = root / "manual-registration.json"
            raw = v.compact(registration)
            path.write_bytes(raw)
            v.verify_registration(path, v.sha(raw), "a" * 40, native, document)
            with self.assertRaises(v.Hold):
                v.verify_registration(path, v.sha(raw), "a" * 40, "f" * 64, document)
            with self.assertRaises(v.Hold):
                v.verify_registration(path, "0" * 64, "a" * 40, native, document)

    def test_complete_canonical_witness_and_ambiguity_abstention(self):
        task = diamond("manual-canonical")
        task["schema"]["edges"][2]["lower"] = 2
        task["costs"][2] = 2
        witness = v.canonical_task(task)
        mapping, order = [2, 0, 3, 1], [3, 1, 0, 2]
        remapped = copy.deepcopy(task)
        remapped["start"], remapped["goal"] = mapping[0], mapping[3]
        remapped["schema"]["edges"] = [dict(task["schema"]["edges"][i], **{
            "from": mapping[task["schema"]["edges"][i]["from"]],
            "to": mapping[task["schema"]["edges"][i]["to"]]}) for i in order]
        remapped["costs"] = [task["costs"][i] for i in order]
        self.assertEqual(witness, v.canonical_task(remapped))
        symmetric = diamond("manual-symmetric")
        symmetric["costs"] = [1] * 4
        with self.assertRaisesRegex(v.Hold, "ambiguous"):
            v.canonical_task(symmetric)

    def test_missing_cell_is_hold_never_not_demonstrated(self):
        with self.assertRaises(v.Hold):
            v.target_inventory([])

    def test_unavailable_or_escaping_raw_files_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(v.Hold):
                v.read(root.parent / "unrelated-file.json", root)


if __name__ == "__main__":
    unittest.main()
