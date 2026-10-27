"""Independent, read-only raw consumer for SYMBIOTE-QUERY-TRANSFER-001.

Never imports a native evaluator, opens an oracle, creates a registration, or
generates the prospective cohort. Successful integrity checks and reciprocal
benefit are separate conclusions. These checks cannot authenticate a trusted
controller against a whole-history rewriter or prove an OS-process restart.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from fractions import Fraction
import hashlib
import heapq
import json
from pathlib import Path
import re
import subprocess
import sys

PROTOCOL = "SYMBIOTE-QUERY-TRANSFER-001"
FAMILY = "finite-positive-cost-directed-graph/v1"
ROLES = ("from-start", "interior", "to-goal", "direct")
ARMS = ("isolated-prior", "fresh-default", "fixed-start", "fixed-goal", "local-trained", "exchanged")
COHORT = {"seeds": [7, 19, 43, 101], "prices": [1, 100], "target_layers": [4, 5],
          "arms": list(ARMS), "actors_per_pair": 2}
QUERY_FIELDS = ("source_queries", "calibration_queries", "calibration_truth_edges", "target_queries",
                "target_truth_edges", "retention_truth_edges", "diagnostic_queries", "diagnostic_truth_edges")
BILL_FIELDS = QUERY_FIELDS + ("computation_work", "replay_work", "exchange_bytes", "exchange_units", "adoption_units")
ZERO = "0" * 64
MAX_LEDGER = 4 * 1024 * 1024
MAX_REPORT = 64 * 1024 * 1024
LIMITS = {"max_queries": 24, "model_work": 10000, "policy_work": 10000}


class Hold(ValueError):
    """Missing, ambiguous, inconsistent, or out-of-protocol evidence."""


def require(condition, message):
    if not condition:
        raise Hold(message)


def compact(value, *, sorted_keys=False):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=sorted_keys,
                      allow_nan=False).encode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    """Rust serde_json::Value canonical encoding (all map keys sorted)."""
    return sha(compact(value, sorted_keys=True))


def equal(actual, expected, label):
    # Distinguish booleans from integers; Python's True == 1 is too permissive.
    require(compact(actual, sorted_keys=True) == compact(expected, sorted_keys=True),
            f"{label}: recorded value differs from independent recomputation")


def fields(value, keys, label):
    require(type(value) is dict and set(value) == set(keys), f"{label}: unexpected/missing typed fields")
    return value


def integer(value, lower=0, upper=10_000_000, label="integer"):
    require(type(value) is int and lower <= value <= upper, f"{label}: bounded integer required")
    return value


def label(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", value), "invalid bounded label")
    return value


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key {key}")
        result[key] = value
    return result


def decode(raw):
    try:
        return json.loads(raw, object_pairs_hook=no_duplicates,
                          parse_float=lambda _: (_ for _ in ()).throw(Hold("floating-point evidence unsupported")),
                          parse_constant=lambda _: (_ for _ in ()).throw(Hold("nonfinite JSON unsupported")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Hold(f"invalid bounded JSON: {error}") from error


def read(path, root=None, maximum=MAX_LEDGER):
    path = Path(path)
    if root is not None:
        root = Path(root).resolve()
        try:
            path.resolve().relative_to(root)
        except ValueError as error:
            raise Hold("raw evidence path escapes registered state") from error
        cursor = path
        while cursor != root and cursor != cursor.parent:
            require(not cursor.is_symlink() and not getattr(cursor, "is_junction", lambda: False)(),
                    "linked raw evidence is unsupported")
            cursor = cursor.parent
    require(path.is_file() and not path.is_symlink(), f"missing regular evidence file: {path}")
    require(path.stat().st_size <= maximum, f"evidence byte budget exceeded: {path}")
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, "evidence grew beyond byte budget")
    return raw


def graph(schema, start, goal, costs=None, *, durable=False):
    fields(schema, ("nodes", "edges"), "graph schema")
    n = integer(schema["nodes"], 2, 12 if durable else 64, "nodes")
    integer(start, 0, n - 1, "start")
    integer(goal, 0, n - 1, "goal")
    require(start != goal, "distinct route endpoints required")
    edges = schema["edges"]
    require(type(edges) is list and 1 <= len(edges) <= (56 if durable else 256), "edge count outside bound")
    pairs = set()
    for edge in edges:
        fields(edge, ("from", "to", "lower", "upper"), "edge")
        a = integer(edge["from"], 0, n - 1)
        b = integer(edge["to"], 0, n - 1)
        lo = integer(edge["lower"], 1, 9 if durable else 1000)
        integer(edge["upper"], lo, 9 if durable else 1000)
        require(a != b and (a, b) not in pairs, "duplicate/loop edge")
        pairs.add((a, b))
    if costs is not None:
        require(type(costs) is list and len(costs) == len(edges), "truth cost shape differs")
        for cost in costs:
            integer(cost, 1, 1000, "truth cost")
    return n, edges


def validate_task(task):
    fields(task, ("context", "schema", "start", "goal", "costs"), "GraphTask")
    label(task["context"])
    graph(task["schema"], task["start"], task["goal"], task["costs"])
    return task


def optimum(task):
    """Independent full-truth Bellman-Ford plus exact scan accounting."""
    validate_task(task)
    n, edges = graph(task["schema"], task["start"], task["goal"], task["costs"])
    distances = [None] * n
    distances[task["start"]] = 0
    work = 0
    for _ in range(n - 1):
        changed = False
        for edge, cost in zip(edges, task["costs"]):
            work += 1
            if distances[edge["from"]] is None:
                continue
            proposed = distances[edge["from"]] + cost
            if distances[edge["to"]] is None or proposed < distances[edge["to"]]:
                distances[edge["to"]] = proposed
                changed = True
        if not changed:
            break
    return distances[task["goal"]], work


def optimistic(schema, start, goal, observed, work=0, budget=10000):
    """Reconstruct observable exact route and native edge-scan work.

    A separate Bellman-Ford distance check prevents accepting a non-shortest
    route merely because its query history is internally consistent.
    """
    n, edges = graph(schema, start, goal)
    distance = [None] * n
    previous = [None] * n
    distance[start] = 0
    queue = [(0, start)]
    while queue:
        cost, node = heapq.heappop(queue)
        if distance[node] != cost:
            continue
        if node == goal:
            break
        for index, edge in enumerate(edges):
            if work + 1 > budget:
                return None, work, "budget_exhausted"
            work += 1
            if edge["from"] != node:
                continue
            proposed = cost + observed.get(index, edge["lower"])
            dest = edge["to"]
            if distance[dest] is None or proposed < distance[dest]:
                distance[dest], previous[dest] = proposed, index
                heapq.heappush(queue, (proposed, dest))
    if distance[goal] is None:
        return None, work, "supported"
    ids, nodes, cursor = [], [goal], goal
    while cursor != start:
        require(len(ids) < n, "route predecessor cycle")
        index = previous[cursor]
        require(index is not None, "broken route predecessor")
        ids.append(index)
        cursor = edges[index]["from"]
        nodes.append(cursor)
    ids.reverse()
    nodes.reverse()
    bound_task = {"context": "manual-observable-bound", "schema": schema, "start": start,
                  "goal": goal, "costs": [observed.get(i, e["lower"]) for i, e in enumerate(edges)]}
    equal(distance[goal], optimum(bound_task)[0], "optimistic shortest-path distance")
    return {"edges": ids, "nodes": nodes, "cost": distance[goal]}, work, "supported"


def role(schema, start, goal, edge_id):
    edge = schema["edges"][edge_id]
    if edge["from"] == start and edge["to"] == goal:
        return "direct"
    if edge["from"] == start:
        return "from-start"
    if edge["to"] == goal:
        return "to-goal"
    return "interior"


def policy(roles):
    require(type(roles) is list and 1 <= len(roles) <= 4 and len(set(roles)) == len(roles)
            and all(r in ROLES for r in roles), "unsupported query role grammar")
    return {"schema": "symbiote.optimistic-route-query-policy/1", "family": FAMILY,
            "selection_rule": "rank-unknown-optimistic-route-roles/v1", "ranked_roles": roles}


def validate_policy(value):
    fields(value, ("schema", "family", "selection_rule", "ranked_roles"), "QueryPolicy")
    equal(value, policy(value["ranked_roles"]), "portable policy grammar")
    return value


def derive(training):
    require(type(training) is list and 2 <= len(training) <= 8, "source trace count outside journal bounds")
    contexts, totals, work, observation_count = set(), {}, 0, 0
    for trace in training:
        fields(trace, ("context", "schema", "start", "goal", "observations"), "SourceTrace")
        context = label(trace["context"])
        require(context not in contexts, "duplicate source context")
        contexts.add(context)
        _, edges = graph(trace["schema"], trace["start"], trace["goal"])
        require(trace["schema"]["nodes"] <= 12 and len(edges) <= 24, "strategy graph exceeds journal bounds")
        rows = trace["observations"]
        require(type(rows) is list and 1 <= len(rows) <= len(edges), "source observations shape")
        work += len(edges) + len(rows)
        observation_count += len(rows)
        require(work <= 10000 and observation_count <= 4096, "source work/observation budget")
        seen = set()
        for row in rows:
            fields(row, ("edge", "cost"), "source observation")
            edge_id = integer(row["edge"], 0, len(edges) - 1)
            require(edge_id not in seen, "duplicate source edge")
            seen.add(edge_id)
            edge = edges[edge_id]
            cost = integer(row["cost"], edge["lower"], edge["upper"])
            name = role(trace["schema"], trace["start"], trace["goal"], edge_id)
            item = totals.setdefault(name, {"observations": 0, "contexts": set(), "excess": 0, "interval_width": 0})
            item["observations"] += 1
            item["contexts"].add(context)
            item["excess"] += cost - edge["lower"]
            item["interval_width"] += edge["upper"] - edge["lower"]
    ranked = [r for r in ROLES if r in totals and len(totals[r]["contexts"]) >= 2
              and totals[r]["interval_width"] > 0]
    ranked.sort(key=lambda r: (-Fraction(totals[r]["excess"], totals[r]["interval_width"]), ROLES.index(r)))
    return policy(ranked), work, observation_count


def validate_record(record):
    fields(record, ("id", "revision", "source", "policy", "training", "provenance"), "StrategyRecord")
    label(record["id"])
    label(record["source"])
    integer(record["revision"], 1, 2**64 - 1)
    require(type(record["provenance"]) is str and 0 < len(record["provenance"].encode()) <= 1024,
            "strategy provenance outside bound")
    ranked, work, count = derive(record["training"])
    equal(record["policy"], ranked, "source-observation-derived role policy")
    return work, count


def trial(task, prior=None, limits=None):
    """Recompute every actual query, accepted observation, certificate and counter."""
    validate_task(task)
    limits = LIMITS if limits is None else limits
    fields(limits, LIMITS, "TrialLimits")
    integer(limits["max_queries"], 0, 256)
    integer(limits["model_work"], 1, 10_000_000)
    integer(limits["policy_work"], 1, 10_000_000)
    if prior is not None:
        validate_policy(prior)
    observed, queried, history = {}, [], []
    model_work = policy_work = 0
    certificate = None
    schema, start, goal = task["schema"], task["start"], task["goal"]
    edges = schema["edges"]
    while True:
        route, model_work, status = optimistic(schema, start, goal, observed, model_work, limits["model_work"])
        if route is not None and all(i in observed for i in route["edges"]):
            status, certificate = "certified", route["cost"]
            break
        if status != "supported":
            break
        if route is None:
            status = "unreachable"
            break
        if len(queried) >= limits["max_queries"]:
            status = "query-budget"
            break
        unknown = [(position, i) for position, i in enumerate(route["edges"]) if i not in observed]
        if prior is not None:
            roles = prior["ranked_roles"]
            cost = len(edges) + len(route["edges"]) + len(history) + len(roles)
            if cost > limits["policy_work"] - policy_work:
                status = "policy-budget"
                break
            policy_work += cost
            choices = [(roles.index(r) if r in roles else len(roles), position, i)
                       for position, i in unknown for r in [role(schema, start, goal, i)]]
            edge_id = min(choices)[2] if choices else None
        else:
            edge_id = unknown[0][1] if unknown else None
        if edge_id is None:
            status = "abstained"
            break
        queried.append(edge_id)
        value = task["costs"][edge_id]
        if not edges[edge_id]["lower"] <= value <= edges[edge_id]["upper"]:
            status = "contradicted"
            break
        if model_work + 1 > limits["model_work"]:
            status = "budget_exhausted"
            break
        model_work += 1
        observed[edge_id] = value
        history.append({"edge": edge_id, "cost": value})
    truth, evaluator_work = optimum(task)
    return {"context": task["context"], "status": status, "queried_edges": queried, "observations": history,
            "certified_cost": certificate, "oracle_optimum": truth,
            "incorrect_certificate": certificate is not None and certificate != truth,
            "model_work": model_work, "policy_work": policy_work, "evaluator_work": evaluator_work}


def correct(result):
    return result["certified_cost"] is not None and not result["incorrect_certificate"] and result["certified_cost"] == result["oracle_optimum"]


def regression(comparison):
    a, b = comparison["baseline"], comparison["candidate"]
    return b["incorrect_certificate"] or (correct(a) and (not correct(b) or len(b["queried_edges"]) > len(a["queried_edges"])))


def compare(task, prior):
    return {"task": task, "baseline": trial(task), "candidate": trial(task, prior)}


def trial_work(result):
    return sum(result[k] for k in ("model_work", "policy_work", "evaluator_work"))


def assessment(record, calibration, counterexamples, incumbent):
    source_work, source_observations = validate_record(record)
    require(type(calibration) is list and 2 <= len(calibration) <= 4, "calibration shape")
    contexts = {r["context"] for r in record["training"]}
    for task in calibration:
        validate_task(task)
        require(task["context"] not in contexts, "source/calibration context leakage")
        contexts.add(task["context"])
    rows = [compare(t, record["policy"]) for t in calibration]
    checks = [compare(t, record["policy"]) for t in counterexamples]
    incumbent_trials = [trial(t, incumbent["policy"]) for t in calibration] if incumbent else [r["baseline"] for r in rows]
    baseline_queries = sum(len(r["baseline"]["queried_edges"]) for r in rows)
    candidate_queries = sum(len(r["candidate"]["queried_edges"]) for r in rows)
    incumbent_queries = sum(len(r["queried_edges"]) for r in incumbent_trials)
    correctness = all(correct(r["baseline"]) and correct(r["candidate"]) for r in rows)
    safe = not any(regression(r) for r in checks)
    default = not any(regression(r) for r in rows)
    eligible = correctness and default and candidate_queries < incumbent_queries and safe
    reason = ("calibration abstention or incorrect conditional certificate" if not correctness else
              "known query-policy counterexample remains harmful" if not safe else
              "calibration query regression against original default" if not default else
              "no strict calibration query-count improvement over current selected behavior" if candidate_queries >= incumbent_queries else
              "independent calibration query count improves current behavior without default regression")
    verification_work = sum(trial_work(r[p]) for r in rows + checks for p in ("baseline", "candidate"))
    verification_work += sum(trial_work(r) for r in incumbent_trials) if incumbent else 0
    truth_edges = 2 * sum(len(r["task"]["schema"]["edges"]) for r in rows + checks)
    truth_edges += sum(len(t["schema"]["edges"]) for t in calibration) if incumbent else 0
    return {"record_sha256": digest(record), "incumbent_record_sha256": digest(incumbent) if incumbent else None,
            "incumbent_trials": incumbent_trials, "calibration": rows, "regression_checks": checks,
            "eligible": eligible, "reason": reason, "baseline_queries": baseline_queries,
            "candidate_queries": candidate_queries, "incumbent_queries": incumbent_queries,
            "source_observations": source_observations, "verification_truth_edges": truth_edges,
            "source_processing_work": source_work, "verification_work": verification_work,
            "exchange_bytes": len(compact(record)), "adoption_units": int(eligible),
            "metric": "conditional-calibration-oracle-query-count; not net reciprocal utility"}


def canonical_task(task):
    n, edges = graph(task["schema"], task["start"], task["goal"], task["costs"])
    require(n <= 12 and len(edges) <= 56, "canonical domain exceeded")
    colours = [1 if i == task["start"] else 2 if i == task["goal"] else 0 for i in range(n)]
    work = 0
    for _ in range(n):
        profiles = []
        for node in range(n):
            work += 1 + len(edges)
            require(work <= 10000, "canonical refinement budget")
            incoming, outgoing = [], []
            for edge, cost in zip(edges, task["costs"]):
                if edge["to"] == node:
                    incoming.append((edge["lower"], edge["upper"], cost, colours[edge["from"]]))
                if edge["from"] == node:
                    outgoing.append((edge["lower"], edge["upper"], cost, colours[edge["to"]]))
            profiles.append((colours[node], tuple(sorted(incoming)), tuple(sorted(outgoing))))
        classes = sorted(set(profiles))
        colours = [classes.index(p) for p in profiles]
        if len(classes) == n:
            witness_edges = sorted([colours[e["from"]], colours[e["to"]], e["lower"], e["upper"], c]
                                   for e, c in zip(edges, task["costs"]))
            return {"nodes": n, "start": colours[task["start"]], "goal": colours[task["goal"]],
                    "edges": witness_edges, "refinement_scan_units": work}
    raise Hold("ambiguous refinement: no complete weighted isomorphism witness")


def ordered(value, names, name):
    fields(value, names, name)
    return {k: value[k] for k in names}


def typed_record(record):
    result = ordered(record, ("id", "revision", "source", "scope", "schema_fingerprint", "payload", "provenance"), "KnowledgeRecord")
    # payload is serde_json::Value, unlike its surrounding typed struct.
    result["payload"] = decode(compact(result["payload"], sorted_keys=True))
    return result


def typed_graph_assessment(value):
    result = ordered(value, ("heldout_route_queries", "baseline_correct", "candidate_correct", "regressions",
                            "baseline_cost", "candidate_cost", "coverage_improved", "cost_improved", "authority_id",
                            "record_digest", "evidence"), "GraphAssessment")
    evidence = ordered(value["evidence"], ("evaluator", "acquisitions", "training_tasks", "cases", "costs"), "GraphTrialEvidence")
    evidence["acquisitions"] = [ordered(a, ("id", "edge_id", "cost", "receipt_sha256", "receipt"), "GraphAcquisition")
                                for a in evidence["acquisitions"]]
    for acquisition in evidence["acquisitions"]:
        acquisition["receipt"] = decode(compact(acquisition["receipt"], sorted_keys=True))
    evidence["training_tasks"] = [ordered(t, ("id", "input"), "GraphTrainingTask") for t in evidence["training_tasks"]]
    evidence["cases"] = [ordered(c, ("id", "input", "expected", "baseline", "candidate"), "TrialCase") for c in evidence["cases"]]
    evidence["costs"] = ordered(evidence["costs"], ("acquisition", "verification", "adoption", "baseline", "candidate"), "TrialCosts")
    result["evidence"] = evidence
    return result


def typed_payload(payload, kind):
    event = payload.get("event")
    if event == "genesis":
        return ordered(payload, ("event", "version", "identity"), "genesis")
    if kind == "knowledge" and event == "promote_graph":
        result = ordered(payload, ("event", "record", "assessment", "policy_version"), "graph promotion")
        result["record"] = typed_record(result["record"])
        result["assessment"] = typed_graph_assessment(result["assessment"])
        equal(result["policy_version"], 2, "graph promotion policy")
        return result
    raise Hold(f"unexpected {kind} ledger event {event}; verifier is scoped to this protocol")


def chain(path, kind, root):
    raw = read(path, root)
    require(raw and raw.endswith(b"\n"), f"{kind} journal truncated/empty")
    lines = raw.splitlines(keepends=True)
    require(len(lines) <= (128 if kind == "strategy" else 4096), "ledger event budget")
    rows, prefix, accumulated = [], {}, b""
    previous = ZERO
    for sequence, line in enumerate(lines):
        require(line.endswith(b"\n") and line.strip() and len(line) <= 256 * 1024, "invalid journal row bytes")
        row = decode(line)
        fields(row, ("sequence", "previous", "payload", "sha256"), "ledger row")
        equal(row["sequence"], sequence, "ledger sequence")
        equal(row["previous"], previous, "ledger previous hash")
        if kind == "strategy":
            expected = digest([sequence, previous, row["payload"]])
        elif kind == "owner":
            payload = typed_payload(row["payload"], kind)
            expected = sha(compact({"sequence": sequence, "previous": previous, "payload": payload}))
        else:
            expected = sha(compact([sequence, previous, typed_payload(row["payload"], kind)]))
        equal(row["sha256"], expected, "typed ledger content hash")
        accumulated += line
        prefix[expected] = {"rows": sequence + 1, "raw_sha256": sha(accumulated), "raw": accumulated}
        rows.append(row)
        previous = expected
    return rows, prefix, raw


def owner_state(directory, root, expected=None):
    rows, prefix, raw = chain(directory / "ledger.jsonl", "owner", root)
    require(len(rows) == 1, "protocol owner must have only its identity genesis")
    genesis = rows[0]["payload"]
    equal(genesis["version"], 1, "owner genesis version")
    identity = genesis["identity"]
    require(type(identity) is str and re.fullmatch(r"symbiote-[a-f0-9]{24}", identity), "owner identity grammar")
    if expected is not None:
        equal(identity, expected, "bound owner identity")
    return identity, sha(raw), rows[0]["sha256"]


def verify_strategy(directory, root, identity, owner_genesis):
    rows, prefixes, raw = chain(directory / "strategy.jsonl", "strategy", root)
    marker = decode(read(directory / "strategy-owner.json", root, 2048))
    equal(marker, {"schema": "symbiote.strategy-owner/1", "identity": identity,
                   "owner_genesis_sha256": owner_genesis, "strategy_genesis_sha256": rows[0]["sha256"]}, "strategy owner marker")
    active, counterexamples, revisions, sources, attempts = None, [], {}, {}, set()
    considered, revoked, snapshots = [], [], {}
    work = 0
    for index, row in enumerate(rows):
        p = row["payload"]
        if index == 0:
            equal(p, {"event": "genesis", "version": 1, "identity": identity,
                      "owner_genesis_sha256": owner_genesis}, "strategy genesis owner")
        elif p.get("event") == "considered":
            fields(p, ("event", "record", "calibration", "assessment"), "strategy consideration")
            r, calibration = p["record"], p["calibration"]
            expected = assessment(r, calibration, counterexamples, active)
            equal(p["assessment"], expected, "raw strategy assessment")
            attempt = digest([r, calibration])
            require(attempt not in attempts, "duplicate strategy attempt")
            attempts.add(attempt)
            work += expected["source_processing_work"] + expected["verification_work"]
            if expected["eligible"]:
                require(r["revision"] > revisions.get(r["id"], 0) and sources.get(r["id"], r["source"]) == r["source"],
                        "strategy stale version/source namespace")
                revisions[r["id"]], sources[r["id"]], active = r["revision"], r["source"], r
            considered.append(p)
        elif p.get("event") == "revoked":
            fields(p, ("event", "id", "revision", "record_sha256", "counterexample"), "strategy revocation")
            require(active is not None, "revocation has no selected strategy")
            equal([p["id"], p["revision"], p["record_sha256"]], [active["id"], active["revision"], digest(active)], "revocation binding")
            c = p["counterexample"]
            equal(c, compare(c["task"], active["policy"]), "counterexample stepwise replay")
            require(regression(c), "nonharmful prior revoked")
            work += trial_work(c["baseline"]) + trial_work(c["candidate"])
            signature = lambda t: compact({k: v for k, v in t.items() if k != "context"}, sorted_keys=True)
            if all(signature(t) != signature(c["task"]) for t in counterexamples):
                counterexamples.append(c["task"])
            require(len(counterexamples) <= 8, "counterexample registry bound")
            revoked.append(p)
            active = None
        else:
            raise Hold("unknown or repeated strategy genesis/event")
        require(work <= 2_000_000, "strategy cumulative work bound")
        snapshots[row["sha256"]] = {"selected": active, "work": work}
    return {"rows": rows, "prefixes": prefixes, "raw": raw, "snapshots": snapshots,
            "selected": active, "considered": considered, "revoked": revoked}


def forecast(schema, observations, input_value):
    n = schema["nodes"]
    integer(input_value, 0, n * n - 1, "encoded graph query")
    start, goal = divmod(input_value, n)
    graph(schema, start, goal, durable=True)
    observed = {r["edge_id"]: r["cost"] for r in observations}
    require(len(observed) == len(observations), "duplicate retained observation")
    route, work, status = optimistic(schema, start, goal, observed, len(observations), 1024)
    require(status == "supported", "durable forecast model budget")
    certified = route if route and all(i in observed for i in route["edges"]) else None
    if certified:
        integer(certified["cost"], 1, 63, "durable encoded route cost")
    return certified, work


def graph_fingerprint(schema):
    return digest({"kind": "finite-positive-cost-directed-graph", "version": 1,
                   "query_encoding": "start*nodes+goal", "schema": schema})


def verify_graph_promotion(p, task, result, identity, authority, price):
    typed = typed_payload(p, "knowledge")
    record, a = typed["record"], typed["assessment"]
    payload = record["payload"]
    fields(payload, ("kind", "schema", "observations"), "GraphMap payload")
    equal(payload["kind"], "graph-map", "retained payload kind")
    equal(payload["schema"], task["schema"], "retained topology")
    integer(record["revision"], 1, 1)
    equal(record["id"], f"retained-{digest(task)}", "retained identity")
    equal(record["source"], identity, "retained source")
    equal(record["scope"], task["context"], "retained context")
    fingerprint = graph_fingerprint(task["schema"])
    equal(record["schema_fingerprint"], fingerprint, "retained schema fingerprint")
    obs = [{"edge_id": r["edge"], "cost": r["cost"]} for r in result["observations"]]
    equal(payload["observations"], sorted(obs, key=lambda r: r["edge_id"]), "actual queried graph facts only")
    require(obs, "empty retained graph facts")
    main_input = task["start"] * task["schema"]["nodes"] + task["goal"]
    route, main_work = forecast(task["schema"], obs, main_input)
    require(route is not None and len(route["nodes"]) >= 4, "retained main certificate/disjoint endpoints")
    equal(route["cost"], result["certified_cost"], "retained main cost")
    evidence = a["evidence"]
    equal(evidence["evaluator"], authority, "independent laboratory evaluator identity")
    require(authority != identity, "self-evaluator fact promotion")
    acquisitions = evidence["acquisitions"]
    require(len(acquisitions) == len(obs), "acquisition envelope count")
    for sequence, (acq, observation) in enumerate(zip(acquisitions, obs)):
        envelope = acq["receipt"]
        edge, cost = observation["edge_id"], observation["cost"]
        expected_id = digest([authority, identity, task["context"], fingerprint, sequence, edge, cost])
        expected_envelope = {"schema": "symbiote.graph-observation/1", "authority_id": authority,
                             "context": task["context"], "schema_fingerprint": fingerprint,
                             "observer_identity": identity, "sequence": sequence, "id": expected_id,
                             "edge_id": edge, "cost": cost}
        equal(envelope, expected_envelope, "oracle envelope origin/context/sequence/cost")
        equal(acq, {"id": expected_id, "edge_id": edge, "cost": cost,
                    "receipt_sha256": digest(envelope), "receipt": envelope}, "acquisition hash binding")
    equal(evidence["training_tasks"], [{"id": "main-acquisition-route", "input": main_input}], "main acquisition input")
    endpoints = [(route["nodes"][0], route["nodes"][1]), (route["nodes"][-2], route["nodes"][-1])]
    require(set(endpoints[0]).isdisjoint(endpoints[1]), "retention subroutes share endpoints")
    cases, sub_work, empty_work, evaluator_work = [], 0, 0, 0
    for index, (start, goal) in enumerate(endpoints):
        query = start * task["schema"]["nodes"] + goal
        require(query != main_input, "retention query leaks main acquisition input")
        subtask = dict(task, start=start, goal=goal, context=f"{task['context']}-sub-{index}")
        expected, w = optimum(subtask)
        candidate, cw = forecast(task["schema"], obs, query)
        baseline, bw = forecast(task["schema"], [], query)
        require(candidate is not None and baseline is None, "new graph coverage not independently demonstrated")
        equal(candidate["cost"], expected, "independent positive graph subroute optimum")
        cases.append({"id": f"subroute-{index}", "input": query, "expected": expected,
                      "baseline": None, "candidate": expected})
        sub_work += cw
        empty_work += bw
        evaluator_work += w
    equal(evidence["cases"], cases, "separate subroute cases")
    pre_work = main_work + empty_work + sub_work + evaluator_work
    acquisition = len(obs) * price
    verification = 2 * len(task["schema"]["edges"]) * price + pre_work
    equal(evidence["costs"], {"acquisition": acquisition, "verification": verification, "adoption": 1,
                              "baseline": 0, "candidate": acquisition + verification + 1}, "graph evidence costs")
    expected_a = {"heldout_route_queries": 2, "baseline_correct": 0, "candidate_correct": 2,
                  "regressions": 0, "baseline_cost": 0, "candidate_cost": acquisition + verification + 1,
                  "coverage_improved": True, "cost_improved": False, "authority_id": authority,
                  "record_digest": sha(compact(record)), "evidence": evidence}
    equal(a, expected_a, "typed graph assessment recomputation")
    return {"record": record, "record_sha256": sha(compact(record)), "main_input": main_input,
            "main_cost": route["cost"], "cases": cases, "main_work": main_work, "sub_work": sub_work,
            "retention_work": main_work + empty_work + 3 * sub_work + evaluator_work,
            "replay_work": main_work + 2 * sub_work}


def add_trial(bill, result, edges, diagnostic=False):
    prefix = "diagnostic" if diagnostic else "target"
    bill[f"{prefix}_queries"] += len(result["queried_edges"])
    bill[f"{prefix}_truth_edges"] += edges
    bill["computation_work"] += trial_work(result)


def context(seed, actor, phase, index):
    return f"query-transfer-{digest([seed, actor, phase, index])}"


def recipe_shape(task, layers, penalty, goal_penalty, chord=False, drift=False, observations=None):
    """Validate a supplied raw recipe instance; never create/generate a task.

    Complete endpoint-aware paths validate the public node/edge renaming without
    importing the controller's fixture generator or its private labels.
    """
    n, edges = graph(task["schema"], task["start"], task["goal"])
    require(n == layers * 2 and len(edges) == 2 * layers + int(chord), "registered path topology size")
    start, goal = task["start"], task["goal"]
    paths, stack, expansions = [], [(start, [start], [])], 0
    while stack:
        node, nodes, ids = stack.pop()
        expansions += 1
        require(expansions <= 4096, "public topology validation work cap")
        if node == goal:
            if len(ids) == layers:
                paths.append((nodes, ids))
            continue
        if len(ids) >= layers:
            continue
        for i, edge in enumerate(edges):
            if edge["from"] == node and edge["to"] not in nodes:
                stack.append((edge["to"], nodes + [edge["to"]], ids + [i]))
    pairs = [(a, b) for a in paths for b in paths
             if set(a[0][1:-1]).isdisjoint(b[0][1:-1])
             and edges[a[1][0]]["lower"] == 1 and edges[b[1][0]]["lower"] == 2]
    require(len(pairs) == 1, "registered two endpoint-disjoint path witness unavailable")
    first, second = pairs[0]
    base_ids = first[1] + second[1]
    require(len(set(base_ids)) == 2 * layers, "public path edge bijection")
    require(all(edge["upper"] == 9 and edge["lower"] == (2 if i == second[1][0] else 1)
                for i, edge in enumerate(edges)), "registered public interval bounds")
    truth = {i: 1 for i in base_ids}
    truth[second[1][0]] = 2
    truth[first[1][-1 if goal_penalty else 0]] = penalty
    extra = set(range(len(edges))) - set(base_ids)
    if chord:
        require(len(extra) == 1, "registered cross edge missing")
        index = extra.pop()
        equal([edges[index]["from"], edges[index]["to"]], [first[0][2], second[0][-2]], "cross-edge endpoints")
        truth[index] = 9
    else:
        require(not extra, "unexpected graph edge outside renamed paths")
    if observations is None:
        equal(task["costs"], [10 if drift else truth[i] for i in range(len(edges))], "recorded frozen private cost recipe")
    else:
        require(len(observations) == len(edges), "source acquisition must include every recorded edge")
        for observation in observations:
            equal(observation["cost"], truth[observation["edge"]], "actual source observation recipe")


def anchor(identity, rows, index):
    return {"identity": identity, "records": index + 1, "head_sha256": rows[index]["sha256"]}


def retained_metadata(item):
    return {"record_id": item["record"]["id"], "record_sha256": item["record_sha256"],
            "context": item["record"]["scope"], "main_input": item["main_input"],
            "main_cost": item["main_cost"], "cases": item["cases"]}


def verify_participant(p, state, cell, authority):
    fields(p, ("role", "identity", "directory", "initial_policy", "evaluated_target_policy",
               "selected_after_diagnostics", "restarts", "bill", "total_cost", "certified_correct",
               "incorrect_certificates", "target_count", "targets", "negative_controls", "strategy_rows",
               "strategy_head", "knowledge_rows", "knowledge_anchor", "retained_models"), "participant")
    actor = integer(p["role"], 0, 1, "participant role")
    seed, price, arm = cell["seed"], cell["oracle_price"], cell["arm"]
    directory = state / f"price-{price}" / f"seed-{seed}" / arm / f"agent-{actor}"
    equal(str(Path(p["directory"]).resolve()), str(directory.resolve()), "participant state path")
    identity, owner_genesis, _ = owner_state(directory, state, p["identity"])
    strategy = verify_strategy(directory, state, identity, owner_genesis)
    knowledge_rows, knowledge_prefixes, _ = chain(directory / "knowledge.jsonl", "knowledge", state)
    require(len(knowledge_rows) == 3, "two genuine nonempty target GraphMaps required")
    equal(knowledge_rows[0]["payload"], {"event": "genesis", "version": 1, "identity": identity}, "knowledge genesis")
    equal(p["strategy_rows"], len(strategy["rows"]), "strategy row count")
    equal(p["strategy_head"], strategy["rows"][-1]["sha256"], "strategy head")
    equal(p["knowledge_rows"], 3, "knowledge row count")
    equal(p["knowledge_anchor"], anchor(identity, knowledge_rows, 2), "final knowledge anchor")
    equal(p["selected_after_diagnostics"], strategy["selected"], "post-diagnostic selected prior")
    considered = strategy["considered"]
    count = 2 if arm in ("local-trained", "exchanged") else 1 if arm == "isolated-prior" else 0
    require(len(considered) == count, "unexpected training/calibration stages")
    bill = dict.fromkeys(BILL_FIELDS, 0)
    for stage, event in enumerate(considered):
        r, a = event["record"], event["assessment"]
        own = r["source"] == identity
        require(own == (arm != "exchanged" or stage == 0), "source identity differs from arm training design")
        sender = actor if own else 1 - actor
        source_phase = "local-training" if arm == "local-trained" and stage == 1 else "source-training"
        equal([t["context"] for t in r["training"]], [context(seed, sender, source_phase, i) for i in range(2)], "source context map")
        require(all(t["schema"]["nodes"] == 4 for t in r["training"]), "registered source dimensions")
        source_goal = sender != 0 if source_phase == "local-training" else sender == 0
        for trace in r["training"]:
            recipe_shape(trace, 2, 4 + seed % 6, source_goal, observations=trace["observations"])
        phase = "self-calibration" if stage == 0 else "target-calibration"
        equal([t["context"] for t in event["calibration"]], [context(seed, actor, phase, i) for i in range(2)], "calibration context map")
        require(all(t["schema"]["nodes"] == 6 for t in event["calibration"]), "registered calibration dimensions")
        for calibration_task in event["calibration"]:
            recipe_shape(calibration_task, 3, 4 + seed % 6, actor == 0 if stage == 0 else actor != 0)
        if own:
            source_work, source_queries = validate_record(r)
            bill["source_queries"] += source_queries
            bill["computation_work"] += source_work
        bill["calibration_queries"] += sum(len(row[who]["queried_edges"]) for row in a["calibration"] + a["regression_checks"] for who in ("baseline", "candidate"))
        if a["incumbent_record_sha256"] is not None:
            bill["calibration_queries"] += sum(len(row["queried_edges"]) for row in a["incumbent_trials"])
        bill["calibration_truth_edges"] += a["verification_truth_edges"]
        bill["computation_work"] += a["source_processing_work"] + a["verification_work"]
        bill["adoption_units"] += a["adoption_units"]
    initial = considered[0]["record"]["policy"] if considered and considered[0]["assessment"]["eligible"] else None
    equal(p["initial_policy"], initial, "self-calibrated initial policy")
    restarts = p["restarts"]
    require(type(restarts) is list and len(restarts) == (3 if arm == "exchanged" else 2), "actual reopen report count")
    target_head = restarts[0]["strategy_head"]
    require(target_head in strategy["snapshots"], "target prior history pin missing")
    selected_record = strategy["snapshots"][target_head]["selected"]
    selected = (None if arm == "fresh-default" else
                policy(["from-start", "to-goal"]) if arm == "fixed-start" else
                policy(["to-goal", "from-start"]) if arm == "fixed-goal" else
                selected_record["policy"] if selected_record else None)
    equal(p["evaluated_target_policy"], selected, "actual evaluated target policy")
    targets = p["targets"]
    require(type(targets) is list and len(targets) == 2, "two target results required")
    retained, source_contexts, calibration_contexts = [], set(), set()
    for event in considered:
        source_contexts.update(t["context"] for t in event["record"]["training"])
        calibration_contexts.update(t["context"] for t in event["calibration"])
    require(source_contexts.isdisjoint(calibration_contexts), "source/calibration phase leakage")
    for index, target in enumerate(targets):
        fields(target, ("task_sha256", "schema_sha256", "costs_sha256", "canonical_weighted_witness",
                        "canonical_weighted_sha256", "task", "result", "retention"), "target row")
        task = validate_task(target["task"])
        equal(task["context"], context(seed, actor, "final-target", index), "target context recipe binding")
        equal(task["schema"]["nodes"], (8, 10)[index], "registered target dimensions")
        recipe_shape(task, index + 4, 4 + seed % 6, actor != 0, chord=index == 1)
        require(task["context"] not in source_contexts | calibration_contexts, "held-out target used for promotion")
        expected = trial(task, selected)
        equal(target["result"], expected, "target actual query trace/certificate/work")
        equal(target["task_sha256"], digest(task), "full task hash")
        equal(target["schema_sha256"], digest([task["schema"], task["start"], task["goal"]]), "public schema/endpoints hash")
        equal(target["costs_sha256"], digest(task["costs"]), "truth costs hash")
        witness = canonical_task(task)
        equal(target["canonical_weighted_witness"], witness, "complete weighted isomorphism witness")
        equal(target["canonical_weighted_sha256"], digest(witness), "weighted witness hash")
        add_trial(bill, expected, len(task["schema"]["edges"]))
        bill["computation_work"] += witness["refinement_scan_units"]
        item = verify_graph_promotion(knowledge_rows[index + 1]["payload"], task, expected, identity, authority, price)
        retained.append(item)
        metadata = target["retention"]
        fields(metadata, ("retained", "assessment", "knowledge_before", "knowledge_after", "promotion_receipt_sha256",
                          "authority_queries", "actual_forecast_and_evaluator_work", "acquisition_cost_already_charged_in_target_bill",
                          "evidence_cost_scope", "scope"), "retention metadata")
        equal(metadata["retained"], retained_metadata(item), "retained model binding")
        equal(metadata["assessment"], knowledge_rows[index + 1]["payload"]["assessment"], "raw knowledge assessment")
        equal(metadata["knowledge_before"], anchor(identity, knowledge_rows, index), "pre-promotion history anchor")
        equal(metadata["knowledge_after"], anchor(identity, knowledge_rows, index + 1), "post-promotion history anchor")
        equal(metadata["promotion_receipt_sha256"], knowledge_rows[index + 1]["sha256"], "actual promotion receipt")
        truth_edges = 2 * len(task["schema"]["edges"])
        equal(metadata["authority_queries"], truth_edges, "retention evaluator edge reads")
        equal(metadata["actual_forecast_and_evaluator_work"], item["retention_work"], "actual retention/admission/commit work")
        equal(metadata["acquisition_cost_already_charged_in_target_bill"], True, "avoid acquisition double charge")
        bill["retention_truth_edges"] += truth_edges
        bill["computation_work"] += item["retention_work"]
        bill["adoption_units"] += 1
    equal(p["retained_models"], [retained_metadata(item) for item in retained], "nonempty retained model inventory")
    negative = p["negative_controls"]
    if arm == "exchanged" and selected_record is not None:
        fields(negative, ("unsupported_grammar_error", "unsupported_memory_unchanged", "observed_drift_task", "observed_drift",
                          "counterexample", "revoked_for_observed_regression", "hidden_family_label_used_for_rejection"), "negative diagnostic raw contract")
        require(type(negative["unsupported_grammar_error"]) is str and negative["unsupported_grammar_error"], "unsupported grammar did not report failure")
        equal(negative["unsupported_memory_unchanged"], True, "unsupported grammar changed memory")
        equal(negative["hidden_family_label_used_for_rejection"], False, "hidden family rejection prohibited")
        bill["computation_work"] += validate_record(selected_record)[0]
        drift_task = negative["observed_drift_task"]
        equal(drift_task["context"], context(seed, actor, "observed-drift", 0), "diagnostic drift context")
        recipe_shape(drift_task, 3, 4 + seed % 6, actor != 0, drift=True)
        drift = trial(drift_task, selected)
        equal(negative["observed_drift"], drift, "actual observed interval contradiction")
        require(drift["status"] == "contradicted" and drift["certified_cost"] is None, "drift did not fail closed")
        add_trial(bill, drift, len(drift_task["schema"]["edges"]), True)
        counter = negative["counterexample"]
        fields(counter, ("task", "baseline", "candidate"), "diagnostic counterexample")
        equal(counter["task"]["context"], context(seed, actor, "query-prior-counterexample", 0), "counterexample context")
        recipe_shape(counter["task"], 3, 4 + seed % 6, actor == 0)
        expected = compare(counter["task"], selected)
        equal(counter, expected, "counterexample outcome and work")
        for who in ("baseline", "candidate"):
            add_trial(bill, expected[who], len(counter["task"]["schema"]["edges"]), True)
        harmful = regression(expected)
        equal(negative["revoked_for_observed_regression"], harmful, "outcome-based revocation")
        require(len(strategy["revoked"]) == int(harmful), "revocation raw history missing/unexpected")
        for event in strategy["revoked"]:
            equal(event["counterexample"], expected, "durable negative evidence")
            for who in ("baseline", "candidate"):
                add_trial(bill, event["counterexample"][who], len(counter["task"]["schema"]["edges"]), True)
    elif arm == "exchanged":
        equal(negative, {"status": "ABSTAINED_NO_PROMOTED_POLICY"}, "no selected prior diagnostic abstention")
        require(not strategy["revoked"], "unexpected revocation")
    else:
        equal(negative, None, "diagnostic cost must belong only to exchange arm")
        require(not strategy["revoked"], "unexpected control revocation")
    for index, restart in enumerate(restarts):
        fields(restart, ("identity", "strategy_head", "strategy_bytes_sha256", "selected_policy_sha256",
                         "actual_store_and_ledger_reopened", "replay_work_units", "knowledge_bytes_sha256", "knowledge_anchor",
                         "actual_knowledge_store_reopened", "graph_replay_work_units", "retained_predictions"), "actual reopen report")
        equal(restart["identity"], identity, "reopened owner")
        for key in ("actual_store_and_ledger_reopened", "actual_knowledge_store_reopened"):
            equal(restart[key], True, "actual store reopen receipt")
        head = restart["strategy_head"]
        require(head in strategy["prefixes"], "reopen strategy prefix unavailable")
        snap = strategy["snapshots"][head]
        equal(restart["strategy_bytes_sha256"], strategy["prefixes"][head]["raw_sha256"], "byte-preserved strategy history prefix")
        equal(restart["selected_policy_sha256"], digest(snap["selected"]["policy"]) if snap["selected"] else None, "reopened selected prior")
        equal(restart["replay_work_units"], snap["work"], "actual strategy replay work")
        expected_anchor = anchor(identity, knowledge_rows, 0 if index == 0 else 2)
        equal(restart["knowledge_anchor"], expected_anchor, "reopened fact history anchor")
        kp = knowledge_prefixes[expected_anchor["head_sha256"]]
        equal(restart["knowledge_bytes_sha256"], kp["raw_sha256"], "byte-preserved knowledge history prefix")
        models = [] if index == 0 else retained
        predictions = [{"record_sha256": item["record_sha256"], "context": item["record"]["scope"],
                        "input": case["input"], "expected": case["expected"], "prediction": case["expected"]}
                       for item in models for case in item["cases"]]
        equal(restart["retained_predictions"], {"models": len(models), "subroute_predictions": predictions,
                                               "new_authority_calls": 0, "nonempty": bool(models), "knowledge_anchor": expected_anchor},
              "nonempty correct retained predictions with zero new authority")
        graph_work = sum(item["replay_work"] for item in models)
        equal(restart["graph_replay_work_units"], graph_work, "actual fact replay and retained forecast work")
        bill["replay_work"] += snap["work"] + graph_work
    equal(restarts[-1]["strategy_head"], p["strategy_head"], "final reopened strategy history")
    equal(p["target_count"], 2, "target count")
    equal(p["certified_correct"], sum(correct(t["result"]) for t in targets), "independent correct certificates")
    equal(p["incorrect_certificates"], sum(t["result"]["incorrect_certificate"] for t in targets), "independent incorrect certificates")
    return {"participant": p, "bill": bill, "strategy": strategy, "directory": directory, "identity": identity}


def complete(participant):
    return (participant["target_count"] == 2 and participant["certified_correct"] == 2
            and participant["incorrect_certificates"] == 0)


def comparisons(cells):
    by_key = {(c["oracle_price"], c["seed"], c["arm"]): c for c in cells}
    output = []
    for price in COHORT["prices"]:
        for seed in COHORT["seeds"]:
            exchange = by_key[price, seed, "exchanged"]
            controls = []
            for name in ARMS[:-1]:
                baseline = by_key[price, seed, name]
                benefits = [complete(a) and complete(b) and a["certified_correct"] >= b["certified_correct"]
                            and a["incorrect_certificates"] <= b["incorrect_certificates"]
                            and a["total_cost"] < b["total_cost"]
                            for a, b in zip(exchange["participants"], baseline["participants"])]
                controls.append({"control": name, "participant_benefits": benefits, "bilateral": all(benefits)})
            best = []
            for actor, candidate in enumerate(exchange["participants"]):
                costs = [by_key[price, seed, arm]["participants"][actor]["total_cost"]
                         for arm in ("fixed-start", "fixed-goal")
                         if complete(by_key[price, seed, arm]["participants"][actor])]
                best.append(complete(candidate) and bool(costs) and candidate["total_cost"] < min(costs))
            strong = all(r["bilateral"] for r in controls if r["control"] in ("fresh-default", "local-trained")) and all(best)
            output.append({"seed": seed, "oracle_price": price, "controls": controls,
                           "best_fixed_hindsight_participant_benefits": best, "strong_bilateral_utility": strong,
                           "hindsight_bound_is_not_a_deployable_selector": True})
    return output


def fixed_policy_containment(cells):
    """The source grammar contains only the two measured fixed role orders.

    Check containment on actual raw policies and behavior before interpreting
    the preregistered expectation. This is a design limitation, not an observed
    population-level or statistical result.
    """
    indexed = {(c["oracle_price"], c["seed"], c["arm"]): c for c in cells}
    witnesses = []
    for price in COHORT["prices"]:
        for seed in COHORT["seeds"]:
            for actor, exchanged in enumerate(indexed[price, seed, "exchanged"]["participants"]):
                prior = exchanged["evaluated_target_policy"]
                matched = next((name for name, roles in (("fixed-start", ["from-start", "to-goal"]),
                                                         ("fixed-goal", ["to-goal", "from-start"]))
                                if prior == policy(roles)), None)
                require(matched is not None, "exchanged prior falls outside preregistered source-role containment")
                fixed = indexed[price, seed, matched]["participants"][actor]
                equal([t["result"] for t in exchanged["targets"]], [t["result"] for t in fixed["targets"]],
                      "same fixed policy must execute identical target observations/counters")
                require(exchanged["total_cost"] > fixed["total_cost"],
                        "contained exchange policy did not include its additional positive overhead")
                witnesses.append({"oracle_price": price, "seed": seed, "actor": actor,
                                  "matching_fixed_control": matched, "target_behavior_identical": True,
                                  "full_cost_overhead": exchanged["total_cost"] - fixed["total_cost"]})
    return witnesses


def target_inventory(cells):
    labelled, groups = {}, defaultdict(list)
    evaluations = 0
    for cell in cells:
        for actor in cell["participants"]:
            for target in actor["targets"]:
                evaluations += 1
                context_id = target["task"]["context"]
                entry = {"context": context_id, **{k: target[k] for k in (
                    "task_sha256", "schema_sha256", "costs_sha256", "canonical_weighted_sha256", "canonical_weighted_witness")}}
                if context_id in labelled:
                    equal(entry, labelled[context_id], "same labelled target changed across arms or prices")
                labelled[context_id] = entry
    for context_id, entry in sorted(labelled.items()):
        groups[entry["canonical_weighted_sha256"]].append(context_id)
    require(evaluations == 192 and len(labelled) == 16, "registered 16 labelled/192 reused target evaluations missing")
    return {"target_evaluations": evaluations, "unique_labelled_targets": len(labelled),
            "canonical_weighted_classes": len(groups), "labelled_targets": list(v for _, v in sorted(labelled.items())),
            "canonical_collision_groups": dict(groups), "independent_statistical_samples_claimed": False,
            "seed_penalty_groups": [{"seeds": [7, 19, 43], "penalty": 5}, {"seeds": [101], "penalty": 9}],
            "reuse": "same labelled targets reused across6arms and2oracle prices; equal canonical full witnesses prove graph-isomorphic weighted tasks"}


def verify_registration(registration_path, external_sha, source_commit, native_sha256, protocol_document_sha256):
    require(type(external_sha) is str and re.fullmatch(r"[a-f0-9]{64}", external_sha), "external registration SHA256 required")
    require(type(source_commit) is str and re.fullmatch(r"[a-f0-9]{40}", source_commit), "external full source commit required")
    raw = read(registration_path, maximum=65536)
    equal(sha(raw), external_sha, "externally retained registration bytes pin")
    r = decode(raw)
    fields(r, ("schema", "source_commit", "native_sha256", "protocol_document_sha256", "state_directory",
               "protocol", "protocol_sha256", "cohort", "cohort_sha256"), "registration")
    equal(r["schema"], "symbiote.query-transfer-registration/1", "registration version")
    equal(r["source_commit"], source_commit, "external source revision")
    for key, expected in (("native_sha256", native_sha256), ("protocol_document_sha256", protocol_document_sha256)):
        require(type(r[key]) is str and re.fullmatch(r"[a-f0-9]{64}", r[key]), f"{key} must be lowercase SHA256")
        equal(r[key], expected, f"external actual {key}")
    equal(r["cohort"], COHORT, "complete prospective cohort recipe")
    equal(r["cohort_sha256"], digest(COHORT), "cohort recipe digest")
    equal(r["protocol_sha256"], digest(r["protocol"]), "protocol digest")
    protocol_value = r["protocol"]
    require(type(protocol_value) is dict, "protocol object required")
    equal(protocol_value.get("id"), PROTOCOL, "protocol identity")
    equal(protocol_value.get("family"), FAMILY, "protocol model family")
    equal(protocol_value.get("controls"), list(ARMS), "registered control arms")
    equal(protocol_value.get("targets_used_for_policy_promotion"), False, "target policy leakage forbidden")
    equal(protocol_value.get("source_calibration_target_contexts_disjoint"), True, "phase separation required")
    equal(protocol_value.get("limits"), {"seconds": 60, "max_actor_cost": 10_000_000, "trial": LIMITS}, "registered budgets")
    state = Path(r["state_directory"])
    require(state.is_absolute(), "absolute registered state path required")
    require(Path(registration_path).resolve() != state.resolve() and not Path(registration_path).resolve().is_relative_to(state.resolve()),
            "registration must be outside prospective state")
    return r, state.resolve()


def verify_report(report_path, registration_path, external_sha, source_commit, native_sha256, protocol_document_sha256):
    r, state = verify_registration(registration_path, external_sha, source_commit, native_sha256, protocol_document_sha256)
    require(not Path(report_path).resolve().is_relative_to(state), "final report must be outside private actor state")
    report = decode(read(report_path, maximum=MAX_REPORT))
    fields(report, ("schema", "protocol", "source_commit", "registration_sha256", "cohort_sha256", "controller_identity",
                    "status", "first_failure", "elapsed_ms", "completed_cells", "expected_cells", "cells", "comparisons",
                    "reciprocal_efficiency", "cost_regimes_separate", "targets_used_for_policy_promotion",
                    "target_observations_used_for_graph_fact_retention", "exact_support_unchanged", "target_inventory", "limitations"), "final transfer report")
    equal(report["schema"], "symbiote.query-transfer/1", "report schema")
    for key, value in (("protocol", PROTOCOL), ("source_commit", source_commit), ("registration_sha256", external_sha),
                       ("cohort_sha256", r["cohort_sha256"]), ("cost_regimes_separate", True),
                       ("targets_used_for_policy_promotion", False), ("target_observations_used_for_graph_fact_retention", True),
                       ("exact_support_unchanged", True)):
        equal(report[key], value, f"report {key}")
    require(report["status"] == "PASS" and report["first_failure"] is None,
            "producer run incomplete or failed; preserved evidence is HOLD, not a negative research outcome")
    integer(report["elapsed_ms"], 0, 60000, "controller elapsed budget")
    equal(report["expected_cells"], 48, "registered expected cell count")
    equal(report["completed_cells"], 48, "completed raw cell count")
    cells = report["cells"]
    require(type(cells) is list and len(cells) == 48, "48 actual cell receipts required")
    equal(decode(read(state / "transfer-started.json", state)), {"registration_sha256": external_sha,
          "protocol": PROTOCOL, "source_commit": source_commit}, "started-state registration binding")
    authority, _, _ = owner_state(state, state, report["controller_identity"])
    identities = {authority}
    expected_order = [(price, seed, arm) for price in COHORT["prices"] for seed in COHORT["seeds"] for arm in ARMS]
    equal([(c.get("oracle_price"), c.get("seed"), c.get("arm")) for c in cells], expected_order, "complete paired cell grid")
    for cell in cells:
        fields(cell, ("seed", "oracle_price", "arm", "participants", "exchanges"), "paired cell")
        directory = state / f"price-{cell['oracle_price']}" / f"seed-{cell['seed']}" / cell["arm"]
        equal(decode(read(directory / "receipt.json", state, 2 * MAX_LEDGER)), cell, "independent per-cell raw receipt")
        require(type(cell["participants"]) is list and len(cell["participants"]) == 2, "two separate participating owners required")
        equal([p["role"] for p in cell["participants"]], [0, 1], "paired actor roles")
        checked = [verify_participant(p, state, cell, authority) for p in cell["participants"]]
        for item in checked:
            require(item["identity"] not in identities, "owner identity reused across independent arm states")
            identities.add(item["identity"])
        if cell["arm"] == "exchanged":
            exchanges = cell["exchanges"]
            require(type(exchanges) is list and len(exchanges) == 2, "two reciprocal raw wire exchanges required")
            wire_bytes = [read(directory / f"wire-{i}.json", state, 256 * 1024) for i in (0, 1)]
            wire_records = [decode(raw) for raw in wire_bytes]
            for i, item in enumerate(checked):
                own = item["strategy"]["considered"][0]["record"]
                received = item["strategy"]["considered"][1]
                equal(wire_records[i], own, "actual sent source record")
                equal(wire_records[1 - i], received["record"], "actual received candidate record")
                ex = exchanges[i]
                fields(ex, ("recipient", "sender", "decision", "sent_bytes", "received_bytes", "sent_wire_path", "sent_wire_sha256",
                            "received_wire_path", "received_wire_sha256", "artifact_kind"), "reciprocal exchange metadata")
                equal(ex["recipient"], item["identity"], "wire recipient")
                equal(ex["sender"], checked[1 - i]["identity"], "wire sender")
                equal(ex["decision"], {"promoted": received["assessment"]["eligible"], "replayed": False,
                                        "active": received["assessment"]["eligible"], "assessment": received["assessment"]}, "receiver-local evaluated adoption")
                for kind, number in (("sent", i), ("received", 1 - i)):
                    path = directory / f"wire-{number}.json"
                    equal(str(Path(ex[f"{kind}_wire_path"]).resolve()), str(path.resolve()), "exact raw wire path")
                    equal(ex[f"{kind}_wire_sha256"], sha(wire_bytes[number]), "exact raw wire bytes hash")
                    equal(ex[f"{kind}_bytes"], len(wire_bytes[number]), "actual raw wire bytes")
                item["bill"]["exchange_bytes"] = sum(map(len, wire_bytes))
                item["bill"]["exchange_units"] = 2 + sum((len(raw) + 1023) // 1024 for raw in wire_bytes)
        else:
            equal(cell["exchanges"], [], "control did not exchange")
            require(not list(directory.glob("wire-*.json")), "unbilled control wire files")
        for item in checked:
            bill, p = item["bill"], item["participant"]
            fields(p["bill"], BILL_FIELDS, "complete Bill")
            equal(p["bill"], bill, "every Bill component recomputed from raw events")
            total = sum(bill[k] for k in QUERY_FIELDS) * cell["oracle_price"] + sum(bill[k] for k in (
                "computation_work", "replay_work", "exchange_units", "adoption_units"))
            integer(total, 0, 10_000_000, "actor full cost budget")
            equal(p["total_cost"], total, "full price-regime cost")
    derived_comparisons = comparisons(cells)
    equal(report["comparisons"], derived_comparisons, "matched cost and hindsight comparisons")
    inventory = target_inventory(cells)
    equal(report["target_inventory"], inventory, "labelled tasks and complete-witness collision groups")
    containment = fixed_policy_containment(cells)
    normal = [c for c in derived_comparisons if c["oracle_price"] == 100]
    outcome = "DEMONSTRATED_ONLY_IN_THIS_CONTROLLED_COHORT" if all(c["strong_bilateral_utility"] for c in normal) else "NOT_DEMONSTRATED"
    equal(report["reciprocal_efficiency"], outcome, "independent reciprocal efficiency conclusion")
    return {"schema": "symbiote.independent-query-transfer/1", "status": "PASS", "protocol": PROTOCOL,
            "source_commit": source_commit, "registration_sha256": external_sha, "raw_report_sha256": sha(read(report_path, maximum=MAX_REPORT)),
            "verified_cells": 48, "participants": 96, "target_evaluations": 192, "labelled_target_tasks": 16,
            "unique_weighted_isomorphism_groups": inventory["canonical_weighted_classes"],
            "canonical_collision_groups": inventory["canonical_collision_groups"], "reciprocal_efficiency": outcome,
            "predeclared_design_expectation": "NOT_DEMONSTRATED: received role orders are contained in measured fixed controls and add positive overhead",
            "actual_fixed_policy_containment": containment,
            "comparisons": derived_comparisons, "trial_replay": "independent shortest path, query roles, observations, certificates and counters",
            "persistence": "actual single-process Store/StrategyLedger/KnowledgeStore reopen reports with byte-pinned histories and nonempty retained predictions",
            "limitations": ["trusted local controller evidence, not remote authenticity or resistance to whole-history rewriting",
                            "reopen reports do not establish OS-process isolation", "source observations are named provenance partitions, not independent samples",
                            "canonical complete weighted witnesses establish isomorphism, not statistical significance",
                            "best fixed policy is a hindsight bound, not a deployable selector", "logical work/cost units are not measured hardware speed"]}


def verify_source(checkout, source_commit):
    """Read-only binding to the externally named frozen producer source."""
    checkout = Path(checkout)
    try:
        subprocess.run(["git", "cat-file", "-e", f"{source_commit}^{{commit}}"], cwd=checkout,
                       capture_output=True, timeout=10, check=True)
        result = subprocess.run(["git", "diff", "--quiet", source_commit, "--", "crates", "docs/QUERY_TRANSFER_PROTOCOL.md",
                                 "tools/verify_transfer.py", "tools/test_verify_transfer.py"], cwd=checkout,
                                capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as error:
        raise Hold(f"frozen source unavailable: {error}") from error
    require(result.returncode == 0, "current reviewed source differs from externally frozen commit")
    for path in ("crates/symbiote-runtime/src/transfer.rs", "docs/QUERY_TRANSFER_PROTOCOL.md",
                 "tools/verify_transfer.py", "tools/test_verify_transfer.py"):
        result = subprocess.run(["git", "cat-file", "-e", f"{source_commit}:{path}"], cwd=checkout,
                                capture_output=True, timeout=10)
        require(result.returncode == 0, f"required reviewed source absent from freeze: {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--registration-sha256", required=True, help="external pin saved before run")
    parser.add_argument("--source-commit", required=True, help="externally approved full source commit")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--native", type=Path, required=True, help="actual frozen executable, read/hash only; never invoked")
    parser.add_argument("--checkout", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, help="create a new independent receipt; never overwrite")
    args = parser.parse_args()
    try:
        verify_source(args.checkout, args.source_commit)
        native_sha256 = sha(read(args.native, maximum=128 * 1024 * 1024))
        protocol_document_sha256 = sha(read(args.checkout / "docs/QUERY_TRANSFER_PROTOCOL.md", maximum=65536))
        result = verify_report(args.report, args.registration, args.registration_sha256, args.source_commit,
                               native_sha256, protocol_document_sha256)
    except (Hold, OSError, KeyError, TypeError, IndexError, RecursionError) as error:
        result = {"schema": "symbiote.independent-query-transfer/1", "status": "HOLD",
                  "reciprocal_efficiency": "NOT_EVALUABLE_INCOMPLETE", "first_failure": str(error),
                  "prospective_generator_invoked": False}
    if args.output:
        try:
            with args.output.open("xb") as stream:
                stream.write(json.dumps(result, ensure_ascii=False, indent=2).encode() + b"\n")
        except OSError as error:
            print(f"independent receipt not written: {error}", file=sys.stderr)
            return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return int(result["status"] != "PASS")


if __name__ == "__main__":
    sys.exit(main())
