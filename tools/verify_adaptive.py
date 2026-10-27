"""Independently check recorded adaptive evidence; never launch an experiment.

Primitive traffic counters remain witnesses of the pinned native binary. This
checker recomputes their prices, routes, provenance links, journal profiles and
paired utility. It does not attest arbitrary remote truth or capture TLS packets.
"""
import argparse
import hashlib
import heapq
import itertools
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import subprocess
import sys
from fractions import Fraction

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_ID = "SYMBIOTE-PROSPECTIVE-FRONTIER-004"
PROTOCOL_SHA256 = "d3e8454147b67fec510712eac094d0f946e683cd5472e3304ba912f1fea1c567"
BASE_COMMIT = "8dbbd4a7550a88f7f6b91b7aa287665dbc481ef1"
ARMS = ("isolated", "fixed-peer", "uniform-authorized", "prospective-frontier")
PRICES = (100, 1)
ROLES = (0, 1, 2, 3, 4)
ACTIVE_ROLES = (0, 1, 2, 4)
SEEDS = (211, 307, 401, 503, 601, 701)
SCOPE = "prospective-frontier-graph/v1"
BILL_FIELDS = (
    "acquisitions", "observation_purchase_attempts", "rpc_requests", "sessions", "rpc_sent_bytes", "rpc_received_bytes",
    "negotiation_sent_bytes", "negotiation_received_bytes", "verified_receipts",
    "receipt_verification_attempts", "adopted_edges", "received_attempts", "route_queries",
    "model_work", "exported_bytes",
)
RECORD_FIELDS = ("id", "revision", "source", "scope", "schema_fingerprint", "payload", "provenance")
RECEIPT_FIELDS = {"schema", "authority_id", "context", "schema_fingerprint", "observer_identity", "sequence", "id", "edge_id", "cost"}


def require(condition, description):
    if not condition:
        raise RuntimeError("Adaptive verification failed: " + description)


def natural(value, label, maximum=2**64 - 1):
    require(type(value) is int and 0 <= value <= maximum, label + " must be a bounded unsigned integer")
    return value


def hexdigest(value, length=64):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + r"}", value) is not None


def encode(value, *, canonical=False):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=canonical, separators=(",", ":")).encode("utf-8")


def digest(value):
    return hashlib.sha256(encode(value, canonical=True)).hexdigest()


def file_sha(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            result.update(block)
    return result.hexdigest()


def _pairs(values):
    result = {}
    for key, value in values:
        require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result


def loads(raw):
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda value: require(False, "non-finite JSON number"))


def no_credentials(value):
    if isinstance(value, dict):
        require(not {"private_key_pem", "private_key", "key_pem", "api_key", "bearer_token"}.intersection(value), "private credential field cannot enter published evidence")
        for item in value.values():
            no_credentials(item)
    elif isinstance(value, list):
        for item in value:
            no_credentials(item)
    elif isinstance(value, str):
        require(not any(marker in value for marker in ("-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----")), "private PEM material cannot enter published evidence")


def no_hidden_profile_labels(value):
    if isinstance(value, dict):
        require(not {"seed", "seed_index", "counter", "canonical_adjacency", "weights", "expected_labels", "expected_costs", "truth", "hidden_role", "evaluator_role"}.intersection(value),
                "private learner profile cannot contain generator/judge labels")
        for item in value.values():
            no_hidden_profile_labels(item)
    elif isinstance(value, list):
        for item in value:
            no_hidden_profile_labels(item)


def load(path, limit=64 * 1024 * 1024):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "required regular artifact missing: " + path.name)
    require(path.stat().st_size <= limit, "artifact exceeds byte budget: " + path.name)
    value = loads(path.read_text(encoding="utf-8"))
    no_credentials(value)
    return value


def record_digest(record):
    require(isinstance(record, dict) and set(record) == set(RECORD_FIELDS), "native knowledge record fields")
    ordered = {key: record[key] for key in RECORD_FIELDS}
    # The Rust struct preserves field order, while its payload is a JSON Value.
    ordered["payload"] = loads(encode(record["payload"], canonical=True))
    return hashlib.sha256(encode(ordered)).hexdigest()


def schema_fingerprint(schema):
    return digest({"kind": "finite-positive-cost-directed-graph", "version": 1,
                   "query_encoding": "start*nodes+goal", "schema": schema})


def graph(schema, weights=None):
    require(isinstance(schema, dict) and set(schema) == {"nodes", "edges"}, "strict graph schema")
    nodes = natural(schema["nodes"], "node count", 8)
    require(nodes >= 2 and isinstance(schema["edges"], list) and 1 <= len(schema["edges"]) <= 28, "bounded DAG topology")
    seen = set()
    incoming = [0] * nodes
    for edge in schema["edges"]:
        require(isinstance(edge, dict) and set(edge) == {"from", "to", "lower", "upper"}, "strict edge schema")
        start, goal = natural(edge["from"], "edge start", nodes - 1), natural(edge["to"], "edge goal", nodes - 1)
        require(start != goal and (start, goal) not in seen, "unique non-loop directed edges")
        seen.add((start, goal))
        require(1 <= natural(edge["lower"], "lower edge cost", 9) <= natural(edge["upper"], "upper edge cost", 9), "positive cost interval")
        incoming[goal] += 1
    todo = [node for node in range(nodes) if incoming[node] == 0]
    visited = 0
    while todo:
        node = todo.pop()
        visited += 1
        for edge in schema["edges"]:
            if edge["from"] == node:
                incoming[edge["to"]] -= 1
                if incoming[edge["to"]] == 0:
                    todo.append(edge["to"])
    require(visited == nodes, "declared graph must be acyclic")
    if weights is not None:
        require(isinstance(weights, list) and len(weights) == len(schema["edges"]), "one private cost per declared edge")
        for edge, cost in zip(schema["edges"], weights):
            require(edge["lower"] <= natural(cost, "private cost", 9) <= edge["upper"], "private cost within interval")
    return nodes


def shortest(schema, weights):
    """Independent Floyd-Warshall oracle, different from all native learners."""
    nodes = graph(schema, weights)
    distances = [[None] * nodes for _ in range(nodes)]
    for node in range(nodes):
        distances[node][node] = 0
    for edge, cost in zip(schema["edges"], weights):
        distances[edge["from"]][edge["to"]] = cost
    for middle in range(nodes):
        for start in range(nodes):
            for goal in range(nodes):
                if distances[start][middle] is None or distances[middle][goal] is None:
                    continue
                cost = distances[start][middle] + distances[middle][goal]
                if distances[start][goal] is None or cost < distances[start][goal]:
                    distances[start][goal] = cost
    return {start * nodes + goal: distances[start][goal] for start in range(nodes) for goal in range(nodes)
            if start != goal and distances[start][goal] is not None}


def route_check(schema, weights, observations, query, route):
    nodes = graph(schema, weights)
    natural(query, "route query", nodes * nodes - 1)
    start, goal = divmod(query, nodes)
    require(start != goal, "distinct route endpoints")
    if route is None:
        return False
    require(isinstance(route, dict) and set(route) == {"nodes", "edges", "cost", "cost_basis", "family", "conditional"}, "strict conditional route fields")
    require(route["conditional"] is True and route["family"] == "finite-positive-cost-directed-graph/v1"
            and route["cost_basis"] == "observed_edge_costs", "conditional observed-cost route declaration")
    path, edges = route["nodes"], route["edges"]
    require(isinstance(path, list) and isinstance(edges, list) and len(path) == len(edges) + 1 and 2 <= len(path) <= nodes,
            "bounded nonempty route")
    for node in path:
        natural(node, "path node", nodes - 1)
    require(path[0] == start and path[-1] == goal and len(set(path)) == len(path), "simple connected route endpoints")
    total = 0
    for index, edge_id in enumerate(edges):
        natural(edge_id, "route edge", len(schema["edges"]) - 1)
        edge = schema["edges"][edge_id]
        require(path[index:index + 2] == [edge["from"], edge["to"]], "path follows declared edge order")
        require(edge_id in observations and observations[edge_id] == weights[edge_id], "every certified route edge was observed correctly")
        total += weights[edge_id]
    require(natural(route["cost"], "route cost", 63) == total == shortest(schema, weights).get(query), "route matches independent optimum")
    optimistic = [observations.get(index, edge["lower"]) for index, edge in enumerate(schema["edges"])]
    require(total == shortest(schema, optimistic).get(query), "conservative certificate equals global optimistic lower bound")
    return True


def receipt_check(receipt, world, allowed_sources, authority_id=None):
    require(isinstance(receipt, dict) and set(receipt) == RECEIPT_FIELDS, "strict issued observation envelope")
    require(len(encode(receipt, canonical=True)) <= 2048, "single receipt 2KiB cap")
    require(receipt["schema"] == "symbiote.graph-observation/1" and hexdigest(receipt["authority_id"]), "receipt schema and fresh authority identifier")
    if authority_id is not None:
        require(receipt["authority_id"] == authority_id, "receipt belongs to this arm/regime authority epoch")
    require(receipt["context"] == world["context"] and receipt["schema_fingerprint"] == schema_fingerprint(world["schema"]), "exact receipt context/schema")
    require(receipt["observer_identity"] in allowed_sources, "explicit authorized receipt source")
    edge = natural(receipt["edge_id"], "receipt edge", len(world["costs"]) - 1)
    natural(receipt["cost"], "receipt cost", 9)
    require(receipt["cost"] == world["costs"][edge], "genuine observed edge cost")
    require(1_000_000_000 <= natural(receipt["sequence"], "issued receipt sequence", 9_999_999_999), "fixed-width authority sequence")
    body = {key: value for key, value in receipt.items() if key != "id"}
    require(receipt["id"] == digest(body), "issued receipt ID binds complete canonical body")
    return edge


def bill_total(bill, price, edges=None):
    require(isinstance(bill, dict) and set(bill) == set(BILL_FIELDS), "all primitive billing categories present")
    for field in BILL_FIELDS:
        natural(bill[field], "bill " + field)
    require(bill["verified_receipts"] == bill["adopted_edges"] <= bill["receipt_verification_attempts"] <= bill["received_attempts"],
            "successful/attempted verification and adoption diagnostics reconcile")
    require(price in PRICES, "registered price regime")
    if edges is not None:
        require(bill["acquisitions"] <= bill["observation_purchase_attempts"] <= edges and bill["adopted_edges"] <= edges and bill["received_attempts"] <= 3,
                "per-world acquisition/adoption/attempt quota")
        require(bill["rpc_requests"] <= 256 and bill["sessions"] <= 128 and bill["model_work"] <= 100000, "per-world operation/session/work quota")
        require(sum(bill[field] for field in ("rpc_sent_bytes", "rpc_received_bytes", "negotiation_sent_bytes", "negotiation_received_bytes")) <= 1048576,
                "per-world total application traffic quota")
    ceil = lambda value: (value + 1023) // 1024
    return (bill["observation_purchase_attempts"] * price + bill["rpc_requests"] + bill["sessions"] * 2
            + ceil(bill["rpc_sent_bytes"] + bill["negotiation_sent_bytes"])
            + ceil(bill["rpc_received_bytes"] + bill["negotiation_received_bytes"])
            + bill["receipt_verification_attempts"] * 2 + bill["adopted_edges"] + bill["route_queries"]
            + bill["model_work"] + ceil(bill["exported_bytes"]))


def participant_class(baseline, candidate):
    for participant in (baseline, candidate):
        for field in ("cost", "heldout_correct", "incorrect_certificates"):
            natural(participant[field], "participant " + field)
    base_cost, cost = baseline["cost"], candidate["cost"]
    base_coverage, coverage = baseline["heldout_correct"], candidate["heldout_correct"]
    benefit = candidate["incorrect_certificates"] == 0 and coverage >= base_coverage and (
        cost < base_cost or coverage > base_coverage and cost <= base_cost)
    if coverage < base_coverage:
        category = "reduced-coverage"
    elif coverage > base_coverage and cost > base_cost:
        category = "coverage-cost-tradeoff"
    elif benefit:
        category = "benefit"
    elif cost > base_cost:
        category = "higher-cost"
    else:
        category = "equal"
    return benefit, category


def jsonl(path, limit=4 * 1024 * 1024, count=4096):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= limit, "bounded regular JSONL file: " + path.name)
    raw = path.read_bytes()
    require(raw.endswith(b"\n"), "committed JSONL must have a final newline")
    lines = raw.splitlines()
    require(0 < len(lines) <= count and all(lines), "bounded nonempty JSONL records")
    return raw, [loads(line.decode("utf-8")) for line in lines]


def chain(path, kind, identity=None):
    raw, rows = jsonl(path)
    previous = "0" * 64
    for sequence, row in enumerate(rows):
        no_credentials(row)
        require(isinstance(row, dict) and set(row) == {"sequence", "previous", "payload", "sha256"}, "strict ledger receipt wrapper")
        natural(row["sequence"], "ledger sequence", 4095)
        require(row["sequence"] == sequence and row["previous"] == previous, "continuous ledger sequence/hash chain")
        if kind == "operations":
            expected = digest([sequence, previous, row["payload"]])
        elif kind == "knowledge":
            expected = hashlib.sha256(encode([sequence, previous, row["payload"]])).hexdigest()
        elif kind == "identity":
            expected = hashlib.sha256(encode({"sequence": sequence, "previous": previous, "payload": row["payload"]})).hexdigest()
        else:
            raise RuntimeError("unknown ledger kind")
        require(row["sha256"] == expected, "recomputed " + kind + " ledger hash")
        previous = expected
    genesis = rows[0]["payload"]
    require(genesis["event"] == "genesis" and genesis["version"] == 1, "supported ledger genesis")
    owner = genesis["owner_identity"] if kind == "operations" else genesis["identity"]
    if identity is not None:
        require(owner == identity, "ledger owner identity binding")
    return raw, rows, owner


def comparisons(cases, worlds):
    def metrics(case, role):
        if case is None or case["status"] != "COMPLETED":
            return None, "case not completed"
        row = next((item for item in case["participants"] if item["role"] == role), None)
        if row is None:
            return None, "participant missing"
        if row.get("utility_evaluable") is not True:
            return None, "ambiguous source purchase or missing utility witness"
        for field in ("cost", "heldout_correct", "heldout_total", "incorrect_certificates"):
            natural(row[field], "paired " + field)
        require(row["heldout_correct"] <= row["heldout_total"], "coverage within held-out denominator")
        return row, None

    def paired(price, baseline_arm, candidate_arm):
        sums = dict(worlds_evaluable=0, bilateral_benefit_worlds=0, A_B1_baseline_cost=0,
                    A_B1_candidate_cost=0, A_B1_baseline_correct=0, A_B1_candidate_correct=0)
        pairs, wrong = [], 0
        for world in range(worlds):
            groups = [[case for case in cases if (case["price"], case["world"], case["arm"]) == (price, world, arm)]
                      for arm in (baseline_arm, candidate_arm)]
            if any(len(group) != 1 for group in groups):
                pairs.append(dict(world=world, status="NOT_EVALUABLE", reason="missing or repeated paired case"))
                continue
            rows, complete, bilateral = [], True, True
            for role in ACTIVE_ROLES:
                before, first_error = metrics(groups[0][0], role)
                after, next_error = metrics(groups[1][0], role)
                if first_error or next_error or before["heldout_total"] != after["heldout_total"]:
                    rows.append(dict(role=role, **{"class": "NOT_EVALUABLE"}, reason=first_error or next_error or "held-out task counts differ"))
                    complete, bilateral = False, False
                    continue
                safe = before["incorrect_certificates"] == after["incorrect_certificates"] == 0
                benefit, category = participant_class(before, after)
                if not safe:
                    benefit, category = False, "incorrect-certificate"
                rows.append(dict(role=role, benefit=benefit, **{"class": category}, baseline_cost=before["cost"],
                                 candidate_cost=after["cost"], cost_difference=after["cost"] - before["cost"],
                                 baseline_correct=before["heldout_correct"], candidate_correct=after["heldout_correct"],
                                 heldout_total=before["heldout_total"], baseline_incorrect=before["incorrect_certificates"],
                                 candidate_incorrect=after["incorrect_certificates"]))
                if role <= 1:
                    bilateral = bilateral and benefit
            if complete:
                sums["worlds_evaluable"] += 1
                sums["bilateral_benefit_worlds"] += int(bilateral)
                for row in rows:
                    if row["role"] <= 1:
                        for source, target in (("baseline_cost", "A_B1_baseline_cost"), ("candidate_cost", "A_B1_candidate_cost"),
                                               ("baseline_correct", "A_B1_baseline_correct"), ("candidate_correct", "A_B1_candidate_correct")):
                            sums[target] += row[source]
                        wrong += row["baseline_incorrect"] + row["candidate_incorrect"]
            pairs.append(dict(world=world, status="EVALUATED" if complete else "NOT_EVALUABLE", participants=rows,
                              bilateral_A_B1_benefit=bilateral and complete))
        positive = (sums["worlds_evaluable"] == worlds and sums["bilateral_benefit_worlds"] > 0
                    and sums["A_B1_candidate_cost"] < sums["A_B1_baseline_cost"]
                    and sums["A_B1_candidate_correct"] >= sums["A_B1_baseline_correct"] and wrong == 0)
        return dict(baseline_arm=baseline_arm, candidate_arm=candidate_arm, worlds_expected=worlds, **sums,
                    positive_utility_gate="DEMONSTRATED" if positive else "NOT_DEMONSTRATED", paired_worlds=pairs)

    regimes = []
    for price in PRICES:
        regimes.append(dict(observation_price=price, role="primary" if price == 100 else "negative-cost-control",
                            prospective_vs_controls=[paired(price, baseline, ARMS[3]) for baseline in ARMS[:3]],
                            relationship_controls_vs_isolated=[paired(price, ARMS[0], arm) for arm in ARMS[1:3]]))
    normal = regimes[0]["prospective_vs_controls"]
    return dict(normal_policy_utility=normal[0]["positive_utility_gate"],
                normal_better_partner_selection="DEMONSTRATED" if all(item["positive_utility_gate"] == "DEMONSTRATED" for item in normal) else "NOT_DEMONSTRATED",
                regimes=regimes,
                meaning="software completion does not imply a positive scientific utility result; all losses and incomplete pairs remain shown")


def canonical_topology(schema):
    nodes = schema["nodes"]
    edges = {(edge["from"], edge["to"]) for edge in schema["edges"]}
    return min("".join("1" if (start, goal) in edges else "0" for start in order for goal in order)
               for middle in itertools.permutations(range(1, nodes - 1))
               for order in [(0,) + middle + (nodes - 1,)])


def _specified_shape(nodes, seed, counter):
    # This independent checker is invoked only on an already recorded bundle.
    # It never calls the Rust prospective entry point or creates an experiment.
    def stream(label, start, goal):
        return hashlib.sha256(f"SYMBIOTE-PROSPECTIVE-FRONTIER-002|{label}|{nodes}|{seed}|{counter}|{start}|{goal}".encode("ascii")).digest()
    edges = [(node, node + 1) for node in range(nodes - 1)]
    edges += [(start, goal) for start in range(nodes) for goal in range(start + 2, nodes)
              if stream("edge", start, goal)[0] < 96]
    physical = list(range(nodes))
    for position, (_, node) in enumerate(sorted((stream("node-order", node, 0), node) for node in range(1, nodes - 1))):
        physical[node] = position + 1
    ordered = sorted((stream("edge-order", start, goal), start, goal) for start, goal in edges)
    schema = {"nodes": nodes, "edges": [{"from": physical[start], "to": physical[goal], "lower": 1, "upper": 9}
                                          for _, start, goal in ordered]}
    weights = [1 + int.from_bytes(stream("cost", start, goal)[:2], "little") % 9 for _, start, goal in ordered]
    return schema, weights


def validate_worlds(frozen, full=True):
    require(isinstance(frozen, dict) and set(frozen) == {"worlds", "truths"}, "strict frozen environment artifact")
    worlds, truths = frozen["worlds"], frozen["truths"]
    require(isinstance(worlds, list) and len(worlds) == len(truths) and len(worlds) == (24 if full else 3), "complete frozen world/truth registry")
    contexts, seen = set(), {}
    for index, (world, truth) in enumerate(zip(worlds, truths)):
        require(world["index"] == index and world["nodes"] == world["schema"]["nodes"], "frozen world index/node alignment")
        graph(world["schema"], world["costs"])
        require(isinstance(world["context"], str) and re.fullmatch(r"frontier-context-[0-9a-f]{64}", world["context"]) is not None
                and world["context"] not in contexts, "unique opaque world context")
        contexts.add(world["context"])
        if full:
            nodes, seed_index = 5 + index // 6, index % 6
            require(world["nodes"] == nodes and world["seed"] == SEEDS[seed_index] and world["seed_index"] == seed_index, "exact preregistered cohort/order")
            counter = natural(world["counter"], "bounded topology rejection counter", 255)
            expected_schema, expected_weights = _specified_shape(nodes, world["seed"], counter)
            require(world["schema"] == expected_schema and world["costs"] == expected_weights, "independently reconstructed frozen generator specification")
            topology = canonical_topology(world["schema"])
            require(world["canonical_adjacency"] == topology and topology not in seen.setdefault(nodes, set()), "source/target-preserving topology uniqueness")
            require(len(world["schema"]["edges"]) > nodes - 1, "non-backbone edge required")
            for previous_counter in range(counter):
                prior, _ = _specified_shape(nodes, world["seed"], previous_counter)
                require(len(prior["edges"]) == nodes - 1 or canonical_topology(prior) in seen[nodes], "first admissible topology counter cannot be skipped")
            seen[nodes].add(topology)
        else:
            require(world["nodes"] == 4 and world["seed"] == 17, "manual development fixtures only")
        independent = shortest(world["schema"], world["costs"])
        recorded = {int(key): value for key, value in truth["costs"].items()}
        require(all(str(int(key)) == key for key in truth["costs"]) and recorded == independent, "frozen labels match independent Floyd-Warshall")
        natural(truth["path_work"], "bounded judge setup work", 10000000)
    return worlds


def expected_case_order(worlds):
    return [(price, index, ARMS[(index + offset) % 4]) for price in PRICES for index in range(worlds) for offset in range(4)]


def judge_receipts_check(participant, world, authority_epoch):
    groups = []
    if participant["main_status"] == "complete":
        groups.append([dict(input=world["nodes"] - 1, route=participant["main_route"])])
    forecasts = participant["forecasts"]
    groups.extend([[dict(input=claim["input"], route=claim["route"]) for claim in forecasts[index:index + 8]]
                   for index in range(0, len(forecasts), 8)])
    receipts = participant["judge_receipts"]
    require(len(receipts) == len(groups), "every training/held-out certificate page has an independent judge receipt")
    for receipt, claims in zip(receipts, groups):
        require(set(receipt) == {"schema", "authority_id", "context", "request_sha256", "results", "receipt_sha256"}, "strict pass/fail-only judge receipt")
        require(receipt["schema"] == "symbiote.authority-judge/1" and receipt["authority_id"] == authority_epoch
                and receipt["context"] == world["context"], "judge identity/epoch/context binding")
        require(receipt["request_sha256"] == digest(dict(context=world["context"], routes=claims)), "judge verdict binds exact submitted routes/task order")
        require(receipt["receipt_sha256"] == digest({key: value for key, value in receipt.items() if key != "receipt_sha256"}), "judge verdict integrity digest")
        require(len(receipt["results"]) == len(claims), "judge returns every requested task once")
        for result, claim in zip(receipt["results"], claims):
            require(set(result) == {"input", "certified", "correct", "abstained"} and result["input"] == claim["input"], "judge task attribution")
            emitted = claim["route"] is not None
            require(result["certified"] is emitted and result["correct"] is emitted and result["abstained"] is (not emitted), "independently checked judge flags; no hidden expected labels")


def calibration_check(campaign, worlds, identity, epoch):
    rows = [entry for entry in campaign["lifecycle"] if entry.get("event") == "genuine-stale-control-calibration"]
    require(len(rows) == 1, "genuine stale control calibrated before observations")
    receipt, verdict = rows[0]["receipt"], rows[0]["verdict"]
    require(re.fullmatch(r"frontier-prelude-[0-9a-f]{64}", receipt["context"]) is not None, "independent opaque genuine prelude")
    prelude = dict(context=receipt["context"], schema=worlds[0]["schema"], costs=[edge["lower"] for edge in worlds[0]["schema"]["edges"]])
    receipt_check(receipt, prelude, {identity}, epoch)
    require(verdict["authentic"] is True and verdict["applicable"] is True and verdict["receipt_sha256"] == digest(receipt), "calibration verifies a genuine receipt in its ORIGINAL context")


def validate_case(case, world, identities, authority_epoch):
    require(case["context"] == world["context"], "case binds registered opaque world")
    if case["status"] != "COMPLETED":
        require(case["status"] in ("FAILED", "NOT_RUN") and isinstance(case.get("reason"), str), "failed cases retained with reason")
        return
    require(case["nodes"] == world["nodes"], "case binds registered node count")
    require(case["unauthorized_connection_attempts"] == 0 and case["incompatible_agent_api_probes"] == 0, "no forbidden connection/probe assertion")
    participants = case["participants"]
    require(isinstance(participants, list) and [participant["role"] for participant in participants] == list(ROLES), "all five participant categories in role order")
    truth = shortest(world["schema"], world["costs"])
    for role, participant in enumerate(participants):
        require(participant["identity"] == identities[role], "participant private identity matches setup catalogue")
        require(participant["cost"] == bill_total(participant["bill"], case["price"], len(world["costs"])), "actual logical billing recomputation")
        if role == 3:
            require(participant["agent_api_calls"] == participant["acquisitions"] == participant["cost"] == 0, "incompatible category remains idle")
            continue
        allowed = set(identities[index] for index in ((0, 1, 2, 4) if role == 0 else (role, 0)))
        observations, ids = {}, set()
        for acquisition in participant["acquisitions"]:
            require(set(acquisition) == {"id", "edge_id", "cost", "receipt_sha256", "receipt"}, "strict acquisition provenance")
            receipt = acquisition["receipt"]
            natural(acquisition["edge_id"], "acquisition edge", len(world["costs"]) - 1)
            natural(acquisition["cost"], "acquisition cost", 9)
            edge = receipt_check(receipt, world, allowed, authority_epoch)
            require(acquisition["id"] == receipt["id"] and acquisition["receipt_sha256"] == digest(receipt)
                    and acquisition["edge_id"] == edge and acquisition["cost"] == receipt["cost"], "artifact binds exact issued evidence")
            require(edge not in observations and receipt["id"] not in ids, "one acquisition per unique edge")
            observations[edge] = receipt["cost"]
            ids.add(receipt["id"])
        record = participant["record"]
        require(record["source"] == identities[role] and record["scope"] == world["context"]
                and record["schema_fingerprint"] == schema_fingerprint(world["schema"]), "owner-created contextual graph model")
        require(set(record["payload"]) == {"kind", "schema", "observations"} and record["payload"]["kind"] == "graph-map"
                and record["payload"]["schema"] == world["schema"], "exact graph-map schema")
        require(record["payload"]["observations"] == [{"edge_id": edge, "cost": cost} for edge, cost in sorted(observations.items())], "native map equals its received/own observations")
        own = sum(item["receipt"]["observer_identity"] == identities[role] for item in participant["acquisitions"])
        require(participant["bill"]["acquisitions"] == own and participant["bill"]["adopted_edges"] == len(observations) - own,
                "billed successful acquisitions/adoptions reconcile with unique provenance")
        trained = participant["training_inputs"]
        require(isinstance(trained, list) and len(set(trained)) == len(trained) and world["nodes"] - 1 in trained
                and all(item in truth for item in trained), "unique public reachable training tasks including main")
        required = set(truth) - set(trained)
        forecasts = participant["forecasts"]
        require([claim["input"] for claim in forecasts] == sorted(required), "every held-out task appears once in fixed order")
        correct = sum(route_check(world["schema"], world["costs"], observations, claim["input"], claim["route"]) for claim in forecasts)
        require(participant["heldout_total"] == len(required) and participant["heldout_correct"] == correct
                and participant["abstentions"] == len(required) - correct and participant["incorrect_certificates"] == 0,
                "correct coverage/abstention/certificate counts recomputed")
        if participant["main_status"] == "complete":
            require(route_check(world["schema"], world["costs"], observations, world["nodes"] - 1, participant["main_route"]), "completed training route independently certified")
        else:
            require(participant["main_status"] in ("abstained", "not-completed"), "known main-task outcome")
        require(type(participant["utility_evaluable"]) is bool, "explicit source-purchase utility eligibility")
        judge_receipts_check(participant, world, authority_epoch)


def _profile_add(profiles, event):
    if event["outcome"] == "skipped_irrelevant":
        return
    profile = profiles.setdefault(event["peer_id"], dict(attempts=0, verified_novel=0, verification_failures=0, applicability_failures=0))
    profile["attempts"] += 1
    mapping = {"verified_novel": "verified_novel", "verification_failed": "verification_failures", "applicability_failed": "applicability_failures"}
    if event["outcome"] in mapping:
        profile[mapping[event["outcome"]]] += 1


def prospective_choice(decision, profiles, attempted, peers, price):
    details, frontier = decision["details"], decision["frontier_edge"]
    recorded = details["choice"]
    result = dict(peer=None, offer_id=None, probability_numerator=0, probability_denominator=1,
                  reason="local-observation", frontier=frontier, observation_price=price, quote=recorded["quote"])
    known = set(details["known_edges"])
    ads = [ad for ad in details["advertisements"] if ad["peer"] in peers and ad["context"] == decision["context"]
           and ad["scope"] == SCOPE and ad["edge_id"] == frontier and ad["edge_id"] not in known
           and ad["peer"] not in attempted
           and profiles.get(ad["peer"], {}).get("verification_failures", 0) + profiles.get(ad["peer"], {}).get("applicability_failures", 0) < 2]
    ads.sort(key=lambda ad: (-Fraction(profiles.get(ad["peer"], {}).get("verified_novel", 0) + 1,
                                       profiles.get(ad["peer"], {}).get("attempts", 0) + 2), ad["peer"]))
    if not ads:
        result["reason"] = "no-eligible-offer"
        return result
    ad = ads[0]
    profile = profiles.get(ad["peer"], {})
    numerator, denominator = profile.get("verified_novel", 0) + 1, profile.get("attempts", 0) + 2
    result.update(peer=ad["peer"], offer_id=ad["offer_id"], probability_numerator=numerator, probability_denominator=denominator)
    if 46 * denominator >= price * numerator:
        result["reason"] = "conservative-exchange-price-not-lower"
    else:
        quota = details["remaining"]
        reserved = (quota["acquisitions"] >= 1 and quota["attempts"] >= 1 and quota["adopted_edges"] >= 1
                    and quota["model_work"] > details["assessment_work_bound"] and quota["requests"] >= 3
                    and quota["connections"] >= 3 and quota["traffic"] >= 30720)
        result["reason"] = "request-verified-frontier-offer" if reserved else "fallback-and-common-work-reservation-unavailable"
    return result


def rejected_state_check(decision, attempted, world):
    details = decision["details"]
    require(set(details) == {"operation", "attempt_decision_id", "before_state", "after_state", "before_sha256", "after_sha256", "unchanged"},
            "complete rejected-state witness fields")
    require(details["operation"] == "rejected-state-witness" and attempted is not None,
            "rejected-state witness references a prior actual request")
    require(attempted["details"]["choice"]["reason"] == "request-verified-frontier-offer"
            and attempted["context"] == decision["context"] and attempted["selected_peer"] == decision["selected_peer"]
            and attempted["frontier_edge"] == decision["frontier_edge"], "rejected witness source/context/frontier matches its request")
    before, after = details["before_state"], details["after_state"]
    require(details["unchanged"] is True and encode(before, canonical=True) == encode(after, canonical=True),
            "rejected evidence cannot alter any native reasoning state")
    require(details["before_sha256"] == details["after_sha256"] == digest(before)
            == attempted["details"]["before_model_sha256"], "rejected state hashes bind pre-request model")
    require(set(before) == {"schema", "algorithm", "observations", "native_work"}
            and before["schema"] == world["schema"] and before["algorithm"] in ("dijkstra", "simple-paths"), "rejected witness uses bounded current native model")
    natural(before["native_work"], "rejected-state native work", 100000)
    observations = before["observations"]
    require(isinstance(observations, dict), "rejected-state exact observation map")
    for edge, cost in observations.items():
        require(re.fullmatch(r"0|[1-9][0-9]*", edge) is not None, "canonical observed edge ID")
        index = natural(int(edge), "rejected observed edge", len(world["costs"]) - 1)
        require(natural(cost, "rejected observed cost", 9) == world["costs"][index], "rejected state retains genuine prior costs")


def learning_summary(complete, retained, central_profile_effect):
    shared = retained.get("A_B1_common_validated_contexts", 0) > 0
    effect = natural(central_profile_effect, "central post-restart profile effects") > 0
    return dict(prospective_normal_shared_retained_context="DEMONSTRATED" if shared else "NOT_DEMONSTRATED",
                central_A_prior_profile_use_after_restart="DEMONSTRATED" if effect else "NOT_DEMONSTRATED",
                status="DEMONSTRATED" if complete and shared and effect else "NOT_DEMONSTRATED")


def authority_purchase_check(campaign, cases, identities):
    audit, setup = campaign["authority_audit"], campaign["setup_bills"]
    require(len(setup) == 5, "setup billing retains every role")
    complete = all(case["status"] == "COMPLETED" for case in cases)
    for role in ACTIVE_ROLES:
        counters = audit["per_actor"].get(identities[role])
        require(counters is not None, "actual authority counters exist for every active observer")
        for field in ("requests", "observe", "verify", "assess", "invalid"):
            natural(counters[field], "authority " + field)
        participants = [case["participants"][role] for case in cases if case["status"] == "COMPLETED"]
        purchases = sum(row["bill"]["observation_purchase_attempts"] for row in participants) + setup[role]["observation_purchase_attempts"]
        acquisitions = sum(row["bill"]["acquisitions"] for row in participants) + setup[role]["acquisitions"]
        require(counters["observe"] >= acquisitions, "authority counts cover accepted own-source observations")
        if complete and all(row["utility_evaluable"] is True for row in participants):
            require(counters["observe"] == purchases, "every actual authority observation is billed exactly once, including setup")
        verification_fees = sum(row["bill"]["receipt_verification_attempts"] for row in participants) + setup[role]["receipt_verification_attempts"]
        if complete:
            require(counters["verify"] <= verification_fees, "every authority verification has a charged verification attempt")


def public_warmups(world):
    schema, nodes = world["schema"], world["nodes"]
    if world["seed_index"] % 2 == 0:
        distances, previous, queue = {0: 0}, {}, [(0, 0)]
        while queue:
            cost, node = heapq.heappop(queue)
            if distances[node] != cost:
                continue
            if node == nodes - 1:
                break
            for edge_id, edge in enumerate(schema["edges"]):
                proposed = cost + edge["lower"]
                if edge["from"] == node and proposed < distances.get(edge["to"], sys.maxsize):
                    distances[edge["to"]] = proposed
                    previous[edge["to"]] = edge_id
                    heapq.heappush(queue, (proposed, edge["to"]))
        path, current = [], nodes - 1
        while current != 0:
            require(current in previous, "public optimistic main path exists")
            edge_id = previous[current]
            path.append(edge_id)
            current = schema["edges"][edge_id]["from"]
        path.reverse()
    else:
        paths, todo = [], [(0, (), 0)]
        while todo:
            node, edges, cost = todo.pop()
            if node == nodes - 1:
                paths.append((cost, edges))
            else:
                for edge_id, edge in enumerate(schema["edges"]):
                    if edge["from"] == node:
                        todo.append((edge["to"], edges + (edge_id,), cost + edge["lower"]))
        require(bool(paths), "public optimistic main path exists")
        cost = min(item[0] for item in paths)
        path = list(max(item[1] for item in paths if item[0] == cost))
    require(bool(path), "nonempty optimistic route")
    first = path[0]
    second = path[1] if len(path) > 1 else next(edge for edge in range(len(schema["edges"])) if edge != first)
    return [first, second, first, None, second]


def journal_check(path, identity, marker_path, group, role, world_map, arm=None, price=None):
    raw, rows, _ = chain(path, "operations", identity)
    marker = load(marker_path, 4096)
    genesis = rows[0]["payload"]
    require(marker == dict(schema="symbiote.operational-owner/1", version=1, owner_identity=identity,
                           service_id=genesis["service_id"], policy_digest=genesis["policy_digest"], genesis_sha256=rows[0]["sha256"]), "operational marker binds complete genesis")
    require(hexdigest(genesis["policy_digest"]) and genesis["service_id"] == identity, "private profile policy/owner namespace")
    peers = set(group[index] for index in ((1, 2, 4) if role == 0 else (0,)))
    profiles, decisions, outcomes, denied, warmups, profile_snapshots = {}, {}, set(), set(), {}, {}
    completed_decisions, rejected_witnesses = set(), set()
    attempted_by_context = {}
    audit_counts = dict(knowledge_requests=0, verified_novel_current_frontier=0, false_applicability=0,
                        irrelevant_requests=0, irrelevant_selections=0, decisions_with_prior_completed_profiles=0,
                        profile_changed_score_or_action_after_restart=0, profile_changed_action_after_restart=0)
    last_context_index = -1
    for row in rows[1:]:
        event = row["payload"]
        no_hidden_profile_labels(event)
        kind = event["event"]
        if kind == "peer_denied":
            require(event["peer_id"] in {group[3], "operator-unauthorized-descriptor"}, "denial only configured incompatible/unauthorized descriptor")
            denied.add(event["peer_id"])
        elif kind == "source_warmup_retained":
            receipt, context = event["receipt"], event["context"]
            require(context not in warmups and len(warmups) < 25 and event["receipt_sha256"] == digest(receipt), "unique bounded source warmup digest")
            require(receipt["context"] == context and receipt["observer_identity"] == identity, "source telemetry belongs to private journal owner")
            if context in world_map:
                receipt_check(receipt, world_map[context], {identity})
                require(receipt["edge_id"] == public_warmups(world_map[context])[role], "warmup selected from public topology before observing costs")
                require(world_map[context]["index"] > last_context_index, "private world sequence never rewinds")
                last_context_index = world_map[context]["index"]
            else:
                require(re.fullmatch(r"frontier-prelude-[0-9a-f]{64}", context) is not None, "only declared genuine prelude outside cohort")
                first = next(iter(world_map.values()))
                prelude = dict(context=context, schema=first["schema"], costs=[edge["lower"] for edge in first["schema"]["edges"]])
                receipt_check(receipt, prelude, {identity})
            warmups[context] = receipt
        elif kind == "partner_decision_recorded":
            decision = event["decision"]
            require(decision["decision_id"] not in decisions and decision["context"] in world_map, "unique decision bound to registered world")
            require(decision["selected_peer"] is None or decision["selected_peer"] in peers - denied, "decision cannot authorize an unknown/denied peer")
            details = decision["details"]
            if details.get("operation") == "rejected-state-witness":
                attempt_id = details["attempt_decision_id"]
                require(attempt_id not in rejected_witnesses, "one rejected-state witness per actual attempt")
                rejected_state_check(decision, decisions.get(attempt_id), world_map[decision["context"]])
                rejected_witnesses.add(attempt_id)
            if "choice" in details:
                require(encode(details["profiles"], canonical=True) == encode(profiles, canonical=True), "decision uses exactly prior completed private outcomes")
                choice = details["choice"]
                if choice["reason"] == "selected-offer-not-current-frontier":
                    audit_counts["irrelevant_selections"] += 1
                attempted = attempted_by_context.setdefault(decision["context"], set())
                if arm == ARMS[3]:
                    require(all(ad["schema_fingerprint"] == schema_fingerprint(world_map[decision["context"]]["schema"]) for ad in details["advertisements"]), "current applicable advertisement schema")
                    actual = prospective_choice(decision, profiles, attempted, peers, price)
                    require(actual == choice, "independent exact rational prospective decision replay")
                    cold = prospective_choice(decision, {}, attempted, peers, price)
                    if profiles:
                        audit_counts["decisions_with_prior_completed_profiles"] += 1
                        if world_map[decision["context"]]["index"] > (11 if len(world_map) == 24 else 0):
                            score_changed = actual["probability_numerator"] * cold["probability_denominator"] != cold["probability_numerator"] * actual["probability_denominator"]
                            action_changed = actual["peer"] != cold["peer"] or actual["reason"] != cold["reason"]
                            audit_counts["profile_changed_score_or_action_after_restart"] += int(score_changed or action_changed)
                            audit_counts["profile_changed_action_after_restart"] += int(action_changed)
                require(choice["peer"] == decision["selected_peer"] and choice["frontier"] == decision["frontier_edge"], "decision/choice frontier and peer agree")
                require(choice["quote"] == dict(receiver_max=31, contributor_max=15, pair_max=46, frame=4096, control_frame=1024), "frozen method quote")
                if price is not None:
                    require(choice["observation_price"] == price, "choice uses this registered observation-price regime")
                if choice["reason"] == "request-verified-frontier-offer":
                    audit_counts["knowledge_requests"] += 1
                    attempted.add(choice["peer"])
                    if not any(ad["peer"] == choice["peer"] and ad["edge_id"] == decision["frontier_edge"] for ad in details["advertisements"]):
                        audit_counts["irrelevant_requests"] += 1
                    prior = profiles.get(choice["peer"], dict(attempts=0, verified_novel=0, verification_failures=0, applicability_failures=0))
                    require(prior["verification_failures"] + prior["applicability_failures"] < 2, "quarantined peer is not requested")
                    numerator, denominator = ((prior["verified_novel"] + 1, prior["attempts"] + 2) if arm == ARMS[3] else (1, 2))
                    require(choice["probability_numerator"] == numerator and choice["probability_denominator"] == denominator,
                            "prospective score uses prior evidence; controls use neutral prior")
                    require(46 * choice["probability_denominator"] < choice["observation_price"] * choice["probability_numerator"], "strict conservative acquisition inequality")
                    quota = details["remaining"]
                    for value in quota.values():
                        natural(value, "predecision reserved quota")
                    current_world = world_map[decision["context"]]
                    edges, nodes = len(current_world["costs"]), current_world["nodes"]
                    bound = nodes * edges if (current_world["seed_index"] + role) % 2 == 0 else edges * 2**(nodes - 1)
                    require(quota["acquisitions"] >= 1 and quota["attempts"] >= 1 and quota["adopted_edges"] >= 1
                            and quota["model_work"] > bound and quota["requests"] >= 3 and quota["connections"] >= 3
                            and quota["traffic"] >= 3 * (2 * 4096 + 2 * 1024), "whole local fallback and common reasoning reserved before requesting")
            decisions[decision["decision_id"]] = decision
        elif kind == "partner_outcome_recorded":
            outcome = event["outcome"]
            require(outcome["interaction_id"] in decisions and outcome["interaction_id"] not in outcomes, "metadata outcome uniquely references prior decision")
            require(outcome["peer_id"] == decisions[outcome["interaction_id"]]["selected_peer"], "metadata source bound to selected peer")
            require(outcome["kind"] in ("received", "rejected", "abstained", "failed") and outcome["scope"] == SCOPE,
                    "typed metadata outcome remains operational, never a learning signal")
            outcomes.add(outcome["interaction_id"])
        elif kind == "partner_interaction_completed":
            interaction = event["interaction"]
            decision = decisions.get(interaction["decision_id"])
            require(decision is not None and interaction["interaction_id"] not in outcomes, "unique interaction references prior decision")
            require(decision["context"] == interaction["context"] and decision["selected_peer"] == interaction["peer_id"], "outcome context/source exactly selected")
            require(interaction["decision_id"] not in completed_decisions, "one outcome per decision")
            require((interaction["decision_id"] in rejected_witnesses) == (interaction["outcome"] != "verified_novel"),
                    "each rejected attempt has an unchanged-state witness, successful transfer has none")
            completed_decisions.add(interaction["decision_id"])
            outcomes.add(interaction["interaction_id"])
            _profile_add(profiles, interaction)
            if interaction["outcome"] == "verified_novel":
                audit_counts["verified_novel_current_frontier"] += 1
            elif interaction["outcome"] == "applicability_failed":
                audit_counts["false_applicability"] += 1
            elif interaction["outcome"] == "skipped_irrelevant":
                audit_counts["irrelevant_selections"] += 1
        else:
            require(False, "service/unknown event cannot enter an adaptive private profile")
        context = (event.get("context") or event.get("decision", {}).get("context") or event.get("interaction", {}).get("context"))
        if context in world_map:
            profile_snapshots[context] = loads(encode(profiles, canonical=True))
    require(len(decisions) <= 2048 and len(outcomes) <= 256, "bounded durable profile journal")
    require(rejected_witnesses <= completed_decisions, "rejected-state witness has a completed outcome")
    requests = audit_counts["knowledge_requests"]
    audit = dict(status="VERIFIED", **audit_counts, selection_precision=audit_counts["verified_novel_current_frontier"] / requests if requests else None,
                 false_applicability_rate=audit_counts["false_applicability"] / requests if requests else None,
                 prior_profile_use_gate="DEMONSTRATED" if audit_counts["profile_changed_score_or_action_after_restart"] else "NOT_DEMONSTRATED",
                 profiles=profiles, meaning="operational relationship adaptation; not an automatic knowledge promotion or performance proof")
    return dict(raw_sha256=hashlib.sha256(raw).hexdigest(), profiles=profiles, warmups=warmups,
                rows=rows, policy_digest=genesis["policy_digest"], profile_snapshots=profile_snapshots, audit=audit)


def knowledge_check(path, identity, authority_identity, authority_epoch, worlds, cases, role):
    _, rows, _ = chain(path, "knowledge", identity)
    active, historical, revisions, scopes = {}, {}, {}, set()
    for row in rows[1:]:
        event = row["payload"]
        if event["event"] == "revoke":
            require(event["id"] in active and isinstance(event["reason"], str) and event["reason"].strip(), "audited revocation of active knowledge")
            del active[event["id"]]
            continue
        require(event["event"] == "promote_graph" and event["policy_version"] == 2, "native primary knowledge uses supported graph policy")
        record, assessment = event["record"], event["assessment"]
        context, revision = record["scope"], natural(record["revision"], "knowledge revision")
        require(context in worlds and record["source"] == identity and revision > revisions.get(record["id"], 0), "strict owner/context/revision promotion")
        require(context not in scopes, "same stationary primary context cannot be relabelled new learning")
        scopes.add(context)
        world = worlds[context]
        case = cases[context]
        participant = case["participants"][role]
        require(record["id"] == participant["record"]["id"] and record["payload"] == participant["record"]["payload"], "promoted model belongs to exact evaluated case")
        expected = set(shortest(world["schema"], world["costs"])) - set(participant["training_inputs"])
        evidence = assessment["evidence"]
        require(evidence["evaluator"] == authority_identity and assessment["authority_id"] == authority_epoch, "independent authority identity/epoch binds promotion")
        require(assessment["record_digest"] == record_digest(record), "assessment binds full native typed record")
        require({item["input"] for item in evidence["training_tasks"]} == set(participant["training_inputs"]), "promotion training tasks match predeclared task registry")
        observations = {item["edge_id"]: item["cost"] for item in record["payload"]["observations"]}
        required_cases = evidence["cases"]
        require(len(required_cases) == len(expected) and {item["input"] for item in required_cases} == expected, "promotion evaluates ALL held-out routes without duplication")
        truth = shortest(world["schema"], world["costs"])
        for item in required_cases:
            require(item["expected"] == item["candidate"] == truth[item["input"]] and item["baseline"] is None, "new-context capability evidence is independently correct")
        require(assessment["heldout_route_queries"] == assessment["candidate_correct"] == len(expected)
                and assessment["baseline_correct"] == assessment["regressions"] == 0
                and assessment["coverage_improved"] is True and assessment["cost_improved"] is False, "recomputed promotion effectiveness metrics")
        costs = evidence["costs"]
        for value in costs.values():
            natural(value, "promotion cost", 1000000000)
        require(costs["baseline"] == assessment["baseline_cost"] == 0 and costs["candidate"] == assessment["candidate_cost"]
                and costs["acquisition"] + costs["verification"] + costs["adoption"] <= costs["candidate"], "promotion costs include their declared components")
        require(costs["candidate"] <= participant["cost"], "promotion cannot exceed final billed task cost")
        require(evidence["acquisitions"] == participant["acquisitions"], "durable provenance preserves all evaluated own/received observations")
        for claim in participant["forecasts"]:
            require(route_check(world["schema"], world["costs"], observations, claim["input"], claim["route"]), "promoted fixed held-out capability contains no abstention")
        revisions[record["id"]] = revision
        active[record["id"]] = record
        historical[record_digest(record)] = record
    for context, case in cases.items():
        if case["status"] != "COMPLETED":
            continue
        participant = case["participants"][role]
        if participant["promotion"] == "promoted":
            require(record_digest(participant["record"]) in historical, "reported promotion must exist in actual historical learning ledger, never a rolled-back valid prefix")
        elif participant["promotion"] == "already-retained":
            require(any(prior["id"] == participant["record"]["id"] and prior["payload"] == participant["record"]["payload"] for prior in historical.values()), "reused capability has genuine historical promotion")
        else:
            require(participant["promotion"].startswith("withheld-"), "withheld outcome is not learning")
    return active, historical


def _original_parts(path):
    text = str(path)
    if text.startswith("\\\\?\\"):
        text = text[4:]
    return PureWindowsPath(text) if re.match(r"^[A-Za-z]:", text) else PurePosixPath(text)


class Bundle:
    def __init__(self, artifacts, original_root):
        self.artifacts = Path(artifacts).resolve(strict=True)
        self.original = _original_parts(original_root)
        require(self.artifacts.is_dir(), "explicit artifact directory exists")

    def remap(self, original):
        try:
            relative = _original_parts(original).relative_to(self.original)
        except ValueError as error:
            raise RuntimeError("registered artifact path escapes the explicitly remapped original root") from error
        require(".." not in relative.parts, "artifact remap cannot traverse parents")
        target = self.artifacts.joinpath(*relative.parts).resolve(strict=True)
        require(target == self.artifacts or self.artifacts in target.parents, "artifact symlink cannot escape explicit bundle root")
        return target


def _genesis_item(item):
    raw = item["genesis_jsonl"].encode("utf-8")
    require(raw.endswith(b"\n") and len(raw.splitlines()) == 1, "catalogue contains only one immutable genesis")
    row = loads(raw)
    require(row["payload"] == {"event": "genesis", "version": 1, "identity": item["identity"]}, "catalogue genesis owner")
    expected = hashlib.sha256(encode({"sequence": 0, "previous": "0" * 64, "payload": row["payload"]})).hexdigest()
    require(row["sequence"] == 0 and row["previous"] == "0" * 64 and row["sha256"] == expected, "catalogue genesis hash")
    return raw


def validate_restart(proof, identities, active_records, world_map, *, final_index, expected_profiles=None, expected_hashes=None):
    require(isinstance(proof, dict) and proof["after_completed_world"] == final_index, "required fixed restart point preserved")
    require(proof["identity_and_profile_bytes_preserved"] is True, "restart preserves private committed bytes")
    require(proof["oracle_before"] == proof["oracle_after"], "offline restart makes zero observe/verify/assess calls")
    for identity, counters in proof["oracle_before"].items():
        for field in ("observe", "verify", "assess"):
            natural(counters[field], "retained authority counter")
    def normalized(rows):
        return [{"role": item["role"], "pages": item["pages"]} for item in rows]
    require(normalized(proof["before"]) == normalized(proof["after"]), "same exact offline model/profile predictions")
    before_ready, after_ready = proof["roles_before"], proof["roles_after"]
    require(len(before_ready) == len(after_ready) == len(proof["roles_stopped"]) == 5, "all five native roles restart")
    require(len({item["pid"] for item in after_ready}) == 5, "fresh concurrently distinct role processes")
    for role, (before, after, stopped) in enumerate(zip(before_ready, after_ready, proof["roles_stopped"])):
        require(before["identity"] == after["identity"] == identities[role]
                and before["certificate_sha256"] == after["certificate_sha256"]
                and before["instance_nonce"] != after["instance_nonce"], "new instance with stable owner and pinned certificate")
        require(stopped["successful_shutdown"] is True and stopped["ready"] == before, "old owned process was shut down before replacement")
        summary = stopped["summary"]
        require(summary["identity"] == before["identity"] and summary["pid"] == before["pid"]
                and summary["instance_nonce"] == before["instance_nonce"], "stop counters bind exact old child")
        if role == 3:
            require(summary["connections"] == summary["application_requests"] == 0, "measured incompatible-role transport/API silence")
    if expected_hashes is not None:
        require(proof["protected_file_sha256"] == expected_hashes, "raw committed private-file bytes at this restart cut point")
    count, records = 0, set()
    role_models, role_predictions = {}, {}
    contexts = {role: set() for role in ACTIVE_ROLES}
    for item in proof["after"]:
        role = item["role"]
        require(role in ACTIVE_ROLES, "restart only probes compatible API roles")
        role_models[role], role_predictions[role] = set(), set()
        for page in item["pages"]:
            require(page["identity"] == identities[role], "restart retains its exact owner")
            if expected_profiles is not None:
                require(page["profiles"] == expected_profiles[role], "restart profile values match prior committed outcomes at this cut point")
            for model in page["models"]:
                record = active_records[role].get(model["id"])
                require(record is not None and model["record_digest"] == record_digest(record) and model["scope"] == record["scope"], "offline route bound to active validated model")
                world = world_map[record["scope"]]
                require(world["index"] <= final_index, "restart cannot contain future-world knowledge")
                observations = {value["edge_id"]: value["cost"] for value in record["payload"]["observations"]}
                records.add((role, model["record_digest"]))
                role_models[role].add((model["id"], model["record_digest"]))
                for claim in model["routes"]:
                    require(route_check(world["schema"], world["costs"], observations, claim["input"], claim["route"]), "retained offline prediction independently correct")
                    count += 1
                    key = (model["id"], claim["input"])
                    require(key not in role_predictions[role], "offline pagination cannot duplicate capability counts")
                    role_predictions[role].add(key)
                    contexts[role].add(model["scope"])
    # Empty equality is an integrity check, not a learning demonstration.
    rows = [dict(role=role, validated_models=len(role_models[role]), certified_offline_predictions=len(role_predictions[role]),
                 learning_gate="DEMONSTRATED" if role_models[role] and role_predictions[role] else "NOT_DEMONSTRATED") for role in ACTIVE_ROLES]
    for role in ACTIVE_ROLES:
        expected = {(record["id"], record_digest(record)) for record in active_records[role].values()
                    if world_map[record["scope"]]["index"] <= final_index}
        require(role_models[role] == expected, "offline replay includes every accepted artifact, never only a favorable subset")
    common = len(contexts[0] & contexts[1])
    expected_learning = dict(participants=rows, A_B1_common_validated_contexts=common,
                             bilateral_learning_gate="DEMONSTRATED" if common else "NOT_DEMONSTRATED")
    require(proof["learning"] == expected_learning, "non-vacuous per-role/common-context learning counts")
    require(proof["retained_predictions_preserved"] == bool(records and count), "empty equality is never labelled retained learned capability")
    return dict(validated_records=len(records), offline_predictions=count, demonstrated=bool(records and count),
                participants=rows, A_B1_common_validated_contexts=common)


def protected_cutpoint(root, identities, journals, world_map, cut_index):
    result = []
    for role in ROLES:
        directory = root / f"participant-{role}"
        hashes = {}
        for name in ("ledger.jsonl", "knowledge.jsonl", "operations.jsonl", "operations-owner.json"):
            path = directory / name
            if name in ("ledger.jsonl", "operations-owner.json"):
                hashes[name] = file_sha(path)
                continue
            raw, rows = jsonl(path)
            last, contexts, record_contexts = 1, {}, {}
            for index, row in enumerate(rows[1:], 1):
                event = row["payload"]
                context = None
                if name == "operations.jsonl":
                    kind = event["event"]
                    if kind == "partner_decision_recorded":
                        context = event["decision"]["context"]
                        contexts[event["decision"]["decision_id"]] = context
                    elif kind == "partner_interaction_completed":
                        context = event["interaction"]["context"]
                    elif kind == "partner_outcome_recorded":
                        context = contexts[event["outcome"]["interaction_id"]]
                    elif kind == "source_warmup_retained":
                        context = event["context"]
                elif event["event"] == "promote_graph":
                    context = event["record"]["scope"]
                    record_contexts[event["record"]["id"]] = context
                elif event["event"] == "revoke":
                    context = record_contexts[event["id"]]
                if context in world_map and world_map[context]["index"] > cut_index:
                    break
                last = index + 1
            hashes[name] = hashlib.sha256(b"".join(raw.splitlines(keepends=True)[:last])).hexdigest()
        result.append(dict(role=role, identity=identities[role], files=hashes))
    return result


def _path_identity(directory, expected_genesis, identity):
    raw, rows, owner = chain(directory / "ledger.jsonl", "identity", identity)
    require(len(rows) == 1 and raw == expected_genesis, "private original ledger remains its exact paired genesis")
    return owner


def registration_check(report, registration, binary, registration_sha256):
    require(registration["schema"] == "symbiote.primary-registration/1" and registration["protocol_id"] == PROTOCOL_ID
            and registration["protocol_sha256"] == PROTOCOL_SHA256 and registration["base_release_commit"] == BASE_COMMIT,
            "registration protocol/base release binding")
    require(report["registration_sha256"] == registration_sha256, "exact original registration bytes")
    require(hexdigest(registration["candidate_source_commit"], 40) and registration["candidate_source_commit"] == report["source_commit"], "frozen candidate source commitment")
    require(file_sha(binary) == registration["candidate_binary_sha256"], "actual candidate executable matches immutable registration")
    require(registration["run_id"] == report["run_id"] and bool(registration["runner"]["toolchain"]), "run ID/environment binding")


def validate_bundle(report_path, *, registration_path=None, binary=None, artifacts=None, state=None,
                    source_root=ROOT, allow_development=False):
    report_path = Path(report_path).resolve(strict=True)
    report = load(report_path)
    full = report.get("mode") in ("primary", "reproduction")
    require(full or allow_development and report.get("mode") == "development-calibration", "primary/reproduction evidence required unless development is explicit")
    require(report["schema"] == "symbiote.adaptive-research/1" and report["protocol_id"] == PROTOCOL_ID
            and report["protocol_sha256"] == PROTOCOL_SHA256, "supported report/protocol binding")
    registration = None
    if full:
        require(registration_path is not None and binary is not None, "registered source/binary evidence cannot be skipped")
        registration_path = Path(registration_path).resolve(strict=True)
        registration = load(registration_path, 16384)
        registration_check(report, registration, binary, file_sha(registration_path))
        bundle = Bundle(artifacts or registration["artifact_directory"], registration["artifact_directory"])
        require(bundle.remap(registration["receipt_path"]) == report_path, "exact registered receipt path with explicit portable prefix remap")
        state_path = bundle.remap(registration["state_directory"])
        if report["mode"] == "primary":
            started = load(bundle.artifacts / "primary-started.json", 16384)
            require(started == dict(schema="symbiote.primary-started/1", registration_sha256=report["registration_sha256"], run_id=report["run_id"],
                                    protocol_sha256=PROTOCOL_SHA256, candidate_source_commit=report["source_commit"],
                                    candidate_binary_sha256=registration["candidate_binary_sha256"]), "immutable original primary-start marker")
        if source_root is not None:
            source_root = Path(source_root).resolve(strict=True)
            protocol = (source_root / "docs/RESEARCH_V05_PROTOCOL_004.md").read_text(encoding="utf-8").replace("\r\n", "\n")
            require(hashlib.sha256(protocol.encode("utf-8")).hexdigest() == PROTOCOL_SHA256, "actual frozen protocol bytes")
            checked = subprocess.run(["git", "cat-file", "-e", report["source_commit"] + "^{commit}"], cwd=source_root,
                                     capture_output=True, timeout=15)
            require(checked.returncode == 0, "frozen source commit resolves in supplied repository")
    else:
        require(artifacts is not None and state is not None, "development artifacts/state paths must be explicit")
        bundle = Bundle(artifacts, artifacts)
        state_path = Path(state).resolve(strict=True)
        require(bundle.artifacts in state_path.parents, "development private state inside explicit artifact root")
    frozen = load(bundle.artifacts / "frozen-environments.json")
    require(report["frozen_environments_sha256"] == digest(frozen), "frozen environment artifact digest")
    worlds = validate_worlds(frozen, full)
    world_map = {world["context"]: world for world in worlds}
    require(report["world_count"] == len(worlds) and report["price_regimes"] == 2 and report["comparison_arms"] == 4
            and report["cases_expected"] == report["cases_recorded"] == len(worlds) * 8, "full registry counts without cohort inflation")
    _, case_rows = jsonl(bundle.artifacts / "case-receipts.jsonl", limit=64 * 1024 * 1024, count=192)
    require(case_rows == report["cases"], "raw append-only case receipts equal final report in order")
    for case in case_rows:
        natural(case["world"], "case world index", len(worlds) - 1)
        natural(case["price"], "case observation price", 100)
    require([(case["price"], case["world"], case["arm"]) for case in case_rows] == expected_case_order(len(worlds)), "complete price/world/Latin-square arm order, including failures and NOT_RUN")
    catalogue = load(bundle.artifacts / "simulation-genesis-catalogue.json")
    require(digest(catalogue) == report["initial_simulation_genesis_sha256"], "pre-observation role genesis catalogue digest")
    require(catalogue["identity_count"] == 14 and catalogue["state_path_count"] == 49
            and catalogue["counterfactual_learner_identities"] == 5 and catalogue["isolated_learner_profiles"] == 40
            and catalogue["contains_private_keys"] is False and catalogue["contains_learned_records"] is False,
            "five paired identities, eight authorities and49isolated private state paths")
    controller_genesis = _genesis_item(catalogue["controller"])
    require(catalogue["controller"]["identity"] == report["identity"], "report owner is initial controller")
    _path_identity(state_path, controller_genesis, report["identity"])
    groups = {(group["price"], group["arm"]): group for group in catalogue["groups"]}
    campaigns = {(campaign["price"], campaign["arm"]): campaign for campaign in report["campaigns"]}
    expected_groups = {(price, arm) for price in PRICES for arm in ARMS}
    require(len(groups) == len(catalogue["groups"]) == len(campaigns) == len(report["campaigns"]) == 8
            and set(groups) == set(campaigns) == expected_groups, "all eight independent arm/regime namespaces")
    shared_roles, authority_ids, state_paths, files = None, set(), [state_path], []
    policies, authority_epochs, certificate_pins = set(), set(), set()
    retained, journal_results, historical_count = {}, {}, 0
    all_complete = all(case["status"] == "COMPLETED" for case in case_rows)
    for price, arm in [(price, arm) for price in PRICES for arm in ARMS]:
        group, campaign = groups[(price, arm)], campaigns[(price, arm)]
        require([item["role"] for item in group["roles"]] == list(ROLES), "catalogue role order")
        identities = [item["genesis"]["identity"] for item in group["roles"]]
        geneses = [_genesis_item(item["genesis"]) for item in group["roles"]]
        require(len(set(identities)) == 5, "independent role identities")
        require(report["identity"] not in identities, "learner identity never aliases its controller")
        if shared_roles is None:
            shared_roles = (identities, geneses)
        require((identities, geneses) == shared_roles, "all counterfactual arms/regimes use SAME identities/genesis bytes")
        authority_identity = group["authority"]["identity"]
        require(authority_identity not in authority_ids and authority_identity not in identities + [report["identity"]], "independent authority/controller identities")
        authority_ids.add(authority_identity)
        root = state_path / "campaigns" / ("normal" if price == 100 else "cheap") / arm
        authority_path = root / "authority"
        require(state_path in authority_path.resolve(strict=True).parents, "authority state stays within registered private state root")
        _path_identity(authority_path, _genesis_item(group["authority"]), authority_identity)
        state_paths.append(authority_path)
        audit = campaign["authority_audit"]
        if audit is None:
            require(campaign["failed"] is True, "missing authority evidence is explicit failure")
            epoch = None
        else:
            require(audit["identity"] == authority_identity and hexdigest(audit["authority_id"])
                    and audit["expected_labels_returned_to_learners"] == 0, "authority identity/fresh epoch and no hidden label channel")
            epoch = audit["authority_id"]
            require(epoch not in authority_epochs, "authority registry epochs are independent across arm/regime namespaces")
            authority_epochs.add(epoch)
        cases = {world["context"]: next(case for case in case_rows if case["world"] == world["index"] and case["price"] == price and case["arm"] == arm) for world in worlds}
        active_by_role, journals = {}, {}
        for role in ROLES:
            directory = root / f"participant-{role}"
            require(state_path in directory.resolve(strict=True).parents, "participant state stays within registered private state root")
            state_paths.append(directory)
            _path_identity(directory, geneses[role], identities[role])
            for name in ("ledger.jsonl", "knowledge.jsonl", "operations.jsonl", "operations-owner.json"):
                candidate = directory / name
                require(candidate.is_file() and not candidate.is_symlink(), "every private profile component exists: " + name)
                require(not any(os.path.samefile(candidate, prior) for prior in files), "private profiles cannot share a physical ledger file")
                files.append(candidate)
            journal = journal_check(directory / "operations.jsonl", identities[role], directory / "operations-owner.json", identities, role, world_map, arm, price)
            journals[role] = journal
            active, historical = knowledge_check(directory / "knowledge.jsonl", identities[role], authority_identity, epoch, world_map, cases, role) if role != 3 else ({}, {})
            if role == 3:
                _, idle, _ = chain(directory / "knowledge.jsonl", "knowledge", identities[role])
                require(len(idle) == 1 and len(journal["rows"]) == 1, "incompatible actor has genesis-only state and zero agent API use")
            active_by_role[role] = active
            historical_count += len(historical)
            for case in cases.values():
                if case["status"] == "COMPLETED" and role != 3:
                    require(case["participants"][role]["profiles"] == journal["profile_snapshots"].get(case["context"], {}), "reported profiles match recipient's chronological completed-outcome ledger")
        expected_audits = [dict(role=role, audit=journals[role]["audit"]) for role in ROLES]
        require(encode(campaign["profile_audits"], canonical=True) == encode(expected_audits, canonical=True),
                "native profile-effect counters independently replay all prior-outcome decisions")
        state_rows = campaign["participant_states"]
        require([row["role"] for row in state_rows] == list(ROLES)
                and [row["identity"] for row in state_rows] == identities, "reported participant state registry retains every role")
        require(all(bundle.remap(row["state"]) == root / f"participant-{role}" for role, row in enumerate(state_rows)),
                "reported private profile paths bind exact registered role directories")
        for case in cases.values():
            validate_case(case, worlds[case["world"]], identities, epoch)
            if case["status"] == "COMPLETED":
                for role in ACTIVE_ROLES:
                    warmup = journals[role]["warmups"].get(case["context"])
                    require(warmup is not None, "each completed participant retains its genuine own warmup")
                    edge = world_map[case["context"]]["schema"]["edges"][warmup["edge_id"]]
                    expected_training = sorted({world_map[case["context"]]["nodes"] - 1,
                                                edge["from"] * world_map[case["context"]]["nodes"] + edge["to"]})
                    require(case["participants"][role]["training_inputs"] == expected_training, "training-pair deduplication follows public source warmup")
                    interactions = [row["payload"]["interaction"] for row in journals[role]["rows"]
                                    if row["payload"].get("event") == "partner_interaction_completed"
                                    and row["payload"]["interaction"]["context"] == case["context"]
                                    and row["payload"]["interaction"]["outcome"] != "skipped_irrelevant"]
                    participant = case["participants"][role]
                    require(participant["bill"]["received_attempts"] == len(interactions), "actual requests reconcile with completed private interaction records")
                    verified = [interaction for interaction in interactions if interaction["outcome"] == "verified_novel"]
                    require(participant["bill"]["verified_receipts"] == len(verified), "profile success count reconciles with actual verified-adoption meter")
                    acquisition_by_digest = {item["receipt_sha256"]: item["receipt"] for item in participant["acquisitions"]}
                    decisions = {row["payload"]["decision"]["decision_id"]: row["payload"]["decision"] for row in journals[role]["rows"]
                                 if row["payload"].get("event") == "partner_decision_recorded"}
                    used_edges, attempted_peers = set(), set()
                    for interaction in interactions:
                        require(interaction["peer_id"] not in attempted_peers, "at most one offer request per peer/context")
                        attempted_peers.add(interaction["peer_id"])
                        natural(interaction["sent_bytes"], "interaction sent bytes")
                        natural(interaction["received_bytes"], "interaction received bytes")
                        natural(interaction["resource_units"], "interaction declared cost")
                        if interaction["outcome"] == "verified_novel":
                            receipt = acquisition_by_digest.get(interaction["receipt_sha256"])
                            require(receipt is not None and receipt["observer_identity"] == interaction["peer_id"], "successful profile outcome has exact received provenance")
                            decision = decisions[interaction["decision_id"]]
                            require(receipt["edge_id"] == decision["frontier_edge"] and receipt["edge_id"] not in used_edges, "verified novelty supplies precisely the current frontier once")
                            used_edges.add(receipt["edge_id"])
                        else:
                            require(interaction["outcome"] in ("verification_failed", "applicability_failed", "transport_failed", "empty_offer"), "distinct explicit failed-attempt category")
                            require(interaction["receipt_sha256"] not in acquisition_by_digest, "rejected offer never enters current knowledge support")
        if audit is not None and not campaign["failed"]:
            calibration_check(campaign, worlds, identities[4], epoch)
        require(len({journal["policy_digest"] for journal in journals.values()}) == 1, "same group uses same static arm/regime policy")
        policy = next(iter(journals.values()))["policy_digest"]
        expected_policy = digest({"protocol": PROTOCOL_SHA256, "arm": dict(zip(ARMS, ("isolated", "fixed", "uniform", "prospective")))[arm],
                                  "price": price, "family": "unrestricted-exact-DAG/common-ingestion/v1"})
        require(policy == expected_policy and policy not in policies, "distinct pinned static policy per arm/regime")
        policies.add(policy)
        initial = [entry for entry in campaign["lifecycle"] if entry.get("event") == "initial-launch"]
        require(len(initial) == 1, "one recorded initial process launch per group")
        ready = [entry["ready"] for entry in initial[0]["roles"]]
        require(len(ready) == 5 and [entry["identity"] for entry in ready] == identities
                and len({entry["pid"] for entry in ready}) == 5, "initial native role process/identity separation")
        authority_ready = initial[0]["authority"]
        require(authority_ready["identity"] == authority_identity and authority_ready["pid"] not in {entry["pid"] for entry in ready}, "authority process separate from native learners")
        for entry in ready + [authority_ready]:
            require(hexdigest(entry["certificate_sha256"]) and hexdigest(entry["instance_nonce"]), "public TLS pin/instance nonce format")
            require(entry["certificate_sha256"] not in certificate_pins, "same paired identity uses separately pinned arm/regime credentials")
            certificate_pins.add(entry["certificate_sha256"])
        if audit is not None:
            authority_purchase_check(campaign, list(cases.values()), identities)
        for bill in campaign["setup_bills"]:
            bill_total(bill, price)
        require(campaign["setup_cost"] == sum(bill_total(bill, price) for bill in campaign["setup_bills"]), "setup/prelude costs never free")
        completed_cases = [case for case in cases.values() if case["status"] == "COMPLETED"]
        task_cost = sum(participant["cost"] for case in completed_cases for participant in case["participants"])
        require(campaign["completed_worlds"] == len(completed_cases) and campaign["completed_task_cost"] == task_cost
                and campaign["completed_whole_system_logical_cost_with_setup"] == task_cost + campaign["setup_cost"],
                "whole-system campaign totals retain all participants and common setup")
        if campaign["final_restart"] is not None:
            expected_profiles = {role: journals[role]["profile_snapshots"].get(worlds[-1]["context"], {}) for role in ACTIVE_ROLES}
            retained[(price, arm)] = validate_restart(campaign["final_restart"], identities, active_by_role, world_map, final_index=len(worlds) - 1,
                                                     expected_profiles=expected_profiles,
                                                     expected_hashes=protected_cutpoint(root, identities, journals, world_map, len(worlds) - 1))
        else:
            require(campaign["failed"] is True, "missing restart evidence is explicit failure")
        mid_index = 11 if full else 0
        mid = [entry for entry in campaign["lifecycle"] if entry.get("after_completed_world") == mid_index]
        if not campaign["failed"]:
            require(len(mid) == 1, "exact fixed planned mid-campaign restart cannot be omitted or selected by outcome")
            validate_restart(mid[0], identities, active_by_role, world_map, final_index=mid_index,
                             expected_profiles={role: journals[role]["profile_snapshots"].get(worlds[mid_index]["context"], {}) for role in ACTIVE_ROLES},
                             expected_hashes=protected_cutpoint(root, identities, journals, world_map, mid_index))
        journal_results[(price, arm)] = journals
    require(len(state_paths) == 49 and len({path.resolve(strict=True) for path in state_paths}) == 49 and len(authority_ids) == 8, "all49private state directories remain distinct")
    require(report["comparisons"] == comparisons(case_rows, len(worlds)), "all participant classes and paired controls recomputed from raw bills/coverage")
    complete = all_complete and not report["failures"] and report["campaign_cap_reached"] is False
    require(report["status"] == ("PASS" if complete else "HOLD"), "native software status agrees with complete failure registry")
    summary = comparisons(case_rows, len(worlds))
    utility = summary["normal_policy_utility"] if complete else "HOLD"
    primary_retained = retained.get((100, ARMS[3]), {})
    primary_profiles = journal_results.get((100, ARMS[3]), {})
    profile_use = {role: primary_profiles[role]["audit"]["profile_changed_score_or_action_after_restart"] > 0
                   for role in (0, 1)} if primary_profiles else {0: False, 1: False}
    native_learning = learning_summary(complete, primary_retained, int(profile_use[0]))
    require(encode(report["learning_gate"], canonical=True) == encode(native_learning, canonical=True),
            "native learning claim requires common retained capability and actual central-A profile effect")
    return dict(schema="symbiote.adaptive-verification/1", mode=report["mode"], integrity="PASS", software_safety="PASS" if complete else "HOLD",
                selection_vs_isolated=utility, better_partner_selection=summary["normal_better_partner_selection"] if complete else "HOLD",
                persistent_learning=native_learning["status"], prospective_primary_prior_profile_use=profile_use,
                world_count=len(worlds), cases=len(case_rows), counterfactual_role_identities=5, private_state_paths=49,
                historical_promotions=historical_count, retained=[dict(price=price,arm=arm,**value) for (price,arm),value in retained.items()], comparisons=summary,
                failures=report["failures"], source_binding="REGISTERED_BINARY_AND_SOURCE" if full else "DEVELOPMENT_ONLY_UNREGISTERED",
                primitive_witness_scope="native counters/registry assertions; no independent packet capture or remote-truth attestation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--registration", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--artifacts", type=Path, help="explicit original artifact root or extracted evidence directory; remaps only the registered original prefix")
    parser.add_argument("--state", type=Path, help="development mode only")
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--allow-development", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = validate_bundle(args.report, registration_path=args.registration, binary=args.binary, artifacts=args.artifacts,
                             state=args.state, source_root=args.source_root, allow_development=args.allow_development)
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["software_safety"] == "PASS" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"schema": "symbiote.adaptive-verification/1", "integrity": "HOLD", "error": str(error)}), file=sys.stderr)
        sys.exit(1)
