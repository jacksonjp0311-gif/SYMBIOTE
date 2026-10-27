"""Independent checker tests use manual/released fixtures, never the24world cohort."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("adaptive_verifier", ROOT / "tools/verify_adaptive.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def manual_world():
    return dict(index=0, nodes=4, seed=17, seed_index=0, counter=0,
                context="frontier-context-" + "a" * 64,
                schema=dict(nodes=4, edges=[dict(zip(("from", "to", "lower", "upper"), values))
                                          for values in ((0, 1, 1, 3), (1, 3, 1, 3), (0, 2, 1, 3), (2, 3, 1, 3))]),
                costs=[1, 1, 3, 3])


def witness(world=None, owner="symbiote-" + "1" * 24, edge=0):
    world = world or manual_world()
    body = dict(schema="symbiote.graph-observation/1", authority_id="b" * 64,
                context=world["context"], schema_fingerprint=gate.schema_fingerprint(world["schema"]),
                observer_identity=owner, sequence=1000000000 + edge, edge_id=edge, cost=world["costs"][edge])
    return dict(body, id=gate.digest(body))


def case(arm, cost=100, correct=3, world=0, price=100):
    return dict(status="COMPLETED", world=world, price=price, arm=arm,
                participants=[dict(role=role, utility_evaluable=True, cost=cost, heldout_correct=correct,
                                   heldout_total=3, incorrect_certificates=0) for role in gate.ACTIVE_ROLES])


def empty_restart():
    identities = ["symbiote-" + f"{index:024x}" for index in range(1, 6)]
    before, after, stopped = [], [], []
    for role, identity in enumerate(identities):
        ready = dict(identity=identity, pid=100 + role, instance_nonce=f"{role + 1:064x}", certificate_sha256=f"{role + 10:064x}")
        before.append(ready)
        after.append(dict(ready, pid=200 + role, instance_nonce=f"{role + 20:064x}"))
        stopped.append(dict(ready=ready, successful_shutdown=True,
                            summary=dict(identity=identity, pid=ready["pid"], instance_nonce=ready["instance_nonce"], connections=0, application_requests=0)))
    pages = [dict(role=role, pages=[dict(identity=identities[role], models=[], profiles={})]) for role in gate.ACTIVE_ROLES]
    counts = dict(participants=[dict(role=role, validated_models=0, certified_offline_predictions=0, learning_gate="NOT_DEMONSTRATED") for role in gate.ACTIVE_ROLES],
                  A_B1_common_validated_contexts=0, bilateral_learning_gate="NOT_DEMONSTRATED")
    proof = dict(after_completed_world=0, identity_and_profile_bytes_preserved=True, retained_predictions_preserved=False,
                 roles_before=before, roles_after=after, roles_stopped=stopped, before=pages, after=copy.deepcopy(pages),
                 oracle_before={}, oracle_after={}, learning=counts)
    return identities, proof


def native_admission_snapshot():
    """Use production macro fields/descriptions, without starting a native run."""
    source = (ROOT / "crates/symbiote-runtime/src/adaptive_research/admission.rs").read_text(encoding="utf-8")
    macro = next(line for line in source.splitlines() if 'json!({"schema":"symbiote.parent-session-admission/1"' in line)
    quoted = r'"(?:[^"\\]|\\.)*"'
    native_strings = {json.loads(key): json.loads(value) for key, value in re.findall(r'(' + quoted + r')\s*:\s*(' + quoted + r')', macro)}
    native_numbers = {key: int(value) for key, value in re.findall(r'"([a-z_]+)"\s*:\s*([0-9]+)\s*[,}]', macro)}
    snapshot = dict(admission_calls=2, admitted=2, cancelled=0, deadline_rejected=0, wait_cap_rejected=0,
                    poisoned_rejected=0, clock_range_rejected=0, wait_nanoseconds=50000001, wait_ms=50,
                    max_wait_nanoseconds=50000001, max_wait_ms=50)
    snapshot.update(native_strings)
    snapshot.update(native_numbers)
    native_fields = {json.loads(key) for key in re.findall(r'(' + quoted + r')\s*:', macro)}
    if native_fields != set(snapshot):
        raise RuntimeError("Native admission schema changed; update the independent actual-schema fixture explicitly")
    return snapshot


class AdaptiveVerifierTests(unittest.TestCase):
    def test_full_application_billing_includes_failed_purchase_and_verification_fees(self):
        bill = dict.fromkeys(gate.BILL_FIELDS, 0)
        bill.update(observation_purchase_attempts=2, acquisitions=1, rpc_requests=3, sessions=3,
                    rpc_sent_bytes=1024, negotiation_sent_bytes=1, rpc_received_bytes=1025,
                    negotiation_received_bytes=1024, receipt_verification_attempts=2,
                    verified_receipts=1, received_attempts=2, adopted_edges=1, route_queries=1, model_work=5, exported_bytes=1025)
        #200 purchases +3RPC+6session+2sentKiB+3receivedKiB+4verification+1adopt+1query+5work+2export
        self.assertEqual(gate.bill_total(bill, 100, 4), 227)
        self.assertEqual(gate.bill_total(bill, 1, 4), 29)
        altered = copy.deepcopy(bill)
        del altered["observation_purchase_attempts"]
        with self.assertRaises(RuntimeError):
            gate.bill_total(altered, 100, 4)
        altered = copy.deepcopy(bill)
        altered["sessions"] = True
        with self.assertRaises(RuntimeError):
            gate.bill_total(altered, 100, 4)
        altered = copy.deepcopy(bill)
        altered["observation_purchase_attempts"] = 5
        with self.assertRaises(RuntimeError):
            gate.bill_total(altered, 100, 4)

    def test_receipt_body_context_epoch_source_and_actual_weight_are_bound(self):
        world = manual_world()
        original = witness(world)
        self.assertEqual(gate.receipt_check(original, world, {original["observer_identity"]}, "b" * 64), 0)
        for field, value in (("context", "wrong-context"), ("authority_id", "c" * 64),
                             ("observer_identity", "cross-arm-source"), ("schema_fingerprint", "0" * 64), ("cost", 2)):
            changed = copy.deepcopy(original)
            changed[field] = value
            # Even a rehashed body cannot change the declared truth/applicability.
            changed["id"] = gate.digest({key: item for key, item in changed.items() if key != "id"})
            with self.assertRaises(RuntimeError, msg=field):
                gate.receipt_check(changed, world, {original["observer_identity"]}, "b" * 64)

    def test_equal_cost_is_not_enough_without_observed_path_and_global_lower_bound(self):
        world = manual_world()
        route = dict(nodes=[0, 1, 3], edges=[0, 1], cost=2, cost_basis="observed_edge_costs",
                     family="finite-positive-cost-directed-graph/v1", conditional=True)
        self.assertTrue(gate.route_check(world["schema"], world["costs"], {0: 1, 1: 1}, 3, route))
        changed = copy.deepcopy(route)
        changed["nodes"] = [0, 2, 3]
        with self.assertRaises(RuntimeError):
            gate.route_check(world["schema"], world["costs"], {0: 1, 1: 1}, 3, changed)
        with self.assertRaises(RuntimeError):
            gate.route_check(world["schema"], world["costs"], {0: 1}, 3, route)
        # A genuine best path at actualcost4 cannot be certified while an
        # unobserved alternative still has lower-bound2.
        world["costs"] = [2, 2, 3, 3]
        changed = copy.deepcopy(route)
        changed["cost"] = 4
        with self.assertRaises(RuntimeError):
            gate.route_check(world["schema"], world["costs"], {0: 2, 1: 2}, 3, changed)

    def test_paired_utility_never_hides_harmed_partner_or_uses_ambiguous_zero(self):
        rows = [case(arm) for arm in gate.ARMS]
        candidate = rows[3]
        candidate["participants"][0]["cost"] = 10
        candidate["participants"][1]["cost"] = 150
        report = gate.comparisons(rows, 1)
        normal = report["regimes"][0]["prospective_vs_controls"][0]
        self.assertEqual(normal["A_B1_candidate_cost"], 160)
        self.assertEqual(normal["bilateral_benefit_worlds"], 0)
        self.assertEqual(report["normal_policy_utility"], "NOT_DEMONSTRATED")
        candidate["participants"][1]["utility_evaluable"] = False
        normal = gate.comparisons(rows, 1)["regimes"][0]["prospective_vs_controls"][0]
        self.assertEqual(normal["worlds_evaluable"], 0)
        self.assertEqual(normal["paired_worlds"][0]["participants"][1]["class"], "NOT_EVALUABLE")
        self.assertEqual(normal["A_B1_candidate_cost"], 0)  #excluded totals, never an evaluated0cost sample

    def test_software_completion_and_broad_selection_are_separate(self):
        rows = [case("isolated", 100), case("fixed-peer", 90), case("uniform-authorized", 100), case("prospective-frontier", 95)]
        result = gate.comparisons(rows, 1)
        self.assertEqual(result["normal_policy_utility"], "DEMONSTRATED")
        self.assertEqual(result["normal_better_partner_selection"], "NOT_DEMONSTRATED")
        result = gate.comparisons(rows[:3], 1)
        self.assertEqual(result["normal_policy_utility"], "NOT_DEMONSTRATED")
        self.assertEqual(result["regimes"][0]["prospective_vs_controls"][0]["worlds_evaluable"], 0)

    def test_old_frozen_receipt_hashes_remain_readable_without_reserializing_fields(self):
        raw, rows, owner = gate.chain(ROOT / "experiments/v0.2/symbiote-knowledge.jsonl", "knowledge")
        self.assertGreater(len(rows), 1)
        self.assertTrue(owner.startswith("symbiote-"))
        with tempfile.TemporaryDirectory(prefix="symbiote-verifier-chain-test-") as temp:
            path = Path(temp) / "knowledge.jsonl"
            changed = copy.deepcopy(rows)
            changed[-1]["previous"] = "0" * 64
            path.write_bytes(b"".join(gate.encode(row) + b"\n" for row in changed))
            with self.assertRaises(RuntimeError):
                gate.chain(path, "knowledge")
            path.write_bytes(raw[:-1])
            with self.assertRaises(RuntimeError):
                gate.chain(path, "knowledge")

    def test_operational_chain_canonicalizes_values_and_rejects_tampering(self):
        owner = "symbiote-" + "1" * 24
        payload = dict(event="genesis", version=1, owner_identity=owner, service_id=owner, policy_digest="d" * 64)
        row = dict(sequence=0, previous="0" * 64, payload=payload)
        row["sha256"] = gate.digest([0, row["previous"], payload])
        with tempfile.TemporaryDirectory(prefix="symbiote-verifier-ops-test-") as temp:
            path = Path(temp) / "operations.jsonl"
            path.write_bytes(gate.encode(row, canonical=True) + b"\n")
            self.assertEqual(gate.chain(path, "operations", owner)[2], owner)
            row["payload"]["policy_digest"] = "e" * 64
            path.write_bytes(gate.encode(row) + b"\n")
            with self.assertRaises(RuntimeError):
                gate.chain(path, "operations", owner)

    def test_explicit_portable_prefix_remap_never_reads_outside_bundle(self):
        with tempfile.TemporaryDirectory(prefix="symbiote-verifier-remap-") as temp:
            root = Path(temp).resolve(strict=True)
            (root / "state").mkdir()
            bundle = gate.Bundle(root, r"C:\original\registered")
            self.assertEqual(bundle.remap(r"\\?\C:\original\registered\state"), root / "state")
            with self.assertRaises(RuntimeError):
                bundle.remap(r"C:\original\other-study\state")
            with self.assertRaises(RuntimeError):
                bundle.remap(r"C:\original\registered\..\private")

    def test_complete_case_order_is_fixed_and_does_not_create_environment_labels(self):
        order = gate.expected_case_order(3)
        self.assertEqual(len(order), 24)
        self.assertEqual(order[:4], [(100, 0, arm) for arm in gate.ARMS])
        self.assertEqual(order[4:8], [(100, 1, gate.ARMS[(1 + offset) % 4]) for offset in range(4)])
        self.assertEqual(order[12][0], 1)

    def test_strict_json_and_optimized_python_cannot_bypass_a_failed_gate(self):
        for raw in ('{"x":1,"x":2}', '{"x":NaN}'):
            with self.assertRaises(RuntimeError):
                gate.loads(raw)
        script = ("import importlib.util;s=importlib.util.spec_from_file_location('gate'," + repr(str(ROOT / "tools/verify_adaptive.py"))
                  + ");m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.require(False,'tamper-negative-control')")
        result = subprocess.run([sys.executable, "-O", "-c", script], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tamper-negative-control", result.stderr)
        tree = ast.parse((ROOT / "tools/verify_adaptive.py").read_text(encoding="utf-8"))
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))

    def test_empty_restart_is_valid_persistence_but_never_demonstrated_learning(self):
        identities, proof = empty_restart()
        world = manual_world()
        records = dict.fromkeys(gate.ACTIVE_ROLES, {})
        result = gate.validate_restart(proof, identities, records, {world["context"]: world}, final_index=0)
        self.assertFalse(result["demonstrated"])
        self.assertEqual(result["A_B1_common_validated_contexts"], 0)
        for change in ("claim", "same-instance", "probe"):
            altered = copy.deepcopy(proof)
            if change == "claim":
                altered["retained_predictions_preserved"] = True
            elif change == "same-instance":
                altered["roles_after"][0]["instance_nonce"] = altered["roles_before"][0]["instance_nonce"]
            else:
                altered["roles_stopped"][3]["summary"]["connections"] = 1
            with self.assertRaises(RuntimeError, msg=change):
                gate.validate_restart(altered, identities, records, {world["context"]: world}, final_index=0)

    def test_shared_context_learning_requires_correct_nonempty_offline_predictions(self):
        identities, proof = empty_restart()
        world = manual_world()
        records = {role: {} for role in gate.ACTIVE_ROLES}
        route = dict(nodes=[0, 2], edges=[2], cost=3, cost_basis="observed_edge_costs", family="finite-positive-cost-directed-graph/v1", conditional=True)
        for role in (0, 1):
            record = dict(id="manual-validated", revision=1, source=identities[role], scope=world["context"],
                          schema_fingerprint=gate.schema_fingerprint(world["schema"]),
                          payload=dict(kind="graph-map", schema=world["schema"], observations=[dict(edge_id=index, cost=cost) for index, cost in enumerate(world["costs"])]),
                          provenance="manual development test")
            records[role][record["id"]] = record
            model = dict(id=record["id"], scope=world["context"], record_digest=gate.record_digest(record), routes=[dict(input=2, route=route)])
            position = gate.ACTIVE_ROLES.index(role)
            proof["before"][position]["pages"][0]["models"] = [model]
            proof["after"][position]["pages"][0]["models"] = copy.deepcopy([model])
            proof["learning"]["participants"][position].update(validated_models=1, certified_offline_predictions=1, learning_gate="DEMONSTRATED")
        proof["learning"].update(A_B1_common_validated_contexts=1, bilateral_learning_gate="DEMONSTRATED")
        proof["retained_predictions_preserved"] = True
        result = gate.validate_restart(proof, identities, records, {world["context"]: world}, final_index=0)
        self.assertEqual(result["A_B1_common_validated_contexts"], 1)
        altered = copy.deepcopy(proof)
        altered["after"][0]["pages"][0]["models"][0]["routes"][0]["route"]["cost"] = 1
        altered["before"] = copy.deepcopy(altered["after"])
        with self.assertRaises(RuntimeError):
            gate.validate_restart(altered, identities, records, {world["context"]: world}, final_index=0)

    def test_judge_verdict_binds_route_request_not_just_a_positive_boolean(self):
        world = manual_world()
        route = dict(nodes=[0, 1, 3], edges=[0, 1], cost=2, cost_basis="observed_edge_costs", family="finite-positive-cost-directed-graph/v1", conditional=True)
        claims = [dict(input=3, route=route)]
        receipt = dict(schema="symbiote.authority-judge/1", authority_id="b" * 64, context=world["context"],
                       request_sha256=gate.digest(dict(context=world["context"], routes=claims)),
                       results=[dict(input=3, certified=True, correct=True, abstained=False)])
        receipt["receipt_sha256"] = gate.digest(receipt)
        participant = dict(main_status="complete", main_route=route, forecasts=[], judge_receipts=[receipt])
        gate.judge_receipts_check(participant, world, "b" * 64)
        for field, value in (("authority_id", "c" * 64), ("request_sha256", "0" * 64)):
            altered = copy.deepcopy(participant)
            altered["judge_receipts"][0][field] = value
            body = {key: item for key, item in altered["judge_receipts"][0].items() if key != "receipt_sha256"}
            altered["judge_receipts"][0]["receipt_sha256"] = gate.digest(body)
            with self.assertRaises(RuntimeError):
                gate.judge_receipts_check(altered, world, "b" * 64)

    def test_primary_source_binary_protocol_and_registration_bytes_are_bound(self):
        with tempfile.TemporaryDirectory(prefix="symbiote-primary-binding-manual-") as temp:
            binary = Path(temp) / "manual-binary"
            binary.write_bytes(b"manual development bytes; never executed")
            registration = dict(schema="symbiote.primary-registration/1", protocol_id=gate.PROTOCOL_ID,
                                protocol_sha256=gate.PROTOCOL_SHA256, base_release_commit=gate.BASE_COMMIT,
                                candidate_source_commit="a" * 40, candidate_binary_sha256=gate.file_sha(binary),
                                run_id="manual-test", runner=dict(toolchain="manual"))
            report = dict(registration_sha256="e" * 64, source_commit="a" * 40, run_id="manual-test")
            gate.registration_check(report, registration, binary, "e" * 64)
            for field in ("candidate_source_commit", "candidate_binary_sha256", "protocol_sha256"):
                altered = copy.deepcopy(registration)
                altered[field] = "0" * len(altered[field])
                with self.assertRaises(RuntimeError, msg=field):
                    gate.registration_check(report, altered, binary, "e" * 64)
            with self.assertRaises(RuntimeError):
                gate.registration_check(report, registration, binary, "f" * 64)

    def test_oracle_calls_reconcile_exactly_with_purchase_fees_including_setup(self):
        identities = [f"manual-owner-{role}" for role in gate.ROLES]
        setup = [dict.fromkeys(gate.BILL_FIELDS, 0) for _ in gate.ROLES]
        setup[4].update(observation_purchase_attempts=1, acquisitions=1)
        participants = []
        for role in gate.ROLES:
            bill = dict.fromkeys(gate.BILL_FIELDS, 0)
            if role != 3:
                bill.update(observation_purchase_attempts=2, acquisitions=2, receipt_verification_attempts=1)
            participants.append(dict(bill=bill, utility_evaluable=True))
        rows = [dict(status="COMPLETED", participants=participants)]
        counters = {identities[role]: dict(requests=3, observe=2 + int(role == 4), verify=1, assess=0, invalid=0)
                    for role in gate.ACTIVE_ROLES}
        campaign = dict(setup_bills=setup, authority_audit=dict(per_actor=counters))
        gate.authority_purchase_check(campaign, rows, identities)
        for metric in ("observe", "verify"):
            tampered = copy.deepcopy(campaign)
            tampered["authority_audit"]["per_actor"][identities[0]][metric] += 1
            with self.assertRaises(RuntimeError, msg=metric):
                gate.authority_purchase_check(tampered, rows, identities)
        # A lost source reply remains separately unevaluable; an accepted
        # observation diagnostic cannot silently replace the attempt fee.
        ambiguous = copy.deepcopy(rows)
        ambiguous[0]["participants"][0]["utility_evaluable"] = False
        ambiguous[0]["participants"][0]["bill"]["observation_purchase_attempts"] += 1
        gate.authority_purchase_check(campaign, ambiguous, identities)

    def test_rejected_state_witness_cannot_be_rehashed_to_hide_changed_model(self):
        world = manual_world()
        state = dict(schema=world["schema"], algorithm="dijkstra", observations={"0": 1}, native_work=13)
        attempt = dict(context=world["context"], selected_peer="manual-peer", frontier_edge=1,
                       details=dict(choice=dict(reason="request-verified-frontier-offer"), before_model_sha256=gate.digest(state)))
        decision = dict(context=world["context"], selected_peer="manual-peer", frontier_edge=1,
                        details=dict(operation="rejected-state-witness", attempt_decision_id="manual-attempt",
                                     before_state=state, after_state=copy.deepcopy(state), before_sha256=gate.digest(state),
                                     after_sha256=gate.digest(state), unchanged=True))
        gate.rejected_state_check(decision, attempt, world)
        changed = copy.deepcopy(decision)
        changed["details"]["after_state"]["observations"]["1"] = 1
        changed["details"]["after_sha256"] = gate.digest(changed["details"]["after_state"])
        with self.assertRaises(RuntimeError):
            gate.rejected_state_check(changed, attempt, world)
        changed["details"]["before_state"] = copy.deepcopy(changed["details"]["after_state"])
        changed["details"]["before_sha256"] = changed["details"]["after_sha256"]
        with self.assertRaises(RuntimeError):
            gate.rejected_state_check(changed, attempt, world)
        with self.assertRaises(RuntimeError):
            gate.rejected_state_check(decision, None, world)

    def test_actual_profile_effect_and_shared_retained_context_are_both_required(self):
        world = manual_world()
        details = dict(known_edges=[0], assessment_work_bound=16,
                       remaining=dict(acquisitions=1, attempts=1, adopted_edges=1, model_work=1000, requests=3, connections=3, traffic=30720),
                       advertisements=[dict(peer="manual-peer", context=world["context"], schema_fingerprint=gate.schema_fingerprint(world["schema"]),
                                            scope=gate.SCOPE, edge_id=1, offer_id="manual-offer")],
                       choice=dict(quote=dict(receiver_max=31, contributor_max=15, pair_max=46, frame=4096, control_frame=1024)))
        decision = dict(context=world["context"], frontier_edge=1, details=details)
        cold = gate.prospective_choice(decision, {}, set(), {"manual-peer"}, 100)
        prior = {"manual-peer": dict(attempts=1, verified_novel=1, verification_failures=0, applicability_failures=0)}
        warm = gate.prospective_choice(decision, prior, set(), {"manual-peer"}, 100)
        self.assertEqual(cold["reason"], warm["reason"])
        self.assertEqual((cold["probability_numerator"], cold["probability_denominator"]), (1, 2))
        self.assertEqual((warm["probability_numerator"], warm["probability_denominator"]), (2, 3))
        self.assertEqual(gate.learning_summary(True, dict(A_B1_common_validated_contexts=1), 0)["status"], "NOT_DEMONSTRATED")
        self.assertEqual(gate.learning_summary(True, dict(A_B1_common_validated_contexts=0), 1)["status"], "NOT_DEMONSTRATED")
        self.assertEqual(gate.learning_summary(True, dict(A_B1_common_validated_contexts=1), 1)["status"], "DEMONSTRATED")
        self.assertEqual(gate.learning_summary(False, dict(A_B1_common_validated_contexts=1), 1)["status"], "NOT_DEMONSTRATED")

    def test_missing_authority_audit_remains_not_verified_even_with_claimed_epochs(self):
        campaign = dict(price=1, arm="isolated", failed=True, authority_audit=None, final_restart=None)
        group = gate.group_verification(campaign, [dict(status="COMPLETED")], 1)
        self.assertEqual(group["status"], "NOT_VERIFIED")
        self.assertEqual(group["authority"], "NOT_VERIFIED")
        self.assertFalse(group["observations_are_authenticated"])
        self.assertIn("authority-audit-missing", group["reasons"][0])
        with self.assertRaisesRegex(RuntimeError, "authenticity cannot be inferred"):
            gate.knowledge_check(Path("never-read"), "owner", "authority", None, {}, {}, 0)
        # Restoring other evidence cannot silently manufacture the missing audit.
        campaign["final_restart"] = {"claimed_epoch": "a" * 64}
        campaign["failed"] = False
        self.assertEqual(gate.group_verification(campaign, [dict(status="COMPLETED")], 1)["status"], "NOT_VERIFIED")

    def test_engineering_setup_binds_primary_bytes_contexts_and_exact_genesis(self):
        world = manual_world()
        frozen = dict(worlds=[world], truths=[dict(costs={str(key): value for key, value in gate.shortest(world["schema"], world["costs"]).items()}, path_work=10)])
        catalogue = dict(manual_genesis_only="same identities; no learned records")
        campaigns = []
        for index, (price, arm) in enumerate((price, arm) for price in gate.PRICES for arm in gate.ARMS):
            receipt = dict(context="frontier-prelude-" + f"{index + 1:064x}", schema_fingerprint=gate.schema_fingerprint(world["schema"]))
            campaigns.append(dict(price=price, arm=arm, lifecycle=[dict(event="genuine-stale-control-calibration", receipt=receipt)]))
        original = dict(mode="primary", status="HOLD", run_id="manual-original", source_commit="a" * 40,
                        registration_sha256="b" * 64, frozen_environments_sha256=gate.digest(frozen),
                        initial_simulation_genesis_sha256=gate.digest(catalogue), campaigns=campaigns)
        old_registration = dict(candidate_source_commit="a" * 40, candidate_binary_sha256="c" * 64)
        refs = dict(run_id=original["run_id"], registration_sha256="b" * 64, report_sha256="d" * 64,
                    frozen_environments_sha256=gate.digest(frozen), candidate_source_commit="a" * 40, candidate_binary_sha256="c" * 64)
        setup = dict(schema="symbiote.reproduction-setup/1", protocol_id=gate.PROTOCOL_ID, protocol_sha256=gate.PROTOCOL_SHA256,
                     original_primary=refs, genesis_catalogue=catalogue,
                     world_contexts=[dict(index=world["index"], context=world["context"], schema_fingerprint=gate.schema_fingerprint(world["schema"]))],
                     prelude_contexts=gate.prelude_mapping(original))
        binding = dict(setup_sha256="e" * 64, original_primary=refs)
        report = dict(original, mode="engineering-reproduction", source_commit="f" * 40, setup_binding=binding)
        registration = dict(setup_binding=binding)

        def check(proposed_setup=setup, proposed_report=report, proposed_catalogue=catalogue, proposed_frozen=frozen, setup_hash="e" * 64):
            return gate.setup_binding_check(proposed_report, registration, proposed_setup, setup_hash,
                                            original, old_registration, "b" * 64, "d" * 64, "c" * 64,
                                            proposed_catalogue, proposed_frozen, catalogue, frozen)

        result = check()
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["original_primary_status"], "HOLD")
        reordered = copy.deepcopy(setup)
        reordered["prelude_contexts"].reverse()
        self.assertEqual(check(proposed_setup=reordered)["status"], "VERIFIED")
        alterations = []
        altered = copy.deepcopy(setup)
        altered["original_primary"]["candidate_source_commit"] = "0" * 40
        alterations.append(dict(proposed_setup=altered))
        altered = copy.deepcopy(setup)
        altered["world_contexts"][0]["context"] = "frontier-context-" + "0" * 64
        alterations.append(dict(proposed_setup=altered))
        altered = copy.deepcopy(setup)
        altered["prelude_contexts"][0]["context"] = "frontier-prelude-" + "0" * 64
        alterations.append(dict(proposed_setup=altered))
        altered = copy.deepcopy(frozen)
        altered["worlds"][0]["costs"][0] = 2
        alterations.extend([dict(proposed_frozen=altered), dict(proposed_catalogue={"redrawn": "identities"}),
                            dict(setup_hash="0" * 64), dict(proposed_report=dict(report, mode="primary"))])
        for fields in alterations:
            with self.assertRaises(RuntimeError):
                check(**fields)

    def test_parent_admission_reports_actual_elapsed_overhead_without_changing_bill(self):
        snapshot = native_admission_snapshot()
        result = gate.parent_admission_check(snapshot, True)
        self.assertEqual(result["participant_logical_cost_adjustment"], 0)
        for key, value in (("admission_calls", 3), ("admitted", True), ("wait_ms", 49), ("minimum_spacing_ms", 1)):
            altered = dict(snapshot)
            altered[key] = value
            with self.assertRaises(RuntimeError, msg=key):
                gate.parent_admission_check(altered, True)
        # OS descheduling can overshoot the checked cap. Preserve the actual
        # measured wait with an explicit rejection instead of clamping evidence.
        rejected = dict(snapshot, admitted=1, wait_cap_rejected=1, wait_nanoseconds=6000000000,
                        wait_ms=6000, max_wait_nanoseconds=6000000000, max_wait_ms=6000)
        gate.parent_admission_check(rejected, False)
        with self.assertRaises(RuntimeError):
            gate.parent_admission_check(rejected, True)

    def test_full_native_admission_schema_preserves_scope_retry_and_timing_limits(self):
        snapshot = native_admission_snapshot()
        gate.parent_admission_check(snapshot, True)
        for name in ("retry_policy", "scope", "wait_basis", "timing_limit"):
            missing = dict(snapshot)
            del missing[name]
            with self.assertRaises(RuntimeError, msg="missing " + name):
                gate.parent_admission_check(missing, True)
            altered = dict(snapshot)
            altered[name] = "all TCP globally throttled, retried, and wait silently clamped"
            with self.assertRaises(RuntimeError, msg="altered " + name):
                gate.parent_admission_check(altered, True)


if __name__ == "__main__":
    unittest.main()
