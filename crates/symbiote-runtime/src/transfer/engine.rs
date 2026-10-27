use super::*;
use std::sync::Arc;
use std::time::Instant;
use symbiote_memory::knowledge::{graph::forecast_work_units, KnowledgeStore};
use symbiote_memory::strategy::{StrategyAssessment, StrategyLedger, StrategyRecord};
use symbiote_memory::Store;
use symbiote_reasoning::query_strategy::{EdgeRole, QueryPolicy, TrialResult};

#[derive(Clone, Debug, Default, Serialize)]
struct Bill {
    source_queries: u64,
    calibration_queries: u64,
    calibration_truth_edges: u64,
    target_queries: u64,
    target_truth_edges: u64,
    retention_truth_edges: u64,
    diagnostic_queries: u64,
    diagnostic_truth_edges: u64,
    computation_work: u64,
    replay_work: u64,
    exchange_bytes: u64,
    exchange_units: u64,
    adoption_units: u64,
}
impl Bill {
    fn total(&self, price: u64) -> u64 {
        (self.source_queries
            + self.calibration_queries
            + self.calibration_truth_edges
            + self.target_queries
            + self.target_truth_edges
            + self.retention_truth_edges
            + self.diagnostic_queries
            + self.diagnostic_truth_edges)
            * price
            + self.computation_work
            + self.replay_work
            + self.exchange_units
            + self.adoption_units
    }
    fn assessment(&mut self, a: &StrategyAssessment) {
        self.calibration_queries += a.evaluation_queries() as u64;
        self.calibration_truth_edges += a.verification_truth_edges as u64;
        self.computation_work += a.total_work() as u64;
        self.adoption_units += a.adoption_units as u64;
    }
    fn trial(&mut self, r: &TrialResult, truth_edges: usize, diagnostic: bool) {
        if diagnostic {
            self.diagnostic_queries += r.queried_edges.len() as u64;
            self.diagnostic_truth_edges += truth_edges as u64;
        } else {
            self.target_queries += r.queried_edges.len() as u64;
            self.target_truth_edges += truth_edges as u64;
        }
        self.computation_work += (r.model_work + r.policy_work + r.evaluator_work) as u64;
    }
}
struct Actor {
    directory: PathBuf,
    owner: Arc<Store>,
    ledger: StrategyLedger,
    knowledge: KnowledgeStore,
    retained: Vec<retention::Retained>,
    bill: Bill,
    source_record: Option<StrategyRecord>,
    initial_policy: Option<QueryPolicy>,
    restarts: Vec<Value>,
}
impl Actor {
    fn open(directory: PathBuf) -> Result<Self, String> {
        let owner = Arc::new(Store::open(&directory)?);
        let ledger = StrategyLedger::open(Arc::clone(&owner))?;
        let knowledge = KnowledgeStore::open(&directory, owner.identity())?;
        Ok(Self {
            directory,
            owner,
            ledger,
            knowledge,
            retained: Vec::new(),
            bill: Bill::default(),
            source_record: None,
            initial_policy: None,
            restarts: Vec::new(),
        })
    }
    fn restart(self) -> Result<Self, String> {
        let Self {
            directory,
            owner,
            ledger,
            knowledge,
            retained,
            mut bill,
            source_record,
            initial_policy,
            mut restarts,
        } = self;
        let id = owner.identity().to_owned();
        let head = ledger.head_sha256().to_owned();
        let selected = ledger.selected();
        let knowledge_head = knowledge.history_anchor();
        let knowledge_bytes =
            fs::read(knowledge.ledger_path()).map_err(|_| "cannot snapshot graph knowledge")?;
        let bytes =
            fs::read(ledger.ledger_path()).map_err(|_| "cannot snapshot selected policy")?;
        drop(ledger);
        drop(knowledge);
        drop(owner);
        let owner = Arc::new(Store::open(&directory)?);
        let ledger = StrategyLedger::open(Arc::clone(&owner))?;
        let work_before = forecast_work_units()?;
        let knowledge = KnowledgeStore::open(&directory, owner.identity())?;
        let retained_predictions = retention::replay(&knowledge, &retained)?;
        let graph_replay_work = forecast_work_units()?
            .checked_sub(work_before)
            .ok_or("forecast meter regressed")?;
        if owner.identity() != id
            || ledger.head_sha256() != head
            || ledger.selected() != selected
            || fs::read(ledger.ledger_path()).map_err(|_| "cannot read restarted policy")? != bytes
            || knowledge.history_anchor() != knowledge_head
            || fs::read(knowledge.ledger_path())
                .map_err(|_| "cannot read restarted graph knowledge")?
                != knowledge_bytes
        {
            return Err("actual restart changed owner, selected policy or historical bytes".into());
        }
        bill.replay_work += ledger.replay_work_units() as u64 + graph_replay_work;
        restarts.push(
            json!({"identity":id,"strategy_head":head,"strategy_bytes_sha256":sha(&bytes),
            "selected_policy_sha256":selected.as_ref().map(|r|digest(&r.policy)).transpose()?,
            "actual_store_and_ledger_reopened":true,"replay_work_units":ledger.replay_work_units(),
            "knowledge_bytes_sha256":sha(&knowledge_bytes),"knowledge_anchor":knowledge_head,
            "actual_knowledge_store_reopened":true,"graph_replay_work_units":graph_replay_work,
            "retained_predictions":retained_predictions}),
        );
        Ok(Self {
            directory,
            owner,
            ledger,
            knowledge,
            retained,
            bill,
            source_record,
            initial_policy,
            restarts,
        })
    }
}
fn record(
    source: &str,
    id: &str,
    training: Vec<SourceTrace>,
    bill: &mut Bill,
) -> Result<StrategyRecord, String> {
    let derived = derive_policy(&training, 10_000)?;
    bill.source_queries += training
        .iter()
        .map(|trace| trace.observations.len() as u64)
        .sum::<u64>();
    bill.computation_work += derived.work_units as u64;
    Ok(StrategyRecord{id:id.into(),revision:1,source:source.into(),policy:derived.policy,training,
        provenance:"Inert source-observation-derived prior; receiving controller independently evaluates disjoint calibration. No external-agent authenticity claim.".into()})
}
fn setup(actor: &mut Actor, seed: u64, index: usize, arm: &str) -> Result<(), String> {
    if !["isolated-prior", "local-trained", "exchanged"].contains(&arm) {
        return Ok(());
    }
    let source = actor.owner.identity().to_owned();
    let offer = record(
        &source,
        &format!("{source}-source-policy"),
        fixtures::traces(seed, index, "source-training", index == 0)?,
        &mut actor.bill,
    )?;
    let d = actor.ledger.consider(
        offer.clone(),
        fixtures::calibration(seed, index, "self-calibration", index == 0)?,
    )?;
    actor.bill.assessment(&d.assessment);
    actor.source_record = Some(offer);
    actor.initial_policy = actor.ledger.selected().map(|r| r.policy);
    if arm == "local-trained" {
        let learned = record(
            &source,
            &format!("{source}-local-policy"),
            fixtures::traces(seed, index, "local-training", index != 0)?,
            &mut actor.bill,
        )?;
        let d = actor.ledger.consider(
            learned,
            fixtures::calibration(seed, index, "target-calibration", index != 0)?,
        )?;
        actor.bill.assessment(&d.assessment);
    }
    Ok(())
}
fn policy(actor: &Actor, arm: &str) -> Result<Option<QueryPolicy>, String> {
    match arm {
        "fresh-default" => Ok(None),
        "fixed-start" => QueryPolicy::ranked(vec![EdgeRole::FromStart, EdgeRole::ToGoal]).map(Some),
        "fixed-goal" => QueryPolicy::ranked(vec![EdgeRole::ToGoal, EdgeRole::FromStart]).map(Some),
        _ => Ok(actor.ledger.selected().map(|r| r.policy)),
    }
}
fn budget(deadline: Instant, bill: &Bill, price: u64) -> Result<(), String> {
    if Instant::now() >= deadline {
        return Err("registered transfer controller deadline exceeded".into());
    }
    if bill.total(price) > MAX_ACTOR_COST {
        return Err("registered actor resource budget exhausted".into());
    }
    Ok(())
}
fn diagnostics(actor: &mut Actor, seed: u64, index: usize) -> Result<Value, String> {
    let Some(selected) = actor.ledger.selected() else {
        return Ok(json!({"status":"ABSTAINED_NO_PROMOTED_POLICY"}));
    };
    let before = actor.ledger.head_sha256().to_owned();
    let mut unsupported = selected.clone();
    unsupported.id = format!("unsupported-{index}");
    unsupported.policy.family = "arbitrary-agent/v1".into();
    let error = actor
        .ledger
        .consider(
            unsupported,
            fixtures::calibration(seed, index, "negative-calibration", index != 0)?,
        )
        .err()
        .ok_or("unsupported strategy grammar was accepted")?;
    actor.bill.computation_work += derive_policy(&selected.training, 10_000)?.work_units as u64;
    if actor.ledger.head_sha256() != before {
        return Err("rejected grammar changed strategy memory".into());
    }
    let mut drift = fixtures::task(seed, index, "observed-drift", 0, 3, index != 0, false)?;
    drift.costs.fill(10);
    let observed = run_trial(&drift, Some(&selected.policy), TRIAL)?;
    actor.bill.trial(&observed, drift.schema.edges.len(), true);
    if observed.status != "contradicted" || observed.certified_cost.is_some() {
        return Err("observed drift failed to abstain".into());
    }
    let task = fixtures::task(
        seed,
        index,
        "query-prior-counterexample",
        0,
        3,
        index == 0,
        false,
    )?;
    let baseline = run_trial(&task, None, TRIAL)?;
    let candidate = run_trial(&task, Some(&selected.policy), TRIAL)?;
    actor.bill.trial(&baseline, task.schema.edges.len(), true);
    actor.bill.trial(&candidate, task.schema.edges.len(), true);
    let harmful = candidate.incorrect_certificate
        || (baseline.certified_correctly()
            && (!candidate.certified_correctly()
                || candidate.queried_edges.len() > baseline.queried_edges.len()));
    let revoked = if harmful {
        let edges = task.schema.edges.len();
        let proof = actor
            .ledger
            .revoke_for_counterexample(&selected.id, task.clone())?;
        actor.bill.trial(&proof.baseline, edges, true);
        actor.bill.trial(&proof.candidate, edges, true);
        true
    } else {
        false
    };
    Ok(
        json!({"unsupported_grammar_error":error,"unsupported_memory_unchanged":true,
        "observed_drift_task":drift,"observed_drift":observed,
        "counterexample":{"task":task,"baseline":baseline,"candidate":candidate},
        "revoked_for_observed_regression":revoked,"hidden_family_label_used_for_rejection":false}),
    )
}
fn arm(
    root: &Path,
    seed: u64,
    price: u64,
    name: &str,
    authority: &str,
    deadline: Instant,
) -> Result<Value, String> {
    let mut actors = Vec::new();
    for index in 0..2 {
        let mut actor = Actor::open(root.join(format!("agent-{index}")))?;
        setup(&mut actor, seed, index, name)?;
        budget(deadline, &actor.bill, price)?;
        actors.push(actor);
    }
    let mut exchanges = Vec::new();
    if name == "exchanged" {
        let wires = actors
            .iter()
            .map(|a| {
                serde_json::to_vec(a.source_record.as_ref().ok_or("source offer missing")?)
                    .map_err(|_| "cannot encode strategy offer".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (index, wire) in wires.iter().enumerate() {
            let path = root.join(format!("wire-{index}.json"));
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|e| e.to_string())?;
            use std::io::Write;
            file.write_all(wire)
                .and_then(|_| file.sync_all())
                .map_err(|e| e.to_string())?;
        }
        for index in 0..2 {
            let other = 1 - index;
            let received: StrategyRecord = serde_json::from_slice(&wires[other])
                .map_err(|_| "inert strategy schema rejected")?;
            if received.source != actors[other].owner.identity() {
                return Err("declared source differs from controlled sender identity".into());
            }
            actors[index].bill.exchange_bytes += (wires[index].len() + wires[other].len()) as u64;
            actors[index].bill.exchange_units += 2
                + wires[index].len().div_ceil(1024) as u64
                + wires[other].len().div_ceil(1024) as u64;
            let d = actors[index].ledger.consider(
                received,
                fixtures::calibration(seed, index, "target-calibration", index != 0)?,
            )?;
            actors[index].bill.assessment(&d.assessment);
            exchanges.push(json!({"recipient":actors[index].owner.identity(),"sender":actors[other].owner.identity(),
                "decision":d,"sent_bytes":wires[index].len(),"received_bytes":wires[other].len(),
                "sent_wire_path":root.join(format!("wire-{index}.json")),"sent_wire_sha256":sha(&wires[index]),
                "received_wire_path":root.join(format!("wire-{other}.json")),"received_wire_sha256":sha(&wires[other]),
                "artifact_kind":"candidate-query-prior; promotion is receiver-local"}));
        }
    }
    let mut participants = Vec::new();
    for (index, actor) in actors.into_iter().enumerate() {
        let mut actor = actor.restart()?;
        let selected = policy(&actor, name)?;
        let mut targets = Vec::new();
        for (variant, layers) in Cohort::fixed().target_layers.into_iter().enumerate() {
            budget(deadline, &actor.bill, price)?;
            let task = fixtures::task(
                seed,
                index,
                "final-target",
                variant,
                layers,
                index != 0,
                variant == 1,
            )?;
            let trial = run_trial(&task, selected.as_ref(), TRIAL)?;
            actor.bill.trial(&trial, task.schema.edges.len(), false);
            let witness = symbiote_reasoning::query_strategy::canonical_task(&task, 10_000)?;
            actor.bill.computation_work += witness.refinement_scan_units as u64;
            let kept = retention::retain(
                &mut actor.knowledge,
                actor.owner.identity(),
                authority,
                &task,
                &trial,
                price,
            )?;
            actor.bill.retention_truth_edges += kept.truth_queries;
            actor.bill.computation_work += kept.work;
            actor.bill.adoption_units += 1;
            actor.retained.push(kept.retained);
            targets.push(json!({"task_sha256":digest(&task)?,"schema_sha256":digest(&(&task.schema,task.start,task.goal))?,
                "costs_sha256":digest(&task.costs)?,"canonical_weighted_witness":witness,
                "canonical_weighted_sha256":digest(&witness)?,"task":task,"result":trial,"retention":kept.metadata}));
        }
        actor = actor.restart()?;
        let negative = if name == "exchanged" {
            diagnostics(&mut actor, seed, index)?
        } else {
            Value::Null
        };
        if name == "exchanged" {
            actor = actor.restart()?;
        }
        budget(deadline, &actor.bill, price)?;
        let correct = targets
            .iter()
            .filter(|row| {
                row["result"]["certified_cost"].is_number()
                    && row["result"]["incorrect_certificate"] == false
                    && row["result"]["certified_cost"] == row["result"]["oracle_optimum"]
            })
            .count();
        let incorrect = targets
            .iter()
            .filter(|row| row["result"]["incorrect_certificate"] == true)
            .count();
        participants.push(json!({"role":index,"identity":actor.owner.identity(),"directory":actor.directory,
            "initial_policy":actor.initial_policy,"evaluated_target_policy":selected,"selected_after_diagnostics":actor.ledger.selected(),
            "restarts":actor.restarts,"bill":actor.bill,"total_cost":actor.bill.total(price),
            "certified_correct":correct,"incorrect_certificates":incorrect,"target_count":targets.len(),"targets":targets,
            "negative_controls":negative,"strategy_rows":actor.ledger.record_count(),"strategy_head":actor.ledger.head_sha256(),
            "knowledge_rows":actor.knowledge.record_count(),"knowledge_anchor":actor.knowledge.history_anchor(),
            "retained_models":actor.retained}));
    }
    Ok(
        json!({"seed":seed,"oracle_price":price,"arm":name,"participants":participants,"exchanges":exchanges}),
    )
}
pub(super) fn execute(
    root: &Path,
    cohort: &Cohort,
    authority: &str,
    deadline: Instant,
    rows: &mut Vec<Value>,
) -> Result<(), String> {
    for &price in &cohort.prices {
        for &seed in &cohort.seeds {
            for name in ARMS {
                let directory = root.join(format!("price-{price}/seed-{seed}/{name}"));
                let row = arm(&directory, seed, price, name, authority, deadline)?;
                write_new(&directory.join("receipt.json"), &row)?;
                rows.push(row);
            }
        }
    }
    Ok(())
}
fn number(row: &Value, key: &str) -> Result<u64, String> {
    row[key]
        .as_u64()
        .ok_or_else(|| format!("comparison missing integer {key}"))
}
pub(super) fn inventory(rows: &[Value]) -> Result<Value, String> {
    use std::collections::BTreeMap;
    let mut labelled = BTreeMap::<String, Value>::new();
    let mut groups = BTreeMap::<String, Vec<String>>::new();
    let mut evaluations = 0usize;
    for row in rows {
        for actor in row["participants"]
            .as_array()
            .ok_or("target inventory participants missing")?
        {
            for target in actor["targets"]
                .as_array()
                .ok_or("target inventory rows missing")?
            {
                evaluations += 1;
                let context = target["task"]["context"]
                    .as_str()
                    .ok_or("target context missing")?;
                let entry = json!({"context":context,"task_sha256":target["task_sha256"],
                    "schema_sha256":target["schema_sha256"],"costs_sha256":target["costs_sha256"],
                    "canonical_weighted_sha256":target["canonical_weighted_sha256"],
                    "canonical_weighted_witness":target["canonical_weighted_witness"]});
                if let Some(previous) = labelled.insert(context.into(), entry.clone()) {
                    if previous != entry {
                        return Err("matched target changed across arms or prices".into());
                    }
                }
            }
        }
    }
    for (context, entry) in &labelled {
        let key = entry["canonical_weighted_sha256"]
            .as_str()
            .ok_or("canonical target digest missing")?;
        groups.entry(key.into()).or_default().push(context.clone());
    }
    Ok(
        json!({"target_evaluations":evaluations,"unique_labelled_targets":labelled.len(),
        "canonical_weighted_classes":groups.len(),"labelled_targets":labelled.into_values().collect::<Vec<_>>(),
        "canonical_collision_groups":groups,"independent_statistical_samples_claimed":false,
        "seed_penalty_groups":[{"seeds":[7,19,43],"penalty":5},{"seeds":[101],"penalty":9}],
        "reuse":"same labelled targets reused across6arms and2oracle prices; equal canonical full witnesses prove graph-isomorphic weighted tasks"}),
    )
}
fn complete(row: &Value) -> Result<bool, String> {
    let total = number(row, "target_count")?;
    let correct = number(row, "certified_correct")?;
    let incorrect = number(row, "incorrect_certificates")?;
    Ok(total == Cohort::fixed().target_layers.len() as u64 && correct == total && incorrect == 0)
}
pub(super) fn comparisons(rows: &[Value]) -> Result<Vec<Value>, String> {
    let mut output = Vec::new();
    for price in Cohort::fixed().prices {
        for seed in Cohort::fixed().seeds {
            let find = |name: &str| {
                rows.iter()
                    .find(|row| {
                        row["seed"] == seed && row["oracle_price"] == price && row["arm"] == name
                    })
                    .ok_or("registered comparison arm missing")
            };
            let exchange = find("exchanged")?;
            let mut controls = Vec::new();
            for name in ARMS.iter().filter(|name| **name != "exchanged") {
                let baseline = find(name)?;
                let mut benefits = Vec::new();
                for index in 0..2 {
                    let a = &exchange["participants"][index];
                    let b = &baseline["participants"][index];
                    benefits.push(
                        complete(a)?
                            && complete(b)?
                            && number(a, "certified_correct")? >= number(b, "certified_correct")?
                            && number(a, "incorrect_certificates")?
                                <= number(b, "incorrect_certificates")?
                            && number(a, "total_cost")? < number(b, "total_cost")?,
                    );
                }
                controls.push(json!({"control":name,"participant_benefits":benefits,"bilateral":benefits.iter().all(|b|*b)}));
            }
            let mut best_fixed = Vec::new();
            for index in 0..2 {
                let start = &find("fixed-start")?["participants"][index];
                let goal = &find("fixed-goal")?["participants"][index];
                let fixed_complete = complete(start)? && complete(goal)?;
                let costs = [number(start, "total_cost")?, number(goal, "total_cost")?];
                let candidate = &exchange["participants"][index];
                let candidate_cost = number(candidate, "total_cost")?;
                best_fixed.push(
                    complete(candidate)?
                        && fixed_complete
                        && costs
                            .into_iter()
                            .min()
                            .is_some_and(|best| candidate_cost < best),
                );
            }
            let strong = controls
                .iter()
                .filter(|r| {
                    ["fresh-default", "local-trained"]
                        .contains(&r["control"].as_str().unwrap_or(""))
                })
                .all(|r| r["bilateral"] == true)
                && best_fixed.iter().all(|b| *b);
            output.push(json!({"seed":seed,"oracle_price":price,"controls":controls,
            "best_fixed_hindsight_participant_benefits":best_fixed,"strong_bilateral_utility":strong,
            "hindsight_bound_is_not_a_deployable_selector":true}));
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use symbiote_reasoning::planning::{Edge, GraphSchema};
    use symbiote_reasoning::query_strategy::EdgeObservation;
    #[test]
    fn manual_ten_and_twelve_node_facts_replay_after_policy_revocation_without_oracle() {
        let temp = std::env::temp_dir().join(format!(
            "symbiote-transfer-retention-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&temp).unwrap();
        let mut actor = Actor::open(temp.join("owner")).unwrap();
        let diamond = |context: &str, costs: Vec<u16>| GraphTask {
            context: context.into(),
            schema: GraphSchema {
                nodes: 4,
                edges: [(0, 1), (1, 3), (0, 2), (2, 3)]
                    .into_iter()
                    .map(|(from, to)| Edge {
                        from,
                        to,
                        lower: 1,
                        upper: 9,
                    })
                    .collect(),
            },
            start: 0,
            goal: 3,
            costs,
        };
        let training = ["manual-retention-source-a", "manual-retention-source-b"]
            .into_iter()
            .map(|context| {
                let task = diamond(context, vec![1, 9, 1, 1]);
                SourceTrace {
                    context: context.into(),
                    schema: task.schema,
                    start: 0,
                    goal: 3,
                    observations: vec![
                        EdgeObservation { edge: 0, cost: 1 },
                        EdgeObservation { edge: 1, cost: 9 },
                    ],
                }
            })
            .collect::<Vec<_>>();
        let offer = StrategyRecord {
            id: "manual-retention-policy".into(),
            revision: 1,
            source: actor.owner.identity().into(),
            policy: derive_policy(&training, 1000).unwrap().policy,
            training,
            provenance: "Manual source fixture; no prospective cohort".into(),
        };
        assert!(
            actor
                .ledger
                .consider(
                    offer,
                    vec![
                        diamond("manual-retention-cal-a", vec![1, 9, 1, 1]),
                        diamond("manual-retention-cal-b", vec![1, 9, 1, 1])
                    ]
                )
                .unwrap()
                .promoted
        );
        for nodes in [10, 12] {
            let task = GraphTask {
                context: format!("manual-chain-{nodes}"),
                schema: GraphSchema {
                    nodes,
                    edges: (1..nodes)
                        .map(|to| Edge {
                            from: to - 1,
                            to,
                            lower: 1,
                            upper: 9,
                        })
                        .collect(),
                },
                start: 0,
                goal: nodes - 1,
                costs: vec![1; nodes - 1],
            };
            let trial = run_trial(&task, None, TRIAL).unwrap();
            let kept = retention::retain(
                &mut actor.knowledge,
                actor.owner.identity(),
                "manual-distinct-local-judge",
                &task,
                &trial,
                100,
            )
            .unwrap();
            assert!(kept.work > 0);
            assert_eq!(kept.truth_queries, 2 * (nodes - 1) as u64);
            assert_eq!(kept.metadata["assessment"]["heldout_route_queries"], 2);
            actor.retained.push(kept.retained);
        }
        let bytes = fs::read(actor.knowledge.ledger_path()).unwrap();
        actor = actor.restart().unwrap();
        assert_eq!(
            actor.restarts.last().unwrap()["retained_predictions"]["models"],
            2
        );
        assert_eq!(
            actor.restarts.last().unwrap()["retained_predictions"]["subroute_predictions"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        assert_eq!(
            actor.restarts.last().unwrap()["retained_predictions"]["new_authority_calls"],
            0
        );
        actor
            .ledger
            .revoke_for_counterexample(
                "manual-retention-policy",
                diamond("manual-retention-counterexample", vec![9, 1, 1, 1]),
            )
            .unwrap();
        assert!(actor.ledger.selected().is_none());
        actor = actor.restart().unwrap();
        assert_eq!(fs::read(actor.knowledge.ledger_path()).unwrap(), bytes);
        assert_eq!(
            actor.restarts.last().unwrap()["retained_predictions"]["nonempty"],
            true
        );
        assert!(actor.bill.replay_work > 0);
        drop(actor);
        if temp.canonicalize().unwrap().parent()
            == Some(std::env::temp_dir().canonicalize().unwrap().as_path())
        {
            fs::remove_dir_all(temp).unwrap();
        }
    }
    #[test]
    fn incomplete_or_incorrect_coverage_never_supplies_positive_utility() {
        assert!(!complete(
            &json!({"target_count":0,"certified_correct":0,"incorrect_certificates":0})
        )
        .unwrap());
        assert!(!complete(
            &json!({"target_count":2,"certified_correct":2,"incorrect_certificates":1})
        )
        .unwrap());
        assert!(complete(&json!({"target_count":2,"certified_correct":2})).is_err());
        assert!(complete(
            &json!({"target_count":2,"certified_correct":true,"incorrect_certificates":0})
        )
        .is_err());
        assert!(complete(
            &json!({"target_count":2,"certified_correct":2,"incorrect_certificates":0})
        )
        .unwrap());
    }
}
