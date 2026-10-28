//! Local operator-fixture validation. Remote expected values are never accepted.
use super::wire::Offer;
use super::{digest, Config};
use crate::graph_transfer::{self, Measurement, TaskContract};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use symbiote_memory::knowledge::graph::{
    assess_graph, encode_query, graph_receipt_digest, graph_schema_fingerprint, GraphAcquisition,
    GraphAssessment, GraphTrainingTask, GraphTrialEvidence,
};
use symbiote_memory::knowledge::{
    assess, Assessment, KnowledgePayload, KnowledgeRecord, KnowledgeStore, TrialCase, TrialCosts,
    TrialEvidence,
};
use symbiote_reasoning::planning::{GraphSchema, RouteLearner};

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Family {
    Affine {
        width: u8,
        outputs: Vec<u8>,
    },
    Graph {
        schema: GraphSchema,
        costs: Vec<u16>,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema: String,
    scope: String,
    family: Family,
    #[serde(default)]
    task_contract: Option<TaskContract>,
}

pub(super) enum Evaluation {
    Retained,
    Affine(Box<Assessment>),
    Graph(Box<GraphAssessment>),
}
pub(super) struct Prepared {
    pub record: KnowledgeRecord,
    pub fixture_sha256: String,
    pub evaluation: Evaluation,
    pub cases: usize,
    pub work: usize,
    pub measurement: Option<Measurement>,
    pub evaluation_record: Option<Value>,
}
impl Prepared {
    pub fn response(&self) -> Result<Value, String> {
        let promoted = !matches!(self.evaluation, Evaluation::Retained);
        let mut response = json!({"schema":"symbiote.service-evaluation/1","status":if promoted{"PROMOTED"}else{"ALREADY_RETAINED"},"promoted":promoted,"artifact":self.record.id,"revision":self.record.revision,"record_sha256":self.record.digest()?,"fixture_sha256":self.fixture_sha256,"validated_cases":self.cases,"model_work_units":self.work,"truth_basis":"operator-pinned local finite fixture; no remote truth or generalization claim"});
        if let Some(measurement) = &self.measurement {
            response["graph_measurement"] =
                serde_json::to_value(measurement).map_err(|e| e.to_string())?;
        }
        if let Some(record) = &self.evaluation_record {
            response["evaluation_record"] = record.clone();
            response["feedback_baseline"] = json!({"kind":"unknown","reason":"a local isolated task control was measured, but incoming wire and process replay are unavailable as a complete matched per-artifact cost"});
            response["feedback_costs"] = record["candidate_local_costs"].clone();
        }
        Ok(response)
    }
    pub fn commit(self, knowledge: &mut KnowledgeStore) -> Result<Value, String> {
        let receipt = self.response()?;
        match self.evaluation {
            Evaluation::Retained => {}
            Evaluation::Affine(assessment) => knowledge.promote(self.record, *assessment)?,
            Evaluation::Graph(assessment) => knowledge.promote_graph(self.record, *assessment)?,
        }
        Ok(receipt)
    }
}
pub(super) fn local_id(peer: &str, scope: &str, schema: &str) -> Result<String, String> {
    Ok(format!(
        "service-{}",
        &digest(&json!({"peer":peer,"scope":scope,"schema":schema}))?[..32]
    ))
}
pub(super) fn prepare(
    config: &Config,
    knowledge: &KnowledgeStore,
    peer: &str,
    offer: &Offer,
) -> Result<Prepared, String> {
    let _evaluation_timer = super::timing::Timer::start(super::timing::Stage::Evaluation);
    let context = config.context(&offer.record.scope)?;
    let bytes = config.fixture(context)?;
    let fixture: Fixture =
        serde_json::from_slice(&bytes).map_err(|_| "local truth fixture rejected")?;
    if fixture.scope != offer.record.scope
        || !matches!(
            (fixture.schema.as_str(), fixture.task_contract.is_some()),
            ("symbiote.local-truth/1", false) | ("symbiote.local-truth/2", true)
        )
    {
        return Err("local truth fixture context/version mismatch".into());
    }
    let fixture_sha256 = context
        .truth_sha256
        .clone()
        .ok_or("context lacks local truth pin")?;
    let id = local_id(peer, &offer.record.scope, &offer.record.schema_fingerprint)?;
    let active = knowledge
        .active()
        .into_iter()
        .find(|record| record.id == id);
    let existing_same = active
        .as_ref()
        .is_some_and(|record| record.payload == offer.record.payload);
    let mut record=KnowledgeRecord {
        id:id.clone(),revision:knowledge.highest_revision(&id).unwrap_or(0).checked_add(1).ok_or("local knowledge revision exhausted")?,
        source:peer.into(),scope:offer.record.scope.clone(),schema_fingerprint:offer.record.schema_fingerprint.clone(),payload:offer.record.payload.clone(),
        provenance:format!("Authenticated sender {peer}; original inert record {} revision {} SHA256 {}; claimed source {} is preserved as untrusted provenance. Locally checked against fixture SHA256 {fixture_sha256}.",offer.record.id,offer.record.revision,offer.record.digest()?,offer.record.source),
    };
    record
        .validate()
        .map_err(|_| "local derived record rejected")?;
    let evaluator = format!("local-fixture/{}", &fixture_sha256[..24]);
    let training: BTreeSet<u16> = offer.training_inputs.iter().copied().collect();
    if let Some(contract) = fixture.task_contract {
        let (KnowledgePayload::GraphMap(map), Family::Graph { schema, costs }) =
            (record.typed_payload()?, fixture.family)
        else {
            return Err("local truth version 2 requires a partial graph task contract".into());
        };
        if map.schema != schema || graph_schema_fingerprint(&schema)? != record.schema_fingerprint {
            return Err("partial graph differs from the pinned operator topology".into());
        }
        return partial(
            config,
            knowledge,
            record,
            active,
            existing_same,
            map,
            costs,
            contract,
            training,
            fixture_sha256,
            evaluator,
        );
    }
    match (record.typed_payload()?, fixture.family) {
        (
            KnowledgePayload::Affine { width, .. },
            Family::Affine {
                width: fixture_width,
                outputs,
            },
        ) => {
            if width != fixture_width
                || outputs.len() != 1 << width
                || outputs.iter().any(|output| *output > 1)
                || training
                    .iter()
                    .any(|input| usize::from(*input) >= outputs.len())
            {
                return Err(
                    "local affine fixture must cover the exact complete declared input domain"
                        .into(),
                );
            }
            let work = outputs.len();
            if work > config.limits.model_work {
                return Err("local evaluation work budget exhausted".into());
            }
            for (input, output) in outputs.iter().enumerate() {
                if record.predict(input as u16)? != *output {
                    return Err(
                        "candidate contradicts the operator's local affine truth fixture".into(),
                    );
                }
            }
            if existing_same {
                record = active.ok_or("retained record unavailable")?;
                return Ok(Prepared {
                    record,
                    fixture_sha256,
                    evaluation: Evaluation::Retained,
                    cases: outputs.len(),
                    work,
                    measurement: None,
                    evaluation_record: None,
                });
            }
            let cases: Result<Vec<_>, String> = outputs
                .iter()
                .enumerate()
                .filter(|(input, _)| !training.contains(&(*input as u16)))
                .map(|(input, expected)| {
                    Ok(TrialCase {
                        id: format!("fixture-case-{input}"),
                        input: input as u16,
                        expected: *expected,
                        baseline: active
                            .as_ref()
                            .map(|previous| previous.predict(input as u16))
                            .transpose()?,
                        candidate: record.predict(input as u16)?,
                    })
                })
                .collect();
            let evidence = TrialEvidence {
                evaluator,
                training_case_ids: offer
                    .training_inputs
                    .iter()
                    .map(|input| format!("declared-training-{input}"))
                    .collect(),
                training_inputs: offer.training_inputs.clone(),
                cases: cases?,
                costs: costs(work),
            };
            let assessment = assess(&record, &evidence)
                .map_err(|_| "candidate failed native affine coverage/regression assessment")?;
            Ok(Prepared {
                record,
                fixture_sha256,
                cases: evidence.cases.len(),
                work,
                measurement: None,
                evaluation_record: None,
                evaluation: Evaluation::Affine(Box::new(assessment)),
            })
        }
        (
            KnowledgePayload::GraphMap(map),
            Family::Graph {
                schema,
                costs: edge_costs,
            },
        ) => {
            if schema != map.schema
                || graph_schema_fingerprint(&schema)? != record.schema_fingerprint
                || edge_costs.len() != schema.edges.len()
                || edge_costs
                    .iter()
                    .zip(&schema.edges)
                    .any(|(cost, edge)| *cost < edge.lower || *cost > edge.upper)
                || map
                    .observations
                    .iter()
                    .any(|observation| edge_costs[observation.edge_id] != observation.cost)
            {
                return Err("candidate graph observations contradict the operator's complete local graph fixture".into());
            }
            let tasks = schema.nodes * (schema.nodes - 1);
            let work = tasks * 2048 + map.observations.len();
            if work > config.limits.model_work {
                return Err("local graph evaluation work budget exhausted".into());
            }
            let mut truth = RouteLearner::new(schema.clone(), config.limits.model_work)?;
            for (edge, cost) in edge_costs.iter().enumerate() {
                truth.observe(edge, *cost)?;
            }
            let mut training_tasks = Vec::new();
            for input in &offer.training_inputs {
                super::validate_graph_query(&map, *input)?;
                training_tasks.push(GraphTrainingTask {
                    id: format!("declared-route-{input}"),
                    input: *input,
                });
            }
            let mut cases = Vec::new();
            for from in 0..schema.nodes {
                for to in 0..schema.nodes {
                    if from == to {
                        continue;
                    }
                    let input = encode_query(schema.nodes, from, to)?;
                    if training.contains(&input) {
                        continue;
                    }
                    if let Some(candidate) = map.predict(input)? {
                        let route = truth
                            .assess(from, to)?
                            .certified
                            .ok_or("local graph fixture lacks the candidate's reachable route")?;
                        if route.cost != u64::from(candidate) {
                            return Err(
                                "candidate graph route differs from complete local truth".into()
                            );
                        }
                        cases.push(TrialCase {
                            id: format!("fixture-route-{input}"),
                            input,
                            expected: candidate,
                            baseline: active
                                .as_ref()
                                .map(|previous| previous.predict_if_certified(input))
                                .transpose()?
                                .flatten(),
                            candidate,
                        });
                    }
                }
            }
            if existing_same {
                record = active.ok_or("retained record unavailable")?;
                return Ok(Prepared {
                    record,
                    fixture_sha256,
                    evaluation: Evaluation::Retained,
                    cases: cases.len(),
                    work,
                    measurement: None,
                    evaluation_record: None,
                });
            }
            let acquisitions=map.observations.iter().enumerate().map(|(sequence,observation)|{
                let id=digest(&json!({"fixture":fixture_sha256,"context":record.scope,"edge":observation.edge_id,"cost":observation.cost}))?;
                let receipt=json!({"schema":"symbiote.graph-observation/1","authority_id":evaluator,"context":record.scope,"schema_fingerprint":record.schema_fingerprint,"observer_identity":config.identity,"sequence":sequence as u64,"id":id,"edge_id":observation.edge_id,"cost":observation.cost});
                Ok(GraphAcquisition{id,edge_id:observation.edge_id,cost:observation.cost,receipt_sha256:graph_receipt_digest(&receipt)?,receipt})
            }).collect::<Result<Vec<_>,String>>()?;
            let evidence = GraphTrialEvidence {
                evaluator,
                acquisitions,
                training_tasks,
                cases,
                costs: costs(work),
            };
            let assessment = assess_graph(&record, &evidence)
                .map_err(|_| "candidate failed native graph coverage/regression assessment")?;
            Ok(Prepared {
                record,
                fixture_sha256,
                cases: evidence.cases.len(),
                work,
                measurement: None,
                evaluation_record: None,
                evaluation: Evaluation::Graph(Box::new(assessment)),
            })
        }
        _ => Err("candidate family differs from the operator's local truth fixture".into()),
    }
}

/// Only an operator-pinned v2 contract may authorize an uncertain-value inert
/// experiment. No remote artifact, positive score or grant can create this opt-in.
pub(super) fn experiment_contract(
    config: &Config,
    record: &KnowledgeRecord,
) -> Result<Option<(TaskContract, String)>, String> {
    let context = config.context(&record.scope)?;
    let bytes = config.fixture(context)?;
    let fixture: Fixture =
        serde_json::from_slice(&bytes).map_err(|_| "local experiment fixture rejected")?;
    if fixture.schema == "symbiote.local-truth/1" || fixture.schema == "symbiote.local-truth/3" {
        return Ok(None);
    }
    let Some(contract) = fixture.task_contract else {
        return Err("partial experiment lacks operator task contract".into());
    };
    let (KnowledgePayload::GraphMap(map), Family::Graph { schema, .. }) =
        (record.typed_payload()?, fixture.family)
    else {
        return Err("partial experiment requires graph knowledge".into());
    };
    contract.validate(&schema)?;
    if fixture.schema != "symbiote.local-truth/2"
        || fixture.scope != record.scope
        || schema != map.schema
    {
        return Err("partial experiment context or topology mismatch".into());
    }
    Ok(contract
        .experiment_authorized
        .then(|| (contract, context.truth_sha256.clone().unwrap_or_default())))
}
/// Public task metadata only. In particular this never exposes the provider's
/// private edge weights or received artifact contents.
pub(super) fn public_task_contract(config: &Config, scope: &str) -> Result<Option<Value>, String> {
    let context = config.context(scope)?;
    if context.truth_fixture.is_none() {
        return Ok(None);
    }
    let fixture: Fixture = serde_json::from_slice(&config.fixture(context)?)
        .map_err(|_| "public task fixture rejected")?;
    if fixture.schema != "symbiote.local-truth/2" {
        return Ok(None);
    }
    let Family::Graph { schema, .. } = fixture.family else {
        return Err("public graph task requires graph provider".into());
    };
    let contract = fixture
        .task_contract
        .ok_or("public graph task lacks operator contract")?;
    contract.validate(&schema)?;
    Ok(Some(
        json!({"schema":"symbiote.public-task-contract/1","scope":scope,"schema_fingerprint":context.schema_fingerprint,
        "fixture_sha256":context.truth_sha256,"heldout_inputs":contract.heldout_inputs}),
    ))
}

pub(super) fn partial_model_quote(
    config: &Config,
    record: &KnowledgeRecord,
) -> Result<Option<usize>, String> {
    let context = config.context(&record.scope)?;
    let fixture: Fixture = serde_json::from_slice(&config.fixture(context)?)
        .map_err(|_| "local model quote fixture rejected")?;
    if fixture.schema != "symbiote.local-truth/2" {
        return Ok(None);
    }
    let contract = fixture
        .task_contract
        .ok_or("partial model quote lacks task contract")?;
    let KnowledgePayload::GraphMap(map) = record.typed_payload()? else {
        return Err("partial model quote requires graph".into());
    };
    contract.validate(&map.schema)?;
    // Eight complete exact replay/assessment passes, each including both
    // optimistic and observed-witness searches, plus observation/provider work.
    let forecast = map.observations.len() + 2 * map.schema.nodes * map.schema.edges.len();
    Ok(Some(
        8 * forecast * contract.heldout_inputs.len()
            + map.schema.edges.len()
            + map.observations.len(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn partial(
    config: &Config,
    _knowledge: &KnowledgeStore,
    mut record: KnowledgeRecord,
    active: Option<KnowledgeRecord>,
    existing_same: bool,
    map: symbiote_memory::knowledge::graph::GraphMap,
    costs: Vec<u16>,
    contract: TaskContract,
    mut training: BTreeSet<u16>,
    fixture_sha256: String,
    evaluator: String,
) -> Result<Prepared, String> {
    let _compute_timer = super::timing::Timer::start(super::timing::Stage::Compute);
    contract.validate(&map.schema)?;
    training.extend(&contract.training_inputs);
    if contract
        .heldout_inputs
        .iter()
        .any(|input| training.contains(input))
    {
        return Err("partial graph held-out task overlaps declared source training".into());
    }
    let measurement =
        graph_transfer::verify_partial(&map, costs.clone(), &contract, config.limits.model_work)?;
    // This is a genuine separate arm with a private oracle and learner. Its
    // work is retained and counted as control execution, never supplied to the
    // candidate model or silently omitted from the process execution meter.
    let isolated = graph_transfer::isolated_target_control(
        &map.schema,
        costs,
        &contract,
        config.limits.model_work,
    )?;
    let baseline_units = isolated.units(contract.oracle_price)?;
    let evaluation_record = json!({"schema":"symbiote.scoped-evaluation/1","oracle_price":contract.oracle_price,
        "measured_task_baseline":{"units":baseline_units,"evidence_sha256":digest(&serde_json::to_value(&isolated).map_err(|e|e.to_string())?)?,"measurement":isolated,
            "scope":"isolated exact held-out route certificate; no network, adoption or replay fees measured by this arm"},
        "candidate_local_costs":{"unit_model":"bounded-graph-task-local/1","acquisition":0,"validation":measurement.units(contract.oracle_price)?,"adoption":if existing_same{0}else{1},"prediction":0,"wire":0,"replay":0},
        "candidate_measurement":measurement,"unavailable_cost_components":["incoming_wire","whole_process_replay","post-intent_commit_validation"],
        "candidate_zero_fee_fields":"legacy integer placeholders for excluded/unavailable components, not measurements of zero",
        "comparison":"full matched total-cost outcome remains unknown","control_execution_in_candidate_process_meter":true,
        "legacy_trial_container":{"baseline":0,"status":"deprecated noncomparative placeholder; not a measured zero-cost baseline"}});
    if existing_same {
        record = active.ok_or("retained graph record unavailable")?;
        let work = measurement.model_work
            + measurement.provider_checks
            + measurement.lookups.len() as u64
            + isolated.model_work
            + isolated.provider_checks
            + isolated.lookups.len() as u64;
        return Ok(Prepared {
            record,
            fixture_sha256,
            evaluation: Evaluation::Retained,
            cases: measurement.predictions.len(),
            work: work as usize,
            measurement: Some(measurement),
            evaluation_record: Some(evaluation_record),
        });
    }
    let forecast_before = symbiote_memory::knowledge::graph::forecast_work_units()?;
    let cases = measurement
        .predictions
        .iter()
        .map(|(input, prediction)| {
            Ok(TrialCase {
                id: format!("partial-heldout-{input}"),
                input: *input,
                expected: u8::try_from(*prediction)
                    .map_err(|_| "partial route cost out of range")?,
                baseline: active
                    .as_ref()
                    .map(|previous| previous.predict_if_certified(*input))
                    .transpose()?
                    .flatten(),
                candidate: u8::try_from(*prediction)
                    .map_err(|_| "partial route cost out of range")?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let acquisitions=map.observations.iter().enumerate().map(|(sequence,observation)|{
        let id=digest(&json!({"fixture":fixture_sha256,"context":record.scope,"edge":observation.edge_id,"cost":observation.cost}))?;
        let receipt=json!({"schema":"symbiote.graph-observation/1","authority_id":evaluator,"context":record.scope,"schema_fingerprint":record.schema_fingerprint,"observer_identity":config.identity,"sequence":sequence as u64,"id":id,"edge_id":observation.edge_id,"cost":observation.cost});
        Ok(GraphAcquisition{id,edge_id:observation.edge_id,cost:observation.cost,receipt_sha256:graph_receipt_digest(&receipt)?,receipt})
    }).collect::<Result<Vec<_>,String>>()?;
    // No fabricated counterfactual cost is stored as benefit. Actual task-cost
    // controls and full process/transport costs live in the separate experiment.
    let verification = measurement.units(contract.oracle_price)?;
    let evidence = GraphTrialEvidence {
        evaluator,
        acquisitions,
        training_tasks: training
            .into_iter()
            .map(|input| GraphTrainingTask {
                id: format!("partial-training-{input}"),
                input,
            })
            .collect(),
        cases,
        costs: TrialCosts {
            acquisition: 0,
            verification,
            adoption: 1,
            baseline: 0,
            candidate: verification + 1,
        },
    };
    let assessment = assess_graph(&record, &evidence)?;
    let work = measurement.model_work
        + measurement.provider_checks
        + measurement.lookups.len() as u64
        + isolated.model_work
        + isolated.provider_checks
        + isolated.lookups.len() as u64
        + symbiote_memory::knowledge::graph::forecast_work_units()?
        - forecast_before;
    if work > config.limits.model_work as u64 {
        return Err("partial graph local work budget exhausted".into());
    }
    Ok(Prepared {
        record,
        fixture_sha256,
        cases: evidence.cases.len(),
        work: work as usize,
        evaluation: Evaluation::Graph(Box::new(assessment)),
        measurement: Some(measurement),
        evaluation_record: Some(evaluation_record),
    })
}
fn costs(work: usize) -> TrialCosts {
    TrialCosts {
        acquisition: 0,
        verification: work as u64,
        adoption: 1,
        baseline: 0,
        candidate: work as u64 + 1,
    }
}
