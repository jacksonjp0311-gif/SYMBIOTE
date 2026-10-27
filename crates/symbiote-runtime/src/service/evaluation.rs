//! Local operator-fixture validation. Remote expected values are never accepted.
use super::wire::Offer;
use super::{digest, Config};
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
}
impl Prepared {
    pub fn response(&self) -> Result<Value, String> {
        let promoted = !matches!(self.evaluation, Evaluation::Retained);
        Ok(
            json!({"schema":"symbiote.service-evaluation/1","status":if promoted{"PROMOTED"}else{"ALREADY_RETAINED"},"promoted":promoted,"artifact":self.record.id,"revision":self.record.revision,"record_sha256":self.record.digest()?,"fixture_sha256":self.fixture_sha256,"validated_cases":self.cases,"model_work_units":self.work,"truth_basis":"operator-pinned local finite fixture; no remote truth or generalization claim"}),
        )
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
    let context = config.context(&offer.record.scope)?;
    let bytes = config.fixture(context)?;
    let fixture: Fixture =
        serde_json::from_slice(&bytes).map_err(|_| "local truth fixture rejected")?;
    if fixture.schema != "symbiote.local-truth/1" || fixture.scope != offer.record.scope {
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
                evaluation: Evaluation::Graph(Box::new(assessment)),
            })
        }
        _ => Err("candidate family differs from the operator's local truth fixture".into()),
    }
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
