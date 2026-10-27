//! Durable, conditional graph knowledge. Receipt envelopes are inert evidence.
//! The native laboratory authority authenticates them before assessment; this
//! module verifies their binding and internal consistency, not remote honesty.
use super::{label, KnowledgePayload, KnowledgeRecord, TrialCase, TrialCosts};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use symbiote_reasoning::planning::{GraphSchema, Route, RouteLearner};

pub const MAX_NODES: usize = 12;
pub const MAX_EDGES: usize = 56;
pub const MAX_EDGE_COST: u16 = 9;
const MAX_RECEIPT_BYTES: usize = 2048;
// At most 56 observation updates and 12 * 56 edge scans for one Dijkstra query.
const PREDICTION_WORK_BUDGET: usize = 1024;
thread_local! {
    static FORECAST_WORK: Cell<Option<u64>> = const { Cell::new(Some(0)) };
}
/// Actual exact-learner work performed by graph forecasts on this thread.
/// Additive diagnostic only; it does not change evidence or certificates.
pub fn forecast_work_units() -> Result<u64, String> {
    FORECAST_WORK.with(|work| {
        work.get()
            .ok_or_else(|| "graph forecast work counter overflow".into())
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphObservation {
    pub edge_id: usize,
    pub cost: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphMap {
    pub schema: GraphSchema,
    pub observations: Vec<GraphObservation>,
}

fn validate_schema(schema: &GraphSchema) -> Result<(), String> {
    schema.validate()?;
    if schema.nodes > MAX_NODES
        || schema.edges.len() > MAX_EDGES
        || schema.edges.iter().any(|edge| edge.upper > MAX_EDGE_COST)
    {
        return Err(
            "durable graph domain is bounded to 2..12 nodes, 56 edges and costs 1..9".into(),
        );
    }
    Ok(())
}

impl GraphMap {
    pub fn new(
        schema: GraphSchema,
        mut observations: Vec<GraphObservation>,
    ) -> Result<Self, String> {
        observations.sort_by_key(|observation| observation.edge_id);
        let map = Self {
            schema,
            observations,
        };
        map.validate()?;
        Ok(map)
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_schema(&self.schema)?;
        if self.observations.len() > self.schema.edges.len() {
            return Err("graph observations exceed the declared topology".into());
        }
        let mut previous = None;
        for observation in &self.observations {
            let edge = self
                .schema
                .edges
                .get(observation.edge_id)
                .ok_or("observed edge outside graph schema")?;
            if previous.is_some_and(|id| id >= observation.edge_id)
                || observation.cost < edge.lower
                || observation.cost > edge.upper
            {
                return Err(
                    "graph observations need unique ordered edges and in-interval costs".into(),
                );
            }
            previous = Some(observation.edge_id);
        }
        Ok(())
    }

    pub(super) fn from_record(record: &KnowledgeRecord) -> Result<Self, String> {
        match record.typed_payload()? {
            KnowledgePayload::GraphMap(map) => {
                map.validate()?;
                Ok(map)
            }
            KnowledgePayload::Affine { .. } => {
                Err("graph evidence requires graph-map knowledge".into())
            }
        }
    }

    pub fn to_payload(&self) -> Result<Value, String> {
        self.validate()?;
        serde_json::to_value(KnowledgePayload::GraphMap(self.clone())).map_err(|e| e.to_string())
    }

    pub fn forecast(&self, input: u16) -> Result<Option<Route>, String> {
        self.validate()?;
        let (start, goal) = decode_query(self.schema.nodes, input)?;
        let mut learner = RouteLearner::new(self.schema.clone(), PREDICTION_WORK_BUDGET)?;
        let result = (|| {
            for observation in &self.observations {
                learner.observe(observation.edge_id, observation.cost)?;
            }
            let result = learner.assess(start, goal)?;
            if result.status != "supported" {
                return Err(format!(
                    "durable graph prediction unavailable: {}",
                    result.status
                ));
            }
            Ok(result.certified)
        })();
        FORECAST_WORK.with(|work| {
            work.set(
                work.get()
                    .and_then(|n| n.checked_add(learner.model_work() as u64)),
            )
        });
        forecast_work_units()?;
        result
    }

    pub fn predict(&self, input: u16) -> Result<Option<u8>, String> {
        self.forecast(input)?
            .map(|route| {
                let cost =
                    u8::try_from(route.cost).map_err(|_| "certified graph cost exceeds u8")?;
                if !(1..=63).contains(&cost) {
                    return Err("certified graph cost outside bounded domain".into());
                }
                Ok(cost)
            })
            .transpose()
    }
}

/// Edge order is part of the schema because observations identify edge indices.
pub fn graph_schema_fingerprint(schema: &GraphSchema) -> Result<String, String> {
    validate_schema(schema)?;
    super::super::digest(&serde_json::json!({
        "kind":"finite-positive-cost-directed-graph", "version":1,
        "query_encoding":"start*nodes+goal", "schema":schema
    }))
}

pub fn encode_query(nodes: usize, start: usize, goal: usize) -> Result<u16, String> {
    if !(2..=MAX_NODES).contains(&nodes) || start >= nodes || goal >= nodes || start == goal {
        return Err("graph query needs distinct nodes in a 2..12 node schema".into());
    }
    u16::try_from(start * nodes + goal).map_err(|_| "graph query encoding overflow".into())
}

pub fn decode_query(nodes: usize, input: u16) -> Result<(usize, usize), String> {
    if !(2..=MAX_NODES).contains(&nodes) {
        return Err("graph query schema needs 2..12 nodes".into());
    }
    let input = usize::from(input);
    let (start, goal) = (input / nodes, input % nodes);
    encode_query(nodes, start, goal)?;
    Ok((start, goal))
}

/// Canonical Value serialization is shared with the native authority, avoiding
/// an accidental mismatch with a separately ordered Rust struct serializer.
pub fn graph_receipt_digest(receipt: &Value) -> Result<String, String> {
    super::super::digest(receipt)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphAcquisition {
    pub id: String,
    pub edge_id: usize,
    pub cost: u16,
    pub receipt_sha256: String,
    /// Complete bounded inert envelope, retained for later authorized exchange.
    /// Its digest is integrity metadata; authentication remains an authority API operation.
    pub receipt: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationEnvelope {
    schema: String,
    authority_id: String,
    context: String,
    schema_fingerprint: String,
    observer_identity: String,
    sequence: u64,
    id: String,
    edge_id: usize,
    cost: u16,
}

fn sha256_label(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl GraphAcquisition {
    fn validate(&self, record: &KnowledgeRecord) -> Result<ObservationEnvelope, String> {
        if !sha256_label(&self.id)
            || !sha256_label(&self.receipt_sha256)
            || serde_json::to_vec(&self.receipt)
                .map_err(|e| e.to_string())?
                .len()
                > MAX_RECEIPT_BYTES
            || self.receipt_sha256 != graph_receipt_digest(&self.receipt)?
        {
            return Err(
                "graph acquisition needs a bounded envelope and matching integrity digest".into(),
            );
        }
        let envelope: ObservationEnvelope =
            serde_json::from_value(self.receipt.clone()).map_err(|e| e.to_string())?;
        if envelope.schema != "symbiote.graph-observation/1"
            || !label(&envelope.authority_id)
            || !label(&envelope.observer_identity)
            || envelope.context != record.scope
            || envelope.schema_fingerprint != record.schema_fingerprint
            || envelope.id != self.id
            || envelope.edge_id != self.edge_id
            || envelope.cost != self.cost
        {
            return Err(
                "graph envelope does not bind its declared context, schema, observation and origin"
                    .into(),
            );
        }
        Ok(envelope)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphTrainingTask {
    pub id: String,
    pub input: u16,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphTrialEvidence {
    pub evaluator: String,
    pub acquisitions: Vec<GraphAcquisition>,
    /// Route tasks that guided acquisition, not numeric edge identifiers.
    pub training_tasks: Vec<GraphTrainingTask>,
    pub cases: Vec<TrialCase>,
    pub costs: TrialCosts,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphAssessment {
    pub heldout_route_queries: usize,
    pub baseline_correct: usize,
    pub candidate_correct: usize,
    pub regressions: usize,
    pub baseline_cost: u64,
    pub candidate_cost: u64,
    pub coverage_improved: bool,
    pub cost_improved: bool,
    pub authority_id: String,
    record_digest: String,
    pub(super) evidence: GraphTrialEvidence,
}

/// This is a consistency/effectiveness gate over trusted laboratory evidence.
/// An authority epoch is pinned across a bundle, never silently reauthenticated.
pub fn assess_graph(
    record: &KnowledgeRecord,
    evidence: &GraphTrialEvidence,
) -> Result<GraphAssessment, String> {
    record.validate()?;
    let map = GraphMap::from_record(record)?;
    if !label(&evidence.evaluator) || evidence.evaluator == record.source {
        return Err("graph assessment needs a distinct identified laboratory evaluator".into());
    }
    if evidence.cases.is_empty()
        || evidence.cases.len() > MAX_EDGES
        || evidence.training_tasks.len() > MAX_EDGES
        || evidence.acquisitions.len() != map.observations.len()
    {
        return Err("graph trial needs bounded route tasks and exact observation evidence".into());
    }
    evidence.costs.validate()?;
    let mut acquisitions = BTreeMap::new();
    let mut ids = BTreeSet::new();
    let mut sequences = BTreeSet::new();
    let mut authority = None;
    for acquisition in &evidence.acquisitions {
        let envelope = acquisition.validate(record)?;
        if !ids.insert(&acquisition.id)
            || acquisitions
                .insert(acquisition.edge_id, acquisition.cost)
                .is_some()
            || !sequences.insert(envelope.sequence)
            || authority
                .as_ref()
                .is_some_and(|previous| previous != &envelope.authority_id)
        {
            return Err(
                "graph acquisitions must be unique and bound to one authority epoch".into(),
            );
        }
        authority = Some(envelope.authority_id);
    }
    let expected_observations: BTreeMap<_, _> = map
        .observations
        .iter()
        .map(|o| (o.edge_id, o.cost))
        .collect();
    if acquisitions != expected_observations {
        return Err("graph map differs from its acquisition evidence".into());
    }
    let authority_id = authority.ok_or("certifiable graph evidence requires observed edges")?;
    let mut training_ids = BTreeSet::new();
    let mut training_inputs = BTreeSet::new();
    for task in &evidence.training_tasks {
        decode_query(map.schema.nodes, task.input)?;
        if !label(&task.id) || !training_ids.insert(&task.id) || !training_inputs.insert(task.input)
        {
            return Err("graph training route tasks must be uniquely identified".into());
        }
    }
    let mut evaluation_ids = BTreeSet::new();
    let mut evaluation_inputs = BTreeSet::new();
    let mut baseline_correct = 0;
    let mut candidate_correct = 0;
    let mut regressions = 0;
    for case in &evidence.cases {
        decode_query(map.schema.nodes, case.input)?;
        if !label(&case.id)
            || !evaluation_ids.insert(&case.id)
            || !evaluation_inputs.insert(case.input)
            || training_ids.contains(&case.id)
            || training_inputs.contains(&case.input)
        {
            return Err("graph evaluation route tasks must be unique and disjoint from training route tasks".into());
        }
        if !(1..=63).contains(&case.expected)
            || !(1..=63).contains(&case.candidate)
            || case
                .baseline
                .is_some_and(|value| !(1..=63).contains(&value))
        {
            return Err(
                "graph trial route costs must be in 1..63; unknown outcomes abstain".into(),
            );
        }
        if map.predict(case.input)? != Some(case.candidate) {
            return Err("graph candidate lacks a matching conservative route certificate".into());
        }
        baseline_correct += usize::from(case.baseline == Some(case.expected));
        candidate_correct += usize::from(case.candidate == case.expected);
        regressions +=
            usize::from(case.baseline == Some(case.expected) && case.candidate != case.expected);
    }
    let coverage_improved = candidate_correct > baseline_correct;
    let cost_improved =
        candidate_correct == baseline_correct && evidence.costs.candidate < evidence.costs.baseline;
    if candidate_correct != evidence.cases.len()
        || regressions != 0
        || !(coverage_improved || cost_improved)
    {
        return Err(
            "graph knowledge must be correct and improve coverage or equal-coverage total cost"
                .into(),
        );
    }
    Ok(GraphAssessment {
        heldout_route_queries: evidence.cases.len(),
        baseline_correct,
        candidate_correct,
        regressions,
        baseline_cost: evidence.costs.baseline,
        candidate_cost: evidence.costs.candidate,
        coverage_improved,
        cost_improved,
        authority_id,
        record_digest: record.digest()?,
        evidence: evidence.clone(),
    })
}

impl GraphAssessment {
    pub(super) fn validate(&self, record: &KnowledgeRecord) -> Result<(), String> {
        let computed = assess_graph(record, &self.evidence)?;
        if super::super::digest(self)? != super::super::digest(&computed)? {
            return Err("graph assessment was modified or is bound to another record".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
