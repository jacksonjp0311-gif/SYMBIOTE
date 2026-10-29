//! Bounded partial-map validation and separately metered engineering controls.
//! Oracle values never enter a learner except through `lookup`. A transferred
//! edge remains a hypothesis until its receiver performs that lookup itself.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::BTreeSet;
use symbiote_memory::knowledge::graph::{decode_query, encode_query, GraphMap, GraphObservation};
use symbiote_reasoning::planning::{Edge, GraphSchema, RouteLearner};

pub const TASK_SCHEMA: &str = "symbiote.partial-graph-task/1";
pub const PROTOCOL: &str = "SYMBIOTE-RECIPROCAL-ENGINEERING-001";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskContract {
    pub schema: String,
    pub training_inputs: Vec<u16>,
    pub heldout_inputs: Vec<u16>,
    pub oracle_price: u64,
    pub experiment_authorized: bool,
    /// Lifetime offers per context, counted from durable pre-send intents.
    pub max_experimental_offers: usize,
}
impl TaskContract {
    pub fn validate(&self, schema: &GraphSchema) -> Result<(), String> {
        schema.validate()?;
        let training: BTreeSet<_> = self.training_inputs.iter().collect();
        let heldout: BTreeSet<_> = self.heldout_inputs.iter().collect();
        if self.schema != TASK_SCHEMA
            || self.training_inputs.len() > 56
            || !(1..=56).contains(&self.heldout_inputs.len())
            || training.len() != self.training_inputs.len()
            || heldout.len() != self.heldout_inputs.len()
            || !training.is_disjoint(&heldout)
            || ![1, 100_000].contains(&self.oracle_price)
            || self.max_experimental_offers > 8
            || (self.experiment_authorized && self.max_experimental_offers == 0)
        {
            return Err(
                "partial graph task contract violates its finite authorization/domain".into(),
            );
        }
        for input in self.training_inputs.iter().chain(&self.heldout_inputs) {
            decode_query(schema.nodes, *input)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lookup {
    pub provider_sha256: String,
    pub sequence: usize,
    pub edge_id: usize,
    pub cost: u16,
}
#[derive(Clone, Default, Debug, Serialize)]
pub struct ExecutionMeter {
    pub lookups: Vec<Lookup>,
    pub provider_checks: u64,
    pub direct_model_work: u64,
}
thread_local! { static EXECUTION: RefCell<ExecutionMeter> = RefCell::new(ExecutionMeter::default()); }
pub fn execution_snapshot() -> ExecutionMeter {
    EXECUTION.with(|meter| meter.borrow().clone())
}
pub fn execution_receipt(before: &ExecutionMeter, forecast_before: u64) -> Result<Value, String> {
    let after = execution_snapshot();
    let provider_checks = after
        .provider_checks
        .checked_sub(before.provider_checks)
        .ok_or("graph provider meter moved backwards")?;
    let model_work = after
        .direct_model_work
        .checked_sub(before.direct_model_work)
        .ok_or("graph model meter moved backwards")?;
    let forecast_work = symbiote_memory::knowledge::graph::forecast_work_units()?
        .checked_sub(forecast_before)
        .ok_or("graph forecast meter moved backwards")?;
    Ok(
        json!({"schema":"symbiote.graph-execution/1","lookups":after.lookups.get(before.lookups.len()..).ok_or("graph execution trace moved backwards")?,
        "provider_checks":provider_checks,"direct_model_work":model_work,
        "graph_forecast_work":forecast_work,
        "basis":"actual oracle calls and exact learner work; process replay included; hardware and TLS framing separate"}),
    )
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Measurement {
    pub lookups: Vec<Lookup>,
    pub model_work: u64,
    pub provider_checks: u64,
    pub predictions: Vec<(u16, u64)>,
    pub complete: bool,
}
impl Measurement {
    /// Task cost only. Wire, adoption, source discovery and audit execution are
    /// recorded separately and must be added by the experiment consumer.
    pub fn units(&self, price: u64) -> Result<u64, String> {
        (self.lookups.len() as u64)
            .checked_mul(price)
            .and_then(|v| v.checked_add(self.model_work))
            .and_then(|v| v.checked_add(self.provider_checks))
            .ok_or_else(|| "partial graph task cost overflow".into())
    }
}

/// The provider's complete private fixture; no values/slice accessors exist.
pub struct MeteredOracle {
    costs: Vec<u16>,
    trace: Vec<Lookup>,
    provider_checks: u64,
    provider_sha256: String,
}
impl MeteredOracle {
    pub fn new(schema: &GraphSchema, costs: Vec<u16>) -> Result<Self, String> {
        schema.validate()?;
        if costs.len() != schema.edges.len()
            || costs
                .iter()
                .zip(&schema.edges)
                .any(|(cost, edge)| *cost < edge.lower || *cost > edge.upper)
        {
            return Err(
                "private graph provider does not satisfy its declared interval family".into(),
            );
        }
        let provider_sha256 = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&json!({"schema":schema,"costs":costs}))
                    .map_err(|e| e.to_string())?
            )
        );
        EXECUTION.with(|meter| meter.borrow_mut().provider_checks += costs.len() as u64);
        Ok(Self {
            provider_checks: costs.len() as u64,
            costs,
            trace: Vec::new(),
            provider_sha256,
        })
    }
    pub fn lookup(&mut self, edge_id: usize) -> Result<u16, String> {
        // Admit the operation before reading private truth. A refused lookup
        // cannot silently read a value omitted from the execution trace.
        EXECUTION.with(|meter| {
            if meter.borrow().lookups.len() >= 32768 {
                Err("graph oracle execution trace budget exhausted")
            } else {
                Ok(())
            }
        })?;
        let cost = *self
            .costs
            .get(edge_id)
            .ok_or("oracle edge outside declared topology")?;
        let lookup = Lookup {
            provider_sha256: self.provider_sha256.clone(),
            sequence: self.trace.len(),
            edge_id,
            cost,
        };
        EXECUTION.with(|meter| -> Result<(), String> {
            let mut meter = meter.borrow_mut();
            meter.lookups.push(lookup.clone());
            Ok(())
        })?;
        self.trace.push(lookup);
        Ok(cost)
    }
    fn measurement(self, work: usize, predictions: Vec<(u16, u64)>, complete: bool) -> Measurement {
        Measurement {
            lookups: self.trace,
            model_work: work as u64,
            provider_checks: self.provider_checks,
            predictions,
            complete,
        }
    }
}

/// Checks only claimed observations, then asks the unchanged exact learner to
/// certify held-out routes under *all* remaining interval completions.
pub fn verify_partial(
    map: &GraphMap,
    costs: Vec<u16>,
    contract: &TaskContract,
    work_budget: usize,
) -> Result<Measurement, String> {
    map.validate()?;
    contract.validate(&map.schema)?;
    let mut oracle = MeteredOracle::new(&map.schema, costs)?;
    let mut learner = RouteLearner::new(map.schema.clone(), work_budget)?;
    let result = (|| {
        for observation in &map.observations {
            if oracle.lookup(observation.edge_id)? != observation.cost {
                return Err(
                    "partial graph observation contradicts independent local oracle lookup".into(),
                );
            }
            learner.observe(observation.edge_id, observation.cost)?;
        }
        let mut predictions = Vec::new();
        for input in &contract.heldout_inputs {
            let (from, to) = decode_query(map.schema.nodes, *input)?;
            let route = learner
                .assess(from, to)?
                .certified
                .ok_or("partial graph has no exact held-out route certificate")?;
            predictions.push((*input, route.cost));
        }
        Ok(predictions)
    })();
    EXECUTION.with(|meter| meter.borrow_mut().direct_model_work += learner.model_work() as u64);
    result.map(|predictions| oracle.measurement(learner.model_work(), predictions, true))
}

/// A real independent isolated arm. Its oracle and model are private to this
/// call; neither observations nor an inferred map are returned to the receiver.
/// The trace is experiment evidence, not an alternate path to trusted knowledge.
pub fn isolated_target_control(
    schema: &GraphSchema,
    costs: Vec<u16>,
    contract: &TaskContract,
    work_budget: usize,
) -> Result<Measurement, String> {
    contract.validate(schema)?;
    let mut oracle = MeteredOracle::new(schema, costs)?;
    let mut learner = RouteLearner::new(schema.clone(), work_budget)?;
    let result = (|| {
        let mut predictions = Vec::new();
        for input in &contract.heldout_inputs {
            let (from, to) = decode_query(schema.nodes, *input)?;
            loop {
                let result = learner.assess(from, to)?;
                if let Some(route) = result.certified {
                    predictions.push((*input, route.cost));
                    break;
                }
                let edge = result
                    .next_observation
                    .ok_or("isolated control exhausted its exact reasoning allowance")?;
                let cost = oracle.lookup(edge)?;
                learner.observe(edge, cost)?;
            }
        }
        Ok(predictions)
    })();
    EXECUTION.with(|meter| meter.borrow_mut().direct_model_work += learner.model_work() as u64);
    result.map(|predictions| oracle.measurement(learner.model_work(), predictions, true))
}

/// A private generated engineering world. Serialization is only for configuring
/// its trusted provider; controls cannot obtain an unmetered cost slice.
pub struct ParallelWorld {
    pub schema: GraphSchema,
    costs: Vec<u16>,
    pub contract: TaskContract,
    pub branches: Vec<usize>,
}
impl ParallelWorld {
    /// `labels` is frozen independently of truth. The registered cohort uses
    /// `[1,2,3,4]` and `[3,1,4,2]`; smaller worlds are labelled smoke fixtures.
    pub fn new(cheap: usize, labels: Vec<usize>, price: u64) -> Result<Self, String> {
        let count = labels.len();
        if !(2..=4).contains(&count)
            || cheap >= count
            || labels.iter().copied().collect::<BTreeSet<_>>() != (1..=count).collect()
        {
            return Err("parallel graph generator needs a bounded branch permutation".into());
        }
        let goal = count + 1;
        let relay = count + 2;
        let mut edges = Vec::new();
        let mut costs = Vec::new();
        for (index, branch) in labels.iter().enumerate() {
            edges.push(Edge {
                from: 0,
                to: *branch,
                lower: 1,
                upper: 9,
            });
            edges.push(Edge {
                from: *branch,
                to: goal,
                lower: 1,
                upper: 9,
            });
            costs.extend([if index == cheap { 1 } else { 9 }, 1]);
        }
        edges.push(Edge {
            from: goal,
            to: relay,
            lower: 1,
            upper: 9,
        });
        costs.push(1);
        let schema = GraphSchema {
            nodes: count + 3,
            edges,
        };
        let contract = TaskContract {
            schema: TASK_SCHEMA.into(),
            training_inputs: vec![
                encode_query(schema.nodes, 0, goal)?,
                encode_query(schema.nodes, goal, relay)?,
            ],
            heldout_inputs: vec![encode_query(schema.nodes, 0, relay)?],
            oracle_price: price,
            experiment_authorized: true,
            max_experimental_offers: 1,
        };
        contract.validate(&schema)?;
        Ok(Self {
            schema,
            costs,
            contract,
            branches: labels,
        })
    }
    pub fn fixture(&self, scope: &str) -> Value {
        json!({"schema":"symbiote.local-truth/2","scope":scope,
            "family":{"kind":"graph","schema":self.schema,"costs":self.costs},"task_contract":self.contract})
    }
    /// Independent greedy discovery includes every expensive discarded edge in
    /// its trace/cost. The transmitted map compresses only certified route facts.
    pub fn discover(&self) -> Result<(GraphMap, Measurement), String> {
        let (observations, trace) = self.solve(&self.contract.training_inputs, None, None, None)?;
        let mut learner = RouteLearner::new(self.schema.clone(), 100_000)?;
        for item in &observations {
            learner.observe(item.edge_id, item.cost)?;
        }
        let mut useful = BTreeSet::new();
        for input in &self.contract.training_inputs {
            let (from, to) = decode_query(self.schema.nodes, *input)?;
            useful.extend(
                learner
                    .assess(from, to)?
                    .certified
                    .ok_or("source training certificate missing")?
                    .edges,
            );
        }
        let map = GraphMap::new(
            self.schema.clone(),
            observations
                .into_iter()
                .filter(|o| useful.contains(&o.edge_id))
                .collect(),
        )?;
        let mut trace = trace;
        trace.model_work += learner.model_work() as u64;
        EXECUTION.with(|meter| meter.borrow_mut().direct_model_work += learner.model_work() as u64);
        Ok((map, trace))
    }
    pub fn control(
        &self,
        order: Option<&[usize]>,
        budget: Option<u64>,
    ) -> Result<Measurement, String> {
        self.solve(&self.contract.heldout_inputs, order, budget, None)
            .map(|(_, trace)| trace)
    }
    pub fn control_queries(&self, queries: usize) -> Result<Measurement, String> {
        self.solve(&self.contract.heldout_inputs, None, None, Some(queries))
            .map(|(_, trace)| trace)
    }
    fn solve(
        &self,
        tasks: &[u16],
        order: Option<&[usize]>,
        budget: Option<u64>,
        query_limit: Option<usize>,
    ) -> Result<(Vec<GraphObservation>, Measurement), String> {
        if let Some(order) = order {
            if order.iter().copied().collect::<BTreeSet<_>>()
                != self.branches.iter().copied().collect()
                || order.len() != self.branches.len()
            {
                return Err("fixed branch order is not a permutation".into());
            }
        }
        let mut oracle = MeteredOracle::new(&self.schema, self.costs.clone())?;
        let mut learner = RouteLearner::new(
            self.schema.clone(),
            budget.unwrap_or(100_000).min(usize::MAX as u64) as usize,
        )?;
        let mut observations = Vec::new();
        let mut predictions = Vec::new();
        for input in tasks {
            let (from, to) = decode_query(self.schema.nodes, *input)?;
            loop {
                if let Some(limit) = budget {
                    let spent = (oracle.trace.len() as u64) * self.contract.oracle_price
                        + oracle.provider_checks;
                    let remaining = limit.saturating_sub(spent).min(100_000) as usize;
                    if remaining < learner.model_work() {
                        return Err("control exceeded admitted task resource budget".into());
                    }
                    learner.restrict_work_budget(remaining)?;
                }
                let result = learner.assess(from, to)?;
                if result.status == "budget_exhausted" {
                    EXECUTION.with(|meter| {
                        meter.borrow_mut().direct_model_work += learner.model_work() as u64
                    });
                    return Ok((
                        observations,
                        oracle.measurement(learner.model_work(), predictions, false),
                    ));
                }
                if let Some(route) = result.certified {
                    predictions.push((*input, route.cost));
                    break;
                }
                let mut edge = result
                    .next_observation
                    .ok_or("isolated route has no next observation")?;
                if let Some(order) = order {
                    if from == 0 {
                        let observed = |id: usize| {
                            learner
                                .observations()
                                .iter()
                                .find(|(edge, _)| *edge == id)
                                .map(|(_, cost)| *cost)
                        };
                        let mut best = None;
                        for branch in order {
                            let ids: Vec<_> = self
                                .schema
                                .edges
                                .iter()
                                .enumerate()
                                .filter(|(_, e)| {
                                    (e.from == 0 && e.to == *branch) || (e.from == *branch)
                                })
                                .map(|(i, _)| i)
                                .collect();
                            let lower: u64 = ids
                                .iter()
                                .map(|id| {
                                    u64::from(observed(*id).unwrap_or(self.schema.edges[*id].lower))
                                })
                                .sum();
                            if best.as_ref().is_none_or(|(cost, _)| lower < *cost) {
                                best = Some((lower, ids));
                            }
                        }
                        if let Some((_, ids)) = best {
                            if let Some(id) = ids.into_iter().find(|id| observed(*id).is_none()) {
                                edge = id;
                            }
                        }
                    }
                }
                // Admission includes the next query, the already performed exact
                // reasoning and provider initialization. No unmetered extra sample.
                let projected = (oracle.trace.len() as u64 + 1)
                    .checked_mul(self.contract.oracle_price)
                    .and_then(|v| {
                        v.checked_add(learner.model_work() as u64 + oracle.provider_checks + 1)
                    })
                    .ok_or("control resource estimate overflow")?;
                if budget.is_some_and(|limit| projected > limit)
                    || query_limit.is_some_and(|limit| oracle.trace.len() >= limit)
                {
                    EXECUTION.with(|meter| {
                        meter.borrow_mut().direct_model_work += learner.model_work() as u64
                    });
                    return Ok((
                        observations,
                        oracle.measurement(learner.model_work(), predictions, false),
                    ));
                }
                let cost = oracle.lookup(edge)?;
                learner.observe(edge, cost)?;
                observations.push(GraphObservation {
                    edge_id: edge,
                    cost,
                });
            }
        }
        EXECUTION.with(|meter| meter.borrow_mut().direct_model_work += learner.model_work() as u64);
        Ok((
            observations,
            oracle.measurement(learner.model_work(), predictions, true),
        ))
    }
}

pub fn branch_orders(labels: &[usize]) -> Vec<Vec<usize>> {
    fn permute(prefix: &mut Vec<usize>, remaining: Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if remaining.is_empty() {
            out.push(prefix.clone());
        }
        for i in 0..remaining.len() {
            let mut next = remaining.clone();
            let item = next.remove(i);
            prefix.push(item);
            permute(prefix, next, out);
            prefix.pop();
        }
    }
    let mut out = Vec::new();
    permute(&mut Vec::new(), labels.to_vec(), &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn smoke_partial_map_verification_preserves_unknown_intervals_and_wrong_cost_rejects() {
        let world = ParallelWorld::new(1, vec![1, 2], 100_000).unwrap();
        let (map, source) = world.discover().unwrap();
        assert!(source.lookups.len() > map.observations.len());
        assert_eq!(map.observations.len(), 3);
        let measured = verify_partial(&map, world.costs.clone(), &world.contract, 100_000).unwrap();
        assert_eq!(measured.lookups.len(), 3);
        assert_eq!(measured.predictions[0].1, 3);
        assert!(map.observations.len() < map.schema.edges.len());
        let mut wrong = map;
        wrong.observations[0].cost = 2;
        assert!(verify_partial(&wrong, world.costs, &world.contract, 100_000).is_err());
    }
    #[test]
    fn smoke_controls_are_private_and_budget_exhaustion_is_an_abstention() {
        let world = ParallelWorld::new(1, vec![1, 2], 100_000).unwrap();
        let greedy = world.control(None, None).unwrap();
        assert_eq!(greedy.lookups.len(), 4);
        let limited = world.control(None, Some(3 * 100_000 + 500)).unwrap();
        assert!(!limited.complete);
        assert_eq!(limited.lookups.len(), 3);
        for order in branch_orders(&world.branches) {
            assert!(world.control(Some(&order), None).unwrap().complete);
        }
        assert_eq!(world.control(None, None).unwrap().lookups, greedy.lookups);
    }
    #[test]
    fn isolated_task_baseline_has_its_own_real_oracle_and_exact_control_trace() {
        let world = ParallelWorld::new(1, vec![1, 2], 100000).unwrap();
        let baseline =
            isolated_target_control(&world.schema, world.costs.clone(), &world.contract, 100000)
                .unwrap();
        let independent = world.control(None, None).unwrap();
        assert_eq!(baseline.lookups, independent.lookups);
        assert_eq!(baseline.model_work, independent.model_work);
        assert_eq!(baseline.provider_checks, independent.provider_checks);
        assert_eq!(
            baseline.units(100000).unwrap(),
            baseline.lookups.len() as u64 * 100000 + baseline.model_work + baseline.provider_checks
        );
        assert_eq!(baseline.predictions[0].1, 3);
    }
    #[test]
    fn backwards_public_meter_snapshot_is_an_error() {
        let mut snapshot = execution_snapshot();
        snapshot.provider_checks = u64::MAX;
        assert!(execution_receipt(&snapshot, 0).is_err());
        assert!(execution_receipt(&execution_snapshot(), u64::MAX).is_err());
    }
}
