//! Portable inert query priorities. A policy only selects an unobserved edge
//! from the exact learner's current optimistic route. It supplies no edge cost,
//! support restriction, certificate, topology, or executable instruction.
//!
//! Scores are exact weighted normalized excess: sum(cost-lower)/sum(upper-lower).
//! A role needs observations in two named source contexts. Ratios are compared
//! by integer cross multiplication; ties use FromStart, Interior, ToGoal, Direct.
//! Missing roles fall back to the original order of the optimistic route.
use crate::planning::{GraphSchema, Route, RouteLearner, GRAPH_FAMILY};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const POLICY_SCHEMA: &str = "symbiote.optimistic-route-query-policy/1";
pub const SELECTION_RULE: &str = "rank-unknown-optimistic-route-roles/v1";
pub const MIN_SOURCE_CONTEXTS: usize = 2;
pub const MAX_SOURCE_CONTEXTS: usize = 32;
pub const MAX_SOURCE_OBSERVATIONS: usize = 4096;
const MAX_WORK: usize = 10_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EdgeRole {
    FromStart,
    Interior,
    ToGoal,
    Direct,
}
impl EdgeRole {
    pub fn of(
        schema: &GraphSchema,
        start: usize,
        goal: usize,
        edge: usize,
    ) -> Result<Self, String> {
        let edge = schema.edges.get(edge).ok_or("query edge outside graph")?;
        Ok(match (edge.from == start, edge.to == goal) {
            (true, true) => Self::Direct,
            (true, false) => Self::FromStart,
            (false, true) => Self::ToGoal,
            (false, false) => Self::Interior,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryPolicy {
    pub schema: String,
    pub family: String,
    pub selection_rule: String,
    pub ranked_roles: Vec<EdgeRole>,
}
impl QueryPolicy {
    pub fn ranked(roles: Vec<EdgeRole>) -> Result<Self, String> {
        let policy = Self {
            schema: POLICY_SCHEMA.into(),
            family: GRAPH_FAMILY.into(),
            selection_rule: SELECTION_RULE.into(),
            ranked_roles: roles,
        };
        policy.validate()?;
        Ok(policy)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != POLICY_SCHEMA
            || self.family != GRAPH_FAMILY
            || self.selection_rule != SELECTION_RULE
            || self.ranked_roles.is_empty()
            || self.ranked_roles.len() > 4
            || self
                .ranked_roles
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != self.ranked_roles.len()
        {
            return Err("unsupported, empty or duplicate portable query-policy grammar".into());
        }
        Ok(())
    }

    pub fn choose(
        &self,
        schema: &GraphSchema,
        start: usize,
        goal: usize,
        candidate: &Route,
        observations: &[(usize, u16)],
        work_budget: usize,
    ) -> Result<QueryChoice, String> {
        self.validate()?;
        schema.validate()?;
        endpoints(schema, start, goal)?;
        let work = schema
            .edges
            .len()
            .checked_add(candidate.edges.len())
            .and_then(|n| n.checked_add(observations.len()))
            .and_then(|n| n.checked_add(self.ranked_roles.len()))
            .ok_or("query-selection work overflow")?;
        if work > work_budget || work_budget > MAX_WORK {
            return Err("query-selection work budget exhausted".into());
        }
        if candidate.nodes.first() != Some(&start)
            || candidate.nodes.last() != Some(&goal)
            || candidate.nodes.len() != candidate.edges.len() + 1
            || candidate.family != GRAPH_FAMILY
        {
            return Err("query policy requires the exact learner's declared route".into());
        }
        let mut observed = BTreeSet::new();
        for &(edge, cost) in observations {
            let bounds = schema
                .edges
                .get(edge)
                .ok_or("observation edge outside graph")?;
            if cost < bounds.lower || cost > bounds.upper || !observed.insert(edge) {
                return Err("query policy received invalid or duplicate observations".into());
            }
        }
        let mut choices = Vec::new();
        for (position, &id) in candidate.edges.iter().enumerate() {
            let edge = schema.edges.get(id).ok_or("route edge outside graph")?;
            if edge.from != candidate.nodes[position] || edge.to != candidate.nodes[position + 1] {
                return Err("route edge/node witness is inconsistent".into());
            }
            if !observed.contains(&id) {
                let role = EdgeRole::of(schema, start, goal, id)?;
                let rank = self
                    .ranked_roles
                    .iter()
                    .position(|item| *item == role)
                    .unwrap_or(self.ranked_roles.len());
                choices.push((rank, position, id));
            }
        }
        choices.sort_unstable();
        Ok(QueryChoice {
            edge: choices.first().map(|x| x.2),
            work_units: work,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryChoice {
    pub edge: Option<usize>,
    pub work_units: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeObservation {
    pub edge: usize,
    pub cost: u16,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceTrace {
    pub context: String,
    pub schema: GraphSchema,
    pub start: usize,
    pub goal: usize,
    pub observations: Vec<EdgeObservation>,
}
impl SourceTrace {
    pub fn validate(&self) -> Result<(), String> {
        self.schema.validate()?;
        endpoints(&self.schema, self.start, self.goal)?;
        if !label(&self.context)
            || self.observations.is_empty()
            || self.observations.len() > self.schema.edges.len()
        {
            return Err("source trace needs a named context and bounded real observations".into());
        }
        let mut seen = BTreeSet::new();
        for row in &self.observations {
            let edge = self
                .schema
                .edges
                .get(row.edge)
                .ok_or("source observation outside graph")?;
            if !seen.insert(row.edge) || row.cost < edge.lower || row.cost > edge.upper {
                return Err("source trace contradicts its declared observed edge intervals".into());
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleEvidence {
    pub role: EdgeRole,
    pub observations: usize,
    pub contexts: usize,
    pub excess: u64,
    pub interval_width: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedPolicy {
    pub policy: QueryPolicy,
    pub evidence: Vec<RoleEvidence>,
    pub source_contexts: Vec<String>,
    pub work_units: usize,
}

pub fn derive_policy(traces: &[SourceTrace], work_budget: usize) -> Result<DerivedPolicy, String> {
    if traces.len() < MIN_SOURCE_CONTEXTS
        || traces.len() > MAX_SOURCE_CONTEXTS
        || work_budget == 0
        || work_budget > MAX_WORK
    {
        return Err("policy derivation needs two to 32 source contexts and bounded work".into());
    }
    let mut contexts = BTreeSet::new();
    let mut totals = BTreeMap::<EdgeRole, (usize, BTreeSet<String>, u64, u64)>::new();
    let mut work = 0_usize;
    let mut observations = 0_usize;
    for trace in traces {
        trace.validate()?;
        if !contexts.insert(trace.context.clone()) {
            return Err("repeated source context cannot manufacture independent support".into());
        }
        work = work
            .checked_add(trace.schema.edges.len() + trace.observations.len())
            .ok_or("source policy work overflow")?;
        observations += trace.observations.len();
        if work > work_budget || observations > MAX_SOURCE_OBSERVATIONS {
            return Err("source observation or policy derivation work budget exhausted".into());
        }
        for row in &trace.observations {
            let edge = &trace.schema.edges[row.edge];
            let role = EdgeRole::of(&trace.schema, trace.start, trace.goal, row.edge)?;
            let entry = totals.entry(role).or_default();
            entry.0 += 1;
            entry.1.insert(trace.context.clone());
            entry.2 += u64::from(row.cost - edge.lower);
            entry.3 += u64::from(edge.upper - edge.lower);
        }
    }
    let evidence: Vec<_> = totals
        .into_iter()
        .map(
            |(role, (observations, contexts, excess, interval_width))| RoleEvidence {
                role,
                observations,
                contexts: contexts.len(),
                excess,
                interval_width,
            },
        )
        .collect();
    let mut ranked: Vec<_> = evidence
        .iter()
        .filter(|row| row.contexts >= MIN_SOURCE_CONTEXTS && row.interval_width > 0)
        .collect();
    ranked.sort_by(|a, b| {
        let left = u128::from(a.excess) * u128::from(b.interval_width);
        let right = u128::from(b.excess) * u128::from(a.interval_width);
        right.cmp(&left).then(a.role.cmp(&b.role))
    });
    let policy = QueryPolicy::ranked(ranked.iter().map(|row| row.role).collect())?;
    Ok(DerivedPolicy {
        policy,
        evidence,
        source_contexts: contexts.into_iter().collect(),
        work_units: work,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphTask {
    pub context: String,
    pub schema: GraphSchema,
    pub start: usize,
    pub goal: usize,
    /// Privileged local evaluator truth; it is never passed into policy selection.
    pub costs: Vec<u16>,
}
impl GraphTask {
    pub fn validate(&self) -> Result<(), String> {
        self.schema.validate()?;
        endpoints(&self.schema, self.start, self.goal)?;
        if !label(&self.context)
            || self.costs.len() != self.schema.edges.len()
            || self.costs.iter().any(|cost| *cost == 0 || *cost > 1000)
        {
            return Err(
                "task needs a context and one globally bounded positive truth cost per edge".into(),
            );
        }
        // Do not inspect hidden costs to reject a family. An interval violation
        // becomes evidence only when the exact learner actually observes it.
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialLimits {
    pub max_queries: usize,
    pub model_work: usize,
    pub policy_work: usize,
}
impl Default for TrialLimits {
    fn default() -> Self {
        Self {
            max_queries: 256,
            model_work: 1_000_000,
            policy_work: 100_000,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialResult {
    pub context: String,
    pub status: String,
    pub queried_edges: Vec<usize>,
    pub observations: Vec<EdgeObservation>,
    pub certified_cost: Option<u64>,
    pub oracle_optimum: Option<u64>,
    pub incorrect_certificate: bool,
    pub model_work: usize,
    pub policy_work: usize,
    pub evaluator_work: usize,
}
impl TrialResult {
    pub fn certified_correctly(&self) -> bool {
        self.certified_cost.is_some()
            && !self.incorrect_certificate
            && self.certified_cost == self.oracle_optimum
    }
}

/// Separate Bellman-Ford evaluator. No result is used to select a query.
pub fn oracle_optimum(task: &GraphTask) -> Result<(Option<u64>, usize), String> {
    task.validate()?;
    let mut distance = vec![u64::MAX; task.schema.nodes];
    distance[task.start] = 0;
    let mut work = 0;
    for _ in 1..task.schema.nodes {
        let mut changed = false;
        for (id, edge) in task.schema.edges.iter().enumerate() {
            work += 1;
            if distance[edge.from] == u64::MAX {
                continue;
            }
            let proposed = distance[edge.from] + u64::from(task.costs[id]);
            if proposed < distance[edge.to] {
                distance[edge.to] = proposed;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    Ok((
        (distance[task.goal] != u64::MAX).then_some(distance[task.goal]),
        work,
    ))
}

pub fn run_trial(
    task: &GraphTask,
    policy: Option<&QueryPolicy>,
    limits: TrialLimits,
) -> Result<TrialResult, String> {
    task.validate()?;
    if let Some(policy) = policy {
        policy.validate()?;
    }
    if limits.max_queries > 256
        || limits.model_work == 0
        || limits.model_work > MAX_WORK
        || limits.policy_work == 0
        || limits.policy_work > MAX_WORK
    {
        return Err("trial query/model/policy budget outside bounded range".into());
    }
    let mut learner = RouteLearner::new(task.schema.clone(), limits.model_work)?;
    let mut queried = Vec::new();
    let mut policy_work = 0;
    let (status, certified_cost) = loop {
        let assessed = learner.assess(task.start, task.goal)?;
        if let Some(route) = assessed.certified {
            break ("certified", Some(route.cost));
        }
        if assessed.status != "supported" {
            break (assessed.status, None);
        }
        let Some(route) = assessed.candidate else {
            break ("unreachable", None);
        };
        if queried.len() >= limits.max_queries {
            break ("query-budget", None);
        }
        let edge = if let Some(policy) = policy {
            let remaining = limits.policy_work.saturating_sub(policy_work);
            let choice = match policy.choose(
                &task.schema,
                task.start,
                task.goal,
                &route,
                learner.observations(),
                remaining,
            ) {
                Ok(choice) => choice,
                Err(_) => break ("policy-budget", None),
            };
            policy_work += choice.work_units;
            choice.edge
        } else {
            assessed.next_observation
        };
        let Some(edge) = edge else {
            break ("abstained", None);
        };
        queried.push(edge);
        if learner.observe(edge, task.costs[edge]).is_err() {
            break (
                if learner.status() == "contradicted" {
                    "contradicted"
                } else {
                    "budget_exhausted"
                },
                None,
            );
        }
    };
    let (truth, evaluator_work) = oracle_optimum(task)?;
    Ok(TrialResult {
        context: task.context.clone(),
        status: status.into(),
        queried_edges: queried,
        observations: learner
            .observations()
            .iter()
            .map(|&(edge, cost)| EdgeObservation { edge, cost })
            .collect(),
        certified_cost,
        oracle_optimum: truth,
        incorrect_certificate: certified_cost.is_some() && certified_cost != truth,
        model_work: learner.model_work(),
        policy_work,
        evaluator_work,
    })
}

/// Verified public renaming, not inferred topology or hidden-cost transfer.
pub fn remap_task(
    task: &GraphTask,
    node_map: &[usize],
    edge_order: &[usize],
    context: &str,
) -> Result<GraphTask, String> {
    task.validate()?;
    if node_map.len() != task.schema.nodes
        || edge_order.len() != task.schema.edges.len()
        || node_map.iter().copied().collect::<BTreeSet<_>>() != (0..task.schema.nodes).collect()
        || edge_order.iter().copied().collect::<BTreeSet<_>>()
            != (0..task.schema.edges.len()).collect()
    {
        return Err("node and edge remapping require explicit complete bijections".into());
    }
    let mut remapped = task.clone();
    remapped.context = context.into();
    remapped.start = node_map[task.start];
    remapped.goal = node_map[task.goal];
    remapped.schema.edges = edge_order
        .iter()
        .map(|&old| {
            let mut edge = task.schema.edges[old].clone();
            edge.from = node_map[edge.from];
            edge.to = node_map[edge.to];
            edge
        })
        .collect();
    remapped.costs = edge_order.iter().map(|&old| task.costs[old]).collect();
    remapped.validate()?;
    Ok(remapped)
}

/// Exact labelled-graph witness after endpoint-aware colour refinement.
/// Ambiguous refinements abstain: an equal weak fingerprint is never presented
/// as proof of graph isomorphism. Truth costs are used only for evaluator metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalTask {
    pub nodes: usize,
    pub start: usize,
    pub goal: usize,
    /// Sorted (from, to, lower, upper, observed evaluator truth) tuples.
    pub edges: Vec<(usize, usize, u16, u16, u16)>,
    pub refinement_scan_units: usize,
}
pub fn canonical_task(task: &GraphTask, budget: usize) -> Result<CanonicalTask, String> {
    task.validate()?;
    let n = task.schema.nodes;
    if n > 12 || task.schema.edges.len() > 56 || budget > MAX_WORK {
        return Err("canonical witness domain or work budget exceeded".into());
    }
    let mut colours = (0..n)
        .map(|node| {
            if node == task.start {
                1
            } else if node == task.goal {
                2
            } else {
                0
            }
        })
        .collect::<Vec<_>>();
    let mut work = 0usize;
    for _ in 0..n {
        let mut profiles = Vec::new();
        for node in 0..n {
            work = work
                .checked_add(1 + task.schema.edges.len())
                .ok_or("canonical work overflow")?;
            if work > budget {
                return Err("canonical refinement work budget exhausted".into());
            }
            let mut incoming = Vec::new();
            let mut outgoing = Vec::new();
            for (id, edge) in task.schema.edges.iter().enumerate() {
                if edge.to == node {
                    incoming.push((edge.lower, edge.upper, task.costs[id], colours[edge.from]));
                }
                if edge.from == node {
                    outgoing.push((edge.lower, edge.upper, task.costs[id], colours[edge.to]));
                }
            }
            incoming.sort_unstable();
            outgoing.sort_unstable();
            profiles.push((colours[node], incoming, outgoing));
        }
        let mut classes = profiles.clone();
        classes.sort_unstable();
        classes.dedup();
        colours = profiles
            .iter()
            .map(|p| {
                classes
                    .binary_search(p)
                    .expect("profile belongs to its class set")
            })
            .collect();
        if classes.len() == n {
            let mut edges = task
                .schema
                .edges
                .iter()
                .enumerate()
                .map(|(id, e)| {
                    (
                        colours[e.from],
                        colours[e.to],
                        e.lower,
                        e.upper,
                        task.costs[id],
                    )
                })
                .collect::<Vec<_>>();
            edges.sort_unstable();
            return Ok(CanonicalTask {
                nodes: n,
                start: colours[task.start],
                goal: colours[task.goal],
                edges,
                refinement_scan_units: work,
            });
        }
    }
    Err("canonical refinement is ambiguous; no isomorphism certificate issued".into())
}
fn endpoints(schema: &GraphSchema, start: usize, goal: usize) -> Result<(), String> {
    if start >= schema.nodes || goal >= schema.nodes || start == goal {
        return Err("query policy needs two distinct declared endpoints".into());
    }
    Ok(())
}
fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planning::Edge;
    fn manual(context: &str) -> GraphTask {
        GraphTask {
            context: context.into(),
            start: 0,
            goal: 3,
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
            costs: vec![1, 9, 1, 1],
        }
    }
    fn sources() -> Vec<SourceTrace> {
        ["manual-source-a", "manual-source-b"]
            .into_iter()
            .map(|context| {
                let task = manual(context);
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
            .collect()
    }
    #[test]
    fn exact_source_ratio_derives_goal_priority_and_missing_roles_fall_back() {
        let derived = derive_policy(&sources(), 1000).unwrap();
        assert_eq!(
            derived.policy.ranked_roles,
            vec![EdgeRole::ToGoal, EdgeRole::FromStart]
        );
        assert_eq!(derived.evidence[1].excess, 16);
        assert!(derive_policy(&sources(), 1).is_err());
        let mut duplicate = sources();
        duplicate[1].context = duplicate[0].context.clone();
        assert!(derive_policy(&duplicate, 1000).is_err());
    }
    #[test]
    fn priority_changes_real_queries_without_changing_conditional_exact_certificates() {
        let policy = derive_policy(&sources(), 1000).unwrap().policy;
        let task = manual("manual-calibration");
        let baseline = run_trial(&task, None, TrialLimits::default()).unwrap();
        let candidate = run_trial(&task, Some(&policy), TrialLimits::default()).unwrap();
        assert_eq!(baseline.queried_edges, vec![0, 1, 2, 3]);
        assert_eq!(candidate.queried_edges, vec![1, 3, 2]);
        assert!(baseline.certified_correctly() && candidate.certified_correctly());
        assert_eq!(baseline.certified_cost, candidate.certified_cost);
    }
    #[test]
    fn node_and_edge_relabeling_preserve_policy_roles_and_optimal_cost() {
        let policy = derive_policy(&sources(), 1000).unwrap().policy;
        let task = manual("manual-original");
        let remapped = remap_task(&task, &[2, 0, 3, 1], &[3, 1, 0, 2], "manual-remapped").unwrap();
        let result = run_trial(&remapped, Some(&policy), TrialLimits::default()).unwrap();
        assert!(result.certified_correctly());
        assert_eq!(result.certified_cost, Some(2));
        assert!(remap_task(&task, &[0, 0, 2, 3], &[0, 1, 2, 3], "bad").is_err());
    }
    #[test]
    fn inverted_role_costs_are_a_harmful_prior_not_hidden_family_rejection() {
        let policy = derive_policy(&sources(), 1000).unwrap().policy;
        let mut task = manual("manual-inverted");
        task.costs = vec![9, 1, 1, 1];
        let baseline = run_trial(&task, None, TrialLimits::default()).unwrap();
        let candidate = run_trial(&task, Some(&policy), TrialLimits::default()).unwrap();
        assert!(baseline.certified_correctly() && candidate.certified_correctly());
        assert!(candidate.queried_edges.len() > baseline.queried_edges.len());
    }
    #[test]
    fn observed_drift_contradicts_exact_family_and_zero_budget_abstains() {
        let mut task = manual("manual-drift");
        task.costs[0] = 10;
        let result = run_trial(&task, None, TrialLimits::default()).unwrap();
        assert_eq!(result.status, "contradicted");
        assert!(result.certified_cost.is_none());
        let limited = run_trial(
            &manual("manual-budget"),
            None,
            TrialLimits {
                max_queries: 0,
                ..TrialLimits::default()
            },
        )
        .unwrap();
        assert_eq!(limited.status, "query-budget");
        assert!(limited.certified_cost.is_none());
        let mut wrong = QueryPolicy::ranked(vec![EdgeRole::ToGoal]).unwrap();
        wrong.family = "arbitrary-agent/v1".into();
        assert!(run_trial(&task, Some(&wrong), TrialLimits::default()).is_err());
    }

    #[test]
    fn complete_canonical_witness_ignores_verified_renaming_and_abstains_on_symmetry() {
        let mut task = manual("manual-canonical");
        task.schema.edges[2].lower = 2;
        task.costs[2] = 2;
        let remapped = remap_task(
            &task,
            &[2, 0, 3, 1],
            &[3, 1, 0, 2],
            "manual-canonical-other",
        )
        .unwrap();
        assert_eq!(
            canonical_task(&task, 1000).unwrap(),
            canonical_task(&remapped, 1000).unwrap()
        );
        assert!(canonical_task(&task, 1).is_err());
        let mut symmetric = manual("manual-symmetric");
        symmetric.costs.fill(1);
        assert!(canonical_task(&symmetric, 1000)
            .unwrap_err()
            .contains("ambiguous"));
    }
}
