//! Exact robust route reasoning in a declared finite positive-cost graph.
//! Unknown edge costs retain their complete integer interval. A route is certified
//! only when all its costs are observed and equal the optimistic global lower bound.
//! This is conditional graph reasoning, not a universal claim about an environment.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, BinaryHeap};

pub const GRAPH_FAMILY: &str = "finite-positive-cost-directed-graph/v1";
const MAX_NODES: usize = 64;
const MAX_EDGES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub from: usize,
    pub to: usize,
    pub lower: u16,
    pub upper: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSchema {
    pub nodes: usize,
    pub edges: Vec<Edge>,
}
impl GraphSchema {
    pub fn validate(&self) -> Result<(), String> {
        if !(2..=MAX_NODES).contains(&self.nodes)
            || self.edges.is_empty()
            || self.edges.len() > MAX_EDGES
        {
            return Err("bounded graph needs 2..64 nodes and 1..256 directed edges".into());
        }
        let mut pairs = BTreeSet::new();
        for edge in &self.edges {
            if edge.from >= self.nodes
                || edge.to >= self.nodes
                || edge.from == edge.to
                || edge.lower == 0
                || edge.lower > edge.upper
                || edge.upper > 1000
                || !pairs.insert((edge.from, edge.to))
            {
                return Err(
                    "graph edges must be unique, valid and have positive bounded cost intervals"
                        .into(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Route {
    pub nodes: Vec<usize>,
    pub edges: Vec<usize>,
    pub cost: u64,
    pub cost_basis: &'static str,
    pub family: &'static str,
    pub conditional: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RejectedObservation {
    pub edge_id: usize,
    pub cost: u16,
    pub reason: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RouteAssessment {
    pub status: &'static str,
    pub optimistic_cost: Option<u64>,
    pub candidate: Option<Route>,
    pub certified: Option<Route>,
    pub next_observation: Option<usize>,
    pub model_work: usize,
    pub rejected_observation: Option<RejectedObservation>,
    pub physical_certificate_authorized: bool,
}

#[derive(Clone, Debug)]
pub struct RouteLearner {
    schema: GraphSchema,
    observed: Vec<Option<u16>>,
    history: Vec<(usize, u16)>,
    work: usize,
    budget: usize,
    status: &'static str,
    rejected: Option<RejectedObservation>,
}
impl RouteLearner {
    pub fn new(schema: GraphSchema, budget: usize) -> Result<Self, String> {
        schema.validate()?;
        if budget == 0 {
            return Err("route reasoning needs a positive work budget".into());
        }
        Ok(Self {
            observed: vec![None; schema.edges.len()],
            schema,
            history: Vec::new(),
            work: 0,
            budget,
            status: "supported",
            rejected: None,
        })
    }
    pub fn schema(&self) -> &GraphSchema {
        &self.schema
    }
    pub fn observations(&self) -> &[(usize, u16)] {
        &self.history
    }
    pub fn status(&self) -> &str {
        self.status
    }
    pub fn model_work(&self) -> usize {
        self.work
    }
    fn reserve(&mut self, count: usize) -> bool {
        if self.status != "supported" {
            return false;
        }
        if self.work.checked_add(count).is_none_or(|n| n > self.budget) {
            self.status = "budget_exhausted";
            return false;
        }
        self.work += count;
        true
    }
    pub fn observe(&mut self, edge_id: usize, cost: u16) -> Result<(), String> {
        let edge = self
            .schema
            .edges
            .get(edge_id)
            .ok_or("edge id outside declared graph")?;
        if self.status != "supported" {
            return Err(format!("route learner unavailable: {}", self.status));
        }
        if cost < edge.lower
            || cost > edge.upper
            || self.observed[edge_id].is_some_and(|old| old != cost)
        {
            self.status = "contradicted";
            self.rejected = Some(RejectedObservation {
                edge_id,
                cost,
                reason: "stationary cost family contradicted",
            });
            return Err(
                "edge observation contradicts stationary cost interval; prior edge state retained"
                    .into(),
            );
        }
        if self.observed[edge_id] == Some(cost) {
            return Ok(());
        }
        if !self.reserve(1) {
            self.rejected = Some(RejectedObservation {
                edge_id,
                cost,
                reason: "work budget exhausted before accepting observation",
            });
            return Err("route work budget exhausted before update".into());
        }
        self.observed[edge_id] = Some(cost);
        self.history.push((edge_id, cost));
        Ok(())
    }
    fn shortest(&mut self, start: usize, goal: usize) -> Option<Route> {
        let mut distances = vec![u64::MAX; self.schema.nodes];
        let mut previous = vec![None; self.schema.nodes];
        let mut queue = BinaryHeap::new();
        distances[start] = 0;
        queue.push(std::cmp::Reverse((0_u64, start)));
        while let Some(std::cmp::Reverse((distance, node))) = queue.pop() {
            if distance != distances[node] {
                continue;
            }
            if node == goal {
                break;
            }
            for id in 0..self.schema.edges.len() {
                if !self.reserve(1) {
                    return None;
                }
                let edge = &self.schema.edges[id];
                if edge.from != node {
                    continue;
                }
                let cost = u64::from(self.observed[id].unwrap_or(edge.lower));
                let proposed = distance + cost;
                if proposed < distances[edge.to] {
                    distances[edge.to] = proposed;
                    previous[edge.to] = Some(id);
                    queue.push(std::cmp::Reverse((proposed, edge.to)));
                }
            }
        }
        if distances[goal] == u64::MAX {
            return None;
        }
        let mut nodes = vec![goal];
        let mut edges = Vec::new();
        let mut current = goal;
        while current != start {
            let id = previous[current]?;
            edges.push(id);
            current = self.schema.edges[id].from;
            nodes.push(current);
        }
        edges.reverse();
        nodes.reverse();
        let cost_basis = if edges.iter().all(|id| self.observed[*id].is_some()) {
            "observed_edge_costs"
        } else {
            "optimistic_interval_lower_bounds"
        };
        Some(Route {
            nodes,
            edges,
            cost: distances[goal],
            cost_basis,
            family: GRAPH_FAMILY,
            conditional: true,
        })
    }
    pub fn assess(&mut self, start: usize, goal: usize) -> Result<RouteAssessment, String> {
        if start >= self.schema.nodes || goal >= self.schema.nodes || start == goal {
            return Err("choose distinct declared start and goal nodes".into());
        }
        let candidate = if self.status == "supported" {
            self.shortest(start, goal)
        } else {
            None
        };
        let mut certified = None;
        let mut next = None;
        if self.status == "supported" {
            if let Some(route) = &candidate {
                next = route
                    .edges
                    .iter()
                    .find(|id| self.observed[**id].is_none())
                    .copied();
                if next.is_none() {
                    certified = Some(route.clone());
                }
            }
        }
        Ok(RouteAssessment {
            status: self.status,
            optimistic_cost: candidate.as_ref().map(|r| r.cost),
            candidate,
            certified,
            next_observation: next,
            model_work: self.work,
            rejected_observation: self.rejected.clone(),
            physical_certificate_authorized: false,
        })
    }
    /// An inert path hint cannot create knowledge or bypass exact interval support.
    pub fn assess_hint(
        &mut self,
        start: usize,
        goal: usize,
        edges: &[usize],
    ) -> Result<bool, String> {
        let result = self.assess(start, goal)?;
        Ok(result.certified.is_some_and(|route| route.edges == edges))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn diamond() -> GraphSchema {
        GraphSchema {
            nodes: 4,
            edges: vec![
                Edge {
                    from: 0,
                    to: 1,
                    lower: 1,
                    upper: 3,
                },
                Edge {
                    from: 1,
                    to: 3,
                    lower: 1,
                    upper: 3,
                },
                Edge {
                    from: 0,
                    to: 2,
                    lower: 1,
                    upper: 3,
                },
                Edge {
                    from: 2,
                    to: 3,
                    lower: 1,
                    upper: 3,
                },
            ],
        }
    }
    fn independent_best(schema: &GraphSchema, weights: &[u16], start: usize, goal: usize) -> u64 {
        let mut cost = vec![u64::MAX / 2; schema.nodes];
        cost[start] = 0;
        for _ in 0..schema.nodes {
            for (edge, weight) in schema.edges.iter().zip(weights) {
                cost[edge.to] = cost[edge.to].min(cost[edge.from] + u64::from(*weight));
            }
        }
        cost[goal]
    }
    #[test]
    fn exact_conditional_route_matches_every_remaining_completion() {
        for actual_id in 0..81 {
            let mut remainder = actual_id;
            let weights: Vec<u16> = (0..4)
                .map(|_| {
                    let cost = remainder % 3 + 1;
                    remainder /= 3;
                    cost
                })
                .collect();
            let mut learner = RouteLearner::new(diamond(), 10_000).unwrap();
            for _ in 0..=4 {
                let result = learner.assess(0, 3).unwrap();
                if let Some(route) = result.certified {
                    for completion_id in 0..81 {
                        let mut n = completion_id;
                        let completion: Vec<u16> = (0..4)
                            .map(|_| {
                                let x = n % 3 + 1;
                                n /= 3;
                                x
                            })
                            .collect();
                        if learner
                            .observations()
                            .iter()
                            .any(|(edge, cost)| completion[*edge] != *cost)
                        {
                            continue;
                        }
                        assert_eq!(
                            route.cost,
                            independent_best(learner.schema(), &completion, 0, 3)
                        );
                    }
                    break;
                }
                let edge = result
                    .next_observation
                    .expect("exact exploration must identify a route within four observations");
                learner.observe(edge, weights[edge]).unwrap();
            }
        }
    }
    #[test]
    fn observations_select_relevant_edges_and_can_avoid_complete_map() {
        let mut learner = RouteLearner::new(diamond(), 1000).unwrap();
        let first = learner.assess(0, 3).unwrap().next_observation.unwrap();
        assert_eq!(
            learner.assess(0, 3).unwrap().candidate.unwrap().cost_basis,
            "optimistic_interval_lower_bounds"
        );
        learner.observe(first, 1).unwrap();
        let second = learner.assess(0, 3).unwrap().next_observation.unwrap();
        learner.observe(second, 1).unwrap();
        let certified = learner.assess(0, 3).unwrap().certified.unwrap();
        assert_eq!(certified.cost, 2);
        assert_eq!(certified.cost_basis, "observed_edge_costs");
        assert_eq!(learner.observations().len(), 2);
    }
    #[test]
    fn wrong_or_changed_cost_revokes_certainty_without_overwriting_evidence() {
        let mut learner = RouteLearner::new(diamond(), 1000).unwrap();
        learner.observe(0, 1).unwrap();
        assert!(learner.observe(0, 2).is_err());
        assert_eq!(learner.observations(), &[(0, 1)]);
        assert!(learner.assess(0, 3).unwrap().certified.is_none());
        assert_eq!(
            learner
                .assess(0, 3)
                .unwrap()
                .rejected_observation
                .unwrap()
                .cost,
            2
        );
        assert_eq!(learner.status(), "contradicted");
    }
    #[test]
    fn budget_and_unverified_hint_never_certify() {
        let mut learner = RouteLearner::new(diamond(), 1).unwrap();
        assert!(learner.assess(0, 3).unwrap().certified.is_none());
        assert_eq!(learner.status(), "budget_exhausted");
        assert!(!learner.assess_hint(0, 3, &[0, 1]).unwrap());
        let mut fresh = RouteLearner::new(diamond(), 100).unwrap();
        assert!(!fresh.assess_hint(0, 3, &[0, 1]).unwrap());
        assert!(fresh.observations().is_empty());
    }
    #[test]
    fn schema_rejects_ambiguous_or_unbounded_graphs() {
        let mut schema = diamond();
        schema.edges.push(schema.edges[0].clone());
        assert!(schema.validate().is_err());
        let mut schema = diamond();
        schema.edges[0].lower = 0;
        assert!(schema.validate().is_err());
        let mut schema = diamond();
        schema.nodes = 100;
        assert!(schema.validate().is_err());
    }
}
