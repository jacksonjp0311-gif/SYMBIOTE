//! Cloneable exact receiver. Evidence origin never selects a hypothesis family,
//! tie break or assessment schedule. All fixtures here are independent of the
//! prospective cohort.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use symbiote_reasoning::planning::{GraphSchema, Route, RouteLearner, GRAPH_FAMILY};

pub(super) const MODEL_BUDGET: usize = 100_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Algorithm {
    Dijkstra,
    SimplePaths,
}
impl Algorithm {
    pub(super) fn assessment_bound(self, schema: &GraphSchema) -> usize {
        match self {
            Self::Dijkstra => schema.nodes * schema.edges.len(),
            Self::SimplePaths => schema.edges.len() * (1 << (schema.nodes - 1)),
        }
    }
}
#[derive(Clone)]
enum Engine {
    Dijkstra(RouteLearner),
    Paths(Paths),
}
#[derive(Clone)]
struct Paths {
    schema: GraphSchema,
    observed: BTreeMap<usize, u16>,
    work: usize,
}
type PathAssessment = (Option<Route>, Option<Route>, Option<usize>);

pub(super) struct Assessment {
    pub(super) candidate: Option<Route>,
    pub(super) certified: Option<Route>,
    pub(super) next: Option<usize>,
    pub(super) work_delta: usize,
}
#[derive(Clone)]
pub(super) struct ExactModel {
    schema: GraphSchema,
    algorithm: Algorithm,
    engine: Engine,
    observed: BTreeMap<usize, u16>,
}
impl ExactModel {
    pub(super) fn new(schema: GraphSchema, algorithm: Algorithm) -> Result<Self, String> {
        schema.validate()?;
        if schema.nodes > 8
            || schema.edges.len() > 28
            || schema.edges.iter().any(|edge| edge.upper > 9)
        {
            return Err("adaptive model exceeds finite declared graph family".into());
        }
        let mut incoming = vec![0_usize; schema.nodes];
        for edge in &schema.edges {
            incoming[edge.to] += 1;
        }
        let mut frontier = (0..schema.nodes)
            .filter(|node| incoming[*node] == 0)
            .collect::<Vec<_>>();
        let mut visited = 0;
        while let Some(node) = frontier.pop() {
            visited += 1;
            for edge in &schema.edges {
                if edge.from == node {
                    incoming[edge.to] -= 1;
                    if incoming[edge.to] == 0 {
                        frontier.push(edge.to);
                    }
                }
            }
        }
        if visited != schema.nodes {
            return Err("adaptive route model requires a declared acyclic topology".into());
        }
        let engine = match algorithm {
            Algorithm::Dijkstra => {
                Engine::Dijkstra(RouteLearner::new(schema.clone(), MODEL_BUDGET)?)
            }
            Algorithm::SimplePaths => Engine::Paths(Paths {
                schema: schema.clone(),
                observed: BTreeMap::new(),
                work: 0,
            }),
        };
        Ok(Self {
            schema,
            algorithm,
            engine,
            observed: BTreeMap::new(),
        })
    }
    pub(super) fn schema(&self) -> &GraphSchema {
        &self.schema
    }
    pub(super) fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    pub(super) fn work(&self) -> usize {
        match &self.engine {
            Engine::Dijkstra(model) => model.model_work(),
            Engine::Paths(model) => model.work,
        }
    }
    pub(super) fn observed(&self) -> &BTreeMap<usize, u16> {
        &self.observed
    }
    pub(super) fn state(&self) -> Value {
        json!({"schema":self.schema,"algorithm":self.algorithm,"observations":self.observed,"native_work":self.work()})
    }
    /// Called only after own-source authentication or independent peer verification.
    /// Invalid/contradictory input is rejected before cloning or changing support.
    /// The staged model is committed once, with precisely one native work unit.
    pub(super) fn ingest(&mut self, edge_id: usize, cost: u16) -> Result<(), String> {
        let edge = self
            .schema
            .edges
            .get(edge_id)
            .ok_or("edge outside exact graph")?;
        if cost < edge.lower || cost > edge.upper {
            return Err("edge cost outside declared stationary interval".into());
        }
        if let Some(old) = self.observed.get(&edge_id) {
            if *old != cost {
                return Err("edge observation contradicts prior stationary evidence".into());
            }
            return Err("known edge is not a novel observation".into());
        }
        if self.work() >= MODEL_BUDGET {
            return Err("native observation work budget exhausted".into());
        }
        let mut staged = self.clone();
        let before = staged.work();
        match &mut staged.engine {
            Engine::Dijkstra(model) => model.observe(edge_id, cost)?,
            Engine::Paths(model) => {
                model.observed.insert(edge_id, cost);
                model.work += 1;
            }
        }
        if staged.work() != before + 1 {
            return Err("HOLD: observation ingestion does not have common unit work".into());
        }
        staged.observed.insert(edge_id, cost);
        *self = staged;
        Ok(())
    }
    pub(super) fn assess(&mut self, start: usize, goal: usize) -> Result<Assessment, String> {
        if start >= self.schema.nodes || goal >= self.schema.nodes || start == goal {
            return Err("route needs two distinct declared nodes".into());
        }
        let before = self.work();
        let (candidate, certified, next) = match &mut self.engine {
            Engine::Dijkstra(model) => {
                let result = model.assess(start, goal)?;
                if result.status != "supported" {
                    return Err(format!("native route model {}", result.status));
                }
                (result.candidate, result.certified, result.next_observation)
            }
            Engine::Paths(model) => model.assess(start, goal)?,
        };
        let work_delta = self
            .work()
            .checked_sub(before)
            .ok_or("native model work regressed")?;
        if work_delta > self.algorithm.assessment_bound(&self.schema) {
            return Err(
                "HOLD: actual route work exceeded the reserved method-comparison bound".into(),
            );
        }
        Ok(Assessment {
            candidate,
            certified,
            next,
            work_delta,
        })
    }
}
impl Paths {
    fn assess(&mut self, start: usize, goal: usize) -> Result<PathAssessment, String> {
        struct Search<'a> {
            schema: &'a GraphSchema,
            observed: &'a BTreeMap<usize, u16>,
            work: &'a mut usize,
            goal: usize,
            best: Option<Route>,
        }
        impl Search<'_> {
            fn visit(
                &mut self,
                node: usize,
                nodes: &mut Vec<usize>,
                edges: &mut Vec<usize>,
                cost: u64,
            ) -> Result<(), String> {
                if node == self.goal {
                    let route = Route {
                        nodes: nodes.clone(),
                        edges: edges.clone(),
                        cost,
                        cost_basis: "optimistic_interval_lower_bounds",
                        family: GRAPH_FAMILY,
                        conditional: true,
                    };
                    if self.best.as_ref().is_none_or(|best| {
                        route.cost < best.cost
                            || (route.cost == best.cost && route.edges > best.edges)
                    }) {
                        self.best = Some(route);
                    }
                    return Ok(());
                }
                for id in (0..self.schema.edges.len()).rev() {
                    if *self.work >= MODEL_BUDGET {
                        return Err("native path work budget exhausted".into());
                    }
                    *self.work += 1;
                    let edge = &self.schema.edges[id];
                    if edge.from != node || nodes.contains(&edge.to) {
                        continue;
                    }
                    nodes.push(edge.to);
                    edges.push(id);
                    self.visit(
                        edge.to,
                        nodes,
                        edges,
                        cost + u64::from(self.observed.get(&id).copied().unwrap_or(edge.lower)),
                    )?;
                    nodes.pop();
                    edges.pop();
                }
                Ok(())
            }
        }
        let mut search = Search {
            schema: &self.schema,
            observed: &self.observed,
            work: &mut self.work,
            goal,
            best: None,
        };
        search.visit(start, &mut vec![start], &mut Vec::new(), 0)?;
        let Some(mut candidate) = search.best else {
            return Ok((None, None, None));
        };
        let next = candidate
            .edges
            .iter()
            .find(|edge| !self.observed.contains_key(edge))
            .copied();
        let certified = if next.is_none() {
            candidate.cost_basis = "observed_edge_costs";
            Some(candidate.clone())
        } else {
            None
        };
        Ok((Some(candidate), certified, next))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use symbiote_reasoning::planning::Edge;
    fn fixture() -> GraphSchema {
        GraphSchema {
            nodes: 4,
            edges: [(0, 1), (1, 3), (0, 2), (2, 3)]
                .into_iter()
                .map(|(from, to)| Edge {
                    from,
                    to,
                    lower: 1,
                    upper: 3,
                })
                .collect(),
        }
    }
    #[test]
    fn local_and_verified_peer_ingestion_have_identical_state_and_common_work() {
        for algorithm in [Algorithm::Dijkstra, Algorithm::SimplePaths] {
            let mut initial = ExactModel::new(fixture(), algorithm).unwrap();
            initial.ingest(0, 2).unwrap();
            initial.assess(0, 3).unwrap();
            assert_eq!(initial.schema().nodes, 4);
            assert_eq!(initial.algorithm(), algorithm);
            assert_eq!(initial.observed().get(&0), Some(&2));
            for cost in 1..=3 {
                let mut own = initial.clone();
                let mut peer = initial.clone();
                let before = initial.work();
                own.ingest(1, cost).unwrap();
                peer.ingest(1, cost).unwrap();
                assert_eq!(own.work() - before, 1);
                assert_eq!(peer.work() - before, 1);
                assert_eq!(own.state(), peer.state());
                let own_assessment = own.assess(0, 3).unwrap();
                let peer_assessment = peer.assess(0, 3).unwrap();
                assert_eq!(own_assessment.work_delta, peer_assessment.work_delta);
                assert_eq!(
                    json!(own_assessment.candidate),
                    json!(peer_assessment.candidate)
                );
                assert_eq!(
                    json!(own_assessment.certified),
                    json!(peer_assessment.certified)
                );
                assert_eq!(own_assessment.next, peer_assessment.next);
                assert_eq!(own.state(), peer.state());
            }
        }
    }
    #[test]
    fn malformed_and_contradictory_costs_preserve_the_entire_native_state() {
        for algorithm in [Algorithm::Dijkstra, Algorithm::SimplePaths] {
            let mut model = ExactModel::new(fixture(), algorithm).unwrap();
            model.ingest(0, 1).unwrap();
            let before = model.state();
            for (edge, cost) in [(8, 1), (1, 0), (1, 4), (0, 2), (0, 1)] {
                assert!(model.ingest(edge, cost).is_err());
                assert_eq!(model.state(), before);
            }
        }
    }
    #[test]
    fn full_e28_manual_dag_preserves_common_ingestion_and_assessment_work_for_every_legitimate_frontier_cost(
    ) {
        let schema = GraphSchema {
            nodes: 8,
            edges: (0..8)
                .flat_map(|from| {
                    (from + 1..8).map(move |to| Edge {
                        from,
                        to,
                        lower: 1,
                        upper: 9,
                    })
                })
                .collect(),
        };
        for algorithm in [Algorithm::Dijkstra, Algorithm::SimplePaths] {
            for prefix in 0..schema.edges.len() {
                let mut initial = ExactModel::new(schema.clone(), algorithm).unwrap();
                for edge in 0..prefix {
                    initial.ingest(edge, (edge % 9 + 1) as u16).unwrap();
                }
                let assessment = initial.assess(0, 7).unwrap();
                let Some(frontier) = assessment.next else {
                    continue;
                };
                for cost in 1..=9 {
                    let mut own = initial.clone();
                    let mut peer = initial.clone();
                    let before = initial.work();
                    own.ingest(frontier, cost).unwrap();
                    peer.ingest(frontier, cost).unwrap();
                    assert_eq!(own.work() - before, 1);
                    assert_eq!(peer.work() - before, 1);
                    assert_eq!(own.state(), peer.state());
                    let first = own.assess(0, 7).unwrap();
                    let second = peer.assess(0, 7).unwrap();
                    assert_eq!(first.work_delta, second.work_delta);
                    assert!(first.work_delta <= algorithm.assessment_bound(&schema));
                    assert_eq!(json!(first.candidate), json!(second.candidate));
                    assert_eq!(json!(first.certified), json!(second.certified));
                    assert_eq!(first.next, second.next);
                    assert_eq!(own.state(), peer.state());
                }
            }
        }
    }
}
