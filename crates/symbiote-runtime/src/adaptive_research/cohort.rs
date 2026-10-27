//! Frozen generator specification. The prospective entry point is called only
//! after the controller validates a candidate/environment registration. Unit
//! development uses the independent four-node fixture below, never cohort seeds.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use symbiote_protocol::fresh_capability;
use symbiote_reasoning::planning::{Edge, GraphSchema};

const DOMAIN: &str = "SYMBIOTE-PROSPECTIVE-FRONTIER-002";
pub(super) fn hash(
    label: &str,
    n: usize,
    seed: u64,
    counter: usize,
    i: usize,
    j: usize,
) -> [u8; 32] {
    Sha256::digest(format!("{DOMAIN}|{label}|{n}|{seed}|{counter}|{i}|{j}").as_bytes()).into()
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct World {
    pub(super) index: usize,
    pub(super) nodes: usize,
    pub(super) seed: u64,
    pub(super) seed_index: usize,
    pub(super) counter: usize,
    pub(super) canonical_adjacency: String,
    pub(super) context: String,
    pub(super) schema: GraphSchema,
    pub(super) costs: Vec<u16>,
}
#[derive(Default, Serialize, Deserialize)]
pub(super) struct SetupWork {
    pub(super) hashes: u64,
    pub(super) canonical_bits: u64,
    pub(super) candidate_topologies: u64,
}
fn canonical(n: usize, edges: &[(usize, usize)], work: &mut SetupWork) -> String {
    let mut adjacency = vec![vec![false; n]; n];
    for (from, to) in edges {
        adjacency[*from][*to] = true;
    }
    fn permutations(
        order: &mut [usize],
        at: usize,
        adjacency: &[Vec<bool>],
        best: &mut Option<String>,
        work: &mut SetupWork,
    ) {
        if at == order.len() - 1 {
            let mut encoding = String::with_capacity(order.len() * order.len());
            for from in order.iter() {
                for to in order.iter() {
                    encoding.push(if adjacency[*from][*to] { '1' } else { '0' });
                    work.canonical_bits += 1;
                }
            }
            if best.as_ref().is_none_or(|previous| &encoding < previous) {
                *best = Some(encoding);
            }
            return;
        }
        for next in at..order.len() - 1 {
            order.swap(at, next);
            permutations(order, at + 1, adjacency, best, work);
            order.swap(at, next);
        }
    }
    let mut best = None;
    permutations(
        &mut (0..n).collect::<Vec<_>>(),
        1,
        &adjacency,
        &mut best,
        work,
    );
    best.expect("bounded node permutation always exists")
}
fn generate(
    n: usize,
    seed: u64,
    seed_index: usize,
    index: usize,
    previous: &BTreeSet<String>,
    work: &mut SetupWork,
) -> Result<World, String> {
    if !(4..=8).contains(&n) {
        return Err("bounded cohort generator requires 4..8 nodes".into());
    }
    for counter in 0..=255 {
        work.candidate_topologies += 1;
        let mut edges = (0..n - 1).map(|from| (from, from + 1)).collect::<Vec<_>>();
        for from in 0..n {
            for to in from + 1..n {
                if to == from + 1 {
                    continue;
                }
                work.hashes += 1;
                if hash("edge", n, seed, counter, from, to)[0] < 96 {
                    edges.push((from, to));
                }
            }
        }
        if edges.len() == n - 1 {
            continue;
        }
        let canonical_adjacency = canonical(n, &edges, work);
        if previous.contains(&canonical_adjacency) {
            continue;
        }
        let mut interior = (1..n - 1)
            .map(|node| {
                work.hashes += 1;
                (hash("node-order", n, seed, counter, node, 0), node)
            })
            .collect::<Vec<_>>();
        interior.sort();
        let mut physical = (0..n).collect::<Vec<_>>();
        for (position, (_, node)) in interior.into_iter().enumerate() {
            physical[node] = position + 1;
        }
        let mut ordered = edges
            .into_iter()
            .map(|(from, to)| {
                work.hashes += 1;
                (hash("edge-order", n, seed, counter, from, to), from, to)
            })
            .collect::<Vec<_>>();
        ordered.sort();
        let mut costs = Vec::new();
        let mut schema_edges = Vec::new();
        for (_, from, to) in ordered {
            work.hashes += 1;
            let stream = hash("cost", n, seed, counter, from, to);
            costs.push(1 + u16::from_le_bytes([stream[0], stream[1]]) % 9);
            schema_edges.push(Edge {
                from: physical[from],
                to: physical[to],
                lower: 1,
                upper: 9,
            });
        }
        let schema = GraphSchema {
            nodes: n,
            edges: schema_edges,
        };
        schema.validate()?;
        return Ok(World {
            index,
            nodes: n,
            seed,
            seed_index,
            counter,
            canonical_adjacency,
            context: format!("frontier-context-{}", fresh_capability()?),
            schema,
            costs,
        });
    }
    Err("HOLD: cohort configuration uniqueness exhausted its256candidatebound".into())
}

/// The caller must own a validated registration capability. The private
/// constructor lives in the registration module; neither tests nor wire input
/// can mint this zero-sized permit.
pub(super) fn prospective(
    _permit: &super::registration::EvaluationPermit,
) -> Result<(Vec<World>, SetupWork), String> {
    let mut worlds = Vec::new();
    let mut work = SetupWork::default();
    for nodes in [5, 6, 7, 8] {
        let mut seen = BTreeSet::new();
        for (seed_index, seed) in [211, 307, 401, 503, 601, 701].into_iter().enumerate() {
            let world = generate(nodes, seed, seed_index, worlds.len(), &seen, &mut work)?;
            seen.insert(world.canonical_adjacency.clone());
            worlds.push(world);
        }
    }
    if worlds.len() != 24 || work.canonical_bits > 100_000_000 {
        return Err("HOLD: setup work/cohort bound failed".into());
    }
    Ok((worlds, work))
}
pub(super) fn uniform_index(
    world: &World,
    decision: usize,
    arm: usize,
    choices: usize,
) -> Result<usize, String> {
    if choices == 0 || choices > 4 || decision >= 256 {
        return Err("invalid bounded uniform-control request".into());
    }
    let cutoff = (1_u64 << 32) / (choices as u64) * (choices as u64);
    for rejection in 0..256 {
        let stream = hash(
            "uniform",
            world.nodes,
            world.seed,
            decision * 256 + rejection,
            arm,
            0,
        );
        let sample = u32::from_le_bytes(
            stream[..4]
                .try_into()
                .map_err(|_| "uniformstreamtruncated")?,
        ) as u64;
        if sample < cutoff {
            return Ok((sample % (choices as u64)) as usize);
        }
    }
    Err("HOLD: unbiased uniform mapping exhausted its256samplebound".into())
}

/// Judge implementation intentionally differs from both live learners: freeze
/// every reachable pair with a breadth-first stack of complete simple paths.
/// Expected costs never leave the authority except in its controller-only audit.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Truth {
    pub(super) costs: BTreeMap<u16, u64>,
    pub(super) path_work: u64,
}
pub(super) fn freeze_truth(schema: &GraphSchema, weights: &[u16]) -> Result<Truth, String> {
    if weights.len() != schema.edges.len() {
        return Err("judge world shape mismatch".into());
    }
    let mut costs = BTreeMap::new();
    let mut work = 0_u64;
    for start in 0..schema.nodes {
        let mut paths = vec![(start, vec![start], 0_u64)];
        while let Some((node, visited, cost)) = paths.pop() {
            if node != start {
                let input = (start * schema.nodes + node) as u16;
                let best = costs.entry(input).or_insert(u64::MAX);
                *best = (*best).min(cost);
            }
            for (id, edge) in schema.edges.iter().enumerate() {
                work += 1;
                if work > 10_000_000 {
                    return Err("judge finite path work bound exhausted".into());
                }
                if edge.from != node || visited.contains(&edge.to) {
                    continue;
                }
                let mut next = visited.clone();
                next.push(edge.to);
                paths.push((edge.to, next, cost + u64::from(weights[id])));
            }
        }
    }
    Ok(Truth {
        costs,
        path_work: work,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_encoding_ignores_interior_names_on_a_manual_diamond() {
        let mut work = SetupWork::default();
        let first = canonical(4, &[(0, 1), (1, 3), (0, 2), (2, 3)], &mut work);
        let renamed = canonical(4, &[(0, 2), (2, 3), (0, 1), (1, 3)], &mut work);
        assert_eq!(first, renamed);
        assert_ne!(first, canonical(4, &[(0, 1), (1, 2), (2, 3)], &mut work));
    }
    #[test]
    fn independent_four_node_fixture_is_reproducible_without_evaluation_seeds() {
        let mut first_work = SetupWork::default();
        let mut second_work = SetupWork::default();
        let first = generate(4, 17, 0, 0, &BTreeSet::new(), &mut first_work).unwrap();
        let second = generate(4, 17, 0, 0, &BTreeSet::new(), &mut second_work).unwrap();
        assert_eq!(first.schema, second.schema);
        assert_eq!(first.costs, second.costs);
        assert_ne!(first.context, second.context);
        let truth = freeze_truth(&first.schema, &first.costs).unwrap();
        assert!(truth.costs.contains_key(&3));
        assert!(truth.path_work > 0);
        for decision in 0..4 {
            let selected = uniform_index(&first, decision, 2, 3).unwrap();
            assert!(selected < 3);
            assert_eq!(selected, uniform_index(&second, decision, 2, 3).unwrap());
        }
    }
}
