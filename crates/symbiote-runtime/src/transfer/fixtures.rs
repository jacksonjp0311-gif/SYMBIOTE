//! Deterministic controller-only recipe. No held-out generator is called by tests.
use super::*;
use symbiote_reasoning::planning::{Edge, GraphSchema};
use symbiote_reasoning::query_strategy::{remap_task, EdgeObservation};
pub(super) fn task(
    seed: u64,
    actor: usize,
    phase: &str,
    index: usize,
    layers: usize,
    goal_penalty: bool,
    chord: bool,
) -> Result<GraphTask, String> {
    let nodes = layers * 2;
    let goal = nodes - 1;
    let first = std::iter::once(0)
        .chain(1..layers)
        .chain(std::iter::once(goal))
        .collect::<Vec<_>>();
    let second = std::iter::once(0)
        .chain(layers..goal)
        .chain(std::iter::once(goal))
        .collect::<Vec<_>>();
    let mut edges = Vec::new();
    for path in [&first, &second] {
        for pair in path.windows(2) {
            edges.push(Edge {
                from: pair[0],
                to: pair[1],
                lower: 1,
                upper: 9,
            });
        }
    }
    // Public lower bounds make the first path uniquely optimistic. This avoids
    // turning a node-name tie breaker into the calibration treatment.
    edges[layers].lower = 2;
    let mut costs = vec![1; edges.len()];
    costs[layers] = 2;
    costs[if goal_penalty { layers - 1 } else { 0 }] = 4 + (seed % 6) as u16;
    if chord {
        edges.push(Edge {
            from: first[2],
            to: second[second.len() - 2],
            lower: 1,
            upper: 9,
        });
        costs.push(9);
    }
    let context = format!("query-transfer-{}", digest(&(seed, actor, phase, index))?);
    let original = GraphTask {
        context: context.clone(),
        schema: GraphSchema { nodes, edges },
        start: 0,
        goal,
        costs,
    };
    let salt = digest(&(seed, actor, phase, index, "public-permutation"))?;
    let mut random =
        u64::from_str_radix(&salt[..16], 16).map_err(|_| "permutation seed rejected")?;
    let mut node_map = (0..nodes).collect::<Vec<_>>();
    let mut order = (0..original.schema.edges.len()).collect::<Vec<_>>();
    for values in [&mut node_map, &mut order] {
        for i in (1..values.len()).rev() {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let j = (random % (i as u64 + 1)) as usize;
            values.swap(i, j);
        }
    }
    remap_task(&original, &node_map, &order, &context)
}
pub(super) fn traces(
    seed: u64,
    actor: usize,
    phase: &str,
    goal: bool,
) -> Result<Vec<SourceTrace>, String> {
    (0..2)
        .map(|index| {
            let task = task(seed, actor, phase, index, 2, goal, false)?;
            Ok(SourceTrace {
                context: task.context,
                schema: task.schema,
                start: task.start,
                goal: task.goal,
                observations: task
                    .costs
                    .into_iter()
                    .enumerate()
                    .map(|(edge, cost)| EdgeObservation { edge, cost })
                    .collect(),
            })
        })
        .collect()
}
pub(super) fn calibration(
    seed: u64,
    actor: usize,
    phase: &str,
    goal: bool,
) -> Result<Vec<GraphTask>, String> {
    (0..2)
        .map(|index| task(seed, actor, phase, index, 3, goal, false))
        .collect()
}
