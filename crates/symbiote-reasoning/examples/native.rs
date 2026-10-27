//! Embed exact conditional reasoning without a model service or network.
use symbiote_reasoning::planning::{Edge, GraphSchema, RouteLearner};

fn main() -> Result<(), String> {
    let schema = GraphSchema {
        nodes: 4,
        edges: [(0, 1), (1, 3), (0, 2), (2, 3)]
            .into_iter()
            .map(|(from, to)| Edge {
                from,
                to,
                lower: 1,
                upper: 5,
            })
            .collect(),
    };
    let mut learner = RouteLearner::new(schema, 256)?;
    // Two authorized observations suffice here: their route meets the lower
    // bound of every remaining completion. The other edges remain unknown.
    learner.observe(0, 1)?;
    learner.observe(1, 1)?;
    let assessment = learner.assess(0, 3)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&assessment).map_err(|e| e.to_string())?
    );
    if assessment.certified.is_none() {
        return Err("example route was not certified".into());
    }
    Ok(())
}
