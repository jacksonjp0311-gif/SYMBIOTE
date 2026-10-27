//! Fixture runner: JSON document on stdin or the sole file argument; JSON on stdout.
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::Read;
use symbiote_reasoning::{Observation, SymbolicLearner};

#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    max_states: usize,
    max_prefixes: usize,
    initial: Observation,
    steps: Vec<Step>,
    reconstruct: Option<Reconstruction>,
}

#[derive(Deserialize)]
struct Step {
    action: usize,
    observation: Observation,
}

#[derive(Deserialize)]
struct Reconstruction {
    max_states: Option<usize>,
    max_prefixes: Option<usize>,
}

fn checkpoint(learner: &SymbolicLearner) -> Result<Value, String> {
    let snapshot = learner.snapshot();
    Ok(json!({
        "status": snapshot.status,
        "model_rows": snapshot.model_rows,
        "evidence_count": snapshot.evidence_count,
        "max_rows_seen": snapshot.max_rows_seen,
        "support": [learner.predict_support(0)?, learner.predict_support(1)?],
        "conditional": [learner.conditional_certificate(0)?, learner.conditional_certificate(1)?],
        "last_failure": snapshot.last_failure,
        "physical_certificate_authorized": snapshot.physical_certificate_authorized
    }))
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut source = String::new();
    if let Some(path) = std::env::args().nth(1) {
        source = std::fs::read_to_string(path)?;
    } else {
        std::io::stdin().read_to_string(&mut source)?;
    }
    let fixture: Fixture = serde_json::from_str(&source)?;
    let mut results = Vec::new();
    for case in fixture.cases {
        let mut learner = SymbolicLearner::new(case.max_states, case.max_prefixes)?;
        learner.initialize(case.initial)?;
        let mut history = vec![checkpoint(&learner)?];
        for step in case.steps {
            learner.observe(step.action, step.observation)?;
            history.push(checkpoint(&learner)?);
        }
        let reconstruction = case
            .reconstruct
            .map(|r| {
                learner
                    .reconstruct(r.max_states, r.max_prefixes)
                    .and_then(|l| checkpoint(&l))
            })
            .transpose()?;
        results
            .push(json!({"name": case.name, "history": history, "reconstruction": reconstruction}));
    }
    println!("{}", serde_json::to_string(&results)?);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("reasoning fixture failed: {error}");
        std::process::exit(1);
    }
}
