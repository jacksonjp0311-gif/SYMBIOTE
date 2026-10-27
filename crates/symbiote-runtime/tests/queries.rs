//! Real CLI queries must preserve stored evidence and expose conditional abstention.
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use symbiote_memory::knowledge::graph::{
    assess_graph, graph_receipt_digest, graph_schema_fingerprint, GraphAcquisition, GraphMap,
    GraphObservation, GraphTrainingTask, GraphTrialEvidence,
};
use symbiote_memory::knowledge::{KnowledgeRecord, KnowledgeStore, TrialCase, TrialCosts};
use symbiote_memory::Store;
use symbiote_reasoning::planning::{Edge, GraphSchema};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "symbiote-query-{}-{}",
            std::process::id(),
            symbiote_protocol::fresh_capability().unwrap()
        )))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn seeded_graph(path: &std::path::Path) {
    let owner = Store::open(path).unwrap();
    let schema = GraphSchema {
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
    };
    let fingerprint = graph_schema_fingerprint(&schema).unwrap();
    let costs = [1, 2, 3, 1];
    let map = GraphMap::new(
        schema,
        costs
            .iter()
            .enumerate()
            .map(|(edge_id, cost)| GraphObservation {
                edge_id,
                cost: *cost,
            })
            .collect(),
    )
    .unwrap();
    let record = KnowledgeRecord {
        id: "query-map".into(),
        revision: 1,
        source: "query-peer".into(),
        scope: "query-fixture".into(),
        schema_fingerprint: fingerprint.clone(),
        payload: map.to_payload().unwrap(),
        provenance: "Explicit trusted CLI test evaluator; no remote authentication claim".into(),
    };
    let acquisitions = costs.into_iter().enumerate().map(|(edge_id,cost)| {
        let id = format!("{edge_id:064x}");
        let receipt = json!({"schema":"symbiote.graph-observation/1","authority_id":"test-authority","context":"query-fixture","schema_fingerprint":fingerprint,"observer_identity":"query-peer","sequence":edge_id+1,"id":id,"edge_id":edge_id,"cost":cost});
        GraphAcquisition{id,edge_id,cost,receipt_sha256:graph_receipt_digest(&receipt).unwrap(),receipt}
    }).collect();
    let evidence = GraphTrialEvidence {
        evaluator: "query-judge".into(),
        acquisitions,
        training_tasks: vec![GraphTrainingTask {
            id: "training".into(),
            input: 3,
        }],
        cases: vec![
            TrialCase {
                id: "heldout-one".into(),
                input: 7,
                expected: 2,
                baseline: None,
                candidate: 2,
            },
            TrialCase {
                id: "heldout-two".into(),
                input: 11,
                expected: 1,
                baseline: None,
                candidate: 1,
            },
        ],
        costs: TrialCosts {
            acquisition: 400,
            verification: 4,
            adoption: 2,
            baseline: 1000,
            candidate: 450,
        },
    };
    let assessment = assess_graph(&record, &evidence).unwrap();
    KnowledgeStore::open(path, owner.identity())
        .unwrap()
        .promote_graph(record, assessment)
        .unwrap();
}

fn query(path: &std::path::Path, args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .args(args)
        .args(["--state"])
        .arg(path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn actual_offline_queries_expose_route_and_abstention_without_changing_ledgers() {
    let fixture = Fixture::new();
    seeded_graph(&fixture.0);
    let original = fs::read(fixture.0.join("knowledge.jsonl")).unwrap();
    let route = query(
        &fixture.0,
        &[
            "route",
            "--artifact",
            "query-map",
            "--from",
            "0",
            "--to",
            "3",
        ],
    );
    assert_eq!(route["route"]["nodes"], json!([0, 1, 3]));
    assert_eq!(route["route"]["cost"], 3);
    assert_eq!(route["prediction_status"], "conditionally-certified");
    let unknown = query(
        &fixture.0,
        &[
            "route",
            "--artifact",
            "query-map",
            "--from",
            "3",
            "--to",
            "0",
        ],
    );
    assert_eq!(unknown["prediction_status"], "abstained");
    assert!(unknown["route"].is_null());
    let cost = query(
        &fixture.0,
        &["predict", "--artifact", "query-map", "--input", "3"],
    );
    assert_eq!(cost["prediction"], 3);
    assert_eq!(cost["network_requests"], 0);
    let status = query(&fixture.0, &["status"]);
    assert_eq!(status["structural_artifacts"], 1);
    assert_eq!(
        status["structural_knowledge"][0]["model"]["kind"],
        "graph-map"
    );
    assert_eq!(
        original,
        fs::read(fixture.0.join("knowledge.jsonl")).unwrap()
    );
}

#[test]
fn incomplete_or_invalid_queries_are_rejected_before_creating_state() {
    let fixture = Fixture::new();
    for args in [
        vec!["predict", "--artifact", "missing"],
        vec!["predict", "--input", "3"],
        vec!["predict", "--artifact", "missing", "--input", "-1"],
        vec!["route", "--artifact", "map", "--from", "0"],
        vec![
            "route",
            "--artifact",
            "map",
            "--from",
            "99999999999999999999999",
            "--to",
            "1",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_symbiote"))
            .args(args)
            .arg("--state")
            .arg(&fixture.0)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(!fixture.0.exists());
    }
}
