use super::*;
use crate::knowledge::KnowledgeStore;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use symbiote_reasoning::planning::Edge;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let number = crate::TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "symbiote-graph-memory-test-{}-{number}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let (Ok(path), Ok(temp)) = (self.0.canonicalize(), std::env::temp_dir().canonicalize())
        else {
            return;
        };
        if path.parent() == Some(temp.as_path())
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("symbiote-graph-memory-test-"))
        {
            let _ = fs::remove_dir_all(path);
        }
    }
}

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

#[test]
fn twelve_node_domain_roundtrips_exactly_without_widening_route_outputs() {
    for nodes in [10, 12] {
        let schema = GraphSchema {
            nodes,
            edges: (1..nodes)
                .map(|to| Edge {
                    from: to - 1,
                    to,
                    lower: 1,
                    upper: 9,
                })
                .collect(),
        };
        let map = GraphMap::new(
            schema.clone(),
            (0..nodes - 1)
                .map(|edge_id| GraphObservation { edge_id, cost: 1 })
                .collect(),
        )
        .unwrap();
        let raw = serde_json::to_vec(&map).unwrap();
        let restored: GraphMap = serde_json::from_slice(&raw).unwrap();
        let input = encode_query(nodes, 0, nodes - 1).unwrap();
        assert_eq!(decode_query(nodes, input).unwrap(), (0, nodes - 1));
        let before = forecast_work_units().unwrap();
        assert_eq!(restored.predict(input).unwrap(), Some((nodes - 1) as u8));
        let delta = forecast_work_units().unwrap() - before;
        let mut reference = RouteLearner::new(schema, PREDICTION_WORK_BUDGET).unwrap();
        for observation in &map.observations {
            reference
                .observe(observation.edge_id, observation.cost)
                .unwrap();
        }
        assert_eq!(
            reference
                .assess(0, nodes - 1)
                .unwrap()
                .certified
                .unwrap()
                .cost,
            (nodes - 1) as u64
        );
        assert_eq!(delta, reference.model_work() as u64);
        let costly = GraphMap::new(
            map.schema,
            (0..nodes - 1)
                .map(|edge_id| GraphObservation { edge_id, cost: 9 })
                .collect(),
        )
        .unwrap();
        assert_eq!(
            costly.forecast(input).unwrap().unwrap().cost,
            ((nodes - 1) * 9) as u64
        );
        assert!(costly
            .predict(input)
            .unwrap_err()
            .contains("bounded domain"));
    }
    assert!(GraphMap::new(
        GraphSchema {
            nodes: 13,
            edges: vec![Edge {
                from: 0,
                to: 12,
                lower: 1,
                upper: 9
            }]
        },
        vec![]
    )
    .is_err());
    assert!(encode_query(13, 0, 12).is_err());
    assert!(decode_query(13, 12).is_err());
}
fn fixture_record(observations: &[(usize, u16)]) -> KnowledgeRecord {
    let map = GraphMap::new(
        diamond(),
        observations
            .iter()
            .map(|(edge_id, cost)| GraphObservation {
                edge_id: *edge_id,
                cost: *cost,
            })
            .collect(),
    )
    .unwrap();
    KnowledgeRecord {
        id: "graph-context-a".into(),
        revision: 1,
        source: "authorized-peer".into(),
        scope: "graph-world-a".into(),
        schema_fingerprint: graph_schema_fingerprint(&map.schema).unwrap(),
        payload: map.to_payload().unwrap(),
        provenance: "Trusted laboratory fixture; registry authentication is external to memory"
            .into(),
    }
}
fn fixture_evidence(
    record: &KnowledgeRecord,
    queries: &[(u16, u8, Option<u8>)],
) -> GraphTrialEvidence {
    let map = GraphMap::from_record(record).unwrap();
    GraphTrialEvidence {
        evaluator:"independent-graph-judge".into(),
        acquisitions:map.observations.iter().map(|observation| {
            let id = format!("{:064x}",observation.edge_id+1);
            let receipt = json!({"schema":"symbiote.graph-observation/1","authority_id":"fixture-epoch-1","context":record.scope,"schema_fingerprint":record.schema_fingerprint,"observer_identity":"persistent-observer-uuid","sequence":observation.edge_id,"id":id,"edge_id":observation.edge_id,"cost":observation.cost});
            GraphAcquisition {id,edge_id:observation.edge_id,cost:observation.cost,receipt_sha256:graph_receipt_digest(&receipt).unwrap(),receipt}
        }).collect(),
        training_tasks:vec![],
        cases:queries.iter().map(|(input,expected,baseline)| TrialCase {id:format!("heldout-route-{input}"),input:*input,expected:*expected,baseline:*baseline,candidate:*expected}).collect(),
        costs:TrialCosts {acquisition:2,verification:2,adoption:1,baseline:20,candidate:10},
    }
}

#[test]
fn graph_paths_are_conditional_and_uncertain_unreachable_queries_abstain() {
    let record = fixture_record(&[(0, 1), (1, 1)]);
    let query = encode_query(4, 0, 3).unwrap();
    let route = record.graph_forecast(query).unwrap().unwrap();
    assert_eq!(route.edges, vec![0, 1]);
    assert_eq!(route.nodes, vec![0, 1, 3]);
    assert_eq!(route.cost, 2);
    assert!(route.conditional);
    assert_eq!(route.cost_basis, "observed_edge_costs");
    assert_eq!(record.predict(query).unwrap(), 2);
    assert_eq!(
        record
            .predict_if_certified(encode_query(4, 0, 2).unwrap())
            .unwrap(),
        None
    );
    assert!(record.predict(encode_query(4, 0, 2).unwrap()).is_err());
    assert_eq!(
        record
            .graph_forecast(encode_query(4, 3, 0).unwrap())
            .unwrap(),
        None
    );
    assert!(record.predict_if_certified(0).is_err());
    assert!(decode_query(4, u16::MAX).is_err());
}

#[test]
fn strict_schema_order_bounds_and_checked_maximum_cost_are_enforced() {
    let schema = GraphSchema {
        nodes: 8,
        edges: (0..7)
            .map(|node| Edge {
                from: node,
                to: node + 1,
                lower: 1,
                upper: 9,
            })
            .collect(),
    };
    let map = GraphMap::new(
        schema.clone(),
        (0..7)
            .rev()
            .map(|edge_id| GraphObservation { edge_id, cost: 9 })
            .collect(),
    )
    .unwrap();
    assert_eq!(
        map.predict(encode_query(8, 0, 7).unwrap()).unwrap(),
        Some(63)
    );
    let mut wide = schema.clone();
    wide.nodes = 9;
    assert!(graph_schema_fingerprint(&wide).is_ok()); // Newly supported exact domain.
    wide.nodes = 13;
    assert!(graph_schema_fingerprint(&wide).is_err());
    let mut expensive = schema;
    expensive.edges[0].upper = 10;
    assert!(graph_schema_fingerprint(&expensive).is_err());
    assert!(GraphMap::new(
        diamond(),
        vec![
            GraphObservation {
                edge_id: 0,
                cost: 1
            },
            GraphObservation {
                edge_id: 0,
                cost: 1
            }
        ]
    )
    .is_err());
    let mut record = fixture_record(&[(0, 1), (1, 1)]);
    record.payload["execute"] = json!("no executable grammar");
    assert!(record.validate().is_err());
    record.payload.as_object_mut().unwrap().remove("execute");
    record.payload["observations"][0]["cost"] = json!(0);
    assert!(record.validate().is_err());
    let mut reordered = diamond();
    reordered.edges.swap(0, 1);
    assert_ne!(
        graph_schema_fingerprint(&diamond()).unwrap(),
        graph_schema_fingerprint(&reordered).unwrap()
    );
}

#[test]
fn proof_envelopes_bind_exact_map_scope_schema_identity_and_epoch() {
    let record = fixture_record(&[(0, 1), (1, 1)]);
    let evidence = fixture_evidence(&record, &[(3, 2, None)]);
    assert!(assess_graph(&record, &evidence).is_ok());
    for field in [
        "context",
        "schema_fingerprint",
        "schema",
        "authority_id",
        "id",
        "observer_identity",
    ] {
        let mut changed = evidence.clone();
        changed.acquisitions[0].receipt[field] = json!(if field == "observer_identity" {
            ""
        } else {
            "different"
        });
        changed.acquisitions[0].receipt_sha256 =
            graph_receipt_digest(&changed.acquisitions[0].receipt).unwrap();
        assert!(assess_graph(&record, &changed).is_err(), "field {field}");
    }
    let mut changed = evidence.clone();
    changed.acquisitions[0].cost = 2;
    assert!(assess_graph(&record, &changed).is_err());
    let mut changed = evidence.clone();
    changed.acquisitions[0].receipt["unrecognized"] = json!(true);
    changed.acquisitions[0].receipt_sha256 =
        graph_receipt_digest(&changed.acquisitions[0].receipt).unwrap();
    assert!(assess_graph(&record, &changed).is_err());
    let mut changed = evidence.clone();
    changed.acquisitions[0].receipt_sha256 = "0".repeat(64);
    assert!(assess_graph(&record, &changed).is_err());
    let mut changed = evidence.clone();
    changed.acquisitions[1].receipt["sequence"] = json!(0);
    changed.acquisitions[1].receipt_sha256 =
        graph_receipt_digest(&changed.acquisitions[1].receipt).unwrap();
    assert!(assess_graph(&record, &changed).is_err());
    let mut changed = evidence;
    changed.acquisitions.pop();
    assert!(assess_graph(&record, &changed).is_err());
}

#[test]
fn edge_and_task_units_are_distinct_but_route_task_leakage_is_rejected() {
    let record = fixture_record(&[(0, 1), (1, 1)]);
    // Numeric edge id 1 and encoded route query 1 are different units.
    let mut evidence = fixture_evidence(&record, &[(1, 1, None)]);
    evidence.training_tasks.push(GraphTrainingTask {
        id: "warmup-route".into(),
        input: 3,
    });
    assert!(assess_graph(&record, &evidence).is_ok());
    let mut changed = evidence.clone();
    changed.training_tasks[0].input = 1;
    assert!(assess_graph(&record, &changed).is_err());
    let mut changed = evidence.clone();
    changed.training_tasks[0].id = changed.cases[0].id.clone();
    assert!(assess_graph(&record, &changed).is_err());
    let mut changed = evidence;
    changed.cases.push(changed.cases[0].clone());
    assert!(assess_graph(&record, &changed).is_err());
}

#[test]
fn uncertified_candidates_forged_metrics_and_unmeasured_gain_fail() {
    let record = fixture_record(&[(0, 1), (1, 1)]);
    let evidence = fixture_evidence(&record, &[(3, 2, None)]);
    let uncertain = fixture_record(&[(0, 1)]);
    assert!(assess_graph(&uncertain, &fixture_evidence(&uncertain, &[(3, 2, None)])).is_err());
    let mut changed = evidence.clone();
    changed.costs.candidate = 4;
    assert!(assess_graph(&record, &changed).is_err());
    let mut changed = evidence.clone();
    changed.cases[0].expected = 0;
    changed.cases[0].candidate = 0;
    assert!(assess_graph(&record, &changed).is_err());
    let mut changed = evidence.clone();
    changed.cases[0].baseline = Some(2);
    changed.costs.candidate = changed.costs.baseline;
    assert!(assess_graph(&record, &changed).is_err());
    changed.costs.candidate = 10;
    assert!(assess_graph(&record, &changed).unwrap().cost_improved);
    let dir = Directory::new();
    let mut store = KnowledgeStore::open(&dir.0, "graph-owner").unwrap();
    let mut serialized = serde_json::to_value(assess_graph(&record, &evidence).unwrap()).unwrap();
    serialized["candidate_cost"] = json!(0);
    let forged: GraphAssessment = serde_json::from_value(serialized).unwrap();
    assert!(store.promote_graph(record, forged).is_err());
    assert_eq!(store.record_count(), 1);
}

#[test]
fn retained_edges_cannot_change_or_disappear_even_with_identical_route_cost() {
    let dir = Directory::new();
    let original = fixture_record(&[(0, 1), (1, 1), (2, 3), (3, 3)]);
    let mut store = KnowledgeStore::open(&dir.0, "graph-owner").unwrap();
    store
        .promote_graph(
            original.clone(),
            assess_graph(&original, &fixture_evidence(&original, &[(3, 2, None)])).unwrap(),
        )
        .unwrap();
    for observations in [
        &[(0, 1), (1, 1), (2, 2), (3, 3)][..],
        &[(0, 1), (1, 1), (2, 3)][..],
    ] {
        let mut next = fixture_record(observations);
        next.revision = 2;
        let assessment = assess_graph(&next, &fixture_evidence(&next, &[(3, 2, Some(2))])).unwrap();
        let error = store.promote_graph(next, assessment).unwrap_err();
        assert!(error.contains("edges changed or disappeared"), "{error}");
    }
    assert_eq!(store.active(), vec![original]);
    assert_eq!(store.record_count(), 2);
}

#[test]
fn baseline_abstention_binding_retained_queries_and_revocation_survive_restart() {
    let dir = Directory::new();
    let first = fixture_record(&[(0, 1), (1, 1)]);
    let mut store = KnowledgeStore::open(&dir.0, "graph-owner").unwrap();
    store
        .promote_graph(
            first.clone(),
            assess_graph(&first, &fixture_evidence(&first, &[(3, 2, None)])).unwrap(),
        )
        .unwrap();
    let mut next = fixture_record(&[(0, 1), (1, 1), (2, 3), (3, 3)]);
    next.revision = 2;
    let fake_baseline = fixture_evidence(&next, &[(2, 3, Some(2))]);
    assert!(store
        .promote_graph(next.clone(), assess_graph(&next, &fake_baseline).unwrap())
        .unwrap_err()
        .contains("baseline"));
    store
        .promote_graph(
            next.clone(),
            assess_graph(&next, &fixture_evidence(&next, &[(2, 3, None)])).unwrap(),
        )
        .unwrap();
    assert_eq!(store.retained_expected[&first.id].len(), 2);
    drop(store);
    let mut store = KnowledgeStore::open(&dir.0, "graph-owner").unwrap();
    assert_eq!(store.retained_expected[&first.id].len(), 2);
    assert_eq!(
        store.graph_evidence(&first.id).unwrap().acquisitions.len(),
        4
    );
    assert_eq!(store.active()[0].predict(3).unwrap(), 2);
    store
        .revoke(
            &first.id,
            "observed context drift; explicit reset of active stationary assumptions",
        )
        .unwrap();
    assert!(store.graph_evidence(&first.id).is_none());
    assert!(store
        .promote_graph(
            next.clone(),
            assess_graph(&next, &fixture_evidence(&next, &[(3, 2, None)])).unwrap()
        )
        .is_err());
    let mut alias = next.clone();
    alias.id = "alias".into();
    alias.revision = 1;
    assert!(store
        .promote_graph(
            alias.clone(),
            assess_graph(&alias, &fixture_evidence(&alias, &[(3, 2, None)])).unwrap()
        )
        .is_err());
    let mut changed = fixture_record(&[(0, 2), (1, 1), (2, 3), (3, 3)]);
    changed.revision = 3;
    store
        .promote_graph(
            changed.clone(),
            assess_graph(&changed, &fixture_evidence(&changed, &[(3, 3, None)])).unwrap(),
        )
        .unwrap();
    drop(store);
    let store = KnowledgeStore::open(&dir.0, "graph-owner").unwrap();
    assert_eq!(store.highest_revision(&first.id), Some(3));
    assert_eq!(store.active()[0].predict(3).unwrap(), 3);
}

#[test]
fn graph_append_preserves_frozen_affine_bytes_and_migrates_with_full_proofs() {
    let dir = Directory::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let frozen = fs::read(root.join("experiments/v0.2/symbiote-knowledge.jsonl")).unwrap();
    let genesis: Value =
        serde_json::from_slice(frozen.split(|byte| *byte == b'\n').next().unwrap()).unwrap();
    let identity = genesis["payload"]["identity"].as_str().unwrap();
    fs::write(dir.0.join("knowledge.jsonl"), &frozen).unwrap();
    let record = fixture_record(&[(0, 1), (1, 1)]);
    let evidence = fixture_evidence(&record, &[(3, 2, None)]);
    let mut store = KnowledgeStore::open(&dir.0, identity).unwrap();
    store
        .promote_graph(record.clone(), assess_graph(&record, &evidence).unwrap())
        .unwrap();
    let committed = fs::read(store.ledger_path()).unwrap();
    assert!(committed.starts_with(&frozen));
    drop(store);
    assert_eq!(
        crate::maintenance::inspect(&dir.0)
            .unwrap()
            .ledger_integrity,
        "verified_snapshot"
    );
    crate::maintenance::migrate(&dir.0).unwrap();
    assert_eq!(fs::read(dir.0.join("knowledge.jsonl")).unwrap(), committed);
    assert_eq!(
        fs::read(dir.0.join("migration-backup-v1/knowledge.jsonl")).unwrap(),
        committed
    );
    let store = KnowledgeStore::open(&dir.0, identity).unwrap();
    assert_eq!(store.active().len(), 25);
    assert_eq!(store.graph_evidence(&record.id).unwrap(), evidence);
}
