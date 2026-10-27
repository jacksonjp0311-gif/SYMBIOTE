use super::*;
use crate::knowledge::{
    affine_schema_fingerprint, assess, KnowledgeStore, TrialCase, TrialCosts, TrialEvidence,
};
use crate::operational::{body_digest, IdempotencyKey, OperationalEvent, OperationalJournal};
use std::sync::{atomic::Ordering, Arc};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let n = crate::TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("symbiote-backup-test-{}-{n}", std::process::id()));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if let (Ok(path), Ok(temp)) = (self.0.canonicalize(), std::env::temp_dir().canonicalize()) {
            if path.parent() == Some(temp.as_path())
                && path
                    .file_name()
                    .and_then(|v| v.to_str())
                    .is_some_and(|v| v.starts_with("symbiote-backup-test-"))
            {
                let _ = fs::remove_dir_all(path);
            }
        }
    }
}
fn fixture(path: &Path) -> (String, KnowledgeRecord) {
    let owner = Arc::new(Store::open(path).unwrap());
    let identity = owner.identity().to_owned();
    let record = KnowledgeRecord {
        id: "retained-affine".into(),
        revision: 1,
        source: "peer-a".into(),
        scope: "affine-world".into(),
        schema_fingerprint: affine_schema_fingerprint(3).unwrap(),
        payload: json!({"kind":"affine","width":3,"coefficients":3,"bias":false}),
        provenance: "independent manual fixture; never network expected labels".into(),
    };
    let evidence = TrialEvidence {
        evaluator: "independent-local-fixture".into(),
        training_case_ids: vec!["train-0".into(), "train-1".into()],
        training_inputs: vec![0, 1],
        cases: (2_u16..8)
            .map(|input| {
                let prediction = ((input & 3).count_ones() % 2) as u8;
                TrialCase {
                    id: format!("heldout-{input}"),
                    input,
                    expected: prediction,
                    baseline: None,
                    candidate: prediction,
                }
            })
            .collect(),
        costs: TrialCosts {
            acquisition: 2,
            verification: 6,
            adoption: 1,
            baseline: 20,
            candidate: 10,
        },
    };
    let mut knowledge = KnowledgeStore::open(path, &identity).unwrap();
    knowledge
        .promote(record.clone(), assess(&record, &evidence).unwrap())
        .unwrap();
    let mut journal =
        OperationalJournal::open(Arc::clone(&owner), "configured-service/v1", &"a".repeat(64))
            .unwrap();
    let key = IdempotencyKey {
        peer_id: "peer-a".into(),
        operation: "submit".into(),
        scope: record.scope.clone(),
        request_id: "once".into(),
    };
    let body = json!({"inert":"candidate"});
    journal
        .append(OperationalEvent::Quarantined {
            key,
            candidate_id: "candidate-once".into(),
            body_sha256: body_digest(&body).unwrap(),
            body,
            response: json!({"status":"QUARANTINED"}),
        })
        .unwrap();
    let response = json!({"status":"PROMOTED","revision":1});
    journal
        .append(OperationalEvent::EvaluationPrepared {
            candidate_id: "candidate-once".into(),
            record: record.clone(),
            fixture_sha256: "b".repeat(64),
            response: response.clone(),
        })
        .unwrap();
    journal
        .append(OperationalEvent::EvaluationCompleted {
            candidate_id: "candidate-once".into(),
            record_sha256: record.digest().unwrap(),
            response,
        })
        .unwrap();
    journal
        .append(OperationalEvent::PeerDenied {
            peer_id: "peer-a".into(),
            reason: "explicit operator denial survives backup".into(),
        })
        .unwrap();
    drop(journal);
    drop(knowledge);
    drop(owner);
    (identity, record)
}
fn prefix(path: &Path) {
    let bytes = fs::read(path).unwrap();
    let end = bytes.iter().position(|b| *b == b'\n').unwrap() + 1;
    fs::write(path, &bytes[..end]).unwrap();
}

fn strategy_task(context: &str) -> symbiote_reasoning::query_strategy::GraphTask {
    use symbiote_reasoning::planning::{Edge, GraphSchema};
    symbiote_reasoning::query_strategy::GraphTask {
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
fn strategy_record() -> crate::strategy::StrategyRecord {
    use symbiote_reasoning::query_strategy::{derive_policy, EdgeObservation, SourceTrace};
    let training = ["backup-source-a", "backup-source-b"]
        .into_iter()
        .map(|context| {
            let task = strategy_task(context);
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
        .collect::<Vec<_>>();
    crate::strategy::StrategyRecord {
        id: "backup-query-policy".into(),
        revision: 1,
        source: "authorized-fixture".into(),
        policy: derive_policy(&training, 1000).unwrap().policy,
        training,
        provenance: "independent fixture observations; no target oracle disclosure".into(),
    }
}

#[test]
fn strategy_backup_restore_preserves_selection_and_counterexample_revocation() {
    use crate::strategy::{StrategyLedger, STRATEGY_FILE, STRATEGY_OWNER_FILE};
    use symbiote_reasoning::query_strategy::{run_trial, TrialLimits};
    let dir = Directory::new();
    let source = dir.path("strategy-source");
    let owner = Arc::new(Store::open(&source).unwrap());
    let identity = owner.identity().to_string();
    let mut strategy = StrategyLedger::open(owner).unwrap();
    assert!(
        strategy
            .consider(
                strategy_record(),
                vec![strategy_task("backup-cal-a"), strategy_task("backup-cal-b")]
            )
            .unwrap()
            .promoted
    );
    drop(strategy);
    let before_ledger = fs::read(source.join(STRATEGY_FILE)).unwrap();
    let before_marker = fs::read(source.join(STRATEGY_OWNER_FILE)).unwrap();
    assert_eq!(maintenance::migrate(&source).unwrap().layout_version, 2);
    let bundle = dir.path("strategy-bundle");
    let report = create(&source, &bundle, &BackupOptions::default()).unwrap();
    let manifest: BackupManifest =
        serde_json::from_slice(&fs::read(bundle.join(MANIFEST)).unwrap()).unwrap();
    assert_eq!(manifest.ledger_formats.get(STRATEGY_FILE), Some(&1));
    assert_eq!(
        verify(&bundle, &report.manifest_sha256).unwrap().identity,
        identity
    );
    let restored = dir.path("strategy-restored");
    restore(&bundle, &report.manifest_sha256, &restored).unwrap();
    assert_eq!(
        fs::read(restored.join(STRATEGY_FILE)).unwrap(),
        before_ledger
    );
    assert_eq!(
        fs::read(restored.join(STRATEGY_OWNER_FILE)).unwrap(),
        before_marker
    );
    let owner = Arc::new(Store::open(&restored).unwrap());
    assert_eq!(owner.identity(), identity);
    let mut strategy = StrategyLedger::open(owner).unwrap();
    let selected = strategy.selected().unwrap();
    let trial = run_trial(
        &strategy_task("restored-future"),
        Some(&selected.policy),
        TrialLimits {
            max_queries: 24,
            model_work: 10_000,
            policy_work: 10_000,
        },
    )
    .unwrap();
    assert!(trial.certified_correctly());
    assert_eq!(trial.queried_edges, vec![1, 3, 2]);
    let mut harmful = strategy_task("restored-counterexample");
    harmful.costs = vec![9, 1, 1, 1];
    assert!(strategy
        .revoke_for_counterexample(&selected.id, harmful)
        .unwrap()
        .query_regression());
    drop(strategy);
    let second = dir.path("revoked-bundle");
    let report = create(&restored, &second, &BackupOptions::default()).unwrap();
    let final_state = dir.path("revoked-restored");
    restore(&second, &report.manifest_sha256, &final_state).unwrap();
    let owner = Arc::new(Store::open(&final_state).unwrap());
    let mut strategy = StrategyLedger::open(owner).unwrap();
    assert!(strategy.selected().is_none());
    let mut alias = strategy_record();
    alias.id = "renamed-policy".into();
    alias.source = "renamed-source".into();
    for (i, row) in alias.training.iter_mut().enumerate() {
        row.context = format!("renamed-training-{i}");
    }
    let denied = strategy
        .consider(
            alias,
            vec![strategy_task("new-cal-a"), strategy_task("new-cal-b")],
        )
        .unwrap();
    assert!(!denied.promoted);
    assert_eq!(denied.assessment.regression_checks.len(), 1);
    assert!(strategy.selected().is_none());
}

#[test]
fn incomplete_strategy_or_foreign_owner_proof_prevents_backup_before_publication() {
    use crate::strategy::{StrategyLedger, STRATEGY_FILE, STRATEGY_OWNER_FILE};
    let dir = Directory::new();
    let source = dir.path("source");
    let other = dir.path("foreign-owner");
    drop(StrategyLedger::open(Arc::new(Store::open(&source).unwrap())).unwrap());
    drop(StrategyLedger::open(Arc::new(Store::open(&other).unwrap())).unwrap());
    let marker = fs::read(source.join(STRATEGY_OWNER_FILE)).unwrap();
    let journal = fs::read(source.join(STRATEGY_FILE)).unwrap();
    fs::remove_file(source.join(STRATEGY_OWNER_FILE)).unwrap();
    assert!(maintenance::inspect(&source).is_err());
    assert!(maintenance::migrate(&source).is_err());
    assert!(create(
        &source,
        &dir.path("missing-pair"),
        &BackupOptions::default()
    )
    .is_err());
    assert!(!dir.path("missing-pair").exists());
    fs::write(
        source.join(STRATEGY_OWNER_FILE),
        fs::read(other.join(STRATEGY_OWNER_FILE)).unwrap(),
    )
    .unwrap();
    assert!(maintenance::inspect(&source).is_err());
    assert!(maintenance::migrate(&source).is_err());
    assert!(create(
        &source,
        &dir.path("foreign-pair"),
        &BackupOptions::default()
    )
    .is_err());
    assert!(!dir.path("foreign-pair").exists());
    assert_eq!(fs::read(source.join(STRATEGY_FILE)).unwrap(), journal);
    fs::write(source.join(STRATEGY_OWNER_FILE), marker).unwrap();
    assert!(maintenance::inspect(&source).is_ok());
}

#[test]
fn registered_legacy_owner_explicitly_adds_strategy_without_rewriting_history() {
    use crate::strategy::{StrategyLedger, STRATEGY_FILE, STRATEGY_OWNER_FILE};
    let dir = Directory::new();
    let source = dir.path("legacy-source");
    let (identity, record) = fixture(&source);
    assert_eq!(maintenance::migrate(&source).unwrap().layout_version, 1);
    let original = gather(&source).unwrap();
    let old_layout = fs::read(source.join("state-layout.json")).unwrap();
    let mut prepared = StrategyLedger::open(Arc::new(Store::open(&source).unwrap())).unwrap();
    let before_learning = fs::read(source.join(STRATEGY_FILE)).unwrap();
    assert!(prepared
        .consider(
            strategy_record(),
            vec![
                strategy_task("pre-upgrade-cal-a"),
                strategy_task("pre-upgrade-cal-b")
            ]
        )
        .is_err());
    assert_eq!(
        fs::read(source.join(STRATEGY_FILE)).unwrap(),
        before_learning
    );
    drop(prepared);
    let strategy = fs::read(source.join(STRATEGY_FILE)).unwrap();
    let marker = fs::read(source.join(STRATEGY_OWNER_FILE)).unwrap();
    let migrated = maintenance::migrate(&source).unwrap();
    assert_eq!(migrated.layout_version, 2);
    assert!(migrated.changed);
    for (name, bytes) in &original {
        if name != "state-layout.json" && name != "maintenance-audit.jsonl" {
            assert_eq!(
                &fs::read(source.join(name)).unwrap(),
                bytes,
                "legacy evidence changed: {name}"
            );
        }
    }
    assert_eq!(
        fs::read(source.join("migration-backup-v2/previous-state-layout.json")).unwrap(),
        old_layout
    );
    assert_eq!(fs::read(source.join(STRATEGY_FILE)).unwrap(), strategy);
    assert_eq!(fs::read(source.join(STRATEGY_OWNER_FILE)).unwrap(), marker);
    let owner = Store::open(&source).unwrap();
    assert_eq!(owner.identity(), identity);
    let knowledge = KnowledgeStore::open(&source, &identity).unwrap();
    assert!(knowledge.has_historical_promotion(&record).unwrap());
    drop(knowledge);
    drop(owner);
    let bundle = dir.path("upgraded-backup");
    let receipt = create(&source, &bundle, &BackupOptions::default()).unwrap();
    let restored = dir.path("upgraded-restore");
    restore(&bundle, &receipt.manifest_sha256, &restored).unwrap();
    assert_eq!(fs::read(restored.join(STRATEGY_FILE)).unwrap(), strategy);
    assert_eq!(
        fs::read(restored.join(STRATEGY_OWNER_FILE)).unwrap(),
        marker
    );
    assert_eq!(Store::open(&restored).unwrap().identity(), identity);
}

#[test]
fn bytes_predictions_history_denials_idempotency_and_migration_survive_restore() {
    let dir = Directory::new();
    let source = dir.path("source");
    let (identity, record) = fixture(&source);
    maintenance::migrate(&source).unwrap();
    let original = gather(&source).unwrap();
    let bundle = dir.path("bundle");
    let receipt = create(&source, &bundle, &BackupOptions::default()).unwrap();
    assert!(!receipt.network_started);
    assert_eq!(
        verify(&bundle, &receipt.manifest_sha256).unwrap().identity,
        identity
    );
    let restored = dir.path("restored");
    let result = restore(&bundle, &receipt.manifest_sha256, &restored).unwrap();
    assert!(result.requires_activation);
    assert!(!result.network_started);
    for (name, bytes) in &original {
        assert_eq!(&fs::read(restored.join(name)).unwrap(), bytes);
    }
    assert_eq!(
        validate_restore_mapping(&restored, &source, &identity).unwrap(),
        result.restore_mapping_sha256
    );
    let owner = Arc::new(Store::open(&restored).unwrap());
    let knowledge = KnowledgeStore::open(&restored, &identity).unwrap();
    assert!(knowledge.has_historical_promotion(&record).unwrap());
    assert_eq!(knowledge.active()[0].predict(7).unwrap(), 0);
    let journal =
        OperationalJournal::open(Arc::clone(&owner), "configured-service/v1", &"a".repeat(64))
            .unwrap();
    assert!(journal.denied_peers().contains("peer-a"));
    assert!(journal
        .quarantined(&IdempotencyKey {
            peer_id: "peer-a".into(),
            operation: "submit".into(),
            scope: "affine-world".into(),
            request_id: "once".into()
        })
        .is_some());
    drop(journal);
    drop(knowledge);
    drop(owner);
    assert_eq!(gather(&source).unwrap(), original);
}

#[test]
fn missing_altered_or_valid_prefix_archive_never_publishes_a_destination() {
    for change in ["missing", "altered", "prefix"] {
        let dir = Directory::new();
        let source = dir.path("source");
        fixture(&source);
        let bundle = dir.path("bundle");
        let report = create(&source, &bundle, &BackupOptions::default()).unwrap();
        let file = bundle.join("files/knowledge.jsonl");
        match change {
            "missing" => fs::remove_file(&file).unwrap(),
            "altered" => fs::write(&file, b"altered\n").unwrap(),
            _ => prefix(&file),
        }
        assert!(verify(&bundle, &report.manifest_sha256).is_err());
        let target = dir.path("target");
        assert!(restore(&bundle, &report.manifest_sha256, &target).is_err());
        assert!(!target.exists());
    }
}

#[test]
fn completed_operations_reject_knowledge_prefix_rollback_and_mixed_owner() {
    let dir = Directory::new();
    let source = dir.path("source");
    fixture(&source);
    let original = fs::read(source.join("knowledge.jsonl")).unwrap();
    prefix(&source.join("knowledge.jsonl"));
    assert!(
        create(&source, &dir.path("rolled-back"), &BackupOptions::default())
            .unwrap_err()
            .contains("historical")
    );
    fs::write(source.join("knowledge.jsonl"), original).unwrap();
    let foreign = dir.path("foreign");
    fixture(&foreign);
    fs::copy(
        foreign.join("knowledge.jsonl"),
        source.join("knowledge.jsonl"),
    )
    .unwrap();
    assert!(create(&source, &dir.path("mixed"), &BackupOptions::default()).is_err());
}

#[test]
fn live_unknown_and_stale_writers_are_refused_without_lock_deletion() {
    let dir = Directory::new();
    let source = dir.path("source");
    fixture(&source);
    let live = Store::open(&source).unwrap();
    assert!(create(&source, &dir.path("live"), &BackupOptions::default()).is_err());
    drop(live);
    for content in [
        b"unknown owner\n".as_slice(),
        b"process=4294967295\n".as_slice(),
        b"process=0\n".as_slice(),
    ] {
        fs::write(source.join("knowledge.writer.lock"), content).unwrap();
        assert!(create(&source, &dir.path("unknown"), &BackupOptions::default()).is_err());
        assert_eq!(
            fs::read(source.join("knowledge.writer.lock")).unwrap(),
            content
        );
        fs::remove_file(source.join("knowledge.writer.lock")).unwrap();
    }
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .arg("--list")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn().unwrap();
    let owned_pid = child.id();
    assert!(child.wait().unwrap().success());
    let stale = format!("process={owned_pid}\n");
    fs::write(source.join("writer.lock"), &stale).unwrap();
    assert!(create(&source, &dir.path("stale"), &BackupOptions::default()).is_err());
    assert_eq!(
        fs::read_to_string(source.join("writer.lock")).unwrap(),
        stale
    );
}

#[test]
fn occupied_destination_and_interrupted_restore_cannot_activate() {
    let dir = Directory::new();
    let source = dir.path("source");
    let (identity, _) = fixture(&source);
    let bundle = dir.path("bundle");
    let report = create(&source, &bundle, &BackupOptions::default()).unwrap();
    let occupied = dir.path("occupied");
    fs::create_dir(&occupied).unwrap();
    fs::write(occupied.join("sentinel"), b"preserve").unwrap();
    assert!(restore(&bundle, &report.manifest_sha256, &occupied).is_err());
    assert_eq!(fs::read(occupied.join("sentinel")).unwrap(), b"preserve");
    let target = dir.path("interrupted");
    assert!(
        restore_internal(&bundle, &report.manifest_sha256, &target, || Err(
            "supervised cut before publication".into()
        ))
        .is_err()
    );
    assert!(target.join(INCOMPLETE).is_file());
    assert!(reservation(&target).unwrap().is_file());
    assert!(Store::open(&target).is_err());
    assert!(KnowledgeStore::open(&target, &identity).is_err());
    assert!(validate_restore_mapping(&target, &source, &identity).is_err());
}

#[test]
fn relocation_source_may_be_absent_and_future_mutation_invalidates_old_mapping() {
    let dir = Directory::new();
    let source = dir.path("source");
    let (identity, _) = fixture(&source);
    let bundle = dir.path("bundle");
    let report = create(&source, &bundle, &BackupOptions::default()).unwrap();
    let target = dir.path("restored");
    restore(&bundle, &report.manifest_sha256, &target).unwrap();
    assert!(source.starts_with(&dir.0));
    fs::remove_dir_all(&source).unwrap();
    assert!(validate_restore_mapping(&target, &source, &identity).is_ok());
    let owner = Arc::new(Store::open(&target).unwrap());
    let mut journal =
        OperationalJournal::open(Arc::clone(&owner), "configured-service/v1", &"a".repeat(64))
            .unwrap();
    journal
        .append(OperationalEvent::PeerDenied {
            peer_id: "peer-b".into(),
            reason: "later explicit action".into(),
        })
        .unwrap();
    assert!(validate_restore_mapping(&target, &source, &identity).is_err());
}

#[test]
fn unknown_sidecars_and_child_stores_are_never_silently_omitted() {
    let dir = Directory::new();
    let source = dir.path("source");
    fixture(&source);
    fs::write(source.join("unknown-critical.json"), b"{}").unwrap();
    assert!(create(&source, &dir.path("unknown"), &BackupOptions::default()).is_err());
    fs::remove_file(source.join("unknown-critical.json")).unwrap();
    fs::create_dir(source.join("graph")).unwrap();
    fixture(&source.join("graph/another-owner"));
    assert!(create(&source, &dir.path("children"), &BackupOptions::default()).is_err());
}

#[test]
fn rebackup_preserves_historical_restore_markers_as_exact_bytes() {
    let dir = Directory::new();
    let source = dir.path("source");
    let (identity, _) = fixture(&source);
    let first = dir.path("first");
    let a = create(&source, &first, &BackupOptions::default()).unwrap();
    let restored = dir.path("restored");
    let r = restore(&first, &a.manifest_sha256, &restored).unwrap();
    let marker = fs::read(restored.join(marker_name(&r.restore_mapping_sha256))).unwrap();
    let second = dir.path("second");
    let b = create(&restored, &second, &BackupOptions::default()).unwrap();
    let next = dir.path("next");
    restore(&second, &b.manifest_sha256, &next).unwrap();
    assert_eq!(
        fs::read(next.join(marker_name(&r.restore_mapping_sha256))).unwrap(),
        marker
    );
    assert!(validate_restore_mapping(&next, &restored, &identity).is_ok());
}

fn graph_record(scope: &str, native: bool) -> KnowledgeRecord {
    use crate::knowledge::graph::{GraphMap, GraphObservation};
    use symbiote_reasoning::planning::{Edge, GraphSchema};
    let schema = if native {
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
    } else {
        GraphSchema {
            nodes: 2,
            edges: vec![Edge {
                from: 0,
                to: 1,
                lower: 1,
                upper: 3,
            }],
        }
    };
    let observations = if native {
        vec![
            GraphObservation {
                edge_id: 0,
                cost: 1,
            },
            GraphObservation {
                edge_id: 1,
                cost: 1,
            },
        ]
    } else {
        vec![GraphObservation {
            edge_id: 0,
            cost: 2,
        }]
    };
    let map = GraphMap::new(schema, observations).unwrap();
    KnowledgeRecord {
        id: "retained-graph".into(),
        revision: 1,
        source: "graph-peer".into(),
        scope: scope.into(),
        schema_fingerprint: crate::knowledge::graph::graph_schema_fingerprint(&map.schema).unwrap(),
        payload: map.to_payload().unwrap(),
        provenance: "bounded manually observed graph; no research registry needed for generic maps"
            .into(),
    }
}
fn promote_graph(path: &Path, identity: &str, record: &KnowledgeRecord, native: bool) {
    use crate::knowledge::graph::{
        assess_graph, graph_receipt_digest, GraphAcquisition, GraphTrialEvidence,
    };
    let crate::knowledge::KnowledgePayload::GraphMap(map) = record.typed_payload().unwrap() else {
        panic!("manual graph fixture required")
    };
    let acquisitions=map.observations.iter().map(|observation|{
        let id=format!("{:064x}",observation.edge_id+1);
        let receipt=json!({"schema":"symbiote.graph-observation/1","authority_id":"manual-epoch","context":record.scope,"schema_fingerprint":record.schema_fingerprint,"observer_identity":identity,"sequence":observation.edge_id,"id":id,"edge_id":observation.edge_id,"cost":observation.cost});
        GraphAcquisition{id,edge_id:observation.edge_id,cost:observation.cost,receipt_sha256:graph_receipt_digest(&receipt).unwrap(),receipt}
    }).collect();
    let tasks = if native {
        vec![(1, 1), (3, 2)]
    } else {
        vec![(1, 2)]
    };
    let evidence = GraphTrialEvidence {
        evaluator: "manual-graph-evaluator".into(),
        acquisitions,
        training_tasks: vec![],
        cases: tasks
            .into_iter()
            .map(|(input, cost)| TrialCase {
                id: format!("heldout-route-{input}"),
                input,
                expected: cost,
                baseline: None,
                candidate: cost,
            })
            .collect(),
        costs: TrialCosts {
            acquisition: 2,
            verification: 2,
            adoption: 1,
            baseline: 20,
            candidate: 10,
        },
    };
    let mut store = KnowledgeStore::open(path, identity).unwrap();
    store
        .promote_graph(record.clone(), assess_graph(record, &evidence).unwrap())
        .unwrap();
}

#[test]
fn generic_graph_store_restores_actual_forecasts_without_a_research_registry() {
    let dir = Directory::new();
    let source = dir.path("source");
    let (identity, _) = fixture(&source);
    let record = graph_record("service-graph/v1", false);
    promote_graph(&source, &identity, &record, false);
    let bundle = dir.path("bundle");
    let report = create(&source, &bundle, &BackupOptions::default()).unwrap();
    let target = dir.path("target");
    restore(&bundle, &report.manifest_sha256, &target).unwrap();
    let store = KnowledgeStore::open(&target, &identity).unwrap();
    let retained = store
        .active()
        .into_iter()
        .find(|r| r.id == record.id)
        .unwrap();
    assert_eq!(retained.graph_forecast(1).unwrap().unwrap().cost, 2);
    assert!(store.has_historical_promotion(&record).unwrap());
}

#[test]
fn known_native_graph_registry_requires_explicit_pin_and_is_preserved() {
    let dir = Directory::new();
    let source = dir.path("source");
    let (identity, _) = fixture(&source);
    let scope = format!("graph-context-{:064x}", 1);
    let record = graph_record(&scope, true);
    promote_graph(&source, &identity, &record, true);
    assert!(create(
        &source,
        &dir.path("missing-registry"),
        &BackupOptions::default()
    )
    .is_err());
    let registry = json!({"schema":"symbiote.graph-contexts/1","controller_identity":"original-controller","schema_fingerprint":record.schema_fingerprint,"contexts":(1..=81).map(|n|format!("graph-context-{n:064x}")).collect::<Vec<_>>()});
    let bytes = serde_json::to_vec(&registry).unwrap();
    let path = dir.path("contexts.json");
    fs::write(&path, &bytes).unwrap();
    let options = BackupOptions {
        graph_context_registry: Some(RegistryDependency {
            path: path.clone(),
            expected_sha256: hash(&bytes),
        }),
    };
    let wrong = BackupOptions {
        graph_context_registry: Some(RegistryDependency {
            path: path.clone(),
            expected_sha256: "0".repeat(64),
        }),
    };
    assert!(create(&source, &dir.path("wrong-pin"), &wrong).is_err());
    let bundle = dir.path("bundle");
    let report = create(&source, &bundle, &options).unwrap();
    assert!(!source.join(REGISTRY).exists());
    let target = dir.path("target");
    restore(&bundle, &report.manifest_sha256, &target).unwrap();
    assert_eq!(fs::read(target.join(REGISTRY)).unwrap(), bytes);
    let store = KnowledgeStore::open(&target, &identity).unwrap();
    assert_eq!(
        store
            .active()
            .into_iter()
            .find(|r| r.id == record.id)
            .unwrap()
            .predict(3)
            .unwrap(),
        2
    );
}

#[test]
fn manifest_versions_metadata_pins_and_overflow_fail_before_publication() {
    let dir = Directory::new();
    let source = dir.path("source");
    fixture(&source);
    let bundle = dir.path("bundle");
    let report = create(&source, &bundle, &BackupOptions::default()).unwrap();
    let (manifest, original, _) = load_backup(&bundle, &report.manifest_sha256).unwrap();
    assert_eq!(manifest.ledger_formats.get("knowledge.jsonl"), Some(&1));
    assert_eq!(
        manifest.operational_policy_sha256.as_deref(),
        Some("a".repeat(64).as_str())
    );
    assert!(manifest
        .operational_head_sha256
        .as_deref()
        .is_some_and(is_hash));
    for attack in ["version", "os", "overflow", "policy"] {
        let mut changed = manifest.clone();
        match attack {
            "version" => changed.version = 99,
            "os" => changed.operating_system = "unverified-other-os".into(),
            "overflow" => {
                for pin in changed.files.values_mut() {
                    pin.bytes = usize::MAX;
                }
            }
            _ => changed.operational_policy_sha256 = Some("0".repeat(64)),
        }
        let raw = serde_json::to_vec(&changed).unwrap();
        fs::write(bundle.join(MANIFEST), &raw).unwrap();
        assert!(verify(&bundle, &hash(&raw)).is_err());
        assert!(restore(&bundle, &hash(&raw), &dir.path("never-published")).is_err());
        assert!(!dir.path("never-published").exists());
    }
    fs::write(bundle.join(MANIFEST), original).unwrap();
    assert!(verify(&bundle, &report.manifest_sha256).is_ok());
}

#[test]
fn rehashed_historical_restore_metadata_cannot_silently_upgrade_its_format() {
    let dir = Directory::new();
    let source = dir.path("source");
    fixture(&source);
    let bundle = dir.path("bundle");
    let receipt = create(&source, &bundle, &BackupOptions::default()).unwrap();
    let target = dir.path("target");
    let restored = restore(&bundle, &receipt.manifest_sha256, &target).unwrap();
    let marker = target.join(marker_name(&restored.restore_mapping_sha256));
    let mut mapping: RestoreMapping = serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
    let mut manifest: BackupManifest = serde_json::from_str(&mapping.manifest_json).unwrap();
    manifest.version = 99;
    mapping.manifest_json = serde_json::to_string(&manifest).unwrap();
    mapping.manifest_sha256 = hash(mapping.manifest_json.as_bytes());
    let bytes = serde_json::to_vec(&mapping).unwrap();
    fs::remove_file(marker).unwrap();
    fs::write(target.join(marker_name(&hash(&bytes))), bytes).unwrap();
    assert!(create(&target, &dir.path("unsupported"), &BackupOptions::default()).is_err());
}

#[test]
fn moved_restore_markers_remain_visible_and_metadata_survives_later_writes() {
    let dir = Directory::new();
    let source = dir.path("source");
    let (identity, _) = fixture(&source);
    let bundle = dir.path("bundle");
    let receipt = create(&source, &bundle, &BackupOptions::default()).unwrap();
    let target = dir.path("target");
    let restored = restore(&bundle, &receipt.manifest_sha256, &target).unwrap();
    let first = restore_mappings(&target, &identity).unwrap();
    assert_eq!(first.len(), 1);
    assert!(first[0].destination_matches);
    let owner = Arc::new(Store::open(&target).unwrap());
    let mut journal =
        OperationalJournal::open(Arc::clone(&owner), "configured-service/v1", &"a".repeat(64))
            .unwrap();
    journal
        .append(OperationalEvent::PeerDenied {
            peer_id: "peer-b".into(),
            reason: "later legitimate local action".into(),
        })
        .unwrap();
    drop(journal);
    drop(owner);
    assert_eq!(
        restore_mappings(&target, &identity).unwrap()[0].sha256,
        restored.restore_mapping_sha256
    );
    assert!(validate_restore_mapping(&target, &source, &identity).is_err());
    let moved = dir.path("moved");
    assert!(target.starts_with(&dir.0) && moved.starts_with(&dir.0));
    fs::rename(&target, &moved).unwrap();
    let mappings = restore_mappings(&moved, &identity).unwrap();
    assert_eq!(mappings.len(), 1);
    assert!(!mappings[0].destination_matches);
    let expected = normalize_state_location(&source).unwrap();
    assert!(source.starts_with(&dir.0));
    fs::remove_dir_all(&source).unwrap();
    assert_eq!(normalize_state_location(&source).unwrap(), expected);
    assert_eq!(mappings[0].source_state, expected);
    assert!(restore_mappings(&moved, "foreign-owner").is_err());
}

#[test]
fn consumed_path_reuse_skips_stale_snapshots_only_after_metadata_validation() {
    let dir = Directory::new();
    let a = dir.path("a");
    let (identity, _) = fixture(&a);
    let b = dir.path("b");
    let bundle1 = dir.path("bundle1");
    let first = create(&a, &bundle1, &BackupOptions::default()).unwrap();
    let r1 = restore(&bundle1, &first.manifest_sha256, &b).unwrap();
    let owner = Arc::new(Store::open(&b).unwrap());
    let mut journal =
        OperationalJournal::open(Arc::clone(&owner), "configured-service/v1", &"a".repeat(64))
            .unwrap();
    journal
        .append(OperationalEvent::PeerDenied {
            peer_id: "peer-b".into(),
            reason: "state advanced after independently reviewed restoration".into(),
        })
        .unwrap();
    drop(journal);
    drop(owner);
    let bundle2 = dir.path("bundle2");
    let second = create(&b, &bundle2, &BackupOptions::default()).unwrap();
    assert!(a.starts_with(&dir.0));
    fs::remove_dir_all(&a).unwrap();
    let r2 = restore(&bundle2, &second.manifest_sha256, &a).unwrap();
    let bundle3 = dir.path("bundle3");
    let third = create(&a, &bundle3, &BackupOptions::default()).unwrap();
    assert!(b.starts_with(&dir.0));
    fs::remove_dir_all(&b).unwrap();
    let r3 = restore(&bundle3, &third.manifest_sha256, &b).unwrap();
    assert_eq!(restore_mappings(&b, &identity).unwrap().len(), 3);
    assert!(validate_restore_mapping(&b, &a, &identity).is_err());
    // Real service callers obtain these hashes only from typed relocation
    // transactions. This unit test exercises the lower-level exclusion API.
    let mut consumed =
        BTreeSet::from([r1.restore_mapping_sha256.clone(), r2.restore_mapping_sha256]);
    assert_eq!(
        validate_restore_mapping_excluding(&b, &a, &identity, &consumed).unwrap(),
        r3.restore_mapping_sha256
    );
    let old_path = b.join(marker_name(&r1.restore_mapping_sha256));
    let mut malformed: RestoreMapping =
        serde_json::from_slice(&fs::read(&old_path).unwrap()).unwrap();
    malformed.identity = "foreign-owner".into();
    let bytes = serde_json::to_vec(&malformed).unwrap();
    let forged = hash(&bytes);
    fs::remove_file(&old_path).unwrap();
    fs::write(b.join(marker_name(&forged)), bytes).unwrap();
    consumed.insert(forged);
    assert!(
        validate_restore_mapping_excluding(&b, &a, &identity, &consumed)
            .unwrap_err()
            .contains("owner")
    );
}
