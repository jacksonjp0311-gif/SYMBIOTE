use super::*;
use crate::knowledge::affine_schema_fingerprint;
use serde_json::json;
use std::fs;
use std::path::PathBuf;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let number = crate::TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "symbiote-operational-test-{}-{number}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if let (Ok(path), Ok(temp)) = (self.0.canonicalize(), std::env::temp_dir().canonicalize()) {
            if path.parent() == Some(temp.as_path())
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("symbiote-operational-test-"))
            {
                let _ = fs::remove_dir_all(path);
            }
        }
    }
}
fn fixture_owner(dir: &Directory) -> Arc<Store> {
    Arc::new(Store::open(&dir.0).unwrap())
}
fn open(owner: &Arc<Store>) -> OperationalJournal {
    OperationalJournal::open(Arc::clone(owner), "service-a", &"a".repeat(64)).unwrap()
}
fn key(id: &str) -> IdempotencyKey {
    IdempotencyKey {
        peer_id: "peer-a".into(),
        operation: "submit".into(),
        scope: "affine-world".into(),
        request_id: id.into(),
    }
}
fn quarantined(id: &str) -> OperationalEvent {
    let body = json!({"candidate":"inert untrusted proposal","claimed_confidence":1});
    OperationalEvent::Quarantined {
        key: key(id),
        candidate_id: format!("candidate-{id}"),
        body_sha256: digest(&body).unwrap(),
        body,
        response: json!({"status":"QUARANTINED","id":id}),
    }
}
fn record() -> KnowledgeRecord {
    KnowledgeRecord {
        id: "local-artifact".into(),
        revision: 1,
        source: "peer-a".into(),
        scope: "affine-world".into(),
        schema_fingerprint: affine_schema_fingerprint(3).unwrap(),
        payload: json!({"kind":"affine","width":3,"coefficients":3,"bias":false}),
        provenance: "Operator-selected local fixture; no network truth labels".into(),
    }
}
fn prepared(id: &str) -> OperationalEvent {
    OperationalEvent::EvaluationPrepared {
        candidate_id: format!("candidate-{id}"),
        record: record(),
        fixture_sha256: "b".repeat(64),
        response: json!({"status":"PASS","promoted":true,"revision":1}),
    }
}
fn completed(id: &str) -> OperationalEvent {
    OperationalEvent::EvaluationCompleted {
        candidate_id: format!("candidate-{id}"),
        record_sha256: record().digest().unwrap(),
        response: json!({"status":"PASS","promoted":true,"revision":1}),
    }
}
fn rewrite(path: &PathBuf, modify: impl FnOnce(&mut Vec<Receipt>)) {
    let bytes = fs::read(path).unwrap();
    let mut rows: Vec<Receipt> = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    modify(&mut rows);
    let mut previous = ZERO_HASH.to_string();
    let mut bytes = Vec::new();
    for row in &mut rows {
        row.previous = previous;
        row.sha256 = row.hash().unwrap();
        previous = row.sha256.clone();
        serde_json::to_writer(&mut bytes, row).unwrap();
        bytes.push(b'\n');
    }
    fs::write(path, bytes).unwrap();
}

#[test]
fn exact_idempotency_body_binding_and_deny_survive_restart() {
    let dir = Directory::new();
    let owner = fixture_owner(&dir);
    let identity = owner.identity().to_string();
    let original = fs::read(owner.ledger_path()).unwrap();
    let mut journal = open(&owner);
    journal.append(quarantined("one")).unwrap();
    assert!(journal.quarantined(&key("one")).is_some());
    assert!(journal.append(quarantined("one")).is_err());
    let mut changed = quarantined("one");
    if let OperationalEvent::Quarantined {
        body, body_sha256, ..
    } = &mut changed
    {
        *body = json!({"different":true});
        *body_sha256 = digest(body).unwrap();
    }
    assert!(journal.append(changed).is_err());
    journal
        .append(OperationalEvent::PeerDenied {
            peer_id: "peer-a".into(),
            reason: "operator revocation".into(),
        })
        .unwrap();
    assert!(journal.append(quarantined("two")).is_err());
    let bytes = fs::read(journal.ledger_path()).unwrap();
    drop(journal);
    drop(owner);
    let owner = fixture_owner(&dir);
    let journal = open(&owner);
    assert_eq!(journal.identity(), identity);
    assert!(journal.denied_peers().contains("peer-a"));
    assert!(journal.quarantined(&key("one")).is_some());
    assert_eq!(fs::read(journal.ledger_path()).unwrap(), bytes);
    assert_eq!(fs::read(owner.ledger_path()).unwrap(), original);
    assert!(owner.active().is_empty());
}

#[test]
fn intent_completion_requires_exact_record_and_original_response() {
    let dir = Directory::new();
    let owner = fixture_owner(&dir);
    let mut journal = open(&owner);
    assert!(journal.append(completed("one")).is_err());
    journal.append(quarantined("one")).unwrap();
    let mut wrong = prepared("one");
    if let OperationalEvent::EvaluationPrepared { record, .. } = &mut wrong {
        record.source = "claimed-other-peer".into();
    }
    assert!(journal.append(wrong).is_err());
    let mut wrong = prepared("one");
    if let OperationalEvent::EvaluationPrepared { record, .. } = &mut wrong {
        record.scope = "other-context".into();
    }
    assert!(journal.append(wrong).is_err());
    journal.append(prepared("one")).unwrap();
    assert!(journal.append(prepared("one")).is_err());
    let mut wrong = completed("one");
    if let OperationalEvent::EvaluationCompleted { record_sha256, .. } = &mut wrong {
        *record_sha256 = "c".repeat(64);
    }
    assert!(journal.append(wrong).is_err());
    let mut wrong = completed("one");
    if let OperationalEvent::EvaluationCompleted { response, .. } = &mut wrong {
        *response = json!({"already_retained":true});
    }
    assert!(journal.append(wrong).is_err());
    drop(journal);
    let mut journal = open(&owner);
    journal.append(completed("one")).unwrap();
    assert!(journal.append(completed("one")).is_err());
    assert!(journal
        .append(OperationalEvent::EvaluationRejected {
            candidate_id: "candidate-one".into(),
            reason: "cannot erase completed evaluation".into()
        })
        .is_err());
    assert_eq!(journal.record_count(), 4);
}

#[test]
fn pending_intent_or_quarantine_can_be_rejected_but_never_reprepared() {
    let dir = Directory::new();
    let owner = fixture_owner(&dir);
    let mut journal = open(&owner);
    journal.append(quarantined("one")).unwrap();
    journal.append(prepared("one")).unwrap();
    journal
        .append(OperationalEvent::EvaluationRejected {
            candidate_id: "candidate-one".into(),
            reason: "local fixture counterexample, no learning commit".into(),
        })
        .unwrap();
    assert!(journal.append(prepared("one")).is_err());
    journal.append(quarantined("two")).unwrap();
    journal
        .append(OperationalEvent::EvaluationRejected {
            candidate_id: "candidate-two".into(),
            reason: "unsupported local profile".into(),
        })
        .unwrap();
    assert!(journal.append(completed("two")).is_err());
}

#[test]
fn arc_guard_excludes_competing_journals_and_survives_original_owner_drop() {
    let dir = Directory::new();
    let owner = fixture_owner(&dir);
    let identity = owner.identity().to_string();
    let journal = open(&owner);
    assert!(OperationalJournal::open(Arc::clone(&owner), "service-a", &"a".repeat(64)).is_err());
    drop(owner);
    assert!(Store::open(&dir.0).is_err());
    assert!(maintenance::recover(&dir.0).is_err());
    assert!(maintenance::migrate(&dir.0).is_err());
    drop(journal);
    let owner = fixture_owner(&dir);
    assert_eq!(owner.identity(), identity);
    drop(open(&owner));
    assert!(
        OperationalJournal::open(Arc::clone(&owner), "changed-service", &"a".repeat(64)).is_err()
    );
    assert!(OperationalJournal::open(Arc::clone(&owner), "service-a", &"b".repeat(64)).is_err());
    drop(open(&owner));
}

#[test]
fn canonical_value_receipts_preserve_prefix_and_failed_write_keeps_state_unchanged() {
    let dir = Directory::new();
    let owner = fixture_owner(&dir);
    let mut journal = open(&owner);
    journal.append(quarantined("one")).unwrap();
    let committed = fs::read(journal.ledger_path()).unwrap();
    let count = journal.record_count();
    let saved = dir.0.join("operations.saved");
    fs::rename(journal.ledger_path(), &saved).unwrap();
    fs::create_dir(journal.ledger_path()).unwrap();
    assert!(journal
        .append(OperationalEvent::PeerDenied {
            peer_id: "peer-a".into(),
            reason: "test failed filesystem commit".into()
        })
        .is_err());
    assert_eq!(journal.record_count(), count);
    assert!(journal.denied_peers().is_empty());
    fs::remove_dir(journal.ledger_path()).unwrap();
    fs::rename(saved, journal.ledger_path()).unwrap();
    assert_eq!(fs::read(journal.ledger_path()).unwrap(), committed);
    journal.append(prepared("one")).unwrap();
    assert!(fs::read(journal.ledger_path())
        .unwrap()
        .starts_with(&committed));
    drop(journal);
    // Change only object field order in the JSONL wrapper/payload. Payload
    // integrity uses Value canonicalization, not the application enum's order.
    let path = dir.0.join(FILE_NAME);
    let mut bytes = Vec::new();
    for line in fs::read_to_string(&path).unwrap().lines() {
        let value: Value = serde_json::from_str(line).unwrap();
        serde_json::to_writer(&mut bytes, &value).unwrap();
        bytes.push(b'\n');
    }
    fs::write(&path, bytes).unwrap();
    assert_eq!(open(&owner).record_count(), 3);
}

#[test]
fn corrupt_unknown_owner_policy_and_semantically_forged_records_fail_closed() {
    let dir = Directory::new();
    let owner = fixture_owner(&dir);
    let path = dir.0.join(FILE_NAME);
    let mut journal = open(&owner);
    journal.append(quarantined("one")).unwrap();
    drop(journal);
    let valid = fs::read(&path).unwrap();
    fs::write(&path, &valid[..valid.len() - 1]).unwrap();
    assert!(OperationalJournal::open(Arc::clone(&owner), "service-a", &"a".repeat(64)).is_err());
    fs::write(&path, &valid).unwrap();
    rewrite(&path, |rows| rows[0].payload["version"] = json!(99));
    assert!(OperationalJournal::open(Arc::clone(&owner), "service-a", &"a".repeat(64)).is_err());
    fs::write(&path, &valid).unwrap();
    rewrite(&path, |rows| {
        rows[0].payload["owner_identity"] = json!("other-owner")
    });
    assert!(OperationalJournal::open(Arc::clone(&owner), "service-a", &"a".repeat(64)).is_err());
    fs::write(&path, &valid).unwrap();
    rewrite(&path, |rows| {
        rows[1].payload["body_sha256"] = json!("0".repeat(64))
    });
    assert!(OperationalJournal::open(Arc::clone(&owner), "service-a", &"a".repeat(64)).is_err());
    fs::write(&path, &valid).unwrap();
    rewrite(&path, |rows| {
        rows[1].payload["event"] = json!("unreviewed_future_event")
    });
    assert!(OperationalJournal::open(Arc::clone(&owner), "service-a", &"a".repeat(64)).is_err());
    fs::write(&path, &valid).unwrap();
    drop(open(&owner));
}

#[test]
fn snapshot_inspection_migration_and_owner_reset_protection_cover_operational_state() {
    let dir = Directory::new();
    let owner = fixture_owner(&dir);
    let mut journal = open(&owner);
    journal.append(quarantined("one")).unwrap();
    journal.append(prepared("one")).unwrap();
    let operations = fs::read(journal.ledger_path()).unwrap();
    let registration = fs::read(dir.0.join(OWNER_FILE)).unwrap();
    let original = fs::read(owner.ledger_path()).unwrap();
    drop(journal);
    drop(owner);
    let report = maintenance::inspect(&dir.0).unwrap();
    assert!(report.ledger_files.contains(&FILE_NAME.to_string()));
    assert_eq!(report.ledger_integrity, "verified_snapshot");
    maintenance::migrate(&dir.0).unwrap();
    assert_eq!(
        fs::read(dir.0.join("migration-backup-v1/operations.jsonl")).unwrap(),
        operations
    );
    assert_eq!(
        fs::read(dir.0.join("migration-backup-v1").join(OWNER_FILE)).unwrap(),
        registration
    );
    assert_eq!(fs::read(dir.0.join("ledger.jsonl")).unwrap(), original);
    assert_eq!(fs::read(dir.0.join(FILE_NAME)).unwrap(), operations);
    let mut corrupted = operations.clone();
    corrupted[10] ^= 1;
    fs::write(dir.0.join(FILE_NAME), &corrupted).unwrap();
    assert!(maintenance::inspect(&dir.0).is_err());
    assert!(maintenance::migrate(&dir.0).is_err());
    fs::write(dir.0.join(FILE_NAME), operations).unwrap();
    fs::remove_file(dir.0.join("ledger.jsonl")).unwrap();
    assert!(Store::open(&dir.0).is_err());
    assert!(!dir.0.join("ledger.jsonl").exists());
}

#[test]
fn marker_first_crash_cutpoint_is_hold_and_never_initializes_empty_history() {
    let dir = Directory::new();
    let owner = fixture_owner(&dir);
    let identity = owner.identity().to_string();
    let original = fs::read(owner.ledger_path()).unwrap();
    assert!(OperationalJournal::open_with_initialization_hook(
        Arc::clone(&owner),
        "service-a",
        &"a".repeat(64),
        || Err("supervised cutpoint before operational genesis".into())
    )
    .is_err());
    let registration = fs::read(dir.0.join(OWNER_FILE)).unwrap();
    assert!(!dir.0.join(FILE_NAME).exists());
    assert!(OperationalJournal::open(Arc::clone(&owner), "service-a", &"a".repeat(64)).is_err());
    assert!(!dir.0.join(FILE_NAME).exists());
    assert_eq!(fs::read(dir.0.join(OWNER_FILE)).unwrap(), registration);
    assert_eq!(fs::read(owner.ledger_path()).unwrap(), original);
    assert!(maintenance::inspect(&dir.0).is_err());
    assert!(maintenance::migrate(&dir.0).is_err());
    drop(owner);
    assert_eq!(fixture_owner(&dir).identity(), identity);
    fs::remove_file(dir.0.join("ledger.jsonl")).unwrap();
    assert!(Store::open(&dir.0).is_err());
    assert!(crate::knowledge::KnowledgeStore::open(&dir.0, "wrong-owner").is_err());
    assert!(!dir.0.join("ledger.jsonl").exists());
    assert!(!dir.0.join("knowledge.jsonl").exists());
}

#[test]
fn losing_either_operational_file_or_changing_registration_cannot_reset_deny_history() {
    let dir = Directory::new();
    let owner = fixture_owner(&dir);
    let mut journal = open(&owner);
    journal
        .append(OperationalEvent::PeerDenied {
            peer_id: "peer-a".into(),
            reason: "durable operator denial".into(),
        })
        .unwrap();
    drop(journal);
    let registration = fs::read(dir.0.join(OWNER_FILE)).unwrap();
    let operations = fs::read(dir.0.join(FILE_NAME)).unwrap();
    for name in [OWNER_FILE, FILE_NAME] {
        let source = dir.0.join(name);
        let saved = dir.0.join(format!("{name}.saved"));
        fs::rename(&source, &saved).unwrap();
        assert!(
            OperationalJournal::open(Arc::clone(&owner), "service-a", &"a".repeat(64)).is_err()
        );
        assert!(!source.exists());
        assert!(maintenance::inspect(&dir.0).is_err());
        fs::rename(saved, source).unwrap();
    }
    let mut changed: Value = serde_json::from_slice(&registration).unwrap();
    changed["genesis_sha256"] = json!("0".repeat(64));
    fs::write(
        dir.0.join(OWNER_FILE),
        serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    assert!(OperationalJournal::open(Arc::clone(&owner), "service-a", &"a".repeat(64)).is_err());
    assert!(maintenance::inspect(&dir.0).is_err());
    fs::write(dir.0.join(OWNER_FILE), registration).unwrap();
    let journal = open(&owner);
    assert!(journal.denied_peers().contains("peer-a"));
    assert_eq!(fs::read(journal.ledger_path()).unwrap(), operations);
}

#[test]
fn bounded_operational_outcomes_are_never_learning_promotions() {
    let dir = Directory::new();
    let owner = fixture_owner(&dir);
    let mut journal = open(&owner);
    for index in 0..MAX_IDENTITIES {
        journal
            .append(OperationalEvent::PartnerOutcomeRecorded {
                outcome: PartnerOutcomeRecord {
                    interaction_id: format!("interaction-{index}"),
                    peer_id: "peer-a".into(),
                    scope: "affine-world".into(),
                    kind: PartnerOutcomeKind::Received,
                    receipt_sha256: None,
                    resource_units: 1,
                },
            })
            .unwrap();
    }
    assert!(journal
        .append(OperationalEvent::PartnerOutcomeRecorded {
            outcome: PartnerOutcomeRecord {
                interaction_id: "excess".into(),
                peer_id: "peer-a".into(),
                scope: "affine-world".into(),
                kind: PartnerOutcomeKind::Received,
                receipt_sha256: None,
                resource_units: 1
            }
        })
        .is_err());
    assert!(owner.active().is_empty());
    assert!(!dir.0.join("knowledge.jsonl").exists());
    assert_eq!(owner.record_count(), 1);
}

#[test]
fn byte_limits_and_sender_operation_scope_key_separation_are_enforced() {
    let dir = Directory::new();
    let owner = fixture_owner(&dir);
    let mut journal = open(&owner);
    let mut huge = quarantined("huge");
    if let OperationalEvent::Quarantined {
        body, body_sha256, ..
    } = &mut huge
    {
        *body = json!("x".repeat(MAX_BODY_BYTES + 1));
        *body_sha256 = digest(body).unwrap();
    }
    assert!(journal.append(huge).is_err());
    let mut huge = quarantined("huge");
    if let OperationalEvent::Quarantined { response, .. } = &mut huge {
        *response = json!("x".repeat(MAX_RESPONSE_BYTES + 1));
    }
    assert!(journal.append(huge).is_err());
    journal.append(quarantined("one")).unwrap();
    for (index, field) in ["peer", "operation", "scope", "request"].iter().enumerate() {
        let mut distinct = quarantined("one");
        if let OperationalEvent::Quarantined {
            key, candidate_id, ..
        } = &mut distinct
        {
            *candidate_id = format!("distinct-{index}");
            match *field {
                "peer" => key.peer_id = "peer-b".into(),
                "operation" => key.operation = "other".into(),
                "scope" => key.scope = "different".into(),
                _ => key.request_id = "different".into(),
            }
        }
        journal.append(distinct).unwrap();
    }
    assert_eq!(journal.record_count(), 6);
}

fn decision(id: &str) -> OperationalEvent {
    OperationalEvent::PartnerDecisionRecorded {
        decision: PartnerDecisionRecord {
            decision_id: id.into(),
            context: "opaque-context-a".into(),
            frontier_edge: Some(1),
            selected_peer: Some("authorized-opaque-peer".into()),
            details: json!({"p_numerator":1,"p_denominator":2,"Cex":40,"Cobs":100,"reason":"frozen-policy-admission"}),
        },
    }
}
fn interaction(id: &str, decision_id: &str) -> OperationalEvent {
    OperationalEvent::PartnerInteractionCompleted {
        interaction: PartnerInteractionRecord {
            interaction_id: id.into(),
            decision_id: decision_id.into(),
            peer_id: "authorized-opaque-peer".into(),
            context: "opaque-context-a".into(),
            outcome: PartnerInteractionOutcome::VerifiedNovel,
            receipt_sha256: Some("d".repeat(64)),
            sent_bytes: 10,
            received_bytes: 100,
            resource_units: 12,
            subsequently_used: true,
        },
    }
}

#[test]
fn prospective_interaction_requires_prior_bound_decision_and_cannot_double_count() {
    let dir = Directory::new();
    let owner = fixture_owner(&dir);
    let mut journal = open(&owner);
    assert!(journal
        .append(interaction("outcome-a", "decision-a"))
        .is_err());
    journal.append(decision("decision-a")).unwrap();
    assert!(journal.append(decision("decision-a")).is_err());
    for field in ["peer", "context"] {
        let mut wrong = interaction("outcome-a", "decision-a");
        if let OperationalEvent::PartnerInteractionCompleted { interaction } = &mut wrong {
            if field == "peer" {
                interaction.peer_id = "other-peer".into();
            } else {
                interaction.context = "future-context".into();
            }
        }
        assert!(journal.append(wrong).is_err());
    }
    drop(journal);
    let mut journal = open(&owner);
    assert_eq!(journal.events().len(), 1);
    journal
        .append(interaction("outcome-a", "decision-a"))
        .unwrap();
    assert!(journal
        .append(interaction("outcome-b", "decision-a"))
        .is_err());
    journal.append(decision("decision-b")).unwrap();
    assert!(journal
        .append(interaction("outcome-a", "decision-b"))
        .is_err());
    journal
        .append(interaction("outcome-b", "decision-b"))
        .unwrap();
    assert!(journal
        .append(OperationalEvent::PartnerOutcomeRecorded {
            outcome: PartnerOutcomeRecord {
                interaction_id: "outcome-a".into(),
                peer_id: "authorized-opaque-peer".into(),
                scope: "opaque-context-a".into(),
                kind: PartnerOutcomeKind::Received,
                receipt_sha256: None,
                resource_units: 1
            }
        })
        .is_err());
    journal
        .append(OperationalEvent::PartnerOutcomeRecorded {
            outcome: PartnerOutcomeRecord {
                interaction_id: "outcome-c".into(),
                peer_id: "authorized-opaque-peer".into(),
                scope: "opaque-context-a".into(),
                kind: PartnerOutcomeKind::Received,
                receipt_sha256: None,
                resource_units: 1,
            },
        })
        .unwrap();
    journal.append(decision("decision-c")).unwrap();
    assert!(journal
        .append(interaction("outcome-c", "decision-c"))
        .is_err());
    drop(journal);
    let journal = open(&owner);
    assert_eq!(
        journal
            .events()
            .iter()
            .filter(|event| matches!(event, OperationalEvent::PartnerInteractionCompleted { .. }))
            .count(),
        2
    );
    assert!(owner.active().is_empty());
}

#[test]
fn prospective_operational_failures_remain_distinct_and_skip_never_claims_rpc_or_use() {
    let dir = Directory::new();
    let owner = fixture_owner(&dir);
    let mut journal = open(&owner);
    journal.append(decision("decision-a")).unwrap();
    let mut malformed = interaction("outcome-a", "decision-a");
    if let OperationalEvent::PartnerInteractionCompleted { interaction } = &mut malformed {
        interaction.receipt_sha256 = None;
    }
    assert!(journal.append(malformed).is_err());
    for outcome in [
        PartnerInteractionOutcome::TransportFailed,
        PartnerInteractionOutcome::VerificationFailed,
        PartnerInteractionOutcome::ApplicabilityFailed,
    ] {
        let mut malformed = interaction("outcome-a", "decision-a");
        if let OperationalEvent::PartnerInteractionCompleted { interaction } = &mut malformed {
            interaction.outcome = outcome;
        }
        assert!(journal.append(malformed).is_err());
    }
    let mut failed = interaction("outcome-a", "decision-a");
    if let OperationalEvent::PartnerInteractionCompleted { interaction } = &mut failed {
        interaction.outcome = PartnerInteractionOutcome::TransportFailed;
        interaction.receipt_sha256 = None;
        interaction.subsequently_used = false;
    }
    journal.append(failed).unwrap();
    journal.append(decision("decision-b")).unwrap();
    let mut skipped = interaction("outcome-b", "decision-b");
    if let OperationalEvent::PartnerInteractionCompleted { interaction } = &mut skipped {
        interaction.outcome = PartnerInteractionOutcome::SkippedIrrelevant;
        interaction.receipt_sha256 = None;
        interaction.subsequently_used = false;
    }
    assert!(journal.append(skipped.clone()).is_err());
    if let OperationalEvent::PartnerInteractionCompleted { interaction } = &mut skipped {
        interaction.sent_bytes = 0;
        interaction.received_bytes = 0;
    }
    journal.append(skipped).unwrap();
    let outcomes: Vec<_> = journal
        .events()
        .iter()
        .filter_map(|event| match event {
            OperationalEvent::PartnerInteractionCompleted { interaction } => {
                Some(interaction.outcome.clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        outcomes,
        vec![
            PartnerInteractionOutcome::TransportFailed,
            PartnerInteractionOutcome::SkippedIrrelevant
        ]
    );
}

fn source_warmup(owner: &str, context: &str, index: u64) -> OperationalEvent {
    let receipt = json!({"schema":"symbiote.graph-observation/1","authority_id":"manual-development-authority","context":context,"schema_fingerprint":"f".repeat(64),"observer_identity":owner,"sequence":1_000_000_000+index,"id":format!("{index:064x}"),"edge_id":0,"cost":1});
    OperationalEvent::SourceWarmupRetained {
        context: context.into(),
        receipt_sha256: body_digest(&receipt).unwrap(),
        receipt,
    }
}

#[test]
fn own_warmup_telemetry_replays_chronologically_after_restart_without_promoting_learning() {
    let dir = Directory::new();
    let owner = fixture_owner(&dir);
    let identity = owner.identity().to_string();
    let mut journal = open(&owner);
    journal
        .append(source_warmup(&identity, "manual-z-context", 0))
        .unwrap();
    let prefix = fs::read(journal.ledger_path()).unwrap();
    journal
        .append(source_warmup(&identity, "manual-a-context", 1))
        .unwrap();
    assert!(fs::read(journal.ledger_path())
        .unwrap()
        .starts_with(&prefix));
    drop(journal);
    drop(owner);
    let owner = fixture_owner(&dir);
    let journal = open(&owner);
    let latest = journal
        .events()
        .iter()
        .rev()
        .find_map(|event| match event {
            OperationalEvent::SourceWarmupRetained {
                context, receipt, ..
            } => Some((context, receipt)),
            _ => None,
        })
        .unwrap();
    assert_eq!(latest.0, "manual-a-context");
    assert_eq!(latest.1["observer_identity"], identity);
    assert!(owner.active().is_empty());
    assert!(!dir.0.join("knowledge.jsonl").exists());
    drop(journal);
    drop(owner);
    assert_eq!(
        maintenance::inspect(&dir.0).unwrap().ledger_integrity,
        "verified_snapshot"
    );
}

#[test]
fn source_warmups_reject_foreign_owner_hash_context_duplicates_unknown_fields_and_rehashed_tampering(
) {
    let dir = Directory::new();
    let owner = fixture_owner(&dir);
    let identity = owner.identity().to_string();
    let mut journal = open(&owner);
    assert!(journal
        .append(source_warmup("foreign-owner", "manual-context", 0))
        .is_err());
    let mut changed = source_warmup(&identity, "manual-context", 0);
    if let OperationalEvent::SourceWarmupRetained { context, .. } = &mut changed {
        *context = "different-context".into();
    }
    assert!(journal.append(changed).is_err());
    let mut changed = source_warmup(&identity, "manual-context", 0);
    if let OperationalEvent::SourceWarmupRetained { receipt, .. } = &mut changed {
        receipt["cost"] = json!(2);
    }
    assert!(journal.append(changed).is_err());
    let mut changed = source_warmup(&identity, "manual-context", 0);
    if let OperationalEvent::SourceWarmupRetained {
        receipt,
        receipt_sha256,
        ..
    } = &mut changed
    {
        receipt["unreviewed_field"] = json!(true);
        *receipt_sha256 = body_digest(receipt).unwrap();
    }
    assert!(journal.append(changed).is_err());
    let mut huge = source_warmup(&identity, "manual-context", 0);
    if let OperationalEvent::SourceWarmupRetained {
        receipt,
        receipt_sha256,
        ..
    } = &mut huge
    {
        receipt["observer_identity"] = json!("x".repeat(2049));
        *receipt_sha256 = body_digest(receipt).unwrap();
    }
    assert!(journal.append(huge).is_err());
    journal
        .append(source_warmup(&identity, "manual-context", 0))
        .unwrap();
    assert!(journal
        .append(source_warmup(&identity, "manual-context", 1))
        .is_err());
    let path = journal.ledger_path();
    drop(journal);
    rewrite(&path, |rows| {
        rows[1].payload["receipt"]["observer_identity"] = json!("foreign-owner");
        rows[1].payload["receipt_sha256"] =
            json!(body_digest(&rows[1].payload["receipt"]).unwrap());
    });
    assert!(OperationalJournal::open(Arc::clone(&owner), "service-a", &"a".repeat(64)).is_err());
    assert!(maintenance::inspect(&dir.0).is_err());
}

#[test]
fn source_warmup_context_budget_is_fixed_to_twenty_five_manual_contexts() {
    let dir = Directory::new();
    let owner = fixture_owner(&dir);
    let mut journal = open(&owner);
    for index in 0..25_u64 {
        journal
            .append(source_warmup(
                owner.identity(),
                &format!("manual-only-{index}"),
                index,
            ))
            .unwrap();
    }
    assert!(journal
        .append(source_warmup(owner.identity(), "manual-excess", 25))
        .is_err());
    assert_eq!(journal.record_count(), 26);
}
