//! Supervised test fixture, excluded from the distributed SYMBIOTE runtime bundle.
//! It cannot terminate any process and refuses to start outside explicit test mode.
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use symbiote_memory::{
    knowledge::{affine_schema_fingerprint, KnowledgeRecord, KnowledgeStore},
    operational::{body_digest, IdempotencyKey, OperationalEvent, OperationalJournal},
    Store,
};

fn main() {
    if std::env::var("SYMBIOTE_CRASH_FIXTURE").as_deref() != Ok("owned-test-child") {
        eprintln!("This is a supervised crash-test fixture, not the SYMBIOTE runtime.");
        std::process::exit(2);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        eprintln!("fixture needs STATE READY MODE");
        std::process::exit(2);
    }
    let state = PathBuf::from(&args[0]);
    let ready = PathBuf::from(&args[1]);
    let mode = args[2].as_str();
    if !["both", "genesis", "knowledge", "staging", "operational"].contains(&mode) {
        eprintln!("invalid fixture mode");
        std::process::exit(2);
    }
    let original = Store::open(&state).expect("test fixture original store");
    let identity = original.identity().to_string();
    let mut held_original = Some(Arc::new(original));
    let _held_knowledge = if mode == "both" || mode == "knowledge" || mode == "staging" {
        Some(KnowledgeStore::open(&state, &identity).expect("test fixture structural store"))
    } else {
        None
    };
    if mode == "knowledge" {
        held_original.take();
    }
    let _held_operations = if mode == "operational" {
        let mut journal = OperationalJournal::open(
            Arc::clone(held_original.as_ref().unwrap()),
            "crash-fixture",
            &"e".repeat(64),
        )
        .expect("test fixture operational journal");
        let body = json!({"inert":"supervised-crash-fixture"});
        let body_sha256 = body_digest(&body).unwrap();
        journal
            .append(OperationalEvent::Quarantined {
                key: IdempotencyKey {
                    peer_id: "fixture-peer".into(),
                    operation: "submit".into(),
                    scope: "fixture-scope".into(),
                    request_id: "crash-request".into(),
                },
                candidate_id: "crash-candidate".into(),
                body_sha256,
                body,
                response: json!({"status":"QUARANTINED"}),
            })
            .expect("test fixture quarantine");
        journal
            .append(OperationalEvent::EvaluationPrepared {
                candidate_id: "crash-candidate".into(),
                record: KnowledgeRecord {
                    id: "fixture-artifact".into(),
                    revision: 1,
                    source: "fixture-peer".into(),
                    scope: "fixture-scope".into(),
                    schema_fingerprint: affine_schema_fingerprint(2).unwrap(),
                    payload: json!({"kind":"affine","width":2,"coefficients":3,"bias":false}),
                    provenance: "Supervised operational crash intent; not a learning result".into(),
                },
                fixture_sha256: "f".repeat(64),
                response: json!({"promoted":true,"marker":"original-planned-response"}),
            })
            .expect("test fixture pending evaluation intent");
        // Only the journal's Arc remains; the original Store lock must survive.
        held_original.take();
        Some(journal)
    } else {
        None
    };
    if mode == "staging" {
        // Model the observable pre-commit crash boundary: an incomplete private
        // staging file exists, while the canonical atomic-commit targets do not change.
        std::fs::write(
            state.join(format!("ledger.{}.orphan.tmp", std::process::id())),
            b"incomplete staging bytes",
        )
        .expect("test fixture staging file");
    }
    std::fs::write(ready, format!("{}\n{}\n", std::process::id(), identity))
        .expect("test fixture readiness");
    loop {
        std::thread::park();
    }
}
