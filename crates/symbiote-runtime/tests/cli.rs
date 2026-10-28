use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use symbiote_memory::knowledge::{
    affine_schema_fingerprint, assess, KnowledgeRecord, KnowledgeStore, TrialCase, TrialCosts,
    TrialEvidence,
};
use symbiote_memory::Store;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "symbiote-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_symbiote"))
            .args(args)
            .current_dir(&self.0)
            .output()
            .unwrap()
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn help_and_version_are_readable_and_do_not_create_state() {
    let sandbox = Sandbox::new();
    let help = sandbox.run(&[]);
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("Usage: symbiote COMMAND"));
    assert!(text.contains("research"));
    assert!(text.contains("Start here: symbiote demo"));
    assert!(!sandbox.0.join("state").exists());
    let version = sandbox.run(&["--version"]);
    assert_eq!(
        String::from_utf8(version.stdout).unwrap().trim(),
        format!("SYMBIOTE {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn invalid_arguments_fail_before_touching_state() {
    let sandbox = Sandbox::new();
    for args in [
        vec!["run"],
        vec![
            "run",
            "--config",
            "owner.json",
            "--run-policy",
            "policy.json",
        ],
        vec!["run", "--config", "owner.json", "--receipts", "new-run"],
        vec![
            "run",
            "--run-policy",
            "policy.json",
            "--receipts",
            "new-run",
        ],
        vec![
            "run",
            "--config",
            "owner.json",
            "--run-policy",
            "policy.json",
            "--receipts",
            "new-run",
            "--state",
            "override",
        ],
        vec!["demo", "--run-policy", "policy.json"],
        vec!["transfer-register"],
        vec!["transfer-register", "--state", "new-study"],
        vec![
            "transfer-research",
            "--state",
            "new-study",
            "--receipts",
            "report",
            "--registration",
            "registration.json",
        ],
        vec![
            "transfer-research",
            "--state",
            "new-study",
            "--receipts",
            "report",
            "--registration",
            "registration.json",
            "--registration-sha256",
            "abcd",
        ],
        vec!["topology-research", "--receipts", "report"],
        vec!["exploration-research", "--state", "owner"],
        vec!["backup-state"],
        vec!["backup-state", "--backup", "archive"],
        vec!["backup-state", "--state", "owner"],
        vec!["verify-backup", "--backup", "archive"],
        vec![
            "restore-state",
            "--backup",
            "archive",
            "--manifest-sha256",
            "abcd",
            "--state",
            "restored",
        ],
        vec![
            "restore-state",
            "--backup",
            "archive",
            "--manifest-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
        vec![
            "verify-backup",
            "--backup",
            "archive",
            "--manifest-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--state",
            "override",
        ],
        vec![
            "backup-state",
            "--state",
            "owner",
            "--backup",
            "archive",
            "--backup",
            "duplicate",
        ],
        vec![
            "backup-state",
            "--state",
            "owner",
            "--backup",
            "archive",
            "--graph-context-registry",
            "registry.json",
        ],
        vec![
            "backup-state",
            "--state",
            "owner",
            "--backup",
            "archive",
            "--graph-context-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
        vec!["demo", "--backup", "archive"],
        vec![
            "backup-state",
            "--state",
            "owner",
            "--backup",
            "archive",
            "--manifest-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
        vec!["demo", "--review-permission-change"],
        vec!["demo", "--review-relocation"],
        vec!["peer-regrant", "--review-relocation"],
        vec!["policy-transition", "--config", "next.json"],
        vec![
            "policy-status",
            "--config",
            "service.json",
            "--state",
            "override",
        ],
        vec![
            "peer-regrant",
            "--config",
            "service.json",
            "--peer",
            "partner",
        ],
        vec![
            "policy-transition",
            "--config",
            "next.json",
            "--expected-policy",
            "abcd",
            "--expected-head",
            "abcd",
        ],
        vec!["demo", "--state"],
        vec!["demo", "--surprise"],
        vec!["demo", "--fault", "typo"],
        vec!["unknown"],
        vec!["status", "--fault", "drift"],
        vec!["revoke"],
        vec!["demo", "--state", "one", "--state", "two"],
        vec!["adaptive-research"],
        vec![
            "adaptive-research",
            "--reproduce",
            "--registration",
            "record.json",
        ],
        vec!["adaptive-research", "--registration", "record.json"],
        vec!["adaptive-research", "--reproduce", "--state", "unpaired"],
        vec!["demo", "--reproduce"],
        vec![
            "adaptive-research",
            "--reproduce",
            "--setup-catalogue",
            "setup.json",
        ],
        vec!["adaptive-research", "--reproduce", "--setup-sha256", "abcd"],
        vec![
            "adaptive-research",
            "--reproduce",
            "--setup-catalogue",
            "setup.json",
            "--setup-sha256",
            "abcd",
        ],
        vec![
            "adaptive-research",
            "--registration",
            "record.json",
            "--setup-catalogue",
            "setup.json",
            "--setup-sha256",
            "abcd",
        ],
        vec!["demo", "--setup-catalogue", "setup.json"],
        vec!["serve", "--config", "service.json", "--state", "override"],
        vec!["connect", "--config", "service.json", "--peer", "partner"],
        vec!["evaluate", "--config", "service.json"],
        vec![
            "peer-revoke",
            "--config",
            "service.json",
            "--peer",
            "partner",
        ],
    ] {
        let output = sandbox.run(&args);
        assert_eq!(output.status.code(), Some(2), "arguments: {args:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("--help"));
    }
    assert!(!sandbox.0.join("state").exists());
}

#[test]
fn missing_primary_registration_cannot_create_experiment_state() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&[
        "adaptive-research",
        "--registration",
        "missing.json",
        "--state",
        "untouched",
        "--receipts",
        "unwritten.json",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!sandbox.0.join("untouched").exists());
    assert!(!sandbox.0.join("unwritten.json").exists());
    assert!(!sandbox.0.join("primary-started.json").exists());
}

#[test]
fn doctor_and_empty_status_are_nonmutating() {
    let sandbox = Sandbox::new();
    for command in ["doctor", "status"] {
        let output = sandbox.run(&[command, "--state", "untouched", "--json"]);
        assert!(output.status.success());
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["network_requests"], 0);
        assert_eq!(value["state_modified"], false);
        if command == "doctor" {
            assert_eq!(
                value["verification"]["status"],
                "EXTERNAL_EVIDENCE_REQUIRED"
            );
            assert_eq!(
                value["verification"]["online_verification_performed"],
                false
            );
            assert_eq!(
                value["verification"]["release_tag"],
                format!("v{}", env!("CARGO_PKG_VERSION"))
            );
        }
        assert!(!sandbox.0.join("untouched").exists());
    }
}

#[test]
fn standalone_observation_uses_the_engine_then_restarts_without_source_queries() {
    let sandbox = Sandbox::new();
    let run = |receipt: &str| {
        let output = sandbox.run(&[
            "observe-demo",
            "--state",
            "observed",
            "--receipts",
            receipt,
            "--json",
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    let first = run("first.json");
    assert_eq!(first["fresh_promotions"], 1);
    assert_eq!(first["source_queries"], 5);
    assert_eq!(first["network_requests"], 0);
    assert_eq!(first["baseline"]["kind"], "unknown");
    let expected = [1, 0, 1, 0, 0, 1, 0, 1];
    for (case, wanted) in first["predictions"]
        .as_array()
        .unwrap()
        .iter()
        .zip(expected)
    {
        assert_eq!(case["prediction"], wanted);
    }
    let original = fs::read(sandbox.0.join("observed/knowledge.jsonl")).unwrap();
    let restarted = run("restart.json");
    assert_eq!(restarted["fresh_promotions"], 0);
    assert_eq!(restarted["source_queries"], 0);
    assert_eq!(first["identity"], restarted["identity"]);
    assert_eq!(first["record_sha256"], restarted["record_sha256"]);
    assert_eq!(first["predictions"], restarted["predictions"]);
    assert_eq!(
        original,
        fs::read(sandbox.0.join("observed/knowledge.jsonl")).unwrap()
    );
    let revoked = sandbox.run(&[
        "revoke",
        "--state",
        "observed",
        "--artifact",
        "standalone-active-affine",
        "--json",
    ]);
    assert!(revoked.status.success());
    let revoked_bytes = fs::read(sandbox.0.join("observed/knowledge.jsonl")).unwrap();
    let rejected = sandbox.run(&[
        "observe-demo",
        "--state",
        "observed",
        "--receipts",
        "held.json",
        "--json",
    ]);
    assert!(!rejected.status.success());
    assert_eq!(
        revoked_bytes,
        fs::read(sandbox.0.join("observed/knowledge.jsonl")).unwrap(),
        "revocation cannot be silently relearned"
    );
}

#[test]
fn doctor_rejects_corrupt_evidence_and_migration_preserves_ledger_bytes() {
    let sandbox = Sandbox::new();
    let state = sandbox.0.join("checked");
    let identity = {
        let store = Store::open(&state).unwrap();
        store.identity().to_string()
    };
    let original = fs::read(state.join("ledger.jsonl")).unwrap();
    let doctor = sandbox.run(&["doctor", "--state", "checked", "--json"]);
    assert!(doctor.status.success());
    let report: Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(report["ledger_integrity"], "verified_snapshot");
    assert_eq!(fs::read(state.join("ledger.jsonl")).unwrap(), original);
    assert!(!state.join("writer.lock").exists());
    let migration = sandbox.run(&["migrate", "--state", "checked", "--json"]);
    assert!(
        migration.status.success(),
        "{}",
        String::from_utf8_lossy(&migration.stderr)
    );
    let report: Value = serde_json::from_slice(&migration.stdout).unwrap();
    assert_eq!(report["identity"], identity);
    assert_eq!(report["ledger_bytes_changed"], false);
    assert_eq!(fs::read(state.join("ledger.jsonl")).unwrap(), original);
    let mut corrupt = original;
    corrupt[12] ^= 1;
    fs::write(state.join("ledger.jsonl"), &corrupt).unwrap();
    let rejected = sandbox.run(&["doctor", "--state", "checked", "--json"]);
    assert!(!rejected.status.success());
    assert_eq!(fs::read(state.join("ledger.jsonl")).unwrap(), corrupt);
}

#[test]
fn demonstration_has_human_summary_and_explicit_json_mode() {
    let sandbox = Sandbox::new();
    let human = sandbox.run(&["demo"]);
    assert!(
        human.status.success(),
        "{}",
        String::from_utf8_lossy(&human.stderr)
    );
    let text = String::from_utf8(human.stdout).unwrap();
    assert!(text.contains("2 promoted, 0 reused"));
    assert!(text.contains("equal-probe control"));
    assert!(text.contains("simulation units"));
    assert!(text.contains("Receipt:"));
    let machine = sandbox.run(&["--json", "demo"]);
    assert!(
        machine.status.success(),
        "{}",
        String::from_utf8_lossy(&machine.stderr)
    );
    let value: Value = serde_json::from_slice(&machine.stdout).unwrap();
    assert_eq!(value["schema"], "symbiote.demo/1");
    assert_eq!(value["reused"], 2);
}

#[test]
fn retained_structural_models_are_read_and_used_without_ledger_mutation() {
    let sandbox = Sandbox::new();
    let state = sandbox.0.join("models");
    {
        let identity = Store::open(&state).unwrap();
        let record = KnowledgeRecord {
            id: "cli-retained-xor".into(),
            revision: 1,
            source: "partner-a".into(),
            scope: "affine-boolean-v1/cli-test".into(),
            schema_fingerprint: affine_schema_fingerprint(3).unwrap(),
            payload: serde_json::json!({"kind":"affine","width":3,"coefficients":3,"bias":false}),
            provenance: "CLI fixture: distinct finite laboratory evaluator".into(),
        };
        let evidence = TrialEvidence {
            evaluator: "separate-laboratory".into(),
            training_case_ids: vec!["train-0".into()],
            training_inputs: vec![0],
            cases: (1_u16..8)
                .map(|input| {
                    let output = ((input & 3).count_ones() % 2) as u8;
                    TrialCase {
                        id: format!("heldout-{input}"),
                        input,
                        expected: output,
                        baseline: None,
                        candidate: output,
                    }
                })
                .collect(),
            costs: TrialCosts {
                acquisition: 1,
                verification: 7,
                adoption: 1,
                baseline: 20,
                candidate: 10,
            },
        };
        let assessment = assess(&record, &evidence).unwrap();
        KnowledgeStore::open(&state, identity.identity())
            .unwrap()
            .promote(record, assessment)
            .unwrap();
    }
    let before = fs::read(state.join("knowledge.jsonl")).unwrap();
    let output = sandbox.run(&["predict", "--state", "models", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["active_artifacts"], 1);
    assert_eq!(value["structural_artifacts"], 1);
    assert_eq!(value["network_requests"], 0);
    let samples = value["structural_knowledge"][0]["sample_predictions"]
        .as_array()
        .unwrap();
    assert_eq!(samples.len(), 8);
    assert_eq!(samples[3]["output"], 0);
    assert_eq!(fs::read(state.join("knowledge.jsonl")).unwrap(), before);
    assert!(!state.join("knowledge.writer.lock").exists());
    let revoked = sandbox.run(&[
        "revoke",
        "--state",
        "models",
        "--artifact",
        "cli-retained-xor",
        "--json",
    ]);
    assert!(
        revoked.status.success(),
        "{}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    let result: Value = serde_json::from_slice(&revoked.stdout).unwrap();
    assert_eq!(result["revoked_kind"], "structural");
    assert_eq!(result["active_artifacts"], 0);
    let again = sandbox.run(&["status", "--state", "models", "--json"]);
    let result: Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(result["structural_artifacts"], 0);
}

fn backup_fixture(sandbox: &Sandbox) -> (PathBuf, String, String) {
    let state = sandbox.0.join("owner");
    let owner = Store::open(&state).unwrap();
    let record = KnowledgeRecord {
        id: "backup-retained-xor".into(),
        revision: 1,
        source: "manual-partner".into(),
        scope: "manual-backup-context/v1".into(),
        schema_fingerprint: affine_schema_fingerprint(2).unwrap(),
        payload: serde_json::json!({"kind":"affine","width":2,"coefficients":3,"bias":false}),
        provenance: "Finite independently evaluated native CLI backup fixture".into(),
    };
    let evidence = TrialEvidence {
        evaluator: "manual-finite-evaluator".into(),
        training_case_ids: vec!["training-zero".into()],
        training_inputs: vec![0],
        cases: (1u16..4)
            .map(|input| {
                let output = (input.count_ones() % 2) as u8;
                TrialCase {
                    id: format!("heldout-{input}"),
                    input,
                    expected: output,
                    baseline: None,
                    candidate: output,
                }
            })
            .collect(),
        costs: TrialCosts {
            acquisition: 0,
            verification: 3,
            adoption: 1,
            baseline: 20,
            candidate: 4,
        },
    };
    KnowledgeStore::open(&state, owner.identity())
        .unwrap()
        .promote(record.clone(), assess(&record, &evidence).unwrap())
        .unwrap();
    (state, owner.identity().into(), record.id)
}
fn successful_json(output: Output) -> Value {
    assert!(
        output.status.success(),
        "stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn native_backup_cli_restores_identity_bytes_and_offline_predictions_without_activation() {
    let sandbox = Sandbox::new();
    let (source, identity, artifact) = backup_fixture(&sandbox);
    let original = fs::read(source.join("knowledge.jsonl")).unwrap();
    let ledger = fs::read(source.join("ledger.jsonl")).unwrap();
    let backup = sandbox.0.join("owner-backup");
    let restored = sandbox.0.join("restored-owner");
    let saved = successful_json(sandbox.run(&[
        "backup-state",
        "--state",
        source.to_str().unwrap(),
        "--backup",
        backup.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(saved["identity"], identity);
    assert_eq!(saved["network_started"], false);
    let pin = saved["manifest_sha256"].as_str().unwrap();
    let checked = successful_json(sandbox.run(&[
        "verify-backup",
        "--backup",
        backup.to_str().unwrap(),
        "--manifest-sha256",
        pin,
        "--json",
    ]));
    assert_eq!(checked["manifest_sha256"], pin);
    let plain = sandbox.run(&[
        "verify-backup",
        "--backup",
        backup.to_str().unwrap(),
        "--manifest-sha256",
        pin,
    ]);
    assert!(plain.status.success());
    assert!(String::from_utf8(plain.stdout)
        .unwrap()
        .contains("Backup verified"));
    let receipt = successful_json(sandbox.run(&[
        "restore-state",
        "--backup",
        backup.to_str().unwrap(),
        "--manifest-sha256",
        pin,
        "--state",
        restored.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(receipt["identity"], identity);
    assert_eq!(receipt["network_started"], false);
    assert_eq!(receipt["requires_activation"], true);
    assert_eq!(
        fs::read(restored.join("knowledge.jsonl")).unwrap(),
        original
    );
    assert_eq!(fs::read(restored.join("ledger.jsonl")).unwrap(), ledger);
    assert!(!restored.join("writer.lock").exists());
    assert!(!restored.join("knowledge.writer.lock").exists());
    let predicted = successful_json(sandbox.run(&[
        "predict",
        "--state",
        restored.to_str().unwrap(),
        "--artifact",
        &artifact,
        "--input",
        "3",
        "--json",
    ]));
    assert_eq!(predicted["prediction"], 0);
    assert_eq!(predicted["prediction_status"], "conditional-inference");
    assert_eq!(
        fs::read(restored.join("knowledge.jsonl")).unwrap(),
        original
    );
    assert_eq!(fs::read(source.join("ledger.jsonl")).unwrap(), ledger);
}

#[test]
fn native_backup_cli_rejects_live_writer_tampered_manifest_occupied_target_and_registry_pin() {
    let sandbox = Sandbox::new();
    let (source, _, _) = backup_fixture(&sandbox);
    let original = fs::read(source.join("knowledge.jsonl")).unwrap();
    let backup = sandbox.0.join("owner-backup");
    let live = Store::open(&source).unwrap();
    assert!(!sandbox
        .run(&[
            "backup-state",
            "--state",
            source.to_str().unwrap(),
            "--backup",
            backup.to_str().unwrap(),
            "--json"
        ])
        .status
        .success());
    assert!(!backup.exists());
    assert!(source.join("writer.lock").exists());
    drop(live);
    let registry = sandbox.0.join("registry.json");
    fs::write(&registry, b"{}").unwrap();
    assert!(!sandbox
        .run(&[
            "backup-state",
            "--state",
            source.to_str().unwrap(),
            "--backup",
            backup.to_str().unwrap(),
            "--graph-context-registry",
            registry.to_str().unwrap(),
            "--graph-context-sha256",
            &"a".repeat(64),
            "--json"
        ])
        .status
        .success());
    assert!(
        !backup.exists(),
        "explicit registry pin is checked before archive publication"
    );
    let receipt = successful_json(sandbox.run(&[
        "backup-state",
        "--state",
        source.to_str().unwrap(),
        "--backup",
        backup.to_str().unwrap(),
        "--json",
    ]));
    let pin = receipt["manifest_sha256"].as_str().unwrap();
    let occupied = sandbox.0.join("occupied");
    fs::create_dir(&occupied).unwrap();
    fs::write(occupied.join("sentinel"), b"preserve").unwrap();
    assert!(!sandbox
        .run(&[
            "restore-state",
            "--backup",
            backup.to_str().unwrap(),
            "--manifest-sha256",
            pin,
            "--state",
            occupied.to_str().unwrap(),
            "--json"
        ])
        .status
        .success());
    assert_eq!(fs::read(occupied.join("sentinel")).unwrap(), b"preserve");
    let manifest = backup.join("backup-manifest.json");
    let mut altered = fs::read(&manifest).unwrap();
    altered.push(b' ');
    fs::write(&manifest, &altered).unwrap();
    assert!(!sandbox
        .run(&[
            "verify-backup",
            "--backup",
            backup.to_str().unwrap(),
            "--manifest-sha256",
            pin,
            "--json"
        ])
        .status
        .success());
    let target = sandbox.0.join("tampered-restoration");
    assert!(!sandbox
        .run(&[
            "restore-state",
            "--backup",
            backup.to_str().unwrap(),
            "--manifest-sha256",
            pin,
            "--state",
            target.to_str().unwrap(),
            "--json"
        ])
        .status
        .success());
    assert!(!target.exists());
    assert_eq!(fs::read(source.join("knowledge.jsonl")).unwrap(), original);
}
