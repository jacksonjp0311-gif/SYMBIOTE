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
        vec!["demo", "--state"],
        vec!["demo", "--surprise"],
        vec!["demo", "--fault", "typo"],
        vec!["unknown"],
        vec!["status", "--fault", "drift"],
        vec!["revoke"],
        vec!["demo", "--state", "one", "--state", "two"],
    ] {
        let output = sandbox.run(&args);
        assert_eq!(output.status.code(), Some(2), "arguments: {args:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("--help"));
    }
    assert!(!sandbox.0.join("state").exists());
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
        assert!(!sandbox.0.join("untouched").exists());
    }
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
