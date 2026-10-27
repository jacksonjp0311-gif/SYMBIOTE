use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use symbiote_memory::{knowledge::KnowledgeStore, Store};

struct Evidence(PathBuf);
impl Drop for Evidence {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("Preserved failed portfolio evidence: {}", self.0.display());
            return;
        }
        let root = fs::canonicalize(&self.0).unwrap();
        let temporary = fs::canonicalize(std::env::temp_dir()).unwrap();
        assert!(root.starts_with(temporary));
        fs::remove_dir_all(root).unwrap();
    }
}
#[test]
fn native_prior_outcome_changes_experiment_choice_and_retains_independent_learning() {
    let root = std::env::temp_dir().join(format!(
        "symbiote-portfolio-native-{}",
        symbiote_protocol::fresh_capability().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    let evidence = Evidence(root);
    let state = evidence.0.join("state");
    let receipts = evidence.0.join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .args(["exploration-research", "--json", "--state"])
        .arg(&state)
        .arg("--receipts")
        .arg(&receipts)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&fs::read(&receipts).unwrap()).unwrap();
    assert_eq!(report["status"], "PASS");
    assert_eq!(report["choice_before"], "partner-a");
    assert_eq!(report["choice_after_restart"], "partner-b");
    assert_eq!(report["neutral_history_choice_after_restart"], "partner-a");
    assert_eq!(report["retained_models"], 2);
    assert_eq!(report["replay_oracle_calls"], 0);
    let phases = report["phase_reports"].as_array().unwrap();
    assert_eq!(phases.len(), 3);
    let nonces: std::collections::BTreeSet<_> = phases
        .iter()
        .map(|value| value["instance_nonce"].as_str().unwrap())
        .collect();
    assert_eq!(nonces.len(), 3);
    let owner = Store::open(&state.join("owner")).unwrap();
    assert_eq!(report["identity"], owner.identity());
    let knowledge = KnowledgeStore::open(&state.join("owner"), owner.identity()).unwrap();
    assert_eq!(knowledge.active().len(), 2);
    for record in knowledge.active() {
        let coefficient = if record.id == "self-a" { 3_u16 } else { 5_u16 };
        for input in 0..8 {
            assert_eq!(
                record.predict(input).unwrap(),
                ((input & coefficient).count_ones() % 2) as u8
            );
        }
    }
    assert_eq!(phases[0]["result"]["status"], "REJECTED");
    assert_eq!(phases[0]["local_learning_after_rejected_offer"], true);
    assert_eq!(phases[1]["result"]["status"], "PROMOTED");
    for phase in &phases[..2] {
        let metrics = &phase["result"]["metrics"];
        assert_eq!(
            metrics["matched_query_budget_control_correct"],
            metrics["matched_query_budget_control_total"]
        );
        assert!(metrics["model_work_units"].as_u64().unwrap() > 0);
    }
    let bytes = fs::read(knowledge.ledger_path()).unwrap();
    let again = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .args(["exploration-research", "--json", "--state"])
        .arg(&state)
        .arg("--receipts")
        .arg(&receipts)
        .output()
        .unwrap();
    assert!(!again.status.success());
    assert_eq!(fs::read(knowledge.ledger_path()).unwrap(), bytes);
    drop(knowledge);
    drop(owner);
}
