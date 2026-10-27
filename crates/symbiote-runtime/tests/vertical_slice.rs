use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);

struct RunDir(PathBuf);
impl RunDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "symbiote-integration-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn run(&self, command: &str, fault: Option<&str>) -> std::process::Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_symbiote"));
        cmd.arg(command)
            .arg("--state")
            .arg(self.0.join("state"))
            .arg("--receipts")
            .arg(self.0.join("receipt.json"));
        if let Some(fault) = fault {
            cmd.arg("--fault").arg(fault);
        }
        cmd.output().unwrap()
    }
}
impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn json_output(output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn two_agent_reciprocal_learning_survives_process_restart() {
    let dir = RunDir::new();
    let first = json_output(dir.run("demo", None));
    assert_eq!(first["promoted"], 2);
    assert_eq!(first["reused"], 0);
    for p in first["participants"].as_array().unwrap() {
        assert_eq!(p["symbiote"]["isolated_correct"], 16);
        assert_eq!(p["symbiote"]["exchange_correct"], 32);
        assert_eq!(p["symbiote"]["matched_probe_control_correct"], 32);
        assert_eq!(p["partner_benefit"]["after_correct"], 32);
        assert_eq!(p["partner_benefit"]["baseline_resource_units"], 176);
        assert_eq!(
            p["partner_benefit"]["strategy_resource_units_including_verification"],
            72
        );
    }
    let retained = json_output(dir.run("predict", None));
    assert_eq!(retained["identity"], first["identity"]);
    assert_eq!(retained["network_requests"], 0);
    assert_eq!(retained["active_artifacts"], 2);
    let second = json_output(dir.run("demo", None));
    assert_eq!(second["identity"], first["identity"]);
    assert_eq!(second["promoted"], 0);
    assert_eq!(second["reused"], 2);
}

#[test]
fn counterexample_is_rejected_without_learning() {
    let dir = RunDir::new();
    let failed = dir.run("demo", Some("wrong-artifact"));
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("knowledge rejected"));
    let receipt: Value =
        serde_json::from_slice(&fs::read(dir.0.join("receipt.json")).unwrap()).unwrap();
    assert_eq!(receipt["status"], "REJECTED");
    assert_eq!(json_output(dir.run("predict", None))["active_artifacts"], 0);
    // A rejected candidate never consumed a version; recovery can accept a valid offer.
    assert_eq!(json_output(dir.run("demo", None))["promoted"], 2);
}

#[test]
fn drift_revokes_previous_knowledge_and_reports_failure() {
    let dir = RunDir::new();
    json_output(dir.run("demo", None));
    let drift = dir.run("demo", Some("drift"));
    assert!(!drift.status.success());
    let retained = json_output(dir.run("predict", None));
    assert_eq!(retained["active_artifacts"], 1);
    assert_eq!(retained["predictions"][0]["partner"], "beta");
    let recovered = json_output(dir.run("demo", None));
    assert_eq!(recovered["identity"], retained["identity"]);
    assert_eq!(recovered["promoted"], 1);
    assert_eq!(recovered["reused"], 1);
    let reloaded = json_output(dir.run("predict", None));
    assert_eq!(reloaded["predictions"][0]["revision"], 2);
}

#[test]
fn operator_rollback_requires_a_new_evaluated_revision() {
    let dir = RunDir::new();
    let first = json_output(dir.run("demo", None));
    let rollback = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .arg("revoke")
        .arg("--state")
        .arg(dir.0.join("state"))
        .arg("--artifact")
        .arg("alpha-table")
        .output()
        .unwrap();
    assert_eq!(json_output(rollback)["active_artifacts"], 1);
    let recovered = json_output(dir.run("demo", None));
    assert_eq!(recovered["identity"], first["identity"]);
    assert_eq!(recovered["promoted"], 1);
    assert_eq!(
        json_output(dir.run("predict", None))["predictions"][0]["revision"],
        2
    );
}

#[test]
fn corrupt_memory_is_not_silently_reset() {
    let dir = RunDir::new();
    json_output(dir.run("demo", None));
    let ledger = dir.0.join("state").join("ledger.jsonl");
    let mut data = fs::read(&ledger).unwrap();
    data[12] ^= 1;
    fs::write(&ledger, data).unwrap();
    assert!(!dir.run("predict", None).status.success());
}
