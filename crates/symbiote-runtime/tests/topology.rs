//! Native topology engineering fixture; interacting nodes are not independent samples.
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "symbiote-native-topology-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn three_owned_tls_agents_forward_validate_retain_and_revoke_with_negative_costs() {
    let directory = Directory::new();
    let state = directory.0.join("state");
    let receipts = directory.0.join("receipts");
    let stdout = fs::File::create(directory.0.join("stdout.json")).unwrap();
    let stderr = fs::File::create(directory.0.join("stderr.txt")).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .arg("topology-research")
        .args([
            "--state",
            state.to_str().unwrap(),
            "--receipts",
            receipts.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("topology engineering fixture exceeded owned-process deadline");
        }
        thread::sleep(Duration::from_millis(10));
    };
    assert!(
        status.success(),
        "{}",
        fs::read_to_string(directory.0.join("stderr.txt")).unwrap()
    );
    let mut bytes = Vec::new();
    fs::File::open(receipts.join("summary.json"))
        .unwrap()
        .take(262_145)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 262_144);
    let report: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(report["status"], "ENGINEERING_PASS");
    assert_eq!(report["successful_inert_hops"], 6);
    assert_eq!(report["identities"].as_array().unwrap().len(), 3);
    let initial = report["initial_pids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect::<BTreeSet<_>>();
    let restarted = report["restarted_pids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(initial.len(), 3);
    assert_eq!(restarted.len(), 3);
    assert!(initial.is_disjoint(&restarted));
    for delivery in report["deliveries"].as_array().unwrap() {
        assert_eq!(delivery["delivered"], true);
        assert_eq!(delivery["acknowledgment"]["quarantined"], true);
        assert_eq!(delivery["acknowledgment"]["promoted"], false);
        assert_eq!(
            delivery["source_identity"],
            delivery["acknowledgment"]["authenticated_source"]
        );
    }
    assert_eq!(report["no_direct_a_c_tls_grant"]["tls_denied"], true);
    assert_eq!(report["tls_revocation_denial"]["tls_denied"], true);
    for proof in [
        &report["no_direct_a_c_tls_grant"],
        &report["tls_revocation_denial"],
    ] {
        assert_eq!(proof["admission_verdict"], "VERIFIED_SERVER_POLICY_DENIAL");
        assert_eq!(proof["source_probe"]["tls_denied"], false);
        assert_eq!(
            proof["source_probe"]["admission_verdict"],
            "HOLD_UNVERIFIED_CONNECT_FAILURE"
        );
        assert_eq!(proof["live_before"]["pid"], proof["live_after"]["pid"]);
        assert_eq!(
            proof["live_before"]["listener_instance"],
            proof["live_after"]["listener_instance"]
        );
        assert_eq!(
            proof["receiver_after"]["session_failures"]
                .as_u64()
                .unwrap(),
            proof["receiver_before"]["session_failures"]
                .as_u64()
                .unwrap()
                + 1
        );
        assert_eq!(
            proof["receiver_before"]["quarantined"],
            proof["receiver_after"]["quarantined"]
        );
        assert!(!proof["source_probe"]["connect_error"]
            .as_str()
            .unwrap()
            .is_empty());
    }
    assert_eq!(report["persisted_revocation_denial"]["delivered"], false);
    assert_eq!(report["reopened_revocation_denial"]["delivered"], false);
    assert_eq!(
        report["charged_failed_delivery"]["snapshot"]["receipts"]
            .as_array()
            .unwrap()
            .len(),
        7
    );
    assert_eq!(
        report["charged_failed_delivery"]["snapshot"]["receipts"][6]["outcome"],
        "delivery-unknown"
    );
    assert_eq!(report["aggregate_exhaustion_denial"]["delivered"], false);
    assert_eq!(
        report["network_snapshot"]["receipts"]
            .as_array()
            .unwrap()
            .len(),
        7
    );
    for (before, after) in report["before_restart"]
        .as_array()
        .unwrap()
        .iter()
        .zip(report["after_restart"].as_array().unwrap())
    {
        assert_eq!(before["identity"], after["identity"]);
        assert_eq!(before["history_anchor"], after["history_anchor"]);
        assert_eq!(before["knowledge_records"], 2);
        assert_eq!(after["knowledge_records"], 2);
        assert_eq!(after["retained_predictions"], serde_json::json!([1, 3]));
        assert_eq!(after["meter"]["source_warmup_oracle_calls"], 0);
        assert_eq!(after["meter"]["validation_oracle_calls"], 0);
        assert_eq!(after["meter"]["evaluation_oracle_calls"], 0);
        assert_eq!(after["meter"]["fresh_promotions"], 0);
        assert!(
            before["meter"]["secure_plaintext_quote_bytes"]
                .as_u64()
                .unwrap()
                <= 4 * 1024 * 1024
        );
    }
    assert!(report["aggregate_cost_saving_work_units"].as_i64().unwrap() < 0);
    assert_eq!(
        report["all_participants_positive_complete_cost_benefit"],
        false
    );
    // Every source's warmup is charged once, independently from receiver verification.
    let warmup: u64 = report["before_restart"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["meter"]["source_warmup_oracle_calls"].as_u64().unwrap())
        .sum();
    let verification: u64 = report["before_restart"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["meter"]["validation_oracle_calls"].as_u64().unwrap())
        .sum();
    assert_eq!(warmup, 4);
    assert_eq!(verification, 8);
    for entry in walk(&state) {
        let text = fs::read_to_string(entry).unwrap();
        assert!(!text.contains("PRIVATE KEY"));
    }
    let digest_before = fs::read(receipts.join("summary.json")).unwrap();
    let retry = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .arg("topology-research")
        .args([
            "--state",
            state.to_str().unwrap(),
            "--receipts",
            receipts.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!retry.status.success());
    assert_eq!(
        fs::read(receipts.join("summary.json")).unwrap(),
        digest_before
    );
}
fn walk(path: &std::path::Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            files.extend(walk(&entry.path()));
        } else {
            files.push(entry.path());
        }
    }
    files
}
