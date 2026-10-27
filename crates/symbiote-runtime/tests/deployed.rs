use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use symbiote_memory::knowledge::{
    affine_schema_fingerprint, assess, KnowledgeRecord, KnowledgeStore, TrialCase, TrialCosts,
    TrialEvidence,
};
use symbiote_memory::{maintenance, Store};
use symbiote_protocol::{Client, Endpoint};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "symbiote-deployed-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_network(directory: &Path, fault: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_symbiote"));
    command
        .args(["network-research", "--json", "--state"])
        .arg(directory.join("state"))
        .arg("--receipts")
        .arg(directory.join("report.json"));
    if let Some(fault) = fault {
        command.args(["--fault", fault]);
    }
    command.output().unwrap()
}

#[test]
fn native_peers_have_separate_processes_private_identities_and_retained_predictions() {
    let dir = Directory::new();
    let output = run_network(&dir.0, None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["process_separation"], true);
    assert_eq!(report["forged_receipt_rejected"], true);
    assert_eq!(report["cross_domain_receipt_rejected"], true);
    assert_eq!(report["duplicate_receipt_rejected"], true);
    assert_eq!(report["restart_retained_predictions"], true);
    assert_eq!(report["restart_acquisition_requests"], 0);
    assert_eq!(report["restart_verification_requests"], 0);
    assert_eq!(report["restart_assessment_requests"], 0);
    assert!(report["oracle_requests"]["observe"].as_u64().unwrap() > 0);
    let peers = report["participants"].as_array().unwrap();
    assert_ne!(peers[0]["pid"], peers[1]["pid"]);
    assert_ne!(peers[0]["pid"], report["controller_pid"]);
    assert_ne!(peers[1]["pid"], report["controller_pid"]);
    assert_ne!(peers[0]["identity"], peers[1]["identity"]);
    assert_ne!(peers[0]["identity"], report["identity"]);
    assert_ne!(peers[1]["identity"], report["identity"]);
    for peer in peers {
        assert_ne!(peer["instance_nonce"], peer["restart_instance_nonce"]);
        assert!(peer["restart_oracle_requests"]
            .as_object()
            .unwrap()
            .values()
            .all(|count| count == 0));
        assert_eq!(peer["promotion"]["correct"], 11);
        assert_eq!(peer["active_models"], 1);
    }
    let again = run_network(&dir.0, None);
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    let second: Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(second["identity"], report["identity"]);
    for i in 0..2 {
        assert_eq!(
            second["participants"][i]["identity"],
            report["participants"][i]["identity"]
        );
        assert_eq!(second["participants"][i]["promotion"]["promoted"], false);
    }
}

#[test]
fn copied_controller_identity_is_rejected_without_rewriting_or_learning() {
    let dir = Directory::new();
    let state = dir.0.join("state");
    {
        Store::open(&state).unwrap();
    }
    let original = fs::read(state.join("ledger.jsonl")).unwrap();
    let child_state = state.join("network/exact");
    fs::create_dir_all(&child_state).unwrap();
    fs::write(child_state.join("ledger.jsonl"), &original).unwrap();
    let result = run_network(&dir.0, None);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("identity aliases the controller"));
    assert_eq!(fs::read(state.join("ledger.jsonl")).unwrap(), original);
    assert_eq!(
        fs::read(child_state.join("ledger.jsonl")).unwrap(),
        original
    );
    assert!(
        !child_state.join("knowledge.jsonl").exists(),
        "alias rejected before a learning ledger is created"
    );
    assert!(!child_state.join("writer.lock").exists());
    assert!(!dir.0.join("report.json").exists());
}

#[test]
fn copied_peer_identity_is_rejected_before_exchange_without_reset() {
    let dir = Directory::new();
    let state = dir.0.join("state");
    {
        Store::open(&state).unwrap();
    }
    let exact = state.join("network/exact");
    {
        Store::open(&exact).unwrap();
    }
    let original = fs::read(exact.join("ledger.jsonl")).unwrap();
    let linear = state.join("network/linear");
    fs::create_dir_all(&linear).unwrap();
    fs::write(linear.join("ledger.jsonl"), &original).unwrap();
    let result = run_network(&dir.0, None);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("identities alias each other"));
    assert_eq!(fs::read(exact.join("ledger.jsonl")).unwrap(), original);
    assert_eq!(fs::read(linear.join("ledger.jsonl")).unwrap(), original);
    assert!(!linear.join("knowledge.jsonl").exists());
    assert_eq!(
        fs::read_to_string(exact.join("knowledge.jsonl"))
            .unwrap()
            .lines()
            .count(),
        1,
        "no promotion before identity separation"
    );
    assert!(!exact.join("writer.lock").exists());
    assert!(!dir.0.join("report.json").exists());
}

#[test]
fn supervised_faults_are_bounded_preserve_ledgers_and_recover_explicitly() {
    for fault in [
        "startup-timeout",
        "crash-after-ready",
        "crash-after-promotion",
    ] {
        let dir = Directory::new();
        let began = Instant::now();
        let output = run_network(&dir.0, Some(fault));
        assert!(!output.status.success(), "{fault} should fail");
        assert!(
            began.elapsed() < Duration::from_secs(15),
            "{fault} exceeded supervision bound"
        );
        let state = dir.0.join("state/network/exact");
        let ledger = fs::read(state.join("ledger.jsonl")).unwrap();
        let knowledge = fs::read(state.join("knowledge.jsonl")).unwrap();
        assert!(
            Store::open(&state).is_err(),
            "crash must not silently break stale locks"
        );
        let recovery = maintenance::recover(&state).unwrap();
        assert_eq!(recovery.recovered_locks.len(), 2);
        assert!(!recovery.ledgers_modified);
        assert_eq!(fs::read(state.join("ledger.jsonl")).unwrap(), ledger);
        assert_eq!(fs::read(state.join("knowledge.jsonl")).unwrap(), knowledge);
        let peer = dir.0.join("state/network/linear");
        if peer.exists() {
            maintenance::recover(&peer).unwrap();
        }
        let recovered = run_network(&dir.0, None);
        assert!(
            recovered.status.success(),
            "{fault}: {}",
            String::from_utf8_lossy(&recovered.stderr)
        );
        if fault == "crash-after-promotion" {
            let report: Value = serde_json::from_slice(&recovered.stdout).unwrap();
            assert_eq!(
                report["participants"][0]["promotion"]["promoted"], false,
                "committed learning must survive the failed acknowledgement"
            );
        }
    }
}

struct RawPartner {
    child: Child,
    input: Option<ChildStdin>,
    ready: Value,
}
fn raw_configuration(state: &Path, width: u8) -> Value {
    json!({"version":1,"id":"test-native-agent","controller":"test-controller","peer":"test-other-agent","token":"test-capability-only-in-stdin","oracle":{"id":"test-oracle","address":"127.0.0.1:9","token":"test-oracle-capability-private"},"state":state,"source_domain":"test-source","target_domain":"test-target","width":width,"linear":false,"lease_ms":10000,"fault":""})
}
impl RawPartner {
    fn start(state: &Path) -> Self {
        let config = raw_configuration(state, 3);
        let mut command = Command::new(env!("CARGO_BIN_EXE_symbiote"));
        command
            .arg("__research-partner")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        assert!(command
            .get_args()
            .all(|arg| !arg.to_string_lossy().contains("test-capability")));
        let mut child = command.spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        writeln!(input, "{config}").unwrap();
        input.flush().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut line = String::new();
            BufReader::new(stdout).read_line(&mut line).unwrap();
            sender.send(line).unwrap();
        });
        let line = match receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(line) => line,
            Err(_) => {
                if child.try_wait().unwrap().is_none() {
                    child.kill().unwrap();
                }
                child.wait().unwrap();
                panic!("native partner did not become ready");
            }
        };
        reader.join().unwrap();
        assert!(!line.contains("test-capability-only-in-stdin"));
        assert!(!line.contains("test-oracle-capability-private"));
        let ready: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(ready["pid"], child.id());
        Self {
            child,
            input: Some(input),
            ready,
        }
    }
    fn stop(&mut self) {
        writeln!(self.input.as_mut().unwrap(), "{{\"command\":\"shutdown\"}}").unwrap();
        self.input.take();
        let deadline = Instant::now() + Duration::from_secs(4);
        while self.child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        assert!(self.child.wait().unwrap().success());
    }
}
impl Drop for RawPartner {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
fn live_native_writer_cannot_be_recovered_and_capabilities_stay_off_output() {
    let dir = Directory::new();
    let mut peer = RawPartner::start(&dir.0);
    assert!(maintenance::recover(&dir.0).is_err());
    let endpoint = Endpoint {
        id: "test-native-agent".into(),
        address: peer.ready["address"].as_str().unwrap().parse().unwrap(),
        token: "test-capability-only-in-stdin".into(),
    };
    let mut client = Client::connect_scoped(
        &endpoint,
        "test-controller",
        &["status"],
        "boolean-affine/v1",
    )
    .unwrap();
    let status = client.call("status", &json!({})).unwrap();
    assert_eq!(status["identity"], peer.ready["identity"]);
    client.revoke().unwrap();
    peer.stop();
    let mut error = String::new();
    peer.child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut error)
        .unwrap();
    assert!(!error.contains("test-capability"));
    assert!(!dir.0.join("writer.lock").exists());
    assert!(!dir.0.join("knowledge.writer.lock").exists());
}

#[test]
fn owner_pipe_eof_cancels_the_native_partner_without_breaking_private_ledgers() {
    let dir = Directory::new();
    let mut peer = RawPartner::start(&dir.0);
    peer.input.take();
    let deadline = Instant::now() + Duration::from_secs(4);
    while peer.child.try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "owner cancellation did not stop the partner"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !peer.child.wait().unwrap().success(),
        "unexpected owner loss must be reported"
    );
    let inspection = maintenance::inspect(&dir.0).unwrap();
    assert_eq!(inspection.ledger_integrity, "verified_snapshot");
    assert!(!dir.0.join("writer.lock").exists());
    assert!(!dir.0.join("knowledge.writer.lock").exists());
}

#[test]
fn malformed_native_configuration_never_echoes_capability_contents() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .arg("__research-partner")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"{\"token\":\"sensitive-test-value-do-not-echo\"}\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("sensitive-test-value-do-not-echo"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("sensitive-test-value-do-not-echo"));
}

#[test]
fn valid_retained_model_cannot_be_used_under_a_different_input_schema() {
    let dir = Directory::new();
    {
        let identity = Store::open(&dir.0).unwrap();
        let record = KnowledgeRecord { id:"deployed-test-target".into(), revision:1, source:"test-other-agent".into(), scope:"boolean-affine/v1/test-target".into(), schema_fingerprint:affine_schema_fingerprint(3).unwrap(), payload:json!({"kind":"affine","width":3,"coefficients":3,"bias":false}), provenance:"valid three-bit laboratory model; must not become a four-bit model by reconfiguration".into() };
        let evidence = TrialEvidence {
            evaluator: "distinct-schema-test-judge".into(),
            training_case_ids: vec!["training-0".into()],
            training_inputs: vec![0],
            cases: (1_u16..8)
                .map(|input| {
                    let output = ((input & 3).count_ones() & 1) as u8;
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
                baseline: 0,
                candidate: 9,
            },
        };
        let assessment = assess(&record, &evidence).unwrap();
        KnowledgeStore::open(&dir.0, identity.identity())
            .unwrap()
            .promote(record, assessment)
            .unwrap();
    }
    let before = fs::read(dir.0.join("knowledge.jsonl")).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .arg("__research-partner")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(
        child.stdin.take().unwrap(),
        "{}",
        raw_configuration(&dir.0, 4)
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "mismatched stored schema must be rejected before readiness or prediction"
    );
    assert_eq!(fs::read(dir.0.join("knowledge.jsonl")).unwrap(), before);
    assert!(!dir.0.join("writer.lock").exists());
    assert!(!dir.0.join("knowledge.writer.lock").exists());
}
