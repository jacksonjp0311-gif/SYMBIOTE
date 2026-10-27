use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use symbiote_memory::knowledge::KnowledgeStore;
use symbiote_memory::{maintenance, Store};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "symbiote-graph-{}-{}",
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
fn total(meter: &Value, price: u64) -> u64 {
    let count = |field: &str| meter[field].as_u64().unwrap();
    count("acquisitions") * price
        + count("endpoint_requests")
        + count("oracle_requests")
        + count("sessions") * 2
        + count("sent_bytes").div_ceil(1024)
        + count("received_bytes").div_ceil(1024)
        + count("verified_receipts") * 2
        + count("adopted_edges")
        + count("route_queries")
        + count("model_work")
        + count("exported_bytes").div_ceil(1024)
}

#[test]
fn complete_predeclared_cohort_accounts_for_every_world_and_retains_only_complete_holdouts() {
    let directory = Directory::new();
    let state = directory.0.join("state");
    let receipt = directory.0.join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .args(["graph-research", "--json", "--state"])
        .arg(&state)
        .arg("--receipts")
        .arg(&receipt)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report,
        serde_json::from_slice::<Value>(&fs::read(&receipt).unwrap()).unwrap()
    );
    assert_eq!(report["status"], "PASS");
    assert_eq!(report["endpoint_process_separation"], false);
    assert_eq!(report["incorrect_certificates"], 0);
    assert_eq!(report["restart_retained_predictions"], true);
    assert_ne!(report["process_id"], report["restart_process_id"]);
    assert_eq!(
        report["oracle_requests_before_restart"],
        report["oracle_requests_after_restart"]
    );
    assert_eq!(
        report["restart_oracle_requests"],
        json!({"observe":0,"verify":0})
    );
    assert!(report["negative_controls"]
        .as_object()
        .unwrap()
        .values()
        .all(|value| value == true));
    let protocol = include_str!("../../../docs/RESEARCH_V04_PROTOCOL.md").replace("\r\n", "\n");
    assert_eq!(
        report["protocol_sha256"],
        format!("{:x}", Sha256::digest(protocol.as_bytes()))
    );
    let mut promoted = 0;
    let mut withheld = 0;
    for regime in report["regimes"].as_array().unwrap() {
        let cases = regime["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 81);
        let price = regime["observation_price"].as_u64().unwrap();
        let mut baseline_sum = 0;
        let mut candidate_sum = 0;
        assert!(
            regime["classes"]["equal_coverage_higher_cost"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(
            regime["classes"]
                .as_object()
                .unwrap()
                .values()
                .map(|value| value.as_u64().unwrap())
                .sum::<u64>(),
            162
        );
        for (world, case) in cases.iter().enumerate() {
            assert_eq!(case["world"], world);
            let costs = case["costs"].as_array().unwrap();
            for participant in case["participants"].as_array().unwrap() {
                let base = total(&participant["isolated"], price);
                let candidate = total(&participant["exchange"], price);
                assert_eq!(participant["isolated_cost"], base);
                assert_eq!(participant["exchange_cost"], candidate);
                baseline_sum += base;
                candidate_sum += candidate;
                assert_eq!(participant["exchange"]["verified_receipts"], 1);
                assert_eq!(participant["exchange"]["adopted_edges"], 1);
                assert_eq!(participant["isolated"]["verified_receipts"], 0);
                for arm in ["isolated", "exchange"] {
                    let predictions = participant[format!("{arm}_forecasts")].as_array().unwrap();
                    assert_eq!(predictions.len(), 2);
                    let mut certified = 0;
                    for (query, prediction) in predictions.iter().enumerate() {
                        if !prediction.is_null() {
                            certified += 1;
                            assert_eq!(prediction["nodes"], json!([query + 1, 3]));
                            assert_eq!(prediction["edges"], json!([query * 2 + 1]));
                            assert_eq!(prediction["cost"], costs[query * 2 + 1]);
                            assert_eq!(prediction["cost_basis"], "observed_edge_costs");
                        }
                    }
                    assert_eq!(participant[format!("{arm}_heldout_correct")], certified);
                    assert_eq!(participant[format!("{arm}_abstentions")], 2 - certified);
                }
                if regime["name"] == "normal" {
                    if participant["exchange_heldout_correct"] == 2 {
                        assert_eq!(participant["promotion"], "promoted");
                        promoted += 1;
                    } else {
                        assert_eq!(participant["promotion"], "withheld_abstention");
                        withheld += 1;
                    }
                }
            }
        }
        assert_eq!(regime["isolated_cost"], baseline_sum);
        assert_eq!(regime["exchange_cost"], candidate_sum);
    }
    assert!(promoted > 0 && withheld > 0);
    assert_eq!(promoted + withheld, 162);
    assert_eq!(report["promotions"]["promoted"], promoted);
    assert_eq!(report["promotions"]["withheld_abstention"], withheld);
    let mut retained = 0;
    for peer in report["state_directories"].as_array().unwrap() {
        let path = PathBuf::from(peer["state"].as_str().unwrap());
        let inspection = maintenance::inspect(&path).unwrap();
        let knowledge =
            KnowledgeStore::open(&path, inspection.identity.as_deref().unwrap()).unwrap();
        retained += knowledge.active().len();
        for record in knowledge.active() {
            let evidence = knowledge.graph_evidence(&record.id).unwrap();
            assert_eq!(evidence.cases.len(), 2);
            assert_eq!(evidence.training_tasks.len(), 2);
            assert_eq!(evidence.acquisitions.len(), 4);
            assert!(evidence.cases.iter().all(|case| evidence
                .training_tasks
                .iter()
                .all(|task| task.input != case.input)));
        }
    }
    assert_eq!(retained, promoted);
    let example = &report["example_query"];
    let path = PathBuf::from(example["state"].as_str().unwrap());
    let before = fs::read(path.join("knowledge.jsonl")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .args(["route", "--json", "--state"])
        .arg(&path)
        .arg("--artifact")
        .arg(example["artifact"].as_str().unwrap())
        .args(["--from", "1", "--to", "3"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let route: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(route["network_requests"], 0);
    assert_eq!(route["prediction_status"], "conditionally-certified");
    assert_eq!(route["route"]["nodes"], json!([1, 3]));
    assert_eq!(fs::read(path.join("knowledge.jsonl")).unwrap(), before);
    let manifest_path = state.join("graph/contexts.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let contexts = manifest["contexts"].as_array_mut().unwrap();
    assert_eq!(contexts.len(), 81);
    for (index, label) in contexts.iter().enumerate() {
        assert!(label.as_str().unwrap().starts_with("graph-context-"));
        assert_eq!(label, &report["regimes"][0]["cases"][index]["context"]);
    }
    let retained_world = example["artifact"]
        .as_str()
        .unwrap()
        .rsplit('-')
        .next()
        .unwrap()
        .parse::<usize>()
        .unwrap();
    contexts.swap(retained_world, (retained_world + 1) % 81);
    let changed_manifest = serde_json::to_vec(&manifest).unwrap();
    fs::write(&manifest_path, &changed_manifest).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .args(["graph-research", "--json", "--state"])
        .arg(&state)
        .arg("--receipts")
        .arg(directory.0.join("must-not-exist.json"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!directory.0.join("must-not-exist.json").exists());
    assert_eq!(fs::read(&manifest_path).unwrap(), changed_manifest);
    assert_eq!(fs::read(path.join("knowledge.jsonl")).unwrap(), before);
}

#[test]
fn copied_controller_identity_is_rejected_before_graph_knowledge_is_created() {
    let directory = Directory::new();
    let state = directory.0.join("state");
    drop(Store::open(&state).unwrap());
    let bytes = fs::read(state.join("ledger.jsonl")).unwrap();
    let copied = state.join("graph/dijkstra");
    fs::create_dir_all(&copied).unwrap();
    fs::write(copied.join("ledger.jsonl"), &bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .args(["graph-research", "--json", "--state"])
        .arg(&state)
        .arg("--receipts")
        .arg(directory.0.join("report.json"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read(copied.join("ledger.jsonl")).unwrap(), bytes);
    assert!(!copied.join("knowledge.jsonl").exists());
    assert!(!directory.0.join("report.json").exists());
}

#[test]
fn internal_forecast_rejects_unrecognized_configuration_without_echoing_it() {
    let marker = "do-not-echo-internal-graph-config";
    let mut child = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .arg("__graph-forecast")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{{\"unknown\":\"{marker}\"}}\n").as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(marker));
}

#[test]
fn internal_forecast_has_its_own_startup_deadline_when_owner_withholds_input() {
    let started = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .arg("__graph-forecast")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Holding the handle open distinguishes withheld input from clean owner EOF.
    let held_input = child.stdin.take().unwrap();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > Duration::from_secs(6) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("internal forecast missed its own startup deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    drop(held_input);
    assert!(!status.success());
    assert!(started.elapsed() < Duration::from_secs(6));
}

#[test]
fn missing_or_incompatible_opaque_context_mapping_never_resets_existing_evidence() {
    let directory = Directory::new();
    let state = directory.0.join("state");
    drop(Store::open(&state).unwrap());
    let owner = state.join("graph/dijkstra");
    fs::create_dir_all(&owner).unwrap();
    let marker = b"preserve-this-existing-knowledge";
    fs::write(owner.join("knowledge.jsonl"), marker).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .args(["graph-research", "--state"])
        .arg(&state)
        .arg("--receipts")
        .arg(directory.0.join("report.json"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!state.join("graph/contexts.json").exists());
    assert_eq!(fs::read(owner.join("knowledge.jsonl")).unwrap(), marker);
    fs::write(state.join("graph/contexts.json"), b"{\"schema\":\"wrong\"}").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .args(["graph-research", "--state"])
        .arg(&state)
        .arg("--receipts")
        .arg(directory.0.join("report.json"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        fs::read(state.join("graph/contexts.json")).unwrap(),
        b"{\"schema\":\"wrong\"}"
    );
    assert_eq!(fs::read(owner.join("knowledge.jsonl")).unwrap(), marker);
}
