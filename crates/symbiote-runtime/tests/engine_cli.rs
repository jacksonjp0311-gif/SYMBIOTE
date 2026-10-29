//! Packaged native CLI invokes the actual typed Engine lifecycle.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};
use symbiote_runtime::engine::{EngineConfig, SourceDescriptor};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    base: PathBuf,
    config: PathBuf,
    observations: PathBuf,
}
impl Fixture {
    fn new(bad_commitment: bool) -> Self {
        let base = std::env::temp_dir().canonicalize().unwrap();
        let root = base.join(format!(
            "symbiote-engine-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let observations = root.join("observations.json");
        let bytes = serde_json::to_vec(&[0u16,1,2,4,3].iter().enumerate().map(|(sequence,input)|
            json!({"sequence":sequence,"input":input,"output":(input & 5).count_ones()%2})).collect::<Vec<_>>()).unwrap();
        fs::write(&observations, &bytes).unwrap();
        let descriptor = SourceDescriptor {
            source_id: "cli-owned-source".into(),
            scope: "unit-cli/v1".into(),
            epoch: "unit-cli-epoch-1".into(),
            commitment: if bad_commitment {
                "0".repeat(64)
            } else {
                format!("{:x}", Sha256::digest(bytes))
            },
            width: 3,
        };
        let config = root.join("config.json");
        fs::write(
            &config,
            serde_json::to_vec(&EngineConfig::new(vec![descriptor])).unwrap(),
        )
        .unwrap();
        Self {
            root,
            base,
            config,
            observations,
        }
    }
    fn run(&self, args: &[&str]) -> (Output, Value) {
        let output = Command::new(env!("CARGO_BIN_EXE_symbiote"))
            .arg("engine")
            .args(args)
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.stderr.is_empty(),
            "engine CLI must return typed JSON, stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
            panic!(
                "one JSON report required: {e}; stdout={}",
                String::from_utf8_lossy(&output.stdout)
            )
        });
        assert_eq!(report["schema"], "symbiote.engine-cli/1");
        (output, report)
    }
    fn ok(&self, args: &[&str]) -> Value {
        let (output, report) = self.run(args);
        assert!(output.status.success(), "{report}");
        assert_eq!(report["status"], "PASS");
        report
    }
    fn legacy_refuses(&self, state: &Path) {
        let census = || {
            let mut rows = std::collections::BTreeMap::new();
            for entry in fs::read_dir(state).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_file() {
                    rows.insert(entry.file_name(), fs::read(entry.path()).unwrap());
                }
            }
            rows
        };
        let before = census();
        let output = Command::new(env!("CARGO_BIN_EXE_symbiote"))
            .args([
                "observe-demo",
                "--state",
                text(state),
                "--receipts",
                text(&self.root.join("legacy-must-not-write.json")),
                "--json",
            ])
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "legacy writer must refuse closed engine state"
        );
        assert_eq!(
            census(),
            before,
            "legacy refusal must preserve all regular owner file bytes"
        );
        assert!(!self.root.join("legacy-must-not-write.json").exists());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("engine CLI fixture preserved: {}", self.root.display());
            return;
        }
        if let Ok(root) = self.root.canonicalize() {
            if root.parent() == Some(self.base.as_path())
                && root
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("symbiote-engine-cli-")
            {
                let _ = fs::remove_dir_all(root);
            }
        }
    }
}
fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}
#[test]
fn native_typed_engine_learns_reopens_without_source_cancels_and_restores() {
    let fixture = Fixture::new(false);
    let state = fixture.root.join("owner");
    let initialized = fixture.ok(&[
        "init",
        "--state",
        text(&state),
        "--config",
        text(&fixture.config),
    ]);
    let owner = initialized["inspection"]["owner"].as_str().unwrap();
    assert_eq!(initialized["inspection"]["knowledge"]["records"], 1);
    fixture.legacy_refuses(&state);
    let learn = [
        "learn",
        "--state",
        text(&state),
        "--owner",
        owner,
        "--config",
        text(&fixture.config),
        "--source",
        "cli-owned-source",
        "--observations",
        text(&fixture.observations),
    ];
    let first = fixture.ok(&learn);
    let artifact = first["result"]["learning"]["artifact"].as_str().unwrap();
    assert_eq!(first["result"]["learning"]["usage"]["source_calls"], 5);
    assert_eq!(first["source_access"]["calls"], 5);
    assert_eq!(first["source_access"]["file_opened"], true);
    assert_eq!(first["counters"]["promotions"]["ordinary_learning"], 1);
    assert_eq!(first["resources"]["schema"], "symbiote.engine-resources/1");
    fs::remove_file(&fixture.observations).unwrap();
    let retained = fixture.ok(&learn);
    assert_eq!(retained["result"]["learning"]["reused"], true);
    assert_eq!(
        retained["source_access"],
        json!({"calls":0,"read_bytes":0,"file_opened":false})
    );
    assert_eq!(
        retained["inspection"]["knowledge"],
        first["inspection"]["knowledge"]
    );
    let predict = [
        "predict",
        "--state",
        text(&state),
        "--owner",
        owner,
        "--config",
        text(&fixture.config),
        "--artifact",
        artifact,
        "--input",
        "6",
    ];
    let prediction = fixture.ok(&predict);
    assert_eq!(prediction["result"]["prediction"]["answer"], 1);
    assert_eq!(
        prediction["result"]["prediction"]["basis"],
        "conditional_affine"
    );
    let mut cancelled = learn.to_vec();
    cancelled.push("--cancelled");
    let (status, cancelled) = fixture.run(&cancelled);
    assert!(!status.status.success());
    assert_eq!(cancelled["error"]["kind"], "cancelled");
    assert_eq!(
        cancelled["source_access"],
        json!({"calls":0,"read_bytes":0,"file_opened":false})
    );
    assert_eq!(
        cancelled["inspection"]["knowledge"],
        first["inspection"]["knowledge"]
    );
    let backup = fixture.root.join("backup");
    let checkpoint = fixture.ok(&[
        "checkpoint",
        "--state",
        text(&state),
        "--owner",
        owner,
        "--config",
        text(&fixture.config),
        "--backup",
        text(&backup),
    ]);
    let checkpoint_file = fixture.root.join("checkpoint.json");
    fs::write(&checkpoint_file, serde_json::to_vec(&checkpoint).unwrap()).unwrap();
    let pin = checkpoint["result"]["checkpoint"]["manifest_sha256"]
        .as_str()
        .unwrap();
    fixture.ok(&[
        "revoke",
        "--state",
        text(&state),
        "--owner",
        owner,
        "--config",
        text(&fixture.config),
        "--artifact",
        artifact,
        "--reason",
        "unit caller revocation",
    ]);
    let (status, revoked) = fixture.run(&predict);
    assert!(!status.status.success());
    assert_eq!(revoked["error"]["kind"], "revoked");
    let restored = fixture.root.join("restored");
    let restored_receipt = fixture.ok(&[
        "restore",
        "--state",
        text(&restored),
        "--owner",
        owner,
        "--config",
        text(&fixture.config),
        "--checkpoint",
        text(&checkpoint_file),
        "--manifest-sha256",
        pin,
    ]);
    assert_eq!(
        restored_receipt["result"]["restore"]["rollback_discards_later_learning"],
        true
    );
    assert_eq!(
        restored_receipt["result"]["restore"]["network_started"],
        false
    );
    let answer = fixture.ok(&[
        "predict",
        "--state",
        text(&restored),
        "--owner",
        owner,
        "--config",
        text(&fixture.config),
        "--artifact",
        artifact,
        "--input",
        "6",
    ]);
    assert_eq!(answer["result"]["prediction"]["answer"], 1);
    assert_eq!(answer["inspection"]["owner"], owner);
    fixture.legacy_refuses(&restored);
    fixture.ok(&["recover", "--state", text(&restored), "--owner", owner]);
}
#[test]
fn native_engine_rejects_unpinned_frames_and_cancellation_never_opens_source() {
    let fixture = Fixture::new(true);
    let state = fixture.root.join("owner");
    let initial = fixture.ok(&[
        "init",
        "--state",
        text(&state),
        "--config",
        text(&fixture.config),
    ]);
    let owner = initial["inspection"]["owner"].as_str().unwrap();
    let learn = [
        "learn",
        "--state",
        text(&state),
        "--owner",
        owner,
        "--config",
        text(&fixture.config),
        "--source",
        "cli-owned-source",
        "--observations",
        text(&fixture.observations),
    ];
    let (output, rejected) = fixture.run(&learn);
    assert!(!output.status.success());
    assert_eq!(rejected["error"]["kind"], "authorization");
    assert_eq!(
        rejected["inspection"]["knowledge"],
        initial["inspection"]["knowledge"]
    );
    assert_eq!(rejected["source_access"]["calls"], 1);
    assert_eq!(rejected["source_access"]["file_opened"], true);
    fs::remove_file(&fixture.observations).unwrap();
    let mut cancelled = learn.to_vec();
    cancelled.push("--cancelled");
    let (output, report) = fixture.run(&cancelled);
    assert!(!output.status.success());
    assert_eq!(report["error"]["kind"], "cancelled");
    assert_eq!(
        report["source_access"],
        json!({"calls":0,"read_bytes":0,"file_opened":false})
    );
    assert_eq!(
        report["inspection"]["knowledge"],
        initial["inspection"]["knowledge"]
    );
    let fresh = fixture.root.join("not-created");
    let (output, report) = fixture.run(&[
        "init",
        "--state",
        text(&fresh),
        "--config",
        text(&fixture.config),
        "--observations",
        "unknown",
    ]);
    assert!(!output.status.success());
    assert_eq!(report["error"]["kind"], "malformed");
    assert!(!fresh.exists());
}

#[test]
fn native_engine_replay_frames_are_bounded_data_and_must_match_selected_queries() {
    for case in ["unknown-field", "wrong-query", "oversize"] {
        let fixture = Fixture::new(false);
        let bytes = if case == "oversize" {
            vec![b' '; 128 * 1024 + 17]
        } else {
            let mut frames: Value =
                serde_json::from_slice(&fs::read(&fixture.observations).unwrap()).unwrap();
            if case == "unknown-field" {
                frames[0]["strategy"] = json!("inert data cannot introduce a strategy");
            } else {
                // The ordinary engine's first selected query is zero.
                frames[0]["input"] = json!(7);
            }
            serde_json::to_vec(&frames).unwrap()
        };
        fs::write(&fixture.observations, &bytes).unwrap();
        let mut config: EngineConfig =
            serde_json::from_slice(&fs::read(&fixture.config).unwrap()).unwrap();
        config.authorized_sources[0].commitment = format!("{:x}", Sha256::digest(&bytes));
        fs::write(&fixture.config, serde_json::to_vec(&config).unwrap()).unwrap();
        let state = fixture.root.join("owner");
        let initial = fixture.ok(&[
            "init",
            "--state",
            text(&state),
            "--config",
            text(&fixture.config),
        ]);
        let owner = initial["inspection"]["owner"].as_str().unwrap();
        let (output, rejected) = fixture.run(&[
            "learn",
            "--state",
            text(&state),
            "--owner",
            owner,
            "--config",
            text(&fixture.config),
            "--source",
            "cli-owned-source",
            "--observations",
            text(&fixture.observations),
        ]);
        assert!(!output.status.success());
        assert_eq!(
            rejected["error"]["kind"],
            if case == "oversize" {
                "budget_exhausted"
            } else {
                "malformed"
            }
        );
        assert_eq!(
            rejected["inspection"]["knowledge"],
            initial["inspection"]["knowledge"]
        );
        assert_eq!(rejected["source_access"]["calls"], 1);
        if case == "oversize" {
            assert_eq!(rejected["source_access"]["read_bytes"], 128 * 1024 + 1);
        }
    }
}
