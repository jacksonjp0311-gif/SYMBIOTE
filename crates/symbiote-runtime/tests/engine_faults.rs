//! Black-box owned-process cuts through only the documented embedding API.
//! These synthetic unit fixtures are not a registered scientific workload.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};
use symbiote_runtime::engine::{self, exchange::TransferTicket, *};

const CHILD_ROOT: &str = "SYMBIOTE_ENGINE_FAULT_CHILD_ROOT";
const CHILD_PHASE: &str = "SYMBIOTE_ENGINE_FAULT_CHILD_PHASE";
const CHILD_NONCE: &str = "SYMBIOTE_ENGINE_FAULT_CHILD_NONCE";
const ARTIFACTS: &str = "SYMBIOTE_ENGINE_FAULT_ARTIFACTS";
const LEDGERS: [&str; 3] = ["ledger.jsonl", "knowledge.jsonl", "operations.jsonl"];
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory {
    path: PathBuf,
    base: PathBuf,
    preserve: bool,
}
impl Directory {
    fn new(export: bool) -> Self {
        let base = std::env::temp_dir().canonicalize().unwrap();
        let requested = export.then(|| std::env::var_os(ARTIFACTS)).flatten();
        let preserve = requested.is_some();
        let path = requested.map(PathBuf::from).unwrap_or_else(|| {
            base.join(format!(
                "symbiote-engine-faults-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ))
        });
        assert!(
            path.is_absolute(),
            "fault export must be an absolute NEW directory"
        );
        fs::create_dir(&path).unwrap();
        Self {
            path,
            base,
            preserve,
        }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if self.preserve || thread::panicking() {
            if thread::panicking() {
                eprintln!("fault evidence preserved: {}", self.path.display());
            }
            return;
        }
        if let Ok(path) = self.path.canonicalize() {
            if path.parent() == Some(self.base.as_path())
                && path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("symbiote-engine-faults-")
            {
                let _ = fs::remove_dir_all(path);
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FilePin {
    bytes: usize,
    sha256: String,
}
fn pin(path: &Path) -> FilePin {
    assert!(fs::symlink_metadata(path).unwrap().is_file());
    let bytes = fs::read(path).unwrap();
    assert!(
        bytes.len() <= 3 * 1024 * 1024,
        "generic fault fixture exceeded its file bound"
    );
    FilePin {
        bytes: bytes.len(),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
    }
}
fn pins(path: &Path) -> BTreeMap<String, FilePin> {
    LEDGERS
        .into_iter()
        .map(|name| (name.to_owned(), pin(&path.join(name))))
        .collect()
}
fn write_synced(path: &Path, value: &impl Serialize) {
    let bytes = serde_json::to_vec_pretty(value).unwrap();
    assert!(bytes.len() < 128 * 1024);
    let temporary = path.with_extension("writing");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    drop(file);
    fs::rename(temporary, path).unwrap();
}
fn source_descriptor(scope: &str) -> SourceDescriptor {
    SourceDescriptor {
        source_id: format!("unit-fault-{scope}"),
        scope: scope.into(),
        epoch: "unit-fault-epoch-1".into(),
        commitment: "3".repeat(64),
        width: 3,
    }
}
fn configuration() -> EngineConfig {
    EngineConfig::new(vec![
        source_descriptor("fault-left"),
        source_descriptor("fault-right"),
    ])
}
fn options(source: &SourceDescriptor) -> EpisodeOptions {
    let mut options = EpisodeOptions::bounded(source.clone());
    options.query_policy = AffineQueryPolicy::RankBasis;
    options
}
struct Source {
    descriptor: SourceDescriptor,
    mask: u16,
    calls: usize,
    offline: bool,
}
impl Source {
    fn new(scope: &str, mask: u16) -> Self {
        Self {
            descriptor: source_descriptor(scope),
            mask,
            calls: 0,
            offline: false,
        }
    }
}
impl ObservationSource for Source {
    fn descriptor(&self) -> SourceDescriptor {
        self.descriptor.clone()
    }
    fn observe(
        &mut self,
        request: ObservationRequest<'_>,
    ) -> std::result::Result<Observation, SourceError> {
        if self.offline {
            return Err(SourceError::new(
                ErrorKind::Storage,
                "unit source deliberately unavailable",
            ));
        }
        assert_eq!(request.sequence, self.calls);
        assert_eq!(request.source, &self.descriptor);
        self.calls += 1;
        Ok(Observation {
            sequence: request.sequence,
            input: request.input,
            output: ((request.input & self.mask).count_ones() % 2) as u8,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct OwnerSnapshot {
    path: PathBuf,
    identity: String,
    knowledge: KnowledgeAnchor,
    artifact: Option<String>,
    ledgers: BTreeMap<String, FilePin>,
}
fn snapshot(engine: &Engine, path: &Path, artifact: Option<String>) -> OwnerSnapshot {
    let inspection = engine.inspect().unwrap();
    OwnerSnapshot {
        path: path.into(),
        identity: inspection.owner,
        knowledge: inspection.knowledge,
        artifact,
        ledgers: pins(path),
    }
}
#[derive(Debug, Serialize, Deserialize)]
struct Marker {
    schema: String,
    phase: String,
    nonce: String,
    child_pid: u32,
    owners: Vec<OwnerSnapshot>,
    ticket: Option<TransferTicket>,
    event: Option<serde_json::Value>,
}
fn barrier(
    root: &Path,
    phase: &str,
    nonce: &str,
    owners: Vec<OwnerSnapshot>,
    ticket: Option<TransferTicket>,
    event: Option<serde_json::Value>,
) -> ! {
    write_synced(
        &root.join("barrier.json"),
        &Marker {
            schema: "symbiote.engine-fault-barrier/1".into(),
            phase: phase.into(),
            nonce: nonce.into(),
            child_pid: std::process::id(),
            owners,
            ticket,
            event,
        },
    );
    // The parent owns this exact Child handle, verifies the marker and enforces
    // the deadline. No process is discovered or terminated by a supplied PID.
    loop {
        thread::sleep(Duration::from_millis(20));
    }
}
struct CutSink {
    root: PathBuf,
    path: PathBuf,
    phase: String,
    nonce: String,
    owner: String,
    before: KnowledgeAnchor,
}
impl EventSink for CutSink {
    fn event(&mut self, event: &EngineEvent) -> std::result::Result<(), SinkError> {
        let matched = matches!(
            (self.phase.as_str(), event),
            ("started", EngineEvent::EpisodeStarted { .. })
                | ("candidate", EngineEvent::CandidateReady { .. })
                | ("evaluated", EngineEvent::Evaluated { .. })
                | ("retained", EngineEvent::Retained { .. })
                | ("prediction", EngineEvent::Prediction { .. })
        );
        if matched {
            let (knowledge, artifact) = match event {
                EngineEvent::Retained { receipt } => {
                    (receipt.after.clone(), Some(receipt.artifact.clone()))
                }
                EngineEvent::Prediction { prediction } => (
                    prediction.knowledge_at.clone(),
                    Some(prediction.artifact.clone()),
                ),
                _ => (self.before.clone(), None),
            };
            barrier(
                &self.root,
                &self.phase,
                &self.nonce,
                vec![OwnerSnapshot {
                    path: self.path.clone(),
                    identity: self.owner.clone(),
                    knowledge,
                    artifact,
                    ledgers: pins(&self.path),
                }],
                None,
                Some(serde_json::to_value(event).unwrap()),
            );
        }
        Ok(())
    }
}

/// The ordinary test runner returns immediately; only a parent-owned child with
/// a fresh explicit root/phase/nonce enters a barrier.
#[test]
fn engine_fault_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT).map(PathBuf::from) else {
        return;
    };
    let phase = std::env::var(CHILD_PHASE).unwrap();
    let nonce = std::env::var(CHILD_NONCE).unwrap();
    assert!(root.is_absolute() && root.is_dir() && !root.join("barrier.json").exists());
    assert!(matches!(
        phase.as_str(),
        "started"
            | "candidate"
            | "evaluated"
            | "retained"
            | "prediction"
            | "quarantined"
            | "before-outcome"
    ));
    let cfg = configuration();
    let path_a = root.join("a");
    let mut a = Engine::initialize(&path_a, cfg.clone()).unwrap();
    let mut source = Source::new("fault-left", 3);
    let opts = options(&source.descriptor);
    if matches!(phase.as_str(), "quarantined" | "before-outcome") {
        let learned = a.run_episode(&mut source, &opts, &mut NoopSink).unwrap();
        let artifact = a.export_artifact(&learned.artifact).unwrap();
        let path_b = root.join("b");
        let mut b = Engine::initialize(&path_b, cfg.clone()).unwrap();
        let grant = a.authorize_local_exchange(&mut b, &artifact).unwrap();
        let ticket = a.prepare_local_transfer(&mut b, &grant, &artifact).unwrap();
        if phase == "before-outcome" {
            let mut own_source = Source::new("fault-left", 3);
            b.accept_local_transfer(&ticket, &artifact, &mut own_source, &opts, &mut NoopSink)
                .unwrap();
            assert_eq!(own_source.calls, 5);
            let closed_a = a.close().unwrap();
            let closed_b = b.close().unwrap();
            a = Engine::open(&closed_a.state, &closed_a.owner, cfg.clone()).unwrap();
            b = Engine::open(&closed_b.state, &closed_b.owner, cfg).unwrap();
            assert_eq!(b.use_local_transfer(&ticket, 6).unwrap().answer, 1);
            assert!(b.local_transfer_outcomes().unwrap().is_empty());
        }
        let snapshots = vec![
            snapshot(&a, &path_a, Some(artifact.record.id.clone())),
            snapshot(
                &b,
                &path_b,
                (phase == "before-outcome").then(|| artifact.record.id.clone()),
            ),
        ];
        barrier(&root, &phase, &nonce, snapshots, Some(ticket), None);
    }
    let mut sink = CutSink {
        root,
        path: path_a,
        phase: phase.clone(),
        nonce,
        owner: a.identity().unwrap().into(),
        before: a.inspect().unwrap().knowledge,
    };
    let learned = a.run_episode(&mut source, &opts, &mut sink).unwrap();
    if phase == "prediction" {
        a.predict(&learned.artifact, 6, &mut sink).unwrap();
    }
    panic!("requested barrier was not reached: {phase}");
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                if self.0.try_wait().ok().flatten().is_some() {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
            eprintln!(
                "HOLD: owned fault child {} cleanup could not be confirmed",
                self.0.id()
            );
        }
    }
}
fn wait_marker(child: &mut OwnedChild, path: &Path) -> Marker {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        if path.exists() {
            let bytes = fs::read(path).unwrap();
            assert!(bytes.len() < 128 * 1024);
            return serde_json::from_slice(&bytes).unwrap();
        }
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "owned child exited before the synchronized barrier"
        );
        assert!(
            Instant::now() < deadline,
            "bounded child barrier deadline elapsed"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
fn kill_and_wait(child: &mut OwnedChild) {
    child.0.kill().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(!status.success(), "fault child must have been interrupted");
            return;
        }
        assert!(
            Instant::now() < deadline,
            "owned child did not stop after termination"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn owned_process_cuts_preserve_exact_history_or_explicit_hold() {
    let directory = Directory::new(true);
    let started = Instant::now();
    let mut reports = Vec::new();
    for phase in [
        "started",
        "candidate",
        "evaluated",
        "retained",
        "prediction",
        "quarantined",
        "before-outcome",
    ] {
        let root = directory.path.join(phase);
        fs::create_dir(&root).unwrap();
        let nonce = format!(
            "unit-fault-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let mut child = OwnedChild(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "engine_fault_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_ROOT, &root)
                .env(CHILD_PHASE, phase)
                .env(CHILD_NONCE, &nonce)
                .stdin(Stdio::null())
                .stdout(Stdio::from(
                    File::create(root.join("child-stdout.txt")).unwrap(),
                ))
                .stderr(Stdio::from(
                    File::create(root.join("child-stderr.txt")).unwrap(),
                ))
                .spawn()
                .unwrap(),
        );
        let marker = wait_marker(&mut child, &root.join("barrier.json"));
        assert_eq!(marker.schema, "symbiote.engine-fault-barrier/1");
        assert_eq!(marker.phase, phase);
        assert_eq!(marker.nonce, nonce);
        assert_eq!(marker.child_pid, child.0.id());
        assert_eq!(
            marker.owners.len(),
            if marker.ticket.is_some() { 2 } else { 1 }
        );
        for (index, owner) in marker.owners.iter().enumerate() {
            assert_eq!(owner.path, root.join(if index == 0 { "a" } else { "b" }));
            assert_eq!(pins(&owner.path), owner.ledgers);
            assert_eq!(
                Engine::recover_stopped_owner(&owner.path, &owner.identity)
                    .unwrap_err()
                    .kind,
                ErrorKind::OwnerBusy
            );
            assert_eq!(pins(&owner.path), owner.ledgers);
        }
        kill_and_wait(&mut child);
        let mut recovered = Vec::new();
        for owner in &marker.owners {
            assert_eq!(
                pins(&owner.path),
                owner.ledgers,
                "termination must not rewrite committed bytes"
            );
            let recovery = Engine::recover_stopped_owner(&owner.path, &owner.identity).unwrap();
            assert!(!recovery.ledgers_modified && recovery.processes_terminated == 0);
            assert!(!recovery.recovered_locks.is_empty());
            assert_eq!(
                pins(&owner.path),
                owner.ledgers,
                "recovery must only remove dead writer locks"
            );
            recovered.push(recovery);
        }
        let expected_hold = matches!(phase, "started" | "candidate" | "evaluated");
        if expected_hold {
            let owner = &marker.owners[0];
            assert_eq!(
                Engine::open(&owner.path, &owner.identity, configuration())
                    .err()
                    .unwrap()
                    .kind,
                ErrorKind::Hold
            );
            assert_eq!(pins(&owner.path), owner.ledgers);
        } else {
            let first = &marker.owners[0];
            let mut a = Engine::open(&first.path, &first.identity, configuration()).unwrap();
            assert_eq!(a.identity().unwrap(), first.identity);
            assert_eq!(a.inspect().unwrap().knowledge, first.knowledge);
            assert_eq!(pins(&first.path), first.ledgers);
            if let Some(ticket) = &marker.ticket {
                let second = &marker.owners[1];
                let mut b = Engine::open(&second.path, &second.identity, configuration()).unwrap();
                assert_eq!(b.identity().unwrap(), second.identity);
                assert_eq!(b.inspect().unwrap().knowledge, second.knowledge);
                assert_eq!(pins(&second.path), second.ledgers);
                let artifact = a.export_artifact(first.artifact.as_ref().unwrap()).unwrap();
                if phase == "quarantined" {
                    assert_eq!(
                        b.inspect_local_transfer(ticket).unwrap().stage,
                        engine::exchange::TransferStage::Quarantined
                    );
                    let mut source = Source::new("fault-left", 3);
                    b.accept_local_transfer(
                        ticket,
                        &artifact,
                        &mut source,
                        &options(&source_descriptor("fault-left")),
                        &mut NoopSink,
                    )
                    .unwrap();
                    assert_eq!(source.calls, 5);
                    assert_eq!(b.use_local_transfer(ticket, 6).unwrap().answer, 1);
                } else {
                    assert_eq!(
                        b.inspect_local_transfer(ticket).unwrap().stage,
                        engine::exchange::TransferStage::UsedAwaitingOutcome
                    );
                    assert_eq!(b.inspect_local_transfer(ticket).unwrap().actual_uses, 1);
                }
                let retained = b.inspect().unwrap().knowledge;
                let outcome = b.complete_local_transfer(ticket).unwrap();
                assert_eq!(outcome.outcome.uses, 1);
                assert!(
                    !outcome.outcome.verified_benefit && outcome.outcome.measured_net.is_none()
                );
                assert!(
                    a.reconcile_local_transfer(&b, ticket)
                        .unwrap()
                        .newly_reconciled
                );
                assert_eq!(
                    b.inspect().unwrap().knowledge,
                    retained,
                    "outcome closure cannot repromote knowledge"
                );
                let closed_a = a.close().unwrap();
                let closed_b = b.close().unwrap();
                a = Engine::open(&closed_a.state, &closed_a.owner, configuration()).unwrap();
                b = Engine::open(&closed_b.state, &closed_b.owner, configuration()).unwrap();
                let journal = a.inspect().unwrap().operational_head_sha256;
                assert!(
                    !a.reconcile_local_transfer(&b, ticket)
                        .unwrap()
                        .newly_reconciled
                );
                assert_eq!(a.inspect().unwrap().operational_head_sha256, journal);
                assert_eq!(b.inspect().unwrap().knowledge, retained);
                b.close().unwrap();
            } else {
                let mut source = Source::new("fault-left", 3);
                source.offline = true;
                let reused = a
                    .run_episode(
                        &mut source,
                        &options(&source_descriptor("fault-left")),
                        &mut NoopSink,
                    )
                    .unwrap();
                assert!(reused.reused && reused.usage.source_calls == 0 && source.calls == 0);
                assert_eq!(
                    a.predict(first.artifact.as_ref().unwrap(), 6, &mut NoopSink)
                        .unwrap()
                        .answer,
                    Some(1)
                );
                assert_eq!(
                    a.inspect().unwrap().knowledge,
                    first.knowledge,
                    "reopened use cannot repromote knowledge"
                );
            }
            a.close().unwrap();
        }
        reports.push(serde_json::json!({"phase":phase,"expected_result":if expected_hold {"HOLD_UNFINISHED_EPISODE"} else {"EXACT_COMMITTED_REOPEN"},"child_pid":marker.child_pid,"owned_child_killed_and_waited":true,"pre_recovery_ledgers_unchanged":true,"recoveries":recovered,"resumed_without_repromotion":!expected_hold}));
    }
    write_synced(
        &directory.path.join("fault-report.json"),
        &serde_json::json!({"schema":"symbiote.embedding-faults/1","status":"PASS_SOFTWARE","cases":reports,"elapsed_ms":started.elapsed().as_millis(),"scope":"seven synchronized synthetic owned-process cuts; not power-loss durability or scientific samples","independent_scientific_samples":0}),
    );
}

#[test]
fn committed_revoke_with_failed_journal_poison_blocks_unrelated_exchange() {
    let directory = Directory::new(false);
    let a_path = directory.path.join("a");
    let mut a = Engine::initialize(&a_path, configuration()).unwrap();
    let mut b = Engine::initialize(&directory.path.join("b"), configuration()).unwrap();
    let mut left = Source::new("fault-left", 3);
    let left = a
        .run_episode(
            &mut left,
            &options(&source_descriptor("fault-left")),
            &mut NoopSink,
        )
        .unwrap();
    let mut right = Source::new("fault-right", 5);
    let right = a
        .run_episode(
            &mut right,
            &options(&source_descriptor("fault-right")),
            &mut NoopSink,
        )
        .unwrap();
    let artifact = a.export_artifact(&right.artifact).unwrap();
    let grant = a.authorize_local_exchange(&mut b, &artifact).unwrap();
    let operations = a_path.join("operations.jsonl");
    let preserved = a_path.join("operations.preserved");
    let original = fs::read(&operations).unwrap();
    fs::rename(&operations, &preserved).unwrap();
    fs::create_dir(&operations).unwrap();
    let error = a
        .revoke(
            &left.artifact,
            "modeled journal publication obstruction",
            &mut NoopSink,
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Storage);
    assert!(error.committed.is_some());
    // Undo only this test's path obstruction; preserve all actual committed
    // history. No lock or ledger row is deleted or repaired by the engine.
    fs::remove_dir(&operations).unwrap();
    fs::rename(&preserved, &operations).unwrap();
    assert_eq!(fs::read(&operations).unwrap(), original);
    assert!(a
        .inspect()
        .unwrap()
        .active_artifacts
        .contains(&right.artifact));
    let before_a = pins(&a_path);
    let before_b = pins(&directory.path.join("b"));
    assert_eq!(
        a.authorize_local_exchange(&mut b, &artifact)
            .unwrap_err()
            .kind,
        ErrorKind::Hold
    );
    assert_eq!(
        a.prepare_local_transfer(&mut b, &grant, &artifact)
            .unwrap_err()
            .kind,
        ErrorKind::Hold
    );
    assert_eq!(pins(&a_path), before_a);
    assert_eq!(pins(&directory.path.join("b")), before_b);
    let identity = a.identity().unwrap().to_string();
    assert_eq!(a.close().unwrap_err().kind, ErrorKind::Hold);
    assert_eq!(
        Engine::open(&a_path, &identity, configuration())
            .err()
            .unwrap()
            .kind,
        ErrorKind::Hold
    );
    b.close().unwrap();
}

#[cfg(any(windows, unix))]
struct PermissionRestore {
    path: PathBuf,
    original: fs::Permissions,
}
#[cfg(any(windows, unix))]
impl Drop for PermissionRestore {
    fn drop(&mut self) {
        if let Err(error) = fs::set_permissions(&self.path, self.original.clone()) {
            eprintln!("HOLD: restoring owned permission fixture failed: {error}");
        }
    }
}

#[test]
#[cfg(any(windows, unix))]
fn actual_permission_denial_preserves_committed_engine_history() {
    let directory = Directory::new(false);
    let path = directory.path.join("owner");
    let mut engine = Engine::initialize(&path, configuration()).unwrap();
    let owner = engine.identity().unwrap().to_string();
    let mut source = Source::new("fault-left", 3);
    let candidate = engine
        .observe_infer(
            &mut source,
            &options(&source_descriptor("fault-left")),
            &mut NoopSink,
        )
        .unwrap();
    let evaluated = engine.evaluate(candidate, &mut NoopSink).unwrap();
    let before = pins(&path);
    let anchor = engine.inspect().unwrap().knowledge;
    #[cfg(windows)]
    let guarded = path.join("knowledge.jsonl");
    #[cfg(unix)]
    let guarded = path.clone();
    let permissions = fs::metadata(&guarded).unwrap().permissions();
    let restore = PermissionRestore {
        path: guarded.clone(),
        original: permissions.clone(),
    };
    #[cfg(windows)]
    {
        let mut denied = permissions;
        denied.set_readonly(true);
        fs::set_permissions(&guarded, denied).unwrap();
        assert_eq!(
            OpenOptions::new()
                .write(true)
                .open(&guarded)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&guarded, fs::Permissions::from_mode(0o500)).unwrap();
        let probe = guarded.join("permission-probe");
        match OpenOptions::new().write(true).create_new(true).open(&probe) {
            Ok(file) => {
                drop(file);
                fs::remove_file(probe).unwrap();
                drop(restore);
                eprintln!("UNAVAILABLE_PERMISSION_FAULT: current OS identity bypasses directory write permissions; no permission-denial qualification claimed");
                assert_ne!(
                    std::env::var("SYMBIOTE_REQUIRE_PERMISSION_FAULT").as_deref(),
                    Ok("1"),
                    "release job requires a non-privileged actual permission fault"
                );
                return;
            }
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied),
        }
    }
    let error = engine.retain(evaluated, &mut NoopSink).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Storage);
    assert!(error.committed.is_none());
    assert_eq!(engine.inspect().unwrap().knowledge, anchor);
    assert_eq!(pins(&path), before);
    drop(restore);
    drop(engine);
    assert_eq!(
        Engine::open(&path, &owner, configuration())
            .err()
            .unwrap()
            .kind,
        ErrorKind::Hold
    );
    assert_eq!(pins(&path), before);
    eprintln!("ACTUAL_PERMISSION_FAULT_PASS: OS PermissionDenied probe, typed Storage, unchanged committed ledgers, unfinished episode Hold");
}

#[test]
fn live_foreign_knowledge_replacement_cannot_be_overwritten_by_retention() {
    let directory = Directory::new(false);
    let path = directory.path.join("owner");
    let foreign_path = directory.path.join("foreign-owner");
    let mut engine = Engine::initialize(&path, configuration()).unwrap();
    let identity = engine.identity().unwrap().to_string();
    let mut source = Source::new("fault-left", 3);
    let candidate = engine
        .observe_infer(
            &mut source,
            &options(&source_descriptor("fault-left")),
            &mut NoopSink,
        )
        .unwrap();
    let evaluated = engine.evaluate(candidate, &mut NoopSink).unwrap();
    source.offline = true;
    let before = pins(&path);
    let anchor = engine.inspect().unwrap().knowledge;
    let foreign = Engine::initialize(&foreign_path, configuration()).unwrap();
    assert_ne!(foreign.identity().unwrap(), identity);
    foreign.close().unwrap();
    let replacement = fs::read(foreign_path.join("knowledge.jsonl")).unwrap();
    fs::write(path.join("knowledge.jsonl"), &replacement).unwrap();
    let error = engine.retain(evaluated, &mut NoopSink).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Hold);
    assert!(error.committed.is_none());
    assert_eq!(engine.inspect().unwrap().knowledge, anchor);
    assert_eq!(source.calls, 5);
    assert_eq!(fs::read(path.join("knowledge.jsonl")).unwrap(), replacement);
    let after = pins(&path);
    for name in ["ledger.jsonl", "operations.jsonl"] {
        assert_eq!(before[name], after[name]);
    }
    assert_eq!(engine.close().unwrap_err().kind, ErrorKind::Hold);
    assert_eq!(pins(&path), after);
    assert!(matches!(
        Engine::open(&path, &identity, configuration())
            .err()
            .unwrap()
            .kind,
        ErrorKind::Storage | ErrorKind::Hold
    ));
    assert_eq!(fs::read(path.join("knowledge.jsonl")).unwrap(), replacement);
}

/// This host never mounts or fills a normal filesystem. Qualification supplies
/// a dedicated, empty, <=1MiB tmpfs and runs this one ignored test explicitly.
#[test]
#[ignore = "requires an externally provisioned isolated <=1MiB Linux tmpfs; never run as an ordinary test"]
#[cfg(target_os = "linux")]
fn actual_linux_disk_full_preserves_committed_state() {
    use std::io::ErrorKind;
    let root = PathBuf::from(
        std::env::var_os("SYMBIOTE_ENOSPC_ROOT").expect("explicit isolated mount required"),
    );
    assert!(root.is_absolute());
    let root = root.canonicalize().unwrap();
    assert!(root
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("symbiote-enospc-"));
    assert!(
        fs::read_dir(&root).unwrap().next().is_none(),
        "dedicated mount must start empty"
    );
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert!(mountinfo.len() <= 1024 * 1024);
    assert!(
        mountinfo.lines().any(|line| {
            let Some((left, right)) = line.split_once(" - ") else {
                return false;
            };
            let left = left.split_whitespace().collect::<Vec<_>>();
            let right = right.split_whitespace().collect::<Vec<_>>();
            left.get(4).copied() == root.to_str()
                && right.first().copied() == Some("tmpfs")
                && right.get(1).copied() == Some("symbiote-v11-enospc")
        }),
        "root must be the exact dedicated symbiote-v11-enospc tmpfs mount"
    );
    let stat = Command::new("stat")
        .args(["--file-system", "--format=%t:%S:%b"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(stat.status.success() && stat.stdout.len() < 128);
    let stat = String::from_utf8(stat.stdout).unwrap();
    let geometry = stat.trim().split(':').collect::<Vec<_>>();
    assert_eq!(geometry.len(), 3);
    assert_eq!(geometry[0], "1021994", "Linux tmpfs magic required");
    let capacity = geometry[1]
        .parse::<u64>()
        .unwrap()
        .checked_mul(geometry[2].parse().unwrap())
        .unwrap();
    assert!(
        capacity > 0 && capacity <= 1024 * 1024,
        "refusing to fill a filesystem larger than one MiB"
    );
    let state = root.join("owner");
    let mut engine = Engine::initialize(&state, configuration()).unwrap();
    let owner = engine.identity().unwrap().to_string();
    let mut source = Source::new("fault-left", 3);
    let candidate = engine
        .observe_infer(
            &mut source,
            &options(&source_descriptor("fault-left")),
            &mut NoopSink,
        )
        .unwrap();
    let evaluated = engine.evaluate(candidate, &mut NoopSink).unwrap();
    let before = pins(&state);
    let anchor = engine.inspect().unwrap().knowledge;
    let fillpath = root.join("owned-fill.bin");
    struct OwnedFill(PathBuf);
    impl Drop for OwnedFill {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let owned_fill = OwnedFill(fillpath.clone());
    let mut fill = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&fillpath)
        .unwrap();
    let block = [0x5a; 4096];
    let mut written = 0usize;
    let raw_errno = loop {
        assert!(
            written < 2 * 1024 * 1024,
            "fill limit exhausted before an actual ENOSPC; no further writes allowed"
        );
        match fill.write(&block) {
            Ok(0) => panic!("filesystem returned a zero write without ENOSPC"),
            Ok(count) => written += count,
            Err(error) => {
                assert_eq!(error.raw_os_error(), Some(28));
                assert_eq!(error.kind(), ErrorKind::StorageFull);
                break 28;
            }
        }
    };
    drop(fill);
    let error = engine.retain(evaluated, &mut NoopSink).unwrap_err();
    assert_eq!(error.kind, engine::ErrorKind::Storage);
    assert!(error.committed.is_none());
    assert_eq!(engine.inspect().unwrap().knowledge, anchor);
    assert_eq!(pins(&state), before);
    drop(owned_fill); // Free only the file owned by this test; never truncate a ledger.
    drop(engine);
    assert_eq!(
        Engine::open(&state, &owner, configuration())
            .err()
            .unwrap()
            .kind,
        engine::ErrorKind::Hold
    );
    assert_eq!(pins(&state), before);
    let test_path = std::env::current_exe().unwrap();
    assert!(fs::metadata(&test_path).unwrap().len() <= 64 * 1024 * 1024);
    let test_image = fs::read(test_path).unwrap();
    assert!(test_image.len() <= 64 * 1024 * 1024);
    let test_sha256 = format!("{:x}", Sha256::digest(test_image));
    let receipt = serde_json::json!({"schema":"symbiote.engine-enospc/1","status":"PASS_ACTUAL_ENOSPC","source_commit":option_env!("SYMBIOTE_SOURCE_COMMIT").unwrap_or("unknown"),"version":env!("CARGO_PKG_VERSION"),"test_executable_sha256":test_sha256,"root":root,"owner":owner,"mount_source":"symbiote-v11-enospc","tmpfs_magic":"1021994","filesystem_capacity_bytes":capacity,"fill_written_bytes":written,"fill_limit_bytes":2*1024*1024,"raw_errno":raw_errno,"retain_error_kind":"storage","reopen_error_kind":"hold","committed_ledgers":before,"committed_ledgers_unchanged":true,"fill_file_removed":!fillpath.exists(),"native_mount_or_unmount_performed":false,"independent_scientific_samples":0});
    if let Some(output) = std::env::var_os("SYMBIOTE_ENOSPC_RECEIPT").map(PathBuf::from) {
        assert!(
            output.is_absolute() && !output.starts_with(&root),
            "receipt must be outside the filled mount"
        );
        write_synced(&output, &receipt);
    }
    println!("ENOSPC_RECEIPT {receipt}");
}
