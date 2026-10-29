use serde_json::Value;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};
use symbiote_memory::operational::{OperationalEvent, OperationalJournal};
use symbiote_memory::{knowledge::KnowledgeStore, maintenance, Store};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn surviving_strategy_files_never_create_a_replacement_identity() {
    use symbiote_memory::strategy::{StrategyLedger, STRATEGY_FILE, STRATEGY_OWNER_FILE};
    for surviving in ["both", STRATEGY_FILE, STRATEGY_OWNER_FILE] {
        let dir = Directory::new();
        let owner = Arc::new(Store::open(&dir.0).unwrap());
        let identity = owner.identity().to_string();
        drop(StrategyLedger::open(owner).unwrap());
        fs::remove_file(dir.0.join("ledger.jsonl")).unwrap();
        if surviving == STRATEGY_FILE {
            fs::remove_file(dir.0.join(STRATEGY_OWNER_FILE)).unwrap();
        }
        if surviving == STRATEGY_OWNER_FILE {
            fs::remove_file(dir.0.join(STRATEGY_FILE)).unwrap();
        }
        let before: Vec<_> = [STRATEGY_FILE, STRATEGY_OWNER_FILE]
            .iter()
            .map(|name| (*name, fs::read(dir.0.join(name)).ok()))
            .collect();
        assert!(Store::open(&dir.0).is_err());
        assert!(KnowledgeStore::open(&dir.0, &identity).is_err());
        assert!(maintenance::inspect(&dir.0).is_err());
        assert!(maintenance::migrate(&dir.0).is_err());
        assert!(!dir.0.join("ledger.jsonl").exists());
        assert!(!dir.0.join("knowledge.jsonl").exists());
        for (name, bytes) in before {
            assert_eq!(fs::read(dir.0.join(name)).ok(), bytes);
        }
    }
}

#[test]
fn strategy_owner_proof_binds_the_raw_genesis_line_including_its_newline() {
    use symbiote_memory::strategy::{StrategyLedger, STRATEGY_FILE, STRATEGY_OWNER_FILE};
    let dir = Directory::new();
    drop(StrategyLedger::open(Arc::new(Store::open(&dir.0).unwrap())).unwrap());
    let original = fs::read(dir.0.join("ledger.jsonl")).unwrap();
    let strategy = fs::read(dir.0.join(STRATEGY_FILE)).unwrap();
    let marker = fs::read(dir.0.join(STRATEGY_OWNER_FILE)).unwrap();
    let mut changed = original[..original.len() - 1].to_vec();
    changed.extend_from_slice(b"\r\n");
    fs::write(dir.0.join("ledger.jsonl"), &changed).unwrap();
    // Semantic JSON is unchanged; the original owner's exact byte anchor is not.
    let owner = Arc::new(Store::open(&dir.0).unwrap());
    assert!(StrategyLedger::open(owner).is_err());
    assert!(maintenance::inspect(&dir.0).is_err());
    assert!(maintenance::migrate(&dir.0).is_err());
    assert_eq!(fs::read(dir.0.join("ledger.jsonl")).unwrap(), changed);
    assert_eq!(fs::read(dir.0.join(STRATEGY_FILE)).unwrap(), strategy);
    assert_eq!(fs::read(dir.0.join(STRATEGY_OWNER_FILE)).unwrap(), marker);
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = std::env::temp_dir().canonicalize().unwrap();
        let path = root.join(format!(
            "symbiote-lifecycle-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("lifecycle failure evidence preserved: {}", self.0.display());
            return;
        }
        // Check the resolved absolute target before recursively deleting our
        // owned fixture directory, including on Windows.
        if let (Ok(path), Ok(root)) = (self.0.canonicalize(), std::env::temp_dir().canonicalize()) {
            let owned = path.parent() == Some(root.as_path())
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| name.starts_with("symbiote-lifecycle-"));
            if owned {
                let _ = fs::remove_dir_all(path);
            }
        }
    }
}

struct OwnedChild {
    child: Child,
}
impl OwnedChild {
    fn id(&self) -> u32 {
        self.child.id()
    }
    fn stop(&mut self) -> std::io::Result<()> {
        if self.child.try_wait()?.is_some() {
            return Ok(());
        }
        if let Err(error) = self.child.kill() {
            if self.child.try_wait()?.is_none() {
                return Err(error);
            }
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if self.child.try_wait()?.is_some() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "owned fixture was not reaped within cleanup bound",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!(
                "HOLD: owned lifecycle child {} cleanup not confirmed: {error}",
                self.id()
            );
            if !std::thread::panicking() {
                panic!("owned lifecycle child cleanup failed");
            }
        }
    }
}
#[derive(Debug)]
struct StartupFailure {
    pid: Option<u32>,
    detail: String,
    cleanup_verified: bool,
    stderr: PathBuf,
}
impl std::fmt::Display for StartupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} (owned PID {:?}, cleanup_verified={}, stderr={})",
            self.detail,
            self.pid,
            self.cleanup_verified,
            self.stderr.display()
        )
    }
}
fn parse_ready(bytes: &[u8], pid: u32) -> Result<Option<String>, String> {
    if bytes.len() > 256 {
        return Err("readiness marker exceeds 256 bytes".into());
    }
    if bytes.is_empty() || !bytes.ends_with(b"\n") {
        return Ok(None);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "readiness marker is not UTF-8")?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() < 2 {
        return Ok(None);
    }
    if lines.len() != 2 {
        return Err("readiness marker needs exactly two complete lines".into());
    }
    let recorded = lines[0]
        .parse::<u32>()
        .map_err(|_| "readiness PID is malformed")?;
    if recorded != pid {
        return Err("readiness PID differs from the owned child".into());
    }
    let identity = lines[1];
    if identity.is_empty()
        || identity.len() > 128
        || !identity
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
    {
        return Err("readiness identity is malformed".into());
    }
    Ok(Some(identity.into()))
}
struct Fixture {
    child: OwnedChild,
    identity: String,
}
impl Fixture {
    fn spawn(directory: &Path, mode: &str) -> Self {
        Self::try_spawn(directory, mode, |_, _, _| {})
            .unwrap_or_else(|error| panic!("owned fixture startup failed: {error}"))
    }
    fn try_spawn(
        directory: &Path,
        mode: &str,
        mut observed: impl FnMut(u32, &Path, &[u8]),
    ) -> Result<Self, StartupFailure> {
        let ready = directory.join(format!("ready-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
        let stderr = ready.with_extension("stderr");
        let errors = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&stderr)
            .map_err(|error| StartupFailure {
                pid: None,
                detail: format!("open owned child log: {error}"),
                cleanup_verified: true,
                stderr: stderr.clone(),
            })?;
        // Ownership exists before any readiness I/O, parsing, callback or panic.
        // The child has no inherited captured Cargo output pipe to keep open.
        let mut child = Command::new(env!("CARGO_BIN_EXE_symbiote-memory-crash-fixture"))
            .env("SYMBIOTE_CRASH_FIXTURE", "owned-test-child")
            .arg(directory)
            .arg(&ready)
            .arg(mode)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(errors))
            .spawn()
            .map(|child| OwnedChild { child })
            .map_err(|error| StartupFailure {
                pid: None,
                detail: format!("spawn owned fixture: {error}"),
                cleanup_verified: true,
                stderr: stderr.clone(),
            })?;
        let deadline = Instant::now() + Duration::from_secs(8);
        let outcome = (|| loop {
            match fs::File::open(&ready) {
                Ok(file) => {
                    let mut bytes = Vec::new();
                    file.take(257)
                        .read_to_end(&mut bytes)
                        .map_err(|error| format!("read readiness: {error}"))?;
                    observed(child.id(), &ready, &bytes);
                    if let Some(identity) = parse_ready(&bytes, child.id())? {
                        return Ok(identity);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("open readiness: {error}")),
            }
            if let Some(status) = child
                .child
                .try_wait()
                .map_err(|error| format!("observe owned fixture: {error}"))?
            {
                return Err(format!("owned fixture exited before ready: {status}"));
            }
            if Instant::now() >= deadline {
                return Err("owned fixture readiness timeout".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        })();
        match outcome {
            Ok(identity) => Ok(Self { child, identity }),
            Err(detail) => {
                let pid = Some(child.id());
                let cleanup = child.stop();
                Err(StartupFailure {
                    pid,
                    cleanup_verified: cleanup.is_ok(),
                    detail: match cleanup {
                        Ok(()) => detail,
                        Err(error) => format!("{detail}; cleanup failed: {error}"),
                    },
                    stderr,
                })
            }
        }
    }
    fn crash(&mut self) {
        self.child
            .stop()
            .expect("bounded owned fixture kill and reap");
    }
}

#[test]
fn readiness_parser_waits_for_complete_data_and_rejects_invalid_complete_markers() {
    for bytes in [
        b"".as_slice(),
        b"42".as_slice(),
        b"42\n".as_slice(),
        b"42\nowner".as_slice(),
    ] {
        assert_eq!(parse_ready(bytes, 42).unwrap(), None);
    }
    assert_eq!(
        parse_ready(b"42\nowner\n", 42).unwrap(),
        Some("owner".into())
    );
    for bytes in [
        b"wrong\nowner\n".as_slice(),
        b"43\nowner\n".as_slice(),
        b"42\n\n".as_slice(),
        b"42\nowner\nextra\n".as_slice(),
        b"\xff\n".as_slice(),
    ] {
        assert!(parse_ready(bytes, 42).is_err());
    }
    assert!(parse_ready(&[b'x'; 257], 42).is_err());
}

#[test]
fn an_actual_partial_ready_child_waits_for_observation_before_atomic_completion() {
    let directory = Directory::new();
    let mut saw_partial = false;
    let mut fixture = Fixture::try_spawn(&directory.0, "partial-ready", |pid, ready, bytes| {
        if parse_ready(bytes, pid).unwrap().is_none() && !saw_partial {
            saw_partial = true;
            fs::write(
                ready.with_extension("partial-observed"),
                b"parent observed incomplete marker",
            )
            .unwrap();
        }
    })
    .unwrap_or_else(|error| panic!("partial fixture failed: {error}"));
    assert!(
        saw_partial,
        "partial publication must have been read before child completes it"
    );
    let original = fs::read(directory.0.join("ledger.jsonl")).unwrap();
    fixture.crash();
    assert!(!maintenance::recover(&directory.0).unwrap().ledgers_modified);
    assert_eq!(
        fs::read(directory.0.join("ledger.jsonl")).unwrap(),
        original
    );
    assert!(fs::read_dir(&directory.0).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .ends_with(".publishing")));
}

#[test]
fn malformed_readiness_and_child_exit_fail_startup_with_confirmed_owned_cleanup() {
    let directory = Directory::new();
    let error = Fixture::try_spawn(&directory.0, "invalid-ready", |_, _, _| {})
        .err()
        .expect("malformed marker must be rejected");
    assert!(error.cleanup_verified);
    let pid = error.pid.expect("actual child PID");
    let inspection = maintenance::inspect(&directory.0).unwrap();
    assert!(inspection
        .locks
        .iter()
        .any(|lock| lock.process == Some(pid) && lock.state == maintenance::LockState::Dead));
    let original = fs::read(directory.0.join("ledger.jsonl")).unwrap();
    maintenance::recover(&directory.0).unwrap();
    assert_eq!(
        fs::read(directory.0.join("ledger.jsonl")).unwrap(),
        original
    );
    let exited = Directory::new();
    let error = Fixture::try_spawn(&exited.0, "not-an-allowed-mode", |_, _, _| {})
        .err()
        .expect("child must exit before readiness");
    assert!(error.pid.is_some() && error.cleanup_verified);
    assert!(!exited.0.join("ledger.jsonl").exists());
    assert!(fs::read_to_string(error.stderr)
        .unwrap()
        .contains("invalid fixture mode"));
}

#[test]
fn startup_parent_panic_reaps_child_before_any_fixture_is_returned() {
    let directory = Directory::new();
    let pid = std::sync::atomic::AtomicU32::new(0);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _fixture = Fixture::try_spawn(&directory.0, "genesis", |child, _, _| {
            pid.store(child, Ordering::Relaxed);
            assert!(maintenance::inspect(&directory.0)
                .unwrap()
                .locks
                .iter()
                .any(|lock| lock.process == Some(child)
                    && lock.state == maintenance::LockState::Live));
            panic!("controlled parent startup panic while owned child is live");
        });
    }));
    assert!(result.is_err());
    let child = pid.load(Ordering::Relaxed);
    assert!(child > 0);
    let inspection = maintenance::inspect(&directory.0).unwrap();
    assert!(inspection
        .locks
        .iter()
        .any(|lock| lock.process == Some(child) && lock.state == maintenance::LockState::Dead));
    assert!(!maintenance::recover(&directory.0).unwrap().ledgers_modified);
    drop(Store::open(&directory.0).unwrap());
}

#[test]
fn supervised_child_crash_recovers_both_locks_without_resetting_identity_or_ledgers() {
    let dir = Directory::new();
    let mut fixture = Fixture::spawn(&dir.0, "staging");
    let genesis = fs::read(dir.0.join("ledger.jsonl")).unwrap();
    let knowledge = fs::read(dir.0.join("knowledge.jsonl")).unwrap();
    assert!(maintenance::recover(&dir.0)
        .unwrap_err()
        .contains("live process"));
    fixture.crash();
    let report = maintenance::recover(&dir.0).unwrap();
    assert_eq!(
        report.recovered_locks,
        vec!["writer.lock", "knowledge.writer.lock"]
    );
    assert!(!report.ledgers_modified);
    assert_eq!(report.processes_terminated, 0);
    assert_eq!(fs::read(dir.0.join("ledger.jsonl")).unwrap(), genesis);
    assert_eq!(fs::read(dir.0.join("knowledge.jsonl")).unwrap(), knowledge);
    let store = Store::open(&dir.0).unwrap();
    assert_eq!(store.identity(), fixture.identity);
    let structural = KnowledgeStore::open(&dir.0, store.identity()).unwrap();
    assert_eq!(structural.identity(), fixture.identity);
    assert!(dir
        .0
        .join(format!("ledger.{}.orphan.tmp", fixture.child.id()))
        .exists());
}

#[test]
fn a_live_structural_owner_prevents_removal_of_a_dead_genesis_lock() {
    let stale = Directory::new();
    let mut dead = Fixture::spawn(&stale.0, "genesis");
    dead.crash();
    let dir = Directory::new();
    let mut live = Fixture::spawn(&dir.0, "knowledge");
    fs::write(
        dir.0.join("writer.lock"),
        format!("process={}\n", dead.child.id()),
    )
    .unwrap();
    let before = fs::read(dir.0.join("writer.lock")).unwrap();
    assert!(maintenance::recover(&dir.0)
        .unwrap_err()
        .contains("knowledge.writer.lock"));
    assert_eq!(fs::read(dir.0.join("writer.lock")).unwrap(), before);
    live.crash();
    assert_eq!(
        maintenance::recover(&dir.0).unwrap().recovered_locks.len(),
        2
    );
}

#[test]
fn malformed_pid_boundaries_and_stale_gate_are_never_automatically_broken() {
    let dir = Directory::new();
    for bytes in [
        "process=0\n",
        "process=2147483648\n",
        "process=4294967295\n",
        "process=-1\n",
        "process= 1\n",
        "process=1\nextra=bad\n",
        "process=1\nnonce=bad\n",
        "",
        "process=absent\n",
    ] {
        fs::write(dir.0.join("writer.lock"), bytes).unwrap();
        assert!(maintenance::recover(&dir.0)
            .unwrap_err()
            .contains("uncertain"));
        assert_eq!(
            fs::read_to_string(dir.0.join("writer.lock")).unwrap(),
            bytes
        );
    }
    fs::remove_file(dir.0.join("writer.lock")).unwrap();
    fs::write(dir.0.join("maintenance.guard"), b"unrecognized stale gate").unwrap();
    assert!(maintenance::recover(&dir.0).is_err());
    assert!(Store::open(&dir.0).is_err());
    assert_eq!(
        fs::read(dir.0.join("maintenance.guard")).unwrap(),
        b"unrecognized stale gate"
    );
}

#[test]
fn simultaneous_recoveries_serialize_without_double_deleting_locks() {
    let dir = Directory::new();
    let mut fixture = Fixture::spawn(&dir.0, "both");
    fixture.crash();
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let gate = Arc::clone(&barrier);
        let path = dir.0.clone();
        threads.push(std::thread::spawn(move || {
            gate.wait();
            maintenance::recover(&path)
        }));
    }
    barrier.wait();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    let removed: Vec<_> = results
        .into_iter()
        .filter_map(Result::ok)
        .flat_map(|report| report.recovered_locks)
        .collect();
    assert_eq!(removed.len(), 2);
    assert_eq!(
        removed
            .iter()
            .filter(|name| name.as_str() == "writer.lock")
            .count(),
        1
    );
    assert_eq!(maintenance::inspect(&dir.0).unwrap().status, "PASS");
}

#[test]
fn a_writer_racing_recovery_cannot_have_its_new_lock_removed() {
    let dir = Directory::new();
    let mut fixture = Fixture::spawn(&dir.0, "both");
    fixture.crash();
    let barrier = Arc::new(Barrier::new(3));
    let path = dir.0.clone();
    let start = Arc::clone(&barrier);
    let recovery = std::thread::spawn(move || {
        start.wait();
        maintenance::recover(&path)
    });
    let path = dir.0.clone();
    let start = Arc::clone(&barrier);
    let writer = std::thread::spawn(move || {
        start.wait();
        Store::open(&path)
    });
    barrier.wait();
    let recovery = recovery.join().unwrap();
    let writer = writer.join().unwrap();
    if let Ok(store) = writer {
        let lock = fs::read_to_string(dir.0.join("writer.lock")).unwrap();
        assert!(lock.starts_with(&format!("process={}\n", std::process::id())));
        assert_eq!(store.identity(), fixture.identity);
        assert!(maintenance::recover(&dir.0).is_err());
        drop(store);
    } else if recovery.is_err() {
        // Both operations may refuse while the other briefly owns the gate.
        // A later deliberate retry safely recovers the still-stale locks.
        maintenance::recover(&dir.0).unwrap();
    }
    let store = Store::open(&dir.0).unwrap();
    assert_eq!(store.identity(), fixture.identity);
}

#[test]
fn old_release_snapshots_migrate_byte_for_byte_and_unknown_layouts_fail_closed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let old = fs::read(root.join("experiments/genesis-ledger.jsonl")).unwrap();
    let dir = Directory::new();
    fs::write(dir.0.join("ledger.jsonl"), &old).unwrap();
    let owner = Store::open(&dir.0).unwrap().identity().to_string();
    let report = maintenance::migrate(&dir.0).unwrap();
    assert!(report.changed);
    assert_eq!(report.identity, owner);
    assert_eq!(fs::read(dir.0.join("ledger.jsonl")).unwrap(), old);
    assert_eq!(
        fs::read(dir.0.join("migration-backup-v1/ledger.jsonl")).unwrap(),
        old
    );
    assert!(!maintenance::migrate(&dir.0).unwrap().changed);
    let mut layout: Value =
        serde_json::from_slice(&fs::read(dir.0.join("state-layout.json")).unwrap()).unwrap();
    layout["layout_version"] = serde_json::json!(999);
    fs::write(
        dir.0.join("state-layout.json"),
        serde_json::to_vec(&layout).unwrap(),
    )
    .unwrap();
    assert!(maintenance::inspect(&dir.0).is_err());
    assert!(Store::open(&dir.0).is_err());
    assert_eq!(fs::read(dir.0.join("ledger.jsonl")).unwrap(), old);

    let old = fs::read(root.join("experiments/v0.2/symbiote-knowledge.jsonl")).unwrap();
    let first: Value =
        serde_json::from_slice(old.split(|byte| *byte == b'\n').next().unwrap()).unwrap();
    let identity = first["payload"]["identity"].as_str().unwrap();
    let dir = Directory::new();
    fs::write(dir.0.join("knowledge.jsonl"), &old).unwrap();
    assert_eq!(
        KnowledgeStore::open(&dir.0, identity)
            .unwrap()
            .active()
            .len(),
        24
    );
    assert_eq!(maintenance::migrate(&dir.0).unwrap().identity, identity);
    assert_eq!(fs::read(dir.0.join("knowledge.jsonl")).unwrap(), old);
    assert_eq!(
        fs::read(dir.0.join("migration-backup-v1/knowledge.jsonl")).unwrap(),
        old
    );
}

#[test]
fn inspection_is_nonmutating_and_corrupt_evidence_is_never_migrated() {
    let dir = Directory::new();
    let missing = dir.0.join("absent");
    assert_eq!(maintenance::inspect(&missing).unwrap().status, "EMPTY");
    assert!(!missing.exists());
    let store = Store::open(&dir.0).unwrap();
    drop(store);
    assert_eq!(maintenance::inspect(&dir.0).unwrap().status, "PASS");
    assert!(!dir.0.join("maintenance-audit.jsonl").exists());
    let mut bytes = fs::read(dir.0.join("ledger.jsonl")).unwrap();
    bytes[12] ^= 1;
    fs::write(dir.0.join("ledger.jsonl"), &bytes).unwrap();
    assert!(maintenance::inspect(&dir.0).is_err());
    assert!(maintenance::migrate(&dir.0).is_err());
    assert!(!dir.0.join("state-layout.json").exists());
    assert_eq!(fs::read(dir.0.join("ledger.jsonl")).unwrap(), bytes);
}

#[test]
fn a_wrong_structural_owner_cannot_create_a_poisoned_ledger_before_or_after_migration() {
    let dir = Directory::new();
    let store = Store::open(&dir.0).unwrap();
    let identity = store.identity().to_string();
    drop(store);
    let original = fs::read(dir.0.join("ledger.jsonl")).unwrap();
    assert!(KnowledgeStore::open(&dir.0, "wrong-owner").is_err());
    assert!(!dir.0.join("knowledge.jsonl").exists());
    maintenance::migrate(&dir.0).unwrap();
    assert!(KnowledgeStore::open(&dir.0, "wrong-owner").is_err());
    assert!(!dir.0.join("knowledge.jsonl").exists());
    assert_eq!(fs::read(dir.0.join("ledger.jsonl")).unwrap(), original);
    assert_eq!(
        KnowledgeStore::open(&dir.0, &identity).unwrap().identity(),
        identity
    );
}

#[test]
fn supervised_operational_intent_crash_replays_original_response_after_safe_recovery() {
    let dir = Directory::new();
    let mut fixture = Fixture::spawn(&dir.0, "operational");
    assert!(maintenance::recover(&dir.0).is_err());
    let original = fs::read(dir.0.join("ledger.jsonl")).unwrap();
    let operations = fs::read(dir.0.join("operations.jsonl")).unwrap();
    fixture.crash();
    let report = maintenance::recover(&dir.0).unwrap();
    assert_eq!(report.recovered_locks, vec!["writer.lock"]);
    assert_eq!(fs::read(dir.0.join("ledger.jsonl")).unwrap(), original);
    assert_eq!(
        fs::read(dir.0.join("operations.jsonl")).unwrap(),
        operations
    );
    assert!(!dir.0.join("knowledge.jsonl").exists());
    let owner = Arc::new(Store::open(&dir.0).unwrap());
    assert_eq!(owner.identity(), fixture.identity);
    let mut journal =
        OperationalJournal::open(Arc::clone(&owner), "crash-fixture", &"e".repeat(64)).unwrap();
    assert_eq!(journal.events().len(), 2);
    let (record_sha256, response) = match &journal.events()[1] {
        OperationalEvent::EvaluationPrepared {
            record, response, ..
        } => (record.digest().unwrap(), response.clone()),
        _ => panic!("prepared intent missing"),
    };
    journal
        .append(OperationalEvent::EvaluationCompleted {
            candidate_id: "crash-candidate".into(),
            record_sha256,
            response: response.clone(),
        })
        .unwrap();
    assert_eq!(response["marker"], "original-planned-response");
    assert_eq!(response["promoted"], true);
    // Operational receipts alone never commit the planned learning record.
    assert!(owner.active().is_empty());
    assert!(!dir.0.join("knowledge.jsonl").exists());
    drop(journal);
    drop(owner);
    assert_eq!(
        maintenance::inspect(&dir.0).unwrap().ledger_integrity,
        "verified_snapshot"
    );
}
