use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};
use symbiote_memory::operational::{OperationalEvent, OperationalJournal};
use symbiote_memory::{knowledge::KnowledgeStore, maintenance, Store};

static NEXT: AtomicU64 = AtomicU64::new(0);
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

struct Fixture {
    child: Child,
    identity: String,
}
impl Fixture {
    fn spawn(directory: &Path, mode: &str) -> Self {
        let ready = directory.join(format!("ready-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
        let mut child = Command::new(env!("CARGO_BIN_EXE_symbiote-memory-crash-fixture"))
            .env("SYMBIOTE_CRASH_FIXTURE", "owned-test-child")
            .arg(directory)
            .arg(&ready)
            .arg(mode)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if let Ok(text) = fs::read_to_string(&ready) {
                let mut lines = text.lines();
                assert_eq!(lines.next().unwrap().parse::<u32>().unwrap(), child.id());
                let identity = lines.next().unwrap().to_string();
                return Self { child, identity };
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("owned fixture exited before ready: {status}");
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("owned fixture readiness timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn crash(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
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
