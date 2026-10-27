//! Bounded, evidence-gated learning in one explicitly declared finite domain.
//!
//! A hash chain detects accidental corruption; it does not authenticate a ledger
//! against an adversary capable of rewriting its complete contents. Evaluation
//! receives a privileged simulator oracle. It is not a universal truth verifier.
pub mod knowledge;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCOPE: &str = "finite-boolean-v1";
pub const MAX_LEDGER_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_RECORD_BYTES: usize = 16 * 1024;
pub const MAX_RECORDS: usize = 4096;
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub id: String,
    pub revision: u64,
    pub source: String,
    pub scope: String,
    /// Complete table: index and output are two-bit values in 0..=3.
    pub table: Vec<u8>,
    pub provenance: String,
}

impl Artifact {
    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() || self.id.len() > 128 || self.revision == 0 {
            return Err("artifact needs a bounded id and positive revision".into());
        }
        if self.source.trim().is_empty() || self.source.len() > 128 {
            return Err("artifact needs a bounded source identity".into());
        }
        if self.scope != SCOPE || self.table.len() != 4 || self.table.iter().any(|x| *x > 3) {
            return Err("artifact must declare the complete finite-boolean-v1 domain".into());
        }
        if self.provenance.trim().is_empty() || self.provenance.len() > 4096 {
            return Err("artifact requires bounded provenance".into());
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, String> {
        digest(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluation {
    pub baseline_correct: usize,
    pub candidate_correct: usize,
    pub total: usize,
    pub verification_queries: usize,
    pub regressions: usize,
    artifact_digest: String,
    oracle: [u8; 4],
    baseline: [Option<u8>; 4],
}

/// Exhaustively checks a complete simulator domain, independently of provenance.
/// Abstention counts as uncovered, not as an incorrect certified prediction.
/// Costs of the four verification queries are explicit and must be included in
/// any claim about efficiency; coverage improvement alone proves no speedup.
pub fn evaluate(
    artifact: &Artifact,
    oracle: &[u8; 4],
    baseline: &[Option<u8>; 4],
) -> Result<Evaluation, String> {
    artifact.validate()?;
    if oracle.iter().any(|x| *x > 3) || baseline.iter().flatten().any(|x| *x > 3) {
        return Err("evaluation evidence falls outside the declared domain".into());
    }
    let baseline_correct = baseline
        .iter()
        .zip(oracle)
        .filter(|(pred, actual)| **pred == Some(**actual))
        .count();
    let candidate_correct = artifact
        .table
        .iter()
        .zip(oracle)
        .filter(|(pred, actual)| pred == actual)
        .count();
    let regressions = (0..4)
        .filter(|&i| baseline[i] == Some(oracle[i]) && artifact.table[i] != oracle[i])
        .count();
    if candidate_correct != 4 || regressions != 0 || candidate_correct <= baseline_correct {
        return Err(format!(
            "promotion refused: correct {candidate_correct}/4, baseline {baseline_correct}/4, regressions {regressions}"
        ));
    }
    Ok(Evaluation {
        baseline_correct,
        candidate_correct,
        total: 4,
        verification_queries: 4,
        regressions,
        artifact_digest: artifact.digest()?,
        oracle: *oracle,
        baseline: *baseline,
    })
}

impl Evaluation {
    fn validate(&self, artifact: &Artifact) -> Result<(), String> {
        let checked = evaluate(artifact, &self.oracle, &self.baseline)?;
        if self.artifact_digest != checked.artifact_digest
            || self.baseline_correct != checked.baseline_correct
            || self.candidate_correct != checked.candidate_correct
            || self.total != checked.total
            || self.verification_queries != checked.verification_queries
            || self.regressions != checked.regressions
        {
            return Err("evaluation is stale, modified, or bound to another artifact".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Genesis {
        version: u32,
        identity: String,
    },
    Promote {
        artifact: Artifact,
        evaluation: Evaluation,
    },
    Revoke {
        id: String,
        reason: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    sequence: usize,
    previous: String,
    payload: Event,
    sha256: String,
}

#[derive(Serialize)]
struct ReceiptBody<'a> {
    sequence: usize,
    previous: &'a str,
    payload: &'a Event,
}

fn digest<T: Serialize>(value: &T) -> Result<String, String> {
    let data = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    Ok(format!("{:x}", Sha256::digest(data)))
}

impl Receipt {
    fn calculate_hash(&self) -> Result<String, String> {
        digest(&ReceiptBody {
            sequence: self.sequence,
            previous: &self.previous,
            payload: &self.payload,
        })
    }
}

struct WriterLock(PathBuf);
impl Drop for WriterLock {
    fn drop(&mut self) {
        // A stale lock after process death is deliberately not broken by open().
        // Explicit operator recovery must first establish no writer is alive.
        let _ = fs::remove_file(&self.0);
    }
}

/// One writer owns the directory until drop. The ledger itself is the only
/// durable source of truth; no separately updated snapshot can diverge from it.
pub struct Store {
    directory: PathBuf,
    _lock: WriterLock,
    identity: String,
    receipts: Vec<Receipt>,
    active: BTreeMap<String, Artifact>,
    revisions: BTreeMap<String, u64>,
}

impl Store {
    pub fn open(directory: &Path) -> Result<Self, String> {
        fs::create_dir_all(directory).map_err(|e| format!("memory directory: {e}"))?;
        let lock_path = directory.join("writer.lock");
        let mut lock_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|e| {
                format!("exclusive memory lock unavailable (live or stale writer): {e}")
            })?;
        let lock = WriterLock(lock_path);
        writeln!(lock_file, "process={}", std::process::id()).map_err(|e| e.to_string())?;
        lock_file.sync_all().map_err(|e| e.to_string())?;
        let path = directory.join("ledger.jsonl");
        let mut store = Self {
            directory: directory.to_path_buf(),
            _lock: lock,
            identity: String::new(),
            receipts: Vec::new(),
            active: BTreeMap::new(),
            revisions: BTreeMap::new(),
        };
        if path.exists() {
            let file = File::open(&path).map_err(|e| e.to_string())?;
            if file.metadata().map_err(|e| e.to_string())?.len() > MAX_LEDGER_BYTES as u64 {
                return Err("memory ledger exceeds byte budget".into());
            }
            let mut bytes = Vec::new();
            file.take(MAX_LEDGER_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() > MAX_LEDGER_BYTES || bytes.is_empty() || bytes.last() != Some(&b'\n') {
                return Err("memory ledger is empty, truncated, or over budget".into());
            }
            let raw = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
            let mut previous = ZERO_HASH.to_string();
            for (sequence, line) in raw.lines().enumerate() {
                if sequence >= MAX_RECORDS || line.is_empty() || line.len() > MAX_RECORD_BYTES {
                    return Err("memory record exceeds budget or is empty".into());
                }
                let receipt: Receipt = serde_json::from_str(line)
                    .map_err(|e| format!("invalid memory receipt {sequence}: {e}"))?;
                if receipt.sequence != sequence
                    || receipt.previous != previous
                    || receipt.sha256 != receipt.calculate_hash()?
                {
                    return Err(format!("memory hash chain mismatch at receipt {sequence}"));
                }
                store.validate_event(&receipt.payload)?;
                store.apply(&receipt.payload);
                previous = receipt.sha256.clone();
                store.receipts.push(receipt);
            }
            if store.identity.is_empty() {
                return Err("memory genesis identity is missing".into());
            }
        }
        if !path.exists() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?;
            let nonce = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let id = digest(&(now.as_nanos().to_string(), std::process::id(), nonce))?;
            store.append(Event::Genesis {
                version: 1,
                identity: format!("symbiote-{}", &id[..24]),
            })?;
        }
        Ok(store)
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub fn active(&self) -> Vec<Artifact> {
        self.active.values().cloned().collect()
    }

    /// Highest accepted revision, including revoked versions. A new offer must
    /// exceed this value and pass fresh evaluation; revocation is never erased.
    pub fn highest_revision(&self, id: &str) -> Option<u64> {
        self.revisions.get(id).copied()
    }

    pub fn record_count(&self) -> usize {
        self.receipts.len()
    }

    pub fn ledger_path(&self) -> PathBuf {
        self.directory.join("ledger.jsonl")
    }

    pub fn promote(&mut self, artifact: Artifact, evaluation: Evaluation) -> Result<(), String> {
        self.append(Event::Promote {
            artifact,
            evaluation,
        })
    }

    pub fn revoke(&mut self, id: &str, reason: &str) -> Result<(), String> {
        self.append(Event::Revoke {
            id: id.to_string(),
            reason: reason.to_string(),
        })
    }

    fn validate_event(&self, event: &Event) -> Result<(), String> {
        match event {
            Event::Genesis { version, identity } => {
                let valid_identity = identity.strip_prefix("symbiote-").is_some_and(|suffix| {
                    suffix.len() == 24 && suffix.bytes().all(|b| b.is_ascii_hexdigit())
                });
                if !self.receipts.is_empty()
                    || !self.identity.is_empty()
                    || *version != 1
                    || !valid_identity
                {
                    return Err("invalid, unsupported, or repeated genesis identity".into());
                }
            }
            Event::Promote {
                artifact,
                evaluation,
            } => {
                if self.identity.is_empty() {
                    return Err("promotion before genesis".into());
                }
                artifact.validate()?;
                evaluation.validate(artifact)?;
                if self
                    .revisions
                    .get(&artifact.id)
                    .is_some_and(|r| artifact.revision <= *r)
                {
                    return Err("duplicate or stale artifact revision".into());
                }
                if let Some(existing) = self.active.values().find(|existing| {
                    existing.id == artifact.id
                        || (existing.source == artifact.source && existing.scope == artifact.scope)
                }) {
                    let existing_predictions = std::array::from_fn(|i| Some(existing.table[i]));
                    if evaluation.baseline != existing_predictions {
                        return Err(
                            "evaluation baseline does not reflect the active knowledge".into()
                        );
                    }
                }
            }
            Event::Revoke { id, reason } => {
                if !self.active.contains_key(id) || reason.trim().is_empty() || reason.len() > 4096
                {
                    return Err("revocation requires an active artifact and bounded reason".into());
                }
            }
        }
        Ok(())
    }

    fn apply(&mut self, event: &Event) {
        match event {
            Event::Genesis { identity, .. } => self.identity = identity.clone(),
            Event::Promote { artifact, .. } => {
                self.revisions
                    .insert(artifact.id.clone(), artifact.revision);
                self.active.insert(artifact.id.clone(), artifact.clone());
            }
            Event::Revoke { id, .. } => {
                self.active.remove(id);
            }
        }
    }

    fn append(&mut self, event: Event) -> Result<(), String> {
        self.validate_event(&event)?;
        if self.receipts.len() >= MAX_RECORDS {
            return Err("memory record budget exhausted".into());
        }
        let mut receipt = Receipt {
            sequence: self.receipts.len(),
            previous: self
                .receipts
                .last()
                .map(|x| x.sha256.as_str())
                .unwrap_or(ZERO_HASH)
                .to_string(),
            payload: event,
            sha256: String::new(),
        };
        receipt.sha256 = receipt.calculate_hash()?;
        let new_line = serde_json::to_vec(&receipt).map_err(|e| e.to_string())?;
        if new_line.len() > MAX_RECORD_BYTES {
            return Err("memory record byte budget exhausted".into());
        }
        let mut bytes = Vec::new();
        for previous in &self.receipts {
            serde_json::to_writer(&mut bytes, previous).map_err(|e| e.to_string())?;
            bytes.push(b'\n');
        }
        bytes.extend_from_slice(&new_line);
        bytes.push(b'\n');
        if bytes.len() > MAX_LEDGER_BYTES {
            return Err("memory ledger byte budget exhausted".into());
        }
        let number = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = self
            .directory
            .join(format!("ledger.{}.{number}.tmp", std::process::id()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|e| e.to_string())?;
            file.write_all(&bytes).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            drop(file);
            // On Windows std::fs::rename uses replacement semantics. Failed
            // replacement leaves the prior ledger and in-memory state intact.
            fs::rename(&temporary, self.ledger_path())
                .map_err(|e| format!("atomic ledger replacement: {e}"))?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        self.apply(&receipt.payload);
        self.receipts.push(receipt);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let n = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir()
                .join(format!("symbiote-memory-test-{}-{n}", std::process::id()));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn artifact() -> Artifact {
        Artifact {
            id: "copy-right".into(),
            revision: 1,
            source: "sim-alpha".into(),
            scope: SCOPE.into(),
            table: vec![0, 3, 0, 3],
            provenance: "simulator exchange receipt 1".into(),
        }
    }
    fn good_evaluation(a: &Artifact) -> Evaluation {
        evaluate(a, &[0, 3, 0, 3], &[Some(0), None, None, None]).unwrap()
    }

    #[test]
    fn persistent_learning_preserves_identity_and_receipts() {
        let dir = TestDirectory::new();
        let mut store = Store::open(&dir.0).unwrap();
        let identity = store.identity().to_string();
        let a = artifact();
        let e = good_evaluation(&a);
        assert_eq!(
            (
                e.baseline_correct,
                e.candidate_correct,
                e.verification_queries
            ),
            (1, 4, 4)
        );
        store.promote(a.clone(), e).unwrap();
        assert_eq!(store.record_count(), 2);
        drop(store);
        let again = Store::open(&dir.0).unwrap();
        assert_eq!(again.identity(), identity);
        assert_eq!(again.active(), vec![a]);
        assert_eq!(again.record_count(), 2);
    }

    #[test]
    fn invalid_transfer_and_no_improvement_are_rejected() {
        let mut a = artifact();
        a.table[1] = 1;
        assert!(evaluate(&a, &[0, 3, 0, 3], &[None; 4]).is_err());
        a = artifact();
        assert!(evaluate(&a, &[0, 3, 0, 3], &[Some(0), Some(3), Some(0), Some(3)]).is_err());
        a.scope = "universal-intelligence".into();
        assert!(evaluate(&a, &[0, 3, 0, 3], &[None; 4]).is_err());
        a = artifact();
        a.table.pop();
        assert!(evaluate(&a, &[0, 3, 0, 3], &[None; 4]).is_err());
    }

    #[test]
    fn evaluation_cannot_be_reused_for_modified_artifact_or_metrics() {
        let dir = TestDirectory::new();
        let mut store = Store::open(&dir.0).unwrap();
        let mut a = artifact();
        let mut e = good_evaluation(&a);
        e.verification_queries = 0;
        assert!(store.promote(a.clone(), e).is_err());
        let e = good_evaluation(&a);
        a.provenance = "changed after evaluation".into();
        assert!(store.promote(a, e).is_err());
        assert_eq!(store.record_count(), 1);
    }

    #[test]
    fn rollback_is_durable_and_stale_versions_cannot_reactivate() {
        let dir = TestDirectory::new();
        let mut store = Store::open(&dir.0).unwrap();
        let mut a = artifact();
        store.promote(a.clone(), good_evaluation(&a)).unwrap();
        assert!(store.promote(a.clone(), good_evaluation(&a)).is_err());
        store.revoke(&a.id, "scope drift counterexample").unwrap();
        assert!(store.active().is_empty());
        drop(store);
        let mut again = Store::open(&dir.0).unwrap();
        assert!(again.active().is_empty());
        assert!(again.promote(a.clone(), good_evaluation(&a)).is_err());
        a.revision = 2;
        again.promote(a.clone(), good_evaluation(&a)).unwrap();
        assert_eq!(again.active(), vec![a]);
    }

    #[test]
    fn revision_cannot_invent_improvement_by_resetting_active_baseline() {
        let dir = TestDirectory::new();
        let mut store = Store::open(&dir.0).unwrap();
        let mut a = artifact();
        store.promote(a.clone(), good_evaluation(&a)).unwrap();
        a.revision = 2;
        assert!(store.promote(a.clone(), good_evaluation(&a)).is_err());
        assert_eq!(store.active()[0].revision, 1);
    }

    #[test]
    fn artifact_alias_cannot_bypass_existing_behavior_comparison() {
        let dir = TestDirectory::new();
        let mut store = Store::open(&dir.0).unwrap();
        let mut a = artifact();
        store.promote(a.clone(), good_evaluation(&a)).unwrap();
        a.id = "renamed-identical-knowledge".into();
        assert!(store.promote(a.clone(), good_evaluation(&a)).is_err());
        assert_eq!(store.active().len(), 1);
    }

    #[test]
    fn concurrent_writers_and_stale_locks_fail_explicitly() {
        let dir = TestDirectory::new();
        let store = Store::open(&dir.0).unwrap();
        assert!(Store::open(&dir.0).is_err());
        drop(store);
        fs::write(dir.0.join("writer.lock"), b"process=absent\n").unwrap();
        assert!(Store::open(&dir.0).is_err());
    }

    #[test]
    fn corruption_truncation_and_oversize_fail_closed() {
        let dir = TestDirectory::new();
        let store = Store::open(&dir.0).unwrap();
        let path = store.ledger_path();
        drop(store);
        let original = fs::read(&path).unwrap();
        let mut modified = original.clone();
        let i = modified.iter().position(|x| *x == b'1').unwrap();
        modified[i] = b'2';
        fs::write(&path, modified).unwrap();
        assert!(Store::open(&dir.0).is_err());
        fs::write(&path, &original[..original.len() - 1]).unwrap();
        assert!(Store::open(&dir.0).is_err());
        fs::write(&path, vec![b'x'; MAX_LEDGER_BYTES + 1]).unwrap();
        assert!(Store::open(&dir.0).is_err());
    }

    #[test]
    fn failed_write_does_not_mutate_learned_state() {
        let dir = TestDirectory::new();
        let mut store = Store::open(&dir.0).unwrap();
        let path = store.ledger_path();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let a = artifact();
        assert!(store.promote(a.clone(), good_evaluation(&a)).is_err());
        assert!(store.active().is_empty());
        assert_eq!(store.record_count(), 1);
    }
}
