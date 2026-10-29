//! Bounded, evidence-gated learning in one explicitly declared finite domain.
//!
//! A hash chain detects accidental corruption; it does not authenticate a ledger
//! against an adversary capable of rewriting its complete contents. Evaluation
//! receives a privileged simulator oracle. It is not a universal truth verifier.
pub mod backup;
pub mod knowledge;
pub mod maintenance;
pub mod operational;
pub mod reciprocal;
pub mod strategy;
pub mod witness;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCOPE: &str = "finite-boolean-v1";
pub const MAX_LEDGER_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_RECORD_BYTES: usize = 16 * 1024;
pub const MAX_RECORDS: usize = 4096;
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
pub const ENGINE_OWNER_NAMESPACE: &str = "embedding-engine/v1";
pub const ENGINE_MINIMUM_WRITER: &str = "symbiote-engine-writer/1";

/// An explicit writer-format admission marker, not a model or release claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineOwnerRegistration {
    pub namespace: String,
    pub minimum_writer: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EngineOwnerError {
    Admission(String),
    Storage(String),
}
impl std::fmt::Display for EngineOwnerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admission(message) | Self::Storage(message) => formatter.write_str(message),
        }
    }
}
impl std::error::Error for EngineOwnerError {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WriterAdmission {
    Legacy,
    InitializeEngine,
    OpenEngine,
}

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
    EngineOwnerRegistered {
        namespace: String,
        minimum_writer: String,
    },
    Promote {
        artifact: Artifact,
        evaluation: Evaluation,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_version: Option<u32>,
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

/// One writer owns the directory until drop. The ledger itself is the only
/// durable source of truth; no separately updated snapshot can diverge from it.
pub struct Store {
    directory: PathBuf,
    _lock: Option<maintenance::WriterLock>,
    operational_lease: AtomicBool,
    identity: String,
    engine_owner: Option<EngineOwnerRegistration>,
    receipts: Vec<Receipt>,
    active: BTreeMap<String, Artifact>,
    revisions: BTreeMap<String, u64>,
}

impl Store {
    pub fn open(directory: &Path) -> Result<Self, String> {
        Self::open_with_initialization_hook(directory, || {})
    }

    /// Initialize a new engine identity only. Existing unmarked owners require
    /// an explicitly reviewed future migration, never an automatic upgrade.
    pub fn initialize_engine(directory: &Path) -> Result<Self, EngineOwnerError> {
        Self::open_admitted(directory, || {}, WriterAdmission::InitializeEngine)
    }

    pub fn open_engine(directory: &Path) -> Result<Self, EngineOwnerError> {
        Self::open_admitted(directory, || {}, WriterAdmission::OpenEngine)
    }

    pub fn engine_owner_registration(&self) -> Option<&EngineOwnerRegistration> {
        self.engine_owner.as_ref()
    }

    /// A private no-op in production; tests can deterministically schedule a
    /// competing constructor at the pre-genesis filesystem commit boundary.
    fn open_with_initialization_hook(
        directory: &Path,
        before_genesis: impl FnOnce(),
    ) -> Result<Self, String> {
        Self::open_admitted(directory, before_genesis, WriterAdmission::Legacy)
            .map_err(|error| error.to_string())
    }

    fn open_admitted(
        directory: &Path,
        before_genesis: impl FnOnce(),
        admission: WriterAdmission,
    ) -> Result<Self, EngineOwnerError> {
        fs::create_dir_all(directory)
            .map_err(|e| EngineOwnerError::Storage(format!("memory directory: {e}")))?;
        let (lock, _initialization_gate) = maintenance::writer_lock(directory, "writer.lock")
            .map_err(EngineOwnerError::Storage)?;
        let path = directory.join("ledger.jsonl");
        if admission == WriterAdmission::InitializeEngine && path.exists() {
            return Err(EngineOwnerError::Admission(
                "engine initialization requires an absent identity ledger".into(),
            ));
        }
        if admission == WriterAdmission::OpenEngine && !path.exists() {
            return Err(EngineOwnerError::Admission(
                "engine owner registration is missing; refusing initialization".into(),
            ));
        }
        if !directory.join("ledger.jsonl").exists() && directory.join("knowledge.jsonl").exists() {
            return Err(EngineOwnerError::Admission(
                "structural knowledge exists without its identity ledger; refusing identity reset"
                    .into(),
            ));
        }
        if !directory.join("ledger.jsonl").exists()
            && (directory.join("operations.jsonl").exists()
                || directory.join(operational::OWNER_FILE).exists()
                || directory.join(strategy::STRATEGY_FILE).exists()
                || directory.join(strategy::STRATEGY_OWNER_FILE).exists())
        {
            return Err(EngineOwnerError::Admission(
                "operational or strategy history exists without its identity ledger; refusing identity reset"
                    .into(),
            ));
        }
        before_genesis();
        let mut store = Self {
            directory: directory.to_path_buf(),
            _lock: Some(lock),
            operational_lease: AtomicBool::new(false),
            identity: String::new(),
            engine_owner: None,
            receipts: Vec::new(),
            active: BTreeMap::new(),
            revisions: BTreeMap::new(),
        };
        if path.exists() {
            let file = File::open(&path).map_err(|e| EngineOwnerError::Storage(e.to_string()))?;
            if file
                .metadata()
                .map_err(|e| EngineOwnerError::Storage(e.to_string()))?
                .len()
                > MAX_LEDGER_BYTES as u64
            {
                return Err(EngineOwnerError::Admission(
                    "memory ledger exceeds byte budget".into(),
                ));
            }
            let mut bytes = Vec::new();
            file.take(MAX_LEDGER_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| EngineOwnerError::Storage(e.to_string()))?;
            store
                .replay_bytes(&bytes)
                .map_err(EngineOwnerError::Admission)?;
        }
        if !path.exists() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| EngineOwnerError::Storage(e.to_string()))?;
            let nonce = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let id = digest(&(now.as_nanos().to_string(), std::process::id(), nonce))
                .map_err(EngineOwnerError::Admission)?;
            store
                .append(Event::Genesis {
                    version: 1,
                    identity: format!("symbiote-{}", &id[..24]),
                })
                .map_err(EngineOwnerError::Storage)?;
        }
        if admission == WriterAdmission::InitializeEngine {
            store
                .append(Event::EngineOwnerRegistered {
                    namespace: ENGINE_OWNER_NAMESPACE.into(),
                    minimum_writer: ENGINE_MINIMUM_WRITER.into(),
                })
                .map_err(EngineOwnerError::Storage)?;
        }
        match (admission, store.engine_owner.as_ref()) {
            (WriterAdmission::Legacy, Some(_)) => return Err(EngineOwnerError::Admission("engine-owned namespace requires an explicit compatible Engine writer".into())),
            (WriterAdmission::OpenEngine | WriterAdmission::InitializeEngine, None) => return Err(EngineOwnerError::Admission("engine owner registration is missing; unmarked prototypes require explicit migration".into())),
            _ => {},
        }
        maintenance::validate_layout_identity(directory, &store.identity)
            .map_err(EngineOwnerError::Admission)?;
        Ok(store)
    }

    fn replay_bytes(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() > MAX_LEDGER_BYTES || bytes.is_empty() || bytes.last() != Some(&b'\n') {
            return Err("memory ledger is empty, truncated, or over budget".into());
        }
        let raw = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
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
            self.validate_event(&receipt.payload)?;
            self.apply(&receipt.payload);
            previous = receipt.sha256.clone();
            self.receipts.push(receipt);
        }
        if self.identity.is_empty() {
            return Err("memory genesis identity is missing".into());
        }
        Ok(())
    }

    pub(crate) fn validate_snapshot(bytes: &[u8]) -> Result<String, String> {
        Self::validate_owner_snapshot(bytes).map(|(identity, _)| identity)
    }

    pub(crate) fn validate_owner_snapshot(
        bytes: &[u8],
    ) -> Result<(String, Option<EngineOwnerRegistration>), String> {
        let mut snapshot = Self {
            directory: PathBuf::new(),
            _lock: None,
            operational_lease: AtomicBool::new(false),
            identity: String::new(),
            engine_owner: None,
            receipts: Vec::new(),
            active: BTreeMap::new(),
            revisions: BTreeMap::new(),
        };
        snapshot.replay_bytes(bytes)?;
        Ok((snapshot.identity, snapshot.engine_owner))
    }

    /// Validate an original, complete genesis-only ledger without opening a
    /// writer or creating files. Later learning history is never setup data.
    pub fn validate_empty_genesis(bytes: &[u8]) -> Result<String, String> {
        if bytes.is_empty() || bytes.len() > 4096 || bytes.last() != Some(&b'\n') {
            return Err("empty genesis must be a complete bounded JSONL record".into());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| "genesis must be UTF8")?;
        if text.lines().count() != 1 {
            return Err("setup accepts exactly one genesis record, without history".into());
        }
        let receipt: Receipt = serde_json::from_str(text.trim_end_matches(['\r', '\n']))
            .map_err(|_| "setup genesis receipt schema rejected")?;
        if receipt.sequence != 0
            || receipt.previous != ZERO_HASH
            || !matches!(receipt.payload, Event::Genesis { version: 1, .. })
        {
            return Err("setup accepts only an original version-one genesis".into());
        }
        Self::validate_snapshot(bytes)
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
            policy_version: Some(2),
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
            Event::EngineOwnerRegistered {
                namespace,
                minimum_writer,
            } => {
                if self.receipts.len() != 1
                    || self.identity.is_empty()
                    || self.engine_owner.is_some()
                    || namespace != ENGINE_OWNER_NAMESPACE
                    || minimum_writer != ENGINE_MINIMUM_WRITER
                {
                    return Err("unsupported, late or duplicate engine writer registration".into());
                }
            }
            Event::Promote {
                artifact,
                evaluation,
                policy_version,
            } => {
                if self.engine_owner.is_some() {
                    return Err(
                        "legacy finite-table learning cannot mutate an engine-owned namespace"
                            .into(),
                    );
                }
                if self.identity.is_empty() {
                    return Err("promotion before genesis".into());
                }
                artifact.validate()?;
                evaluation.validate(artifact)?;
                if policy_version.is_some_and(|version| version != 2) {
                    return Err("unsupported memory promotion policy".into());
                }
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
                    if policy_version == &Some(2) && evaluation.oracle.as_slice() != existing.table
                    {
                        return Err("stationary context contradicts retained truth; revoke or change context before promotion".into());
                    }
                    let existing_predictions = std::array::from_fn(|i| Some(existing.table[i]));
                    if evaluation.baseline != existing_predictions {
                        return Err(
                            "evaluation baseline does not reflect the active knowledge".into()
                        );
                    }
                }
            }
            Event::Revoke { id, reason } => {
                if self.engine_owner.is_some() {
                    return Err(
                        "legacy finite-table revocation cannot mutate an engine-owned namespace"
                            .into(),
                    );
                }
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
            Event::EngineOwnerRegistered {
                namespace,
                minimum_writer,
            } => {
                self.engine_owner = Some(EngineOwnerRegistration {
                    namespace: namespace.clone(),
                    minimum_writer: minimum_writer.clone(),
                });
            }
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
    fn engine_owner_registration_rejects_generic_writers_and_preserves_genesis() {
        let dir = TestDirectory::new();
        let mut owner = Store::initialize_engine(&dir.0).unwrap();
        let identity = owner.identity().to_string();
        assert_eq!(owner.record_count(), 2);
        assert_eq!(
            owner.engine_owner_registration(),
            Some(&EngineOwnerRegistration {
                namespace: ENGINE_OWNER_NAMESPACE.into(),
                minimum_writer: ENGINE_MINIMUM_WRITER.into()
            })
        );
        let original = fs::read(owner.ledger_path()).unwrap();
        let genesis_end = original.iter().position(|byte| *byte == b'\n').unwrap() + 1;
        assert_eq!(
            Store::validate_empty_genesis(&original[..genesis_end]).unwrap(),
            identity
        );
        assert_eq!(Store::validate_snapshot(&original).unwrap(), identity);
        let a = artifact();
        assert!(owner.promote(a.clone(), good_evaluation(&a)).is_err());
        assert_eq!(fs::read(owner.ledger_path()).unwrap(), original);
        assert!(knowledge::KnowledgeStore::open(&dir.0, &identity).is_err());
        let knowledge = knowledge::KnowledgeStore::open_engine(&dir.0, &identity).unwrap();
        let structural = fs::read(knowledge.ledger_path()).unwrap();
        drop(knowledge);
        drop(owner);
        assert!(Store::open(&dir.0).is_err());
        assert!(knowledge::KnowledgeStore::open(&dir.0, &identity).is_err());
        assert_eq!(fs::read(dir.0.join("ledger.jsonl")).unwrap(), original);
        assert_eq!(fs::read(dir.0.join("knowledge.jsonl")).unwrap(), structural);
        assert_eq!(
            maintenance::inspect(&dir.0).unwrap().identity,
            Some(identity.clone())
        );
        let reopened = Store::open_engine(&dir.0).unwrap();
        assert_eq!(reopened.identity(), identity);
        assert_eq!(fs::read(reopened.ledger_path()).unwrap(), original);
    }

    #[test]
    fn engine_admission_never_upgrades_an_unmarked_owner_or_unknown_writer_marker() {
        let dir = TestDirectory::new();
        let legacy = Store::open(&dir.0).unwrap();
        let identity = legacy.identity().to_string();
        let original = fs::read(legacy.ledger_path()).unwrap();
        drop(legacy);
        assert!(matches!(
            Store::open_engine(&dir.0),
            Err(EngineOwnerError::Admission(_))
        ));
        assert!(matches!(
            Store::initialize_engine(&dir.0),
            Err(EngineOwnerError::Admission(_))
        ));
        assert!(knowledge::KnowledgeStore::open_engine(&dir.0, &identity).is_err());
        assert_eq!(fs::read(dir.0.join("ledger.jsonl")).unwrap(), original);
        assert_eq!(Store::open(&dir.0).unwrap().record_count(), 1);

        let marked = TestDirectory::new();
        let owner = Store::initialize_engine(&marked.0).unwrap();
        let path = owner.ledger_path();
        let saved = fs::read(&path).unwrap();
        drop(owner);
        let mut receipts: Vec<Receipt> = std::str::from_utf8(&saved)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        if let Event::EngineOwnerRegistered { minimum_writer, .. } = &mut receipts[1].payload {
            *minimum_writer = "unsupported-future-writer/99".into();
        } else {
            panic!("expected marker");
        }
        receipts[1].sha256 = receipts[1].calculate_hash().unwrap();
        let mut changed = Vec::new();
        for receipt in receipts {
            serde_json::to_writer(&mut changed, &receipt).unwrap();
            changed.push(b'\n');
        }
        fs::write(&path, &changed).unwrap();
        assert!(matches!(
            Store::open_engine(&marked.0),
            Err(EngineOwnerError::Admission(_))
        ));
        assert!(Store::open(&marked.0).is_err());
        assert_eq!(fs::read(path).unwrap(), changed);
    }

    #[test]
    fn empty_genesis_validation_is_read_only_and_rejects_learning_and_tampering() {
        let dir = TestDirectory::new();
        let mut store = Store::open(&dir.0).unwrap();
        let original = fs::read(store.ledger_path()).unwrap();
        assert_eq!(
            Store::validate_empty_genesis(&original).unwrap(),
            store.identity()
        );
        let mut changed = original.clone();
        let index = changed.iter().position(|byte| *byte == b's').unwrap();
        changed[index] = b'x';
        assert!(Store::validate_empty_genesis(&changed).is_err());
        assert!(Store::validate_empty_genesis(&original[..original.len() - 1]).is_err());
        assert!(
            Store::validate_empty_genesis(&[original.clone(), b"\n".to_vec()].concat()).is_err()
        );
        let a = artifact();
        store.promote(a.clone(), good_evaluation(&a)).unwrap();
        assert!(Store::validate_empty_genesis(&fs::read(store.ledger_path()).unwrap()).is_err());
        assert_eq!(store.record_count(), 2);
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

    #[test]
    fn changed_finite_world_truth_requires_revocation_without_rewriting_history() {
        let dir = TestDirectory::new();
        let mut store = Store::open(&dir.0).unwrap();
        let original = artifact();
        store
            .promote(original.clone(), good_evaluation(&original))
            .unwrap();
        let mut changed = original.clone();
        changed.revision = 2;
        changed.table[2] ^= 1;
        let oracle: [u8; 4] = changed.table.clone().try_into().unwrap();
        let baseline = std::array::from_fn(|i| Some(original.table[i]));
        let evaluation = evaluate(&changed, &oracle, &baseline).unwrap();
        assert!(store
            .promote(changed.clone(), evaluation.clone())
            .unwrap_err()
            .contains("stationary"));
        assert_eq!(store.record_count(), 2);
        assert_eq!(store.active(), vec![original.clone()]);
        store
            .revoke(&original.id, "changed environment verified")
            .unwrap();
        store.promote(changed.clone(), evaluation).unwrap();
        drop(store);
        assert_eq!(Store::open(&dir.0).unwrap().active(), vec![changed]);
    }
}
