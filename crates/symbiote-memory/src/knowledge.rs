//! Scoped, declarative knowledge with distinct held-out laboratory evidence.
//!
//! Expected outputs and cost measurements are supplied by a trusted experiment
//! evaluator. This module checks their internal consistency, not remote honesty.
//! A SHA chain detects accidental modification, not an attacker rewriting it all.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

pub mod graph;

const MAX_RECORD_BYTES: usize = 128 * 1024;
const MAX_CASES: usize = 256;
const MAX_COST: u64 = 1_000_000_000;
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeRecord {
    pub id: String,
    pub revision: u64,
    pub source: String,
    pub scope: String,
    pub schema_fingerprint: String,
    /// Inert typed JSON. Only the explicitly supported declarative grammars are admitted.
    pub payload: Value,
    pub provenance: String,
}

/// Parsing dispatch only; keeping `KnowledgeRecord.payload` as `Value` preserves
/// the exact serialization of every pre-existing affine receipt.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum KnowledgePayload {
    Affine {
        width: u8,
        coefficients: u16,
        bias: bool,
    },
    GraphMap(graph::GraphMap),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AffinePayload {
    kind: String,
    width: u8,
    coefficients: u16,
    bias: bool,
}

impl AffinePayload {
    fn from_record(record: &KnowledgeRecord) -> Result<Self, String> {
        let payload: Self =
            serde_json::from_value(record.payload.clone()).map_err(|e| e.to_string())?;
        if payload.kind != "affine"
            || !(1..=8).contains(&payload.width)
            || payload.coefficients >= 1_u16 << payload.width
        {
            return Err("unsupported or out-of-domain declarative knowledge".into());
        }
        if record.schema_fingerprint != affine_schema_fingerprint(payload.width)? {
            return Err("knowledge schema fingerprint does not match payload".into());
        }
        Ok(payload)
    }

    fn predict(&self, input: u16) -> Result<u8, String> {
        if input >= 1_u16 << self.width {
            return Err("evidence input outside knowledge schema".into());
        }
        Ok((((input & self.coefficients).count_ones() % 2) as u8) ^ u8::from(self.bias))
    }
}

/// Identifies the input coordinate schema, not a claim about an actual system.
pub fn affine_schema_fingerprint(width: u8) -> Result<String, String> {
    if !(1..=8).contains(&width) {
        return Err("affine schema width must be 1..8".into());
    }
    super::digest(&serde_json::json!({
        "kind":"affine-boolean", "version":1, "width":width, "coordinate_order":"least-significant-bit-first"
    }))
}

impl KnowledgeRecord {
    pub fn validate(&self) -> Result<(), String> {
        if !label(&self.id) || !label(&self.source) || !label(&self.scope) || self.revision == 0 {
            return Err(
                "knowledge needs bounded identity, source, scope and positive revision".into(),
            );
        }
        if self.provenance.trim().is_empty() || self.provenance.len() > 4096 {
            return Err("knowledge requires bounded provenance".into());
        }
        match self.typed_payload()? {
            KnowledgePayload::Affine { .. } => {
                AffinePayload::from_record(self)?;
            }
            KnowledgePayload::GraphMap(map) => {
                map.validate()?;
                if self.schema_fingerprint != graph::graph_schema_fingerprint(&map.schema)? {
                    return Err("knowledge schema fingerprint does not match graph payload".into());
                }
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, String> {
        super::digest(self)
    }

    pub fn predict(&self, input: u16) -> Result<u8, String> {
        self.predict_if_certified(input)?.ok_or_else(|| {
            "graph knowledge abstains without a conservative route certificate".into()
        })
    }

    pub fn typed_payload(&self) -> Result<KnowledgePayload, String> {
        serde_json::from_value(self.payload.clone()).map_err(|e| e.to_string())
    }

    /// A graph returns a cost only for a route certified from observed edges.
    /// Unreachable and uncertain queries return `None`, never an invented value.
    pub fn predict_if_certified(&self, input: u16) -> Result<Option<u8>, String> {
        self.validate()?;
        match self.typed_payload()? {
            KnowledgePayload::Affine { .. } => {
                AffinePayload::from_record(self)?.predict(input).map(Some)
            }
            KnowledgePayload::GraphMap(map) => map.predict(input),
        }
    }

    /// Exposes the actual conditional path certificate as well as its cost.
    pub fn graph_forecast(
        &self,
        input: u16,
    ) -> Result<Option<symbiote_reasoning::planning::Route>, String> {
        self.validate()?;
        graph::GraphMap::from_record(self)?.forecast(input)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialCase {
    pub id: String,
    pub input: u16,
    pub expected: u8,
    pub baseline: Option<u8>,
    pub candidate: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialCosts {
    /// Candidate-side breakdown. All three are included in `candidate`.
    pub acquisition: u64,
    pub verification: u64,
    pub adoption: u64,
    /// Total isolated cost, including acquisition and prediction.
    pub baseline: u64,
    /// Total exchange cost, including acquisition, verification, adoption and prediction.
    pub candidate: u64,
}

impl TrialCosts {
    fn validate(&self) -> Result<(), String> {
        let parts = self
            .acquisition
            .checked_add(self.verification)
            .and_then(|v| v.checked_add(self.adoption))
            .ok_or("trial cost overflow")?;
        if parts > self.candidate
            || [
                self.baseline,
                self.candidate,
                self.acquisition,
                self.verification,
                self.adoption,
            ]
            .iter()
            .any(|cost| *cost > MAX_COST)
        {
            return Err("candidate cost excludes measured components or exceeds budget".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialEvidence {
    pub evaluator: String,
    /// IDs and inputs identify actual acquisition examples, in matching order.
    pub training_case_ids: Vec<String>,
    pub training_inputs: Vec<u16>,
    pub cases: Vec<TrialCase>,
    pub costs: TrialCosts,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    pub independent_cases: usize,
    pub baseline_correct: usize,
    pub candidate_correct: usize,
    pub regressions: usize,
    pub baseline_cost: u64,
    pub candidate_cost: u64,
    pub coverage_improved: bool,
    pub cost_improved: bool,
    record_digest: String,
    evidence: TrialEvidence,
}

/// Recomputes every prediction and metric against unique, disjoint held-out cases.
/// A successful assessment is scoped to this declared grammar and laboratory
/// evidence. It is not a certificate of arbitrary remote truth or generalization.
pub fn assess(record: &KnowledgeRecord, evidence: &TrialEvidence) -> Result<Assessment, String> {
    record.validate()?;
    let payload = AffinePayload::from_record(record)?;
    if !label(&evidence.evaluator) || evidence.evaluator == record.source {
        return Err("a distinct identified laboratory evaluator is required".into());
    }
    if evidence.cases.is_empty()
        || evidence.cases.len() > MAX_CASES
        || evidence.training_case_ids.len() != evidence.training_inputs.len()
        || evidence.training_inputs.len() > MAX_CASES
    {
        return Err("trial needs bounded cases and aligned training identifiers/inputs".into());
    }
    evidence.costs.validate()?;
    let mut training_ids = BTreeSet::new();
    let mut training_inputs = BTreeSet::new();
    for (id, input) in evidence
        .training_case_ids
        .iter()
        .zip(&evidence.training_inputs)
    {
        payload.predict(*input)?;
        if !label(id) || !training_ids.insert(id) || !training_inputs.insert(*input) {
            return Err("training examples must have unique bounded IDs and inputs".into());
        }
    }
    let mut evaluation_ids = BTreeSet::new();
    let mut evaluation_inputs = BTreeSet::new();
    let mut baseline_correct = 0;
    let mut candidate_correct = 0;
    let mut regressions = 0;
    for case in &evidence.cases {
        if !label(&case.id)
            || !evaluation_ids.insert(&case.id)
            || !evaluation_inputs.insert(case.input)
            || training_ids.contains(&case.id)
            || training_inputs.contains(&case.input)
        {
            return Err("held-out examples must be unique and disjoint from training".into());
        }
        if case.expected > 1 || case.candidate > 1 || case.baseline.is_some_and(|b| b > 1) {
            return Err("trial outputs must be binary".into());
        }
        if payload.predict(case.input)? != case.candidate {
            return Err(
                "recorded candidate prediction does not follow declarative knowledge".into(),
            );
        }
        baseline_correct += usize::from(case.baseline == Some(case.expected));
        candidate_correct += usize::from(case.candidate == case.expected);
        regressions +=
            usize::from(case.baseline == Some(case.expected) && case.candidate != case.expected);
    }
    let coverage_improved = candidate_correct > baseline_correct;
    let cost_improved =
        candidate_correct == baseline_correct && evidence.costs.candidate < evidence.costs.baseline;
    if candidate_correct != evidence.cases.len()
        || regressions != 0
        || !(coverage_improved || cost_improved)
    {
        return Err("knowledge must be correct on held-out evidence and improve coverage or equal-coverage total cost".into());
    }
    Ok(Assessment {
        independent_cases: evidence.cases.len(),
        baseline_correct,
        candidate_correct,
        regressions,
        baseline_cost: evidence.costs.baseline,
        candidate_cost: evidence.costs.candidate,
        coverage_improved,
        cost_improved,
        record_digest: record.digest()?,
        evidence: evidence.clone(),
    })
}

impl Assessment {
    fn validate(&self, record: &KnowledgeRecord) -> Result<(), String> {
        let computed = assess(record, &self.evidence)?;
        if super::digest(self)? != super::digest(&computed)? {
            return Err("assessment was modified or is bound to another record".into());
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
        record: KnowledgeRecord,
        assessment: Box<Assessment>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_version: Option<u32>,
    },
    PromoteGraph {
        record: KnowledgeRecord,
        assessment: Box<graph::GraphAssessment>,
        policy_version: u32,
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

impl Receipt {
    fn hash(&self) -> Result<String, String> {
        super::digest(&(self.sequence, &self.previous, &self.payload))
    }
}

/// Per-instance application I/O diagnostics, never a learning reward or OS
/// durability/power-loss certificate. Publication bytes overlap complete writes;
/// do not sum them. Hash serialization, allocator/CPU and identity setup are separate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KnowledgeIoDiagnostics {
    pub cold_read_bytes: u64,
    /// Actual bounded reads performed by live prepublication integrity guards.
    pub integrity_read_bytes: u64,
    /// Exact raw-byte hashing for cold pins, guards and successful publications.
    pub integrity_hashed_bytes: u64,
    pub integrity_checks: u64,
    pub integrity_failures: u64,
    pub full_history_serialized_bytes: u64,
    /// Extra canonical serialization used only to cache exact publication capacity.
    pub capacity_quote_serialized_bytes: u64,
    pub write_submitted_bytes: u64,
    pub write_all_completed_bytes: u64,
    pub committed_publication_bytes: u64,
    pub publication_attempts: u64,
    pub publication_failures: u64,
    pub failed_write_all_calls: u64,
    /// Some(0) when no write_all failed; None after a failure because partial
    /// successful bytes are not observable through Write::write_all's error.
    pub failed_partial_write_bytes: Option<u64>,
    pub saturated: bool,
}
impl Default for KnowledgeIoDiagnostics {
    fn default() -> Self {
        Self {
            cold_read_bytes: 0,
            integrity_read_bytes: 0,
            integrity_hashed_bytes: 0,
            integrity_checks: 0,
            integrity_failures: 0,
            full_history_serialized_bytes: 0,
            capacity_quote_serialized_bytes: 0,
            write_submitted_bytes: 0,
            write_all_completed_bytes: 0,
            committed_publication_bytes: 0,
            publication_attempts: 0,
            publication_failures: 0,
            failed_write_all_calls: 0,
            failed_partial_write_bytes: Some(0),
            saturated: false,
        }
    }
}
fn io_add(target: &mut u64, amount: u64) -> bool {
    let overflow = target.checked_add(amount).is_none();
    *target = target.saturating_add(amount);
    overflow
}
fn write_application_bytes(
    writer: &mut impl Write,
    bytes: &[u8],
    io: &mut KnowledgeIoDiagnostics,
) -> Result<(), String> {
    io.saturated |= io_add(&mut io.write_submitted_bytes, bytes.len() as u64);
    if let Err(error) = writer.write_all(bytes) {
        io.saturated |= io_add(&mut io.failed_write_all_calls, 1);
        io.failed_partial_write_bytes = None;
        return Err(error.to_string());
    }
    io.saturated |= io_add(&mut io.write_all_completed_bytes, bytes.len() as u64);
    Ok(())
}
/// Unchanged native limits and the live owner's last successfully published
/// physical ledger size plus exact cached canonical rewrite size. Physical
/// whitespace can be reclaimed by the existing compact rewrite. The extra cold
/// serialization is counted separately. This is not an I/O success promise.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KnowledgeCapacity {
    pub used_records: usize,
    pub used_ledger_bytes: usize,
    pub canonical_ledger_bytes: usize,
    pub max_records: usize,
    pub max_ledger_bytes: usize,
    pub max_record_bytes: usize,
    pub remaining_records: usize,
    pub remaining_ledger_bytes: usize,
    pub remaining_publication_bytes: usize,
}
/// Classification comes from the guard that failed, without parsing prose.
/// A storage failure is not permission to recreate or repair a live ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemoryWriteError {
    Capacity(String),
    Invalid(String),
    Integrity(String),
    Storage(String),
}
impl std::fmt::Display for MemoryWriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Capacity(message)
            | Self::Invalid(message)
            | Self::Integrity(message)
            | Self::Storage(message) => formatter.write_str(message),
        }
    }
}
impl std::error::Error for MemoryWriteError {}
/// Separate, versioned native ledger. The caller's persistent identity is bound
/// into genesis. Opening it never resets or migrates the original v0.1 ledger.
pub struct KnowledgeStore {
    directory: PathBuf,
    _lock: Option<super::maintenance::WriterLock>,
    identity: String,
    genesis: bool,
    receipts: Vec<Receipt>,
    active: BTreeMap<String, KnowledgeRecord>,
    revisions: BTreeMap<String, u64>,
    bindings: BTreeMap<String, (String, String, String)>,
    retained_expected: BTreeMap<String, BTreeMap<u16, u8>>,
    retained_graph_edges: BTreeMap<String, BTreeMap<usize, u16>>,
    io: KnowledgeIoDiagnostics,
    ledger_bytes: usize,
    canonical_ledger_bytes: usize,
    disk_sha256: Option<String>,
}

/// A read-only position in a validated owner history. This does not grant trust
/// to an external value; consumers retain the current anchor independently.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeAnchor {
    pub identity: String,
    pub records: usize,
    pub head_sha256: String,
}

impl KnowledgeStore {
    pub fn open(directory: &Path, identity: &str) -> Result<Self, String> {
        Self::open_admitted(directory, identity, false)
    }

    pub fn open_engine(directory: &Path, identity: &str) -> Result<Self, String> {
        Self::open_admitted(directory, identity, true)
    }

    fn open_admitted(directory: &Path, identity: &str, engine: bool) -> Result<Self, String> {
        if !label(identity) {
            return Err("invalid persistent knowledge owner identity".into());
        }
        fs::create_dir_all(directory).map_err(|e| format!("knowledge directory: {e}"))?;
        let (lock, _initialization_gate) =
            super::maintenance::writer_lock(directory, "knowledge.writer.lock")?;
        if engine {
            super::maintenance::validate_engine_knowledge_owner(directory, identity)?;
        } else {
            super::maintenance::validate_knowledge_owner(directory, identity)?;
        }
        // Reject an unsupported registered format before a first knowledge
        // genesis can mutate that owner's directory.
        super::maintenance::validate_layout_identity(directory, identity)?;
        let mut store = Self {
            directory: directory.to_path_buf(),
            _lock: Some(lock),
            identity: identity.into(),
            genesis: false,
            receipts: Vec::new(),
            active: BTreeMap::new(),
            revisions: BTreeMap::new(),
            bindings: BTreeMap::new(),
            retained_expected: BTreeMap::new(),
            retained_graph_edges: BTreeMap::new(),
            io: KnowledgeIoDiagnostics::default(),
            ledger_bytes: 0,
            canonical_ledger_bytes: 0,
            disk_sha256: None,
        };
        let path = store.ledger_path();
        if path.exists() {
            let file = File::open(&path).map_err(|e| e.to_string())?;
            if file.metadata().map_err(|e| e.to_string())?.len() > super::MAX_LEDGER_BYTES as u64 {
                return Err("knowledge ledger exceeds byte budget".into());
            }
            let mut bytes = Vec::new();
            let read = file
                .take(super::MAX_LEDGER_BYTES as u64 + 1)
                .read_to_end(&mut bytes);
            store.io.saturated |= io_add(&mut store.io.cold_read_bytes, bytes.len() as u64);
            read.map_err(|e| e.to_string())?;
            store.ledger_bytes = bytes.len();
            if bytes.len() > super::MAX_LEDGER_BYTES
                || bytes.is_empty()
                || bytes.last() != Some(&b'\n')
            {
                return Err("knowledge ledger empty, truncated or over budget".into());
            }
            let raw = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
            let mut previous = ZERO_HASH.to_string();
            for (sequence, line) in raw.lines().enumerate() {
                if sequence >= super::MAX_RECORDS
                    || line.is_empty()
                    || line.len() > MAX_RECORD_BYTES
                {
                    return Err("knowledge record exceeds budget or is empty".into());
                }
                let receipt: Receipt = serde_json::from_str(line)
                    .map_err(|e| format!("invalid knowledge receipt {sequence}: {e}"))?;
                if receipt.sequence != sequence
                    || receipt.previous != previous
                    || receipt.sha256 != receipt.hash()?
                {
                    return Err(format!(
                        "knowledge hash chain mismatch at receipt {sequence}"
                    ));
                }
                store.validate_event(&receipt.payload)?;
                let canonical = serde_json::to_vec(&receipt)
                    .map_err(|e| e.to_string())?
                    .len()
                    + 1;
                store.canonical_ledger_bytes = store
                    .canonical_ledger_bytes
                    .checked_add(canonical)
                    .ok_or("knowledge canonical byte size overflow")?;
                store.io.saturated |= io_add(
                    &mut store.io.capacity_quote_serialized_bytes,
                    canonical as u64,
                );
                store.apply(&receipt.payload);
                previous = receipt.sha256.clone();
                store.receipts.push(receipt);
            }
            if !store.genesis {
                return Err("knowledge genesis missing".into());
            }
            store.disk_sha256 = Some(store.pin_bytes(&bytes));
        }
        if !path.exists() {
            store.append(Event::Genesis {
                version: 1,
                identity: identity.into(),
            })?;
        }
        super::maintenance::validate_layout_identity(directory, &store.identity)?;
        Ok(store)
    }

    pub(crate) fn validate_snapshot(bytes: &[u8], identity: &str) -> Result<(), String> {
        if bytes.len() > super::MAX_LEDGER_BYTES || bytes.is_empty() || bytes.last() != Some(&b'\n')
        {
            return Err("knowledge ledger empty, truncated or over budget".into());
        }
        let mut snapshot = Self {
            directory: PathBuf::new(),
            _lock: None,
            identity: identity.into(),
            genesis: false,
            receipts: Vec::new(),
            active: BTreeMap::new(),
            revisions: BTreeMap::new(),
            bindings: BTreeMap::new(),
            retained_expected: BTreeMap::new(),
            retained_graph_edges: BTreeMap::new(),
            io: KnowledgeIoDiagnostics::default(),
            ledger_bytes: 0,
            canonical_ledger_bytes: 0,
            disk_sha256: None,
        };
        let mut previous = ZERO_HASH.to_string();
        for (sequence, line) in std::str::from_utf8(bytes)
            .map_err(|e| e.to_string())?
            .lines()
            .enumerate()
        {
            if sequence >= super::MAX_RECORDS || line.is_empty() || line.len() > MAX_RECORD_BYTES {
                return Err("knowledge record exceeds budget or is empty".into());
            }
            let receipt: Receipt = serde_json::from_str(line)
                .map_err(|e| format!("invalid knowledge receipt {sequence}: {e}"))?;
            if receipt.sequence != sequence
                || receipt.previous != previous
                || receipt.sha256 != receipt.hash()?
            {
                return Err(format!(
                    "knowledge hash chain mismatch at receipt {sequence}"
                ));
            }
            snapshot.validate_event(&receipt.payload)?;
            snapshot.apply(&receipt.payload);
            previous = receipt.sha256.clone();
            snapshot.receipts.push(receipt);
        }
        if !snapshot.genesis {
            return Err("knowledge genesis missing".into());
        }
        Ok(())
    }

    /// Snapshot only: no file read/write, source callback or global counter.
    pub fn io_diagnostics(&self) -> KnowledgeIoDiagnostics {
        self.io.clone()
    }
    /// Current native capacity. Callers may reject certain exhaustion before
    /// learning; exact next-frame serialization and storage can still fail.
    pub fn capacity(&self) -> KnowledgeCapacity {
        KnowledgeCapacity {
            used_records: self.receipts.len(),
            used_ledger_bytes: self.ledger_bytes,
            canonical_ledger_bytes: self.canonical_ledger_bytes,
            max_records: super::MAX_RECORDS,
            max_ledger_bytes: super::MAX_LEDGER_BYTES,
            max_record_bytes: MAX_RECORD_BYTES,
            remaining_records: super::MAX_RECORDS.saturating_sub(self.receipts.len()),
            remaining_ledger_bytes: super::MAX_LEDGER_BYTES.saturating_sub(self.ledger_bytes),
            remaining_publication_bytes: super::MAX_LEDGER_BYTES
                .saturating_sub(self.canonical_ledger_bytes),
        }
    }
    pub fn identity(&self) -> &str {
        &self.identity
    }
    pub fn active(&self) -> Vec<KnowledgeRecord> {
        self.active.values().cloned().collect()
    }
    /// Reconstructs active knowledge at an exact already-validated prefix.
    /// Later revocation or supersession cannot rewrite a historical decision.
    pub fn active_at(&self, anchor: &KnowledgeAnchor) -> Result<Vec<KnowledgeRecord>, String> {
        self.validate_anchor(anchor)?;
        let mut active = BTreeMap::new();
        for receipt in self.receipts.iter().take(anchor.records) {
            match &receipt.payload {
                Event::Promote { record, .. } | Event::PromoteGraph { record, .. } => {
                    active.insert(record.id.clone(), record.clone());
                }
                Event::Revoke { id, .. } => {
                    active.remove(id);
                }
                Event::Genesis { .. } => {}
            }
        }
        Ok(active.into_values().collect())
    }
    pub fn highest_revision(&self, id: &str) -> Option<u64> {
        self.revisions.get(id).copied()
    }
    /// An operational completion can anchor a past learning commit even after
    /// legitimate revocation or a newer revision. This checks exact validated
    /// historical content; active membership alone cannot prove that history.
    pub fn has_historical_promotion(&self, expected: &KnowledgeRecord) -> Result<bool, String> {
        expected.validate()?;
        let expected_digest = expected.digest()?;
        for receipt in &self.receipts {
            let record = match &receipt.payload {
                Event::Promote { record, .. } | Event::PromoteGraph { record, .. } => record,
                _ => continue,
            };
            if record.id == expected.id
                && record.revision == expected.revision
                && record.digest()? == expected_digest
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub fn record_count(&self) -> usize {
        self.receipts.len()
    }
    pub fn history_anchor(&self) -> KnowledgeAnchor {
        KnowledgeAnchor {
            identity: self.identity.clone(),
            records: self.receipts.len(),
            head_sha256: self
                .receipts
                .last()
                .map(|receipt| receipt.sha256.clone())
                .unwrap_or_else(|| ZERO_HASH.into()),
        }
    }
    pub fn validate_anchor(&self, anchor: &KnowledgeAnchor) -> Result<(), String> {
        if anchor.identity != self.identity
            || anchor.records == 0
            || anchor.records > self.receipts.len()
            || self.receipts[anchor.records - 1].sha256 != anchor.head_sha256
        {
            return Err("knowledge prefix anchor is missing, foreign or changed".into());
        }
        Ok(())
    }
    /// Finds one exact committed promotion between two verified history heads.
    /// The original stored evaluation must match, and the record must still be
    /// active at the completion head. Later revocation preserves the old proof.
    pub fn promotion_between(
        &self,
        record: &KnowledgeRecord,
        evidence: &Value,
        before: &KnowledgeAnchor,
        after: &KnowledgeAnchor,
    ) -> Result<String, String> {
        self.validate_anchor(before)?;
        self.validate_anchor(after)?;
        if before.records >= after.records {
            return Err("experiment has no new knowledge history".into());
        }
        let expected = record.digest()?;
        let mut active = None;
        let mut matched = None;
        for receipt in self.receipts.iter().take(after.records) {
            match &receipt.payload {
                Event::Promote {
                    record: stored,
                    assessment,
                    ..
                } if stored.id == record.id => {
                    active = Some(stored.digest()?);
                    if receipt.sequence >= before.records
                        && active.as_deref() == Some(expected.as_str())
                        && serde_json::to_value(&assessment.evidence).map_err(|e| e.to_string())?
                            == *evidence
                    {
                        matched = Some(receipt.sha256.clone());
                    }
                }
                Event::PromoteGraph {
                    record: stored,
                    assessment,
                    ..
                } if stored.id == record.id => {
                    active = Some(stored.digest()?);
                    if receipt.sequence >= before.records
                        && active.as_deref() == Some(expected.as_str())
                        && serde_json::to_value(&assessment.evidence).map_err(|e| e.to_string())?
                            == *evidence
                    {
                        matched = Some(receipt.sha256.clone());
                    }
                }
                Event::Revoke { id, .. } if id == &record.id => active = None,
                _ => {}
            }
        }
        if active.as_deref() != Some(expected.as_str()) {
            return Err("completed experiment record was revoked or superseded".into());
        }
        matched.ok_or_else(|| {
            "no fresh promotion with this exact stored evaluation between selected heads".into()
        })
    }
    pub fn ledger_path(&self) -> PathBuf {
        self.directory.join("knowledge.jsonl")
    }
    /// Exact original assessment evidence for one validated historical promotion.
    /// This accessor preserves the distinction between history and current use;
    /// callers claiming a current capability must also require active membership.
    pub fn promotion_evidence_between(
        &self,
        record: &KnowledgeRecord,
        before: &KnowledgeAnchor,
        after: &KnowledgeAnchor,
    ) -> Result<(String, Value), String> {
        self.validate_anchor(before)?;
        self.validate_anchor(after)?;
        let expected = record.digest()?;
        for receipt in self
            .receipts
            .iter()
            .take(after.records)
            .skip(before.records)
        {
            let (stored, evidence) = match &receipt.payload {
                Event::Promote {
                    record, assessment, ..
                } => (
                    record,
                    serde_json::to_value(&assessment.evidence)
                        .map_err(|error| error.to_string())?,
                ),
                Event::PromoteGraph {
                    record, assessment, ..
                } => (
                    record,
                    serde_json::to_value(&assessment.evidence)
                        .map_err(|error| error.to_string())?,
                ),
                _ => continue,
            };
            if stored.digest()? == expected {
                let promotion = self.promotion_between(record, &evidence, before, after)?;
                return Ok((promotion, evidence));
            }
        }
        Err("exact historical promotion evidence is unavailable".into())
    }
    pub fn promote(
        &mut self,
        record: KnowledgeRecord,
        assessment: Assessment,
    ) -> Result<(), String> {
        self.promote_checked(record, assessment)
            .map_err(|error| error.to_string())
    }

    pub fn promote_checked(
        &mut self,
        record: KnowledgeRecord,
        assessment: Assessment,
    ) -> Result<(), MemoryWriteError> {
        self.append_checked(Event::Promote {
            record,
            assessment: Box::new(assessment),
            policy_version: Some(2),
        })
    }

    pub fn promote_graph(
        &mut self,
        record: KnowledgeRecord,
        assessment: graph::GraphAssessment,
    ) -> Result<(), String> {
        self.promote_graph_checked(record, assessment)
            .map_err(|error| error.to_string())
    }

    pub fn promote_graph_checked(
        &mut self,
        record: KnowledgeRecord,
        assessment: graph::GraphAssessment,
    ) -> Result<(), MemoryWriteError> {
        self.append_checked(Event::PromoteGraph {
            record,
            assessment: Box::new(assessment),
            policy_version: 2,
        })
    }

    /// Returns the latest active graph's complete inert proof envelopes. Old
    /// authority epochs must still be rejected by a fresh native authority.
    pub fn graph_evidence(&self, id: &str) -> Option<graph::GraphTrialEvidence> {
        if !self.active.contains_key(id) {
            return None;
        }
        self.receipts
            .iter()
            .rev()
            .find_map(|receipt| match &receipt.payload {
                Event::PromoteGraph {
                    record, assessment, ..
                } if record.id == id => Some(assessment.evidence.clone()),
                _ => None,
            })
    }

    pub fn revoke(&mut self, id: &str, reason: &str) -> Result<(), String> {
        self.revoke_checked(id, reason)
            .map_err(|error| error.to_string())
    }

    pub fn revoke_checked(&mut self, id: &str, reason: &str) -> Result<(), MemoryWriteError> {
        self.append_checked(Event::Revoke {
            id: id.into(),
            reason: reason.into(),
        })
    }

    fn validate_event(&self, event: &Event) -> Result<(), String> {
        match event {
            Event::Genesis { version, identity } => {
                if self.genesis
                    || !self.receipts.is_empty()
                    || *version != 1
                    || identity != &self.identity
                {
                    return Err("unsupported genesis or persistent identity mismatch".into());
                }
            }
            Event::Promote {
                record,
                assessment,
                policy_version,
            } => {
                if !self.genesis {
                    return Err("knowledge promotion before genesis".into());
                }
                record.validate()?;
                assessment.validate(record)?;
                if policy_version.is_some_and(|version| version != 2) {
                    return Err("unsupported knowledge promotion policy".into());
                }
                if policy_version == &Some(2) {
                    if let Some(retained) = self.retained_expected.get(&record.id) {
                        for case in &assessment.evidence.cases {
                            if retained
                                .get(&case.input)
                                .is_some_and(|expected| *expected != case.expected)
                            {
                                return Err("stationary context changed expected labels; revoke or change context before promotion".into());
                            }
                        }
                        for (input, expected) in retained {
                            if record.predict(*input)? != *expected {
                                return Err("new knowledge regresses on retained validated cases; revoke or change context before promotion".into());
                            }
                        }
                    }
                }
                if self
                    .revisions
                    .get(&record.id)
                    .is_some_and(|r| record.revision <= *r)
                {
                    return Err("duplicate or stale knowledge revision".into());
                }
                let binding = (
                    record.source.clone(),
                    record.scope.clone(),
                    record.schema_fingerprint.clone(),
                );
                if self
                    .bindings
                    .get(&record.id)
                    .is_some_and(|bound| bound != &binding)
                {
                    return Err("knowledge identity cannot change source, scope or schema".into());
                }
                if self
                    .bindings
                    .iter()
                    .any(|(id, value)| id != &record.id && value == &binding)
                {
                    return Err(
                        "knowledge alias cannot bypass existing source/scope/schema history".into(),
                    );
                }
                if let Some(existing) = self.active.get(&record.id) {
                    for case in &assessment.evidence.cases {
                        if case.baseline != Some(existing.predict(case.input)?) {
                            return Err("trial baseline does not reflect active knowledge".into());
                        }
                    }
                }
            }
            Event::PromoteGraph {
                record,
                assessment,
                policy_version,
            } => {
                if !self.genesis || *policy_version != 2 {
                    return Err("graph promotion requires genesis and supported policy 2".into());
                }
                record.validate()?;
                assessment.validate(record)?;
                if self
                    .revisions
                    .get(&record.id)
                    .is_some_and(|revision| record.revision <= *revision)
                {
                    return Err("duplicate or stale knowledge revision".into());
                }
                let binding = (
                    record.source.clone(),
                    record.scope.clone(),
                    record.schema_fingerprint.clone(),
                );
                if self
                    .bindings
                    .get(&record.id)
                    .is_some_and(|previous| previous != &binding)
                    || self
                        .bindings
                        .iter()
                        .any(|(id, value)| id != &record.id && value == &binding)
                {
                    return Err(
                        "graph identity or alias cannot bypass source, scope and schema history"
                            .into(),
                    );
                }
                let map = graph::GraphMap::from_record(record)?;
                let observations: BTreeMap<_, _> = map
                    .observations
                    .iter()
                    .map(|o| (o.edge_id, o.cost))
                    .collect();
                if let Some(retained) = self.retained_graph_edges.get(&record.id) {
                    if retained
                        .iter()
                        .any(|(edge, cost)| observations.get(edge) != Some(cost))
                    {
                        return Err("stationary graph edges changed or disappeared; revoke or change context before promotion".into());
                    }
                }
                if let Some(retained) = self.retained_expected.get(&record.id) {
                    for case in &assessment.evidence.cases {
                        if retained
                            .get(&case.input)
                            .is_some_and(|expected| *expected != case.expected)
                        {
                            return Err("stationary graph route labels changed; revoke or change context before promotion".into());
                        }
                    }
                    for (input, expected) in retained {
                        if record.predict_if_certified(*input)? != Some(*expected) {
                            return Err(
                                "new graph knowledge regresses or abstains on retained route cases"
                                    .into(),
                            );
                        }
                    }
                }
                if let Some(existing) = self.active.get(&record.id) {
                    for case in &assessment.evidence.cases {
                        if case.baseline != existing.predict_if_certified(case.input)? {
                            return Err(
                                "graph trial baseline does not reflect active knowledge".into()
                            );
                        }
                    }
                }
            }
            Event::Revoke { id, reason } => {
                if !self.genesis
                    || !self.active.contains_key(id)
                    || reason.trim().is_empty()
                    || reason.len() > 4096
                {
                    return Err(
                        "knowledge revocation requires active record and bounded reason".into(),
                    );
                }
            }
        }
        Ok(())
    }

    fn apply(&mut self, event: &Event) {
        match event {
            Event::Genesis { .. } => self.genesis = true,
            Event::Promote {
                record,
                assessment,
                policy_version,
            } => {
                self.revisions.insert(record.id.clone(), record.revision);
                self.bindings.insert(
                    record.id.clone(),
                    (
                        record.source.clone(),
                        record.scope.clone(),
                        record.schema_fingerprint.clone(),
                    ),
                );
                self.active.insert(record.id.clone(), record.clone());
                let retained = self.retained_expected.entry(record.id.clone()).or_default();
                // Legacy policy could supersede a changing law. Preserve old
                // read compatibility without rewriting its accepted history.
                if policy_version.is_none() {
                    retained.clear();
                }
                for case in &assessment.evidence.cases {
                    retained.insert(case.input, case.expected);
                }
            }
            Event::PromoteGraph {
                record, assessment, ..
            } => {
                self.revisions.insert(record.id.clone(), record.revision);
                self.bindings.insert(
                    record.id.clone(),
                    (
                        record.source.clone(),
                        record.scope.clone(),
                        record.schema_fingerprint.clone(),
                    ),
                );
                self.active.insert(record.id.clone(), record.clone());
                let retained = self.retained_expected.entry(record.id.clone()).or_default();
                for case in &assessment.evidence.cases {
                    retained.insert(case.input, case.expected);
                }
                // Validation guarantees every map observation exactly matches
                // these typed acquisitions and preserves all earlier edges.
                let edges = self
                    .retained_graph_edges
                    .entry(record.id.clone())
                    .or_default();
                for acquisition in &assessment.evidence.acquisitions {
                    edges.insert(acquisition.edge_id, acquisition.cost);
                }
            }
            Event::Revoke { id, .. } => {
                self.active.remove(id);
                self.retained_expected.remove(id);
                self.retained_graph_edges.remove(id);
            }
        }
    }

    fn pin_bytes(&mut self, bytes: &[u8]) -> String {
        self.io.saturated |= io_add(&mut self.io.integrity_hashed_bytes, bytes.len() as u64);
        format!("{:x}", Sha256::digest(bytes))
    }

    /// The cooperative writer lock does not authorize replacing unknown bytes.
    /// Check both before creating a temporary and again before replacement. This
    /// detects external change; it is not an adversarial OS compare-and-swap.
    fn check_disk_pin(&mut self) -> Result<(), MemoryWriteError> {
        self.io.saturated |= io_add(&mut self.io.integrity_checks, 1);
        let checked = (|| {
            let path = self.ledger_path();
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return if self.disk_sha256.is_none() {
                        Ok(())
                    } else {
                        Err(MemoryWriteError::Integrity(
                            "live knowledge ledger is missing; refusing replacement".into(),
                        ))
                    };
                }
                Err(error) => {
                    return Err(MemoryWriteError::Storage(format!(
                        "knowledge integrity metadata: {error}"
                    )))
                }
            };
            if self.disk_sha256.is_none() {
                return Err(MemoryWriteError::Integrity(
                    "knowledge genesis requires an absent ledger".into(),
                ));
            }
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(MemoryWriteError::Integrity(
                    "live knowledge ledger is not a regular pinned file".into(),
                ));
            }
            let file = File::open(&path).map_err(|error| {
                MemoryWriteError::Storage(format!("knowledge integrity read: {error}"))
            })?;
            let mut bytes = Vec::new();
            let read = file
                .take(super::MAX_LEDGER_BYTES as u64 + 1)
                .read_to_end(&mut bytes);
            self.io.saturated |= io_add(&mut self.io.integrity_read_bytes, bytes.len() as u64);
            read.map_err(|error| {
                MemoryWriteError::Storage(format!("knowledge integrity read: {error}"))
            })?;
            let actual = self.pin_bytes(&bytes);
            if bytes.len() != self.ledger_bytes
                || self.disk_sha256.as_deref() != Some(actual.as_str())
            {
                return Err(MemoryWriteError::Integrity(
                    "live knowledge ledger bytes changed; refusing replacement".into(),
                ));
            }
            Ok(())
        })();
        checked.inspect_err(|_| {
            self.io.saturated |= io_add(&mut self.io.integrity_failures, 1);
        })
    }

    fn append(&mut self, event: Event) -> Result<(), String> {
        self.append_checked(event)
            .map_err(|error| error.to_string())
    }

    fn append_checked(&mut self, event: Event) -> Result<(), MemoryWriteError> {
        self.validate_event(&event)
            .map_err(MemoryWriteError::Invalid)?;
        if self.receipts.len() >= super::MAX_RECORDS {
            return Err(MemoryWriteError::Capacity(
                "knowledge record budget exhausted".into(),
            ));
        }
        let mut receipt = Receipt {
            sequence: self.receipts.len(),
            previous: self
                .receipts
                .last()
                .map(|r| r.sha256.as_str())
                .unwrap_or(ZERO_HASH)
                .into(),
            payload: event,
            sha256: String::new(),
        };
        receipt.sha256 = receipt.hash().map_err(MemoryWriteError::Invalid)?;
        let new_line =
            serde_json::to_vec(&receipt).map_err(|e| MemoryWriteError::Invalid(e.to_string()))?;
        if new_line.len() > MAX_RECORD_BYTES {
            return Err(MemoryWriteError::Capacity(
                "knowledge record byte budget exhausted".into(),
            ));
        }
        let mut bytes = Vec::new();
        for old in &self.receipts {
            serde_json::to_writer(&mut bytes, old)
                .map_err(|e| MemoryWriteError::Invalid(e.to_string()))?;
            bytes.push(b'\n');
        }
        bytes.extend_from_slice(&new_line);
        bytes.push(b'\n');
        self.io.saturated |= io_add(
            &mut self.io.full_history_serialized_bytes,
            bytes.len() as u64,
        );
        if bytes.len() > super::MAX_LEDGER_BYTES {
            return Err(MemoryWriteError::Capacity(
                "knowledge ledger byte budget exhausted".into(),
            ));
        }
        self.check_disk_pin()?;
        let number = super::TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = self
            .directory
            .join(format!("knowledge.{}.{number}.tmp", std::process::id()));
        self.io.saturated |= io_add(&mut self.io.publication_attempts, 1);
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|e| MemoryWriteError::Storage(e.to_string()))?;
            write_application_bytes(&mut file, &bytes, &mut self.io)
                .map_err(MemoryWriteError::Storage)?;
            file.sync_all()
                .map_err(|e| MemoryWriteError::Storage(e.to_string()))?;
            drop(file);
            self.check_disk_pin()?;
            fs::rename(&temporary, self.ledger_path()).map_err(|e| {
                MemoryWriteError::Storage(format!("atomic knowledge replacement: {e}"))
            })?;
            Ok(())
        })();
        if let Err(error) = result {
            self.io.saturated |= io_add(&mut self.io.publication_failures, 1);
            let _ = fs::remove_file(temporary);
            return Err(error);
        }
        self.io.saturated |= io_add(&mut self.io.committed_publication_bytes, bytes.len() as u64);
        self.ledger_bytes = bytes.len();
        self.canonical_ledger_bytes = bytes.len();
        self.disk_sha256 = Some(self.pin_bytes(&bytes));
        self.apply(&receipt.payload);
        self.receipts.push(receipt);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let n = super::super::TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let p =
                std::env::temp_dir().join(format!("symbiote-knowledge-{}-{n}", std::process::id()));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn record() -> KnowledgeRecord {
        KnowledgeRecord {
            id: "xor-context-a".into(),
            revision: 1,
            source: "partner-a".into(),
            scope: "affine-boolean-v1/context-a".into(),
            schema_fingerprint: affine_schema_fingerprint(3).unwrap(),
            payload: json!({"kind":"affine","width":3,"coefficients":3,"bias":false}),
            provenance: "observed training trace; independent held-out lab checks".into(),
        }
    }
    fn evidence() -> TrialEvidence {
        TrialEvidence {
            evaluator: "independent-lab".into(),
            training_case_ids: vec!["training-0".into(), "training-1".into()],
            training_inputs: vec![0, 1],
            cases: (2..8)
                .map(|input| TrialCase {
                    id: format!("heldout-{input}"),
                    input,
                    expected: ((input & 3).count_ones() % 2) as u8,
                    baseline: None,
                    candidate: ((input & 3).count_ones() % 2) as u8,
                })
                .collect(),
            costs: TrialCosts {
                acquisition: 2,
                verification: 6,
                adoption: 1,
                baseline: 20,
                candidate: 10,
            },
        }
    }
    #[test]
    fn io_diagnostics_leave_failed_partial_write_bytes_unknown_and_saturate() {
        struct PartialWriter {
            wrote: bool,
        }
        impl Write for PartialWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.wrote {
                    Err(std::io::Error::other("controlled partial write failure"))
                } else {
                    self.wrote = true;
                    Ok(bytes.len().min(1))
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut io = KnowledgeIoDiagnostics::default();
        assert!(write_application_bytes(
            &mut PartialWriter { wrote: false },
            b"some bytes",
            &mut io
        )
        .is_err());
        assert_eq!(io.write_submitted_bytes, 10);
        assert_eq!(io.write_all_completed_bytes, 0);
        assert_eq!(io.failed_write_all_calls, 1);
        assert_eq!(io.failed_partial_write_bytes, None);
        io.write_submitted_bytes = u64::MAX;
        assert!(write_application_bytes(&mut Vec::new(), b"x", &mut io).is_ok());
        assert!(io.saturated);
        assert_eq!(io.write_submitted_bytes, u64::MAX);
        assert_eq!(
            io.failed_partial_write_bytes, None,
            "later successes do not erase unknown earlier partial bytes"
        );
    }
    #[test]
    fn io_diagnostics_count_full_rewrites_and_isolate_cold_owners() {
        let first = Directory::new();
        let other = Directory::new();
        let mut store = KnowledgeStore::open(&first.0, "owner-a").unwrap();
        let genesis = fs::read(store.ledger_path()).unwrap();
        let r = record();
        store
            .promote(r.clone(), assess(&r, &evidence()).unwrap())
            .unwrap();
        let promoted = fs::read(store.ledger_path()).unwrap();
        store.revoke(&r.id, "controlled revocation").unwrap();
        let revoked = fs::read(store.ledger_path()).unwrap();
        let work = store.io_diagnostics();
        let expected = (genesis.len() + promoted.len() + revoked.len()) as u64;
        assert_eq!(work.cold_read_bytes, 0);
        assert_eq!(work.full_history_serialized_bytes, expected);
        assert_eq!(work.write_submitted_bytes, expected);
        assert_eq!(work.write_all_completed_bytes, expected);
        assert_eq!(work.committed_publication_bytes, expected);
        let guarded = 2 * (genesis.len() + promoted.len()) as u64;
        assert_eq!(work.integrity_read_bytes, guarded);
        assert_eq!(work.integrity_hashed_bytes, expected + guarded);
        assert_eq!(work.integrity_checks, 6);
        assert_eq!(work.integrity_failures, 0);
        assert!(expected > revoked.len() as u64);
        assert_eq!(work.publication_attempts, 3);
        assert_eq!(work.publication_failures, 0);
        assert_eq!(work.failed_partial_write_bytes, Some(0));
        assert!(!work.saturated);
        let capacity = store.capacity();
        assert_eq!(capacity.used_records, 3);
        assert_eq!(capacity.used_ledger_bytes, revoked.len());
        assert_eq!(capacity.max_records, super::super::MAX_RECORDS);
        assert_eq!(capacity.max_ledger_bytes, super::super::MAX_LEDGER_BYTES);
        assert_eq!(capacity.max_record_bytes, MAX_RECORD_BYTES);
        let separate = KnowledgeStore::open(&other.0, "owner-b").unwrap();
        assert_eq!(separate.io_diagnostics().publication_attempts, 1);
        assert_eq!(store.io_diagnostics(), work);
        drop(separate);
        drop(store);
        let cold = KnowledgeStore::open(&first.0, "owner-a").unwrap();
        let read = cold.io_diagnostics();
        assert_eq!(read.cold_read_bytes, revoked.len() as u64);
        assert_eq!(read.integrity_hashed_bytes, revoked.len() as u64);
        assert_eq!(read.integrity_read_bytes, 0);
        assert_eq!(read.integrity_checks, 0);
        assert_eq!(read.publication_attempts, 0);
        assert_eq!(read.full_history_serialized_bytes, 0);
        assert_eq!(read.capacity_quote_serialized_bytes, revoked.len() as u64);
        assert_eq!(read.committed_publication_bytes, 0);
        assert_eq!(cold.capacity(), capacity);
        assert_eq!(fs::read(cold.ledger_path()).unwrap(), revoked);
    }
    #[test]
    fn integrity_guard_rejects_a_replaced_path_before_publication() {
        let dir = Directory::new();
        let mut store = KnowledgeStore::open(&dir.0, "owner").unwrap();
        let at = store.history_anchor();
        let capacity = store.capacity();
        let before = store.io_diagnostics();
        let path = store.ledger_path();
        let saved = dir.0.join("knowledge.saved");
        fs::rename(&path, &saved).unwrap();
        fs::create_dir(&path).unwrap();
        let r = record();
        let error = store
            .promote(r.clone(), assess(&r, &evidence()).unwrap())
            .unwrap_err();
        assert!(error.contains("not a regular pinned file"));
        let failed = store.io_diagnostics();
        assert_eq!(store.history_anchor(), at);
        assert_eq!(store.capacity(), capacity);
        assert_eq!(failed.publication_attempts, before.publication_attempts);
        assert_eq!(failed.publication_failures, 0);
        assert_eq!(failed.write_submitted_bytes, before.write_submitted_bytes);
        assert_eq!(
            failed.write_all_completed_bytes,
            failed.write_submitted_bytes
        );
        assert_eq!(
            failed.committed_publication_bytes,
            before.committed_publication_bytes
        );
        assert_eq!(failed.failed_write_all_calls, 0);
        assert_eq!(failed.integrity_failures, 1);
        assert_eq!(
            failed.failed_partial_write_bytes,
            Some(0),
            "the integrity guard rejected the replaced path without submitting bytes"
        );
        fs::remove_dir(&path).unwrap();
        fs::rename(saved, path).unwrap();
    }
    #[test]
    fn live_mutation_never_overwrites_unknown_bytes_on_promote_or_revoke() {
        let foreign = Directory::new();
        let foreign_store = KnowledgeStore::open(&foreign.0, "foreign-owner").unwrap();
        let foreign_bytes = fs::read(foreign_store.ledger_path()).unwrap();
        for mutation in ["foreign", "corrupt", "truncated", "missing"] {
            for revoke in [false, true] {
                let dir = Directory::new();
                let mut store = KnowledgeStore::open(&dir.0, "owner").unwrap();
                let r = record();
                store
                    .promote_checked(r.clone(), assess(&r, &evidence()).unwrap())
                    .unwrap();
                let at = store.history_anchor();
                let active = store.active();
                let capacity = store.capacity();
                let before = store.io_diagnostics();
                let path = store.ledger_path();
                let original = fs::read(&path).unwrap();
                let replacement = match mutation {
                    "foreign" => Some(foreign_bytes.clone()),
                    "corrupt" => {
                        let mut bytes = original.clone();
                        bytes[12] ^= 1;
                        Some(bytes)
                    }
                    "truncated" => Some(original[..original.len() - 1].to_vec()),
                    "missing" => None,
                    _ => unreachable!(),
                };
                match &replacement {
                    Some(bytes) => fs::write(&path, bytes).unwrap(),
                    None => fs::remove_file(&path).unwrap(),
                }
                let result = if revoke {
                    store.revoke_checked(&r.id, "controlled withdrawal")
                } else {
                    let mut next = r.clone();
                    next.id = "independent-next".into();
                    next.scope = "independent-next".into();
                    store.promote_checked(next.clone(), assess(&next, &evidence()).unwrap())
                };
                assert!(
                    matches!(result, Err(MemoryWriteError::Integrity(_))),
                    "{mutation}, revoke={revoke}: {result:?}"
                );
                assert_eq!(store.history_anchor(), at);
                assert_eq!(store.active(), active);
                assert_eq!(store.capacity(), capacity);
                assert_eq!(fs::read(&path).ok(), replacement);
                let after = store.io_diagnostics();
                assert_eq!(after.publication_attempts, before.publication_attempts);
                assert_eq!(after.write_submitted_bytes, before.write_submitted_bytes);
                assert_eq!(
                    after.committed_publication_bytes,
                    before.committed_publication_bytes
                );
                assert_eq!(after.integrity_failures, before.integrity_failures + 1);
            }
        }
    }
    #[test]
    fn capacity_keeps_compact_publication_room_in_a_physically_full_history() {
        let dir = Directory::new();
        let mut store = KnowledgeStore::open(&dir.0, "owner").unwrap();
        for index in 0..31 {
            let mut r = record();
            r.id = format!("capacity-{index}");
            r.scope = format!("capacity-scope-{index}");
            store
                .promote(r.clone(), assess(&r, &evidence()).unwrap())
                .unwrap();
        }
        let path = store.ledger_path();
        let original = fs::read(&path).unwrap();
        assert_eq!(store.record_count(), 32);
        drop(store);
        // Existing native JSONL accepts trailing JSON whitespace. Make the
        // physical file full without changing any receipt or its chain hash.
        let mut padded = Vec::new();
        let stride = super::super::MAX_LEDGER_BYTES / 32;
        for line in original
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let end = padded.len() + stride - 1;
            assert!(line.len() < stride);
            padded.extend_from_slice(line);
            padded.resize(end, b' ');
            padded.push(b'\n');
        }
        assert_eq!(padded.len(), super::super::MAX_LEDGER_BYTES);
        fs::write(&path, padded).unwrap();
        let mut reopened = KnowledgeStore::open(&dir.0, "owner").unwrap();
        let capacity = reopened.capacity();
        assert_eq!(capacity.remaining_ledger_bytes, 0);
        assert_eq!(capacity.canonical_ledger_bytes, original.len());
        assert!(capacity.remaining_publication_bytes > 0);
        assert_eq!(
            reopened.io_diagnostics().cold_read_bytes,
            super::super::MAX_LEDGER_BYTES as u64
        );
        assert_eq!(
            reopened.io_diagnostics().capacity_quote_serialized_bytes,
            original.len() as u64
        );
        let mut r = record();
        r.id = "after-physical-full".into();
        r.scope = "after-physical-full".into();
        reopened
            .promote(r.clone(), assess(&r, &evidence()).unwrap())
            .unwrap();
        assert_eq!(reopened.record_count(), 33);
        let after = reopened.capacity();
        assert!(after.used_ledger_bytes < after.max_ledger_bytes);
        assert_eq!(after.used_ledger_bytes, after.canonical_ledger_bytes);
        assert_eq!(
            fs::metadata(path).unwrap().len(),
            after.used_ledger_bytes as u64
        );
    }
    #[test]
    fn checked_writes_classify_actual_serialized_capacity_without_prose_parsing() {
        let dir = Directory::new();
        let store = KnowledgeStore::open(&dir.0, "owner").unwrap();
        let path = store.ledger_path();
        let genesis = fs::read(&path).unwrap();
        let first: Receipt = serde_json::from_slice(&genesis[..genesis.len() - 1]).unwrap();
        drop(store);
        let mut bytes = genesis;
        let mut previous = first.sha256;
        let mut index = 1;
        let next = loop {
            let mut r = record();
            r.id = format!("large-{index}");
            r.scope = format!("large-scope-{index}");
            r.provenance = "p".repeat(4096);
            r.schema_fingerprint = affine_schema_fingerprint(8).unwrap();
            r.payload["width"] = serde_json::json!(8);
            let mut trial = evidence();
            trial.training_case_ids.clear();
            trial.training_inputs.clear();
            trial.cases = (0..256)
                .map(|input| {
                    let expected = r.predict(input).unwrap();
                    TrialCase {
                        id: format!("{}-{input}", "c".repeat(110)),
                        input,
                        expected,
                        candidate: expected,
                        baseline: None,
                    }
                })
                .collect();
            let assessment = assess(&r, &trial).unwrap();
            let mut receipt = Receipt {
                sequence: index,
                previous: previous.clone(),
                payload: Event::Promote {
                    record: r.clone(),
                    assessment: Box::new(assessment.clone()),
                    policy_version: Some(2),
                },
                sha256: String::new(),
            };
            receipt.sha256 = receipt.hash().unwrap();
            let row = serde_json::to_vec(&receipt).unwrap();
            assert!(row.len() <= MAX_RECORD_BYTES);
            if bytes.len() + row.len() + 1 > super::super::MAX_LEDGER_BYTES {
                break (r, assessment);
            }
            bytes.extend_from_slice(&row);
            bytes.push(b'\n');
            previous = receipt.sha256;
            index += 1;
        };
        // These are valid test-only native receipts; replay independently checks
        // them before the real append guard quotes the next complete publication.
        fs::write(&path, &bytes).unwrap();
        let mut store = KnowledgeStore::open(&dir.0, "owner").unwrap();
        let at = store.history_anchor();
        let remaining = store.capacity().remaining_publication_bytes;
        assert!(remaining > 0);
        let result = store.promote_checked(next.0, next.1);
        assert!(matches!(result, Err(MemoryWriteError::Capacity(_))));
        assert_eq!(store.history_anchor(), at);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(store.io_diagnostics().publication_attempts, 0);
        assert!(
            store.io_diagnostics().full_history_serialized_bytes
                > super::super::MAX_LEDGER_BYTES as u64
        );
        assert!(matches!(
            store.revoke_checked("absent", "no such record"),
            Err(MemoryWriteError::Invalid(_))
        ));
    }
    #[test]
    fn heldout_learning_retains_owner_state_and_evidence() {
        let dir = Directory::new();
        let r = record();
        let a = assess(&r, &evidence()).unwrap();
        assert_eq!(a.independent_cases, 6);
        assert!(a.coverage_improved);
        let mut store = KnowledgeStore::open(&dir.0, "symbiote-owner").unwrap();
        store.promote(r.clone(), a).unwrap();
        drop(store);
        let again = KnowledgeStore::open(&dir.0, "symbiote-owner").unwrap();
        assert_eq!(again.active(), vec![r]);
        assert_eq!(again.record_count(), 2);
        assert_eq!(again.identity(), "symbiote-owner");
        drop(again);
        assert!(KnowledgeStore::open(&dir.0, "another-owner").is_err());
    }
    #[test]
    fn exact_promotion_history_survives_revocation_and_newer_revision_without_writes() {
        let dir = Directory::new();
        let original = record();
        let mut store = KnowledgeStore::open(&dir.0, "owner").unwrap();
        assert!(!store.has_historical_promotion(&original).unwrap());
        let empty_anchor = store.history_anchor();
        store
            .promote(original.clone(), assess(&original, &evidence()).unwrap())
            .unwrap();
        let committed = fs::read(store.ledger_path()).unwrap();
        let original_anchor = store.history_anchor();
        assert!(store.has_historical_promotion(&original).unwrap());
        assert_eq!(
            fs::read(store.ledger_path()).unwrap(),
            committed,
            "history lookup must be read-only"
        );
        store
            .revoke(&original.id, "operator withdrew active use")
            .unwrap();
        assert!(store.active().is_empty());
        let revoked_anchor = store.history_anchor();
        assert!(store.has_historical_promotion(&original).unwrap());
        let mut next = original.clone();
        next.revision = 2;
        next.provenance = "explicitly revalidated next revision".into();
        store
            .promote(next.clone(), assess(&next, &evidence()).unwrap())
            .unwrap();
        assert_eq!(store.active(), vec![next.clone()]);
        assert!(store.has_historical_promotion(&original).unwrap());
        assert!(store.has_historical_promotion(&next).unwrap());
        let mut uncommitted = original.clone();
        uncommitted.provenance = "different valid content was never committed".into();
        assert!(!store.has_historical_promotion(&uncommitted).unwrap());
        drop(store);
        let replayed = KnowledgeStore::open(&dir.0, "owner").unwrap();
        assert!(replayed.has_historical_promotion(&original).unwrap());
        assert!(replayed.has_historical_promotion(&next).unwrap());
        assert!(replayed.active_at(&empty_anchor).unwrap().is_empty());
        assert_eq!(
            replayed.active_at(&original_anchor).unwrap(),
            vec![original]
        );
        assert!(replayed.active_at(&revoked_anchor).unwrap().is_empty());
        assert_eq!(
            replayed.active_at(&replayed.history_anchor()).unwrap(),
            vec![next]
        );
        let mut forged = original_anchor;
        forged.head_sha256 = "0".repeat(64);
        assert!(replayed.active_at(&forged).is_err());
    }
    #[test]
    fn training_leakage_duplicates_wrong_outputs_and_inert_instructions_are_rejected() {
        let r = record();
        let mut e = evidence();
        e.cases.push(e.cases[0].clone());
        assert!(assess(&r, &e).is_err());
        let mut e = evidence();
        e.cases[0].input = 0;
        assert!(assess(&r, &e).is_err());
        let mut e = evidence();
        e.cases[0].id = "training-0".into();
        assert!(assess(&r, &e).is_err());
        let mut e = evidence();
        e.cases[0].expected ^= 1;
        assert!(assess(&r, &e).is_err());
        let mut e = evidence();
        e.cases[0].candidate ^= 1;
        assert!(assess(&r, &e).is_err());
        let mut e = evidence();
        e.evaluator = r.source.clone();
        assert!(assess(&r, &e).is_err());
        let mut r = record();
        r.payload["execute"] = json!("delete files");
        assert!(assess(&r, &evidence()).is_err());
    }
    #[test]
    fn cost_benefit_counts_all_components_and_requires_strict_gain() {
        let r = record();
        let mut e = evidence();
        for c in &mut e.cases {
            c.baseline = Some(c.expected);
        }
        let assessment = assess(&r, &e).unwrap();
        assert!(!assessment.coverage_improved);
        assert!(assessment.cost_improved);
        e.costs.candidate = e.costs.baseline;
        assert!(assess(&r, &e).is_err());
        e.costs.candidate = 1;
        assert!(assess(&r, &e).is_err());
        e.costs.acquisition = u64::MAX;
        assert!(assess(&r, &e).is_err());
    }
    #[test]
    fn stale_modified_and_aliased_knowledge_cannot_promote() {
        let dir = Directory::new();
        let mut store = KnowledgeStore::open(&dir.0, "owner").unwrap();
        let r = record();
        let mut a = assess(&r, &evidence()).unwrap();
        a.candidate_cost = 0;
        assert!(store.promote(r.clone(), a).is_err());
        let a = assess(&r, &evidence()).unwrap();
        let mut changed = r.clone();
        changed.provenance = "changed".into();
        assert!(store.promote(changed, a).is_err());
        store
            .promote(r.clone(), assess(&r, &evidence()).unwrap())
            .unwrap();
        let mut changed = r.clone();
        changed.revision = 2;
        assert!(store
            .promote(changed.clone(), assess(&changed, &evidence()).unwrap())
            .is_err());
        changed.id = "alias".into();
        assert!(store
            .promote(changed.clone(), assess(&changed, &evidence()).unwrap())
            .is_err());
        store.revoke(&r.id, "measured counterexample").unwrap();
        assert_eq!(store.highest_revision(&r.id), Some(1));
        assert!(store
            .promote(r.clone(), assess(&r, &evidence()).unwrap())
            .is_err());
        let mut revision = r;
        revision.revision = 2;
        store
            .promote(revision.clone(), assess(&revision, &evidence()).unwrap())
            .unwrap();
        drop(store);
        let again = KnowledgeStore::open(&dir.0, "owner").unwrap();
        assert_eq!(again.active(), vec![revision]);
        assert_eq!(again.record_count(), 4);
    }
    #[test]
    fn locks_corruption_truncation_and_failed_write_fail_closed() {
        let dir = Directory::new();
        let mut store = KnowledgeStore::open(&dir.0, "owner").unwrap();
        assert!(KnowledgeStore::open(&dir.0, "owner").is_err());
        let original = fs::read(store.ledger_path()).unwrap();
        fs::remove_file(store.ledger_path()).unwrap();
        fs::create_dir(store.ledger_path()).unwrap();
        let r = record();
        assert!(store
            .promote(r.clone(), assess(&r, &evidence()).unwrap())
            .is_err());
        assert!(store.active().is_empty());
        fs::remove_dir(store.ledger_path()).unwrap();
        let path = store.ledger_path();
        drop(store);
        fs::write(&path, &original[..original.len() - 1]).unwrap();
        assert!(KnowledgeStore::open(&dir.0, "owner").is_err());
        let mut modified = original;
        modified[12] ^= 1;
        fs::write(&path, modified).unwrap();
        assert!(KnowledgeStore::open(&dir.0, "owner").is_err());
        fs::write(&path, vec![b'x'; super::super::MAX_LEDGER_BYTES + 1]).unwrap();
        assert!(KnowledgeStore::open(&dir.0, "owner").is_err());
    }

    #[test]
    fn changed_stationary_labels_require_explicit_revocation_before_new_version() {
        let dir = Directory::new();
        let mut store = KnowledgeStore::open(&dir.0, "owner").unwrap();
        let original = record();
        store
            .promote(original.clone(), assess(&original, &evidence()).unwrap())
            .unwrap();
        let mut changed = original.clone();
        changed.revision = 2;
        changed.payload["coefficients"] = json!(1);
        let mut trial = evidence();
        for case in &mut trial.cases {
            case.expected = changed.predict(case.input).unwrap();
            case.candidate = case.expected;
            case.baseline = Some(original.predict(case.input).unwrap());
        }
        let assessment = assess(&changed, &trial).unwrap();
        assert!(store
            .promote(changed.clone(), assessment.clone())
            .unwrap_err()
            .contains("stationary"));
        assert_eq!(store.active(), vec![original.clone()]);
        assert_eq!(store.record_count(), 2);
        store
            .revoke(
                &original.id,
                "independent counterexample invalidates stationary context",
            )
            .unwrap();
        store.promote(changed.clone(), assessment).unwrap();
        drop(store);
        assert_eq!(
            KnowledgeStore::open(&dir.0, "owner").unwrap().active(),
            vec![changed]
        );
    }

    #[test]
    fn a_new_evaluation_subset_cannot_hide_regressions_on_retained_cases() {
        let dir = Directory::new();
        let mut store = KnowledgeStore::open(&dir.0, "owner").unwrap();
        let original = record();
        let mut first = evidence();
        first.cases.retain(|case| case.input == 2);
        store
            .promote(original.clone(), assess(&original, &first).unwrap())
            .unwrap();
        let mut changed = original.clone();
        changed.revision = 2;
        changed.payload["coefficients"] = json!(1);
        let mut next = evidence();
        next.cases.retain(|case| case.input == 4);
        for case in &mut next.cases {
            case.expected = changed.predict(case.input).unwrap();
            case.candidate = case.expected;
            case.baseline = Some(original.predict(case.input).unwrap());
        }
        let assessment = assess(&changed, &next).unwrap();
        assert!(assessment.cost_improved);
        assert!(store
            .promote(changed, assessment)
            .unwrap_err()
            .contains("retained validated cases"));
        assert_eq!(store.active(), vec![original]);
    }
}
