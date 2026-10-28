//! Scoped, declarative knowledge with distinct held-out laboratory evidence.
//!
//! Expected outputs and cost measurements are supplied by a trusted experiment
//! evaluator. This module checks their internal consistency, not remote honesty.
//! A SHA chain detects accidental modification, not an attacker rewriting it all.
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
        if !label(identity) {
            return Err("invalid persistent knowledge owner identity".into());
        }
        fs::create_dir_all(directory).map_err(|e| format!("knowledge directory: {e}"))?;
        let (lock, _initialization_gate) =
            super::maintenance::writer_lock(directory, "knowledge.writer.lock")?;
        super::maintenance::validate_knowledge_owner(directory, identity)?;
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
        };
        let path = store.ledger_path();
        if path.exists() {
            let file = File::open(&path).map_err(|e| e.to_string())?;
            if file.metadata().map_err(|e| e.to_string())?.len() > super::MAX_LEDGER_BYTES as u64 {
                return Err("knowledge ledger exceeds byte budget".into());
            }
            let mut bytes = Vec::new();
            file.take(super::MAX_LEDGER_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
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
                store.apply(&receipt.payload);
                previous = receipt.sha256.clone();
                store.receipts.push(receipt);
            }
            if !store.genesis {
                return Err("knowledge genesis missing".into());
            }
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
        self.append(Event::Promote {
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
        self.append(Event::PromoteGraph {
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
        self.append(Event::Revoke {
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

    fn append(&mut self, event: Event) -> Result<(), String> {
        self.validate_event(&event)?;
        if self.receipts.len() >= super::MAX_RECORDS {
            return Err("knowledge record budget exhausted".into());
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
        receipt.sha256 = receipt.hash()?;
        let new_line = serde_json::to_vec(&receipt).map_err(|e| e.to_string())?;
        if new_line.len() > MAX_RECORD_BYTES {
            return Err("knowledge record byte budget exhausted".into());
        }
        let mut bytes = Vec::new();
        for old in &self.receipts {
            serde_json::to_writer(&mut bytes, old).map_err(|e| e.to_string())?;
            bytes.push(b'\n');
        }
        bytes.extend_from_slice(&new_line);
        bytes.push(b'\n');
        if bytes.len() > super::MAX_LEDGER_BYTES {
            return Err("knowledge ledger byte budget exhausted".into());
        }
        let number = super::TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = self
            .directory
            .join(format!("knowledge.{}.{number}.tmp", std::process::id()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|e| e.to_string())?;
            file.write_all(&bytes).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            drop(file);
            fs::rename(&temporary, self.ledger_path())
                .map_err(|e| format!("atomic knowledge replacement: {e}"))?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(temporary);
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
