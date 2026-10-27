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
    /// Inert typed JSON. Only the explicitly supported affine data is admitted.
    pub payload: Value,
    pub provenance: String,
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
        AffinePayload::from_record(self)?;
        Ok(())
    }

    pub fn digest(&self) -> Result<String, String> {
        super::digest(self)
    }

    pub fn predict(&self, input: u16) -> Result<u8, String> {
        self.validate()?;
        AffinePayload::from_record(self)?.predict(input)
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
    _lock: super::WriterLock,
    identity: String,
    genesis: bool,
    receipts: Vec<Receipt>,
    active: BTreeMap<String, KnowledgeRecord>,
    revisions: BTreeMap<String, u64>,
    bindings: BTreeMap<String, (String, String, String)>,
}

impl KnowledgeStore {
    pub fn open(directory: &Path, identity: &str) -> Result<Self, String> {
        if !label(identity) {
            return Err("invalid persistent knowledge owner identity".into());
        }
        fs::create_dir_all(directory).map_err(|e| format!("knowledge directory: {e}"))?;
        let lock_path = directory.join("knowledge.writer.lock");
        let mut lock_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|e| {
                format!("exclusive knowledge lock unavailable (live or stale writer): {e}")
            })?;
        let lock = super::WriterLock(lock_path);
        writeln!(lock_file, "process={}", std::process::id()).map_err(|e| e.to_string())?;
        lock_file.sync_all().map_err(|e| e.to_string())?;
        let mut store = Self {
            directory: directory.to_path_buf(),
            _lock: lock,
            identity: identity.into(),
            genesis: false,
            receipts: Vec::new(),
            active: BTreeMap::new(),
            revisions: BTreeMap::new(),
            bindings: BTreeMap::new(),
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
        Ok(store)
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }
    pub fn active(&self) -> Vec<KnowledgeRecord> {
        self.active.values().cloned().collect()
    }
    pub fn highest_revision(&self, id: &str) -> Option<u64> {
        self.revisions.get(id).copied()
    }
    pub fn record_count(&self) -> usize {
        self.receipts.len()
    }
    pub fn ledger_path(&self) -> PathBuf {
        self.directory.join("knowledge.jsonl")
    }
    pub fn promote(
        &mut self,
        record: KnowledgeRecord,
        assessment: Assessment,
    ) -> Result<(), String> {
        self.append(Event::Promote {
            record,
            assessment: Box::new(assessment),
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
            Event::Promote { record, assessment } => {
                if !self.genesis {
                    return Err("knowledge promotion before genesis".into());
                }
                record.validate()?;
                assessment.validate(record)?;
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
            Event::Promote { record, .. } => {
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
            }
            Event::Revoke { id, .. } => {
                self.active.remove(id);
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
}
