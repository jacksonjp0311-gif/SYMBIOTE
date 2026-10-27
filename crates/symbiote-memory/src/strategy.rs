//! Durable evaluated query policies, separate from facts and route knowledge.
//! Promotion means fewer calibration queries with unchanged exact correctness.
//! It is not a universal utility or transfer guarantee. Full acquisition,
//! verification, exchange, adoption and replay costs are exposed separately.
//! Hash chains detect corruption; they do not defeat a whole-history rewriter.
use crate::{maintenance, Store, MAX_LEDGER_BYTES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use symbiote_reasoning::query_strategy::{
    derive_policy, run_trial, DerivedPolicy, GraphTask, QueryPolicy, SourceTrace, TrialLimits,
    TrialResult,
};

pub const STRATEGY_FILE: &str = "strategy.jsonl";
pub const STRATEGY_OWNER_FILE: &str = "strategy-owner.json";
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_ROW_BYTES: usize = 256 * 1024;
const MAX_EVENTS: usize = 128;
const MAX_TOTAL_WORK: usize = 2_000_000;
const LIMITS: TrialLimits = TrialLimits {
    max_queries: 24,
    model_work: 10_000,
    policy_work: 10_000,
};
static LEASES: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();

fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
}
fn bytes_sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn canonical<T: Serialize>(value: &T) -> Result<String, String> {
    crate::digest(&serde_json::to_value(value).map_err(|_| "cannot encode strategy value")?)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrategyRecord {
    pub id: String,
    pub revision: u64,
    pub source: String,
    pub policy: QueryPolicy,
    pub training: Vec<SourceTrace>,
    pub provenance: String,
}
impl StrategyRecord {
    pub fn validate(&self) -> Result<DerivedPolicy, String> {
        if !label(&self.id)
            || !label(&self.source)
            || self.revision == 0
            || self.provenance.trim().is_empty()
            || self.provenance.len() > 1024
            || self.training.len() > 8
        {
            return Err(
                "strategy needs bounded identity/revision/source/training/provenance".into(),
            );
        }
        if self
            .training
            .iter()
            .any(|trace| trace.schema.nodes > 12 || trace.schema.edges.len() > 24)
        {
            return Err("durable strategy training exceeds controlled graph budget".into());
        }
        let derived = derive_policy(&self.training, 10_000)?;
        if derived.policy != self.policy {
            return Err(
                "received ranking is not derived from its declared source observations".into(),
            );
        }
        Ok(derived)
    }
    pub fn digest(&self) -> Result<String, String> {
        canonical(self)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryComparison {
    pub task: GraphTask,
    pub baseline: TrialResult,
    pub candidate: TrialResult,
}
impl QueryComparison {
    pub fn query_regression(&self) -> bool {
        self.candidate.incorrect_certificate
            || (self.baseline.certified_correctly() && !self.candidate.certified_correctly())
            || (self.baseline.certified_correctly()
                && self.candidate.certified_correctly()
                && self.candidate.queried_edges.len() > self.baseline.queried_edges.len())
    }
}
fn compare(task: &GraphTask, policy: &QueryPolicy) -> Result<QueryComparison, String> {
    task.validate()?;
    if task.schema.nodes > 12 || task.schema.edges.len() > 24 {
        return Err("strategy calibration exceeds controlled graph budget".into());
    }
    Ok(QueryComparison {
        task: task.clone(),
        baseline: run_trial(task, None, LIMITS)?,
        candidate: run_trial(task, Some(policy), LIMITS)?,
    })
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrategyAssessment {
    pub record_sha256: String,
    pub incumbent_record_sha256: Option<String>,
    pub incumbent_trials: Vec<TrialResult>,
    pub calibration: Vec<QueryComparison>,
    pub regression_checks: Vec<QueryComparison>,
    pub eligible: bool,
    pub reason: String,
    pub baseline_queries: usize,
    pub candidate_queries: usize,
    pub incumbent_queries: usize,
    pub source_observations: usize,
    pub verification_truth_edges: usize,
    pub source_processing_work: usize,
    pub verification_work: usize,
    pub exchange_bytes: usize,
    pub adoption_units: usize,
    pub metric: String,
}
impl StrategyAssessment {
    pub fn evaluation_queries(&self) -> usize {
        self.calibration
            .iter()
            .chain(&self.regression_checks)
            .map(|row| row.baseline.queried_edges.len() + row.candidate.queried_edges.len())
            .sum::<usize>()
            + if self.incumbent_record_sha256.is_some() {
                self.incumbent_trials
                    .iter()
                    .map(|row| row.queried_edges.len())
                    .sum()
            } else {
                0
            }
    }
    pub fn total_work(&self) -> usize {
        self.source_processing_work + self.verification_work
    }
}
pub fn assess(
    record: &StrategyRecord,
    calibration: &[GraphTask],
    known_counterexamples: &[GraphTask],
    incumbent: Option<&StrategyRecord>,
) -> Result<StrategyAssessment, String> {
    let derived = record.validate()?;
    if !(2..=4).contains(&calibration.len()) || known_counterexamples.len() > 8 {
        return Err(
            "strategy needs two to four calibration tasks and at most eight regression checks"
                .into(),
        );
    }
    let mut contexts: BTreeSet<_> = derived.source_contexts.iter().cloned().collect();
    let mut rows = Vec::new();
    for task in calibration {
        if !contexts.insert(task.context.clone()) {
            return Err(
                "source/calibration contexts must be distinct; target evaluation cannot promote"
                    .into(),
            );
        }
        rows.push(compare(task, &record.policy)?);
    }
    let mut regression = Vec::new();
    for task in known_counterexamples {
        regression.push(compare(task, &record.policy)?);
    }
    let incumbent_trials = if let Some(prior) = incumbent {
        prior.policy.validate()?;
        calibration
            .iter()
            .map(|task| run_trial(task, Some(&prior.policy), LIMITS))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        rows.iter().map(|row| row.baseline.clone()).collect()
    };
    let incumbent_queries = incumbent_trials
        .iter()
        .map(|row| row.queried_edges.len())
        .sum();
    let baseline_queries = rows
        .iter()
        .map(|row| row.baseline.queried_edges.len())
        .sum();
    let candidate_queries = rows
        .iter()
        .map(|row| row.candidate.queried_edges.len())
        .sum();
    let correctness = rows
        .iter()
        .all(|row| row.baseline.certified_correctly() && row.candidate.certified_correctly());
    let safe_regressions = regression.iter().all(|row| !row.query_regression());
    let default_guard = rows.iter().all(|row| !row.query_regression());
    let eligible =
        correctness && default_guard && candidate_queries < incumbent_queries && safe_regressions;
    let mut verification_work: usize = rows
        .iter()
        .chain(&regression)
        .map(|row| {
            row.baseline.model_work
                + row.baseline.policy_work
                + row.baseline.evaluator_work
                + row.candidate.model_work
                + row.candidate.policy_work
                + row.candidate.evaluator_work
        })
        .sum();
    if incumbent.is_some() {
        verification_work += incumbent_trials
            .iter()
            .map(|row| row.model_work + row.policy_work + row.evaluator_work)
            .sum::<usize>();
    }
    Ok(StrategyAssessment {
        record_sha256: record.digest()?, incumbent_record_sha256:incumbent.map(StrategyRecord::digest).transpose()?, incumbent_trials,
        baseline_queries, candidate_queries, incumbent_queries, eligible,
        reason: if !correctness { "calibration abstention or incorrect conditional certificate" }
            else if !safe_regressions { "known query-policy counterexample remains harmful" }
            else if !default_guard { "calibration query regression against original default" }
            else if candidate_queries >= incumbent_queries { "no strict calibration query-count improvement over current selected behavior" }
            else { "independent calibration query count improves current behavior without default regression" }.into(),
        source_observations: record.training.iter().map(|trace| trace.observations.len()).sum(),
        verification_truth_edges: 2*rows.iter().chain(&regression).map(|row| row.task.schema.edges.len()).sum::<usize>()
            + if incumbent.is_some() {calibration.iter().map(|task|task.schema.edges.len()).sum::<usize>()} else {0},
        source_processing_work: derived.work_units, verification_work,
        exchange_bytes: serde_json::to_vec(record).map_err(|_| "cannot count strategy bytes")?.len(),
        adoption_units: usize::from(eligible),
        metric: "conditional-calibration-oracle-query-count; not net reciprocal utility".into(),
        calibration: rows, regression_checks: regression,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
enum Event {
    Genesis {
        version: u32,
        identity: String,
        owner_genesis_sha256: String,
    },
    Considered {
        record: StrategyRecord,
        calibration: Vec<GraphTask>,
        assessment: StrategyAssessment,
    },
    Revoked {
        id: String,
        revision: u64,
        record_sha256: String,
        counterexample: QueryComparison,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    sequence: usize,
    previous: String,
    payload: Event,
    sha256: String,
}
fn row_hash(row: &Row) -> Result<String, String> {
    canonical(&(
        row.sequence,
        &row.previous,
        serde_json::to_value(&row.payload).map_err(|_| "cannot encode strategy receipt")?,
    ))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerMarker {
    schema: String,
    identity: String,
    owner_genesis_sha256: String,
    strategy_genesis_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrategyDecision {
    pub promoted: bool,
    pub replayed: bool,
    pub active: bool,
    pub assessment: StrategyAssessment,
}
#[derive(Clone, Default)]
struct Model {
    active: BTreeMap<String, StrategyRecord>,
    revisions: BTreeMap<String, u64>,
    sources: BTreeMap<String, String>,
    attempts: BTreeMap<String, StrategyAssessment>,
    // Every policy declares the same broad graph family. A renamed record,
    // source or context must not erase a known harmful task.
    counterexamples: Vec<GraphTask>,
    work: usize,
}
impl Model {
    fn accept(
        &mut self,
        record: &StrategyRecord,
        calibration: &[GraphTask],
        assessment: &StrategyAssessment,
    ) -> Result<(), String> {
        let attempt = canonical(&(record, calibration))?;
        if self.attempts.contains_key(&attempt) {
            return Err("duplicate strategy assessment receipt".into());
        }
        if self
            .work
            .checked_add(assessment.total_work())
            .is_none_or(|n| n > MAX_TOTAL_WORK)
        {
            return Err("strategy journal cumulative verification work budget exhausted".into());
        }
        if assessment.eligible {
            if self
                .revisions
                .get(&record.id)
                .is_some_and(|old| *old >= record.revision)
                || self
                    .sources
                    .get(&record.id)
                    .is_some_and(|source| source != &record.source)
            {
                return Err("stale strategy revision or changed declared source namespace".into());
            }
            self.revisions.insert(record.id.clone(), record.revision);
            self.sources
                .insert(record.id.clone(), record.source.clone());
            // One current global prior. Older accepted revisions remain in the
            // immutable journal, never as shadow policies that bypass revocation.
            self.active.clear();
            self.active.insert(record.id.clone(), record.clone());
        }
        self.work += assessment.total_work();
        self.attempts.insert(attempt, assessment.clone());
        Ok(())
    }
    fn revoke(
        &mut self,
        id: &str,
        revision: u64,
        digest: &str,
        comparison: &QueryComparison,
    ) -> Result<(), String> {
        let record = self.active.get(id).ok_or("no active strategy to revoke")?;
        if record.revision != revision
            || record.digest()? != digest
            || !comparison.query_regression()
        {
            return Err("strategy revocation needs its active revision and an observed harmful counterexample".into());
        }
        let known = self.counterexamples.iter().any(|task| {
            task.schema == comparison.task.schema
                && task.start == comparison.task.start
                && task.goal == comparison.task.goal
                && task.costs == comparison.task.costs
        });
        if self.counterexamples.len() >= 8 && !known {
            return Err("strategy family counterexample registry exhausted".into());
        }
        let work = comparison.baseline.model_work
            + comparison.baseline.evaluator_work
            + comparison.candidate.model_work
            + comparison.candidate.policy_work
            + comparison.candidate.evaluator_work;
        self.work = self
            .work
            .checked_add(work)
            .filter(|n| *n <= MAX_TOTAL_WORK)
            .ok_or("strategy journal cumulative verification work exhausted")?;
        if !known {
            self.counterexamples.push(comparison.task.clone());
        }
        self.active.remove(id);
        Ok(())
    }
}
struct Replay {
    model: Model,
    rows: usize,
    head: String,
    genesis: String,
}
fn replay(bytes: &[u8], owner: &str, owner_genesis: &str) -> Result<Replay, String> {
    if bytes.is_empty() || bytes.len() > MAX_LEDGER_BYTES || bytes.last() != Some(&b'\n') {
        return Err("HOLD: missing, oversized or truncated strategy journal".into());
    }
    let mut state = Model::default();
    let mut previous = ZERO.into();
    let mut count = 0;
    let mut genesis = String::new();
    for (sequence, line) in bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .enumerate()
    {
        if line.is_empty() {
            return Err("blank strategy receipts are not permitted".into());
        }
        if sequence >= MAX_EVENTS || line.len() > MAX_ROW_BYTES {
            return Err("strategy receipt count/size budget exceeded".into());
        }
        let row: Row =
            serde_json::from_slice(line).map_err(|_| "strategy receipt schema rejected")?;
        if row.sequence != sequence || row.previous != previous || row.sha256 != row_hash(&row)? {
            return Err("strategy receipt chain or content digest rejected".into());
        }
        match &row.payload {
            Event::Genesis {
                version,
                identity,
                owner_genesis_sha256,
            } => {
                if sequence != 0
                    || *version != 1
                    || identity != owner
                    || owner_genesis_sha256 != owner_genesis
                {
                    return Err("foreign, repeated or unsupported strategy genesis".into());
                }
                genesis = row.sha256.clone();
            }
            Event::Considered {
                record,
                calibration,
                assessment,
            } => {
                if sequence == 0 {
                    return Err("strategy genesis must be first".into());
                }
                let expected = assess(
                    record,
                    calibration,
                    &state.counterexamples,
                    state.active.values().next(),
                )?;
                if &expected != assessment {
                    return Err("strategy assessment differs from independent replay".into());
                }
                state.accept(record, calibration, assessment)?;
            }
            Event::Revoked {
                id,
                revision,
                record_sha256,
                counterexample,
            } => {
                let record = state
                    .active
                    .get(id)
                    .ok_or("revocation has no active strategy")?;
                if compare(&counterexample.task, &record.policy)? != *counterexample {
                    return Err(
                        "strategy counterexample differs from independently replayed observations"
                            .into(),
                    );
                }
                state.revoke(id, *revision, record_sha256, counterexample)?;
            }
        }
        previous = row.sha256;
        count += 1;
    }
    if genesis.is_empty() {
        return Err("strategy genesis missing".into());
    }
    Ok(Replay {
        model: state,
        rows: count,
        head: previous,
        genesis,
    })
}
struct Lease {
    owner: Arc<Store>,
    directory: PathBuf,
}
impl Lease {
    fn acquire(owner: Arc<Store>) -> Result<Self, String> {
        if owner._lock.is_none() {
            return Err("strategy requires an actual live Store writer guard".into());
        }
        let directory = std::fs::canonicalize(&owner.directory)
            .map_err(|_| "strategy owner directory unavailable")?;
        let mut leases = LEASES
            .get_or_init(|| Mutex::new(BTreeSet::new()))
            .lock()
            .map_err(|_| "strategy lease registry unavailable")?;
        if !leases.insert(directory.clone()) {
            return Err("only one strategy ledger may use an owner".into());
        }
        Ok(Self { owner, directory })
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(leases) = LEASES.get() {
            if let Ok(mut leases) = leases.lock() {
                leases.remove(&self.directory);
            }
        }
    }
}
pub struct StrategyLedger {
    lease: Lease,
    marker: OwnerMarker,
    model: Model,
    committed: Vec<u8>,
    count: usize,
    head: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrategySnapshot {
    pub identity: String,
    pub record_count: usize,
    pub head_sha256: String,
    pub active: Vec<StrategyRecord>,
    pub replay_work_units: usize,
}
impl StrategyLedger {
    pub fn open(owner: Arc<Store>) -> Result<Self, String> {
        let lease = Lease::acquire(owner)?;
        crate::backup::writer_admission(&lease.owner.directory)?;
        maintenance::validate_layout_identity(&lease.owner.directory, lease.owner.identity())?;
        let raw_owner = maintenance::read_regular(&lease.owner.ledger_path(), MAX_LEDGER_BYTES)?
            .ok_or("strategy owner ledger missing")?;
        let first = raw_owner
            .split_inclusive(|byte| *byte == b'\n')
            .next()
            .ok_or("owner genesis missing")?;
        let owner_genesis = bytes_sha(first);
        let directory = &lease.owner.directory;
        let journal = maintenance::read_regular(&directory.join(STRATEGY_FILE), MAX_LEDGER_BYTES)?;
        let marker = maintenance::read_regular(&directory.join(STRATEGY_OWNER_FILE), 2048)?;
        if journal.is_some() != marker.is_some() {
            return Err("HOLD: strategy journal/owner marker pair incomplete; never recreate surviving learning history".into());
        }
        if let (Some(committed), Some(marker)) = (journal, marker) {
            let marker: OwnerMarker =
                serde_json::from_slice(&marker).map_err(|_| "strategy owner marker rejected")?;
            let replay = replay(&committed, lease.owner.identity(), &owner_genesis)?;
            validate_marker(
                &marker,
                lease.owner.identity(),
                &owner_genesis,
                &replay.genesis,
            )?;
            return Ok(Self {
                lease,
                marker,
                model: replay.model,
                committed,
                count: replay.rows,
                head: replay.head,
            });
        }
        let mut row = Row {
            sequence: 0,
            previous: ZERO.into(),
            payload: Event::Genesis {
                version: 1,
                identity: lease.owner.identity().into(),
                owner_genesis_sha256: owner_genesis.clone(),
            },
            sha256: String::new(),
        };
        row.sha256 = row_hash(&row)?;
        let marker = OwnerMarker {
            schema: "symbiote.strategy-owner/1".into(),
            identity: lease.owner.identity().into(),
            owner_genesis_sha256: owner_genesis,
            strategy_genesis_sha256: row.sha256.clone(),
        };
        let marker_bytes =
            serde_json::to_vec(&marker).map_err(|_| "cannot encode strategy owner marker")?;
        let mut committed =
            serde_json::to_vec(&row).map_err(|_| "cannot encode strategy genesis")?;
        committed.push(b'\n');
        // Marker first: an interrupted first registration cannot silently reset.
        maintenance::atomic_replace(directory, STRATEGY_OWNER_FILE, &marker_bytes)?;
        maintenance::atomic_replace(directory, STRATEGY_FILE, &committed)?;
        Ok(Self {
            lease,
            marker,
            model: Model::default(),
            committed,
            count: 1,
            head: row.sha256,
        })
    }
    pub fn validate_snapshot(
        bytes: &[u8],
        marker: &[u8],
        owner: &str,
        owner_genesis_sha256: &str,
    ) -> Result<StrategySnapshot, String> {
        if marker.len() > 2048 {
            return Err("strategy owner marker exceeds its byte budget".into());
        }
        let marker: OwnerMarker =
            serde_json::from_slice(marker).map_err(|_| "strategy owner marker rejected")?;
        let replay = replay(bytes, owner, owner_genesis_sha256)?;
        validate_marker(&marker, owner, owner_genesis_sha256, &replay.genesis)?;
        Ok(StrategySnapshot {
            identity: owner.into(),
            record_count: replay.rows,
            head_sha256: replay.head,
            active: replay.model.active.values().cloned().collect(),
            replay_work_units: replay.model.work,
        })
    }
    pub fn identity(&self) -> &str {
        self.lease.owner.identity()
    }
    pub fn active(&self) -> Vec<StrategyRecord> {
        self.model.active.values().cloned().collect()
    }
    pub fn selected(&self) -> Option<StrategyRecord> {
        self.model.active.values().next().cloned()
    }
    pub fn record_count(&self) -> usize {
        self.count
    }
    pub fn head_sha256(&self) -> &str {
        &self.head
    }
    pub fn replay_work_units(&self) -> usize {
        self.model.work
    }
    pub fn ledger_path(&self) -> PathBuf {
        self.lease.owner.directory.join(STRATEGY_FILE)
    }
    pub fn marker_path(&self) -> PathBuf {
        self.lease.owner.directory.join(STRATEGY_OWNER_FILE)
    }
    pub fn owner_genesis_sha256(&self) -> &str {
        &self.marker.owner_genesis_sha256
    }

    pub fn consider(
        &mut self,
        record: StrategyRecord,
        calibration: Vec<GraphTask>,
    ) -> Result<StrategyDecision, String> {
        let attempt = canonical(&(&record, &calibration))?;
        if let Some(assessment) = self.model.attempts.get(&attempt) {
            return Ok(StrategyDecision {
                promoted: false,
                replayed: true,
                active: self.model.active.get(&record.id) == Some(&record),
                assessment: assessment.clone(),
            });
        }
        let assessment = assess(
            &record,
            &calibration,
            &self.model.counterexamples,
            self.model.active.values().next(),
        )?;
        let mut next = self.model.clone();
        next.accept(&record, &calibration, &assessment)?;
        let active = next.active.get(&record.id) == Some(&record);
        self.commit(
            Event::Considered {
                record,
                calibration,
                assessment: assessment.clone(),
            },
            next,
        )?;
        Ok(StrategyDecision {
            promoted: assessment.eligible,
            replayed: false,
            active,
            assessment,
        })
    }
    pub fn revoke_for_counterexample(
        &mut self,
        id: &str,
        task: GraphTask,
    ) -> Result<QueryComparison, String> {
        let record = self
            .model
            .active
            .get(id)
            .ok_or("no active strategy to evaluate for revocation")?
            .clone();
        let counterexample = compare(&task, &record.policy)?;
        let mut next = self.model.clone();
        next.revoke(id, record.revision, &record.digest()?, &counterexample)?;
        self.commit(
            Event::Revoked {
                id: id.into(),
                revision: record.revision,
                record_sha256: record.digest()?,
                counterexample: counterexample.clone(),
            },
            next,
        )?;
        Ok(counterexample)
    }
    fn commit(&mut self, payload: Event, model: Model) -> Result<(), String> {
        maintenance::validate_strategy_learning_admission(&self.lease.owner.directory)?;
        if self.count >= MAX_EVENTS {
            return Err("strategy event budget exhausted".into());
        }
        let mut row = Row {
            sequence: self.count,
            previous: self.head.clone(),
            payload,
            sha256: String::new(),
        };
        row.sha256 = row_hash(&row)?;
        let mut addition = serde_json::to_vec(&row).map_err(|_| "cannot encode strategy event")?;
        addition.push(b'\n');
        if addition.len() > MAX_ROW_BYTES
            || self.committed.len() + addition.len() > MAX_LEDGER_BYTES
        {
            return Err("strategy ledger row/byte budget exhausted".into());
        }
        let mut next = self.committed.clone();
        next.extend(addition);
        maintenance::atomic_replace(&self.lease.owner.directory, STRATEGY_FILE, &next)?;
        self.model = model;
        self.committed = next;
        self.head = row.sha256;
        self.count += 1;
        Ok(())
    }
}
fn validate_marker(
    marker: &OwnerMarker,
    owner: &str,
    genesis: &str,
    strategy_genesis: &str,
) -> Result<(), String> {
    if marker.schema != "symbiote.strategy-owner/1"
        || marker.identity != owner
        || marker.owner_genesis_sha256 != genesis
        || marker.strategy_genesis_sha256 != strategy_genesis
    {
        return Err("foreign or inconsistent strategy owner registration".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use symbiote_reasoning::planning::{Edge, GraphSchema};
    use symbiote_reasoning::query_strategy::EdgeObservation;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "symbiote-strategy-manual-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn task(context: &str) -> GraphTask {
        GraphTask {
            context: context.into(),
            start: 0,
            goal: 3,
            schema: GraphSchema {
                nodes: 4,
                edges: [(0, 1), (1, 3), (0, 2), (2, 3)]
                    .into_iter()
                    .map(|(from, to)| Edge {
                        from,
                        to,
                        lower: 1,
                        upper: 9,
                    })
                    .collect(),
            },
            costs: vec![1, 9, 1, 1],
        }
    }
    fn record(source: &str, revision: u64) -> StrategyRecord {
        let training = ["manual-train-a", "manual-train-b"]
            .into_iter()
            .map(|context| {
                let task = task(context);
                SourceTrace {
                    context: context.into(),
                    schema: task.schema,
                    start: 0,
                    goal: 3,
                    observations: vec![
                        EdgeObservation { edge: 0, cost: 1 },
                        EdgeObservation { edge: 1, cost: 9 },
                    ],
                }
            })
            .collect::<Vec<_>>();
        StrategyRecord {
            id: "manual-policy".into(),
            revision,
            source: source.into(),
            policy: derive_policy(&training, 1000).unwrap().policy,
            training,
            provenance: "Manual trusted local source observations; no external-agent claim".into(),
        }
    }
    fn calibration() -> Vec<GraphTask> {
        vec![task("manual-cal-a"), task("manual-cal-b")]
    }
    #[test]
    fn promotion_restarts_with_same_real_query_behavior_and_bytes() {
        let dir = Directory::new();
        let owner = Arc::new(Store::open(&dir.0).unwrap());
        let id = owner.identity().to_string();
        let mut ledger = StrategyLedger::open(Arc::clone(&owner)).unwrap();
        let decision = ledger
            .consider(record("manual-partner", 1), calibration())
            .unwrap();
        assert!(decision.promoted && !decision.replayed);
        let before = std::fs::read(ledger.ledger_path()).unwrap();
        let policy = ledger.active()[0].policy.clone();
        assert_eq!(
            run_trial(&task("manual-future"), Some(&policy), LIMITS)
                .unwrap()
                .queried_edges,
            vec![1, 3, 2]
        );
        drop(ledger);
        drop(owner);
        let owner = Arc::new(Store::open(&dir.0).unwrap());
        assert_eq!(owner.identity(), id);
        let mut ledger = StrategyLedger::open(owner).unwrap();
        assert_eq!(ledger.active()[0].policy, policy);
        assert_eq!(std::fs::read(ledger.ledger_path()).unwrap(), before);
        assert!(
            ledger
                .consider(record("manual-partner", 1), calibration())
                .unwrap()
                .replayed
        );
        assert_eq!(std::fs::read(ledger.ledger_path()).unwrap(), before);
    }
    #[test]
    fn rejection_revocation_and_supersession_are_auditable_and_stale_safe() {
        let dir = Directory::new();
        let owner = Arc::new(Store::open(&dir.0).unwrap());
        let mut ledger = StrategyLedger::open(owner).unwrap();
        assert!(
            ledger
                .consider(record("partner", 1), calibration())
                .unwrap()
                .promoted
        );
        let prefix = std::fs::read(ledger.ledger_path()).unwrap();
        assert!(
            !ledger
                .consider(
                    record("partner", 2),
                    vec![task("new-cal-a"), task("new-cal-b")]
                )
                .unwrap()
                .promoted
        );
        assert_eq!(ledger.active()[0].revision, 1);
        assert!(std::fs::read(ledger.ledger_path())
            .unwrap()
            .starts_with(&prefix));
        let mut inverted = task("manual-inverted");
        inverted.costs = vec![9, 1, 1, 1];
        assert!(ledger
            .revoke_for_counterexample("manual-policy", inverted)
            .unwrap()
            .query_regression());
        assert!(ledger.active().is_empty());
        let denied = ledger
            .consider(
                record("partner", 3),
                vec![task("later-cal-a"), task("later-cal-b")],
            )
            .unwrap();
        assert!(!denied.promoted);
        assert!(!denied.assessment.regression_checks.is_empty());
    }
    #[test]
    fn received_hint_does_not_override_training_or_bypass_independent_calibration() {
        let dir = Directory::new();
        let owner = Arc::new(Store::open(&dir.0).unwrap());
        let mut ledger = StrategyLedger::open(owner).unwrap();
        let mut forged = record("partner", 1);
        forged.policy.ranked_roles.reverse();
        let before = std::fs::read(ledger.ledger_path()).unwrap();
        assert!(ledger.consider(forged, calibration()).is_err());
        assert_eq!(std::fs::read(ledger.ledger_path()).unwrap(), before);
        let mut wrong = calibration();
        for case in &mut wrong {
            case.costs = vec![9, 1, 1, 1];
        }
        assert!(
            !ledger
                .consider(record("partner", 1), wrong)
                .unwrap()
                .promoted
        );
        assert!(ledger.active().is_empty());
        assert!(
            ledger
                .consider(record("partner", 1), calibration())
                .unwrap()
                .promoted
        );
    }
    #[test]
    fn missing_half_and_corrupt_receipts_hold_without_reinitialization() {
        let dir = Directory::new();
        let owner = Arc::new(Store::open(&dir.0).unwrap());
        let ledger = StrategyLedger::open(Arc::clone(&owner)).unwrap();
        let marker = ledger.marker_path();
        let path = ledger.ledger_path();
        let raw = std::fs::read(&path).unwrap();
        drop(ledger);
        std::fs::remove_file(&marker).unwrap();
        assert!(StrategyLedger::open(Arc::clone(&owner)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), raw);
    }
    #[test]
    fn live_owner_arc_and_duplicate_handle_guard_block_competing_writers() {
        let dir = Directory::new();
        let owner = Arc::new(Store::open(&dir.0).unwrap());
        let ledger = StrategyLedger::open(Arc::clone(&owner)).unwrap();
        assert!(StrategyLedger::open(Arc::clone(&owner)).is_err());
        drop(owner);
        assert!(Store::open(&dir.0).is_err());
        drop(ledger);
        assert!(Store::open(&dir.0).is_ok());
    }
    #[test]
    fn harmful_ranking_cannot_reactivate_via_record_source_or_context_aliases() {
        let dir = Directory::new();
        let owner = Arc::new(Store::open(&dir.0).unwrap());
        let mut ledger = StrategyLedger::open(Arc::clone(&owner)).unwrap();
        let original = record("partner", 1);
        assert!(
            ledger
                .consider(original.clone(), calibration())
                .unwrap()
                .promoted
        );
        let mut inverted = task("actual-old-counterexample");
        inverted.costs = vec![9, 1, 1, 1];
        ledger
            .revoke_for_counterexample(&original.id, inverted)
            .unwrap();
        let replayed = ledger.consider(original, calibration()).unwrap();
        assert!(replayed.replayed);
        assert!(!replayed.promoted && !replayed.active);
        let mut alias = record("renamed-partner", 1);
        alias.id = "renamed-record".into();
        for (index, trace) in alias.training.iter_mut().enumerate() {
            trace.context = format!("renamed-source-{index}");
        }
        let rejected = ledger
            .consider(alias, vec![task("new-good-cal-a"), task("new-good-cal-b")])
            .unwrap();
        assert!(!rejected.promoted && !rejected.active);
        assert_eq!(rejected.assessment.regression_checks.len(), 1);
        assert!(ledger.active().is_empty());
        drop(ledger);
        let ledger = StrategyLedger::open(owner).unwrap();
        assert!(ledger.active().is_empty());
    }
    #[test]
    fn rehashed_forged_calibration_metrics_are_rejected_on_replay_without_writes() {
        let dir = Directory::new();
        let owner = Arc::new(Store::open(&dir.0).unwrap());
        let mut ledger = StrategyLedger::open(Arc::clone(&owner)).unwrap();
        ledger
            .consider(record("partner", 1), calibration())
            .unwrap();
        let path = ledger.ledger_path();
        let bytes = std::fs::read(&path).unwrap();
        drop(ledger);
        let mut rows = bytes
            .split(|b| *b == b'\n')
            .filter(|r| !r.is_empty())
            .map(|r| serde_json::from_slice::<Row>(r).unwrap())
            .collect::<Vec<_>>();
        if let Event::Considered { assessment, .. } = &mut rows.last_mut().unwrap().payload {
            assessment.candidate_queries = 0;
        } else {
            panic!("missing consideration");
        }
        rows.last_mut().unwrap().sha256 = row_hash(rows.last().unwrap()).unwrap();
        let mut forged = Vec::new();
        for row in rows {
            forged.extend(serde_json::to_vec(&row).unwrap());
            forged.push(b'\n');
        }
        std::fs::write(&path, &forged).unwrap();
        assert!(StrategyLedger::open(owner).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), forged);
    }
    #[test]
    fn selected_policy_supersedes_only_for_real_incumbent_improvement() {
        let dir = Directory::new();
        let owner = Arc::new(Store::open(&dir.0).unwrap());
        let mut ledger = StrategyLedger::open(Arc::clone(&owner)).unwrap();
        assert!(
            ledger
                .consider(record("partner", 1), calibration())
                .unwrap()
                .promoted
        );
        let prefix = std::fs::read(ledger.ledger_path()).unwrap();
        let mut replacement = record("partner", 2);
        for trace in &mut replacement.training {
            trace.observations[0].cost = 9;
            trace.observations[1].cost = 1;
        }
        replacement.policy = derive_policy(&replacement.training, 1000).unwrap().policy;
        let mut calibration = vec![task("replacement-cal-a"), task("replacement-cal-b")];
        for case in &mut calibration {
            case.costs = vec![9, 1, 1, 1];
        }
        let decision = ledger.consider(replacement, calibration).unwrap();
        assert!(decision.promoted && decision.active);
        assert_eq!(
            decision.assessment.candidate_queries,
            decision.assessment.baseline_queries
        );
        assert!(decision.assessment.candidate_queries < decision.assessment.incumbent_queries);
        assert_eq!(ledger.active().len(), 1);
        assert_eq!(ledger.selected().unwrap().revision, 2);
        assert!(std::fs::read(ledger.ledger_path())
            .unwrap()
            .starts_with(&prefix));
        drop(ledger);
        assert_eq!(
            StrategyLedger::open(owner)
                .unwrap()
                .selected()
                .unwrap()
                .revision,
            2
        );
    }
}
