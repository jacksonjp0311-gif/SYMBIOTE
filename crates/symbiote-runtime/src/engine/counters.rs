//! Read-only, versioned counts from native completed episodes and store witnesses.
//! Counters never authorize retention or turn an imported digest into evidence.
use super::{journal, types::*, Audit, Engine, EngineState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use symbiote_memory::{
    knowledge::{KnowledgeRecord, KnowledgeStore},
    operational::OperationalEvent,
};

/// An inert exact-prefix lookup coordinate. Every use revalidates both histories.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CounterAnchor {
    pub knowledge: KnowledgeAnchor,
    pub operational_events: usize,
    pub operational_prefix_sha256: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum LearningOrigin {
    OrdinaryLearning,
    ReceiverRole,
}
impl LearningOrigin {
    fn index(self) -> usize {
        match self {
            Self::OrdinaryLearning => 0,
            Self::ReceiverRole => 1,
        }
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RoleCounts {
    pub ordinary_learning: usize,
    pub receiver_role: usize,
    pub total: usize,
}
impl RoleCounts {
    fn from_sets<T>(s: &[BTreeSet<T>; 2]) -> Self {
        Self {
            ordinary_learning: s[0].len(),
            receiver_role: s[1].len(),
            total: s[0].len() + s[1].len(),
        }
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PromotionCounts {
    pub ordinary_learning: usize,
    pub receiver_role: usize,
    pub total_new: usize,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct OutcomeCounts {
    pub ordinary_learning: usize,
    pub receiver_role: usize,
    pub partner_receiver: usize,
    pub total: usize,
}
impl OutcomeCounts {
    fn local<T>(s: &[BTreeSet<T>; 2]) -> Self {
        Self {
            ordinary_learning: s[0].len(),
            receiver_role: s[1].len(),
            partner_receiver: 0,
            total: s[0].len() + s[1].len(),
        }
    }
}
/// Historical retention remains visible even when one of these current holds applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum CurrentValidity {
    Active,
    RevokedOrSuperseded,
    SourceEpochHold,
    PolicyHold,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RetentionStatus {
    pub episode_id: String,
    pub origin: LearningOrigin,
    pub artifact: String,
    pub record_sha256: String,
    pub promotion_sha256: String,
    pub before: KnowledgeAnchor,
    pub after: KnowledgeAnchor,
    pub source: SourceDescriptor,
    pub current: CurrentValidity,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CurrentOutcomeSubsets {
    pub completed_outcomes: RoleCounts,
    pub capability_outcomes: RoleCounts,
    pub measured_benefits: RoleCounts,
}
/// A saved peer response is historical metadata, not a fresh remote membership check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum RemoteValidity {
    UnknownWithoutReceiver,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecordedReconciliation {
    pub exchange_id: String,
    pub sender: String,
    pub receiver: String,
    pub scope: String,
    pub record_sha256: String,
    pub promotion_sha256: String,
    pub receiver_knowledge: KnowledgeAnchor,
    pub receiver_journal_sha256: String,
    pub experience_sha256: String,
    pub recorded_outcome: crate::service::feedback::Outcome,
    pub current_remote_validity: RemoteValidity,
}
/// Origin counts are disjoint. Reuse/capability/benefit subsets are not additional
/// promotions. Default counters cover the durable lifetime; use counters_since
/// for an explicit run/experiment prefix. Repeated reads create no new credit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct CounterReport {
    pub schema: &'static str,
    pub from: CounterAnchor,
    pub to: CounterAnchor,
    pub promotions: PromotionCounts,
    pub reused_records: RoleCounts,
    pub completed_outcomes: OutcomeCounts,
    pub capability_outcomes: OutcomeCounts,
    pub measured_benefits: OutcomeCounts,
    pub current_active_local: CurrentOutcomeSubsets,
    pub durable_history_completed_outcomes: OutcomeCounts,
    pub retentions: Vec<RetentionStatus>,
    pub pending_episodes: usize,
    pub partner_outcome_snapshots_recorded: usize,
    pub durable_history_partner_outcome_snapshots_recorded: usize,
    pub recorded_reconciliations: Vec<RecordedReconciliation>,
    pub current_remote_validity: RemoteValidity,
    pub partner_current_status: &'static str,
}
/// Per-owner application counters. Inclusive byte categories overlap; this is
/// not exclusive CPU time, total OS I/O, TLS framing, peak memory or power-loss proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ResourceReport {
    pub schema: &'static str,
    pub owner: String,
    pub knowledge_anchor: KnowledgeAnchor,
    pub knowledge_io: symbiote_memory::knowledge::KnowledgeIoDiagnostics,
    pub knowledge_capacity: symbiote_memory::knowledge::KnowledgeCapacity,
    pub operational_prefix_work: symbiote_memory::operational::PrefixWork,
    pub scope: &'static str,
}
struct Episode {
    source: SourceDescriptor,
    before: KnowledgeAnchor,
    audit: Option<Audit>,
    sha: Option<String>,
    inferred_reused: Option<bool>,
    evaluated: bool,
}
fn hold(message: impl Into<String>) -> EngineError {
    EngineError::new(ErrorKind::Hold, "counters", message)
}
fn proof<T>(r: std::result::Result<T, String>) -> Result<T> {
    r.map_err(hold)
}
fn record_sha(record: &KnowledgeRecord) -> Result<String> {
    proof(record.digest())
}
fn genesis(knowledge: &KnowledgeStore) -> Result<KnowledgeAnchor> {
    use std::io::{BufRead, BufReader};
    let file = std::fs::File::open(knowledge.ledger_path())
        .map_err(|e| EngineError::new(ErrorKind::Storage, "counters", e.to_string()))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    // Native genesis is tiny; never allocate an unbounded line supplied by a path.
    let n = std::io::Read::take(&mut reader, 16385)
        .read_line(&mut line)
        .map_err(|e| EngineError::new(ErrorKind::Storage, "counters", e.to_string()))?;
    if n == 0 || n > 16384 || !line.ends_with('\n') {
        return Err(hold("knowledge genesis unavailable or oversized"));
    }
    let row: Value = serde_json::from_str(&line).map_err(|e| hold(e.to_string()))?;
    let anchor = KnowledgeAnchor {
        identity: knowledge.identity().into(),
        records: 1,
        head_sha256: row["sha256"]
            .as_str()
            .ok_or_else(|| hold("knowledge genesis SHA absent"))?
            .into(),
    };
    proof(knowledge.validate_anchor(&anchor))?;
    Ok(anchor)
}
fn current(
    state: &EngineState,
    audit: &Audit,
    record: &KnowledgeRecord,
) -> Result<CurrentValidity> {
    if audit.policy_sha256 != state.policy_sha256 {
        return Ok(CurrentValidity::PolicyHold);
    }
    if !state.config.authorized_sources.contains(&audit.source) {
        return Ok(CurrentValidity::SourceEpochHold);
    }
    if !state.knowledge.active().iter().any(|r| r == record) {
        return Ok(CurrentValidity::RevokedOrSuperseded);
    }
    Ok(CurrentValidity::Active)
}
fn read_report(state: &EngineState, from: CounterAnchor) -> Result<CounterReport> {
    let count = state.journal.events().len();
    proof(state.knowledge.validate_anchor(&from.knowledge))?;
    if from.operational_events > count
        || proof(state.journal.event_prefix_sha256(from.operational_events))?
            != from.operational_prefix_sha256
    {
        return Err(hold("counter start is unavailable, foreign or changed"));
    }
    let to = CounterAnchor {
        knowledge: state.knowledge.history_anchor(),
        operational_events: count,
        operational_prefix_sha256: proof(state.journal.event_prefix_sha256(count))?,
    };
    let parsed = journal::entries(state)?;
    let positions: Vec<_> = state
        .journal
        .events()
        .iter()
        .enumerate()
        .filter_map(|(i, e)| match e {
            OperationalEvent::PartnerDecisionRecorded { decision }
                if decision.details["schema"]
                    .as_str()
                    .is_some_and(|s| s.starts_with("symbiote.embedding-engine/")) =>
            {
                Some(i)
            }
            _ => None,
        })
        .collect();
    if positions.len() != parsed.len() {
        return Err(hold("counter entry positions are incomplete"));
    }
    let mut head = genesis(&state.knowledge)?;
    let mut start_head = head.clone();
    let mut pending: BTreeMap<String, Episode> = BTreeMap::new();
    let mut seen_episodes = BTreeSet::new();
    let mut promotions = [BTreeSet::new(), BTreeSet::new()];
    let mut reused = promotions.clone();
    let mut retentions = Vec::new();
    let mut all_promotions = BTreeSet::new();
    let mut statuses = BTreeMap::new();
    let mut promotion_sources = BTreeMap::new();
    for (position, (scope, entry)) in positions.into_iter().zip(parsed) {
        match entry {
            journal::Entry::Started {
                episode,
                source,
                before,
            } => {
                proof(state.knowledge.validate_anchor(&before))?;
                if !pending.is_empty()
                    || !seen_episodes.insert(episode.clone())
                    || before != head
                    || source.scope != scope
                {
                    return Err(hold(
                        "counter episode start is overlapping or has a wrong native head",
                    ));
                }
                pending.insert(
                    episode,
                    Episode {
                        source,
                        before,
                        audit: None,
                        sha: None,
                        inferred_reused: None,
                        evaluated: false,
                    },
                );
            }
            journal::Entry::Inferred {
                episode,
                audit,
                record_sha256,
                reused,
            } => {
                let p = pending
                    .get_mut(&episode)
                    .ok_or_else(|| hold("counter inference lacks its exact start"))?;
                if p.audit.is_some()
                    || audit.schema != "symbiote.engine-observation-audit/1"
                    || audit.owner != state.owner.identity()
                    || audit.source != p.source
                    || audit.policy_sha256 != state.journal.policy_digest()
                    || (!reused && audit.episode != episode)
                {
                    return Err(hold("counter inference authority or unique audit differs"));
                }
                p.audit = Some(audit);
                p.sha = Some(record_sha256);
                p.inferred_reused = Some(reused);
            }
            journal::Entry::Evaluated {
                episode,
                record_sha256,
                ..
            } => {
                let p = pending
                    .get_mut(&episode)
                    .ok_or_else(|| hold("counter evaluation lacks its episode"))?;
                if p.evaluated || p.sha.as_ref() != Some(&record_sha256) {
                    return Err(hold(
                        "counter evaluation is duplicated or names another inference",
                    ));
                }
                p.evaluated = true;
            }
            journal::Entry::Finished {
                episode,
                record,
                before,
                after,
                reused: was_reused,
                ..
            } => {
                let p = pending
                    .remove(&episode)
                    .ok_or_else(|| hold("counter completion lacks its native episode"))?;
                let audit = p
                    .audit
                    .ok_or_else(|| hold("counter completion lacks native observations"))?;
                let sha = record_sha(&record)?;
                if !p.evaluated
                    || p.sha.as_ref() != Some(&sha)
                    || p.before != before
                    || head != before
                    || p.inferred_reused != Some(was_reused)
                    || record.scope != scope
                    || !proof(state.knowledge.active_at(&after))?
                        .iter()
                        .any(|r| r == &record)
                {
                    return Err(hold(
                        "counter completion artifact or causal native head differs",
                    ));
                }
                let origin = match &audit.incoming_artifact_sha256 {
                    Some(incoming) => {
                        if incoming != &sha {
                            return Err(hold(
                                "receiver origin does not bind the exact incoming artifact",
                            ));
                        }
                        LearningOrigin::ReceiverRole
                    }
                    None => {
                        if record.source != state.owner.identity() {
                            return Err(hold(
                                "ordinary promotion record is not owned by this engine",
                            ));
                        }
                        LearningOrigin::OrdinaryLearning
                    }
                };
                let role = origin.index();
                if was_reused {
                    if before != after {
                        return Err(hold("reuse cannot hide a native knowledge change"));
                    }
                    if position >= from.operational_events {
                        reused[role].insert(sha);
                    }
                } else {
                    if after.records != before.records + 1 {
                        return Err(hold(
                            "counter retention is not exactly one native promotion",
                        ));
                    }
                    let (promotion, evidence) = proof(
                        state
                            .knowledge
                            .promotion_evidence_between(&record, &before, &after),
                    )?;
                    if !all_promotions.insert(promotion.clone()) {
                        return Err(hold("one committed promotion was credited twice"));
                    }
                    if audit.training == 0
                        || audit.training >= audit.queries.len()
                        || audit.queries.iter().enumerate().any(|(i, q)| {
                            q.sequence != i
                                || record.predict_if_certified(q.input).ok().flatten()
                                    != Some(q.output)
                        })
                    {
                        return Err(hold(
                            "counter observation trace does not support retained model",
                        ));
                    }
                    if !evidence["cases"].as_array().is_some_and(|cases| {
                        !cases.is_empty()
                            && cases.iter().all(|c| {
                                audit.queries.iter().skip(audit.training).any(|q| {
                                    c["input"].as_u64() == Some(u64::from(q.input))
                                        && c["expected"].as_u64() == Some(u64::from(q.output))
                                })
                            })
                    }) {
                        return Err(hold("counter promotion cases lack independently recorded heldout observations"));
                    }
                    let validity = current(state, &audit, &record)?;
                    statuses.insert(promotion.clone(), validity);
                    promotion_sources.insert(promotion.clone(), audit.source.clone());
                    if position >= from.operational_events {
                        promotions[role].insert(promotion.clone());
                        retentions.push(RetentionStatus {
                            episode_id: episode,
                            origin,
                            artifact: record.id.clone(),
                            record_sha256: sha,
                            promotion_sha256: promotion,
                            before: before.clone(),
                            after: after.clone(),
                            source: audit.source,
                            current: validity,
                        });
                    }
                    head = after;
                }
            }
            journal::Entry::Failed {
                episode,
                knowledge_at,
                ..
            } => {
                let p = pending
                    .remove(&episode)
                    .ok_or_else(|| hold("counter failure lacks its episode"))?;
                if p.before != knowledge_at || head != knowledge_at {
                    return Err(hold("counter failed episode concealed a native commit"));
                }
            }
            journal::Entry::Revoked {
                artifact,
                before,
                after,
            } => {
                if before != head
                    || after.records != before.records + 1
                    || !proof(state.knowledge.active_at(&before))?
                        .iter()
                        .any(|r| r.id == artifact)
                    || proof(state.knowledge.active_at(&after))?
                        .iter()
                        .any(|r| r.id == artifact)
                {
                    return Err(hold("counter revocation is not its exact native change"));
                }
                head = after;
            }
            journal::Entry::Used {
                artifact,
                record_sha256,
                input,
                answer,
                knowledge_at,
            } => {
                let record = proof(state.knowledge.active_at(&knowledge_at))?
                    .into_iter()
                    .find(|r| r.id == artifact && r.digest().ok().as_ref() == Some(&record_sha256))
                    .ok_or_else(|| hold("counter use names no exact active native record"))?;
                let actual = match record.typed_payload().map_err(hold)? {
                    symbiote_memory::knowledge::KnowledgePayload::Affine { width, .. }
                        if input >= (1u16 << width) =>
                    {
                        None
                    }
                    _ => proof(record.predict_if_certified(input))?,
                };
                if actual != answer {
                    return Err(hold("counter actual use differs from native model"));
                }
            }
        }
        if position < from.operational_events {
            start_head = head.clone();
        }
    }
    if start_head != from.knowledge {
        return Err(hold(
            "counter start combines knowledge from another operational prefix",
        ));
    }
    if head != to.knowledge {
        return Err(hold(
            "native knowledge contains an unaccounted or unfinished promotion",
        ));
    }
    let index =
        crate::service::feedback::replay_index(&state.journal, &state.knowledge).map_err(hold)?;
    let mut terminal = BTreeMap::new();
    for (i, event) in state.journal.events().iter().enumerate() {
        if let OperationalEvent::PartnerDecisionRecorded { decision } = event {
            let f = &decision.details["event"];
            if decision.details["schema"] == crate::service::feedback::SCHEMA
                && matches!(f["phase"].as_str(), Some("outcome" | "rejected"))
            {
                let id = f["exchange_id"]
                    .as_str()
                    .ok_or_else(|| hold("outcome exchange absent"))?;
                if terminal.insert(id.to_string(), i).is_some() {
                    return Err(hold("counter outcome repeated"));
                }
            }
        }
    }
    let mut completed = [BTreeSet::new(), BTreeSet::new()];
    let mut capability = completed.clone();
    let mut measured = completed.clone();
    let mut active = completed.clone();
    let mut active_cap = completed.clone();
    let mut active_measured = completed.clone();
    let mut history = completed.clone();
    for ex in &index.experiences {
        let role = match ex.binding.origin {
            crate::service::feedback::DecisionOrigin::NativeLearningIntent => 0,
            crate::service::feedback::DecisionOrigin::ReceiverEvaluation => 1,
        };
        let id = &ex.binding.exchange_id;
        history[role].insert(id.clone());
        if *terminal
            .get(id)
            .ok_or_else(|| hold("validated outcome lacks actual terminal event"))?
            < from.operational_events
        {
            continue;
        }
        completed[role].insert(id.clone());
        if let crate::service::feedback::ExperienceProof::Promotion {
            promotion_sha256, ..
        } = &ex.proof
        {
            let expected_fixture=promotion_sources.get(promotion_sha256).map(|source|super::digest(&serde_json::json!({"schema":"symbiote.engine-independent-affine-evaluator/1","source":source,"receiver_policy_sha256":state.policy_sha256,"validation":"independent exact inference and disjoint validation"}))).transpose()?;
            let is_active = ex.currently_active
                && ex.binding.policy_sha256 == state.policy_sha256
                && expected_fixture.as_ref() == Some(&ex.binding.fixture_sha256)
                && statuses.get(promotion_sha256) == Some(&CurrentValidity::Active);
            if is_active {
                active[role].insert(id.clone());
            }
            let qualified = ex.outcome.quality
                == crate::service::feedback::Quality::CapabilityExtended
                && ex.outcome.uses > 0;
            if qualified {
                capability[role].insert(promotion_sha256.clone());
                if is_active {
                    active_cap[role].insert(promotion_sha256.clone());
                }
            }
            if qualified
                && ex.outcome.verified_benefit
                && ex.outcome.measured_net.is_some_and(|net| net > 0)
                && index.scoped_measurement_sha256(id).map_err(hold)?.is_some()
            {
                measured[role].insert(promotion_sha256.clone());
                if is_active {
                    active_measured[role].insert(promotion_sha256.clone());
                }
            }
        }
    }
    // The exchange module remains authoritative. These are only historical
    // records; without the actual receiver handle no remote truth/currentness
    // or measured capability gain is inferred from a snapshot's claimed fields.
    super::exchange::validate(state)?;
    let mut recorded = Vec::new();
    let mut historical_snapshots = BTreeSet::new();
    for (position, event) in state.journal.events().iter().enumerate() {
        let OperationalEvent::PartnerDecisionRecorded { decision } = event else {
            continue;
        };
        let f = &decision.details["event"];
        if decision.details["schema"] != super::exchange::SCHEMA || f["phase"] != "reconciled" {
            continue;
        }
        let ticket = &f["ticket"];
        let experience = &f["experience"];
        let receiver = ticket["receiver"]
            .as_str()
            .ok_or_else(|| hold("snapshot receiver absent"))?;
        if experience["proof"]["kind"] != "promotion" {
            return Err(hold("recorded reconciliation has no promotion coordinate"));
        }
        let promotion = experience["proof"]["promotion_sha256"]
            .as_str()
            .ok_or_else(|| hold("snapshot promotion absent"))?;
        let at: KnowledgeAnchor = serde_json::from_value(experience["proof"]["after"].clone())
            .map_err(|e| hold(e.to_string()))?;
        let receiver_knowledge: KnowledgeAnchor =
            serde_json::from_value(f["receiver_knowledge"].clone())
                .map_err(|e| hold(e.to_string()))?;
        if at.identity != receiver
            || receiver_knowledge.identity != receiver
            || at.records > receiver_knowledge.records
            || at.records == receiver_knowledge.records
                && at.head_sha256 != receiver_knowledge.head_sha256
            || !historical_snapshots.insert((
                receiver.to_string(),
                promotion.to_string(),
                at.head_sha256,
            ))
        {
            return Err(hold(
                "recorded promotion snapshot is duplicate or has mismatched knowledge coordinates",
            ));
        }
        if position < from.operational_events {
            continue;
        }
        let text = |value: &Value, key: &str| {
            value[key]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| hold(format!("snapshot {key} absent")))
        };
        recorded.push(RecordedReconciliation {
            exchange_id: text(ticket, "exchange_id")?,
            sender: text(ticket, "sender")?,
            receiver: receiver.into(),
            scope: text(ticket, "scope")?,
            record_sha256: text(ticket, "record_sha256")?,
            promotion_sha256: promotion.into(),
            receiver_knowledge,
            receiver_journal_sha256: text(f, "receiver_journal_sha256")?,
            experience_sha256: text(f, "experience_sha256")?,
            recorded_outcome: serde_json::from_value(experience["outcome"].clone())
                .map_err(|e| hold(e.to_string()))?,
            current_remote_validity: RemoteValidity::UnknownWithoutReceiver,
        });
    }
    let counts = RoleCounts::from_sets(&promotions);
    Ok(CounterReport{schema:"symbiote.engine-learning-counters/1",from,to,promotions:PromotionCounts{ordinary_learning:counts.ordinary_learning,receiver_role:counts.receiver_role,total_new:counts.total},reused_records:RoleCounts::from_sets(&reused),completed_outcomes:OutcomeCounts::local(&completed),capability_outcomes:OutcomeCounts::local(&capability),measured_benefits:OutcomeCounts::local(&measured),current_active_local:CurrentOutcomeSubsets{completed_outcomes:RoleCounts::from_sets(&active),capability_outcomes:RoleCounts::from_sets(&active_cap),measured_benefits:RoleCounts::from_sets(&active_measured)},durable_history_completed_outcomes:OutcomeCounts::local(&history),retentions,pending_episodes:pending.len(),partner_outcome_snapshots_recorded:recorded.len(),durable_history_partner_outcome_snapshots_recorded:historical_snapshots.len(),recorded_reconciliations:recorded,current_remote_validity:RemoteValidity::UnknownWithoutReceiver,partner_current_status:"historical peer snapshots only; current verification requires reconcile_local_transfer with the actual receiver handle"})
}
impl Engine {
    /// Inspect existing instance counters without additional filesystem activity.
    /// Identity-ledger setup and whole-process/OS resource accounting are separate.
    pub fn resources(&self) -> Result<ResourceReport> {
        let state = self.state()?;
        Ok(ResourceReport{schema:"symbiote.engine-resources/1",owner:state.owner.identity().into(),knowledge_anchor:state.knowledge.history_anchor(),knowledge_io:state.knowledge.io_diagnostics(),knowledge_capacity:state.knowledge.capacity(),operational_prefix_work:state.journal.prefix_work(),scope:"per-instance application bytes/work; overlapping categories, identity setup and whole-process CPU/peak memory separate"})
    }
    /// Capture an exact inert prefix for later counters_since. No event is appended.
    pub fn counter_anchor(&self) -> Result<CounterAnchor> {
        let state = self.state()?;
        Ok(CounterAnchor {
            knowledge: state.knowledge.history_anchor(),
            operational_events: state.journal.events().len(),
            operational_prefix_sha256: proof(
                state
                    .journal
                    .event_prefix_sha256(state.journal.events().len()),
            )?,
        })
    }
    /// Inspect the durable lifetime. Reopening preserves totals; it never increments them.
    pub fn counters(&self) -> Result<CounterReport> {
        let state = self.state()?;
        read_report(
            state,
            CounterAnchor {
                knowledge: genesis(&state.knowledge)?,
                operational_events: 0,
                operational_prefix_sha256: proof(state.journal.event_prefix_sha256(0))?,
            },
        )
    }
    /// Inspect commits in an exact validated prefix window. Capabilities/benefits
    /// remain historical; current_active_local is a separately evaluated subset.
    pub fn counters_since(&self, from: &CounterAnchor) -> Result<CounterReport> {
        read_report(self.state()?, from.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "symbiote-engine-counters-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    struct Source {
        descriptor: SourceDescriptor,
        calls: usize,
        offline: bool,
    }
    impl Source {
        fn new() -> Self {
            Self {
                descriptor: SourceDescriptor {
                    source_id: "counter-source".into(),
                    scope: "counter-scope/v1".into(),
                    epoch: "epoch-1".into(),
                    commitment: "11".repeat(32),
                    width: 3,
                },
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
            r: ObservationRequest<'_>,
        ) -> std::result::Result<Observation, SourceError> {
            if self.offline {
                return Err(SourceError::new(
                    ErrorKind::Storage,
                    "source deliberately offline",
                ));
            }
            assert_eq!(r.sequence, self.calls);
            self.calls += 1;
            Ok(Observation {
                input: r.input,
                output: ((r.input & 3).count_ones() % 2) as u8,
                sequence: r.sequence,
            })
        }
    }
    fn options(s: &Source) -> EpisodeOptions {
        let mut o = EpisodeOptions::bounded(s.descriptor.clone());
        o.query_policy = AffineQueryPolicy::RankBasis;
        o
    }
    #[test]
    fn facade_counter_windows_reconcile_real_roles_reuse_revocation_and_reopen() {
        let d = Directory::new();
        let mut source = Source::new();
        let cfg = EngineConfig::new(vec![source.descriptor.clone()]);
        let mut sink = NoopSink;
        let mut teacher = Engine::initialize(&d.0.join("teacher"), cfg.clone()).unwrap();
        let start = teacher.counter_anchor().unwrap();
        let opts = options(&source);
        let learned = teacher.run_episode(&mut source, &opts, &mut sink).unwrap();
        let resources = teacher.resources().unwrap();
        assert_eq!(resources.knowledge_io.publication_attempts, 2);
        assert!(
            resources.knowledge_io.committed_publication_bytes
                > resources.knowledge_capacity.used_ledger_bytes as u64
        );
        assert_eq!(resources.knowledge_io.cold_read_bytes, 0);
        assert_eq!(
            resources,
            teacher.resources().unwrap(),
            "resource inspection adds no I/O or work"
        );
        let fresh = teacher.counters_since(&start).unwrap();
        assert_eq!(
            fresh.promotions,
            PromotionCounts {
                ordinary_learning: 1,
                receiver_role: 0,
                total_new: 1
            }
        );
        assert_eq!(fresh, teacher.counters_since(&start).unwrap());
        let artifact = teacher.export_artifact(&learned.artifact).unwrap();
        let mut receiver_source = Source::new();
        let mut receiver = Engine::initialize(&d.0.join("receiver"), cfg.clone()).unwrap();
        let receiver_start = receiver.counter_anchor().unwrap();
        let opts = options(&receiver_source);
        let grant = teacher
            .authorize_local_exchange(&mut receiver, &artifact)
            .unwrap();
        let ticket = teacher
            .prepare_local_transfer(&mut receiver, &grant, &artifact)
            .unwrap();
        receiver
            .accept_local_transfer(&ticket, &artifact, &mut receiver_source, &opts, &mut sink)
            .unwrap();
        receiver.use_local_transfer(&ticket, 7).unwrap();
        receiver.complete_local_transfer(&ticket).unwrap();
        assert!(
            teacher
                .reconcile_local_transfer(&receiver, &ticket)
                .unwrap()
                .newly_reconciled
        );
        let recorded = teacher.counters().unwrap();
        assert_eq!(recorded.partner_outcome_snapshots_recorded, 1);
        assert_eq!(
            recorded.current_remote_validity,
            RemoteValidity::UnknownWithoutReceiver
        );
        assert_eq!(recorded.capability_outcomes.partner_receiver, 0);
        assert_eq!(recorded.measured_benefits.total, 0);
        let after_reply = teacher.counter_anchor().unwrap();
        assert!(
            !teacher
                .reconcile_local_transfer(&receiver, &ticket)
                .unwrap()
                .newly_reconciled
        );
        assert_eq!(
            teacher
                .counters_since(&after_reply)
                .unwrap()
                .partner_outcome_snapshots_recorded,
            0
        );
        let received = receiver.counters_since(&receiver_start).unwrap();
        assert_eq!(
            received.promotions,
            PromotionCounts {
                ordinary_learning: 0,
                receiver_role: 1,
                total_new: 1
            }
        );
        assert_eq!(received.retentions[0].current, CurrentValidity::Active);
        assert_eq!(
            received.capability_outcomes.total, 0,
            "retention alone is not a completed verified-use outcome"
        );
        let after = receiver.counter_anchor().unwrap();
        receiver_source.offline = true;
        let candidate = receiver
            .evaluate_artifact(&artifact, &mut receiver_source, &opts, &mut sink)
            .unwrap();
        assert!(receiver.retain(candidate, &mut sink).unwrap().reused);
        let reused = receiver.counters_since(&after).unwrap();
        assert_eq!(reused.promotions.total_new, 0);
        assert_eq!(reused.reused_records.receiver_role, 1);
        assert_eq!(receiver_source.calls, 5);
        receiver
            .revoke(&artifact.record.id, "controlled revocation", &mut sink)
            .unwrap();
        assert!(teacher
            .reconcile_local_transfer(&receiver, &ticket)
            .is_err());
        assert_eq!(
            teacher
                .counters()
                .unwrap()
                .durable_history_partner_outcome_snapshots_recorded,
            1,
            "old recorded snapshot survives revocation without claiming current remote validity"
        );
        let historical = receiver.counters().unwrap();
        assert_eq!(historical.promotions.receiver_role, 1);
        assert_eq!(
            historical.retentions[0].current,
            CurrentValidity::RevokedOrSuperseded
        );
        let closed = receiver.close().unwrap();
        let receiver = Engine::open(&closed.state, &closed.owner, cfg).unwrap();
        let cold_resources = receiver.resources().unwrap();
        assert!(cold_resources.knowledge_io.cold_read_bytes > 0);
        assert_eq!(cold_resources.knowledge_io.publication_attempts, 0);
        assert_eq!(receiver.counters().unwrap(), historical);
        assert_eq!(
            receiver
                .counters_since(&receiver.counter_anchor().unwrap())
                .unwrap()
                .promotions
                .total_new,
            0
        );
    }
    #[test]
    fn facade_counters_distinguish_current_authority_holds_and_reject_rehashed_fiction() {
        let d = Directory::new();
        let mut source = Source::new();
        let cfg = EngineConfig::new(vec![source.descriptor.clone()]);
        let mut sink = NoopSink;
        let mut engine = Engine::initialize(&d.0.join("owner"), cfg).unwrap();
        let opts = options(&source);
        engine.run_episode(&mut source, &opts, &mut sink).unwrap();
        let actual = engine.counters().unwrap();
        let mut false_anchor = engine.counter_anchor().unwrap();
        false_anchor.knowledge.head_sha256 = "55".repeat(32);
        assert_eq!(
            engine.counters_since(&false_anchor).unwrap_err().kind,
            ErrorKind::Hold
        );
        engine.state_mut().unwrap().config.authorized_sources[0].epoch = "changed".into();
        let stale = engine.counters().unwrap();
        assert_eq!(stale.promotions.total_new, 1);
        assert_eq!(
            stale.retentions[0].current,
            CurrentValidity::SourceEpochHold
        );
        engine.state_mut().unwrap().config.authorized_sources[0].epoch = "epoch-1".into();
        let policy = engine.state().unwrap().policy_sha256.clone();
        engine.state_mut().unwrap().policy_sha256 = "55".repeat(32);
        assert_eq!(
            engine.counters().unwrap().retentions[0].current,
            CurrentValidity::PolicyHold
        );
        engine.state_mut().unwrap().policy_sha256 = policy;
        assert_eq!(engine.counters().unwrap(), actual);
        // Native journal writer creates valid envelope/row hashes. They still cannot
        // invent an episode or promotion absent from the actual causal store history.
        let state = engine.state_mut().unwrap();
        let record = state.knowledge.active().pop().unwrap();
        let at = state.knowledge.history_anchor();
        journal::append(
            state,
            &source.descriptor.scope,
            journal::Entry::Finished {
                episode: "invented".into(),
                record,
                before: at.clone(),
                after: at,
                reused: true,
                usage: EpisodeUsage::default(),
            },
        )
        .unwrap();
        assert_eq!(engine.counters().unwrap_err().kind, ErrorKind::Hold);
    }
}
