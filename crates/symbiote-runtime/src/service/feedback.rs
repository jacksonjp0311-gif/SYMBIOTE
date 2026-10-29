//! Receiver-local causal feedback over existing operational and knowledge ledgers.
//! Hashes bind evidence; they do not authenticate arbitrary remote truth. Measured
//! baselines below must match an actual stored local assessment, whose trusted
//! evaluator assumption remains explicit. Unknown/estimated costs never verify gain.
use super::{
    config::Config,
    digest, label,
    wire::{Operation, Request},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;
use symbiote_memory::knowledge::{
    KnowledgeAnchor, KnowledgePayload, KnowledgeRecord, KnowledgeStore,
};
use symbiote_memory::operational::{OperationalEvent, OperationalJournal, PartnerDecisionRecord};

pub const SCHEMA: &str = "symbiote.learning-feedback/1";
const RECEIVER_DECISION: &str = "symbiote.receiver-evaluation-decision/1";
const LIMIT: u64 = 1_000_000_000;
const TASK_WINDOW: &str = "received-graph-task-sense-through-first-use/1";

/// Thread-local actual feedback validation work. These diagnostic counts do not
/// price hardware, change logical reasoning units, or establish learning gain.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ReplayWork {
    pub rebuilds: u64,
    pub event_visits: u64,
    pub store_use_prediction_rechecks: u64,
    pub reference_prefix_reads: u64,
    pub reference_prefix_event_visits: u64,
    pub reference_prefix_bytes: u64,
    pub single_pass_starts: u64,
    pub single_pass_finishes: u64,
    pub elapsed_ns: u64,
    pub saturated: bool,
}
thread_local! { static REPLAY_WORK: RefCell<ReplayWork> = RefCell::new(ReplayWork::default()); }
fn work(update: impl FnOnce(&mut ReplayWork)) {
    REPLAY_WORK.with(|current| update(&mut current.borrow_mut()));
}
fn add_count(target: &mut u64, amount: u64) -> bool {
    let overflow = target.checked_add(amount).is_none();
    *target = target.saturating_add(amount);
    overflow
}
struct ReplayTimer(Instant);
impl Drop for ReplayTimer {
    fn drop(&mut self) {
        work(|work| {
            work.saturated |= add_count(
                &mut work.elapsed_ns,
                self.0.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
            );
        });
    }
}
pub fn replay_work() -> ReplayWork {
    REPLAY_WORK.with(|current| current.borrow().clone())
}

/// Opaque, actually sampled native counters. Capture at SENSE entry and carry
/// only the unique artifact's acquisition; this is not a caller-supplied fee.
#[derive(Debug)]
pub struct LocalExecutionStart {
    scope: String,
    sender: String,
    boundary: SenseBoundary,
    execution: crate::graph_transfer::ExecutionMeter,
    forecast: u64,
}
pub fn capture_local_execution(
    journal: &OperationalJournal,
    scope: &str,
    sender_id: &str,
) -> Result<LocalExecutionStart, String> {
    if !label(scope) || !label(sender_id) {
        return Err("task window scope/peer invalid".into());
    }
    Ok(LocalExecutionStart {
        scope: scope.into(),
        sender: sender_id.into(),
        boundary: SenseBoundary {
            owner: journal.identity().into(),
            events: journal.events().len(),
            prefix_sha256: journal.event_prefix_sha256(journal.events().len())?,
        },
        execution: crate::graph_transfer::execution_snapshot(),
        forecast: symbiote_memory::knowledge::graph::forecast_work_units()?,
    })
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SenseBoundary {
    owner: String,
    events: usize,
    prefix_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MeterPoint {
    lookups: usize,
    provider_checks: u64,
    direct_model_work: u64,
    graph_forecast_work: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopedMeasurement {
    schema: String,
    scope: String,
    sender: String,
    boundary: SenseBoundary,
    evaluation_sha256: String,
    acquisition_sha256: String,
    before: MeterPoint,
    after: MeterPoint,
    lookups: Vec<crate::graph_transfer::Lookup>,
    baseline: Baseline,
    costs: CandidateCosts,
    private_control_audit_units: u64,
    accounting_boundary: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SenseAcquisition {
    schema: String,
    sense_decision_id: String,
    source_record_sha256: String,
    sent_bytes: u64,
    received_bytes: u64,
    unit_model: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Baseline {
    Measured { units: u64, evidence_sha256: String },
    Estimate { units: u64, basis: String },
    Unknown { reason: String },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateCosts {
    pub unit_model: String,
    pub acquisition: u64,
    pub validation: u64,
    pub adoption: u64,
    pub prediction: u64,
    pub wire: u64,
    pub replay: u64,
}
impl CandidateCosts {
    pub fn total(&self) -> Result<u64, String> {
        if !label(&self.unit_model) {
            return Err("feedback cost unit model is absent".into());
        }
        [
            self.acquisition,
            self.validation,
            self.adoption,
            self.prediction,
            self.wire,
            self.replay,
        ]
        .into_iter()
        .try_fold(0_u64, |sum, value| {
            sum.checked_add(value)
                .filter(|total| *total <= LIMIT)
                .ok_or_else(|| "feedback cost total exceeds its checked bound".into())
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub origin: DecisionOrigin,
    pub exchange_id: String,
    pub decision_id: String,
    pub sender_id: String,
    pub receiver_id: String,
    pub scope: String,
    pub schema_fingerprint: String,
    pub request_sha256: String,
    pub candidate_id: String,
    pub offered_record_sha256: String,
    pub policy_sha256: String,
    pub fixture_sha256: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOrigin {
    NativeLearningIntent,
    ReceiverEvaluation,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UseBasis {
    RetainedEvaluation { evidence_sha256: String },
    ConditionalFamily { family: String },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Quality {
    CapabilityExtended,
    CorrectOnRetainedCase,
    Rejected,
    Conditional,
    Unused,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Recommendation {
    Prefer,
    Defer,
    Explore,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub quality: Quality,
    pub baseline: Baseline,
    pub candidate_cost: Option<u64>,
    pub measured_net: Option<i64>,
    pub verified_benefit: bool,
    pub uses: usize,
    pub unit_model: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum Feedback {
    Decision {
        binding: Binding,
        before: KnowledgeAnchor,
        baseline: Baseline,
    },
    Promoted {
        exchange_id: String,
        record_sha256: String,
        before: KnowledgeAnchor,
        after: KnowledgeAnchor,
        evidence_sha256: String,
        promotion_sha256: String,
        costs: CandidateCosts,
        baseline: Baseline,
    },
    StoreUse {
        exchange_id: String,
        record_sha256: String,
        knowledge_at: KnowledgeAnchor,
        input: u16,
        output: u8,
        model_work: u64,
        sequence: usize,
        basis: UseBasis,
    },
    Outcome {
        exchange_id: String,
        knowledge_at: KnowledgeAnchor,
        outcome: Outcome,
    },
    Rejected {
        exchange_id: String,
        knowledge_at: KnowledgeAnchor,
        rejection_sha256: String,
        outcome: Outcome,
    },
    CostObservation {
        exchange_id: String,
        measurement: ScopedMeasurement,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    scope: String,
    event: Feedback,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverDecision {
    schema: String,
    phase: String,
    request: Request,
    candidate_id: String,
    knowledge_before: KnowledgeAnchor,
    service_policy_sha256: String,
    fixture_sha256: String,
}
#[derive(Clone)]
struct Promotion {
    record: KnowledgeRecord,
    before: KnowledgeAnchor,
    after: KnowledgeAnchor,
    evidence: Value,
    evidence_sha256: String,
    promotion_sha256: String,
    costs: CandidateCosts,
}
#[derive(Clone)]
struct Trace {
    binding: Binding,
    before: KnowledgeAnchor,
    decision_position: usize,
    baseline: Baseline,
    promotion: Option<Promotion>,
    uses: usize,
    correct_uses: usize,
    extended_uses: usize,
    uncertain_prior: bool,
    use_work: u64,
    outcome: Option<Outcome>,
    rejected: Option<(String, KnowledgeAnchor)>,
    task_measurement: Option<ScopedMeasurement>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Experience {
    pub binding: Binding,
    pub proof: ExperienceProof,
    pub outcome: Outcome,
    pub currently_active: bool,
    pub recommendation: Recommendation,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExperienceProof {
    Promotion {
        localized_record_sha256: String,
        promotion_sha256: String,
        before: KnowledgeAnchor,
        after: KnowledgeAnchor,
        evidence_sha256: String,
    },
    Rejected {
        rejection_sha256: String,
        knowledge_at: KnowledgeAnchor,
    },
}
#[derive(Default)]
pub struct FeedbackIndex {
    traces: BTreeMap<String, Trace>,
    pub experiences: Vec<Experience>,
}
impl FeedbackIndex {
    pub fn experience(&self, exchange_id: &str) -> Option<&Experience> {
        self.experiences
            .iter()
            .find(|experience| experience.binding.exchange_id == exchange_id)
    }
    /// Digest of the exact typed finite-window receipt, when one was recorded.
    /// The index is a snapshot; use `verified_scoped_benefit` for current credit.
    pub fn scoped_measurement_sha256(&self, exchange_id: &str) -> Result<Option<String>, String> {
        self.traces
            .get(exchange_id)
            .and_then(|trace| trace.task_measurement.as_ref())
            .map(|measurement| {
                digest(&serde_json::to_value(measurement).map_err(|e| e.to_string())?)
            })
            .transpose()
    }
}
/// Verify a scoped received-task benefit against the current receiver ledgers.
/// The expected exact decision/request/fixture binding and receipt SHA prevent
/// substituting an independently valid exchange. Costs are never caller supplied.
/// This is the declared finite native task window, not lifetime economic utility.
pub fn verified_scoped_benefit(
    journal: &OperationalJournal,
    store: &KnowledgeStore,
    expected_binding: &Binding,
    expected_measurement_sha256: &str,
) -> bool {
    let Ok(index) = replay_index(journal, store) else {
        return false;
    };
    let Some(experience) = index.experience(&expected_binding.exchange_id) else {
        return false;
    };
    experience.binding == *expected_binding
        && experience.currently_active
        && experience.outcome.verified_benefit
        && experience.outcome.quality == Quality::CapabilityExtended
        && experience.outcome.measured_net.is_some_and(|net| net > 0)
        && experience.outcome.unit_model.as_deref() == Some(TASK_WINDOW)
        && index
            .scoped_measurement_sha256(&expected_binding.exchange_id)
            .ok()
            .flatten()
            .as_deref()
            == Some(expected_measurement_sha256)
}
pub fn handles(event: &OperationalEvent) -> bool {
    matches!(event,OperationalEvent::PartnerDecisionRecorded{decision}
        if decision.details["schema"].as_str().is_some_and(|schema|schema.starts_with("symbiote.learning-feedback/")||schema.starts_with("symbiote.receiver-evaluation-decision/")))
}
fn decode(event: &OperationalEvent) -> Result<Option<Feedback>, String> {
    if !handles(event) {
        return Ok(None);
    }
    let OperationalEvent::PartnerDecisionRecorded { decision } = event else {
        unreachable!()
    };
    if decision.details["schema"]
        .as_str()
        .is_some_and(|schema| schema.starts_with("symbiote.receiver-evaluation-decision/"))
    {
        return Ok(None);
    }
    let envelope: Envelope = serde_json::from_value(decision.details.clone())
        .map_err(|_| "unsupported feedback fields or phase")?;
    if envelope.schema != SCHEMA {
        return Err("unsupported learning feedback version".into());
    }
    let exchange = match &envelope.event {
        Feedback::Decision { binding, .. } => &binding.exchange_id,
        Feedback::Promoted { exchange_id, .. }
        | Feedback::StoreUse { exchange_id, .. }
        | Feedback::Outcome { exchange_id, .. }
        | Feedback::Rejected { exchange_id, .. } => exchange_id,
        Feedback::CostObservation { exchange_id, .. } => exchange_id,
    };
    if decision.context != envelope.scope
        || decision.selected_peer.is_some()
        || decision.frontier_edge.is_some()
        || decision.decision_id != format!("feedback-{}", digest(&envelope)?)
        || !super::config::sha(exchange)
    {
        return Err("feedback carrier identity does not bind its exact typed body".into());
    }
    Ok(Some(envelope.event))
}
/// Validate the exact typed envelope and its carrier hash before a bounded
/// witness consumer inspects fields. This alone does not validate learning,
/// authority, promotion, use, current membership, or economic benefit.
pub(super) fn validate_carrier(event: &OperationalEvent) -> Result<(), String> {
    decode(event)?
        .ok_or_else(|| "event is not a typed feedback carrier".to_string())
        .map(|_| ())
}
fn carrier(event: Feedback, scope: &str) -> Result<OperationalEvent, String> {
    let envelope = Envelope {
        schema: SCHEMA.into(),
        scope: scope.into(),
        event,
    };
    Ok(OperationalEvent::PartnerDecisionRecorded {
        decision: PartnerDecisionRecord {
            decision_id: format!("feedback-{}", digest(&envelope)?),
            context: scope.into(),
            frontier_edge: None,
            selected_peer: None,
            details: serde_json::to_value(envelope).map_err(|error| error.to_string())?,
        },
    })
}
fn active_at(
    store: &KnowledgeStore,
    record: &KnowledgeRecord,
    at: &KnowledgeAnchor,
) -> Result<bool, String> {
    Ok(store.active_at(at)?.iter().any(|active| active == record))
}
fn original<'a>(
    events: &'a [OperationalEvent],
    id: &str,
) -> Result<&'a PartnerDecisionRecord, String> {
    events
        .iter()
        .find_map(|event| match event {
            OperationalEvent::PartnerDecisionRecorded { decision }
                if decision.decision_id == id =>
            {
                Some(decision)
            }
            _ => None,
        })
        .ok_or_else(|| "feedback has no prior actual learning decision".into())
}
fn receiver_decision(
    event: &OperationalEvent,
    prior: &[OperationalEvent],
    store: &KnowledgeStore,
) -> Result<bool, String> {
    let OperationalEvent::PartnerDecisionRecorded { decision } = event else {
        return Ok(false);
    };
    if !decision.details["schema"]
        .as_str()
        .is_some_and(|schema| schema.starts_with("symbiote.receiver-evaluation-decision/"))
    {
        return Ok(false);
    }
    let saved: ReceiverDecision = serde_json::from_value(decision.details.clone())
        .map_err(|_| "receiver decision fields rejected")?;
    let sender = decision
        .selected_peer
        .as_ref()
        .ok_or("receiver decision lacks authenticated sender")?;
    let request = serde_json::to_value(&saved.request).map_err(|error| error.to_string())?;
    let request_sha = digest(&request)?;
    store.validate_anchor(&saved.knowledge_before)?;
    if saved.schema!=RECEIVER_DECISION||saved.phase!="evaluate_received"||decision.context!=saved.request.scope||decision.frontier_edge.is_some()
        ||decision.decision_id!=format!("receiver-evaluate-{}",digest(&saved)?)||!super::config::sha(&saved.fixture_sha256)
        ||!super::config::sha(&saved.service_policy_sha256)||saved.request.body.name()!="candidate.submit"
        ||saved.candidate_id!=super::candidate_id_for(sender,&request_sha)?
        ||!prior.iter().any(|event|matches!(event,OperationalEvent::Quarantined{candidate_id,body_sha256,key,body,..}
            if candidate_id==&saved.candidate_id&&body_sha256==&request_sha&&body==&request&&key.peer_id==*sender&&key.scope==saved.request.scope)) {
        return Err("receiver evaluation decision lacks its exact earlier authenticated quarantine".into());
    }
    Ok(true)
}
fn validate_binding(
    binding: &Binding,
    before: &KnowledgeAnchor,
    events: &[OperationalEvent],
    store: &KnowledgeStore,
) -> Result<(), String> {
    for value in [
        &binding.exchange_id,
        &binding.schema_fingerprint,
        &binding.request_sha256,
        &binding.candidate_id,
        &binding.offered_record_sha256,
        &binding.policy_sha256,
        &binding.fixture_sha256,
    ] {
        if !super::config::sha(value) {
            return Err("feedback digest field is invalid".into());
        }
    }
    if !label(&binding.decision_id)
        || !label(&binding.sender_id)
        || !label(&binding.scope)
        || binding.receiver_id != store.identity()
        || binding.receiver_id == binding.sender_id
    {
        return Err("feedback participant/context binding is invalid".into());
    }
    store.validate_anchor(before)?;
    let decision = original(events, &binding.decision_id)?;
    let details = &decision.details;
    let request: Request = serde_json::from_value(details["request"].clone())
        .map_err(|_| "feedback decision has no exact submit request")?;
    let Operation::Submit { offer } = &request.body else {
        return Err("feedback decision is not a candidate submit".into());
    };
    let expected_candidate = super::candidate_id_for(&binding.sender_id, &binding.request_sha256)?;
    let origin_matches = match binding.origin {
        DecisionOrigin::NativeLearningIntent => {
            details["schema"] == "symbiote.cognition-decision/1" && details["phase"] == "learn"
        }
        DecisionOrigin::ReceiverEvaluation => {
            details["schema"] == RECEIVER_DECISION
                && details["phase"] == "evaluate_received"
                && details["fixture_sha256"] == binding.fixture_sha256
        }
    };
    if !origin_matches
        || request.schema != "symbiote.service-request/1"
        || decision.context != binding.scope
        || decision.selected_peer.as_ref() != Some(&binding.sender_id)
        || details["service_policy_sha256"] != binding.policy_sha256
        || details["knowledge_before"] != serde_json::to_value(before).map_err(|e| e.to_string())?
        || digest(&details["request"])? != binding.request_sha256
        || request.scope != binding.scope
        || offer.record.schema_fingerprint != binding.schema_fingerprint
        || offer.record.digest()? != binding.offered_record_sha256
        || expected_candidate != binding.candidate_id
        || details["candidate_id"] != binding.candidate_id
    {
        return Err("feedback is detached from its exact decision/request/artifact".into());
    }
    if binding.exchange_id != exchange_id(binding)? {
        return Err("feedback exchange identity changed".into());
    }
    Ok(())
}
fn exchange_id(binding: &Binding) -> Result<String, String> {
    digest(
        &json!({"decision":binding.decision_id,"sender":binding.sender_id,"receiver":binding.receiver_id,
        "request":binding.request_sha256,"candidate":binding.candidate_id,"scope":binding.scope,
        "schema":binding.schema_fingerprint,"policy":binding.policy_sha256,"fixture":binding.fixture_sha256}),
    )
}
pub fn binding_for(
    journal: &OperationalJournal,
    store: &KnowledgeStore,
    decision_id: &str,
    fixture_sha256: &str,
) -> Result<Binding, String> {
    let decision = original(journal.events(), decision_id)?;
    binding_from_decision(
        decision,
        store.identity(),
        journal.policy_digest(),
        fixture_sha256,
    )
}
fn binding_from_decision(
    decision: &PartnerDecisionRecord,
    receiver: &str,
    policy: &str,
    fixture_sha256: &str,
) -> Result<Binding, String> {
    let details = &decision.details;
    let request: Request = serde_json::from_value(details["request"].clone())
        .map_err(|_| "learning decision lacks submit request")?;
    let Operation::Submit { offer } = &request.body else {
        return Err("feedback only accepts submitted knowledge".into());
    };
    let sender = decision
        .selected_peer
        .clone()
        .ok_or("learning decision lacks actual sender")?;
    let request_sha256 = digest(&details["request"])?;
    let mut binding = Binding {
        origin: if details["schema"] == RECEIVER_DECISION {
            DecisionOrigin::ReceiverEvaluation
        } else {
            DecisionOrigin::NativeLearningIntent
        },
        exchange_id: String::new(),
        decision_id: decision.decision_id.clone(),
        sender_id: sender.clone(),
        receiver_id: receiver.into(),
        scope: request.scope.clone(),
        schema_fingerprint: offer.record.schema_fingerprint.clone(),
        candidate_id: super::candidate_id_for(&sender, &request_sha256)?,
        request_sha256,
        offered_record_sha256: offer.record.digest()?,
        policy_sha256: policy.into(),
        fixture_sha256: fixture_sha256.into(),
    };
    binding.exchange_id = exchange_id(&binding)?;
    Ok(binding)
}
fn validate_baseline(baseline: &Baseline) -> Result<(), String> {
    match baseline {
        Baseline::Measured {
            units,
            evidence_sha256,
        } if *units <= LIMIT && super::config::sha(evidence_sha256) => Ok(()),
        Baseline::Estimate { units, basis }
            if *units <= LIMIT && !basis.trim().is_empty() && basis.len() <= 1024 =>
        {
            Ok(())
        }
        Baseline::Unknown { reason } if !reason.trim().is_empty() && reason.len() <= 1024 => Ok(()),
        _ => Err("feedback baseline lacks bounded provenance".into()),
    }
}
fn prepared(
    events: &[OperationalEvent],
    binding: &Binding,
    decision_position: usize,
) -> Result<KnowledgeRecord, String> {
    let quarantine=events.iter().position(|event|matches!(event,OperationalEvent::Quarantined{candidate_id,body_sha256,key,..}
        if candidate_id==&binding.candidate_id&&body_sha256==&binding.request_sha256&&key.peer_id==binding.sender_id&&key.scope==binding.scope))
        .filter(|position|match binding.origin {DecisionOrigin::NativeLearningIntent=>*position>decision_position,DecisionOrigin::ReceiverEvaluation=>*position<decision_position})
        .ok_or("feedback has no later exact authenticated quarantined request")?;
    let preparation = events
        .iter()
        .enumerate()
        .find_map(|(position, event)| match event {
            OperationalEvent::EvaluationPrepared {
                candidate_id,
                record,
                fixture_sha256,
                ..
            } if candidate_id == &binding.candidate_id
                && fixture_sha256 == &binding.fixture_sha256
                && position > quarantine
                && position > decision_position =>
            {
                Some((position, record.clone()))
            }
            _ => None,
        })
        .ok_or("feedback has no later exact local evaluation intent")?;
    if !events.iter().enumerate().any(|(position,event)|matches!(event,OperationalEvent::EvaluationCompleted{candidate_id,record_sha256,response}
        if candidate_id==&binding.candidate_id&&position>preparation.0&&record_sha256==&preparation.1.digest().unwrap_or_default()
        &&response["promoted"]==true&&response["status"]=="PROMOTED")) {
        return Err("feedback requires completed fresh local promotion".into());
    }
    if preparation.1.source != binding.sender_id
        || preparation.1.scope != binding.scope
        || preparation.1.schema_fingerprint != binding.schema_fingerprint
    {
        return Err("localized record differs from the actual received context".into());
    }
    Ok(preparation.1)
}
fn cost_value(evidence: &Value, key: &str) -> Result<u64, String> {
    evidence["costs"][key]
        .as_u64()
        .filter(|value| *value <= LIMIT)
        .ok_or_else(|| "stored assessment cost is missing or invalid".into())
}
fn expected(evidence: &Value, input: u16) -> Option<u8> {
    evidence["cases"]
        .as_array()?
        .iter()
        .find(|case| case["input"].as_u64() == Some(u64::from(input)))?["expected"]
        .as_u64()
        .and_then(|value| u8::try_from(value).ok())
}
fn prediction(record: &KnowledgeRecord, input: u16) -> Result<(u8, u64), String> {
    let before = symbiote_memory::knowledge::graph::forecast_work_units()?;
    let output = record
        .predict_if_certified(input)?
        .ok_or("stored model abstains on this input")?;
    let work = match record.typed_payload()? {
        KnowledgePayload::Affine { .. } => 1,
        KnowledgePayload::GraphMap(_) => symbiote_memory::knowledge::graph::forecast_work_units()?
            .checked_sub(before)
            .ok_or("graph prediction counter regressed")?,
    };
    Ok((output, work))
}
/// None means mutually inconsistent earlier facts: never call that an extension.
fn earlier_coverage(
    records: &[KnowledgeRecord],
    record: &KnowledgeRecord,
    input: u16,
) -> Result<Option<bool>, String> {
    let compatible: Vec<_> = records
        .iter()
        .filter(|prior| {
            prior.scope == record.scope && prior.schema_fingerprint == record.schema_fingerprint
        })
        .collect();
    match record.typed_payload()? {
        KnowledgePayload::Affine { .. } => {
            for prior in compatible {
                if prior.predict_if_certified(input)?.is_some() {
                    return Ok(Some(true));
                }
            }
            Ok(Some(false))
        }
        KnowledgePayload::GraphMap(map) => {
            let mut observations = BTreeMap::new();
            for prior in compatible {
                let KnowledgePayload::GraphMap(prior) = prior.typed_payload()? else {
                    return Ok(None);
                };
                if prior.schema != map.schema {
                    return Ok(None);
                }
                for observation in prior.observations {
                    if observations
                        .insert(observation.edge_id, observation.cost)
                        .is_some_and(|old| old != observation.cost)
                    {
                        return Ok(None);
                    }
                }
            }
            let union =
                symbiote_memory::knowledge::graph::GraphMap::new(
                    map.schema,
                    observations
                        .into_iter()
                        .map(|(edge_id, cost)| {
                            symbiote_memory::knowledge::graph::GraphObservation { edge_id, cost }
                        })
                        .collect(),
                )?;
            Ok(Some(union.predict(input)?.is_some()))
        }
    }
}
fn meter_point(execution: &crate::graph_transfer::ExecutionMeter, forecast: u64) -> MeterPoint {
    MeterPoint {
        lookups: execution.lookups.len(),
        provider_checks: execution.provider_checks,
        direct_model_work: execution.direct_model_work,
        graph_forecast_work: forecast,
    }
}
fn delta(after: u64, before: u64) -> Result<u64, String> {
    after
        .checked_sub(before)
        .filter(|value| *value <= LIMIT)
        .ok_or_else(|| "task window counter regressed or exceeded its bound".into())
}
#[cfg(test)]
fn validate_sense_boundary(
    boundary: &SenseBoundary,
    events: &[OperationalEvent],
    binding: &Binding,
    sense_decision_id: &str,
) -> Result<(), String> {
    validate_sense_boundary_inner(boundary, events, binding, sense_decision_id, None)
}
fn validate_sense_boundary_inner(
    boundary: &SenseBoundary,
    events: &[OperationalEvent],
    binding: &Binding,
    sense_decision_id: &str,
    journal: Option<&OperationalJournal>,
) -> Result<(), String> {
    let prefix = events
        .get(..boundary.events)
        .ok_or("SENSE start prefix is absent")?;
    let prefix_sha256 = if let Some(journal) = journal {
        // Only private callers constructing replay from this actual journal (or
        // its exact committed prefix plus a proposed append) supply this source.
        // No external event slice or deserialized cache can choose a witness.
        journal.event_prefix_sha256(boundary.events)?
    } else {
        let value = serde_json::to_value(prefix).map_err(|error| error.to_string())?;
        let bytes = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
        work(|work| {
            work.saturated |= add_count(&mut work.reference_prefix_reads, 1);
            work.saturated |=
                add_count(&mut work.reference_prefix_event_visits, prefix.len() as u64);
            work.saturated |= add_count(&mut work.reference_prefix_bytes, bytes.len() as u64);
        });
        format!("{:x}", Sha256::digest(&bytes))
    };
    if boundary.owner != binding.receiver_id
        || prefix_sha256 != boundary.prefix_sha256
        || !matches!(events.get(boundary.events), Some(OperationalEvent::PartnerDecisionRecorded { decision })
            if decision.decision_id == sense_decision_id
                && decision.context == binding.scope
                && decision.selected_peer.as_deref() == Some(binding.sender_id.as_str())
                && decision.details["schema"] == "symbiote.cognition-decision/1"
                && decision.details["phase"] == "sense")
    {
        return Err(
            "task start was not captured immediately before its exact SENSE decision".into(),
        );
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn scoped_measurement(
    trace: &Trace,
    events: &[OperationalEvent],
    scope: String,
    sender: String,
    boundary: SenseBoundary,
    before: MeterPoint,
    after: MeterPoint,
    lookups: Vec<crate::graph_transfer::Lookup>,
    journal: Option<&OperationalJournal>,
) -> Result<ScopedMeasurement, String> {
    if scope != trace.binding.scope
        || sender != trace.binding.sender_id
        || trace.binding.origin != DecisionOrigin::NativeLearningIntent
        || trace.uses != 1
        || trace.outcome.is_some()
    {
        return Err("scoped task cost requires one actual native received-task use".into());
    }
    let promotion = trace
        .promotion
        .as_ref()
        .ok_or("task cost has no exact local promotion")?;
    let decision = original(events, &trace.binding.decision_id)?;
    let acquisition: SenseAcquisition =
        serde_json::from_value(decision.details["acquisition"].clone())
            .map_err(|_| "task cost lacks unique actual acquisition witness")?;
    validate_sense_boundary_inner(
        &boundary,
        events,
        &trace.binding,
        &acquisition.sense_decision_id,
        journal,
    )?;
    let sense = original(events, &acquisition.sense_decision_id)?;
    let wire = acquisition
        .sent_bytes
        .checked_add(acquisition.received_bytes)
        .filter(|value| *value <= LIMIT)
        .ok_or("task wire fee exceeds bound")?;
    let sense_position=events.iter().position(|event|matches!(event,OperationalEvent::PartnerDecisionRecorded{decision:saved} if saved.decision_id==acquisition.sense_decision_id)).ok_or("sense boundary absent")?;
    let learn_position=events.iter().position(|event|matches!(event,OperationalEvent::PartnerDecisionRecorded{decision:saved} if saved.decision_id==trace.binding.decision_id)).ok_or("learn boundary absent")?;
    if acquisition.schema!="symbiote.sense-acquisition/1"||acquisition.unit_model!="application-plaintext-bytes/1"
        ||acquisition.source_record_sha256!=trace.binding.offered_record_sha256||sense_position>=learn_position
        ||sense.context!=scope||sense.selected_peer.as_ref()!=Some(&sender)||sense.details["schema"]!="symbiote.cognition-decision/1"||sense.details["phase"]!="sense"
        ||!events[sense_position+1..learn_position].iter().any(|event|matches!(event,OperationalEvent::PartnerOutcomeRecorded{outcome}
            if outcome.interaction_id==acquisition.sense_decision_id&&outcome.peer_id==sender&&outcome.scope==scope
            &&outcome.kind==symbiote_memory::operational::PartnerOutcomeKind::Received
            &&outcome.receipt_sha256.as_deref()==Some(trace.binding.offered_record_sha256.as_str())
            &&outcome.resource_units==acquisition.sent_bytes.div_ceil(1024)+acquisition.received_bytes.div_ceil(1024))) {
        return Err("task wire fee is not the earlier exact one-offer SENSE outcome".into());
    }
    let evaluation = events
        .iter()
        .find_map(|event| match event {
            OperationalEvent::EvaluationCompleted {
                candidate_id,
                response,
                ..
            } if candidate_id == &trace.binding.candidate_id => response.get("evaluation_record"),
            _ => None,
        })
        .ok_or("task control lacks actual local evaluation record")?;
    if evaluation["schema"] != "symbiote.scoped-evaluation/1" {
        return Err("task evaluation schema unsupported".into());
    }
    let price = evaluation["oracle_price"]
        .as_u64()
        .filter(|price| [1, 100_000].contains(price))
        .ok_or("task oracle price unsupported")?;
    let candidate: crate::graph_transfer::Measurement =
        serde_json::from_value(evaluation["candidate_measurement"].clone())
            .map_err(|_| "candidate task measurement rejected")?;
    let isolated: crate::graph_transfer::Measurement =
        serde_json::from_value(evaluation["measured_task_baseline"]["measurement"].clone())
            .map_err(|_| "isolated task measurement rejected")?;
    let baseline_units = isolated.units(price)?;
    let baseline_sha =
        digest(&serde_json::to_value(&isolated).map_err(|error| error.to_string())?)?;
    if !candidate.complete
        || !isolated.complete
        || candidate.predictions.len() != 1
        || candidate.predictions != isolated.predictions
        || evaluation["measured_task_baseline"]["units"].as_u64() != Some(baseline_units)
        || evaluation["measured_task_baseline"]["evidence_sha256"] != baseline_sha
    {
        return Err("task baseline was not the exact complete independent control".into());
    }
    for (input, output) in &candidate.predictions {
        if expected(&promotion.evidence, *input).map(u64::from) != Some(*output) {
            return Err("task control addresses another evaluated behavior".into());
        }
    }
    let KnowledgePayload::GraphMap(map) = promotion.record.typed_payload()? else {
        return Err("scoped task measurement only supports exact graph knowledge".into());
    };
    if candidate.lookups.len() != map.observations.len()
        || candidate.provider_checks != map.schema.edges.len() as u64
        || isolated.provider_checks != candidate.provider_checks
    {
        return Err("task provider/candidate lookup count differs from actual topology".into());
    }
    for (sequence, (lookup, observation)) in
        candidate.lookups.iter().zip(&map.observations).enumerate()
    {
        if lookup.sequence != sequence
            || lookup.edge_id != observation.edge_id
            || lookup.cost != observation.cost
        {
            return Err("task candidate lookup differs from the promoted checked fact".into());
        }
    }
    let provider = candidate
        .lookups
        .first()
        .ok_or("candidate has no actual provider lookup")?
        .provider_sha256
        .as_str();
    let mut unique = BTreeSet::new();
    for (sequence, lookup) in isolated.lookups.iter().enumerate() {
        let edge = map
            .schema
            .edges
            .get(lookup.edge_id)
            .ok_or("control queried an absent edge")?;
        if lookup.sequence != sequence
            || !unique.insert(lookup.edge_id)
            || lookup.provider_sha256 != provider
            || lookup.cost < edge.lower
            || lookup.cost > edge.upper
        {
            return Err("control trace has repeated/foreign/out-of-domain oracle evidence".into());
        }
    }
    let mut exact_lookups = candidate.lookups.clone();
    exact_lookups.extend(isolated.lookups.clone());
    let count = after
        .lookups
        .checked_sub(before.lookups)
        .ok_or("task lookup counter regressed")?;
    let direct = delta(after.direct_model_work, before.direct_model_work)?;
    let providers = delta(after.provider_checks, before.provider_checks)?;
    let forecast = delta(after.graph_forecast_work, before.graph_forecast_work)?;
    if lookups != exact_lookups
        || count != lookups.len()
        || count > 112
        || direct
            != candidate
                .model_work
                .checked_add(isolated.model_work)
                .ok_or("task direct work overflow")?
        || providers
            != candidate
                .provider_checks
                .checked_add(isolated.provider_checks)
                .ok_or("task provider work overflow")?
        || forecast < trace.use_work
    {
        return Err(
            "native task meter is not exactly this candidate plus its separately charged control"
                .into(),
        );
    }
    let validation = candidate.units(price)?;
    let costs = CandidateCosts {
        unit_model: TASK_WINDOW.into(),
        acquisition: 0,
        validation,
        adoption: cost_value(&promotion.evidence, "adoption")?,
        prediction: trace.use_work,
        wire,
        replay: forecast - trace.use_work,
    };
    costs.total()?;
    Ok(ScopedMeasurement{schema:"symbiote.received-task-cost/1".into(),scope,sender,boundary,evaluation_sha256:digest(evaluation)?,
        acquisition_sha256:digest(&decision.details["acquisition"])?,before,after,lookups,
        baseline:Baseline::Measured{units:baseline_units,evidence_sha256:baseline_sha},costs,private_control_audit_units:baseline_units,
        accounting_boundary:"actual SENSE entry through first retained-task use; weighted local oracle queries, exact graph work, adoption unit and witnessed plaintext bytes; private control execution and later closure/audit are retained in whole-process totals, not lifetime profit".into()})
}
fn derive(trace: &Trace, store: &KnowledgeStore, at: &KnowledgeAnchor) -> Result<Outcome, String> {
    let promotion = trace
        .promotion
        .as_ref()
        .ok_or("feedback outcome has no promotion")?;
    let candidate_cost = if let Some(measured) = &trace.task_measurement {
        measured.costs.total()?
    } else {
        promotion
            .costs
            .total()?
            .checked_add(trace.use_work)
            .filter(|value| *value <= LIMIT)
            .ok_or("feedback use cost overflow")?
    };
    let baseline = trace
        .task_measurement
        .as_ref()
        .map_or(&trace.baseline, |measured| &measured.baseline);
    let measured_net = match baseline {
        Baseline::Measured { units, .. } => Some(
            i64::try_from(*units).map_err(|_| "baseline cost out of range")?
                - i64::try_from(candidate_cost).map_err(|_| "candidate cost out of range")?,
        ),
        _ => None,
    };
    let quality = if trace.uses == 0 {
        Quality::Unused
    } else if trace.uncertain_prior {
        Quality::Conditional
    } else if trace.uses == trace.correct_uses && trace.extended_uses > 0 {
        Quality::CapabilityExtended
    } else if trace.uses == trace.correct_uses {
        Quality::CorrectOnRetainedCase
    } else {
        Quality::Conditional
    };
    Ok(Outcome {
        verified_benefit: (if trace.task_measurement.is_some() {
            quality == Quality::CapabilityExtended
        } else {
            matches!(
                quality,
                Quality::CorrectOnRetainedCase | Quality::CapabilityExtended
            )
        }) && measured_net.is_some_and(|net| net > 0)
            && active_at(store, &promotion.record, at)?,
        quality,
        baseline: baseline.clone(),
        candidate_cost: Some(candidate_cost),
        measured_net,
        uses: trace.uses,
        unit_model: Some(
            trace
                .task_measurement
                .as_ref()
                .map_or(&promotion.costs.unit_model, |measured| {
                    &measured.costs.unit_model
                })
                .clone(),
        ),
    })
}
fn rebuild(events: &[OperationalEvent], store: &KnowledgeStore) -> Result<FeedbackIndex, String> {
    rebuild_inner(events, store, None)
}
fn rebuild_inner(
    events: &[OperationalEvent],
    store: &KnowledgeStore,
    journal: Option<&OperationalJournal>,
) -> Result<FeedbackIndex, String> {
    let _timer = ReplayTimer(Instant::now());
    work(|work| work.saturated |= add_count(&mut work.rebuilds, 1));
    let mut index = FeedbackIndex::default();
    let mut credited = BTreeSet::new();
    for (position, event) in events.iter().enumerate() {
        apply_feedback_event(
            &mut index,
            &mut credited,
            position,
            event,
            events,
            store,
            journal,
        )?;
    }
    finish_index(index, store)
}
fn rechecked_prediction(record: &KnowledgeRecord, input: u16) -> Result<(u8, u64), String> {
    work(|work| work.saturated |= add_count(&mut work.store_use_prediction_rechecks, 1));
    prediction(record, input)
}
fn apply_feedback_event(
    index: &mut FeedbackIndex,
    credited: &mut BTreeSet<String>,
    position: usize,
    event: &OperationalEvent,
    events: &[OperationalEvent],
    store: &KnowledgeStore,
    journal: Option<&OperationalJournal>,
) -> Result<(), String> {
    work(|work| work.saturated |= add_count(&mut work.event_visits, 1));
    if receiver_decision(event, &events[..position], store)? {
        return Ok(());
    }
    let Some(event) = decode(event)? else {
        return Ok(());
    };
    match event {
        Feedback::Decision {
            binding,
            before,
            baseline,
        } => {
            validate_binding(&binding, &before, &events[..position], store)?;
            validate_baseline(&baseline)?;
            if index.traces.contains_key(&binding.exchange_id)
                || index
                    .traces
                    .values()
                    .any(|trace| trace.binding.candidate_id == binding.candidate_id)
            {
                return Err("duplicate feedback decision/candidate credit".into());
            }
            index.traces.insert(
                binding.exchange_id.clone(),
                Trace {
                    binding,
                    before,
                    decision_position: position,
                    baseline,
                    promotion: None,
                    uses: 0,
                    correct_uses: 0,
                    extended_uses: 0,
                    uncertain_prior: false,
                    use_work: 0,
                    outcome: None,
                    rejected: None,
                    task_measurement: None,
                },
            );
        }
        Feedback::Promoted {
            exchange_id,
            record_sha256,
            before,
            after,
            evidence_sha256,
            promotion_sha256,
            costs,
            baseline,
        } => {
            let trace = index
                .traces
                .get_mut(&exchange_id)
                .ok_or("promotion lacks prior feedback decision")?;
            let record = prepared(&events[..position], &trace.binding, trace.decision_position)?;
            let (promotion, evidence) =
                store.promotion_evidence_between(&record, &before, &after)?;
            let original = original(&events[..position], &trace.binding.decision_id)?;
            let request: Request = serde_json::from_value(original.details["request"].clone())
                .map_err(|_| "original request changed")?;
            let Operation::Submit { offer } = request.body else {
                unreachable!()
            };
            if trace.promotion.is_some()
                || before != trace.before
                || record.digest()? != record_sha256
                || record.payload != offer.record.payload
                || promotion != promotion_sha256
                || digest(&evidence)? != evidence_sha256
                || !credited.insert(promotion.clone())
            {
                return Err("feedback promotion was swapped, replayed or credited twice".into());
            }
            if costs.total()? != cost_value(&evidence, "candidate")?
                || costs.acquisition != cost_value(&evidence, "acquisition")?
                || costs.validation != cost_value(&evidence, "verification")?
                || costs.adoption != cost_value(&evidence, "adoption")?
            {
                return Err("feedback costs differ from original stored evaluation".into());
            }
            validate_baseline(&baseline)?;
            if baseline != trace.baseline {
                let recorded = events[..position]
                    .iter()
                    .find_map(|event| match event {
                        OperationalEvent::EvaluationCompleted {
                            candidate_id,
                            response,
                            ..
                        } if candidate_id == &trace.binding.candidate_id => {
                            response.get("feedback_baseline")
                        }
                        _ => None,
                    })
                    .ok_or("changed baseline has no actual typed evaluation measurement")?;
                if serde_json::from_value::<Baseline>(recorded.clone())
                    .map_err(|_| "typed evaluation baseline rejected")?
                    != baseline
                {
                    return Err(
                        "feedback baseline changed independently of its actual evaluation".into(),
                    );
                }
                trace.baseline = baseline;
            }
            if let Baseline::Measured {
                units,
                evidence_sha256: baseline_sha,
            } = &trace.baseline
            {
                if *units != cost_value(&evidence, "baseline")? || baseline_sha != &evidence_sha256
                {
                    return Err(
                        "measured baseline is not the exact stored evaluation evidence".into(),
                    );
                }
            }
            trace.promotion = Some(Promotion {
                record,
                before,
                after,
                evidence,
                evidence_sha256,
                promotion_sha256: promotion,
                costs,
            });
        }
        Feedback::StoreUse {
            exchange_id,
            record_sha256,
            knowledge_at,
            input,
            output,
            model_work,
            sequence,
            basis,
        } => {
            let trace = index
                .traces
                .get_mut(&exchange_id)
                .ok_or("model use lacks prior feedback decision")?;
            let promotion = trace
                .promotion
                .as_ref()
                .ok_or("model use precedes local promotion")?;
            if trace.outcome.is_some()
                || sequence != trace.uses
                || record_sha256 != promotion.record.digest()?
                || knowledge_at.records < promotion.after.records
                || !active_at(store, &promotion.record, &knowledge_at)?
                || rechecked_prediction(&promotion.record, input)? != (output, model_work)
            {
                return Err(
                    "model use is inactive, mismatched, replayed or not its actual prediction"
                        .into(),
                );
            }
            let correct = expected(&promotion.evidence, input) == Some(output);
            let exact_basis = if correct {
                UseBasis::RetainedEvaluation {
                    evidence_sha256: promotion.evidence_sha256.clone(),
                }
            } else {
                UseBasis::ConditionalFamily {
                    family: "declared finite knowledge family".into(),
                }
            };
            if basis != exact_basis {
                return Err("model use correctness basis is unsupported".into());
            }
            trace.use_work = trace
                .use_work
                .checked_add(model_work)
                .filter(|value| *value <= LIMIT)
                .ok_or("model use work overflow")?;
            trace.uses += 1;
            trace.correct_uses += usize::from(correct);
            if correct {
                let coverage =
                    earlier_coverage(&store.active_at(&trace.before)?, &promotion.record, input)?;
                trace.extended_uses += usize::from(coverage == Some(false));
                trace.uncertain_prior |= coverage.is_none();
            }
        }
        Feedback::Outcome {
            exchange_id,
            knowledge_at,
            outcome,
        } => {
            let trace = index
                .traces
                .get_mut(&exchange_id)
                .ok_or("outcome lacks its decision")?;
            if trace.outcome.is_some() || derive(trace, store, &knowledge_at)? != outcome {
                return Err("feedback outcome is fabricated or duplicated".into());
            }
            trace.outcome = Some(outcome);
        }
        Feedback::Rejected {
            exchange_id,
            knowledge_at,
            rejection_sha256,
            outcome,
        } => {
            let trace = index
                .traces
                .get_mut(&exchange_id)
                .ok_or("rejection lacks its earlier feedback decision")?;
            store.validate_anchor(&knowledge_at)?;
            let rejection = events[..position]
                .iter()
                .enumerate()
                .find(|(index, event)| {
                    matches!(event,OperationalEvent::EvaluationRejected{candidate_id,..}
                if candidate_id==&trace.binding.candidate_id)
                        && *index > trace.decision_position
                })
                .map(|(_, event)| event)
                .ok_or("feedback rejection lacks a later actual evaluator rejection")?;
            if trace.promotion.is_some()
                || trace.outcome.is_some()
                || trace.uses != 0
                || digest(&serde_json::to_value(rejection).map_err(|e| e.to_string())?)?
                    != rejection_sha256
                || outcome != rejected_outcome(&trace.baseline)
            {
                return Err("rejection feedback is fabricated or credited twice".into());
            }
            trace.rejected = Some((rejection_sha256, knowledge_at));
            trace.outcome = Some(outcome);
        }
        Feedback::CostObservation {
            exchange_id,
            measurement,
        } => {
            let trace = index
                .traces
                .get_mut(&exchange_id)
                .ok_or("cost observation has no prior exchange")?;
            if trace.task_measurement.is_some() {
                return Err(
                    "task measurement cannot be replayed or superseded after opening".into(),
                );
            }
            let expected = scoped_measurement(
                trace,
                &events[..position],
                measurement.scope.clone(),
                measurement.sender.clone(),
                measurement.boundary.clone(),
                measurement.before.clone(),
                measurement.after.clone(),
                measurement.lookups.clone(),
                journal,
            )?;
            if expected != measurement {
                return Err(
                    "scoped task costs differ from actual bound meter/control/wire receipts".into(),
                );
            }
            trace.task_measurement = Some(measurement);
        }
    }
    Ok(())
}
fn finish_index(mut index: FeedbackIndex, store: &KnowledgeStore) -> Result<FeedbackIndex, String> {
    for trace in index.traces.values() {
        if let (Some(promotion), Some(outcome)) = (&trace.promotion, &trace.outcome) {
            let current = store
                .active()
                .iter()
                .any(|record| record == &promotion.record);
            let recommendation = recommend(outcome, current);
            index.experiences.push(Experience {
                binding: trace.binding.clone(),
                proof: ExperienceProof::Promotion {
                    localized_record_sha256: promotion.record.digest()?,
                    promotion_sha256: promotion.promotion_sha256.clone(),
                    before: promotion.before.clone(),
                    after: promotion.after.clone(),
                    evidence_sha256: promotion.evidence_sha256.clone(),
                },
                outcome: outcome.clone(),
                currently_active: current,
                recommendation,
            });
        } else if let (Some((rejection, at)), Some(outcome)) = (&trace.rejected, &trace.outcome) {
            index.experiences.push(Experience {
                binding: trace.binding.clone(),
                proof: ExperienceProof::Rejected {
                    rejection_sha256: rejection.clone(),
                    knowledge_at: at.clone(),
                },
                outcome: outcome.clone(),
                currently_active: false,
                recommendation: Recommendation::Defer,
            });
        }
    }
    Ok(index)
}

fn recommend(outcome: &Outcome, active: bool) -> Recommendation {
    if !active
        || outcome.quality == Quality::Rejected
        || outcome.measured_net.is_some_and(|net| net <= 0)
    {
        Recommendation::Defer
    } else if outcome.verified_benefit || outcome.quality == Quality::CapabilityExtended {
        Recommendation::Prefer
    } else {
        Recommendation::Explore
    }
}
fn rejected_outcome(baseline: &Baseline) -> Outcome {
    Outcome {
        quality: Quality::Rejected,
        baseline: baseline.clone(),
        candidate_cost: None,
        measured_net: None,
        verified_benefit: false,
        uses: 0,
        unit_model: None,
    }
}
pub fn replay_index(
    journal: &OperationalJournal,
    store: &KnowledgeStore,
) -> Result<FeedbackIndex, String> {
    if journal.identity() != store.identity() {
        return Err("feedback journal belongs to another knowledge owner".into());
    }
    rebuild_inner(journal.events(), store, Some(journal))
}
/// Retained full-prefix calculation for exact regression/profiling comparisons.
/// It checks the same evidence and intentionally bypasses the derived index.
pub fn replay_index_reference(
    journal: &OperationalJournal,
    store: &KnowledgeStore,
) -> Result<FeedbackIndex, String> {
    if journal.identity() != store.identity() {
        return Err("feedback journal belongs to another knowledge owner".into());
    }
    rebuild(journal.events(), store)
}
pub fn pending_use(
    journal: &OperationalJournal,
    store: &KnowledgeStore,
    record_sha256: &str,
) -> Result<Option<String>, String> {
    if journal.identity() != store.identity() {
        return Err("feedback journal owner changed".into());
    }
    let mut pending = None;
    for event in journal.events() {
        match decode(event)? {
            Some(Feedback::Promoted {
                exchange_id,
                record_sha256: record,
                ..
            }) if record == record_sha256 => pending = Some(exchange_id),
            Some(
                Feedback::Outcome { exchange_id, .. } | Feedback::Rejected { exchange_id, .. },
            ) if pending.as_ref() == Some(&exchange_id) => pending = None,
            _ => {}
        }
    }
    Ok(pending)
}
/// Conservative admission for the bounded validation passes used by first-use
/// attribution. Actual graph replay remains visible in the native graph meter.
pub fn use_work_quote(
    journal: &OperationalJournal,
    store: &KnowledgeStore,
) -> Result<usize, String> {
    let mut uses = 0_usize;
    for event in journal.events() {
        if matches!(decode(event)?, Some(Feedback::StoreUse { .. })) {
            uses += 1;
        }
    }
    uses.checked_add(1)
        .and_then(|count| count.checked_mul(store.record_count() + 1))
        .and_then(|count| count.checked_mul(6 * 1024))
        .ok_or_else(|| "feedback replay work quote overflow".into())
}
/// Historical profile reconstruction must not import a later revocation or
/// promotion into the knowledge head saved by an earlier decision.
pub(super) fn replay_prefix(
    events: &[OperationalEvent],
    store: &KnowledgeStore,
    at: &KnowledgeAnchor,
) -> Result<FeedbackIndex, String> {
    let mut index = rebuild(events, store)?;
    let active = store.active_at(at)?;
    for trace in index.traces.values() {
        if trace.before.records > at.records
            || trace
                .promotion
                .as_ref()
                .is_some_and(|promotion| promotion.after.records > at.records)
        {
            return Err("feedback prefix uses future knowledge".into());
        }
    }
    for experience in &mut index.experiences {
        experience.currently_active = match &experience.proof {
            ExperienceProof::Promotion {
                localized_record_sha256,
                ..
            } => active
                .iter()
                .any(|record| record.digest().ok().as_ref() == Some(localized_record_sha256)),
            _ => false,
        };
        experience.recommendation = recommend(&experience.outcome, experience.currently_active);
    }
    Ok(index)
}
fn append(
    journal: &mut OperationalJournal,
    store: &KnowledgeStore,
    event: Feedback,
    scope: &str,
) -> Result<(), String> {
    let event = carrier(event, scope)?;
    let mut events = journal.events().to_vec();
    events.push(event.clone());
    rebuild_inner(&events, store, Some(journal))?;
    journal.append(event)
}
pub fn begin(
    journal: &mut OperationalJournal,
    store: &KnowledgeStore,
    binding: Binding,
    baseline: Baseline,
) -> Result<String, String> {
    let prior = replay_index(journal, store)?;
    if let Some(trace) = prior
        .traces
        .values()
        .find(|trace| trace.binding.candidate_id == binding.candidate_id)
    {
        if trace.binding.request_sha256 != binding.request_sha256
            || trace.binding.sender_id != binding.sender_id
            || trace.binding.policy_sha256 != binding.policy_sha256
            || trace.binding.fixture_sha256 != binding.fixture_sha256
        {
            return Err(
                "cached feedback candidate belongs to another request or authority epoch".into(),
            );
        }
        return Ok(trace.binding.exchange_id.clone());
    }
    let id = binding.exchange_id.clone();
    let scope = binding.scope.clone();
    append(
        journal,
        store,
        Feedback::Decision {
            binding,
            before: store.history_anchor(),
            baseline,
        },
        &scope,
    )?;
    Ok(id)
}
/// Explicit receiver decision to evaluate an already authenticated quarantine.
/// This origin does not claim to witness a remote sender's earlier plan.
pub fn begin_evaluation(
    journal: &mut OperationalJournal,
    store: &KnowledgeStore,
    candidate: &str,
    fixture_sha256: &str,
) -> Result<String, String> {
    let index = replay_index(journal, store)?;
    if let Some(trace) = index
        .traces
        .values()
        .find(|trace| trace.binding.candidate_id == candidate)
    {
        if trace.binding.fixture_sha256 != fixture_sha256
            || trace.binding.policy_sha256 != journal.policy_digest()
        {
            return Err("pending feedback authority changed before evaluation".into());
        }
        return Ok(trace.binding.exchange_id.clone());
    }
    let (sender, request) = journal
        .events()
        .iter()
        .find_map(|event| match event {
            OperationalEvent::Quarantined {
                candidate_id,
                key,
                body,
                ..
            } if candidate_id == candidate => Some((key.peer_id.clone(), body.clone())),
            _ => None,
        })
        .ok_or("receiver evaluation has no authenticated quarantine")?;
    let request: Request =
        serde_json::from_value(request).map_err(|_| "receiver quarantine request rejected")?;
    let scope = request.scope.clone();
    let saved = ReceiverDecision {
        schema: RECEIVER_DECISION.into(),
        phase: "evaluate_received".into(),
        request,
        candidate_id: candidate.into(),
        knowledge_before: store.history_anchor(),
        service_policy_sha256: journal.policy_digest().into(),
        fixture_sha256: fixture_sha256.into(),
    };
    let id = format!("receiver-evaluate-{}", digest(&saved)?);
    let event = OperationalEvent::PartnerDecisionRecorded {
        decision: PartnerDecisionRecord {
            decision_id: id.clone(),
            context: scope.clone(),
            frontier_edge: None,
            selected_peer: Some(sender),
            details: serde_json::to_value(saved).map_err(|error| error.to_string())?,
        },
    };
    receiver_decision(&event, journal.events(), store)?;
    let OperationalEvent::PartnerDecisionRecorded { decision } = &event else {
        unreachable!()
    };
    let binding = binding_from_decision(
        decision,
        store.identity(),
        journal.policy_digest(),
        fixture_sha256,
    )?;
    let exchange = binding.exchange_id.clone();
    let feedback = carrier(
        Feedback::Decision {
            binding,
            before: store.history_anchor(),
            baseline: Baseline::Unknown {
                reason: "no complete receiver-local control cost was measured before evaluation"
                    .into(),
            },
        },
        &scope,
    )?;
    let mut checked = journal.events().to_vec();
    checked.extend([event.clone(), feedback.clone()]);
    rebuild_inner(&checked, store, Some(journal))?;
    // One durable replacement prevents a crash from separating the receiver
    // decision and its feedback boundary. Existing bytes remain an exact prefix.
    let expected_head = journal.head_sha256().to_string();
    journal.append_checked_batch(&expected_head, vec![event, feedback])?;
    Ok(exchange)
}
pub fn promoted(
    journal: &mut OperationalJournal,
    store: &KnowledgeStore,
    candidate: &str,
    record: &KnowledgeRecord,
    before: KnowledgeAnchor,
    after: KnowledgeAnchor,
    costs: CandidateCosts,
) -> Result<Option<String>, String> {
    let index = replay_index(journal, store)?;
    let Some(trace) = index
        .traces
        .values()
        .find(|trace| trace.binding.candidate_id == candidate)
    else {
        return Ok(None);
    };
    let (promotion, evidence) = store.promotion_evidence_between(record, &before, &after)?;
    let id = trace.binding.exchange_id.clone();
    let baseline = journal
        .events()
        .iter()
        .find_map(|event| match event {
            OperationalEvent::EvaluationCompleted {
                candidate_id,
                response,
                ..
            } if candidate_id == candidate => response.get("feedback_baseline"),
            _ => None,
        })
        .map(|value| {
            serde_json::from_value::<Baseline>(value.clone())
                .map_err(|_| "typed evaluation feedback baseline rejected")
        })
        .transpose()?
        .unwrap_or_else(|| trace.baseline.clone());
    append(
        journal,
        store,
        Feedback::Promoted {
            exchange_id: id.clone(),
            record_sha256: record.digest()?,
            before,
            after,
            evidence_sha256: digest(&evidence)?,
            promotion_sha256: promotion,
            costs,
            baseline,
        },
        &trace.binding.scope,
    )?;
    Ok(Some(id))
}
pub fn record_use(
    journal: &mut OperationalJournal,
    store: &KnowledgeStore,
    exchange_id: &str,
    input: u16,
) -> Result<Value, String> {
    let index = replay_index(journal, store)?;
    let trace = index
        .traces
        .get(exchange_id)
        .ok_or("unknown feedback exchange")?;
    let promotion = trace
        .promotion
        .as_ref()
        .ok_or("cannot use an unpromoted exchange")?;
    let at = store.history_anchor();
    if !active_at(store, &promotion.record, &at)? {
        return Err("cannot use revoked or superseded feedback knowledge".into());
    }
    let (output, work) = prediction(&promotion.record, input)?;
    let basis = if expected(&promotion.evidence, input) == Some(output) {
        UseBasis::RetainedEvaluation {
            evidence_sha256: promotion.evidence_sha256.clone(),
        }
    } else {
        UseBasis::ConditionalFamily {
            family: "declared finite knowledge family".into(),
        }
    };
    let event = Feedback::StoreUse {
        exchange_id: exchange_id.into(),
        record_sha256: promotion.record.digest()?,
        knowledge_at: at,
        input,
        output,
        model_work: work,
        sequence: trace.uses,
        basis,
    };
    let value = serde_json::to_value(&event).map_err(|error| error.to_string())?;
    append(journal, store, event, &trace.binding.scope)?;
    Ok(value)
}
pub fn complete(
    journal: &mut OperationalJournal,
    store: &KnowledgeStore,
    exchange_id: &str,
) -> Result<Outcome, String> {
    let index = replay_index(journal, store)?;
    let trace = index
        .traces
        .get(exchange_id)
        .ok_or("unknown feedback exchange")?;
    let at = store.history_anchor();
    let outcome = derive(trace, store, &at)?;
    append(
        journal,
        store,
        Feedback::Outcome {
            exchange_id: exchange_id.into(),
            knowledge_at: at,
            outcome: outcome.clone(),
        },
        &trace.binding.scope,
    )?;
    Ok(outcome)
}
/// Derive the finite received-task cost window from actual native counters and
/// the unique earlier SENSE acquisition. Invoke after actual `record_use` and
/// before `complete`; multi-offer/offline/legacy cases remain explicitly unknown.
/// This does not claim lifetime, bilateral or whole-campaign economic benefit.
pub fn measure_local(
    journal: &mut OperationalJournal,
    store: &KnowledgeStore,
    exchange_id: &str,
    started: LocalExecutionStart,
) -> Result<Option<Value>, String> {
    // Sample the end before validation: validation of this receipt and subsequent
    // closure are audit work outside the operational task window, still visible
    // in the native whole-process execution meter.
    let after_execution = crate::graph_transfer::execution_snapshot();
    let after_forecast = symbiote_memory::knowledge::graph::forecast_work_units()?;
    if after_execution
        .lookups
        .get(..started.execution.lookups.len())
        != Some(started.execution.lookups.as_slice())
    {
        return Err("task window native lookup prefix changed".into());
    }
    let lookups = after_execution.lookups[started.execution.lookups.len()..].to_vec();
    let before = meter_point(&started.execution, started.forecast);
    let after = meter_point(&after_execution, after_forecast);
    let index = replay_index(journal, store)?;
    let trace = index
        .traces
        .get(exchange_id)
        .ok_or("task cost exchange absent")?;
    if trace.binding.origin != DecisionOrigin::NativeLearningIntent
        || original(journal.events(), &trace.binding.decision_id)?.details["acquisition"].is_null()
    {
        return Ok(None);
    }
    let measurement = scoped_measurement(
        trace,
        journal.events(),
        started.scope,
        started.sender,
        started.boundary,
        before,
        after,
        lookups,
        Some(journal),
    )?;
    let value = serde_json::to_value(&measurement).map_err(|error| error.to_string())?;
    append(
        journal,
        store,
        Feedback::CostObservation {
            exchange_id: exchange_id.into(),
            measurement,
        },
        &trace.binding.scope,
    )?;
    Ok(Some(value))
}
pub fn rejected(
    journal: &mut OperationalJournal,
    store: &KnowledgeStore,
    candidate: &str,
) -> Result<Option<Outcome>, String> {
    let index = replay_index(journal, store)?;
    let Some(trace) = index
        .traces
        .values()
        .find(|trace| trace.binding.candidate_id == candidate)
    else {
        return Ok(None);
    };
    let event=journal.events().iter().find(|event|matches!(event,OperationalEvent::EvaluationRejected{candidate_id,..} if candidate_id==candidate))
        .ok_or("cannot record feedback without an actual local rejection")?;
    let outcome = rejected_outcome(&trace.baseline);
    append(
        journal,
        store,
        Feedback::Rejected {
            exchange_id: trace.binding.exchange_id.clone(),
            knowledge_at: store.history_anchor(),
            rejection_sha256: digest(
                &serde_json::to_value(event).map_err(|error| error.to_string())?,
            )?,
            outcome: outcome.clone(),
        },
        &trace.binding.scope,
    )?;
    Ok(Some(outcome))
}
// Retained chronological per-carrier startup reference used by qualification
// tests. Production uses StartupReplay with the same authority/event checks.
#[cfg(test)]
pub(super) fn validate_profile_event(
    config: &Config,
    event: &OperationalEvent,
    prior: &[OperationalEvent],
    store: &KnowledgeStore,
) -> Result<(), String> {
    validate_profile_authority(config, event, prior, store)?;
    let mut events = prior.to_vec();
    events.push(event.clone());
    rebuild(&events, store).map(|_| ())
}

fn validate_profile_authority(
    config: &Config,
    event: &OperationalEvent,
    prior: &[OperationalEvent],
    store: &KnowledgeStore,
) -> Result<(), String> {
    if receiver_decision(event, prior, store)? {
        let OperationalEvent::PartnerDecisionRecorded { decision } = event else {
            unreachable!()
        };
        let saved: ReceiverDecision = serde_json::from_value(decision.details.clone())
            .map_err(|_| "receiver decision rejected")?;
        if saved.service_policy_sha256 != config.policy_digest
            || config.context(&decision.context)?.truth_sha256.as_ref()
                != Some(&saved.fixture_sha256)
        {
            return Err("receiver decision policy/fixture epoch changed".into());
        }
        saved.request.validate(config)?;
        super::State::authorize_policy(
            config,
            decision
                .selected_peer
                .as_deref()
                .ok_or("receiver sender absent")?,
            &saved.request,
        )?;
        return Ok(());
    }
    let Some(decoded) = decode(event)? else {
        return Err("unknown feedback namespace".into());
    };
    if let Feedback::Decision { binding, .. } = &decoded {
        let context = config.context(&binding.scope)?;
        if binding.policy_sha256 != config.policy_digest
            || context.truth_sha256.as_ref() != Some(&binding.fixture_sha256)
            || context.schema_fingerprint != binding.schema_fingerprint
            || config.identity != binding.receiver_id
        {
            return Err(
                "feedback intent differs from its actual operator policy/fixture epoch".into(),
            );
        }
        config
            .peer(&binding.sender_id)?
            .access(&binding.scope, "candidate.submit")?;
    }
    Ok(())
}

/// A single cold-start validation cursor over one live, already hash-checked
/// journal. Each event must be supplied in order with its historical operator
/// policy. It is not serializable, shared, or reusable for another journal.
pub(super) struct StartupReplay<'a> {
    journal: &'a OperationalJournal,
    index: FeedbackIndex,
    credited: BTreeSet<String>,
    next: usize,
    failed: bool,
}
impl<'a> StartupReplay<'a> {
    pub(super) fn new(
        journal: &'a OperationalJournal,
        store: &KnowledgeStore,
    ) -> Result<Self, String> {
        if journal.identity() != store.identity() {
            return Err("feedback startup owner changed".into());
        }
        work(|work| work.saturated |= add_count(&mut work.single_pass_starts, 1));
        Ok(Self {
            journal,
            index: FeedbackIndex::default(),
            credited: BTreeSet::new(),
            next: 0,
            failed: false,
        })
    }
    pub(super) fn validate_next(
        &mut self,
        config: &Config,
        position: usize,
        store: &KnowledgeStore,
    ) -> Result<(), String> {
        let _timer = ReplayTimer(Instant::now());
        if self.failed || position != self.next || store.identity() != self.journal.identity() {
            self.failed = true;
            return Err("feedback startup skipped/replayed an event or changed owner".into());
        }
        self.failed = true;
        let events = self.journal.events();
        let event = events
            .get(position)
            .ok_or("feedback startup event is absent")?;
        if handles(event) {
            validate_profile_authority(config, event, &events[..position], store)?;
        }
        apply_feedback_event(
            &mut self.index,
            &mut self.credited,
            position,
            event,
            events,
            store,
            Some(self.journal),
        )?;
        self.next += 1;
        self.failed = false;
        Ok(())
    }
    pub(super) fn finish(self, store: &KnowledgeStore) -> Result<FeedbackIndex, String> {
        let _timer = ReplayTimer(Instant::now());
        if self.failed
            || self.next != self.journal.events().len()
            || store.identity() != self.journal.identity()
        {
            return Err("feedback startup did not validate the complete owned journal".into());
        }
        let result = finish_index(self.index, store)?;
        work(|work| work.saturated |= add_count(&mut work.single_pass_finishes, 1));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    //! Controlled local-ledger verifier fixtures, not experimental utility results.
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
    };
    use symbiote_memory::{
        knowledge::{affine_schema_fingerprint, assess, TrialCase, TrialCosts, TrialEvidence},
        operational::{IdempotencyKey, PartnerDecisionRecord},
        reciprocal::{PromotionSeal, PromotionWitness, ReciprocalReceipt},
        Store,
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture {
        path: PathBuf,
        journal: Option<OperationalJournal>,
        store: Option<KnowledgeStore>,
        policy: String,
        fixture: String,
    }
    struct Proof {
        id: String,
        record: KnowledgeRecord,
        evidence: Value,
        before: KnowledgeAnchor,
        after: KnowledgeAnchor,
    }
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "symbiote-feedback-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            let owner = Arc::new(Store::open(&path).unwrap());
            let identity = owner.identity().to_string();
            let policy = "11".repeat(32);
            let fixture = "22".repeat(32);
            let journal = OperationalJournal::open(owner, "configured-peer/v1", &policy).unwrap();
            let store = KnowledgeStore::open(&path, &identity).unwrap();
            Self {
                path,
                journal: Some(journal),
                store: Some(store),
                policy,
                fixture,
            }
        }
        fn learn(&mut self, name: &str, baseline_kind: u8, baseline_cost: u64) -> Proof {
            let scope = format!("affine-{name}/v1");
            let sender = format!("sender-{name}");
            let record = KnowledgeRecord {
                id: format!("localized-{name}"),
                revision: 1,
                source: sender.clone(),
                scope: scope.clone(),
                schema_fingerprint: affine_schema_fingerprint(3).unwrap(),
                payload: json!({"kind":"affine","width":3,"coefficients":3,"bias":false}),
                provenance: "controlled verifier fixture; independent local held-out checks".into(),
            };
            let mut offered = record.clone();
            offered.id = format!("remote-{name}");
            offered.source = "claimed-upstream".into();
            let request = json!({"schema":"symbiote.service-request/1","scope":scope,"request_id":format!("request-{name}"),
                "body":{"operation":"candidate.submit","offer":{"record":offered,"training_inputs":[0,1]}}});
            let request_sha = digest(&request).unwrap();
            let candidate = super::super::candidate_id_for(&sender, &request_sha).unwrap();
            let before = self.store.as_ref().unwrap().history_anchor();
            let decision_id = format!("decision-{name}");
            self.journal.as_mut().unwrap().append(OperationalEvent::PartnerDecisionRecorded{decision:PartnerDecisionRecord{
                decision_id:decision_id.clone(),context:scope.clone(),frontier_edge:None,selected_peer:Some(sender.clone()),details:json!({
                    "schema":"symbiote.cognition-decision/1","phase":"learn","request":request,"candidate_id":candidate,
                    "knowledge_before":before,"service_policy_sha256":self.policy})}}).unwrap();
            let evidence = TrialEvidence {
                evaluator: "controlled-local-fixture".into(),
                training_case_ids: vec!["train-0".into(), "train-1".into()],
                training_inputs: vec![0, 1],
                cases: (2..8)
                    .map(|input| {
                        let answer = ((input & 3_u16).count_ones() % 2) as u8;
                        TrialCase {
                            id: format!("heldout-{input}"),
                            input,
                            expected: answer,
                            baseline: None,
                            candidate: answer,
                        }
                    })
                    .collect(),
                costs: TrialCosts {
                    acquisition: 2,
                    verification: 6,
                    adoption: 1,
                    baseline: baseline_cost,
                    candidate: 10,
                },
            };
            let evidence_value = serde_json::to_value(&evidence).unwrap();
            let baseline = match baseline_kind {
                0 => Baseline::Measured {
                    units: baseline_cost,
                    evidence_sha256: digest(&evidence_value).unwrap(),
                },
                1 => Baseline::Estimate {
                    units: baseline_cost,
                    basis: "fixture estimate, not a measured control".into(),
                },
                _ => Baseline::Unknown {
                    reason: "no isolated baseline was executed".into(),
                },
            };
            let binding = binding_for(
                self.journal.as_ref().unwrap(),
                self.store.as_ref().unwrap(),
                &decision_id,
                &self.fixture,
            )
            .unwrap();
            let id = begin(
                self.journal.as_mut().unwrap(),
                self.store.as_ref().unwrap(),
                binding,
                baseline,
            )
            .unwrap();
            let key = IdempotencyKey {
                peer_id: sender,
                operation: "candidate.submit".into(),
                scope: scope.clone(),
                request_id: format!("request-{name}"),
            };
            self.journal
                .as_mut()
                .unwrap()
                .append(OperationalEvent::Quarantined {
                    key,
                    candidate_id: candidate.clone(),
                    body_sha256: request_sha,
                    body: request,
                    response: super::super::quarantine_response(&candidate),
                })
                .unwrap();
            let response = json!({"schema":"symbiote.service-evaluation/1","status":"PROMOTED","promoted":true,"record_sha256":record.digest().unwrap()});
            self.journal
                .as_mut()
                .unwrap()
                .append(OperationalEvent::EvaluationPrepared {
                    candidate_id: candidate.clone(),
                    record: record.clone(),
                    fixture_sha256: self.fixture.clone(),
                    response: response.clone(),
                })
                .unwrap();
            self.store
                .as_mut()
                .unwrap()
                .promote(record.clone(), assess(&record, &evidence).unwrap())
                .unwrap();
            let after = self.store.as_ref().unwrap().history_anchor();
            self.journal
                .as_mut()
                .unwrap()
                .append(OperationalEvent::EvaluationCompleted {
                    candidate_id: candidate.clone(),
                    record_sha256: record.digest().unwrap(),
                    response,
                })
                .unwrap();
            let costs = CandidateCosts {
                unit_model: "controlled-fixture-work/1".into(),
                acquisition: 2,
                validation: 6,
                adoption: 1,
                prediction: 1,
                wire: 0,
                replay: 0,
            };
            assert_eq!(
                promoted(
                    self.journal.as_mut().unwrap(),
                    self.store.as_ref().unwrap(),
                    &candidate,
                    &record,
                    before.clone(),
                    after.clone(),
                    costs
                )
                .unwrap(),
                Some(id.clone())
            );
            Proof {
                id,
                record,
                evidence: evidence_value,
                before,
                after,
            }
        }
        fn use_and_complete(&mut self, proof: &Proof, input: u16) -> Outcome {
            record_use(
                self.journal.as_mut().unwrap(),
                self.store.as_ref().unwrap(),
                &proof.id,
                input,
            )
            .unwrap();
            complete(
                self.journal.as_mut().unwrap(),
                self.store.as_ref().unwrap(),
                &proof.id,
            )
            .unwrap()
        }
        fn receipt(&self, proof: &Proof) -> ReciprocalReceipt {
            ReciprocalReceipt::seal_promoted(
                self.store.as_ref().unwrap(),
                witness(proof),
                &PromotionSeal {
                    sender_identity: proof.record.source.clone(),
                    sender_knowledge_before_sha256: "33".repeat(32),
                    persisted_after_restart: None,
                    completed: true,
                },
            )
            .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.journal.take();
            self.store.take();
            let _ = fs::remove_dir_all(&self.path);
        }
    }
    fn witness(proof: &Proof) -> PromotionWitness<'_> {
        PromotionWitness {
            record: &proof.record,
            evidence: &proof.evidence,
            before: &proof.before,
            after: &proof.after,
        }
    }

    #[test]
    fn exact_causal_chain_and_actual_use_are_required_before_measured_credit() {
        let mut fixture = Fixture::new();
        let proof = fixture.learn("a", 0, 20);
        let receipt = fixture.receipt(&proof);
        assert!(receipt.confirmed_benefit(fixture.store.as_ref().unwrap(), witness(&proof)));
        assert!(!crate::reciprocal::bound_attributed_benefit(
            fixture.journal.as_ref().unwrap(),
            fixture.store.as_ref().unwrap(),
            &proof.id,
            &receipt,
            witness(&proof)
        ));
        let outcome = fixture.use_and_complete(&proof, 2);
        assert_eq!(outcome.uses, 1);
        assert_eq!(outcome.candidate_cost, Some(11));
        assert_eq!(outcome.measured_net, Some(9));
        assert!(outcome.verified_benefit);
        assert!(crate::reciprocal::bound_attributed_benefit(
            fixture.journal.as_ref().unwrap(),
            fixture.store.as_ref().unwrap(),
            &proof.id,
            &receipt,
            witness(&proof)
        ));
        assert_eq!(
            replay_index(
                fixture.journal.as_ref().unwrap(),
                fixture.store.as_ref().unwrap()
            )
            .unwrap()
            .experience(&proof.id)
            .unwrap()
            .recommendation,
            Recommendation::Prefer
        );
    }
    #[test]
    fn two_individually_valid_receipts_cannot_be_swapped_between_exchanges() {
        let mut fixture = Fixture::new();
        let a = fixture.learn("a", 0, 20);
        fixture.use_and_complete(&a, 2);
        let b = fixture.learn("b", 0, 20);
        fixture.use_and_complete(&b, 2);
        let ar = fixture.receipt(&a);
        let br = fixture.receipt(&b);
        assert!(ar.confirmed_benefit(fixture.store.as_ref().unwrap(), witness(&a)));
        assert!(br.confirmed_benefit(fixture.store.as_ref().unwrap(), witness(&b)));
        assert!(!crate::reciprocal::bound_attributed_benefit(
            fixture.journal.as_ref().unwrap(),
            fixture.store.as_ref().unwrap(),
            &a.id,
            &br,
            witness(&b)
        ));
        assert!(!crate::reciprocal::bound_attributed_benefit(
            fixture.journal.as_ref().unwrap(),
            fixture.store.as_ref().unwrap(),
            &b.id,
            &ar,
            witness(&a)
        ));
    }
    #[test]
    fn unknown_estimated_conditional_and_negative_cases_do_not_verify_efficiency() {
        for (kind, baseline, input, expected_recommendation) in [
            (1, 20, 2, Recommendation::Prefer),
            (2, 20, 2, Recommendation::Prefer),
            (0, 5, 2, Recommendation::Defer),
            (0, 20, 0, Recommendation::Explore),
        ] {
            let mut fixture = Fixture::new();
            let proof = fixture.learn("a", kind, baseline);
            let outcome = fixture.use_and_complete(&proof, input);
            assert!(!outcome.verified_benefit);
            if kind != 0 {
                assert_eq!(outcome.measured_net, None);
            }
            assert_eq!(
                replay_index(
                    fixture.journal.as_ref().unwrap(),
                    fixture.store.as_ref().unwrap()
                )
                .unwrap()
                .experience(&proof.id)
                .unwrap()
                .recommendation,
                expected_recommendation
            );
        }
    }
    #[test]
    fn duplicate_credit_and_fabricated_store_use_are_rejected() {
        let mut fixture = Fixture::new();
        let proof = fixture.learn("a", 0, 20);
        let fake = Feedback::StoreUse {
            exchange_id: proof.id.clone(),
            record_sha256: proof.record.digest().unwrap(),
            knowledge_at: proof.after.clone(),
            input: 2,
            output: 0,
            model_work: 1,
            sequence: 0,
            basis: UseBasis::RetainedEvaluation {
                evidence_sha256: digest(&proof.evidence).unwrap(),
            },
        };
        assert!(append(
            fixture.journal.as_mut().unwrap(),
            fixture.store.as_ref().unwrap(),
            fake,
            &proof.record.scope
        )
        .is_err());
        fixture.use_and_complete(&proof, 2);
        assert!(complete(
            fixture.journal.as_mut().unwrap(),
            fixture.store.as_ref().unwrap(),
            &proof.id
        )
        .is_err());
        assert!(record_use(
            fixture.journal.as_mut().unwrap(),
            fixture.store.as_ref().unwrap(),
            &proof.id,
            2
        )
        .is_err());
        let index = replay_index(
            fixture.journal.as_ref().unwrap(),
            fixture.store.as_ref().unwrap(),
        )
        .unwrap();
        assert_eq!(index.experiences.len(), 1);
    }
    #[test]
    fn replay_rebuilds_retained_experience_and_revocation_removes_current_credit() {
        let mut fixture = Fixture::new();
        let proof = fixture.learn("a", 0, 20);
        fixture.use_and_complete(&proof, 2);
        let receipt = fixture.receipt(&proof);
        let before = serde_json::to_value(
            replay_index(
                fixture.journal.as_ref().unwrap(),
                fixture.store.as_ref().unwrap(),
            )
            .unwrap()
            .experiences,
        )
        .unwrap();
        let identity = fixture.store.as_ref().unwrap().identity().to_string();
        fixture.store.take();
        fixture.journal.take();
        let owner = Arc::new(Store::open(&fixture.path).unwrap());
        fixture.journal =
            Some(OperationalJournal::open(owner, "configured-peer/v1", &fixture.policy).unwrap());
        fixture.store = Some(KnowledgeStore::open(&fixture.path, &identity).unwrap());
        assert_eq!(
            serde_json::to_value(
                replay_index(
                    fixture.journal.as_ref().unwrap(),
                    fixture.store.as_ref().unwrap()
                )
                .unwrap()
                .experiences
            )
            .unwrap(),
            before
        );
        fixture
            .store
            .as_mut()
            .unwrap()
            .revoke(&proof.record.id, "independent counterexample")
            .unwrap();
        assert!(!receipt.confirmed_benefit(fixture.store.as_ref().unwrap(), witness(&proof)));
        assert!(!crate::reciprocal::bound_attributed_benefit(
            fixture.journal.as_ref().unwrap(),
            fixture.store.as_ref().unwrap(),
            &proof.id,
            &receipt,
            witness(&proof)
        ));
        assert_eq!(
            replay_index(
                fixture.journal.as_ref().unwrap(),
                fixture.store.as_ref().unwrap()
            )
            .unwrap()
            .experience(&proof.id)
            .unwrap()
            .recommendation,
            Recommendation::Defer
        );
        let historical = replay_prefix(
            fixture.journal.as_ref().unwrap().events(),
            fixture.store.as_ref().unwrap(),
            &proof.after,
        )
        .unwrap();
        assert!(historical.experience(&proof.id).unwrap().currently_active);
        assert_eq!(
            historical.experience(&proof.id).unwrap().recommendation,
            Recommendation::Prefer,
            "a later revocation must not rewrite a previously saved decision profile"
        );
        assert!(fixture
            .store
            .as_ref()
            .unwrap()
            .promotion_evidence_between(&proof.record, &proof.before, &proof.after)
            .is_ok());
    }
    #[test]
    fn unsupported_feedback_and_counter_overflow_fail_explicitly() {
        let mut fixture = Fixture::new();
        let proof = fixture.learn("a", 2, 20);
        let event = carrier(
            Feedback::Outcome {
                exchange_id: proof.id.clone(),
                knowledge_at: proof.after.clone(),
                outcome: Outcome {
                    quality: Quality::Unused,
                    baseline: Baseline::Unknown {
                        reason: "test".into(),
                    },
                    candidate_cost: Some(10),
                    measured_net: None,
                    verified_benefit: false,
                    uses: 0,
                    unit_model: Some("test/1".into()),
                },
            },
            &proof.record.scope,
        )
        .unwrap();
        let OperationalEvent::PartnerDecisionRecorded { mut decision } = event else {
            unreachable!()
        };
        decision.details["schema"] = json!("symbiote.learning-feedback/999");
        assert!(rebuild(
            &[OperationalEvent::PartnerDecisionRecorded { decision }],
            fixture.store.as_ref().unwrap()
        )
        .is_err());
        assert!(CandidateCosts {
            unit_model: "test/1".into(),
            acquisition: u64::MAX,
            validation: 1,
            adoption: 0,
            prediction: 0,
            wire: 0,
            replay: 0
        }
        .total()
        .is_err());
    }

    #[test]
    fn prior_union_coverage_and_conflicts_never_create_new_capability_credit() {
        use symbiote_memory::knowledge::graph::{
            encode_query, graph_schema_fingerprint, GraphMap, GraphObservation,
        };
        use symbiote_reasoning::planning::{Edge, GraphSchema};
        let schema = GraphSchema {
            nodes: 4,
            edges: (0..3)
                .map(|from| Edge {
                    from,
                    to: from + 1,
                    lower: 1,
                    upper: 9,
                })
                .collect(),
        };
        let make = |name: &str, items: Vec<(usize, u16)>| KnowledgeRecord {
            id: name.into(),
            revision: 1,
            source: name.into(),
            scope: "shared-graph/v1".into(),
            schema_fingerprint: graph_schema_fingerprint(&schema).unwrap(),
            payload: GraphMap::new(
                schema.clone(),
                items
                    .into_iter()
                    .map(|(edge_id, cost)| GraphObservation { edge_id, cost })
                    .collect(),
            )
            .unwrap()
            .to_payload()
            .unwrap(),
            provenance: "logical fact-union verifier fixture".into(),
        };
        let target = encode_query(4, 0, 3).unwrap();
        let left = make("left", vec![(0, 1)]);
        let right = make("right", vec![(1, 1), (2, 1)]);
        let candidate = make("candidate", vec![(0, 1), (1, 1), (2, 1)]);
        assert_eq!(left.predict_if_certified(target).unwrap(), None);
        assert_eq!(right.predict_if_certified(target).unwrap(), None);
        assert_eq!(
            earlier_coverage(&[left.clone(), right], &candidate, target).unwrap(),
            Some(true)
        );
        assert_eq!(
            earlier_coverage(std::slice::from_ref(&left), &candidate, target).unwrap(),
            Some(false)
        );
        let conflicting = make("conflicting", vec![(0, 2), (1, 1), (2, 1)]);
        assert_eq!(
            earlier_coverage(&[left, conflicting], &candidate, target).unwrap(),
            None
        );
    }

    #[test]
    fn an_actual_rejected_receiver_exchange_closes_with_unknown_cost_and_no_promotion_credit() {
        let mut fixture = Fixture::new();
        let record = KnowledgeRecord {
            id: "wrong-affine".into(),
            revision: 1,
            source: "untrusted-source".into(),
            scope: "affine-rejected/v1".into(),
            schema_fingerprint: affine_schema_fingerprint(3).unwrap(),
            payload: json!({"kind":"affine","width":3,"coefficients":4,"bias":true}),
            provenance: "inert rejected fixture".into(),
        };
        let body = json!({"schema":"symbiote.service-request/1","scope":record.scope,"request_id":"rejected-request", "body":{"operation":"candidate.submit","offer":{"record":record,"training_inputs":[0,1]}}});
        let body_sha256 = digest(&body).unwrap();
        let candidate = super::super::candidate_id_for("sender-rejected", &body_sha256).unwrap();
        fixture
            .journal
            .as_mut()
            .unwrap()
            .append(OperationalEvent::Quarantined {
                key: IdempotencyKey {
                    peer_id: "sender-rejected".into(),
                    operation: "candidate.submit".into(),
                    scope: "affine-rejected/v1".into(),
                    request_id: "rejected-request".into(),
                },
                candidate_id: candidate.clone(),
                body_sha256,
                body,
                response: super::super::quarantine_response(&candidate),
            })
            .unwrap();
        let exchange = begin_evaluation(
            fixture.journal.as_mut().unwrap(),
            fixture.store.as_ref().unwrap(),
            &candidate,
            &fixture.fixture,
        )
        .unwrap();
        fixture
            .journal
            .as_mut()
            .unwrap()
            .append(OperationalEvent::EvaluationRejected {
                candidate_id: candidate.clone(),
                reason: "independent local evidence contradicts candidate".into(),
            })
            .unwrap();
        let outcome = rejected(
            fixture.journal.as_mut().unwrap(),
            fixture.store.as_ref().unwrap(),
            &candidate,
        )
        .unwrap()
        .unwrap();
        assert_eq!(outcome.quality, Quality::Rejected);
        assert_eq!(outcome.candidate_cost, None);
        assert_eq!(outcome.measured_net, None);
        assert!(!outcome.verified_benefit);
        assert!(fixture.store.as_ref().unwrap().active().is_empty());
        let index = replay_index(
            fixture.journal.as_ref().unwrap(),
            fixture.store.as_ref().unwrap(),
        )
        .unwrap();
        let experience = index.experience(&exchange).unwrap();
        assert_eq!(experience.recommendation, Recommendation::Defer);
        assert!(matches!(experience.proof, ExperienceProof::Rejected { .. }));
        assert!(rejected(
            fixture.journal.as_mut().unwrap(),
            fixture.store.as_ref().unwrap(),
            &candidate
        )
        .is_err());
    }

    fn configured_fixture() -> (Fixture, Config) {
        let path = std::env::temp_dir().join(format!(
            "symbiote-feedback-configured-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let owner = Arc::new(Store::open(&path).unwrap());
        let identity = owner.identity().to_string();
        let fixture_pin = "22".repeat(32);
        let contexts = ["a", "b"].map(|name| json!({"scope":format!("affine-{name}/v1"),"schema_fingerprint":affine_schema_fingerprint(3).unwrap(),"truth_fixture":format!("{name}.json"),"truth_sha256":fixture_pin}));
        let peers = ["a", "b"].into_iter().enumerate().map(|(index,name)| json!({
            "alias":format!("peer-{name}"),"id":format!("sender-{name}"),"address":format!("127.0.0.1:{}",9200+index),"server_name":"localhost",
            "certificate_sha256":if index==0 {"bb".repeat(32)} else {"cc".repeat(32)},
            "access":[{"scope":format!("affine-{name}/v1"),"operations":["candidate.submit"],"artifacts":["*"]}]
        })).collect::<Vec<_>>();
        let config = Config::historical(&json!({"ca_sha256":"dd".repeat(32),"manifest":{
            "schema":"symbiote.service-config/1","state":path,"identity":identity,"certificate":"public.pem","private_key":"private.pem","certificate_sha256":"aa".repeat(32),"ca_certificate":"ca.pem","bind_address":"127.0.0.1:0","peers":peers,"contexts":contexts,
            "limits":{"max_requests":32,"max_connections":8,"max_frame_bytes":65536,"timeout_ms":1000,"lifetime_ms":10000,"per_peer_requests":16,"max_offers":8,"max_offer_bytes":8192,"model_work":100000}
        }})).unwrap();
        let journal =
            OperationalJournal::open(owner, "configured-peer/v1", &config.policy_digest).unwrap();
        let store = KnowledgeStore::open(&path, &identity).unwrap();
        (
            Fixture {
                path,
                journal: Some(journal),
                store: Some(store),
                policy: config.policy_digest.clone(),
                fixture: fixture_pin,
            },
            config,
        )
    }
    fn single_pass(fixture: &Fixture, config: &Config) -> Result<FeedbackIndex, String> {
        let journal = fixture.journal.as_ref().unwrap();
        let store = fixture.store.as_ref().unwrap();
        let mut replay = StartupReplay::new(journal, store)?;
        for position in 0..journal.events().len() {
            replay.validate_next(config, position, store)?;
        }
        replay.finish(store)
    }
    #[test]
    fn single_pass_matches_reference_with_rejection_of_wrong_epochs_and_later_revocation() {
        let (mut fixture, config) = configured_fixture();
        let a = fixture.learn("a", 0, 20);
        fixture.use_and_complete(&a, 2);
        let b = fixture.learn("b", 0, 5);
        fixture.use_and_complete(&b, 2);
        let journal = fixture.journal.as_ref().unwrap();
        let store = fixture.store.as_ref().unwrap();
        let before = replay_work();
        for (position, event) in journal.events().iter().enumerate() {
            if handles(event) {
                validate_profile_event(&config, event, &journal.events()[..position], store)
                    .unwrap();
            }
        }
        let reference_work = replay_work();
        let actual = single_pass(&fixture, &config).unwrap();
        let optimized_work = replay_work();
        let expected = replay_index_reference(journal, store).unwrap();
        assert_eq!(
            serde_json::to_value(&actual.experiences).unwrap(),
            serde_json::to_value(&expected.experiences).unwrap()
        );
        assert!(
            reference_work.event_visits - before.event_visits
                > optimized_work.event_visits - reference_work.event_visits
        );
        assert!(
            reference_work.store_use_prediction_rechecks - before.store_use_prediction_rechecks
                > optimized_work.store_use_prediction_rechecks
                    - reference_work.store_use_prediction_rechecks
        );
        assert_eq!(
            optimized_work.event_visits - reference_work.event_visits,
            journal.events().len() as u64
        );
        assert_eq!(
            optimized_work.store_use_prediction_rechecks
                - reference_work.store_use_prediction_rechecks,
            2
        );
        assert_eq!(
            actual.experience(&a.id).unwrap().recommendation,
            Recommendation::Prefer
        );
        assert_eq!(
            actual.experience(&b.id).unwrap().recommendation,
            Recommendation::Defer
        );
        let mut wrong = Config::historical(&config.public_snapshot()).unwrap();
        wrong.policy_digest = "ee".repeat(32);
        assert!(single_pass(&fixture, &wrong).is_err());
        let mut wrong = Config::historical(&config.public_snapshot()).unwrap();
        wrong.contexts[0].truth_sha256 = Some("ff".repeat(32));
        assert!(single_pass(&fixture, &wrong).is_err());
        let mut denied = Config::historical(&config.public_snapshot()).unwrap();
        denied.peers[0].access[0].operations = vec!["knowledge.list".into()];
        assert!(single_pass(&fixture, &denied).is_err());
        fixture
            .store
            .as_mut()
            .unwrap()
            .revoke(&a.record.id, "later counterexample")
            .unwrap();
        let actual = single_pass(&fixture, &config).unwrap();
        let expected = replay_index_reference(
            fixture.journal.as_ref().unwrap(),
            fixture.store.as_ref().unwrap(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&actual.experiences).unwrap(),
            serde_json::to_value(&expected.experiences).unwrap()
        );
        assert_eq!(
            actual.experience(&a.id).unwrap().recommendation,
            Recommendation::Defer
        );
        let historical = replay_prefix(
            fixture.journal.as_ref().unwrap().events(),
            fixture.store.as_ref().unwrap(),
            &b.after,
        )
        .unwrap();
        assert_eq!(
            historical.experience(&a.id).unwrap().recommendation,
            Recommendation::Prefer
        );
    }
    #[test]
    fn startup_cursor_cannot_skip_repeat_finish_early_or_credit_duplicate_feedback() {
        let (mut fixture, config) = configured_fixture();
        let proof = fixture.learn("a", 0, 20);
        fixture.use_and_complete(&proof, 2);
        let journal = fixture.journal.as_ref().unwrap();
        let store = fixture.store.as_ref().unwrap();
        let mut replay = StartupReplay::new(journal, store).unwrap();
        assert!(replay.validate_next(&config, 1, store).is_err());
        assert!(replay.validate_next(&config, 0, store).is_err());
        assert!(replay.finish(store).is_err());
        let mut replay = StartupReplay::new(journal, store).unwrap();
        replay.validate_next(&config, 0, store).unwrap();
        assert!(replay.validate_next(&config, 0, store).is_err());
        assert!(replay.finish(store).is_err());
        let mut malformed = journal.events().to_vec();
        let duplicate = malformed
            .iter()
            .find(|event| matches!(decode(event), Ok(Some(Feedback::Outcome { .. }))))
            .unwrap()
            .clone();
        malformed.push(duplicate);
        assert!(rebuild(&malformed, store).is_err());
        let mut index = FeedbackIndex::default();
        let mut credited = BTreeSet::new();
        let mut rejected = false;
        for (position, event) in malformed.iter().enumerate() {
            if apply_feedback_event(
                &mut index,
                &mut credited,
                position,
                event,
                &malformed,
                store,
                None,
            )
            .is_err()
            {
                rejected = true;
                break;
            }
        }
        assert!(
            rejected,
            "single-pass body must reject the same duplicate credit"
        );
    }

    #[test]
    fn typed_carrier_validation_rejects_rehashed_unknown_or_unbound_envelopes() {
        let mut fixture = Fixture::new();
        let proof = fixture.learn("a", 0, 20);
        fixture.use_and_complete(&proof, 2);
        let events = fixture.journal.as_ref().unwrap().events();
        for event in events.iter().filter(|event| handles(event)) {
            validate_carrier(event).unwrap();
        }
        assert!(
            validate_carrier(&events[0]).is_err(),
            "ordinary operational metadata is not a feedback carrier"
        );
        let original = events.iter().find(|event| handles(event)).unwrap();
        for change in ["scope", "extra", "schema", "id"] {
            let mut changed = original.clone();
            let OperationalEvent::PartnerDecisionRecorded { decision } = &mut changed else {
                unreachable!()
            };
            match change {
                "scope" => decision.details["scope"] = json!("foreign/v1"),
                "extra" => {
                    decision.details["event"]["unrecognized"] = json!(true);
                    decision.decision_id =
                        format!("feedback-{}", digest(&decision.details).unwrap());
                }
                "schema" => decision.details["schema"] = json!("symbiote.learning-feedback/999"),
                _ => decision.decision_id = format!("feedback-{}", "a".repeat(64)),
            }
            assert!(validate_carrier(&changed).is_err(), "{change}");
        }
    }
    #[test]
    fn a_legal_late_capture_cannot_omit_the_actual_sense_boundary() {
        let mut fixture = Fixture::new();
        let early =
            capture_local_execution(fixture.journal.as_ref().unwrap(), "graph/v1", "sender")
                .unwrap();
        let binding = Binding {
            origin: DecisionOrigin::NativeLearningIntent,
            exchange_id: "exchange".into(),
            decision_id: "learn".into(),
            sender_id: "sender".into(),
            receiver_id: fixture.journal.as_ref().unwrap().identity().into(),
            scope: "graph/v1".into(),
            schema_fingerprint: "11".repeat(32),
            request_sha256: "22".repeat(32),
            candidate_id: "candidate".into(),
            offered_record_sha256: "33".repeat(32),
            policy_sha256: fixture.policy.clone(),
            fixture_sha256: fixture.fixture.clone(),
        };
        fixture
            .journal
            .as_mut()
            .unwrap()
            .append(OperationalEvent::PartnerDecisionRecorded {
                decision: PartnerDecisionRecord {
                    decision_id: "sense".into(),
                    context: "graph/v1".into(),
                    frontier_edge: None,
                    selected_peer: Some("sender".into()),
                    details: json!({"schema":"symbiote.cognition-decision/1","phase":"sense"}),
                },
            })
            .unwrap();
        let events = fixture.journal.as_ref().unwrap().events();
        validate_sense_boundary(&early.boundary, events, &binding, "sense").unwrap();
        let journal = fixture.journal.as_ref().unwrap();
        assert_eq!(
            early.boundary.prefix_sha256,
            journal
                .event_prefix_sha256_reference(early.boundary.events)
                .unwrap()
        );
        validate_sense_boundary_inner(&early.boundary, events, &binding, "sense", Some(journal))
            .unwrap();

        let late = capture_local_execution(fixture.journal.as_ref().unwrap(), "graph/v1", "sender")
            .unwrap();
        assert!(validate_sense_boundary(&late.boundary, events, &binding, "sense").is_err());
        assert!(validate_sense_boundary_inner(
            &late.boundary,
            events,
            &binding,
            "sense",
            Some(journal)
        )
        .is_err());

        let mut substituted = early.boundary.clone();
        substituted.owner = "different-owner".into();
        assert!(validate_sense_boundary(&substituted, events, &binding, "sense").is_err());
        assert!(validate_sense_boundary_inner(
            &substituted,
            events,
            &binding,
            "sense",
            Some(journal)
        )
        .is_err());

        substituted = early.boundary.clone();
        substituted.prefix_sha256 = "44".repeat(32);
        assert!(validate_sense_boundary(&substituted, events, &binding, "sense").is_err());
        assert!(validate_sense_boundary_inner(
            &substituted,
            events,
            &binding,
            "sense",
            Some(journal)
        )
        .is_err());

        assert!(
            validate_sense_boundary(&early.boundary, events, &binding, "foreign-sense").is_err()
        );
    }
}
