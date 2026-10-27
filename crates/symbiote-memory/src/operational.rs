//! Owner-bound operational audit, separate from evaluated learning evidence.
//!
//! These records express operator policy, quarantine and request outcomes. They
//! do not prove improvement or authenticate a remote source. The service must
//! enforce its configured peer grants and local fixture authority on every call
//! and replay. Hashes detect accidental corruption, not a full ledger rewrite.
use crate::{digest, knowledge::KnowledgeRecord, maintenance, Store};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

const FILE_NAME: &str = "operations.jsonl";
pub(crate) const OWNER_FILE: &str = "operations-owner.json";
pub(crate) const MAX_OWNER_BYTES: usize = 4096;
const MAX_RECORD_BYTES: usize = 64 * 1024;
/// A complete original 64KiB manifest plus its public CA-digest wrapper.
pub const MAX_SERVICE_POLICY_BYTES: usize = 68 * 1024;
const MAX_POLICY_RECORD_BYTES: usize = 160 * 1024;
const MAX_BODY_BYTES: usize = 32 * 1024;
const MAX_RESPONSE_BYTES: usize = 8 * 1024;
const MAX_PREPARED_BYTES: usize = 16 * 1024;
const MAX_IDENTITIES: usize = 128;
const MAX_DECISIONS: usize = 2048;
const MAX_SOURCE_WARMUPS: usize = 25;
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}
fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn reason(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 4096
}
fn bounded(value: &Value, maximum: usize) -> Result<(), String> {
    if serde_json::to_vec(value)
        .map_err(|error| error.to_string())?
        .len()
        > maximum
    {
        return Err("operational value exceeds its byte budget".into());
    }
    Ok(())
}

fn record_limit(payload: &Value) -> usize {
    if payload.get("event").and_then(Value::as_str) == Some("policy_transitioned") {
        MAX_POLICY_RECORD_BYTES
    } else {
        MAX_RECORD_BYTES
    }
}

/// Canonical JSON Value digest used for the complete quarantined request body.
pub fn body_digest(value: &Value) -> Result<String, String> {
    digest(value)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdempotencyKey {
    pub peer_id: String,
    pub operation: String,
    pub scope: String,
    pub request_id: String,
}
impl IdempotencyKey {
    fn validate(&self) -> Result<(), String> {
        if [
            &self.peer_id,
            &self.operation,
            &self.scope,
            &self.request_id,
        ]
        .iter()
        .any(|value| !label(value))
        {
            return Err(
                "idempotency needs bounded sender, operation, scope and request identity".into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartnerOutcomeKind {
    Received,
    Rejected,
    Abstained,
    Failed,
}

/// Prospective operational telemetry only. No reward, truth labels, partner
/// selection policy or learning promotion can be inferred from this record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartnerOutcomeRecord {
    pub interaction_id: String,
    pub peer_id: String,
    pub scope: String,
    pub kind: PartnerOutcomeKind,
    pub receipt_sha256: Option<String>,
    pub resource_units: u64,
}

/// Persisted before the corresponding RPC. Eligibility, rational score and
/// declared budgets are bounded inert details interpreted by the frozen policy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartnerDecisionRecord {
    pub decision_id: String,
    pub context: String,
    pub frontier_edge: Option<usize>,
    pub selected_peer: Option<String>,
    pub details: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartnerInteractionOutcome {
    VerifiedNovel,
    VerificationFailed,
    ApplicabilityFailed,
    TransportFailed,
    EmptyOffer,
    SkippedIrrelevant,
}

/// One completed operational attempt, never an independent scientific sample or
/// an improvement proof. Transport failure is distinct from false knowledge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartnerInteractionRecord {
    pub interaction_id: String,
    pub decision_id: String,
    pub peer_id: String,
    pub context: String,
    pub outcome: PartnerInteractionOutcome,
    pub receipt_sha256: Option<String>,
    pub sent_bytes: u64,
    pub received_bytes: u64,
    pub resource_units: u64,
    pub subsequently_used: bool,
}

/// Public audit of an explicitly reviewed verified restore relocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRelocation {
    pub restore_mapping_sha256: String,
    pub prior_state: String,
    pub restored_state: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationalEvent {
    Quarantined {
        key: IdempotencyKey,
        candidate_id: String,
        body_sha256: String,
        body: Value,
        response: Value,
    },
    EvaluationPrepared {
        candidate_id: String,
        record: KnowledgeRecord,
        fixture_sha256: String,
        response: Value,
    },
    EvaluationCompleted {
        candidate_id: String,
        record_sha256: String,
        response: Value,
    },
    EvaluationRejected {
        candidate_id: String,
        reason: String,
    },
    PeerDenied {
        peer_id: String,
        reason: String,
    },
    /// Local operator-only policy epoch. The service validates both public
    /// manifests; these inert snapshots contain paths/pins, never key bytes.
    LifecycleStarted {
        operation: String,
        expected_head: String,
        intent_sha256: String,
    },
    PolicyTransitioned {
        previous_policy_digest: String,
        policy_digest: String,
        expected_head: String,
        previous_policy: Value,
        policy: Value,
        reviewed_permission_change: bool,
        relocation: Option<PolicyRelocation>,
        reason: String,
    },
    PeerRestored {
        peer_id: String,
        denial_sha256: String,
        reviewed_permission_change: bool,
        policy_digest: String,
        expected_head: String,
        reason: String,
    },
    PartnerOutcomeRecorded {
        outcome: PartnerOutcomeRecord,
    },
    PartnerDecisionRecorded {
        decision: PartnerDecisionRecord,
    },
    PartnerInteractionCompleted {
        interaction: PartnerInteractionRecord,
    },
    /// A genuine own-source observation retained as telemetry. Authentication
    /// happens in the actor before append; this event grants no learning status.
    SourceWarmupRetained {
        context: String,
        receipt_sha256: String,
        receipt: Value,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceWarmupEnvelope {
    schema: String,
    authority_id: String,
    context: String,
    schema_fingerprint: String,
    observer_identity: String,
    sequence: u64,
    id: String,
    edge_id: usize,
    cost: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Genesis {
    event: String,
    version: u32,
    owner_identity: String,
    service_id: String,
    policy_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerRegistration {
    schema: String,
    version: u32,
    owner_identity: String,
    service_id: String,
    policy_digest: String,
    genesis_sha256: String,
}

fn validate_registration(bytes: &[u8], replay: &Replay) -> Result<(), String> {
    if bytes.len() > MAX_OWNER_BYTES {
        return Err("operational owner registration exceeds its byte budget".into());
    }
    let registration: OwnerRegistration = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid operational owner registration: {error}"))?;
    if registration.schema != "symbiote.operational-owner/1"
        || registration.version != 1
        || registration.owner_identity != replay.genesis.owner_identity
        || registration.service_id != replay.genesis.service_id
        || registration.policy_digest != replay.genesis.policy_digest
        || registration.genesis_sha256 != replay.genesis_sha256
    {
        return Err(
            "operational registration differs from its original owner, service, policy or genesis"
                .into(),
        );
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    sequence: usize,
    previous: String,
    payload: Value,
    sha256: String,
}
impl Receipt {
    fn hash(&self) -> Result<String, String> {
        digest(&(self.sequence, &self.previous, &self.payload))
    }
}

#[derive(Clone, Debug)]
enum Stage {
    Quarantined,
    Prepared {
        record_digest: String,
        response: Value,
    },
    Completed,
    Rejected,
}
#[derive(Clone)]
struct LifecycleIntent {
    operation: String,
    expected_head: String,
    intent_sha256: String,
    settlements: usize,
}
fn lifecycle_anchor(event: &OperationalEvent) -> Option<(&'static str, &str)> {
    match event {
        OperationalEvent::PolicyTransitioned { expected_head, .. } => {
            Some(("policy-transition", expected_head))
        }
        OperationalEvent::PeerRestored { expected_head, .. } => {
            Some(("peer-regrant", expected_head))
        }
        _ => None,
    }
}
fn event_digest(event: &OperationalEvent) -> Result<String, String> {
    digest(&serde_json::to_value(event).map_err(|e| e.to_string())?)
}

#[derive(Clone, Default)]
struct State {
    owner_identity: String,
    service_id: String,
    policy_digest: String,
    policy_transitions: usize,
    lifecycle: Option<LifecycleIntent>,
    denial_heads: BTreeMap<String, String>,
    requests: BTreeSet<IdempotencyKey>,
    candidates: BTreeMap<String, (IdempotencyKey, Stage)>,
    denied: BTreeSet<String>,
    outcomes: BTreeSet<String>,
    decisions: BTreeMap<String, (String, Option<String>)>,
    completed_decisions: BTreeSet<String>,
    interactions: BTreeSet<String>,
    source_warmups: BTreeSet<String>,
}
impl State {
    fn validate(&self, event: &OperationalEvent) -> Result<(), String> {
        if let Some(intent) = &self.lifecycle {
            match event {
                OperationalEvent::EvaluationCompleted { .. }
                | OperationalEvent::EvaluationRejected { .. }
                    if intent.settlements < 128 => {}
                _ if lifecycle_anchor(event).is_some_and(|(operation, head)| {
                    operation == intent.operation && head == intent.expected_head
                }) && event_digest(event)? == intent.intent_sha256 => {}
                _ => return Err(
                    "HOLD: lifecycle transaction differs from its exact bounded committed intent"
                        .into(),
                ),
            }
        } else if lifecycle_anchor(event).is_some() {
            return Err("HOLD: lifecycle completion has no exact transaction boundary".into());
        }
        match event {
            OperationalEvent::LifecycleStarted {
                operation,
                expected_head,
                intent_sha256,
            } => {
                if self.service_id != "configured-service/v1"
                    || !["policy-transition", "peer-regrant"].contains(&operation.as_str())
                    || !sha256(expected_head)
                    || !sha256(intent_sha256)
                {
                    return Err("lifecycle boundary needs an exact local service operation, head and intent".into());
                }
            }
            OperationalEvent::Quarantined {
                key,
                candidate_id,
                body_sha256,
                body,
                response,
            } => {
                key.validate()?;
                bounded(body, MAX_BODY_BYTES)?;
                bounded(response, MAX_RESPONSE_BYTES)?;
                if !label(candidate_id)
                    || !sha256(body_sha256)
                    || *body_sha256 != digest(body)?
                    || self.requests.contains(key)
                    || self.candidates.contains_key(candidate_id)
                    || self.candidates.len() >= MAX_IDENTITIES
                    || self.denied.contains(&key.peer_id)
                {
                    return Err("quarantine conflicts with its body hash, request identity, deny policy or candidate budget".into());
                }
            }
            OperationalEvent::EvaluationPrepared {
                candidate_id,
                record,
                fixture_sha256,
                response,
            } => {
                let (key, stage) = self
                    .candidates
                    .get(candidate_id)
                    .ok_or("evaluation requires an existing quarantined candidate")?;
                record.validate()?;
                bounded(response, MAX_RESPONSE_BYTES)?;
                if !matches!(stage, Stage::Quarantined)
                    || !sha256(fixture_sha256)
                    || record.source != key.peer_id
                    || record.scope != key.scope
                    || serde_json::to_vec(record)
                        .map_err(|error| error.to_string())?
                        .len()
                        > MAX_PREPARED_BYTES
                    || self.denied.contains(&key.peer_id)
                {
                    return Err("evaluation intent must bind quarantined sender/scope, local fixture and bounded native record".into());
                }
            }
            OperationalEvent::EvaluationCompleted {
                candidate_id,
                record_sha256,
                response,
            } => {
                bounded(response, MAX_RESPONSE_BYTES)?;
                let (_, stage) = self
                    .candidates
                    .get(candidate_id)
                    .ok_or("evaluation completion requires a prepared candidate")?;
                if !matches!(stage,Stage::Prepared {record_digest:expected,response:planned} if expected == record_sha256 && planned == response)
                {
                    return Err("evaluation completion must match its pending record digest".into());
                }
            }
            OperationalEvent::EvaluationRejected {
                candidate_id,
                reason: message,
            } => {
                let (_, stage) = self
                    .candidates
                    .get(candidate_id)
                    .ok_or("evaluation rejection requires a quarantined candidate")?;
                if !matches!(stage, Stage::Quarantined | Stage::Prepared { .. }) || !reason(message)
                {
                    return Err(
                        "evaluation rejection requires a nonterminal candidate and bounded reason"
                            .into(),
                    );
                }
            }
            OperationalEvent::PeerDenied {
                peer_id,
                reason: message,
            } => {
                if !label(peer_id)
                    || !reason(message)
                    || (!self.denied.contains(peer_id) && self.denied.len() >= MAX_IDENTITIES)
                {
                    return Err("operational denial requires a bounded known-peer label, reason and available deny budget".into());
                }
            }
            OperationalEvent::PolicyTransitioned {
                previous_policy_digest,
                policy_digest,
                expected_head,
                previous_policy,
                policy,
                reason: message,
                relocation,
                ..
            } => {
                if relocation.as_ref().is_some_and(|proof| {
                    !sha256(&proof.restore_mapping_sha256)
                        || proof.prior_state.is_empty()
                        || proof.prior_state.len() > 4096
                        || proof.restored_state.is_empty()
                        || proof.restored_state.len() > 4096
                }) {
                    return Err("policy relocation needs a bounded verified restore mapping".into());
                }
                bounded(previous_policy, MAX_SERVICE_POLICY_BYTES)?;
                bounded(policy, MAX_SERVICE_POLICY_BYTES)?;
                if self.service_id != "configured-service/v1"
                    || self.policy_transitions >= 16
                    || previous_policy_digest != &self.policy_digest
                    || (previous_policy_digest == policy_digest && relocation.is_none())
                    || !sha256(expected_head)
                    || digest(previous_policy)? != *previous_policy_digest
                    || digest(policy)? != *policy_digest
                    || !reason(message)
                    || self.candidates.values().any(|(_, stage)| {
                        matches!(stage, Stage::Quarantined | Stage::Prepared { .. })
                    })
                {
                    return Err("policy transition needs the current policy, validated public snapshots, settled candidates and bounded local intent".into());
                }
            }
            OperationalEvent::PeerRestored {
                peer_id,
                denial_sha256,
                reviewed_permission_change,
                policy_digest,
                expected_head,
                reason: message,
            } => {
                if self.service_id != "configured-service/v1"
                    || !reviewed_permission_change
                    || self.candidates.values().any(|(key, stage)| {
                        key.peer_id == *peer_id
                            && matches!(stage, Stage::Quarantined | Stage::Prepared { .. })
                    })
                    || !self.denied.contains(peer_id)
                    || self.denial_heads.get(peer_id) != Some(denial_sha256)
                    || policy_digest != &self.policy_digest
                    || !sha256(expected_head)
                    || !reason(message)
                {
                    return Err("peer regrant needs its current policy, exact latest denial and explicit bounded local intent".into());
                }
            }
            OperationalEvent::PartnerOutcomeRecorded { outcome } => {
                if [&outcome.interaction_id, &outcome.peer_id, &outcome.scope]
                    .iter()
                    .any(|value| !label(value))
                    || outcome
                        .receipt_sha256
                        .as_ref()
                        .is_some_and(|value| !sha256(value))
                    || outcome.resource_units > 1_000_000_000
                    || self.outcomes.contains(&outcome.interaction_id)
                    || self.interactions.contains(&outcome.interaction_id)
                    || self.outcomes.len() >= MAX_IDENTITIES
                {
                    return Err("partner outcome needs a unique bounded identity and inert measured metadata".into());
                }
            }
            OperationalEvent::PartnerDecisionRecorded { decision } => {
                bounded(&decision.details, MAX_RESPONSE_BYTES)?;
                if !label(&decision.decision_id)
                    || !label(&decision.context)
                    || decision.frontier_edge.is_some_and(|edge| edge >= 56)
                    || decision
                        .selected_peer
                        .as_ref()
                        .is_some_and(|peer| !label(peer) || self.denied.contains(peer))
                    || !decision.details.is_object()
                    || self.decisions.contains_key(&decision.decision_id)
                    || self.decisions.len() >= MAX_DECISIONS
                {
                    return Err("partner decision requires unique bounded identity, frontier and eligible peer metadata".into());
                }
            }
            OperationalEvent::PartnerInteractionCompleted { interaction } => {
                let (context, peer) = self
                    .decisions
                    .get(&interaction.decision_id)
                    .ok_or("partner interaction requires a previously committed decision")?;
                if !label(&interaction.interaction_id)
                    || !label(&interaction.peer_id)
                    || context != &interaction.context
                    || peer.as_ref() != Some(&interaction.peer_id)
                    || self.completed_decisions.contains(&interaction.decision_id)
                    || self.interactions.contains(&interaction.interaction_id)
                    || self.outcomes.contains(&interaction.interaction_id)
                    || self.interactions.len() >= MAX_IDENTITIES
                    || interaction
                        .receipt_sha256
                        .as_ref()
                        .is_some_and(|value| !sha256(value))
                    || interaction.resource_units > 1_000_000_000
                    || interaction
                        .sent_bytes
                        .checked_add(interaction.received_bytes)
                        .is_none_or(|bytes| bytes > 1_000_000_000)
                    || (interaction.outcome == PartnerInteractionOutcome::VerifiedNovel
                        && interaction.receipt_sha256.is_none())
                    || (interaction.subsequently_used
                        && interaction.outcome != PartnerInteractionOutcome::VerifiedNovel)
                    || (interaction.outcome == PartnerInteractionOutcome::SkippedIrrelevant
                        && (interaction.sent_bytes != 0
                            || interaction.received_bytes != 0
                            || interaction.receipt_sha256.is_some()))
                {
                    return Err("partner interaction must uniquely complete its prior decision with bound peer/context and consistent operational counters".into());
                }
            }
            OperationalEvent::SourceWarmupRetained {
                context,
                receipt_sha256,
                receipt,
            } => {
                bounded(receipt, 2048)?;
                let envelope: SourceWarmupEnvelope = serde_json::from_value(receipt.clone())
                    .map_err(|_| "source warmup has an unsupported observation envelope")?;
                if !label(context)
                    || !sha256(receipt_sha256)
                    || *receipt_sha256 != digest(receipt)?
                    || envelope.schema != "symbiote.graph-observation/1"
                    || !label(&envelope.authority_id)
                    || !sha256(&envelope.schema_fingerprint)
                    || !sha256(&envelope.id)
                    || envelope.sequence == 0
                    || envelope.edge_id >= 56
                    || !(1..=9).contains(&envelope.cost)
                    || envelope.context != *context
                    || envelope.observer_identity != self.owner_identity
                    || self.source_warmups.contains(context)
                    || self.source_warmups.len() >= MAX_SOURCE_WARMUPS
                {
                    return Err("source warmup must bind its owner/context/digest uniquely within the25context budget".into());
                }
            }
        }
        Ok(())
    }
    fn apply(&mut self, event: &OperationalEvent, receipt_sha256: &str) -> Result<(), String> {
        if let Some(intent) = &mut self.lifecycle {
            if matches!(
                event,
                OperationalEvent::EvaluationCompleted { .. }
                    | OperationalEvent::EvaluationRejected { .. }
            ) {
                intent.settlements += 1;
            }
        }
        match event {
            OperationalEvent::LifecycleStarted {
                operation,
                expected_head,
                intent_sha256,
            } => {
                self.lifecycle = Some(LifecycleIntent {
                    operation: operation.clone(),
                    expected_head: expected_head.clone(),
                    intent_sha256: intent_sha256.clone(),
                    settlements: 0,
                });
            }
            OperationalEvent::Quarantined {
                key, candidate_id, ..
            } => {
                self.requests.insert(key.clone());
                self.candidates
                    .insert(candidate_id.clone(), (key.clone(), Stage::Quarantined));
            }
            OperationalEvent::EvaluationPrepared {
                candidate_id,
                record,
                response,
                ..
            } => {
                self.candidates
                    .get_mut(candidate_id)
                    .ok_or("prepared candidate missing")?
                    .1 = Stage::Prepared {
                    record_digest: record.digest()?,
                    response: response.clone(),
                };
            }
            OperationalEvent::EvaluationCompleted { candidate_id, .. } => {
                self.candidates
                    .get_mut(candidate_id)
                    .ok_or("completed candidate missing")?
                    .1 = Stage::Completed;
            }
            OperationalEvent::EvaluationRejected { candidate_id, .. } => {
                self.candidates
                    .get_mut(candidate_id)
                    .ok_or("rejected candidate missing")?
                    .1 = Stage::Rejected;
            }
            OperationalEvent::PeerDenied { peer_id, .. } => {
                self.denied.insert(peer_id.clone());
                self.denial_heads
                    .insert(peer_id.clone(), receipt_sha256.into());
            }
            OperationalEvent::PolicyTransitioned { policy_digest, .. } => {
                self.policy_digest.clone_from(policy_digest);
                self.policy_transitions += 1;
                self.lifecycle = None;
            }
            OperationalEvent::PeerRestored { peer_id, .. } => {
                self.denied.remove(peer_id);
                self.lifecycle = None;
            }
            OperationalEvent::PartnerOutcomeRecorded { outcome } => {
                self.outcomes.insert(outcome.interaction_id.clone());
            }
            OperationalEvent::PartnerDecisionRecorded { decision } => {
                self.decisions.insert(
                    decision.decision_id.clone(),
                    (decision.context.clone(), decision.selected_peer.clone()),
                );
            }
            OperationalEvent::PartnerInteractionCompleted { interaction } => {
                self.completed_decisions
                    .insert(interaction.decision_id.clone());
                self.interactions.insert(interaction.interaction_id.clone());
            }
            OperationalEvent::SourceWarmupRetained { context, .. } => {
                self.source_warmups.insert(context.clone());
            }
        }
        Ok(())
    }
}

struct Replay {
    genesis: Genesis,
    genesis_sha256: String,
    events: Vec<OperationalEvent>,
    state: State,
    last_hash: String,
    count: usize,
}
fn replay(bytes: &[u8], owner: &str) -> Result<Replay, String> {
    if bytes.is_empty() || bytes.len() > crate::MAX_LEDGER_BYTES || bytes.last() != Some(&b'\n') {
        return Err("operational journal is empty, truncated or exceeds its byte budget".into());
    }
    let mut last_hash = ZERO_HASH.to_string();
    let mut genesis = None;
    let mut genesis_sha256 = String::new();
    let mut events = Vec::new();
    let mut state = State::default();
    let raw = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    let mut count = 0;
    for (sequence, line) in raw.lines().enumerate() {
        if sequence >= crate::MAX_RECORDS || line.is_empty() || line.len() > MAX_POLICY_RECORD_BYTES
        {
            return Err("operational journal record exceeds count/byte limits or is empty".into());
        }
        let row: Receipt = serde_json::from_str(line)
            .map_err(|error| format!("invalid operational receipt {sequence}: {error}"))?;
        if line.len() > record_limit(&row.payload) {
            return Err("operational record exceeds its event-specific byte limit".into());
        }
        if row.sequence != sequence || row.previous != last_hash || row.sha256 != row.hash()? {
            return Err(format!(
                "operational journal hash chain mismatch at receipt {sequence}"
            ));
        }
        if sequence == 0 {
            let first: Genesis =
                serde_json::from_value(row.payload.clone()).map_err(|error| error.to_string())?;
            if first.event != "genesis"
                || first.version != 1
                || first.owner_identity != owner
                || !label(&first.owner_identity)
                || !label(&first.service_id)
                || !sha256(&first.policy_digest)
            {
                return Err(
                    "operational genesis version, policy or persistent owner mismatch".into(),
                );
            }
            genesis = Some(first);
            state.owner_identity = owner.into();
            state
                .service_id
                .clone_from(&genesis.as_ref().unwrap().service_id);
            state
                .policy_digest
                .clone_from(&genesis.as_ref().unwrap().policy_digest);
            genesis_sha256 = row.sha256.clone();
        } else {
            let event: OperationalEvent = serde_json::from_value(row.payload.clone())
                .map_err(|error| format!("unsupported operational event: {error}"))?;
            if let OperationalEvent::LifecycleStarted { expected_head, .. } = &event {
                if expected_head != &last_hash {
                    return Err("HOLD: lifecycle boundary does not bind its immediately preceding journal head".into());
                }
            }
            state.validate(&event)?;
            state.apply(&event, &row.sha256)?;
            events.push(event);
        }
        last_hash = row.sha256;
        count += 1;
    }
    if state.lifecycle.is_some() {
        return Err("HOLD: incomplete lifecycle transaction; preserve and restore the complete atomic journal".into());
    }
    Ok(Replay {
        genesis: genesis.ok_or("operational genesis missing")?,
        genesis_sha256,
        events,
        state,
        last_hash,
        count,
    })
}

/// Maintenance checks typed operational consistency and owner/integrity. It
/// cannot check current peer grants or the truth/authority of a local fixture.
pub(crate) fn validate_snapshot(
    bytes: &[u8],
    owner: &str,
    registration: &[u8],
) -> Result<(), String> {
    validate_registration(registration, &replay(bytes, owner)?)
}

struct Lease {
    owner: Arc<Store>,
}
impl Lease {
    fn acquire(owner: Arc<Store>) -> Result<Self, String> {
        if owner._lock.is_none() {
            return Err("operational journal requires a live original Store writer guard".into());
        }
        owner
            .operational_lease
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "only one operational journal may use a Store writer guard")?;
        Ok(Self { owner })
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.owner.operational_lease.store(false, Ordering::Release);
    }
}

/// Retains the real Store lock through an Arc guard. Cloned Arcs cannot create
/// competing journals; maintenance/recovery remains blocked for its lifetime.
pub struct OperationalJournal {
    lease: Lease,
    genesis: Genesis,
    events: Vec<OperationalEvent>,
    state: State,
    committed: Vec<u8>,
    last_hash: String,
    count: usize,
}
impl OperationalJournal {
    pub fn open(owner: Arc<Store>, service_id: &str, policy_digest: &str) -> Result<Self, String> {
        Self::open_with_initialization_hook(owner, service_id, policy_digest, || Ok(()))
    }
    // A private supervised test boundary; never controlled by service requests.
    fn open_with_initialization_hook(
        owner: Arc<Store>,
        service_id: &str,
        policy_digest: &str,
        before_genesis: impl FnOnce() -> Result<(), String>,
    ) -> Result<Self, String> {
        Self::open_internal(owner, service_id, policy_digest, before_genesis)
    }
    fn open_internal(
        owner: Arc<Store>,
        service_id: &str,
        policy_digest: &str,
        before_genesis: impl FnOnce() -> Result<(), String>,
    ) -> Result<Self, String> {
        if !label(service_id) || !sha256(policy_digest) {
            return Err(
                "operational service identity and policy digest must be bounded and valid".into(),
            );
        }
        let lease = Lease::acquire(owner)?;
        let directory = &lease.owner.directory;
        maintenance::validate_layout_identity(directory, lease.owner.identity())?;
        let path = directory.join(FILE_NAME);
        let registration = maintenance::read_regular(&directory.join(OWNER_FILE), MAX_OWNER_BYTES)?;
        let committed = maintenance::read_regular(&path, crate::MAX_LEDGER_BYTES)?;
        if registration.is_some() != committed.is_some() {
            return Err("HOLD: operational journal/owner registration is missing; preserve the surviving file and restore history, never reset denial or idempotency state".into());
        }
        if let Some(bytes) = committed {
            let replay = replay(&bytes, lease.owner.identity())?;
            validate_registration(
                registration
                    .as_ref()
                    .ok_or("operational owner registration missing")?,
                &replay,
            )?;
            if replay.genesis.service_id != service_id
                || replay.state.policy_digest != policy_digest
            {
                return Err("HOLD: operational service/policy changed; preserve deny and idempotency history and use an explicit supported policy revision".into());
            }
            return Ok(Self {
                lease,
                genesis: replay.genesis,
                events: replay.events,
                state: replay.state,
                committed: bytes,
                last_hash: replay.last_hash,
                count: replay.count,
            });
        }
        let genesis = Genesis {
            event: "genesis".into(),
            version: 1,
            owner_identity: lease.owner.identity().into(),
            service_id: service_id.into(),
            policy_digest: policy_digest.into(),
        };
        let mut row = Receipt {
            sequence: 0,
            previous: ZERO_HASH.into(),
            payload: serde_json::to_value(&genesis).map_err(|error| error.to_string())?,
            sha256: String::new(),
        };
        row.sha256 = row.hash()?;
        let mut committed = serde_json::to_vec(&row).map_err(|error| error.to_string())?;
        committed.push(b'\n');
        let registration = OwnerRegistration {
            schema: "symbiote.operational-owner/1".into(),
            version: 1,
            owner_identity: genesis.owner_identity.clone(),
            service_id: genesis.service_id.clone(),
            policy_digest: genesis.policy_digest.clone(),
            genesis_sha256: row.sha256.clone(),
        };
        let registration_bytes =
            serde_json::to_vec(&registration).map_err(|error| error.to_string())?;
        maintenance::atomic_replace(directory, OWNER_FILE, &registration_bytes)?;
        // The registration is durable first. A crash at this boundary leaves a
        // deliberate HOLD rather than permission to initialize empty history.
        before_genesis()?;
        maintenance::atomic_replace(directory, FILE_NAME, &committed)?;
        let state = State {
            owner_identity: genesis.owner_identity.clone(),
            service_id: genesis.service_id.clone(),
            policy_digest: genesis.policy_digest.clone(),
            ..State::default()
        };
        Ok(Self {
            lease,
            genesis,
            events: Vec::new(),
            state,
            committed,
            last_hash: row.sha256,
            count: 1,
        })
    }
    pub fn events(&self) -> &[OperationalEvent] {
        &self.events
    }
    pub fn record_count(&self) -> usize {
        self.count
    }
    pub fn ledger_path(&self) -> PathBuf {
        self.lease.owner.directory.join(FILE_NAME)
    }
    pub fn identity(&self) -> &str {
        &self.genesis.owner_identity
    }
    pub fn service_id(&self) -> &str {
        &self.genesis.service_id
    }
    pub fn policy_digest(&self) -> &str {
        &self.state.policy_digest
    }
    pub fn genesis_policy_digest(&self) -> &str {
        &self.genesis.policy_digest
    }
    pub fn head_sha256(&self) -> &str {
        &self.last_hash
    }
    pub fn latest_denial_sha256(&self, peer: &str) -> Option<&str> {
        self.state.denial_heads.get(peer).map(String::as_str)
    }
    pub fn denied_peers(&self) -> BTreeSet<String> {
        self.state.denied.clone()
    }
    pub fn quarantined(&self, key: &IdempotencyKey) -> Option<&OperationalEvent> {
        self.events.iter().find(
            |event| matches!(event,OperationalEvent::Quarantined {key:prior,..} if prior==key),
        )
    }
    pub fn append(&mut self, event: OperationalEvent) -> Result<(), String> {
        self.append_checked_batch(&self.last_hash.clone(), vec![event])
    }
    /// Atomically append a bounded operator transaction against one exact head.
    /// All rows are validated before the sole durable replacement. Existing
    /// bytes remain an exact prefix; a crash leaves the old or complete new
    /// journal, never a policy change separated from candidate cancellation.
    pub fn append_checked_batch(
        &mut self,
        expected_head: &str,
        events: Vec<OperationalEvent>,
    ) -> Result<(), String> {
        self.append_checked_batch_with_hooks(expected_head, events, || Ok(()), || {})
    }
    fn append_checked_batch_with_hooks(
        &mut self,
        expected_head: &str,
        mut events: Vec<OperationalEvent>,
        before_publish: impl FnOnce() -> Result<(), String>,
        after_publish: impl FnOnce(),
    ) -> Result<(), String> {
        if expected_head != self.last_hash || events.is_empty() || events.len() > 129 {
            return Err(
                "HOLD: stale journal head or unsupported operational transaction size".into(),
            );
        }
        if events
            .iter()
            .any(|event| matches!(event, OperationalEvent::LifecycleStarted { .. }))
        {
            return Err("caller-supplied lifecycle boundaries are forbidden".into());
        }
        let boundary = events
            .last()
            .and_then(lifecycle_anchor)
            .map(|(operation, head)| (operation.to_string(), head.to_string()));
        if let Some((operation, anchor)) = boundary {
            if anchor != expected_head
                || events[..events.len() - 1].iter().any(|event| {
                    !matches!(
                        event,
                        OperationalEvent::EvaluationCompleted { .. }
                            | OperationalEvent::EvaluationRejected { .. }
                    )
                })
            {
                return Err("lifecycle batch must contain only terminal settlements followed by its exact final intent".into());
            }
            let intent_sha256 = event_digest(events.last().ok_or("missing lifecycle intent")?)?;
            events.insert(
                0,
                OperationalEvent::LifecycleStarted {
                    operation,
                    expected_head: anchor,
                    intent_sha256,
                },
            );
        } else if events.iter().any(|event| lifecycle_anchor(event).is_some()) {
            return Err("lifecycle intent must terminate its atomic batch".into());
        }
        let mut state = self.state.clone();
        let mut bytes = self.committed.clone();
        let mut last_hash = self.last_hash.clone();
        let mut count = self.count;
        for event in &events {
            if let OperationalEvent::PolicyTransitioned {
                expected_head: anchor,
                ..
            }
            | OperationalEvent::PeerRestored {
                expected_head: anchor,
                ..
            } = event
            {
                if anchor != expected_head {
                    return Err(
                        "HOLD: lifecycle intent does not bind this exact transaction head".into(),
                    );
                }
            }
            state.validate(event)?;
            if count >= crate::MAX_RECORDS {
                return Err("operational journal record budget exhausted".into());
            }
            let mut row = Receipt {
                sequence: count,
                previous: last_hash,
                payload: serde_json::to_value(event).map_err(|error| error.to_string())?,
                sha256: String::new(),
            };
            row.sha256 = row.hash()?;
            let line = serde_json::to_vec(&row).map_err(|error| error.to_string())?;
            if line.len() > record_limit(&row.payload) {
                return Err("operational record byte budget exhausted".into());
            }
            bytes.extend_from_slice(&line);
            bytes.push(b'\n');
            if bytes.len() > crate::MAX_LEDGER_BYTES {
                return Err("operational journal byte budget exhausted".into());
            }
            state.apply(event, &row.sha256)?;
            last_hash = row.sha256;
            count += 1;
        }
        if state.lifecycle.is_some() {
            return Err("HOLD: incomplete lifecycle batch cannot be published".into());
        }
        before_publish()?;
        maintenance::atomic_replace(&self.lease.owner.directory, FILE_NAME, &bytes)?;
        after_publish();
        self.committed = bytes;
        self.last_hash = last_hash;
        self.count = count;
        self.state = state;
        self.events.extend(events);
        Ok(())
    }
}

#[cfg(test)]
mod policy_lifecycle_tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "symbiote-policy-unit-{}-{}",
                std::process::id(),
                crate::TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn policy(index: u64) -> Value {
        json!({"manifest":{"public_policy_fixture":index},"ca_sha256":"a".repeat(64)})
    }
    fn transition(old: &Value, new: &Value, head: &str) -> OperationalEvent {
        OperationalEvent::PolicyTransitioned {
            previous_policy_digest: digest(old).unwrap(),
            policy_digest: digest(new).unwrap(),
            expected_head: head.into(),
            previous_policy: old.clone(),
            policy: new.clone(),
            reviewed_permission_change: false,
            relocation: None,
            reason: "explicit native unit operator".into(),
        }
    }
    fn quarantine() -> OperationalEvent {
        let body = json!({"inert":"pending fixture"});
        OperationalEvent::Quarantined {
            key: IdempotencyKey {
                peer_id: "peer".into(),
                operation: "submit".into(),
                scope: "scope".into(),
                request_id: "request".into(),
            },
            candidate_id: "candidate".into(),
            body_sha256: digest(&body).unwrap(),
            body,
            response: json!({"pending":true}),
        }
    }
    #[test]
    fn checked_policy_batch_preserves_genesis_marker_and_prefix_or_changes_nothing() {
        let dir = Directory::new();
        let owner = Arc::new(Store::open(&dir.0).unwrap());
        let old = policy(0);
        let new = policy(1);
        let mut journal = OperationalJournal::open(
            Arc::clone(&owner),
            "configured-service/v1",
            &digest(&old).unwrap(),
        )
        .unwrap();
        journal.append(quarantine()).unwrap();
        let original = fs::read(journal.ledger_path()).unwrap();
        let marker = fs::read(dir.0.join(OWNER_FILE)).unwrap();
        let head = journal.head_sha256().to_string();
        assert!(journal
            .append_checked_batch(&"f".repeat(64), vec![transition(&old, &new, &head)])
            .is_err());
        assert!(
            journal
                .append_checked_batch(&head, vec![transition(&old, &new, &head)])
                .is_err(),
            "unsettled candidate forbids policy change"
        );
        assert_eq!(fs::read(journal.ledger_path()).unwrap(), original);
        let events = vec![
            OperationalEvent::EvaluationRejected {
                candidate_id: "candidate".into(),
                reason: "operator transition canceled pending intent".into(),
            },
            transition(&old, &new, &head),
        ];
        journal.append_checked_batch(&head, events).unwrap();
        assert!(fs::read(journal.ledger_path())
            .unwrap()
            .starts_with(&original));
        assert_eq!(fs::read(dir.0.join(OWNER_FILE)).unwrap(), marker);
        drop(journal);
        assert!(OperationalJournal::open(
            Arc::clone(&owner),
            "configured-service/v1",
            &digest(&old).unwrap()
        )
        .is_err());
        let reopened = OperationalJournal::open(
            Arc::clone(&owner),
            "configured-service/v1",
            &digest(&new).unwrap(),
        )
        .unwrap();
        assert_eq!(reopened.genesis_policy_digest(), digest(&old).unwrap());
        assert_eq!(reopened.policy_digest(), digest(&new).unwrap());
    }
    #[test]
    fn policy_publication_cutpoints_reopen_old_or_complete_new_without_partial_settlement() {
        for after_publication in [false, true] {
            let dir = Directory::new();
            let owner = Arc::new(Store::open(&dir.0).unwrap());
            let old = policy(0);
            let new = policy(1);
            let mut journal = OperationalJournal::open(
                Arc::clone(&owner),
                "configured-service/v1",
                &digest(&old).unwrap(),
            )
            .unwrap();
            journal.append(quarantine()).unwrap();
            let original = fs::read(journal.ledger_path()).unwrap();
            let marker = fs::read(dir.0.join(OWNER_FILE)).unwrap();
            let head = journal.head_sha256().to_string();
            let events = vec![
                OperationalEvent::EvaluationRejected {
                    candidate_id: "candidate".into(),
                    reason: "cancel at atomic policy boundary".into(),
                },
                transition(&old, &new, &head),
            ];
            if after_publication {
                let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    journal.append_checked_batch_with_hooks(
                        &head,
                        events,
                        || Ok(()),
                        || panic!("modeled process interruption after publication"),
                    )
                }));
                assert!(interrupted.is_err());
            } else {
                assert!(journal
                    .append_checked_batch_with_hooks(
                        &head,
                        events,
                        || Err("modeled interruption before publication".into()),
                        || {}
                    )
                    .is_err());
            }
            drop(journal);
            let approved = if after_publication { &new } else { &old };
            let reopened = OperationalJournal::open(
                Arc::clone(&owner),
                "configured-service/v1",
                &digest(approved).unwrap(),
            )
            .unwrap();
            assert_eq!(
                reopened.events().len(),
                if after_publication { 4 } else { 1 }
            );
            let recovered = fs::read(reopened.ledger_path()).unwrap();
            if after_publication {
                assert!(recovered.starts_with(&original));
            } else {
                assert_eq!(recovered, original);
            }
            assert_eq!(fs::read(dir.0.join(OWNER_FILE)).unwrap(), marker);
        }
    }
    #[test]
    fn regrant_requires_exact_latest_denial_current_policy_and_head() {
        let dir = Directory::new();
        let owner = Arc::new(Store::open(&dir.0).unwrap());
        let public = policy(0);
        let policy = digest(&public).unwrap();
        let mut journal =
            OperationalJournal::open(owner, "configured-service/v1", &policy).unwrap();
        journal
            .append(OperationalEvent::PeerDenied {
                peer_id: "peer".into(),
                reason: "first denial".into(),
            })
            .unwrap();
        let first = journal.latest_denial_sha256("peer").unwrap().to_string();
        journal
            .append(OperationalEvent::PeerDenied {
                peer_id: "peer".into(),
                reason: "latest denial".into(),
            })
            .unwrap();
        let head = journal.head_sha256().to_string();
        let event = |denial: String| OperationalEvent::PeerRestored {
            peer_id: "peer".into(),
            denial_sha256: denial,
            reviewed_permission_change: true,
            policy_digest: policy.clone(),
            expected_head: head.clone(),
            reason: "explicit reviewed regrant".into(),
        };
        let original = fs::read(journal.ledger_path()).unwrap();
        assert!(journal.append(event(first)).is_err());
        assert_eq!(fs::read(journal.ledger_path()).unwrap(), original);
        journal
            .append(event(
                journal.latest_denial_sha256("peer").unwrap().to_string(),
            ))
            .unwrap();
        assert!(!journal.denied_peers().contains("peer"));
    }
}

#[cfg(test)]
mod lifecycle_anchor_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn rehashed_final_intent_cannot_move_to_an_older_known_head_with_or_without_settlements() {
        for settlements in [false, true] {
            let dir = std::env::temp_dir().join(format!(
                "symbiote-policy-anchor-{}-{}",
                std::process::id(),
                crate::TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            let owner = Arc::new(Store::open(&dir).unwrap());
            let identity = owner.identity().to_string();
            let old = json!({"public":0});
            let new = json!({"public":1});
            let mut journal = OperationalJournal::open(
                Arc::clone(&owner),
                "configured-service/v1",
                &digest(&old).unwrap(),
            )
            .unwrap();
            let genesis_head = journal.head_sha256().to_string();
            let mut rows = Vec::new();
            if settlements {
                let body = json!({"inert":true});
                journal
                    .append(OperationalEvent::Quarantined {
                        key: IdempotencyKey {
                            peer_id: "peer".into(),
                            operation: "submit".into(),
                            scope: "scope".into(),
                            request_id: "request".into(),
                        },
                        candidate_id: "candidate".into(),
                        body_sha256: digest(&body).unwrap(),
                        body,
                        response: json!({}),
                    })
                    .unwrap();
                rows.push(OperationalEvent::EvaluationRejected {
                    candidate_id: "candidate".into(),
                    reason: "explicit transition cancellation".into(),
                });
            } else {
                journal
                    .append(OperationalEvent::PeerDenied {
                        peer_id: "peer".into(),
                        reason: "record before the transition".into(),
                    })
                    .unwrap();
            }
            let head = journal.head_sha256().to_string();
            rows.push(OperationalEvent::PolicyTransitioned {
                previous_policy_digest: digest(&old).unwrap(),
                policy_digest: digest(&new).unwrap(),
                expected_head: head.clone(),
                previous_policy: old,
                policy: new,
                reviewed_permission_change: false,
                relocation: None,
                reason: "operator intent".into(),
            });
            journal.append_checked_batch(&head, rows).unwrap();
            let committed = std::fs::read(journal.ledger_path()).unwrap();
            let mut receipts = String::from_utf8(committed.clone())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<Receipt>(line).unwrap())
                .collect::<Vec<_>>();
            let last = receipts.last_mut().unwrap();
            last.payload["expected_head"] = json!(genesis_head);
            last.sha256 = last.hash().unwrap();
            let mutated = receipts
                .iter()
                .flat_map(|row| {
                    let mut bytes = serde_json::to_vec(row).unwrap();
                    bytes.push(b'\n');
                    bytes
                })
                .collect::<Vec<_>>();
            assert!(
                replay(&mutated, &identity).is_err(),
                "rehashing the final row cannot replace its recorded exact intent"
            );
            let boundary = receipts
                .iter()
                .position(|row| row.payload["event"] == "lifecycle_started")
                .unwrap();
            let incomplete = String::from_utf8(committed)
                .unwrap()
                .lines()
                .take(boundary + 1)
                .map(|line| format!("{line}\n"))
                .collect::<String>();
            assert!(
                replay(incomplete.as_bytes(), &identity).is_err(),
                "a valid hash prefix ending in a transaction boundary remains HOLD"
            );
            drop(journal);
            drop(owner);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}

#[cfg(test)]
mod tests;
