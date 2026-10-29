//! Owner-bound operational audit, separate from evaluated learning evidence.
//!
//! These records express operator policy, quarantine and request outcomes. They
//! do not prove improvement or authenticate a remote source. The service must
//! enforce its configured peer grants and local fixture authority on every call
//! and replay. Hashes detect accidental corruption, not a full ledger rewrite.
use crate::{digest, knowledge::KnowledgeRecord, maintenance, Store};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

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

/// Actual prefix-index work, separate from reasoning units and learning rewards.
/// Byte counts are application bytes supplied to canonical JSON/SHA-256, not
/// allocator overhead, hash padding or exclusive CPU time. Memory is the index's
/// inline size plus reserved digest storage, not whole-process peak memory.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PrefixWork {
    pub canonicalized_bytes: u64,
    pub hashed_bytes: u64,
    pub event_visits: u64,
    pub cache_reads: u64,
    pub reference_reads: u64,
    pub reference_event_visits: u64,
    pub reference_canonicalized_bytes: u64,
    pub reference_hashed_bytes: u64,
    pub ledger_bytes_read: u64,
    pub durable_bytes_written: u64,
    pub committed_bytes_cloned: u64,
    pub index_bytes: u64,
    pub index_elapsed_ns: u64,
    pub reference_elapsed_ns: u64,
    pub saturated: bool,
}
fn add_count(target: &mut u64, amount: u64) -> bool {
    let overflow = target.checked_add(amount).is_none();
    *target = target.saturating_add(amount);
    overflow
}
fn elapsed(start: Instant) -> u64 {
    start.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}
struct PrefixIndex {
    // Hash of '[' + canonical elements/commas, deliberately without ']'.
    state: Sha256,
    digests: Vec<[u8; 32]>,
    work: RefCell<PrefixWork>,
    indexed: bool,
}
impl PrefixIndex {
    fn new(indexed: bool) -> Self {
        let mut state = Sha256::new();
        let mut digests = Vec::new();
        if indexed {
            state.update(b"[");
            let mut closed = state.clone();
            closed.update(b"]");
            digests.push(closed.finalize().into());
        }
        Self {
            state,
            digests,
            work: RefCell::new(PrefixWork {
                hashed_bytes: if indexed { 2 } else { 0 },
                ..PrefixWork::default()
            }),
            indexed,
        }
    }
    fn advance(
        &self,
        state: &mut Sha256,
        event: &OperationalEvent,
        previous_events: usize,
    ) -> Result<[u8; 32], String> {
        let started = Instant::now();
        // Value serialization matches the retained whole-array reference's
        // ordering/escaping exactly, including arbitrary nested JSON objects.
        let value = serde_json::to_value(event).map_err(|error| error.to_string())?;
        let bytes = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
        if previous_events != 0 {
            state.update(b",");
        }
        state.update(&bytes);
        let mut closed = state.clone();
        closed.update(b"]");
        let result = closed.finalize().into();
        let mut work = self.work.borrow_mut();
        work.saturated |= add_count(&mut work.canonicalized_bytes, bytes.len() as u64);
        work.saturated |= add_count(
            &mut work.hashed_bytes,
            bytes.len() as u64 + u64::from(previous_events != 0) + 1,
        );
        work.saturated |= add_count(&mut work.event_visits, 1);
        work.saturated |= add_count(&mut work.index_elapsed_ns, elapsed(started));
        Ok(result)
    }
    fn append_replayed(&mut self, event: &OperationalEvent) -> Result<(), String> {
        if !self.indexed {
            return Ok(());
        }
        let mut state = self.state.clone();
        let digest = self.advance(&mut state, event, self.digests.len() - 1)?;
        self.state = state;
        self.digests.push(digest);
        Ok(())
    }
    fn digest(&self, events: usize) -> Result<String, String> {
        let started = Instant::now();
        let bytes = self
            .digests
            .get(events)
            .ok_or("operational event prefix is unavailable")?;
        let mut result = String::with_capacity(64);
        for byte in bytes {
            write!(&mut result, "{byte:02x}").expect("String formatting cannot fail");
        }
        let mut work = self.work.borrow_mut();
        work.saturated |= add_count(&mut work.cache_reads, 1);
        work.saturated |= add_count(&mut work.index_elapsed_ns, elapsed(started));
        Ok(result)
    }
    fn snapshot(&self) -> PrefixWork {
        let mut work = self.work.borrow().clone();
        work.index_bytes = (std::mem::size_of::<Self>()
            + self.digests.capacity() * std::mem::size_of::<[u8; 32]>())
            as u64;
        work
    }
}

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
    prefixes: PrefixIndex,
}
fn replay(bytes: &[u8], owner: &str) -> Result<Replay, String> {
    replay_inner(bytes, owner, false)
}
fn replay_inner(bytes: &[u8], owner: &str, indexed: bool) -> Result<Replay, String> {
    if bytes.is_empty() || bytes.len() > crate::MAX_LEDGER_BYTES || bytes.last() != Some(&b'\n') {
        return Err("operational journal is empty, truncated or exceeds its byte budget".into());
    }
    let mut last_hash = ZERO_HASH.to_string();
    let mut genesis = None;
    let mut genesis_sha256 = String::new();
    let mut events = Vec::new();
    let mut state = State::default();
    let mut prefixes = PrefixIndex::new(indexed);
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
            prefixes.append_replayed(&event)?;
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
        prefixes,
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
    prefixes: PrefixIndex,
}
impl OperationalJournal {
    pub fn open(owner: Arc<Store>, service_id: &str, policy_digest: &str) -> Result<Self, String> {
        Self::open_with_initialization_hook(owner, service_id, policy_digest, || Ok(()))
    }
    /// Retained full-serialization path for exact engineering comparisons.
    /// All owner, policy, hash-chain and durable-write checks remain identical;
    /// only the derived prefix index is disabled, including its construction.
    pub fn open_reference(
        owner: Arc<Store>,
        service_id: &str,
        policy_digest: &str,
    ) -> Result<Self, String> {
        Self::open_internal(owner, service_id, policy_digest, || Ok(()), false)
    }
    // A private supervised test boundary; never controlled by service requests.
    fn open_with_initialization_hook(
        owner: Arc<Store>,
        service_id: &str,
        policy_digest: &str,
        before_genesis: impl FnOnce() -> Result<(), String>,
    ) -> Result<Self, String> {
        Self::open_internal(owner, service_id, policy_digest, before_genesis, true)
    }
    fn open_internal(
        owner: Arc<Store>,
        service_id: &str,
        policy_digest: &str,
        before_genesis: impl FnOnce() -> Result<(), String>,
        indexed: bool,
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
            let replay = replay_inner(&bytes, lease.owner.identity(), indexed)?;
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
            replay.prefixes.work.borrow_mut().ledger_bytes_read = bytes.len() as u64;
            return Ok(Self {
                lease,
                genesis: replay.genesis,
                events: replay.events,
                state: replay.state,
                committed: bytes,
                last_hash: replay.last_hash,
                count: replay.count,
                prefixes: replay.prefixes,
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
        let prefixes = PrefixIndex::new(indexed);
        prefixes.work.borrow_mut().durable_bytes_written = committed.len() as u64;
        Ok(Self {
            lease,
            genesis,
            events: Vec::new(),
            state,
            committed,
            last_hash: row.sha256,
            count: 1,
            prefixes,
        })
    }
    pub fn events(&self) -> &[OperationalEvent] {
        &self.events
    }
    /// Exact retained SHA256(canonical JSON array of typed events), excluding
    /// genesis. Derived only from this live journal's validated history; an
    /// imported digest or a missing prefix never creates a trusted index entry.
    pub fn event_prefix_sha256(&self, events: usize) -> Result<String, String> {
        if self.prefixes.indexed {
            self.prefixes.digest(events)
        } else {
            self.event_prefix_sha256_reference(events)
        }
    }
    /// Retained full-serialization reference for parity and bounded profiling.
    /// This deliberately performs the original work rather than reading cache.
    pub fn event_prefix_sha256_reference(&self, events: usize) -> Result<String, String> {
        let prefix = self
            .events
            .get(..events)
            .ok_or("operational event prefix is unavailable")?;
        let started = Instant::now();
        let value = serde_json::to_value(prefix).map_err(|error| error.to_string())?;
        let bytes = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
        let result = format!("{:x}", Sha256::digest(&bytes));
        let mut work = self.prefixes.work.borrow_mut();
        work.saturated |= add_count(&mut work.reference_reads, 1);
        work.saturated |= add_count(&mut work.reference_event_visits, prefix.len() as u64);
        work.saturated |= add_count(&mut work.reference_canonicalized_bytes, bytes.len() as u64);
        work.saturated |= add_count(&mut work.reference_hashed_bytes, bytes.len() as u64);
        work.saturated |= add_count(&mut work.reference_elapsed_ns, elapsed(started));
        Ok(result)
    }
    /// Diagnostic actual work only; never an input to trust, reward or grants.
    pub fn prefix_work(&self) -> PrefixWork {
        self.prefixes.snapshot()
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
        {
            let mut work = self.prefixes.work.borrow_mut();
            work.saturated |= add_count(&mut work.committed_bytes_cloned, bytes.len() as u64);
        }
        let mut last_hash = self.last_hash.clone();
        let mut count = self.count;
        let mut prefix_state = self.prefixes.state.clone();
        let mut prefix_digests = Vec::with_capacity(events.len());
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
            if self.prefixes.indexed {
                prefix_digests.push(self.prefixes.advance(
                    &mut prefix_state,
                    event,
                    self.events.len() + prefix_digests.len(),
                )?);
            }
            last_hash = row.sha256;
            count += 1;
        }
        if state.lifecycle.is_some() {
            return Err("HOLD: incomplete lifecycle batch cannot be published".into());
        }
        before_publish()?;
        maintenance::atomic_replace(&self.lease.owner.directory, FILE_NAME, &bytes)?;
        after_publish();
        {
            let mut work = self.prefixes.work.borrow_mut();
            work.saturated |= add_count(&mut work.durable_bytes_written, bytes.len() as u64);
        }
        self.committed = bytes;
        self.last_hash = last_hash;
        self.count = count;
        self.state = state;
        self.events.extend(events);
        // No cache state becomes visible before the complete journal is durable.
        self.prefixes.state = prefix_state;
        self.prefixes.digests.extend(prefix_digests);
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
            for end in 0..=reopened.events().len() {
                assert_eq!(
                    reopened.event_prefix_sha256(end).unwrap(),
                    reopened.event_prefix_sha256_reference(end).unwrap()
                );
            }
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

#[cfg(test)]
mod prefix_index_tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "symbiote-prefix-unit-{}-{}",
                std::process::id(),
                crate::TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn journal(&self) -> OperationalJournal {
            OperationalJournal::open(
                Arc::new(Store::open(&self.0).unwrap()),
                "prefix-unit/v1",
                &"a".repeat(64),
            )
            .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn decision(index: usize) -> OperationalEvent {
        OperationalEvent::PartnerDecisionRecorded {
            decision: PartnerDecisionRecord {
                decision_id: format!("prefix-{index}"),
                context: "prefix-unit/v1".into(),
                frontier_edge: None,
                selected_peer: Some("peer".into()),
                details: json!({"z": [null, true, false, 0, -7, 1.25, {"\u{3b2}":"\u{e9} \u{1f980}", "a": "line\n\r\t\u{0}\"\\", "literal":"\\n\\u0000"}], "a": {"nested": [index, {}]}}),
            },
        }
    }
    fn every_prefix(journal: &OperationalJournal) {
        for end in 0..=journal.events().len() {
            assert_eq!(
                journal.event_prefix_sha256(end).unwrap(),
                journal.event_prefix_sha256_reference(end).unwrap()
            );
            assert_eq!(
                journal.event_prefix_sha256(end).unwrap(),
                digest(&serde_json::to_value(&journal.events()[..end]).unwrap()).unwrap()
            );
        }
        assert!(journal
            .event_prefix_sha256(journal.events().len() + 1)
            .is_err());
        assert!(journal
            .event_prefix_sha256_reference(journal.events().len() + 1)
            .is_err());
    }
    #[test]
    fn exact_prefixes_match_reference_after_single_batch_and_cold_reopen() {
        let fixture = Fixture::new();
        let mut journal = fixture.journal();
        every_prefix(&journal);
        for index in 0..3 {
            journal.append(decision(index)).unwrap();
            every_prefix(&journal);
        }
        let original = fs::read(journal.ledger_path()).unwrap();
        let head = journal.head_sha256().to_string();
        journal
            .append_checked_batch(&head, (3..8).map(decision).collect())
            .unwrap();
        every_prefix(&journal);
        assert!(fs::read(journal.ledger_path())
            .unwrap()
            .starts_with(&original));
        let saved = (0..=journal.events().len())
            .map(|end| journal.event_prefix_sha256(end).unwrap())
            .collect::<Vec<_>>();
        let bytes = fs::read(journal.ledger_path()).unwrap();
        drop(journal);
        let reopened = fixture.journal();
        every_prefix(&reopened);
        assert_eq!(reopened.prefix_work().ledger_bytes_read, bytes.len() as u64);
        assert_eq!(reopened.prefix_work().durable_bytes_written, 0);
        for (end, hash) in saved.iter().enumerate() {
            assert_eq!(&reopened.event_prefix_sha256(end).unwrap(), hash);
        }
        assert_eq!(fs::read(reopened.ledger_path()).unwrap(), bytes);
    }
    #[test]
    fn rejected_and_prepublication_failed_appends_do_not_publish_prefixes() {
        let fixture = Fixture::new();
        let mut journal = fixture.journal();
        journal.append(decision(0)).unwrap();
        let hash = journal.event_prefix_sha256(1).unwrap();
        let bytes = fs::read(journal.ledger_path()).unwrap();
        let head = journal.head_sha256().to_string();
        assert!(journal.append(decision(0)).is_err());
        assert!(journal
            .append_checked_batch(&"b".repeat(64), vec![decision(1)])
            .is_err());
        assert!(journal
            .append_checked_batch_with_hooks(
                &head,
                vec![decision(1), decision(2)],
                || Err("injected before publication".into()),
                || {}
            )
            .is_err());
        assert_eq!(journal.events().len(), 1);
        assert_eq!(journal.event_prefix_sha256(1).unwrap(), hash);
        assert!(journal.event_prefix_sha256(2).is_err());
        assert_eq!(fs::read(journal.ledger_path()).unwrap(), bytes);
        assert_eq!(
            journal.prefix_work().event_visits,
            3,
            "failed proposed work is still counted"
        );
        journal.append(decision(3)).unwrap();
        every_prefix(&journal);
        drop(journal);
        every_prefix(&fixture.journal());
    }
    #[test]
    fn warm_reads_do_not_serialize_or_hash_history_and_reference_work_is_visible() {
        let fixture = Fixture::new();
        let mut journal = fixture.journal();
        let head = journal.head_sha256().to_string();
        journal
            .append_checked_batch(&head, (0..5).map(decision).collect())
            .unwrap();
        let before = journal.prefix_work();
        for _ in 0..7 {
            journal.event_prefix_sha256(5).unwrap();
        }
        let warm = journal.prefix_work();
        assert_eq!(warm.cache_reads - before.cache_reads, 7);
        assert_eq!(warm.canonicalized_bytes, before.canonicalized_bytes);
        assert_eq!(warm.hashed_bytes, before.hashed_bytes);
        assert_eq!(warm.event_visits, before.event_visits);
        let expected = digest(&serde_json::to_value(journal.events()).unwrap()).unwrap();
        assert_eq!(journal.event_prefix_sha256_reference(5).unwrap(), expected);
        let reference = journal.prefix_work();
        assert_eq!(reference.reference_reads - warm.reference_reads, 1);
        assert_eq!(
            reference.reference_event_visits - warm.reference_event_visits,
            5
        );
        assert!(reference.reference_hashed_bytes > warm.reference_hashed_bytes);
        assert!(reference.index_bytes >= 6 * 32);
        assert!(!reference.saturated);
    }

    fn registered_profile_guard() -> Result<(Value, Vec<u8>, String, PathBuf), String> {
        let registration_path = PathBuf::from(
            std::env::var_os("SYMBIOTE_ENGINE_EVOLUTION_REGISTRATION")
                .ok_or("external registration path required")?,
        );
        let pin = std::env::var("SYMBIOTE_ENGINE_EVOLUTION_REGISTRATION_SHA256")
            .map_err(|_| "external registration SHA required")?;
        if !sha256(&pin)
            || fs::metadata(&registration_path)
                .map_err(|e| e.to_string())?
                .len()
                > 1024 * 1024
        {
            return Err("registration pin/size rejected".into());
        }
        let raw = fs::read(&registration_path).map_err(|e| e.to_string())?;
        if format!("{:x}", Sha256::digest(&raw)) != pin {
            return Err("external registration SHA mismatch".into());
        }
        let registration: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        if registration["schema"] != "symbiote.engine-evolution-registration/1"
            || registration["protocol"] != "SYMBIOTE-ENGINE-EVOLUTION-002"
            || registration["baseline_source"] != "0616f9a6dc6788078c623a3c2ed2ef237ae11de6"
            || registration["prefix_profile"] != json!({"histories":[0,16,64,256],"captures":32})
        {
            return Err("registered prefix workload differs from frozen protocol".into());
        }
        let protocol = format!(
            "{:x}",
            Sha256::digest(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../docs/ENGINE_EVOLUTION_PROTOCOL_002.md"
            )))
        );
        if registration["protocol_sha256"] != protocol {
            return Err("registration protocol SHA differs from compiled source".into());
        }
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let declared = PathBuf::from(
            registration["memory_test"]["path"]
                .as_str()
                .ok_or("memory test path missing")?,
        );
        if fs::canonicalize(&exe).map_err(|e| e.to_string())?
            != fs::canonicalize(declared).map_err(|e| e.to_string())?
            || fs::metadata(&exe).map_err(|e| e.to_string())?.len() > 128 * 1024 * 1024
        {
            return Err("registered memory executable path/size differs".into());
        }
        let exe_sha = format!(
            "{:x}",
            Sha256::digest(fs::read(&exe).map_err(|e| e.to_string())?)
        );
        if registration["memory_test"]["sha256"] != exe_sha {
            return Err("registered memory executable SHA differs".into());
        }
        let output = PathBuf::from(
            std::env::var_os("SYMBIOTE_PREFIX_PROFILE_ARTIFACTS")
                .ok_or("fresh profile artifact directory required")?,
        );
        Ok((registration, raw, pin, output))
    }
    fn profile_arm(
        path: &std::path::Path,
        indexed: bool,
        history: usize,
    ) -> Result<(Value, Vec<String>), String> {
        let started = Instant::now();
        let owner = Arc::new(Store::open(path)?);
        let journal = if indexed {
            OperationalJournal::open(owner, "prefix-profile/v1", &"a".repeat(64))?
        } else {
            OperationalJournal::open_reference(owner, "prefix-profile/v1", &"a".repeat(64))?
        };
        let cold_elapsed = elapsed(started);
        let cold = journal.prefix_work();
        if journal.events().len() != history {
            return Err("registered history count differs".into());
        }
        let started = Instant::now();
        let mut captures = Vec::new();
        for _ in 0..32 {
            captures.push(journal.event_prefix_sha256(history)?);
        }
        let capture_elapsed = elapsed(started);
        let after_captures = journal.prefix_work();
        let started = Instant::now();
        let prefixes = (0..=history)
            .map(|end| journal.event_prefix_sha256(end))
            .collect::<Result<Vec<_>, _>>()?;
        let parity_elapsed = elapsed(started);
        let after_parity = journal.prefix_work();
        if captures.iter().any(|hash| Some(hash) != prefixes.last()) {
            return Err("capture changed within frozen history".into());
        }
        let started = Instant::now();
        drop(journal);
        let close_elapsed = elapsed(started);
        Ok((
            json!({"mode":if indexed{"indexed"}else{"reference"},"cold_open_elapsed_ns":cold_elapsed,
            "capture_elapsed_ns":capture_elapsed,"all_prefixes_elapsed_ns":parity_elapsed,"close_elapsed_ns":close_elapsed,
            "cold_work":cold,"after_captures_work":after_captures,"after_parity_work":after_parity,
            "capture_count":captures.len(),"capture_digest":captures.first(),"prefixes":prefixes}),
            prefixes,
        ))
    }
    /// Registered once-only engineering workload; ordinary tests do not open
    /// these histories. The external supervisor provides source/executable pins,
    /// a hard process-tree deadline and the complete evidence byte ceiling.
    #[test]
    #[ignore = "requires frozen engine-evolution-002 registration and external bounded supervisor"]
    fn registered_engine_evolution_002_prefix_profile() -> Result<(), String> {
        let whole_started = Instant::now();
        let (registration, registration_raw, registration_sha, root) = registered_profile_guard()?;
        fs::create_dir(&root).map_err(|e| format!("fresh profile directory required: {e}"))?;
        fs::write(root.join("registration.json"), registration_raw).map_err(|e| e.to_string())?;
        let mut histories = Vec::new();
        for (case, history) in [0_usize, 16, 64, 256].into_iter().enumerate() {
            if whole_started.elapsed() > std::time::Duration::from_secs(600) {
                return Err("prefix profile deadline exhausted".into());
            }
            let path = root.join(format!("history-{history:03}"));
            fs::create_dir(&path).map_err(|e| e.to_string())?;
            let started = Instant::now();
            let mut seed = OperationalJournal::open_reference(
                Arc::new(Store::open(&path)?),
                "prefix-profile/v1",
                &"a".repeat(64),
            )?;
            for from in (0..history).step_by(64) {
                let end = (from + 64).min(history);
                let head = seed.head_sha256().to_string();
                seed.append_checked_batch(&head, (from..end).map(decision).collect())?;
            }
            let setup_work = seed.prefix_work();
            let owner = seed.identity().to_string();
            let head = seed.head_sha256().to_string();
            drop(seed);
            let setup_elapsed = elapsed(started);
            let ledger = fs::read(path.join(FILE_NAME)).map_err(|e| e.to_string())?;
            let ledger_sha = format!("{:x}", Sha256::digest(&ledger));
            // Counterbalanced predetermined order; warm OS/filesystem effects
            // remain engineering diagnostics, not independent hardware samples.
            let order = if case % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            };
            let mut arms = Vec::new();
            let mut gold = None;
            for indexed in order {
                let (report, prefixes) = profile_arm(&path, indexed, history)?;
                if let Some(expected) = &gold {
                    if expected != &prefixes {
                        return Err("indexed/reference prefix parity failed".into());
                    }
                } else {
                    gold = Some(prefixes);
                }
                arms.push(report);
            }
            if fs::read(path.join(FILE_NAME)).map_err(|e| e.to_string())? != ledger {
                return Err("profile reads changed durable history".into());
            }
            histories.push(json!({"history_events":history,"owner":owner,"journal_head_sha256":head,"journal_sha256":ledger_sha,
                "journal_bytes":ledger.len(),"setup":{"mode":"reference","work":setup_work,"elapsed_ns":setup_elapsed},
                "arms":arms,"all_prefixes_equal":true}));
        }
        let report = json!({"schema":"symbiote.prefix-profile/1","status":"PASS_EXACT_PREFIX_ENGINEERING",
            "protocol":"SYMBIOTE-ENGINE-EVOLUTION-002","registration_sha256":registration_sha,"registration":registration,
            "histories":histories,"elapsed_ns_before_final_census":elapsed(whole_started),"logical_graph_units_changed":false,"independent_scientific_samples":0,
            "scope":"one-host retained canonical-hash algorithm versus derived index; all setup/cold/warm/parity costs retained separately",
            "work_basis":"prefix-only byte/event counters; cold-open elapsed includes Store and journal validation; ledger read/write bytes are this journal instance, not physical disk counters",
            "memory_basis":"index inline size plus reserved digest storage; external supervisor measures process peak memory",
            "comparison":"per-arm cold+warm totals include shared setup once; whole experiment includes setup plus both arms; overlapping timers are not additive CPU"});
        let bytes = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
        let mut census_bytes = 0_u64;
        let mut pending = vec![root.clone()];
        while let Some(path) = pending.pop() {
            for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let kind = entry.file_type().map_err(|e| e.to_string())?;
                if kind.is_dir() {
                    pending.push(entry.path());
                } else if kind.is_file() {
                    census_bytes = census_bytes
                        .checked_add(entry.metadata().map_err(|e| e.to_string())?.len())
                        .ok_or("evidence byte overflow")?;
                } else {
                    return Err("unexpected evidence filesystem object".into());
                }
            }
        }
        if census_bytes
            .checked_add(bytes.len() as u64)
            .is_none_or(|total| total > 128 * 1024 * 1024)
            || whole_started.elapsed() > std::time::Duration::from_secs(600)
        {
            return Err("final profile closure exceeds registered evidence/time bounds".into());
        }
        fs::write(root.join("profile-report.json"), &bytes).map_err(|e| e.to_string())?;
        if whole_started.elapsed() > std::time::Duration::from_secs(600) {
            return Err("profile final write exceeded deadline".into());
        }
        println!("SYMBIOTE_PREFIX_PROFILE_JSON {}",serde_json::to_string(&json!({"schema":"symbiote.prefix-profile-location/1","status":"PASS_EXACT_PREFIX_ENGINEERING","path":root.join("profile-report.json"),"sha256":format!("{:x}",Sha256::digest(&bytes)),"evidence_bytes":census_bytes+bytes.len() as u64,"whole_elapsed_ns":elapsed(whole_started)})).map_err(|e|e.to_string())?);
        Ok(())
    }
    #[test]
    fn explicit_reference_mode_preserves_hashes_without_constructing_an_index() {
        let indexed_fixture = Fixture::new();
        let reference_fixture = Fixture::new();
        let mut indexed = indexed_fixture.journal();
        let mut reference = OperationalJournal::open_reference(
            Arc::new(Store::open(&reference_fixture.0).unwrap()),
            "prefix-unit/v1",
            &"a".repeat(64),
        )
        .unwrap();
        for event in (0..5).map(decision) {
            indexed.append(event.clone()).unwrap();
            reference.append(event).unwrap();
        }
        for end in 0..=5 {
            assert_eq!(
                indexed.event_prefix_sha256(end).unwrap(),
                reference.event_prefix_sha256(end).unwrap()
            );
        }
        let actual = reference.prefix_work();
        assert_eq!(actual.event_visits, 0);
        assert_eq!(actual.hashed_bytes, 0);
        assert_eq!(actual.reference_reads, 6);
        assert_eq!(actual.reference_event_visits, 15);
        assert!(actual.durable_bytes_written > 0);
        assert!(actual.committed_bytes_cloned > 0);
        let before = fs::read(reference.ledger_path()).unwrap();
        drop(reference);
        let reference = OperationalJournal::open_reference(
            Arc::new(Store::open(&reference_fixture.0).unwrap()),
            "prefix-unit/v1",
            &"a".repeat(64),
        )
        .unwrap();
        assert_eq!(reference.prefix_work().hashed_bytes, 0);
        assert_eq!(reference.prefix_work().event_visits, 0);
        assert_eq!(
            reference.prefix_work().ledger_bytes_read,
            before.len() as u64
        );
        for end in 0..=5 {
            assert_eq!(
                indexed.event_prefix_sha256(end).unwrap(),
                reference.event_prefix_sha256(end).unwrap()
            );
        }
    }
    #[test]
    fn corrupt_durable_history_cannot_supply_a_cached_prefix_on_reopen() {
        let fixture = Fixture::new();
        let mut journal = fixture.journal();
        journal.append(decision(0)).unwrap();
        let path = journal.ledger_path();
        drop(journal);
        let mut bytes = fs::read(&path).unwrap();
        let at = bytes
            .windows(8)
            .position(|window| window == b"prefix-0")
            .unwrap();
        bytes[at + 7] = b'9';
        fs::write(&path, bytes).unwrap();
        let owner = Arc::new(Store::open(&fixture.0).unwrap());
        assert!(OperationalJournal::open(owner, "prefix-unit/v1", &"a".repeat(64)).is_err());
    }
}
