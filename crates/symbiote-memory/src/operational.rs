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
#[derive(Clone, Default)]
struct State {
    owner_identity: String,
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
        match event {
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
    fn apply(&mut self, event: &OperationalEvent) -> Result<(), String> {
        match event {
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
        if sequence >= crate::MAX_RECORDS || line.is_empty() || line.len() > MAX_RECORD_BYTES {
            return Err("operational journal record exceeds count/byte limits or is empty".into());
        }
        let row: Receipt = serde_json::from_str(line)
            .map_err(|error| format!("invalid operational receipt {sequence}: {error}"))?;
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
            genesis_sha256 = row.sha256.clone();
        } else {
            let event: OperationalEvent = serde_json::from_value(row.payload.clone())
                .map_err(|error| format!("unsupported operational event: {error}"))?;
            state.validate(&event)?;
            state.apply(&event)?;
            events.push(event);
        }
        last_hash = row.sha256;
        count += 1;
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
                || replay.genesis.policy_digest != policy_digest
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
        &self.genesis.policy_digest
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
        self.state.validate(&event)?;
        if self.count >= crate::MAX_RECORDS {
            return Err("operational journal record budget exhausted".into());
        }
        let mut row = Receipt {
            sequence: self.count,
            previous: self.last_hash.clone(),
            payload: serde_json::to_value(&event).map_err(|error| error.to_string())?,
            sha256: String::new(),
        };
        row.sha256 = row.hash()?;
        let line = serde_json::to_vec(&row).map_err(|error| error.to_string())?;
        if line.len() > MAX_RECORD_BYTES {
            return Err("operational record byte budget exhausted".into());
        }
        let mut bytes = self.committed.clone();
        bytes.extend_from_slice(&line);
        bytes.push(b'\n');
        if bytes.len() > crate::MAX_LEDGER_BYTES {
            return Err("operational journal byte budget exhausted".into());
        }
        // Derive the post-commit state before writing, so no fallible operation
        // remains between a successful replacement and in-memory application.
        let mut state = self.state.clone();
        state.apply(&event)?;
        maintenance::atomic_replace(&self.lease.owner.directory, FILE_NAME, &bytes)?;
        self.committed = bytes;
        self.last_hash = row.sha256;
        self.count += 1;
        self.state = state;
        self.events.push(event);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
