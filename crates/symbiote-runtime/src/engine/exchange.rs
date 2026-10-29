//! Explicit local exchanges between host-owned engine handles. Receipt bytes are
//! inert: reconciliation requires the actual receiver and its checked ledgers.
//! This does not widen the separately granted network outcome protocol.
use super::*;
use crate::service::feedback::{self, CandidateCosts, ExperienceProof};
use symbiote_memory::operational::{
    body_digest, IdempotencyKey, OperationalEvent, PartnerDecisionRecord,
};

pub const SCHEMA: &str = "symbiote.local-engine-exchange/1";

/// A host's explicit bilateral permission, checked in both durable journals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalGrant {
    id: String,
    sender: String,
    receiver: String,
    source: SourceDescriptor,
    record_sha256: String,
    sender_policy_sha256: String,
    receiver_policy_sha256: String,
}
/// Portable routing/binding data, never a promotion or success capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferTicket {
    pub exchange_id: String,
    pub sender: String,
    pub receiver: String,
    pub scope: String,
    pub record_sha256: String,
    pub candidate_id: String,
    grant: LocalGrant,
    request_sha256: String,
    fixture_sha256: String,
    before: KnowledgeAnchor,
}
#[derive(Clone, Debug, Serialize)]
pub struct TransferReceipt {
    pub ticket: TransferTicket,
    pub learning: LearningReceipt,
}
#[derive(Clone, Debug, Serialize)]
pub struct TransferUse {
    pub ticket_id: String,
    pub record_sha256: String,
    pub input: u16,
    pub answer: u8,
    pub model_work: u64,
    pub basis: Value,
    pub knowledge_at: KnowledgeAnchor,
}
#[derive(Clone, Debug, Serialize)]
pub struct TransferOutcome {
    pub ticket: TransferTicket,
    pub outcome: feedback::Outcome,
    pub experience_sha256: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Reconciliation {
    pub exchange_id: String,
    pub newly_reconciled: bool,
    pub receiver_currently_active: bool,
    pub outcome: feedback::Outcome,
    pub experience_sha256: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum TransferStage {
    Quarantined,
    EvaluationPrepared,
    RetainedAwaitingAttribution,
    ReadyForUse,
    UsedAwaitingOutcome,
    Completed,
    RevokedOrSuperseded,
}
#[derive(Clone, Debug, Serialize)]
pub struct TransferStatus {
    pub exchange_id: String,
    pub stage: TransferStage,
    pub actual_uses: usize,
    pub currently_active: bool,
    pub new_credit: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum Entry {
    Granted {
        grant: LocalGrant,
        role: String,
    },
    Sent {
        grant: LocalGrant,
        request: Value,
        candidate_id: String,
    },
    Bound {
        ticket: TransferTicket,
    },
    Accepted {
        ticket: TransferTicket,
        learning: Value,
    },
    Reconciled {
        ticket: TransferTicket,
        receiver_knowledge: KnowledgeAnchor,
        receiver_journal_sha256: String,
        experience: Value,
        experience_sha256: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    scope: String,
    event: Entry,
}
fn error(kind: ErrorKind, op: &'static str, value: impl Into<String>) -> EngineError {
    EngineError::new(kind, op, value)
}
fn hash_value(value: &impl Serialize) -> Result<String> {
    let value = serde_json::to_value(value)
        .map_err(|e| error(ErrorKind::Malformed, "exchange-hash", e.to_string()))?;
    super::digest(&value)
}
fn append(state: &mut EngineState, scope: &str, entry: Entry) -> Result<()> {
    let value = serde_json::to_value(Envelope {
        schema: SCHEMA.into(),
        scope: scope.into(),
        event: entry,
    })
    .map_err(|e| error(ErrorKind::Malformed, "exchange", e.to_string()))?;
    let id = format!("local-exchange-{}", hash_value(&value)?);
    state
        .journal
        .append(OperationalEvent::PartnerDecisionRecorded {
            decision: PartnerDecisionRecord {
                decision_id: id,
                context: scope.into(),
                frontier_edge: None,
                selected_peer: None,
                details: value,
            },
        })
        .map_err(|e| error(ErrorKind::Storage, "exchange", e))
}
fn entries(state: &EngineState) -> Result<Vec<Entry>> {
    let mut result = Vec::new();
    for event in state.journal.events() {
        let OperationalEvent::PartnerDecisionRecorded { decision } = event else {
            continue;
        };
        if !decision.details["schema"]
            .as_str()
            .is_some_and(|s| s.starts_with("symbiote.local-engine-exchange/"))
        {
            continue;
        }
        let envelope: Envelope = serde_json::from_value(decision.details.clone())
            .map_err(|e| error(ErrorKind::Hold, "exchange-replay", e.to_string()))?;
        if envelope.schema != SCHEMA
            || envelope.scope != decision.context
            || decision.decision_id != format!("local-exchange-{}", hash_value(&decision.details)?)
        {
            return Err(error(
                ErrorKind::Hold,
                "exchange-replay",
                "local exchange carrier changed",
            ));
        }
        result.push(envelope.event);
    }
    Ok(result)
}
fn ready(engine: &Engine) -> Result<()> {
    engine.check(None)?;
    if engine.cancellation().is_cancelled() {
        return Err(error(
            ErrorKind::Cancelled,
            "exchange",
            "host cancelled admission",
        ));
    }
    if engine.state()?.pending.is_some() {
        return Err(error(
            ErrorKind::Hold,
            "exchange",
            "finish or explicitly recover the pending episode first",
        ));
    }
    Ok(())
}
fn authorized(state: &EngineState, source: &SourceDescriptor) -> Result<()> {
    if !state.config.authorized_sources.contains(source) {
        return Err(error(
            ErrorKind::Authorization,
            "exchange",
            "source/context/epoch is outside host authorization",
        ));
    }
    Ok(())
}
fn grant_id(grant: &LocalGrant) -> Result<String> {
    hash_value(
        &json!({"sender":grant.sender,"receiver":grant.receiver,"source":grant.source,
        "artifact":grant.record_sha256,"sender_policy":grant.sender_policy_sha256,"receiver_policy":grant.receiver_policy_sha256}),
    )
}
fn check_grant(state: &EngineState, grant: &LocalGrant, role: &str) -> Result<()> {
    if grant.id != grant_id(grant)?
        || grant.sender == grant.receiver
        || (role == "sender"
            && (state.owner.identity() != grant.sender
                || state.policy_sha256 != grant.sender_policy_sha256))
        || (role == "receiver"
            && (state.owner.identity() != grant.receiver
                || state.policy_sha256 != grant.receiver_policy_sha256))
    {
        return Err(error(
            ErrorKind::Authorization,
            "exchange",
            "local grant identity or policy mismatch",
        ));
    }
    authorized(state, &grant.source)?;
    if !entries(state)?
        .iter()
        .any(|e| matches!(e,Entry::Granted{grant:g,role:r}if g==grant&&r==role))
    {
        return Err(error(
            ErrorKind::Authorization,
            "exchange",
            "this owner has not granted this exact exchange",
        ));
    }
    Ok(())
}
fn request(grant: &LocalGrant, artifact: &Artifact) -> Value {
    json!({"schema":"symbiote.service-request/1","scope":artifact.record.scope,
        "request_id":format!("local-{}",&grant.id[..40]),"body":{"operation":"candidate.submit",
        "offer":{"record":artifact.record,"training_inputs":artifact.training_inputs}}})
}
fn check_artifact(artifact: &Artifact) -> Result<()> {
    if artifact.training_inputs.len() > 256
        || artifact
            .training_inputs
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != artifact.training_inputs.len()
    {
        return Err(error(
            ErrorKind::Malformed,
            "exchange",
            "training declaration exceeds its bounded unique input envelope",
        ));
    }
    artifact
        .record
        .validate()
        .map_err(|e| error(ErrorKind::Malformed, "exchange", e))?;
    if artifact.schema != "symbiote.engine-artifact/1"
        || artifact.sender != artifact.record.source
        || artifact
            .record
            .digest()
            .map_err(|e| error(ErrorKind::Malformed, "exchange", e))?
            != artifact.record_sha256
        || artifact.source.scope != artifact.record.scope
    {
        return Err(error(
            ErrorKind::Malformed,
            "exchange",
            "inert artifact binding is invalid",
        ));
    }
    match artifact
        .record
        .typed_payload()
        .map_err(|e| error(ErrorKind::Malformed, "exchange", e))?
    {
        symbiote_memory::knowledge::KnowledgePayload::Affine { width, .. }
            if width == artifact.source.width
                && artifact.training_inputs.iter().all(|i| *i < 1u16 << width) => {}
        _ => {
            return Err(error(
                ErrorKind::IncompatibleSchema,
                "exchange",
                "local embedding transfer requires matching bounded affine coordinates",
            ))
        }
    }
    Ok(())
}
fn check_ticket(state: &EngineState, ticket: &TransferTicket, role: &str) -> Result<()> {
    check_grant(state, &ticket.grant, role)?;
    if ticket.sender != ticket.grant.sender
        || ticket.receiver != ticket.grant.receiver
        || ticket.record_sha256 != ticket.grant.record_sha256
        || ticket.scope != ticket.grant.source.scope
    {
        return Err(error(
            ErrorKind::Malformed,
            "exchange",
            "ticket is detached from its grant",
        ));
    }
    if !entries(state)?
        .iter()
        .any(|e| matches!(e,Entry::Bound{ticket:t}if t==ticket))
    {
        return Err(error(
            ErrorKind::Authorization,
            "exchange",
            "ticket is not bound in this owner's history",
        ));
    }
    if role == "receiver" {
        let index = feedback::replay_index(&state.journal, &state.knowledge)
            .map_err(|e| error(ErrorKind::Hold, "exchange", e))?;
        let bound=state.journal.events().iter().any(|event|matches!(event,OperationalEvent::PartnerDecisionRecorded{decision}
            if decision.details["schema"]==feedback::SCHEMA && decision.details["event"]["phase"]=="decision"
            &&decision.details["event"]["binding"]["exchange_id"]==ticket.exchange_id
            &&decision.details["event"]["binding"]["candidate_id"]==ticket.candidate_id
            &&decision.details["event"]["binding"]["request_sha256"]==ticket.request_sha256
            &&decision.details["event"]["binding"]["offered_record_sha256"]==ticket.record_sha256
            &&decision.details["event"]["binding"]["fixture_sha256"]==ticket.fixture_sha256
            &&decision.details["event"]["before"]==serde_json::to_value(&ticket.before).unwrap_or(Value::Null)));
        if !bound {
            return Err(error(
                ErrorKind::Hold,
                "exchange",
                "ticket has no exact original native feedback decision",
            ));
        }
        // Pending uses are validated by the shared feedback implementation below.
        if let Some(experience) = index.experience(&ticket.exchange_id) {
            if experience.binding.candidate_id != ticket.candidate_id
                || experience.binding.request_sha256 != ticket.request_sha256
                || experience.binding.offered_record_sha256 != ticket.record_sha256
                || experience.binding.fixture_sha256 != ticket.fixture_sha256
            {
                return Err(error(
                    ErrorKind::Hold,
                    "exchange",
                    "ticket differs from the actual feedback chain",
                ));
            }
        }
    }
    Ok(())
}
fn active_record(state: &EngineState, ticket: &TransferTicket) -> Result<KnowledgeRecord> {
    state
        .knowledge
        .active()
        .into_iter()
        .find(|r| r.digest().ok().as_ref() == Some(&ticket.record_sha256))
        .ok_or_else(|| {
            error(
                ErrorKind::Revoked,
                "exchange",
                "exact transferred record is absent, revoked or superseded",
            )
        })
}

impl Engine {
    /// Read checked receiver-local state without generating any new credit.
    pub fn inspect_local_transfer(&self, ticket: &TransferTicket) -> Result<TransferStatus> {
        let state = self.state()?;
        if state.poisoned {
            return Err(error(
                ErrorKind::Hold,
                "inspect-transfer",
                "owner has an incomplete committed operation",
            ));
        }
        check_ticket(state, ticket, "receiver")?;
        let index = feedback::replay_index(&state.journal, &state.knowledge)
            .map_err(|e| error(ErrorKind::Hold, "inspect-transfer", e))?;
        let active = state
            .knowledge
            .active()
            .iter()
            .any(|r| r.digest().ok().as_ref() == Some(&ticket.record_sha256));
        let mut prepared = false;
        let mut promoted = false;
        let mut uses = 0;
        for event in state.journal.events() {
            match event {
                OperationalEvent::EvaluationPrepared { candidate_id, .. }
                    if candidate_id == &ticket.candidate_id =>
                {
                    prepared = true
                }
                OperationalEvent::PartnerDecisionRecorded { decision }
                    if decision.details["schema"] == feedback::SCHEMA
                        && decision.details["event"]["exchange_id"] == ticket.exchange_id =>
                {
                    match decision.details["event"]["phase"].as_str() {
                        Some("promoted") => promoted = true,
                        Some("store_use") => uses += 1,
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        let stage = if (promoted || index.experience(&ticket.exchange_id).is_some()) && !active {
            TransferStage::RevokedOrSuperseded
        } else if index.experience(&ticket.exchange_id).is_some() {
            TransferStage::Completed
        } else if uses > 0 {
            TransferStage::UsedAwaitingOutcome
        } else if promoted {
            TransferStage::ReadyForUse
        } else if prepared && active {
            TransferStage::RetainedAwaitingAttribution
        } else if prepared {
            TransferStage::EvaluationPrepared
        } else {
            TransferStage::Quarantined
        };
        Ok(TransferStatus {
            exchange_id: ticket.exchange_id.clone(),
            stage,
            actual_uses: uses,
            currently_active: active,
            new_credit: false,
        })
    }
    /// Validated local historical experiences, with present membership separate.
    pub fn local_transfer_outcomes(&self) -> Result<Vec<feedback::Experience>> {
        let state = self.state()?;
        if state.poisoned {
            return Err(error(
                ErrorKind::Hold,
                "inspect-outcomes",
                "owner has an incomplete committed operation",
            ));
        }
        Ok(feedback::replay_index(&state.journal, &state.knowledge)
            .map_err(|e| error(ErrorKind::Hold, "inspect-outcomes", e))?
            .experiences)
    }
    /// The host explicitly grants a local relationship using both owned handles.
    /// Possessing an artifact or a receipt does not call this method implicitly.
    pub fn authorize_local_exchange(
        &mut self,
        receiver: &mut Engine,
        artifact: &Artifact,
    ) -> Result<LocalGrant> {
        ready(self)?;
        ready(receiver)?;
        check_artifact(artifact)?;
        let sender = self.state()?;
        let target = receiver.state()?;
        authorized(sender, &artifact.source)?;
        authorized(target, &artifact.source)?;
        if sender.owner.identity() != artifact.sender
            || sender.owner.identity() == target.owner.identity()
            || !sender
                .knowledge
                .active()
                .iter()
                .any(|r| r.digest().ok().as_ref() == Some(&artifact.record_sha256))
        {
            return Err(error(
                ErrorKind::Authorization,
                "authorize-exchange",
                "sender does not own this active artifact",
            ));
        }
        let mut grant = LocalGrant {
            id: String::new(),
            sender: sender.owner.identity().into(),
            receiver: target.owner.identity().into(),
            source: artifact.source.clone(),
            record_sha256: artifact.record_sha256.clone(),
            sender_policy_sha256: sender.policy_sha256.clone(),
            receiver_policy_sha256: target.policy_sha256.clone(),
        };
        grant.id = grant_id(&grant)?;
        for (engine, role) in [(self, "sender"), (receiver, "receiver")] {
            if !entries(engine.state()?)?
                .iter()
                .any(|e| matches!(e,Entry::Granted{grant:g,role:r}if g==&grant&&r==role))
            {
                append(
                    engine.state_mut()?,
                    &grant.source.scope,
                    Entry::Granted {
                        grant: grant.clone(),
                        role: role.into(),
                    },
                )?;
            }
        }
        Ok(grant)
    }
    /// Record the exact send decision and an explicitly authorized local quarantine.
    pub fn prepare_local_transfer(
        &mut self,
        receiver: &mut Engine,
        grant: &LocalGrant,
        artifact: &Artifact,
    ) -> Result<TransferTicket> {
        ready(self)?;
        ready(receiver)?;
        check_artifact(artifact)?;
        check_grant(self.state()?, grant, "sender")?;
        check_grant(receiver.state()?, grant, "receiver")?;
        if artifact.record_sha256 != grant.record_sha256 {
            return Err(error(
                ErrorKind::Malformed,
                "prepare-transfer",
                "grant names another artifact",
            ));
        }
        if !self
            .state()?
            .knowledge
            .active()
            .iter()
            .any(|r| r.digest().ok().as_ref() == Some(&artifact.record_sha256))
        {
            return Err(error(
                ErrorKind::Revoked,
                "prepare-transfer",
                "sender's exact artifact is no longer active",
            ));
        }
        if let Some(ticket) = entries(self.state()?)?.into_iter().find_map(|e| match e {
            Entry::Bound { ticket } if ticket.grant == *grant => Some(ticket),
            _ => None,
        }) {
            check_ticket(receiver.state()?, &ticket, "receiver")?;
            return Ok(ticket);
        }
        let body = request(grant, artifact);
        let request_sha256 = hash_value(&body)?;
        let candidate_id = hash_value(
            &json!({"authenticated_sender":grant.sender,"canonical_body_sha256":request_sha256}),
        )?;
        let fixture_sha256 = hash_value(
            &json!({"schema":"symbiote.engine-independent-affine-evaluator/1","source":artifact.source,
            "receiver_policy_sha256":grant.receiver_policy_sha256,"validation":"independent exact inference and disjoint validation"}),
        )?;
        let prior = entries(self.state()?)?;
        if !prior.iter().any(|e|matches!(e,Entry::Sent{grant:g,request:r,candidate_id:c}if g==grant&&r==&body&&c==&candidate_id)) {
            append(self.state_mut()?,&artifact.record.scope,Entry::Sent{grant:grant.clone(),request:body.clone(),candidate_id:candidate_id.clone()})?;
        }
        let target = receiver.state_mut()?;
        if !target.journal.events().iter().any(
            |e| matches!(e,OperationalEvent::Quarantined{candidate_id:c,..}if c==&candidate_id),
        ) {
            target.journal.append(OperationalEvent::Quarantined{key:IdempotencyKey{peer_id:grant.sender.clone(),operation:"candidate.submit".into(),scope:artifact.record.scope.clone(),request_id:body["request_id"].as_str().unwrap().into()},
                candidate_id:candidate_id.clone(),body_sha256:body_digest(&body).map_err(|e|error(ErrorKind::Malformed,"prepare-transfer",e))?,body,
                response:json!({"schema":"symbiote.service-quarantine/1","status":"QUARANTINED","candidate":candidate_id,"promoted":false})})
                .map_err(|e|error(ErrorKind::Storage,"prepare-transfer",e))?;
        }
        let before = target.knowledge.history_anchor();
        let exchange_id = feedback::begin_evaluation(
            &mut target.journal,
            &target.knowledge,
            &candidate_id,
            &fixture_sha256,
        )
        .map_err(|e| error(ErrorKind::Hold, "prepare-transfer", e))?;
        let ticket = TransferTicket {
            exchange_id,
            sender: grant.sender.clone(),
            receiver: grant.receiver.clone(),
            scope: artifact.record.scope.clone(),
            record_sha256: artifact.record_sha256.clone(),
            candidate_id,
            grant: grant.clone(),
            request_sha256,
            fixture_sha256,
            before,
        };
        for engine in [self, receiver] {
            append(
                engine.state_mut()?,
                &ticket.scope,
                Entry::Bound {
                    ticket: ticket.clone(),
                },
            )?;
        }
        Ok(ticket)
    }
    /// Independently evaluate the inert record; retain its exact original bytes.
    pub fn accept_local_transfer(
        &mut self,
        ticket: &TransferTicket,
        artifact: &Artifact,
        source: &mut impl ObservationSource,
        options: &EpisodeOptions,
        sink: &mut impl EventSink,
    ) -> Result<TransferReceipt> {
        ready(self)?;
        check_artifact(artifact)?;
        check_ticket(self.state()?, ticket, "receiver")?;
        if artifact.record_sha256 != ticket.record_sha256
            || artifact.source != ticket.grant.source
            || options.source != ticket.grant.source
        {
            return Err(error(
                ErrorKind::Malformed,
                "accept-transfer",
                "artifact, source or epoch differs from ticket",
            ));
        }
        if self.state()?.journal.events().iter().any(|e|matches!(e,OperationalEvent::EvaluationPrepared{candidate_id,..}if candidate_id==&ticket.candidate_id)) {
            return Err(error(ErrorKind::Hold,"accept-transfer","evaluation already prepared; inspect committed history instead of repeating acquisition"));
        }
        let evaluated = self.evaluate_artifact(artifact, source, options, sink)?;
        let before = self.state()?.knowledge.history_anchor();
        if before != ticket.before {
            return Err(error(
                ErrorKind::Hold,
                "accept-transfer",
                "knowledge changed after the original decision",
            ));
        }
        if evaluated.candidate.reused {
            return Err(error(
                ErrorKind::Uncertain,
                "accept-transfer",
                "this candidate does not extend retained knowledge",
            ));
        }
        let evidence = evaluated.candidate.evidence.clone();
        let response = json!({"schema":"symbiote.engine-transfer-evaluation/1","status":"PROMOTED","promoted":true,"candidate":ticket.candidate_id,
            "record_sha256":ticket.record_sha256,"feedback_baseline":{"kind":"unknown","reason":"no measured isolated cost is part of ordinary engine admission"}});
        self.state_mut()?
            .journal
            .append(OperationalEvent::EvaluationPrepared {
                candidate_id: ticket.candidate_id.clone(),
                record: artifact.record.clone(),
                fixture_sha256: ticket.fixture_sha256.clone(),
                response: response.clone(),
            })
            .map_err(|e| error(ErrorKind::Storage, "accept-transfer", e))?;
        let learning = self.retain(evaluated, sink)?;
        if learning.record_sha256 != ticket.record_sha256
            || learning.before != ticket.before
            || learning.reused
        {
            return Err(error(
                ErrorKind::Hold,
                "accept-transfer",
                "retention does not witness the exact fresh transfer",
            ));
        }
        let state = self.state_mut()?;
        state
            .journal
            .append(OperationalEvent::EvaluationCompleted {
                candidate_id: ticket.candidate_id.clone(),
                record_sha256: ticket.record_sha256.clone(),
                response,
            })
            .map_err(|e| error(ErrorKind::Storage, "accept-transfer", e))?;
        let costs = CandidateCosts {
            unit_model: "engine-gf2-assessment/1".into(),
            acquisition: evidence.costs.acquisition,
            validation: evidence.costs.verification,
            adoption: evidence.costs.adoption,
            prediction: 0,
            wire: 0,
            replay: 0,
        };
        feedback::promoted(
            &mut state.journal,
            &state.knowledge,
            &ticket.candidate_id,
            &artifact.record,
            learning.before.clone(),
            learning.after.clone(),
            costs,
        )
        .map_err(|e| error(ErrorKind::Hold, "accept-transfer", e))?
        .ok_or_else(|| {
            error(
                ErrorKind::Hold,
                "accept-transfer",
                "promotion has no original feedback decision",
            )
        })?;
        append(
            state,
            &ticket.scope,
            Entry::Accepted {
                ticket: ticket.clone(),
                learning: serde_json::to_value(&learning)
                    .map_err(|e| error(ErrorKind::Malformed, "accept-transfer", e.to_string()))?,
            },
        )?;
        Ok(TransferReceipt {
            ticket: ticket.clone(),
            learning,
        })
    }
    /// Perform and durably record an actual conditional prediction after reopen.
    pub fn use_local_transfer(
        &mut self,
        ticket: &TransferTicket,
        input: u16,
    ) -> Result<TransferUse> {
        ready(self)?;
        check_ticket(self.state()?, ticket, "receiver")?;
        active_record(self.state()?, ticket)?;
        if input >= 1u16 << ticket.grant.source.width {
            return Err(error(
                ErrorKind::Malformed,
                "use-transfer",
                "input outside the declared domain",
            ));
        }
        let state = self.state_mut()?;
        let value = feedback::record_use(
            &mut state.journal,
            &state.knowledge,
            &ticket.exchange_id,
            input,
        )
        .map_err(|e| error(ErrorKind::Hold, "use-transfer", e))?;
        Ok(TransferUse {
            ticket_id: ticket.exchange_id.clone(),
            record_sha256: ticket.record_sha256.clone(),
            input,
            answer: value["output"]
                .as_u64()
                .ok_or_else(|| error(ErrorKind::Hold, "use-transfer", "native use lacks output"))?
                as u8,
            model_work: value["model_work"]
                .as_u64()
                .ok_or_else(|| error(ErrorKind::Hold, "use-transfer", "native use lacks work"))?,
            basis: value["basis"].clone(),
            knowledge_at: state.knowledge.history_anchor(),
        })
    }
    pub fn complete_local_transfer(&mut self, ticket: &TransferTicket) -> Result<TransferOutcome> {
        ready(self)?;
        check_ticket(self.state()?, ticket, "receiver")?;
        active_record(self.state()?, ticket)?;
        let state = self.state_mut()?;
        let mut index = feedback::replay_index(&state.journal, &state.knowledge)
            .map_err(|e| error(ErrorKind::Hold, "complete-transfer", e))?;
        if index.experience(&ticket.exchange_id).is_none() {
            if !state.journal.events().iter().any(|event|matches!(event,OperationalEvent::PartnerDecisionRecorded{decision}
                if decision.details["schema"]==feedback::SCHEMA&&decision.details["event"]["phase"]=="store_use"
                &&decision.details["event"]["exchange_id"]==ticket.exchange_id)) {
                return Err(error(ErrorKind::Uncertain,"complete-transfer","no actual model use has occurred"));
            }
            feedback::complete(&mut state.journal, &state.knowledge, &ticket.exchange_id)
                .map_err(|e| error(ErrorKind::Hold, "complete-transfer", e))?;
            index = feedback::replay_index(&state.journal, &state.knowledge)
                .map_err(|e| error(ErrorKind::Hold, "complete-transfer", e))?;
        }
        let experience = index.experience(&ticket.exchange_id).ok_or_else(|| {
            error(
                ErrorKind::Hold,
                "complete-transfer",
                "outcome has no checked experience",
            )
        })?;
        if experience.outcome.uses == 0 {
            return Err(error(
                ErrorKind::Uncertain,
                "complete-transfer",
                "no actual model use has occurred",
            ));
        }
        Ok(TransferOutcome {
            ticket: ticket.clone(),
            outcome: experience.outcome.clone(),
            experience_sha256: hash_value(experience)?,
        })
    }
    /// Read live checked receiver evidence and reconcile the exact send once.
    /// A forged or historical unrelated receipt cannot substitute for `receiver`.
    pub fn reconcile_local_transfer(
        &mut self,
        receiver: &Engine,
        ticket: &TransferTicket,
    ) -> Result<Reconciliation> {
        ready(self)?;
        ready(receiver)?;
        check_ticket(self.state()?, ticket, "sender")?;
        check_ticket(receiver.state()?, ticket, "receiver")?;
        active_record(self.state()?, ticket)?;
        let target = receiver.state()?;
        active_record(target, ticket)?;
        let index = feedback::replay_index(&target.journal, &target.knowledge)
            .map_err(|e| error(ErrorKind::Hold, "reconcile-transfer", e))?;
        let experience = index.experience(&ticket.exchange_id).ok_or_else(|| {
            error(
                ErrorKind::Uncertain,
                "reconcile-transfer",
                "receiver has not completed this outcome",
            )
        })?;
        let b = &experience.binding;
        if b.sender_id != ticket.sender
            || b.receiver_id != ticket.receiver
            || b.offered_record_sha256 != ticket.record_sha256
            || b.request_sha256 != ticket.request_sha256
            || b.candidate_id != ticket.candidate_id
            || b.fixture_sha256 != ticket.fixture_sha256
            || b.policy_sha256 != ticket.grant.receiver_policy_sha256
            || !experience.currently_active
            || experience.outcome.uses == 0
        {
            return Err(error(
                ErrorKind::Hold,
                "reconcile-transfer",
                "live outcome does not bind the exact active transfer",
            ));
        }
        let ExperienceProof::Promotion {
            before,
            after,
            localized_record_sha256,
            ..
        } = &experience.proof
        else {
            return Err(error(
                ErrorKind::Uncertain,
                "reconcile-transfer",
                "outcome does not witness a promotion",
            ));
        };
        if before != &ticket.before
            || localized_record_sha256 != &ticket.record_sha256
            || after.records <= before.records
        {
            return Err(error(
                ErrorKind::Hold,
                "reconcile-transfer",
                "outcome promotion anchors were swapped",
            ));
        }
        let experience_sha256 = hash_value(experience)?;
        let prior = entries(self.state()?)?;
        let exists = prior
            .iter()
            .any(|e| matches!(e,Entry::Reconciled{ticket:t,..}if t==ticket));
        if !exists {
            append(
                self.state_mut()?,
                &ticket.scope,
                Entry::Reconciled {
                    ticket: ticket.clone(),
                    receiver_knowledge: target.knowledge.history_anchor(),
                    receiver_journal_sha256: target.journal.head_sha256().into(),
                    experience: serde_json::to_value(experience).map_err(|e| {
                        error(ErrorKind::Malformed, "reconcile-transfer", e.to_string())
                    })?,
                    experience_sha256: experience_sha256.clone(),
                },
            )?;
        }
        Ok(Reconciliation {
            exchange_id: ticket.exchange_id.clone(),
            newly_reconciled: !exists,
            receiver_currently_active: experience.currently_active,
            outcome: experience.outcome.clone(),
            experience_sha256,
        })
    }
}

/// Validate local carriers and existing native feedback on every engine reopen.
/// Remote historical reconciliation is historical evidence; current verification
/// still requires a live receiver handle, as `reconcile_local_transfer` does.
pub(crate) fn validate(state: &EngineState) -> Result<()> {
    let mut granted = std::collections::BTreeSet::new();
    let mut bound = std::collections::BTreeSet::new();
    let mut reconciled = std::collections::BTreeSet::new();
    for entry in entries(state)? {
        match entry {
            Entry::Granted { grant, role } => {
                if role != "sender" && role != "receiver" {
                    return Err(error(
                        ErrorKind::Hold,
                        "exchange-replay",
                        "unknown grant role",
                    ));
                }
                check_grant(state, &grant, &role)?;
                granted.insert(grant.id);
            }
            Entry::Sent {
                grant,
                request,
                candidate_id,
            } => {
                check_grant(state, &grant, "sender")?;
                if !granted.contains(&grant.id) {
                    return Err(error(
                        ErrorKind::Hold,
                        "exchange-replay",
                        "send precedes its explicit local grant",
                    ));
                }
                let sha = hash_value(&request)?;
                let record: KnowledgeRecord =
                    serde_json::from_value(request["body"]["offer"]["record"].clone())
                        .map_err(|e| error(ErrorKind::Hold, "exchange-replay", e.to_string()))?;
                if candidate_id
                    != hash_value(
                        &json!({"authenticated_sender":grant.sender,"canonical_body_sha256":sha}),
                    )?
                    || record
                        .digest()
                        .map_err(|e| error(ErrorKind::Hold, "exchange-replay", e))?
                        != grant.record_sha256
                    || record.source != grant.sender
                    || record.scope != grant.source.scope
                    || request["scope"] != grant.source.scope
                    || request["schema"] != "symbiote.service-request/1"
                    || request["body"]["operation"] != "candidate.submit"
                {
                    return Err(error(
                        ErrorKind::Hold,
                        "exchange-replay",
                        "send binding changed",
                    ));
                }
            }
            Entry::Bound { ticket } => {
                if !granted.contains(&ticket.grant.id) {
                    return Err(error(
                        ErrorKind::Hold,
                        "exchange-replay",
                        "binding precedes grant",
                    ));
                }
                let role = if state.owner.identity() == ticket.sender {
                    "sender"
                } else {
                    "receiver"
                };
                check_ticket(state, &ticket, role)?;
                if !bound.insert(ticket.exchange_id) {
                    return Err(error(
                        ErrorKind::Hold,
                        "exchange-replay",
                        "duplicate transfer binding",
                    ));
                }
            }
            Entry::Accepted { ticket, learning } => {
                check_ticket(state, &ticket, "receiver")?;
                if !bound.contains(&ticket.exchange_id)
                    || learning["record_sha256"] != ticket.record_sha256
                    || learning["reused"] != false
                    || learning["before"]
                        != serde_json::to_value(&ticket.before).unwrap_or(Value::Null)
                {
                    return Err(error(
                        ErrorKind::Hold,
                        "exchange-replay",
                        "acceptance is detached from exact original promotion",
                    ));
                }
            }
            Entry::Reconciled {
                ticket,
                experience,
                experience_sha256,
                ..
            } => {
                check_ticket(state, &ticket, "sender")?;
                if !bound.contains(&ticket.exchange_id)
                    || !reconciled.insert(ticket.exchange_id.clone())
                    || hash_value(&experience)? != experience_sha256
                    || experience["binding"]["exchange_id"] != ticket.exchange_id
                    || experience["binding"]["offered_record_sha256"] != ticket.record_sha256
                    || experience["binding"]["request_sha256"] != ticket.request_sha256
                    || experience["binding"]["candidate_id"] != ticket.candidate_id
                    || experience["binding"]["sender_id"] != ticket.sender
                    || experience["binding"]["receiver_id"] != ticket.receiver
                    || experience["outcome"]["uses"].as_u64().unwrap_or(0) == 0
                {
                    return Err(error(
                        ErrorKind::Hold,
                        "exchange-replay",
                        "historical reconciliation binding changed",
                    ));
                }
            }
        }
    }
    feedback::replay_index(&state.journal, &state.knowledge)
        .map_err(|e| error(ErrorKind::Hold, "exchange-replay", e))?;
    Ok(())
}
