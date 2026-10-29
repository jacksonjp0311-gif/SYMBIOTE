//! Explicit receiver-owned processing and bounded ledger-witness reconciliation.
//! TLS authenticates origin; configured native evaluator/fixture authority is an
//! explicit assumption. Retained-case use is not unanswered-task generalization.
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use symbiote_memory::knowledge::{KnowledgeAnchor, KnowledgeRecord};
use symbiote_memory::operational::PartnerDecisionRecord;
use symbiote_memory::witness::LedgerWitness;

const SCHEMA: &str = "symbiote.contribution-channel/1";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Policy {
    pub schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver: Option<Receiver>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<Sender>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receiver {
    pub peer: String,
    pub scope: String,
    pub fixture_sha256: String,
    pub goal: u16,
    pub max_candidates_per_episode: usize,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Sender {
    pub peer: String,
    pub scope: String,
    pub receiver_policy_sha256: String,
    pub fixture_sha256: String,
    pub goal: u16,
    pub max_polls: usize,
}
fn history_grant(config: &Config, peer: &str, scope: &str) -> Result<(), String> {
    let grant = config.peer(peer)?.access(scope, "outcome.read")?;
    if grant.artifacts != ["*"] {
        return Err(
            "complete outcome history requires explicit wildcard artifact permission".into(),
        );
    }
    Ok(())
}
impl Policy {
    pub fn validate(&self, config: &Config) -> Result<(), String> {
        if self.schema != "symbiote.contribution-policy/1"
            || config.peers.len() != 1
            || config.contexts.len() != 1
            || (self.receiver.is_none() && self.sender.is_none())
        {
            return Err("outcome proofs require explicit isolated one-peer/context policy".into());
        }
        for (peer, scope, goal) in self
            .receiver
            .iter()
            .map(|p| (&p.peer, &p.scope, p.goal))
            .chain(self.sender.iter().map(|p| (&p.peer, &p.scope, p.goal)))
        {
            let peer = config.peer_alias(peer)?;
            let context = config.context(scope)?;
            let width = (1..=8u8)
                .find(|w| {
                    symbiote_memory::knowledge::affine_schema_fingerprint(*w)
                        .is_ok_and(|fp| fp == context.schema_fingerprint)
                })
                .ok_or("initial outcome channel requires a supported exact affine context")?;
            if goal >= (1u16 << width) {
                return Err("outcome goal is outside declared finite domain".into());
            }
            peer.access(scope, "candidate.submit")?;
            history_grant(config, &peer.id, scope)?;
        }
        if let Some(p) = &self.receiver {
            if !config::sha(&p.fixture_sha256)
                || config.context(&p.scope)?.truth_sha256.as_ref() != Some(&p.fixture_sha256)
                || !(1..=2).contains(&p.max_candidates_per_episode)
            {
                return Err("receiver goal fixture/budget rejected".into());
            }
        }
        if let Some(p) = &self.sender {
            if !config::sha(&p.fixture_sha256)
                || !config::sha(&p.receiver_policy_sha256)
                || !(1..=16).contains(&p.max_polls)
            {
                return Err("outcome sender pins/poll budget rejected".into());
            }
        }
        Ok(())
    }
}
/// Live local opt-in validation only; historical replay never opens these paths.
pub(super) fn validate_live(config: &Config, policy: &Policy) -> Result<(), String> {
    if let Some(receiver) = &policy.receiver {
        let value: Value =
            serde_json::from_slice(&config.fixture(config.context(&receiver.scope)?)?)
                .map_err(|_| "receiver fixture JSON rejected")?;
        let width = value["family"]["width"]
            .as_u64()
            .filter(|w| (1..=8).contains(w))
            .ok_or("receiver affine width unsupported")?;
        if value["schema"] != "symbiote.local-truth/1"
            || value["family"]["kind"] != "affine"
            || u64::from(receiver.goal) >= (1u64 << width)
        {
            return Err(
                "initial receiver outcome goal requires its own pinned exact affine evaluator"
                    .into(),
            );
        }
    }
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Proof {
    schema: String,
    pub challenge: String,
    pub candidate: String,
    pub request_sha256: String,
    pub sender: String,
    pub receiver: String,
    pub scope: String,
    pub fixture_sha256: String,
    pub policy: Value,
    pub goal: u16,
    pub exchange_id: String,
    pub record: KnowledgeRecord,
    pub before: KnowledgeAnchor,
    pub after: KnowledgeAnchor,
    pub current: KnowledgeAnchor,
    pub promotion_sha256: String,
    pub ledgers: LedgerWitness,
}
// Exact /1 typed serialization order is retained for receiver decision IDs.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverDecisionWitness {
    schema: String,
    phase: String,
    request: Request,
    candidate_id: String,
    knowledge_before: KnowledgeAnchor,
    service_policy_sha256: String,
    fixture_sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    ReceiverGoal {
        candidate: String,
        peer: String,
        scope: String,
        fixture_sha256: String,
        goal: u16,
        policy_sha256: String,
    },
    Poll {
        decision_id: String,
        peer: String,
        scope: String,
        candidate: String,
        request_sha256: String,
        challenge: String,
        receiver_policy_sha256: String,
        fixture_sha256: String,
        goal: u16,
    },
    WitnessChunk {
        decision_id: String,
        proof_sha256: String,
        index: usize,
        total: usize,
        hex: String,
    },
    Reconciled {
        decision_id: String,
        proof_sha256: String,
        credit_key: String,
        capability_verified: bool,
        cost_benefit_verified: bool,
    },
}
fn stored_proof(events: &[OperationalEvent], decision: &str, sha: &str) -> Result<Proof, String> {
    let mut parts = Vec::new();
    let mut total = None;
    for event in events {
        if let Some(Event::WitnessChunk {
            decision_id,
            proof_sha256,
            index,
            total: count,
            hex,
        }) = decode(event)?
        {
            if proof_sha256 == sha {
                if decision_id != decision {
                    return Err("witness chunks cross contribution decisions".into());
                }
                if index != parts.len() || total.is_some_and(|n| n != count) {
                    return Err("witness chunk ordering/total changed".into());
                }
                total = Some(count);
                parts.push(hex);
            }
        }
    }
    if total != Some(parts.len()) || parts.is_empty() {
        return Err("complete receiver witness chunks absent".into());
    }
    let mut raw = Vec::new();
    for hex in parts {
        for pair in hex.as_bytes().as_chunks::<2>().0 {
            let part = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
            raw.push(u8::from_str_radix(part, 16).map_err(|_| "witness hex rejected")?);
        }
    }
    if raw.len() > symbiote_memory::witness::MAX_WITNESS_BYTES || config::hash_bytes(&raw) != sha {
        return Err("receiver witness chunk digest differs".into());
    }
    serde_json::from_slice(&raw).map_err(|_| "complete typed receiver witness rejected".into())
}
fn encode_event(event: Event, scope: &str) -> Result<OperationalEvent, String> {
    let details = json!({"schema":SCHEMA,"event":event});
    Ok(OperationalEvent::PartnerDecisionRecorded {
        decision: PartnerDecisionRecord {
            decision_id: format!("outcome-{}", digest(&details)?),
            context: scope.into(),
            frontier_edge: None,
            selected_peer: None,
            details,
        },
    })
}
pub(super) fn handles(event: &OperationalEvent) -> bool {
    matches!(event,OperationalEvent::PartnerDecisionRecorded{decision} if decision.details["schema"].as_str().is_some_and(|s|s.starts_with("symbiote.contribution-channel/")))
}
fn decode(event: &OperationalEvent) -> Result<Option<Event>, String> {
    if !handles(event) {
        return Ok(None);
    }
    let OperationalEvent::PartnerDecisionRecorded { decision } = event else {
        unreachable!()
    };
    if decision.details["schema"] != SCHEMA
        || decision.frontier_edge.is_some()
        || decision.selected_peer.is_some()
        || decision.decision_id != format!("outcome-{}", digest(&decision.details)?)
    {
        return Err("unsupported or altered contribution event".into());
    }
    serde_json::from_value(decision.details["event"].clone())
        .map(Some)
        .map_err(|_| "contribution event schema rejected".into())
}
fn original<'a>(
    events: &'a [OperationalEvent],
    id: &str,
) -> Result<&'a PartnerDecisionRecord, String> {
    events
        .iter()
        .find_map(|e| match e {
            OperationalEvent::PartnerDecisionRecorded { decision }
                if decision.decision_id == id =>
            {
                Some(decision)
            }
            _ => None,
        })
        .ok_or("original contribution decision absent".into())
}
fn offered(
    events: &[OperationalEvent],
    id: &str,
    peer: &str,
    scope: &str,
) -> Result<(Request, KnowledgeRecord), String> {
    let d = original(events, id)?;
    if d.details["schema"] != "symbiote.cognition-decision/1"
        || d.details["phase"] != "contribute"
        || d.context != scope
        || d.selected_peer.as_deref() != Some(peer)
    {
        return Err("outcome does not name its original actual contribution decision".into());
    }
    let request: Request = serde_json::from_value(d.details["request"].clone())
        .map_err(|_| "original contribution request rejected")?;
    let Operation::Submit { offer } = &request.body else {
        return Err("contribution was not an inert offer".into());
    };
    Ok((request.clone(), offer.record.clone()))
}
fn credit(proof: &Proof) -> Result<String, String> {
    digest(&json!({"receiver":proof.receiver,"promotion":proof.promotion_sha256}))
}
pub(super) fn validate_event(
    config: &Config,
    event: &OperationalEvent,
    prior: &[OperationalEvent],
    _knowledge: &KnowledgeStore,
) -> Result<(), String> {
    let Some(event) = decode(event)? else {
        return Ok(());
    };
    match event {
        Event::ReceiverGoal {
            candidate,
            peer,
            scope,
            fixture_sha256,
            goal: _,
            policy_sha256,
        } => {
            config.peer(&peer)?.access(&scope, "outcome.read")?;
            if config.context(&scope)?.truth_sha256.as_ref()!=Some(&fixture_sha256)||policy_sha256!=config.policy_digest||!prior.iter().any(|e|matches!(e,OperationalEvent::Quarantined{candidate_id,key,..}if candidate_id==&candidate&&key.peer_id==peer&&key.scope==scope)){return Err("receiver goal lacks its authentic quarantine/epoch".into());}
        }
        Event::Poll {
            decision_id,
            peer,
            scope,
            candidate,
            request_sha256,
            challenge,
            receiver_policy_sha256,
            fixture_sha256,
            ..
        } => {
            let (request, _) = offered(prior, &decision_id, &peer, &scope)?;
            config.peer(&peer)?.access(&scope, "outcome.read")?;
            if !config::sha(&challenge)
                || !config::sha(&receiver_policy_sha256)
                || !config::sha(&fixture_sha256)
                || digest(&serde_json::to_value(&request).map_err(|e| e.to_string())?)?
                    != request_sha256
                || candidate_id_for(&config.identity, &request_sha256)? != candidate
            {
                return Err("outcome poll original request/challenge binding rejected".into());
            }
        }
        Event::WitnessChunk {
            decision_id,
            proof_sha256,
            index,
            total,
            hex,
        } => {
            let decision = original(prior, &decision_id)?;
            if decision.details["phase"] != "contribute"
                || !config::sha(&proof_sha256)
                || !(1..=32).contains(&total)
                || index >= total
                || hex.len() > 4096
                || hex.len() % 2 != 0
                || hex.is_empty()
                || !hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("bounded witness chunk rejected".into());
            }
        }
        Event::Reconciled {
            decision_id,
            proof_sha256,
            credit_key,
            capability_verified,
            cost_benefit_verified,
        } => {
            let proof = stored_proof(prior, &decision_id, &proof_sha256)?;
            let poll = prior
                .iter()
                .rev()
                .find_map(|e| match decode(e) {
                    Ok(Some(p @ Event::Poll { .. })) => {
                        if let Event::Poll {
                            decision_id: ref id,
                            challenge: ref ch,
                            ..
                        } = p
                        {
                            if id == &decision_id && ch == &proof.challenge {
                                return Some(p);
                            }
                        }
                        None
                    }
                    _ => None,
                })
                .ok_or("reconciliation lacks exact earlier poll")?;
            let Event::Poll {
                peer,
                scope,
                candidate,
                request_sha256,
                challenge,
                receiver_policy_sha256,
                fixture_sha256,
                goal,
                ..
            } = poll
            else {
                unreachable!()
            };
            let (_, record) = offered(prior, &decision_id, &peer, &scope)?;
            let capability = verify(
                &proof,
                &config.identity,
                &peer,
                &scope,
                &candidate,
                &request_sha256,
                &record,
                &challenge,
                &receiver_policy_sha256,
                &fixture_sha256,
                goal,
            )?;
            if credit_key!=credit(&proof)?||capability_verified!=capability||cost_benefit_verified||prior.iter().any(|e|matches!(decode(e),Ok(Some(Event::Reconciled{credit_key:old,..}))if old==credit_key)){return Err("receiver outcome duplicated or unsupported economic credit".into());}
        }
    }
    Ok(())
}
fn append(state: &mut State, event: Event, scope: &str) -> Result<(), String> {
    let event = encode_event(event, scope)?;
    validate_event(
        &state.config,
        &event,
        state.journal.events(),
        &state.knowledge,
    )?;
    state.journal.append(event)
}

/// Only the receiver's own opt-in loop invokes this. Reading an outcome never
/// authorizes evaluation, adoption, a task, or arbitrary transferred execution.
pub(super) fn process_pending(state: &mut State, permit: &Receiver) -> Result<usize, String> {
    let peer = state.config.peer_alias(&permit.peer)?.id.clone();
    let finished = feedback::replay_index(&state.journal, &state.knowledge)?;
    let candidates: Vec<_> = state
        .journal
        .events()
        .iter()
        .filter_map(|e| match e {
            OperationalEvent::Quarantined {
                candidate_id, key, ..
            } if key.peer_id == peer
                && key.scope == permit.scope
                && !finished
                    .experiences
                    .iter()
                    .any(|e| e.binding.candidate_id == *candidate_id) =>
            {
                Some(candidate_id.clone())
            }
            _ => None,
        })
        .take(permit.max_candidates_per_episode)
        .collect();
    let mut used = 0;
    for candidate in candidates {
        if state.journal.denied_peers().contains(&peer) {
            return Err("receiver contributor denied".into());
        }
        if !state.journal.events().iter().any(
            |e| matches!(decode(e),Ok(Some(Event::ReceiverGoal{candidate:c,..}))if c==candidate),
        ) {
            append(
                state,
                Event::ReceiverGoal {
                    candidate: candidate.clone(),
                    peer: peer.clone(),
                    scope: permit.scope.clone(),
                    fixture_sha256: permit.fixture_sha256.clone(),
                    goal: permit.goal,
                    policy_sha256: state.config.policy_digest.clone(),
                },
                &permit.scope,
            )?;
        }
        let exchange = feedback::begin_evaluation(
            &mut state.journal,
            &state.knowledge,
            &candidate,
            &permit.fixture_sha256,
        )?;
        let before: KnowledgeAnchor = state
            .journal
            .events()
            .iter()
            .find_map(|e| match e {
                OperationalEvent::PartnerDecisionRecorded { decision }
                    if decision.details["schema"] == feedback::SCHEMA
                        && decision.details["event"]["phase"] == "decision"
                        && decision.details["event"]["binding"]["exchange_id"] == exchange =>
                {
                    serde_json::from_value(decision.details["event"]["before"].clone()).ok()
                }
                _ => None,
            })
            .ok_or("receiver feedback boundary absent")?;
        if !matches!(
            state.offer(&candidate)?.1.record.typed_payload()?,
            symbiote_memory::knowledge::KnowledgePayload::Affine { .. }
        ) {
            return Err("initial receiver channel cannot evaluate unsupported graph family".into());
        }
        let offered = state.offer(&candidate)?.1.record;
        if state.completed(&candidate).is_none()
            && state.knowledge.active().iter().any(|r| {
                r.scope == offered.scope
                    && r.schema_fingerprint == offered.schema_fingerprint
                    && r.payload == offered.payload
            })
        {
            state.journal.append(OperationalEvent::EvaluationRejected{candidate_id:candidate.clone(),reason:"receiver goal already has this exact declarative knowledge; no new adoption or credit".into()})?;
            feedback::rejected(&mut state.journal, &state.knowledge, &candidate)?;
            continue;
        }
        let response = state.evaluate(&candidate)?;
        if response["status"] == "REJECTED" {
            feedback::rejected(&mut state.journal, &state.knowledge, &candidate)?;
            continue;
        }
        if response["promoted"] != true {
            return Err("receiver channel requires a fresh evaluated promotion".into());
        }
        let record = state.record(
            response["artifact"]
                .as_str()
                .ok_or("receiver artifact absent")?,
            &permit.scope,
        )?;
        let after = state.knowledge.history_anchor();
        let promoted=state.journal.events().iter().any(|e|matches!(e,OperationalEvent::PartnerDecisionRecorded{decision} if decision.details["schema"]==feedback::SCHEMA&&decision.details["event"]["phase"]=="promoted"&&decision.details["event"]["exchange_id"]==exchange));
        if !promoted {
            let (_, evidence) = state
                .knowledge
                .promotion_evidence_between(&record, &before, &after)?;
            let costs = &evidence["costs"];
            feedback::promoted(
                &mut state.journal,
                &state.knowledge,
                &candidate,
                &record,
                before,
                after,
                feedback::CandidateCosts {
                    unit_model: "native-stored-evaluation/1".into(),
                    acquisition: costs["acquisition"]
                        .as_u64()
                        .ok_or("acquisition cost absent")?,
                    validation: costs["verification"]
                        .as_u64()
                        .ok_or("validation cost absent")?,
                    adoption: costs["adoption"].as_u64().ok_or("adoption cost absent")?,
                    prediction: 0,
                    wire: 0,
                    replay: 0,
                },
            )?;
        }
        let used_already=state.journal.events().iter().any(|e|matches!(e,OperationalEvent::PartnerDecisionRecorded{decision} if decision.details["schema"]==feedback::SCHEMA&&decision.details["event"]["phase"]=="store_use"&&decision.details["event"]["exchange_id"]==exchange));
        if !used_already {
            feedback::record_use(&mut state.journal, &state.knowledge, &exchange, permit.goal)?;
        }
        feedback::complete(&mut state.journal, &state.knowledge, &exchange)?;
        used += 1;
    }
    Ok(used)
}
pub(super) fn export(
    state: &State,
    peer: &str,
    scope: &str,
    candidate: &str,
    request_sha: &str,
    challenge: &str,
) -> Result<Value, String> {
    history_grant(&state.config, peer, scope)?;
    if state.config.peers.len() != 1 || state.config.contexts.len() != 1 {
        return Err("outcome export privacy requires isolated one-peer/context".into());
    }
    let (source, offer) = state.offer(candidate)?;
    if source != peer || offer.record.scope != scope {
        return Err("outcome is private to its actual contributor/context".into());
    }
    let request = state
        .journal
        .events()
        .iter()
        .find_map(|e| match e {
            OperationalEvent::Quarantined {
                candidate_id,
                body_sha256,
                body,
                ..
            } if candidate_id == candidate && body_sha256 == request_sha => Some(body),
            _ => None,
        })
        .ok_or("outcome original request SHA differs")?;
    if digest(request)? != request_sha {
        return Err("outcome request digest changed".into());
    }
    let index = feedback::replay_index(&state.journal, &state.knowledge)?;
    let Some(experience) = index
        .experiences
        .iter()
        .find(|e| e.binding.candidate_id == candidate)
    else {
        return Ok(
            json!({"schema":"symbiote.contribution-outcome/1","status":"PENDING","candidate":candidate,"challenge":challenge}),
        );
    };
    let feedback::ExperienceProof::Promotion {
        localized_record_sha256,
        promotion_sha256,
        before,
        after,
        ..
    } = &experience.proof
    else {
        return Ok(
            json!({"schema":"symbiote.contribution-outcome/1","status":"REJECTED","candidate":candidate,"challenge":challenge}),
        );
    };
    if !experience.currently_active || experience.outcome.uses == 0 {
        return Err("receiver outcome record is revoked, replaced or unused".into());
    }
    let record = state
        .knowledge
        .active()
        .into_iter()
        .find(|r| r.digest().ok().as_ref() == Some(localized_record_sha256))
        .ok_or("receiver active record absent")?;
    let goal = state
        .journal
        .events()
        .iter()
        .find_map(|e| match decode(e) {
            Ok(Some(Event::ReceiverGoal {
                candidate: c, goal, ..
            })) if c == candidate => Some(goal),
            _ => None,
        })
        .ok_or("receiver local opt-in goal absent")?;
    let text = |path: &Path| -> Result<String, String> {
        String::from_utf8(config::read_bounded(
            path,
            symbiote_memory::witness::MAX_WITNESS_BYTES,
        )?)
        .map_err(|e| e.to_string())
    };
    let proof = Proof {
        schema: "symbiote.contribution-outcome/1".into(),
        challenge: challenge.into(),
        candidate: candidate.into(),
        request_sha256: request_sha.into(),
        sender: peer.into(),
        receiver: state.config.identity.clone(),
        scope: scope.into(),
        fixture_sha256: experience.binding.fixture_sha256.clone(),
        policy: state.config.public_snapshot(),
        goal,
        exchange_id: experience.binding.exchange_id.clone(),
        record,
        before: before.clone(),
        after: after.clone(),
        current: state.knowledge.history_anchor(),
        promotion_sha256: promotion_sha256.clone(),
        ledgers: LedgerWitness {
            schema: "symbiote.ledger-witness/1".into(),
            identity: state.config.identity.clone(),
            knowledge: text(&state.knowledge.ledger_path())?,
            operations: text(&state.journal.ledger_path())?,
            registration: text(&state.config.state.join("operations-owner.json"))?,
        },
    };
    // Reject an incomplete or unrelated history before any private bytes leave.
    verify(
        &proof,
        peer,
        &state.config.identity,
        scope,
        candidate,
        request_sha,
        &offer.record,
        challenge,
        &state.config.policy_digest,
        &proof.fixture_sha256,
        goal,
    )?;
    if serde_json::to_vec(&proof).map_err(|e| e.to_string())?.len()
        > symbiote_memory::witness::MAX_WITNESS_BYTES
    {
        return Err("complete receiver proof exceeds durable witness bound".into());
    }
    let response =
        json!({"schema":"symbiote.contribution-outcome/1","status":"USED","proof":proof});
    if serde_json::to_vec(&response)
        .map_err(|e| e.to_string())?
        .len()
        + 1024
        > state.config.limits.max_frame_bytes
    {
        return Err("complete outcome proof exceeds authorized frame budget; no truncation".into());
    }
    Ok(response)
}

#[allow(clippy::too_many_arguments)]
fn verify(
    proof: &Proof,
    sender: &str,
    receiver: &str,
    scope: &str,
    candidate: &str,
    request_sha: &str,
    offered: &KnowledgeRecord,
    challenge: &str,
    policy_sha: &str,
    fixture_sha: &str,
    goal: u16,
) -> Result<bool, String> {
    if proof.schema != "symbiote.contribution-outcome/1"
        || proof.sender != sender
        || proof.receiver != receiver
        || proof.scope != scope
        || proof.candidate != candidate
        || proof.request_sha256 != request_sha
        || proof.challenge != challenge
        || proof.fixture_sha256 != fixture_sha
        || proof.goal != goal
    {
        return Err("receiver outcome participants/request/challenge/fixture differ".into());
    }
    let policy = Config::historical(&proof.policy)?;
    if policy.identity != receiver
        || policy.policy_digest != policy_sha
        || policy.peers.len() != 1
        || policy.contexts.len() != 1
        || policy.context(scope)?.truth_sha256.as_deref() != Some(fixture_sha)
    {
        return Err("receiver witness epoch/authority/privacy rejected".into());
    }
    history_grant(&policy, sender, scope)?;
    policy.peer(sender)?.access(scope, "candidate.submit")?;
    let view = proof.ledgers.validate()?;
    if view.identity != receiver
        || proof.current != view.current_anchor()?
        || candidate_id_for(sender, request_sha)? != candidate
        || proof.record.id != evaluation::local_id(sender, scope, &offered.schema_fingerprint)?
        || proof.record.source != sender
        || proof.record.scope != scope
        || proof.record.payload != offered.payload
        || proof.record.schema_fingerprint != offered.schema_fingerprint
        || !view
            .active_at(&proof.current)?
            .iter()
            .any(|r| r.digest().ok() == proof.record.digest().ok())
    {
        return Err("receiver witness exact active artifact/anchor differs".into());
    }
    if view.operation_rows[0]["payload"]["service_id"] != "configured-service/v1" {
        return Err("receiver proof names an unsupported operational lineage".into());
    }
    if view.knowledge_rows.len() > 4 || view.events.len() > 64 {
        return Err("receiver proof exceeds initial bounded history envelope".into());
    }
    for row in view.knowledge_rows.iter().skip(1) {
        if row["payload"]["record"].is_object() && row["payload"]["record"]["scope"] != scope {
            return Err("unrelated private knowledge history cannot be exported".into());
        }
    }
    let mut denied = false;
    let epoch = view.operation_rows[0]["payload"]["policy_digest"]
        .as_str()
        .ok_or("receiver genesis policy absent")?
        .to_string();
    for e in &view.events {
        match e {
            OperationalEvent::PeerDenied { peer_id, .. } if peer_id == sender => denied = true,
            OperationalEvent::PeerRestored { peer_id, .. } if peer_id == sender => denied = false,
            OperationalEvent::PolicyTransitioned { .. }|OperationalEvent::LifecycleStarted{..}=>return Err("initial complete-history outcome proofs reject prior policy transitions/relocations".into()),
            OperationalEvent::PeerDenied{peer_id,..}|OperationalEvent::PeerRestored{peer_id,..} if peer_id!=sender=>return Err("unrelated private peer history cannot be exported".into()),
            OperationalEvent::PartnerOutcomeRecorded{outcome} if outcome.peer_id!=sender||outcome.scope!=scope=>return Err("unrelated private outcome history cannot be exported".into()),
            OperationalEvent::PartnerInteractionCompleted{interaction} if interaction.peer_id!=sender||interaction.context!=scope=>return Err("unrelated private interaction history cannot be exported".into()),
            OperationalEvent::SourceWarmupRetained{..}=>return Err("initial outcome envelope excludes independent private source telemetry".into()),
            OperationalEvent::Quarantined { key, .. }
                if key.peer_id != sender || key.scope != scope =>
            {
                return Err("unrelated private quarantine cannot be exported".into())
            }
            OperationalEvent::EvaluationPrepared { record, .. } if record.scope != scope => {
                return Err("unrelated private knowledge cannot be exported".into())
            }
            _ => {}
        }
    }
    if denied || epoch != policy_sha {
        return Err("receiver policy/denial is stale".into());
    }
    let mut receiver_decision = None;
    let mut feedback_decision = None;
    let mut quarantine = None;
    let mut prepared = None;
    let mut completed = None;
    let mut use_event = None;
    let mut outcome = None;
    let mut promoted = None;
    let mut receiver_goal = None;
    for (i, e) in view.events.iter().enumerate() {
        match e {
            OperationalEvent::Quarantined {
                key,
                candidate_id,
                body_sha256,
                body,
                ..
            } if candidate_id == candidate => {
                if key.peer_id != sender
                    || key.scope != scope
                    || body_sha256 != request_sha
                    || digest(body)? != request_sha
                    || body["body"]["offer"]["record"]
                        != serde_json::to_value(offered).map_err(|e| e.to_string())?
                {
                    return Err("receiver original quarantine swapped".into());
                }
                quarantine = Some(i);
            }
            OperationalEvent::EvaluationPrepared {
                candidate_id,
                record,
                fixture_sha256,
                response,
            } if candidate_id == candidate => {
                if record.digest()? != proof.record.digest()? || fixture_sha256 != fixture_sha {
                    return Err("receiver evaluation artifact/source differs".into());
                }
                prepared = Some((i, response));
            }
            OperationalEvent::EvaluationCompleted {
                candidate_id,
                record_sha256,
                response,
            } if candidate_id == candidate => {
                if record_sha256 != &proof.record.digest()? {
                    return Err("receiver completion record differs".into());
                }
                completed = Some((i, response));
            }
            OperationalEvent::PartnerDecisionRecorded { decision } => {
                if decision.details["schema"]
                    .as_str()
                    .is_some_and(|s| s.starts_with("symbiote.learning-feedback/"))
                {
                    feedback::validate_carrier(e)?;
                }
                if !matches!(
                    decision.details["schema"].as_str(),
                    Some(SCHEMA | "symbiote.receiver-evaluation-decision/1" | feedback::SCHEMA)
                ) || decision.context != scope
                    || decision
                        .selected_peer
                        .as_ref()
                        .is_some_and(|peer| peer != sender)
                {
                    return Err("unrelated private decision cannot be exported".into());
                }
                if let Some(Event::ReceiverGoal {
                    candidate: c,
                    peer,
                    fixture_sha256,
                    goal: g,
                    policy_sha256,
                    ..
                }) = decode(e)?
                {
                    if c == candidate
                        && (peer != sender
                            || fixture_sha256 != fixture_sha
                            || g != goal
                            || policy_sha256 != policy_sha
                            || receiver_goal.replace(i).is_some())
                    {
                        return Err("receiver own goal is conflicting or duplicated".into());
                    }
                }
                if decision.details["schema"] == "symbiote.receiver-evaluation-decision/1"
                    && decision.details["candidate_id"] == candidate
                {
                    receiver_decision = Some((i, decision));
                }
                let f = &decision.details["event"];
                if decision.details["schema"] == feedback::SCHEMA
                    && f["phase"] == "decision"
                    && f["binding"]["exchange_id"] == proof.exchange_id
                {
                    feedback_decision = Some((i, f));
                }
                if decision.details["schema"] == feedback::SCHEMA
                    && f["exchange_id"] == proof.exchange_id
                {
                    match f["phase"].as_str() {
                        Some("promoted") => promoted = Some((i, f)),
                        Some("store_use") => {
                            if use_event.is_some() {
                                return Err("duplicate receiver use credit".into());
                            }
                            use_event = Some((i, f));
                        }
                        Some("outcome") => outcome = Some((i, f)),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    let (d, rd) = receiver_decision.ok_or("receiver own evaluation decision absent")?;
    let (f, fd) = feedback_decision.ok_or("receiver feedback decision absent")?;
    let q = quarantine.ok_or("receiver quarantine absent")?;
    let (p, pr) = prepared.ok_or("receiver preparation absent")?;
    let (c, cr) = completed.ok_or("receiver completion absent")?;
    let (m, pe) = promoted.ok_or("receiver feedback promotion absent")?;
    let (u, ue) = use_event.ok_or("receiver actual use absent")?;
    let (o, oe) = outcome.ok_or("receiver actual outcome absent")?;
    let g = receiver_goal.ok_or("receiver prior own goal absent")?;
    if !(q < g && g < d)
        || !(q < d && d < f && f < p && p < c && c < m && m < u && u < o)
        || pr != cr
        || pe["record_sha256"] != proof.record.digest()?
        || pe["promotion_sha256"] != proof.promotion_sha256
        || pe["before"] != serde_json::to_value(&proof.before).map_err(|e| e.to_string())?
        || pe["after"] != serde_json::to_value(&proof.after).map_err(|e| e.to_string())?
    {
        return Err("receiver causal ordering/anchors rejected".into());
    }
    let binding: feedback::Binding = serde_json::from_value(fd["binding"].clone())
        .map_err(|_| "typed receiver binding absent")?;
    let body = match &view.events[q] {
        OperationalEvent::Quarantined { body, .. } => body,
        _ => unreachable!(),
    };
    let exchange = digest(
        &json!({"decision":binding.decision_id,"sender":binding.sender_id,"receiver":binding.receiver_id,"request":binding.request_sha256,"candidate":binding.candidate_id,"scope":binding.scope,"schema":binding.schema_fingerprint,"policy":binding.policy_sha256,"fixture":binding.fixture_sha256}),
    )?;
    if binding.exchange_id != exchange
        || binding.origin != feedback::DecisionOrigin::ReceiverEvaluation
        || binding.exchange_id != proof.exchange_id
        || binding.decision_id != rd.decision_id
        || binding.sender_id != sender
        || binding.receiver_id != receiver
        || binding.scope != scope
        || binding.schema_fingerprint != offered.schema_fingerprint
        || binding.request_sha256 != request_sha
        || binding.candidate_id != candidate
        || binding.offered_record_sha256 != offered.digest()?
        || binding.policy_sha256 != policy_sha
        || binding.fixture_sha256 != fixture_sha
        || rd.details["request"] != *body
    {
        return Err("receiver decision exact causal binding differs".into());
    }
    let saved: ReceiverDecisionWitness = serde_json::from_value(rd.details.clone())
        .map_err(|_| "receiver evaluation decision schema rejected")?;
    if rd.details["phase"] != "evaluate_received"
        || rd.selected_peer.as_deref() != Some(sender)
        || rd.details["knowledge_before"]
            != serde_json::to_value(&proof.before).map_err(|e| e.to_string())?
        || rd.details["service_policy_sha256"] != policy_sha
        || rd.details["fixture_sha256"] != fixture_sha
        || rd.decision_id != format!("receiver-evaluate-{}", digest(&saved)?)
        || fd["before"] != serde_json::to_value(&proof.before).map_err(|e| e.to_string())?
        || fd["baseline"]["kind"] != "unknown"
    {
        return Err("receiver local evaluation authority differs".into());
    }
    if proof.after.records != proof.before.records + 1
        || view.anchor(proof.before.records)? != proof.before
        || view.anchor(proof.after.records)? != proof.after
    {
        return Err("receiver promotion is not one fresh exact ledger change".into());
    }
    let row = &view.knowledge_rows[proof.after.records - 1];
    let evidence = &row["payload"]["assessment"]["evidence"];
    if row["sha256"] != proof.promotion_sha256
        || row["payload"]["record"]
            != serde_json::to_value(&proof.record).map_err(|e| e.to_string())?
        || pe["evidence_sha256"] != digest(evidence)?
    {
        return Err("receiver original assessment witness changed".into());
    }
    if !matches!(
        proof.record.typed_payload()?,
        symbiote_memory::knowledge::KnowledgePayload::Affine { .. }
    ) {
        return Err(
            "initial receiver channel supports exact affine retained-case proofs only".into(),
        );
    }
    let prediction = proof
        .record
        .predict_if_certified(goal)?
        .ok_or("receiver retained model abstains")?;
    if ue["basis"]["kind"] != "retained_evaluation"
        || ue["basis"]["evidence_sha256"] != digest(evidence)?
        || ue["model_work"] != 1
        || ue["record_sha256"] != proof.record.digest()?
        || ue["input"].as_u64() != Some(u64::from(goal))
        || ue["output"].as_u64() != Some(u64::from(prediction))
        || ue["sequence"] != 0
        || ue["knowledge_at"] != serde_json::to_value(&proof.after).map_err(|e| e.to_string())?
        || !evidence["cases"].as_array().is_some_and(|cases| {
            cases.iter().any(|c| {
                c["input"].as_u64() == Some(u64::from(goal))
                    && c["expected"].as_u64() == Some(u64::from(prediction))
            })
        })
    {
        return Err("receiver actual retained-evaluation use is missing or unsupported".into());
    }
    let costs: feedback::CandidateCosts =
        serde_json::from_value(pe["costs"].clone()).map_err(|_| "receiver typed costs absent")?;
    if Some(costs.total()?) != evidence["costs"]["candidate"].as_u64()
        || costs.unit_model != "native-stored-evaluation/1"
        || costs.acquisition
            != evidence["costs"]["acquisition"]
                .as_u64()
                .ok_or("native acquisition absent")?
        || costs.validation
            != evidence["costs"]["verification"]
                .as_u64()
                .ok_or("native validation absent")?
        || costs.adoption
            != evidence["costs"]["adoption"]
                .as_u64()
                .ok_or("native adoption absent")?
        || costs.prediction != 0
        || costs.wire != 0
        || costs.replay != 0
        || pe["baseline"] != fd["baseline"]
    {
        return Err("receiver local cost witness differs".into());
    }
    let result = &oe["outcome"];
    if result["candidate_cost"].as_u64() != costs.total()?.checked_add(1)
        || result["unit_model"] != costs.unit_model
        || result["baseline"] != fd["baseline"]
    {
        return Err("receiver retained-use cost total differs".into());
    }
    if result["uses"] != 1
        || result["baseline"]["kind"] != "unknown"
        || result["verified_benefit"] != false
        || !result["measured_net"].is_null()
        || oe["knowledge_at"] != serde_json::to_value(&proof.after).map_err(|e| e.to_string())?
    {
        return Err("receiver cannot promote unknown economics into measured gain".into());
    }
    let novel = !view
        .active_at(&proof.before)?
        .iter()
        .any(|r| r.scope == scope && r.schema_fingerprint == proof.record.schema_fingerprint);
    if result["quality"]
        != if novel {
            "capability_extended"
        } else {
            "correct_on_retained_case"
        }
    {
        return Err("receiver capability claim differs from prior knowledge".into());
    }
    Ok(novel)
}

pub(super) fn next_poll(
    state: &State,
    p: &Sender,
) -> Result<Option<(String, Request, String)>, String> {
    let peer = state.config.peer_alias(&p.peer)?.id.clone();
    for e in state.journal.events() {
        if let OperationalEvent::PartnerDecisionRecorded { decision } = e {
            if decision.context != p.scope
                || decision.selected_peer.as_deref() != Some(peer.as_str())
                || decision.details["schema"] != "symbiote.cognition-decision/1"
                || decision.details["phase"] != "contribute"
            {
                continue;
            }
            // Historical credit is reusable, not a claim of newly refreshed status.
            if state.journal.events().iter().any(|e|matches!(decode(e),Ok(Some(Event::Reconciled{decision_id,..}))if decision_id==decision.decision_id)){continue;}
            let polls=state.journal.events().iter().filter(|e|matches!(decode(e),Ok(Some(Event::Poll{decision_id,..}))if decision_id==decision.decision_id)).count();
            if polls >= p.max_polls {
                continue;
            }
            let (request, _) = offered(
                state.journal.events(),
                &decision.decision_id,
                &peer,
                &p.scope,
            )?;
            let request_sha = digest(&serde_json::to_value(&request).map_err(|e| e.to_string())?)?;
            return Ok(Some((decision.decision_id.clone(), request, request_sha)));
        }
    }
    Ok(None)
}
pub(super) fn begin_poll(
    state: &mut State,
    p: &Sender,
    decision_id: &str,
    request_sha: &str,
) -> Result<(String, String), String> {
    let peer = state.config.peer_alias(&p.peer)?.id.clone();
    let candidate = candidate_id_for(&state.config.identity, request_sha)?;
    let challenge = digest(
        &json!({"owner":state.config.identity,"head":state.journal.head_sha256(),"decision":decision_id,"candidate":candidate}),
    )?;
    append(
        state,
        Event::Poll {
            decision_id: decision_id.into(),
            peer,
            scope: p.scope.clone(),
            candidate: candidate.clone(),
            request_sha256: request_sha.into(),
            challenge: challenge.clone(),
            receiver_policy_sha256: p.receiver_policy_sha256.clone(),
            fixture_sha256: p.fixture_sha256.clone(),
            goal: p.goal,
        },
        &p.scope,
    )?;
    Ok((candidate, challenge))
}
pub(super) fn reconcile(
    state: &mut State,
    p: &Sender,
    decision_id: &str,
    request_sha: &str,
    challenge: &str,
    response: Value,
) -> Result<Option<bool>, String> {
    if response["schema"] != "symbiote.contribution-outcome/1" {
        return Err("unsupported receiver outcome response".into());
    }
    if response["status"] == "PENDING" || response["status"] == "REJECTED" {
        if response["candidate"] != candidate_id_for(&state.config.identity, request_sha)?
            || response["challenge"] != challenge
        {
            return Err("receiver pending/rejected nonce binding differs".into());
        }
        return Ok(None);
    }
    if response["status"] != "USED" {
        return Err("unsupported receiver outcome status".into());
    }
    let proof: Proof = serde_json::from_value(response["proof"].clone())
        .map_err(|_| "receiver complete outcome proof rejected")?;
    let peer = state.config.peer_alias(&p.peer)?.id.clone();
    let (_, record) = offered(state.journal.events(), decision_id, &peer, &p.scope)?;
    let candidate = candidate_id_for(&state.config.identity, request_sha)?;
    let capability = verify(
        &proof,
        &state.config.identity,
        &peer,
        &p.scope,
        &candidate,
        request_sha,
        &record,
        challenge,
        &p.receiver_policy_sha256,
        &p.fixture_sha256,
        p.goal,
    )?;
    let key = credit(&proof)?;
    let old =
        state.journal.events().iter().any(
            |e| matches!(decode(e),Ok(Some(Event::Reconciled{credit_key,..}))if credit_key==key),
        );
    if !old {
        let raw = serde_json::to_vec(&proof).map_err(|e| e.to_string())?;
        let proof_sha = config::hash_bytes(&raw);
        let total = raw.len().div_ceil(2048);
        let mut batch = Vec::new();
        for (index, bytes) in raw.chunks(2048).enumerate() {
            let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
            batch.push(encode_event(
                Event::WitnessChunk {
                    decision_id: decision_id.into(),
                    proof_sha256: proof_sha.clone(),
                    index,
                    total,
                    hex,
                },
                &p.scope,
            )?);
        }
        batch.push(encode_event(
            Event::Reconciled {
                decision_id: decision_id.into(),
                proof_sha256: proof_sha,
                credit_key: key,
                capability_verified: capability,
                cost_benefit_verified: false,
            },
            &p.scope,
        )?);
        let mut checked = state.journal.events().to_vec();
        for event in &batch {
            validate_event(&state.config, event, &checked, &state.knowledge)?;
            checked.push(event.clone());
        }
        let head = state.journal.head_sha256().to_string();
        state.journal.append_checked_batch(&head, batch)?;
    }
    Ok(if old { None } else { Some(capability) })
}
pub(super) struct CounterCredits {
    pub new_completed: usize,
    pub new_capability: usize,
    pub new_measured: usize,
    pub history_completed: usize,
}
/// Preserve committed reconciliations; current remote state after the reply is
/// deliberately not inferred. Revalidate complete native witnesses, not flags.
pub(super) fn counter_credits(state: &State, start: usize) -> Result<CounterCredits, String> {
    if start > state.journal.events().len() {
        return Err("counter outcome start is unavailable".into());
    }
    let mut policy = lifecycle::initial_policy(&state.config, &state.journal)?;
    let mut history = BTreeSet::new();
    let mut fresh = BTreeSet::new();
    let mut capability = BTreeSet::new();
    let mut measured = BTreeSet::new();
    for (i, event) in state.journal.events().iter().enumerate() {
        if let Some(Event::Reconciled {
            credit_key,
            capability_verified,
            cost_benefit_verified,
            ..
        }) = decode(event)?
        {
            validate_event(
                &policy,
                event,
                &state.journal.events()[..i],
                &state.knowledge,
            )?;
            if !history.insert(credit_key.clone()) {
                return Err("duplicate promotion credit in outcome counter".into());
            }
            if i >= start {
                fresh.insert(credit_key.clone());
                if capability_verified {
                    capability.insert(credit_key.clone());
                }
                if cost_benefit_verified {
                    measured.insert(credit_key);
                }
            }
        }
        if let OperationalEvent::PolicyTransitioned { policy: next, .. } = event {
            policy = Config::historical(next)?;
        }
    }
    Ok(CounterCredits {
        new_completed: fresh.len(),
        new_capability: capability.len(),
        new_measured: measured.len(),
        history_completed: history.len(),
    })
}

pub(super) fn already_sent(
    state: &State,
    peer: &str,
    scope: &str,
    record: &KnowledgeRecord,
) -> Result<bool, String> {
    let sha = record.digest()?;
    Ok(state.journal.events().iter().any(|e|matches!(e,OperationalEvent::PartnerDecisionRecorded{decision}if decision.context==scope&&decision.selected_peer.as_deref()==Some(peer)&&decision.details["schema"]=="symbiote.cognition-decision/1"&&decision.details["phase"]=="contribute"&&decision.details["source_record_sha256"]==sha)))
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
    struct Fixture {
        state: Option<State>,
        path: PathBuf,
        request: Request,
        candidate: String,
        request_sha: String,
        permit: Receiver,
    }
    impl Fixture {
        fn new(wrong: bool) -> Self {
            let path = std::env::temp_dir().join(format!(
                "symbiote-outcome-unit-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            let identity = {
                let owner = Store::open(&path).unwrap();
                owner.identity().to_string()
            };
            let truth = json!({"schema":"symbiote.local-truth/1","scope":"unit-affine/v1","family":{"kind":"affine","width":3,"outputs":(0..8u16).map(|x|((x&3).count_ones()%2)as u8).collect::<Vec<_>>()}});
            let bytes = serde_json::to_vec(&truth).unwrap();
            let truth_path = path.join("truth.json");
            fs::write(&truth_path, &bytes).unwrap();
            let fixture_sha = config::hash_bytes(&bytes);
            let fp = symbiote_memory::knowledge::affine_schema_fingerprint(3).unwrap();
            let policy = json!({"ca_sha256":"33".repeat(32),"manifest":{"schema":"symbiote.service-config/1","state":path,"identity":identity,"certificate":"leaf.pem","private_key":"never-open.key","certificate_sha256":"11".repeat(32),"ca_certificate":"ca.pem","bind_address":"127.0.0.1:1","contexts":[{"scope":"unit-affine/v1","schema_fingerprint":fp,"truth_fixture":truth_path,"truth_sha256":fixture_sha}],"peers":[{"alias":"peer","id":"sender","address":"127.0.0.1:2","server_name":"sender.test","certificate_sha256":"22".repeat(32),"access":[{"scope":"unit-affine/v1","operations":["candidate.submit","outcome.read"],"artifacts":["*"]}]}],"limits":{"max_requests":32,"max_connections":32,"max_frame_bytes":65536,"timeout_ms":500,"lifetime_ms":15000,"per_peer_requests":32,"max_offers":8,"max_offer_bytes":16384,"model_work":200000}}});
            let mut state = State::open(Config::historical(&policy).unwrap()).unwrap();
            let request = Request {
                schema: "symbiote.service-request/1".into(),
                scope: "unit-affine/v1".into(),
                request_id: "unit-submit".into(),
                body: Operation::Submit {
                    offer: Box::new(Offer {
                        record: KnowledgeRecord {
                            id: "offered".into(),
                            revision: 1,
                            source: "sender".into(),
                            scope: "unit-affine/v1".into(),
                            schema_fingerprint: fp,
                            payload: json!({"kind":"affine","width":3,"coefficients":if wrong{5}else{3},"bias":false}),
                            provenance: "unit verifier software fixture".into(),
                        },
                        training_inputs: vec![0, 1, 2, 4],
                    }),
                },
            };
            let body = serde_json::to_value(&request).unwrap();
            let request_sha = digest(&body).unwrap();
            let candidate = candidate_id_for("sender", &request_sha).unwrap();
            state
                .journal
                .append(OperationalEvent::Quarantined {
                    key: IdempotencyKey {
                        peer_id: "sender".into(),
                        scope: request.scope.clone(),
                        operation: "candidate.submit".into(),
                        request_id: request.request_id.clone(),
                    },
                    candidate_id: candidate.clone(),
                    body_sha256: request_sha.clone(),
                    body,
                    response: quarantine_response(&candidate),
                })
                .unwrap();
            let permit = Receiver {
                peer: "peer".into(),
                scope: request.scope.clone(),
                fixture_sha256: fixture_sha,
                goal: 7,
                max_candidates_per_episode: 1,
            };
            Self {
                state: Some(state),
                path,
                request,
                candidate,
                request_sha,
                permit,
            }
        }
        fn proof(&mut self) -> Proof {
            process_pending(self.state.as_mut().unwrap(), &self.permit).unwrap();
            let response = export(
                self.state.as_ref().unwrap(),
                "sender",
                &self.request.scope,
                &self.candidate,
                &self.request_sha,
                &"44".repeat(32),
            )
            .unwrap();
            serde_json::from_value(response["proof"].clone()).unwrap()
        }
        fn check(&self, p: &Proof) -> Result<bool, String> {
            let state = self.state.as_ref().unwrap();
            let Operation::Submit { offer } = &self.request.body else {
                unreachable!()
            };
            verify(
                p,
                "sender",
                &state.config.identity,
                &self.request.scope,
                &self.candidate,
                &self.request_sha,
                &offer.record,
                &"44".repeat(32),
                &state.config.policy_digest,
                &self.permit.fixture_sha256,
                7,
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            drop(self.state.take());
            let _ = fs::remove_dir_all(&self.path);
        }
    }
    // Rehash the native ledger after a semantic mutation: checks must do more than hashes.
    fn mutate_ops(proof: &mut Proof, mut edit: impl FnMut(&mut Value)) {
        let mut rows: Vec<Value> = proof
            .ledgers
            .operations
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        for r in rows.iter_mut().skip(1) {
            if r["payload"]["event"] == "partner_decision_recorded" {
                edit(&mut r["payload"]);
            }
        }
        replace_ops(proof, rows);
    }
    fn replace_ops(proof: &mut Proof, mut rows: Vec<Value>) {
        let mut previous = "0".repeat(64);
        for r in &mut rows {
            r["previous"] = json!(previous);
            let sha = digest(&(
                r["sequence"].as_u64().unwrap(),
                &r["previous"],
                &r["payload"],
            ))
            .unwrap();
            r["sha256"] = json!(sha);
            previous = sha;
        }
        proof.ledgers.operations = rows
            .into_iter()
            .map(|r| serde_json::to_string(&r).unwrap() + "\n")
            .collect();
    }
    #[test]
    fn complete_witness_checks_actual_decision_use_cost_and_epoch_not_just_hashes() {
        let mut f = Fixture::new(false);
        let p = f.proof();
        assert!(f.check(&p).unwrap());
        for field in [
            "sender",
            "request",
            "challenge",
            "fixture",
            "promotion",
            "current",
        ] {
            let mut bad = p.clone();
            match field {
                "sender" => bad.sender = "other".into(),
                "request" => bad.request_sha256 = "55".repeat(32),
                "challenge" => bad.challenge = "55".repeat(32),
                "fixture" => bad.fixture_sha256 = "55".repeat(32),
                "promotion" => bad.promotion_sha256 = "55".repeat(32),
                _ => bad.current = bad.before.clone(),
            }
            assert!(f.check(&bad).is_err(), "{field}");
        }
        for field in ["output", "model_work", "basis", "cost", "binding"] {
            let mut bad = p.clone();
            mutate_ops(&mut bad, |e| {
                let d = &mut e["decision"]["details"];
                let phase = d["event"]["phase"].as_str().unwrap_or("").to_string();
                if phase == "store_use" {
                    match field {
                        "output" => d["event"]["output"] = json!(1),
                        "model_work" => d["event"]["model_work"] = json!(0),
                        "basis" => {
                            d["event"]["basis"] =
                                json!({"kind":"conditional_family","family":"untrusted"})
                        }
                        _ => {}
                    }
                }
                if field == "cost" && phase == "outcome" {
                    d["event"]["outcome"]["candidate_cost"] = json!(0);
                }
                if field == "binding" && phase == "decision" {
                    d["event"]["binding"]["offered_record_sha256"] = json!("55".repeat(32));
                }
            });
            assert!(f.check(&bad).is_err(), "rehashed {field}");
        }
        let mut reordered = p.clone();
        let mut rr: Vec<Value> = reordered
            .ledgers
            .operations
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        let goal = rr
            .iter()
            .position(|r| r["payload"]["decision"]["details"]["event"]["phase"] == "receiver_goal")
            .unwrap();
        let row = rr.remove(goal);
        rr.push(row);
        for (i, r) in rr.iter_mut().enumerate() {
            r["sequence"] = json!(i);
        }
        replace_ops(&mut reordered, rr);
        assert!(
            f.check(&reordered).is_err(),
            "fully rehashed late receiver goal"
        );
        let state = f.state.as_mut().unwrap();
        state
            .knowledge
            .revoke(&p.record.id, "unit revocation")
            .unwrap();
        assert!(export(
            state,
            "sender",
            &f.request.scope,
            &f.candidate,
            &f.request_sha,
            &"44".repeat(32)
        )
        .is_err());
    }

    #[test]
    fn role_counters_reconcile_duplicate_supersession_revocation_and_restart() {
        use super::super::cognitive::counters::{Counters, Role};
        let mut f = Fixture::new(false);
        let state = f.state.as_mut().unwrap();
        let mut counters = Counters::begin(state).unwrap();
        let before = counters.capture(state).unwrap();
        assert_eq!(process_pending(state, &f.permit).unwrap(), 1);
        counters
            .checkpoint(state, &before, Role::ReceiverRole, None)
            .unwrap();
        let first = counters.finish(state).unwrap();
        assert_eq!(
            first["promotions"],
            json!({"ordinary_learning":0,"receiver_role":1,"total_new":1})
        );
        assert_eq!(first["completed_outcomes"]["receiver_role"], 1);
        assert_eq!(first["capability_outcomes"]["receiver_role"], 1);
        assert_eq!(
            first["current_active_local"]["capability_outcomes"]["receiver_role"],
            1
        );
        assert_eq!(first["measured_benefits"]["total"], 0);
        assert_eq!(
            first,
            counters.finish(state).unwrap(),
            "read must not create credit"
        );
        let fixture = state.config.contexts[0]
            .truth_fixture
            .as_ref()
            .unwrap()
            .clone();
        let fixture_bytes = fs::read(&fixture).unwrap();
        let mut changed = fixture_bytes.clone();
        changed.push(b' ');
        fs::write(&fixture, changed).unwrap();
        let changed = counters.finish(state).unwrap();
        assert_eq!(changed["completed_outcomes"]["receiver_role"], 1);
        assert_eq!(
            changed["current_active_local"]["capability_outcomes"]["total"], 0,
            "changed evaluator bytes cannot verify current membership"
        );
        fs::write(fixture, fixture_bytes).unwrap();
        let mut duplicate = f.request.clone();
        duplicate.request_id = "duplicate-payload".into();
        state.submit("sender", &duplicate).unwrap();
        let before = counters.capture(state).unwrap();
        assert_eq!(process_pending(state, &f.permit).unwrap(), 0);
        counters
            .checkpoint(state, &before, Role::ReceiverRole, None)
            .unwrap();
        let reused = counters.finish(state).unwrap();
        assert_eq!(reused["promotions"]["total_new"], 1);
        assert_eq!(reused["reused_records"]["receiver_role"], 1);
        assert_eq!(reused["completed_outcomes"]["receiver_role"], 2);
        assert_eq!(reused["capability_outcomes"]["receiver_role"], 1);
        // An actually committed new version is a promotion event, not evidence
        // that the identical payload acquired another verified capability.
        let before = counters.capture(state).unwrap();
        let mut replacement = state.knowledge.active().pop().unwrap();
        let (_, evidence) = state
            .knowledge
            .promotion_evidence_between(
                &replacement,
                &serde_json::from_value::<KnowledgeAnchor>(
                    first["initial_knowledge_anchor"].clone(),
                )
                .unwrap(),
                &state.knowledge.history_anchor(),
            )
            .unwrap();
        replacement.revision += 1;
        replacement.provenance = "controlled native supersession fixture".into();
        let mut evidence: symbiote_memory::knowledge::TrialEvidence =
            serde_json::from_value(evidence).unwrap();
        for case in &mut evidence.cases {
            case.baseline = Some(case.candidate);
        }
        // Controlled assessment fixture permits a same-payload version change;
        // no feedback measurement or engine cost-benefit credit is created.
        evidence.costs.baseline = evidence.costs.candidate + 1;
        state
            .knowledge
            .promote(
                replacement.clone(),
                symbiote_memory::knowledge::assess(&replacement, &evidence).unwrap(),
            )
            .unwrap();
        counters
            .checkpoint(state, &before, Role::OrdinaryLearning, None)
            .unwrap();
        let superseded = counters.finish(state).unwrap();
        assert_eq!(
            superseded["promotions"],
            json!({"ordinary_learning":1,"receiver_role":1,"total_new":2})
        );
        assert_eq!(superseded["capability_outcomes"]["receiver_role"], 1);
        assert_eq!(
            superseded["current_active_local"]["capability_outcomes"]["total"],
            0
        );
        let before = counters.capture(state).unwrap();
        state
            .knowledge
            .revoke(&replacement.id, "controlled revocation")
            .unwrap();
        counters
            .checkpoint(state, &before, Role::OrdinaryLearning, None)
            .unwrap();
        let revoked = counters.finish(state).unwrap();
        assert_eq!(revoked["completed_outcomes"]["receiver_role"], 2);
        assert_eq!(revoked["capability_outcomes"]["receiver_role"], 1);
        assert_eq!(
            revoked["current_active_local"]["completed_outcomes"]["total"],
            0
        );
        let reopened = Counters::begin(state).unwrap().finish(state).unwrap();
        assert_eq!(reopened["promotions"]["total_new"], 0);
        assert_eq!(reopened["completed_outcomes"]["total"], 0);
        assert_eq!(
            reopened["durable_history_completed_outcomes"]["receiver_role"],
            2
        );
    }
    #[test]
    fn role_counters_reject_hash_claims_without_native_commits() {
        use super::super::cognitive::counters::{Counters, Role};
        let mut f = Fixture::new(false);
        let state = f.state.as_mut().unwrap();
        let mut counters = Counters::begin(state).unwrap();
        let before = counters.capture(state).unwrap();
        let invented = json!({"status":"REUSED","before":state.knowledge.history_anchor(),"after":state.knowledge.history_anchor(),"queries_performed":0,"record_sha256":"55".repeat(32),"artifact":"invented","scope":f.request.scope});
        assert!(counters
            .checkpoint(state, &before, Role::OrdinaryLearning, Some(&invented))
            .is_err());
        let before = counters.capture(state).unwrap();
        process_pending(state, &f.permit).unwrap();
        let file = state.knowledge.ledger_path();
        let original = fs::read(&file).unwrap();
        let mut rows: Vec<Value> = String::from_utf8(original.clone())
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        rows[1]["sha256"] = json!("55".repeat(32));
        fs::write(
            &file,
            rows.iter()
                .map(|v| serde_json::to_string(v).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        assert!(counters
            .checkpoint(state, &before, Role::ReceiverRole, None)
            .is_err());
        fs::write(file, original).unwrap();
        let opfile = state.journal.ledger_path();
        let opbytes = fs::read(&opfile).unwrap();
        fs::write(&opfile, &opbytes[..opbytes.len() - 1]).unwrap();
        assert!(counters.finish(state).unwrap_err().contains("truncated"));
        fs::write(opfile, opbytes).unwrap();
    }
    #[test]
    fn reading_an_outcome_never_evaluates_or_mutates_receiver_state() {
        let f = Fixture::new(false);
        let state = f.state.as_ref().unwrap();
        let head = state.journal.head_sha256().to_string();
        let anchor = state.knowledge.history_anchor();
        let result = export(
            state,
            "sender",
            &f.request.scope,
            &f.candidate,
            &f.request_sha,
            &"44".repeat(32),
        )
        .unwrap();
        assert_eq!(result["status"], "PENDING");
        assert_eq!(state.journal.head_sha256(), head);
        assert_eq!(state.knowledge.history_anchor(), anchor);
    }
    #[test]
    fn receiver_rejects_wrong_transfer_and_closes_real_negative_feedback() {
        let mut f = Fixture::new(true);
        assert_eq!(
            process_pending(f.state.as_mut().unwrap(), &f.permit).unwrap(),
            0
        );
        let state = f.state.as_ref().unwrap();
        assert!(state.knowledge.active().is_empty());
        let index = feedback::replay_index(&state.journal, &state.knowledge).unwrap();
        assert_eq!(index.experiences.len(), 1);
        assert_eq!(
            index.experiences[0].outcome.quality,
            feedback::Quality::Rejected
        );
        assert!(!index.experiences[0].outcome.verified_benefit);
        assert_eq!(
            export(
                state,
                "sender",
                &f.request.scope,
                &f.candidate,
                &f.request_sha,
                &"44".repeat(32)
            )
            .unwrap()["status"],
            "REJECTED"
        );
        assert_eq!(
            process_pending(f.state.as_mut().unwrap(), &f.permit).unwrap(),
            0
        );
    }
    #[test]
    fn export_rejects_unrelated_history_and_bounded_frame_before_disclosure() {
        let mut f = Fixture::new(false);
        let _ = f.proof();
        let state = f.state.as_mut().unwrap();
        state.config.peers[0].access[0].artifacts = vec!["offered".into()];
        assert!(export(
            state,
            "sender",
            &f.request.scope,
            &f.candidate,
            &f.request_sha,
            &"44".repeat(32)
        )
        .is_err());
        state.config.peers[0].access[0].artifacts = vec!["*".into()];
        state.config.limits.max_frame_bytes = 1024;
        assert!(export(
            state,
            "sender",
            &f.request.scope,
            &f.candidate,
            &f.request_sha,
            &"44".repeat(32)
        )
        .is_err());
        state.config.limits.max_frame_bytes = 65536;
        assert!(export(
            state,
            "other",
            &f.request.scope,
            &f.candidate,
            &f.request_sha,
            &"44".repeat(32)
        )
        .is_err());
        state
            .journal
            .append(OperationalEvent::PartnerDecisionRecorded {
                decision: PartnerDecisionRecord {
                    decision_id: "private-other-context".into(),
                    context: "other-context/v1".into(),
                    frontier_edge: None,
                    selected_peer: None,
                    details: json!({"schema":"private/1","not_for_export":"private context"}),
                },
            })
            .unwrap();
        assert!(export(
            state,
            "sender",
            &f.request.scope,
            &f.candidate,
            &f.request_sha,
            &"44".repeat(32)
        )
        .is_err());
    }
    #[test]
    fn retained_use_recovers_once_after_completed_evaluation() {
        let mut f = Fixture::new(false);
        let state = f.state.as_mut().unwrap();
        append(
            state,
            Event::ReceiverGoal {
                candidate: f.candidate.clone(),
                peer: "sender".into(),
                scope: f.request.scope.clone(),
                fixture_sha256: f.permit.fixture_sha256.clone(),
                goal: 7,
                policy_sha256: state.config.policy_digest.clone(),
            },
            &f.request.scope,
        )
        .unwrap();
        feedback::begin_evaluation(
            &mut state.journal,
            &state.knowledge,
            &f.candidate,
            &f.permit.fixture_sha256,
        )
        .unwrap();
        assert_eq!(state.evaluate(&f.candidate).unwrap()["promoted"], true);
        assert_eq!(process_pending(state, &f.permit).unwrap(), 1);
        assert_eq!(process_pending(state, &f.permit).unwrap(), 0);
    }
}
