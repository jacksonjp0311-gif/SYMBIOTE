//! An operator-bounded native learning participant. Remote records remain inert.
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use symbiote_memory::knowledge::{KnowledgeAnchor, KnowledgePayload, KnowledgeRecord};
use symbiote_memory::operational::{
    PartnerDecisionRecord, PartnerInteractionOutcome, PartnerInteractionRecord, PartnerOutcomeKind,
    PartnerOutcomeRecord,
};
use symbiote_protocol::{SecureTraffic, SecureTrafficSnapshot};
use symbiote_reasoning::symbiosis::{
    self, affine_full_fixture_transfer, graph_fixture_transfer, outbound_views, plan, reconcile,
    ExchangePlan, ExchangeTerms, OutboundEvidence, ParticipantView, ValueReconciliation,
};

const DETAILS: &str = "symbiote.cognition-decision/1";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunPolicy {
    schema: String,
    expected_identity: String,
    service_policy_sha256: String,
    max_episodes: usize,
    max_duration_ms: u64,
    interval_ms: u64,
    max_rpc_attempts: u64,
    max_model_work: usize,
    max_plaintext_bytes: u64,
    max_candidates_per_episode: usize,
    max_contributions_per_episode: usize,
    peers: Vec<String>,
    scopes: Vec<String>,
    contribute: bool,
}
impl RunPolicy {
    fn validate(&self, config: &Config) -> Result<(), String> {
        if self.schema != "symbiote.cognition-policy/1"
            || self.expected_identity != config.identity
            || self.service_policy_sha256 != config.policy_digest
            || !(1..=128).contains(&self.max_episodes)
            || !(1000..=config.limits.lifetime_ms).contains(&self.max_duration_ms)
            || self.interval_ms > 60_000
            || !(1..=config.limits.max_requests).contains(&self.max_rpc_attempts)
            || !(1024..=config.limits.model_work).contains(&self.max_model_work)
            || !(1024..=64 * 1024 * 1024).contains(&self.max_plaintext_bytes)
            || !(1..=8).contains(&self.max_candidates_per_episode)
            || self.max_contributions_per_episode > 8
            || self.peers.is_empty()
            || self.peers.len() > 32
            || self.scopes.is_empty()
            || self.scopes.len() > 8
            || self.peers.iter().collect::<BTreeSet<_>>().len() != self.peers.len()
            || self.scopes.iter().collect::<BTreeSet<_>>().len() != self.scopes.len()
        {
            return Err("native run policy must exactly bind this owner and approved service epoch within narrower finite budgets".into());
        }
        for alias in &self.peers {
            config.peer_alias(alias)?;
        }
        for scope in &self.scopes {
            let context = config.context(scope)?;
            if context.truth_fixture.is_none() {
                return Err(
                    "native learning scope requires an operator-pinned local truth fixture".into(),
                );
            }
        }
        Ok(())
    }
}
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Profile {
    peer: String,
    scope: String,
    visits: u64,
    failures: u64,
    verified_novel: u64,
    resource_units: u64,
}
fn profiles(
    events: &[OperationalEvent],
    config: &Config,
    policy: &RunPolicy,
) -> Result<Vec<Profile>, String> {
    let mut denied = BTreeSet::new();
    for event in events {
        match event {
            OperationalEvent::PeerDenied { peer_id, .. } => {
                denied.insert(peer_id.clone());
            }
            OperationalEvent::PeerRestored { peer_id, .. } => {
                denied.remove(peer_id);
            }
            _ => {}
        }
    }
    let mut result = Vec::new();
    for alias in &policy.peers {
        let peer = config.peer_alias(alias)?;
        if denied.contains(&peer.id) {
            continue;
        }
        for scope in &policy.scopes {
            if [
                "capabilities",
                "knowledge.list",
                "knowledge.read",
                "candidate.submit",
            ]
            .iter()
            .any(|operation| peer.access(scope, operation).is_err())
            {
                continue;
            }
            let mut profile = Profile {
                peer: peer.id.clone(),
                scope: scope.clone(),
                ..Profile::default()
            };
            for event in events {
                match event {
                    OperationalEvent::PartnerDecisionRecorded { decision }
                        if decision.selected_peer.as_deref() == Some(&peer.id)
                            && decision.context == *scope
                            && decision.details["schema"] == DETAILS
                            && decision.details["phase"] == "sense" =>
                    {
                        profile.visits += 1
                    }
                    OperationalEvent::PartnerOutcomeRecorded { outcome }
                        if outcome.peer_id == peer.id && outcome.scope == *scope =>
                    {
                        profile.failures += u64::from(matches!(
                            outcome.kind,
                            PartnerOutcomeKind::Failed | PartnerOutcomeKind::Rejected
                        ));
                        profile.resource_units += outcome.resource_units;
                    }
                    OperationalEvent::PartnerInteractionCompleted { interaction }
                        if interaction.peer_id == peer.id && interaction.context == *scope =>
                    {
                        profile.verified_novel += u64::from(
                            interaction.outcome == PartnerInteractionOutcome::VerifiedNovel,
                        );
                        profile.failures += u64::from(matches!(
                            interaction.outcome,
                            PartnerInteractionOutcome::VerificationFailed
                                | PartnerInteractionOutcome::TransportFailed
                        ));
                        profile.resource_units += interaction.resource_units;
                    }
                    _ => {}
                }
            }
            result.push(profile);
        }
    }
    // Exploration remains primary; outcome/cost evidence breaks equally visited ties.
    result.sort_by(|a, b| {
        (
            a.visits,
            a.failures,
            std::cmp::Reverse(a.verified_novel),
            a.resource_units,
            &a.peer,
            &a.scope,
        )
            .cmp(&(
                b.visits,
                b.failures,
                std::cmp::Reverse(b.verified_novel),
                b.resource_units,
                &b.peer,
                &b.scope,
            ))
    });
    Ok(result)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    schema: String,
    phase: String,
    policy: RunPolicy,
    run_policy_sha256: String,
    service_policy_sha256: String,
    profiles: Vec<Profile>,
    source_record_sha256: Option<String>,
    candidate_id: Option<String>,
    request: Option<Request>,
    knowledge_before: KnowledgeAnchor,
    origin_peer: Option<String>,
}
struct Intent<'a> {
    phase: &'a str,
    peer: &'a str,
    scope: &'a str,
    request: Option<Request>,
    origin: Option<String>,
}
fn decision_record(
    config: &Config,
    policy: &RunPolicy,
    events: &[OperationalEvent],
    intent: Intent<'_>,
    before: KnowledgeAnchor,
) -> Result<PartnerDecisionRecord, String> {
    let Intent {
        phase,
        peer,
        scope,
        request,
        origin,
    } = intent;
    let source = request
        .as_ref()
        .and_then(|request| {
            if let Operation::Submit { offer } = &request.body {
                Some(offer.record.digest())
            } else {
                None
            }
        })
        .transpose()?;
    let candidate = if phase == "learn" {
        request
            .as_ref()
            .map(|request| candidate_id_for(peer, &request_digest(request)?))
            .transpose()?
    } else {
        None
    };
    let details = Decision {
        schema: DETAILS.into(),
        phase: phase.into(),
        policy: policy.clone(),
        run_policy_sha256: digest(policy)?,
        service_policy_sha256: config.policy_digest.clone(),
        profiles: profiles(events, config, policy)?,
        source_record_sha256: source,
        candidate_id: candidate,
        request,
        knowledge_before: before,
        origin_peer: origin,
    };
    Ok(PartnerDecisionRecord {
        decision_id: format!("cognition-{}", symbiote_protocol::fresh_capability()?),
        context: scope.into(),
        frontier_edge: None,
        selected_peer: Some(peer.into()),
        details: serde_json::to_value(details).map_err(|_| "cannot encode native decision")?,
    })
}
fn parse_decision(
    decision: &PartnerDecisionRecord,
    policy: &Config,
    prior: &[OperationalEvent],
    knowledge: &KnowledgeStore,
) -> Result<Decision, String> {
    let details: Decision = serde_json::from_value(decision.details.clone())
        .map_err(|_| "non-cognitive profile event in configured service namespace")?;
    details.policy.validate(policy)?;
    knowledge.validate_anchor(&details.knowledge_before)?;
    validate_as_of_anchor(knowledge, &details.knowledge_before, prior)?;
    if details.schema != DETAILS
        || details.run_policy_sha256 != digest(&details.policy)?
        || details.service_policy_sha256 != policy.policy_digest
        || details.profiles != profiles(prior, policy, &details.policy)?
        || decision.frontier_edge.is_some()
    {
        return Err("native decision differs from its effective historical policy or preceding outcome profiles".into());
    }
    let peer = decision
        .selected_peer
        .as_deref()
        .ok_or("native decision requires an explicitly eligible peer")?;
    if !details
        .profiles
        .iter()
        .any(|profile| profile.peer == peer && profile.scope == decision.context)
    {
        return Err("native decision selected an unregistered or denied peer/context".into());
    }
    if details.phase == "sense" {
        let selected = details
            .profiles
            .first()
            .ok_or("native decision has no eligible profiles")?;
        if selected.peer != peer
            || selected.scope != decision.context
            || details.request.is_some()
            || details.source_record_sha256.is_some()
            || details.candidate_id.is_some()
        {
            return Err("native partner choice does not replay from preceding own outcomes".into());
        }
    } else {
        if !["learn", "contribute"].contains(&details.phase.as_str()) {
            return Err("unknown cognitive decision phase".into());
        }
        let request = details
            .request
            .as_ref()
            .ok_or("native candidate binding is missing")?;
        request.validate(policy)?;
        State::authorize_policy(policy, peer, request)?;
        let Operation::Submit { offer } = &request.body else {
            return Err("native candidate binding is not an inert submit request".into());
        };
        if request.scope != decision.context
            || details.source_record_sha256.as_deref() != Some(offer.record.digest()?.as_str())
            || (details.phase == "learn"
                && details.candidate_id != Some(candidate_id_for(peer, &request_digest(request)?)?))
        {
            return Err(
                "native source digest, context or canonical candidate binding changed".into(),
            );
        }
        if details.phase == "contribute"
            && (details.origin_peer.as_deref() == Some(peer) || details.origin_peer.is_none())
        {
            return Err(
                "native contribution cannot echo a partner's own model as a discovery".into(),
            );
        }
        if details.phase == "contribute" {
            let offered = offer.record.digest()?;
            let retained = knowledge
                .active_at(&details.knowledge_before)?
                .into_iter()
                .find(|record| record.digest().ok().as_deref() == Some(offered.as_str()))
                .ok_or(
                    "native contribution was not retained active knowledge at its saved owner head",
                )?;
            if details.origin_peer.as_deref() != Some(retained.source.as_str())
                || retained.source == peer
            {
                return Err("native contribution origin differs from its actual retained source or echoes its recipient".into());
            }
        }
    }
    Ok(details)
}
fn original_decision<'a>(
    prior: &'a [OperationalEvent],
    id: &str,
) -> Result<&'a PartnerDecisionRecord, String> {
    prior
        .iter()
        .find_map(|event| {
            if let OperationalEvent::PartnerDecisionRecorded { decision } = event {
                if decision.decision_id == id {
                    return Some(decision);
                }
            }
            None
        })
        .ok_or_else(|| "native outcome has no preceding bounded decision".into())
}
fn fresh_promotion(
    knowledge: &KnowledgeStore,
    before: &KnowledgeAnchor,
    record_sha: &str,
) -> Result<String, String> {
    knowledge.validate_anchor(before)?;
    let bytes = config::read_bounded(&knowledge.ledger_path(), 16 * 1024 * 1024)?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| "native learning history encoding changed")?;
    for (index, line) in text.lines().enumerate().skip(before.records) {
        let row: Value =
            serde_json::from_str(line).map_err(|_| "native learning receipt encoding changed")?;
        if ["promote", "promote_graph"].contains(&row["payload"]["event"].as_str().unwrap_or("")) {
            let record: KnowledgeRecord = serde_json::from_value(row["payload"]["record"].clone())
                .map_err(|_| "native promoted record encoding changed")?;
            if record.digest()? == record_sha
                && index >= before.records
                && knowledge.has_historical_promotion(&record)?
            {
                return row["sha256"]
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| "native knowledge receipt has no digest".into());
            }
        }
    }
    Err("native outcome has no actual fresh local promotion after its saved knowledge head".into())
}
fn validate_as_of_anchor(
    knowledge: &KnowledgeStore,
    before: &KnowledgeAnchor,
    prior: &[OperationalEvent],
) -> Result<(), String> {
    let mut minimum = 1;
    let completed = prior
        .iter()
        .filter_map(|event| {
            if let OperationalEvent::EvaluationCompleted { record_sha256, .. } = event {
                Some(record_sha256)
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>();
    if !completed.is_empty() {
        let bytes = config::read_bounded(&knowledge.ledger_path(), 16 * 1024 * 1024)?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| "native owner history encoding changed")?;
        for (index, line) in text.lines().enumerate() {
            let row: Value =
                serde_json::from_str(line).map_err(|_| "native owner history row changed")?;
            if ["promote", "promote_graph"]
                .contains(&row["payload"]["event"].as_str().unwrap_or(""))
            {
                let record: KnowledgeRecord =
                    serde_json::from_value(row["payload"]["record"].clone())
                        .map_err(|_| "native owner promotion row changed")?;
                if completed
                    .iter()
                    .any(|sha| **sha == record.digest().unwrap_or_default())
                {
                    minimum = minimum.max(index + 1);
                }
            }
        }
    }
    for event in prior {
        if let OperationalEvent::PartnerDecisionRecorded { decision } = event {
            if decision.details["schema"] == DETAILS {
                let anchor: KnowledgeAnchor =
                    serde_json::from_value(decision.details["knowledge_before"].clone())
                        .map_err(|_| "preceding cognitive owner anchor changed")?;
                knowledge.validate_anchor(&anchor)?;
                minimum = minimum.max(anchor.records);
            }
        }
    }
    if before.records < minimum {
        return Err("native decision owner anchor predates already completed owner history".into());
    }
    Ok(())
}
pub(super) fn validate_profile_event(
    policy: &Config,
    event: &OperationalEvent,
    prior: &[OperationalEvent],
    knowledge: &KnowledgeStore,
) -> Result<(), String> {
    match event {
        OperationalEvent::PartnerDecisionRecorded { decision } => {
            parse_decision(decision, policy, prior, knowledge)?;
        }
        OperationalEvent::PartnerOutcomeRecorded { outcome } => {
            let decision = original_decision(prior, &outcome.interaction_id)?;
            let details: Decision = serde_json::from_value(decision.details.clone())
                .map_err(|_| "native outcome decision schema changed")?;
            if details.schema != DETAILS
                || !["sense", "contribute"].contains(&details.phase.as_str())
                || decision.selected_peer.as_deref() != Some(&outcome.peer_id)
                || decision.context != outcome.scope
            {
                return Err("native telemetry outcome attribution changed".into());
            }
        }
        OperationalEvent::PartnerInteractionCompleted { interaction } => {
            let decision = original_decision(prior, &interaction.decision_id)?;
            let details: Decision = serde_json::from_value(decision.details.clone())
                .map_err(|_| "native learning decision schema changed")?;
            if details.schema != DETAILS
                || details.phase != "learn"
                || decision.selected_peer.as_deref() != Some(&interaction.peer_id)
                || decision.context != interaction.context
            {
                return Err("native learning outcome attribution changed".into());
            }
            if interaction.outcome == PartnerInteractionOutcome::VerifiedNovel {
                if prior.iter().any(|event|matches!(event,OperationalEvent::PartnerInteractionCompleted {interaction:earlier}
                    if earlier.outcome==PartnerInteractionOutcome::VerifiedNovel && earlier.receipt_sha256==interaction.receipt_sha256)) {
                    return Err("native local promotion receipt was already credited by an earlier interaction".into());
                }
                let candidate = details
                    .candidate_id
                    .ok_or("native fresh learning candidate missing")?;
                let decision_position=prior.iter().position(|event|matches!(event,OperationalEvent::PartnerDecisionRecorded {decision:earlier} if earlier.decision_id==decision.decision_id)).ok_or("native decision boundary missing")?;
                let (completed_position,completed) = prior
                    .iter().enumerate()
                    .rev()
                    .find_map(|(index,event)| {
                        if let OperationalEvent::EvaluationCompleted {
                            candidate_id,
                            record_sha256,
                            ..
                        } = event
                        {
                            if candidate_id == &candidate && index>decision_position {
                                return Some((index,record_sha256));
                            }
                        }
                        None
                    })
                    .ok_or("native novel outcome lacks an actual completed local evaluation after its own decision")?;
                let prepared = prior
                    .iter()
                    .enumerate()
                    .find_map(|(index, event)| match event {
                        OperationalEvent::EvaluationPrepared {
                            candidate_id,
                            record,
                            ..
                        } if candidate_id == &candidate
                            && index > decision_position
                            && index < completed_position =>
                        {
                            Some(record)
                        }
                        _ => None,
                    })
                    .ok_or("native novel outcome lacks its own subsequent prepared evaluation")?;
                if prepared.digest()? != *completed
                    || prepared.source != interaction.peer_id
                    || prepared.scope != interaction.context
                {
                    return Err("native novel evaluation source, context or committed record binding changed".into());
                }
                if interaction.receipt_sha256.as_deref()
                    != Some(
                        fresh_promotion(knowledge, &details.knowledge_before, completed)?.as_str(),
                    )
                {
                    return Err(
                        "native novel outcome does not name its exact fresh local learning receipt"
                            .into(),
                    );
                }
            }
        }
        _ => return Err("research profile events are outside configured cognition".into()),
    }
    Ok(())
}

#[derive(Clone, Default, Serialize)]
struct Budget {
    rpc_attempts: u64,
    model_work_reserved: usize,
    outbound_plaintext_reserved: u64,
    listener_plaintext_reserved: u64,
}
impl Budget {
    fn rpc(&mut self, policy: &RunPolicy, quote: u64) -> Result<(), String> {
        if self.rpc_attempts >= policy.max_rpc_attempts
            || self.listener_plaintext_reserved + self.outbound_plaintext_reserved + quote
                > policy.max_plaintext_bytes
        {
            return Err("budget:global-rpc-or-plaintext".into());
        }
        self.rpc_attempts += 1;
        self.outbound_plaintext_reserved += quote;
        Ok(())
    }
    fn model(&mut self, policy: &RunPolicy, quote: usize) -> Result<(), String> {
        if self
            .model_work_reserved
            .checked_add(quote)
            .is_none_or(|work| work > policy.max_model_work)
        {
            return Err("budget:global-model-work".into());
        }
        self.model_work_reserved += quote;
        Ok(())
    }
}
struct Recorder {
    file: File,
    sequence: u64,
}
impl Recorder {
    fn emit(&mut self, phase: &str, details: Value) -> Result<(), String> {
        let value = json!({"schema":"symbiote.cognition-event/1","sequence":self.sequence,"phase":phase,"details":details});
        self.sequence += 1;
        let line =
            serde_json::to_vec(&value).map_err(|_| "cannot encode native cognitive receipt")?;
        if line.len() > 65_536 {
            return Err("native cognitive event exceeds frame budget".into());
        }
        self.file
            .write_all(&line)
            .and_then(|_| self.file.write_all(b"\n"))
            .and_then(|_| self.file.flush())
            .map_err(|_| "cannot persist native cognitive receipt")?;
        println!("{}", String::from_utf8_lossy(&line));
        std::io::stdout()
            .flush()
            .map_err(|_| "cannot publish native cognition event".to_string())
    }
}
fn append(state: &mut State, event: OperationalEvent) -> Result<(), String> {
    validate_profile_event(
        &state.config,
        &event,
        state.journal.events(),
        &state.knowledge,
    )?;
    state.journal.append(event)
}
fn request(scope: &str, id: String, body: Operation) -> Request {
    Request {
        schema: "symbiote.service-request/1".into(),
        scope: scope.into(),
        request_id: id,
        body,
    }
}
fn request_digest(request: &Request) -> Result<String, String> {
    digest(
        &serde_json::to_value(request)
            .map_err(|_| "cannot canonicalize native candidate request")?,
    )
}
fn rpc(cycle: &Cycle<'_>, peer: &str, request: &Request) -> Result<Value, String> {
    let state = cycle.state;
    let budget = cycle.budget;
    let policy = cycle.policy;
    let traffic = cycle.traffic;
    let cancelled = cycle.cancelled;
    let deadline = cycle.deadline;
    if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
        return Err("cancelled:before-rpc".into());
    }
    // Build only from the operator registry while locked; never hold owner state across a reciprocal RPC.
    let (mut endpoint, client_config, frame) = {
        let owner = state.lock().map_err(|_| "native owner lock poisoned")?;
        request.validate(&owner.config)?;
        owner.authorize(peer, request)?;
        if owner.journal.denied_peers().contains(peer) {
            return Err("native outbound peer is durably denied".into());
        }
        (
            owner.config.endpoint(
                owner.config.peer(peer)?,
                &request.scope,
                request.body.name(),
            ),
            owner.config.client()?,
            owner.config.limits.max_frame_bytes,
        )
    };
    budget
        .lock()
        .map_err(|_| "native resource lock poisoned")?
        .rpc(policy, 6 * frame as u64)?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining < Duration::from_millis(400) {
        return Err("cancelled:absolute-rpc-deadline".into());
    }
    endpoint.limits.timeout = (remaining / 8)
        .min(endpoint.limits.timeout)
        .max(Duration::from_millis(1));
    let mut client =
        SecureClient::connect_with_metering(&endpoint, &client_config, traffic.clone(), frame)?;
    let cancellation = client.cancellation_handle()?;
    let watch_cancel = Arc::clone(cancelled);
    let (stop, watch) = mpsc::sync_channel(1);
    let watchdog = std::thread::spawn(move || loop {
        if watch_cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
            let _ = cancellation.cancel();
            break;
        }
        if watch.recv_timeout(Duration::from_millis(5)).is_ok() {
            break;
        }
    });
    let result = client.call(
        request.body.name(),
        &serde_json::to_value(request).map_err(|_| "cannot encode native RPC")?,
    );
    let revoked = if result.is_ok() {
        client.revoke()
    } else {
        Ok(())
    };
    let _ = stop.try_send(());
    watchdog
        .join()
        .map_err(|_| "native cancellation worker panicked")?;
    let value = result?;
    revoked?;
    if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
        return Err("cancelled:after-rpc".into());
    }
    Ok(value)
}
fn family_terms(record: &KnowledgeRecord) -> Result<symbiosis::ExchangeTerms, String> {
    match record.typed_payload()? {
        KnowledgePayload::Affine { width, .. } => affine_full_fixture_transfer(width),
        KnowledgePayload::GraphMap(map) => {
            let nodes = u64::try_from(map.schema.nodes).map_err(|_| "graph node count overflow")?;
            let edges =
                u64::try_from(map.schema.edges.len()).map_err(|_| "graph edge count overflow")?;
            graph_fixture_transfer(nodes, edges)
        }
    }
}

fn prior_negative_exchanges(
    events: &[OperationalEvent],
    peer: &str,
    scope: &str,
) -> Result<u64, String> {
    let count = events
        .iter()
        .filter(|event| {
            matches!(event, OperationalEvent::PartnerOutcomeRecorded { outcome }
                if outcome.peer_id == peer
                    && outcome.scope == scope
                    && matches!(outcome.kind, PartnerOutcomeKind::Failed | PartnerOutcomeKind::Rejected))
        })
        .count();
    Ok(u64::try_from(count).unwrap_or(u64::MAX))
}

fn plan_value(exchange_plan: &ExchangePlan) -> Result<Value, String> {
    Ok(json!({
        "schema": exchange_plan.schema,
        "decision": exchange_plan.decision,
        "local_utility": utility_value(exchange_plan.local_utility)?,
        "remote_utility": utility_value(exchange_plan.remote_utility)?,
        "local_gain_qualified": exchange_plan.local_gain_qualified,
        "remote_gain_qualified": exchange_plan.remote_gain_qualified,
        "bilateral_authorization": exchange_plan.bilateral_authorization,
        "exchanges_knowledge": exchange_plan.exchanges_knowledge,
        "opens_connection": exchange_plan.opens_connection
    }))
}

fn reconciliation_value(reconciliation: &ValueReconciliation) -> Result<Value, String> {
    Ok(json!({
        "schema": reconciliation.schema,
        "predicted_decision": reconciliation.predicted_decision,
        "predicted_local_utility": utility_value(reconciliation.predicted_local_utility)?,
        "payload_sent": reconciliation.payload_sent,
        "measured_local_net": utility_value(reconciliation.measured_local_net)?,
        "action_matched": reconciliation.action_matched,
        "benefit_verified": reconciliation.benefit_verified,
        "utility_matched": reconciliation.utility_matched
    }))
}

fn utility_value(value: Option<i128>) -> Result<Value, String> {
    match value {
        None => Ok(Value::Null),
        Some(value) => i64::try_from(value)
            .map(|value| json!(value))
            .map_err(|_| "value-of-symbiosis utility does not fit the receipt integer".into()),
    }
}

fn model_quote(record: &KnowledgeRecord) -> Result<usize, String> {
    match record.typed_payload()? {
        KnowledgePayload::Affine { width, .. } => Ok((1_usize << width) * 16),
        KnowledgePayload::GraphMap(map) => {
            Ok(map.schema.nodes * (map.schema.nodes - 1) * 8192 + map.observations.len() * 8)
        }
    }
}
fn delta(before: &SecureTrafficSnapshot, after: &SecureTrafficSnapshot) -> (u64, u64) {
    (
        after.rpc_sent_bytes + after.negotiation_sent_bytes
            - before.rpc_sent_bytes
            - before.negotiation_sent_bytes,
        after.rpc_received_bytes + after.negotiation_received_bytes
            - before.rpc_received_bytes
            - before.negotiation_received_bytes,
    )
}
struct Cycle<'a> {
    state: &'a Arc<Mutex<State>>,
    budget: &'a Arc<Mutex<Budget>>,
    policy: &'a RunPolicy,
    traffic: &'a SecureTraffic,
    cancelled: &'a Arc<AtomicBool>,
    deadline: Instant,
    recorder: &'a mut Recorder,
}
impl Cycle<'_> {
    fn call(&self, peer: &str, request: &Request) -> Result<Value, String> {
        rpc(self, peer, request)
    }
    fn intent(
        &self,
        phase: &str,
        peer: &str,
        scope: &str,
        request: Option<Request>,
        origin: Option<String>,
    ) -> Result<PartnerDecisionRecord, String> {
        let mut owner = self
            .state
            .lock()
            .map_err(|_| "native owner lock poisoned")?;
        let decision = decision_record(
            &owner.config,
            self.policy,
            owner.journal.events(),
            Intent {
                phase,
                peer,
                scope,
                request,
                origin,
            },
            owner.knowledge.history_anchor(),
        )?;
        append(
            &mut owner,
            OperationalEvent::PartnerDecisionRecorded {
                decision: decision.clone(),
            },
        )?;
        Ok(decision)
    }
    fn telemetry(
        &self,
        decision: &PartnerDecisionRecord,
        kind: PartnerOutcomeKind,
        receipt: Option<String>,
        units: u64,
    ) -> Result<(), String> {
        let mut owner = self
            .state
            .lock()
            .map_err(|_| "native owner lock poisoned")?;
        append(
            &mut owner,
            OperationalEvent::PartnerOutcomeRecorded {
                outcome: PartnerOutcomeRecord {
                    interaction_id: decision.decision_id.clone(),
                    peer_id: decision
                        .selected_peer
                        .clone()
                        .ok_or("native telemetry peer missing")?,
                    scope: decision.context.clone(),
                    kind,
                    receipt_sha256: receipt,
                    resource_units: units,
                },
            },
        )
    }
    fn sense(&mut self, profile: &Profile) -> Result<Vec<Offer>, String> {
        let decision = self.intent("sense", &profile.peer, &profile.scope, None, None)?;
        self.recorder.emit("SENSE",json!({"decision":decision.decision_id,"peer":profile.peer,"scope":profile.scope,"profile":profile}))?;
        self.recorder.emit("MODEL",json!({"decision":decision.decision_id,"selection_basis":"preceding durable own outcomes and bounded exploration","profiles":decision.details["profiles"]}))?;
        self.recorder.emit("CONNECT",json!({"peer":profile.peer,"scope":profile.scope,"authorization":"explicit operator registry and current durable denials"}))?;
        let before = self.traffic.snapshot();
        let result = (|| -> Result<Vec<Offer>, String> {
            let capabilities = self.call(
                &profile.peer,
                &request(
                    &profile.scope,
                    format!("{}-cap", decision.decision_id),
                    Operation::Capabilities,
                ),
            )?;
            let fingerprint = {
                self.state
                    .lock()
                    .map_err(|_| "native owner lock poisoned")?
                    .config
                    .context(&profile.scope)?
                    .schema_fingerprint
                    .clone()
            };
            if capabilities["identity"] != profile.peer
                || capabilities["context"] != profile.scope
                || capabilities["schema_fingerprint"] != fingerprint
            {
                return Err("native sensor received incompatible capabilities".into());
            }
            let inventory = self.call(
                &profile.peer,
                &request(
                    &profile.scope,
                    format!("{}-list", decision.decision_id),
                    Operation::List { after: None },
                ),
            )?;
            let metadata = inventory["artifacts"]
                .as_array()
                .ok_or("native inventory schema rejected")?;
            if metadata.len() > 32 {
                return Err("native inventory count budget exceeded".into());
            }
            let mut offers = Vec::new();
            for metadata in metadata.iter().take(self.policy.max_candidates_per_episode) {
                let artifact = metadata["id"]
                    .as_str()
                    .ok_or("native inventory artifact ID missing")?;
                let value = self.call(
                    &profile.peer,
                    &request(
                        &profile.scope,
                        format!("{}-read-{}", decision.decision_id, offers.len()),
                        Operation::Read {
                            artifact: artifact.into(),
                        },
                    ),
                )?;
                let record: KnowledgeRecord = serde_json::from_value(value["record"].clone())
                    .map_err(|_| "native sensor received unsupported inert artifact")?;
                record.validate()?;
                if record.scope != profile.scope
                    || record.schema_fingerprint != fingerprint
                    || record.id != artifact
                    || value["sender"] != profile.peer
                    || value["record_sha256"] != record.digest()?
                    || metadata["sha256"] != record.digest()?
                {
                    return Err("native source record context or digest binding failed".into());
                }
                offers.push(Offer {
                    record,
                    training_inputs: Vec::new(),
                });
            }
            Ok(offers)
        })();
        let after = self.traffic.snapshot();
        let (sent, received) = delta(&before, &after);
        let units = sent.div_ceil(1024) + received.div_ceil(1024);
        match &result {
            Ok(offers) => self.telemetry(
                &decision,
                if offers.is_empty() {
                    PartnerOutcomeKind::Abstained
                } else {
                    PartnerOutcomeKind::Received
                },
                offers
                    .first()
                    .map(|offer| offer.record.digest())
                    .transpose()?,
                units,
            )?,
            Err(_) => self.telemetry(&decision, PartnerOutcomeKind::Failed, None, units)?,
        }
        if let Ok(offers) = &result {
            self.recorder.emit("EXCHANGE",json!({"peer":profile.peer,"scope":profile.scope,"inert_candidates":offers.len(),"source_sha256":offers.iter().map(|offer|offer.record.digest()).collect::<Result<Vec<_>,_>>()?,"trusted":false}))?;
        }
        result
    }
    fn learn(&mut self, peer: &str, offer: Offer) -> Result<bool, String> {
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            return Err("cancelled:before-learning".into());
        }
        let scope = offer.record.scope.clone();
        let source_sha = offer.record.digest()?;
        let request = request(
            &scope,
            format!(
                "cognition-offer-{}",
                &digest(&json!({"peer":peer,"source":source_sha,"context":scope}))?[..40]
            ),
            Operation::Submit {
                offer: Box::new(offer),
            },
        );
        let candidate = candidate_id_for(peer, &request_digest(&request)?)?;
        let same_model = {
            let owner = self
                .state
                .lock()
                .map_err(|_| "native owner lock poisoned")?;
            let Operation::Submit { offer } = &request.body else {
                unreachable!()
            };
            owner.knowledge.active().iter().any(|record| {
                record.scope == scope
                    && record.schema_fingerprint == offer.record.schema_fingerprint
                    && record.payload == offer.record.payload
            })
        };
        if same_model {
            let decision = self.intent("learn", peer, &scope, Some(request), None)?;
            let mut owner = self
                .state
                .lock()
                .map_err(|_| "native owner lock poisoned")?;
            let anchor = owner.knowledge.history_anchor();
            let original_response = owner.completed(&candidate);
            append(
                &mut owner,
                OperationalEvent::PartnerInteractionCompleted {
                    interaction: PartnerInteractionRecord {
                        interaction_id: decision.decision_id.clone(),
                        decision_id: decision.decision_id,
                        peer_id: peer.into(),
                        context: scope,
                        outcome: PartnerInteractionOutcome::SkippedIrrelevant,
                        receipt_sha256: None,
                        sent_bytes: 0,
                        received_bytes: 0,
                        resource_units: 0,
                        subsequently_used: false,
                    },
                },
            )?;
            drop(owner);
            self.recorder.emit("LEARN",json!({"status":"REUSED","source_record_sha256":source_sha,"candidate":candidate,"before":anchor,"after":anchor,
                "response":original_response,"fresh_promotion_receipt":Value::Null,"basis":"exact already validated context/schema/payload; old promoted receipt does not create new learning"}))?;
            return Ok(false);
        }
        let cached = {
            self.state
                .lock()
                .map_err(|_| "native owner lock poisoned")?
                .completed(&candidate)
                .is_some()
        };
        let quote = if cached {
            0
        } else {
            let Operation::Submit { offer } = &request.body else {
                unreachable!()
            };
            model_quote(&offer.record)?
        };
        self.budget
            .lock()
            .map_err(|_| "native resource lock poisoned")?
            .model(self.policy, quote)?;
        let decision = self.intent("learn", peer, &scope, Some(request.clone()), None)?;
        self.recorder.emit("VERIFY",json!({"decision":decision.decision_id,"peer":peer,"scope":scope,"source_record_sha256":source_sha,"candidate":candidate,"reserved_model_work":quote}))?;
        let mut owner = self
            .state
            .lock()
            .map_err(|_| "native owner lock poisoned")?;
        request.validate(&owner.config)?;
        owner.authorize(peer, &request)?;
        if owner.journal.denied_peers().contains(peer) {
            return Err("native candidate sender is denied".into());
        }
        let before = owner.knowledge.history_anchor();
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            return Err("cancelled:before-quarantine".into());
        }
        let quarantine = owner.submit(peer, &request)?;
        if quarantine["candidate"] != candidate {
            return Err("native candidate differs from exact canonical binding".into());
        }
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            return Err("cancelled:before-local-evaluation".into());
        }
        let response = owner.evaluate(&candidate)?;
        let after = owner.knowledge.history_anchor();
        let (outcome, receipt, novel, label) = if before.records < after.records {
            let local_sha = response["record_sha256"]
                .as_str()
                .ok_or("fresh native promotion lacks local record SHA")?;
            let receipt = fresh_promotion(&owner.knowledge, &before, local_sha)?;
            (
                PartnerInteractionOutcome::VerifiedNovel,
                Some(receipt),
                true,
                "FRESH_PROMOTION",
            )
        } else if response["status"] == "REJECTED" {
            (
                PartnerInteractionOutcome::VerificationFailed,
                Some(digest(&response)?),
                false,
                "REJECTED",
            )
        } else {
            (
                PartnerInteractionOutcome::SkippedIrrelevant,
                None,
                false,
                "REUSED",
            )
        };
        append(
            &mut owner,
            OperationalEvent::PartnerInteractionCompleted {
                interaction: PartnerInteractionRecord {
                    interaction_id: decision.decision_id.clone(),
                    decision_id: decision.decision_id.clone(),
                    peer_id: peer.into(),
                    context: scope.clone(),
                    outcome,
                    receipt_sha256: receipt.clone(),
                    sent_bytes: 0,
                    received_bytes: 0,
                    resource_units: quote as u64,
                    subsequently_used: false,
                },
            },
        )?;
        drop(owner);
        self.recorder.emit("LEARN",json!({"status":label,"source_record_sha256":source_sha,"candidate":candidate,"before":before,"after":after,"fresh_promotion_receipt":receipt,"response":response}))?;
        Ok(novel)
    }
    fn contribute(&mut self) -> Result<usize, String> {
        if !self.policy.contribute {
            return Ok(0);
        }
        let (models, targets) = {
            let owner = self
                .state
                .lock()
                .map_err(|_| "native owner lock poisoned")?;
            (
                owner.knowledge.active(),
                profiles(owner.journal.events(), &owner.config, self.policy)?,
            )
        };
        let mut count = 0;
        for model in models {
            for target in targets
                .iter()
                .filter(|profile| profile.scope == model.scope && profile.peer != model.source)
            {
                if count >= self.policy.max_contributions_per_episode {
                    return Ok(count);
                }
                let record_sha = model.digest()?;
                let repeated = {
                    let owner = self
                        .state
                        .lock()
                        .map_err(|_| "native owner lock poisoned")?;
                    owner.journal.events().iter().any(|event|if let OperationalEvent::PartnerDecisionRecorded {decision}=event {
                        decision.details["schema"]==DETAILS&&decision.details["phase"]=="contribute"&&decision.selected_peer.as_deref()==Some(&target.peer)
                            &&decision.details["source_record_sha256"]==record_sha
                            &&owner.journal.events().iter().any(|event|matches!(event,OperationalEvent::PartnerOutcomeRecorded {outcome} if outcome.interaction_id==decision.decision_id&&outcome.kind==PartnerOutcomeKind::Received))
                    }else{false})
                };
                if repeated {
                    continue;
                }
                let (local_authorized, prior_negative) = {
                    let owner = self
                        .state
                        .lock()
                        .map_err(|_| "native owner lock poisoned")?;
                    let authorized = owner
                        .config
                        .peer(&target.peer)?
                        .access(&model.scope, "candidate.submit")
                        .is_ok()
                        && !owner.journal.denied_peers().contains(&target.peer);
                    (
                        authorized,
                        prior_negative_exchanges(
                            owner.journal.events(),
                            &target.peer,
                            &model.scope,
                        )?,
                    )
                };
                if !local_authorized {
                    let exchange_plan = plan(
                        ParticipantView {
                            terms: ExchangeTerms {
                                expected_gain: 0,
                                transfer_cost: 0,
                                verification_cost: 0,
                                regression_risk: 0,
                                gain_qualified: false,
                            },
                            evidence_complete: false,
                            prior_negative_exchanges: prior_negative,
                            authorization_present: false,
                            local_has_unshared_evidence: false,
                            remote_has_unshared_evidence: false,
                            discriminating_experiment_available: false,
                        },
                        None,
                    )?;
                    self.record_value(ValueReceipt {
                        exchange_plan: &exchange_plan,
                        peer: &target.peer,
                        scope: &model.scope,
                        record_sha: &record_sha,
                        partner_holds_scope: false,
                        schema_compatible: None,
                        reason: "local authorization absent",
                    })?;
                    continue;
                }
                let observation_id =
                    &digest(&json!({"target":target.peer,"record":record_sha}))?[..32];
                let before = self.traffic.snapshot();
                let observed = (|| -> Result<(bool, bool, bool), String> {
                    let capabilities = self.call(
                        &target.peer,
                        &request(
                            &model.scope,
                            format!("cognition-cap-{observation_id}"),
                            Operation::Capabilities,
                        ),
                    )?;
                    let schema_compatible = capabilities["identity"] == target.peer
                        && capabilities["context"] == model.scope
                        && capabilities["schema_fingerprint"] == model.schema_fingerprint;
                    let remote_authorized =
                        capabilities["operations"].as_array().is_some_and(|ops| {
                            ops.iter().any(|operation| operation == "candidate.submit")
                        });
                    let inventory = self.call(
                        &target.peer,
                        &request(
                            &model.scope,
                            format!("cognition-inventory-{observation_id}"),
                            Operation::List { after: None },
                        ),
                    )?;
                    let holds_scope = !inventory["artifacts"]
                        .as_array()
                        .ok_or("contribution inventory schema rejected")?
                        .is_empty();
                    Ok((schema_compatible, remote_authorized, holds_scope))
                })();
                let (schema_compatible, remote_authorized, partner_holds_scope) = match observed {
                    Ok(observed) => observed,
                    Err(error) => {
                        let exchange_plan = plan(
                            ParticipantView {
                                terms: ExchangeTerms {
                                    expected_gain: 0,
                                    transfer_cost: 0,
                                    verification_cost: 0,
                                    regression_risk: 0,
                                    gain_qualified: false,
                                },
                                evidence_complete: false,
                                prior_negative_exchanges: prior_negative,
                                authorization_present: true,
                                local_has_unshared_evidence: false,
                                remote_has_unshared_evidence: false,
                                discriminating_experiment_available: false,
                            },
                            None,
                        )?;
                        self.record_value(ValueReceipt {
                            exchange_plan: &exchange_plan,
                            peer: &target.peer,
                            scope: &model.scope,
                            record_sha: &record_sha,
                            partner_holds_scope: false,
                            schema_compatible: None,
                            reason: &error,
                        })?;
                        if error.starts_with("budget:") || error.starts_with("cancelled:") {
                            return Err(error);
                        }
                        continue;
                    }
                };
                let family_terms = family_terms(&model)?;
                let (local, remote) = outbound_views(OutboundEvidence {
                    schema_compatible,
                    partner_holds_scope,
                    local_authorized: true,
                    remote_authorized,
                    prior_negative_exchanges: prior_negative,
                    family_terms,
                });
                let exchange_plan = plan(local, remote)?;
                if !exchange_plan.exchanges_knowledge {
                    self.record_value(ValueReceipt {
                        exchange_plan: &exchange_plan,
                        peer: &target.peer,
                        scope: &model.scope,
                        record_sha: &record_sha,
                        partner_holds_scope,
                        schema_compatible: Some(schema_compatible),
                        reason: "pre-exchange value declined a payload",
                    })?;
                    continue;
                }
                let offer = Offer {
                    record: model.clone(),
                    training_inputs: Vec::new(),
                };
                let submit = request(
                    &model.scope,
                    format!("cognition-contribute-{observation_id}"),
                    Operation::Submit {
                        offer: Box::new(offer),
                    },
                );
                let decision = self.intent(
                    "contribute",
                    &target.peer,
                    &model.scope,
                    Some(submit.clone()),
                    Some(model.source.clone()),
                )?;
                let result = self.call(&target.peer, &submit);
                let (sent, received) = delta(&before, &self.traffic.snapshot());
                match result {
                    Ok(response) => {
                        let quarantined =
                            response["status"] == "QUARANTINED" && response["promoted"] == false;
                        self.telemetry(
                            &decision,
                            if quarantined {
                                PartnerOutcomeKind::Received
                            } else {
                                PartnerOutcomeKind::Abstained
                            },
                            Some(digest(&response)?),
                            sent.div_ceil(1024) + received.div_ceil(1024),
                        )?;
                        let reconciliation = reconcile(&exchange_plan, true, None);
                        self.recorder.emit(
                            "CONTRIBUTE",
                            json!({
                                "peer": target.peer,
                                "scope": model.scope,
                                "origin_peer": model.source,
                                "source_record_sha256": record_sha,
                                "quarantined_offer": quarantined,
                                "partner_benefit_verified": false,
                                "value": plan_value(&exchange_plan)?,
                                "reconciliation": reconciliation_value(&reconciliation)?,
                                "response": response
                            }),
                        )?;
                        count += usize::from(quarantined);
                    }
                    Err(error) => {
                        self.telemetry(
                            &decision,
                            PartnerOutcomeKind::Failed,
                            None,
                            sent.div_ceil(1024) + received.div_ceil(1024),
                        )?;
                        let reconciliation = reconcile(&exchange_plan, true, None);
                        self.recorder.emit(
                            "CONTRIBUTE",
                            json!({
                                "peer": target.peer,
                                "status": "FAILED",
                                "error": error,
                                "partner_benefit_verified": false,
                                "value": plan_value(&exchange_plan)?,
                                "reconciliation": reconciliation_value(&reconciliation)?
                            }),
                        )?;
                        if error.starts_with("budget:") || error.starts_with("cancelled:") {
                            return Err(error);
                        }
                    }
                }
            }
        }
        Ok(count)
    }

    fn record_value(&mut self, receipt: ValueReceipt<'_>) -> Result<(), String> {
        let reconciliation = reconcile(receipt.exchange_plan, false, None);
        self.recorder.emit(
            "VALUE",
            json!({
                "peer": receipt.peer,
                "scope": receipt.scope,
                "source_record_sha256": receipt.record_sha,
                "partner_holds_scope": receipt.partner_holds_scope,
                "schema_compatible": receipt.schema_compatible,
                "reason": receipt.reason,
                "value": plan_value(receipt.exchange_plan)?,
                "reconciliation": reconciliation_value(&reconciliation)?,
                "partner_benefit_verified": false
            }),
        )
    }
}

struct ValueReceipt<'a> {
    exchange_plan: &'a ExchangePlan,
    peer: &'a str,
    scope: &'a str,
    record_sha: &'a str,
    partner_holds_scope: bool,
    schema_compatible: Option<bool>,
    reason: &'a str,
}
fn owner_control(cancelled: Arc<AtomicBool>) -> mpsc::Receiver<String> {
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut reader = BufReader::new(std::io::stdin().lock());
        let mut bytes = Vec::new();
        let reason = loop {
            match reader.fill_buf() {
                Ok(chunk) => {
                    if chunk.is_empty() {
                        break "owner-eof";
                    }
                    let count = chunk
                        .iter()
                        .position(|byte| *byte == b'\n')
                        .map_or(chunk.len(), |i| i + 1);
                    if bytes.len() + count > 256 {
                        break "owner-control-budget";
                    }
                    bytes.extend_from_slice(&chunk[..count]);
                    let complete = chunk[count - 1] == b'\n';
                    reader.consume(count);
                    if complete {
                        break if serde_json::from_slice::<Value>(&bytes).ok()
                            == Some(json!({"command":"shutdown"}))
                        {
                            "owner-shutdown"
                        } else {
                            "owner-control-rejected"
                        };
                    }
                }
                Err(_) => break "owner-control-failed",
            }
        };
        cancelled.store(true, Ordering::Release);
        let _ = send.try_send(reason.into());
    });
    receive
}
pub fn run(config_path: &Path, policy_path: &Path, receipts: &Path) -> Result<Value, String> {
    let cancel = Arc::new(AtomicBool::new(false));
    let control = owner_control(Arc::clone(&cancel));
    run_controlled(config_path, policy_path, receipts, cancel, Some(control))
}
/// Embedded operation uses explicit cancellation and never reads global stdin.
#[allow(dead_code)]
pub fn run_with_cancel(
    config_path: &Path,
    policy_path: &Path,
    receipts: &Path,
    cancelled: Arc<AtomicBool>,
) -> Result<Value, String> {
    run_controlled(config_path, policy_path, receipts, cancelled, None)
}
fn run_controlled(
    config_path: &Path,
    policy_path: &Path,
    receipts: &Path,
    cancelled: Arc<AtomicBool>,
    controls: Option<mpsc::Receiver<String>>,
) -> Result<Value, String> {
    match fs::symlink_metadata(receipts) {
        Ok(_) => return Err(
            "native run requires a fresh receipts directory; prior evidence is never overwritten"
                .into(),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(
                "cannot safely inspect native receipts destination before opening owner state"
                    .into(),
            )
        }
    }
    let config = Config::load(config_path)?;
    let policy_bytes = config::read_bounded(policy_path, 16_384)?;
    let policy: RunPolicy =
        serde_json::from_slice(&policy_bytes).map_err(|_| "native run policy schema rejected")?;
    policy.validate(&config)?;
    let deadline = Instant::now() + Duration::from_millis(policy.max_duration_ms);
    let owner = State::open_for_cognition(config)?;
    if Instant::now() >= deadline {
        return Err("HOLD: native owner validation exceeded the run deadline; pending work was not recovered".into());
    }
    fs::create_dir_all(receipts).map_err(|_| "cannot create native run receipts")?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(receipts.join("events.jsonl"))
        .map_err(|_| "cannot create native events receipt")?;
    let mut recorder = Recorder { file, sequence: 0 };
    let identity = owner.config.identity.clone();
    let initial = owner.knowledge.history_anchor();
    let listener_quote = 2
        * owner.config.limits.max_frame_bytes as u64
        * (owner.config.limits.max_connections + owner.config.limits.max_requests);
    if listener_quote > policy.max_plaintext_bytes {
        return Err("native plaintext budget cannot reserve the configured listener's bounded negotiation/RPC ceiling; listener was not opened".into());
    }
    let budget = Arc::new(Mutex::new(Budget {
        listener_plaintext_reserved: listener_quote,
        ..Budget::default()
    }));
    let denied = owner.journal.denied_peers();
    let server_config = if !cancelled.load(Ordering::Acquire)
        && owner
            .config
            .peers
            .iter()
            .any(|peer| !denied.contains(&peer.id))
    {
        Some(owner.config.server(&denied)?)
    } else {
        None
    };
    let state = Arc::new(Mutex::new(owner));
    let handler_state = Arc::clone(&state);
    let handler_budget = Arc::clone(&budget);
    let handler_policy = policy.clone();
    let handler_cancel = Arc::clone(&cancelled);
    let mut server = server_config
        .map(|config| {
            spawn_secure_server(config, move |session, operation, payload| {
                if handler_cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
                    return Err("native episode lifetime exhausted".into());
                }
                {
                    let mut budget = handler_budget
                        .lock()
                        .map_err(|_| "native resource lock poisoned")?;
                    budget.rpc(&handler_policy, 0)?;
                    if operation == "knowledge.predict" {
                        budget.model(&handler_policy, 1024)?;
                    }
                }
                handler_state
                    .lock()
                    .map_err(|_| "native owner lock poisoned")?
                    .handle(session, operation, payload)
            })
        })
        .transpose()?;
    recorder.emit("READY",json!({"identity":identity,"pid":std::process::id(),"address":server.as_ref().map(|server|server.address()),"listener_opened":server.is_some(),
        "service_policy_sha256":policy.service_policy_sha256,"run_policy_sha256":digest(&policy)?,"protocol":"symbiote/2","language_model_required":false}))?;
    let traffic = SecureTraffic::default();
    let mut episodes = 0;
    let mut novel = 0;
    let mut contributions = 0;
    let mut reason = "episode-budget".to_string();
    let result = (|| -> Result<(), String> {
        while episodes < policy.max_episodes {
            if cancelled.load(Ordering::Acquire) {
                reason = controls
                    .as_ref()
                    .and_then(|control| control.try_recv().ok())
                    .unwrap_or_else(|| "cancelled".into());
                break;
            }
            if Instant::now() >= deadline {
                reason = "duration-budget".into();
                break;
            }
            if config::read_bounded(policy_path, 16_384)? != policy_bytes {
                return Err("HOLD: immutable native run policy changed during execution".into());
            }
            let next = {
                let owner = state.lock().map_err(|_| "native owner lock poisoned")?;
                profiles(owner.journal.events(), &owner.config, &policy)?
                    .first()
                    .cloned()
            };
            let Some(profile) = next else {
                reason = "no-eligible-authorized-partners".into();
                break;
            };
            episodes += 1;
            let mut cycle = Cycle {
                state: &state,
                budget: &budget,
                policy: &policy,
                traffic: &traffic,
                cancelled: &cancelled,
                deadline,
                recorder: &mut recorder,
            };
            match cycle.sense(&profile) {
                Ok(offers) => {
                    for offer in offers {
                        novel += usize::from(cycle.learn(&profile.peer, offer)?);
                    }
                }
                Err(error) => {
                    cycle.recorder.emit("REASSESS",json!({"peer":profile.peer,"scope":profile.scope,"status":"OBSERVATION_FAILED","error":error}))?;
                    if error.starts_with("budget:") || error.starts_with("cancelled:") {
                        reason = error;
                        break;
                    }
                }
            }
            contributions += cycle.contribute()?;
            // VALUE events already recorded the pre-exchange decision. This row
            // only states that delivery and promotion are not benefit.
            cycle.recorder.emit("MEASURE", json!({
                "schema": "symbiote.reciprocal-measure/1",
                "partner_benefit_verified": false,
                "quarantine_is_benefit": false,
                "promotion_is_benefit": false,
                "reason": "VALUE events are the pre-exchange decisions; quarantine and promotion are not benefit"
            }))?;
            cycle.recorder.emit("REASSESS",json!({"episode":episodes,"fresh_promotions":novel,"quarantined_contributions":contributions,"budget":budget.lock().map_err(|_|"native resource lock poisoned")?.clone()}))?;
            let until = (Instant::now() + Duration::from_millis(policy.interval_ms)).min(deadline);
            while Instant::now() < until && !cancelled.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        Ok(())
    })();
    cancelled.store(true, Ordering::Release);
    if let Some(server) = server.as_mut() {
        server.shutdown()?;
    }
    if let Err(error) = result {
        if error.starts_with("budget:") || error.starts_with("cancelled:") {
            reason = error;
        } else {
            recorder.emit("HOLD", json!({"error":error}))?;
            return Err(error);
        }
    }
    let owner = state.lock().map_err(|_| "native owner lock poisoned")?;
    let summary = json!({"schema":"symbiote.cognition-summary/1","status":"STOPPED","identity":identity,"reason":reason,"episodes":episodes,
        "initial_knowledge_anchor":initial,"final_knowledge_anchor":owner.knowledge.history_anchor(),"active_models":owner.knowledge.active().len(),
        "fresh_promotions":novel,"quarantined_contributions":contributions,"partner_benefits_verified":0,
        "profiles":profiles(owner.journal.events(),&owner.config,&policy)?,"budget":budget.lock().map_err(|_|"native resource lock poisoned")?.clone(),
        "outbound_plaintext_traffic":traffic.snapshot(),"inbound_plaintext_traffic":server.as_ref().map(|server|server.traffic().snapshot()),
        "protocol":"symbiote/2","oracle_assumption":"operator-pinned local finite fixtures; no remote honesty or generalization claim",
        "bandwidth_basis":"JSON negotiation/RPC application plaintext; cryptographic handshake and TLS wire framing excluded",
        "learning_basis":"fresh actual local model promotions, never peer PASS receipts; duplicate promoted receipts are reused"});
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(receipts.join("summary.json"))
        .map_err(|_| "cannot create native summary")?;
    file.write_all(
        &serde_json::to_vec_pretty(&summary).map_err(|_| "cannot encode native summary")?,
    )
    .and_then(|_| file.sync_all())
    .map_err(|_| "cannot persist native summary")?;
    Ok(summary)
}

#[cfg(test)]
mod replay_tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use symbiote_memory::knowledge::{affine_schema_fingerprint, graph::graph_schema_fingerprint};
    use symbiote_reasoning::planning::{Edge, GraphSchema};
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    struct Fixture {
        path: std::path::PathBuf,
        config: std::path::PathBuf,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "symbiote-cognitive-replay-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            let id = {
                let owner = Store::open(&path.join("state")).unwrap();
                owner.identity().to_string()
            };
            let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            let ca_key = KeyPair::generate().unwrap();
            let ca = ca_params.self_signed(&ca_key).unwrap();
            let issuer = rcgen::Issuer::from_params(&ca_params, ca_key);
            fs::write(path.join("ca.pem"), ca.pem()).unwrap();
            let mut pins = Vec::new();
            for name in ["owner", "source-a", "recipient-b"] {
                let mut params = CertificateParams::new(vec![format!("{name}.test")]).unwrap();
                params.extended_key_usages = vec![
                    ExtendedKeyUsagePurpose::ServerAuth,
                    ExtendedKeyUsagePurpose::ClientAuth,
                ];
                params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
                let key = KeyPair::generate().unwrap();
                let cert = params.signed_by(&key, &issuer).unwrap();
                pins.push(
                    symbiote_protocol::TlsIdentity::from_pem(
                        cert.pem().as_bytes(),
                        key.serialize_pem().as_bytes(),
                    )
                    .unwrap()
                    .certificate_sha256()
                    .to_string(),
                );
                fs::write(path.join(format!("{name}.pem")), cert.pem()).unwrap();
                fs::write(path.join(format!("{name}.key")), key.serialize_pem()).unwrap();
            }
            let graph = graph();
            let truth = json!({"schema":"symbiote.local-truth/1","scope":"affine-unit/v1","family":{"kind":"affine","width":2,"outputs":[0,1,0,1]}});
            let graph_truth = json!({"schema":"symbiote.local-truth/1","scope":"graph-unit/v1","family":{"kind":"graph","schema":graph,"costs":[1,2,5]}});
            let mut contexts = Vec::new();
            for (name, scope, fingerprint, truth) in [
                (
                    "affine",
                    "affine-unit/v1",
                    affine_schema_fingerprint(2).unwrap(),
                    truth,
                ),
                (
                    "graph",
                    "graph-unit/v1",
                    graph_schema_fingerprint(&graph).unwrap(),
                    graph_truth,
                ),
            ] {
                let bytes = serde_json::to_vec(&truth).unwrap();
                fs::write(path.join(format!("{name}.json")), &bytes).unwrap();
                contexts.push(json!({"scope":scope,"schema_fingerprint":fingerprint,"truth_fixture":format!("{name}.json"),"truth_sha256":config::hash_bytes(&bytes)}));
            }
            let manifest = json!({"schema":"symbiote.service-config/1","state":"state","identity":id,"certificate":"owner.pem","private_key":"owner.key","certificate_sha256":pins[0],
                "ca_certificate":"ca.pem","bind_address":"127.0.0.1:0","peers":([("source-a",1),("recipient-b",2)].into_iter().map(|(peer,index)|json!({"alias":peer,"id":peer,"address":format!("127.0.0.1:{}",41000+index),
                    "server_name":format!("{peer}.test"),"certificate_sha256":pins[index],"access":contexts.iter().map(|context|json!({"scope":context["scope"],"operations":OPERATIONS,"artifacts":["*"]})).collect::<Vec<_>>()})).collect::<Vec<_>>()),
                "contexts":contexts,"limits":{"max_requests":32,"max_connections":16,"max_frame_bytes":32768,"timeout_ms":100,"lifetime_ms":15000,"per_peer_requests":32,"max_offers":16,"max_offer_bytes":16384,"model_work":200000}});
            let config = path.join("config.json");
            fs::write(&config, serde_json::to_vec(&manifest).unwrap()).unwrap();
            Self { path, config }
        }
        fn state(&self) -> State {
            State::open_for_cognition(Config::load(&self.config).unwrap()).unwrap()
        }
    }
    fn graph() -> GraphSchema {
        GraphSchema {
            nodes: 3,
            edges: [(0, 1), (1, 2), (0, 2)]
                .into_iter()
                .map(|(from, to)| Edge {
                    from,
                    to,
                    lower: 1,
                    upper: 9,
                })
                .collect(),
        }
    }
    fn policy(state: &State) -> RunPolicy {
        RunPolicy {
            schema: "symbiote.cognition-policy/1".into(),
            expected_identity: state.config.identity.clone(),
            service_policy_sha256: state.config.policy_digest.clone(),
            max_episodes: 4,
            max_duration_ms: 1000,
            interval_ms: 0,
            max_rpc_attempts: 16,
            max_model_work: 200000,
            max_plaintext_bytes: 64 * 1024 * 1024,
            max_candidates_per_episode: 1,
            max_contributions_per_episode: 1,
            peers: vec!["source-a".into(), "recipient-b".into()],
            scopes: vec!["affine-unit/v1".into(), "graph-unit/v1".into()],
            contribute: true,
        }
    }
    fn offer() -> Offer {
        Offer {
            record: KnowledgeRecord {
                id: "source-model".into(),
                revision: 1,
                source: "untrusted-original".into(),
                scope: "affine-unit/v1".into(),
                schema_fingerprint: affine_schema_fingerprint(2).unwrap(),
                payload: json!({"kind":"affine","width":2,"coefficients":1,"bias":false}),
                provenance: "inert unit model".into(),
            },
            training_inputs: Vec::new(),
        }
    }
    fn learned(state: &mut State) -> (PartnerDecisionRecord, PartnerInteractionRecord, Request) {
        let request = request(
            "affine-unit/v1",
            "unit-offer".into(),
            Operation::Submit {
                offer: Box::new(offer()),
            },
        );
        let before = state.knowledge.history_anchor();
        let decision = decision_record(
            &state.config,
            &policy(state),
            state.journal.events(),
            Intent {
                phase: "learn",
                peer: "source-a",
                scope: "affine-unit/v1",
                request: Some(request.clone()),
                origin: None,
            },
            before.clone(),
        )
        .unwrap();
        append(
            state,
            OperationalEvent::PartnerDecisionRecorded {
                decision: decision.clone(),
            },
        )
        .unwrap();
        let quarantine = state.submit("source-a", &request).unwrap();
        let response = state
            .evaluate(quarantine["candidate"].as_str().unwrap())
            .unwrap();
        let receipt = fresh_promotion(
            &state.knowledge,
            &before,
            response["record_sha256"].as_str().unwrap(),
        )
        .unwrap();
        let interaction = PartnerInteractionRecord {
            interaction_id: decision.decision_id.clone(),
            decision_id: decision.decision_id.clone(),
            peer_id: "source-a".into(),
            context: "affine-unit/v1".into(),
            outcome: PartnerInteractionOutcome::VerifiedNovel,
            receipt_sha256: Some(receipt),
            sent_bytes: 0,
            received_bytes: 0,
            resource_units: 1,
            subsequently_used: false,
        };
        (decision, interaction, request)
    }
    #[test]
    fn old_completion_old_anchor_and_duplicate_promotion_credit_are_rejected() {
        let fixture = Fixture::new();
        let mut state = fixture.state();
        let old = state.knowledge.history_anchor();
        let (_, original, request) = learned(&mut state);
        let stale = decision_record(
            &state.config,
            &policy(&state),
            state.journal.events(),
            Intent {
                phase: "learn",
                peer: "source-a",
                scope: "affine-unit/v1",
                request: Some(request.clone()),
                origin: None,
            },
            old,
        )
        .unwrap();
        assert!(validate_profile_event(
            &state.config,
            &OperationalEvent::PartnerDecisionRecorded { decision: stale },
            state.journal.events(),
            &state.knowledge
        )
        .unwrap_err()
        .contains("predates"));
        let next = decision_record(
            &state.config,
            &policy(&state),
            state.journal.events(),
            Intent {
                phase: "learn",
                peer: "source-a",
                scope: "affine-unit/v1",
                request: Some(request),
                origin: None,
            },
            state.knowledge.history_anchor(),
        )
        .unwrap();
        append(
            &mut state,
            OperationalEvent::PartnerDecisionRecorded {
                decision: next.clone(),
            },
        )
        .unwrap();
        let mut recycled = original.clone();
        recycled.interaction_id = next.decision_id.clone();
        recycled.decision_id = next.decision_id;
        assert!(validate_profile_event(
            &state.config,
            &OperationalEvent::PartnerInteractionCompleted {
                interaction: recycled.clone()
            },
            state.journal.events(),
            &state.knowledge
        )
        .unwrap_err()
        .contains("after its own decision"));
        append(
            &mut state,
            OperationalEvent::PartnerInteractionCompleted {
                interaction: original,
            },
        )
        .unwrap();
        assert!(validate_profile_event(
            &state.config,
            &OperationalEvent::PartnerInteractionCompleted {
                interaction: recycled
            },
            state.journal.events(),
            &state.knowledge
        )
        .unwrap_err()
        .contains("already credited"));
    }
    fn contribution(
        state: &State,
        record: KnowledgeRecord,
        origin: &str,
        before: KnowledgeAnchor,
    ) -> PartnerDecisionRecord {
        let request = request(
            "affine-unit/v1",
            "unit-contribution".into(),
            Operation::Submit {
                offer: Box::new(Offer {
                    record,
                    training_inputs: Vec::new(),
                }),
            },
        );
        decision_record(
            &state.config,
            &policy(state),
            state.journal.events(),
            Intent {
                phase: "contribute",
                peer: "recipient-b",
                scope: "affine-unit/v1",
                request: Some(request),
                origin: Some(origin.into()),
            },
            before,
        )
        .unwrap()
    }
    #[test]
    fn contribution_requires_exact_active_prefix_model_and_actual_origin() {
        let fixture = Fixture::new();
        let mut state = fixture.state();
        let _ = learned(&mut state);
        let record = state.knowledge.active()[0].clone();
        let before = state.knowledge.history_anchor();
        let valid = contribution(&state, record.clone(), "source-a", before.clone());
        let wrong_origin = contribution(&state, record.clone(), "other-source", before.clone());
        assert!(validate_profile_event(
            &state.config,
            &OperationalEvent::PartnerDecisionRecorded {
                decision: wrong_origin
            },
            state.journal.events(),
            &state.knowledge
        )
        .is_err());
        let mut fake = record.clone();
        fake.id = "never-promoted".into();
        let unretained = contribution(&state, fake, "source-a", before.clone());
        assert!(validate_profile_event(
            &state.config,
            &OperationalEvent::PartnerDecisionRecorded {
                decision: unretained
            },
            state.journal.events(),
            &state.knowledge
        )
        .is_err());
        let prior = state.journal.events().to_vec();
        state
            .knowledge
            .revoke(&record.id, "unit revocation")
            .unwrap();
        assert!(
            validate_profile_event(
                &state.config,
                &OperationalEvent::PartnerDecisionRecorded { decision: valid },
                &prior,
                &state.knowledge
            )
            .is_ok(),
            "later revocation must preserve a historically valid contribution"
        );
        let revoked = contribution(
            &state,
            record.clone(),
            "source-a",
            state.knowledge.history_anchor(),
        );
        assert!(validate_profile_event(
            &state.config,
            &OperationalEvent::PartnerDecisionRecorded { decision: revoked },
            state.journal.events(),
            &state.knowledge
        )
        .is_err());
        let mut incoming = offer();
        incoming.record.revision = 2;
        let req = request(
            "affine-unit/v1",
            "unit-new-revision".into(),
            Operation::Submit {
                offer: Box::new(incoming),
            },
        );
        let candidate = state.submit("source-a", &req).unwrap();
        assert_eq!(
            state
                .evaluate(candidate["candidate"].as_str().unwrap())
                .unwrap()["status"],
            "PROMOTED"
        );
        let superseded = contribution(&state, record, "source-a", state.knowledge.history_anchor());
        assert!(validate_profile_event(
            &state.config,
            &OperationalEvent::PartnerDecisionRecorded {
                decision: superseded
            },
            state.journal.events(),
            &state.knowledge
        )
        .is_err());
    }
    #[test]
    fn pending_graph_evaluation_is_not_recovered_by_small_budget_or_precancelled_run() {
        let fixture = Fixture::new();
        let mut state = fixture.state();
        let map = graph();
        let offer = Offer {
            record: KnowledgeRecord {
                id: "pending-graph".into(),
                revision: 1,
                source: "source-a".into(),
                scope: "graph-unit/v1".into(),
                schema_fingerprint: graph_schema_fingerprint(&map).unwrap(),
                payload: json!({"kind":"graph-map","schema":map,"observations":[{"edge_id":0,"cost":1},{"edge_id":1,"cost":2},{"edge_id":2,"cost":5}]}),
                provenance: "inert pending graph".into(),
            },
            training_inputs: Vec::new(),
        };
        let request = request(
            "graph-unit/v1",
            "pending-unit-graph".into(),
            Operation::Submit {
                offer: Box::new(offer.clone()),
            },
        );
        let response = state.submit("source-a", &request).unwrap();
        let prepared =
            super::super::evaluation::prepare(&state.config, &state.knowledge, "source-a", &offer)
                .unwrap();
        state
            .journal
            .append(OperationalEvent::EvaluationPrepared {
                candidate_id: response["candidate"].as_str().unwrap().into(),
                record: prepared.record.clone(),
                fixture_sha256: prepared.fixture_sha256.clone(),
                response: prepared.response().unwrap(),
            })
            .unwrap();
        let bytes = fs::read(state.knowledge.ledger_path()).unwrap();
        let mut run_policy = policy(&state);
        run_policy.max_model_work = 1024;
        let policy_path = fixture.path.join("run.json");
        fs::write(&policy_path, serde_json::to_vec(&run_policy).unwrap()).unwrap();
        drop(state);
        for cancelled in [false, true] {
            let error = run_with_cancel(
                &fixture.config,
                &policy_path,
                &fixture.path.join(format!("receipts-{cancelled}")),
                Arc::new(AtomicBool::new(cancelled)),
            )
            .unwrap_err();
            assert!(error.contains("pending local evaluation"));
            assert_eq!(
                fs::read(fixture.path.join("state/knowledge.jsonl")).unwrap(),
                bytes
            );
        }
    }
}
