//! Configured, finite native knowledge service. Remote data never supplies code,
//! authority endpoints, expected labels or permission to promote local knowledge.
mod config;
mod evaluation;
mod wire;

use config::Config;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use symbiote_memory::{
    knowledge::{KnowledgeRecord, KnowledgeStore},
    operational::{IdempotencyKey, OperationalEvent, OperationalJournal},
    Store,
};
use symbiote_protocol::{spawn_secure_server, SecureClient, SecureSession};
use wire::{Offer, Operation, Request};

const OPERATIONS: &[&str] = &[
    "capabilities",
    "knowledge.list",
    "knowledge.read",
    "knowledge.predict",
    "candidate.submit",
    "candidate.status",
];

fn digest<T: Serialize>(value: &T) -> Result<String, String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).map_err(|_| "cannot canonicalize service data")?)
    ))
}
fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}
fn validate_graph_query(
    map: &symbiote_memory::knowledge::graph::GraphMap,
    input: u16,
) -> Result<(), String> {
    symbiote_memory::knowledge::graph::decode_query(map.schema.nodes, input).map(|_| ())
}

pub(crate) fn prepare(state: &Path) -> Result<Value, String> {
    if state.join("knowledge.jsonl").exists() && !state.join("ledger.jsonl").exists() {
        return Err("knowledge exists without its service identity; state was preserved".into());
    }
    let identity = Store::open(state)?;
    Ok(
        json!({"schema":"symbiote.service-preparation/1","status":"PREPARED","identity":identity.identity(),"state":state,"network_requests":0,"learning_artifacts_created":0,"certificates_created":0}),
    )
}
fn owner(config: &Config) -> Result<Arc<Store>, String> {
    if symbiote_memory::maintenance::inspect(&config.state)?
        .identity
        .as_deref()
        != Some(&config.identity)
    {
        return Err("service configuration does not match a prepared persistent identity".into());
    }
    let owner = Arc::new(Store::open(&config.state)?);
    if owner.identity() != config.identity {
        return Err("service identity changed after configuration validation".into());
    }
    Ok(owner)
}

struct State {
    config: Config,
    knowledge: KnowledgeStore,
    journal: OperationalJournal,
    requests: BTreeMap<String, u64>,
    work: usize,
}
impl State {
    fn open(config: Config) -> Result<Self, String> {
        let mut state = Self::load(config)?;
        state.recover_evaluations()?;
        Ok(state)
    }
    fn load(config: Config) -> Result<Self, String> {
        let owner = owner(&config)?;
        let registered = config
            .state
            .join("operations-owner.json")
            .try_exists()
            .map_err(|_| "cannot inspect service registration")?
            || config
                .state
                .join("operations.jsonl")
                .try_exists()
                .map_err(|_| "cannot inspect service journal")?;
        if registered
            && !config
                .state
                .join("knowledge.jsonl")
                .try_exists()
                .map_err(|_| "cannot inspect registered knowledge ledger")?
        {
            return Err("HOLD: registered service knowledge ledger is missing; state was preserved without reinitialization".into());
        }
        let knowledge = KnowledgeStore::open(&config.state, owner.identity())?;
        let journal =
            OperationalJournal::open(owner, "configured-service/v1", &config.policy_digest)?;
        let state = Self {
            config,
            knowledge,
            journal,
            requests: BTreeMap::new(),
            work: 0,
        };
        state.validate_replay()?;
        Ok(state)
    }
    fn validate_replay(&self) -> Result<(), String> {
        for event in self.journal.events() {
            match event {
                OperationalEvent::Quarantined {
                    key,
                    candidate_id,
                    body_sha256,
                    body,
                    response,
                } => {
                    let request: Request = serde_json::from_value(body.clone())
                        .map_err(|_| "quarantine replay contains an unsupported request")?;
                    request.validate(&self.config)?;
                    self.authorize(&key.peer_id, &request)?;
                    if key.operation != "candidate.submit"
                        || request.body.name() != key.operation
                        || request.scope != key.scope
                        || request.request_id != key.request_id
                        || digest(body)? != *body_sha256
                        || candidate_id != &candidate_id_for(&key.peer_id, body_sha256)?
                        || response != &quarantine_response(candidate_id)
                    {
                        return Err("quarantine attribution or receipt replay mismatch".into());
                    }
                }
                OperationalEvent::EvaluationPrepared {
                    candidate_id,
                    record,
                    fixture_sha256,
                    ..
                } => {
                    let (peer, offer) = self.offer(candidate_id)?;
                    if record.id
                        != evaluation::local_id(
                            &peer,
                            &offer.record.scope,
                            &offer.record.schema_fingerprint,
                        )?
                        || record.source != peer
                        || record.scope != offer.record.scope
                        || record.payload != offer.record.payload
                        || self.config.context(&record.scope)?.truth_sha256.as_ref()
                            != Some(fixture_sha256)
                    {
                        return Err("evaluation intent does not match its authenticated candidate and pinned fixture".into());
                    }
                }
                OperationalEvent::EvaluationCompleted {
                    candidate_id,
                    record_sha256,
                    ..
                } => {
                    let record = self
                        .journal
                        .events()
                        .iter()
                        .find_map(|event| match event {
                            OperationalEvent::EvaluationPrepared {
                                candidate_id: prepared,
                                record,
                                ..
                            } if prepared == candidate_id => Some(record),
                            _ => None,
                        })
                        .ok_or("HOLD: completed operational evaluation has no prepared record")?;
                    if record.digest()? != *record_sha256
                        || !self.knowledge.has_historical_promotion(record)?
                    {
                        return Err("HOLD: completed operational evaluation is missing its exact historical learning promotion; preserve and restore learning history".into());
                    }
                }
                OperationalEvent::PeerDenied { peer_id, .. } => {
                    self.config.peer(peer_id)?;
                }
                OperationalEvent::PartnerOutcomeRecorded { .. }
                | OperationalEvent::PartnerDecisionRecorded { .. }
                | OperationalEvent::PartnerInteractionCompleted { .. }
                | OperationalEvent::SourceWarmupRetained { .. } => {
                    return Err("adaptive-profile events are outside the configured service journal namespace".into());
                }
                _ => {}
            }
        }
        Ok(())
    }
    fn authorize(&self, peer_id: &str, request: &Request) -> Result<(), String> {
        let access = self
            .config
            .peer(peer_id)?
            .access(&request.scope, request.body.name())?;
        if request
            .body
            .artifact()
            .is_some_and(|artifact| !access.permits_artifact(artifact))
        {
            return Err("artifact is outside the configured peer allowlist".into());
        }
        Ok(())
    }
    fn offer(&self, candidate: &str) -> Result<(String, Offer), String> {
        for event in self.journal.events() {
            if let OperationalEvent::Quarantined {
                key,
                candidate_id,
                body,
                ..
            } = event
            {
                if candidate_id == candidate {
                    let request: Request = serde_json::from_value(body.clone())
                        .map_err(|_| "cannot replay quarantined candidate")?;
                    if let Operation::Submit { offer } = request.body {
                        return Ok((key.peer_id.clone(), *offer));
                    }
                }
            }
        }
        Err("unknown candidate digest".into())
    }
    fn completed(&self, candidate: &str) -> Option<Value> {
        self.journal.events().iter().find_map(|event|match event{
        OperationalEvent::EvaluationCompleted{candidate_id,response,..} if candidate_id==candidate=>Some(response.clone()),
        OperationalEvent::EvaluationRejected{candidate_id,reason} if candidate_id==candidate=>Some(json!({"schema":"symbiote.service-evaluation/1","status":"REJECTED","candidate":candidate,"reason":reason,"promoted":false})),_=>None})
    }
    fn recover_evaluations(&mut self) -> Result<(), String> {
        self.settle_denied_intents()?;
        let pending: Vec<_> = self
            .journal
            .events()
            .iter()
            .filter_map(|event| match event {
                OperationalEvent::EvaluationPrepared {
                    candidate_id,
                    record,
                    fixture_sha256,
                    response,
                } if self.completed(candidate_id).is_none() => Some((
                    candidate_id.clone(),
                    record.clone(),
                    fixture_sha256.clone(),
                    response.clone(),
                )),
                _ => None,
            })
            .collect();
        for (candidate, record, fixture, response) in pending {
            let (peer, offer) = self.offer(&candidate)?;
            let context = self.config.context(&record.scope)?;
            self.config.fixture(context)?;
            if context.truth_sha256.as_ref() != Some(&fixture) {
                return Err("pending evaluation truth fixture changed; recovery is HOLD".into());
            }
            if !self.active_matches(&record)? {
                if self.journal.denied_peers().contains(&peer) {
                    return Err(
                        "pending evaluation sender is denied before promotion; recovery is HOLD"
                            .into(),
                    );
                }
                let prepared = evaluation::prepare(&self.config, &self.knowledge, &peer, &offer)
                    .map_err(|_| "pending evaluation cannot be reproduced; recovery is HOLD")?;
                if prepared.record.digest() != record.digest() || prepared.response()? != response {
                    return Err(
                        "pending evaluation conflicts with current knowledge; recovery is HOLD"
                            .into(),
                    );
                }
                prepared.commit(&mut self.knowledge)?;
            }
            self.journal.append(OperationalEvent::EvaluationCompleted {
                candidate_id: candidate,
                record_sha256: record.digest()?,
                response,
            })?;
        }
        Ok(())
    }
    fn settle_denied_intents(&mut self) -> Result<(), String> {
        let pending: Vec<_> = self
            .journal
            .events()
            .iter()
            .filter_map(|event| match event {
                OperationalEvent::EvaluationPrepared {
                    candidate_id,
                    record,
                    response,
                    ..
                } if self.completed(candidate_id).is_none() => {
                    Some((candidate_id.clone(), record.clone(), response.clone()))
                }
                _ => None,
            })
            .collect();
        for (candidate, record, response) in pending {
            let (peer, _) = self.offer(&candidate)?;
            if !self.journal.denied_peers().contains(&peer) {
                continue;
            }
            if self.active_matches(&record)? {
                // The earlier commit remains historical knowledge. Closing its
                // interrupted acknowledgement is not a new promotion.
                self.journal.append(OperationalEvent::EvaluationCompleted {
                    candidate_id: candidate,
                    record_sha256: record.digest()?,
                    response,
                })?;
            } else {
                self.journal.append(OperationalEvent::EvaluationRejected {
                    candidate_id: candidate,
                    reason:
                        "operator denial canceled pending recovery; no new promotion was performed"
                            .into(),
                })?;
            }
        }
        Ok(())
    }
    fn active_matches(&self, expected: &KnowledgeRecord) -> Result<bool, String> {
        let expected = expected.digest()?;
        for record in self.knowledge.active() {
            if record.digest()? == expected {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn handle(
        &mut self,
        session: &SecureSession,
        operation: &str,
        payload: Value,
    ) -> Result<Value, String> {
        let request: Request =
            serde_json::from_value(payload).map_err(|_| "unsupported typed service request")?;
        request.validate(&self.config)?;
        if request.scope != session.scope
            || request.body.name() != operation
            || self.journal.denied_peers().contains(&session.peer_id)
        {
            return Err("service session/context authorization rejected".into());
        }
        self.authorize(&session.peer_id, &request)?;
        let count = self.requests.entry(session.peer_id.clone()).or_default();
        if *count >= self.config.limits.per_peer_requests {
            return Err("per-peer service request budget exhausted".into());
        }
        *count += 1;
        match &request.body {
            Operation::Capabilities => Ok(
                json!({"schema":"symbiote.service-capabilities/1","identity":self.config.identity,"context":request.scope,"schema_fingerprint":self.config.context(&request.scope)?.schema_fingerprint,"families":["affine","graph-map"],"operations":session.operations,"max_offer_bytes":self.config.limits.max_offer_bytes,"remote_promotion":false,"truth_basis":"local operator fixtures only"}),
            ),
            Operation::List { after } => {
                let access = self
                    .config
                    .peer(&session.peer_id)?
                    .access(&request.scope, operation)?;
                let fingerprint = &self.config.context(&request.scope)?.schema_fingerprint;
                let eligible: Vec<_> = self
                    .knowledge
                    .active()
                    .into_iter()
                    .filter(|record| {
                        record.scope == request.scope
                            && record.schema_fingerprint == *fingerprint
                            && access.permits_artifact(&record.id)
                            && after.as_ref().is_none_or(|cursor| record.id > *cursor)
                    })
                    .collect();
                let mut records = Vec::new();
                let mut last = None;
                for record in &eligible {
                    if records.len() >= 32 {
                        break;
                    }
                    let metadata = json!({"id":record.id,"revision":record.revision,"schema_fingerprint":record.schema_fingerprint,"sha256":record.digest()?});
                    records.push(metadata);
                    if serde_json::to_vec(&records)
                        .map_err(|_| "cannot bound metadata page")?
                        .len()
                        + 1024
                        > self.config.limits.max_frame_bytes
                    {
                        records.pop();
                        break;
                    }
                    last = Some(record.id.clone());
                }
                let next_after = if records.len() < eligible.len() {
                    last
                } else {
                    None
                };
                Ok(
                    json!({"schema":"symbiote.service-knowledge/1","artifacts":records,"next_after":next_after}),
                )
            }
            Operation::Read { artifact } => {
                let record = self.record(artifact, &request.scope)?;
                Ok(
                    json!({"schema":"symbiote.service-artifact/1","record":record,"record_sha256":record.digest()?,"sender":self.config.identity,"trust":"inert locally retained knowledge; receiver must independently evaluate"}),
                )
            }
            Operation::Predict { artifact, input } => {
                let record = self.record(artifact, &request.scope)?;
                let charge = if matches!(
                    record.typed_payload()?,
                    symbiote_memory::knowledge::KnowledgePayload::Affine { .. }
                ) {
                    1
                } else {
                    1024
                };
                if self
                    .work
                    .checked_add(charge)
                    .is_none_or(|work| work > self.config.limits.model_work)
                {
                    return Err("service reasoning work budget exhausted".into());
                }
                self.work += charge;
                let route = if charge == 1024 {
                    record.graph_forecast(*input)?
                } else {
                    None
                };
                let prediction = if charge == 1024 {
                    route
                        .as_ref()
                        .map(|route| {
                            u8::try_from(route.cost).map_err(|_| "bounded route cost overflow")
                        })
                        .transpose()?
                } else {
                    record.predict_if_certified(*input)?
                };
                Ok(
                    json!({"schema":"symbiote.service-prediction/1","artifact":record.id,"record_sha256":record.digest()?,"input":input,"prediction":prediction,"route":route,"conditional":true,"physical_certificate_authorized":false}),
                )
            }
            Operation::Submit { .. } => self.submit(&session.peer_id, &request),
            Operation::CandidateStatus { candidate } => {
                let (peer, offer) = self.offer(candidate)?;
                if peer != session.peer_id || offer.record.scope != request.scope {
                    return Err(
                        "candidate status is private to its authenticated sender/context".into(),
                    );
                }
                Ok(self
                    .completed(candidate)
                    .unwrap_or_else(|| quarantine_response(candidate)))
            }
        }
    }
    fn record(&self, id: &str, scope: &str) -> Result<KnowledgeRecord, String> {
        self.knowledge
            .active()
            .into_iter()
            .find(|record| {
                record.id == id
                    && record.scope == scope
                    && self.config.context(scope).is_ok_and(|context| {
                        context.schema_fingerprint == record.schema_fingerprint
                    })
            })
            .ok_or_else(|| "no active artifact exists within this exact authorized context".into())
    }
    fn submit(&mut self, peer: &str, request: &Request) -> Result<Value, String> {
        let key = IdempotencyKey {
            peer_id: peer.into(),
            operation: "candidate.submit".into(),
            scope: request.scope.clone(),
            request_id: request.request_id.clone(),
        };
        let body = serde_json::to_value(request).map_err(|_| "cannot canonicalize candidate")?;
        let body_sha256 = digest(&body)?;
        if let Some(OperationalEvent::Quarantined {
            body_sha256: previous,
            response,
            ..
        }) = self.journal.quarantined(&key)
        {
            if previous != &body_sha256 {
                return Err("idempotency key was already bound to different canonical data".into());
            }
            return Ok(response.clone());
        }
        let offers = self
            .journal
            .events()
            .iter()
            .filter(|event| matches!(event, OperationalEvent::Quarantined { .. }))
            .count();
        if offers >= self.config.limits.max_offers {
            return Err("durable quarantine offer budget exhausted".into());
        }
        let Operation::Submit { offer } = &request.body else {
            return Err("quarantine requires a typed candidate".into());
        };
        for event in self.journal.events() {
            if let OperationalEvent::Quarantined {
                key: previous,
                body: previous_body,
                ..
            } = event
            {
                if previous.peer_id == peer && previous.scope == request.scope {
                    let old: Request = serde_json::from_value(previous_body.clone())
                        .map_err(|_| "quarantine replay failed")?;
                    if let Operation::Submit { offer: old } = old.body {
                        if old.record.schema_fingerprint == offer.record.schema_fingerprint
                            && (old.record.id != offer.record.id
                                || old.record.revision > offer.record.revision
                                || (old.record.revision == offer.record.revision
                                    && old.record.digest() != offer.record.digest()))
                        {
                            return Err("candidate source binding, revision or original digest conflicts with prior authenticated offers".into());
                        }
                    }
                }
            }
        }
        let candidate_id = candidate_id_for(peer, &body_sha256)?;
        let response = quarantine_response(&candidate_id);
        self.journal.append(OperationalEvent::Quarantined {
            key,
            candidate_id,
            body_sha256,
            body,
            response: response.clone(),
        })?;
        Ok(response)
    }
    fn evaluate(&mut self, candidate: &str) -> Result<Value, String> {
        if !config::sha(candidate) {
            return Err("candidate digest rejected".into());
        }
        if let Some(response) = self.completed(candidate) {
            return Ok(response);
        }
        let (peer, offer) = self.offer(candidate)?;
        if self.journal.denied_peers().contains(&peer) {
            return Err("candidate sender is durably denied".into());
        }
        // Missing or changed operator authority is an operational HOLD, not
        // counterevidence against an otherwise untested received candidate.
        self.config
            .fixture(self.config.context(&offer.record.scope)?)?;
        let prepared = match evaluation::prepare(&self.config, &self.knowledge, &peer, &offer) {
            Ok(value) => value,
            Err(reason) => {
                self.journal.append(OperationalEvent::EvaluationRejected {
                    candidate_id: candidate.into(),
                    reason: reason.clone(),
                })?;
                return self
                    .completed(candidate)
                    .ok_or_else(|| "cannot replay rejection receipt".into());
            }
        };
        let response = prepared.response()?;
        let record_sha256 = prepared.record.digest()?;
        self.journal.append(OperationalEvent::EvaluationPrepared {
            candidate_id: candidate.into(),
            record: prepared.record.clone(),
            fixture_sha256: prepared.fixture_sha256.clone(),
            response: response.clone(),
        })?;
        if prepared.commit(&mut self.knowledge)? != response {
            return Err(
                "committed evaluation receipt differs from its durable intent; recovery is HOLD"
                    .into(),
            );
        }
        self.journal.append(OperationalEvent::EvaluationCompleted {
            candidate_id: candidate.into(),
            record_sha256,
            response: response.clone(),
        })?;
        Ok(response)
    }
}
fn candidate_id_for(peer: &str, body: &str) -> Result<String, String> {
    digest(&json!({"authenticated_sender":peer,"canonical_body_sha256":body}))
}
fn quarantine_response(candidate: &str) -> Value {
    json!({"schema":"symbiote.service-quarantine/1","status":"QUARANTINED","candidate":candidate,"promoted":false})
}

pub(crate) fn serve(path: &Path) -> Result<Value, String> {
    let state = State::open(Config::load(path)?)?;
    let identity = state.config.identity.clone();
    let policy = state.config.policy_digest.clone();
    if state
        .config
        .peers
        .iter()
        .all(|peer| state.journal.denied_peers().contains(&peer.id))
    {
        return Ok(
            json!({"schema":"symbiote.service-stop/1","status":"STOPPED","identity":identity,"reason":"no-authorized-peers","requests":0,"connections":0,"operational_records":state.journal.record_count(),"active_knowledge":state.knowledge.active().len(),"listener_opened":false}),
        );
    }
    let lease = Duration::from_millis(state.config.limits.lifetime_ms);
    let server_config = state.config.server(&state.journal.denied_peers())?;
    let state = Arc::new(Mutex::new(state));
    let handler = Arc::clone(&state);
    let mut server = spawn_secure_server(server_config, move |session, operation, payload| {
        handler
            .lock()
            .map_err(|_| "service state unavailable")?
            .handle(session, operation, payload)
    })?;
    println!(
        "{}",
        json!({"schema":"symbiote.service-ready/1","identity":identity,"pid":std::process::id(),"address":server.address(),"policy_sha256":policy,"lifetime_ms":lease.as_millis(),"protocol":"symbiote/2"})
    );
    std::io::stdout()
        .flush()
        .map_err(|_| "cannot publish service readiness")?;
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut reader = BufReader::new(std::io::stdin().lock());
        let result = (|| {
            let mut bytes = Vec::new();
            loop {
                let available = reader
                    .fill_buf()
                    .map_err(|_| "service owner control pipe failed")?;
                if available.is_empty() {
                    return Ok("owner-eof");
                }
                let count = available
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(available.len(), |index| index + 1);
                if bytes.len() + count > 256 {
                    return Err("service owner control exceeds its byte budget");
                }
                bytes.extend_from_slice(&available[..count]);
                let complete = available[count - 1] == b'\n';
                reader.consume(count);
                if complete {
                    break;
                }
            }
            let command: Value =
                serde_json::from_slice(&bytes).map_err(|_| "invalid service owner control")?;
            if command != json!({"command":"shutdown"}) {
                return Err("unsupported service owner control");
            }
            Ok("owner-shutdown")
        })();
        let _ = tx.try_send(result);
    });
    let reason = match rx.recv_timeout(lease) {
        Ok(value) => value.map_err(str::to_string)?,
        Err(mpsc::RecvTimeoutError::Timeout) => "lifetime-budget",
        Err(_) => "owner-channel-closed",
    };
    server.shutdown()?;
    let state = state.lock().map_err(|_| "cannot summarize service state")?;
    Ok(
        json!({"schema":"symbiote.service-stop/1","status":"STOPPED","identity":identity,"reason":reason,"requests":server.request_count(),"connections":server.connection_count(),"failed_sessions":server.session_failures(),"operational_records":state.journal.record_count(),"active_knowledge":state.knowledge.active().len(),"model_work_units":state.work}),
    )
}
pub(crate) fn peers(path: &Path) -> Result<Value, String> {
    let state = State::open(Config::load(path)?)?;
    let denied = state.journal.denied_peers();
    let peers:Vec<_>=state.config.peers.iter().map(|peer|json!({"alias":peer.alias,"id":peer.id,"address":peer.address,"server_name":peer.server_name,"access":peer.access,"denied":denied.contains(&peer.id)})).collect();
    Ok(
        json!({"schema":"symbiote.service-peers/1","identity":state.config.identity,"peers":peers,"network_requests":0,"discovery":"explicit operator registry only"}),
    )
}
pub(crate) fn connect(path: &Path, peer_alias: &str, request_path: &Path) -> Result<Value, String> {
    let state = State::open(Config::load(path)?)?;
    let config = &state.config;
    let request: Request = serde_json::from_slice(&config::read_bounded(request_path, 65_536)?)
        .map_err(|_| "typed service request rejected")?;
    request.validate(config)?;
    let peer = config
        .peers
        .iter()
        .find(|peer| peer.alias == peer_alias)
        .ok_or("unknown explicitly configured peer alias")?;
    if state.journal.denied_peers().contains(&peer.id) {
        return Err("outbound peer is durably denied".into());
    }
    let access = peer.access(&request.scope, request.body.name())?;
    if request
        .body
        .artifact()
        .is_some_and(|id| !access.permits_artifact(id))
    {
        return Err("artifact is outside the outbound operator grant".into());
    }
    let mut client = SecureClient::connect(
        &config.endpoint(peer, &request.scope, request.body.name()),
        &config.client()?,
    )?;
    let response = client.call(
        request.body.name(),
        &serde_json::to_value(&request).map_err(|_| "cannot encode typed service request")?,
    )?;
    client.revoke()?;
    Ok(response)
}
pub(crate) fn evaluate(path: &Path, candidate: &str) -> Result<Value, String> {
    State::open(Config::load(path)?)?.evaluate(candidate)
}
pub(crate) fn peer_revoke(path: &Path, peer: &str, reason: &str) -> Result<Value, String> {
    if reason.trim().is_empty() || reason.len() > 1024 {
        return Err("peer denial needs a nonempty bounded reason".into());
    }
    // Denial must commit before replay can admit a pending candidate. A generic
    // startup recovery here would promote first and defeat the owner's action.
    let mut state = State::load(Config::load(path)?)?;
    let peer = state
        .config
        .peers
        .iter()
        .find(|entry| entry.alias == peer || entry.id == peer)
        .ok_or("cannot deny an unknown configured peer")?
        .id
        .clone();
    let existing = state.journal.denied_peers().contains(&peer);
    if !existing {
        state.journal.append(OperationalEvent::PeerDenied {
            peer_id: peer.clone(),
            reason: reason.into(),
        })?;
    }
    state.settle_denied_intents()?;
    Ok(
        json!({"schema":"symbiote.service-peer-denial/1","identity":state.config.identity,"peer":peer,"denied":true,"already_denied":existing,"persistent":true}),
    )
}
