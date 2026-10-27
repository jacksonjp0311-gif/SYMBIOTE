//! Native recipient-controlled learning and prospective partner decisions.
use super::evidence::{Receipt, Verification};
use super::meter::{difference, Bill, Meter};
use super::model::{Algorithm, Assessment, ExactModel};
use super::policy::{Advertisement, Arm, Decision, Profile, Quote, RegistryPeer};
use super::process::Running;
use super::registration::PROTOCOL_SHA256;
use super::wire::{Bootstrap, Descriptor, OfferMode, PublicEndpoint, Role, SCOPE};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use symbiote_memory::knowledge::graph::{
    assess_graph, encode_query, graph_schema_fingerprint, GraphMap, GraphObservation,
    GraphTrainingTask, GraphTrialEvidence,
};
use symbiote_memory::knowledge::{KnowledgeRecord, KnowledgeStore, TrialCase, TrialCosts};
use symbiote_memory::operational::{
    body_digest, OperationalEvent, OperationalJournal, PartnerDecisionRecord,
    PartnerInteractionOutcome, PartnerInteractionRecord, PartnerOutcomeKind, PartnerOutcomeRecord,
};
use symbiote_memory::Store;
use symbiote_protocol::{
    spawn_secure_server_metered, SecureClient, SecureSession, SecureTraffic, TlsClientConfig,
};
use symbiote_reasoning::planning::{GraphSchema, Route};

const QUOTE: Quote = Quote {
    receiver_max: 31,
    contributor_max: 15,
    pair_max: 46,
    frame: 4096,
    control_frame: 1024,
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Begin {
    context: String,
    schema: GraphSchema,
    algorithm: Algorithm,
    warmup_edge: usize,
    prelude: bool,
}
struct Current {
    context: String,
    model: ExactModel,
    warmup_edge: usize,
    prelude: bool,
    warmup: Option<Receipt>,
    receipts: BTreeMap<usize, Receipt>,
    assessment: Option<Assessment>,
    advertisements: Option<Vec<Advertisement>>,
    attempted: BTreeSet<String>,
    forecasts: BTreeMap<u16, Option<Route>>,
    meter: Meter,
    finished: bool,
    abstention: Option<String>,
    promotion: String,
    served: BTreeSet<String>,
    contribution_meters: Vec<(SecureTraffic, u64)>,
    metadata_outcomes: Vec<Value>,
    source_response_ambiguous: bool,
}
struct Actor {
    owner: Arc<Store>,
    knowledge: KnowledgeStore,
    journal: OperationalJournal,
    controller: String,
    arm: Arm,
    price: u64,
    offer_mode: OfferMode,
    inactive: bool,
    client: TlsClientConfig,
    registry: Vec<Descriptor>,
    oracle: Option<PublicEndpoint>,
    fixed_peer: Option<String>,
    previous_warmup: Option<Receipt>,
    current: Option<Current>,
    server: SecureTraffic,
    world_deadline: Arc<Mutex<Option<Instant>>>,
}
fn json_bytes(value: &Value) -> Result<u64, String> {
    Ok(serde_json::to_vec(value).map_err(|e| e.to_string())?.len() as u64)
}
fn failure_code(error: &str) -> &'static str {
    let message = error.to_ascii_lowercase();
    if message.contains("deadline") || message.contains("timeout") {
        return "transport-timeout";
    }
    if message.contains("certificate")
        || message.contains("pin")
        || message.contains("authentication")
    {
        return "transport-authentication";
    }
    if message.contains("malformed") || message.contains("frame") || message.contains("json") {
        return "malformed-frame";
    }
    if message.contains("budget") || message.contains("quota") {
        return "resource-budget";
    }
    if message.contains("scope") || message.contains("authoriz") {
        return "unsupported-scope-or-authorization";
    }
    if message.contains("contradict") {
        return "graph-contradiction";
    }
    if message.contains("ledger") || message.contains("storage") || message.contains("journal") {
        return "storage-failure";
    }
    "transport-failure"
}
fn reachable(schema: &GraphSchema, start: usize, goal: usize) -> bool {
    let mut seen = BTreeSet::new();
    let mut todo = vec![start];
    while let Some(node) = todo.pop() {
        if node == goal {
            return true;
        }
        if !seen.insert(node) {
            continue;
        }
        todo.extend(
            schema
                .edges
                .iter()
                .filter(|edge| edge.from == node)
                .map(|edge| edge.to),
        );
    }
    false
}
impl Actor {
    fn profiles(&self) -> BTreeMap<String, Profile> {
        let mut profiles = BTreeMap::<String, Profile>::new();
        for event in self.journal.events() {
            if let OperationalEvent::PartnerInteractionCompleted { interaction } = event {
                if interaction.outcome == PartnerInteractionOutcome::SkippedIrrelevant {
                    continue;
                }
                let profile = profiles.entry(interaction.peer_id.clone()).or_default();
                profile.attempts += 1;
                match interaction.outcome {
                    PartnerInteractionOutcome::VerifiedNovel => profile.verified_novel += 1,
                    PartnerInteractionOutcome::VerificationFailed => {
                        profile.verification_failures += 1
                    }
                    PartnerInteractionOutcome::ApplicabilityFailed => {
                        profile.applicability_failures += 1
                    }
                    _ => {}
                }
            }
        }
        profiles
    }
    fn bill(&self, current: &Current) -> Result<Bill, String> {
        current.meter.snapshot(&self.server, current.model.work())
    }
    fn rpc(
        &self,
        current: &mut Current,
        endpoint: &PublicEndpoint,
        operation: &str,
        payload: &Value,
        frame: usize,
    ) -> Result<Value, String> {
        let bill = self.bill(current)?;
        let quota = bill.remaining(current.model.schema().edges.len())?;
        if quota.requests == 0 || quota.connections == 0 || quota.traffic < 2 * frame + 2048 {
            return Err("outgoing RPC fallback/traffic quota unavailable".into());
        }
        current.meter.counters.rpc_requests += 1;
        let traffic = SecureTraffic::default();
        current.meter.outgoing.push(traffic.clone());
        let mut client = SecureClient::connect_with_metering(
            &endpoint.endpoint(operation, frame)?,
            &self.client,
            traffic,
            1024,
        )?;
        if client.agreement().operations != vec![operation.to_string()]
            || client.agreement().max_frame_bytes > frame
        {
            return Err("HOLD: negotiated operation/frame bounds changed".into());
        }
        let result = client.call(operation, payload);
        let cancelled = client.cancel();
        cancelled?;
        self.bill(current)?
            .remaining(current.model.schema().edges.len())?;
        result
    }
    fn own_observation(&self, current: &mut Current, edge: usize) -> Result<(), String> {
        if current.receipts.contains_key(&edge) {
            return Err("frontier policy attempted a known edge".into());
        }
        let quota = self
            .bill(current)?
            .remaining(current.model.schema().edges.len())?;
        if quota.acquisitions == 0 || quota.model_work == 0 {
            return Err("local observation quota exhausted".into());
        }
        let oracle = self
            .oracle
            .as_ref()
            .ok_or("native authority not configured")?;
        // A source purchase attempt consumes its announced logical price even
        // when the reply is lost. Accepted observations are reported separately.
        current.meter.counters.observation_purchase_attempts += 1;
        let reply = match self.rpc(
            current,
            oracle,
            "observe",
            &json!({"context":current.context,"edge_id":edge}),
            4096,
        ) {
            Ok(reply) => reply,
            Err(error) => {
                current.source_response_ambiguous = true;
                return Err(error);
            }
        };
        let receipt: Receipt = match serde_json::from_value(reply) {
            Ok(receipt) => receipt,
            Err(_) => {
                current.source_response_ambiguous = true;
                return Err("own source returned malformed observation".into());
            }
        };
        if let Err(error) = receipt.applicable(
            &current.context,
            current.model.schema(),
            self.owner.identity(),
            edge,
        ) {
            current.source_response_ambiguous = true;
            return Err(error);
        }
        if let Err(error) = current.model.ingest(edge, receipt.cost) {
            current.source_response_ambiguous = true;
            return Err(error);
        }
        current.receipts.insert(edge, receipt);
        current.meter.counters.acquisitions += 1;
        Ok(())
    }
    fn assess(&self, current: &mut Current) -> Result<Assessment, String> {
        current.meter.counters.route_queries += 1;
        current.model.assess(0, current.model.schema().nodes - 1)
    }
    fn collect_ads(&mut self, current: &mut Current) -> Result<(), String> {
        if current.advertisements.is_some() {
            return Ok(());
        }
        let mut advertisements = Vec::new();
        if self.arm != Arm::Isolated {
            for descriptor in self.registry.clone() {
                if !descriptor.authorized || !descriptor.compatible {
                    continue;
                }
                if self.arm == Arm::Fixed
                    && self.fixed_peer.as_deref() != Some(descriptor.identity.as_str())
                {
                    continue;
                }
                let endpoint = descriptor
                    .endpoint
                    .as_ref()
                    .ok_or("authorized compatible endpoint missing")?;
                let decision_id = body_digest(&json!([
                    self.owner.identity(),
                    current.context,
                    "advertisement",
                    descriptor.identity,
                    self.journal.record_count()
                ]))?;
                self.journal.append(OperationalEvent::PartnerDecisionRecorded{decision:PartnerDecisionRecord{decision_id:decision_id.clone(),context:current.context.clone(),frontier_edge:None,selected_peer:Some(descriptor.identity.clone()),details:json!({"operation":"advertise","reason":"authorized-compatible-metadata","knowledge_attempt":false})}})?;
                let before = self.bill(current)?;
                let result = self.rpc(
                    current,
                    endpoint,
                    "advertise",
                    &json!({"context":current.context}),
                    4096,
                );
                let (status, kind) = match result {
                    Err(error) => (failure_code(&error), PartnerOutcomeKind::Failed),
                    Ok(value) => match serde_json::from_value::<Advertisement>(value) {
                        Err(_) => ("malformed-advertisement", PartnerOutcomeKind::Rejected),
                        Ok(advertisement) => {
                            if advertisement.peer != descriptor.identity {
                                ("wrong-advertised-identity", PartnerOutcomeKind::Rejected)
                            } else if advertisement.context != current.context
                                || advertisement.scope != SCOPE
                                || advertisement.schema_fingerprint
                                    != graph_schema_fingerprint(current.model.schema())?
                            {
                                ("inapplicable-advertisement", PartnerOutcomeKind::Rejected)
                            } else {
                                advertisements.push(advertisement);
                                (
                                    "applicable-inert-advertisement",
                                    PartnerOutcomeKind::Received,
                                )
                            }
                        }
                    },
                };
                let after = self.bill(current)?;
                current.metadata_outcomes.push(json!({"peer":descriptor.identity,"operation":"advertise","outcome":status,"knowledge_quality_profile_changed":false}));
                self.journal
                    .append(OperationalEvent::PartnerOutcomeRecorded {
                        outcome: PartnerOutcomeRecord {
                            interaction_id: decision_id,
                            peer_id: descriptor.identity,
                            scope: SCOPE.into(),
                            kind,
                            receipt_sha256: None,
                            resource_units: after
                                .total(self.price)
                                .saturating_sub(before.total(self.price)),
                        },
                    })?;
            }
        }
        current.advertisements = Some(advertisements);
        Ok(())
    }
    fn attempt(
        &self,
        current: &mut Current,
        peer: &str,
        offer: &str,
        edge: usize,
    ) -> Result<(PartnerInteractionOutcome, Option<String>), String> {
        let descriptor = self
            .registry
            .iter()
            .find(|entry| entry.identity == peer && entry.authorized && entry.compatible)
            .ok_or("policy attempted an unauthorized/incompatible relationship")?;
        let endpoint = descriptor
            .endpoint
            .as_ref()
            .ok_or("authorized peer endpoint absent")?;
        current.meter.counters.received_attempts += 1;
        current.attempted.insert(peer.into());
        let reply = match self.rpc(
            current,
            endpoint,
            "request-edge",
            &json!({"context":current.context,"edge_id":edge,"offer_id":offer}),
            4096,
        ) {
            Ok(value) => value,
            Err(_) => return Ok((PartnerInteractionOutcome::TransportFailed, None)),
        };
        if reply.is_null() {
            return Ok((PartnerInteractionOutcome::EmptyOffer, None));
        }
        // The declared verification fee pays an inspection attempt, including
        // malformed artifacts and a lost remote-verifier reply. Success is a
        // distinct diagnostic counter and never refunds a failed attempt.
        current.meter.counters.receipt_verification_attempts += 1;
        if json_bytes(&reply)? > 2048 {
            return Err("HOLD: peer receipt exceeded the frozen 2048-byte bound".into());
        }
        let receipt: Receipt = match serde_json::from_value(reply) {
            Ok(receipt) => receipt,
            Err(_) => return Ok((PartnerInteractionOutcome::VerificationFailed, None)),
        };
        let digest = receipt.digest()?;
        let oracle = self.oracle.as_ref().ok_or("authority not configured")?;
        let verification=match self.rpc(current,oracle,"verify",&json!({"receipt":receipt,"context":current.context,"schema_fingerprint":graph_schema_fingerprint(current.model.schema())?,"observer_identity":peer,"edge_id":edge}),4096){Ok(value)=>value,Err(_)=>return Ok((PartnerInteractionOutcome::TransportFailed,Some(digest)))};
        let verified: Verification = serde_json::from_value(verification)
            .map_err(|_| "authority returned malformed receipt verdict")?;
        if verified.receipt_sha256 != digest || !verified.authentic {
            return Ok((PartnerInteractionOutcome::VerificationFailed, Some(digest)));
        }
        if !verified.applicable
            || receipt
                .applicable(&current.context, current.model.schema(), peer, edge)
                .is_err()
        {
            return Ok((PartnerInteractionOutcome::ApplicabilityFailed, Some(digest)));
        }
        current.model.ingest(edge, receipt.cost)?;
        current.meter.counters.verified_receipts += 1;
        current.receipts.insert(edge, receipt);
        current.meter.counters.adopted_edges += 1;
        Ok((PartnerInteractionOutcome::VerifiedNovel, Some(digest)))
    }
    fn advance(&mut self, current: &mut Current, payload: Value) -> Result<Value, String> {
        if current.prelude {
            return Err("prelude is not a route learning task".into());
        }
        if current.warmup.is_none() {
            return Err("all source warmups must precede learning".into());
        }
        self.collect_ads(current)?;
        let assessment = match current.assessment.take() {
            Some(assessment) => assessment,
            None => match self.assess(current) {
                Ok(assessment) => assessment,
                Err(_) => {
                    current.abstention = Some("work-budget".into());
                    return Ok(json!({"status":"abstained"}));
                }
            },
        };
        if assessment.certified.is_some() {
            let route = json!(assessment.certified);
            current.assessment = Some(assessment);
            return Ok(json!({"status":"complete","route":route}));
        }
        let Some(frontier) = assessment.next else {
            current.abstention = Some("unsupported-frontier".into());
            return Ok(json!({"status":"abstained"}));
        };
        let registry = self
            .registry
            .iter()
            .map(|peer| RegistryPeer {
                identity: peer.identity.clone(),
                authorized: peer.authorized,
                compatible: peer.compatible,
            })
            .collect::<Vec<_>>();
        let profiles = self.profiles();
        let known = current
            .model
            .observed()
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let quota = self
            .bill(current)?
            .remaining(current.model.schema().edges.len())?;
        let choice = Decision {
            arm: self.arm,
            context: &current.context,
            schema_fingerprint: &graph_schema_fingerprint(current.model.schema())?,
            scope: SCOPE,
            frontier,
            known: &known,
            registry: &registry,
            advertisements: current.advertisements.as_deref().unwrap_or(&[]),
            profiles: &profiles,
            attempted_context_peers: &current.attempted,
            fixed_peer: self.fixed_peer.as_deref(),
            uniform_index: payload["uniform_draws"][current
                .advertisements
                .as_ref()
                .map_or(0, Vec::len)
                .to_string()]
            .as_u64()
            .map(|index| index as usize),
            observation_price: self.price,
            quota: &quota,
            assessment_bound: current
                .model
                .algorithm()
                .assessment_bound(current.model.schema()),
            quote: QUOTE,
        }
        .choose()?;
        let decision_id = body_digest(&json!([
            self.owner.identity(),
            current.context,
            self.journal.record_count(),
            frontier
        ]))?;
        self.journal.append(OperationalEvent::PartnerDecisionRecorded{decision:PartnerDecisionRecord{decision_id:decision_id.clone(),context:current.context.clone(),frontier_edge:Some(frontier),selected_peer:choice.peer.clone(),details:json!({"choice":choice,"remaining":quota,"profiles":profiles,"advertisements":current.advertisements,"known_edges":known,"assessment_work_bound":current.model.algorithm().assessment_bound(current.model.schema()),"frontier_assessment_native_work":assessment.work_delta,"before_model_sha256":body_digest(&current.model.state())?})}})?;
        let before_model = current.model.state();
        let before_bill = self.bill(current)?;
        let mut completed = None;
        if choice.reason == "request-verified-frontier-offer" {
            let peer = choice
                .peer
                .as_deref()
                .ok_or("admissible request lacks peer")?;
            let offer = choice
                .offer_id
                .as_deref()
                .ok_or("admissible request lacks offer")?;
            let outcome = self.attempt(current, peer, offer, frontier)?;
            if outcome.0 != PartnerInteractionOutcome::VerifiedNovel {
                let after_state = current.model.state();
                self.journal.append(OperationalEvent::PartnerDecisionRecorded{decision:PartnerDecisionRecord{decision_id:body_digest(&json!([decision_id,"rejected-state-witness"]))?,context:current.context.clone(),frontier_edge:Some(frontier),selected_peer:Some(peer.into()),details:json!({"operation":"rejected-state-witness","attempt_decision_id":decision_id,"before_state":before_model,"after_state":after_state,"before_sha256":body_digest(&before_model)?,"after_sha256":body_digest(&after_state)?,"unchanged":before_model==after_state})}})?;
            }
            if outcome.0 != PartnerInteractionOutcome::VerifiedNovel
                && current.model.state() != before_model
            {
                return Err("HOLD: rejected observation changed native reasoning state".into());
            }
            let attempt_bill = self.bill(current)?;
            let common_ingestion = u64::from(outcome.0 == PartnerInteractionOutcome::VerifiedNovel);
            if attempt_bill
                .total(self.price)
                .saturating_sub(before_bill.total(self.price))
                .saturating_sub(common_ingestion)
                > QUOTE.receiver_max
            {
                return Err("HOLD: actual receiver attempt exceeded preregistered bound".into());
            }
            completed = Some((peer.to_string(), outcome));
        }
        if !completed
            .as_ref()
            .is_some_and(|(_, outcome)| outcome.0 == PartnerInteractionOutcome::VerifiedNovel)
        {
            if let Err(error) = self.own_observation(current, frontier) {
                current.abstention = Some(failure_code(&error).into());
            }
        }
        if current.abstention.is_none() {
            match self.assess(current) {
                Ok(assessment) => current.assessment = Some(assessment),
                Err(_) => current.abstention = Some("work-budget".into()),
            }
        }
        if let Some((peer, (outcome, digest))) = completed {
            let after = self.bill(current)?;
            self.journal
                .append(OperationalEvent::PartnerInteractionCompleted {
                    interaction: PartnerInteractionRecord {
                        interaction_id: decision_id.clone(),
                        decision_id,
                        peer_id: peer,
                        context: current.context.clone(),
                        outcome: outcome.clone(),
                        receipt_sha256: digest,
                        sent_bytes: after.sent().saturating_sub(before_bill.sent()),
                        received_bytes: after.received().saturating_sub(before_bill.received()),
                        resource_units: after
                            .total(self.price)
                            .saturating_sub(before_bill.total(self.price)),
                        subsequently_used: outcome == PartnerInteractionOutcome::VerifiedNovel
                            && current.assessment.is_some(),
                    },
                })?;
        }
        Ok(
            json!({"status":if current.abstention.is_some(){"abstained"}else if current.assessment.as_ref().is_some_and(|assessment|assessment.certified.is_some()){"complete"}else{"continue"},"route":current.assessment.as_ref().and_then(|assessment|assessment.certified.as_ref())}),
        )
    }
    fn advertisement(&self, current: &Current) -> Result<Advertisement, String> {
        let warmup = current
            .warmup
            .as_ref()
            .ok_or("no already-issued source observation")?;
        let receipt = match self.offer_mode {
            OfferMode::CurrentWarmup => warmup,
            OfferMode::PreviousContext => self
                .previous_warmup
                .as_ref()
                .ok_or("stale-control prelude receipt missing")?,
        };
        Ok(Advertisement {
            peer: self.owner.identity().into(),
            context: current.context.clone(),
            schema_fingerprint: graph_schema_fingerprint(current.model.schema())?,
            scope: SCOPE.into(),
            edge_id: current.warmup_edge,
            offer_id: receipt.id.clone(),
        })
    }
    fn record(&self, current: &Current) -> Result<KnowledgeRecord, String> {
        let map = GraphMap::new(
            current.model.schema().clone(),
            current
                .model
                .observed()
                .iter()
                .map(|(edge, cost)| GraphObservation {
                    edge_id: *edge,
                    cost: *cost,
                })
                .collect(),
        )?;
        let id = format!("map-{}", current.context);
        Ok(KnowledgeRecord{id:id.clone(),revision:self.knowledge.highest_revision(&id).unwrap_or(0)+1,source:self.owner.identity().into(),scope:current.context.clone(),schema_fingerprint:graph_schema_fingerprint(current.model.schema())?,payload:map.to_payload()?,provenance:"Native stationary graph map; exact per-edge observation origins retained in authenticated inert envelopes.".into()})
    }
    fn dispatch(
        &mut self,
        current: &mut Current,
        session: &SecureSession,
        operation: &str,
        payload: Value,
    ) -> Result<Value, String> {
        match operation {
            "warmup" => {
                if current.warmup.is_some() {
                    return Err("warmup already acquired".into());
                }
                self.own_observation(current, current.warmup_edge)?;
                current.warmup = current.receipts.get(&current.warmup_edge).cloned();
                let receipt = current
                    .warmup
                    .as_ref()
                    .ok_or("own warmup receipt disappeared")?;
                self.journal
                    .append(OperationalEvent::SourceWarmupRetained {
                        context: current.context.clone(),
                        receipt_sha256: receipt.digest()?,
                        receipt: receipt.value()?,
                    })?;
                Ok(json!({"acquired":true}))
            }
            "advertise" => {
                if payload["context"] != current.context {
                    return Err("advertisement context differs".into());
                }
                Ok(json!(self.advertisement(current)?))
            }
            "request-edge" => {
                let advertisement = self.advertisement(current)?;
                if payload["context"] != current.context
                    || payload["edge_id"] != advertisement.edge_id
                    || payload["offer_id"] != advertisement.offer_id
                {
                    return Err("request does not bind an existing exact advertised offer".into());
                }
                let mut before = self.bill(current)?;
                let incoming = session.traffic.snapshot();
                before.rpc_requests = before
                    .rpc_requests
                    .checked_sub(1)
                    .ok_or("incoming RPC counter missing")?;
                before.sessions = before
                    .sessions
                    .checked_sub(incoming.connection_attempts)
                    .ok_or("incoming session counter missing")?;
                before.rpc_sent_bytes = before
                    .rpc_sent_bytes
                    .checked_sub(incoming.rpc_sent_bytes)
                    .ok_or("incoming byte counter missing")?;
                before.rpc_received_bytes = before
                    .rpc_received_bytes
                    .checked_sub(incoming.rpc_received_bytes)
                    .ok_or("incoming byte counter missing")?;
                before.negotiation_sent_bytes = before
                    .negotiation_sent_bytes
                    .checked_sub(incoming.negotiation_sent_bytes)
                    .ok_or("incoming negotiation counter missing")?;
                before.negotiation_received_bytes = before
                    .negotiation_received_bytes
                    .checked_sub(incoming.negotiation_received_bytes)
                    .ok_or("incoming negotiation counter missing")?;
                if !before
                    .remaining(current.model.schema().edges.len())?
                    .reserve_contributor(4096, 1024)
                {
                    return Err("contributor reservation unavailable".into());
                }
                if !current.served.insert(session.peer_id.clone()) {
                    return Err("this peer already requested an offer in this context".into());
                }
                let receipt = match self.offer_mode {
                    OfferMode::CurrentWarmup => current.warmup.as_ref(),
                    OfferMode::PreviousContext => self.previous_warmup.as_ref(),
                }
                .ok_or("advertised receipt unavailable")?;
                let value = receipt.value()?;
                current.meter.counters.exported_bytes += json_bytes(&value)?;
                current
                    .contribution_meters
                    .push((session.traffic.clone(), json_bytes(&value)?));
                Ok(value)
            }
            "advance" => self.advance(current, payload),
            "forecast" => {
                let input = u16::try_from(payload["input"].as_u64().ok_or("route input missing")?)
                    .map_err(|_| "route input too large")?;
                let n = current.model.schema().nodes;
                let start = input as usize / n;
                let goal = input as usize % n;
                encode_query(n, start, goal)?;
                let training = self.training(current)?;
                if training.iter().any(|task| task.input == input)
                    || current.forecasts.contains_key(&input)
                {
                    return Err("held-out query is trained or repeated".into());
                }
                current.meter.counters.route_queries += 1;
                let route = match current.model.assess(start, goal) {
                    Ok(assessment) => assessment.certified,
                    Err(_) => {
                        current.abstention = Some("work-budget".into());
                        None
                    }
                };
                current.forecasts.insert(input, route.clone());
                Ok(
                    json!({"input":input,"route":route,"reason":if current.abstention.is_some(){"work-budget"}else{"conditional-support"}}),
                )
            }
            "export-page" => {
                let result = if payload["kind"] == "model" {
                    json!({"record":self.record(current)?,"training_tasks":self.training(current)?})
                } else {
                    let offset =
                        payload["offset"].as_u64().ok_or("export offset missing")? as usize;
                    let receipts = current
                        .receipts
                        .values()
                        .map(Receipt::acquisition)
                        .collect::<Result<Vec<_>, _>>()?;
                    if offset > receipts.len() {
                        return Err("export offset outside evidence".into());
                    }
                    let end = (offset + 8).min(receipts.len());
                    json!({"acquisitions":&receipts[offset..end],"next":if end<receipts.len(){Some(end)}else{None}})
                };
                if json_bytes(&result)? > 15_000 {
                    return Err("bounded model export page requires smaller pagination".into());
                }
                current.meter.counters.exported_bytes += json_bytes(&result)?;
                Ok(result)
            }
            "finish" => {
                for (traffic, exported) in &current.contribution_meters {
                    let snapshot = traffic.snapshot();
                    let sent = snapshot.rpc_sent_bytes + snapshot.negotiation_sent_bytes;
                    let received =
                        snapshot.rpc_received_bytes + snapshot.negotiation_received_bytes;
                    if snapshot.rpc_sent_bytes > 4096
                        || snapshot.rpc_received_bytes > 4096
                        || snapshot.negotiation_sent_bytes > 1024
                        || snapshot.negotiation_received_bytes > 1024
                        || snapshot.connection_attempts != 1
                        || 1 + 2
                            + sent.div_ceil(1024)
                            + received.div_ceil(1024)
                            + exported.div_ceil(1024)
                            > QUOTE.contributor_max
                    {
                        return Err("HOLD: contributor operation exceeded the frozen quote".into());
                    }
                }
                if current.prelude {
                    current.promotion = "prelude-not-learning".into();
                } else {
                    current.promotion = self.promote(current)?;
                }
                current.finished = true;
                if let Some(receipt) = &current.warmup {
                    self.previous_warmup = Some(receipt.clone());
                }
                *self
                    .world_deadline
                    .lock()
                    .map_err(|_| "world deadline lock poisoned")? = None;
                Ok(
                    json!({"bill_before_response":self.bill(current)?,"promotion":current.promotion,"abstention":current.abstention,"profiles":self.profiles(),"metadata_outcomes":current.metadata_outcomes,"source_response_ambiguous":current.source_response_ambiguous,"identity":self.owner.identity(),"context":current.context,"decision_records":self.journal.record_count()}),
                )
            }
            _ => {
                let _ = session;
                Err("unsupported authorized participant operation".into())
            }
        }
    }
    fn training(&self, current: &Current) -> Result<Vec<GraphTrainingTask>, String> {
        let edge = &current.model.schema().edges[current.warmup_edge];
        let n = current.model.schema().nodes;
        let mut tasks = BTreeMap::from([
            (encode_query(n, 0, n - 1)?, "main"),
            (encode_query(n, edge.from, edge.to)?, "warmup"),
        ]);
        Ok(tasks
            .iter_mut()
            .map(|(input, id)| GraphTrainingTask {
                id: (*id).into(),
                input: *input,
            })
            .collect())
    }
    fn promote(&mut self, current: &mut Current) -> Result<String, String> {
        let schema = current.model.schema();
        let training = self.training(current)?;
        let mut required = Vec::new();
        for start in 0..schema.nodes {
            for goal in 0..schema.nodes {
                if start != goal && reachable(schema, start, goal) {
                    let input = encode_query(schema.nodes, start, goal)?;
                    if !training.iter().any(|task| task.input == input) {
                        required.push(input);
                    }
                }
            }
        }
        if required.is_empty()
            || required
                .iter()
                .any(|input| !current.forecasts.get(input).is_some_and(Option::is_some))
        {
            return Ok("withheld-abstention".into());
        }
        let record = self.record(current)?;
        if self.knowledge.active().iter().any(|old| {
            old.id == record.id
                && old.payload == record.payload
                && old.scope == record.scope
                && old.schema_fingerprint == record.schema_fingerprint
                && old.source == record.source
        }) {
            return Ok("already-retained".into());
        }
        let reserve = self
            .bill(current)?
            .remaining(current.model.schema().edges.len())?;
        let assessment_calls = 2 + required.len().div_ceil(8);
        if reserve.requests < assessment_calls
            || reserve.connections < assessment_calls
            || reserve.traffic < assessment_calls * (2 * 16_384 + 2048) + 16_384
        {
            return Ok("withheld-evaluation-budget".into());
        }
        let oracle = self.oracle.as_ref().ok_or("authority not configured")?;
        let job=self.rpc(current,oracle,"assess",&json!({"stage":"begin","context":current.context,"record":record,"receipt_ids":current.receipts.values().map(|receipt|receipt.id.clone()).collect::<Vec<_>>()}),16_384)?;
        let job_id = job["job_id"]
            .as_str()
            .ok_or("assessment job binding missing")?
            .to_string();
        for page in required.chunks(8) {
            let routes = page
                .iter()
                .map(|input| json!({"input":input,"route":current.forecasts[input]}))
                .collect::<Vec<_>>();
            self.rpc(
                current,
                oracle,
                "assess",
                &json!({"stage":"routes","job_id":job_id,"routes":routes}),
                16_384,
            )?;
        }
        let verdict = self.rpc(
            current,
            oracle,
            "assess",
            &json!({"stage":"finish","job_id":job_id}),
            16_384,
        )?;
        if verdict["pass"] != true
            || verdict["record_digest"].as_str() != Some(record.digest()?.as_str())
        {
            return Ok("withheld-independent-assessment".into());
        }
        let mut cases = Vec::new();
        for input in required {
            let route = current.forecasts[&input]
                .as_ref()
                .ok_or("complete promotion lost a route")?;
            cases.push(TrialCase {
                id: format!("heldout-{input}"),
                input,
                expected: route.cost as u8,
                baseline: None,
                candidate: route.cost as u8,
            });
        }
        let bill = self.bill(current)?;
        let evidence = GraphTrialEvidence {
            evaluator: oracle.identity.clone(),
            acquisitions: current
                .receipts
                .values()
                .map(Receipt::acquisition)
                .collect::<Result<Vec<_>, _>>()?,
            training_tasks: training,
            cases,
            costs: TrialCosts {
                acquisition: bill.observation_purchase_attempts * self.price,
                verification: bill.receipt_verification_attempts * 2,
                adoption: bill.adopted_edges,
                baseline: 0,
                candidate: bill.total(self.price),
            },
        };
        let assessment = assess_graph(&record, &evidence)?;
        self.knowledge.promote_graph(record, assessment)?;
        Ok("promoted".into())
    }
    fn handle(
        &mut self,
        session: &SecureSession,
        operation: &str,
        payload: Value,
    ) -> Result<Value, String> {
        let owner = session.peer_id == self.controller;
        if self.inactive {
            return Err("incompatible participant API must remain unprobed".into());
        }
        if operation == "configure" {
            if !owner || self.current.is_some() || !self.registry.is_empty() {
                return Err("configuration is owner-only and precedes every world".into());
            }
            self.registry = serde_json::from_value(payload["registry"].clone())
                .map_err(|_| "registry configuration rejected")?;
            self.oracle = Some(
                serde_json::from_value(payload["oracle"].clone())
                    .map_err(|_| "authority endpoint configuration rejected")?,
            );
            for peer in &self.registry {
                if !peer.authorized || !peer.compatible {
                    if self.journal.denied_peers().contains(&peer.identity) {
                        continue;
                    }
                    self.journal.append(OperationalEvent::PeerDenied {
                        peer_id: peer.identity.clone(),
                        reason: if !peer.authorized {
                            "not-authorized".into()
                        } else {
                            "incompatible-schema-or-scope".into()
                        },
                    })?;
                } else {
                    let endpoint = peer
                        .endpoint
                        .as_ref()
                        .ok_or("authorized endpoint missing")?;
                    if endpoint.identity != peer.identity || endpoint.scope != SCOPE {
                        return Err("registry identity/scope mismatch".into());
                    }
                }
            }
            self.fixed_peer = self
                .registry
                .iter()
                .filter(|peer| peer.authorized && peer.compatible)
                .map(|peer| peer.identity.clone())
                .min();
            return Ok(json!({"configured":true}));
        }
        if operation == "retained-page" {
            if !owner
                || self
                    .current
                    .as_ref()
                    .is_some_and(|current| !current.finished)
            {
                return Err(
                    "offline replay requires owner and no active authority configuration".into(),
                );
            }
            let offset = payload["offset"].as_u64().unwrap_or(0) as usize;
            let route_offset = payload["route_offset"].as_u64().unwrap_or(0) as usize;
            let records = self.knowledge.active();
            if offset > records.len() {
                return Err("retained offset invalid".into());
            }
            let mut models = Vec::new();
            let mut next = None;
            if let Some(record) = records.get(offset) {
                let evidence = self
                    .knowledge
                    .graph_evidence(&record.id)
                    .ok_or("retained graph evidence missing")?;
                if route_offset > evidence.cases.len() {
                    return Err("retained route offset invalid".into());
                }
                let end = (route_offset + 8).min(evidence.cases.len());
                let mut routes = Vec::new();
                for case in &evidence.cases[route_offset..end] {
                    routes.push(
                        json!({"input":case.input,"route":record.graph_forecast(case.input)?}),
                    );
                }
                models.push(json!({"record_digest":record.digest()?,"id":record.id,"scope":record.scope,"routes":routes}));
                if end < evidence.cases.len() {
                    next = Some(json!({"offset":offset,"route_offset":end}));
                } else if offset + 1 < records.len() {
                    next = Some(json!({"offset":offset+1,"route_offset":0}));
                }
            }
            return Ok(
                json!({"identity":self.owner.identity(),"models":models,"next":next,"profiles":self.profiles(),"authority_available":self.oracle.is_some()}),
            );
        }
        if operation == "begin" {
            if !owner
                || self
                    .current
                    .as_ref()
                    .is_some_and(|current| !current.finished)
            {
                return Err("world already active or begin not owner-authorized".into());
            }
            let begin: Begin =
                serde_json::from_value(payload).map_err(|_| "world initialization rejected")?;
            let model = ExactModel::new(begin.schema, begin.algorithm)?;
            if begin.warmup_edge >= model.schema().edges.len() {
                return Err("warmup outside public graph".into());
            }
            let baseline = difference(self.server.snapshot(), session.traffic.snapshot())?;
            let mut meter = Meter::new(baseline);
            meter.counters.rpc_requests = 1;
            self.current = Some(Current {
                context: begin.context,
                model,
                warmup_edge: begin.warmup_edge,
                prelude: begin.prelude,
                warmup: None,
                receipts: BTreeMap::new(),
                assessment: None,
                advertisements: None,
                attempted: BTreeSet::new(),
                forecasts: BTreeMap::new(),
                meter,
                finished: false,
                abstention: None,
                promotion: "not-evaluated".into(),
                served: BTreeSet::new(),
                contribution_meters: Vec::new(),
                metadata_outcomes: Vec::new(),
                source_response_ambiguous: false,
            });
            *self
                .world_deadline
                .lock()
                .map_err(|_| "world deadline poisoned")? =
                Some(Instant::now() + Duration::from_secs(30));
            return Ok(json!({"begun":true}));
        }
        if !owner
            && !self
                .registry
                .iter()
                .any(|peer| peer.identity == session.peer_id && peer.authorized && peer.compatible)
        {
            return Err("operator registry does not authorize this data caller".into());
        }
        let mut current = self
            .current
            .take()
            .ok_or("native participant has no active world")?;
        current.meter.counters.rpc_requests += 1;
        let result = (|| {
            if current.finished {
                return Err("world is already finalized".into());
            }
            self.bill(&current)?
                .remaining(current.model.schema().edges.len())?;
            self.dispatch(&mut current, session, operation, payload)
        })();
        self.current = Some(current);
        result
    }
}
pub(super) fn create(bootstrap: Bootstrap, owner: Arc<Store>) -> Result<Running, String> {
    let ceilings = ["advertise", "request-edge"]
        .into_iter()
        .filter(|operation| {
            bootstrap
                .grants
                .iter()
                .any(|grant| grant.operations.iter().any(|allowed| allowed == operation))
        })
        .map(|operation| (operation.into(), 4096))
        .collect();
    let server_config = bootstrap
        .server(SCOPE)?
        .with_operation_frame_limits(ceilings)?;
    let client = bootstrap.client()?;
    let Role::Learner {
        arm,
        observation_price,
        offer_mode,
        inactive,
    } = bootstrap.role
    else {
        return Err("learner factory received authority bootstrap".into());
    };
    if ![1, 100].contains(&observation_price) || bootstrap.protocol_sha256 != PROTOCOL_SHA256 {
        return Err("learner protocol/price configuration rejected".into());
    }
    let policy_digest = body_digest(
        &json!({"protocol":PROTOCOL_SHA256,"arm":arm,"price":observation_price,"family":"unrestricted-exact-DAG/common-ingestion/v1"}),
    )?;
    if (bootstrap.state.join("operations.jsonl").exists()
        || bootstrap.state.join("operations-owner.json").exists())
        && !bootstrap.state.join("knowledge.jsonl").is_file()
    {
        return Err("HOLD: native learner knowledge ledger missing beside its registered operational history; refusing an empty replacement".into());
    }
    let journal = OperationalJournal::open(owner.clone(), owner.identity(), &policy_digest)?;
    let previous_warmup = journal
        .events()
        .iter()
        .rev()
        .find_map(|event| {
            if let OperationalEvent::SourceWarmupRetained { receipt, .. } = event {
                Some(serde_json::from_value::<Receipt>(receipt.clone()))
            } else {
                None
            }
        })
        .transpose()
        .map_err(|_| "retained source warmup cannot be decoded")?;
    let knowledge = KnowledgeStore::open(&bootstrap.state, owner.identity())?;
    let deadline = Arc::new(Mutex::new(None));
    let actor = Arc::new(Mutex::new(Actor {
        owner,
        knowledge,
        journal,
        controller: bootstrap.controller_identity,
        arm,
        price: observation_price,
        offer_mode,
        inactive,
        client,
        registry: Vec::new(),
        oracle: None,
        fixed_peer: None,
        previous_warmup,
        current: None,
        server: SecureTraffic::default(),
        world_deadline: deadline.clone(),
    }));
    let handler = actor.clone();
    let server =
        spawn_secure_server_metered(server_config, 1024, move |session, operation, payload| {
            handler
                .lock()
                .map_err(|_| "native recipient state lock poisoned")?
                .handle(session, operation, payload)
        })?;
    actor
        .lock()
        .map_err(|_| "native recipient initialization lock poisoned")?
        .server = server.traffic();
    Ok(Running {
        server,
        world_deadline: deadline,
    })
}

#[cfg(test)]
#[path = "actor_tests.rs"]
mod admission_tests;
