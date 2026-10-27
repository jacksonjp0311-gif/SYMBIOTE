//! Three owned native agents exchanging inert graph observations over mutual TLS.
//! The fixed laboratory oracle is a declared assumption, not remote honesty.
use crate::network::{
    EdgeConsent, KnowledgeEnvelope, NetworkLimits, NetworkPolicy, NetworkSnapshot, SymbioticNetwork,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use symbiote_memory::knowledge::graph::{
    assess_graph, encode_query, graph_receipt_digest, graph_schema_fingerprint, GraphAcquisition,
    GraphMap, GraphObservation, GraphTrialEvidence,
};
use symbiote_memory::knowledge::{KnowledgeRecord, KnowledgeStore, TrialCase, TrialCosts};
use symbiote_memory::Store;
use symbiote_protocol::{
    spawn_secure_server, SecureClient, SecureEndpoint, SecureLimits, SecurePeerGrant,
    SecureServerConfig, SecureTraffic, SecureTrafficSnapshot, TlsClientConfig, TlsIdentity,
};
use symbiote_reasoning::planning::{Edge, GraphSchema, RouteLearner};

const SCOPE: &str = "controlled-topology-diamond/v1";
const CONTROL_SCOPE: &str = "controlled-topology-control/v1";
const AUTHORITY: &str = "pinned-topology-laboratory/v1";
const CONTROLLER: &str = "topology-controller";
const FRAME: usize = 65_536;
const DEADLINE: Duration = Duration::from_secs(3);
const CONTROL_DEADLINE: Duration = Duration::from_secs(8);
const COSTS: [u16; 4] = [1, 1, 3, 3];
const HOLDOUT: [(usize, usize); 2] = [(1, 3), (2, 3)];
const SEEDS: [&[usize]; 3] = [&[0, 2], &[1], &[3]];
const SECURE_QUOTE: u64 = 6 * FRAME as u64;
const SECURE_BUDGET: u64 = 4 * 1024 * 1024;
fn reserve_secure(used: &mut u64) -> Result<(), String> {
    if used
        .checked_add(SECURE_QUOTE)
        .is_none_or(|total| total > SECURE_BUDGET)
    {
        return Err("aggregate secure plaintext quote budget exhausted before attempt".into());
    }
    *used += SECURE_QUOTE;
    Ok(())
}

fn hash<T: Serialize>(value: &T) -> Result<String, String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).map_err(|_| "cannot encode topology digest")?)
    ))
}
fn schema() -> GraphSchema {
    GraphSchema {
        nodes: 4,
        edges: [(0, 1), (1, 3), (0, 2), (2, 3)]
            .into_iter()
            .map(|(from, to)| Edge {
                from,
                to,
                lower: 1,
                upper: 3,
            })
            .collect(),
    }
}
fn limits() -> SecureLimits {
    SecureLimits {
        max_requests: 64,
        max_connections: 32,
        max_frame_bytes: FRAME,
        timeout: DEADLINE,
    }
}
fn write_new(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())
}
fn read_json<R: BufRead>(reader: &mut R, limit: usize) -> Result<Value, String> {
    let mut frame = Vec::new();
    loop {
        let chunk = reader
            .fill_buf()
            .map_err(|_| "topology control read failed")?;
        if chunk.is_empty() {
            return Err("topology control EOF".into());
        }
        let end = chunk.iter().position(|b| *b == b'\n');
        let count = end.map_or(chunk.len(), |n| n + 1);
        if frame.len() + count > limit {
            return Err("topology control frame exceeded".into());
        }
        frame.extend_from_slice(&chunk[..count]);
        reader.consume(count);
        if end.is_some() {
            return serde_json::from_slice(&frame)
                .map_err(|_| "invalid topology control JSON".into());
        }
    }
}
fn output(value: &Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| "topology output encoding failed")?;
    bytes.push(b'\n');
    if bytes.len() > FRAME {
        return Err("topology stdout frame exceeded".into());
    }
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&bytes)
        .and_then(|_| stdout.flush())
        .map_err(|_| "topology stdout closed".into())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Material {
    certificate: String,
    key: String,
    pin: String,
    name: String,
}
impl Material {
    fn identity(&self) -> Result<TlsIdentity, String> {
        let identity = TlsIdentity::from_pem(self.certificate.as_bytes(), self.key.as_bytes())?;
        if identity.certificate_sha256() != self.pin {
            return Err("topology credential pin mismatch".into());
        }
        Ok(identity)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    state: PathBuf,
    role: usize,
    restart: bool,
    material: Material,
    ca: String,
    controller_pin: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Peer {
    role: usize,
    id: String,
    pin: String,
    name: String,
    address: SocketAddr,
}
impl Peer {
    fn endpoint(&self, scope: &str, operations: &[&str]) -> SecureEndpoint {
        SecureEndpoint {
            server_id: self.id.clone(),
            address: self.address,
            server_name: self.name.clone(),
            server_certificate_sha256: self.pin.clone(),
            scope: scope.into(),
            operations: operations.iter().map(|s| (*s).into()).collect(),
            limits: limits(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceProof {
    schema: String,
    source: String,
    acquisitions: Vec<GraphAcquisition>,
}
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
struct Meter {
    source_warmup_oracle_calls: u64,
    validation_oracle_calls: u64,
    evaluation_oracle_calls: u64,
    explicit_learner_work: u64,
    oracle_learner_work: u64,
    library_assessment_work: u64,
    received_artifacts: u64,
    verified_observations: u64,
    adopted_edges: u64,
    fresh_promotions: u64,
    attempted_forwards: u64,
    failed_forwards: u64,
    direct_denial_probes: u64,
    predictions: u64,
    secure_plaintext_quote_bytes: u64,
}
impl Meter {
    fn total(&self, traffic: &SecureTrafficSnapshot) -> u64 {
        self.source_warmup_oracle_calls
            + self.validation_oracle_calls
            + self.evaluation_oracle_calls
            + self.explicit_learner_work
            + self.oracle_learner_work
            + self.library_assessment_work
            + self.verified_observations
            + self.adopted_edges
            + self.fresh_promotions
            + self.predictions
            + traffic.connection_attempts * 2
            + (traffic.rpc_sent_bytes
                + traffic.rpc_received_bytes
                + traffic.negotiation_sent_bytes
                + traffic.negotiation_received_bytes)
                .div_ceil(1024)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Isolated {
    oracle_calls: u64,
    learner_work: u64,
    route_cost: u64,
    heldout: Vec<Option<u8>>,
    total_work_units: u64,
}

fn observations(proof: &SourceProof) -> Vec<GraphObservation> {
    proof
        .acquisitions
        .iter()
        .map(|a| GraphObservation {
            edge_id: a.edge_id,
            cost: a.cost,
        })
        .collect()
}
fn source_record(proof: &SourceProof) -> Result<KnowledgeRecord, String> {
    Ok(KnowledgeRecord {
        id: format!("topology-source-{}", proof.source),
        revision: 1,
        source: proof.source.clone(),
        scope: SCOPE.into(),
        schema_fingerprint: graph_schema_fingerprint(&schema())?,
        payload: GraphMap::new(schema(), observations(proof))?.to_payload()?,
        provenance: serde_json::to_string(proof).map_err(|_| "source proof encoding failed")?,
    })
}
fn acquisition(source: &str, edge: usize) -> Result<GraphAcquisition, String> {
    let id = hash(
        &json!({"schema":"topology-observation-id/1","source":source,"scope":SCOPE,"edge":edge,"cost":COSTS[edge]}),
    )?;
    let receipt = json!({"schema":"symbiote.graph-observation/1","authority_id":AUTHORITY,"context":SCOPE,
        "schema_fingerprint":graph_schema_fingerprint(&schema())?,"observer_identity":source,"sequence":edge+1,
        "id":id,"edge_id":edge,"cost":COSTS[edge]});
    Ok(GraphAcquisition {
        id,
        edge_id: edge,
        cost: COSTS[edge],
        receipt_sha256: graph_receipt_digest(&receipt)?,
        receipt,
    })
}
fn learner_from(proof: &SourceProof) -> Result<RouteLearner, String> {
    let mut learner = RouteLearner::new(schema(), 100_000)?;
    for observation in &proof.acquisitions {
        learner.observe(observation.edge_id, observation.cost)?;
    }
    Ok(learner)
}
fn isolated(proof: &SourceProof) -> Result<Isolated, String> {
    let mut learner = learner_from(proof)?;
    let mut oracle_calls = proof.acquisitions.len() as u64;
    let route = loop {
        let result = learner.assess(0, 3)?;
        if let Some(route) = result.certified {
            break route;
        }
        let edge = result
            .next_observation
            .ok_or("isolated learner has no bounded frontier")?;
        if oracle_calls >= 4 {
            return Err("isolated oracle budget exhausted".into());
        }
        learner.observe(edge, COSTS[edge])?;
        oracle_calls += 1;
    };
    let mut heldout = Vec::new();
    for (start, goal) in HOLDOUT {
        heldout.push(
            learner
                .assess(start, goal)?
                .certified
                .map(|route| route.cost as u8),
        );
    }
    let learner_work = learner.model_work() as u64;
    Ok(Isolated {
        oracle_calls,
        learner_work,
        route_cost: route.cost,
        heldout,
        total_work_units: oracle_calls + learner_work,
    })
}

struct Agent {
    // Each child holds its own exclusive identity and knowledge writer leases.
    _owner: Store,
    knowledge: KnowledgeStore,
    directory: PathBuf,
    role: usize,
    id: String,
    source: SourceProof,
    quarantined: Vec<KnowledgeEnvelope>,
    peers: Vec<Peer>,
    policy: Option<NetworkPolicy>,
    armed: Option<NetworkSnapshot>,
    client: TlsClientConfig,
    traffic: SecureTraffic,
    meter: Meter,
    isolated: Isolated,
    baseline_heldout: Vec<Option<u8>>,
    revoked: BTreeSet<String>,
    tls_granted_peers: BTreeSet<String>,
}
impl Agent {
    fn open(bootstrap: &Bootstrap) -> Result<Self, String> {
        if bootstrap.role >= 3
            || bootstrap.ca.len() > 65_536
            || bootstrap.material.key.len() > 16_384
            || !bootstrap.state.is_absolute()
        {
            return Err("invalid private topology bootstrap".into());
        }
        let owner = Store::open(&bootstrap.state)?;
        let id = owner.identity().to_string();
        let knowledge = KnowledgeStore::open(&bootstrap.state, &id)?;
        let warmup_path = bootstrap.state.join("private-warmup.json");
        let mut meter = Meter::default();
        let source = if bootstrap.restart {
            let value = read_file(&warmup_path, 16_384)?;
            serde_json::from_slice::<SourceProof>(&value)
                .map_err(|_| "retained private warmup invalid")?
        } else {
            let proof = SourceProof {
                schema: "symbiote.topology-source/1".into(),
                source: id.clone(),
                acquisitions: SEEDS[bootstrap.role]
                    .iter()
                    .map(|edge| acquisition(&id, *edge))
                    .collect::<Result<Vec<_>, _>>()?,
            };
            meter.source_warmup_oracle_calls = proof.acquisitions.len() as u64;
            write_new(&warmup_path, &proof)?;
            proof
        };
        if source.schema != "symbiote.topology-source/1"
            || source.source != id
            || source
                .acquisitions
                .iter()
                .map(|a| a.edge_id)
                .collect::<Vec<_>>()
                != SEEDS[bootstrap.role]
        {
            return Err("private warmup identity or seed binding rejected".into());
        }
        let mut baseline = learner_from(&source)?;
        let mut baseline_heldout = Vec::new();
        for (start, goal) in HOLDOUT {
            baseline_heldout.push(
                baseline
                    .assess(start, goal)?
                    .certified
                    .map(|r| r.cost as u8),
            );
        }
        // Restart inference uses only persisted knowledge; this seed baseline is descriptive.
        meter.explicit_learner_work += baseline.model_work() as u64;
        let isolated = if bootstrap.restart {
            serde_json::from_slice(&read_file(
                &bootstrap.state.join("isolated-control.json"),
                4096,
            )?)
            .map_err(|_| "retained isolated control invalid")?
        } else {
            let control = isolated(&source)?;
            write_new(&bootstrap.state.join("isolated-control.json"), &control)?;
            control
        };
        let mut quarantined = Vec::new();
        let mut revoked = BTreeSet::new();
        for entry in fs::read_dir(&bootstrap.state).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("quarantine-") && name.ends_with(".json") {
                if quarantined.len() >= 8 {
                    return Err("retained topology quarantine budget exceeded".into());
                }
                quarantined.push(
                    serde_json::from_slice(&read_file(&entry.path(), 16_384)?)
                        .map_err(|_| "retained quarantine invalid")?,
                );
            }
            if name.starts_with("revoked-") && name.ends_with(".json") {
                let value: Value = serde_json::from_slice(&read_file(&entry.path(), 1024)?)
                    .map_err(|_| "retained revocation invalid")?;
                revoked.insert(
                    value["peer_id"]
                        .as_str()
                        .ok_or("retained revocation identity missing")?
                        .to_string(),
                );
            }
        }
        let client = TlsClientConfig::new(
            id.clone(),
            bootstrap.material.identity()?,
            bootstrap.ca.as_bytes(),
        )?;
        Ok(Self {
            _owner: owner,
            knowledge,
            directory: bootstrap.state.clone(),
            role: bootstrap.role,
            id,
            source,
            quarantined,
            peers: Vec::new(),
            policy: None,
            armed: None,
            client,
            traffic: SecureTraffic::default(),
            meter,
            isolated,
            baseline_heldout,
            revoked,
            tls_granted_peers: BTreeSet::new(),
        })
    }
    fn arm(&mut self, snapshot: NetworkSnapshot, pin: &str) -> Result<(), String> {
        let policy = self
            .policy
            .clone()
            .ok_or("topology policy not configured")?;
        SymbioticNetwork::open(
            policy,
            Some(snapshot.clone()),
            Some(pin),
            DEADLINE,
            Arc::new(AtomicBool::new(false)),
        )?;
        self.armed = Some(snapshot);
        Ok(())
    }
    fn receive(&mut self, peer: &str, payload: Value) -> Result<Value, String> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Delivery {
            envelope: KnowledgeEnvelope,
            prior: NetworkSnapshot,
            pin: String,
        }
        let delivery: Delivery =
            serde_json::from_value(payload).map_err(|_| "invalid inert topology delivery")?;
        let envelope = delivery.envelope;
        envelope.validate()?;
        let armed = self
            .armed
            .as_ref()
            .ok_or("destination has no independent controller snapshot pin")?;
        if delivery.prior != *armed
            || delivery.pin != armed.sha256
            || envelope.record.scope != SCOPE
            || envelope.route.last() != Some(&self.id)
            || envelope.route.len() < 2
            || envelope.route[envelope.route.len() - 2] != peer
            || self.revoked.contains(peer)
        {
            return Err(
                "topology delivery custody, scope or independently pinned prefix rejected".into(),
            );
        }
        // Authentication identifies the current sender; it does not grant this
        // particular directed transfer. Admission is independently decided here.
        let policy = self
            .policy
            .as_ref()
            .ok_or("receiver operator policy missing")?;
        let key = (
            peer.to_string(),
            self.id.clone(),
            envelope.record.scope.clone(),
        );
        if !policy.edges.iter().any(|edge| {
            edge.source == peer
                && edge.destination == self.id
                && edge.scope == envelope.record.scope
                && edge.source_granted
                && edge.destination_granted
        }) || armed.revoked.contains(&key)
        {
            return Err(
                "receiver denies absent, unilateral or revoked immediate edge consent".into(),
            );
        }
        self.arm(delivery.prior.clone(), &delivery.pin)?;
        for length in 2..envelope.route.len() {
            let mut prefix = envelope.clone();
            prefix.route.truncate(length);
            let digest = hash(&prefix)?;
            if !delivery.prior.receipts.iter().any(|receipt| {
                receipt.outcome == "delivered-inert"
                    && receipt.envelope_sha256 == digest
                    && receipt.record_sha256 == envelope.record.digest().unwrap_or_default()
            }) {
                return Err("receiver lacks actual preceding successful custody receipt".into());
            }
        }
        if self.quarantined.len() >= 8
            || self
                .quarantined
                .iter()
                .any(|known| known.record.digest().ok() == envelope.record.digest().ok())
        {
            return Err("duplicate or excessive topology artifact quarantine".into());
        }
        // Durable inert custody precedes oracle validation, model update and promotion.
        write_new(
            &self
                .directory
                .join(format!("quarantine-{:02}.json", self.quarantined.len())),
            &envelope,
        )?;
        let digest = hash(&envelope)?;
        self.quarantined.push(envelope);
        self.meter.received_artifacts += 1;
        self.armed = None;
        Ok(
            json!({"quarantined":true,"receiver_pid":std::process::id(),"receiver_identity":self.id,
            "authenticated_source":peer,"envelope_sha256":digest,"promoted":false}),
        )
    }
    fn envelope(&self, origin: &str) -> Result<KnowledgeEnvelope, String> {
        if origin == self.id {
            return KnowledgeEnvelope::local(source_record(&self.source)?, &self.id);
        }
        self.quarantined
            .iter()
            .find(|env| env.claimed_origin == origin)
            .cloned()
            .ok_or_else(|| "source does not hold requested inert artifact".into())
    }
    fn send(&mut self, payload: &Value) -> Result<Value, String> {
        let destination = payload["destination"]
            .as_str()
            .ok_or("destination missing")?;
        let origin = payload["origin"].as_str().ok_or("origin missing")?;
        let prior: NetworkSnapshot = serde_json::from_value(payload["prior"].clone())
            .map_err(|_| "source snapshot missing")?;
        let pin = payload["pin"]
            .as_str()
            .ok_or("source external pin missing")?;
        let policy = self.policy.clone().ok_or("topology policy missing")?;
        let mut network = SymbioticNetwork::open(
            policy,
            Some(prior.clone()),
            Some(pin),
            DEADLINE,
            Arc::new(AtomicBool::new(false)),
        )?;
        let envelope = self.envelope(origin)?;
        let peer = self
            .peers
            .iter()
            .find(|peer| peer.id == destination)
            .ok_or("operator endpoint not configured")?;
        let mut endpoint = peer.endpoint(SCOPE, &["knowledge.receive"]);
        if payload["fail_connection"] == true {
            let unused =
                TcpListener::bind("127.0.0.1:0").map_err(|_| "failure-control port unavailable")?;
            endpoint.address = unused
                .local_addr()
                .map_err(|_| "failure-control port invalid")?;
            drop(unused);
        }
        self.meter.attempted_forwards += 1;
        let client_config = self.client.clone();
        let traffic = self.traffic.clone();
        let mut acknowledgment = Value::Null;
        let owner_id = self.id.clone();
        let quote = &mut self.meter.secure_plaintext_quote_bytes;
        let result = network.forward(
            &self.id,
            destination,
            &envelope,
            |forwarded, deadline, cancelled| {
                if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                    return Err("source send cancelled".into());
                }
                reserve_secure(quote)?;
                // Reserve one eighth of the remaining hop deadline for each
                // blocking connect, handshake, negotiation and RPC frame stage.
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining < Duration::from_millis(8) {
                    return Err("source absolute hop deadline exhausted".into());
                }
                endpoint.limits.timeout = (remaining / 8).min(DEADLINE);
                let mut client =
                    SecureClient::connect_with_metering(&endpoint, &client_config, traffic, FRAME)?;
                let response = client.call(
                    "knowledge.receive",
                    &json!({"envelope":forwarded,"prior":prior,"pin":pin}),
                );
                let revoked = client.revoke();
                let value = response?;
                revoked?;
                if value["quarantined"] != true
                    || value["authenticated_source"] != owner_id
                    || value["envelope_sha256"] != hash(forwarded)?
                {
                    return Err("destination custody acknowledgment mismatch".into());
                }
                acknowledgment = value;
                Ok(())
            },
        );
        if result.is_err() {
            self.meter.failed_forwards += 1;
        }
        Ok(
            json!({"delivered":result.is_ok(),"failure":result.as_ref().err(),"receipt":result.ok(),
            "snapshot":network.snapshot()?,"acknowledgment":acknowledgment,"source_pid":std::process::id(),"source_identity":self.id}),
        )
    }
    fn direct_probe(&mut self, destination: &str) -> Result<Value, String> {
        let peer = self
            .peers
            .iter()
            .find(|peer| peer.id == destination)
            .ok_or("probe endpoint not configured")?;
        self.meter.direct_denial_probes += 1;
        reserve_secure(&mut self.meter.secure_plaintext_quote_bytes)?;
        let result = SecureClient::connect_with_metering(
            &peer.endpoint(SCOPE, &["knowledge.receive"]),
            &self.client,
            self.traffic.clone(),
            FRAME,
        );
        match result {
            Ok(mut client) => {
                client.cancel()?;
                Ok(
                    json!({"tls_denied":false,"connected":true,"admission_verdict":"UNEXPECTEDLY_CONNECTED",
                        "delivery_attempted":false,"source_pid":std::process::id(),"source_identity":self.id}),
                )
            }
            Err(error) => {
                let classification = if error.starts_with("secure transport I/O:") {
                    "transport-connect-or-handshake-failure"
                } else {
                    "configuration-identity-or-negotiation-failure"
                };
                Ok(
                    json!({"tls_denied":false,"connected":false,"admission_verdict":"HOLD_UNVERIFIED_CONNECT_FAILURE",
                    "connect_error":error.chars().take(1024).collect::<String>(),"failure_class":classification,
                    "delivery_attempted":false,"source_pid":std::process::id(),"source_identity":self.id}),
                )
            }
        }
    }
    fn adopt(&mut self) -> Result<Value, String> {
        if !self.knowledge.active().is_empty() {
            return Err("fresh topology promotion refuses existing active knowledge".into());
        }
        let mut by_edge = BTreeMap::new();
        for acquisition in &self.source.acquisitions {
            by_edge.insert(acquisition.edge_id, acquisition.clone());
        }
        let mut origins = Vec::new();
        for envelope in &self.quarantined {
            let proof: SourceProof = serde_json::from_str(&envelope.record.provenance)
                .map_err(|_| "inert source proof invalid")?;
            let peer = self
                .peers
                .iter()
                .find(|peer| peer.id == proof.source)
                .ok_or("unrecognized original source")?;
            if proof.schema != "symbiote.topology-source/1"
                || proof.source != envelope.claimed_origin
                || envelope.record != source_record(&proof)?
                || proof
                    .acquisitions
                    .iter()
                    .map(|a| a.edge_id)
                    .collect::<Vec<_>>()
                    != SEEDS[peer.role]
            {
                return Err("inert source proof provenance or seed ownership rejected".into());
            }
            for acquisition in &proof.acquisitions {
                self.meter.validation_oracle_calls += 1;
                if acquisition.edge_id >= COSTS.len()
                    || *acquisition != crate_acquisition(&proof.source, acquisition.edge_id)?
                {
                    return Err(
                        "independent pinned local oracle rejected received observation".into(),
                    );
                }
                if by_edge
                    .insert(acquisition.edge_id, acquisition.clone())
                    .is_some()
                {
                    return Err("overlapping source observations rejected".into());
                }
                self.meter.verified_observations += 1;
            }
            origins.push(envelope.record.digest()?);
        }
        if by_edge.len() != 4 {
            return Err("topology adoption needs all independently checked edges".into());
        }
        let acquisitions = by_edge.into_values().collect::<Vec<_>>();
        let proof = SourceProof {
            schema: "symbiote.topology-source/1".into(),
            source: self.id.clone(),
            acquisitions: acquisitions.clone(),
        };
        let mut learner = learner_from(&proof)?;
        let mut cases = Vec::new();
        let mut per_pass_work = 0_u64;
        for (index, (start, goal)) in HOLDOUT.into_iter().enumerate() {
            let route = learner
                .assess(start, goal)?
                .certified
                .ok_or("candidate heldout route not certified")?;
            self.meter.evaluation_oracle_calls += 1;
            let mut oracle = RouteLearner::new(schema(), 100_000)?;
            for (edge, cost) in COSTS.into_iter().enumerate() {
                oracle.observe(edge, cost)?;
            }
            let expected = oracle
                .assess(start, goal)?
                .certified
                .ok_or("local oracle failed")?
                .cost as u8;
            self.meter.oracle_learner_work += oracle.model_work() as u64;
            let mut independent = learner_from(&proof)?;
            independent.assess(start, goal)?;
            per_pass_work += independent.model_work() as u64;
            cases.push(TrialCase {
                id: format!("topology-heldout-{index}"),
                input: encode_query(4, start, goal)?,
                expected,
                baseline: self.baseline_heldout[index],
                candidate: route.cost as u8,
            });
        }
        self.meter.explicit_learner_work += learner.model_work() as u64;
        // assess_graph + promote_graph's independent validation each forecast every case.
        self.meter.library_assessment_work += 2 * per_pass_work;
        self.meter.adopted_edges =
            acquisitions.len() as u64 - self.source.acquisitions.len() as u64;
        let record=KnowledgeRecord {id:"topology-diamond-route-map".into(),revision:1,source:"topology-local-synthesis".into(),scope:SCOPE.into(),
            schema_fingerprint:graph_schema_fingerprint(&schema())?,payload:GraphMap::new(schema(),observations(&proof))?.to_payload()?,
            provenance:serde_json::to_string(&json!({"source_records":origins,"own_source":self.id,"oracle_assumption":AUTHORITY})).map_err(|_|"provenance encoding failed")?};
        let traffic = self.traffic.snapshot();
        let acquisition_cost = self.meter.source_warmup_oracle_calls;
        let verification = self.meter.validation_oracle_calls
            + self.meter.evaluation_oracle_calls
            + self.meter.oracle_learner_work
            + self.meter.explicit_learner_work
            + self.meter.library_assessment_work
            + self.meter.verified_observations;
        let adoption = self.meter.adopted_edges + 1;
        let evidence = GraphTrialEvidence {
            evaluator: self.id.clone(),
            acquisitions,
            training_tasks: Vec::new(),
            cases,
            costs: TrialCosts {
                acquisition: acquisition_cost,
                verification,
                adoption,
                baseline: self.isolated.total_work_units,
                candidate: acquisition_cost
                    + verification
                    + adoption
                    + traffic.connection_attempts * 2
                    + (traffic.rpc_sent_bytes
                        + traffic.rpc_received_bytes
                        + traffic.negotiation_sent_bytes
                        + traffic.negotiation_received_bytes)
                        .div_ceil(1024),
            },
        };
        let assessment = assess_graph(&record, &evidence)?;
        let assessment_json =
            serde_json::to_value(&assessment).map_err(|_| "assessment encoding failed")?;
        self.knowledge.promote_graph(record, assessment)?;
        self.meter.fresh_promotions += 1;
        write_new(
            &self.directory.join("local-adoption.json"),
            &json!({"assessment":assessment_json,"evidence":evidence,"pid":std::process::id(),"owner":self.id}),
        )?;
        Ok(
            json!({"assessment":assessment_json,"fresh_promotion":true,"history_anchor":self.knowledge.history_anchor(),"identity":self.id,"pid":std::process::id()}),
        )
    }
    fn status(&mut self) -> Result<Value, String> {
        let active = self.knowledge.active();
        let mut predictions = Vec::new();
        if let Some(record) = active.first() {
            for (start, goal) in HOLDOUT {
                let value = record.predict_if_certified(encode_query(4, start, goal)?)?;
                let map: GraphMap = match record.typed_payload()? {
                    symbiote_memory::knowledge::KnowledgePayload::GraphMap(map) => map,
                    _ => return Err("retained topology payload changed kind".into()),
                };
                let mut model = RouteLearner::new(map.schema.clone(), 100_000)?;
                for observation in map.observations {
                    model.observe(observation.edge_id, observation.cost)?;
                }
                model.assess(start, goal)?;
                self.meter.explicit_learner_work += model.model_work() as u64;
                // Both retained forecast and independently metered forecast were actually computed.
                self.meter.explicit_learner_work += model.model_work() as u64;
                self.meter.predictions += 1;
                predictions.push(value);
            }
        }
        Ok(
            json!({"role":self.role,"identity":self.id,"pid":std::process::id(),"meter":self.meter,
            "outgoing_tls_traffic":self.traffic.snapshot(),"explicit_work_units":self.meter.total(&self.traffic.snapshot()),
            "isolated_adaptive_control":self.isolated,"preexchange_heldout":self.baseline_heldout,"retained_predictions":predictions,
            "knowledge_records":self.knowledge.record_count(),"history_anchor":self.knowledge.history_anchor(),
            "quarantined":self.quarantined.len(),"revoked_peers":self.revoked}),
        )
    }
}
fn crate_acquisition(source: &str, edge: usize) -> Result<GraphAcquisition, String> {
    acquisition(source, edge)
}
fn read_file(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| "topology retained file missing")?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "topology retained file read failed")?;
    if bytes.len() > limit {
        return Err("topology retained file byte budget exceeded".into());
    }
    Ok(bytes)
}

pub fn serve_from_stdin() -> Result<(), String> {
    let result = serve_inner();
    if let Err(error) = &result {
        // Stage codes are useful diagnostics; bootstrap/key/JSON values never reach stderr.
        let stage = if error.contains("bootstrap") || error.contains("credential") {
            "bootstrap"
        } else if error.contains("TLS") || error.contains("secure") {
            "secure-transport"
        } else if error.contains("knowledge")
            || error.contains("retained")
            || error.contains("writer")
        {
            "durable-state"
        } else if error.contains("control") || error.contains("stdout") {
            "process-control"
        } else {
            "evaluation-or-policy"
        };
        eprintln!("SYMBIOTE topology child failure: stage={stage}");
    }
    result
}
fn serve_inner() -> Result<(), String> {
    let mut stdin = BufReader::new(std::io::stdin());
    let bootstrap: Bootstrap = serde_json::from_value(read_json(&mut stdin, FRAME)?)
        .map_err(|_| "private topology bootstrap rejected")?;
    let agent = Arc::new(Mutex::new(Agent::open(&bootstrap)?));
    let id = agent
        .lock()
        .map_err(|_| "topology owner lock poisoned")?
        .id
        .clone();
    output(&json!({"ready_identity":id,"pid":std::process::id(),"role":bootstrap.role}))?;
    let mut server: Option<symbiote_protocol::SecureServerHandle> = None;
    let listener_instance = symbiote_protocol::fresh_capability()?;
    let mut operations = 0_usize;
    loop {
        let value = match read_json(&mut stdin, FRAME) {
            Ok(value) => value,
            Err(error) if error == "topology control EOF" => break,
            Err(error) => return Err(error),
        };
        operations += 1;
        if operations > 128 {
            return Err("topology control operation budget exhausted".into());
        }
        let operation = value["operation"]
            .as_str()
            .ok_or("control operation missing")?;
        if operation == "stop" {
            if let Some(server) = server.as_mut() {
                server.shutdown()?;
            }
            output(&json!({"stopped":true,"pid":std::process::id()}))?;
            break;
        }
        let result = (|| -> Result<Value, String> {
            if operation == "configure" {
                if server.is_some() {
                    return Err("topology server already configured".into());
                }
                let peers: Vec<Peer> = serde_json::from_value(value["peers"].clone())
                    .map_err(|_| "public peers invalid")?;
                let policy: NetworkPolicy = serde_json::from_value(value["policy"].clone())
                    .map_err(|_| "network policy invalid")?;
                policy.validate()?;
                if peers.len() != 3
                    || peers.iter().map(|peer| peer.role).collect::<BTreeSet<_>>()
                        != BTreeSet::from([0, 1, 2])
                    || peers
                        .iter()
                        .any(|peer| peer.role >= 3 || !peer.address.ip().is_loopback())
                {
                    return Err("operator peer inventory invalid".into());
                }
                let mut grants = vec![SecurePeerGrant {
                    id: CONTROLLER.into(),
                    certificate_sha256: bootstrap.controller_pin.clone(),
                    scopes: BTreeMap::from([(CONTROL_SCOPE.into(), vec!["control.status".into()])]),
                }];
                for peer in &peers {
                    if peer.role.abs_diff(bootstrap.role) == 1
                        && policy.edges.iter().any(|edge| {
                            edge.source == peer.id
                                && edge.destination == id
                                && edge.scope == SCOPE
                                && edge.source_granted
                                && edge.destination_granted
                        })
                    {
                        grants.push(SecurePeerGrant {
                            id: peer.id.clone(),
                            certificate_sha256: peer.pin.clone(),
                            scopes: BTreeMap::from([(
                                SCOPE.into(),
                                vec!["knowledge.receive".into()],
                            )]),
                        });
                    }
                }
                let granted_peer_ids = grants
                    .iter()
                    .filter(|grant| grant.id != CONTROLLER)
                    .map(|grant| grant.id.clone())
                    .collect();
                let config = SecureServerConfig::new(
                    "127.0.0.1:0"
                        .parse()
                        .map_err(|_| "loopback address invalid")?,
                    id.clone(),
                    bootstrap.material.identity()?,
                    bootstrap.ca.as_bytes(),
                    grants,
                    limits(),
                )?;
                {
                    let mut state = agent.lock().map_err(|_| "topology owner lock poisoned")?;
                    state.peers = peers;
                    state.policy = Some(policy);
                    state.tls_granted_peers = granted_peer_ids;
                }
                let owned = Arc::clone(&agent);
                let current_instance = listener_instance.clone();
                let handle = spawn_secure_server(config, move |session, operation, payload| {
                    let mut owner = owned.lock().map_err(|_| "topology owner lock poisoned")?;
                    match (session.scope.as_str(), operation) {
                        (CONTROL_SCOPE, "control.status") if session.peer_id == CONTROLLER => Ok(
                            json!({"identity":owner.id,"pid":std::process::id(),"role":owner.role,"listener_instance":current_instance}),
                        ),
                        (SCOPE, "knowledge.receive") => owner.receive(&session.peer_id, payload),
                        _ => Err("topology dispatch outside negotiated authority".into()),
                    }
                })?;
                for revoked in &agent
                    .lock()
                    .map_err(|_| "topology owner lock poisoned")?
                    .revoked
                {
                    handle.revoke_peer(revoked)?;
                }
                let address = handle.address();
                server = Some(handle);
                return Ok(json!({"address":address,"identity":id,"pid":std::process::id()}));
            }
            if operation == "revoke-peer" {
                let peer = value["peer"].as_str().ok_or("revoked peer missing")?;
                let handle = server.as_ref().ok_or("TLS server missing")?;
                handle.revoke_peer(peer)?;
                let mut state = agent.lock().map_err(|_| "topology owner lock poisoned")?;
                write_new(
                    &state
                        .directory
                        .join(format!("revoked-{}.json", hash(&peer)?)),
                    &json!({"peer_id":peer}),
                )?;
                state.revoked.insert(peer.into());
                return Ok(json!({"revoked":true,"peer":peer}));
            }
            let mut state = agent.lock().map_err(|_| "topology owner lock poisoned")?;
            match operation {
                "peers" => {
                    state.peers = serde_json::from_value(value["peers"].clone())
                        .map_err(|_| "public endpoints invalid")?;
                    Ok(json!({"configured":true}))
                }
                "arm" => {
                    let prior = serde_json::from_value(value["prior"].clone())
                        .map_err(|_| "destination snapshot invalid")?;
                    state.arm(
                        prior,
                        value["pin"]
                            .as_str()
                            .ok_or("destination external pin missing")?,
                    )?;
                    Ok(json!({"armed":true}))
                }
                "send" => state.send(&value),
                "direct-probe" => state.direct_probe(
                    value["destination"]
                        .as_str()
                        .ok_or("probe destination missing")?,
                ),
                "adopt" => state.adopt(),
                "admission-status" => {
                    let handle = server.as_ref().ok_or("TLS server missing")?;
                    Ok(
                        json!({"identity":state.id,"pid":std::process::id(),"listener_instance":listener_instance,
                        "operator_policy_sha256":hash(state.policy.as_ref().ok_or("operator policy missing")?)?,
                        "armed_snapshot_sha256":state.armed.as_ref().map(|snapshot|snapshot.sha256.clone()),
                        "armed_revocations":state.armed.as_ref().map(|snapshot|snapshot.revoked.clone()),
                        "granted_peer_ids":state.tls_granted_peers,"revoked_peer_ids":state.revoked,
                        "session_failures":handle.session_failures(),"last_failure":handle.last_failure(),
                        "connection_count":handle.connection_count(),"quarantined":state.quarantined.len()}),
                    )
                }
                "status" => {
                    let mut status = state.status()?;
                    let handle = server.as_ref().ok_or("TLS server missing")?;
                    status["incoming_tls_traffic"] = json!(handle.traffic().snapshot());
                    status["tls_session_failures"] = json!(handle.session_failures());
                    Ok(status)
                }
                _ => Err("unknown topology control operation".into()),
            }
        })();
        match result {
            Ok(value) => output(&json!({"ok":true,"result":value}))?,
            Err(error) => output(&json!({"ok":false,"error":error}))?,
        }
    }
    if let Some(server) = server.as_mut() {
        server.shutdown()?;
    }
    Ok(())
}

struct OwnedProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    replies: mpsc::Receiver<Result<Value, String>>,
    reader: Option<JoinHandle<()>>,
    stderr_reader: Option<JoinHandle<()>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    sent: u64,
    received: u64,
    stopped: bool,
    id: String,
    pid: u32,
}
impl OwnedProcess {
    fn spawn(bootstrap: &Bootstrap) -> Result<Self, String> {
        let mut child =
            Command::new(std::env::current_exe().map_err(|_| "current native executable missing")?)
                .arg("__topology-agent")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|_| "owned topology child startup failed")?;
        let pid = child.id();
        let stdin = child
            .stdin
            .take()
            .ok_or("owned topology child stdin missing")?;
        let stdout = child
            .stdout
            .take()
            .ok_or("owned topology child stdout missing")?;
        let mut child_stderr = child
            .stderr
            .take()
            .ok_or("owned topology child stderr missing")?;
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&stderr);
        let stderr_reader = thread::spawn(move || {
            let mut buffer = [0_u8; 512];
            while let Ok(count) = child_stderr.read(&mut buffer) {
                if count == 0 {
                    break;
                }
                if let Ok(mut bytes) = captured.lock() {
                    let retained = count.min(4096_usize.saturating_sub(bytes.len()));
                    bytes.extend_from_slice(&buffer[..retained]);
                }
            }
        });
        let (send, replies) = mpsc::sync_channel(4);
        let reader = thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let result = read_json(&mut reader, FRAME);
                let done = result.is_err();
                if send.try_send(result).is_err() || done {
                    break;
                }
            }
        });
        let mut process = Self {
            child,
            stdin: Some(stdin),
            replies,
            reader: Some(reader),
            stderr_reader: Some(stderr_reader),
            stderr,
            sent: 0,
            received: 0,
            stopped: false,
            id: String::new(),
            pid,
        };
        process.write(
            &serde_json::to_value(bootstrap).map_err(|_| "private bootstrap encoding rejected")?,
        )?;
        let ready = process.read()?;
        process.id = ready["ready_identity"]
            .as_str()
            .ok_or("owned child failed to establish persistent identity")?
            .to_string();
        if ready["pid"].as_u64() != Some(pid as u64)
            || ready["role"].as_u64() != Some(bootstrap.role as u64)
        {
            return Err("owned child PID or role mismatch".into());
        }
        Ok(process)
    }
    fn write(&mut self, value: &Value) -> Result<(), String> {
        let mut bytes = serde_json::to_vec(value).map_err(|_| "control encoding failed")?;
        bytes.push(b'\n');
        if bytes.len() > FRAME {
            return Err("controller outbound frame budget exceeded".into());
        }
        self.sent += bytes.len() as u64;
        let mut stdin = self.stdin.take().ok_or("owned child stdin closed")?;
        let (send, receive) = mpsc::sync_channel(1);
        let writer = thread::spawn(move || {
            let result = stdin
                .write_all(&bytes)
                .and_then(|_| stdin.flush())
                .map_err(|_| "owned child stdin write failed".to_string());
            let _ = send.send((stdin, result));
        });
        match receive.recv_timeout(CONTROL_DEADLINE) {
            Ok((stdin, result)) => {
                self.stdin = Some(stdin);
                writer
                    .join()
                    .map_err(|_| "owned child control writer panicked")?;
                result
            }
            Err(_) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                let _ = writer.join();
                Err("owned child control write deadline exceeded".into())
            }
        }
    }
    fn read(&mut self) -> Result<Value, String> {
        let value = self
            .replies
            .recv_timeout(CONTROL_DEADLINE)
            .map_err(|_| {
                format!(
                    "owned child operation deadline exceeded; {}",
                    self.diagnostics()
                )
            })?
            .map_err(|error| format!("{error}; {}", self.diagnostics()))?;
        self.received += serde_json::to_vec(&value)
            .map_err(|_| "control reply encoding failed")?
            .len() as u64
            + 1;
        if self.sent > 128 * FRAME as u64 || self.received > 128 * FRAME as u64 {
            return Err("owned child aggregate control byte budget exceeded".into());
        }
        Ok(value)
    }
    fn call(&mut self, value: Value) -> Result<Value, String> {
        self.write(&value)?;
        let response = self.read()?;
        if response["ok"] != true {
            return Err(response["error"]
                .as_str()
                .unwrap_or("owned child control rejected")
                .to_string());
        }
        Ok(response["result"].clone())
    }
    fn stop(&mut self) -> Result<(), String> {
        if self.stopped {
            return Ok(());
        }
        self.write(&json!({"operation":"stop"}))?;
        let reply = self.read()?;
        if reply["stopped"] != true {
            return Err("owned child did not acknowledge shutdown".into());
        }
        self.stdin.take();
        let deadline = Instant::now() + CONTROL_DEADLINE;
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|_| "owned child join failed")?
            {
                if !status.success() {
                    return Err("owned child exited unsuccessfully".into());
                }
                break;
            }
            if Instant::now() >= deadline {
                return Err("owned child cleanup deadline exceeded".into());
            }
            thread::sleep(Duration::from_millis(5));
        }
        if let Some(reader) = self.reader.take() {
            reader
                .join()
                .map_err(|_| "owned child stdout reader panicked")?;
        }
        if let Some(reader) = self.stderr_reader.take() {
            reader
                .join()
                .map_err(|_| "owned child stderr reader panicked")?;
        }
        self.stopped = true;
        Ok(())
    }
    fn diagnostics(&self) -> Value {
        let bytes = self
            .stderr
            .lock()
            .map(|bytes| bytes.clone())
            .unwrap_or_default();
        json!({"child_pid":self.pid,"stderr_captured_bytes":bytes.len(),"redacted_diagnostic":safe_stderr(&bytes)})
    }
}
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self.child.kill();
            self.stdin.take();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }
}
fn safe_stderr(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut safe = Vec::new();
    let mut withheld = false;
    for line in text.lines() {
        let stage = line.strip_prefix("SYMBIOTE topology child failure: stage=");
        if stage.is_some_and(|stage| {
            [
                "bootstrap",
                "secure-transport",
                "durable-state",
                "process-control",
                "evaluation-or-policy",
            ]
            .contains(&stage)
        }) || line
            == "SYMBIOTE topology participant stopped; private bootstrap contents are withheld."
        {
            safe.push(line);
        } else if !line.trim().is_empty() {
            withheld = true;
        }
    }
    if withheld {
        safe.push("[other child diagnostics withheld]");
    }
    safe.join("; ")
}

fn pki() -> Result<(String, Vec<Material>), String> {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|_| "laboratory CA configuration failed")?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let key = KeyPair::generate().map_err(|_| "laboratory CA key generation failed")?;
    let certificate = params
        .self_signed(&key)
        .map_err(|_| "laboratory CA signing failed")?;
    let issuer = rcgen::Issuer::from_params(&params, key);
    let mut materials = Vec::new();
    for role in [
        "topology-a",
        "topology-b",
        "topology-c",
        "topology-controller",
    ] {
        let name = format!("{role}.symbiote.test");
        let mut params = CertificateParams::new(vec![name.clone()])
            .map_err(|_| "laboratory identity configuration failed")?;
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate().map_err(|_| "laboratory identity key generation failed")?;
        let cert = params
            .signed_by(&key, &issuer)
            .map_err(|_| "laboratory identity signing failed")?;
        let certificate = cert.pem();
        let key = key.serialize_pem();
        let pin = TlsIdentity::from_pem(certificate.as_bytes(), key.as_bytes())?
            .certificate_sha256()
            .to_string();
        materials.push(Material {
            certificate,
            key,
            pin,
            name,
        });
    }
    Ok((certificate.pem(), materials))
}
fn policy(ids: &[String]) -> NetworkPolicy {
    NetworkPolicy {
        schema: "symbiote.network-policy/1".into(),
        coordinator: CONTROLLER.into(),
        edges: [(0, 1), (1, 0), (1, 2), (2, 1)]
            .into_iter()
            .map(|(source, destination)| EdgeConsent {
                source: ids[source].clone(),
                destination: ids[destination].clone(),
                scope: SCOPE.into(),
                source_granted: true,
                destination_granted: true,
                epoch: 1,
            })
            .collect(),
        limits: NetworkLimits {
            attempts: 7,
            payload_bytes: 16_384,
            total_bytes: 7 * 16_384,
            hops: 2,
        },
    }
}
fn configure(
    children: &mut [OwnedProcess],
    materials: &[Material],
    policy: &NetworkPolicy,
) -> Result<Vec<Peer>, String> {
    let mut peers = children
        .iter()
        .enumerate()
        .map(|(role, child)| Peer {
            role,
            id: child.id.clone(),
            pin: materials[role].pin.clone(),
            name: materials[role].name.clone(),
            address: "127.0.0.1:0".parse().expect("static loopback"),
        })
        .collect::<Vec<_>>();
    for (index, child) in children.iter_mut().enumerate() {
        let response =
            child.call(json!({"operation":"configure","peers":peers,"policy":policy}))?;
        peers[index].address = serde_json::from_value(response["address"].clone())
            .map_err(|_| "child loopback endpoint invalid")?;
        if !peers[index].address.ip().is_loopback() || peers[index].address.port() == 0 {
            return Err("child returned non-loopback endpoint".into());
        }
    }
    for child in children {
        child.call(json!({"operation":"peers","peers":peers}))?;
    }
    Ok(peers)
}
fn persist_snapshot(
    state: &Path,
    receipts: &Path,
    number: usize,
    snapshot: &NetworkSnapshot,
) -> Result<(), String> {
    write_new(
        &receipts.join(format!("network-snapshot-{number:02}.json")),
        snapshot,
    )?;
    // Independent controller anchor is deliberately outside all participant owner stores.
    write_new(
        &state.join(format!("controller-network-anchor-{number:02}.json")),
        &json!({"snapshot_sha256":snapshot.sha256,"snapshot_file":format!("network-snapshot-{number:02}.json"),"receipt_count":snapshot.receipts.len()}),
    )
}
fn validate_next(
    policy: &NetworkPolicy,
    prior: &NetworkSnapshot,
    value: &Value,
    delivered: bool,
) -> Result<NetworkSnapshot, String> {
    let next: NetworkSnapshot = serde_json::from_value(value["snapshot"].clone())
        .map_err(|_| "source did not return full network snapshot")?;
    SymbioticNetwork::open(
        policy.clone(),
        Some(next.clone()),
        Some(&next.sha256),
        DEADLINE,
        Arc::new(AtomicBool::new(false)),
    )?;
    if next.receipts.len() != prior.receipts.len() + 1
        || next.receipts[..prior.receipts.len()] != prior.receipts
        || next.schema != prior.schema
        || next.policy_sha256 != prior.policy_sha256
        || next.revoked != prior.revoked
        || value["delivered"] != delivered
        || next.receipts.last().is_none_or(|receipt| {
            receipt.outcome
                != if delivered {
                    "delivered-inert"
                } else {
                    "delivery-unknown"
                }
        })
    {
        return Err("actual forward receipt does not extend independently retained prefix".into());
    }
    Ok(next)
}
fn run_hop(
    children: &mut [OwnedProcess],
    source: usize,
    destination: usize,
    origin: usize,
    prior: &NetworkSnapshot,
    fail: bool,
) -> Result<Value, String> {
    let source_id = children[source].id.clone();
    let destination_id = children[destination].id.clone();
    let origin_id = children[origin].id.clone();
    children[destination].call(json!({"operation":"arm","prior":prior,"pin":prior.sha256}))?;
    let result = children[source].call(
        json!({"operation":"send","destination":destination_id,"origin":origin_id,
        "prior":prior,"pin":prior.sha256,"fail_connection":fail}),
    )?;
    if result["source_pid"].as_u64() != Some(children[source].pid as u64)
        || result["source_identity"] != source_id
    {
        return Err("source child did not own the actual transmission".into());
    }
    if result["delivered"] == true
        && (result["acknowledgment"]["receiver_pid"].as_u64()
            != Some(children[destination].pid as u64)
            || result["acknowledgment"]["authenticated_source"] != source_id)
    {
        return Err(
            "authenticated custody acknowledgment belongs to wrong native participant".into(),
        );
    }
    Ok(result)
}

struct ProbeTransport<'a> {
    client: &'a TlsClientConfig,
    traffic: SecureTraffic,
    quotes: &'a mut u64,
}
fn live_control(
    peer: &Peer,
    expected_pid: u32,
    transport: &mut ProbeTransport<'_>,
) -> Result<Value, String> {
    reserve_secure(transport.quotes)?;
    let mut client = SecureClient::connect_with_metering(
        &peer.endpoint(CONTROL_SCOPE, &["control.status"]),
        transport.client,
        transport.traffic.clone(),
        FRAME,
    )
    .map_err(|error| format!("HOLD: live destination control TLS unavailable: {error}"))?;
    let status = client
        .call("control.status", &Value::Null)
        .map_err(|error| format!("HOLD: live destination status unavailable: {error}"))?;
    client.revoke()?;
    if status["identity"] != peer.id
        || status["pid"].as_u64() != Some(expected_pid as u64)
        || status["listener_instance"]
            .as_str()
            .is_none_or(|instance| instance.len() != 64)
    {
        return Err(
            "HOLD: live destination TLS returned wrong owned PID or listener instance".into(),
        );
    }
    Ok(status)
}
fn verify_denial(
    peer: &Peer,
    source: &str,
    expected_pid: u32,
    prior: &NetworkSnapshot,
    policy: &NetworkPolicy,
    observations: &Value,
    reason: &str,
) -> Result<Value, String> {
    let live_before = &observations["live_before"];
    let live_after = &observations["live_after"];
    let before = &observations["receiver_before"];
    let after = &observations["receiver_after"];
    let probe = &observations["source_probe"];
    let instance = live_before["listener_instance"]
        .as_str()
        .ok_or("HOLD: missing live TLS listener identity before denial")?;
    if instance.len() != 64
        || live_after["listener_instance"] != instance
        || live_before["identity"] != peer.id
        || live_after["identity"] != peer.id
        || live_before["pid"].as_u64() != Some(expected_pid as u64)
        || live_after["pid"].as_u64() != Some(expected_pid as u64)
        || before["identity"] != peer.id
        || after["identity"] != peer.id
        || before["pid"] != live_before["pid"]
        || after["pid"] != live_after["pid"]
        || before["listener_instance"] != instance
        || after["listener_instance"] != instance
        || before["operator_policy_sha256"] != hash(policy)?
        || after["operator_policy_sha256"] != hash(policy)?
        || before["armed_snapshot_sha256"] != prior.sha256
        || after["armed_snapshot_sha256"] != prior.sha256
        || before["armed_revocations"] != json!(prior.revoked)
        || after["armed_revocations"] != json!(prior.revoked)
        || probe["connected"] != false
        || probe["admission_verdict"] != "HOLD_UNVERIFIED_CONNECT_FAILURE"
        || probe["source_identity"] != source
        || probe["source_pid"] != observations["expected_source_pid"]
        || probe["connect_error"].as_str().is_none_or(str::is_empty)
    {
        return Err("HOLD: connect failure lacks same-instance live destination and pinned policy observations".into());
    }
    let before_failures = before["session_failures"]
        .as_u64()
        .ok_or("HOLD: receiver failure counter missing")?;
    let before_connections = before["connection_count"]
        .as_u64()
        .ok_or("HOLD: receiver connection counter missing")?;
    if after["session_failures"].as_u64() != before_failures.checked_add(1)
        || after["connection_count"].as_u64() != before_connections.checked_add(2)
        || before["quarantined"] != after["quarantined"]
    {
        return Err("HOLD: source failure is not bound to one receiver rejection between live control sessions".into());
    }
    let grant_ids = before["granted_peer_ids"]
        .as_array()
        .ok_or("HOLD: actual receiver grant inventory missing")?;
    let revoked_ids = before["revoked_peer_ids"]
        .as_array()
        .ok_or("HOLD: receiver revocation inventory missing")?;
    if before["granted_peer_ids"] != after["granted_peer_ids"]
        || before["revoked_peer_ids"] != after["revoked_peer_ids"]
    {
        return Err(
            "HOLD: receiver authorization changed while checking negative admission".into(),
        );
    }
    let edge = policy
        .edges
        .iter()
        .find(|edge| edge.source == source && edge.destination == peer.id && edge.scope == SCOPE);
    let expected_failure = match reason {
        "ungranted-peer" => {
            if grant_ids.iter().any(|id| id == source)
                || edge.is_some_and(|edge| edge.source_granted && edge.destination_granted)
            {
                return Err(
                    "HOLD: no-grant probe contradicts actual operator or receiver grant inventory"
                        .into(),
                );
            }
            "client certificate has no operator-owned identity grant"
        }
        "revoked-peer" => {
            if !grant_ids.iter().any(|id| id == source)
                || !revoked_ids.iter().any(|id| id == source)
                || !edge.is_some_and(|edge| edge.source_granted && edge.destination_granted)
                || !prior
                    .revoked
                    .contains(&(source.into(), peer.id.clone(), SCOPE.into()))
            {
                return Err("HOLD: revocation probe lacks actual receiver and independently pinned operator revocation".into());
            }
            "client authorization revoked"
        }
        _ => return Err("HOLD: unknown negative admission experiment".into()),
    };
    if after["last_failure"] != expected_failure {
        return Err("HOLD: receiver rejected session for a different or unknown reason".into());
    }
    Ok(
        json!({"tls_denied":true,"admission_verdict":"VERIFIED_SERVER_POLICY_DENIAL","denial_stage":"peer authorization after TLS certificate authentication",
        "expected_reason":reason,"source_probe":probe,"live_before":live_before,"live_after":live_after,
        "receiver_before":before,"receiver_after":after,"proof_basis":"live same-PID same-instance TLS control before and after; exactly one recorded receiver rejection with expected policy reason"}),
    )
}
fn negative_admission(
    children: &mut [OwnedProcess],
    source: usize,
    peer: &Peer,
    prior: &NetworkSnapshot,
    policy: &NetworkPolicy,
    transport: &mut ProbeTransport<'_>,
    reason: &str,
) -> Result<Value, String> {
    let destination = peer.role;
    let source_id = children[source].id.clone();
    let expected_pid = children[destination].pid;
    children[destination].call(json!({"operation":"arm","prior":prior,"pin":prior.sha256}))?;
    let live_before = live_control(peer, expected_pid, transport)?;
    let receiver_before = children[destination].call(json!({"operation":"admission-status"}))?;
    let probe = children[source].call(json!({"operation":"direct-probe","destination":peer.id}))?;
    let live_after = live_control(peer, expected_pid, transport)?;
    let receiver_after = children[destination].call(json!({"operation":"admission-status"}))?;
    verify_denial(
        peer,
        &source_id,
        expected_pid,
        prior,
        policy,
        &json!({"live_before":live_before,"live_after":live_after,
        "receiver_before":receiver_before,"receiver_after":receiver_after,"source_probe":probe,"expected_source_pid":children[source].pid}),
        reason,
    )
}

/// Fresh, finite engineering fixture. No release, generalized benefit or independent sample claim.
pub fn run(state: &Path, receipts: &Path) -> Result<Value, String> {
    if state.exists() || receipts.exists() {
        return Err("topology experiment requires fresh state and receipt paths; prior evidence is never overwritten".into());
    }
    fs::create_dir_all(state).map_err(|e| e.to_string())?;
    fs::create_dir_all(receipts).map_err(|e| e.to_string())?;
    let state = state.canonicalize().map_err(|e| e.to_string())?;
    let receipts = receipts.canonicalize().map_err(|e| e.to_string())?;
    if state == receipts || state.starts_with(&receipts) || receipts.starts_with(&state) {
        return Err(
            "participant state and public receipts require separate fresh directories".into(),
        );
    }
    write_new(
        &receipts.join("registration.json"),
        &json!({"schema":"symbiote.topology-registration/1","scope":SCOPE,
        "graph":schema(),"costs":COSTS,"source_seed_edges":SEEDS,"heldout":HOLDOUT,
        "oracle_assumption":"each native child independently evaluates the same pinned finite laboratory fixture; this is not remote honesty",
        "comparison":"preexchange warmup coverage gates promotion; isolated adaptive complete-cost control reported independently",
        "replication_unit":"one manual fixture with three interacting participants, not three independent samples",
        "network":"only A<->B<->C; controller control.status is a separate scope",
        "secure_plaintext_budget_per_source_and_controller":SECURE_BUDGET,"quote_per_connection_attempt":SECURE_QUOTE,
        "tls_record_and_cryptographic_handshake_wire_bytes":"not measured; application and negotiation plaintext counted separately"}),
    )?;
    let (ca, materials) = pki()?;
    let controller =
        TlsClientConfig::new(CONTROLLER.into(), materials[3].identity()?, ca.as_bytes())?;
    let mut children = Vec::new();
    for (role, material) in materials.iter().take(3).enumerate() {
        children.push(OwnedProcess::spawn(&Bootstrap {
            state: state.join(format!("node-{role}")),
            role,
            restart: false,
            material: material.clone(),
            ca: ca.clone(),
            controller_pin: materials[3].pin.clone(),
        })?);
    }
    let ids = children
        .iter()
        .map(|child| child.id.clone())
        .collect::<Vec<_>>();
    let initial_pids = children.iter().map(|child| child.pid).collect::<Vec<_>>();
    if ids.iter().collect::<BTreeSet<_>>().len() != 3
        || initial_pids.iter().collect::<BTreeSet<_>>().len() != 3
    {
        return Err("native topology needs three distinct owned identities and PIDs".into());
    }
    let policy = policy(&ids);
    policy.validate()?;
    let peers = configure(&mut children, &materials, &policy)?;
    let controller_traffic = SecureTraffic::default();
    let mut controller_quotes = 0_u64;
    for peer in &peers {
        reserve_secure(&mut controller_quotes)?;
        let mut client = SecureClient::connect_with_metering(
            &peer.endpoint(CONTROL_SCOPE, &["control.status"]),
            &controller,
            controller_traffic.clone(),
            FRAME,
        )?;
        let status = client.call("control.status", &Value::Null)?;
        client.revoke()?;
        if status["identity"] != peer.id
            || status["pid"].as_u64() != Some(children[peer.role].pid as u64)
        {
            return Err("separate controller TLS grant returned wrong participant".into());
        }
    }
    let mut snapshot = SymbioticNetwork::open(
        policy.clone(),
        None,
        None,
        DEADLINE,
        Arc::new(AtomicBool::new(false)),
    )?
    .snapshot()?;
    let mut snapshot_number = 0;
    persist_snapshot(&state, &receipts, snapshot_number, &snapshot)?;
    let mut deliveries = Vec::new();
    for (source, destination, origin) in [
        (0, 1, 0),
        (1, 0, 1),
        (1, 2, 1),
        (2, 1, 2),
        (1, 2, 0),
        (1, 0, 2),
    ] {
        let delivery = run_hop(&mut children, source, destination, origin, &snapshot, false)?;
        snapshot = validate_next(&policy, &snapshot, &delivery, true)?;
        snapshot_number += 1;
        persist_snapshot(&state, &receipts, snapshot_number, &snapshot)?;
        deliveries.push(delivery);
    }
    let mut adoptions = Vec::new();
    for child in &mut children {
        adoptions.push(child.call(json!({"operation":"adopt"}))?);
    }
    let no_grant = negative_admission(
        &mut children,
        0,
        &peers[2],
        &snapshot,
        &policy,
        &mut ProbeTransport {
            client: &controller,
            traffic: controller_traffic.clone(),
            quotes: &mut controller_quotes,
        },
        "ungranted-peer",
    )?;
    let mut restored = SymbioticNetwork::open(
        policy.clone(),
        Some(snapshot.clone()),
        Some(&snapshot.sha256),
        DEADLINE,
        Arc::new(AtomicBool::new(false)),
    )?;
    restored.revoke(&ids[1], &ids[2], SCOPE)?;
    snapshot = restored.snapshot()?;
    snapshot_number += 1;
    persist_snapshot(&state, &receipts, snapshot_number, &snapshot)?;
    children[2].call(json!({"operation":"revoke-peer","peer":ids[1]}))?;
    let revoked = run_hop(&mut children, 1, 2, 1, &snapshot, false)?;
    if revoked["delivered"] != false || revoked["snapshot"] != json!(snapshot) {
        return Err(
            "persisted network revocation allowed a new delivery or changed charged history".into(),
        );
    }
    let tls_revoked = negative_admission(
        &mut children,
        1,
        &peers[2],
        &snapshot,
        &policy,
        &mut ProbeTransport {
            client: &controller,
            traffic: controller_traffic.clone(),
            quotes: &mut controller_quotes,
        },
        "revoked-peer",
    )?;
    let failed = run_hop(&mut children, 2, 1, 2, &snapshot, true)?;
    snapshot = validate_next(&policy, &snapshot, &failed, false)?;
    snapshot_number += 1;
    persist_snapshot(&state, &receipts, snapshot_number, &snapshot)?;
    let exhausted = run_hop(&mut children, 0, 1, 0, &snapshot, false)?;
    if exhausted["delivered"] != false
        || exhausted["snapshot"] != json!(snapshot)
        || snapshot.receipts.len() != policy.limits.attempts
    {
        return Err("aggregate attempt exhaustion was refunded or bypassed".into());
    }
    let mut before_restart = Vec::new();
    for child in &mut children {
        before_restart.push(child.call(json!({"operation":"status"}))?);
    }
    for child in &mut children {
        child.stop()?;
    }
    let first_control=children.iter().map(|child|json!({"identity":child.id,"stdin_bytes":child.sent,"stdout_bytes":child.received,"child_diagnostics":child.diagnostics()})).collect::<Vec<_>>();
    drop(children);
    // Reopen from the actual written snapshot and independently retained anchor, not memory copies.
    let persisted: NetworkSnapshot = serde_json::from_slice(&read_file(
        &receipts.join(format!("network-snapshot-{snapshot_number:02}.json")),
        FRAME,
    )?)
    .map_err(|_| "persisted network snapshot malformed")?;
    let anchor: Value = serde_json::from_slice(&read_file(
        &state.join(format!(
            "controller-network-anchor-{snapshot_number:02}.json"
        )),
        4096,
    )?)
    .map_err(|_| "external controller anchor malformed")?;
    let pin = anchor["snapshot_sha256"]
        .as_str()
        .ok_or("external controller pin missing")?;
    SymbioticNetwork::open(
        policy.clone(),
        Some(persisted.clone()),
        Some(pin),
        DEADLINE,
        Arc::new(AtomicBool::new(false)),
    )?;
    let mut restarted = Vec::new();
    for (role, material) in materials.iter().take(3).enumerate() {
        restarted.push(OwnedProcess::spawn(&Bootstrap {
            state: state.join(format!("node-{role}")),
            role,
            restart: true,
            material: material.clone(),
            ca: ca.clone(),
            controller_pin: materials[3].pin.clone(),
        })?);
    }
    if restarted
        .iter()
        .enumerate()
        .any(|(index, child)| child.id != ids[index] || initial_pids.contains(&child.pid))
    {
        return Err("restart did not retain identities in fresh owned native processes".into());
    }
    configure(&mut restarted, &materials, &policy)?;
    let restart_revoked = run_hop(&mut restarted, 1, 2, 1, &persisted, false)?;
    if restart_revoked["delivered"] != false || restart_revoked["snapshot"] != json!(persisted) {
        return Err("reopened revoked edge became dispatchable".into());
    }
    let mut after_restart = Vec::new();
    for (index, child) in restarted.iter_mut().enumerate() {
        let status = child.call(json!({"operation":"status"}))?;
        if status["history_anchor"] != before_restart[index]["history_anchor"]
            || status["retained_predictions"] != json!([1, 3])
            || status["meter"]["source_warmup_oracle_calls"] != 0
            || status["meter"]["validation_oracle_calls"] != 0
            || status["meter"]["evaluation_oracle_calls"] != 0
            || status["meter"]["fresh_promotions"] != 0
        {
            return Err("native restart failed retained heldout inference without oracle calls or promotions".into());
        }
        after_restart.push(status);
    }
    for child in &mut restarted {
        child.stop()?;
    }
    let restart_control=restarted.iter().map(|child|json!({"identity":child.id,"stdin_bytes":child.sent,"stdout_bytes":child.received,"child_diagnostics":child.diagnostics()})).collect::<Vec<_>>();
    let mut comparisons = Vec::new();
    let mut total_delta = 0_i64;
    for (index, status) in before_restart.iter().enumerate() {
        let explicit = status["explicit_work_units"]
            .as_u64()
            .ok_or("participant work meter missing")?;
        let incoming: SecureTrafficSnapshot =
            serde_json::from_value(status["incoming_tls_traffic"].clone())
                .map_err(|_| "participant inbound traffic missing")?;
        let incoming_units = (incoming.rpc_sent_bytes
            + incoming.rpc_received_bytes
            + incoming.negotiation_sent_bytes
            + incoming.negotiation_received_bytes)
            .div_ceil(1024);
        let control_units = (first_control[index]["stdin_bytes"].as_u64().unwrap_or(0)
            + first_control[index]["stdout_bytes"].as_u64().unwrap_or(0))
        .div_ceil(1024);
        let candidate = explicit + incoming_units + control_units;
        let baseline = status["isolated_adaptive_control"]["total_work_units"]
            .as_u64()
            .ok_or("isolated cost missing")?;
        let delta = baseline as i64 - candidate as i64;
        total_delta += delta;
        comparisons.push(json!({"identity":ids[index],"isolated_adaptive_total_work_units":baseline,
            "network_total_work_units":candidate,"cost_saving_work_units":delta,"positive_complete_cost_benefit":delta>0,
            "preexchange_coverage":status["preexchange_heldout"],"isolated_adaptive_coverage":status["isolated_adaptive_control"]["heldout"],
            "network_heldout_predictions":status["retained_predictions"],"accounting":"source oracle + independent validation + heldout oracle + explicit and repeated assessment model work + adoption + outbound sessions/plaintext + inbound plaintext + private control bytes"}));
    }
    let report = json!({"schema":"symbiote.native-topology-research/1","status":"ENGINEERING_PASS","scientific_status":"one controlled manual fixture; measured negative cost result is retained",
        "scope":SCOPE,"owned_native_processes":3,"initial_pids":initial_pids,"restarted_pids":restarted.iter().map(|c|c.pid).collect::<Vec<_>>(),
        "identities":ids,"topology_policy":policy,"successful_inert_hops":deliveries.len(),"deliveries":deliveries,"fresh_local_adoptions":adoptions,
        "no_direct_a_c_tls_grant":no_grant,"persisted_revocation_denial":revoked,"tls_revocation_denial":tls_revoked,
        "charged_failed_delivery":failed,"aggregate_exhaustion_denial":exhausted,"reopened_revocation_denial":restart_revoked,
        "network_snapshot":snapshot,"payload_budget_basis":"forwarded inert-envelope serialization only; failed dispatch remains reserved",
        "secure_plaintext_quotes":{"per_actor_budget":SECURE_BUDGET,"controller_reserved_bytes":controller_quotes,"quote_per_attempt":SECURE_QUOTE,
            "controller_actual":controller_traffic.snapshot(),"basis":"negotiation and RPC application plaintext; TLS record and cryptographic handshake wire bytes excluded"},
        "before_restart":before_restart,"after_restart":after_restart,"private_control_bytes":first_control,"restart_private_control_bytes":restart_control,
        "participant_comparisons":comparisons,"aggregate_cost_saving_work_units":total_delta,
        "all_participants_positive_complete_cost_benefit":comparisons.iter().all(|row|row["positive_complete_cost_benefit"]==true),
        "limitations":["single manually fixed stationary diamond graph","shared trusted-host laboratory oracle; no remote honesty proof","no independent population samples or generalization claim",
            "no performance or reciprocal utility claim when complete cost comparison is negative","TLS cryptographic wire bytes and operating system CPU time are not measured",
            "private process control is trusted; source artifacts cannot choose endpoints, grants, private keys or code"]});
    write_new(&receipts.join("summary.json"), &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    #[test]
    fn receiver_oracle_rejects_forged_inert_observation_without_promotion() {
        let path = std::env::temp_dir().join(format!(
            "symbiote-topology-counterexample-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let (ca, materials) = pki().unwrap();
        let bootstrap = Bootstrap {
            state: path.clone(),
            role: 0,
            restart: false,
            material: materials[0].clone(),
            ca,
            controller_pin: materials[3].pin.clone(),
        };
        let mut agent = Agent::open(&bootstrap).unwrap();
        let other = "controlled-source-c";
        agent.peers.push(Peer {
            role: 2,
            id: other.into(),
            pin: materials[2].pin.clone(),
            name: materials[2].name.clone(),
            address: "127.0.0.1:1".parse().unwrap(),
        });
        let mut false_acquisition = acquisition(other, 3).unwrap();
        false_acquisition.cost = 2;
        false_acquisition.receipt["cost"] = json!(2);
        false_acquisition.receipt_sha256 =
            graph_receipt_digest(&false_acquisition.receipt).unwrap();
        let proof = SourceProof {
            schema: "symbiote.topology-source/1".into(),
            source: other.into(),
            acquisitions: vec![false_acquisition],
        };
        let mut envelope = KnowledgeEnvelope::local(source_record(&proof).unwrap(), other).unwrap();
        envelope.route.push(agent.id.clone());
        write_new(&path.join("quarantine-00.json"), &envelope).unwrap();
        agent.quarantined.push(envelope);
        let anchor = agent.knowledge.history_anchor();
        assert!(agent
            .adopt()
            .unwrap_err()
            .contains("independent pinned local oracle"));
        assert_eq!(agent.knowledge.history_anchor(), anchor);
        assert_eq!(agent.meter.fresh_promotions, 0);
        assert_eq!(agent.meter.validation_oracle_calls, 1);
        drop(agent);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn secure_reservation_charges_failed_attempts_and_stops_before_excess() {
        let mut used = 0;
        let mut attempts = 0;
        while reserve_secure(&mut used).is_ok() {
            attempts += 1;
        }
        assert!(attempts > 0);
        assert!(used <= SECURE_BUDGET);
        assert!(used + SECURE_QUOTE > SECURE_BUDGET);
        let prior = used;
        assert!(reserve_secure(&mut used).is_err());
        assert_eq!(used, prior);
    }

    #[test]
    fn authenticated_neighbor_cannot_bypass_receiver_mutual_consent_or_revocation() {
        let path = std::env::temp_dir().join(format!(
            "symbiote-topology-receiver-consent-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let (ca, materials) = pki().unwrap();
        let bootstrap = Bootstrap {
            state: path.clone(),
            role: 0,
            restart: false,
            material: materials[0].clone(),
            ca,
            controller_pin: materials[3].pin.clone(),
        };
        let mut agent = Agent::open(&bootstrap).unwrap();
        let peer = "authenticated-native-neighbor";
        let ids = vec![agent.id.clone(), peer.into(), "native-c".into()];
        let allowed = policy(&ids);
        let proof = SourceProof {
            schema: "symbiote.topology-source/1".into(),
            source: peer.into(),
            acquisitions: vec![acquisition(peer, 1).unwrap()],
        };
        let mut envelope = KnowledgeEnvelope::local(source_record(&proof).unwrap(), peer).unwrap();
        envelope.route.push(agent.id.clone());
        let original_anchor = agent.knowledge.history_anchor();
        for denial in [
            "source-withheld",
            "destination-withheld",
            "operator-revoked",
        ] {
            let mut policy = allowed.clone();
            let edge = policy
                .edges
                .iter_mut()
                .find(|edge| edge.source == peer && edge.destination == agent.id)
                .unwrap();
            if denial == "source-withheld" {
                edge.source_granted = false;
            }
            if denial == "destination-withheld" {
                edge.destination_granted = false;
            }
            agent.policy = Some(policy.clone());
            let mut network = SymbioticNetwork::open(
                policy,
                None,
                None,
                DEADLINE,
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap();
            if denial == "operator-revoked" {
                network.revoke(peer, &agent.id, SCOPE).unwrap();
            }
            let snapshot = network.snapshot().unwrap();
            agent.arm(snapshot.clone(), &snapshot.sha256).unwrap();
            // This is a valid typed artifact from an authenticated neighboring ID,
            // with the exact independently armed prefix. Sender-side checks are absent.
            let error = agent
                .receive(
                    peer,
                    json!({"envelope":envelope,"prior":snapshot,"pin":snapshot.sha256}),
                )
                .unwrap_err();
            assert!(
                error.contains("immediate edge consent"),
                "{denial}: {error}"
            );
            assert!(agent.quarantined.is_empty());
            assert_eq!(agent.meter.received_artifacts, 0);
            assert_eq!(agent.knowledge.history_anchor(), original_anchor);
            assert!(!path.join("quarantine-00.json").exists());
        }
        agent.policy = Some(allowed.clone());
        let snapshot = SymbioticNetwork::open(
            allowed,
            None,
            None,
            DEADLINE,
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap()
        .snapshot()
        .unwrap();
        agent.arm(snapshot.clone(), &snapshot.sha256).unwrap();
        assert_eq!(
            agent
                .receive(
                    peer,
                    json!({"envelope":envelope,"prior":snapshot,"pin":snapshot.sha256})
                )
                .unwrap()["quarantined"],
            true
        );
        assert_eq!(agent.quarantined.len(), 1);
        drop(agent);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn producer_rehash_cannot_remove_controller_revocations_when_advancing_anchor() {
        let ids = vec!["native-a".into(), "native-b".into(), "native-c".into()];
        let policy = policy(&ids);
        let mut network = SymbioticNetwork::open(
            policy.clone(),
            None,
            None,
            DEADLINE,
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        network.revoke(&ids[1], &ids[2], SCOPE).unwrap();
        let prior = network.snapshot().unwrap();
        let proof = SourceProof {
            schema: "symbiote.topology-source/1".into(),
            source: ids[0].clone(),
            acquisitions: vec![acquisition(&ids[0], 0).unwrap()],
        };
        let envelope = KnowledgeEnvelope::local(source_record(&proof).unwrap(), &ids[0]).unwrap();
        network
            .forward(&ids[0], &ids[1], &envelope, |_, _, _| Ok(()))
            .unwrap();
        let valid = network.snapshot().unwrap();
        assert!(validate_next(
            &policy,
            &prior,
            &json!({"snapshot":valid,"delivered":true}),
            true
        )
        .is_ok());
        let mut forged = valid;
        forged.revoked.clear();
        forged.sha256.clear();
        forged.sha256 = hash(&forged).unwrap();
        // Producer-controlled self-consistency alone accepts this newly rehashed snapshot.
        assert!(SymbioticNetwork::open(
            policy.clone(),
            Some(forged.clone()),
            Some(&forged.sha256),
            DEADLINE,
            Arc::new(AtomicBool::new(false))
        )
        .is_ok());
        assert!(validate_next(
            &policy,
            &prior,
            &json!({"snapshot":forged,"delivered":true}),
            true
        )
        .is_err());
        assert_eq!(
            prior.revoked,
            vec![(ids[1].clone(), ids[2].clone(), SCOPE.into())]
        );
    }

    #[test]
    fn dead_listener_connect_failure_is_hold_and_never_policy_denial() {
        let path = std::env::temp_dir().join(format!(
            "symbiote-topology-dead-listener-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let (ca, materials) = pki().unwrap();
        let bootstrap = Bootstrap {
            state: path.clone(),
            role: 0,
            restart: false,
            material: materials[0].clone(),
            ca: ca.clone(),
            controller_pin: materials[3].pin.clone(),
        };
        let mut agent = Agent::open(&bootstrap).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let peer = Peer {
            role: 2,
            id: "dead-native-c".into(),
            pin: materials[2].pin.clone(),
            name: materials[2].name.clone(),
            address,
        };
        agent.peers.push(peer.clone());
        let probe = agent.direct_probe(&peer.id).unwrap();
        assert_eq!(probe["tls_denied"], false);
        assert_eq!(probe["connected"], false);
        assert_eq!(
            probe["admission_verdict"],
            "HOLD_UNVERIFIED_CONNECT_FAILURE"
        );
        assert!(!probe["connect_error"].as_str().unwrap().is_empty());
        let controller = TlsClientConfig::new(
            CONTROLLER.into(),
            materials[3].identity().unwrap(),
            ca.as_bytes(),
        )
        .unwrap();
        let mut quotes = 0;
        let mut transport = ProbeTransport {
            client: &controller,
            traffic: SecureTraffic::default(),
            quotes: &mut quotes,
        };
        assert!(live_control(&peer, std::process::id(), &mut transport)
            .unwrap_err()
            .starts_with("HOLD:"));
        let policy = policy(&[agent.id.clone(), "native-b".into(), peer.id.clone()]);
        let snapshot = SymbioticNetwork::open(
            policy.clone(),
            None,
            None,
            DEADLINE,
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap()
        .snapshot()
        .unwrap();
        // Even reusing earlier positive live-session metadata cannot turn a dead
        // listener's refusal into an observed receiver authorization rejection.
        let live =
            json!({"identity":peer.id,"pid":std::process::id(),"listener_instance":"a".repeat(64)});
        let receiver = json!({"identity":peer.id,"pid":std::process::id(),"listener_instance":"a".repeat(64),
            "operator_policy_sha256":hash(&policy).unwrap(),"armed_snapshot_sha256":snapshot.sha256,"armed_revocations":[],
            "granted_peer_ids":["native-b"],"revoked_peer_ids":[],"session_failures":0,"connection_count":0,"quarantined":0,
            "last_failure":Value::Null});
        let error=verify_denial(&peer,&agent.id,std::process::id(),&snapshot,&policy,&json!({"live_before":live,"live_after":live,
            "receiver_before":receiver,"receiver_after":receiver,"source_probe":probe,"expected_source_pid":std::process::id()}),"ungranted-peer").unwrap_err();
        assert!(error.starts_with("HOLD:"));
        assert!(error.contains("receiver rejection"));
        assert!(agent.quarantined.is_empty());
        assert_eq!(agent.meter.fresh_promotions, 0);
        drop(agent);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn child_diagnostics_retain_bounded_stage_and_withhold_private_material() {
        let text=b"SYMBIOTE topology child failure: stage=bootstrap\n-----BEGIN PRIVATE KEY-----\nsecret-bootstrap-value\n";
        let safe = safe_stderr(text);
        assert!(safe.contains("stage=bootstrap"));
        assert!(!safe.contains("PRIVATE KEY"));
        assert!(!safe.contains("secret-bootstrap-value"));
    }
}
