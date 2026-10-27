//! Separately supervised native agents with private durable state.
//!
//! The controller owns the laboratory oracle and judge. Child processes receive
//! only authenticated observation/verifier grants, never hidden function laws.
mod tls;

use super::{
    affine_schema_fingerprint, assess, parameters, AffineStrategy, Authority, Environment, Judge,
    KnowledgeRecord, KnowledgeStore, Learner, ObservationReceipt, Store, TrialCase, TrialCosts,
    TrialEvidence, SCOPE,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use symbiote_protocol::{
    fresh_capability, spawn_scoped_server, spawn_secure_server, Client, Endpoint, SecureClient,
    SecureServerHandle, ServerConfig, ServerHandle,
};

const CONFIG_LIMIT: usize = 4096;
const READY_LIMIT: usize = 4096;
const LOG_LIMIT: usize = 4096;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const STOP_TIMEOUT: Duration = Duration::from_secs(2);
const AGENT_OPS: &[&str] = &[
    "next", "observe", "bundle", "adopt", "promote", "forecast", "status",
];
const ORACLE_OPS: &[&str] = &["observe", "verify", "assess"];

enum AgentClient {
    Legacy(Client),
    Tls(Box<SecureClient>),
}
impl AgentClient {
    fn call(&mut self, operation: &str, payload: &Value) -> Result<Value, String> {
        match self {
            Self::Legacy(client) => client.call(operation, payload),
            Self::Tls(client) => client.call(operation, payload),
        }
    }
    fn revoke(&mut self) -> Result<(), String> {
        match self {
            Self::Legacy(client) => client.revoke(),
            Self::Tls(client) => client.revoke(),
        }
    }
}

enum NativeServer {
    Legacy(ServerHandle),
    Tls(SecureServerHandle),
}
impl NativeServer {
    fn address(&self) -> SocketAddr {
        match self {
            Self::Legacy(server) => server.endpoint().address,
            Self::Tls(server) => server.address(),
        }
    }
    fn grant(&self) -> Grant {
        match self {
            Self::Legacy(server) => {
                let endpoint = server.endpoint();
                Grant {
                    id: endpoint.id,
                    address: endpoint.address,
                    token: endpoint.token,
                }
            }
            Self::Tls(server) => Grant {
                id: server.server_id().into(),
                address: server.address(),
                token: String::new(),
            },
        }
    }
    fn shutdown(&mut self) -> Result<(), String> {
        match self {
            Self::Legacy(server) => server.shutdown(),
            Self::Tls(server) => server.shutdown(),
        }
    }
    fn revoke_peer(&self, id: &str) -> Result<(), String> {
        match self {
            Self::Tls(server) => server.revoke_peer(id),
            Self::Legacy(_) => Err("certificate revocation requires TLS".into()),
        }
    }
}

fn fit_native(client: &mut AgentClient, width: u8) -> Result<Vec<ObservationReceipt>, String> {
    for _ in 0..=width {
        let next = client.call("next", &json!({}))?;
        let Some(input) = next["input"].as_u64() else {
            break;
        };
        client.call("observe", &json!({"input":input}))?;
    }
    if !client.call("next", &json!({}))?["input"].is_null() {
        return Err("source model did not converge within declared query bound".into());
    }
    serde_json::from_value(client.call("bundle", &json!({}))?)
        .map_err(|_| "native peer returned an invalid observation bundle".into())
}

// These values contain capability secrets. Deliberately do not implement Debug.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    id: String,
    address: SocketAddr,
    token: String,
}
impl Grant {
    fn endpoint(&self) -> Endpoint {
        Endpoint {
            id: self.id.clone(),
            address: self.address,
            token: self.token.clone(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildConfig {
    version: u32,
    id: String,
    controller: String,
    peer: String,
    token: String,
    oracle: Grant,
    state: PathBuf,
    source_domain: String,
    target_domain: String,
    width: u8,
    linear: bool,
    lease_ms: u64,
    #[serde(default)]
    fault: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls: Option<tls::Bootstrap>,
}
impl ChildConfig {
    fn validate(&self) -> Result<(), String> {
        let label = |x: &str| {
            !x.is_empty()
                && x.len() <= 128
                && x.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        };
        if !matches!((self.version, self.tls.is_some()), (1, false) | (2, true))
            || !label(&self.id)
            || !label(&self.controller)
            || !label(&self.peer)
            || !label(&self.source_domain)
            || !label(&self.target_domain)
            || !(3..=8).contains(&self.width)
            || !(1000..=60_000).contains(&self.lease_ms)
            || (self.tls.is_none()
                && (!(16..=256).contains(&self.token.len())
                    || !(16..=256).contains(&self.oracle.token.len())))
            || (self.tls.is_some() && (!self.token.is_empty() || !self.oracle.token.is_empty()))
            || !self.oracle.address.ip().is_loopback()
            || !label(&self.oracle.id)
            || ![
                "",
                "stall-before-ready",
                "exit-after-ready",
                "exit-after-promotion",
            ]
            .contains(&self.fault.as_str())
        {
            return Err("child configuration rejected".into());
        }
        if let Some(tls) = &self.tls {
            tls.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    schema: String,
    id: String,
    identity: String,
    pid: u32,
    instance_nonce: String,
    address: SocketAddr,
    active_models: usize,
}

fn digest<T: Serialize>(value: &T) -> Result<String, String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).map_err(|_| "cannot encode evidence")?)
    ))
}

fn bounded_line(reader: &mut impl BufRead, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|_| "child control stream failed")?;
        if available.is_empty() {
            return Err("child control stream closed before a complete frame".into());
        }
        let count = available
            .iter()
            .position(|x| *x == b'\n')
            .map_or(available.len(), |i| i + 1);
        if bytes.len() + count > limit {
            return Err("child control frame exceeds limit".into());
        }
        bytes.extend_from_slice(&available[..count]);
        let ended = available[count - 1] == b'\n';
        reader.consume(count);
        if ended {
            return Ok(bytes);
        }
    }
}

fn terminate_owned(child: &mut Child) -> Result<(), String> {
    match child
        .try_wait()
        .map_err(|_| "owned child liveness is unknown; lifecycle is HOLD")?
    {
        Some(_) => Ok(()),
        None => {
            if child.kill().is_err() && !matches!(child.try_wait(), Ok(Some(_))) {
                return Err("owned child cancellation failed; lifecycle is HOLD".into());
            }
            child
                .wait()
                .map_err(|_| "cannot join cancelled native child")?;
            Ok(())
        }
    }
}

/// Owns the actual OS process, pipes and readers. No capability appears in argv.
struct SupervisedChild {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<JoinHandle<Result<Vec<u8>, String>>>,
    stderr: Option<JoinHandle<Result<Vec<u8>, String>>>,
    ready: Ready,
    token: String,
    tls: bool,
    controls: mpsc::Receiver<()>,
}
impl SupervisedChild {
    fn spawn(config: &ChildConfig) -> Result<Self, String> {
        config.validate()?;
        let previous = symbiote_memory::maintenance::inspect(&config.state)?;
        if previous.identity.as_deref() == Some(config.controller.as_str()) {
            return Err(
                "native partner identity aliases the controller; existing state was preserved"
                    .into(),
            );
        }
        let mut frame =
            serde_json::to_vec(config).map_err(|_| "cannot encode child configuration")?;
        frame.push(b'\n');
        let frame_limit = if config.tls.is_some() {
            tls::BOOTSTRAP_LIMIT
        } else {
            CONFIG_LIMIT
        };
        if frame.len() > frame_limit {
            return Err("child configuration exceeds startup budget".into());
        }
        let executable = std::env::current_exe().map_err(|_| "cannot locate native executable")?;
        let mut command = Command::new(executable);
        command
            .arg("__research-partner")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let mut child = command
            .spawn()
            .map_err(|_| "native partner process could not start")?;
        let mut stdin = child.stdin.take().ok_or("child stdin unavailable")?;
        let output = child.stdout.take().ok_or("child stdout unavailable")?;
        let errors = child.stderr.take().ok_or("child stderr unavailable")?;
        let (write_tx, write_rx) = mpsc::channel();
        let writer = thread::spawn(move || {
            let result = stdin.write_all(&frame).and_then(|()| stdin.flush());
            // Never include the frame or secrets in an error or diagnostic.
            let _ = write_tx.send(
                result
                    .map(|()| stdin)
                    .map_err(|_| "child configuration write failed".to_string()),
            );
        });
        let (ready_tx, ready_rx) = mpsc::channel();
        let (control_tx, control_rx) = mpsc::sync_channel(1);
        let tls_controls = config.tls.is_some();
        let stdout = thread::spawn(move || {
            let mut reader = BufReader::new(output);
            let result = bounded_line(&mut reader, READY_LIMIT).and_then(|raw| {
                serde_json::from_slice::<Ready>(&raw)
                    .map_err(|_| "invalid child readiness frame".to_string())
            });
            let _ = ready_tx.send(result);
            let mut trailing = Vec::new();
            if tls_controls {
                let mut consumed = 0;
                loop {
                    if reader
                        .fill_buf()
                        .map_err(|_| "child stdout failed")?
                        .is_empty()
                    {
                        break;
                    }
                    let line = bounded_line(&mut reader, 256)?;
                    consumed += line.len();
                    if consumed > LOG_LIMIT {
                        return Err("child control acknowledgements exceeded budget".into());
                    }
                    if serde_json::from_slice::<Value>(&line).ok()
                        != Some(
                            json!({"schema":"symbiote.partner-control/1","event":"controller-revoked"}),
                        )
                    {
                        return Err("invalid child control acknowledgement".into());
                    }
                    control_tx
                        .try_send(())
                        .map_err(|_| "unexpected repeated child acknowledgement")?;
                }
            } else {
                reader
                    .take((LOG_LIMIT + 1) as u64)
                    .read_to_end(&mut trailing)
                    .map_err(|_| "child stdout failed")?;
                if trailing.len() > LOG_LIMIT {
                    return Err("child stdout exceeded budget".into());
                }
            }
            Ok(trailing)
        });
        let stderr = thread::spawn(move || {
            let mut bytes = Vec::new();
            errors
                .take((LOG_LIMIT + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| "child stderr failed")?;
            if bytes.len() > LOG_LIMIT {
                return Err("child stderr exceeded budget".into());
            }
            Ok(bytes)
        });
        let startup = (|| {
            let deadline = Instant::now() + STARTUP_TIMEOUT;
            let stdin = write_rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|_| "child startup write deadline exceeded")??;
            let ready = ready_rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|_| "child readiness deadline exceeded")??;
            if ready.schema != "symbiote.partner-ready/1"
                || ready.id != config.id
                || ready.pid != child.id()
                || ready.instance_nonce.len() != 64
                || !ready
                    .instance_nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || !ready.address.ip().is_loopback()
                || ready.identity.len() != 33
                || !ready.identity.starts_with("symbiote-")
                || ready.active_models > 4096
                || (config.tls.is_some() && ready.identity != config.id)
            {
                return Err("child identity/readiness validation failed".to_string());
            }
            let readiness = serde_json::to_string(&ready).map_err(|_| "cannot audit readiness")?;
            if (!config.token.is_empty() && readiness.contains(&config.token))
                || (!config.oracle.token.is_empty() && readiness.contains(&config.oracle.token))
            {
                return Err("child readiness exposed a capability".into());
            }
            Ok((stdin, ready))
        })();
        match startup {
            Ok((stdin, ready)) => {
                let _ = writer.join();
                Ok(Self {
                    child,
                    stdin: Some(stdin),
                    stdout: Some(stdout),
                    stderr: Some(stderr),
                    ready,
                    token: config.token.clone(),
                    tls: config.tls.is_some(),
                    controls: control_rx,
                })
            }
            Err(error) => {
                // Readers are joined only after a positively exited owned
                // process. An OS liveness error leaves bounded watchdogs in
                // force instead of risking a kill against uncertain ownership.
                terminate_owned(&mut child)?;
                let _ = writer.join();
                let _ = stdout.join();
                let _ = stderr.join();
                Err(error)
            }
        }
    }

    fn connect(
        &self,
        controller: &str,
        deployment: Option<&tls::Deployment>,
        linear: bool,
    ) -> Result<AgentClient, String> {
        if let Some(deployment) = deployment {
            if !self.tls {
                return Err("TLS deployment cannot fall back to the legacy transport".into());
            }
            return Ok(AgentClient::Tls(Box::new(SecureClient::connect(
                &deployment.agent_endpoint(linear, self.ready.address)?,
                &deployment.controller,
            )?)));
        }
        if self.tls {
            return Err("TLS partner requires a provisioned TLS client".into());
        }
        Ok(AgentClient::Legacy(Client::connect_scoped(
            &Endpoint {
                id: self.ready.id.clone(),
                address: self.ready.address,
                token: self.token.clone(),
            },
            controller,
            AGENT_OPS,
            SCOPE,
        )?))
    }

    fn revoke_controller(&mut self) -> Result<(), String> {
        if !self.tls {
            return Err("certificate revocation requires TLS".into());
        }
        let input = self
            .stdin
            .as_mut()
            .ok_or("partner control pipe unavailable")?;
        input
            .write_all(b"{\"command\":\"revoke-controller\"}\n")
            .and_then(|()| input.flush())
            .map_err(|_| "cannot send bounded owner revocation".to_string())?;
        self.controls
            .recv_timeout(STOP_TIMEOUT)
            .map_err(|_| "child certificate revocation acknowledgement deadline exceeded".into())
    }

    fn shutdown(&mut self) -> Result<(), String> {
        if let Some(mut input) = self.stdin.take() {
            let _ = input.write_all(b"{\"command\":\"shutdown\"}\n");
            drop(input);
        }
        let deadline = Instant::now() + STOP_TIMEOUT;
        let status = loop {
            match self
                .child
                .try_wait()
                .map_err(|_| "cannot inspect partner process")?
            {
                Some(status) => break status,
                None if Instant::now() >= deadline => {
                    terminate_owned(&mut self.child)?;
                    self.join_readers()?;
                    return Err("partner shutdown deadline exceeded; process killed and joined; inspect its lock state".into());
                }
                None => thread::sleep(Duration::from_millis(10)),
            }
        };
        self.join_readers()?;
        if !status.success() {
            return Err("partner exited unsuccessfully; preserve its ledger and recover stale locks explicitly".into());
        }
        Ok(())
    }

    fn join_readers(&mut self) -> Result<(), String> {
        if let Some(reader) = self.stdout.take() {
            let trailing = reader
                .join()
                .map_err(|_| "partner stdout reader panicked")??;
            if !trailing.is_empty() {
                return Err("partner wrote unexpected stdout after readiness".into());
            }
        }
        if let Some(reader) = self.stderr.take() {
            let errors = reader
                .join()
                .map_err(|_| "partner stderr reader panicked")??;
            if !errors.is_empty() {
                return Err("partner emitted a bounded diagnostic (content withheld to protect capabilities)".into());
            }
        }
        Ok(())
    }
}
impl Drop for SupervisedChild {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.shutdown();
            if terminate_owned(&mut self.child).is_err() {
                return;
            }
        }
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.join_readers();
        }
    }
}

#[derive(Default)]
struct OracleCounters {
    observe: AtomicU64,
    verify: AtomicU64,
    assess: AtomicU64,
}
impl OracleCounters {
    fn snapshot(&self) -> [u64; 3] {
        [
            self.observe.load(Ordering::SeqCst),
            self.verify.load(Ordering::SeqCst),
            self.assess.load(Ordering::SeqCst),
        ]
    }
}

struct OracleView {
    source: String,
    target: String,
    width: u8,
    environment: Environment,
    judge: Judge,
    authority: Arc<Mutex<Authority>>,
    counters: Arc<OracleCounters>,
}
impl OracleView {
    fn handle(&self, operation: &str, payload: Value) -> Result<Value, String> {
        match operation {
            "observe" => {
                self.counters.observe.fetch_add(1, Ordering::SeqCst);
            }
            "verify" => {
                self.counters.verify.fetch_add(1, Ordering::SeqCst);
            }
            "assess" => {
                self.counters.assess.fetch_add(1, Ordering::SeqCst);
            }
            _ => return Err("unsupported laboratory operation".into()),
        }
        if operation == "observe" {
            let raw = payload["input"].as_u64().ok_or("input required")?;
            let input = u16::try_from(raw).map_err(|_| "input outside schema")?;
            let output = self.environment.observe(input)?;
            return Ok(json!(self
                .authority
                .lock()
                .map_err(|_| "lab authority unavailable")?
                .issue(&self.source, self.width, input, output)?));
        }
        let receipts: Vec<ObservationReceipt> = serde_json::from_value(payload["receipts"].clone())
            .map_err(|_| "invalid observation evidence")?;
        self.authority
            .lock()
            .map_err(|_| "lab authority unavailable")?
            .verify(&receipts, &self.target, self.width)?;
        if operation == "verify" {
            return Ok(
                json!({"verified":true,"bundle_digest":digest(&receipts)?,"observations":receipts.len()}),
            );
        }
        if operation == "assess" {
            let strategy: AffineStrategy = serde_json::from_value(payload["strategy"].clone())
                .map_err(|_| "invalid declarative strategy")?;
            if strategy.width != self.width {
                return Err("candidate schema mismatch".into());
            }
            if receipts
                .iter()
                .any(|receipt| strategy.predict(receipt.input).ok() != Some(receipt.output))
            {
                return Err("candidate contradicts its authenticated training observations".into());
            }
            let training: BTreeSet<u16> = receipts.iter().map(|r| r.input).collect();
            let cases: Result<Vec<TrialCase>, String> = (0..1_u16 << self.width)
                .filter(|input| !training.contains(input))
                .map(|input| {
                    Ok(TrialCase {
                        id: format!("network-heldout-{input}"),
                        input,
                        expected: self.judge.expected(input),
                        baseline: None,
                        candidate: strategy.predict(input)?,
                    })
                })
                .collect();
            let cases = cases?;
            let acquisition = receipts.len() as u64 * 100;
            let verification = cases.len() as u64 + receipts.len() as u64;
            return Ok(json!(TrialEvidence {
                evaluator: "separate-network-laboratory-judge/v1".into(),
                training_case_ids: receipts.iter().map(|r| r.id.clone()).collect(),
                training_inputs: receipts.iter().map(|r| r.input).collect(),
                cases,
                // This prototype establishes coverage and persistence only.
                // No isolated cost experiment has been executed here.
                costs: TrialCosts {
                    acquisition,
                    verification,
                    adoption: 1,
                    baseline: 0,
                    candidate: acquisition + verification + 1
                },
            }));
        }
        Err("unsupported laboratory operation".into())
    }
}

struct NativeAgent {
    config: ChildConfig,
    _identity: Store,
    knowledge: KnowledgeStore,
    source: Learner,
    received: Option<Learner>,
    transcript: Vec<ObservationReceipt>,
    received_receipts: Vec<ObservationReceipt>,
}
impl NativeAgent {
    fn oracle(&self, operation: &str, payload: &Value) -> Result<Value, String> {
        // The local transport serves one session at a time. Never keep an idle
        // oracle connection open while another child needs the listener.
        let mut client = if let Some(tls) = &self.config.tls {
            AgentClient::Tls(Box::new(SecureClient::connect(
                &tls.oracle_endpoint(&self.config.oracle.id, self.config.oracle.address)?,
                &tls.client(&self.config.id)?,
            )?))
        } else {
            AgentClient::Legacy(Client::connect_scoped(
                &self.config.oracle.endpoint(),
                &self.config.id,
                ORACLE_OPS,
                SCOPE,
            )?)
        };
        let result = client.call(operation, payload)?;
        client.revoke()?;
        Ok(result)
    }
    fn record_id(&self) -> String {
        format!("deployed-{}", self.config.target_domain)
    }
    fn retained(&self) -> Result<Option<KnowledgeRecord>, String> {
        let record = self
            .knowledge
            .active()
            .into_iter()
            .find(|record| record.id == self.record_id());
        if let Some(record) = record.as_ref() {
            let strategy: AffineStrategy = serde_json::from_value(record.payload.clone())
                .map_err(|_| "retained declarative model is invalid")?;
            if record.source != self.config.peer
                || record.scope != format!("{SCOPE}/{}", self.config.target_domain)
                || record.schema_fingerprint != affine_schema_fingerprint(self.config.width)?
                || strategy.width != self.config.width
            {
                return Err("retained model does not match this agent's exact peer, context and input schema".into());
            }
        }
        Ok(record)
    }
    fn handle(&mut self, operation: &str, payload: Value) -> Result<Value, String> {
        if operation == "status" {
            return Ok(
                json!({"identity":self._identity.identity(),"pid":std::process::id(),"active_models":self.knowledge.active().len(),"model_origin":if self.retained()?.is_some(){"persistent-knowledge"}else{"none"}}),
            );
        }
        if operation == "next" {
            return Ok(json!({"input":self.source.next()?}));
        }
        if operation == "observe" {
            let receipt: ObservationReceipt =
                serde_json::from_value(self.oracle("observe", &payload)?)
                    .map_err(|_| "invalid oracle observation")?;
            if receipt.domain != self.config.source_domain
                || receipt.schema != affine_schema_fingerprint(self.config.width)?
            {
                return Err("oracle observation scope mismatch".into());
            }
            self.source.observe(receipt.input, receipt.output)?;
            self.transcript.push(receipt.clone());
            return Ok(json!(receipt));
        }
        if operation == "bundle" {
            return Ok(json!(self.transcript));
        }
        if operation == "adopt" {
            let receipts: Vec<ObservationReceipt> =
                serde_json::from_value(payload).map_err(|_| "invalid transfer evidence")?;
            let verified = self.oracle("verify", &json!({"receipts":receipts}))?;
            if verified["verified"] != true
                || verified["bundle_digest"].as_str() != Some(digest(&receipts)?.as_str())
            {
                return Err("independent receipt verification failed".into());
            }
            let mut learner = Learner::new(self.config.width, self.config.linear)?;
            for receipt in &receipts {
                learner.observe(receipt.input, receipt.output)?;
            }
            let strategy = learner.strategy()?;
            self.received = Some(learner);
            self.received_receipts = receipts;
            return Ok(
                json!({"status":"PROVISIONAL","strategy":strategy,"verified_observations":self.received_receipts.len()}),
            );
        }
        if operation == "promote" {
            let strategy = self
                .received
                .as_ref()
                .ok_or("no provisional model")?
                .strategy()?;
            if let Some(record) = self.retained()? {
                if record.payload == json!(strategy) {
                    return Ok(
                        json!({"promoted":false,"already_retained":true,"active_models":self.knowledge.active().len()}),
                    );
                }
                return Err(
                    "retained model disagrees; explicit reassessment and revocation required"
                        .into(),
                );
            }
            let evidence: TrialEvidence = serde_json::from_value(self.oracle(
                "assess",
                &json!({"strategy":strategy,"receipts":self.received_receipts}),
            )?)
            .map_err(|_| "invalid independent assessment")?;
            let id = self.record_id();
            let record = KnowledgeRecord {
                id: id.clone(), revision: self.knowledge.highest_revision(&id).unwrap_or(0).checked_add(1).ok_or("knowledge revision exhausted")?,
                source: self.config.peer.clone(), scope: format!("{SCOPE}/{}", self.config.target_domain), schema_fingerprint: affine_schema_fingerprint(self.config.width)?, payload: json!(strategy),
                provenance: "Actual external-process observations verified through pinned laboratory authority API; distinct judge checked disjoint inputs before this private child ledger promotion".into(),
            };
            let assessment = assess(&record, &evidence)?;
            let correct = assessment.candidate_correct;
            let total = assessment.independent_cases;
            self.knowledge.promote(record, assessment)?;
            if self.config.fault == "exit-after-promotion" {
                std::process::exit(74);
            }
            return Ok(
                json!({"promoted":true,"already_retained":false,"correct":correct,"total":total,"active_models":self.knowledge.active().len()}),
            );
        }
        if operation == "forecast" {
            let inputs: Vec<u16> = serde_json::from_value(payload["inputs"].clone())
                .map_err(|_| "bounded input list required")?;
            if inputs.len() > 256 || inputs.iter().any(|x| *x >= 1 << self.config.width) {
                return Err("forecast outside bounded schema".into());
            }
            if let Some(record) = self.retained()? {
                let predictions: Result<Vec<u8>, String> =
                    inputs.iter().map(|input| record.predict(*input)).collect();
                return Ok(json!({"outputs":predictions?,"origin":"persistent-knowledge"}));
            }
            let received = self
                .received
                .as_mut()
                .ok_or("no evaluated model available")?;
            let predictions: Result<Vec<Option<u8>>, String> = inputs
                .iter()
                .map(|input| received.predict(*input))
                .collect();
            return Ok(json!({"outputs":predictions?,"origin":"provisional-conditional-model"}));
        }
        Err("unsupported native partner operation".into())
    }
}

pub(crate) fn serve_from_stdin() -> Result<(), String> {
    // Bound even a caller that starts the hidden mode but withholds its config.
    let (configured_tx, configured_rx) = mpsc::channel();
    let startup_watchdog = thread::spawn(move || {
        if matches!(
            configured_rx.recv_timeout(STARTUP_TIMEOUT),
            Err(mpsc::RecvTimeoutError::Timeout)
        ) {
            std::process::exit(70);
        }
    });
    let mut input = BufReader::new(std::io::stdin().lock());
    let raw = bounded_line(&mut input, tls::BOOTSTRAP_LIMIT)?;
    let config: ChildConfig =
        serde_json::from_slice(&raw).map_err(|_| "child configuration rejected")?;
    if config.tls.is_none() && raw.len() > CONFIG_LIMIT {
        return Err("legacy child configuration exceeds startup budget".into());
    }
    config.validate()?;
    let _ = configured_tx.send(());
    let _ = startup_watchdog.join();
    let (finished_tx, finished_rx) = mpsc::channel();
    let lease = Duration::from_millis(config.lease_ms);
    let watchdog = thread::spawn(move || {
        if matches!(
            finished_rx.recv_timeout(lease),
            Err(mpsc::RecvTimeoutError::Timeout)
        ) {
            std::process::exit(71);
        }
    });
    let identity = Store::open(&config.state)?;
    if identity.identity() == config.controller {
        return Err("native partner identity aliases the controller".into());
    }
    if config.tls.is_some() && identity.identity() != config.id {
        return Err("TLS partner identity does not match the provisioned certificate role".into());
    }
    let knowledge = KnowledgeStore::open(&config.state, identity.identity())?;
    let private_identity = identity.identity().to_string();
    let active_models = knowledge.active().len();
    let server_config = ServerConfig {
        id: config.id.clone(),
        token: config.token.clone(),
        client_id: config.controller.clone(),
        operations: AGENT_OPS.iter().map(|x| x.to_string()).collect(),
        max_requests: 128,
        max_frame_bytes: 32768,
        timeout: Duration::from_secs(3),
    };
    let fault = config.fault.clone();
    let id = config.id.clone();
    let tls_config = config
        .tls
        .as_ref()
        .map(|tls| tls.server(&config.id, &config.controller))
        .transpose()?;
    let controller_id = config.controller.clone();
    let agent = NativeAgent {
        source: Learner::new(config.width, config.linear)?,
        config,
        _identity: identity,
        knowledge,
        received: None,
        transcript: Vec::new(),
        received_receipts: Vec::new(),
    };
    agent.retained()?;
    let shared = Arc::new(Mutex::new(agent));
    let handler = Arc::clone(&shared);
    let handle = move |op: &str, payload: Value| {
        handler
            .lock()
            .map_err(|_| "native agent state unavailable")?
            .handle(op, payload)
    };
    let mut server = if let Some(config) = tls_config {
        NativeServer::Tls(spawn_secure_server(config, move |_, op, payload| {
            handle(op, payload)
        })?)
    } else {
        NativeServer::Legacy(spawn_scoped_server(server_config, SCOPE, handle)?)
    };
    if fault == "stall-before-ready" {
        thread::sleep(lease + Duration::from_secs(1));
    }
    let ready = Ready {
        schema: "symbiote.partner-ready/1".into(),
        id,
        identity: private_identity,
        pid: std::process::id(),
        instance_nonce: fresh_capability()?,
        address: server.address(),
        active_models,
    };
    println!(
        "{}",
        serde_json::to_string(&ready).map_err(|_| "cannot encode readiness")?
    );
    std::io::stdout()
        .flush()
        .map_err(|_| "cannot flush readiness")?;
    if fault == "exit-after-ready" {
        std::process::exit(73);
    }
    // Child lifecycle commands are owner-controlled enums on stdin, never code.
    let mut commands = 0;
    let normal = loop {
        commands += 1;
        if commands > 8 {
            break false;
        }
        let Ok(raw) = bounded_line(&mut input, 128) else {
            break false;
        };
        let Ok(command) = serde_json::from_slice::<Value>(&raw) else {
            break false;
        };
        if command == json!({"command":"shutdown"}) {
            break true;
        }
        if command == json!({"command":"revoke-controller"})
            && matches!(server, NativeServer::Tls(_))
        {
            server.revoke_peer(&controller_id)?;
            println!(
                "{}",
                json!({"schema":"symbiote.partner-control/1","event":"controller-revoked"})
            );
            std::io::stdout()
                .flush()
                .map_err(|_| "cannot acknowledge owner revocation")?;
            continue;
        }
        break false;
    };
    server.shutdown()?;
    drop(shared);
    let _ = finished_tx.send(());
    let _ = watchdog.join();
    if !normal {
        return Err("partner control pipe ended without an explicit shutdown".into());
    }
    Ok(())
}

fn private_config(
    id: &str,
    peer: &str,
    controller: &str,
    state: PathBuf,
    domains: (&str, &str),
    oracle: Endpoint,
    linear: bool,
) -> Result<ChildConfig, String> {
    Ok(ChildConfig {
        version: 1,
        id: id.into(),
        controller: controller.into(),
        peer: peer.into(),
        token: fresh_capability()?,
        oracle: Grant {
            id: oracle.id,
            address: oracle.address,
            token: oracle.token,
        },
        state,
        source_domain: domains.0.into(),
        target_domain: domains.1.into(),
        width: 4,
        linear,
        lease_ms: 30_000,
        fault: String::new(),
        tls: None,
    })
}

pub(crate) fn run(state: &Path, receipts: &Path) -> Result<Value, String> {
    run_with_fault(state, receipts, "none")
}

pub(crate) fn run_with_fault(state: &Path, receipts: &Path, fault: &str) -> Result<Value, String> {
    run_configured(state, receipts, fault, None)
}

/// Prepare durable role identities only. This explicitly provisions no trust,
/// certificates, network sessions, observations or learning artifacts.
pub(crate) fn initialize_tls_state(state: &Path) -> Result<Value, String> {
    let paths = [
        state.to_path_buf(),
        state.join("network-tls/exact"),
        state.join("network-tls/linear"),
    ];
    let mut existing = BTreeSet::new();
    for path in &paths {
        let inspection = symbiote_memory::maintenance::inspect(path)?;
        if let Some(id) = inspection.identity {
            if !existing.insert(id) {
                return Err(
                    "prepared TLS role identities alias each other; existing state was preserved"
                        .into(),
                );
            }
        } else if path.join("knowledge.jsonl").exists() {
            return Err("structural knowledge exists without its TLS role identity".into());
        }
    }
    let controller = Store::open(&paths[0])?;
    let exact = Store::open(&paths[1])?;
    let linear = Store::open(&paths[2])?;
    if [controller.identity(), exact.identity(), linear.identity()]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .len()
        != 3
    {
        return Err("prepared TLS roles require three distinct persistent identities".into());
    }
    Ok(
        json!({"schema":"symbiote.tls-preparation/1","status":"PREPARED","roles":{
        "controller":{"id":controller.identity(),"state":paths[0]},
        "exact":{"id":exact.identity(),"state":paths[1]},
        "linear":{"id":linear.identity(),"state":paths[2]}},
        "network_requests":0,"learning_artifacts_created":0,"certificates_created":0}),
    )
}

pub(crate) fn run_tls(state: &Path, receipts: &Path, config_path: &Path) -> Result<Value, String> {
    let deployment = tls::Deployment::load(state, config_path)?;
    run_configured(state, receipts, "none", Some(&deployment))
}

fn run_configured(
    state: &Path,
    receipts: &Path,
    fault: &str,
    deployment: Option<&tls::Deployment>,
) -> Result<Value, String> {
    let identity = Store::open(state)?;
    let controller = identity.identity().to_string();
    if deployment.is_some_and(|tls| tls.controller_id != controller) {
        return Err("controller persistent identity changed after TLS provisioning".into());
    }
    let width = 4;
    let domain_a = "deployed-alpha-context-a";
    let domain_b = "deployed-beta-context-b";
    let (coeff_a, bias_a) = parameters(width, 7, false);
    let (coeff_b, bias_b) = parameters(width, 7, true);
    let authority = Arc::new(Mutex::new(Authority::default()));
    let counters_a = Arc::new(OracleCounters::default());
    let counters_b = Arc::new(OracleCounters::default());
    let oracle_config = |id: &str, client: &str| -> Result<ServerConfig, String> {
        Ok(ServerConfig {
            id: id.into(),
            token: fresh_capability()?,
            client_id: client.into(),
            operations: ORACLE_OPS.iter().map(|s| s.to_string()).collect(),
            max_requests: 128,
            max_frame_bytes: 32768,
            timeout: Duration::from_secs(3),
        })
    };
    let view_a = OracleView {
        source: domain_a.into(),
        target: domain_b.into(),
        width,
        environment: Environment::Circuit {
            width,
            wires: (0..usize::from(width))
                .filter(|i| coeff_a & (1 << i) != 0)
                .collect(),
            inverted: bias_a,
        },
        judge: Judge::new(width, coeff_b, bias_b),
        authority: Arc::clone(&authority),
        counters: Arc::clone(&counters_a),
    };
    let view_b = OracleView {
        source: domain_b.into(),
        target: domain_a.into(),
        width,
        environment: Environment::Arithmetic {
            width,
            mask: coeff_b,
            offset: u8::from(bias_b),
        },
        judge: Judge::new(width, coeff_a, bias_a),
        authority,
        counters: Arc::clone(&counters_b),
    };
    let mut oracle_a = if let Some(tls) = deployment {
        NativeServer::Tls(spawn_secure_server(
            tls.oracle_server(false)?,
            move |_, op, payload| view_a.handle(op, payload),
        )?)
    } else {
        NativeServer::Legacy(spawn_scoped_server(
            oracle_config("deployed-oracle-alpha", "network-exact")?,
            SCOPE,
            move |op, payload| view_a.handle(op, payload),
        )?)
    };
    let mut oracle_b = if let Some(tls) = deployment {
        NativeServer::Tls(spawn_secure_server(
            tls.oracle_server(true)?,
            move |_, op, payload| view_b.handle(op, payload),
        )?)
    } else {
        NativeServer::Legacy(spawn_scoped_server(
            oracle_config("deployed-oracle-beta", "network-linear")?,
            SCOPE,
            move |op, payload| view_b.handle(op, payload),
        )?)
    };
    let id_a = deployment.map_or("network-exact", |tls| tls.exact.id.as_str());
    let id_b = deployment.map_or("network-linear", |tls| tls.linear.id.as_str());
    let child_root = if deployment.is_some() {
        "network-tls"
    } else {
        "network"
    };
    let mut config_a = private_config(
        id_a,
        id_b,
        &controller,
        state.join(child_root).join("exact"),
        (domain_a, domain_b),
        oracle_a.grant().endpoint(),
        false,
    )?;
    config_a.fault = match fault {
        "none" => "",
        "startup-timeout" => "stall-before-ready",
        "crash-after-ready" => "exit-after-ready",
        "crash-after-promotion" => "exit-after-promotion",
        _ => return Err("unsupported deployment laboratory fault".into()),
    }
    .into();
    let mut config_b = private_config(
        id_b,
        id_a,
        &controller,
        state.join(child_root).join("linear"),
        (domain_b, domain_a),
        oracle_b.grant().endpoint(),
        true,
    )?;
    if let Some(tls) = deployment {
        for (config, linear) in [(&mut config_a, false), (&mut config_b, true)] {
            config.version = 2;
            config.token.clear();
            config.oracle.token.clear();
            config.tls = Some(tls.bootstrap(linear));
        }
    }
    let mut child_a = SupervisedChild::spawn(&config_a)?;
    let previous_b = symbiote_memory::maintenance::inspect(&config_b.state)?;
    if previous_b.identity.as_deref() == Some(child_a.ready.identity.as_str()) {
        return Err(
            "native partner identities alias each other; existing state was preserved".into(),
        );
    }
    let mut child_b = SupervisedChild::spawn(&config_b)?;
    if child_a.ready.pid == child_b.ready.pid
        || child_a.ready.pid == std::process::id()
        || child_b.ready.pid == std::process::id()
        || child_a.ready.identity == child_b.ready.identity
        || child_a.ready.identity == controller
        || child_b.ready.identity == controller
    {
        return Err("native process/identity separation failed".into());
    }
    let ready_a = child_a.ready.clone();
    let ready_b = child_b.ready.clone();
    let mut client_a = child_a.connect(&controller, deployment, false)?;
    let mut client_b = child_b.connect(&controller, deployment, true)?;
    let bundle_a = fit_native(&mut client_a, width)?;
    let bundle_b = fit_native(&mut client_b, width)?;
    let mut forged = bundle_b.clone();
    forged[0].output ^= 1;
    let forged_rejected = client_a.call("adopt", &json!(forged)).is_err();
    // A rejected request closes the client by design; reconnect with the same
    // explicitly authorized capability before the valid exchange.
    drop(client_a);
    client_a = child_a.connect(&controller, deployment, false)?;
    let cross_domain_rejected = client_a.call("adopt", &json!(bundle_a)).is_err();
    drop(client_a);
    client_a = child_a.connect(&controller, deployment, false)?;
    let mut repeated = bundle_b.clone();
    repeated[1] = repeated[0].clone();
    let duplicate_rejected = client_a.call("adopt", &json!(repeated)).is_err();
    drop(client_a);
    client_a = child_a.connect(&controller, deployment, false)?;
    client_a.call("adopt", &json!(bundle_b))?;
    client_b.call("adopt", &json!(bundle_a))?;
    let promoted_a = client_a.call("promote", &json!({}))?;
    let promoted_b = client_b.call("promote", &json!({}))?;
    let inputs: Vec<u16> = (0..1 << width).collect();
    let predictions_a = client_a.call("forecast", &json!({"inputs":inputs}))?;
    let predictions_b = client_b.call("forecast", &json!({"inputs":inputs}))?;
    client_a.revoke()?;
    client_b.revoke()?;
    let revoked_session_rejected =
        deployment.is_none() || client_a.call("status", &json!({})).is_err();
    child_a.shutdown()?;
    child_b.shutdown()?;
    let before_restart_a = counters_a.snapshot();
    let before_restart_b = counters_b.snapshot();
    // Real new OS processes load the private ledgers and predict without a new
    // offer, observation, adoption or promotion request.
    let mut restart_a = SupervisedChild::spawn(&config_a)?;
    let mut restart_b = SupervisedChild::spawn(&config_b)?;
    if restart_a.ready.identity == controller
        || restart_b.ready.identity == controller
        || restart_a.ready.identity == restart_b.ready.identity
    {
        return Err("restarted native identities are not independent".into());
    }
    let mut retained_a = restart_a.connect(&controller, deployment, false)?;
    let mut retained_b = restart_b.connect(&controller, deployment, true)?;
    let after_a = retained_a.call("forecast", &json!({"inputs":inputs}))?;
    let after_b = retained_b.call("forecast", &json!({"inputs":inputs}))?;
    let after_restart_a = counters_a.snapshot();
    let after_restart_b = counters_b.snapshot();
    let requests_a: Vec<u64> = after_restart_a
        .iter()
        .zip(before_restart_a)
        .map(|(after, before)| after - before)
        .collect();
    let requests_b: Vec<u64> = after_restart_b
        .iter()
        .zip(before_restart_b)
        .map(|(after, before)| after - before)
        .collect();
    let restart_requests: Vec<u64> = requests_a
        .iter()
        .zip(&requests_b)
        .map(|(a, b)| a + b)
        .collect();
    let total_requests: Vec<u64> = after_restart_a
        .iter()
        .zip(after_restart_b)
        .map(|(a, b)| a + b)
        .collect();
    let retained = after_a == predictions_a
        && after_b == predictions_b
        && after_a["origin"] == "persistent-knowledge"
        && after_b["origin"] == "persistent-knowledge"
        && restart_a.ready.identity == ready_a.identity
        && restart_b.ready.identity == ready_b.identity
        && restart_a.ready.instance_nonce != ready_a.instance_nonce
        && restart_b.ready.instance_nonce != ready_b.instance_nonce
        && restart_requests.iter().all(|count| *count == 0);
    if !retained
        || !forged_rejected
        || !cross_domain_rejected
        || !duplicate_rejected
        || !revoked_session_rejected
    {
        return Err("deployed evidence/persistence gate failed".into());
    }
    retained_a.revoke()?;
    retained_b.revoke()?;
    let mut certificate_revocation_rejected = false;
    if deployment.is_some() {
        restart_a.revoke_controller()?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match restart_a.connect(&controller, deployment, false) {
                Err(_) => {
                    certificate_revocation_rejected = true;
                    break;
                }
                Ok(mut client) => {
                    let _ = client.revoke();
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        if !certificate_revocation_rejected {
            return Err("TLS certificate revocation did not prevent reconnection".into());
        }
    }
    let mut report = json!({
        "schema":"symbiote.network-research/1", "version":env!("CARGO_PKG_VERSION"), "status":"PASS", "identity":controller,
        "scope":"Boolean affine width4; native process/persistence prototype", "controller_pid":std::process::id(),
        "participants":[{"agent":"network-exact","pid":ready_a.pid,"restart_pid":restart_a.ready.pid,"instance_nonce":ready_a.instance_nonce,"restart_instance_nonce":restart_a.ready.instance_nonce,"identity":ready_a.identity,"active_models":restart_a.ready.active_models,"promotion":promoted_a,"restart_oracle_requests":{"observe":requests_a[0],"verify":requests_a[1],"assess":requests_a[2]}}, {"agent":"network-linear","pid":ready_b.pid,"restart_pid":restart_b.ready.pid,"instance_nonce":ready_b.instance_nonce,"restart_instance_nonce":restart_b.ready.instance_nonce,"identity":ready_b.identity,"active_models":restart_b.ready.active_models,"promotion":promoted_b,"restart_oracle_requests":{"observe":requests_b[0],"verify":requests_b[1],"assess":requests_b[2]}}],
        "process_separation":true, "private_identity_and_ledgers":true, "forged_receipt_rejected":forged_rejected,
        "cross_domain_receipt_rejected":cross_domain_rejected,"duplicate_receipt_rejected":duplicate_rejected,
        "restart_retained_predictions":retained,
        "restart_acquisition_requests":restart_requests[0],"restart_verification_requests":restart_requests[1],"restart_assessment_requests":restart_requests[2],
        "oracle_requests":{"observe":total_requests[0],"verify":total_requests[1],"assess":total_requests[2]},
        "hidden_law_parameters_sent_to_children":false, "secrets_in_arguments_or_readiness":false,
        "performance_claim":"none; no paired cost comparison is executed by this deployment prototype",
        "limitations":["trusted same-host laboratory oracle and evaluator", "independent native learner implementations share one executable", "loopback transport; no sandbox against a malicious same-user process", "one four-bit context; no new general transfer claim"]
    });
    if let Some(tls) = deployment {
        report["schema"] = json!("symbiote.tls-network-research/1");
        report["transport"] = json!({"protocol":"symbiote/2","tls_version":"TLS1.3","mutual_authentication":true,"explicit_ca_and_leaf_pins":true,"scope":SCOPE,"persistent_identity_bound":true,"revoked_session_rejected":revoked_session_rejected,"certificate_revocation_rejected":certificate_revocation_rejected,"plaintext_fallback":false});
        report["participants"][0]["authenticated_id"] = json!(tls.exact.id);
        report["participants"][1]["authenticated_id"] = json!(tls.linear.id);
        report["participants"][0]["certificate_sha256"] =
            json!(tls.exact.material.certificate_sha256);
        report["participants"][1]["certificate_sha256"] =
            json!(tls.linear.material.certificate_sha256);
        report["limitations"] = json!(["trusted same-host laboratory oracle and evaluator","independent native learner implementations share one executable","operator-provisioned TLS on explicit loopback endpoints; external deployment not tested","no sandbox against a malicious same-user process","one four-bit context; no new general transfer or cost improvement claim"]);
    }
    restart_a.shutdown()?;
    restart_b.shutdown()?;
    oracle_a.shutdown()?;
    oracle_b.shutdown()?;
    if let Some(parent) = receipts.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(
        receipts,
        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn control_frames_are_bounded_and_malformed_configuration_is_redacted() {
        let mut input = std::io::Cursor::new(vec![b'x'; CONFIG_LIMIT + 1]);
        assert!(bounded_line(&mut input, CONFIG_LIMIT).is_err());
        let raw = br#"{"token":"capability-must-not-be-printed"}"#;
        let result =
            serde_json::from_slice::<ChildConfig>(raw).map_err(|_| "child configuration rejected");
        assert_eq!(result.err(), Some("child configuration rejected"));
    }
}
