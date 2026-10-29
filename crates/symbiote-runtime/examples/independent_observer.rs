//! Explicitly authorized loopback embedding; not a new configured service mode.
//! The source supplies individual observations, never coefficients or a table.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use symbiote_memory::knowledge::{
    affine_schema_fingerprint, assess, KnowledgeAnchor, KnowledgeRecord, KnowledgeStore,
    TrialCosts, TrialEvidence,
};
use symbiote_reasoning::structural::{AffineQueryPolicy, CompactAffineLearner};
use symbiote_runtime::service::observation::{
    infer_with_policy, Observation, ObservationPermit, ObservationSource, Usage,
};

const FRAME_BYTES: usize = 4096;
const FREEZE_BYTES: usize = 131_072;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    source_id: String,
    scope: String,
    epoch: String,
    commitment: String,
    width: u8,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceConfig {
    schema: String,
    owner: String,
    source_id: String,
    scope: String,
    epoch: String,
    commitment: String,
    width: u8,
    address: SocketAddr,
    token_file: PathBuf,
    timeout_ms: u64,
    max_queries: usize,
    max_work_units: usize,
}
impl SourceConfig {
    fn descriptor(&self) -> Descriptor {
        Descriptor {
            source_id: self.source_id.clone(),
            scope: self.scope.clone(),
            epoch: self.epoch.clone(),
            commitment: self.commitment.clone(),
            width: self.width,
        }
    }
    fn validate(&self) -> Result<(), String> {
        if self.schema != "symbiote.independent-source-config/1"
            || ![&self.owner, &self.source_id, &self.scope, &self.epoch]
                .into_iter()
                .all(|value| label(value))
            || !hex(&self.commitment)
            || self.width != 8
            || !self.address.ip().is_loopback()
            || self.address.port() == 0
            || !self.token_file.is_absolute()
            || !(1..=12_000).contains(&self.timeout_ms)
            || !(1..=256).contains(&self.max_queries)
            || !(1..=1_000_000).contains(&self.max_work_units)
        {
            return Err(
                "invalid explicitly authorized bounded width-eight source configuration".into(),
            );
        }
        Ok(())
    }
}
#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceIo {
    attempts: usize,
    connections: usize,
    request_bytes: usize,
    response_bytes: usize,
}
#[derive(Serialize)]
struct Request<'a> {
    schema: &'static str,
    source_id: &'a str,
    scope: &'a str,
    epoch: &'a str,
    sequence: usize,
    input: u16,
    token: &'a str,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    schema: String,
    source_id: String,
    scope: String,
    epoch: String,
    commitment: String,
    width: u8,
    sequence: usize,
    input: u16,
    output: u8,
}
struct LoopbackSource {
    descriptor: Descriptor,
    address: SocketAddr,
    token: String,
    sequence: usize,
    io: SourceIo,
    cancel_file: Option<PathBuf>,
}
impl LoopbackSource {
    fn check(&self, cancelled: &AtomicBool, deadline: Instant) -> Result<(), String> {
        if cancelled.load(Ordering::Acquire)
            || Instant::now() >= deadline
            || self.cancel_file.as_ref().is_some_and(|path| path.exists())
        {
            return Err("cancelled or expired independent observation".into());
        }
        Ok(())
    }
    fn new(config: &SourceConfig, cancel_file: Option<PathBuf>) -> Result<Self, String> {
        let bytes = read_bounded(&config.token_file, 256)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(&config.token_file)
                .map_err(|_| "token metadata unavailable")?
                .permissions()
                .mode()
                & 0o077
                != 0
            {
                return Err("source token file must be private to its owner".into());
            }
        }
        let token = std::str::from_utf8(&bytes)
            .map_err(|_| "invalid private source token")?
            .trim();
        if !(16..=256).contains(&token.len())
            || !token
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || b"_-".contains(&value))
        {
            return Err("invalid private source token".into());
        }
        Ok(Self {
            descriptor: config.descriptor(),
            address: config.address,
            token: token.into(),
            sequence: 0,
            io: SourceIo::default(),
            cancel_file,
        })
    }
}
impl ObservationSource for LoopbackSource {
    fn width(&self) -> u8 {
        self.descriptor.width
    }
    fn observe(
        &mut self,
        input: u16,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> Result<Observation, String> {
        self.check(cancelled, deadline)?;
        self.io.attempts += 1;
        let remaining = deadline.saturating_duration_since(Instant::now());
        let mut stream =
            TcpStream::connect_timeout(&self.address, remaining.min(Duration::from_millis(50)))
                .map_err(|_| "independent source connection unavailable")?;
        self.io.connections += 1;
        stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .map_err(|_| "source read deadline unavailable")?;
        stream
            .set_write_timeout(Some(Duration::from_millis(50)))
            .map_err(|_| "source write deadline unavailable")?;
        let request = Request {
            schema: "symbiote.switchbox-request/1",
            source_id: &self.descriptor.source_id,
            scope: &self.descriptor.scope,
            epoch: &self.descriptor.epoch,
            sequence: self.sequence,
            input,
            token: &self.token,
        };
        let mut bytes =
            serde_json::to_vec(&request).map_err(|_| "source request serialization failed")?;
        bytes.push(b'\n');
        if bytes.len() > FRAME_BYTES {
            return Err("source request exceeds frame limit".into());
        }
        let mut pending = bytes.as_slice();
        while !pending.is_empty() {
            self.check(cancelled, deadline)?;
            match stream.write(pending) {
                Ok(0) => return Err("source request stream closed".into()),
                Ok(count) => {
                    self.io.request_bytes += count;
                    pending = &pending[count..];
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) => {}
                Err(_) => return Err("source request write failed".into()),
            }
        }
        let mut response = Vec::new();
        let mut chunk = [0u8; 256];
        let line = loop {
            self.check(cancelled, deadline)?;
            match stream.read(&mut chunk) {
                Ok(0) => return Err("source response closed before its frame".into()),
                Ok(count) => {
                    self.io.response_bytes += count;
                    if response.len() + count > FRAME_BYTES {
                        return Err("source response exceeds frame limit".into());
                    }
                    response.extend_from_slice(&chunk[..count]);
                    if let Some(end) = response.iter().position(|value| *value == b'\n') {
                        if response[end + 1..]
                            .iter()
                            .any(|value| !value.is_ascii_whitespace())
                        {
                            return Err("source returned more than one response frame".into());
                        }
                        break &response[..end];
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) => {}
                Err(_) => return Err("source response read failed".into()),
            }
        };
        self.check(cancelled, deadline)?;
        let reply: Reply =
            serde_json::from_slice(line).map_err(|_| "malformed independent source response")?;
        if reply.schema != "symbiote.switchbox-response/1"
            || reply.source_id != self.descriptor.source_id
            || reply.scope != self.descriptor.scope
            || reply.epoch != self.descriptor.epoch
            || reply.commitment != self.descriptor.commitment
            || reply.width != self.descriptor.width
            || reply.sequence != self.sequence
            || reply.input != input
            || reply.output > 1
        {
            return Err("independent source response binding rejected".into());
        }
        self.sequence += 1;
        Ok(Observation {
            sequence: reply.sequence,
            input: reply.input,
            output: reply.output,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Freeze {
    schema: String,
    status: String,
    build_source_commit: String,
    identity: String,
    source: Descriptor,
    source_descriptor_sha256: String,
    query_policy: AffineQueryPolicy,
    record: KnowledgeRecord,
    record_sha256: String,
    knowledge_before: KnowledgeAnchor,
    knowledge_after: KnowledgeAnchor,
    observations: Vec<Observation>,
    observed_inputs: Vec<u16>,
    training_count: usize,
    source_queries: usize,
    gf2_work_units: usize,
    snapshot: Value,
    source_io: SourceIo,
    events: Vec<Value>,
    baseline_kind: String,
    physical_certificate_authorized: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema: String,
    freeze_sha256: String,
    inputs: Vec<u16>,
}
struct Args {
    mode: String,
    config: PathBuf,
    state: PathBuf,
    receipts: PathBuf,
    inputs: Option<PathBuf>,
    policy: AffineQueryPolicy,
    cancel_file: Option<PathBuf>,
}
fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}
fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn digest<T: Serialize>(value: &T) -> Result<String, String> {
    let value = serde_json::to_value(value).map_err(|_| "canonical value unavailable")?;
    let bytes = serde_json::to_vec(&value).map_err(|_| "canonical bytes unavailable")?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    if path.is_symlink() || !path.is_file() {
        return Err("input must be an existing regular nonlinked file".into());
    }
    let file = fs::File::open(path).map_err(|_| "input open failed")?;
    if file.metadata().map_err(|_| "input metadata failed")?.len() > limit as u64 {
        return Err("input byte limit exceeded".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "input read failed")?;
    if bytes.len() > limit {
        return Err("input byte limit exceeded".into());
    }
    Ok(bytes)
}
fn encoded<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| "receipt serialization failed")?;
    bytes.push(b'\n');
    if bytes.len() > FREEZE_BYTES {
        return Err("receipt byte limit exceeded".into());
    }
    Ok(bytes)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "fresh receipt path required")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "receipt publication failed".to_string())
}
impl Args {
    fn parse(values: &[String]) -> Result<Self, String> {
        let mode = values.first().ok_or("learn or predict command required")?;
        if !matches!(mode.as_str(), "learn" | "predict") {
            return Err("unknown example command".into());
        }
        let mut options = BTreeMap::new();
        for pair in values[1..].chunks(2) {
            if pair.len() != 2
                || ![
                    "--source-config",
                    "--state",
                    "--receipts",
                    "--inputs",
                    "--query-policy",
                    "--cancel-file",
                ]
                .contains(&pair[0].as_str())
                || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
            {
                return Err("unique named example arguments required".into());
            }
        }
        let get = |name| {
            options
                .get(name)
                .copied()
                .map(PathBuf::from)
                .ok_or_else(|| format!("missing {name}"))
        };
        let policy = match options
            .get("--query-policy")
            .copied()
            .unwrap_or("reference")
        {
            "reference" => AffineQueryPolicy::Reference,
            "rank" => AffineQueryPolicy::RankBasis,
            _ => return Err("query policy must be reference or rank".into()),
        };
        if mode == "predict"
            && (options.contains_key("--query-policy") || options.contains_key("--cancel-file"))
        {
            return Err("prediction is a frozen offline operation".into());
        }
        if mode == "learn" && options.contains_key("--inputs") {
            return Err("learning cannot receive evaluation inputs".into());
        }
        Ok(Self {
            mode: mode.clone(),
            config: get("--source-config")?,
            state: get("--state")?,
            receipts: get("--receipts")?,
            inputs: options.get("--inputs").map(|value| PathBuf::from(*value)),
            policy,
            cancel_file: options
                .get("--cancel-file")
                .map(|value| PathBuf::from(*value)),
        })
    }
}
fn learn(args: &Args, config: &SourceConfig) -> Result<Value, String> {
    if args.state.join("freeze.json").exists() || args.receipts.exists() {
        return Err("fresh learning and receipt paths required".into());
    }
    let mut store = KnowledgeStore::open(&args.state, &config.owner)?;
    let before = store.history_anchor();
    let descriptor = config.descriptor();
    let descriptor_sha = digest(&descriptor)?;
    let id = format!("independent-{}", &descriptor_sha[..32]);
    if store.highest_revision(&id).is_some() {
        return Err("prior or revoked model requires a separate reviewed operation".into());
    }
    let permit = ObservationPermit {
        schema: "symbiote.observation-permit/1".into(),
        scopes: vec![config.scope.clone()],
        max_queries_total: config.max_queries,
        max_gf2_work_total: config.max_work_units,
        heldout_cases: 1,
    };
    let mut source = LoopbackSource::new(config, args.cancel_file.clone())?;
    let mut usage = Usage::default();
    let mut events = Vec::new();
    let deadline = Instant::now() + Duration::from_millis(config.timeout_ms);
    let result = infer_with_policy(
        &mut source,
        &permit,
        &mut usage,
        &AtomicBool::new(false),
        deadline,
        args.policy,
        |phase, details| {
            events.push(json!({"phase":phase,"details":details}));
            Ok(())
        },
    );
    let inferred = match result {
        Ok(value) => value,
        Err(reason) => {
            let failure = json!({"schema":"symbiote.independent-observer-failure/1","status":"HOLD","reason":reason,
                "identity":config.owner,"source":descriptor,"source_queries":usage.queries,"gf2_work_units":usage.gf2_work,
                "query_policy":args.policy,"source_io":source.io,"events":events,
                "knowledge_before":before,"knowledge_after":store.history_anchor(),"fresh_promotions":0});
            write_new(&args.receipts, &encoded(&failure)?)?;
            return Err(reason);
        }
    };
    let audit = json!({"schema":"symbiote.independent-observation-audit/1","owner":config.owner,
        "source":descriptor,"source_descriptor_sha256":descriptor_sha,"query_policy":args.policy,
        "observations":inferred.queries,"training_count":inferred.training,"snapshot":inferred.snapshot,
        "conditional_family":"boolean-affine/v1","physical_certificate_authorized":false});
    let record = KnowledgeRecord {
        id,
        revision: 1,
        source: config.owner.clone(),
        scope: config.scope.clone(),
        schema_fingerprint: affine_schema_fingerprint(config.width)?,
        payload: serde_json::to_value(&inferred.model).map_err(|_| "model serialization failed")?,
        provenance: serde_json::to_string(&audit)
            .map_err(|_| "observation provenance unavailable")?,
    };
    let acquisition = (usage.queries + usage.gf2_work) as u64;
    let evidence = TrialEvidence {
        evaluator: format!("observer-eval/{}", &descriptor_sha[..24]),
        training_case_ids: inferred
            .queries
            .iter()
            .take(inferred.training)
            .map(|item| format!("training-{}", item.sequence))
            .collect(),
        training_inputs: inferred
            .queries
            .iter()
            .take(inferred.training)
            .map(|item| item.input)
            .collect(),
        cases: inferred.cases,
        costs: TrialCosts {
            acquisition,
            verification: 1,
            adoption: 1,
            baseline: 0,
            candidate: acquisition + 2,
        },
    };
    let assessment = assess(&record, &evidence)?;
    source.check(&AtomicBool::new(false), deadline)?;
    store.promote(record.clone(), assessment)?;
    let frozen = Freeze {
        schema: "symbiote.independent-observer-freeze/1".into(),
        status: "FROZEN".into(),
        build_source_commit: option_env!("SYMBIOTE_SOURCE_COMMIT")
            .unwrap_or("unknown")
            .into(),
        identity: config.owner.clone(),
        source: descriptor,
        source_descriptor_sha256: descriptor_sha,
        query_policy: args.policy,
        record_sha256: record.digest()?,
        record,
        knowledge_before: before,
        knowledge_after: store.history_anchor(),
        observed_inputs: inferred.queries.iter().map(|item| item.input).collect(),
        observations: inferred.queries,
        training_count: inferred.training,
        source_queries: usage.queries,
        gf2_work_units: usage.gf2_work,
        snapshot: inferred.snapshot,
        source_io: source.io,
        events,
        baseline_kind: "unknown".into(),
        physical_certificate_authorized: false,
    };
    let bytes = encoded(&frozen)?;
    write_new(&args.state.join("freeze.json"), &bytes)?;
    write_new(&args.receipts, &bytes)?;
    Ok(
        json!({"status":"FROZEN","receipts":args.receipts,"freeze_sha256":hash(&bytes),
        "source_queries":usage.queries,"gf2_work_units":usage.gf2_work,"query_policy":args.policy}),
    )
}
fn predict(args: &Args, config: &SourceConfig) -> Result<Value, String> {
    // Missing state is rejected before opening a store could initialize it.
    if !args.state.join("knowledge.jsonl").is_file() {
        return Err("existing frozen knowledge state required".into());
    }
    let freeze_bytes = read_bounded(&args.state.join("freeze.json"), FREEZE_BYTES)?;
    let frozen: Freeze =
        serde_json::from_slice(&freeze_bytes).map_err(|_| "frozen receipt schema rejected")?;
    let inputs: Inputs = serde_json::from_slice(&read_bounded(
        args.inputs.as_deref().ok_or("prediction inputs required")?,
        16_384,
    )?)
    .map_err(|_| "fresh input schema rejected")?;
    if inputs.schema != "symbiote.independent-observer-inputs/1"
        || inputs.freeze_sha256 != hash(&freeze_bytes)
        || inputs.inputs.is_empty()
        || inputs.inputs.len() > 256
        || inputs.inputs.iter().collect::<BTreeSet<_>>().len() != inputs.inputs.len()
        || inputs
            .inputs
            .iter()
            .any(|input| *input >= 256 || frozen.observed_inputs.contains(input))
        || frozen.schema != "symbiote.independent-observer-freeze/1"
        || frozen.status != "FROZEN"
        || frozen.identity != config.owner
        || frozen.source != config.descriptor()
        || frozen.source_descriptor_sha256 != digest(&config.descriptor())?
        || frozen.record_sha256 != frozen.record.digest()?
        || frozen.record.source != config.owner
        || frozen.record.scope != config.scope
        || frozen.training_count != 9
        || frozen.observations.len() != 10
        || frozen.observed_inputs
            != frozen
                .observations
                .iter()
                .map(|item| item.input)
                .collect::<Vec<_>>()
    {
        return Err("fresh inputs or frozen owner/source binding rejected".into());
    }
    let store = KnowledgeStore::open(&args.state, &config.owner)?;
    let before = store.history_anchor();
    if before != frozen.knowledge_after
        || !store
            .active()
            .iter()
            .any(|record| record.digest().ok().as_deref() == Some(frozen.record_sha256.as_str()))
    {
        return Err("frozen model was changed, superseded or revoked".into());
    }
    let audit: Value = serde_json::from_str(&frozen.record.provenance)
        .map_err(|_| "ledger-bound observation audit unavailable")?;
    if audit["schema"] != "symbiote.independent-observation-audit/1"
        || audit["owner"] != config.owner
        || audit["source"]
            != serde_json::to_value(&frozen.source).map_err(|_| "source descriptor unavailable")?
        || audit["source_descriptor_sha256"] != frozen.source_descriptor_sha256
        || audit["query_policy"]
            != serde_json::to_value(frozen.query_policy).map_err(|_| "query policy unavailable")?
        || audit["observations"]
            != serde_json::to_value(&frozen.observations)
                .map_err(|_| "observation audit unavailable")?
        || audit["training_count"] != frozen.training_count
        || audit["snapshot"] != frozen.snapshot
    {
        return Err("freeze differs from its ledger-bound observation audit".into());
    }
    let (_, trial) = store.promotion_evidence_between(
        &frozen.record,
        &frozen.knowledge_before,
        &frozen.knowledge_after,
    )?;
    let trial: TrialEvidence = serde_json::from_value(trial)
        .map_err(|_| "original stored observation evaluation unavailable")?;
    let heldout = &frozen.observations[frozen.training_count];
    if frozen.knowledge_before.records.checked_add(1) != Some(frozen.knowledge_after.records)
        || trial.training_inputs
            != frozen.observations[..frozen.training_count]
                .iter()
                .map(|item| item.input)
                .collect::<Vec<_>>()
        || trial.cases.len() != 1
        || trial.cases[0].input != heldout.input
        || trial.cases[0].expected != heldout.output
        || trial.cases[0].candidate != heldout.output
    {
        return Err("freeze differs from its actual stored promotion evaluation".into());
    }
    let ledger_before = hash(&read_bounded(&store.ledger_path(), 16 * 1024 * 1024)?);
    let mut replay = CompactAffineLearner::new(config.width, config.max_work_units)?;
    for (sequence, observation) in frozen.observations.iter().enumerate() {
        if observation.sequence != sequence || observation.output > 1 {
            return Err("frozen observation binding changed".into());
        }
        if sequence < frozen.training_count {
            replay.observe(observation.input, observation.output)?;
        } else if replay.forecast(observation.input)?.answer != Some(observation.output) {
            return Err("retained validation contradicted".into());
        }
    }
    let replay_model = replay
        .identified()
        .ok_or("retained observations do not identify a model")?;
    if serde_json::to_value(replay_model).map_err(|_| "replayed model unavailable")?
        != frozen.record.payload
    {
        return Err("retained model differs from exact observation replay".into());
    }
    let replay_work = replay.snapshot().work_units;
    let mut predictions = Vec::new();
    for input in inputs.inputs {
        let forecast = replay.forecast(input)?;
        let prediction = frozen.record.predict(input)?;
        if forecast.answer != Some(prediction) {
            return Err("retained declarative prediction differs from exact replay".into());
        }
        predictions.push(json!({"input":input,"prediction":prediction,"basis":forecast.basis,"conditional":true,"physical_certificate_authorized":false}));
    }
    if before != store.history_anchor()
        || ledger_before != hash(&read_bounded(&store.ledger_path(), 16 * 1024 * 1024)?)
    {
        return Err("knowledge changed during frozen prediction".into());
    }
    let result = json!({"schema":"symbiote.independent-observer-predictions/1","status":"PREDICTIONS_COMMITTED",
        "build_source_commit":option_env!("SYMBIOTE_SOURCE_COMMIT").unwrap_or("unknown"),
        "identity":config.owner,"source":config.descriptor(),"freeze_sha256":inputs.freeze_sha256,
        "record_sha256":frozen.record_sha256,"knowledge_before":before,"knowledge_after":store.history_anchor(),
        "source_queries":0,"source_contact_attempts":0,"query_policy":frozen.query_policy,"observed_inputs":frozen.observed_inputs,
        "replay_gf2_work_units":replay_work,"gf2_work_units":replay.snapshot().work_units,
        "retained_prediction_calls":predictions.len(),"predictions":predictions,"snapshot":replay.snapshot(),
        "learning_during_evaluation":false,"labels_received":false,"baseline_kind":"unknown","scientific_samples":0});
    let bytes = encoded(&result)?;
    write_new(&args.receipts, &bytes)?;
    Ok(
        json!({"status":"PREDICTIONS_COMMITTED","receipts":args.receipts,"receipts_sha256":hash(&bytes),"source_queries":0}),
    )
}
fn main() {
    let values: Vec<_> = std::env::args().skip(1).collect();
    if values == ["--version"] {
        println!(
            "{}",
            json!({"schema":"symbiote.independent-observer-version/1","name":"independent_observer", "version":env!("CARGO_PKG_VERSION"),"build_source_commit":option_env!("SYMBIOTE_SOURCE_COMMIT").unwrap_or("unknown")})
        );
        return;
    }
    if values.is_empty() || values[0] == "--help" {
        println!("independent_observer learn --source-config FILE --state DIR --receipts FILE --query-policy reference|rank [--cancel-file FILE]\nindependent_observer predict --source-config FILE --state DIR --inputs FILE --receipts FILE");
        return;
    }
    let result = Args::parse(&values).and_then(|args| {
        let config: SourceConfig = serde_json::from_slice(&read_bounded(&args.config, 16_384)?)
            .map_err(|_| "independent source configuration rejected")?;
        config.validate()?;
        if args.mode == "learn" {
            learn(&args, &config)
        } else {
            predict(&args, &config)
        }
    });
    match result {
        Ok(value) => println!("{value}"),
        Err(reason) => {
            eprintln!("{}", json!({"status":"HOLD","reason":reason}));
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn descriptor() -> Descriptor {
        Descriptor {
            source_id: "unit-source".into(),
            scope: "unit-affine/v1".into(),
            epoch: "unit-epoch-1".into(),
            commitment: "a".repeat(64),
            width: 8,
        }
    }
    fn source(address: SocketAddr) -> LoopbackSource {
        LoopbackSource {
            descriptor: descriptor(),
            address,
            token: "unit-only-private-token".into(),
            sequence: 0,
            io: SourceIo::default(),
            cancel_file: None,
        }
    }
    fn one_reply(reply: Vec<u8>, delay: Duration) -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                if stream.read(&mut byte).unwrap() == 0 {
                    break;
                }
                request.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
                assert!(request.len() < FRAME_BYTES);
            }
            let value: Value = serde_json::from_slice(&request).unwrap();
            assert_eq!(value["token"], "unit-only-private-token");
            thread::sleep(delay);
            let _ = stream.write_all(&reply);
        });
        (address, handle)
    }
    fn reply() -> Value {
        json!({"schema":"symbiote.switchbox-response/1","source_id":"unit-source",
            "scope":"unit-affine/v1","epoch":"unit-epoch-1","commitment":"a".repeat(64),
            "width":8,"sequence":0,"input":7,"output":0})
    }
    #[test]
    fn loopback_binding_and_actual_io_are_checked_without_exposing_the_token() {
        let mut bytes = serde_json::to_vec(&reply()).unwrap();
        bytes.push(b'\n');
        let expected_response = bytes.len();
        let (address, server) = one_reply(bytes, Duration::ZERO);
        let mut source = source(address);
        let observation = source
            .observe(
                7,
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(observation.output, 0);
        assert_eq!(source.io.attempts, 1);
        assert_eq!(source.io.connections, 1);
        assert_eq!(source.io.response_bytes, expected_response);
        assert!(source.io.request_bytes > 0);
        assert!(!serde_json::to_string(&source.io)
            .unwrap()
            .contains("unit-only-private-token"));
        server.join().unwrap();
    }
    #[test]
    fn malformed_unavailable_and_foreign_replies_fail_boundedly() {
        let mut frames = vec![b"not-json\n".to_vec(), vec![b'x'; FRAME_BYTES + 1]];
        for (field, value) in [
            ("sequence", json!(1)),
            ("input", json!(6)),
            ("output", json!(2)),
            ("epoch", json!("changed")),
            ("width", json!(7)),
            ("commitment", json!("b".repeat(64))),
            ("source_id", json!("foreign")),
            ("extra", json!("unrequested")),
        ] {
            let mut value_object = reply();
            value_object[field] = value;
            let mut bytes = serde_json::to_vec(&value_object).unwrap();
            bytes.push(b'\n');
            frames.push(bytes);
        }
        for bytes in frames {
            let (address, server) = one_reply(bytes, Duration::ZERO);
            let mut source = source(address);
            assert!(source
                .observe(
                    7,
                    &AtomicBool::new(false),
                    Instant::now() + Duration::from_secs(2)
                )
                .is_err());
            assert_eq!(source.sequence, 0);
            assert_eq!(source.io.attempts, 1);
            server.join().unwrap();
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        assert!(source(address)
            .observe(
                7,
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(1)
            )
            .is_err());
    }
    #[test]
    fn stalled_reply_and_cancellation_have_no_unbounded_read() {
        let mut bytes = serde_json::to_vec(&reply()).unwrap();
        bytes.push(b'\n');
        let (address, server) = one_reply(bytes, Duration::from_millis(200));
        let started = Instant::now();
        assert!(source(address)
            .observe(
                7,
                &AtomicBool::new(false),
                started + Duration::from_millis(80)
            )
            .is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
        let mut source = source(address);
        assert!(source
            .observe(
                7,
                &AtomicBool::new(true),
                Instant::now() + Duration::from_secs(1)
            )
            .is_err());
        assert_eq!(source.io.attempts, 0);
    }
}
