//! External consumer of documented engine APIs. Private wiring stays in an
//! independently implemented source process; this program receives one reply
//! per explicitly authorized observation and never receives grading labels.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use symbiote_runtime::engine::{
    AffineQueryPolicy, Artifact, Engine, EngineConfig, EngineEvent, EpisodeOptions, ErrorKind,
    EventSink, Observation, ObservationRequest, ObservationSource, SinkError, SourceDescriptor,
    SourceError,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_JSON: usize = 1024 * 1024;

fn read(path: &Path) -> Result<Vec<u8>> {
    for parent in path.ancestors() {
        let metadata = fs::symlink_metadata(parent)?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("reparse input path refused".into());
            }
        }
        if metadata.file_type().is_symlink() {
            return Err("linked input path refused".into());
        }
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take((MAX_JSON + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_JSON {
        return Err("bounded JSON input exceeded".into());
    }
    Ok(bytes)
}
fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&read(path)?)?)
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn write(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_JSON {
        return Err("bounded JSON output exceeded".into());
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
fn file_bytes(path: &Path) -> Result<u64> {
    let mut total = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if matches!(
            entry.file_name().to_str(),
            Some("writer.lock" | "knowledge.writer.lock" | "operations.writer.lock")
        ) {
            continue;
        }
        if entry.file_type()?.is_symlink() {
            return Err("linked state refused".into());
        }
        total += if entry.file_type()?.is_dir() {
            file_bytes(&entry.path())?
        } else {
            entry.metadata()?.len()
        };
    }
    Ok(total)
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    source: SourceDescriptor,
    address: SocketAddr,
    token_file: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateConfig {
    schema: String,
    sources: Vec<SourceDescriptor>,
    endpoints: BTreeMap<String, Endpoint>,
}
#[derive(Default, Serialize)]
struct IoUsage {
    attempts: usize,
    connections: usize,
    request_bytes: usize,
    response_bytes: usize,
}
#[derive(Serialize)]
struct Trace {
    source: SourceDescriptor,
    observations: Vec<Observation>,
    io: IoUsage,
}
struct NetworkSource {
    endpoint: Endpoint,
    token: String,
    trace: Trace,
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
impl NetworkSource {
    fn new(endpoint: Endpoint) -> Result<Self> {
        if !endpoint.address.ip().is_loopback()
            || endpoint.address.port() == 0
            || !endpoint.token_file.is_absolute()
        {
            return Err("explicit authorized loopback endpoint required".into());
        }
        let bytes = read(&endpoint.token_file)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(&endpoint.token_file)?.permissions().mode() & 0o077 != 0 {
                return Err("private bearer file permissions required".into());
            }
        }
        let token = std::str::from_utf8(&bytes)?.trim().to_string();
        if !(16..=256).contains(&token.len())
            || !token
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b"_-".contains(&v))
        {
            return Err("private source bearer invalid".into());
        }
        Ok(Self {
            trace: Trace {
                source: endpoint.source.clone(),
                observations: Vec::new(),
                io: IoUsage::default(),
            },
            endpoint,
            token,
        })
    }
    fn observe_inner(&mut self, request: ObservationRequest<'_>) -> Result<Observation> {
        let check = || -> Result<()> {
            if request.cancellation.is_cancelled() || Instant::now() >= request.deadline {
                return Err("source cancelled or deadline exceeded".into());
            }
            Ok(())
        };
        check()?;
        if request.source != &self.endpoint.source
            || request.sequence != self.trace.observations.len()
        {
            return Err("source authorization or sequence differs".into());
        }
        self.trace.io.attempts += 1;
        let remaining = request
            .deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(500));
        if remaining.is_zero() {
            return Err("source deadline".into());
        }
        let mut stream = TcpStream::connect_timeout(&self.endpoint.address, remaining)?;
        self.trace.io.connections += 1;
        stream.set_read_timeout(Some(Duration::from_millis(50)))?;
        stream.set_write_timeout(Some(Duration::from_millis(50)))?;
        let mut wire = serde_json::to_vec(&json!({"schema":"symbiote.switchbox-request/1",
            "source_id":request.source.source_id,"scope":request.source.scope,"epoch":request.source.epoch,
            "sequence":request.sequence,"input":request.input,"token":self.token}))?;
        wire.push(b'\n');
        if wire.len() > 4096 {
            return Err("source request frame budget".into());
        }
        let mut sent = 0;
        while sent < wire.len() {
            check()?;
            match stream.write(&wire[sent..]) {
                Ok(0) => return Err("source request closed".into()),
                Ok(count) => {
                    sent += count;
                    self.trace.io.request_bytes += count;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let mut raw = Vec::new();
        loop {
            check()?;
            let mut one = [0u8; 1];
            match stream.read(&mut one) {
                Ok(0) => return Err("source response closed".into()),
                Ok(_) => {
                    raw.push(one[0]);
                    self.trace.io.response_bytes += 1;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue
                }
                Err(error) => return Err(error.into()),
            }
            if raw.len() > 4096 {
                return Err("source response frame budget".into());
            }
            if one[0] == b'\n' {
                break;
            }
        }
        check()?;
        let reply: Reply = serde_json::from_slice(&raw)?;
        let expected = request.source;
        if reply.schema != "symbiote.switchbox-response/1"
            || reply.source_id != expected.source_id
            || reply.scope != expected.scope
            || reply.epoch != expected.epoch
            || reply.commitment != expected.commitment
            || reply.width != expected.width
            || reply.sequence != request.sequence
            || reply.input != request.input
            || reply.output > 1
        {
            return Err("source reply binding rejected".into());
        }
        let observation = Observation {
            sequence: reply.sequence,
            input: reply.input,
            output: reply.output,
        };
        self.trace.observations.push(observation.clone());
        Ok(observation)
    }
}
impl ObservationSource for NetworkSource {
    fn descriptor(&self) -> SourceDescriptor {
        self.endpoint.source.clone()
    }
    fn observe(
        &mut self,
        request: ObservationRequest<'_>,
    ) -> std::result::Result<Observation, SourceError> {
        let cancellation = request.cancellation.clone();
        let deadline = request.deadline;
        self.observe_inner(request).map_err(|_| {
            SourceError::new(
                if cancellation.is_cancelled() {
                    ErrorKind::Cancelled
                } else if Instant::now() >= deadline {
                    ErrorKind::DeadlineExceeded
                } else {
                    ErrorKind::Authorization
                },
                "bounded independent source observation rejected",
            )
        })
    }
}
#[derive(Default, Serialize)]
struct Sink {
    events: Vec<Value>,
}
impl EventSink for Sink {
    fn event(&mut self, event: &EngineEvent) -> std::result::Result<(), SinkError> {
        if self.events.len() >= 1024 {
            return Err(SinkError::new("consumer event budget"));
        }
        self.events
            .push(serde_json::to_value(event).map_err(|_| SinkError::new("event encoding"))?);
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Freeze {
    schema: String,
    arm: String,
    config: EngineConfig,
    owners: Vec<String>,
    foreign_artifacts: Vec<String>,
    artifacts: Vec<Artifact>,
    tickets: Vec<Value>,
    inspections: Vec<Value>,
    acquisition: Value,
    build_source_commit: String,
}
fn options(source: SourceDescriptor) -> EpisodeOptions {
    let mut value = EpisodeOptions::bounded(source);
    value.max_queries = 16;
    value.max_gf2_work = 1_000_000;
    value.duration = Duration::from_secs(12);
    value.query_policy = AffineQueryPolicy::RankBasis;
    value
}
fn source(config: &PrivateConfig, role: &str) -> Result<NetworkSource> {
    NetworkSource::new(
        config
            .endpoints
            .get(role)
            .ok_or("missing authorized endpoint")?
            .clone(),
    )
}
fn acquire(config_path: &Path, out: &Path, arm: &str) -> Result<()> {
    if !out.is_absolute() || !matches!(arm, "transfer" | "isolated" | "equal") {
        return Err("fresh absolute arm output required".into());
    }
    let private: PrivateConfig = load(config_path)?;
    if private.schema != "symbiote.transfer-source-config/1" || private.sources.len() != 2 {
        return Err("two explicit source authorizations required".into());
    }
    fs::create_dir(out)?;
    let started = Instant::now();
    let config = EngineConfig::new(private.sources.clone());
    let mut a = Engine::initialize(&out.join("a"), config.clone())?;
    let mut b = Engine::initialize(&out.join("b"), config.clone())?;
    let resource_start = json!([a.resources()?, b.resources()?]);
    let owners = vec![a.identity()?.into(), b.identity()?.into()];
    if owners[0] == owners[1] {
        return Err("owners must be distinct".into());
    }
    let mut sink = Sink::default();
    let mut a_own = source(&private, "a-own")?;
    let mut b_own = source(&private, "b-own")?;
    let options_a = options(a_own.descriptor());
    let options_b = options(b_own.descriptor());
    let learned_a = a.run_episode(&mut a_own, &options_a, &mut sink)?;
    let learned_b = b.run_episode(&mut b_own, &options_b, &mut sink)?;
    let mut a_foreign = source(&private, "a-foreign")?;
    let mut b_foreign = source(&private, "b-foreign")?;
    let (foreign, tickets, received, artifacts) = if arm == "transfer" {
        let artifact_a = a.export_artifact(&learned_a.artifact)?;
        let artifact_b = b.export_artifact(&learned_b.artifact)?;
        write(&out.join("artifact-a.json"), &artifact_a)?;
        write(&out.join("artifact-b.json"), &artifact_b)?;
        let grant_ab = a.authorize_local_exchange(&mut b, &artifact_a)?;
        let ticket_ab = a.prepare_local_transfer(&mut b, &grant_ab, &artifact_a)?;
        let received_b = b.accept_local_transfer(
            &ticket_ab,
            &artifact_a,
            &mut b_foreign,
            &options(artifact_a.source.clone()),
            &mut sink,
        )?;
        let grant_ba = b.authorize_local_exchange(&mut a, &artifact_b)?;
        let ticket_ba = b.prepare_local_transfer(&mut a, &grant_ba, &artifact_b)?;
        let received_a = a.accept_local_transfer(
            &ticket_ba,
            &artifact_b,
            &mut a_foreign,
            &options(artifact_b.source.clone()),
            &mut sink,
        )?;
        (
            vec![artifact_b.record.id.clone(), artifact_a.record.id.clone()],
            vec![
                serde_json::to_value(ticket_ba)?,
                serde_json::to_value(ticket_ab)?,
            ],
            json!([received_a, received_b]),
            vec![artifact_b, artifact_a],
        )
    } else {
        let options_a = options(a_foreign.descriptor());
        let options_b = options(b_foreign.descriptor());
        let received_a = a.run_episode(&mut a_foreign, &options_a, &mut sink)?;
        let received_b = b.run_episode(&mut b_foreign, &options_b, &mut sink)?;
        (
            vec![received_a.artifact.clone(), received_b.artifact.clone()],
            Vec::new(),
            json!([received_a, received_b]),
            Vec::new(),
        )
    };
    let inspections = vec![
        serde_json::to_value(a.inspect()?)?,
        serde_json::to_value(b.inspect()?)?,
    ];
    let resource_end = json!([a.resources()?, b.resources()?]);
    let closed = json!([a.close()?, b.close()?]);
    let acquisition = json!({"own_learning":[learned_a,learned_b],"received":received,
        "source_traces":{"a-own":a_own.trace,"b-own":b_own.trace,"a-foreign":a_foreign.trace,"b-foreign":b_foreign.trace},
        "events":sink.events,"closed":closed,"resource_start":resource_start,"resource_end":resource_end,"elapsed_ms":started.elapsed().as_millis(),
        "state_bytes":[file_bytes(&out.join("a"))?,file_bytes(&out.join("b"))?],
        "unit_policy":"GF2/source calls/bytes/calls/time separately; uninstrumented replay/evaluator CPU unknown"});
    write(
        &out.join("freeze.json"),
        &Freeze {
            schema: "symbiote.transfer-freeze/1".into(),
            arm: arm.into(),
            config,
            owners,
            foreign_artifacts: foreign,
            artifacts,
            tickets,
            inspections,
            acquisition,
            build_source_commit: option_env!("SYMBIOTE_SOURCE_COMMIT")
                .unwrap_or("unknown")
                .into(),
        },
    )
}
fn open(root: &Path, freeze: &Freeze) -> Result<(Engine, Engine)> {
    if freeze.schema != "symbiote.transfer-freeze/1"
        || freeze.owners.len() != 2
        || freeze.foreign_artifacts.len() != 2
    {
        return Err("invalid frozen consumer context".into());
    }
    Ok((
        Engine::open(&root.join("a"), &freeze.owners[0], freeze.config.clone())?,
        Engine::open(&root.join("b"), &freeze.owners[1], freeze.config.clone())?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema: String,
    freeze_sha256: String,
    inputs: Vec<u16>,
}
fn predict(root: &Path, inputs_path: &Path, out: &Path, hold_after_commit: bool) -> Result<()> {
    let frozen_raw = read(&root.join("freeze.json"))?;
    let freeze: Freeze = serde_json::from_slice(&frozen_raw)?;
    let inputs: Inputs = load(inputs_path)?;
    if inputs.schema != "symbiote.transfer-fresh-inputs/1"
        || inputs.freeze_sha256 != digest(&frozen_raw)
        || inputs.inputs.len() != 32
        || inputs
            .inputs
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != 32
        || inputs.inputs.iter().any(|input| *input >= 256)
    {
        return Err("bounded fresh input commitment required".into());
    }
    for trace in freeze.acquisition["source_traces"]
        .as_object()
        .ok_or("source traces absent")?
        .values()
    {
        for observation in trace["observations"]
            .as_array()
            .ok_or("observations absent")?
        {
            if inputs
                .inputs
                .iter()
                .any(|input| Some(u64::from(*input)) == observation["input"].as_u64())
            {
                return Err("evaluation input overlaps training/validation".into());
            }
        }
    }
    let started = Instant::now();
    let state_before = [file_bytes(&root.join("a"))?, file_bytes(&root.join("b"))?];
    let (mut a, mut b) = open(root, &freeze)?;
    let before = json!([a.inspect()?, b.inspect()?]);
    let resource_start = json!([a.resources()?, b.resources()?]);
    let mut sink = Sink::default();
    let mut predictions: Vec<Vec<Value>> = vec![Vec::new(), Vec::new()];
    let mut uses = Vec::new();
    let mut horizons = vec![Vec::new(), Vec::new()];
    for (index, engine) in [&mut a, &mut b].into_iter().enumerate() {
        let owner_started = Instant::now();
        let mut owner_work = 0u64;
        if freeze.arm == "transfer" {
            let ticket = serde_json::from_value(freeze.tickets[index].clone())?;
            for input in &inputs.inputs {
                let actual_use = engine.use_local_transfer(&ticket, *input)?;
                owner_work = owner_work
                    .checked_add(actual_use.model_work)
                    .ok_or("native model-work counter overflow")?;
                let actual_use = serde_json::to_value(actual_use)?;
                predictions[index].push(actual_use.clone());
                uses.push(actual_use);
                if [1, 16, 32].contains(&predictions[index].len()) {
                    horizons[index].push(json!({"horizon":predictions[index].len(),
                    "state_bytes":file_bytes(&root.join(if index==0{"a"}else{"b"}))?,"inclusive_elapsed_ms":owner_started.elapsed().as_millis(),
                    "model_work":owner_work,"resources":engine.resources()?,
                    "model_work_kind":"actual transfer-use meter; source-off prediction and journal costs remain separate"}));
                }
            }
        } else {
            for input in &inputs.inputs {
                predictions[index].push(serde_json::to_value(engine.predict(
                    &freeze.foreign_artifacts[index],
                    *input,
                    &mut sink,
                )?)?);
                if [1, 16, 32].contains(&predictions[index].len()) {
                    horizons[index].push(json!({"horizon":predictions[index].len(),
                    "state_bytes":file_bytes(&root.join(if index==0{"a"}else{"b"}))?,"inclusive_elapsed_ms":owner_started.elapsed().as_millis(),
                    "model_work":null,"resources":engine.resources()?,"model_work_kind":"unknown direct Engine::predict CPU; actual calls/elapsed/durable bytes measured"}));
                }
            }
        }
    }
    let after = json!([a.inspect()?, b.inspect()?]);
    let resource_end = json!([a.resources()?, b.resources()?]);
    let closed = if hold_after_commit {
        json!({"status":"held-live-for-owned-process-interruption"})
    } else {
        json!([a.close()?, b.close()?])
    };
    write(
        out,
        &json!({"schema":"symbiote.transfer-prediction-commit/1","status":"PREDICTIONS_COMMITTED",
        "arm":freeze.arm,"freeze_sha256":digest(&frozen_raw),"inputs_sha256":digest(&read(inputs_path)?),
        "predictions":predictions,"uses":uses,"horizons":horizons,"before":before,"after":after,"closed":closed,
        "resource_start":resource_start,"resource_end":resource_end,
        "source_calls":0,"source_contact_attempts":0,"labels_received":false,"learning_during_evaluation":false,
        "events":sink.events,"elapsed_ms":started.elapsed().as_millis(),
        "state_before_bytes":state_before,"state_after_bytes":[file_bytes(&root.join("a"))?,file_bytes(&root.join("b"))?],
        "prediction_calls_per_owner":32,"direct_prediction_calls_per_owner":if freeze.arm=="transfer"{0}else{32},
        "actual_transfer_use_calls_per_owner":if freeze.arm=="transfer"{32}else{0},
        "unmetered_replay_and_prediction_cpu":"unknown; wall duration and actual calls reported",
        "build_source_commit":option_env!("SYMBIOTE_SOURCE_COMMIT").unwrap_or("unknown")}),
    )?;
    if hold_after_commit {
        let marker = out.with_file_name(format!(
            "{}.interruption-ready.json",
            out.file_name().ok_or("receipt filename")?.to_string_lossy()
        ));
        let pending = marker.with_extension("pending");
        write(
            &pending,
            &json!({"schema":"symbiote.transfer-interruption-ready/1","pid":std::process::id(),
                "prediction_receipt_sha256":digest(&read(out)?),"owners":freeze.owners,
                "handles_intentionally_open":true,"next_operation":"externally owned kill before outcome"}),
        )?;
        fs::hard_link(pending, marker)?;
        println!(
            "{}",
            json!({"status":"PREDICTIONS_COMMITTED_AWAITING_OWNED_KILL","pid":std::process::id()})
        );
        std::io::stdout().flush()?;
        loop {
            std::thread::park_timeout(Duration::from_secs(1));
        }
    }
    Ok(())
}
fn recover(root: &Path, out: &Path) -> Result<()> {
    let freeze: Freeze = load(&root.join("freeze.json"))?;
    let mut before = BTreeMap::new();
    for role in ["a", "b"] {
        for name in [
            "ledger.jsonl",
            "knowledge.jsonl",
            "operations.jsonl",
            "operations-owner.json",
        ] {
            before.insert(
                format!("{role}/{name}"),
                digest(&read(&root.join(role).join(name))?),
            );
        }
    }
    let recovered = json!([
        Engine::recover_stopped_owner(&root.join("a"), &freeze.owners[0])?,
        Engine::recover_stopped_owner(&root.join("b"), &freeze.owners[1])?
    ]);
    for (name, hash) in &before {
        if digest(&read(&root.join(name))?) != *hash {
            return Err("stale-lock recovery rewrote committed history".into());
        }
    }
    write(
        out,
        &json!({"schema":"symbiote.transfer-explicit-recovery/1","owners":freeze.owners,
        "recovery":recovered,"committed_file_hashes_unchanged":before,"source_calls":0}),
    )
}
fn complete(
    root: &Path,
    predictions_path: &Path,
    grade_commit: &str,
    out: &Path,
    repeat: bool,
) -> Result<()> {
    if grade_commit.len() != 64 || !grade_commit.bytes().all(|v| v.is_ascii_hexdigit()) {
        return Err("external grade commitment required".into());
    }
    let freeze: Freeze = load(&root.join("freeze.json"))?;
    if freeze.arm != "transfer" {
        return Err("only transferred artifacts have reciprocal outcomes".into());
    }
    let predictions: Value = load(predictions_path)?;
    if predictions["status"] != "PREDICTIONS_COMMITTED"
        || predictions["freeze_sha256"] != digest(&read(&root.join("freeze.json"))?)
    {
        return Err("prediction phase commitment differs".into());
    }
    let started = Instant::now();
    let (mut a, mut b) = open(root, &freeze)?;
    let resource_start = json!([a.resources()?, b.resources()?]);
    let ticket_a = serde_json::from_value(freeze.tickets[0].clone())?;
    let ticket_b = serde_json::from_value(freeze.tickets[1].clone())?;
    let outcomes = if repeat {
        Value::Null
    } else {
        json!([
            a.complete_local_transfer(&ticket_a)?,
            b.complete_local_transfer(&ticket_b)?
        ])
    };
    let reconciled = json!([
        b.reconcile_local_transfer(&a, &ticket_a)?,
        a.reconcile_local_transfer(&b, &ticket_b)?
    ]);
    let after = json!([a.inspect()?, b.inspect()?]);
    let resource_end = json!([a.resources()?, b.resources()?]);
    let closed = json!([a.close()?, b.close()?]);
    write(
        out,
        &json!({"schema":"symbiote.transfer-outcome-phase/1","repeat_reconciliation":repeat,
        "predictions_sha256":digest(&read(predictions_path)?),"external_grade_commitment":grade_commit,
        "outcomes":outcomes,"reconciliations":reconciled,"after":after,"closed":closed,
        "resource_start":resource_start,"resource_end":resource_end,
        "source_calls":0,"labels_received":false,"elapsed_ms":started.elapsed().as_millis(),
        "state_bytes":[file_bytes(&root.join("a"))?,file_bytes(&root.join("b"))?],
        "measured_economic_benefit":"unknown; no positive benefit declared"}),
    )
}
fn main() {
    if let Err(error) = run() {
        eprintln!("transfer consumer failed: {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--version"] {
        println!(
            "{}",
            json!({"schema":"symbiote.transfer-consumer-version/1","version":env!("CARGO_PKG_VERSION"),
            "build_source_commit":option_env!("SYMBIOTE_SOURCE_COMMIT").unwrap_or("unknown")})
        );
        return Ok(());
    }
    let phase = args.first().ok_or("phase required")?;
    let mut values = BTreeMap::new();
    let mut index = 1;
    let mut hold_after_commit = false;
    while index < args.len() {
        if args[index] == "--hold-after-commit" {
            if phase != "predict" || hold_after_commit {
                return Err("interruption flag only once on predict".into());
            }
            hold_after_commit = true;
            index += 1;
            continue;
        }
        if index + 1 >= args.len()
            || !args[index].starts_with("--")
            || values
                .insert(args[index].as_str(), args[index + 1].as_str())
                .is_some()
        {
            return Err("unique phase options required".into());
        }
        index += 2;
    }
    let get = |key: &str| -> Result<&str> {
        values
            .get(key)
            .copied()
            .ok_or_else(|| format!("missing {key}").into())
    };
    let out = Path::new(get("--out")?);
    match phase.as_str() {
        "acquire" => acquire(Path::new(get("--config")?), out, get("--arm")?),
        "predict" => predict(
            Path::new(get("--state")?),
            Path::new(get("--inputs")?),
            out,
            hold_after_commit,
        ),
        "recover" => recover(Path::new(get("--state")?), out),
        "complete" | "reconcile" => complete(
            Path::new(get("--state")?),
            Path::new(get("--predictions")?),
            get("--grade-commit")?,
            out,
            phase == "reconcile",
        ),
        _ => Err("unknown bounded phase".into()),
    }
}
