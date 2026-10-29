//! Product command-line host for the documented typed embedding API.
//! Arguments, file adapters and presentation belong to this binary, not Engine.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
use symbiote_runtime::engine::*;

const SCHEMA: &str = "symbiote.engine-cli/1";
const MAX_SOURCE_BYTES: usize = 128 * 1024;
#[derive(Debug, Serialize)]
struct Failure {
    kind: ErrorKind,
    operation: &'static str,
    diagnostic: String,
    committed: Option<KnowledgeAnchor>,
}
type HostResult<T> = std::result::Result<T, Failure>;
impl From<EngineError> for Failure {
    fn from(error: EngineError) -> Self {
        Self {
            kind: error.kind,
            operation: error.operation,
            diagnostic: error.diagnostic,
            committed: error.committed,
        }
    }
}
fn failure(kind: ErrorKind, operation: &'static str, message: impl Into<String>) -> Failure {
    Failure {
        kind,
        operation,
        diagnostic: message.into(),
        committed: None,
    }
}
struct Arguments {
    command: String,
    values: BTreeMap<String, String>,
    cancelled: bool,
}
impl Arguments {
    fn parse(args: &[String]) -> HostResult<Self> {
        let command = args
            .first()
            .ok_or_else(|| {
                failure(
                    ErrorKind::Malformed,
                    "arguments",
                    "engine subcommand required",
                )
            })?
            .clone();
        let options: &[&str] = match command.as_str() {
            "init" => &["--state", "--config"],
            "learn" => &[
                "--state",
                "--owner",
                "--config",
                "--source",
                "--observations",
            ],
            "predict" => &["--state", "--owner", "--config", "--artifact", "--input"],
            "inspect" => &["--state", "--owner", "--config"],
            "revoke" => &["--state", "--owner", "--config", "--artifact", "--reason"],
            "checkpoint" => &["--state", "--owner", "--config", "--backup"],
            "restore" => &[
                "--state",
                "--owner",
                "--config",
                "--checkpoint",
                "--manifest-sha256",
            ],
            "recover" => &["--state", "--owner"],
            _ => {
                return Err(failure(
                    ErrorKind::Malformed,
                    "arguments",
                    "unknown engine subcommand",
                ))
            }
        };
        let mut values = BTreeMap::new();
        let mut cancelled = false;
        let mut json_seen = false;
        let mut index = 1;
        while index < args.len() {
            let flag = &args[index];
            if flag == "--json" && !json_seen {
                json_seen = true;
                index += 1;
                continue;
            }
            if flag == "--cancelled" && command == "learn" && !cancelled {
                cancelled = true;
                index += 1;
                continue;
            }
            if !options.contains(&flag.as_str()) || values.contains_key(flag) {
                return Err(failure(
                    ErrorKind::Malformed,
                    "arguments",
                    format!("unknown, duplicate or unsupported option {flag}"),
                ));
            }
            let value = args
                .get(index + 1)
                .filter(|v| !v.starts_with("--"))
                .ok_or_else(|| {
                    failure(
                        ErrorKind::Malformed,
                        "arguments",
                        format!("value required for {flag}"),
                    )
                })?;
            values.insert(flag.clone(), value.clone());
            index += 2;
        }
        for required in options {
            if !values.contains_key(*required) {
                return Err(failure(
                    ErrorKind::Malformed,
                    "arguments",
                    format!("{required} required for engine {command}"),
                ));
            }
        }
        Ok(Self {
            command,
            values,
            cancelled,
        })
    }
    fn value(&self, key: &str) -> &str {
        &self.values[key]
    }
    fn absolute(&self, key: &str) -> HostResult<PathBuf> {
        let path = PathBuf::from(self.value(key));
        if !path.is_absolute() {
            return Err(failure(
                ErrorKind::Malformed,
                "arguments",
                format!("{key} must be absolute"),
            ));
        }
        Ok(path)
    }
}
fn bounded_read(path: &Path, maximum: usize, operation: &'static str) -> HostResult<Vec<u8>> {
    let file =
        File::open(path).map_err(|e| failure(ErrorKind::Storage, operation, e.to_string()))?;
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| failure(ErrorKind::Storage, operation, e.to_string()))?;
    if bytes.len() > maximum {
        return Err(failure(
            ErrorKind::BudgetExhausted,
            operation,
            "file exceeds its declared byte ceiling",
        ));
    }
    Ok(bytes)
}
fn config(args: &Arguments) -> HostResult<EngineConfig> {
    serde_json::from_slice(&bounded_read(
        Path::new(args.value("--config")),
        32 * 1024,
        "config",
    )?)
    .map_err(|e| failure(ErrorKind::Malformed, "config", e.to_string()))
}
#[derive(Default, Serialize)]
struct SourceAccess {
    calls: usize,
    read_bytes: usize,
    file_opened: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayFrame {
    sequence: usize,
    input: u16,
    output: u8,
}
struct ReplaySource {
    source: SourceDescriptor,
    path: PathBuf,
    frames: Option<Vec<ReplayFrame>>,
    access: SourceAccess,
}
impl ReplaySource {
    fn load(&mut self) -> std::result::Result<(), SourceError> {
        let file = File::open(&self.path)
            .map_err(|e| SourceError::new(ErrorKind::Storage, e.to_string()))?;
        self.access.file_opened = true;
        let mut bytes = Vec::new();
        let read = file
            .take(MAX_SOURCE_BYTES as u64 + 1)
            .read_to_end(&mut bytes);
        self.access.read_bytes = bytes.len();
        read.map_err(|e| SourceError::new(ErrorKind::Storage, e.to_string()))?;
        if bytes.len() > MAX_SOURCE_BYTES {
            return Err(SourceError::new(
                ErrorKind::BudgetExhausted,
                "observation file exceeds 128 KiB",
            ));
        }
        if format!("{:x}", Sha256::digest(&bytes)) != self.source.commitment {
            return Err(SourceError::new(
                ErrorKind::Authorization,
                "observation bytes differ from the caller-pinned source commitment",
            ));
        }
        let frames: Vec<ReplayFrame> = serde_json::from_slice(&bytes)
            .map_err(|e| SourceError::new(ErrorKind::Malformed, e.to_string()))?;
        let mut inputs = std::collections::BTreeSet::new();
        if frames.is_empty()
            || frames.len() > 256
            || frames.iter().enumerate().any(|(sequence, q)| {
                q.sequence != sequence
                    || q.output > 1
                    || q.input >= (1u16 << self.source.width)
                    || !inputs.insert(q.input)
            })
        {
            return Err(SourceError::new(
                ErrorKind::Malformed,
                "observations require 1..256 ordered unique in-domain binary frames",
            ));
        }
        self.frames = Some(frames);
        Ok(())
    }
}
impl ObservationSource for ReplaySource {
    fn descriptor(&self) -> SourceDescriptor {
        self.source.clone()
    }
    fn observe(
        &mut self,
        request: ObservationRequest<'_>,
    ) -> std::result::Result<Observation, SourceError> {
        let sequence = self.access.calls;
        self.access.calls += 1;
        if request.sequence != sequence || request.source != &self.source {
            return Err(SourceError::new(
                ErrorKind::Authorization,
                "observation request binding differs",
            ));
        }
        if self.frames.is_none() {
            self.load()?;
        }
        let frame = self.frames.as_ref().unwrap().get(sequence).ok_or_else(|| {
            SourceError::new(
                ErrorKind::Uncertain,
                "authorized replay has no next requested observation",
            )
        })?;
        if frame.input != request.input || frame.sequence != request.sequence {
            return Err(SourceError::new(
                ErrorKind::Malformed,
                "replay frame is not the exact selected query/sequence",
            ));
        }
        Ok(Observation {
            sequence: frame.sequence,
            input: frame.input,
            output: frame.output,
        })
    }
}
fn diagnostics(engine: &Engine) -> HostResult<Value> {
    Ok(
        json!({"inspection":engine.inspect()?,"counters":engine.counters()?,"resources":engine.resources()?}),
    )
}
fn envelope(command: &str) -> Value {
    json!({"schema":SCHEMA,"command":command,"engine":version(),"conditional":true,"economic_benefit_verified":false})
}
fn failed(mut report: Value, error: Failure) -> (Value, bool) {
    report["status"] = json!("ERROR");
    report["error"] = json!(error);
    (report, false)
}
fn finish(
    engine: Engine,
    mut report: Value,
    operation: HostResult<Value>,
    source: Option<SourceAccess>,
) -> (Value, bool) {
    if let Some(source) = source {
        report["source_access"] = json!(source);
    }
    let diagnostic = diagnostics(&engine);
    let close = engine.close().map_err(Failure::from);
    report["closed"] = json!(close.is_ok());
    if let Err(error) = &close {
        report["close_error"] = json!(error);
    }
    match diagnostic {
        Ok(value) => {
            report["inspection"] = value["inspection"].clone();
            report["counters"] = value["counters"].clone();
            report["resources"] = value["resources"].clone();
        }
        Err(error) => {
            report["diagnostic_error"] = json!(error);
            if operation.is_ok() {
                return failed(report, error);
            }
        }
    }
    match operation {
        Err(error) => failed(report, error),
        Ok(result) => match close {
            Err(error) => failed(report, error),
            Ok(_) => {
                report["status"] = json!("PASS");
                report["result"] = result;
                (report, true)
            }
        },
    }
}
fn execute(args: &Arguments) -> HostResult<(Value, bool)> {
    let state = args.absolute("--state")?;
    let report = envelope(&args.command);
    if args.command == "recover" {
        let result = Engine::recover_stopped_owner(&state, args.value("--owner"))?;
        return Ok((
            json!({"schema":SCHEMA,"command":"recover","status":"PASS","result":result}),
            true,
        ));
    }
    let cfg = config(args)?;
    if args.command == "restore" {
        let value: Value = serde_json::from_slice(&bounded_read(
            Path::new(args.value("--checkpoint")),
            128 * 1024,
            "checkpoint_read",
        )?)
        .map_err(|e| failure(ErrorKind::Malformed, "checkpoint_read", e.to_string()))?;
        let checkpoint: Checkpoint = serde_json::from_value(
            value
                .get("result")
                .and_then(|v| v.get("checkpoint"))
                .unwrap_or(&value)
                .clone(),
        )
        .map_err(|e| failure(ErrorKind::Malformed, "checkpoint_read", e.to_string()))?;
        if checkpoint.manifest_sha256 != args.value("--manifest-sha256")
            || checkpoint.owner != args.value("--owner")
        {
            return Err(failure(
                ErrorKind::Authorization,
                "restore",
                "checkpoint differs from the independent owner/manifest pins",
            ));
        }
        let (engine, restored) = Engine::restore(&checkpoint, &state, cfg)?;
        return Ok(finish(
            engine,
            report,
            Ok(json!({"restore":restored})),
            None,
        ));
    }
    // Parse the numeric application input before opening a persistent owner.
    let input = if args.command == "predict" {
        Some(
            args.value("--input")
                .parse::<u16>()
                .map_err(|_| failure(ErrorKind::Malformed, "arguments", "input must be a u16"))?,
        )
    } else {
        None
    };
    let selected = if args.command == "learn" {
        let sources = cfg
            .authorized_sources
            .iter()
            .filter(|s| s.source_id == args.value("--source"))
            .cloned()
            .collect::<Vec<_>>();
        if sources.len() != 1 {
            return Err(failure(
                ErrorKind::Authorization,
                "source",
                "source ID must select exactly one explicitly configured descriptor",
            ));
        }
        Some(sources[0].clone())
    } else {
        None
    };
    let mut engine = if args.command == "init" {
        Engine::initialize(&state, cfg.clone())?
    } else {
        Engine::open(&state, args.value("--owner"), cfg.clone())?
    };
    if args.command == "checkpoint" {
        let mut report = report;
        let diagnostic = diagnostics(&engine)?;
        let backup = args.absolute("--backup")?;
        let checkpoint = engine.close()?.checkpoint(&backup)?;
        report["status"] = json!("PASS");
        report["closed"] = json!(true);
        report["result"] = json!({"checkpoint":checkpoint});
        report["inspection"] = diagnostic["inspection"].clone();
        report["counters"] = diagnostic["counters"].clone();
        report["resources"] = diagnostic["resources"].clone();
        return Ok((report, true));
    }
    let mut access = None;
    let operation = match args.command.as_str() {
        "init" => Ok(json!({"initialized":true,"owner":engine.identity()?})),
        "inspect" => Ok(json!({"read_only":true})),
        "predict" => engine
            .predict(args.value("--artifact"), input.unwrap(), &mut NoopSink)
            .map(|p| json!({"prediction":p}))
            .map_err(Failure::from),
        "revoke" => engine
            .revoke(
                args.value("--artifact"),
                args.value("--reason"),
                &mut NoopSink,
            )
            .map(|anchor| json!({"revoked":args.value("--artifact"),"knowledge":anchor}))
            .map_err(Failure::from),
        "learn" => {
            let source = selected.unwrap();
            let mut options = EpisodeOptions::bounded(source.clone());
            options.max_queries = cfg.max_queries_per_episode;
            options.max_gf2_work = cfg.max_gf2_work_per_episode;
            options.duration = Duration::from_millis(cfg.max_duration_ms);
            options.query_policy = AffineQueryPolicy::RankBasis;
            let mut source = ReplaySource {
                source,
                path: PathBuf::from(args.value("--observations")),
                frames: None,
                access: SourceAccess::default(),
            };
            if args.cancelled {
                engine.cancel();
            }
            let learned = engine.run_episode(&mut source,&options,&mut NoopSink).map(|receipt|json!({"learning":receipt,"query_policy":options.query_policy.name()})).map_err(Failure::from);
            access = Some(source.access);
            learned
        }
        _ => unreachable!("validated engine subcommand"),
    };
    Ok(finish(engine, report, operation, access))
}
pub fn run(args: &[String]) -> i32 {
    if args.is_empty() || args == ["--help"] || args == ["help"] {
        println!(
            "{}",
            json!({"schema":SCHEMA,"status":"HELP","usage":"symbiote engine COMMAND --state ABSOLUTE_DIRECTORY [OPTIONS]","commands":{"init":"--config FILE","learn":"--owner ID --config FILE --source SOURCE_ID --observations FILE [--cancelled]","predict":"--owner ID --config FILE --artifact ID --input U16","inspect":"--owner ID --config FILE","revoke":"--owner ID --config FILE --artifact ID --reason TEXT","checkpoint":"--owner ID --config FILE --backup NEW_ABSOLUTE_DIRECTORY","restore":"--owner ID --config FILE --checkpoint SAVED_CHECKPOINT_JSON --manifest-sha256 EXTERNAL_PIN","recover":"--owner ID"},"output":"one JSON result, including typed error.kind on nonzero exit","source":"lazy authorized observation replay; 128KiB/256 ordered individual binary frames; exact file SHA256 is the configured source commitment"})
        );
        return 0;
    }
    let result = Arguments::parse(args).and_then(|args| execute(&args));
    let (report, success) = match result {
        Ok(result) => result,
        Err(error) => failed(
            envelope(args.first().map_or("unknown", String::as_str)),
            error,
        ),
    };
    println!("{report}");
    if success {
        0
    } else {
        1
    }
}
