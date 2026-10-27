//! Independent, bounded, LLM-free SYMBIOTE genesis runtime.
mod adaptive_research;
mod graph_research;
mod research;
mod service;

use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use symbiote_memory::knowledge::{KnowledgePayload, KnowledgeStore};
use symbiote_memory::{evaluate, Artifact, Store};
use symbiote_protocol::{spawn_server, Client, EchoBuffer, Sensor, ServerConfig, Telemetry};
use symbiote_reasoning::SymbolicLearner;

const SCOPE: &str = "finite-boolean-v1";
const OPERATIONS: &[&str] = &[
    "telemetry",
    "offer",
    "probe",
    "contribute",
    "partner_metrics",
];

struct ApiSensor<'a> {
    client: &'a mut Client,
}
impl Sensor for ApiSensor<'_> {
    fn collect(&mut self) -> Result<Vec<Telemetry>, String> {
        serde_json::from_value(self.client.call("telemetry", &json!({}))?)
            .map_err(|e| e.to_string())
    }
}

fn score_predictions(table: &[Option<u8>; 4], oracle: &[u8; 4]) -> usize {
    (0..32)
        .filter(|i| table[i % 4] == Some(oracle[i % 4]))
        .count()
}

fn strategy_predict(strategy: &str, input: usize) -> Result<u8, String> {
    let first = ((input >> 1) & 1) as u8;
    let second = (input & 1) as u8;
    match strategy {
        "xor" => Ok(first ^ second),
        "and" => Ok(first & second),
        "or" => Ok(first | second),
        "first-bit" => Ok(first),
        "second-bit" => Ok(second),
        _ => Err("unsupported inert strategy expression".into()),
    }
}

fn derive_strategy(table: &[u8]) -> Result<String, String> {
    for strategy in ["xor", "and", "or", "first-bit", "second-bit"] {
        if (0..4).all(|i| strategy_predict(strategy, i).ok() == table.get(i).copied()) {
            return Ok(strategy.into());
        }
    }
    Err("no verified abstraction in declared Boolean expression grammar".into())
}

fn bits(code: u8) -> [Option<u8>; 2] {
    [Some((code >> 1) & 1), Some(code & 1)]
}

#[derive(Clone)]
struct Partner {
    id: String,
    oracle: [u8; 4],
    adopted: Option<Artifact>,
    strategy: Option<String>,
    verification_queries: usize,
    faults: String,
}

impl Partner {
    fn respond(&mut self, op: &str, payload: Value) -> Result<Value, String> {
        if op == "telemetry" {
            // Published chronological action-0 trace: hidden input advances 0 -> 1.
            let rows: Vec<Telemetry> = (0..2)
                .map(|i| Telemetry {
                    agent_id: self.id.clone(),
                    sequence: i as u64,
                    task: SCOPE.into(),
                    action: "advance".into(),
                    tool: Some("finite-oracle".into()),
                    success: true,
                    resource_units: 1,
                    confidence: None,
                    feedback: json!({"input":i,"output":self.oracle[i]}),
                    error: None,
                    recovered: false,
                })
                .collect();
            return Ok(json!(rows));
        }
        if op == "offer" {
            let mut table = self.oracle.to_vec();
            if self.faults == "wrong-artifact" {
                table[2] ^= 1;
            }
            let revision = payload["after_revision"]
                .as_u64()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or("revision budget exhausted")?;
            return Ok(json!(Artifact {
                id: format!("{}-table", self.id), revision, source: self.id.clone(),
                scope: SCOPE.into(), table,
                provenance: format!("simulated {} published finite task table; untrusted until independently probed", self.id),
            }));
        }
        if op == "probe" {
            let i = payload["input"].as_u64().ok_or("input required")? as usize;
            if i >= 4 {
                return Err("input outside finite scope".into());
            }
            return Ok(json!({"output":self.oracle[i]}));
        }
        if op == "contribute" {
            let candidate: Artifact =
                serde_json::from_value(payload["artifact"].clone()).map_err(|e| e.to_string())?;
            let strategy = payload["strategy"]
                .as_str()
                .ok_or("derived strategy required")?;
            if !(0..4)
                .all(|i| strategy_predict(strategy, i).ok() == candidate.table.get(i).copied())
            {
                return Err("strategy does not reproduce the proposed complete table".into());
            }
            let baseline = self
                .adopted
                .as_ref()
                .map(|a| std::array::from_fn(|i| Some(a.table[i])))
                .unwrap_or_else(|| self.baseline());
            // Partner retains independent adoption authority. This evaluator is
            // privileged simulator code, not an assertion from the sender.
            let evaluation = evaluate(&candidate, &self.oracle, &baseline)?;
            self.verification_queries += evaluation.verification_queries;
            self.adopted = Some(candidate);
            self.strategy = Some(strategy.into());
            return Ok(json!({"adopted":true,"evaluation":evaluation}));
        }
        if op == "partner_metrics" {
            let baseline_correct = (0..32)
                .filter(|i| self.baseline()[i % 4] == Some(self.oracle[i % 4]))
                .count();
            let mut before_units = 0;
            let mut after_units = self.verification_queries * 10;
            let mut before_complete_correct = 0;
            let mut after_correct = 0;
            for i in 0..32 {
                let input = i % 4;
                let before = match self.baseline()[input] {
                    Some(output) => {
                        before_units += 1;
                        output
                    }
                    None => {
                        before_units += 10;
                        self.oracle[input]
                    }
                };
                before_complete_correct += usize::from(before == self.oracle[input]);
                let after = self
                    .strategy
                    .as_ref()
                    .map(|s| strategy_predict(s, input))
                    .transpose()?;
                if let Some(output) = after {
                    after_units += 1;
                    after_correct += usize::from(output == self.oracle[input]);
                }
            }
            return Ok(
                json!({"baseline_correct":baseline_correct,"baseline_with_oracle_fallback_correct":before_complete_correct,"after_correct":after_correct,"total":32,"verification_queries":self.verification_queries,"strategy":self.strategy,"baseline_resource_units":before_units,"strategy_resource_units_including_verification":after_units,"cost_model":"local lookup/expression=1; simulated oracle=10; logical units, not wall-clock"}),
            );
        }
        Err("unsupported operation".into())
    }

    fn baseline(&self) -> [Option<u8>; 4] {
        [Some(self.oracle[0]), Some(self.oracle[1]), None, None]
    }
}

fn probe(client: &mut Client) -> Result<[u8; 4], String> {
    let mut oracle = [0; 4];
    for (input, output) in oracle.iter_mut().enumerate() {
        let reply = client.call("probe", &json!({"input":input}))?;
        let code = reply["output"].as_u64().ok_or("invalid oracle response")?;
        if code > 3 {
            return Err("oracle output outside scope".into());
        }
        *output = code as u8;
    }
    Ok(oracle)
}

fn receipt_file(path: &Path, report: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(
        path,
        serde_json::to_vec_pretty(report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn demo(state: &Path, receipts: &Path, fault: &str) -> Result<Value, String> {
    let mut store = Store::open(state)?;
    let identity = store.identity().to_string();
    let mut participants = Vec::new();
    let mut phases = Vec::new();
    let mut promoted = 0;
    let mut reused = 0;
    for (id, mut oracle) in [("alpha", [0, 1, 1, 0]), ("beta", [0, 1, 0, 1])] {
        if fault == "drift" && id == "alpha" {
            oracle[2] ^= 1;
        }
        let partner = Arc::new(Mutex::new(Partner {
            id: id.into(),
            oracle,
            adopted: None,
            strategy: None,
            verification_queries: 0,
            faults: fault.into(),
        }));
        let service = Arc::clone(&partner);
        let mut server = spawn_server(
            ServerConfig {
                id: id.into(),
                token: format!("simulation-only-consent-{id}"),
                client_id: identity.clone(),
                operations: OPERATIONS.iter().map(|s| s.to_string()).collect(),
                max_requests: 32,
                max_frame_bytes: 16384,
                timeout: Duration::from_secs(2),
            },
            move |op, payload| {
                service
                    .lock()
                    .map_err(|_| "partner state poisoned".to_string())?
                    .respond(op, payload)
            },
        )?;
        // Discovery is an explicit, owner-authorized local registry: no scanning.
        let endpoint = server.endpoint();
        let mut client = Client::connect(&endpoint, &identity, OPERATIONS)?;
        phases.push(json!({"partner":id,"phase":"CONNECT","protocol":"symbiote/1","authorization":"explicit-local-registry","scope":SCOPE}));
        let telemetry = ApiSensor {
            client: &mut client,
        }
        .collect()?;
        let mut echo = EchoBuffer::new(8)?;
        let mut model = SymbolicLearner::new(4, 4096)?;
        let mut baseline = [None; 4];
        for row in telemetry {
            row.validate()?;
            if row.agent_id != id || row.task != SCOPE {
                return Err("telemetry identity/scope mismatch".into());
            }
            let input = row.feedback["input"]
                .as_u64()
                .ok_or("telemetry input missing")? as usize;
            let output = row.feedback["output"]
                .as_u64()
                .ok_or("telemetry output missing")?;
            if input > 3 || output > 3 {
                return Err("telemetry outside declared domain".into());
            }
            baseline[input] = Some(output as u8);
            if row.sequence == 0 {
                model.initialize(bits(output as u8))?;
            }
            if row.sequence != 0 {
                model.observe(0, bits(output as u8))?;
            }
            echo.push(row)?;
        }
        phases.push(
            json!({"partner":id,"phase":"SENSE","observations":echo.len(),"resource_units":2}),
        );
        phases.push(json!({"partner":id,"phase":"MODEL","grammar":"Moore<=4,2-actions,2-bit stationary","status":model.status(),"hypotheses":model.count(),"next_support":model.predict_support(0)?,"epistemic_status":"conditional-inference"}));

        let expected_id = format!("{id}-table");
        let retained = store
            .active()
            .into_iter()
            .find(|a| a.id == expected_id && a.source == id && a.scope == SCOPE);
        let candidate = match retained {
            Some(artifact) => {
                reused += 1;
                artifact
            }
            None => {
                phases.push(json!({"partner":id,"phase":"EXCHANGE","opportunity":"two unseen inputs in local task model","status":"untrusted-candidate"}));
                serde_json::from_value::<Artifact>(
                    client.call("offer", &json!({"applicability":SCOPE,"after_revision":store.highest_revision(&expected_id).unwrap_or(0)}))?,
                )
                .map_err(|e| e.to_string())?
            }
        };
        if candidate.id != expected_id || candidate.source != id || candidate.scope != SCOPE {
            return Err("received artifact identity/applicability mismatch".into());
        }
        // The native agent sees evaluator answers only through the authorized API.
        // All four inputs are checked; no confirmation threshold substitutes for this.
        let observed_oracle = probe(&mut client)?;
        let evaluation = match evaluate(&candidate, &observed_oracle, &baseline) {
            Ok(evaluation) => evaluation,
            Err(error) => {
                if store.active().iter().any(|a| a.id == expected_id) {
                    store.revoke(&expected_id, "counterexample during reassessment")?;
                }
                let failure = json!({"schema":"symbiote.demo/1","status":"REJECTED","identity":identity,"partner":id,"reason":error,"promoted_before_failure":promoted,"phases":phases});
                receipt_file(receipts, &failure)?;
                return Err(format!("knowledge rejected for {id}: {error}"));
            }
        };
        phases.push(json!({"partner":id,"phase":"VERIFY","evaluation":evaluation,"scope":"exhaustively-checked-four-input-simulator"}));
        if !store.active().iter().any(|a| a.id == candidate.id) {
            store.promote(candidate.clone(), evaluation.clone())?;
            promoted += 1;
        }
        phases.push(json!({"partner":id,"phase":"LEARN","artifact":candidate.id,"revision":candidate.revision,"retained":reused > 0}));
        let before_correct = score_predictions(&baseline, &observed_oracle);
        let after_correct = score_predictions(
            &std::array::from_fn(|i| Some(candidate.table[i])),
            &observed_oracle,
        );
        // Execute the same-budget control: acquire every input through the same
        // authorized probe API without asking for an offer, then build a table.
        let control_observations = probe(&mut client)?;
        let control_table = std::array::from_fn(|i| Some(control_observations[i]));
        let control_correct = score_predictions(&control_table, &observed_oracle);
        // Contribution is a complete prediction strategy reconstructed from independently
        // checked observations. The recipient re-evaluates it and controls adoption.
        let contribution = Artifact {
            id: format!("{identity}-contribution-{id}"), revision: 1, source: identity.clone(), scope: SCOPE.into(),
            table: observed_oracle.to_vec(),
            provenance: format!("SYMBIOTE independently checked {} against four authorized API probes; replaces incomplete local prediction strategy", candidate.id),
        };
        let strategy = derive_strategy(&observed_oracle)?;
        let adopted = client.call(
            "contribute",
            &json!({"artifact":contribution,"strategy":strategy}),
        )?;
        let partner_metrics = client.call("partner_metrics", &json!({}))?;
        phases.push(json!({"partner":id,"phase":"CONTRIBUTE","derived_abstraction":strategy,"adoption":adopted}));
        phases.push(json!({"partner":id,"phase":"REASSESS","drift":echo.drift(),"independent_probes":4,"persistent_artifact":candidate.id}));
        participants.push(json!({
            "partner":id,"symbiote":{"isolated_correct":before_correct,"exchange_correct":after_correct,"total":32,"isolated_abstentions":32-before_correct,"verification_queries":4,"telemetry_observations":2,"matched_probe_control_correct":control_correct,"matched_probe_control_queries":4},
            "partner_benefit":partner_metrics,"measured_change":"persistent complete finite prediction table replaces two-input partial table",
        }));
        client.revoke()?;
        server.shutdown()?;
    }
    let report = json!({
        "schema":"symbiote.demo/1","version":env!("CARGO_PKG_VERSION"),"status":"PASS","identity":identity,
        "language_model":false,"authorized_endpoints":2,"promoted":promoted,"reused":reused,"active_artifacts":store.active().len(),
        "participants":participants,"phases":phases,
        "scientific_status":"deterministic finite-domain software experiment; not generalized intelligence",
        "cost_accounting":{"symbiote_verification_queries":8,"matched_probe_control_queries":8,"partner_verification_queries":8,"telemetry_observations":4,"task_predictions":64,"task_predictions_are_repeated_not_independent_samples":true},
        "control_interpretation":"Exchange extends persistent prediction coverage relative to the two-observation isolated baseline. A control allowed the same four complete probes also reaches full coverage; no sample-efficiency or general transfer advantage is established.",
    });
    receipt_file(receipts, &report)?;
    Ok(report)
}

#[derive(Debug)]
struct Cli {
    command: String,
    state: PathBuf,
    receipts: PathBuf,
    fault: String,
    artifact: Option<String>,
    tls_config: Option<PathBuf>,
    input: Option<u16>,
    from: Option<usize>,
    to: Option<usize>,
    config: Option<PathBuf>,
    peer: Option<String>,
    request: Option<PathBuf>,
    candidate: Option<String>,
    reason: Option<String>,
    registration: Option<PathBuf>,
    reproduce: bool,
    automatic_artifact_paths: bool,
    json: bool,
}

impl Cli {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut command = None;
        let mut options = std::collections::BTreeMap::new();
        let mut json = false;
        let mut reproduce = false;
        let mut index = 0;
        while index < args.len() {
            let arg = &args[index];
            if arg == "--json" {
                if json {
                    return Err("--json was supplied more than once".into());
                }
                json = true;
                index += 1;
                continue;
            }
            if arg == "--reproduce" {
                if reproduce {
                    return Err("--reproduce was supplied more than once".into());
                }
                reproduce = true;
                index += 1;
                continue;
            }
            if arg == "--help" || arg == "-h" {
                command = Some("help".to_string());
                index += 1;
                continue;
            }
            if arg == "--version" || arg == "-V" {
                command = Some("version".to_string());
                index += 1;
                continue;
            }
            if [
                "--state",
                "--receipts",
                "--fault",
                "--artifact",
                "--tls-config",
                "--input",
                "--from",
                "--to",
                "--config",
                "--peer",
                "--request",
                "--candidate",
                "--reason",
                "--registration",
            ]
            .contains(&arg.as_str())
            {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| format!("{arg} requires a value"))?;
                if value.is_empty() || value.starts_with("--") {
                    return Err(format!("{arg} requires a nonempty value"));
                }
                if options.insert(arg.clone(), value.clone()).is_some() {
                    return Err(format!("{arg} was supplied more than once"));
                }
                index += 2;
                continue;
            }
            if arg.starts_with('-') {
                return Err(format!("unknown option: {arg}"));
            }
            if command.is_some() {
                return Err(format!("unexpected argument: {arg}"));
            }
            command = Some(arg.clone());
            index += 1;
        }
        let command = command.unwrap_or_else(|| "help".into());
        if ![
            "help",
            "version",
            "demo",
            "benchmark",
            "research",
            "graph-research",
            "adaptive-research",
            "network-research",
            "prepare-tls-state",
            "route",
            "prepare-service",
            "serve",
            "peers",
            "connect",
            "evaluate",
            "peer-revoke",
            "predict",
            "verify-memory",
            "status",
            "revoke",
            "doctor",
            "inspect-state",
            "recover",
            "migrate",
        ]
        .contains(&command.as_str())
        {
            return Err(format!("unknown command: {command}"));
        }
        for option in options.keys() {
            let allowed = match option.as_str() {
                "--state" => ![
                    "help",
                    "version",
                    "serve",
                    "peers",
                    "connect",
                    "evaluate",
                    "peer-revoke",
                ]
                .contains(&command.as_str()),
                "--receipts" => [
                    "demo",
                    "benchmark",
                    "research",
                    "graph-research",
                    "adaptive-research",
                    "network-research",
                ]
                .contains(&command.as_str()),
                "--fault" => ["demo", "benchmark", "network-research"].contains(&command.as_str()),
                "--artifact" => ["revoke", "predict", "route"].contains(&command.as_str()),
                "--tls-config" => command == "network-research",
                "--input" => command == "predict",
                "--from" | "--to" => command == "route",
                "--config" => ["serve", "peers", "connect", "evaluate", "peer-revoke"]
                    .contains(&command.as_str()),
                "--peer" => ["connect", "peer-revoke"].contains(&command.as_str()),
                "--request" => command == "connect",
                "--candidate" => command == "evaluate",
                "--reason" => command == "peer-revoke",
                "--registration" => command == "adaptive-research",
                _ => false,
            };
            if !allowed {
                return Err(format!("{option} does not apply to {command}"));
            }
        }
        let fault = options.remove("--fault").unwrap_or_else(|| "none".into());
        let faults = if command == "network-research" {
            &[
                "none",
                "startup-timeout",
                "crash-after-ready",
                "crash-after-promotion",
            ][..]
        } else {
            &["none", "wrong-artifact", "drift"][..]
        };
        if !faults.contains(&fault.as_str()) {
            return Err(format!(
                "unknown fault: {fault}; allowed values: {}",
                faults.join(", ")
            ));
        }
        let artifact = options.remove("--artifact");
        let tls_config = options.remove("--tls-config").map(PathBuf::from);
        if tls_config.is_some() && fault != "none" {
            return Err("--tls-config cannot be combined with fault injection".into());
        }
        if ["revoke", "route"].contains(&command.as_str()) && artifact.is_none() {
            return Err(format!("{command} requires --artifact ID"));
        }
        let input = options
            .remove("--input")
            .map(|value| {
                value
                    .parse::<u16>()
                    .map_err(|_| "--input must be a nonnegative 16-bit integer")
            })
            .transpose()?;
        let from = options
            .remove("--from")
            .map(|value| {
                value
                    .parse::<usize>()
                    .map_err(|_| "--from must be a nonnegative node index")
            })
            .transpose()?;
        let to = options
            .remove("--to")
            .map(|value| {
                value
                    .parse::<usize>()
                    .map_err(|_| "--to must be a nonnegative node index")
            })
            .transpose()?;
        if command == "predict" && (artifact.is_some() != input.is_some()) {
            return Err("querying predict requires both --artifact ID and --input N".into());
        }
        if command == "route" && (from.is_none() || to.is_none()) {
            return Err("route requires --from NODE and --to NODE".into());
        }
        let config = options.remove("--config").map(PathBuf::from);
        let peer = options.remove("--peer");
        let request = options.remove("--request").map(PathBuf::from);
        let candidate = options.remove("--candidate");
        let reason = options.remove("--reason");
        let registration = options.remove("--registration").map(PathBuf::from);
        if reproduce && command != "adaptive-research" {
            return Err("--reproduce applies only to adaptive-research".into());
        }
        if command == "adaptive-research" {
            if reproduce == registration.is_some() {
                return Err(
                    "adaptive-research requires exactly one of --reproduce or --registration FILE"
                        .into(),
                );
            }
            let state_set = options.contains_key("--state");
            let receipt_set = options.contains_key("--receipts");
            if state_set != receipt_set || (!reproduce && !state_set) {
                return Err("registered or custom adaptive experiments require both --state DIR and --receipts FILE".into());
            }
        }
        if ["serve", "peers", "connect", "evaluate", "peer-revoke"].contains(&command.as_str())
            && config.is_none()
        {
            return Err(format!("{command} requires --config FILE"));
        }
        if ["connect", "peer-revoke"].contains(&command.as_str()) && peer.is_none() {
            return Err(format!("{command} requires --peer ID"));
        }
        if command == "connect" && request.is_none() {
            return Err("connect requires --request FILE".into());
        }
        if command == "evaluate" && candidate.is_none() {
            return Err("evaluate requires --candidate SHA256".into());
        }
        if command == "peer-revoke" && reason.is_none() {
            return Err("peer-revoke requires --reason TEXT".into());
        }
        let default_receipt = if command == "graph-research" {
            "experiments/local/graph-research.json"
        } else if command == "network-research" {
            "experiments/local/network-research.json"
        } else if command == "research" {
            "experiments/local/research.json"
        } else {
            "experiments/local/demo.json"
        };
        let automatic_artifact_paths =
            command == "adaptive-research" && reproduce && !options.contains_key("--state");
        let automatic_root = if automatic_artifact_paths {
            Some(std::env::temp_dir().join(format!(
                "symbiote-reproduction-{}",
                symbiote_protocol::fresh_capability()?
            )))
        } else {
            None
        };
        let state = options
            .remove("--state")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                automatic_root
                    .as_ref()
                    .map(|root| root.join("state"))
                    .unwrap_or_else(|| PathBuf::from("state/demo"))
            });
        let receipts = options
            .remove("--receipts")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                automatic_root
                    .as_ref()
                    .map(|root| root.join("reciprocal-frontier.json"))
                    .unwrap_or_else(|| PathBuf::from(default_receipt))
            });
        Ok(Self {
            command,
            state,
            receipts,
            fault,
            artifact,
            tls_config,
            input,
            from,
            to,
            config,
            peer,
            request,
            candidate,
            reason,
            registration,
            reproduce,
            automatic_artifact_paths,
            json,
        })
    }
}

fn path_exists(path: &Path) -> Result<bool, String> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("cannot inspect {}: {error}", path.display())),
    }
}

fn execute(cli: &Cli) -> Result<Value, String> {
    let command = cli.command.as_str();
    let state = &cli.state;
    let receipts = &cli.receipts;
    if command == "adaptive-research" {
        if cli.automatic_artifact_paths {
            let parent = state.parent().ok_or("automatic artifact parent missing")?;
            fs::create_dir(parent)
                .map_err(|_| "cannot create fresh reproduction artifact directory")?;
            fs::create_dir(state).map_err(|_| "cannot create fresh reproduction state")?;
        }
        if cli.reproduce {
            return adaptive_research::run_reproduction(state, receipts);
        }
        return adaptive_research::run_primary(
            state,
            receipts,
            cli.registration
                .as_deref()
                .ok_or("--registration required")?,
        );
    }
    if command == "prepare-service" {
        return service::prepare(state);
    }
    if ["serve", "peers", "connect", "evaluate", "peer-revoke"].contains(&command) {
        let config = cli.config.as_deref().ok_or("--config required")?;
        return match command {
            "serve" => service::serve(config),
            "peers" => service::peers(config),
            "connect" => service::connect(
                config,
                cli.peer.as_deref().ok_or("--peer required")?,
                cli.request.as_deref().ok_or("--request required")?,
            ),
            "evaluate" => service::evaluate(
                config,
                cli.candidate.as_deref().ok_or("--candidate required")?,
            ),
            "peer-revoke" => service::peer_revoke(
                config,
                cli.peer.as_deref().ok_or("--peer required")?,
                cli.reason.as_deref().ok_or("--reason required")?,
            ),
            _ => unreachable!(),
        };
    }
    if command == "graph-research" {
        return graph_research::run(state, receipts);
    }
    if command == "research" {
        return research::run(state, receipts);
    }
    if command == "network-research" {
        if let Some(config) = &cli.tls_config {
            return research::deployed::run_tls(state, receipts, config);
        }
        if cli.fault == "none" {
            return research::deployed::run(state, receipts);
        }
        return research::deployed::run_with_fault(state, receipts, &cli.fault);
    }
    if command == "prepare-tls-state" {
        return research::deployed::initialize_tls_state(state);
    }
    if command == "inspect-state" {
        return Ok(json!(symbiote_memory::maintenance::inspect(state)?));
    }
    if command == "recover" {
        return Ok(json!(symbiote_memory::maintenance::recover(state)?));
    }
    if command == "migrate" {
        return Ok(json!(symbiote_memory::maintenance::migrate(state)?));
    }
    if command == "demo" || command == "benchmark" {
        return demo(state, receipts, &cli.fault);
    }
    if command == "doctor" {
        let inspection = symbiote_memory::maintenance::inspect(state)?;
        let state_exists = path_exists(state)?;
        let ledger_exists = path_exists(&state.join("ledger.jsonl"))?;
        let lock_exists = path_exists(&state.join("writer.lock"))?;
        let knowledge_exists = path_exists(&state.join("knowledge.jsonl"))?;
        let knowledge_lock_exists = path_exists(&state.join("knowledge.writer.lock"))?;
        return Ok(
            json!({"schema":"symbiote.doctor/1","version":env!("CARGO_PKG_VERSION"),"status":inspection.status,"os":std::env::consts::OS,"architecture":std::env::consts::ARCH,"state":state,"state_exists":state_exists,"ledger_exists":ledger_exists,"writer_lock_exists":lock_exists,"knowledge_exists":knowledge_exists,"knowledge_writer_lock_exists":knowledge_lock_exists,"ledger_integrity":inspection.ledger_integrity,"locks":inspection.locks,"network_requests":0,"state_modified":false}),
        );
    }
    if command == "route" || (command == "predict" && cli.artifact.is_some()) {
        if !path_exists(&state.join("ledger.jsonl"))?
            || !path_exists(&state.join("knowledge.jsonl"))?
        {
            return Err(
                "no retained structural knowledge; check --state DIR and --artifact ID".into(),
            );
        }
        let identity = Store::open(state)?;
        let knowledge = KnowledgeStore::open(state, identity.identity())?;
        let id = cli.artifact.as_deref().ok_or("--artifact is required")?;
        let record = knowledge
            .active()
            .into_iter()
            .find(|record| record.id == id)
            .ok_or_else(|| format!("no active structural knowledge named {id}"))?;
        if command == "route" {
            let KnowledgePayload::GraphMap(map) = record.typed_payload()? else {
                return Err("route requires graph-map knowledge".into());
            };
            let input = symbiote_memory::knowledge::graph::encode_query(
                map.schema.nodes,
                cli.from.ok_or("--from required")?,
                cli.to.ok_or("--to required")?,
            )?;
            let route = record.graph_forecast(input)?;
            return Ok(
                json!({"schema":"symbiote.route/1","status":"PASS","identity":identity.identity(),"artifact":record.id,"revision":record.revision,"scope":record.scope,"record_sha256":record.digest()?,"from":cli.from,"to":cli.to,"route":route,"prediction_status":if route.is_some(){"conditionally-certified"}else{"abstained"},"network_requests":0}),
            );
        }
        let input = cli.input.ok_or("--input required")?;
        let prediction = record.predict_if_certified(input)?;
        return Ok(
            json!({"schema":"symbiote.prediction/1","status":"PASS","identity":identity.identity(),"artifact":record.id,"revision":record.revision,"scope":record.scope,"record_sha256":record.digest()?,"input":input,"prediction":prediction,"prediction_status":if prediction.is_some(){"conditional-inference"}else{"abstained"},"network_requests":0}),
        );
    }
    if ["status", "predict", "verify-memory"].contains(&command)
        && !path_exists(&state.join("ledger.jsonl"))?
    {
        if path_exists(&state.join("knowledge.jsonl"))? {
            return Err("structural knowledge exists without its identity ledger".into());
        }
        return Ok(
            json!({"schema":"symbiote.retained/1","identity":null,"active_artifacts":0,"genesis_artifacts":0,"structural_artifacts":0,"predictions":[],"structural_knowledge":[],"network_requests":0,"status":"EMPTY","state_modified":false}),
        );
    }
    if command == "predict" || command == "verify-memory" || command == "status" {
        let store = Store::open(state)?;
        let predictions: Vec<Value> = store.active().into_iter().map(|a| json!({"partner":a.source,"artifact":a.id,"revision":a.revision,"scope":a.scope,"predictions":a.table})).collect();
        let mut structural_knowledge = Vec::new();
        if path_exists(&state.join("knowledge.jsonl"))? {
            let knowledge = KnowledgeStore::open(state, store.identity())?;
            for record in knowledge.active() {
                let mut sample_predictions = Vec::new();
                match record.typed_payload()? {
                    KnowledgePayload::Affine { width, .. } => {
                        for input in 0..8_usize.min(1_usize << width) {
                            sample_predictions.push(
                                json!({"input":input,"output":record.predict(input as u16)?}),
                            );
                        }
                    }
                    KnowledgePayload::GraphMap(map) => {
                        for start in 0..map.schema.nodes {
                            for goal in 0..map.schema.nodes {
                                if start == goal || sample_predictions.len() >= 8 {
                                    continue;
                                }
                                let input = symbiote_memory::knowledge::graph::encode_query(
                                    map.schema.nodes,
                                    start,
                                    goal,
                                )?;
                                let route = record.graph_forecast(input)?;
                                sample_predictions.push(json!({"input":input,"from":start,"to":goal,"route":route,"prediction_status":if route.is_some(){"conditionally-certified"}else{"abstained"}}));
                            }
                        }
                    }
                }
                structural_knowledge.push(json!({"id":record.id,"source":record.source,"scope":record.scope,"revision":record.revision,"schema_fingerprint":record.schema_fingerprint,"model":record.payload,"sample_predictions":sample_predictions,"prediction_status":"validated-in-declared-synthetic-scope"}));
            }
        }
        return Ok(
            json!({"schema":"symbiote.retained/1","identity":store.identity(),"active_artifacts":predictions.len()+structural_knowledge.len(),"genesis_artifacts":predictions.len(),"structural_artifacts":structural_knowledge.len(),"predictions":predictions,"structural_knowledge":structural_knowledge,"network_requests":0,"status":"PASS"}),
        );
    }
    if command == "revoke" {
        if !path_exists(&state.join("ledger.jsonl"))? {
            return Err("no retained state to revoke; check --state DIR".into());
        }
        let mut store = Store::open(state)?;
        let id = cli.artifact.as_deref().ok_or("--artifact is required")?;
        let mut structural_count = 0;
        let mut revoked_kind = "genesis";
        if store.active().iter().any(|artifact| artifact.id == id) {
            store.revoke(id, "operator requested rollback")?;
            if path_exists(&state.join("knowledge.jsonl"))? {
                structural_count = KnowledgeStore::open(state, store.identity())?
                    .active()
                    .len();
            }
        } else {
            if !path_exists(&state.join("knowledge.jsonl"))? {
                return Err(format!("no active knowledge named {id}"));
            }
            let mut knowledge = KnowledgeStore::open(state, store.identity())?;
            knowledge.revoke(id, "operator requested rollback")?;
            structural_count = knowledge.active().len();
            revoked_kind = "structural";
        }
        return Ok(
            json!({"status":"PASS","revoked":id,"revoked_kind":revoked_kind,"active_artifacts":store.active().len()+structural_count}),
        );
    }
    if command == "version" {
        return Ok(
            json!({"name":"SYMBIOTE","version":env!("CARGO_PKG_VERSION"),"build_source_commit":option_env!("SYMBIOTE_SOURCE_COMMIT").unwrap_or("unknown")}),
        );
    }
    if command == "help" {
        return Ok(
            json!({"SYMBIOTE":env!("CARGO_PKG_VERSION"),"commands":["demo [--state DIR] [--receipts FILE]","research [--state DIR] [--receipts FILE]","graph-research [--state DIR] [--receipts FILE]","network-research [--state DIR] [--receipts FILE] [--tls-config FILE]","adaptive-research --reproduce [--state FRESH_DIR --receipts FILE]","adaptive-research --registration FILE --state FRESH_DIR --receipts FILE","prepare-tls-state [--state DIR]","route --artifact ID --from NODE --to NODE [--state DIR]","prepare-service --state DIR","serve --config FILE","peers --config FILE","connect --config FILE --peer ALIAS --request FILE","evaluate --config FILE --candidate SHA256","peer-revoke --config FILE --peer ALIAS --reason TEXT","benchmark --state FRESH_DIR","status [--state DIR]","predict [--state DIR]","doctor [--state DIR]","inspect-state [--state DIR]","recover [--state DIR]","migrate [--state DIR]","verify-memory [--state DIR]","revoke --artifact ID [--state DIR]"],"options":["--json","--help","--version"],"fault_injection":["--fault wrong-artifact","--fault drift"]}),
        );
    }
    Err(format!("unknown command: {command}"))
}

fn display(report: &Value, cli: &Cli) -> String {
    if cli.command == "serve" {
        return serde_json::to_string(report).expect("serializable service frame");
    }
    if [
        "peers",
        "connect",
        "evaluate",
        "peer-revoke",
        "prepare-service",
    ]
    .contains(&cli.command.as_str())
    {
        return serde_json::to_string_pretty(report).expect("serializable service receipt");
    }
    if cli.json {
        return serde_json::to_string_pretty(report).expect("serializable report");
    }
    let version = env!("CARGO_PKG_VERSION");
    if cli.command == "version" {
        return format!("SYMBIOTE {version}");
    }
    if cli.command == "help" {
        return format!("SYMBIOTE {version} — Symbiotic Adaptive Intelligence\n\nUsage: symbiote COMMAND [OPTIONS]\n\n  demo           Run the authorized two-agent learning demonstration\n  research       Run structural-transfer experiments and matched controls\n  graph-research Run route-planning exchange and all paired controls\n  adaptive-research  Compare partner selection: --reproduce (fresh temporary study)\n  network-research  Run separately deployed native research agents\n  prepare-tls-state  Initialize public role IDs for TLS provisioning\n  route          Query a retained graph: --artifact ID --from N --to N\n  prepare-service  Create an identity for configured TLS deployment\n  serve          Serve granted native knowledge: --config FILE\n  peers          List an explicit registry: --config FILE\n  connect        One granted operation: --config FILE --peer ALIAS --request FILE\n  evaluate       Check a quarantined offer: --config FILE --candidate SHA256\n  peer-revoke    Persist denial: --config FILE --peer ALIAS --reason TEXT\n  inspect-state  Inspect integrity and writer liveness without mutation\n  recover        Remove only verified-dead writer locks\n  migrate        Register legacy state with byte-preserving backups\n  status         Show identity and retained knowledge\n  predict        Display retained predictions without network access\n  doctor         Inspect local readiness without changing state\n  benchmark      Run the Genesis comparison (use a fresh state directory)\n  verify-memory  Validate the persistent knowledge ledger\n  revoke         Revoke knowledge: --artifact ID\n\nOptions:\n  --state DIR      State directory (default: state/demo)\n  --receipts FILE  Receipt output for learning experiments\n  --tls-config FILE  Explicit mTLS manifest for network-research\n  --reproduce       New adaptive study in a fresh temporary directory\n  --registration FILE  Immutable primary-study registration\n  --artifact ID --input N  Query one retained model with predict\n  --json           Machine-readable output\n  --help, -h       Show this help\n  --version, -V    Show the version\n\nStart here: symbiote demo\nThen:       symbiote status\nNo language model or API key is required for the local demonstrations.");
    }
    let status = report["status"].as_str().unwrap_or("COMPLETE");
    let mut lines = vec![format!("SYMBIOTE {version} | {} | {status}", cli.command)];
    if cli.command == "doctor" {
        lines.push(format!(
            "Platform: {} / {}",
            report["os"].as_str().unwrap_or("unknown"),
            report["architecture"].as_str().unwrap_or("unknown")
        ));
        lines.push(format!("State: {}", cli.state.display()));
        lines.push(format!(
            "Genesis ledger: {} | Structural knowledge: {}",
            report["ledger_exists"], report["knowledge_exists"]
        ));
        lines.push(format!(
            "Writer locks: genesis {} / knowledge {}",
            report["writer_lock_exists"], report["knowledge_writer_lock_exists"]
        ));
        if report["writer_lock_exists"] == true || report["knowledge_writer_lock_exists"] == true {
            lines.push(
                "A writer may be active. Confirm it has exited before recovering a stale lock."
                    .into(),
            );
        }
        lines.push("Inspection only; no state changes or network requests.".into());
        lines.push(format!(
            "Ledger integrity: {}",
            report["ledger_integrity"]
                .as_str()
                .unwrap_or("not verified")
        ));
        return lines.join("\n");
    }
    if let Some(identity) = report["identity"].as_str() {
        lines.push(format!("Identity: {identity}"));
    }
    if let Some(active) = report["active_artifacts"].as_u64() {
        lines.push(format!("Validated knowledge: {active} active artifact(s)"));
    }
    if let Some(promoted) = report["promoted"].as_u64() {
        if cli.command == "research" {
            lines.push(format!(
                "This experiment: {promoted} promoted, {} already retained",
                report["already_retained"].as_u64().unwrap_or(0)
            ));
        } else {
            lines.push(format!(
                "This cycle: {promoted} promoted, {} reused",
                report["reused"].as_u64().unwrap_or(0)
            ));
        }
    }
    if let Some(participants) = report["participants"]
        .as_array()
        .filter(|_| ["demo", "benchmark"].contains(&cli.command.as_str()))
    {
        for participant in participants {
            let s = &participant["symbiote"];
            let p = &participant["partner_benefit"];
            lines.push(format!(
                "  {}: prediction coverage {}/{} -> {}/{}; equal-probe control {}/{}",
                participant["partner"].as_str().unwrap_or("partner"),
                s["isolated_correct"],
                s["total"],
                s["exchange_correct"],
                s["total"],
                s["matched_probe_control_correct"],
                s["total"]
            ));
            lines.push(format!(
                "    Partner resource units: {} -> {} (simulation units, validation included)",
                p["baseline_resource_units"], p["strategy_resource_units_including_verification"]
            ));
        }
        lines.push(
            "Finite laboratory tasks; this does not establish a general transfer advantage.".into(),
        );
    }
    if let Some(predictions) = report["predictions"].as_array() {
        for prediction in predictions {
            lines.push(format!(
                "  {}: revision {} | inputs 0..3 -> {}",
                prediction["partner"].as_str().unwrap_or("partner"),
                prediction["revision"],
                prediction["predictions"]
            ));
        }
        let structural_count = report["structural_artifacts"].as_u64().unwrap_or(0);
        if structural_count > 0 {
            lines.push(format!(
                "Structural knowledge: {structural_count} validated model(s)"
            ));
            if let Some(models) = report["structural_knowledge"].as_array() {
                for model in models.iter().take(8) {
                    let description = if model["model"]["kind"] == "graph-map" {
                        format!("graph with {} nodes", model["model"]["schema"]["nodes"])
                    } else {
                        format!("{}-bit affine model", model["model"]["width"])
                    };
                    lines.push(format!(
                        "  {}: revision {} | {description}",
                        model["id"].as_str().unwrap_or("model"),
                        model["revision"]
                    ));
                }
                if models.len() > 8 {
                    lines.push(format!(
                        "  ... {} more; use --json for all models and sample predictions",
                        models.len() - 8
                    ));
                }
            }
        }
        if predictions.is_empty() && structural_count == 0 {
            lines.push("No retained knowledge yet. Run: symbiote demo".into());
        }
        lines.push("Network requests: 0".into());
    }
    if cli.command == "revoke" {
        lines.push(format!(
            "Revoked: {}",
            report["revoked"].as_str().unwrap_or("unknown")
        ));
    }
    if cli.command == "route" || (cli.command == "predict" && cli.artifact.is_some()) {
        lines.push(format!(
            "Artifact: {} | revision {}",
            report["artifact"].as_str().unwrap_or("unknown"),
            report["revision"]
        ));
        if let Some(route) = report["route"].as_object() {
            lines.push(format!(
                "Route: {} | cost {}",
                route["nodes"], route["cost"]
            ));
        }
        if let Some(prediction) = report.get("prediction") {
            lines.push(format!("Input {} -> {}", report["input"], prediction));
        }
        lines.push(format!(
            "Prediction: {}",
            report["prediction_status"].as_str().unwrap_or("abstained")
        ));
        lines.push("Retained knowledge; network requests: 0".into());
    }
    if cli.command == "prepare-tls-state" {
        lines.push(
            serde_json::to_string_pretty(report).expect("serializable public role identities"),
        );
    }
    if cli.command == "research" {
        for field in ["cases", "passed", "failed", "experiment", "scope"] {
            if let Some(value) = report.get(field) {
                lines.push(format!(
                    "{field}: {}",
                    value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string())
                ));
            }
        }
        if let Some(participants) = report["participants"].as_array() {
            for participant in participants {
                lines.push(format!(
                    "  {}: isolated cost {} / exchange cost {} | correct {}/{}",
                    participant["agent"].as_str().unwrap_or("participant"),
                    participant["isolated_cost"],
                    participant["exchange_cost"],
                    participant["correct"],
                    participant["total"]
                ));
            }
        }
        if let Some(conclusion) = report["conclusion"].as_str() {
            lines.push(conclusion.into());
        }
        lines.push("Use --json for complete experimental measurements.".into());
    }
    if cli.command == "network-research" {
        if let Some(participants) = report["participants"].as_array() {
            for agent in participants {
                lines.push(format!(
                    "  {}: native PID {} -> restarted PID {} | {} retained model(s)",
                    agent["agent"].as_str().unwrap_or("agent"),
                    agent["pid"],
                    agent["restart_pid"],
                    agent["active_models"]
                ));
            }
        }
        lines.push(format!(
            "Private identity and predictions survived restart: {}",
            report["restart_retained_predictions"]
        ));
        lines.push(format!(
            "Forged observation rejected: {}",
            report["forged_receipt_rejected"]
        ));
        lines.push("Deployment/persistence prototype; no new paired efficiency claim.".into());
    }
    if cli.command == "adaptive-research" {
        lines.push(format!(
            "Build source: {}",
            report["source_commit"].as_str().unwrap_or("unknown")
        ));
        if report["source_commit"] == "unknown" {
            lines.push("This source build has no commit binding; full scientific evidence verification requires a bound build.".into());
        }
        lines.push(format!(
            "Study: {} worlds × {} prices × {} arms | {} / {} cases recorded",
            report["world_count"],
            report["price_regimes"],
            report["comparison_arms"],
            report["cases_recorded"],
            report["cases_expected"]
        ));
        if let Some(regimes) = report["comparisons"]["regimes"].as_array() {
            for regime in regimes {
                if let Some(comparisons) = regime["prospective_vs_controls"].as_array() {
                    for comparison in comparisons {
                        lines.push(format!(
                            "  Price {} / prospective vs {}: A+B1 cost {} vs {} | bilateral benefit in {} worlds",
                            regime["observation_price"], comparison["baseline_arm"].as_str().unwrap_or("control"),
                            comparison["A_B1_candidate_cost"], comparison["A_B1_baseline_cost"],
                            comparison["bilateral_benefit_worlds"]
                        ));
                    }
                }
            }
        }
        lines.push(format!(
            "Normal-price utility: {} | Better partner selection: {} | Persistent learning: {}",
            report["comparisons"]["normal_policy_utility"]
                .as_str()
                .unwrap_or("NOT_DEMONSTRATED"),
            report["comparisons"]["normal_better_partner_selection"]
                .as_str()
                .unwrap_or("NOT_DEMONSTRATED"),
            report["learning_gate"]["status"]
                .as_str()
                .unwrap_or("NOT_DEMONSTRATED")
        ));
        lines.push("PASS denotes completed software and safety checks. Selection and utility claims require the paired measurements in the receipt.".into());
        lines.push(
            "Owned local TLS processes; finite synthetic tasks and declared logical costs.".into(),
        );
    }
    if cli.command == "graph-research" {
        if let Some(regimes) = report["regimes"].as_array() {
            for regime in regimes {
                lines.push(format!("  {}: {} worlds | isolated cost {} / exchange cost {} | bilateral benefit in {} worlds",regime["name"].as_str().unwrap_or("regime"),regime["worlds"],regime["isolated_cost"],regime["exchange_cost"],regime["bilateral_benefit_worlds"]));
                lines.push(format!("    Outcomes: {}", regime["classes"]));
            }
        }
        lines.push(format!(
            "Knowledge: {} promoted, {} withheld for incomplete held-out coverage",
            report["promotions"]["promoted"].as_u64().unwrap_or(0),
            report["promotions"]["withheld_abstention"]
                .as_u64()
                .unwrap_or(0)
        ));
        lines.push(format!(
            "Retained graph predictions survived process restart: {}",
            report["restart_retained_predictions"]
        ));
        if let Some(example) = report.get("example_query") {
            lines.push(format!(
                "Try: symbiote route --state \"{}\" --artifact {} --from 1 --to 3",
                example["state"]
                    .as_str()
                    .unwrap_or("state/demo/graph/dijkstra"),
                example["artifact"].as_str().unwrap_or("model")
            ));
        }
        lines.push("Finite graph family and declared logical costs; all harmful cases remain in the report.".into());
    }
    if cli.command == "inspect-state" {
        lines.push(format!(
            "Ledger integrity: {}",
            report["ledger_integrity"]
                .as_str()
                .unwrap_or("not verified")
        ));
        if let Some(locks) = report["locks"].as_array() {
            for lock in locks {
                lines.push(format!(
                    "  {}: {} | owner PID {}",
                    lock["name"].as_str().unwrap_or("lock"),
                    lock["state"].as_str().unwrap_or("unknown"),
                    lock["process"]
                ));
            }
        }
        lines.push("Read-only inspection; no state changes.".into());
    }
    if cli.command == "recover" {
        lines.push(format!(
            "Verified-dead locks recovered: {}",
            report["recovered_locks"]
        ));
        lines.push("Learning ledgers preserved; no processes terminated.".into());
    }
    if cli.command == "migrate" {
        lines.push(format!(
            "Layout version: {} | changed: {}",
            report["layout_version"], report["changed"]
        ));
        lines.push("Original learning ledger bytes preserved with registered backups.".into());
    }
    lines.push(format!("State: {}", cli.state.display()));
    if [
        "demo",
        "benchmark",
        "research",
        "graph-research",
        "network-research",
        "adaptive-research",
    ]
    .contains(&cli.command.as_str())
    {
        lines.push(format!("Receipt: {}", cli.receipts.display()));
    }
    lines.join("\n")
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args
        .first()
        .is_some_and(|arg| arg == "__adaptive-participant")
    {
        if args.len() != 1 || adaptive_research::serve_from_stdin().is_err() {
            eprintln!(
                "SYMBIOTE adaptive participant stopped; private bootstrap contents are withheld."
            );
            std::process::exit(1);
        }
        return;
    }
    #[cfg(debug_assertions)]
    if args
        .first()
        .is_some_and(|arg| arg == "__adaptive-development")
    {
        if args.len() != 1 || adaptive_research::development_from_stdin().is_err() {
            eprintln!("SYMBIOTE fixed-fixture development probe failed; private input contents are withheld.");
            std::process::exit(1);
        }
        return;
    }
    if args.first().is_some_and(|arg| arg == "__graph-forecast") {
        if args.len() != 1 || graph_research::forecast_from_stdin().is_err() {
            eprintln!("SYMBIOTE graph forecast failed; private request contents are withheld.");
            std::process::exit(1);
        }
        return;
    }
    if args.first().is_some_and(|arg| arg == "__research-partner") {
        if args.len() != 1 || research::deployed::serve_from_stdin().is_err() {
            eprintln!("SYMBIOTE native partner stopped with an error; configuration and capability contents are withheld.");
            std::process::exit(1);
        }
        return;
    }
    let cli = match Cli::parse(args) {
        Ok(cli) => cli,
        Err(error) => {
            eprintln!("SYMBIOTE: {error}\nRun `symbiote --help` for usage.");
            std::process::exit(2);
        }
    };
    match execute(&cli) {
        Ok(report) => {
            println!("{}", display(&report, &cli));
            if ["FAIL", "HOLD", "REJECTED"].contains(&report["status"].as_str().unwrap_or("")) {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("SYMBIOTE failure: {error}");
            std::process::exit(1);
        }
    }
}
