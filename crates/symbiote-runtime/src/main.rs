//! Independent, bounded, LLM-free SYMBIOTE genesis runtime.
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
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
        "schema":"symbiote.demo/1","version":"0.1.0","status":"PASS","identity":identity,
        "language_model":false,"authorized_endpoints":2,"promoted":promoted,"reused":reused,"active_artifacts":store.active().len(),
        "participants":participants,"phases":phases,
        "scientific_status":"deterministic finite-domain software experiment; not generalized intelligence",
        "cost_accounting":{"symbiote_verification_queries":8,"matched_probe_control_queries":8,"partner_verification_queries":8,"telemetry_observations":4,"task_predictions":64,"task_predictions_are_repeated_not_independent_samples":true},
        "control_interpretation":"Exchange extends persistent prediction coverage relative to the two-observation isolated baseline. A control allowed the same four complete probes also reaches full coverage; no sample-efficiency or general transfer advantage is established.",
    });
    receipt_file(receipts, &report)?;
    Ok(report)
}

fn argument(args: &[String], flag: &str, default: &str) -> String {
    args.iter()
        .position(|s| s == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| default.into())
}

fn execute() -> Result<Value, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");
    let state = PathBuf::from(argument(&args, "--state", "state/demo"));
    let receipts = PathBuf::from(argument(&args, "--receipts", "experiments/local/demo.json"));
    if command == "demo" || command == "benchmark" {
        return demo(&state, &receipts, &argument(&args, "--fault", "none"));
    }
    if command == "predict" || command == "verify-memory" {
        let store = Store::open(&state)?;
        let predictions: Vec<Value> = store.active().into_iter().map(|a| json!({"partner":a.source,"artifact":a.id,"revision":a.revision,"scope":a.scope,"predictions":a.table})).collect();
        return Ok(
            json!({"schema":"symbiote.retained/1","identity":store.identity(),"active_artifacts":predictions.len(),"predictions":predictions,"network_requests":0,"status":"PASS"}),
        );
    }
    if command == "revoke" {
        let mut store = Store::open(&state)?;
        let id = argument(&args, "--artifact", "");
        if id.is_empty() {
            return Err("--artifact is required".into());
        }
        store.revoke(&id, "operator requested rollback")?;
        return Ok(json!({"status":"PASS","revoked":id,"active_artifacts":store.active().len()}));
    }
    if command == "help" || command == "--help" || command == "-h" {
        return Ok(
            json!({"SYMBIOTE":"0.1.0","commands":["demo --state DIR --receipts FILE","benchmark --state FRESH_DIR --receipts FILE","predict --state DIR","verify-memory --state DIR","revoke --state DIR --artifact ID"],"fault_injection":["--fault wrong-artifact","--fault drift"]}),
        );
    }
    Err(format!("unknown command: {command}"))
}

fn main() {
    match execute() {
        Ok(report) => println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serializable report")
        ),
        Err(error) => {
            eprintln!("SYMBIOTE failure: {error}");
            std::process::exit(1);
        }
    }
}
