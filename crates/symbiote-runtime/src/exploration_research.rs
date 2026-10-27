//! A fixed two-world native control for prospective experiment choice.
//! Three separate invocations keep one owner and independently pinned history.
//! It demonstrates bounded choice/retention, not superior general exploration.
use crate::exploration::{
    ExperimentPortfolio, ExperimentSpec, ExplorationPolicy, ExplorationSnapshot,
    LocalExperimentEvidence,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use symbiote_memory::knowledge::{
    affine_schema_fingerprint, assess, KnowledgeRecord, KnowledgeStore, TrialCase, TrialCosts,
    TrialEvidence,
};
use symbiote_memory::Store;
use symbiote_reasoning::structural::AffineLearner;

const MAX_FRAME: usize = 256 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: String,
    phase: String,
    owner: PathBuf,
    prior: Option<ExplorationSnapshot>,
    pin: Option<String>,
}

fn write_new(path: &Path, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_FRAME {
        return Err("exploration receipt exceeds byte budget".into());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())
}
fn policy(owner: &str) -> Result<ExplorationPolicy, String> {
    let learner = AffineLearner::new(3, 10_000)?;
    let hypotheses = learner.hypothesis_count() as u64;
    Ok(ExplorationPolicy {
        schema: "symbiote.exploration-policy/1".into(),
        owner: owner.into(),
        catalog: ["a", "b"]
            .into_iter()
            .map(|id| {
                Ok(ExperimentSpec {
                    id: format!("partner-{id}"),
                    scope: format!("portfolio-{id}/v1"),
                    artifact_id: format!("received-{id}"),
                    schema_fingerprint: affine_schema_fingerprint(3)?,
                    authorized: true,
                    hypothesis_count: hypotheses,
                    expected_eliminations: hypotheses / 2,
                    complete_cost_ceiling: 64,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
        maximum_steps: 2,
        total_cost_ceiling: 128,
    })
}
fn law(input: u16, coefficients: u16) -> u8 {
    ((input & coefficients).count_ones() % 2) as u8
}
fn evaluate(
    id: &str,
    candidate: u16,
    truth: u16,
    source: &str,
) -> Result<(KnowledgeRecord, TrialEvidence, Value), String> {
    let mut learner = AffineLearner::new(3, 20_000)?;
    let initial = learner.hypothesis_count();
    let mut queries = Vec::new();
    while let Some(input) = learner.choose_query()? {
        let output = law(input, truth);
        learner.observe(input, output)?;
        queries.push((input, output));
    }
    let training: Vec<_> = queries.iter().map(|(input, _)| *input).collect();
    let heldout: Vec<_> = (0..8).filter(|input| !training.contains(input)).collect();
    if heldout.is_empty() {
        return Err("local exploration evaluation has no held-out inputs".into());
    }
    let candidate = if source == "local-discovery" {
        learner
            .identified()
            .ok_or("local evidence did not identify an exact model")?
            .coefficients
    } else {
        candidate
    };
    let record=KnowledgeRecord {id:if source=="local-discovery" {format!("self-{id}")}else{format!("received-{id}")},revision:1,
        source:source.into(),scope:format!("portfolio-{id}/v1"),schema_fingerprint:affine_schema_fingerprint(3)?,
        payload:json!({"kind":"affine","width":3,"coefficients":candidate,"bias":false}),
        provenance:"Fixed native two-world control. Source proposal is inert; independent exact observations and disjoint held-out cases govern adoption.".into()};
    let evidence = TrialEvidence {
        evaluator: "portfolio-local-evaluator".into(),
        training_case_ids: training
            .iter()
            .map(|input| format!("training-{id}-{input}"))
            .collect(),
        training_inputs: training,
        cases: heldout
            .iter()
            .map(|input| TrialCase {
                id: format!("held-{id}-{input}"),
                input: *input,
                expected: law(*input, truth),
                baseline: None,
                candidate: law(*input, candidate),
            })
            .collect(),
        costs: TrialCosts {
            acquisition: queries.len() as u64,
            verification: heldout.len() as u64,
            adoption: 1,
            baseline: 16,
            candidate: 12,
        },
    };
    let mut matched_correct = 0;
    for case in &evidence.cases {
        matched_correct += usize::from(learner.predict(case.input)? == Some(case.expected));
    }
    let information = json!({"hypotheses_before":initial,"hypotheses_after":learner.hypothesis_count(),
        "observations":queries,"heldout_inputs":heldout,"model_work_units":learner.snapshot().model_evaluations,
        "oracle_calls":queries.len()+heldout.len(),"complete_declared_units":12,
        "unit_contract":"declared model:4 source/acquisition +4 heldout verification +1 adoption +3 proposal/selection coordination; no network-traffic cost claim; CPU work reported separately",
        "matched_query_budget_control_correct":matched_correct,"matched_query_budget_control_total":heldout.len(),
        "scope":"one fixed affine task; labels are trusted local lab observations"});
    Ok((record, evidence, information))
}
fn worker(config: Config) -> Result<Value, String> {
    if config.schema != "symbiote.exploration-worker/1"
        || !["reject-first", "learn-second", "replay"].contains(&config.phase.as_str())
        || !config.owner.is_absolute()
    {
        return Err("invalid bounded exploration bootstrap".into());
    }
    let owner = Store::open(&config.owner)?;
    let mut knowledge = KnowledgeStore::open(&config.owner, owner.identity())?;
    let mut portfolio = ExperimentPortfolio::open(
        policy(owner.identity())?,
        &knowledge,
        config.prior,
        config.pin.as_deref(),
    )?;
    let nonce = symbiote_protocol::fresh_capability()?;
    if config.phase == "replay" {
        if portfolio.select(&knowledge)?.is_some() {
            return Err("completed portfolio regained experiment budget".into());
        }
        let predictions = knowledge
            .active()
            .iter()
            .map(|record| {
                Ok(json!({"artifact":record.id,"scope":record.scope,
            "values":(0..8).map(|input|record.predict(input)).collect::<Result<Vec<_>,_>>()?}))
            })
            .collect::<Result<Vec<_>, String>>()?;
        if predictions.len() != 2 {
            return Err(
                "retained portfolio did not preserve both independently evaluated models".into(),
            );
        }
        return Ok(
            json!({"phase":config.phase,"identity":owner.identity(),"pid":std::process::id(),"instance_nonce":nonce,
            "predictions":predictions,"active_models":2,"oracle_calls":0,"new_promotions":0,"budget_exhausted":true}),
        );
    }
    let neutral_choice =
        ExperimentPortfolio::open(policy(owner.identity())?, &knowledge, None, None)?
            .select(&knowledge)?;
    let choice = portfolio
        .select(&knowledge)?
        .ok_or("no authorized experiment fits the remaining budget")?;
    let (result, local_discovery) = if config.phase == "reject-first" {
        if choice.experiment != "partner-a" {
            return Err(
                "initial exact tie-break did not choose the registered first experiment".into(),
            );
        }
        let (wrong, evidence, metrics) = evaluate("a", 1, 3, "partner-a")?;
        let failure = assess(&wrong, &evidence)
            .err()
            .ok_or("incorrect proposal was accepted")?;
        // Useful observations survive a bad proposal: SYMBIOTE derives its own
        // exact model instead of discarding independently verified experience.
        let (local, local_evidence, local_metrics) = evaluate("a", 3, 3, "local-discovery")?;
        knowledge.promote(local.clone(), assess(&local, &local_evidence)?)?;
        portfolio.fail(
            &choice.experiment,
            "actual incorrect held-out predictions; independently learned local model retained",
        )?;
        (
            json!({"status":"REJECTED","reason":failure,"metrics":metrics,
            "independent_local_model":local.id,"local_discovery_metrics":local_metrics}),
            true,
        )
    } else {
        if choice.experiment != "partner-b" || choice.prior_attempts != 0 {
            return Err(
                "durable prior rejection did not change the prospective experiment choice".into(),
            );
        }
        let (record, evidence, metrics) = evaluate("b", 5, 5, "partner-b")?;
        knowledge.promote(record.clone(), assess(&record, &evidence)?)?;
        portfolio.complete(
            &choice.experiment,
            LocalExperimentEvidence::Affine { record, evidence },
            &knowledge,
        )?;
        (json!({"status":"PROMOTED","metrics":metrics}), false)
    };
    let snapshot = portfolio.snapshot()?;
    Ok(
        json!({"phase":config.phase,"identity":owner.identity(),"pid":std::process::id(),"instance_nonce":nonce,
        "choice":choice,"neutral_history_choice":neutral_choice,"result":result,"retained_models":knowledge.active().len(),"snapshot":snapshot,
        "reserved_cost":portfolio.reserved_cost(),"local_learning_after_rejected_offer":local_discovery,
        "knowledge_head":knowledge.history_anchor()}),
    )
}
pub fn serve_from_stdin() -> Result<(), String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_FRAME as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "exploration bootstrap unavailable")?;
    if bytes.len() > MAX_FRAME {
        return Err("exploration bootstrap exceeds its byte budget".into());
    }
    let config: Config =
        serde_json::from_slice(&bytes).map_err(|_| "exploration bootstrap rejected")?;
    let result = worker(config)?;
    let output = serde_json::to_vec(&result).map_err(|_| "cannot encode exploration receipt")?;
    if output.len() > MAX_FRAME {
        return Err("exploration output exceeds its byte budget".into());
    }
    std::io::stdout()
        .write_all(&output)
        .and_then(|()| std::io::stdout().flush())
        .map_err(|_| "exploration output unavailable".into())
}
struct OwnedChild {
    child: Child,
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}
fn invoke(config: Config, output: &Path) -> Result<Value, String> {
    let child = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
        .arg("__exploration-agent")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut owned = OwnedChild {
        child,
        reader: None,
        writer: None,
    };
    let input = serde_json::to_vec(&config).map_err(|e| e.to_string())?;
    if input.len() > MAX_FRAME {
        return Err("exploration private command exceeds its bound".into());
    }
    let mut stdin = owned.child.stdin.take().ok_or("child input unavailable")?;
    let (written, write_result) = mpsc::sync_channel(1);
    owned.writer = Some(thread::spawn(move || {
        let result = stdin.write_all(&input).and_then(|()| stdin.flush());
        drop(stdin);
        let _ = written.send(result);
    }));
    write_result
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| "owned exploration bootstrap write deadline")?
        .map_err(|_| "owned exploration bootstrap pipe failed")?;
    let stdout = owned
        .child
        .stdout
        .take()
        .ok_or("child output unavailable")?;
    let (sender, receiver) = mpsc::sync_channel(1);
    owned.reader = Some(thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = BufReader::new(stdout)
            .take(MAX_FRAME as u64 + 1)
            .read_to_end(&mut bytes);
        let _ = sender.send(result.map(|_| bytes));
    }));
    let started = Instant::now();
    let bytes = receiver
        .recv_timeout(Duration::from_secs(10))
        .map_err(|_| "owned exploration child output deadline/EOF")?
        .map_err(|_| "owned exploration child read failed")?;
    if bytes.len() > MAX_FRAME {
        return Err("owned exploration child exceeded output bound".into());
    }
    let status = loop {
        if let Some(status) = owned.child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(12) {
            return Err("owned exploration child exit deadline".into());
        }
        thread::sleep(Duration::from_millis(5));
    };
    if !status.success() {
        return Err(
            "owned exploration child rejected bootstrap or failed its controlled task".into(),
        );
    }
    let result: Value =
        serde_json::from_slice(&bytes).map_err(|_| "owned exploration child receipt malformed")?;
    let mut raw = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.with_extension("stdout"))
        .map_err(|e| e.to_string())?;
    raw.write_all(&bytes)
        .and_then(|()| raw.sync_all())
        .map_err(|e| e.to_string())?;
    let mut result = result;
    result["control_frame"] = json!({"stdin_bytes":serde_json::to_vec(&config).map_err(|e|e.to_string())?.len(),
        "stdout_bytes":bytes.len(),"native_wall_ms":started.elapsed().as_millis(),
        "cost_scope":"actual local private-control frame bytes; no TLS/external-agent transport in this control"});
    write_new(output, &result)?;
    Ok(result)
}
pub fn run(state: &Path, receipts: &Path) -> Result<Value, String> {
    if state.exists() || receipts.exists() {
        return Err("exploration control requires fresh state and receipt destinations".into());
    }
    fs::create_dir_all(state.parent().unwrap_or_else(|| Path::new(".")))
        .map_err(|e| e.to_string())?;
    fs::create_dir(state).map_err(|e| e.to_string())?;
    let base = fs::canonicalize(state).map_err(|e| e.to_string())?;
    let owner = base.join("owner");
    let mut prior = None;
    let mut pin = None;
    let mut phases = Vec::new();
    for phase in ["reject-first", "learn-second", "replay"] {
        let report = invoke(
            Config {
                schema: "symbiote.exploration-worker/1".into(),
                phase: phase.into(),
                owner: owner.clone(),
                prior: prior.clone(),
                pin: pin.clone(),
            },
            &base.join(format!("{phase}.json")),
        )?;
        if phase != "replay" {
            let snapshot: ExplorationSnapshot =
                serde_json::from_value(report["snapshot"].clone()).map_err(|e| e.to_string())?;
            pin = Some(snapshot.sha256.clone());
            prior = Some(snapshot);
        }
        phases.push(report);
    }
    let identities: std::collections::BTreeSet<_> = phases
        .iter()
        .filter_map(|value| value["identity"].as_str())
        .collect();
    let nonces: std::collections::BTreeSet<_> = phases
        .iter()
        .filter_map(|value| value["instance_nonce"].as_str())
        .collect();
    if identities.len() != 1 || nonces.len() != 3 || phases[2]["oracle_calls"] != 0 {
        return Err("native portfolio restart evidence rejected".into());
    }
    let metrics = [
        &phases[0]["result"]["metrics"],
        &phases[0]["result"]["local_discovery_metrics"],
        &phases[1]["result"]["metrics"],
    ];
    let sum_required = |key: &str| -> Result<u64, String> {
        metrics.iter().try_fold(0_u64, |total, value| {
            total
                .checked_add(
                    value[key]
                        .as_u64()
                        .ok_or_else(|| format!("required experiment metric {key} missing"))?,
                )
                .ok_or_else(|| "experiment metric overflow".into())
        })
    };
    let declared_task_units = sum_required("complete_declared_units")?;
    let oracle_calls = sum_required("oracle_calls")?;
    let reserved_cost = phases[1]["reserved_cost"]
        .as_u64()
        .ok_or("completed reservation measurement missing")?;
    let report = json!({"schema":"symbiote.exploration-control/1","status":"PASS","version":env!("CARGO_PKG_VERSION"),
        "controller_pid":std::process::id(),"identity":phases[0]["identity"],"native_instances":nonces.len(),
        "choice_before":phases[0]["choice"]["experiment"],"choice_after_restart":phases[1]["choice"]["experiment"],"neutral_history_choice_after_restart":phases[1]["neutral_history_choice"]["experiment"],
        "retained_models":phases[2]["active_models"],"replay_oracle_calls":phases[2]["oracle_calls"],
        "reserved_cost":reserved_cost,"declared_task_units":declared_task_units,"measured_local_oracle_calls":oracle_calls,"no_unsanctioned_endpoint":true,
        "information_rank_basis":"declared initial-family estimate from exact initial affine hypothesis count; one binary observation has worst-case half-space elimination; not an optimal live information-gain claim; source usefulness uses durable observed outcomes",
        "matched_budget_control":"isolated exact learners receive the same observation budget and also cover all held-out inputs; no transfer efficiency advantage claimed",
        "scope":"fixed two-world native engineering control; does not establish general experiment optimality, new statistical samples or independent multi-host operation",
        "phase_reports":phases});
    write_new(receipts, &report)?;
    Ok(report)
}
