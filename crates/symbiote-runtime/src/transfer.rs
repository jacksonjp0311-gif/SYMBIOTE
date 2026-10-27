//! Frozen-registration, same-controller portable query-policy experiment.
//! No external discovery, remote execution, process-isolation or universal
//! transfer claim. The independent full-truth evaluator never selects queries.
mod engine;
mod fixtures;
mod retention;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use symbiote_reasoning::query_strategy::{
    derive_policy, run_trial, GraphTask, SourceTrace, TrialLimits,
};

pub const PROTOCOL: &str = "SYMBIOTE-QUERY-TRANSFER-001";
const ARMS: [&str; 6] = [
    "isolated-prior",
    "fresh-default",
    "fixed-start",
    "fixed-goal",
    "local-trained",
    "exchanged",
];
const TRIAL: TrialLimits = TrialLimits {
    max_queries: 24,
    model_work: 10_000,
    policy_work: 10_000,
};
const MAX_ACTOR_COST: u64 = 10_000_000;
const MAX_SECONDS: u64 = 60;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cohort {
    seeds: Vec<u64>,
    prices: Vec<u64>,
    target_layers: Vec<usize>,
    arms: Vec<String>,
    actors_per_pair: usize,
}
impl Cohort {
    fn fixed() -> Self {
        Self {
            seeds: vec![7, 19, 43, 101],
            prices: vec![1, 100],
            target_layers: vec![4, 5],
            arms: ARMS.iter().map(|s| (*s).into()).collect(),
            actors_per_pair: 2,
        }
    }
}
pub fn protocol() -> Value {
    json!({"id":PROTOCOL,"family":"finite-positive-cost-directed-graph/v1",
        "policy":"rank unknown edges only on exact optimistic route by public endpoint role",
        "source_score":"sum(cost-lower)/sum(upper-lower); exact integer cross products",
        "minimum_distinct_source_contexts":2,"ties":["from-start","interior","to-goal","direct"],
        "missing_roles":"original optimistic-route edge order after trained roles",
        "source_graph_layers":2,"calibration_graph_layers":3,"target_graph_layers":[4,5],
        "public_bounds":"first edge of alternate path lower=2; all other lowers=1; every upper=9; first path uniquely optimistic before permutation",
        "source_contexts_per_actor":2,"calibration_contexts_per_stage":2,
        "target_topology":"two longer directed paths; second variant adds a high-cost cross edge",
        "private_truth_recipe":"penalty 4+seed%6 on first-path start or goal; peer source roles complementary; receiver target role opposite its own source",
        "permutations":"explicit verified complete node and edge bijections, deterministic controller seed; learner receives no role-family label or seed",
        "limits":{"seconds":MAX_SECONDS,"max_actor_cost":MAX_ACTOR_COST,"trial":TRIAL},
        "costs":"all actual source observations including unused offers; each calibration default/candidate/incumbent evaluator full truth pass; target full truth and2subroute truth passes; reasoning/policy/verification/replay work plus canonical refinement scans; both send+receive KiB units; adoption; diagnostics",
        "controls":ARMS,"strong_control":"best measured fixed start/goal per participant is a labelled hindsight bound",
        "positive_utility":"both participants strictly reduce full cost without coverage/error loss against fresh/local-trained/best-fixed on every normal-price seed",
        "source_calibration_target_contexts_disjoint":true,"targets_used_for_policy_promotion":false,
        "target_observations_used_for_graph_fact_retention":true,
        "retention":"all arms persist actual queried edges as bounded GraphMaps; two endpoint-disjoint subroute queries distinct from main acquisition route are independently evaluated before promotion; actual owner/knowledge restart yields nonempty predictions with zero new oracle calls",
        "retention_domain":"2..12 nodes, at most56 edges, edge costs1..9, encoded route cost1..63; larger outputs explicitly unsupported",
        "canonical_metadata":"endpoint-aware exact weighted graph witness after unique colour refinement; ambiguous graphs abstain, not conflated; no significance or independent-world claim",
        "sampling":"16 labelled target tasks reused over6arms and2prices,192 target evaluations; seeds7/19/43 share penalty5,101 penalty9; report exact structural collision groups",
        "negative_controls":"unsupported declared grammar, actual observed interval drift, query-count regression with durable revocation if harmful",
        "scope":"single trusted controller; no external-agent, statistical-population or physical-certificate claim"})
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn digest<T: Serialize>(v: &T) -> Result<String, String> {
    let v = serde_json::to_value(v).map_err(|_| "cannot encode transfer value")?;
    Ok(sha(
        &serde_json::to_vec(&v).map_err(|_| "cannot encode canonical transfer JSON")?
    ))
}
fn valid_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn stamp() -> Result<String, String> {
    let s = option_env!("SYMBIOTE_SOURCE_COMMIT").unwrap_or("unknown");
    if s.len() != 40
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(
            "transfer registration requires a reviewed full-source-commit-stamped build".into(),
        );
    }
    Ok(s.into())
}
fn native_sha256() -> Result<String, String> {
    let path = std::env::current_exe().map_err(|_| "native executable unavailable")?;
    let size = fs::metadata(&path)
        .map_err(|_| "native executable metadata unavailable")?
        .len();
    if size == 0 || size > 128 * 1024 * 1024 {
        return Err("native executable exceeds registration byte bound".into());
    }
    let mut file = fs::File::open(path).map_err(|_| "native executable unavailable")?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65536];
    let mut total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| "cannot hash native executable")?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > 128 * 1024 * 1024 {
            return Err("native executable changed beyond byte bound".into());
        }
        digest.update(&buffer[..read]);
    }
    if total != size {
        return Err("native executable changed during registration".into());
    }
    Ok(format!("{:x}", digest.finalize()))
}
fn protocol_document_sha256() -> String {
    sha(include_bytes!("../../../docs/QUERY_TRANSFER_PROTOCOL.md"))
}
fn absolute(path: &Path) -> Result<PathBuf, String> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| "working directory unavailable")?
            .join(path)
    };
    let mut tail = Vec::new();
    let mut cursor = joined.as_path();
    while !cursor.exists() {
        tail.push(
            cursor
                .file_name()
                .ok_or("state must name a new directory")?
                .to_os_string(),
        );
        cursor = cursor.parent().ok_or("state ancestor unavailable")?;
    }
    let mut result = fs::canonicalize(cursor).map_err(|_| "state ancestor cannot be resolved")?;
    for part in tail.into_iter().rev() {
        if part == ".." || part == "." {
            return Err("unresolved path traversal is not permitted".into());
        }
        result.push(part);
    }
    Ok(result)
}
fn write_new(path: &Path, value: &impl Serialize) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| format!("receipt parent: {e}"))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("new receipt required: {e}"))?;
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|_| "cannot encode transfer receipt")?;
    bytes.push(b'\n');
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("receipt commit: {e}"))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    schema: String,
    source_commit: String,
    native_sha256: String,
    protocol_document_sha256: String,
    state_directory: PathBuf,
    protocol: Value,
    protocol_sha256: String,
    cohort: Cohort,
    cohort_sha256: String,
}
pub fn register(state: &Path, receipt: &Path) -> Result<Value, String> {
    let state = absolute(state)?;
    let receipt_absolute = absolute(receipt)?;
    if receipt_absolute.starts_with(&state) || state.starts_with(&receipt_absolute) {
        return Err("registration receipt must be outside the future actor-state root".into());
    }
    let source_commit = stamp()?;
    if fs::symlink_metadata(&state).is_ok() {
        return Err("registration requires an absent actor-state root".into());
    }
    let protocol = protocol();
    let cohort = Cohort::fixed();
    let registration = Registration {
        schema: "symbiote.query-transfer-registration/1".into(),
        source_commit,
        native_sha256: native_sha256()?,
        protocol_document_sha256: protocol_document_sha256(),
        state_directory: state,
        protocol_sha256: digest(&protocol)?,
        protocol,
        cohort_sha256: digest(&cohort)?,
        cohort,
    };
    write_new(receipt, &registration)?;
    let raw = fs::read(receipt).map_err(|_| "cannot read committed registration")?;
    Ok(
        json!({"schema":"symbiote.query-transfer-registration-receipt/1","status":"REGISTERED_NOT_RUN",
        "registration":receipt,"registration_sha256":sha(&raw),"source_commit":registration.source_commit,
        "state":registration.state_directory,"protocol_sha256":registration.protocol_sha256,
        "cohort_sha256":registration.cohort_sha256,"target_truth_opened":false,"state_created":false}),
    )
}
pub fn run_registered(
    state: &Path,
    registration: &Path,
    registration_sha: &str,
    receipts: &Path,
) -> Result<Value, String> {
    if !valid_sha(registration_sha) {
        return Err("independently retained lowercase registration SHA256 required".into());
    }
    let meta = fs::symlink_metadata(registration).map_err(|_| "registration unavailable")?;
    if !meta.is_file() || meta.len() > 65_536 {
        return Err("bounded regular registration required".into());
    }
    let mut raw = Vec::new();
    fs::File::open(registration)
        .map_err(|_| "cannot open registration")?
        .take(65_537)
        .read_to_end(&mut raw)
        .map_err(|_| "cannot read registration")?;
    if raw.len() > 65_536 || sha(&raw) != registration_sha {
        return Err("registration differs from external SHA256 pin".into());
    }
    let registration: Registration =
        serde_json::from_slice(&raw).map_err(|_| "registration schema rejected")?;
    let state = absolute(state)?;
    let receipt_absolute = absolute(receipts)?;
    if receipt_absolute.starts_with(&state) || state.starts_with(&receipt_absolute) {
        return Err("final receipt must be outside the registered actor-state root".into());
    }
    let specification = protocol();
    if registration.schema != "symbiote.query-transfer-registration/1"
        || registration.source_commit != stamp()?
        || registration.native_sha256 != native_sha256()?
        || registration.protocol_document_sha256 != protocol_document_sha256()
        || registration.protocol != specification
        || registration.protocol_sha256 != digest(&specification)?
        || registration.cohort != Cohort::fixed()
        || registration.cohort_sha256 != digest(&Cohort::fixed())?
        || registration.state_directory != state
    {
        return Err("source/protocol/cohort/state differs from frozen registration".into());
    }
    if fs::symlink_metadata(&state).is_ok() || fs::symlink_metadata(receipts).is_ok() {
        return Err("fresh state/output required; never retry a started transfer run".into());
    }
    fs::create_dir_all(&state).map_err(|_| "cannot create registered actor root")?;
    write_new(
        &state.join("transfer-started.json"),
        &json!({"registration_sha256":registration_sha,"protocol":PROTOCOL,"source_commit":registration.source_commit}),
    )?;
    let coordinator = symbiote_memory::Store::open(&state)?;
    let started = Instant::now();
    let deadline = started + Duration::from_secs(MAX_SECONDS);
    let mut rows = Vec::new();
    let mut error = engine::execute(
        &state,
        &registration.cohort,
        coordinator.identity(),
        deadline,
        &mut rows,
    )
    .err();
    let comparisons = if error.is_none() {
        match engine::comparisons(&rows) {
            Ok(v) => v,
            Err(e) => {
                error = Some(e);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let normal = comparisons
        .iter()
        .filter(|r| r["oracle_price"] == 100)
        .collect::<Vec<_>>();
    let strong = normal.len() == 4 && normal.iter().all(|r| r["strong_bilateral_utility"] == true);
    if started.elapsed() > Duration::from_secs(MAX_SECONDS) && error.is_none() {
        error = Some("final transfer deadline exceeded".into());
    }
    let report = json!({"schema":"symbiote.query-transfer/1","protocol":PROTOCOL,"source_commit":registration.source_commit,
        "registration_sha256":registration_sha,"cohort_sha256":registration.cohort_sha256,"controller_identity":coordinator.identity(),
        "status":if error.is_none(){"PASS"}else{"HOLD"},"first_failure":error,"elapsed_ms":started.elapsed().as_millis(),
        "completed_cells":rows.len(),"expected_cells":48,"cells":rows,"comparisons":comparisons,
        "reciprocal_efficiency":if error.is_some(){"NOT_EVALUABLE_INCOMPLETE"}else if strong{"DEMONSTRATED_ONLY_IN_THIS_CONTROLLED_COHORT"}else{"NOT_DEMONSTRATED"},
        "cost_regimes_separate":true,"targets_used_for_policy_promotion":false,
        "target_observations_used_for_graph_fact_retention":true,"exact_support_unchanged":true,
        "target_inventory":engine::inventory(&rows)?,
        "limitations":["one trusted controller process","fixed fixtures are not a statistical population",
            "declared logical costs are not measured hardware speed","best-fixed per-participant hindsight is an optimistic bound",
            "a received ranking can be harmful on another cost pattern","no generalized intelligence or autonomous self-improvement claim"]});
    write_new(receipts, &report)?;
    if let Some(e) = error {
        return Err(format!("transfer HOLD, evidence preserved: {e}"));
    }
    Ok(report)
}
