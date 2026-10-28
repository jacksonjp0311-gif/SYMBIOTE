//! Standalone driver for the same bounded observation backend as configured run.
//! This owned synthetic source requires no network, credentials or language model.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use symbiote_memory::knowledge::{
    affine_schema_fingerprint, assess, KnowledgeRecord, KnowledgeStore, TrialCosts, TrialEvidence,
};
use symbiote_memory::Store;
use symbiote_reasoning::structural::CompactAffineLearner;
use symbiote_runtime::service::observation::{
    infer_from_source, Observation, ObservationPermit, ObservationSource, Usage,
};

const SCOPE: &str = "standalone-observation/affine-v1";
const ARTIFACT: &str = "standalone-active-affine";
const SOURCE: &str = "owned-synthetic-affine/3-bit-xor5-bias1/v1";

struct Source {
    queries: usize,
}
impl ObservationSource for Source {
    fn width(&self) -> u8 {
        3
    }
    fn observe(
        &mut self,
        input: u16,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> Result<Observation, String> {
        if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err("owned observation source cancelled/timed out".into());
        }
        if input >= 8 {
            return Err("owned source input outside its finite domain".into());
        }
        let item = Observation {
            sequence: self.queries,
            input,
            output: (((input & 5).count_ones() as u8) & 1) ^ 1,
        };
        self.queries += 1;
        Ok(item)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Audit {
    schema: String,
    source_sha256: String,
    owner: String,
    training: usize,
    observations: Vec<Observation>,
    snapshot: Value,
}
fn source_sha() -> String {
    format!("{:x}", Sha256::digest(SOURCE.as_bytes()))
}

pub fn run(state: &Path, receipts: &Path) -> Result<Value, String> {
    let identity_owner = Store::open(state)?;
    let identity = identity_owner.identity().to_string();
    let mut knowledge = KnowledgeStore::open(state, &identity)?;
    let before = knowledge.history_anchor();
    let existing = knowledge
        .active()
        .into_iter()
        .find(|record| record.id == ARTIFACT);
    let (record, queries, work, snapshot, phases, promoted) = if let Some(record) = existing {
        let audit: Audit = serde_json::from_str(&record.provenance)
            .map_err(|_| "retained observation audit rejected")?;
        if audit.schema != "symbiote.standalone-observation-audit/1"
            || audit.source_sha256 != source_sha()
            || audit.owner != identity
            || audit.training != 4
            || audit.observations.len() != 5
            || record.source != identity
            || record.scope != SCOPE
            || record.schema_fingerprint != affine_schema_fingerprint(3)?
        {
            return Err(
                "retained model differs from its original owned source or audit; state preserved"
                    .into(),
            );
        }
        let mut replay = CompactAffineLearner::new(3, 100_000)?;
        for (sequence, item) in audit.observations.iter().enumerate() {
            if item.sequence != sequence || item.input >= 8 || item.output > 1 {
                return Err("retained source audit has invalid observations".into());
            }
            if sequence < audit.training {
                replay.observe(item.input, item.output)?;
            } else if record.predict(item.input)? != item.output {
                return Err("retained held-out evidence contradicts its model".into());
            }
        }
        let model = replay
            .identified()
            .ok_or("retained observations do not identify one model")?;
        if record.payload != serde_json::to_value(model).map_err(|e| e.to_string())? {
            return Err("retained model is not implied by its observation audit".into());
        }
        let snapshot = serde_json::to_value(replay.snapshot()).map_err(|e| e.to_string())?;
        let work = replay.snapshot().work_units;
        (
            record,
            0,
            work,
            snapshot,
            vec![
                json!({"phase":"REUSE","source_queries":0,"basis":"retained independently assessed observations and model; replay work is counted"}),
            ],
            false,
        )
    } else {
        if knowledge.highest_revision(ARTIFACT).is_some() {
            return Err(
                "owned observation model was revoked; explicit source review is required".into(),
            );
        }
        let permit = ObservationPermit {
            schema: "symbiote.observation-permit/1".into(),
            scopes: vec![SCOPE.into()],
            max_queries_total: 16,
            max_gf2_work_total: 100_000,
            heldout_cases: 1,
        };
        let mut source = Source { queries: 0 };
        let mut usage = Usage::default();
        let mut phases = Vec::new();
        let inference = infer_from_source(
            &mut source,
            &permit,
            &mut usage,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(2),
            |phase, details| {
                phases.push(json!({"phase":phase,"details":details}));
                Ok(())
            },
        )?;
        let audit = Audit {
            schema: "symbiote.standalone-observation-audit/1".into(),
            source_sha256: source_sha(),
            owner: identity.clone(),
            training: inference.training,
            observations: inference.queries.clone(),
            snapshot: inference.snapshot.clone(),
        };
        let record = KnowledgeRecord {
            id: ARTIFACT.into(),
            revision: 1,
            source: identity.clone(),
            scope: SCOPE.into(),
            schema_fingerprint: affine_schema_fingerprint(3)?,
            payload: serde_json::to_value(&inference.model).map_err(|e| e.to_string())?,
            provenance: serde_json::to_string(&audit).map_err(|e| e.to_string())?,
        };
        let acquisition = usage.gf2_work as u64 + inference.training as u64;
        let verification = inference.cases.len() as u64;
        let evidence = TrialEvidence {
            evaluator: "owned-demo-observation-validator/v1".into(),
            training_case_ids: inference
                .queries
                .iter()
                .take(inference.training)
                .map(|item| format!("observation-{}", item.sequence))
                .collect(),
            training_inputs: inference
                .queries
                .iter()
                .take(inference.training)
                .map(|item| item.input)
                .collect(),
            cases: inference.cases,
            costs: TrialCosts {
                acquisition,
                verification,
                adoption: 1,
                baseline: 0,
                candidate: acquisition + verification + 1,
            },
        };
        knowledge.promote(record.clone(), assess(&record, &evidence)?)?;
        (
            record,
            source.queries,
            usage.gf2_work,
            inference.snapshot,
            phases,
            true,
        )
    };
    let predictions: Vec<_> = (0..8)
        .map(|input| Ok(json!({"input":input,"prediction":record.predict(input)?})))
        .collect::<Result<_, String>>()?;
    let report = json!({"schema":"symbiote.observation-demo/1","version":env!("CARGO_PKG_VERSION"),"status":"PASS","identity":identity,
        "source":"explicitly owned deterministic three-bit affine observation source","source_sha256":source_sha(),"network_requests":0,"language_model":false,
        "fresh_promotions":usize::from(promoted),"source_queries":queries,"gf2_work_units":work,"snapshot":snapshot,"phases":phases,
        "before":before,"after":knowledge.history_anchor(),"artifact":record.id,"record_sha256":record.digest()?,"predictions":predictions,
        "baseline":{"kind":"unknown","reason":"no isolated total-cost comparison was measured; legacy trial cost container is not an economic baseline"},
        "interpretation":"exact conditional capability from actual observations; no general intelligence or economic gain is claimed"});
    super::receipt_file(receipts, &report)?;
    Ok(report)
}
