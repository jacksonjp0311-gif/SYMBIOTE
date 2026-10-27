//! Target fact retention is evaluated separately from policy generalization.
//! One trusted controller supplies scoped oracle envelopes, not remote signatures.
use super::*;
use symbiote_memory::knowledge::{
    graph::{
        assess_graph, encode_query, forecast_work_units, graph_receipt_digest,
        graph_schema_fingerprint, GraphAcquisition, GraphMap, GraphObservation, GraphTrainingTask,
        GraphTrialEvidence,
    },
    KnowledgeRecord, KnowledgeStore, TrialCase, TrialCosts,
};
use symbiote_reasoning::query_strategy::{oracle_optimum, TrialResult};

#[derive(Clone, Debug, Serialize)]
pub(super) struct Retained {
    pub record_id: String,
    pub record_sha256: String,
    pub context: String,
    pub main_input: u16,
    pub main_cost: u8,
    pub cases: Vec<TrialCase>,
}
pub(super) struct Result {
    pub metadata: Value,
    pub retained: Retained,
    pub truth_queries: u64,
    pub work: u64,
}
pub(super) fn retain(
    knowledge: &mut KnowledgeStore,
    actor: &str,
    authority: &str,
    task: &GraphTask,
    trial: &TrialResult,
    price: u64,
) -> std::result::Result<Result, String> {
    if !trial.certified_correctly()
        || trial.context != task.context
        || trial.observations.is_empty()
        || trial.queried_edges
            != trial
                .observations
                .iter()
                .map(|o| o.edge)
                .collect::<Vec<_>>()
        || trial
            .observations
            .iter()
            .any(|o| task.costs.get(o.edge) != Some(&o.cost))
    {
        return Err(
            "fact retention requires nonempty, correctly certified actual target observations"
                .into(),
        );
    }
    let work_before = forecast_work_units()?;
    let map = GraphMap::new(
        task.schema.clone(),
        trial
            .observations
            .iter()
            .map(|o| GraphObservation {
                edge_id: o.edge,
                cost: o.cost,
            })
            .collect(),
    )?;
    let main_input = encode_query(task.schema.nodes, task.start, task.goal)?;
    let main = map
        .forecast(main_input)?
        .ok_or("retained target route is not certified")?;
    if Some(main.cost) != trial.certified_cost || main.nodes.len() < 4 {
        return Err("retained main witness changed or lacks two disjoint subroutes".into());
    }
    let main_cost =
        u8::try_from(main.cost).map_err(|_| "retained route exceeds declared cost domain")?;
    if !(1..=63).contains(&main_cost) {
        return Err("retained route cost outside 1..63".into());
    }
    let fingerprint = graph_schema_fingerprint(&task.schema)?;
    let task_sha = digest(task)?;
    let record = KnowledgeRecord {id:format!("retained-{task_sha}"),revision:1,source:actor.into(),
        scope:task.context.clone(),schema_fingerprint:fingerprint.clone(),payload:map.to_payload()?,
        provenance:"Observed target edges retained after separate Bellman-Ford subroute validation by the trusted same-controller oracle. Envelopes bind local scope/observer; hashes do not authenticate an external agent. This is fact retention, not policy-promotion evidence.".into()};
    let empty = GraphMap::new(task.schema.clone(), vec![])?;
    let mut cases = Vec::new();
    let mut evaluator_work = 0u64;
    let last = main.nodes.len() - 1;
    for (i, (start, goal)) in [
        (main.nodes[0], main.nodes[1]),
        (main.nodes[last - 1], main.nodes[last]),
    ]
    .into_iter()
    .enumerate()
    {
        let input = encode_query(task.schema.nodes, start, goal)?;
        if input == main_input {
            return Err("retention evaluation overlaps acquisition route".into());
        }
        let subtask = GraphTask {
            context: format!("{}-sub-{i}", task.context),
            schema: task.schema.clone(),
            start,
            goal,
            costs: task.costs.clone(),
        };
        let (expected, work) = oracle_optimum(&subtask)?;
        evaluator_work += work as u64;
        let expected = expected
            .and_then(|n| u8::try_from(n).ok())
            .filter(|n| (1..=63).contains(n))
            .ok_or("retention evaluator route outside declared finite cost domain")?;
        let baseline = empty.predict(input)?;
        let candidate = map
            .predict(input)?
            .ok_or("queried facts do not certify held-out subroute")?;
        if candidate != expected || baseline.is_some() {
            return Err("retained facts failed new-coverage evaluation".into());
        }
        cases.push(TrialCase {
            id: format!("subroute-{i}"),
            input,
            expected,
            baseline,
            candidate,
        });
    }
    let acquisitions = trial
        .observations
        .iter()
        .enumerate()
        .map(|(sequence, o)| {
            let id = digest(&(
                authority,
                actor,
                &task.context,
                &fingerprint,
                sequence,
                o.edge,
                o.cost,
            ))?;
            let receipt = json!({"schema":"symbiote.graph-observation/1","authority_id":authority,
            "context":task.context,"schema_fingerprint":fingerprint,"observer_identity":actor,
            "sequence":sequence,"id":id,"edge_id":o.edge,"cost":o.cost});
            Ok(GraphAcquisition {
                id,
                edge_id: o.edge,
                cost: o.cost,
                receipt_sha256: graph_receipt_digest(&receipt)?,
                receipt,
            })
        })
        .collect::<std::result::Result<Vec<_>, String>>()?;
    let truth_queries = 2 * task.schema.edges.len() as u64;
    let acquisition = trial.queried_edges.len() as u64 * price;
    let pre_admission_work = forecast_work_units()?
        .checked_sub(work_before)
        .ok_or("forecast meter regressed")?
        + evaluator_work;
    let verification = truth_queries * price + pre_admission_work;
    let evidence = GraphTrialEvidence {
        evaluator: authority.into(),
        acquisitions,
        training_tasks: vec![GraphTrainingTask {
            id: "main-acquisition-route".into(),
            input: main_input,
        }],
        cases: cases.clone(),
        costs: TrialCosts {
            acquisition,
            verification,
            adoption: 1,
            baseline: 0,
            candidate: acquisition + verification + 1,
        },
    };
    let before = knowledge.history_anchor();
    let assessment = assess_graph(&record, &evidence)?;
    let record_sha256 = record.digest()?;
    knowledge.promote_graph(record.clone(), assessment.clone())?;
    let after = knowledge.history_anchor();
    let commit = knowledge.promotion_between(
        &record,
        &serde_json::to_value(&evidence).map_err(|e| e.to_string())?,
        &before,
        &after,
    )?;
    let work = forecast_work_units()?
        .checked_sub(work_before)
        .ok_or("forecast meter regressed")?
        + evaluator_work;
    let retained = Retained {
        record_id: record.id.clone(),
        record_sha256,
        context: task.context.clone(),
        main_input,
        main_cost,
        cases,
    };
    Ok(Result {
        metadata: json!({"retained":retained,"assessment":assessment,"knowledge_before":before,
        "knowledge_after":after,"promotion_receipt_sha256":commit,"authority_queries":truth_queries,
        "actual_forecast_and_evaluator_work":work,"acquisition_cost_already_charged_in_target_bill":true,
        "evidence_cost_scope":"acquisition and pre-admission validation; full Bill additionally charges admission/commit/replay work",
        "scope":"two endpoint-disjoint subroute evaluations; not independent target samples"}),
        retained,
        truth_queries,
        work,
    })
}
pub(super) fn replay(
    knowledge: &KnowledgeStore,
    expected: &[Retained],
) -> std::result::Result<Value, String> {
    let active = knowledge.active();
    if active.len() != expected.len() {
        return Err("retained graph count changed after restart".into());
    }
    let mut predictions = Vec::new();
    for item in expected {
        let record = active
            .iter()
            .find(|r| r.id == item.record_id)
            .ok_or("retained graph missing after restart")?;
        if record.digest()? != item.record_sha256
            || record.scope != item.context
            || record.predict_if_certified(item.main_input)? != Some(item.main_cost)
        {
            return Err("retained graph digest or main prediction changed".into());
        }
        for case in &item.cases {
            let prediction = record.predict_if_certified(case.input)?;
            if prediction != Some(case.expected) {
                return Err("restarted graph failed nonempty retained prediction".into());
            }
            predictions.push(json!({"record_sha256":item.record_sha256,"context":item.context,"input":case.input,"expected":case.expected,"prediction":prediction}));
        }
    }
    Ok(
        json!({"models":active.len(),"subroute_predictions":predictions,"new_authority_calls":0,
        "nonempty":!expected.is_empty(),"knowledge_anchor":knowledge.history_anchor()}),
    )
}
