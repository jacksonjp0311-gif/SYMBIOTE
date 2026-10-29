//! Active, explicitly permitted observation, separate from imported artifacts.
//! The local fixture adapter is a bounded test oracle. An embedding may supply
//! another authorized adapter; returned observations remain scoped evidence.
//! Models and predictions are conditional on the declared finite affine family.
use super::{digest, Config};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use symbiote_memory::knowledge::{
    affine_schema_fingerprint, assess, KnowledgeRecord, KnowledgeStore, TrialCase, TrialCosts,
    TrialEvidence,
};
use symbiote_reasoning::structural::{AffineQueryPolicy, AffineStrategy, CompactAffineLearner};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationPermit {
    pub schema: String,
    pub scopes: Vec<String>,
    pub max_queries_total: usize,
    pub max_gf2_work_total: usize,
    pub heldout_cases: usize,
}
impl ObservationPermit {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != "symbiote.observation-permit/1"
            || self.scopes.is_empty()
            || self.scopes.len() > 8
            || self.scopes.iter().collect::<BTreeSet<_>>().len() != self.scopes.len()
            || self.scopes.iter().any(|scope| !super::label(scope))
            || !(1..=256).contains(&self.max_queries_total)
            || !(1..=1_000_000).contains(&self.max_gf2_work_total)
            || !(1..=4).contains(&self.heldout_cases)
        {
            return Err("invalid bounded observation permit".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub sequence: usize,
    pub input: u16,
    pub output: u8,
}
/// Implementations must honor the absolute deadline and cancellation token.
/// This interface grants neither a connection nor permission to inspect a peer.
pub trait ObservationSource {
    fn width(&self) -> u8;
    fn observe(
        &mut self,
        input: u16,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> Result<Observation, String>;
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Family {
    Affine { width: u8, outputs: Vec<u8> },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema: String,
    scope: String,
    family: Family,
}
struct LocalOracle {
    width: u8,
    outputs: Vec<u8>,
    queries: usize,
}
impl ObservationSource for LocalOracle {
    fn width(&self) -> u8 {
        self.width
    }
    fn observe(
        &mut self,
        input: u16,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> Result<Observation, String> {
        check(cancelled, deadline)?;
        let output = *self
            .outputs
            .get(usize::from(input))
            .ok_or("observation input outside declared finite domain")?;
        let value = Observation {
            sequence: self.queries,
            input,
            output,
        };
        self.queries += 1;
        Ok(value)
    }
}
fn check(cancelled: &AtomicBool, deadline: Instant) -> Result<(), String> {
    if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
        return Err("cancelled:local-observation".into());
    }
    Ok(())
}
fn load(config: &Config, scope: &str) -> Result<(LocalOracle, String), String> {
    let _io_timer = super::timing::Timer::start(super::timing::Stage::Io);
    let context = config.context(scope)?;
    let fixture: Fixture = serde_json::from_slice(&config.fixture(context)?)
        .map_err(|_| "local observation fixture schema rejected")?;
    let Family::Affine { width, outputs } = fixture.family;
    if fixture.schema != "symbiote.local-truth/3"
        || fixture.scope != scope
        || !(1..=8).contains(&width)
        || outputs.len() != (1_usize << width)
        || outputs.iter().any(|output| *output > 1)
        || context.schema_fingerprint != affine_schema_fingerprint(width)?
    {
        return Err("observation source must match the pinned finite affine context".into());
    }
    Ok((
        LocalOracle {
            width,
            outputs,
            queries: 0,
        },
        context
            .truth_sha256
            .clone()
            .ok_or("observation source lacks operator pin")?,
    ))
}
pub(super) fn validate_context(config: &Config, scope: &str) -> Result<(), String> {
    load(config, scope).map(|_| ())
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Usage {
    pub queries: usize,
    pub gf2_work: usize,
}
#[derive(Clone, Debug, Serialize)]
pub struct Inference {
    pub model: AffineStrategy,
    pub queries: Vec<Observation>,
    pub training: usize,
    pub snapshot: Value,
    pub cases: Vec<TrialCase>,
}

/// Run the same bounded active backend used by configured local observation.
/// The host supplies an already authorized, cooperative source. The result is
/// inert conditional knowledge and an audit; this function never promotes it,
/// attaches to another agent, grants access or executes a received instruction.
pub fn infer_from_source<S: ObservationSource>(
    source: &mut S,
    permit: &ObservationPermit,
    usage: &mut Usage,
    cancelled: &AtomicBool,
    deadline: Instant,
    emit: impl FnMut(&str, Value) -> Result<(), String>,
) -> Result<Inference, String> {
    infer_with_policy(
        source,
        permit,
        usage,
        cancelled,
        deadline,
        AffineQueryPolicy::Reference,
        emit,
    )
}

/// Additive policy selection; callers must retain the selected policy name with
/// their audit. Reference callers keep their existing query and receipt shapes.
#[allow(clippy::too_many_arguments)]
pub fn infer_with_policy<S: ObservationSource>(
    source: &mut S,
    permit: &ObservationPermit,
    usage: &mut Usage,
    cancelled: &AtomicBool,
    deadline: Instant,
    query_policy: AffineQueryPolicy,
    mut emit: impl FnMut(&str, Value) -> Result<(), String>,
) -> Result<Inference, String> {
    permit.validate()?;
    if !(1..=8).contains(&source.width())
        || usage.queries > permit.max_queries_total
        || usage.gf2_work >= permit.max_gf2_work_total
    {
        return Err(
            "observation adapter width or remaining query/work allowance is invalid".into(),
        );
    }
    infer_policy(
        source,
        permit,
        usage,
        cancelled,
        deadline,
        query_policy,
        &mut emit,
    )
}

/// Active query selection cannot use fixture contents, an imported model or a
/// received hint. The caller chooses this compact backend explicitly.
#[cfg(test)]
fn infer<S: ObservationSource>(
    source: &mut S,
    permit: &ObservationPermit,
    usage: &mut Usage,
    cancelled: &AtomicBool,
    deadline: Instant,
    emit: &mut impl FnMut(&str, Value) -> Result<(), String>,
) -> Result<Inference, String> {
    infer_policy(
        source,
        permit,
        usage,
        cancelled,
        deadline,
        AffineQueryPolicy::Reference,
        emit,
    )
}

#[allow(clippy::too_many_arguments)]
fn infer_policy<S: ObservationSource>(
    source: &mut S,
    permit: &ObservationPermit,
    usage: &mut Usage,
    cancelled: &AtomicBool,
    deadline: Instant,
    query_policy: AffineQueryPolicy,
    emit: &mut impl FnMut(&str, Value) -> Result<(), String>,
) -> Result<Inference, String> {
    let remaining = permit
        .max_gf2_work_total
        .checked_sub(usage.gf2_work)
        .ok_or("budget:observation-gf2")?;
    let width = source.width();
    let mut learner = CompactAffineLearner::new(width, remaining)?;
    let mut queries = Vec::new();
    let result = (|| {
        while learner.identified().is_none() {
            check(cancelled, deadline)?;
            let input = {
                let _timer = super::timing::Timer::start(super::timing::Stage::Compute);
                learner
                    .choose_query_with_policy(query_policy)?
                    .ok_or("exact affine inference has no admissible query")?
            };
            let before = learner.snapshot();
            if usage.queries >= permit.max_queries_total {
                return Err("budget:local-observation-queries".into());
            }
            // Charge the admitted source invocation even if the adapter fails
            // after performing work. Retrying cannot reclaim a spent allowance.
            usage.queries += 1;
            let observation = source.observe(input, cancelled, deadline)?;
            check(cancelled, deadline)?;
            if observation.sequence != queries.len()
                || observation.input != input
                || observation.output > 1
            {
                return Err("observation source returned an invalid query binding".into());
            }
            queries.push(observation.clone());
            emit(
                "OBSERVE",
                json!({"schema":"symbiote.active-observation/1","stage":"training","observation":observation,"reason":"exact balanced support split","before":before}),
            )?;
            {
                let _timer = super::timing::Timer::start(super::timing::Stage::Compute);
                learner.observe(input, observation.output)?;
            }
            emit(
                "MODEL",
                json!({"schema":"symbiote.active-inference/1","snapshot":learner.snapshot(),"received_hint_used":false}),
            )?;
        }
        let model = learner
            .identified()
            .ok_or("affine model remains uncertain")?;
        let training = queries.len();
        let mut cases = Vec::new();
        for input in 0..(1_u16 << width) {
            if queries[..training]
                .iter()
                .any(|observation| observation.input == input)
            {
                continue;
            }
            if cases.len() >= permit.heldout_cases {
                break;
            }
            check(cancelled, deadline)?;
            let prediction = {
                let _timer = super::timing::Timer::start(super::timing::Stage::Compute);
                learner
                    .forecast(input)?
                    .answer
                    .ok_or("inferred model abstained on held-out input")?
            };
            if usage.queries >= permit.max_queries_total {
                return Err("budget:local-observation-heldout".into());
            }
            usage.queries += 1;
            let observation = source.observe(input, cancelled, deadline)?;
            check(cancelled, deadline)?;
            if observation.sequence != queries.len()
                || observation.input != input
                || observation.output > 1
            {
                return Err("held-out observation binding rejected".into());
            }
            queries.push(observation.clone());
            emit(
                "VERIFY",
                json!({"schema":"symbiote.active-observation/1","stage":"heldout","observation":observation,"conditional_prediction":prediction,"physical_certificate_authorized":false}),
            )?;
            if observation.output != prediction {
                return Err("observations contradict the declared stationary affine family; no model promoted".into());
            }
            cases.push(TrialCase {
                id: format!("heldout-{input}"),
                input,
                expected: observation.output,
                baseline: None,
                candidate: prediction,
            });
        }
        if cases.len() != permit.heldout_cases {
            return Err(
                "observation domain lacks enough distinct held-out inputs; no model promoted"
                    .into(),
            );
        }
        check(cancelled, deadline)?;
        Ok(Inference {
            model,
            queries,
            training,
            snapshot: serde_json::to_value(learner.snapshot()).map_err(|e| e.to_string())?,
            cases,
        })
    })();
    usage.gf2_work = usage
        .gf2_work
        .checked_add(learner.snapshot().work_units)
        .ok_or("observation GF2 usage overflow")?;
    result
}

pub(super) struct Control<'a> {
    pub permit: &'a ObservationPermit,
    pub cancelled: &'a AtomicBool,
    pub deadline: Instant,
}
pub(super) fn learn(
    config: &Config,
    knowledge: &mut KnowledgeStore,
    scope: &str,
    usage: &mut Usage,
    control: Control<'_>,
    mut emit: impl FnMut(&str, Value) -> Result<(), String>,
) -> Result<Value, String> {
    let Control {
        permit,
        cancelled,
        deadline,
    } = control;
    permit.validate()?;
    if !permit.scopes.iter().any(|allowed| allowed == scope) {
        return Err("local observation scope is outside the explicit permit".into());
    }
    check(cancelled, deadline)?;
    let (mut source, pin) = load(config, scope)?;
    let id = format!(
        "observed-{}",
        &digest(&json!({"owner":config.identity,"scope":scope,"fixture":pin}))?[..32]
    );
    let before = knowledge.history_anchor();
    let decision_id = format!(
        "observe-{}",
        &digest(
            &json!({"owner":config.identity,"scope":scope,"head":before.head_sha256,"fixture":pin})
        )?[..32]
    );
    emit(
        "SENSE",
        json!({"schema":"symbiote.observation-decision/1","decision_id":decision_id,"scope":scope,"source_fixture_sha256":pin,"authorization":permit,"backend":"affine-gf2/1","before":before}),
    )?;
    if let Some(record) = knowledge
        .active()
        .into_iter()
        .find(|record| record.id == id)
    {
        let _replay_timer = super::timing::Timer::start(super::timing::Stage::Replay);
        let audit: Value = serde_json::from_str(&record.provenance)
            .map_err(|_| "retained observation audit unavailable")?;
        if record.source != config.identity
            || record.scope != scope
            || audit["schema"] != "symbiote.local-observation-audit/1"
            || audit["owner_identity"] != config.identity
            || audit["fixture_sha256"] != pin
            || audit["scope"] != scope
        {
            return Err("retained observation provenance is foreign or changed".into());
        }
        let training = audit["training_count"]
            .as_u64()
            .ok_or("retained training count unavailable")? as usize;
        let observations: Vec<Observation> = serde_json::from_value(audit["queries"].clone())
            .map_err(|_| "retained observation trace changed")?;
        if training > observations.len() {
            return Err("retained observation training boundary changed".into());
        }
        let mut learner = CompactAffineLearner::new(
            source.width(),
            permit
                .max_gf2_work_total
                .checked_sub(usage.gf2_work)
                .ok_or("budget:observation-replay-gf2")?,
        )?;
        for (sequence, observation) in observations.iter().take(training).enumerate() {
            if observation.sequence != sequence {
                return Err("retained observation order changed".into());
            }
            learner.observe(observation.input, observation.output)?;
        }
        usage.gf2_work += learner.snapshot().work_units;
        let model = learner
            .identified()
            .ok_or("retained observation trace is not an identified model")?;
        if record.payload
            != json!({"kind":"affine","width":model.width,"coefficients":model.coefficients,"bias":model.bias})
        {
            return Err("retained model differs from exact observation replay".into());
        }
        let predictions:Vec<_>=observations.iter().skip(training).map(|item|Ok(json!({"input":item.input,"prediction":record.predict(item.input)?,"conditional":true,"physical_certificate_authorized":false}))).collect::<Result<_,String>>()?;
        let response = json!({"schema":"symbiote.observation-learning/1","status":"REUSED","decision_id":decision_id,"scope":scope,"before":before,"after":before,
            "fresh_promotions":0,"queries_performed":0,"record_sha256":record.digest()?,"artifact":record.id,"audit_sha256":digest(&audit)?,"snapshot":learner.snapshot(),"retained_predictions":predictions});
        emit("LEARN", response.clone())?;
        return Ok(response);
    }
    if knowledge.highest_revision(&id).is_some() {
        return Err(
            "HOLD: revoked local observation model requires operator review before relearning"
                .into(),
        );
    }
    let inferred = infer_from_source(&mut source, permit, usage, cancelled, deadline, &mut emit)?;
    let audit = json!({"schema":"symbiote.local-observation-audit/1","owner_identity":config.identity,"scope":scope,"fixture_sha256":pin,
        "queries":inferred.queries,"training_count":inferred.training,"snapshot":inferred.snapshot,
        "cost_model":"actual-query-plus-gf2-row-operations/1","conditional_family":symbiote_reasoning::structural::AFFINE_FAMILY,"physical_certificate_authorized":false});
    let provenance = serde_json::to_string(&audit).map_err(|e| e.to_string())?;
    if provenance.len() > 4096 {
        return Err("budget:observation-provenance-bytes".into());
    }
    let record = KnowledgeRecord {
        id,
        revision: 1,
        source: config.identity.clone(),
        scope: scope.into(),
        schema_fingerprint: affine_schema_fingerprint(source.width())?,
        payload: json!({"kind":"affine","width":inferred.model.width,"coefficients":inferred.model.coefficients,"bias":inferred.model.bias}),
        provenance,
    };
    let acquired = inferred.training as u64
        + inferred.snapshot["work_units"]
            .as_u64()
            .ok_or("GF2 work receipt unavailable")?;
    let verification = inferred.cases.len() as u64;
    let evidence = TrialEvidence {
        evaluator: format!("local-observer/{}", &pin[..24]),
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
            acquisition: acquired,
            verification,
            adoption: 1,
            baseline: 0,
            candidate: acquired + verification + 1,
        },
    };
    let assessment = {
        let _timer = super::timing::Timer::start(super::timing::Stage::Evaluation);
        assess(&record, &evidence)?
    };
    check(cancelled, deadline)?;
    {
        let _timer = super::timing::Timer::start(super::timing::Stage::Io);
        knowledge.promote(record.clone(), assessment)?;
    }
    let after = knowledge.history_anchor();
    let retained = knowledge
        .active()
        .into_iter()
        .find(|retained| retained.digest().ok() == record.digest().ok())
        .ok_or("fresh observation model is not active after promotion")?;
    let predictions:Vec<_>=evidence.cases.iter().map(|case|Ok(json!({"input":case.input,"prediction":retained.predict(case.input)?,"conditional":true,"physical_certificate_authorized":false}))).collect::<Result<_,String>>()?;
    let response = json!({"schema":"symbiote.observation-learning/1","status":"FRESH_PROMOTION","decision_id":decision_id,"scope":scope,"before":before,"after":after,
        "fresh_promotions":1,"queries_performed":inferred.queries.len(),"record_sha256":record.digest()?,"artifact":record.id,"audit_sha256":digest(&audit)?,"snapshot":inferred.snapshot,
        "retained_predictions":predictions,"costs":evidence.costs,"baseline_status":"unknown; capability coverage improved, no measured efficiency claim"});
    emit("LEARN", response.clone())?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn permit(queries: usize) -> ObservationPermit {
        ObservationPermit {
            schema: "symbiote.observation-permit/1".into(),
            scopes: vec!["test/v1".into()],
            max_queries_total: queries,
            max_gf2_work_total: 100_000,
            heldout_cases: 1,
        }
    }
    #[test]
    fn active_observation_infers_without_an_imported_model_and_holds_out_a_distinct_input() {
        let mut source = LocalOracle {
            width: 3,
            outputs: (0..8u16)
                .map(|input| ((input & 3).count_ones() % 2) as u8)
                .collect(),
            queries: 0,
        };
        let mut usage = Usage::default();
        let cancellation = AtomicBool::new(false);
        let inferred = infer_from_source(
            &mut source,
            &permit(8),
            &mut usage,
            &cancellation,
            Instant::now() + std::time::Duration::from_secs(1),
            |_phase: &str, _details: Value| Ok(()),
        )
        .unwrap();
        assert_eq!(inferred.training, 4);
        assert_eq!(inferred.queries.len(), 5);
        assert_eq!(usage.queries, 5);
        assert!(inferred.queries[..4]
            .iter()
            .all(|item| item.input != inferred.cases[0].input));
        assert_eq!(inferred.model.coefficients, 3);
        assert!(usage.gf2_work > 0);
    }
    #[test]
    fn source_query_limits_and_cancellation_do_not_fabricate_a_model() {
        let mut source = LocalOracle {
            width: 3,
            outputs: vec![0; 8],
            queries: 0,
        };
        let mut usage = Usage::default();
        assert!(infer(
            &mut source,
            &permit(2),
            &mut usage,
            &AtomicBool::new(false),
            Instant::now() + std::time::Duration::from_secs(1),
            &mut |_, _| Ok(())
        )
        .is_err());
        assert_eq!(usage.queries, 2);
        assert_eq!(source.queries, 2);
        assert!(source
            .observe(
                0,
                &AtomicBool::new(true),
                Instant::now() + std::time::Duration::from_secs(1)
            )
            .is_err());
        assert_eq!(source.queries, 2);
    }
    #[test]
    fn an_independent_heldout_counterexample_rejects_an_identified_hypothesis() {
        let mut outputs = vec![0; 8];
        outputs[3] = 1;
        let mut source = LocalOracle {
            width: 3,
            outputs,
            queries: 0,
        };
        let mut usage = Usage::default();
        let result = infer(
            &mut source,
            &permit(8),
            &mut usage,
            &AtomicBool::new(false),
            Instant::now() + std::time::Duration::from_secs(1),
            &mut |_, _| Ok(()),
        );
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("contradict"));
        assert_eq!(source.queries, 5);
        assert_eq!(usage.queries, 5);
        assert!(usage.gf2_work > 0);
    }
    #[test]
    fn public_adapter_rejects_wider_domains_and_overspent_usage_before_queries() {
        let mut source = LocalOracle {
            width: 9,
            outputs: vec![0; 512],
            queries: 0,
        };
        let mut usage = Usage::default();
        assert!(infer_from_source(
            &mut source,
            &permit(8),
            &mut usage,
            &AtomicBool::new(false),
            Instant::now() + std::time::Duration::from_secs(1),
            |_, _| Ok(())
        )
        .is_err());
        assert_eq!(source.queries, 0);
        source.width = 3;
        source.outputs.truncate(8);
        usage.queries = 9;
        assert!(infer_from_source(
            &mut source,
            &permit(8),
            &mut usage,
            &AtomicBool::new(false),
            Instant::now() + std::time::Duration::from_secs(1),
            |_, _| Ok(())
        )
        .is_err());
        assert_eq!(source.queries, 0);
    }
    #[test]
    fn failed_source_invocation_spends_allowance_and_cannot_be_retried_for_free() {
        struct FailingSource(usize);
        impl ObservationSource for FailingSource {
            fn width(&self) -> u8 {
                3
            }
            fn observe(
                &mut self,
                _input: u16,
                _cancelled: &AtomicBool,
                _deadline: Instant,
            ) -> Result<Observation, String> {
                self.0 += 1;
                Err("authorized adapter failed after its query attempt".into())
            }
        }
        let mut source = FailingSource(0);
        let mut usage = Usage::default();
        for _ in 0..2 {
            assert!(infer_from_source(
                &mut source,
                &permit(1),
                &mut usage,
                &AtomicBool::new(false),
                Instant::now() + std::time::Duration::from_secs(1),
                |_, _| Ok(()),
            )
            .is_err());
        }
        assert_eq!(source.0, 1);
        assert_eq!(usage.queries, 1);
    }

    #[test]
    fn late_or_cancelled_final_source_reply_cannot_return_success() {
        struct FinalReply {
            queries: usize,
            expire: bool,
        }
        impl ObservationSource for FinalReply {
            fn width(&self) -> u8 {
                3
            }
            fn observe(
                &mut self,
                input: u16,
                cancelled: &AtomicBool,
                deadline: Instant,
            ) -> Result<Observation, String> {
                let result = Observation {
                    sequence: self.queries,
                    input,
                    output: (input.count_ones() % 2) as u8,
                };
                self.queries += 1;
                if self.queries == 5 {
                    if self.expire {
                        std::thread::sleep(
                            deadline.saturating_duration_since(Instant::now())
                                + std::time::Duration::from_millis(1),
                        );
                    } else {
                        cancelled.store(true, Ordering::Release);
                    }
                }
                Ok(result)
            }
        }
        for expire in [false, true] {
            let mut source = FinalReply { queries: 0, expire };
            let mut usage = Usage::default();
            let cancelled = AtomicBool::new(false);
            let result = infer_with_policy(
                &mut source,
                &permit(8),
                &mut usage,
                &cancelled,
                Instant::now() + std::time::Duration::from_millis(200),
                AffineQueryPolicy::RankBasis,
                |_, _| Ok(()),
            );
            assert!(result.is_err());
            assert_eq!(usage.queries, 5);
            assert!(usage.gf2_work > 0);
        }
    }

    #[test]
    fn optional_rank_policy_uses_identical_observations_with_less_selection_work() {
        let mut usages = Vec::new();
        let mut traces = Vec::new();
        for policy in [AffineQueryPolicy::Reference, AffineQueryPolicy::RankBasis] {
            let mut source = LocalOracle {
                width: 8,
                outputs: (0..256u16)
                    .map(|input| (input.count_ones() % 2) as u8)
                    .collect(),
                queries: 0,
            };
            let mut usage = Usage::default();
            let result = infer_with_policy(
                &mut source,
                &permit(16),
                &mut usage,
                &AtomicBool::new(false),
                Instant::now() + std::time::Duration::from_secs(1),
                policy,
                |_, _| Ok(()),
            )
            .unwrap();
            traces.push(serde_json::to_value(result.queries).unwrap());
            usages.push(usage);
        }
        assert_eq!(traces[0], traces[1]);
        assert_eq!(usages[0].queries, 10);
        assert_eq!(usages[1].queries, 10);
        assert!(usages[1].gf2_work < usages[0].gf2_work);
    }
    #[test]
    fn failed_emission_keeps_spent_source_and_work_allowances() {
        let mut source = LocalOracle {
            width: 3,
            outputs: vec![0; 8],
            queries: 0,
        };
        let mut usage = Usage::default();
        assert!(infer_with_policy(
            &mut source,
            &permit(8),
            &mut usage,
            &AtomicBool::new(false),
            Instant::now() + std::time::Duration::from_secs(1),
            AffineQueryPolicy::RankBasis,
            |_, _| Err("observer audit publication failed".into())
        )
        .is_err());
        assert_eq!(usage.queries, 1);
        assert_eq!(source.queries, 1);
        assert!(usage.gf2_work > 0);
    }
}
