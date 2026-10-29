use super::{types::*, Audit, EngineState, Pending};
use serde::{Deserialize, Serialize};
use symbiote_memory::{
    knowledge::KnowledgeRecord,
    operational::{OperationalEvent, PartnerDecisionRecord},
};
pub(crate) const SCHEMA: &str = "symbiote.embedding-engine/1";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Entry {
    Started {
        episode: String,
        source: SourceDescriptor,
        before: KnowledgeAnchor,
    },
    Inferred {
        episode: String,
        audit: Audit,
        record_sha256: String,
        reused: bool,
    },
    Evaluated {
        episode: String,
        record_sha256: String,
        cases: usize,
    },
    Finished {
        episode: String,
        record: KnowledgeRecord,
        before: KnowledgeAnchor,
        after: KnowledgeAnchor,
        reused: bool,
        usage: EpisodeUsage,
    },
    Failed {
        episode: String,
        kind: ErrorKind,
        usage: EpisodeUsage,
        knowledge_at: KnowledgeAnchor,
    },
    Used {
        artifact: String,
        record_sha256: String,
        input: u16,
        answer: Option<u8>,
        knowledge_at: KnowledgeAnchor,
    },
    Revoked {
        artifact: String,
        before: KnowledgeAnchor,
        after: KnowledgeAnchor,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    scope: String,
    position: usize,
    event: Entry,
}
pub(crate) fn append(state: &mut EngineState, scope: &str, event: Entry) -> Result<()> {
    let value = serde_json::to_value(Envelope {
        schema: SCHEMA.into(),
        scope: scope.into(),
        position: state.journal.events().len(),
        event,
    })
    .map_err(|e| EngineError::new(ErrorKind::Malformed, "journal", e.to_string()))?;
    let id = format!("engine-{}", super::digest(&value)?);
    state
        .journal
        .append(OperationalEvent::PartnerDecisionRecorded {
            decision: PartnerDecisionRecord {
                decision_id: id,
                context: scope.into(),
                frontier_edge: None,
                selected_peer: None,
                details: value,
            },
        })
        .map_err(|e| EngineError::new(ErrorKind::Storage, "journal", e))
}
pub(crate) fn entries(state: &EngineState) -> Result<Vec<(String, Entry)>> {
    let mut result = Vec::new();
    for (position, event) in state.journal.events().iter().enumerate() {
        let OperationalEvent::PartnerDecisionRecorded { decision } = event else {
            continue;
        };
        let schema = decision.details["schema"].as_str().unwrap_or("");
        if !schema.starts_with("symbiote.embedding-engine/") {
            continue;
        }
        let envelope: Envelope = serde_json::from_value(decision.details.clone())
            .map_err(|e| EngineError::new(ErrorKind::Malformed, "replay", e.to_string()))?;
        if envelope.schema != SCHEMA
            || envelope.position != position
            || envelope.scope != decision.context
            || decision.frontier_edge.is_some()
            || decision.selected_peer.is_some()
            || decision.decision_id != format!("engine-{}", super::digest(&decision.details)?)
        {
            return Err(EngineError::new(
                ErrorKind::Malformed,
                "replay",
                "engine journal envelope/version/hash changed",
            ));
        }
        result.push((envelope.scope, envelope.event));
    }
    Ok(result)
}
fn validate_audit(state: &mut EngineState, audit: &Audit) -> Result<()> {
    if audit.schema != "symbiote.engine-observation-audit/1"
        || audit.owner != state.owner.identity()
        || audit.training > audit.queries.len()
        || audit.queries.len() > 256
        || !state.config.authorized_sources.contains(&audit.source)
    {
        return Err(EngineError::new(
            ErrorKind::Malformed,
            "replay_audit",
            "invalid observation audit identity/bounds",
        ));
    }
    let declared = audit.snapshot["work_unit_budget"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= state.config.max_gf2_work_per_episode as u64)
        .ok_or_else(|| {
            EngineError::new(
                ErrorKind::BudgetExhausted,
                "replay_audit",
                "saved model budget invalid",
            )
        })? as usize;
    // Independent of episode spending: total cold structural verification is
    // capped, counted and reported rather than allowed to grow without a bound.
    let remaining = 1_000_000_usize
        .checked_sub(state.replay_gf2_work)
        .filter(|n| *n > 0)
        .ok_or_else(|| {
            EngineError::new(
                ErrorKind::BudgetExhausted,
                "replay_audit",
                "cold replay GF2 ceiling exhausted",
            )
        })?;
    let budget = declared.min(remaining);
    let policy = match audit.snapshot.get("query_policy") {
        None => AffineQueryPolicy::Reference,
        Some(v) => serde_json::from_value(v.clone()).map_err(|e| {
            EngineError::new(ErrorKind::IncompatibleSchema, "replay_audit", e.to_string())
        })?,
    };
    let mut model =
        symbiote_reasoning::structural::CompactAffineLearner::new(audit.source.width, budget)
            .map_err(|e| EngineError::new(ErrorKind::IncompatibleSchema, "replay_audit", e))?;
    let result = (|| {
        let mut inputs = std::collections::BTreeSet::new();
        for (sequence, q) in audit.queries.iter().enumerate() {
            if q.sequence != sequence
                || q.input >= (1u16 << audit.source.width)
                || q.output > 1
                || !inputs.insert(q.input)
            {
                return Err(EngineError::new(
                    ErrorKind::Malformed,
                    "replay_audit",
                    "observation order/input/output changed",
                ));
            }
            if sequence < audit.training {
                let next = model
                    .choose_query_with_policy(policy)
                    .map_err(|e| EngineError::new(ErrorKind::Malformed, "replay_audit", e))?
                    .ok_or_else(|| {
                        EngineError::new(
                            ErrorKind::BudgetExhausted,
                            "replay_audit",
                            "query unavailable under replay bound",
                        )
                    })?;
                if next != q.input {
                    return Err(EngineError::new(
                        ErrorKind::Malformed,
                        "replay_audit",
                        "recorded query is not exact selected query",
                    ));
                }
                model.observe(q.input, q.output).map_err(|e| {
                    EngineError::new(
                        if *model.status()
                            == symbiote_reasoning::structural::AffineStatus::BudgetExhausted
                        {
                            ErrorKind::BudgetExhausted
                        } else {
                            ErrorKind::Contradiction
                        },
                        "replay_audit",
                        e,
                    )
                })?;
            } else {
                if model.identified().is_none() {
                    return Err(EngineError::new(
                        ErrorKind::Uncertain,
                        "replay_audit",
                        "heldout verification preceded identification",
                    ));
                }
                if model
                    .forecast(q.input)
                    .map_err(|e| EngineError::new(ErrorKind::Malformed, "replay_audit", e))?
                    .answer
                    != Some(q.output)
                {
                    return Err(EngineError::new(
                        ErrorKind::Contradiction,
                        "replay_audit",
                        "heldout result differs from inferred model",
                    ));
                }
            }
        }
        if model.identified().is_none() || audit.queries.len() == audit.training {
            return Err(EngineError::new(
                ErrorKind::Uncertain,
                "replay_audit",
                "audit lacks identified model/disjoint validation",
            ));
        }
        let actual = serde_json::to_value(model.snapshot())
            .map_err(|e| EngineError::new(ErrorKind::Malformed, "replay_audit", e.to_string()))?;
        let mut expected = audit.snapshot.clone();
        expected["work_unit_budget"] = serde_json::json!(budget);
        if actual != expected {
            return Err(EngineError::new(
                ErrorKind::Malformed,
                "replay_audit",
                "snapshot/work differ from exact query replay",
            ));
        }
        Ok(())
    })();
    state.replay_gf2_work = state
        .replay_gf2_work
        .checked_add(model.snapshot().work_units)
        .ok_or_else(|| {
            EngineError::new(
                ErrorKind::BudgetExhausted,
                "replay_audit",
                "replay counter overflow",
            )
        })?;
    result
}
fn expected_usage(state: &mut EngineState, audit: &Audit, reused: bool) -> Result<EpisodeUsage> {
    if !reused {
        return Ok(EpisodeUsage {
            source_calls: audit.queries.len(),
            gf2_work_units: audit.snapshot["work_units"].as_u64().ok_or_else(|| {
                EngineError::new(ErrorKind::Malformed, "replay", "audit lacks work units")
            })? as usize,
            evaluation_cases: audit.queries.len() - audit.training,
        });
    }
    // Reuse performs the actual observe-only reconstruction used by the live
    // path. It has no new source calls or held-out evaluation. Charge this
    // extra cold verification to the same fixed replay ceiling.
    let remaining = 1_000_000_usize
        .checked_sub(state.replay_gf2_work)
        .filter(|n| *n > 0)
        .ok_or_else(|| {
            EngineError::new(
                ErrorKind::BudgetExhausted,
                "replay",
                "cold reuse replay ceiling exhausted",
            )
        })?;
    let mut learner = symbiote_reasoning::structural::CompactAffineLearner::new(
        audit.source.width,
        remaining.min(state.config.max_gf2_work_per_episode),
    )
    .map_err(|e| EngineError::new(ErrorKind::IncompatibleSchema, "replay", e))?;
    let result = (|| {
        for q in audit.queries.iter().take(audit.training) {
            learner.observe(q.input, q.output).map_err(|e| {
                EngineError::new(
                    if *learner.status()
                        == symbiote_reasoning::structural::AffineStatus::BudgetExhausted
                    {
                        ErrorKind::BudgetExhausted
                    } else {
                        ErrorKind::Contradiction
                    },
                    "replay",
                    e,
                )
            })?;
        }
        if serde_json::to_value(learner.identified())
            .map_err(|e| EngineError::new(ErrorKind::Malformed, "replay", e.to_string()))?
            != audit.snapshot["conditional_strategy"]
        {
            return Err(EngineError::new(
                ErrorKind::Contradiction,
                "replay",
                "reuse model differs from audited inference",
            ));
        }
        Ok(EpisodeUsage {
            source_calls: 0,
            gf2_work_units: learner.snapshot().work_units,
            evaluation_cases: 0,
        })
    })();
    state.replay_gf2_work = state
        .replay_gf2_work
        .checked_add(learner.snapshot().work_units)
        .ok_or_else(|| {
            EngineError::new(
                ErrorKind::BudgetExhausted,
                "replay",
                "reuse replay counter overflow",
            )
        })?;
    result
}
pub(crate) fn replay(state: &mut EngineState) -> Result<()> {
    let mut pending: Option<Pending> = None;
    let mut covered = std::collections::BTreeSet::from([1_usize]);
    for (scope, event) in entries(state)? {
        match event {
            Entry::Started {
                episode,
                source,
                before,
            } => {
                if pending.is_some()
                    || source.scope != scope
                    || !state.config.authorized_sources.contains(&source)
                {
                    return Err(EngineError::new(
                        ErrorKind::Hold,
                        "replay",
                        "overlapping or unauthorized saved episode",
                    ));
                }
                state
                    .knowledge
                    .validate_anchor(&before)
                    .map_err(|e| EngineError::new(ErrorKind::Storage, "replay", e))?;
                pending = Some(Pending {
                    episode,
                    source,
                    before,
                    audit: None,
                    record_sha256: None,
                    usage: EpisodeUsage::default(),
                    reused: None,
                    evaluated_cases: None,
                });
            }
            Entry::Inferred {
                episode,
                audit,
                record_sha256,
                reused,
            } => {
                validate_audit(state, &audit)?;
                let usage = expected_usage(state, &audit, reused)?;
                let current = pending
                    .as_mut()
                    .filter(|p| p.episode == episode)
                    .ok_or_else(|| {
                        EngineError::new(ErrorKind::Hold, "replay", "inference without its episode")
                    })?;
                if current.audit.is_some()
                    || audit.source != current.source
                    || audit.policy_sha256 != state.policy_sha256
                    || (!reused && audit.episode != episode)
                {
                    return Err(EngineError::new(
                        ErrorKind::Authorization,
                        "replay",
                        "inference source/policy differs",
                    ));
                }
                current.audit = Some(audit);
                current.record_sha256 = Some(record_sha256);
                current.usage = usage;
                current.reused = Some(reused);
            }
            Entry::Evaluated {
                episode,
                record_sha256,
                cases,
            } => {
                let p = pending
                    .as_mut()
                    .filter(|p| {
                        p.episode == episode
                            && p.record_sha256.as_ref() == Some(&record_sha256)
                            && p.evaluated_cases.is_none()
                    })
                    .ok_or_else(|| {
                        EngineError::new(
                            ErrorKind::Hold,
                            "replay",
                            "evaluation lacks exact inference",
                        )
                    })?;
                if cases == 0
                    || cases > p.audit.as_ref().map_or(0, |a| a.queries.len() - a.training)
                {
                    return Err(EngineError::new(
                        ErrorKind::Hold,
                        "replay",
                        "evaluation count exceeds exact heldout audit",
                    ));
                }
                p.evaluated_cases = Some(cases);
            }
            Entry::Finished {
                episode,
                record,
                before,
                after,
                reused,
                usage,
            } => {
                let p = pending
                    .take()
                    .filter(|p| p.episode == episode && p.before == before)
                    .ok_or_else(|| {
                        EngineError::new(
                            ErrorKind::Hold,
                            "replay",
                            "completion lacks exact episode",
                        )
                    })?;
                let hash = record
                    .digest()
                    .map_err(|e| EngineError::new(ErrorKind::Malformed, "replay", e))?;
                let audit = p.audit.ok_or_else(|| {
                    EngineError::new(
                        ErrorKind::Hold,
                        "replay",
                        "completion has no observation audit",
                    )
                })?;
                if p.reused != Some(reused)
                    || p.evaluated_cases.is_none()
                    || p.usage != usage
                    || record.payload != audit.snapshot["conditional_strategy"]
                    || record.scope != audit.source.scope
                    || record.schema_fingerprint
                        != symbiote_memory::knowledge::affine_schema_fingerprint(audit.source.width)
                            .map_err(|e| {
                                EngineError::new(ErrorKind::IncompatibleSchema, "replay", e)
                            })?
                    || match &audit.incoming_artifact_sha256 {
                        Some(incoming) => incoming != &hash,
                        None => {
                            record.source != state.owner.identity()
                                || record.provenance
                                    != serde_json::to_string(&audit).map_err(|e| {
                                        EngineError::new(
                                            ErrorKind::Malformed,
                                            "replay",
                                            e.to_string(),
                                        )
                                    })?
                        }
                    }
                {
                    return Err(EngineError::new(ErrorKind::Contradiction, "replay", "completion model, attribution, work or evaluation differs from exact audited inference"));
                }
                if p.record_sha256.as_ref() != Some(&hash)
                    || !state
                        .knowledge
                        .active_at(&after)
                        .map_err(|e| EngineError::new(ErrorKind::Storage, "replay", e))?
                        .iter()
                        .any(|r| r == &record)
                {
                    return Err(EngineError::new(
                        ErrorKind::Hold,
                        "replay",
                        "completion artifact is absent from its exact history",
                    ));
                }
                if !reused && !covered.insert(after.records) {
                    return Err(EngineError::new(
                        ErrorKind::Hold,
                        "replay",
                        "knowledge change credited twice",
                    ));
                }
                if reused {
                    if before != after {
                        return Err(EngineError::new(
                            ErrorKind::Hold,
                            "replay",
                            "reuse changed history",
                        ));
                    }
                } else {
                    let (_, evidence) = state
                        .knowledge
                        .promotion_evidence_between(&record, &before, &after)
                        .map_err(|e| EngineError::new(ErrorKind::Hold, "replay", e))?;
                    let cases = evidence["cases"].as_array().ok_or_else(|| {
                        EngineError::new(
                            ErrorKind::Malformed,
                            "replay",
                            "stored native cases absent",
                        )
                    })?;
                    if p.evaluated_cases != Some(cases.len()) {
                        return Err(EngineError::new(
                            ErrorKind::Contradiction,
                            "replay",
                            "saved native evidence and evaluation count differ",
                        ));
                    }
                    for case in cases {
                        if !audit.queries.iter().skip(audit.training).any(|q| {
                            case["input"].as_u64() == Some(u64::from(q.input))
                                && case["expected"].as_u64() == Some(u64::from(q.output))
                        }) {
                            return Err(EngineError::new(
                                ErrorKind::Contradiction,
                                "replay",
                                "native assessment did not use actual heldout observations",
                            ));
                        }
                    }
                }
            }
            Entry::Failed {
                episode,
                knowledge_at,
                ..
            } => {
                let p = pending
                    .take()
                    .filter(|p| p.episode == episode)
                    .ok_or_else(|| {
                        EngineError::new(ErrorKind::Hold, "replay", "failure lacks episode")
                    })?;
                if p.before != knowledge_at {
                    return Err(EngineError::new(
                        ErrorKind::Hold,
                        "replay",
                        "failed episode concealed a knowledge change",
                    ));
                }
            }
            Entry::Used {
                artifact,
                record_sha256,
                input,
                answer,
                knowledge_at,
            } => {
                let active = state
                    .knowledge
                    .active_at(&knowledge_at)
                    .map_err(|e| EngineError::new(ErrorKind::Storage, "replay", e))?;
                let record = active
                    .iter()
                    .find(|r| r.id == artifact && r.digest().ok().as_ref() == Some(&record_sha256))
                    .ok_or_else(|| {
                        EngineError::new(
                            ErrorKind::Revoked,
                            "replay",
                            "stored use lacks active exact record",
                        )
                    })?;
                let actual = match record
                    .typed_payload()
                    .map_err(|e| EngineError::new(ErrorKind::Malformed, "replay", e))?
                {
                    symbiote_memory::knowledge::KnowledgePayload::Affine { width, .. }
                        if input >= (1u16 << width) =>
                    {
                        None
                    }
                    _ => record
                        .predict_if_certified(input)
                        .map_err(|e| EngineError::new(ErrorKind::Malformed, "replay", e))?,
                };
                if actual != answer {
                    return Err(EngineError::new(
                        ErrorKind::Contradiction,
                        "replay",
                        "stored prediction differs from retained model",
                    ));
                }
            }
            Entry::Revoked {
                artifact,
                before,
                after,
            } => {
                state
                    .knowledge
                    .validate_anchor(&before)
                    .and_then(|_| state.knowledge.validate_anchor(&after))
                    .map_err(|e| EngineError::new(ErrorKind::Storage, "replay", e))?;
                if !covered.insert(after.records) {
                    return Err(EngineError::new(
                        ErrorKind::Hold,
                        "replay",
                        "knowledge revocation credited twice",
                    ));
                }
                if after.records != before.records + 1
                    || state
                        .knowledge
                        .active_at(&after)
                        .map_err(|e| EngineError::new(ErrorKind::Storage, "replay", e))?
                        .iter()
                        .any(|r| r.id == artifact)
                {
                    return Err(EngineError::new(
                        ErrorKind::Hold,
                        "replay",
                        "revocation is not its exact committed change",
                    ));
                }
            }
        }
    }
    if covered.len() != state.knowledge.record_count()
        || covered
            .iter()
            .copied()
            .ne(1..=state.knowledge.record_count())
    {
        return Err(EngineError::new(ErrorKind::Hold,"open","knowledge changed without an exact completed engine operation; inspect/restore committed evidence"));
    }
    if let Some(p) = pending {
        return Err(EngineError::new(ErrorKind::Hold,"open",format!("episode {} is incomplete; inspect and restore an independently pinned stopped-owner checkpoint; no retry/reset performed",p.episode)));
    }
    Ok(())
}
