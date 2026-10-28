//! Semantic inventory comparison and bounded, replayable proposal backoff.
//! These decisions grant neither trust nor permission. The operational journal
//! remains authoritative; the index is rebuilt from checked events after restart.
use super::{digest, Config, State};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use symbiote_memory::knowledge::{
    KnowledgeAnchor, KnowledgePayload, KnowledgeRecord, KnowledgeStore,
};
use symbiote_memory::operational::{OperationalEvent, PartnerDecisionRecord};

const SCHEMA: &str = "symbiote.proposal-memory/1";
const CACHE_EVENTS: usize = 64;

fn evaluator_code() -> &'static str {
    static CODE: OnceLock<String> = OnceLock::new();
    CODE.get_or_init(|| {
        // Also invalidate unstamped development builds when their evaluator or
        // reasoning code changes without a package-version change.
        let sources: &[&[u8]] = &[
            include_bytes!("evaluation.rs"),
            include_bytes!("feedback.rs"),
            include_bytes!("observation.rs"),
            include_bytes!("selection.rs"),
            include_bytes!("../graph_transfer.rs"),
            include_bytes!("../../../symbiote-memory/src/knowledge.rs"),
            include_bytes!("../../../symbiote-memory/src/knowledge/graph.rs"),
            include_bytes!("../../../symbiote-reasoning/src/planning.rs"),
            include_bytes!("../../../symbiote-reasoning/src/structural/compact.rs"),
        ];
        let mut hash = Sha256::new();
        hash.update(b"symbiote.evaluator-code/1\0");
        for source in sources {
            hash.update((source.len() as u64).to_le_bytes());
            hash.update(source);
        }
        format!("{:x}", hash.finalize())
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Relationship {
    Equivalent,
    Subsumed,
    Complementary,
    Superseding,
    Incompatible,
    Unknown,
}
impl Relationship {
    pub(super) fn redundant(self) -> bool {
        matches!(self, Self::Equivalent | Self::Subsumed)
    }
}

/// Compare the meaning of payloads, not artifact names, sources or revisions.
/// Compatible positive-edge facts preserve all previously supported predictions
/// when strengthened. A strict fact superset is not a claim of a measured gain.
pub(super) fn relationship(
    candidate: &KnowledgeRecord,
    existing: &[KnowledgeRecord],
) -> Result<Relationship, String> {
    candidate.validate()?;
    if existing.len() > 32 {
        return Err("semantic inventory exceeds its bounded record count".into());
    }
    let related: Vec<_> = existing
        .iter()
        .filter(|record| record.scope == candidate.scope)
        .collect();
    if related.is_empty() {
        return Ok(Relationship::Unknown);
    }
    for prior in &related {
        prior.validate()?;
        if prior.schema_fingerprint != candidate.schema_fingerprint {
            return Ok(Relationship::Incompatible);
        }
    }
    match candidate.typed_payload()? {
        KnowledgePayload::Affine {
            width,
            coefficients,
            bias,
        } => {
            for prior in related {
                match prior.typed_payload()? {
                    KnowledgePayload::Affine {
                        width: w,
                        coefficients: a,
                        bias: b,
                    } if (width, coefficients, bias) == (w, a, b) => {}
                    _ => return Ok(Relationship::Incompatible),
                }
            }
            Ok(Relationship::Equivalent)
        }
        KnowledgePayload::GraphMap(map) => {
            let candidate_facts: BTreeMap<_, _> = map
                .observations
                .iter()
                .map(|o| (o.edge_id, o.cost))
                .collect();
            // The recipient may hold the same knowledge split across artifacts.
            // Union only compatible, non-conflicting exact facts; this does not
            // import any of those remote assertions into our own knowledge.
            let mut prior_facts = BTreeMap::new();
            for prior in related {
                let KnowledgePayload::GraphMap(old) = prior.typed_payload()? else {
                    return Ok(Relationship::Incompatible);
                };
                if old.schema != map.schema {
                    return Ok(Relationship::Incompatible);
                }
                for observation in old.observations {
                    if prior_facts
                        .insert(observation.edge_id, observation.cost)
                        .is_some_and(|old| old != observation.cost)
                    {
                        return Ok(Relationship::Incompatible);
                    }
                }
            }
            if candidate_facts
                .iter()
                .any(|(edge, cost)| prior_facts.get(edge).is_some_and(|old| old != cost))
            {
                Ok(Relationship::Incompatible)
            } else if candidate_facts == prior_facts {
                Ok(Relationship::Equivalent)
            } else if candidate_facts
                .iter()
                .all(|(edge, cost)| prior_facts.get(edge) == Some(cost))
            {
                Ok(Relationship::Subsumed)
            } else if prior_facts
                .iter()
                .all(|(edge, cost)| candidate_facts.get(edge) == Some(cost))
            {
                Ok(Relationship::Superseding)
            } else {
                Ok(Relationship::Complementary)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Key {
    pub artifact_sha256: String,
    pub peer: String,
    pub scope: String,
    pub evaluator_sha256: String,
    pub policy_sha256: String,
}
pub(super) fn key(config: &Config, peer: &str, scope: &str, artifact: &str) -> Result<Key, String> {
    config.peer(peer)?;
    let context = config.context(scope)?;
    Ok(Key {
        artifact_sha256: artifact.into(),
        peer: peer.into(),
        scope: scope.into(),
        evaluator_sha256: digest(
            &serde_json::json!({"version":env!("CARGO_PKG_VERSION"),"code":evaluator_code(),
            "truth":context.truth_sha256,"schema":context.schema_fingerprint,"kind":"configured-evaluation"}),
        )?,
        policy_sha256: config.policy_digest.clone(),
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Memory {
    Declined {
        key: Key,
        anchor: KnowledgeAnchor,
        reason: String,
        expires_at_event: usize,
    },
    SourceEvaluated {
        key: Key,
        anchor: KnowledgeAnchor,
        candidate: String,
        local_record_sha256: Option<String>,
    },
}
impl Memory {
    fn key(&self) -> &Key {
        match self {
            Self::Declined { key, .. } | Self::SourceEvaluated { key, .. } => key,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    memory: Memory,
}

fn parse(event: &OperationalEvent) -> Result<Option<Memory>, String> {
    let OperationalEvent::PartnerDecisionRecorded { decision } = event else {
        return Ok(None);
    };
    if decision.details["schema"] != SCHEMA {
        return Ok(None);
    }
    let envelope: Envelope = serde_json::from_value(decision.details.clone())
        .map_err(|_| "proposal memory schema rejected")?;
    if decision.decision_id != format!("proposal-{}", digest(&decision.details)?)
        || decision.selected_peer.as_deref() != Some(&envelope.memory.key().peer)
        || decision.context != envelope.memory.key().scope
        || decision.frontier_edge.is_some()
    {
        return Err("proposal memory carrier binding differs".into());
    }
    Ok(Some(envelope.memory))
}
pub(super) fn handles(event: &OperationalEvent) -> bool {
    matches!(event, OperationalEvent::PartnerDecisionRecorded { decision } if decision.details["schema"] == SCHEMA)
}
pub(super) fn validate_event(
    config: &Config,
    event: &OperationalEvent,
    preceding: &[OperationalEvent],
    knowledge: &KnowledgeStore,
) -> Result<(), String> {
    let memory = parse(event)?.ok_or("not a proposal memory event")?;
    let k = memory.key();
    config.peer(&k.peer)?;
    config.context(&k.scope)?;
    if [&k.artifact_sha256, &k.evaluator_sha256, &k.policy_sha256]
        .iter()
        .any(|value| !super::config::sha(value))
        || k.policy_sha256 != config.policy_digest
    {
        return Err("proposal memory policy/digest rejected".into());
    }
    match memory {
        Memory::Declined {
            anchor,
            reason,
            expires_at_event,
            ..
        } => {
            knowledge.validate_anchor(&anchor)?;
            if reason.is_empty()
                || reason.len() > 512
                || expires_at_event <= preceding.len()
                || expires_at_event > preceding.len().saturating_add(CACHE_EVENTS)
            {
                return Err("proposal backoff has invalid reason/expiry".into());
            }
        }
        Memory::SourceEvaluated {
            key,
            anchor,
            candidate,
            local_record_sha256,
        } => {
            knowledge.validate_anchor(&anchor)?;
            let request_matches = preceding.iter().any(|event| matches!(event,
                OperationalEvent::Quarantined { key: source, candidate_id, body, .. }
                if candidate_id == &candidate && source.peer_id == key.peer && source.scope == key.scope
                    && serde_json::from_value::<super::wire::Request>(body.clone()).ok().is_some_and(|request|
                       matches!(request.body, super::wire::Operation::Submit{offer} if offer.record.digest().ok().as_deref() == Some(&key.artifact_sha256)))));
            if !request_matches {
                return Err("source cache lacks its exact authenticated quarantine".into());
            }
            if let Some(local) = &local_record_sha256 {
                let completed = preceding.iter().any(|event| matches!(event,
                    OperationalEvent::EvaluationCompleted { candidate_id, record_sha256, .. }
                    if candidate_id == &candidate && record_sha256 == local));
                if !completed || !knowledge.active_at(&anchor)?.iter().any(|record| record.digest().ok().as_deref() == Some(local)) {
                    return Err("source cache lacks an actual active evaluated model".into());
                }
            } else if !preceding.iter().any(|event| matches!(event,
                OperationalEvent::EvaluationRejected { candidate_id, .. } if candidate_id == &candidate)) {
                return Err("source rejection cache lacks an actual rejection".into());
            }
        }
    }
    Ok(())
}
fn memory_event(memory: Memory) -> Result<OperationalEvent, String> {
    let key = memory.key().clone();
    let details = serde_json::to_value(Envelope {
        schema: SCHEMA.into(),
        memory,
    })
    .map_err(|e| e.to_string())?;
    Ok(OperationalEvent::PartnerDecisionRecorded {
        decision: PartnerDecisionRecord {
            decision_id: format!("proposal-{}", digest(&details)?),
            context: key.scope,
            selected_peer: Some(key.peer),
            frontier_edge: None,
            details,
        },
    })
}
fn retain(state: &mut State, memory: Memory) -> Result<(), String> {
    let event = memory_event(memory)?;
    validate_event(
        &state.config,
        &event,
        state.journal.events(),
        &state.knowledge,
    )?;
    state.journal.append(event)
}
pub(super) fn declined(state: &mut State, key: Key, reason: &str) -> Result<(), String> {
    retain(
        state,
        Memory::Declined {
            key,
            anchor: state.knowledge.history_anchor(),
            reason: reason.into(),
            expires_at_event: state
                .journal
                .events()
                .len()
                .checked_add(CACHE_EVENTS)
                .ok_or("proposal expiry overflow")?,
        },
    )
}
pub(super) fn is_backed_off(events: &[OperationalEvent], key: &Key) -> Result<bool, String> {
    for event in events.iter().rev() {
        if let Some(Memory::Declined {
            key: old,
            expires_at_event,
            ..
        }) = parse(event)?
        {
            if &old == key {
                return Ok(events.len() < expires_at_event);
            }
        }
    }
    Ok(false)
}
/// Rebuild a completion index once rather than nesting a complete journal scan
/// inside every historical proposal. This is an access optimization only.
pub(super) fn already_contributed(
    events: &[OperationalEvent],
    peer: &str,
    scope: &str,
    artifact: &str,
) -> bool {
    let received: BTreeSet<_> = events
        .iter()
        .filter_map(|event| match event {
            OperationalEvent::PartnerOutcomeRecorded { outcome }
                if outcome.kind == symbiote_memory::operational::PartnerOutcomeKind::Received =>
            {
                Some(outcome.interaction_id.as_str())
            }
            _ => None,
        })
        .collect();
    events.iter().any(|event| matches!(event, OperationalEvent::PartnerDecisionRecorded { decision }
        if decision.details["schema"] == "symbiote.cognition-decision/1"
            && decision.details["phase"] == "contribute" && decision.selected_peer.as_deref() == Some(peer)
            && decision.context == scope && decision.details["source_record_sha256"] == artifact
            && received.contains(decision.decision_id.as_str())))
}
pub(super) fn source_evaluated(
    state: &mut State,
    key: Key,
    candidate: &str,
    local: Option<String>,
) -> Result<(), String> {
    // Idempotent cache publication: no duplicate decision is appended after replay.
    for event in state.journal.events() {
        if let Some(Memory::SourceEvaluated {
            key: old,
            candidate: previous,
            ..
        }) = parse(event)?
        {
            if old == key && previous == candidate {
                return Ok(());
            }
        }
    }
    retain(
        state,
        Memory::SourceEvaluated {
            key,
            anchor: state.knowledge.history_anchor(),
            candidate: candidate.into(),
            local_record_sha256: local,
        },
    )
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SourceStatus {
    Unknown,
    Retained,
    RejectedOrRevoked,
}
pub(super) fn source_status(state: &State, key: &Key) -> Result<SourceStatus, String> {
    let active = state
        .knowledge
        .active()
        .iter()
        .map(KnowledgeRecord::digest)
        .collect::<Result<BTreeSet<_>, _>>()?;
    cached_source_status(
        state.journal.events(),
        key,
        &state.knowledge.history_anchor(),
        &active,
    )
}
fn cached_source_status(
    events: &[OperationalEvent],
    key: &Key,
    current: &KnowledgeAnchor,
    active: &BTreeSet<String>,
) -> Result<SourceStatus, String> {
    for (position, event) in events.iter().enumerate().rev() {
        if let Some(Memory::SourceEvaluated {
            key: old,
            anchor,
            local_record_sha256,
            ..
        }) = parse(event)?
        {
            if &old == key {
                return Ok(match local_record_sha256 {
                    Some(sha) if active.contains(&sha) => SourceStatus::Retained,
                    // Never automatically reinstate an explicitly revoked or
                    // superseded exact model from the unchanged source. A new
                    // artifact/evaluator/policy key is required for that review.
                    Some(_) => SourceStatus::RejectedOrRevoked,
                    None if &anchor != current
                        || events.len() >= position.saturating_add(CACHE_EVENTS) =>
                    {
                        SourceStatus::Unknown
                    }
                    None => SourceStatus::RejectedOrRevoked,
                });
            }
        }
    }
    Ok(SourceStatus::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use symbiote_memory::knowledge::affine_schema_fingerprint;
    fn record() -> KnowledgeRecord {
        KnowledgeRecord {
            id: "r".into(),
            revision: 1,
            source: "peer".into(),
            scope: "scope".into(),
            schema_fingerprint: affine_schema_fingerprint(2).unwrap(),
            payload: json!({"kind":"affine","width":2,"coefficients":3,"bias":true}),
            provenance: "finite semantic comparison".into(),
        }
    }
    #[test]
    fn artifact_names_sources_and_revisions_do_not_create_new_affine_knowledge() {
        let first = record();
        let mut same = first.clone();
        same.id = "other".into();
        same.source = "other-source".into();
        same.revision = 4;
        assert_eq!(
            relationship(&first, &[same]).unwrap(),
            Relationship::Equivalent
        );
        let mut wrong = first.clone();
        wrong.payload["bias"] = json!(false);
        assert_eq!(
            relationship(&first, &[wrong]).unwrap(),
            Relationship::Incompatible
        );
        assert_eq!(relationship(&first, &[]).unwrap(), Relationship::Unknown);
    }
    #[test]
    fn declined_proposal_survives_reopen_but_changed_evidence_and_bounded_expiry_reconsider_it() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        use symbiote_memory::{operational::OperationalJournal, Store};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "symbiote-selection-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let owner = Arc::new(Store::open(&path).unwrap());
        let knowledge = KnowledgeStore::open(&path, owner.identity()).unwrap();
        let key = Key {
            artifact_sha256: "a".repeat(64),
            peer: "peer".into(),
            scope: "scope".into(),
            evaluator_sha256: "b".repeat(64),
            policy_sha256: "c".repeat(64),
        };
        let mut journal =
            OperationalJournal::open(owner.clone(), "proposal-tests/v1", &key.policy_sha256)
                .unwrap();
        journal
            .append(
                memory_event(Memory::Declined {
                    key: key.clone(),
                    anchor: knowledge.history_anchor(),
                    reason: "measured negative proposal".into(),
                    expires_at_event: CACHE_EVENTS,
                })
                .unwrap(),
            )
            .unwrap();
        assert!(is_backed_off(journal.events(), &key).unwrap());
        drop(journal);
        drop(knowledge);
        drop(owner);
        let owner = Arc::new(Store::open(&path).unwrap());
        let mut journal =
            OperationalJournal::open(owner.clone(), "proposal-tests/v1", &key.policy_sha256)
                .unwrap();
        assert!(
            is_backed_off(journal.events(), &key).unwrap(),
            "restart must not forget a decline"
        );
        for changed in 0..3 {
            let mut revised = key.clone();
            match changed {
                0 => revised.artifact_sha256 = "d".repeat(64),
                1 => revised.evaluator_sha256 = "e".repeat(64),
                _ => revised.policy_sha256 = "f".repeat(64),
            }
            assert!(!is_backed_off(journal.events(), &revised).unwrap());
        }
        for tick in 1..CACHE_EVENTS {
            journal
                .append(OperationalEvent::PartnerDecisionRecorded {
                    decision: PartnerDecisionRecord {
                        decision_id: format!("unrelated-tick-{tick}"),
                        context: "scope".into(),
                        frontier_edge: None,
                        selected_peer: None,
                        details: json!({"tick":tick}),
                    },
                })
                .unwrap();
        }
        assert!(
            !is_backed_off(journal.events(), &key).unwrap(),
            "bounded expiry preserves exploration"
        );
        drop(journal);
        drop(owner);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn partial_graphs_compare_exact_facts_without_treating_every_nonempty_inventory_as_equivalent()
    {
        use symbiote_memory::knowledge::graph::{
            graph_schema_fingerprint, GraphMap, GraphObservation,
        };
        use symbiote_reasoning::planning::{Edge, GraphSchema};
        let schema = GraphSchema {
            nodes: 3,
            edges: vec![
                Edge {
                    from: 0,
                    to: 1,
                    lower: 1,
                    upper: 9,
                },
                Edge {
                    from: 1,
                    to: 2,
                    lower: 1,
                    upper: 9,
                },
            ],
        };
        let mut candidate = record();
        candidate.schema_fingerprint = graph_schema_fingerprint(&schema).unwrap();
        // Use the canonical tagged payload serializer rather than an inferred shape.
        candidate.payload = serde_json::to_value(KnowledgePayload::GraphMap(
            GraphMap::new(
                schema.clone(),
                vec![GraphObservation {
                    edge_id: 0,
                    cost: 1,
                }],
            )
            .unwrap(),
        ))
        .unwrap();
        let mut other = candidate.clone();
        other.payload = serde_json::to_value(KnowledgePayload::GraphMap(
            GraphMap::new(
                schema.clone(),
                vec![GraphObservation {
                    edge_id: 1,
                    cost: 1,
                }],
            )
            .unwrap(),
        ))
        .unwrap();
        assert_eq!(
            relationship(&candidate, &[other.clone()]).unwrap(),
            Relationship::Complementary
        );
        let second_half = other.clone();
        other.payload = serde_json::to_value(KnowledgePayload::GraphMap(
            GraphMap::new(
                schema.clone(),
                vec![
                    GraphObservation {
                        edge_id: 0,
                        cost: 1,
                    },
                    GraphObservation {
                        edge_id: 1,
                        cost: 1,
                    },
                ],
            )
            .unwrap(),
        ))
        .unwrap();
        assert_eq!(
            relationship(&candidate, &[other.clone()]).unwrap(),
            Relationship::Subsumed
        );
        assert_eq!(
            relationship(&other, &[candidate.clone()]).unwrap(),
            Relationship::Superseding
        );
        assert_eq!(
            relationship(&other, &[candidate.clone(), second_half]).unwrap(),
            Relationship::Equivalent,
            "compatible knowledge split across artifacts must suppress a redundant full offer"
        );
        assert_eq!(
            relationship(&candidate, &[candidate.clone()]).unwrap(),
            Relationship::Equivalent
        );
        other.payload = serde_json::to_value(KnowledgePayload::GraphMap(
            GraphMap::new(
                schema,
                vec![GraphObservation {
                    edge_id: 0,
                    cost: 2,
                }],
            )
            .unwrap(),
        ))
        .unwrap();
        assert_eq!(
            relationship(&candidate, &[other.clone()]).unwrap(),
            Relationship::Incompatible
        );
        assert_eq!(
            relationship(&candidate, &[candidate.clone(), other]).unwrap(),
            Relationship::Incompatible
        );
    }

    #[test]
    fn source_rejection_expires_or_tracks_changed_knowledge_but_revocation_needs_new_evidence() {
        let key = Key {
            artifact_sha256: "a".repeat(64),
            peer: "peer".into(),
            scope: "scope".into(),
            evaluator_sha256: "b".repeat(64),
            policy_sha256: "c".repeat(64),
        };
        let anchor = KnowledgeAnchor {
            identity: "owner".into(),
            records: 0,
            head_sha256: "d".repeat(64),
        };
        let rejected = memory_event(Memory::SourceEvaluated {
            key: key.clone(),
            anchor: anchor.clone(),
            candidate: "rejected".into(),
            local_record_sha256: None,
        })
        .unwrap();
        let mut events = vec![rejected];
        let active = BTreeSet::new();
        assert!(
            cached_source_status(&events, &key, &anchor, &active).unwrap()
                == SourceStatus::RejectedOrRevoked
        );
        let mut changed = anchor.clone();
        changed.records = 1;
        changed.head_sha256 = "e".repeat(64);
        assert!(
            cached_source_status(&events, &key, &changed, &active).unwrap()
                == SourceStatus::Unknown
        );
        for index in 1..CACHE_EVENTS {
            events.push(OperationalEvent::PartnerDecisionRecorded {
                decision: PartnerDecisionRecord {
                    decision_id: format!("unrelated-{index}"),
                    context: "scope".into(),
                    frontier_edge: None,
                    selected_peer: None,
                    details: json!({"tick":index}),
                },
            });
        }
        assert!(
            cached_source_status(&events, &key, &anchor, &active).unwrap() == SourceStatus::Unknown
        );
        let local_sha = "f".repeat(64);
        let promoted = memory_event(Memory::SourceEvaluated {
            key: key.clone(),
            anchor: anchor.clone(),
            candidate: "promoted".into(),
            local_record_sha256: Some(local_sha.clone()),
        })
        .unwrap();
        assert!(
            cached_source_status(std::slice::from_ref(&promoted), &key, &changed, &active).unwrap()
                == SourceStatus::RejectedOrRevoked
        );
        assert!(
            cached_source_status(&[promoted], &key, &changed, &BTreeSet::from([local_sha]))
                .unwrap()
                == SourceStatus::Retained
        );
    }
}
