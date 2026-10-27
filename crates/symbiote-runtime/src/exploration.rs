//! Evidence-conditioned choice among an explicitly authorized experiment catalog.
//! Expected information ranks experiments; it never certifies a received model.
//! Snapshots require an independently retained current digest when reopening.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use symbiote_memory::knowledge::graph::{assess_graph, GraphTrialEvidence};
use symbiote_memory::knowledge::{
    assess, KnowledgeAnchor, KnowledgeRecord, KnowledgeStore, TrialEvidence,
};

fn digest<T: Serialize>(value: &T) -> Result<String, String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).map_err(|e| e.to_string())?)
    ))
}
fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExperimentSpec {
    pub id: String,
    pub scope: String,
    pub artifact_id: String,
    pub schema_fingerprint: String,
    pub authorized: bool,
    pub hypothesis_count: u64,
    pub expected_eliminations: u64,
    /// Hard complete reservation, including observation, verification, traffic,
    /// adoption and execution. Unused units are conservatively not refunded.
    pub complete_cost_ceiling: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExplorationPolicy {
    pub schema: String,
    pub owner: String,
    pub catalog: Vec<ExperimentSpec>,
    pub maximum_steps: usize,
    pub total_cost_ceiling: u64,
}
impl ExplorationPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != "symbiote.exploration-policy/1"
            || !label(&self.owner)
            || self.catalog.is_empty()
            || self.catalog.len() > 16
            || !(1..=128).contains(&self.maximum_steps)
            || self.total_cost_ceiling == 0
            || self.total_cost_ceiling > 1_000_000_000
        {
            return Err("bounded authorized experiment policy required".into());
        }
        let mut ids = BTreeSet::new();
        let mut artifacts = BTreeSet::new();
        for spec in &self.catalog {
            if !label(&spec.id)
                || !label(&spec.scope)
                || !label(&spec.artifact_id)
                || !artifacts.insert(&spec.artifact_id)
                || spec.schema_fingerprint.len() != 64
                || !spec
                    .schema_fingerprint
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                || !ids.insert(&spec.id)
                || !(1..=1_000_000).contains(&spec.hypothesis_count)
                || spec.expected_eliminations == 0
                || spec.expected_eliminations > spec.hypothesis_count
                || spec.complete_cost_ceiling == 0
                || spec.complete_cost_ceiling > self.total_cost_ceiling
            {
                return Err("invalid, duplicate or unbounded experiment proposal".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExperimentChoice {
    pub sequence: usize,
    pub experiment: String,
    pub scope: String,
    pub reserved_cost: u64,
    pub score_numerator: u64,
    pub score_denominator: u64,
    pub prior_attempts: u64,
    pub prior_verified_benefits: u64,
    pub before: KnowledgeAnchor,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LocalExperimentEvidence {
    Affine {
        record: KnowledgeRecord,
        evidence: TrialEvidence,
    },
    Graph {
        record: KnowledgeRecord,
        evidence: GraphTrialEvidence,
    },
}
impl LocalExperimentEvidence {
    fn record(&self) -> &KnowledgeRecord {
        match self {
            Self::Affine { record, .. } | Self::Graph { record, .. } => record,
        }
    }
    fn check(
        &self,
        store: &KnowledgeStore,
        before: &KnowledgeAnchor,
        after: &KnowledgeAnchor,
    ) -> Result<(u64, String), String> {
        let evidence = match self {
            Self::Affine { evidence, .. } => serde_json::to_value(evidence),
            Self::Graph { evidence, .. } => serde_json::to_value(evidence),
        }
        .map_err(|e| e.to_string())?;
        let promotion = store.promotion_between(self.record(), &evidence, before, after)?;
        match self {
            Self::Affine { record, evidence } => {
                Ok((assess(record, evidence)?.candidate_cost, promotion))
            }
            Self::Graph { record, evidence } => {
                Ok((assess_graph(record, evidence)?.candidate_cost, promotion))
            }
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ExplorationEvent {
    Selected {
        choice: ExperimentChoice,
    },
    Verified {
        experiment: String,
        evidence: Box<LocalExperimentEvidence>,
        after: KnowledgeAnchor,
    },
    Failed {
        experiment: String,
        reason: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplorationSnapshot {
    pub schema: String,
    pub policy_sha256: String,
    pub events: Vec<ExplorationEvent>,
    pub sha256: String,
}
pub struct ExperimentPortfolio {
    policy: ExplorationPolicy,
    events: Vec<ExplorationEvent>,
    performance: BTreeMap<String, (u64, u64)>,
    reserved: u64,
    steps: usize,
    pending: Option<ExperimentChoice>,
    credited_records: BTreeSet<String>,
    knowledge_position: usize,
}
impl ExperimentPortfolio {
    pub fn open(
        policy: ExplorationPolicy,
        store: &KnowledgeStore,
        prior: Option<ExplorationSnapshot>,
        expected_snapshot_sha256: Option<&str>,
    ) -> Result<Self, String> {
        policy.validate()?;
        if policy.owner != store.identity() {
            return Err("experiment history belongs to another owner".into());
        }
        if prior.is_some() != expected_snapshot_sha256.is_some() {
            return Err("current independent exploration snapshot pin required".into());
        }
        let mut result = Self {
            policy,
            events: Vec::new(),
            performance: BTreeMap::new(),
            reserved: 0,
            steps: 0,
            pending: None,
            credited_records: BTreeSet::new(),
            knowledge_position: 0,
        };
        if let Some(snapshot) = prior {
            let mut body = snapshot.clone();
            body.sha256.clear();
            if snapshot.schema != "symbiote.exploration-state/1"
                || snapshot.policy_sha256 != digest(&result.policy)?
                || expected_snapshot_sha256 != Some(snapshot.sha256.as_str())
                || digest(&body)? != snapshot.sha256
                || snapshot.events.len() > 256
            {
                return Err("exploration history integrity/policy rejected".into());
            }
            for event in snapshot.events {
                match event {
                    ExplorationEvent::Selected { choice } => {
                        let replay = result
                            .select_at(store, &choice.before)?
                            .ok_or("historical selection exceeds current bounds")?;
                        if replay != choice {
                            return Err(
                                "historical decision differs from preceding verified experience"
                                    .into(),
                            );
                        }
                    }
                    ExplorationEvent::Verified {
                        experiment,
                        evidence,
                        after,
                    } => result.complete_at(&experiment, *evidence, store, &after)?,
                    ExplorationEvent::Failed { experiment, reason } => {
                        result.fail(&experiment, &reason)?
                    }
                }
            }
        }
        Ok(result)
    }
    pub fn snapshot(&self) -> Result<ExplorationSnapshot, String> {
        let mut snapshot = ExplorationSnapshot {
            schema: "symbiote.exploration-state/1".into(),
            policy_sha256: digest(&self.policy)?,
            events: self.events.clone(),
            sha256: String::new(),
        };
        snapshot.sha256 = digest(&snapshot)?;
        Ok(snapshot)
    }
    pub fn pending(&self) -> Option<&ExperimentChoice> {
        self.pending.as_ref()
    }
    pub fn reserved_cost(&self) -> u64 {
        self.reserved
    }
    /// Exact rational ranking. A pending or abandoned operation keeps its budget;
    /// reopening never authorizes an automatic retry of an uncertain experiment.
    pub fn select(&mut self, store: &KnowledgeStore) -> Result<Option<ExperimentChoice>, String> {
        self.select_at(store, &store.history_anchor())
    }
    fn select_at(
        &mut self,
        store: &KnowledgeStore,
        before: &KnowledgeAnchor,
    ) -> Result<Option<ExperimentChoice>, String> {
        if self.policy.owner != store.identity() {
            return Err("foreign experiment owner".into());
        }
        store.validate_anchor(before)?;
        if before.records < self.knowledge_position {
            return Err("knowledge history moved backwards between experiments".into());
        }
        if self.pending.is_some() {
            return Err("settle the pending experiment explicitly before selecting another".into());
        }
        if self.steps >= self.policy.maximum_steps {
            return Ok(None);
        }
        let mut best: Option<ExperimentChoice> = None;
        for spec in &self.policy.catalog {
            if !spec.authorized
                || self
                    .reserved
                    .checked_add(spec.complete_cost_ceiling)
                    .is_none_or(|total| total > self.policy.total_cost_ceiling)
            {
                continue;
            }
            let (attempts, benefits) = self.performance.get(&spec.id).copied().unwrap_or_default();
            let numerator = spec
                .expected_eliminations
                .checked_mul(benefits + 1)
                .ok_or("experiment score overflow")?;
            let denominator = spec
                .hypothesis_count
                .checked_mul(attempts + 2)
                .and_then(|n| n.checked_mul(spec.complete_cost_ceiling))
                .ok_or("experiment denominator overflow")?;
            let choice = ExperimentChoice {
                sequence: self.steps + 1,
                experiment: spec.id.clone(),
                scope: spec.scope.clone(),
                reserved_cost: spec.complete_cost_ceiling,
                score_numerator: numerator,
                score_denominator: denominator,
                prior_attempts: attempts,
                prior_verified_benefits: benefits,
                before: before.clone(),
            };
            let better = best.as_ref().is_none_or(|old| {
                let left = u128::from(numerator) * u128::from(old.score_denominator);
                let right = u128::from(old.score_numerator) * u128::from(denominator);
                left > right || (left == right && choice.experiment < old.experiment)
            });
            if better {
                best = Some(choice);
            }
        }
        if let Some(choice) = &best {
            self.reserved += choice.reserved_cost;
            self.steps += 1;
            self.knowledge_position = before.records;
            self.pending = Some(choice.clone());
            self.events.push(ExplorationEvent::Selected {
                choice: choice.clone(),
            });
        }
        Ok(best)
    }
    pub fn complete(
        &mut self,
        id: &str,
        evidence: LocalExperimentEvidence,
        store: &KnowledgeStore,
    ) -> Result<(), String> {
        self.complete_at(id, evidence, store, &store.history_anchor())
    }
    fn complete_at(
        &mut self,
        id: &str,
        evidence: LocalExperimentEvidence,
        store: &KnowledgeStore,
        after: &KnowledgeAnchor,
    ) -> Result<(), String> {
        if self.policy.owner != store.identity() {
            return Err("foreign experiment owner".into());
        }
        let choice = self.pending.as_ref().ok_or("no pending experiment")?;
        let spec = self
            .policy
            .catalog
            .iter()
            .find(|spec| spec.id == id)
            .ok_or("unknown experiment")?;
        if choice.experiment != id
            || evidence.record().scope != choice.scope
            || evidence.record().id != spec.artifact_id
            || evidence.record().schema_fingerprint != spec.schema_fingerprint
        {
            return Err("evidence does not match pending experiment scope".into());
        }
        let (cost, promotion_sha256) = evidence.check(store, &choice.before, after)?;
        if cost > choice.reserved_cost {
            return Err("HOLD: measured experiment cost exceeds its complete reservation".into());
        }
        if self.credited_records.contains(&promotion_sha256) {
            return Err(
                "one durable promotion cannot be credited as repeated experiment gains".into(),
            );
        }
        self.credited_records.insert(promotion_sha256);
        self.knowledge_position = after.records;
        let entry = self.performance.entry(id.into()).or_default();
        entry.0 += 1;
        entry.1 += 1;
        self.events.push(ExplorationEvent::Verified {
            experiment: id.into(),
            evidence: Box::new(evidence),
            after: after.clone(),
        });
        self.pending = None;
        Ok(())
    }
    pub fn fail(&mut self, id: &str, reason: &str) -> Result<(), String> {
        let choice = self.pending.as_ref().ok_or("no pending experiment")?;
        if choice.experiment != id || reason.trim().is_empty() || reason.len() > 1024 {
            return Err("failure does not match pending experiment".into());
        }
        self.performance.entry(id.into()).or_default().0 += 1;
        self.events.push(ExplorationEvent::Failed {
            experiment: id.into(),
            reason: reason.into(),
        });
        self.pending = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use symbiote_memory::Store;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn fixture() -> (std::path::PathBuf, Store, KnowledgeStore) {
        let path = std::env::temp_dir().join(format!(
            "symbiote-portfolio-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let owner = Store::open(&path).unwrap();
        let knowledge = KnowledgeStore::open(&path, owner.identity()).unwrap();
        (path, owner, knowledge)
    }
    fn policy(owner: &str) -> ExplorationPolicy {
        ExplorationPolicy {
            schema: "symbiote.exploration-policy/1".into(),
            owner: owner.into(),
            catalog: [("a", true), ("b", true), ("secret", false)]
                .into_iter()
                .map(|(id, authorized)| ExperimentSpec {
                    id: id.into(),
                    scope: "task".into(),
                    artifact_id: format!("artifact-{id}"),
                    schema_fingerprint: symbiote_memory::knowledge::affine_schema_fingerprint(2)
                        .unwrap(),
                    authorized,
                    hypothesis_count: 8,
                    expected_eliminations: 4,
                    complete_cost_ceiling: 10,
                })
                .collect(),
            maximum_steps: 3,
            total_cost_ceiling: 30,
        }
    }
    fn learning(id: &str) -> (KnowledgeRecord, TrialEvidence) {
        let record = KnowledgeRecord {
            id: format!("artifact-{id}"),
            revision: 1,
            source: format!("partner-{id}"),
            scope: "task".into(),
            schema_fingerprint: symbiote_memory::knowledge::affine_schema_fingerprint(2).unwrap(),
            payload: serde_json::json!({"kind":"affine","width":2,"coefficients":1,"bias":false}),
            provenance: "separate local held-out evaluation".into(),
        };
        let evidence = TrialEvidence {
            evaluator: "local-evaluator".into(),
            training_case_ids: vec!["train-0".into()],
            training_inputs: vec![0],
            cases: (1..4)
                .map(|input| symbiote_memory::knowledge::TrialCase {
                    id: format!("held-{input}"),
                    input,
                    expected: (input & 1) as u8,
                    baseline: None,
                    candidate: (input & 1) as u8,
                })
                .collect(),
            costs: symbiote_memory::knowledge::TrialCosts {
                acquisition: 1,
                verification: 3,
                adoption: 1,
                baseline: 10,
                candidate: 6,
            },
        };
        (record, evidence)
    }
    #[test]
    fn only_fresh_matching_committed_evidence_can_credit_a_selected_experiment() {
        let (path, owner, mut knowledge) = fixture();
        let config = policy(owner.identity());
        let mut portfolio =
            ExperimentPortfolio::open(config.clone(), &knowledge, None, None).unwrap();
        portfolio.select(&knowledge).unwrap();
        let (record, evidence) = learning("a");
        knowledge
            .promote(record.clone(), assess(&record, &evidence).unwrap())
            .unwrap();
        let mut cheaper = evidence.clone();
        cheaper.costs.candidate = 5;
        assert!(portfolio
            .complete(
                "a",
                LocalExperimentEvidence::Affine {
                    record: record.clone(),
                    evidence: cheaper
                },
                &knowledge
            )
            .is_err());
        let (foreign, evidence_b) = learning("b");
        knowledge
            .promote(foreign.clone(), assess(&foreign, &evidence_b).unwrap())
            .unwrap();
        assert!(portfolio
            .complete(
                "a",
                LocalExperimentEvidence::Affine {
                    record: foreign,
                    evidence: evidence_b
                },
                &knowledge
            )
            .is_err());
        portfolio
            .complete(
                "a",
                LocalExperimentEvidence::Affine {
                    record: record.clone(),
                    evidence: evidence.clone(),
                },
                &knowledge,
            )
            .unwrap();
        let snapshot = portfolio.snapshot().unwrap();
        let pin = snapshot.sha256.clone();
        assert_eq!(
            portfolio.select(&knowledge).unwrap().unwrap().experiment,
            "a"
        );
        assert!(portfolio
            .complete(
                "a",
                LocalExperimentEvidence::Affine {
                    record: record.clone(),
                    evidence: evidence.clone()
                },
                &knowledge
            )
            .is_err());
        knowledge
            .revoke(&record.id, "observed drift after the completed experiment")
            .unwrap();
        let mut replay =
            ExperimentPortfolio::open(config, &knowledge, Some(snapshot), Some(&pin)).unwrap();
        assert_eq!(replay.select(&knowledge).unwrap().unwrap().experiment, "a");
        assert!(replay
            .complete(
                "a",
                LocalExperimentEvidence::Affine { record, evidence },
                &knowledge
            )
            .is_err());
        drop(replay);
        drop(portfolio);
        drop(knowledge);
        drop(owner);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn preselection_and_revoked_promotions_are_not_new_experiment_benefits() {
        let (path, owner, mut knowledge) = fixture();
        let config = policy(owner.identity());
        let (record, evidence) = learning("a");
        knowledge
            .promote(record.clone(), assess(&record, &evidence).unwrap())
            .unwrap();
        let mut portfolio = ExperimentPortfolio::open(config, &knowledge, None, None).unwrap();
        portfolio.select(&knowledge).unwrap();
        assert!(portfolio
            .complete(
                "a",
                LocalExperimentEvidence::Affine {
                    record: record.clone(),
                    evidence: evidence.clone()
                },
                &knowledge
            )
            .is_err());
        portfolio
            .fail("a", "the model predates this experiment")
            .unwrap();
        portfolio.select(&knowledge).unwrap();
        let (record_b, evidence_b) = learning("b");
        knowledge
            .promote(record_b.clone(), assess(&record_b, &evidence_b).unwrap())
            .unwrap();
        knowledge
            .revoke(&record_b.id, "new candidate regressed before completion")
            .unwrap();
        assert!(portfolio
            .complete(
                "b",
                LocalExperimentEvidence::Affine {
                    record: record_b,
                    evidence: evidence_b
                },
                &knowledge
            )
            .is_err());
        drop(portfolio);
        drop(knowledge);
        drop(owner);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn persistent_failure_changes_next_prospective_choice_without_refunding_cost() {
        let (path, owner, knowledge) = fixture();
        let config = policy(owner.identity());
        let mut portfolio =
            ExperimentPortfolio::open(config.clone(), &knowledge, None, None).unwrap();
        assert_eq!(
            portfolio.select(&knowledge).unwrap().unwrap().experiment,
            "a"
        );
        assert!(portfolio.select(&knowledge).is_err());
        portfolio.fail("a", "measured rejection").unwrap();
        let snapshot = portfolio.snapshot().unwrap();
        let pin = snapshot.sha256.clone();
        drop(portfolio);
        drop(knowledge);
        drop(owner);
        let owner = Store::open(&path).unwrap();
        let knowledge = KnowledgeStore::open(&path, owner.identity()).unwrap();
        let mut reopened =
            ExperimentPortfolio::open(config, &knowledge, Some(snapshot), Some(&pin)).unwrap();
        let choice = reopened.select(&knowledge).unwrap().unwrap();
        assert_eq!(choice.experiment, "b");
        assert_eq!(reopened.reserved_cost(), 20);
        reopened.fail("b", "no measured gain").unwrap();
        reopened.select(&knowledge).unwrap();
        reopened.fail("a", "rejected").unwrap();
        assert!(reopened.select(&knowledge).unwrap().is_none());
        drop(reopened);
        drop(knowledge);
        drop(owner);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn altered_history_foreign_owner_and_unsettled_restart_fail_closed() {
        let (path, owner, knowledge) = fixture();
        let config = policy(owner.identity());
        let mut portfolio =
            ExperimentPortfolio::open(config.clone(), &knowledge, None, None).unwrap();
        portfolio.select(&knowledge).unwrap();
        let snapshot = portfolio.snapshot().unwrap();
        let pin = snapshot.sha256.clone();
        let mut reopened = ExperimentPortfolio::open(
            config.clone(),
            &knowledge,
            Some(snapshot.clone()),
            Some(&pin),
        )
        .unwrap();
        assert!(reopened.select(&knowledge).is_err());
        reopened
            .fail("a", "explicit abandoned-attempt settlement")
            .unwrap();
        let mut altered = snapshot;
        altered.events.clear();
        altered.sha256.clear();
        altered.sha256 = digest(&altered).unwrap();
        assert!(
            ExperimentPortfolio::open(config.clone(), &knowledge, Some(altered), Some(&pin))
                .is_err()
        );
        let mut foreign = config;
        foreign.owner = "other".into();
        assert!(ExperimentPortfolio::open(foreign, &knowledge, None, None).is_err());
        drop(reopened);
        drop(portfolio);
        drop(knowledge);
        drop(owner);
        std::fs::remove_dir_all(path).unwrap();
    }
}
