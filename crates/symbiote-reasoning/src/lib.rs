//! Exact bounded hidden-state support, ported from BRUTE `bgr90/symbolic.py`.
//!
//! A singleton support is conditional on the declared stationary deterministic
//! Moore-machine family. It does not establish that a real agent belongs to it.
pub mod planning;
pub mod query_strategy;
pub mod structural;

use serde::Serialize;
use std::collections::BTreeSet;

pub type Observation = [Option<u8>; 2];
const ALL: u8 = 0b1111;
const TRANS_UNKNOWN: i8 = -1;

pub fn mask_for_observation(observation: Observation) -> Result<u8, String> {
    if observation.iter().flatten().any(|value| *value > 1) {
        return Err("expected two nullable binary channels".into());
    }
    let mut mask = 0;
    for code in 0..4 {
        if observation
            .iter()
            .enumerate()
            .all(|(j, value)| value.is_none_or(|value| ((code >> (1 - j)) & 1) == value))
        {
            mask |= 1 << code;
        }
    }
    Ok(mask)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Prefix {
    trans: Vec<i8>,
    masks: Vec<u8>,
    current: usize,
    used: usize,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Evidence {
    pub action: Option<usize>,
    pub observation: Observation,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Snapshot {
    pub status: String,
    pub conditional_model_scope: String,
    pub model_rows: usize,
    pub evidence_count: usize,
    pub max_rows_seen: usize,
    pub transitions_examined: usize,
    pub last_failure: Option<String>,
    pub physical_certificate_authorized: bool,
}

#[derive(Clone, Debug)]
pub struct SymbolicLearner {
    max_states: usize,
    max_prefixes: usize,
    evidence: Vec<Evidence>,
    belief: BTreeSet<Prefix>,
    status: &'static str,
    transitions_examined: usize,
    max_rows_seen: usize,
    last_failure: Option<String>,
}

impl SymbolicLearner {
    pub fn new(max_states: usize, max_prefixes: usize) -> Result<Self, String> {
        if !(1..=6).contains(&max_states) {
            return Err("maximum state count must be 1..6".into());
        }
        if max_prefixes < 4 {
            return Err("need at least four hypothesis rows".into());
        }
        Ok(Self {
            max_states,
            max_prefixes,
            evidence: Vec::new(),
            belief: BTreeSet::new(),
            status: "uninitialized",
            transitions_examined: 0,
            max_rows_seen: 0,
            last_failure: None,
        })
    }

    pub fn initialize(&mut self, observation: Observation) -> Result<(), String> {
        if !self.evidence.is_empty() {
            return Err("already initialized".into());
        }
        let mask = mask_for_observation(observation)?;
        let mut masks = vec![0; self.max_states];
        masks[0] = mask;
        self.belief.insert(Prefix {
            trans: vec![TRANS_UNKNOWN; self.max_states * 2],
            masks,
            current: 0,
            used: 1,
        });
        self.status = "supported";
        self.evidence.push(Evidence {
            action: None,
            observation,
        });
        self.max_rows_seen = 1;
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.belief.len()
    }

    pub fn status(&self) -> &str {
        self.status
    }

    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }

    pub fn predict_support(&self, action: usize) -> Result<Option<Vec<u8>>, String> {
        check_action(action)?;
        if self.status != "supported" {
            return Ok(None);
        }
        let mut union = 0;
        for prefix in &self.belief {
            let dest = prefix.trans[prefix.current * 2 + action];
            if dest < 0 {
                for j in 0..prefix.used {
                    union |= prefix.masks[j];
                }
                if prefix.used < self.max_states {
                    union |= ALL;
                }
            } else {
                union |= prefix.masks[dest as usize];
            }
            if union == ALL {
                break;
            }
        }
        Ok(Some(
            (0..4).filter(|code| union & (1 << code) != 0).collect(),
        ))
    }

    pub fn conditional_certificate(&self, action: usize) -> Result<Option<u8>, String> {
        Ok(self
            .predict_support(action)?
            .filter(|support| support.len() == 1)
            .map(|support| support[0]))
    }

    pub fn observe(&mut self, action: usize, observation: Observation) -> Result<(), String> {
        if self.evidence.is_empty() {
            return Err("not initialized".into());
        }
        check_action(action)?;
        let mask = mask_for_observation(observation)?;
        self.evidence.push(Evidence {
            action: Some(action),
            observation,
        });
        // Evidence survives failed inference and can be explicitly reconstructed.
        if self.status != "supported" {
            return Ok(());
        }
        let mut result = BTreeSet::new();
        for prefix in &self.belief {
            let edge = prefix.current * 2 + action;
            let known = prefix.trans[edge];
            let choices: Vec<usize> = if known >= 0 {
                vec![known as usize]
            } else {
                (0..prefix.used + usize::from(prefix.used < self.max_states)).collect()
            };
            for dest in choices {
                let new = dest == prefix.used;
                let prior = if new { ALL } else { prefix.masks[dest] };
                let emission = prior & mask;
                if emission == 0 {
                    continue;
                }
                let mut candidate = prefix.clone();
                if known < 0 {
                    candidate.trans[edge] = dest as i8;
                }
                if new || emission != prior {
                    candidate.masks[dest] = emission;
                }
                candidate.current = dest;
                candidate.used += usize::from(new);
                self.transitions_examined += 1;
                result.insert(candidate);
                if result.len() > self.max_prefixes {
                    self.fail(
                        "budget_exhausted",
                        "unambiguous work cap hit; abstain and preserve evidence",
                    );
                    return Ok(());
                }
            }
        }
        if result.is_empty() {
            self.fail(
                "grammar_contradicted",
                "no finite model under state cap explains all observations",
            );
            return Ok(());
        }
        self.max_rows_seen = self.max_rows_seen.max(result.len());
        self.belief = result;
        Ok(())
    }

    fn fail(&mut self, status: &'static str, reason: &str) {
        self.status = status;
        self.last_failure = Some(reason.into());
        self.belief.clear();
    }

    pub fn reconstruct(
        &self,
        max_states: Option<usize>,
        max_prefixes: Option<usize>,
    ) -> Result<Self, String> {
        let initial = self.evidence.first().ok_or("not initialized")?;
        let mut new = Self::new(
            max_states.unwrap_or(self.max_states),
            max_prefixes.unwrap_or(self.max_prefixes),
        )?;
        new.initialize(initial.observation)?;
        for evidence in &self.evidence[1..] {
            new.observe(
                evidence.action.ok_or("missing action")?,
                evidence.observation,
            )?;
        }
        Ok(new)
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            status: self.status.into(),
            conditional_model_scope: format!("deterministic <= {} hidden states", self.max_states),
            model_rows: self.count(),
            evidence_count: self.evidence.len(),
            max_rows_seen: self.max_rows_seen,
            transitions_examined: self.transitions_examined,
            last_failure: self.last_failure.clone(),
            physical_certificate_authorized: false,
        }
    }
}

fn check_action(action: usize) -> Result<(), String> {
    if action > 1 {
        return Err("action must be 0 or 1".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_masks_preserve_missing_bits() {
        assert_eq!(mask_for_observation([None, None]).unwrap(), 15);
        assert_eq!(mask_for_observation([Some(0), None]).unwrap(), 3);
        assert_eq!(mask_for_observation([None, Some(1)]).unwrap(), 10);
        assert_eq!(mask_for_observation([Some(1), Some(0)]).unwrap(), 4);
        assert!(mask_for_observation([Some(2), None]).is_err());
    }

    #[test]
    fn budget_abstains_preserves_evidence_and_reconstructs() {
        let mut learner = SymbolicLearner::new(4, 4).unwrap();
        learner.initialize([None, None]).unwrap();
        for action in [0, 1, 0, 1] {
            learner.observe(action, [None, None]).unwrap();
        }
        assert_eq!(learner.status(), "budget_exhausted");
        assert_eq!(learner.count(), 0);
        assert_eq!(learner.predict_support(0).unwrap(), None);
        assert_eq!(learner.evidence().len(), 5);
        let recovered = learner.reconstruct(None, Some(200000)).unwrap();
        assert_eq!(recovered.status(), "supported");
        assert_eq!(recovered.evidence(), learner.evidence());
    }

    #[test]
    fn contradiction_never_becomes_a_certificate() {
        let mut learner = SymbolicLearner::new(1, 100).unwrap();
        learner.initialize([Some(0), Some(0)]).unwrap();
        learner.observe(0, [Some(1), Some(1)]).unwrap();
        assert_eq!(learner.status(), "grammar_contradicted");
        assert_eq!(learner.conditional_certificate(0).unwrap(), None);
        let expanded = learner.reconstruct(Some(2), None).unwrap();
        assert_eq!(expanded.status(), "supported");
        assert!(!expanded.snapshot().physical_certificate_authorized);
    }

    #[test]
    fn invalid_operations_are_explicit_and_do_not_add_evidence() {
        assert!(SymbolicLearner::new(0, 100).is_err());
        assert!(SymbolicLearner::new(7, 100).is_err());
        assert!(SymbolicLearner::new(2, 3).is_err());
        let mut learner = SymbolicLearner::new(2, 100).unwrap();
        assert!(learner.observe(0, [None, None]).is_err());
        learner.initialize([Some(0), None]).unwrap();
        assert!(learner.initialize([None, None]).is_err());
        assert!(learner.observe(2, [None, None]).is_err());
        assert!(learner.observe(0, [None, Some(2)]).is_err());
        assert_eq!(learner.evidence().len(), 1);
        assert!(learner.predict_support(2).is_err());
    }
}
