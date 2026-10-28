//! Exact structural reasoning over an explicitly supplied Boolean affine family.
//!
//! This is an independently implemented SYMBIOTE extension, not a claim that
//! BRUTE's complete certification policy has been ported. A unique hypothesis is
//! conditional on a stationary affine environment; observations alone cannot
//! establish that the environment belongs to this family. Received strategies
//! are inert hints and never remove a hypothesis without genuine observations.

use serde::{Deserialize, Serialize};

mod compact;
pub use compact::{CompactAffineLearner, CompactAffineSnapshot, CompactAffineWork};

pub const AFFINE_FAMILY: &str = "boolean-affine/v1";
pub const MAX_WIDTH: u8 = 8;

/// Canonical affine function: parity(input & coefficients) XOR bias.
/// Input coordinate zero is the least-significant bit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename = "affine")]
pub struct AffineStrategy {
    pub width: u8,
    pub coefficients: u16,
    pub bias: bool,
}

impl<'de> Deserialize<'de> for AffineStrategy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "kind", deny_unknown_fields)]
        enum WireStrategy {
            #[serde(rename = "affine")]
            Affine {
                width: u8,
                coefficients: u16,
                bias: bool,
            },
        }
        let WireStrategy::Affine {
            width,
            coefficients,
            bias,
        } = WireStrategy::deserialize(deserializer)?;
        Self::new(width, coefficients, bias).map_err(serde::de::Error::custom)
    }
}

impl AffineStrategy {
    pub fn new(width: u8, coefficients: u16, bias: bool) -> Result<Self, String> {
        let strategy = Self {
            width,
            coefficients,
            bias,
        };
        strategy.validate()?;
        Ok(strategy)
    }

    pub fn validate(&self) -> Result<(), String> {
        check_width(self.width)?;
        if self.coefficients >= domain_size(self.width) {
            return Err("affine coefficients exceed the declared width".into());
        }
        Ok(())
    }

    pub fn predict(&self, input: u16) -> Result<u8, String> {
        self.validate()?;
        check_input(self.width, input)?;
        Ok(self.predict_valid(input))
    }

    fn predict_valid(&self, input: u16) -> u8 {
        ((input & self.coefficients).count_ones() as u8 & 1) ^ u8::from(self.bias)
    }

    /// Explicit coordinate relabelling: each source index maps to one target
    /// index. Schema equivalence must be established by the caller; a permutation
    /// by itself supplies no evidence that a different environment is affine.
    pub fn remap(&self, source_to_target: &[u8]) -> Result<Self, String> {
        self.validate()?;
        if source_to_target.len() != usize::from(self.width) {
            return Err("coordinate mapping must cover the complete schema".into());
        }
        let mut visited = 0_u16;
        let mut coefficients = 0_u16;
        for (source, &target) in source_to_target.iter().enumerate() {
            if target >= self.width || visited & (1 << target) != 0 {
                return Err("coordinate mapping must be a bijective permutation".into());
            }
            visited |= 1 << target;
            if self.coefficients & (1 << source) != 0 {
                coefficients |= 1 << target;
            }
        }
        Self::new(self.width, coefficients, self.bias)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AffineObservation {
    pub input: u16,
    pub output: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AffineStatus {
    Supported,
    BudgetExhausted,
    Contradicted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AffineSnapshot {
    pub family: &'static str,
    pub width: u8,
    pub status: AffineStatus,
    pub hypotheses: usize,
    pub accepted_observations: usize,
    pub model_evaluations: usize,
    pub model_evaluation_budget: usize,
    pub conditional_strategy: Option<AffineStrategy>,
    pub last_failure: Option<String>,
    pub pending_observation: Option<AffineObservation>,
    pub physical_certificate_authorized: bool,
}

/// Exact candidate assessment within the declared affine family. This enum does
/// not authenticate a sender or certify the adequacy of the supplied family.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CandidateAssessment {
    Rejected {
        reason: String,
    },
    Unverified {
        compatible_hypotheses: usize,
    },
    ConditionallyVerified {
        family: &'static str,
        evidence_count: usize,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PredictionBasis {
    Observed,
    Inferred,
    Uncertain,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AffinePrediction {
    pub input: u16,
    pub possible_outputs: Option<Vec<u8>>,
    pub answer: Option<u8>,
    pub basis: PredictionBasis,
    pub conditional_family: &'static str,
    pub physical_certificate_authorized: bool,
}

/// Complete version-space inference with a cumulative model-evaluation budget.
///
/// At width w there are exactly 2^(w+1) canonical hypotheses and 2^w inputs.
/// No approximation or received prior shrinks that support. Query selection
/// maximizes worst-case hypothesis elimination, with deterministic tie breaking.
#[derive(Clone, Debug)]
pub struct AffineLearner {
    width: u8,
    hypotheses: Vec<AffineStrategy>,
    observations: Vec<AffineObservation>,
    max_model_evaluations: usize,
    model_evaluations: usize,
    status: AffineStatus,
    last_failure: Option<String>,
    pending_observation: Option<AffineObservation>,
    hint: Option<AffineStrategy>,
}

impl AffineLearner {
    pub fn new(width: u8, max_model_evaluations: usize) -> Result<Self, String> {
        check_width(width)?;
        if max_model_evaluations == 0 {
            return Err("affine reasoning needs a positive model-evaluation budget".into());
        }
        let hypotheses = (0..domain_size(width))
            .flat_map(|coefficients| {
                [false, true].map(move |bias| AffineStrategy {
                    width,
                    coefficients,
                    bias,
                })
            })
            .collect();
        Ok(Self {
            width,
            hypotheses,
            observations: Vec::new(),
            max_model_evaluations,
            model_evaluations: 0,
            status: AffineStatus::Supported,
            last_failure: None,
            pending_observation: None,
            hint: None,
        })
    }

    pub fn width(&self) -> u8 {
        self.width
    }

    pub fn status(&self) -> &AffineStatus {
        &self.status
    }

    pub fn hypothesis_count(&self) -> usize {
        self.hypotheses.len()
    }

    pub fn observations(&self) -> &[AffineObservation] {
        &self.observations
    }

    pub fn snapshot(&self) -> AffineSnapshot {
        AffineSnapshot {
            family: AFFINE_FAMILY,
            width: self.width,
            status: self.status.clone(),
            hypotheses: self.hypotheses.len(),
            accepted_observations: self.observations.len(),
            model_evaluations: self.model_evaluations,
            model_evaluation_budget: self.max_model_evaluations,
            conditional_strategy: self.identified(),
            last_failure: self.last_failure.clone(),
            pending_observation: self.pending_observation.clone(),
            physical_certificate_authorized: false,
        }
    }

    /// Hint validation never counts as an observation. A hint can only change
    /// ties between equally informative queries; it cannot authorize an answer.
    pub fn set_hint(&mut self, strategy: &AffineStrategy) -> Result<(), String> {
        strategy.validate()?;
        if strategy.width != self.width {
            return Err("received hint has a different input schema".into());
        }
        if !self.reserve_work(self.observations.len()) {
            return Err("affine reasoning unavailable while checking hint".into());
        }
        if self
            .observations
            .iter()
            .any(|observation| strategy.predict_valid(observation.input) != observation.output)
        {
            return Err("received hint contradicts accepted observations".into());
        }
        self.hint = Some(strategy.clone());
        Ok(())
    }

    pub fn clear_hint(&mut self) {
        self.hint = None;
    }

    /// Returns the unique strategy only conditionally on the supplied family.
    pub fn identified(&self) -> Option<AffineStrategy> {
        if self.status == AffineStatus::Supported && self.hypotheses.len() == 1 {
            return self.hypotheses.first().cloned();
        }
        None
    }

    /// Transactional model update. A contradictory observation is retained as
    /// pending evidence and disables predictions; it never partly mutates the
    /// previously supported model bank. Repeated identical evidence is a no-op.
    pub fn observe(&mut self, input: u16, output: u8) -> Result<(), String> {
        check_input(self.width, input)?;
        if output > 1 {
            return Err("affine observation must publish one binary output".into());
        }
        self.require_supported()?;
        let observation = AffineObservation { input, output };
        if self.observations.contains(&observation) {
            return Ok(());
        }
        if !self.reserve_work(self.hypotheses.len()) {
            self.pending_observation = Some(observation);
            return Err("affine reasoning budget exhausted; observation not applied".into());
        }
        let retained: Vec<_> = self
            .hypotheses
            .iter()
            .filter(|strategy| strategy.predict_valid(input) == output)
            .cloned()
            .collect();
        if retained.is_empty() {
            self.status = AffineStatus::Contradicted;
            self.last_failure = Some("all affine hypotheses contradicted".into());
            self.pending_observation = Some(observation);
            return Err("all affine hypotheses contradicted; prior model bank unchanged".into());
        }
        self.hypotheses = retained;
        self.observations.push(observation);
        // A previously compatible hint becomes merely rejected data if later
        // observations disagree. It never prevents the evidence update.
        if self
            .hint
            .as_ref()
            .is_some_and(|strategy| strategy.predict_valid(input) != output)
        {
            self.hint = None;
        }
        Ok(())
    }

    /// None denotes unavailable support, never an empty impossibility proof.
    pub fn support(&mut self, input: u16) -> Result<Option<Vec<u8>>, String> {
        check_input(self.width, input)?;
        if self.status != AffineStatus::Supported || !self.reserve_work(self.hypotheses.len()) {
            return Ok(None);
        }
        let (mut zero, mut one) = (false, false);
        for hypothesis in &self.hypotheses {
            match hypothesis.predict_valid(input) {
                0 => zero = true,
                _ => one = true,
            }
        }
        let mut support = Vec::with_capacity(2);
        if zero {
            support.push(0);
        }
        if one {
            support.push(1);
        }
        Ok(Some(support))
    }

    /// Known and inferred singleton answers are both conditional on the model
    /// family. More than one possible output means explicit abstention.
    pub fn predict(&mut self, input: u16) -> Result<Option<u8>, String> {
        Ok(self.forecast(input)?.answer)
    }

    /// Preserve the distinction between direct observations, conditional
    /// inferences, unverified hypotheses, and unavailable reasoning support.
    pub fn forecast(&mut self, input: u16) -> Result<AffinePrediction, String> {
        let possible_outputs = self.support(input)?;
        let answer = possible_outputs
            .as_ref()
            .and_then(|support| (support.len() == 1).then(|| support[0]));
        let basis = match (&possible_outputs, answer) {
            (None, _) => PredictionBasis::Unavailable,
            (_, None) => PredictionBasis::Uncertain,
            (_, Some(_)) if self.observations.iter().any(|item| item.input == input) => {
                PredictionBasis::Observed
            }
            _ => PredictionBasis::Inferred,
        };
        Ok(AffinePrediction {
            input,
            possible_outputs,
            answer,
            basis,
            conditional_family: AFFINE_FAMILY,
            physical_certificate_authorized: false,
        })
    }

    /// Maximin information-seeking query: maximize min(zero_count,one_count).
    /// All candidate queries are scored exactly before any result is returned.
    /// The complete scan's cost is reserved up front, so a budget hit cannot
    /// silently select an approximately best query from a partial scan.
    pub fn choose_query(&mut self) -> Result<Option<u16>, String> {
        if self.status != AffineStatus::Supported || self.hypotheses.len() == 1 {
            return Ok(None);
        }
        let inputs: Vec<_> = (0..domain_size(self.width))
            .filter(|input| {
                !self
                    .observations
                    .iter()
                    .any(|observation| observation.input == *input)
            })
            .collect();
        if !self.reserve_work(inputs.len() * self.hypotheses.len()) {
            return Ok(None);
        }
        let mut best: Option<(usize, bool, u16)> = None;
        for input in inputs {
            let ones = self
                .hypotheses
                .iter()
                .filter(|hypothesis| hypothesis.predict_valid(input) == 1)
                .count();
            let worst_case_elimination = ones.min(self.hypotheses.len() - ones);
            if worst_case_elimination == 0 {
                continue;
            }
            let hint_positive = self
                .hint
                .as_ref()
                .is_some_and(|hint| hint.predict_valid(input) == 1);
            let score = (worst_case_elimination, hint_positive, u16::MAX - input);
            if best.is_none_or(|current| score > current) {
                best = Some(score);
            }
        }
        Ok(best.map(|(_, _, reversed_input)| u16::MAX - reversed_input))
    }

    /// Verify received knowledge against accepted evidence and complete support.
    /// Canonical affine functions are distinct: all completions agree with a
    /// candidate iff the single remaining canonical strategy equals it.
    pub fn assess_candidate(
        &mut self,
        strategy: &AffineStrategy,
    ) -> Result<CandidateAssessment, String> {
        if let Err(reason) = strategy.validate() {
            return Ok(CandidateAssessment::Rejected { reason });
        }
        if strategy.width != self.width {
            return Ok(CandidateAssessment::Rejected {
                reason: "candidate applicability/schema mismatch".into(),
            });
        }
        if self.status != AffineStatus::Supported || !self.reserve_work(self.observations.len()) {
            return Ok(CandidateAssessment::Unavailable {
                reason: self
                    .last_failure
                    .clone()
                    .unwrap_or_else(|| "affine support unavailable".into()),
            });
        }
        if self
            .observations
            .iter()
            .any(|observation| strategy.predict_valid(observation.input) != observation.output)
        {
            return Ok(CandidateAssessment::Rejected {
                reason: "candidate contradicted by genuine observations".into(),
            });
        }
        if self.identified().as_ref() == Some(strategy) {
            return Ok(CandidateAssessment::ConditionallyVerified {
                family: AFFINE_FAMILY,
                evidence_count: self.observations.len(),
            });
        }
        Ok(CandidateAssessment::Unverified {
            compatible_hypotheses: self.hypotheses.len(),
        })
    }

    fn require_supported(&self) -> Result<(), String> {
        if self.status != AffineStatus::Supported {
            return Err(format!("affine model unavailable: {:?}", self.status));
        }
        Ok(())
    }

    fn reserve_work(&mut self, count: usize) -> bool {
        if self.status != AffineStatus::Supported {
            return false;
        }
        let Some(total) = self.model_evaluations.checked_add(count) else {
            self.status = AffineStatus::BudgetExhausted;
            self.last_failure = Some("affine model-evaluation counter overflow".into());
            return false;
        };
        if total > self.max_model_evaluations {
            self.status = AffineStatus::BudgetExhausted;
            self.last_failure = Some("affine model-evaluation budget exhausted".into());
            return false;
        }
        self.model_evaluations = total;
        true
    }
}

fn check_width(width: u8) -> Result<(), String> {
    if !(1..=MAX_WIDTH).contains(&width) {
        return Err("Boolean affine width must be in 1..=8".into());
    }
    Ok(())
}

fn domain_size(width: u8) -> u16 {
    1 << width
}

fn check_input(width: u8, input: u16) -> Result<(), String> {
    if input >= domain_size(width) {
        return Err("input exceeds the declared Boolean schema".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUDGET: usize = 2_000_000;

    #[test]
    fn serialized_strategy_is_inert_validated_and_explicitly_scoped() {
        let strategy = AffineStrategy::new(3, 0b101, true).unwrap();
        let value = serde_json::to_value(&strategy).unwrap();
        assert_eq!(value["kind"], "affine");
        assert_eq!(
            serde_json::from_value::<AffineStrategy>(value).unwrap(),
            strategy
        );
        assert!(serde_json::from_str::<AffineStrategy>(
            r#"{"kind":"affine","width":9,"coefficients":0,"bias":false}"#,
        )
        .is_err());
        assert!(AffineStrategy::new(0, 0, false).is_err());
        assert!(AffineStrategy::new(2, 4, false).is_err());
        assert!(strategy.predict(8).is_err());
        assert!(serde_json::from_str::<AffineStrategy>(
            r#"{"kind":"execute","width":2,"coefficients":1,"bias":false}"#
        )
        .is_err());
    }

    #[test]
    fn all_small_affine_worlds_are_identified_in_exactly_width_plus_one_queries() {
        for width in 1..=5 {
            for coefficients in 0..domain_size(width) {
                for bias in [false, true] {
                    let truth = AffineStrategy::new(width, coefficients, bias).unwrap();
                    let mut learner = AffineLearner::new(width, BUDGET).unwrap();
                    assert_eq!(learner.hypothesis_count(), 1 << (width + 1));
                    let mut queries = 0;
                    while let Some(input) = learner.choose_query().unwrap() {
                        learner
                            .observe(input, truth.predict(input).unwrap())
                            .unwrap();
                        queries += 1;
                        assert!(queries <= usize::from(width) + 1);
                    }
                    assert_eq!(queries, usize::from(width) + 1);
                    assert_eq!(learner.identified(), Some(truth.clone()));
                    for input in 0..domain_size(width) {
                        assert_eq!(
                            learner.predict(input).unwrap(),
                            Some(truth.predict(input).unwrap())
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn maximum_width_is_bounded_and_generalizes_to_unobserved_inputs() {
        let truth = AffineStrategy::new(8, 0b1010_1101, true).unwrap();
        let mut learner = AffineLearner::new(8, BUDGET).unwrap();
        while let Some(input) = learner.choose_query().unwrap() {
            learner
                .observe(input, truth.predict(input).unwrap())
                .unwrap();
        }
        assert_eq!(learner.observations().len(), 9);
        assert_eq!(learner.identified(), Some(truth.clone()));
        let heldout: Vec<_> = (0..256)
            .filter(|input| !learner.observations().iter().any(|o| o.input == *input))
            .collect();
        assert_eq!(heldout.len(), 247);
        for input in heldout {
            assert_eq!(
                learner.predict(input).unwrap(),
                Some(truth.predict(input).unwrap())
            );
        }
    }

    #[test]
    fn hints_never_shrink_support_or_authorize_predictions() {
        let hint = AffineStrategy::new(3, 0b101, true).unwrap();
        let mut learner = AffineLearner::new(3, BUDGET).unwrap();
        learner.set_hint(&hint).unwrap();
        assert_eq!(learner.hypothesis_count(), 16);
        assert_eq!(learner.predict(5).unwrap(), None);
        assert_eq!(
            learner.assess_candidate(&hint).unwrap(),
            CandidateAssessment::Unverified {
                compatible_hypotheses: 16
            }
        );
        learner.observe(0, 0).unwrap();
        assert_eq!(learner.hypothesis_count(), 8);
        assert_eq!(learner.predict(0).unwrap(), Some(0));
        assert!(matches!(
            learner.assess_candidate(&hint).unwrap(),
            CandidateAssessment::Rejected { .. }
        ));
        assert!(learner.set_hint(&hint).is_err());
    }

    #[test]
    fn query_choice_is_maximin_exact_and_deterministic() {
        let mut learner = AffineLearner::new(3, BUDGET).unwrap();
        assert_eq!(learner.choose_query().unwrap(), Some(0));
        learner.observe(0, 0).unwrap();
        assert_eq!(learner.choose_query().unwrap(), Some(1));
        learner.observe(1, 1).unwrap();
        assert_eq!(learner.choose_query().unwrap(), Some(2));
        learner.observe(2, 0).unwrap();
        // Input 3 is known by affine closure, so it cannot reduce support.
        assert_eq!(learner.predict(3).unwrap(), Some(1));
        assert_eq!(learner.choose_query().unwrap(), Some(4));
    }

    #[test]
    fn observations_inferences_and_unverified_predictions_remain_distinct() {
        let mut learner = AffineLearner::new(3, BUDGET).unwrap();
        assert_eq!(
            learner.forecast(7).unwrap().basis,
            PredictionBasis::Uncertain
        );
        for (input, output) in [(0, 0), (1, 1), (2, 0)] {
            learner.observe(input, output).unwrap();
        }
        assert_eq!(
            learner.forecast(1).unwrap().basis,
            PredictionBasis::Observed
        );
        let prediction = learner.forecast(3).unwrap();
        assert_eq!(prediction.basis, PredictionBasis::Inferred);
        assert_eq!(prediction.answer, Some(1));
        assert_eq!(
            learner.forecast(7).unwrap().basis,
            PredictionBasis::Uncertain
        );
        assert!(!prediction.physical_certificate_authorized);
        assert_eq!(prediction.conditional_family, AFFINE_FAMILY);
    }

    #[test]
    fn wrong_family_and_conflicting_observations_disable_certificates_transactionally() {
        let mut learner = AffineLearner::new(2, BUDGET).unwrap();
        for (input, output) in [(0, 0), (1, 0), (2, 0)] {
            learner.observe(input, output).unwrap();
        }
        assert_eq!(
            learner.identified(),
            Some(AffineStrategy::new(2, 0, false).unwrap())
        );
        // AND matches three basis observations and fails on the fourth input.
        // Thus affine identification is conditional, never an open-world proof.
        let before = learner.hypothesis_count();
        assert!(learner.observe(3, 1).is_err());
        assert_eq!(learner.hypothesis_count(), before);
        assert_eq!(learner.observations().len(), 3);
        assert_eq!(learner.status(), &AffineStatus::Contradicted);
        assert_eq!(
            learner.snapshot().pending_observation,
            Some(AffineObservation {
                input: 3,
                output: 1
            })
        );
        assert_eq!(learner.predict(3).unwrap(), None);
        assert_eq!(learner.identified(), None);
        assert!(!learner.snapshot().physical_certificate_authorized);
    }

    #[test]
    fn budget_exhaustion_never_returns_a_partial_query_or_answer() {
        let mut learner = AffineLearner::new(8, 512).unwrap();
        let before = learner.hypothesis_count();
        assert_eq!(learner.choose_query().unwrap(), None);
        assert_eq!(learner.status(), &AffineStatus::BudgetExhausted);
        assert_eq!(learner.hypothesis_count(), before);
        assert_eq!(learner.predict(0).unwrap(), None);
        assert_eq!(learner.snapshot().model_evaluations, 0);

        let mut learner = AffineLearner::new(2, 7).unwrap();
        assert!(learner.observe(0, 1).is_err());
        assert_eq!(learner.hypothesis_count(), 8);
        assert!(learner.observations().is_empty());
        assert_eq!(
            learner.snapshot().pending_observation,
            Some(AffineObservation {
                input: 0,
                output: 1
            })
        );
    }

    #[test]
    fn only_full_support_can_conditionally_verify_received_strategy() {
        let strategy = AffineStrategy::new(3, 0b101, false).unwrap();
        let mut learner = AffineLearner::new(3, BUDGET).unwrap();
        for input in [0, 1, 2] {
            learner
                .observe(input, strategy.predict(input).unwrap())
                .unwrap();
        }
        assert!(matches!(
            learner.assess_candidate(&strategy).unwrap(),
            CandidateAssessment::Unverified {
                compatible_hypotheses: 2
            }
        ));
        learner.observe(4, strategy.predict(4).unwrap()).unwrap();
        assert_eq!(
            learner.assess_candidate(&strategy).unwrap(),
            CandidateAssessment::ConditionallyVerified {
                family: AFFINE_FAMILY,
                evidence_count: 4
            }
        );
        let different_width = AffineStrategy::new(2, 1, false).unwrap();
        assert!(matches!(
            learner.assess_candidate(&different_width).unwrap(),
            CandidateAssessment::Rejected { .. }
        ));
    }

    #[test]
    fn schema_remapping_requires_a_complete_bijection() {
        let source = AffineStrategy::new(3, 0b011, true).unwrap();
        let mapped = source.remap(&[2, 0, 1]).unwrap();
        assert_eq!(mapped, AffineStrategy::new(3, 0b101, true).unwrap());
        for source_input in 0..8 {
            let mut target_input = 0;
            for (source_bit, target_bit) in [2, 0, 1].iter().enumerate() {
                target_input |= ((source_input >> source_bit) & 1) << target_bit;
            }
            assert_eq!(
                source.predict(source_input).unwrap(),
                mapped.predict(target_input).unwrap()
            );
        }
        assert!(source.remap(&[0, 0, 1]).is_err());
        assert!(source.remap(&[0, 1]).is_err());
        assert!(source.remap(&[0, 1, 3]).is_err());
    }

    #[test]
    fn duplicate_evidence_is_bounded_and_invalid_requests_do_not_mutate_state() {
        let mut learner = AffineLearner::new(2, BUDGET).unwrap();
        learner.observe(0, 1).unwrap();
        let before = learner.snapshot();
        for _ in 0..1000 {
            learner.observe(0, 1).unwrap();
        }
        assert_eq!(learner.snapshot(), before);
        assert!(learner.observe(4, 0).is_err());
        assert!(learner.observe(0, 2).is_err());
        assert_eq!(learner.snapshot(), before);
        assert!(AffineLearner::new(9, BUDGET).is_err());
        assert!(AffineLearner::new(1, 0).is_err());
    }
}
