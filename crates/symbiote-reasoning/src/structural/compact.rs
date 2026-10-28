//! Exact affine support represented by independent GF(2) equations.
//!
//! Parameters are the width coefficient bits followed by the bias bit. An
//! observation contributes the equation `[input, 1] * parameters = output`.
//! Reduced row echelon form preserves the complete affine solution space:
//! rank r leaves exactly 2^(width+1-r) canonical strategies. A query is fixed
//! precisely when its row lies in the observed row span; otherwise each output
//! has exactly half the remaining support. No received hint changes the rows.
//!
//! This is an additive backend. The enumerating `AffineLearner` and its receipt
//! counters remain unchanged. GF(2) work units below are versioned logical
//! operations, not enumerated model evaluations, CPU instructions or wall time.

use super::{
    check_input, check_width, domain_size, AffineObservation, AffinePrediction, AffineStatus,
    AffineStrategy, CandidateAssessment, PredictionBasis, AFFINE_FAMILY, MAX_WIDTH,
};
use serde::Serialize;

const MAX_PARAMETERS: usize = MAX_WIDTH as usize + 1;
pub const SNAPSHOT_SCHEMA: &str = "symbiote.affine-gf2-snapshot/1";
pub const WORK_MODEL: &str = "gf2-row-operations/1";

/// One unit per basis-slot test, packed row XOR (including its RHS), stored
/// equation, scored query or strategy prediction. Administrative input/history
/// checks and extracting an identified strategy are not model-work operations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CompactAffineWork {
    pub row_checks: usize,
    pub row_xors: usize,
    pub row_insertions: usize,
    pub query_candidates: usize,
    pub strategy_predictions: usize,
}
impl CompactAffineWork {
    pub fn units(&self) -> usize {
        self.row_checks
            + self.row_xors
            + self.row_insertions
            + self.query_candidates
            + self.strategy_predictions
    }
    fn add(&mut self, other: Self) {
        self.row_checks += other.row_checks;
        self.row_xors += other.row_xors;
        self.row_insertions += other.row_insertions;
        self.query_candidates += other.query_candidates;
        self.strategy_predictions += other.strategy_predictions;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CompactAffineSnapshot {
    pub schema: &'static str,
    pub family: &'static str,
    pub work_model: &'static str,
    pub width: u8,
    pub status: AffineStatus,
    pub rank: usize,
    pub free_parameters: usize,
    pub hypotheses: usize,
    pub accepted_observations: usize,
    pub work_units: usize,
    pub work_unit_budget: usize,
    pub work: CompactAffineWork,
    pub conditional_strategy: Option<AffineStrategy>,
    pub last_failure: Option<String>,
    pub pending_observation: Option<AffineObservation>,
    pub physical_certificate_authorized: bool,
}

#[derive(Clone, Copy, Debug)]
struct Equation {
    row: u16,
    rhs: u8,
}

/// Exact finite affine inference using at most nine packed basis rows. Public
/// operations mirror the enumerator; selecting this type explicitly selects
/// the different work model. Supported widths remain 1..=8.
#[derive(Clone, Debug)]
pub struct CompactAffineLearner {
    width: u8,
    basis: [Option<Equation>; MAX_PARAMETERS],
    rank: usize,
    observations: Vec<AffineObservation>,
    work: CompactAffineWork,
    max_work_units: usize,
    status: AffineStatus,
    last_failure: Option<String>,
    pending_observation: Option<AffineObservation>,
    hint: Option<AffineStrategy>,
}
impl CompactAffineLearner {
    pub fn new(width: u8, max_work_units: usize) -> Result<Self, String> {
        check_width(width)?;
        if max_work_units == 0 {
            return Err("compact affine reasoning needs a positive GF(2) work budget".into());
        }
        Ok(Self {
            width,
            basis: [None; MAX_PARAMETERS],
            rank: 0,
            observations: Vec::new(),
            work: CompactAffineWork::default(),
            max_work_units,
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
    pub fn rank(&self) -> usize {
        self.rank
    }
    pub fn hypothesis_count(&self) -> usize {
        1 << (self.parameters() - self.rank)
    }
    pub fn observations(&self) -> &[AffineObservation] {
        &self.observations
    }
    pub fn snapshot(&self) -> CompactAffineSnapshot {
        CompactAffineSnapshot {
            schema: SNAPSHOT_SCHEMA,
            family: AFFINE_FAMILY,
            work_model: WORK_MODEL,
            width: self.width,
            status: self.status.clone(),
            rank: self.rank,
            free_parameters: self.parameters() - self.rank,
            hypotheses: self.hypothesis_count(),
            accepted_observations: self.observations.len(),
            work_units: self.work.units(),
            work_unit_budget: self.max_work_units,
            work: self.work,
            conditional_strategy: self.identified(),
            last_failure: self.last_failure.clone(),
            pending_observation: self.pending_observation.clone(),
            physical_certificate_authorized: false,
        }
    }
    pub fn set_hint(&mut self, strategy: &AffineStrategy) -> Result<(), String> {
        strategy.validate()?;
        if strategy.width != self.width {
            return Err("received hint has a different input schema".into());
        }
        if !self.admit(self.observations.len()) {
            return Err("compact affine reasoning unavailable while checking hint".into());
        }
        let mut work = CompactAffineWork::default();
        let contradicted = self.observations.iter().any(|observation| {
            work.strategy_predictions += 1;
            strategy.predict_valid(observation.input) != observation.output
        });
        self.work.add(work);
        if contradicted {
            return Err("received hint contradicts accepted observations".into());
        }
        self.hint = Some(strategy.clone());
        Ok(())
    }
    pub fn clear_hint(&mut self) {
        self.hint = None;
    }
    pub fn identified(&self) -> Option<AffineStrategy> {
        if self.status != AffineStatus::Supported || self.rank != self.parameters() {
            return None;
        }
        // Full-rank RREF is the identity matrix, so the RHS bits are the parameters.
        let mut coefficients = 0;
        for bit in 0..usize::from(self.width) {
            coefficients |= u16::from(self.basis[bit]?.rhs) << bit;
        }
        Some(AffineStrategy {
            width: self.width,
            coefficients,
            bias: self.basis[usize::from(self.width)]?.rhs == 1,
        })
    }
    pub fn observe(&mut self, input: u16, output: u8) -> Result<(), String> {
        check_input(self.width, input)?;
        if output > 1 {
            return Err("affine observation must publish one binary output".into());
        }
        if self.status != AffineStatus::Supported {
            return Err(format!("affine model unavailable: {:?}", self.status));
        }
        let observation = AffineObservation { input, output };
        if self.observations.contains(&observation) {
            return Ok(());
        }
        // Reserve a worst-case bound before any elimination or state update.
        // Actual counters below record only operations that really ran.
        if !self.admit(4 * self.parameters() + 1 + usize::from(self.hint.is_some())) {
            self.pending_observation = Some(observation);
            return Err("compact affine budget exhausted; observation not applied".into());
        }
        let mut work = CompactAffineWork::default();
        let reduced = self.reduce(self.query_row(input), output, &mut work);
        if reduced.row == 0 && reduced.rhs == 1 {
            self.work.add(work);
            self.status = AffineStatus::Contradicted;
            self.last_failure = Some("all affine hypotheses contradicted".into());
            self.pending_observation = Some(observation);
            return Err("all affine hypotheses contradicted; prior model bank unchanged".into());
        }
        if reduced.row != 0 {
            let pivot = reduced.row.trailing_zeros() as usize;
            let mut next = self.basis;
            for slot in next.iter_mut().take(self.parameters()) {
                work.row_checks += 1;
                if let Some(equation) = slot {
                    if equation.row & (1 << pivot) != 0 {
                        equation.row ^= reduced.row;
                        equation.rhs ^= reduced.rhs;
                        work.row_xors += 1;
                    }
                }
            }
            next[pivot] = Some(reduced);
            work.row_insertions += 1;
            self.basis = next;
            self.rank += 1;
        }
        self.observations.push(observation);
        if let Some(hint) = &self.hint {
            work.strategy_predictions += 1;
            if hint.predict_valid(input) != output {
                self.hint = None;
            }
        }
        self.work.add(work);
        Ok(())
    }
    /// Exact cardinalities for each output. Unavailable reasoning returns None;
    /// a contradictory observation never exposes an empty support certificate.
    pub fn support_counts(&mut self, input: u16) -> Result<Option<[usize; 2]>, String> {
        check_input(self.width, input)?;
        if !self.admit(2 * self.parameters()) {
            return Ok(None);
        }
        let mut work = CompactAffineWork::default();
        let reduced = self.reduce(self.query_row(input), 0, &mut work);
        self.work.add(work);
        let count = self.hypothesis_count();
        Ok(Some(if reduced.row == 0 {
            if reduced.rhs == 0 {
                [count, 0]
            } else {
                [0, count]
            }
        } else {
            [count / 2, count / 2]
        }))
    }
    pub fn support(&mut self, input: u16) -> Result<Option<Vec<u8>>, String> {
        Ok(self.support_counts(input)?.map(|counts| {
            (0..2)
                .filter(|output| counts[usize::from(*output)] > 0)
                .collect()
        }))
    }
    pub fn predict(&mut self, input: u16) -> Result<Option<u8>, String> {
        Ok(self.forecast(input)?.answer)
    }
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
    pub fn choose_query(&mut self) -> Result<Option<u16>, String> {
        if self.status != AffineStatus::Supported || self.hypothesis_count() == 1 {
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
        let bound = inputs.len() * (2 * self.parameters() + 1 + usize::from(self.hint.is_some()));
        if !self.admit(bound) {
            return Ok(None);
        }
        let mut work = CompactAffineWork::default();
        let mut best = None;
        for input in inputs {
            work.query_candidates += 1;
            if self.reduce(self.query_row(input), 0, &mut work).row == 0 {
                continue;
            }
            // A nonzero linear functional partitions a finite affine solution
            // space into exactly equal halves. Every informative query is tied.
            let hint_positive = self.hint.as_ref().is_some_and(|hint| {
                work.strategy_predictions += 1;
                hint.predict_valid(input) == 1
            });
            let score = (self.hypothesis_count() / 2, hint_positive, u16::MAX - input);
            if best.is_none_or(|current| score > current) {
                best = Some(score);
            }
        }
        self.work.add(work);
        Ok(best.map(|(_, _, reversed)| u16::MAX - reversed))
    }
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
        if !self.admit(self.observations.len()) {
            return Ok(CandidateAssessment::Unavailable {
                reason: self
                    .last_failure
                    .clone()
                    .unwrap_or_else(|| "affine support unavailable".into()),
            });
        }
        let mut work = CompactAffineWork::default();
        let contradicted = self.observations.iter().any(|observation| {
            work.strategy_predictions += 1;
            strategy.predict_valid(observation.input) != observation.output
        });
        self.work.add(work);
        if contradicted {
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
            compatible_hypotheses: self.hypothesis_count(),
        })
    }
    fn parameters(&self) -> usize {
        usize::from(self.width) + 1
    }
    fn query_row(&self, input: u16) -> u16 {
        input | (1 << self.width)
    }
    fn reduce(&self, mut row: u16, mut rhs: u8, work: &mut CompactAffineWork) -> Equation {
        for pivot in 0..self.parameters() {
            work.row_checks += 1;
            if row & (1 << pivot) != 0 {
                if let Some(equation) = self.basis[pivot] {
                    row ^= equation.row;
                    rhs ^= equation.rhs;
                    work.row_xors += 1;
                }
            }
        }
        Equation { row, rhs }
    }
    fn admit(&mut self, upper_bound: usize) -> bool {
        if self.status != AffineStatus::Supported {
            return false;
        }
        if self
            .work
            .units()
            .checked_add(upper_bound)
            .is_none_or(|total| total > self.max_work_units)
        {
            self.status = AffineStatus::BudgetExhausted;
            self.last_failure =
                Some("compact affine GF(2) work budget exhausted before operation".into());
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structural::AffineLearner;

    const BUDGET: usize = 1_000_000_000;

    fn semantic_parity(reference: &AffineLearner, compact: &CompactAffineLearner, full: bool) {
        assert_eq!(reference.width(), compact.width());
        assert_eq!(reference.status(), compact.status());
        assert_eq!(reference.hypothesis_count(), compact.hypothesis_count());
        assert_eq!(reference.observations(), compact.observations());
        assert_eq!(reference.identified(), compact.identified());
        assert_eq!(
            compact.hypothesis_count(),
            1 << (usize::from(compact.width()) + 1 - compact.rank())
        );
        let mut reference_query = reference.clone();
        let mut compact_query = compact.clone();
        assert_eq!(
            reference_query.choose_query().unwrap(),
            compact_query.choose_query().unwrap()
        );
        let width = compact.width();
        let inputs: Vec<_> = if full {
            (0..domain_size(width)).collect()
        } else {
            vec![
                0,
                1,
                domain_size(width) - 1,
                (compact.observations().len() as u16 * 7) % domain_size(width),
            ]
        };
        for input in inputs {
            let mut reference = reference.clone();
            let mut compact = compact.clone();
            assert_eq!(
                reference.forecast(input).unwrap(),
                compact.forecast(input).unwrap()
            );
            if reference.status() == &AffineStatus::Supported {
                let mut counts = [0; 2];
                for hypothesis in &reference.hypotheses {
                    counts[usize::from(hypothesis.predict_valid(input))] += 1;
                }
                assert_eq!(compact.support_counts(input).unwrap(), Some(counts));
            } else {
                assert_eq!(compact.support_counts(input).unwrap(), None);
            }
        }
        let candidates: Vec<_> = if full {
            (0..domain_size(width))
                .flat_map(|coefficients| {
                    [false, true]
                        .map(move |bias| AffineStrategy::new(width, coefficients, bias).unwrap())
                })
                .collect()
        } else {
            [0, domain_size(width) - 1]
                .into_iter()
                .flat_map(|coefficients| {
                    [false, true]
                        .map(move |bias| AffineStrategy::new(width, coefficients, bias).unwrap())
                })
                .collect()
        };
        for candidate in candidates {
            let mut reference = reference.clone();
            let mut compact = compact.clone();
            assert_eq!(
                reference.assess_candidate(&candidate).unwrap(),
                compact.assess_candidate(&candidate).unwrap()
            );
            if reference.status() == &AffineStatus::Supported {
                assert_eq!(
                    reference.set_hint(&candidate).is_ok(),
                    compact.set_hint(&candidate).is_ok()
                );
                assert_eq!(
                    reference.choose_query().unwrap(),
                    compact.choose_query().unwrap()
                );
                reference.clear_hint();
                compact.clear_hint();
                assert_eq!(
                    reference.choose_query().unwrap(),
                    compact.choose_query().unwrap()
                );
            }
        }
        assert!(!compact.snapshot().physical_certificate_authorized);
    }

    fn all_histories(
        reference: AffineLearner,
        compact: CompactAffineLearner,
        depth: usize,
        checked: &mut usize,
    ) {
        semantic_parity(&reference, &compact, true);
        *checked += 1;
        if depth == 0 || reference.status() != &AffineStatus::Supported {
            return;
        }
        for input in 0..domain_size(reference.width()) {
            for output in 0..=1 {
                let mut reference = reference.clone();
                let mut compact = compact.clone();
                assert_eq!(
                    reference.observe(input, output).is_ok(),
                    compact.observe(input, output).is_ok()
                );
                all_histories(reference, compact, depth - 1, checked);
            }
        }
    }

    #[test]
    fn exhaustive_small_histories_match_enumeration_including_dependence_and_contradictions() {
        let mut checked = 0;
        for (width, depth) in [(1, 4), (2, 4), (3, 3)] {
            all_histories(
                AffineLearner::new(width, BUDGET).unwrap(),
                CompactAffineLearner::new(width, BUDGET).unwrap(),
                depth,
                &mut checked,
            );
        }
        assert!(checked > 1_000);
    }

    #[test]
    fn every_canonical_world_at_all_supported_widths_has_identical_queries_and_predictions() {
        for width in 1..=MAX_WIDTH {
            for coefficients in 0..domain_size(width) {
                for bias in [false, true] {
                    let truth = AffineStrategy::new(width, coefficients, bias).unwrap();
                    let mut reference = AffineLearner::new(width, BUDGET).unwrap();
                    let mut compact = CompactAffineLearner::new(width, BUDGET).unwrap();
                    let mut queries = 0;
                    loop {
                        let expected = reference.choose_query().unwrap();
                        assert_eq!(compact.choose_query().unwrap(), expected);
                        let Some(input) = expected else {
                            break;
                        };
                        let output = truth.predict(input).unwrap();
                        reference.observe(input, output).unwrap();
                        compact.observe(input, output).unwrap();
                        assert_eq!(reference.hypothesis_count(), compact.hypothesis_count());
                        queries += 1;
                        assert!(queries <= usize::from(width) + 1);
                    }
                    assert_eq!(queries, usize::from(width) + 1);
                    assert_eq!(compact.identified(), Some(truth.clone()));
                    for input in 0..domain_size(width) {
                        assert_eq!(
                            reference.forecast(input).unwrap(),
                            compact.forecast(input).unwrap()
                        );
                        assert_eq!(
                            compact.predict(input).unwrap(),
                            Some(truth.predict(input).unwrap())
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn generated_arbitrary_histories_and_hint_ties_match_the_reference_through_width_eight() {
        let mut random = 0x5eeda11f_u64;
        for width in 1..=MAX_WIDTH {
            for seed in 0..24 {
                let truth =
                    AffineStrategy::new(width, (seed * 17 + 3) % domain_size(width), seed % 2 == 0)
                        .unwrap();
                let hint = AffineStrategy::new(width, truth.coefficients ^ 1, !truth.bias).unwrap();
                let mut reference = AffineLearner::new(width, BUDGET).unwrap();
                let mut compact = CompactAffineLearner::new(width, BUDGET).unwrap();
                reference.set_hint(&hint).unwrap();
                compact.set_hint(&hint).unwrap();
                for _ in 0..20 {
                    semantic_parity(&reference, &compact, false);
                    random = random
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    let input = ((random >> 32) as u16) % domain_size(width);
                    let output = truth.predict(input).unwrap();
                    reference.observe(input, output).unwrap();
                    compact.observe(input, output).unwrap();
                    // Repeated identical evidence must not spend work or change rank.
                    let before = compact.snapshot();
                    compact.observe(input, output).unwrap();
                    assert_eq!(compact.snapshot(), before);
                }
                let first = compact.observations()[0].clone();
                let before = compact.snapshot();
                assert!(reference.observe(first.input, first.output ^ 1).is_err());
                assert!(compact.observe(first.input, first.output ^ 1).is_err());
                assert_eq!(compact.snapshot().rank, before.rank);
                assert_eq!(compact.snapshot().hypotheses, before.hypotheses);
                assert_eq!(compact.observations().len(), before.accepted_observations);
                semantic_parity(&reference, &compact, false);
                let failed = compact.snapshot();
                assert!(compact.observe(0, 0).is_err());
                assert_eq!(compact.snapshot(), failed);
            }
        }
    }

    #[test]
    fn compact_budget_failures_are_transactional_and_keep_a_separate_work_model() {
        assert!(CompactAffineLearner::new(0, 100).is_err());
        assert!(CompactAffineLearner::new(9, 100).is_err());
        assert!(CompactAffineLearner::new(1, 0).is_err());
        let mut query = CompactAffineLearner::new(8, 1).unwrap();
        assert_eq!(query.choose_query().unwrap(), None);
        assert_eq!(query.status(), &AffineStatus::BudgetExhausted);
        assert_eq!(query.snapshot().work_units, 0);
        assert_eq!(query.hypothesis_count(), 512);
        assert_eq!(query.predict(0).unwrap(), None);
        let mut update = CompactAffineLearner::new(2, 1).unwrap();
        assert!(update.observe(0, 1).is_err());
        assert_eq!(update.hypothesis_count(), 8);
        assert!(update.observations().is_empty());
        assert_eq!(
            update.snapshot().pending_observation,
            Some(AffineObservation {
                input: 0,
                output: 1
            })
        );
        let mut learner = CompactAffineLearner::new(3, 10_000).unwrap();
        learner.observe(0, 0).unwrap();
        let snapshot = learner.snapshot();
        assert_eq!(snapshot.schema, SNAPSHOT_SCHEMA);
        assert_eq!(snapshot.work_model, WORK_MODEL);
        assert_eq!(snapshot.work_units, snapshot.work.units());
        assert_eq!(snapshot.work.row_checks, 8);
        assert_eq!(snapshot.work.row_insertions, 1);
        let value = serde_json::to_value(&snapshot).unwrap();
        assert!(value.get("model_evaluations").is_none());
        assert!(value.get("model_evaluation_budget").is_none());
        assert!(learner.observe(16, 0).is_err());
        assert!(learner.observe(0, 2).is_err());
        assert_eq!(learner.snapshot(), snapshot);
        // The historical enumerator receipt shape is untouched.
        let legacy =
            serde_json::to_value(AffineLearner::new(3, BUDGET).unwrap().snapshot()).unwrap();
        assert!(legacy.get("model_evaluations").is_some());
        assert!(legacy.get("work_model").is_none());
    }

    #[test]
    fn observed_inferred_and_unknown_answers_remain_distinct_and_conditional() {
        let mut learner = CompactAffineLearner::new(3, BUDGET).unwrap();
        learner
            .set_hint(&AffineStrategy::new(3, 5, true).unwrap())
            .unwrap();
        assert_eq!(learner.hypothesis_count(), 16);
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
        let inferred = learner.forecast(3).unwrap();
        assert_eq!(inferred.basis, PredictionBasis::Inferred);
        assert_eq!(inferred.answer, Some(1));
        assert_eq!(inferred.conditional_family, AFFINE_FAMILY);
        assert!(!inferred.physical_certificate_authorized);
        assert_eq!(learner.choose_query().unwrap(), Some(4));
    }

    #[test]
    fn bounded_backend_comparison_reports_distinct_work_models_and_measured_time() {
        use std::hint::black_box;
        use std::time::Instant;
        let runs = 16;
        let mut legacy_work = 0;
        let started = Instant::now();
        for index in 0..runs {
            let truth = AffineStrategy::new(8, black_box(index * 11), index % 2 == 0).unwrap();
            let mut learner = AffineLearner::new(8, BUDGET).unwrap();
            while let Some(input) = learner.choose_query().unwrap() {
                learner
                    .observe(input, truth.predict(input).unwrap())
                    .unwrap();
            }
            assert_eq!(learner.identified(), Some(truth));
            legacy_work += learner.snapshot().model_evaluations;
        }
        let legacy_microseconds = started.elapsed().as_micros();
        let mut compact_work = 0;
        let started = Instant::now();
        for index in 0..runs {
            let truth = AffineStrategy::new(8, black_box(index * 11), index % 2 == 0).unwrap();
            let mut learner = CompactAffineLearner::new(8, BUDGET).unwrap();
            while let Some(input) = learner.choose_query().unwrap() {
                learner
                    .observe(input, truth.predict(input).unwrap())
                    .unwrap();
            }
            assert_eq!(learner.identified(), Some(truth));
            compact_work += learner.snapshot().work_units;
        }
        let compact_microseconds = started.elapsed().as_micros();
        println!(
            "{}",
            serde_json::json!({"schema":"symbiote.affine-backend-comparison/1","width":8,"runs":runs,
            "reference":{"work_field":"legacy AffineSnapshot.model_evaluations","units":legacy_work,"elapsed_microseconds":legacy_microseconds},
            "compact":{"work_model":WORK_MODEL,"units":compact_work,"elapsed_microseconds":compact_microseconds},
            "interpretation":"engineering microbenchmark; logical units are not interchangeable; no agent-learning or general speedup claim"})
        );
    }
}
