//! Prospective value of one proposed knowledge exchange.
//!
//! `U = expected_gain - transfer_cost - verification_cost - regression_risk`
//! is computed separately in each participant's own declared units. Those units
//! are never added together. A connection decision is not an authorization;
//! operator grants remain external. No result here is a convergence or
//! generality claim.

use crate::structural::{AffineLearner, AffineStrategy, CandidateAssessment};
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "symbiote.value-of-symbiosis/1";
const REPEATED_NEGATIVE_LIMIT: u64 = 3;

/// Costs and a prospective gain already expressed in one participant's units.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeTerms {
    pub expected_gain: u64,
    pub transfer_cost: u64,
    pub verification_cost: u64,
    pub regression_risk: u64,
}

impl ExchangeTerms {
    pub fn utility(self) -> Result<i128, String> {
        let gain = i128::from(self.expected_gain);
        let cost = i128::from(self.transfer_cost)
            .checked_add(i128::from(self.verification_cost))
            .and_then(|sum| sum.checked_add(i128::from(self.regression_risk)))
            .ok_or("exchange costs overflow the value-of-symbiosis integer")?;
        gain.checked_sub(cost)
            .ok_or_else(|| "exchange utility overflow".into())
    }
}

/// Constrained choices. None of these grants network access or trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SymbiosisDecision {
    Connect,
    Observe,
    RequestKnowledge,
    OfferKnowledge,
    Experiment,
    Defer,
    Abstain,
    Disconnect,
}

impl SymbiosisDecision {
    /// Knowledge leaves the caller only for a reciprocal, request, or offer choice.
    /// An experiment stays local. Abstention, deferral, observation and
    /// disconnection do not transfer a payload.
    pub fn exchanges_knowledge(self) -> bool {
        matches!(
            self,
            Self::Connect | Self::RequestKnowledge | Self::OfferKnowledge
        )
    }
}

/// What one participant can actually support before an exchange.
///
/// `authorization_present` records an operator grant that already exists.
/// This view cannot create one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParticipantView {
    pub terms: ExchangeTerms,
    pub evidence_complete: bool,
    pub prior_negative_exchanges: u64,
    pub authorization_present: bool,
    pub local_has_unshared_evidence: bool,
    pub remote_has_unshared_evidence: bool,
    pub discriminating_experiment_available: bool,
}

/// Choose the next constrained action from measured participant-specific terms.
pub fn decide(
    local: ParticipantView,
    remote: Option<ParticipantView>,
) -> Result<SymbiosisDecision, String> {
    if !local.authorization_present {
        return Ok(SymbiosisDecision::Abstain);
    }
    if !local.evidence_complete {
        if local.prior_negative_exchanges >= REPEATED_NEGATIVE_LIMIT {
            return Ok(SymbiosisDecision::Disconnect);
        }
        return Ok(if local.discriminating_experiment_available {
            SymbiosisDecision::Experiment
        } else {
            SymbiosisDecision::Observe
        });
    }
    let local_utility = local.terms.utility()?;
    if local_utility < 0 {
        return Ok(
            if local.prior_negative_exchanges + 1 >= REPEATED_NEGATIVE_LIMIT {
                SymbiosisDecision::Disconnect
            } else {
                SymbiosisDecision::Defer
            },
        );
    }
    if local_utility == 0 {
        return Ok(SymbiosisDecision::Defer);
    }
    let Some(remote) = remote.filter(|remote| remote.evidence_complete) else {
        return Ok(
            if local.remote_has_unshared_evidence && !local.local_has_unshared_evidence {
                SymbiosisDecision::RequestKnowledge
            } else {
                SymbiosisDecision::Observe
            },
        );
    };
    let remote_utility = remote.terms.utility()?;
    if remote_utility < 0 {
        return Ok(SymbiosisDecision::Defer);
    }
    if remote_utility > 0 && local.local_has_unshared_evidence && local.remote_has_unshared_evidence
    {
        return Ok(SymbiosisDecision::Connect);
    }
    if local.local_has_unshared_evidence && !local.remote_has_unshared_evidence {
        return Ok(SymbiosisDecision::OfferKnowledge);
    }
    if remote_utility > 0
        && local.remote_has_unshared_evidence
        && !local.local_has_unshared_evidence
    {
        return Ok(SymbiosisDecision::RequestKnowledge);
    }
    if local.discriminating_experiment_available {
        return Ok(SymbiosisDecision::Experiment);
    }
    Ok(SymbiosisDecision::Defer)
}

/// Mutual-benefit floor. Zero is nonnegative and is not research success.
pub fn mutually_nonnegative(local_net: i128, remote_net: i128) -> bool {
    local_net >= 0 && remote_net >= 0
}

/// Research success requires a strict gain for every participant.
pub fn research_success(local_net: i128, remote_net: i128) -> bool {
    local_net > 0 && remote_net > 0
}

/// Oracle-query accounting for one affine target under four selection rules.
///
/// A hint may break ties inside `AffineLearner::choose_query`. It is not
/// allowed to shrink support or to certify a prediction. Fixed basis order is
/// the cheap isolated control: input 0, then each standard basis vector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrategyIdentification {
    pub coefficients: u16,
    pub bias: bool,
    pub independent_queries: usize,
    pub fixed_basis_queries: usize,
    pub hinted_queries: usize,
    pub wrong_hint_queries: usize,
    pub independent_inputs: Vec<u16>,
    pub hinted_inputs: Vec<u16>,
    pub hypotheses_before_hint: usize,
    pub hypotheses_after_hint: usize,
    pub truth_certified: bool,
    pub wrong_hint_certified: bool,
    pub hint_unverified_before_observations: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AffineExchangeMeasurement {
    pub width: u8,
    pub strategies: usize,
    pub rows: Vec<StrategyIdentification>,
    pub independent_oracle_queries: usize,
    pub fixed_basis_oracle_queries: usize,
    pub hinted_oracle_queries: usize,
    pub wrong_hint_oracle_queries: usize,
    pub incorrect_certificates: usize,
    pub hint_changed_any_query_sequence: bool,
    pub hint_reduced_any_oracle_count: bool,
}

enum Mode<'a> {
    Independent,
    FixedBasis,
    Hint(&'a AffineStrategy),
    WrongHint(&'a AffineStrategy),
}

/// Enumerate every canonical affine truth of `width` and count oracle queries.
///
/// This is a mechanism measurement. It is not a preregistered transfer cohort.
pub fn measure_affine_exchange(width: u8) -> Result<AffineExchangeMeasurement, String> {
    let domain = 1_u16
        .checked_shl(u32::from(width))
        .ok_or("affine width exceeds the measurement domain")?;
    let mut rows = Vec::new();
    for coefficients in 0..domain {
        for bias in [false, true] {
            let truth = AffineStrategy::new(width, coefficients, bias)?;
            let wrong = AffineStrategy::new(width, coefficients, !bias)?;
            let (independent_queries, independent_inputs, _, _) = run(&truth, Mode::Independent)?;
            let (fixed_basis_queries, _, _, _) = run(&truth, Mode::FixedBasis)?;
            let (hinted_queries, hinted_inputs, before, after) = run(&truth, Mode::Hint(&truth))?;
            let (wrong_hint_queries, _, _, _) = run(&truth, Mode::WrongHint(&wrong))?;
            rows.push(StrategyIdentification {
                coefficients,
                bias,
                independent_queries,
                fixed_basis_queries,
                hinted_queries,
                wrong_hint_queries,
                independent_inputs,
                hinted_inputs,
                hypotheses_before_hint: before,
                hypotheses_after_hint: after,
                // `run` returns only after the conditional certificate equals the fixture.
                truth_certified: true,
                // A bias-flipped hint is a different strategy, so certifying the truth
                // did not certify that hint.
                wrong_hint_certified: false,
                hint_unverified_before_observations: hint_stays_unverified(&truth)?,
            });
        }
    }
    let incorrect_certificates = rows
        .iter()
        .filter(|row| !row.truth_certified || row.wrong_hint_certified)
        .count();
    Ok(AffineExchangeMeasurement {
        width,
        strategies: rows.len(),
        independent_oracle_queries: rows.iter().map(|row| row.independent_queries).sum(),
        fixed_basis_oracle_queries: rows.iter().map(|row| row.fixed_basis_queries).sum(),
        hinted_oracle_queries: rows.iter().map(|row| row.hinted_queries).sum(),
        wrong_hint_oracle_queries: rows.iter().map(|row| row.wrong_hint_queries).sum(),
        hint_changed_any_query_sequence: rows
            .iter()
            .any(|row| row.independent_inputs != row.hinted_inputs),
        hint_reduced_any_oracle_count: rows.iter().any(|row| {
            row.hinted_queries < row.independent_queries
                || row.hinted_queries < row.fixed_basis_queries
        }),
        rows,
        incorrect_certificates,
    })
}

fn hint_stays_unverified(truth: &AffineStrategy) -> Result<bool, String> {
    let mut learner = AffineLearner::new(truth.width, 1_000_000)?;
    learner.set_hint(truth)?;
    Ok(matches!(
        learner.assess_candidate(truth)?,
        CandidateAssessment::Unverified { .. }
    ))
}

fn run(truth: &AffineStrategy, mode: Mode<'_>) -> Result<(usize, Vec<u16>, usize, usize), String> {
    let mut learner = AffineLearner::new(truth.width, 1_000_000)?;
    let before = learner.hypothesis_count();
    match mode {
        Mode::Hint(hint) | Mode::WrongHint(hint) => learner.set_hint(hint)?,
        Mode::Independent | Mode::FixedBasis => {}
    }
    let after = learner.hypothesis_count();
    if !matches!(mode, Mode::Independent | Mode::FixedBasis) && after != before {
        return Err("received hint changed exact affine support before any observation".into());
    }
    let mut inputs = Vec::new();
    while learner.identified().is_none() {
        if inputs.len() > usize::from(truth.width) + 8 {
            return Err("affine identification exceeded the information-bound window".into());
        }
        let input = match mode {
            Mode::FixedBasis => next_basis(&inputs, truth.width)?,
            _ => learner
                .choose_query()?
                .ok_or("affine query abstained before a conditional certificate")?,
        };
        learner.observe(input, truth.predict(input)?)?;
        inputs.push(input);
    }
    if learner.identified().as_ref() != Some(truth) {
        return Err(
            "affine identification certified a strategy other than the fixture truth".into(),
        );
    }
    Ok((inputs.len(), inputs, before, after))
}

fn next_basis(used: &[u16], width: u8) -> Result<u16, String> {
    let mut candidates = vec![0];
    for bit in 0..width {
        candidates.push(1_u16 << bit);
    }
    candidates
        .into_iter()
        .find(|input| !used.contains(input))
        .ok_or_else(|| "fixed basis control ran out of coordinate queries".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(gain: u64, negative: u64, authorized: bool) -> ParticipantView {
        ParticipantView {
            terms: ExchangeTerms {
                expected_gain: gain,
                transfer_cost: 1,
                verification_cost: 1,
                regression_risk: 1,
            },
            evidence_complete: true,
            prior_negative_exchanges: negative,
            authorization_present: authorized,
            local_has_unshared_evidence: true,
            remote_has_unshared_evidence: true,
            discriminating_experiment_available: false,
        }
    }

    #[test]
    fn utility_is_gain_minus_three_costs_in_one_participants_units() {
        let terms = ExchangeTerms {
            expected_gain: 10,
            transfer_cost: 2,
            verification_cost: 3,
            regression_risk: 4,
        };
        assert_eq!(terms.utility().unwrap(), 1);
        assert!(
            ExchangeTerms {
                expected_gain: 0,
                transfer_cost: u64::MAX,
                verification_cost: u64::MAX,
                regression_risk: u64::MAX,
            }
            .utility()
            .unwrap()
                < 0
        );
    }

    #[test]
    fn decisions_cover_the_constrained_action_set() {
        assert_eq!(
            decide(view(10, 0, false), None).unwrap(),
            SymbiosisDecision::Abstain
        );
        let mut incomplete = view(10, 0, true);
        incomplete.evidence_complete = false;
        assert_eq!(
            decide(incomplete, None).unwrap(),
            SymbiosisDecision::Observe
        );
        incomplete.discriminating_experiment_available = true;
        assert_eq!(
            decide(incomplete, None).unwrap(),
            SymbiosisDecision::Experiment
        );
        incomplete.discriminating_experiment_available = false;
        incomplete.prior_negative_exchanges = 3;
        assert_eq!(
            decide(incomplete, None).unwrap(),
            SymbiosisDecision::Disconnect
        );

        let mut negative = view(0, 0, true);
        negative.terms.expected_gain = 0;
        assert_eq!(
            decide(negative, Some(negative)).unwrap(),
            SymbiosisDecision::Defer
        );
        negative.prior_negative_exchanges = 2;
        assert_eq!(
            decide(negative, Some(negative)).unwrap(),
            SymbiosisDecision::Disconnect
        );

        let zero = view(3, 0, true);
        assert_eq!(zero.terms.utility().unwrap(), 0);
        assert_eq!(
            decide(zero, Some(view(10, 0, true))).unwrap(),
            SymbiosisDecision::Defer
        );

        let good = view(10, 0, true);
        assert_eq!(
            decide(good, Some(good)).unwrap(),
            SymbiosisDecision::Connect
        );
        assert!(SymbiosisDecision::Connect.exchanges_knowledge());
        assert!(!SymbiosisDecision::Defer.exchanges_knowledge());
        assert!(!SymbiosisDecision::Experiment.exchanges_knowledge());

        let mut offer = good;
        offer.remote_has_unshared_evidence = false;
        assert_eq!(
            decide(offer, Some(good)).unwrap(),
            SymbiosisDecision::OfferKnowledge
        );
        let mut request = good;
        request.local_has_unshared_evidence = false;
        assert_eq!(
            decide(request, Some(good)).unwrap(),
            SymbiosisDecision::RequestKnowledge
        );
        assert_eq!(
            decide(offer, None).unwrap(),
            SymbiosisDecision::Observe,
            "an unmeasured partner is not pushed an offer"
        );
        assert_eq!(
            decide(request, None).unwrap(),
            SymbiosisDecision::RequestKnowledge
        );

        let mut harmful = good;
        harmful.terms.expected_gain = 0;
        assert_eq!(
            decide(good, Some(harmful)).unwrap(),
            SymbiosisDecision::Defer
        );
        assert!(!research_success(0, 5));
        assert!(mutually_nonnegative(0, 5));
        assert!(research_success(1, 2));
        assert!(!research_success(1, -1));
    }

    #[test]
    fn width3_hints_do_not_beat_the_fixed_basis_control() {
        let measured = measure_affine_exchange(3).unwrap();
        assert_eq!(measured.strategies, 16);
        assert_eq!(measured.incorrect_certificates, 0);
        let bound = 4;
        assert!(measured.rows.iter().all(|row| {
            row.independent_queries == bound
                && row.fixed_basis_queries == bound
                && row.hinted_queries == bound
                && row.wrong_hint_queries == bound
                && row.hypotheses_before_hint == row.hypotheses_after_hint
                && row.hypotheses_before_hint == 16
                && row.truth_certified
                && !row.wrong_hint_certified
                && row.hint_unverified_before_observations
        }));
        assert!(!measured.hint_reduced_any_oracle_count);
        assert_eq!(measured.independent_oracle_queries, 64);
        assert_eq!(measured.fixed_basis_oracle_queries, 64);
        assert_eq!(measured.hinted_oracle_queries, 64);
        assert_eq!(measured.wrong_hint_oracle_queries, 64);
        let terms = ExchangeTerms {
            expected_gain: 0,
            transfer_cost: u64::try_from(measured.strategies).unwrap(),
            verification_cost: u64::try_from(measured.strategies).unwrap(),
            regression_risk: 0,
        };
        assert!(terms.utility().unwrap() < 0);
        let mut local = view(0, 0, true);
        local.terms = terms;
        assert_eq!(
            decide(local, Some(local)).unwrap(),
            SymbiosisDecision::Defer
        );
        assert!(!decide(local, Some(local)).unwrap().exchanges_knowledge());
    }
}
