//! Prospective value of one proposed knowledge exchange.
//!
//! `U = expected_gain - transfer_cost - verification_cost - regression_risk`
//! is computed separately in each participant's own declared units. Those units
//! are never added together. A connection decision is not an authorization;
//! operator grants remain external. No result here is a convergence or
//! generality claim.

use crate::structural::{AffineLearner, AffineStrategy, CandidateAssessment};
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "symbiote.value-of-symbiosis/2";
pub const RECONCILIATION_SCHEMA: &str = "symbiote.value-reconciliation/1";
const REPEATED_NEGATIVE_LIMIT: u64 = 3;

/// Costs and a prospective gain already expressed in one participant's units.
///
/// `gain_qualified` is false when `expected_gain` was not measured or explicitly
/// qualified. That state is not a utility of zero. `utility` is only the
/// arithmetic; decisions use `assess`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeTerms {
    pub expected_gain: u64,
    pub transfer_cost: u64,
    pub verification_cost: u64,
    pub regression_risk: u64,
    pub gain_qualified: bool,
}

/// A qualified number, or an estimate the caller has not measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UtilityAssessment {
    Uncertain,
    Qualified(i128),
}

impl ExchangeTerms {
    /// Arithmetic on the stored integers. This does not decide whether the gain
    /// was qualified.
    pub fn utility(self) -> Result<i128, String> {
        let gain = i128::from(self.expected_gain);
        let cost = i128::from(self.transfer_cost)
            .checked_add(i128::from(self.verification_cost))
            .and_then(|sum| sum.checked_add(i128::from(self.regression_risk)))
            .ok_or("exchange costs overflow the value-of-symbiosis integer")?;
        gain.checked_sub(cost)
            .ok_or_else(|| "exchange utility overflow".into())
    }

    pub fn assess(self) -> Result<UtilityAssessment, String> {
        if !self.gain_qualified {
            return Ok(UtilityAssessment::Uncertain);
        }
        Ok(UtilityAssessment::Qualified(self.utility()?))
    }
}

/// Check counts already converted into one participant's units.
///
/// `isolated_checks: None` means the isolated bound was not measured. It is not
/// a claim that the isolated work is zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferMeasurement {
    pub isolated_checks: Option<u64>,
    pub verification_checks: u64,
    pub transfer_checks: u64,
    pub regression_checks: u64,
}

impl TransferMeasurement {
    pub fn terms(self) -> Result<ExchangeTerms, String> {
        Ok(ExchangeTerms {
            expected_gain: self.isolated_checks.unwrap_or(0),
            transfer_cost: self.transfer_checks,
            verification_cost: self.verification_checks,
            regression_risk: self.regression_checks,
            gain_qualified: self.isolated_checks.is_some(),
        })
    }
}

/// Full-fixture affine verification checks every domain row. Isolated
/// identification still needs `width + 1` queries. Those are the same unit
/// only as check counts; this is not a claim that a hint beats the bound.
pub fn affine_full_fixture_transfer(width: u8) -> Result<ExchangeTerms, String> {
    if !(1..=8).contains(&width) {
        return Err("affine transfer width must be 1..=8".into());
    }
    let verification = 1_u64
        .checked_shl(u32::from(width))
        .ok_or("affine verification domain overflow")?;
    TransferMeasurement {
        isolated_checks: Some(u64::from(width) + 1),
        verification_checks: verification,
        transfer_checks: 1,
        regression_checks: 0,
    }
    .terms()
}

/// Observing each edge once is the isolated lower bound used here. The
/// cognitive evaluator still rechecks every ordered pair, which is a larger
/// check count. This does not certify a graph transfer as beneficial.
pub fn graph_fixture_transfer(nodes: u64, edges: u64) -> Result<ExchangeTerms, String> {
    if !(2..=64).contains(&nodes) || !(1..=256).contains(&edges) {
        return Err("graph transfer bounds must match the supported schema".into());
    }
    let routes = nodes
        .checked_sub(1)
        .and_then(|others| nodes.checked_mul(others))
        .ok_or("graph route check count overflow")?;
    TransferMeasurement {
        isolated_checks: Some(edges),
        verification_checks: routes,
        transfer_checks: 1,
        regression_checks: 0,
    }
    .terms()
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
    /// A payload leaves the caller only for a request or an offer.
    /// `Connect` recommends an authorized relationship. It does not transfer
    /// knowledge. An experiment stays local. Abstention, deferral, observation
    /// and disconnection do not transfer a payload.
    pub fn exchanges_knowledge(self) -> bool {
        matches!(self, Self::RequestKnowledge | Self::OfferKnowledge)
    }

    /// Relationship recommendation. This is not a knowledge payload and it does
    /// not create an operator grant.
    pub fn opens_connection(self) -> bool {
        matches!(self, Self::Connect)
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
///
/// An unqualified gain is not zero. A missing remote measurement is not a
/// request. `Connect` requires authorization on both views and still does not
/// send a payload.
pub fn decide(
    local: ParticipantView,
    remote: Option<ParticipantView>,
) -> Result<SymbiosisDecision, String> {
    if !local.authorization_present {
        return Ok(SymbiosisDecision::Abstain);
    }
    if !local.evidence_complete || !local.terms.gain_qualified {
        if local.prior_negative_exchanges >= REPEATED_NEGATIVE_LIMIT {
            return Ok(SymbiosisDecision::Disconnect);
        }
        return Ok(if local.discriminating_experiment_available {
            SymbiosisDecision::Experiment
        } else {
            SymbiosisDecision::Observe
        });
    }
    let local_utility = match local.terms.assess()? {
        UtilityAssessment::Uncertain => {
            return Err("qualified gain flag disagreed with the utility assessment".into())
        }
        UtilityAssessment::Qualified(value) => value,
    };
    if local_utility < 0 {
        let repeated = local.prior_negative_exchanges.saturating_add(1) >= REPEATED_NEGATIVE_LIMIT;
        return Ok(if repeated {
            SymbiosisDecision::Disconnect
        } else {
            SymbiosisDecision::Defer
        });
    }
    if local_utility == 0 {
        return Ok(SymbiosisDecision::Defer);
    }
    let Some(remote) = remote.filter(|remote| remote.evidence_complete) else {
        return Ok(SymbiosisDecision::Observe);
    };
    if !remote.terms.gain_qualified {
        return Ok(SymbiosisDecision::Observe);
    }
    let remote_utility = match remote.terms.assess()? {
        UtilityAssessment::Uncertain => {
            return Err("qualified remote gain flag disagreed with the utility assessment".into())
        }
        UtilityAssessment::Qualified(value) => value,
    };
    if remote_utility < 0 {
        return Ok(SymbiosisDecision::Defer);
    }
    if remote_utility > 0 && local.local_has_unshared_evidence && local.remote_has_unshared_evidence
    {
        return Ok(if remote.authorization_present {
            SymbiosisDecision::Connect
        } else {
            SymbiosisDecision::Observe
        });
    }
    if remote_utility > 0
        && remote.authorization_present
        && local.local_has_unshared_evidence
        && !local.remote_has_unshared_evidence
    {
        return Ok(SymbiosisDecision::OfferKnowledge);
    }
    if remote_utility > 0
        && remote.authorization_present
        && local.remote_has_unshared_evidence
        && !local.local_has_unshared_evidence
    {
        return Ok(SymbiosisDecision::RequestKnowledge);
    }
    if !remote.authorization_present
        && (local.local_has_unshared_evidence || local.remote_has_unshared_evidence)
    {
        return Ok(SymbiosisDecision::Observe);
    }
    if local.discriminating_experiment_available {
        return Ok(SymbiosisDecision::Experiment);
    }
    Ok(SymbiosisDecision::Defer)
}

/// Evidence the caller measured before an outbound offer. Flags do not create
/// grants. Family terms are ignored when the schema is incompatible or the
/// partner already holds the scope; those cases use an explicit qualified zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboundEvidence {
    pub schema_compatible: bool,
    pub partner_holds_scope: bool,
    pub local_authorized: bool,
    pub remote_authorized: bool,
    pub prior_negative_exchanges: u64,
    pub family_terms: ExchangeTerms,
}

pub fn outbound_views(evidence: OutboundEvidence) -> (ParticipantView, Option<ParticipantView>) {
    let terms = if !evidence.schema_compatible {
        ExchangeTerms {
            expected_gain: 0,
            transfer_cost: 1,
            verification_cost: 1,
            regression_risk: 1,
            gain_qualified: true,
        }
    } else if evidence.partner_holds_scope {
        ExchangeTerms {
            expected_gain: 0,
            transfer_cost: 1,
            verification_cost: 0,
            regression_risk: 0,
            gain_qualified: true,
        }
    } else {
        evidence.family_terms
    };
    let useful = evidence.schema_compatible && !evidence.partner_holds_scope;
    let local = ParticipantView {
        terms,
        evidence_complete: true,
        prior_negative_exchanges: evidence.prior_negative_exchanges,
        authorization_present: evidence.local_authorized,
        local_has_unshared_evidence: useful,
        remote_has_unshared_evidence: false,
        discriminating_experiment_available: false,
    };
    let remote = ParticipantView {
        authorization_present: evidence.remote_authorized,
        prior_negative_exchanges: 0,
        local_has_unshared_evidence: false,
        remote_has_unshared_evidence: false,
        ..local
    };
    (local, Some(remote))
}

/// The decision and the estimates that produced it. Utility is absent when the
/// gain was not qualified or the evidence was incomplete. Absence is not zero.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangePlan {
    pub schema: String,
    pub decision: SymbiosisDecision,
    pub local_utility: Option<i128>,
    pub remote_utility: Option<i128>,
    pub local_gain_qualified: bool,
    pub remote_gain_qualified: bool,
    pub bilateral_authorization: bool,
    pub exchanges_knowledge: bool,
    pub opens_connection: bool,
}

pub fn plan(
    local: ParticipantView,
    remote: Option<ParticipantView>,
) -> Result<ExchangePlan, String> {
    let decision = decide(local, remote)?;
    let local_utility = if local.evidence_complete {
        match local.terms.assess()? {
            UtilityAssessment::Uncertain => None,
            UtilityAssessment::Qualified(value) => Some(value),
        }
    } else {
        None
    };
    let (remote_utility, remote_gain_qualified, remote_authorized) = match remote {
        Some(remote) if remote.evidence_complete => {
            let utility = match remote.terms.assess()? {
                UtilityAssessment::Uncertain => None,
                UtilityAssessment::Qualified(value) => Some(value),
            };
            (
                utility,
                remote.terms.gain_qualified,
                remote.authorization_present,
            )
        }
        Some(remote) => (
            None,
            remote.terms.gain_qualified,
            remote.authorization_present,
        ),
        None => (None, false, false),
    };
    Ok(ExchangePlan {
        schema: SCHEMA.into(),
        decision,
        local_utility,
        remote_utility,
        local_gain_qualified: local.terms.gain_qualified,
        remote_gain_qualified,
        bilateral_authorization: local.authorization_present && remote_authorized,
        exchanges_knowledge: decision.exchanges_knowledge(),
        opens_connection: decision.opens_connection(),
    })
}

/// Predicted action against what the runtime actually did.
///
/// `benefit_verified` stays false. A caller-supplied net is a measurement input
/// for the mismatch record; it is not a benefit flag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueReconciliation {
    pub schema: String,
    pub predicted_decision: SymbiosisDecision,
    pub predicted_local_utility: Option<i128>,
    pub payload_sent: bool,
    pub measured_local_net: Option<i128>,
    pub action_matched: bool,
    pub benefit_verified: bool,
    pub utility_matched: Option<bool>,
}

pub fn reconcile(
    exchange_plan: &ExchangePlan,
    payload_sent: bool,
    measured_local_net: Option<i128>,
) -> ValueReconciliation {
    let utility_matched = match (exchange_plan.local_utility, measured_local_net) {
        (Some(predicted), Some(measured)) => Some(predicted.signum() == measured.signum()),
        _ => None,
    };
    ValueReconciliation {
        schema: RECONCILIATION_SCHEMA.into(),
        predicted_decision: exchange_plan.decision,
        predicted_local_utility: exchange_plan.local_utility,
        payload_sent,
        measured_local_net,
        action_matched: payload_sent == exchange_plan.exchanges_knowledge,
        benefit_verified: false,
        utility_matched,
    }
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
                gain_qualified: true,
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
            gain_qualified: true,
        };
        assert_eq!(terms.utility().unwrap(), 1);
        assert!(matches!(
            terms.assess().unwrap(),
            UtilityAssessment::Qualified(1)
        ));
        assert!(
            ExchangeTerms {
                expected_gain: 0,
                transfer_cost: u64::MAX,
                verification_cost: u64::MAX,
                regression_risk: u64::MAX,
                gain_qualified: true,
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
        assert!(!SymbiosisDecision::Connect.exchanges_knowledge());
        assert!(SymbiosisDecision::Connect.opens_connection());
        assert!(SymbiosisDecision::OfferKnowledge.exchanges_knowledge());
        assert!(!SymbiosisDecision::OfferKnowledge.opens_connection());
        assert!(!SymbiosisDecision::Defer.exchanges_knowledge());
        assert!(!SymbiosisDecision::Experiment.exchanges_knowledge());
        let mut unilateral = good;
        unilateral.authorization_present = false;
        assert_eq!(
            decide(good, Some(unilateral)).unwrap(),
            SymbiosisDecision::Observe,
            "a connection recommendation requires both authorizations and sends no payload"
        );
        assert!(!decide(good, Some(unilateral))
            .unwrap()
            .exchanges_knowledge());

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
            SymbiosisDecision::Observe,
            "an unmeasured partner is not sent a knowledge request"
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
            gain_qualified: true,
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

    #[test]
    fn uncertain_gain_is_not_zero_and_negative_counters_do_not_overflow() {
        let mut uncertain = view(0, 0, true);
        uncertain.terms = ExchangeTerms {
            expected_gain: 0,
            transfer_cost: 0,
            verification_cost: 0,
            regression_risk: 0,
            gain_qualified: false,
        };
        assert_eq!(uncertain.terms.utility().unwrap(), 0);
        assert_eq!(
            uncertain.terms.assess().unwrap(),
            UtilityAssessment::Uncertain
        );
        assert_eq!(
            decide(uncertain, Some(uncertain)).unwrap(),
            SymbiosisDecision::Observe
        );
        let planned = plan(uncertain, Some(uncertain)).unwrap();
        assert_eq!(planned.local_utility, None);
        assert!(!planned.exchanges_knowledge);

        let mut known_zero = uncertain;
        known_zero.terms.gain_qualified = true;
        assert_eq!(
            decide(known_zero, Some(known_zero)).unwrap(),
            SymbiosisDecision::Defer
        );
        assert_eq!(
            plan(known_zero, Some(known_zero)).unwrap().local_utility,
            Some(0)
        );

        let mut saturated = view(0, u64::MAX, true);
        saturated.terms.expected_gain = 0;
        assert_eq!(
            decide(saturated, Some(saturated)).unwrap(),
            SymbiosisDecision::Disconnect
        );
    }

    #[test]
    fn policy_declines_unnecessary_transfer_and_selects_a_qualified_candidate() {
        let affine = affine_full_fixture_transfer(3).unwrap();
        assert!(affine.utility().unwrap() < 0);
        let (local, remote) = outbound_views(OutboundEvidence {
            schema_compatible: true,
            partner_holds_scope: false,
            local_authorized: true,
            remote_authorized: true,
            prior_negative_exchanges: 0,
            family_terms: affine,
        });
        let declined = plan(local, remote).unwrap();
        assert_eq!(declined.decision, SymbiosisDecision::Defer);
        assert!(!declined.exchanges_knowledge);
        assert!(!declined.opens_connection);
        let declined_reconciliation = reconcile(&declined, false, None);
        assert!(declined_reconciliation.action_matched);
        assert!(!declined_reconciliation.benefit_verified);
        assert_eq!(declined_reconciliation.utility_matched, None);

        let redundant = outbound_views(OutboundEvidence {
            schema_compatible: true,
            partner_holds_scope: true,
            local_authorized: true,
            remote_authorized: true,
            prior_negative_exchanges: 0,
            family_terms: affine,
        });
        let redundant = plan(redundant.0, redundant.1).unwrap();
        assert_eq!(redundant.decision, SymbiosisDecision::Defer);
        assert_eq!(redundant.local_utility, Some(-1));
        assert!(!reconcile(&redundant, true, Some(4)).action_matched);
        assert!(!reconcile(&redundant, true, Some(4)).benefit_verified);
        assert_eq!(
            reconcile(&redundant, true, Some(4)).utility_matched,
            Some(false)
        );

        let graph = graph_fixture_transfer(3, 3).unwrap();
        assert!(graph.utility().unwrap() < 0);
        let graph_plan = plan(
            outbound_views(OutboundEvidence {
                schema_compatible: true,
                partner_holds_scope: false,
                local_authorized: true,
                remote_authorized: true,
                prior_negative_exchanges: 0,
                family_terms: graph,
            })
            .0,
            outbound_views(OutboundEvidence {
                schema_compatible: true,
                partner_holds_scope: false,
                local_authorized: true,
                remote_authorized: true,
                prior_negative_exchanges: 0,
                family_terms: graph,
            })
            .1,
        )
        .unwrap();
        assert_eq!(graph_plan.decision, SymbiosisDecision::Defer);

        let saved = TransferMeasurement {
            isolated_checks: Some(8),
            verification_checks: 1,
            transfer_checks: 1,
            regression_checks: 0,
        }
        .terms()
        .unwrap();
        assert_eq!(saved.utility().unwrap(), 6);
        let (local, remote) = outbound_views(OutboundEvidence {
            schema_compatible: true,
            partner_holds_scope: false,
            local_authorized: true,
            remote_authorized: true,
            prior_negative_exchanges: 0,
            family_terms: saved,
        });
        let selected = plan(local, remote).unwrap();
        assert_eq!(selected.decision, SymbiosisDecision::OfferKnowledge);
        assert!(selected.exchanges_knowledge);
        assert!(!selected.opens_connection);
        assert_eq!(selected.local_utility, Some(6));
        assert!(selected.bilateral_authorization);
        let selected_reconciliation = reconcile(&selected, true, None);
        assert!(selected_reconciliation.action_matched);
        assert!(!selected_reconciliation.benefit_verified);

        let (local, remote) = outbound_views(OutboundEvidence {
            schema_compatible: true,
            partner_holds_scope: false,
            local_authorized: false,
            remote_authorized: true,
            prior_negative_exchanges: 0,
            family_terms: saved,
        });
        let denied = plan(local, remote).unwrap();
        assert_eq!(denied.decision, SymbiosisDecision::Abstain);
        assert!(!denied.exchanges_knowledge);
        assert!(!denied.bilateral_authorization);
        assert!(!reconcile(&denied, false, Some(6)).benefit_verified);

        let (local, remote) = outbound_views(OutboundEvidence {
            schema_compatible: true,
            partner_holds_scope: false,
            local_authorized: true,
            remote_authorized: false,
            prior_negative_exchanges: 0,
            family_terms: saved,
        });
        let remote_denied = plan(local, remote).unwrap();
        assert_eq!(remote_denied.decision, SymbiosisDecision::Observe);
        assert!(!remote_denied.exchanges_knowledge);
        assert!(!remote_denied.opens_connection);
    }
}
