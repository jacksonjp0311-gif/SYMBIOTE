//! One reciprocal measurement cycle over the existing exact affine learner.
//!
//! The cycle asks whether exchanging a true strategy hint beats equal-budget
//! isolated identification after transfer and verification costs. It does not
//! open a preregistered cohort and does not replace query-transfer protocol 001.

use serde::Serialize;
use sha2::{Digest, Sha256};
use symbiote_memory::reciprocal::{ReceiptDraft, ReciprocalReceipt, ValidationOutcome};
use symbiote_reasoning::structural::AffineStrategy;
use symbiote_reasoning::symbiosis::{
    decide, measure_affine_exchange, research_success, AffineExchangeMeasurement, ExchangeTerms,
    ParticipantView, SymbiosisDecision,
};

pub const ORACLE_UNIT: u64 = 100;
pub const TRANSFER_UNIT: u64 = 5;
pub const VERIFICATION_UNIT: u64 = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExchangeCycleReport {
    pub measurement: AffineExchangeMeasurement,
    pub decision: SymbiosisDecision,
    pub local_utility: i128,
    pub remote_utility: i128,
    pub receiver_receipt: ReciprocalReceipt,
    pub return_receipt: ReciprocalReceipt,
    pub research_success: bool,
}

/// Measure both directions of a redundant affine hint exchange.
///
/// Each direction pays one transfer and one verification unit per strategy.
/// Oracle work is charged at `ORACLE_UNIT` for every query the exact learner
/// actually makes. The isolated control is the same learner without the hint.
pub fn redundant_affine_exchange(width: u8) -> Result<ExchangeCycleReport, String> {
    let measurement = measure_affine_exchange(width)?;
    let strategies = u64::try_from(measurement.strategies)
        .map_err(|_| "affine measurement strategy count overflow")?;
    let oracle_gain = measurement
        .independent_oracle_queries
        .saturating_sub(measurement.hinted_oracle_queries);
    let terms = ExchangeTerms {
        expected_gain: u64::try_from(oracle_gain).map_err(|_| "oracle gain overflow")?
            * ORACLE_UNIT,
        transfer_cost: strategies * TRANSFER_UNIT,
        verification_cost: strategies * VERIFICATION_UNIT,
        regression_risk: u64::try_from(measurement.incorrect_certificates)
            .map_err(|_| "incorrect certificate count overflow")?,
    };
    let view = ParticipantView {
        terms,
        evidence_complete: true,
        prior_negative_exchanges: 0,
        authorization_present: true,
        local_has_unshared_evidence: true,
        remote_has_unshared_evidence: true,
        discriminating_experiment_available: false,
    };
    let decision = decide(view, Some(view))?;
    let local_utility = terms.utility()?;
    let remote_utility = terms.utility()?;
    let isolated_cost = u64::try_from(measurement.independent_oracle_queries)
        .map_err(|_| "isolated query count overflow")?
        * ORACLE_UNIT;
    let exchange_cost = u64::try_from(measurement.hinted_oracle_queries)
        .map_err(|_| "hinted query count overflow")?
        * ORACLE_UNIT
        + terms.transfer_cost
        + terms.verification_cost;
    let transferred = digest_json(&AffineStrategy::new(width, 0, false)?)?;
    let before = empty_anchor();
    let behavior_changed = measurement.hint_changed_any_query_sequence;
    let receiver_receipt = ReciprocalReceipt::seal(ReceiptDraft {
        evaluator_identity: "affine-receiver-b".into(),
        sender_identity: "affine-sender-a".into(),
        receiver_knowledge_before_sha256: before.clone(),
        sender_knowledge_before_sha256: before.clone(),
        transferred_record_sha256: transferred.clone(),
        validation: ValidationOutcome::LocalEvidence,
        adopted: false,
        behavior_changed,
        isolated_control_cost: isolated_cost,
        exchange_path_cost: exchange_cost,
        sender_return_net: Some(remote_utility),
        persisted_after_restart: None,
        certification_bypassed: false,
    })?;
    let return_receipt = ReciprocalReceipt::seal(ReceiptDraft {
        evaluator_identity: "affine-receiver-a".into(),
        sender_identity: "affine-sender-b".into(),
        receiver_knowledge_before_sha256: before.clone(),
        sender_knowledge_before_sha256: before,
        transferred_record_sha256: transferred,
        validation: ValidationOutcome::LocalEvidence,
        adopted: false,
        behavior_changed,
        isolated_control_cost: isolated_cost,
        exchange_path_cost: exchange_cost,
        sender_return_net: Some(local_utility),
        persisted_after_restart: None,
        certification_bypassed: false,
    })?;
    Ok(ExchangeCycleReport {
        research_success: research_success(local_utility, remote_utility),
        measurement,
        decision,
        local_utility,
        remote_utility,
        receiver_receipt,
        return_receipt,
    })
}

fn empty_anchor() -> String {
    "00".repeat(32)
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redundant_affine_hints_are_declined_and_are_not_mutual_benefit() {
        let report = redundant_affine_exchange(3).unwrap();
        assert_eq!(report.decision, SymbiosisDecision::Defer);
        assert!(!report.decision.exchanges_knowledge());
        assert!(report.local_utility < 0);
        assert!(report.remote_utility < 0);
        assert!(!report.research_success);
        assert!(!report.receiver_receipt.receiver_benefit_verified());
        assert!(!report.return_receipt.receiver_benefit_verified());
        assert!(!report.receiver_receipt.durable_benefit_verified());
        assert!(!report.receiver_receipt.mutual_research_success());
        assert!(report.receiver_receipt.verify_binding().is_ok());
        assert!(report.return_receipt.verify_binding().is_ok());
        assert_eq!(report.measurement.incorrect_certificates, 0);
        assert!(!report.measurement.hint_reduced_any_oracle_count);
        assert!(report.receiver_receipt.receiver_net().unwrap() < 0);
        assert_eq!(report.receiver_receipt.persisted_after_restart, None);
    }
}
