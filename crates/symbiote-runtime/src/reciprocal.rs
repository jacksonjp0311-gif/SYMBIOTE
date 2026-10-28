//! One reciprocal measurement cycle over the existing exact affine learner.
//!
//! The cycle asks whether exchanging a true strategy hint beats equal-budget
//! isolated identification after transfer and verification costs. It does not
//! open a preregistered cohort and does not replace query-transfer protocol 001.

use serde::Serialize;
use sha2::{Digest, Sha256};
use symbiote_memory::knowledge::KnowledgeStore;
use symbiote_memory::reciprocal::{
    PromotionWitness, ReceiptDraft, ReciprocalReceipt, ValidationOutcome,
};
use symbiote_reasoning::structural::AffineStrategy;
use symbiote_reasoning::symbiosis::{
    decide, measure_affine_exchange, research_success, AffineExchangeMeasurement, ExchangePlan,
    ExchangeTerms, ParticipantView, SymbiosisDecision,
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
        gain_qualified: true,
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

/// A receipt verifies benefit only when this plan sent knowledge and the
/// receiver ledger reseals that same receipt. A declined plan stays false
/// even if the receipt itself verifies. This is an attribution gate, not a
/// reciprocal-efficiency result.
pub fn attributed_benefit(
    exchange_plan: &ExchangePlan,
    payload_sent: bool,
    receipt: &ReciprocalReceipt,
    store: &KnowledgeStore,
    witness: PromotionWitness<'_>,
) -> bool {
    payload_sent
        && exchange_plan.exchanges_knowledge
        && exchange_plan.decision.exchanges_knowledge()
        && receipt.receiver_benefit_verified(store, witness)
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
        assert!(matches!(
            report.receiver_receipt.attribution,
            symbiote_memory::reciprocal::ReceiptAttribution::ContentDigest
        ));
        assert!(matches!(
            report.return_receipt.attribution,
            symbiote_memory::reciprocal::ReceiptAttribution::ContentDigest
        ));
        assert!(report.receiver_receipt.verify_binding().is_ok());
        assert!(report.return_receipt.verify_binding().is_ok());
        assert_eq!(report.measurement.incorrect_certificates, 0);
        assert!(!report.measurement.hint_reduced_any_oracle_count);
        assert!(report.receiver_receipt.receiver_net().unwrap() < 0);
        assert_eq!(report.receiver_receipt.persisted_after_restart, None);
    }

    #[test]
    fn declined_plan_and_foreign_receipt_cannot_verify_benefit() {
        use symbiote_memory::knowledge::{
            affine_schema_fingerprint, assess, KnowledgeRecord, TrialCase, TrialCosts,
            TrialEvidence,
        };
        use symbiote_memory::reciprocal::PromotionSeal;
        use symbiote_reasoning::symbiosis::{
            outbound_views, plan, OutboundEvidence, TransferMeasurement,
        };

        let record = KnowledgeRecord {
            id: "xor-context-a".into(),
            revision: 1,
            source: "partner-a".into(),
            scope: "affine-boolean-v1/context-a".into(),
            schema_fingerprint: affine_schema_fingerprint(3).unwrap(),
            payload: serde_json::json!({
                "kind": "affine",
                "width": 3,
                "coefficients": 3,
                "bias": false
            }),
            provenance: "observed training trace; independent held-out lab checks".into(),
        };
        let trial = TrialEvidence {
            evaluator: "independent-lab".into(),
            training_case_ids: vec!["training-0".into(), "training-1".into()],
            training_inputs: vec![0, 1],
            cases: (2..8)
                .map(|input| TrialCase {
                    id: format!("heldout-{input}"),
                    input,
                    expected: ((input & 3).count_ones() % 2) as u8,
                    baseline: None,
                    candidate: ((input & 3).count_ones() % 2) as u8,
                })
                .collect(),
            costs: TrialCosts {
                acquisition: 2,
                verification: 6,
                adoption: 1,
                baseline: 20,
                candidate: 10,
            },
        };
        let assessment = assess(&record, &trial).unwrap();
        let evidence = serde_json::to_value(&trial).unwrap();
        let dir =
            std::env::temp_dir().join(format!("symbiote-runtime-receipt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut store = KnowledgeStore::open(&dir, "owner-a").unwrap();
        let before = store.history_anchor();
        store.promote(record.clone(), assessment).unwrap();
        let after = store.history_anchor();
        let receipt = ReciprocalReceipt::seal_promoted(
            &store,
            PromotionWitness {
                record: &record,
                evidence: &evidence,
                before: &before,
                after: &after,
            },
            &PromotionSeal {
                sender_identity: "partner-a".into(),
                sender_knowledge_before_sha256: "22".repeat(32),
                persisted_after_restart: Some(true),
                completed: true,
            },
        )
        .unwrap();
        let witness = PromotionWitness {
            record: &record,
            evidence: &evidence,
            before: &before,
            after: &after,
        };
        assert!(receipt.receiver_benefit_verified(&store, witness));

        let saved = TransferMeasurement {
            isolated_checks: Some(8),
            verification_checks: 1,
            transfer_checks: 1,
            regression_checks: 0,
        }
        .terms()
        .unwrap();
        let (offer_local, offer_remote) = outbound_views(OutboundEvidence {
            schema_compatible: true,
            partner_holds_scope: false,
            local_authorized: true,
            remote_authorized: true,
            prior_negative_exchanges: 0,
            family_terms: saved,
        });
        let offer = plan(offer_local, offer_remote).unwrap();
        assert!(offer.exchanges_knowledge);
        assert!(attributed_benefit(&offer, true, &receipt, &store, witness));
        let mut inconsistent = offer.clone();
        inconsistent.decision = SymbiosisDecision::Defer;
        assert!(!attributed_benefit(
            &inconsistent,
            true,
            &receipt,
            &store,
            witness
        ));
        assert!(!attributed_benefit(
            &offer, false, &receipt, &store, witness
        ));

        let declined_terms =
            symbiote_reasoning::symbiosis::affine_full_fixture_transfer(3).unwrap();
        let (declined_local, declined_remote) = outbound_views(OutboundEvidence {
            schema_compatible: true,
            partner_holds_scope: false,
            local_authorized: true,
            remote_authorized: true,
            prior_negative_exchanges: 0,
            family_terms: declined_terms,
        });
        let declined = plan(declined_local, declined_remote).unwrap();
        assert_eq!(declined.decision, SymbiosisDecision::Defer);
        assert!(!attributed_benefit(
            &declined, true, &receipt, &store, witness
        ));

        let digest = ReciprocalReceipt::seal(ReceiptDraft {
            evaluator_identity: "owner-a".into(),
            sender_identity: "partner-a".into(),
            receiver_knowledge_before_sha256: before.head_sha256.clone(),
            sender_knowledge_before_sha256: "22".repeat(32),
            transferred_record_sha256: record.digest().unwrap(),
            validation: ValidationOutcome::LocalEvidence,
            adopted: true,
            behavior_changed: true,
            isolated_control_cost: 20,
            exchange_path_cost: 10,
            sender_return_net: Some(6),
            persisted_after_restart: Some(true),
            certification_bypassed: false,
        })
        .unwrap();
        assert!(!digest.receiver_benefit_verified(&store, witness));
        assert!(!attributed_benefit(&offer, true, &digest, &store, witness));

        let other = std::env::temp_dir().join(format!(
            "symbiote-runtime-receipt-other-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&other);
        std::fs::create_dir_all(&other).unwrap();
        let mut other_store = KnowledgeStore::open(&other, "owner-b").unwrap();
        let other_before = other_store.history_anchor();
        other_store
            .promote(record.clone(), assess(&record, &trial).unwrap())
            .unwrap();
        let other_after = other_store.history_anchor();
        assert!(!attributed_benefit(
            &offer,
            true,
            &receipt,
            &other_store,
            PromotionWitness {
                record: &record,
                evidence: &evidence,
                before: &other_before,
                after: &other_after,
            },
        ));
        drop(store);
        drop(other_store);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other);
    }
}
