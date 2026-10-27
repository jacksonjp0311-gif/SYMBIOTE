//! Receiver-originated evaluation of one knowledge exchange.
//!
//! The binding is a SHA-256 digest of the canonical receipt body. It detects
//! accidental or uncoordinated modification. It is not a claim that a remote
//! party is honest, and it is not a signature over a private key.
//!
//! Quarantine, agreement and model promotion are not fields and are not
//! benefit. Benefit requires local evidence, adoption, a later behavior change,
//! a strictly lower cost than the equal-resource isolated control, and no
//! bypass of the exact certification policy.

use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "symbiote.reciprocal-evaluation/1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationOutcome {
    LocalEvidence,
    Rejected,
    Abstained,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReciprocalReceipt {
    pub schema: String,
    pub evaluator_identity: String,
    pub sender_identity: String,
    pub receiver_knowledge_before_sha256: String,
    pub sender_knowledge_before_sha256: String,
    pub transferred_record_sha256: String,
    pub validation: ValidationOutcome,
    pub adopted: bool,
    pub behavior_changed: bool,
    pub isolated_control_cost: u64,
    pub exchange_path_cost: u64,
    pub sender_return_net: Option<i128>,
    pub persisted_after_restart: Option<bool>,
    pub certification_bypassed: bool,
    pub binding_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptDraft {
    pub evaluator_identity: String,
    pub sender_identity: String,
    pub receiver_knowledge_before_sha256: String,
    pub sender_knowledge_before_sha256: String,
    pub transferred_record_sha256: String,
    pub validation: ValidationOutcome,
    pub adopted: bool,
    pub behavior_changed: bool,
    pub isolated_control_cost: u64,
    pub exchange_path_cost: u64,
    pub sender_return_net: Option<i128>,
    pub persisted_after_restart: Option<bool>,
    pub certification_bypassed: bool,
}

#[derive(Serialize)]
struct ReceiptBody<'a> {
    schema: &'a str,
    evaluator_identity: &'a str,
    sender_identity: &'a str,
    receiver_knowledge_before_sha256: &'a str,
    sender_knowledge_before_sha256: &'a str,
    transferred_record_sha256: &'a str,
    validation: ValidationOutcome,
    adopted: bool,
    behavior_changed: bool,
    isolated_control_cost: u64,
    exchange_path_cost: u64,
    sender_return_net: Option<i128>,
    persisted_after_restart: Option<bool>,
    certification_bypassed: bool,
}

impl ReciprocalReceipt {
    pub fn seal(draft: ReceiptDraft) -> Result<Self, String> {
        validate_claim(&draft)?;
        let mut receipt = Self {
            schema: SCHEMA.into(),
            evaluator_identity: draft.evaluator_identity,
            sender_identity: draft.sender_identity,
            receiver_knowledge_before_sha256: draft.receiver_knowledge_before_sha256,
            sender_knowledge_before_sha256: draft.sender_knowledge_before_sha256,
            transferred_record_sha256: draft.transferred_record_sha256,
            validation: draft.validation,
            adopted: draft.adopted,
            behavior_changed: draft.behavior_changed,
            isolated_control_cost: draft.isolated_control_cost,
            exchange_path_cost: draft.exchange_path_cost,
            sender_return_net: draft.sender_return_net,
            persisted_after_restart: draft.persisted_after_restart,
            certification_bypassed: draft.certification_bypassed,
            binding_sha256: String::new(),
        };
        receipt.binding_sha256 = receipt.calculated_binding()?;
        Ok(receipt)
    }

    pub fn verify_binding(&self) -> Result<(), String> {
        if self.schema != SCHEMA {
            return Err("reciprocal receipt schema is not recognized".into());
        }
        let draft = self.draft();
        validate_claim(&draft)?;
        if !is_sha256(&self.binding_sha256) || self.binding_sha256 != self.calculated_binding()? {
            return Err("reciprocal receipt binding does not match its body".into());
        }
        Ok(())
    }

    /// Isolated cost minus exchange cost, only after the binding checks.
    pub fn receiver_net(&self) -> Result<i128, String> {
        self.verify_binding()?;
        Ok(i128::from(self.isolated_control_cost) - i128::from(self.exchange_path_cost))
    }

    /// True only when the receiver's own evidence shows a strict cost improvement.
    pub fn receiver_benefit_verified(&self) -> bool {
        self.verify_binding().is_ok()
            && self.validation == ValidationOutcome::LocalEvidence
            && self.adopted
            && self.behavior_changed
            && !self.certification_bypassed
            && self.exchange_path_cost < self.isolated_control_cost
    }

    /// Persistence is a separate measurement. Absence is not durability.
    pub fn durable_benefit_verified(&self) -> bool {
        self.receiver_benefit_verified() && self.persisted_after_restart == Some(true)
    }

    /// Both participants improved. Nonnegative sender return is not enough.
    pub fn mutual_research_success(&self) -> bool {
        self.receiver_benefit_verified() && self.sender_return_net.is_some_and(|net| net > 0)
    }

    fn draft(&self) -> ReceiptDraft {
        ReceiptDraft {
            evaluator_identity: self.evaluator_identity.clone(),
            sender_identity: self.sender_identity.clone(),
            receiver_knowledge_before_sha256: self.receiver_knowledge_before_sha256.clone(),
            sender_knowledge_before_sha256: self.sender_knowledge_before_sha256.clone(),
            transferred_record_sha256: self.transferred_record_sha256.clone(),
            validation: self.validation,
            adopted: self.adopted,
            behavior_changed: self.behavior_changed,
            isolated_control_cost: self.isolated_control_cost,
            exchange_path_cost: self.exchange_path_cost,
            sender_return_net: self.sender_return_net,
            persisted_after_restart: self.persisted_after_restart,
            certification_bypassed: self.certification_bypassed,
        }
    }

    fn calculated_binding(&self) -> Result<String, String> {
        super::digest(&ReceiptBody {
            schema: &self.schema,
            evaluator_identity: &self.evaluator_identity,
            sender_identity: &self.sender_identity,
            receiver_knowledge_before_sha256: &self.receiver_knowledge_before_sha256,
            sender_knowledge_before_sha256: &self.sender_knowledge_before_sha256,
            transferred_record_sha256: &self.transferred_record_sha256,
            validation: self.validation,
            adopted: self.adopted,
            behavior_changed: self.behavior_changed,
            isolated_control_cost: self.isolated_control_cost,
            exchange_path_cost: self.exchange_path_cost,
            sender_return_net: self.sender_return_net,
            persisted_after_restart: self.persisted_after_restart,
            certification_bypassed: self.certification_bypassed,
        })
    }
}

fn validate_claim(draft: &ReceiptDraft) -> Result<(), String> {
    if !label(&draft.evaluator_identity) || !label(&draft.sender_identity) {
        return Err("reciprocal receipt needs bounded distinct participant identities".into());
    }
    if draft.evaluator_identity == draft.sender_identity {
        return Err(
            "a reciprocal receipt must be bound to a receiver other than the sender".into(),
        );
    }
    for digest in [
        &draft.receiver_knowledge_before_sha256,
        &draft.sender_knowledge_before_sha256,
        &draft.transferred_record_sha256,
    ] {
        if !is_sha256(digest) {
            return Err("reciprocal receipt knowledge bindings must be SHA-256 digests".into());
        }
    }
    if draft.adopted && draft.validation != ValidationOutcome::LocalEvidence {
        return Err("adoption cannot be recorded without local evidence".into());
    }
    if draft.certification_bypassed && draft.adopted {
        return Err("a certification bypass cannot be recorded as adoption".into());
    }
    Ok(())
}

fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> String {
        format!("{byte:02x}{}", "ab".repeat(31))
    }

    fn draft(adopted: bool, changed: bool, isolated: u64, exchange: u64) -> ReceiptDraft {
        ReceiptDraft {
            evaluator_identity: "receiver-b".into(),
            sender_identity: "sender-a".into(),
            receiver_knowledge_before_sha256: digest(1),
            sender_knowledge_before_sha256: digest(2),
            transferred_record_sha256: digest(3),
            validation: ValidationOutcome::LocalEvidence,
            adopted,
            behavior_changed: changed,
            isolated_control_cost: isolated,
            exchange_path_cost: exchange,
            sender_return_net: Some(4),
            persisted_after_restart: Some(true),
            certification_bypassed: false,
        }
    }

    #[test]
    fn strict_improvement_is_benefit_and_tamper_is_not() {
        let receipt = ReciprocalReceipt::seal(draft(true, true, 100, 40)).unwrap();
        assert!(receipt.receiver_benefit_verified());
        assert!(receipt.durable_benefit_verified());
        assert!(receipt.mutual_research_success());
        assert_eq!(receipt.receiver_net().unwrap(), 60);

        let mut equal = draft(true, true, 100, 100);
        equal.sender_return_net = Some(0);
        equal.persisted_after_restart = None;
        let equal = ReciprocalReceipt::seal(equal).unwrap();
        assert!(!equal.receiver_benefit_verified());
        assert!(!equal.durable_benefit_verified());
        assert!(!equal.mutual_research_success());

        let unchanged = ReciprocalReceipt::seal(draft(true, false, 100, 40)).unwrap();
        assert!(!unchanged.receiver_benefit_verified());
        let unadopted = ReciprocalReceipt::seal(draft(false, true, 100, 40)).unwrap();
        assert!(!unadopted.receiver_benefit_verified());

        let mut rejected = draft(false, false, 100, 40);
        rejected.validation = ValidationOutcome::Rejected;
        let rejected = ReciprocalReceipt::seal(rejected).unwrap();
        assert!(!rejected.receiver_benefit_verified());

        let mut bypass = draft(false, true, 100, 40);
        bypass.certification_bypassed = true;
        let bypass = ReciprocalReceipt::seal(bypass).unwrap();
        assert!(!bypass.receiver_benefit_verified());
        assert!(ReciprocalReceipt::seal({
            let mut adopted_bypass = draft(true, true, 100, 40);
            adopted_bypass.certification_bypassed = true;
            adopted_bypass
        })
        .is_err());

        let mut tampered = receipt.clone();
        tampered.exchange_path_cost = 1;
        assert!(tampered.verify_binding().is_err());
        assert!(!tampered.receiver_benefit_verified());
        assert!(tampered.receiver_net().is_err());
    }

    #[test]
    fn sender_cannot_receipt_itself_and_restart_absence_is_not_durable() {
        let mut same = draft(true, true, 10, 1);
        same.sender_identity = same.evaluator_identity.clone();
        assert!(ReciprocalReceipt::seal(same).is_err());
        let mut missing_restart = draft(true, true, 10, 1);
        missing_restart.persisted_after_restart = None;
        missing_restart.sender_return_net = None;
        let receipt = ReciprocalReceipt::seal(missing_restart).unwrap();
        assert!(receipt.receiver_benefit_verified());
        assert!(!receipt.durable_benefit_verified());
        assert!(!receipt.mutual_research_success());
    }
}
