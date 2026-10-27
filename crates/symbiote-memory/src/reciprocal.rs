//! Receiver-originated evaluation of one knowledge exchange.
//!
//! `seal` writes a SHA-256 content digest. That digest detects accidental
//! modification of the receipt body. It does not show that the receiver
//! promoted anything, and it is not a private-key signature.
//!
//! `seal_promoted` reads one promotion between two validated anchors in the
//! receiver's own ledger. Adoption, behavior and both costs come from that
//! promotion. A caller-supplied flag cannot make them true. Quarantine,
//! agreement, delivery and an unfinished promotion are not benefit.
//!
//! Benefit additionally requires a behavior change and a stored exchange total
//! strictly below the stored isolated baseline. The component breakdown is
//! already included in that total, so it is not added again. Mutual success
//! requires two such receipts with crossed identities and the same transferred
//! record. One receipt cannot certify the other participant.
//!
//! A host that can rewrite a ledger and recompute these digests is outside
//! this module's threat model. The hash chain detects accidental corruption.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::knowledge::{KnowledgeAnchor, KnowledgeRecord, KnowledgeStore, TrialCosts};

pub const SCHEMA: &str = "symbiote.reciprocal-evaluation/2";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationOutcome {
    LocalEvidence,
    Rejected,
    Abstained,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedOutcome {
    Interrupted,
    Incompatible,
    Rejected,
}

/// How the receipt was grounded. Only a completed ledger promotion can verify benefit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReceiptAttribution {
    ContentDigest,
    LedgerPromotion {
        promotion_sha256: String,
        records_before: usize,
        records_after: usize,
        behavior_before_sha256: String,
        behavior_after_sha256: String,
        completed: bool,
    },
    Observed {
        outcome: ObservedOutcome,
    },
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
    pub attribution: ReceiptAttribution,
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

/// Caller-supplied names for a ledger seal. Costs, adoption and behavior are not fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromotionSeal {
    pub sender_identity: String,
    pub sender_knowledge_before_sha256: String,
    pub persisted_after_restart: Option<bool>,
    pub completed: bool,
}

/// The receiver ledger position a promotion receipt must match.
#[derive(Clone, Copy, Debug)]
pub struct PromotionWitness<'a> {
    pub record: &'a KnowledgeRecord,
    pub evidence: &'a Value,
    pub before: &'a KnowledgeAnchor,
    pub after: &'a KnowledgeAnchor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedDraft {
    pub evaluator_identity: String,
    pub sender_identity: String,
    pub receiver_knowledge_before_sha256: String,
    pub sender_knowledge_before_sha256: String,
    pub transferred_record_sha256: String,
    pub outcome: ObservedOutcome,
    pub isolated_control_cost: u64,
    pub exchange_path_cost: u64,
    pub persisted_after_restart: Option<bool>,
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
    attribution: &'a ReceiptAttribution,
}

#[derive(Deserialize)]
struct StoredTrialCosts {
    costs: TrialCosts,
}

impl ReciprocalReceipt {
    /// Content digest only. Adoption flags are recorded claims, not benefit.
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
            attribution: ReceiptAttribution::ContentDigest,
            binding_sha256: String::new(),
        };
        receipt.binding_sha256 = receipt.calculated_binding()?;
        receipt.verify_binding()?;
        Ok(receipt)
    }

    /// Seal an exchange that did not become a completed receiver promotion.
    pub fn seal_observed(draft: ObservedDraft) -> Result<Self, String> {
        let validation = match draft.outcome {
            ObservedOutcome::Rejected => ValidationOutcome::Rejected,
            ObservedOutcome::Interrupted | ObservedOutcome::Incompatible => {
                ValidationOutcome::Abstained
            }
        };
        Self::seal_attributed(
            ReceiptDraft {
                evaluator_identity: draft.evaluator_identity,
                sender_identity: draft.sender_identity,
                receiver_knowledge_before_sha256: draft.receiver_knowledge_before_sha256,
                sender_knowledge_before_sha256: draft.sender_knowledge_before_sha256,
                transferred_record_sha256: draft.transferred_record_sha256,
                validation,
                adopted: false,
                behavior_changed: false,
                isolated_control_cost: draft.isolated_control_cost,
                exchange_path_cost: draft.exchange_path_cost,
                sender_return_net: None,
                persisted_after_restart: draft.persisted_after_restart,
                certification_bypassed: false,
            },
            ReceiptAttribution::Observed {
                outcome: draft.outcome,
            },
        )
    }

    /// Attribute the receipt to the receiver ledger. `completed: false` stays abstained
    /// even when the promotion is present.
    pub fn seal_promoted(
        store: &KnowledgeStore,
        witness: PromotionWitness<'_>,
        seal: &PromotionSeal,
    ) -> Result<Self, String> {
        if !label(&seal.sender_identity) || seal.sender_identity == store.identity() {
            return Err(
                "a reciprocal receipt must name a sender other than the receiving owner".into(),
            );
        }
        if !is_sha256(&seal.sender_knowledge_before_sha256) {
            return Err("sender knowledge binding must be a SHA-256 digest".into());
        }
        store.validate_anchor(witness.before)?;
        store.validate_anchor(witness.after)?;
        let transferred = witness.record.digest()?;
        let matched = store.promotion_between(
            witness.record,
            witness.evidence,
            witness.before,
            witness.after,
        );
        if !seal.completed {
            let Ok(promotion_sha256) = matched else {
                return Self::seal_observed(ObservedDraft {
                    evaluator_identity: store.identity().to_string(),
                    sender_identity: seal.sender_identity.clone(),
                    receiver_knowledge_before_sha256: witness.before.head_sha256.clone(),
                    sender_knowledge_before_sha256: seal.sender_knowledge_before_sha256.clone(),
                    transferred_record_sha256: transferred,
                    outcome: ObservedOutcome::Interrupted,
                    isolated_control_cost: 0,
                    exchange_path_cost: 0,
                    persisted_after_restart: seal.persisted_after_restart,
                });
            };
            return Self::finish_ledger(
                store,
                witness,
                seal,
                &promotion_sha256,
                &transferred,
                false,
            );
        }
        let promotion_sha256 = matched?;
        Self::finish_ledger(store, witness, seal, &promotion_sha256, &transferred, true)
    }

    /// Re-seal against the receiver ledger and require the same binding.
    pub fn confirmed_benefit(&self, store: &KnowledgeStore, witness: PromotionWitness<'_>) -> bool {
        let Ok(resealed) = Self::seal_promoted(
            store,
            witness,
            &PromotionSeal {
                sender_identity: self.sender_identity.clone(),
                sender_knowledge_before_sha256: self.sender_knowledge_before_sha256.clone(),
                persisted_after_restart: self.persisted_after_restart,
                completed: true,
            },
        ) else {
            return false;
        };
        self == &resealed && resealed.receiver_benefit_verified()
    }

    pub fn verify_binding(&self) -> Result<(), String> {
        if self.schema != SCHEMA {
            return Err("reciprocal receipt schema is not recognized".into());
        }
        let draft = self.draft();
        validate_claim(&draft)?;
        self.validate_attribution()?;
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

    /// True only for a completed ledger promotion with a derived strict cost improvement.
    pub fn receiver_benefit_verified(&self) -> bool {
        self.verify_binding().is_ok()
            && self.completed_promotion()
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

    /// Both receivers improved on the same transferred record. A sender net on
    /// one receipt is not the other receiver's evidence.
    pub fn mutual_research_success(left: &Self, right: &Self) -> bool {
        left.receiver_benefit_verified()
            && right.receiver_benefit_verified()
            && left.evaluator_identity == right.sender_identity
            && left.sender_identity == right.evaluator_identity
            && left.transferred_record_sha256 == right.transferred_record_sha256
    }

    fn finish_ledger(
        store: &KnowledgeStore,
        witness: PromotionWitness<'_>,
        seal: &PromotionSeal,
        promotion_sha256: &str,
        transferred: &str,
        completed: bool,
    ) -> Result<Self, String> {
        let behavior_before_sha256 =
            scope_behavior_digest(store, witness.before, &witness.record.scope)?;
        let behavior_after_sha256 =
            scope_behavior_digest(store, witness.after, &witness.record.scope)?;
        let behavior_changed = behavior_before_sha256 != behavior_after_sha256;
        let (isolated_control_cost, exchange_path_cost) = stored_costs(witness.evidence)?;
        let attribution = ReceiptAttribution::LedgerPromotion {
            promotion_sha256: promotion_sha256.to_string(),
            records_before: witness.before.records,
            records_after: witness.after.records,
            behavior_before_sha256,
            behavior_after_sha256,
            completed,
        };
        Self::seal_attributed(
            ReceiptDraft {
                evaluator_identity: store.identity().to_string(),
                sender_identity: seal.sender_identity.clone(),
                receiver_knowledge_before_sha256: witness.before.head_sha256.clone(),
                sender_knowledge_before_sha256: seal.sender_knowledge_before_sha256.clone(),
                transferred_record_sha256: transferred.to_string(),
                validation: if completed {
                    ValidationOutcome::LocalEvidence
                } else {
                    ValidationOutcome::Abstained
                },
                adopted: completed,
                behavior_changed: completed && behavior_changed,
                isolated_control_cost,
                exchange_path_cost,
                sender_return_net: None,
                persisted_after_restart: seal.persisted_after_restart,
                certification_bypassed: false,
            },
            attribution,
        )
    }

    fn seal_attributed(
        draft: ReceiptDraft,
        attribution: ReceiptAttribution,
    ) -> Result<Self, String> {
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
            attribution,
            binding_sha256: String::new(),
        };
        receipt.validate_attribution()?;
        receipt.binding_sha256 = receipt.calculated_binding()?;
        receipt.verify_binding()?;
        Ok(receipt)
    }

    fn completed_promotion(&self) -> bool {
        match &self.attribution {
            ReceiptAttribution::LedgerPromotion {
                promotion_sha256,
                records_before,
                records_after,
                behavior_before_sha256,
                behavior_after_sha256,
                completed: true,
            } => {
                is_sha256(promotion_sha256)
                    && is_sha256(behavior_before_sha256)
                    && is_sha256(behavior_after_sha256)
                    && behavior_before_sha256 != behavior_after_sha256
                    && records_before < records_after
            }
            _ => false,
        }
    }

    fn validate_attribution(&self) -> Result<(), String> {
        match &self.attribution {
            ReceiptAttribution::ContentDigest => Ok(()),
            ReceiptAttribution::Observed { .. } => {
                if self.adopted
                    || self.behavior_changed
                    || self.validation == ValidationOutcome::LocalEvidence
                    || self.certification_bypassed
                {
                    return Err(
                        "an observed receipt cannot claim adoption, behavior change, or local evidence"
                            .into(),
                    );
                }
                Ok(())
            }
            ReceiptAttribution::LedgerPromotion {
                promotion_sha256,
                records_before,
                records_after,
                behavior_before_sha256,
                behavior_after_sha256,
                completed,
            } => {
                if !is_sha256(promotion_sha256)
                    || !is_sha256(behavior_before_sha256)
                    || !is_sha256(behavior_after_sha256)
                {
                    return Err("ledger promotion attribution needs SHA-256 bindings".into());
                }
                if records_before >= records_after {
                    return Err("ledger promotion attribution has no new history".into());
                }
                let changed = behavior_before_sha256 != behavior_after_sha256;
                if *completed {
                    if !self.adopted
                        || self.validation != ValidationOutcome::LocalEvidence
                        || self.certification_bypassed
                        || self.behavior_changed != changed
                    {
                        return Err(
                            "a completed promotion receipt must match its derived adoption and behavior"
                                .into(),
                        );
                    }
                } else if self.adopted
                    || self.behavior_changed
                    || self.validation == ValidationOutcome::LocalEvidence
                {
                    return Err(
                        "an incomplete promotion cannot be recorded as adopted local evidence"
                            .into(),
                    );
                }
                Ok(())
            }
        }
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
            attribution: &self.attribution,
        })
    }
}

fn stored_costs(evidence: &Value) -> Result<(u64, u64), String> {
    let stored: StoredTrialCosts =
        serde_json::from_value(evidence.clone()).map_err(|error| error.to_string())?;
    let parts = stored
        .costs
        .acquisition
        .checked_add(stored.costs.verification)
        .and_then(|sum| sum.checked_add(stored.costs.adoption))
        .ok_or("stored trial cost overflow")?;
    if parts > stored.costs.candidate {
        return Err("stored exchange total excludes its measured components".into());
    }
    Ok((stored.costs.baseline, stored.costs.candidate))
}

fn scope_behavior_digest(
    store: &KnowledgeStore,
    anchor: &KnowledgeAnchor,
    scope: &str,
) -> Result<String, String> {
    let mut payloads: Vec<Value> = store
        .active_at(anchor)?
        .into_iter()
        .filter(|record| record.scope == scope)
        .map(|record| record.payload)
        .collect();
    payloads.sort_by_key(|payload| payload.to_string());
    super::digest(&payloads)
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
    use crate::knowledge::{
        affine_schema_fingerprint, assess, KnowledgeStore, TrialCase, TrialCosts, TrialEvidence,
    };
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TempOwner {
        store: Option<KnowledgeStore>,
        dir: PathBuf,
    }

    impl TempOwner {
        fn open(identity: &str) -> Self {
            let n = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir()
                .join(format!("symbiote-reciprocal-{}-{n}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            let store = KnowledgeStore::open(&dir, identity).unwrap();
            Self {
                store: Some(store),
                dir,
            }
        }

        fn store(&mut self) -> &mut KnowledgeStore {
            self.store.as_mut().unwrap()
        }
    }

    impl Drop for TempOwner {
        fn drop(&mut self) {
            self.store.take();
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

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

    fn record() -> KnowledgeRecord {
        KnowledgeRecord {
            id: "xor-context-a".into(),
            revision: 1,
            source: "partner-a".into(),
            scope: "affine-boolean-v1/context-a".into(),
            schema_fingerprint: affine_schema_fingerprint(3).unwrap(),
            payload: json!({"kind":"affine","width":3,"coefficients":3,"bias":false}),
            provenance: "observed training trace; independent held-out lab checks".into(),
        }
    }

    fn evidence(costs: TrialCosts) -> TrialEvidence {
        TrialEvidence {
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
            costs,
        }
    }

    fn positive_costs() -> TrialCosts {
        TrialCosts {
            acquisition: 2,
            verification: 6,
            adoption: 1,
            baseline: 20,
            candidate: 10,
        }
    }

    struct Promoted {
        owner: TempOwner,
        record: KnowledgeRecord,
        evidence: Value,
        before: KnowledgeAnchor,
        after: KnowledgeAnchor,
    }

    fn promote_costs(identity: &str, costs: TrialCosts) -> Promoted {
        let record = record();
        let trial = evidence(costs);
        let assessment = assess(&record, &trial).unwrap();
        let evidence = serde_json::to_value(&trial).unwrap();
        let mut owner = TempOwner::open(identity);
        let before = owner.store().history_anchor();
        owner.store().promote(record.clone(), assessment).unwrap();
        let after = owner.store().history_anchor();
        Promoted {
            owner,
            record,
            evidence,
            before,
            after,
        }
    }

    fn witness(promoted: &Promoted) -> PromotionWitness<'_> {
        PromotionWitness {
            record: &promoted.record,
            evidence: &promoted.evidence,
            before: &promoted.before,
            after: &promoted.after,
        }
    }

    fn seal_for(
        promoted: &Promoted,
        sender: &str,
        persisted: Option<bool>,
        completed: bool,
    ) -> ReciprocalReceipt {
        ReciprocalReceipt::seal_promoted(
            promoted.owner.store.as_ref().unwrap(),
            witness(promoted),
            &PromotionSeal {
                sender_identity: sender.into(),
                sender_knowledge_before_sha256: digest(9),
                persisted_after_restart: persisted,
                completed,
            },
        )
        .unwrap()
    }

    #[test]
    fn content_digest_is_not_benefit_and_tamper_breaks_the_binding() {
        let receipt = ReciprocalReceipt::seal(draft(true, true, 100, 40)).unwrap();
        assert!(matches!(
            receipt.attribution,
            ReceiptAttribution::ContentDigest
        ));
        assert!(!receipt.receiver_benefit_verified());
        assert!(!receipt.durable_benefit_verified());
        assert_eq!(receipt.receiver_net().unwrap(), 60);
        let peer = ReciprocalReceipt::seal(draft(true, true, 100, 40)).unwrap();
        assert!(!ReciprocalReceipt::mutual_research_success(&receipt, &peer));

        let mut equal = draft(true, true, 100, 100);
        equal.sender_return_net = Some(0);
        equal.persisted_after_restart = None;
        let equal = ReciprocalReceipt::seal(equal).unwrap();
        assert!(!equal.receiver_benefit_verified());

        let mut rejected = draft(false, false, 100, 40);
        rejected.validation = ValidationOutcome::Rejected;
        assert!(!ReciprocalReceipt::seal(rejected)
            .unwrap()
            .receiver_benefit_verified());
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

        let mut swapped = receipt.clone();
        swapped.sender_identity = "other-sender".into();
        assert!(swapped.verify_binding().is_err());
        assert!(!swapped.receiver_benefit_verified());
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
        assert!(!receipt.receiver_benefit_verified());
        assert!(!receipt.durable_benefit_verified());
    }

    #[test]
    fn ledger_promotion_attributes_strict_improvement_only() {
        let promoted = promote_costs("owner-a", positive_costs());
        let receipt = seal_for(&promoted, "partner-a", Some(true), true);
        assert!(receipt.receiver_benefit_verified());
        assert!(receipt.durable_benefit_verified());
        assert!(
            receipt.confirmed_benefit(promoted.owner.store.as_ref().unwrap(), witness(&promoted))
        );
        assert_eq!(receipt.isolated_control_cost, 20);
        assert_eq!(receipt.exchange_path_cost, 10);
        assert_eq!(receipt.sender_return_net, None);
        assert!(receipt.adopted);
        assert!(receipt.behavior_changed);
        assert_eq!(receipt.evaluator_identity, "owner-a");

        let interrupted = seal_for(&promoted, "partner-a", Some(true), false);
        assert!(!interrupted.receiver_benefit_verified());
        assert!(!interrupted.adopted);
        assert_eq!(interrupted.validation, ValidationOutcome::Abstained);
        assert!(!interrupted
            .confirmed_benefit(promoted.owner.store.as_ref().unwrap(), witness(&promoted)));

        let mut replayed = promoted.before.clone();
        replayed.records = promoted.after.records;
        replayed.head_sha256 = promoted.after.head_sha256.clone();
        assert!(ReciprocalReceipt::seal_promoted(
            promoted.owner.store.as_ref().unwrap(),
            PromotionWitness {
                before: &replayed,
                ..witness(&promoted)
            },
            &PromotionSeal {
                sender_identity: "partner-a".into(),
                sender_knowledge_before_sha256: digest(9),
                persisted_after_restart: Some(true),
                completed: true,
            },
        )
        .is_err());

        let mut incompatible = promoted.evidence.clone();
        incompatible["evaluator"] = json!("other-lab");
        assert!(ReciprocalReceipt::seal_promoted(
            promoted.owner.store.as_ref().unwrap(),
            PromotionWitness {
                evidence: &incompatible,
                ..witness(&promoted)
            },
            &PromotionSeal {
                sender_identity: "partner-a".into(),
                sender_knowledge_before_sha256: digest(9),
                persisted_after_restart: None,
                completed: true,
            },
        )
        .is_err());
        assert!(ReciprocalReceipt::seal_promoted(
            promoted.owner.store.as_ref().unwrap(),
            witness(&promoted),
            &PromotionSeal {
                sender_identity: "owner-a".into(),
                sender_knowledge_before_sha256: digest(9),
                persisted_after_restart: None,
                completed: true,
            },
        )
        .is_err());
        let mut tampered = receipt.clone();
        tampered.isolated_control_cost = 100;
        assert!(tampered.verify_binding().is_err());
        assert!(!tampered.receiver_benefit_verified());
        assert!(
            !tampered.confirmed_benefit(promoted.owner.store.as_ref().unwrap(), witness(&promoted))
        );
    }

    #[test]
    fn neutral_negative_same_payload_and_rejected_are_not_benefit() {
        let neutral = promote_costs(
            "owner-neutral",
            TrialCosts {
                acquisition: 2,
                verification: 6,
                adoption: 1,
                baseline: 20,
                candidate: 20,
            },
        );
        let neutral_receipt = seal_for(&neutral, "partner-a", Some(true), true);
        assert_eq!(neutral_receipt.receiver_net().unwrap(), 0);
        assert!(!neutral_receipt.receiver_benefit_verified());

        let negative = promote_costs(
            "owner-negative",
            TrialCosts {
                acquisition: 2,
                verification: 6,
                adoption: 1,
                baseline: 20,
                candidate: 30,
            },
        );
        let negative_receipt = seal_for(&negative, "partner-a", None, true);
        assert!(negative_receipt.receiver_net().unwrap() < 0);
        assert!(!negative_receipt.receiver_benefit_verified());
        assert!(!negative_receipt.durable_benefit_verified());

        let rejected = ReciprocalReceipt::seal_observed(ObservedDraft {
            evaluator_identity: "owner-negative".into(),
            sender_identity: "partner-a".into(),
            receiver_knowledge_before_sha256: digest(4),
            sender_knowledge_before_sha256: digest(5),
            transferred_record_sha256: digest(6),
            outcome: ObservedOutcome::Rejected,
            isolated_control_cost: 20,
            exchange_path_cost: 10,
            persisted_after_restart: Some(true),
        })
        .unwrap();
        assert_eq!(rejected.validation, ValidationOutcome::Rejected);
        assert!(!rejected.receiver_benefit_verified());
        assert!(!rejected.durable_benefit_verified());

        let mut owner = TempOwner::open("owner-same");
        let original = record();
        let first = evidence(positive_costs());
        let before = owner.store().history_anchor();
        owner
            .store()
            .promote(original.clone(), assess(&original, &first).unwrap())
            .unwrap();
        let middle = owner.store().history_anchor();
        let mut next = original.clone();
        next.revision = 2;
        next.provenance = "same payload, next revision".into();
        let mut second = evidence(positive_costs());
        for case in &mut second.cases {
            case.baseline = Some(case.expected);
        }
        owner
            .store()
            .promote(next.clone(), assess(&next, &second).unwrap())
            .unwrap();
        let after = owner.store().history_anchor();
        let evidence = serde_json::to_value(&second).unwrap();
        let unchanged = ReciprocalReceipt::seal_promoted(
            owner.store.as_ref().unwrap(),
            PromotionWitness {
                record: &next,
                evidence: &evidence,
                before: &middle,
                after: &after,
            },
            &PromotionSeal {
                sender_identity: "partner-a".into(),
                sender_knowledge_before_sha256: digest(9),
                persisted_after_restart: Some(true),
                completed: true,
            },
        )
        .unwrap();
        assert!(unchanged.adopted);
        assert!(!unchanged.behavior_changed);
        assert!(!unchanged.receiver_benefit_verified());
        let first_receipt = ReciprocalReceipt::seal_promoted(
            owner.store.as_ref().unwrap(),
            PromotionWitness {
                record: &original,
                evidence: &serde_json::to_value(&first).unwrap(),
                before: &before,
                after: &middle,
            },
            &PromotionSeal {
                sender_identity: "partner-a".into(),
                sender_knowledge_before_sha256: digest(9),
                persisted_after_restart: Some(true),
                completed: true,
            },
        )
        .unwrap();
        assert!(first_receipt.behavior_changed);
        assert!(first_receipt.receiver_benefit_verified());
    }

    #[test]
    fn mutual_success_needs_two_crossed_ledger_receipts() {
        let left = promote_costs("owner-a", positive_costs());
        let right = promote_costs("owner-b", positive_costs());
        let left_receipt = seal_for(&left, "owner-b", Some(true), true);
        let right_receipt = seal_for(&right, "owner-a", Some(true), true);
        assert!(ReciprocalReceipt::mutual_research_success(
            &left_receipt,
            &right_receipt
        ));
        assert!(ReciprocalReceipt::mutual_research_success(
            &right_receipt,
            &left_receipt
        ));
        assert!(!ReciprocalReceipt::mutual_research_success(
            &left_receipt,
            &left_receipt
        ));
        let same_sender = seal_for(&right, "partner-a", Some(true), true);
        assert!(!ReciprocalReceipt::mutual_research_success(
            &left_receipt,
            &same_sender
        ));
        assert!(
            !left_receipt.confirmed_benefit(right.owner.store.as_ref().unwrap(), witness(&right))
        );
        let claimed = ReciprocalReceipt::seal(draft(true, true, 100, 40)).unwrap();
        assert!(!ReciprocalReceipt::mutual_research_success(
            &left_receipt,
            &claimed
        ));
    }
}
