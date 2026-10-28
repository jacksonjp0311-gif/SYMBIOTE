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
//! requires two independently witnessed directional receipts with crossed
//! identities and initial knowledge anchors. One receipt cannot certify the
//! other participant. Serialized attribution and restart flags are claims;
//! verification always reads the receiver ledger. A stopped-store replay check
//! observes retained knowledge after reopening, not an OS process restart.
//!
//! A host that can rewrite a ledger and recompute these digests is outside
//! this module's threat model. The hash chain detects accidental corruption.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

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
    /// Informational producer claim; never sufficient restart or durability evidence.
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

/// Sender must match the stored record's source. Forwarded custody needs a separate
/// authenticated provenance witness and is not inferred here. Costs, adoption and
/// behavior are derived; `persisted_after_restart` remains an informational claim.
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
        if seal.sender_identity != witness.record.source {
            return Err("receipt sender must match the promoted record's stored source".into());
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
        if !store.active().iter().any(|record| record == witness.record) {
            return false;
        }
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
        self == &resealed && resealed.claims_benefit()
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

    /// Legacy receipt-only predicate, retained for source compatibility.
    ///
    /// A serialized receipt cannot supply an independent ledger witness. This
    /// method therefore always returns false, including for an honestly produced
    /// receipt. Use `confirmed_benefit` with the receiver's store and witness.
    #[deprecated(
        since = "1.0.1",
        note = "receipt fields cannot verify benefit; use confirmed_benefit(store, witness)"
    )]
    pub fn receiver_benefit_verified(&self) -> bool {
        false
    }

    /// Legacy receipt-only durability predicate, retained for source compatibility.
    ///
    /// Producer restart flags are claims, so this method always returns false.
    /// Use `retained_benefit_after_store_reopen` for a stopped-store replay check;
    /// that check does not itself prove an operating-system process restart.
    #[deprecated(
        since = "1.0.1",
        note = "restart flags are not evidence; use retained_benefit_after_store_reopen"
    )]
    pub fn durable_benefit_verified(&self) -> bool {
        false
    }

    /// Reopen a stopped owner's existing ledger and verify that this exact beneficial
    /// promotion remains active. A live writer, missing/corrupt history, a revoked
    /// record, or a fabricated receipt returns false. The producer's restart flag is
    /// informational and has no effect. This proves store replay, not process restart,
    /// power-loss durability or deployment qualification. No missing ledger is created.
    pub fn retained_benefit_after_store_reopen(
        &self,
        directory: &Path,
        witness: PromotionWitness<'_>,
    ) -> bool {
        if !self.claims_benefit() || !directory.join("knowledge.jsonl").is_file() {
            return false;
        }
        let Ok(store) = KnowledgeStore::open(directory, &self.evaluator_identity) else {
            return false;
        };
        self.confirmed_benefit(&store, witness)
            && store.active().iter().any(|record| {
                record.digest().as_deref() == Ok(self.transferred_record_sha256.as_str())
            })
    }

    /// Legacy receipt-only mutual predicate, retained for source compatibility.
    /// Neither participant's serialized claims witness the other's ledger, so
    /// this method always returns false. Use `witnessed_mutual_research_success`.
    #[deprecated(
        since = "1.0.1",
        note = "receipts alone cannot verify mutual benefit; use witnessed_mutual_research_success"
    )]
    pub fn mutual_research_success(_left: &Self, _right: &Self) -> bool {
        false
    }

    /// Each direction must independently match its own receiver ledger. Crossed
    /// initial knowledge anchors bind the two directional artifacts to the same
    /// participant states; the artifacts need not be identical. This does not verify
    /// an OS restart or authenticate the truth of an arbitrary remote ledger.
    pub fn witnessed_mutual_research_success(
        left: &Self,
        left_store: &KnowledgeStore,
        left_witness: PromotionWitness<'_>,
        right: &Self,
        right_store: &KnowledgeStore,
        right_witness: PromotionWitness<'_>,
    ) -> bool {
        left.confirmed_benefit(left_store, left_witness)
            && right.confirmed_benefit(right_store, right_witness)
            && left.evaluator_identity == right.sender_identity
            && left.sender_identity == right.evaluator_identity
            && left.sender_knowledge_before_sha256 == right.receiver_knowledge_before_sha256
            && right.sender_knowledge_before_sha256 == left.receiver_knowledge_before_sha256
    }

    /// Internal arithmetic/shape predicate. Never expose this as verification of
    /// untrusted receipts: a caller can recompute every hash in a serialized body.
    fn claims_benefit(&self) -> bool {
        self.verify_binding().is_ok()
            && self.completed_promotion()
            && self.validation == ValidationOutcome::LocalEvidence
            && self.adopted
            && self.behavior_changed
            && !self.certification_bypassed
            && self.exchange_path_cost < self.isolated_control_cost
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
    // Another source's identical model adds provenance, not predictive capability.
    payloads.dedup();
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
    use crate::knowledge::{affine_schema_fingerprint, assess, TrialCase, TrialEvidence};
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
            Self {
                store: Some(KnowledgeStore::open(&dir, identity).unwrap()),
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
    fn draft() -> ReceiptDraft {
        ReceiptDraft {
            evaluator_identity: "receiver-b".into(),
            sender_identity: "sender-a".into(),
            receiver_knowledge_before_sha256: digest(1),
            sender_knowledge_before_sha256: digest(2),
            transferred_record_sha256: digest(3),
            validation: ValidationOutcome::LocalEvidence,
            adopted: true,
            behavior_changed: true,
            isolated_control_cost: 100,
            exchange_path_cost: 40,
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
    fn promote_from(identity: &str, source: &str, costs: TrialCosts) -> Promoted {
        let mut record = record();
        record.source = source.into();
        let trial = evidence(costs);
        let mut owner = TempOwner::open(identity);
        let before = owner.store().history_anchor();
        owner
            .store()
            .promote(record.clone(), assess(&record, &trial).unwrap())
            .unwrap();
        let after = owner.store().history_anchor();
        Promoted {
            owner,
            record,
            evidence: serde_json::to_value(trial).unwrap(),
            before,
            after,
        }
    }
    fn promote_costs(identity: &str, costs: TrialCosts) -> Promoted {
        promote_from(identity, "partner-a", costs)
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
        sender_anchor: &str,
        persisted: Option<bool>,
        completed: bool,
    ) -> ReciprocalReceipt {
        ReciprocalReceipt::seal_promoted(
            promoted.owner.store.as_ref().unwrap(),
            witness(promoted),
            &PromotionSeal {
                sender_identity: promoted.record.source.clone(),
                sender_knowledge_before_sha256: sender_anchor.into(),
                persisted_after_restart: persisted,
                completed,
            },
        )
        .unwrap()
    }
    fn benefit(receipt: &ReciprocalReceipt, promoted: &Promoted) -> bool {
        receipt.confirmed_benefit(promoted.owner.store.as_ref().unwrap(), witness(promoted))
    }
    fn mutual(
        left: &ReciprocalReceipt,
        lp: &Promoted,
        right: &ReciprocalReceipt,
        rp: &Promoted,
    ) -> bool {
        ReciprocalReceipt::witnessed_mutual_research_success(
            left,
            lp.owner.store.as_ref().unwrap(),
            witness(lp),
            right,
            rp.owner.store.as_ref().unwrap(),
            witness(rp),
        )
    }

    #[test]
    fn content_digest_is_not_benefit_and_tamper_breaks_the_binding() {
        let promoted = promote_costs("receiver-b", positive_costs());
        let receipt = ReciprocalReceipt::seal(draft()).unwrap();
        assert!(matches!(
            receipt.attribution,
            ReceiptAttribution::ContentDigest
        ));
        assert!(receipt.verify_binding().is_ok());
        assert_eq!(receipt.receiver_net().unwrap(), 60);
        assert!(!benefit(&receipt, &promoted));
        assert!(
            !receipt.retained_benefit_after_store_reopen(&promoted.owner.dir, witness(&promoted))
        );
        assert!(!mutual(&receipt, &promoted, &receipt, &promoted));
        let mut rejected = draft();
        rejected.adopted = false;
        rejected.validation = ValidationOutcome::Rejected;
        assert!(!benefit(
            &ReciprocalReceipt::seal(rejected).unwrap(),
            &promoted
        ));
        let mut bypass = draft();
        bypass.certification_bypassed = true;
        assert!(ReciprocalReceipt::seal(bypass).is_err());
        let mut tampered = receipt.clone();
        tampered.exchange_path_cost = 1;
        assert!(tampered.verify_binding().is_err());
        assert!(tampered.receiver_net().is_err());
        assert!(!benefit(&tampered, &promoted));
        let mut swapped = receipt;
        swapped.sender_identity = "other-sender".into();
        assert!(swapped.verify_binding().is_err());
        assert!(!benefit(&swapped, &promoted));
    }

    #[test]
    fn sender_cannot_receipt_itself_and_flags_are_not_evidence() {
        let mut same = draft();
        same.sender_identity = same.evaluator_identity.clone();
        assert!(ReciprocalReceipt::seal(same).is_err());
        let promoted = promote_costs("receiver-b", positive_costs());
        for flag in [None, Some(false), Some(true)] {
            let mut claimed = draft();
            claimed.persisted_after_restart = flag;
            let receipt = ReciprocalReceipt::seal(claimed).unwrap();
            assert!(!benefit(&receipt, &promoted));
            assert!(!receipt
                .retained_benefit_after_store_reopen(&promoted.owner.dir, witness(&promoted)));
        }
    }

    #[test]
    fn ledger_promotion_attributes_strict_improvement_only() {
        let promoted = promote_costs("owner-a", positive_costs());
        let receipt = seal_for(&promoted, &digest(9), Some(true), true);
        assert!(benefit(&receipt, &promoted));
        assert!(
            receipt.confirmed_benefit(promoted.owner.store.as_ref().unwrap(), witness(&promoted))
        );
        assert_eq!(
            (receipt.isolated_control_cost, receipt.exchange_path_cost),
            (20, 10)
        );
        assert_eq!(receipt.sender_return_net, None);
        assert!(receipt.adopted && receipt.behavior_changed);
        assert_eq!(receipt.evaluator_identity, "owner-a");
        let interrupted = seal_for(&promoted, &digest(9), Some(true), false);
        assert!(!benefit(&interrupted, &promoted));
        assert!(!interrupted.adopted);
        assert_eq!(interrupted.validation, ValidationOutcome::Abstained);
        let mut replayed = promoted.before.clone();
        replayed.records = promoted.after.records;
        replayed.head_sha256 = promoted.after.head_sha256.clone();
        let seal = PromotionSeal {
            sender_identity: "partner-a".into(),
            sender_knowledge_before_sha256: digest(9),
            persisted_after_restart: None,
            completed: true,
        };
        assert!(ReciprocalReceipt::seal_promoted(
            promoted.owner.store.as_ref().unwrap(),
            PromotionWitness {
                before: &replayed,
                ..witness(&promoted)
            },
            &seal
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
            &seal
        )
        .is_err());
        let mut tampered = receipt;
        tampered.isolated_control_cost = 100;
        tampered.binding_sha256 = tampered.calculated_binding().unwrap();
        assert!(tampered.verify_binding().is_ok());
        assert!(
            !benefit(&tampered, &promoted),
            "rehashing changed costs cannot change the ledger"
        );
    }

    #[test]
    fn neutral_negative_same_payload_and_rejected_are_not_benefit() {
        for total in [20, 30] {
            let mut costs = positive_costs();
            costs.candidate = total;
            let promoted = promote_costs("owner-neutral", costs);
            let receipt = seal_for(&promoted, &digest(9), None, true);
            assert!(receipt.receiver_net().unwrap() <= 0);
            assert!(!benefit(&receipt, &promoted));
        }
        let mut promoted = promote_costs("owner-same", positive_costs());
        let first_receipt = seal_for(&promoted, &digest(9), None, true);
        assert!(benefit(&first_receipt, &promoted));
        let mut next = promoted.record.clone();
        next.revision = 2;
        next.provenance = "same payload, next revision".into();
        let mut trial = evidence(positive_costs());
        for case in &mut trial.cases {
            case.baseline = Some(case.expected);
        }
        promoted.before = promoted.after;
        promoted
            .owner
            .store()
            .promote(next.clone(), assess(&next, &trial).unwrap())
            .unwrap();
        promoted.after = promoted.owner.store().history_anchor();
        promoted.record = next;
        promoted.evidence = serde_json::to_value(trial).unwrap();
        let unchanged = seal_for(&promoted, &digest(9), None, true);
        assert!(unchanged.adopted);
        assert!(!unchanged.behavior_changed);
        assert!(!benefit(&unchanged, &promoted));
        let rejected = ReciprocalReceipt::seal_observed(ObservedDraft {
            evaluator_identity: "owner-same".into(),
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
        assert!(!benefit(&rejected, &promoted));
    }

    #[test]
    fn mutual_success_needs_two_crossed_witnessed_directional_receipts() {
        let left = promote_from("owner-a", "owner-b", positive_costs());
        let right = promote_from("owner-b", "owner-a", positive_costs());
        let lr = seal_for(&left, &right.before.head_sha256, None, true);
        let rr = seal_for(&right, &left.before.head_sha256, None, true);
        assert_ne!(lr.transferred_record_sha256, rr.transferred_record_sha256);
        assert!(mutual(&lr, &left, &rr, &right));
        assert!(mutual(&rr, &right, &lr, &left));
        assert!(!mutual(&lr, &left, &lr, &left));
        assert!(
            !mutual(&lr, &right, &rr, &left),
            "foreign ledgers cannot validate the pair"
        );
        let wrong_anchor = seal_for(&right, &digest(9), None, true);
        assert!(benefit(&wrong_anchor, &right));
        assert!(!mutual(&lr, &left, &wrong_anchor, &right));
        let claimed = ReciprocalReceipt::seal(draft()).unwrap();
        assert!(!mutual(&lr, &left, &claimed, &right));
    }

    #[test]
    #[allow(deprecated)]
    fn v1_receipt_only_signatures_stay_compatible_and_fail_closed() {
        // These function-pointer types are the original public v1.0 signatures.
        let receiver_check: fn(&ReciprocalReceipt) -> bool =
            ReciprocalReceipt::receiver_benefit_verified;
        let durability_check: fn(&ReciprocalReceipt) -> bool =
            ReciprocalReceipt::durable_benefit_verified;
        let mutual_check: fn(&ReciprocalReceipt, &ReciprocalReceipt) -> bool =
            ReciprocalReceipt::mutual_research_success;
        let left = promote_from("owner-a", "owner-b", positive_costs());
        let right = promote_from("owner-b", "owner-a", positive_costs());
        let lr = seal_for(&left, &right.before.head_sha256, Some(true), true);
        let rr = seal_for(&right, &left.before.head_sha256, Some(true), true);
        assert!(benefit(&lr, &left));
        assert!(benefit(&rr, &right));
        assert!(mutual(&lr, &left, &rr, &right));
        // Even genuine receipts cannot verify themselves without the ledgers.
        for receipt in [&lr, &rr] {
            assert!(!receiver_check(receipt));
            assert!(!durability_check(receipt));
        }
        assert!(!mutual_check(&lr, &rr));
        assert!(!mutual_check(&rr, &lr));
    }

    #[test]
    fn fabricated_ledger_json_with_a_fresh_hash_is_not_verified_benefit() {
        let mut claimed = ReciprocalReceipt::seal(draft()).unwrap();
        claimed.attribution = ReceiptAttribution::LedgerPromotion {
            promotion_sha256: digest(10),
            records_before: 1,
            records_after: 2,
            behavior_before_sha256: digest(11),
            behavior_after_sha256: digest(12),
            completed: true,
        };
        claimed.binding_sha256 = claimed.calculated_binding().unwrap();
        let untrusted: ReciprocalReceipt =
            serde_json::from_slice(&serde_json::to_vec(&claimed).unwrap()).unwrap();
        assert!(untrusted.verify_binding().is_ok());
        let mut owner = TempOwner::open("receiver-b");
        let anchor = owner.store().history_anchor();
        let record = record();
        let evidence = serde_json::to_value(evidence(positive_costs())).unwrap();
        let witness = PromotionWitness {
            record: &record,
            evidence: &evidence,
            before: &anchor,
            after: &anchor,
        };
        assert!(!untrusted.confirmed_benefit(owner.store.as_ref().unwrap(), witness));
        assert!(!untrusted.retained_benefit_after_store_reopen(&owner.dir, witness));
        owner.store.take();
        assert!(!untrusted.retained_benefit_after_store_reopen(&owner.dir, witness));
    }

    #[test]
    fn an_identical_payload_from_another_source_is_not_changed_behavior() {
        let mut promoted = promote_costs("owner-a", positive_costs());
        let mut duplicate = promoted.record.clone();
        duplicate.id = "same-model-new-source".into();
        duplicate.source = "partner-b".into();
        let trial = evidence(positive_costs());
        promoted.before = promoted.owner.store().history_anchor();
        promoted
            .owner
            .store()
            .promote(duplicate.clone(), assess(&duplicate, &trial).unwrap())
            .unwrap();
        promoted.after = promoted.owner.store().history_anchor();
        promoted.record = duplicate;
        promoted.evidence = serde_json::to_value(trial).unwrap();
        let receipt = seal_for(&promoted, &digest(9), Some(true), true);
        assert!(receipt.adopted);
        assert!(!receipt.behavior_changed);
        assert!(!benefit(&receipt, &promoted));
    }

    #[test]
    fn promoted_receipt_cannot_assign_credit_to_an_unrelated_sender() {
        let promoted = promote_costs("owner-a", positive_costs());
        for sender in ["unrelated-sender", "owner-a"] {
            assert!(ReciprocalReceipt::seal_promoted(
                promoted.owner.store.as_ref().unwrap(),
                witness(&promoted),
                &PromotionSeal {
                    sender_identity: sender.into(),
                    sender_knowledge_before_sha256: digest(9),
                    persisted_after_restart: None,
                    completed: true
                }
            )
            .is_err());
        }
        let mut reassigned = seal_for(&promoted, &digest(9), None, true);
        reassigned.sender_identity = "unrelated-sender".into();
        reassigned.binding_sha256 = reassigned.calculated_binding().unwrap();
        assert!(reassigned.verify_binding().is_ok());
        assert!(!benefit(&reassigned, &promoted));
    }

    #[test]
    fn a_caller_restart_flag_is_not_a_reopen_observation() {
        for flag in [None, Some(false), Some(true)] {
            let mut promoted = promote_costs("owner-a", positive_costs());
            let receipt = seal_for(&promoted, &digest(9), flag, true);
            assert!(benefit(&receipt, &promoted));
            assert!(
                !receipt
                    .retained_benefit_after_store_reopen(&promoted.owner.dir, witness(&promoted)),
                "a live writer cannot substitute a caller flag for reopening"
            );
            let missing = promoted.owner.dir.join("missing");
            assert!(!receipt.retained_benefit_after_store_reopen(&missing, witness(&promoted)));
            assert!(
                !missing.exists(),
                "verification must not initialize missing state"
            );
            promoted.owner.store.take();
            assert!(receipt
                .retained_benefit_after_store_reopen(&promoted.owner.dir, witness(&promoted)));
            fs::write(
                promoted.owner.dir.join("knowledge.jsonl"),
                b"invalid-history\n",
            )
            .unwrap();
            assert!(!receipt
                .retained_benefit_after_store_reopen(&promoted.owner.dir, witness(&promoted)));
        }
    }

    #[test]
    fn later_revocation_preserves_auditable_history_but_not_verified_current_benefit() {
        let mut promoted = promote_costs("owner-a", positive_costs());
        let receipt = seal_for(&promoted, &digest(9), Some(true), true);
        let id = promoted.record.id.clone();
        promoted
            .owner
            .store()
            .revoke(&id, "independent counterexample")
            .unwrap();
        assert!(!benefit(&receipt, &promoted));
        assert!(
            promoted
                .owner
                .store
                .as_ref()
                .unwrap()
                .promotion_between(
                    &promoted.record,
                    &promoted.evidence,
                    &promoted.before,
                    &promoted.after
                )
                .is_ok(),
            "historical promotion remains auditable after revocation"
        );
        promoted.owner.store.take();
        assert!(
            !receipt.retained_benefit_after_store_reopen(&promoted.owner.dir, witness(&promoted))
        );
    }
}
