//! Consented, bounded forwarding of inert knowledge. A forwarding receipt is
//! custody evidence, never an evaluation or a learning-promotion certificate.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use symbiote_memory::knowledge::KnowledgeRecord;

fn digest<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EdgeConsent {
    pub source: String,
    pub destination: String,
    pub scope: String,
    pub source_granted: bool,
    pub destination_granted: bool,
    pub epoch: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkLimits {
    pub attempts: usize,
    pub payload_bytes: usize,
    pub total_bytes: usize,
    pub hops: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    pub schema: String,
    pub coordinator: String,
    pub edges: Vec<EdgeConsent>,
    pub limits: NetworkLimits,
}
impl NetworkPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != "symbiote.network-policy/1"
            || !label(&self.coordinator)
            || self.edges.is_empty()
            || self.edges.len() > 32
            || !(1..=1024).contains(&self.limits.attempts)
            || !(1..=65536).contains(&self.limits.payload_bytes)
            || self.limits.total_bytes < self.limits.payload_bytes
            || self.limits.total_bytes > 4 * 1024 * 1024
            || !(1..=8).contains(&self.limits.hops)
        {
            return Err("invalid bounded network policy".into());
        }
        let mut keys = BTreeSet::new();
        let mut nodes = BTreeSet::new();
        for edge in &self.edges {
            if !label(&edge.source)
                || !label(&edge.destination)
                || !label(&edge.scope)
                || edge.source == edge.destination
                || edge.epoch == 0
                || !keys.insert((&edge.source, &edge.destination, &edge.scope))
            {
                return Err("invalid, repeated or self-directed consent edge".into());
            }
            nodes.insert(&edge.source);
            nodes.insert(&edge.destination);
        }
        if nodes.len() > 16 {
            return Err("network identity budget exceeded".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeEnvelope {
    pub schema: String,
    pub record: KnowledgeRecord,
    /// Origin and prior route are claims until checked against independent hops.
    pub claimed_origin: String,
    pub route: Vec<String>,
}
impl KnowledgeEnvelope {
    pub fn local(record: KnowledgeRecord, owner: &str) -> Result<Self, String> {
        record.validate()?;
        if !label(owner) {
            return Err("invalid envelope owner".into());
        }
        Ok(Self {
            schema: "symbiote.network-envelope/1".into(),
            record,
            claimed_origin: owner.into(),
            route: vec![owner.into()],
        })
    }
    pub fn validate(&self) -> Result<(), String> {
        self.record.validate()?;
        if self.schema != "symbiote.network-envelope/1"
            || !label(&self.claimed_origin)
            || self.route.is_empty()
            || self.route.len() > 9
            || self.route.first() != Some(&self.claimed_origin)
            || self.route.iter().any(|id| !label(id))
            || self.route.iter().collect::<BTreeSet<_>>().len() != self.route.len()
        {
            return Err("invalid, cyclic or excessive claimed provenance route".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ForwardReceipt {
    pub sequence: usize,
    pub source: String,
    pub destination: String,
    pub scope: String,
    pub consent_epoch: u64,
    pub envelope_sha256: String,
    pub record_sha256: String,
    pub reserved_bytes: usize,
    pub outcome: String,
    pub previous_sha256: String,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkSnapshot {
    pub schema: String,
    pub policy_sha256: String,
    pub revoked: Vec<(String, String, String)>,
    pub receipts: Vec<ForwardReceipt>,
    pub sha256: String,
}
pub struct SymbioticNetwork {
    policy: NetworkPolicy,
    snapshot: NetworkSnapshot,
    spent_bytes: usize,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}
impl SymbioticNetwork {
    /// Caller persists snapshots outside owner knowledge stores. Reopening does
    /// not refund failed attempts or restore revoked edges. A changed policy
    /// requires a separately reviewed new session; snapshots cannot grant edges.
    pub fn open(
        policy: NetworkPolicy,
        prior: Option<NetworkSnapshot>,
        expected_snapshot_sha256: Option<&str>,
        timeout: Duration,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self, String> {
        policy.validate()?;
        if timeout.is_zero() || timeout > Duration::from_secs(3600) {
            return Err("network session needs a bounded positive deadline".into());
        }
        let policy_sha256 = digest(&policy)?;
        if prior.is_some() != expected_snapshot_sha256.is_some() {
            return Err(
                "reopened network requires an independently retained current snapshot pin".into(),
            );
        }
        if let Some(saved) = &prior {
            let mut body = saved.clone();
            body.sha256.clear();
            if expected_snapshot_sha256 != Some(saved.sha256.as_str())
                || digest(&body)? != saved.sha256
            {
                return Err(
                    "network snapshot digest mismatch; preserve the current external anchor".into(),
                );
            }
        }
        let snapshot = prior.unwrap_or_else(|| NetworkSnapshot {
            schema: "symbiote.network-state/1".into(),
            policy_sha256: policy_sha256.clone(),
            revoked: Vec::new(),
            receipts: Vec::new(),
            sha256: String::new(),
        });
        if snapshot.schema != "symbiote.network-state/1"
            || snapshot.policy_sha256 != policy_sha256
            || snapshot.receipts.len() > policy.limits.attempts
            || snapshot.revoked.len() > policy.edges.len()
        {
            return Err("network snapshot policy or bounds rejected".into());
        }
        let mut previous = "0".repeat(64);
        let mut spent_bytes = 0_usize;
        for (index, receipt) in snapshot.receipts.iter().enumerate() {
            let edge = policy
                .edges
                .iter()
                .find(|edge| {
                    edge.source == receipt.source
                        && edge.destination == receipt.destination
                        && edge.scope == receipt.scope
                })
                .ok_or("forward history contains an unconsented edge")?;
            let mut body = receipt.clone();
            body.sha256.clear();
            if receipt.sequence != index + 1
                || receipt.previous_sha256 != previous
                || !edge.source_granted
                || !edge.destination_granted
                || edge.epoch != receipt.consent_epoch
                || !["delivered-inert", "delivery-unknown"].contains(&receipt.outcome.as_str())
                || receipt.reserved_bytes == 0
                || receipt.reserved_bytes > policy.limits.payload_bytes
                || receipt.envelope_sha256.len() != 64
                || receipt.record_sha256.len() != 64
                || digest(&body)? != receipt.sha256
            {
                return Err("forward history integrity rejected".into());
            }
            spent_bytes = spent_bytes
                .checked_add(receipt.reserved_bytes)
                .ok_or("network byte overflow")?;
            previous = receipt.sha256.clone();
        }
        if spent_bytes > policy.limits.total_bytes {
            return Err("network snapshot exceeds byte budget".into());
        }
        let mut revocations = BTreeSet::new();
        for key in &snapshot.revoked {
            if !revocations.insert(key)
                || !policy.edges.iter().any(|edge| {
                    (&edge.source, &edge.destination, &edge.scope) == (&key.0, &key.1, &key.2)
                })
            {
                return Err("unknown or duplicate revoked edge".into());
            }
        }
        Ok(Self {
            policy,
            snapshot,
            spent_bytes,
            deadline: Instant::now() + timeout,
            cancelled,
        })
    }
    pub fn snapshot(&self) -> Result<NetworkSnapshot, String> {
        let mut snapshot = self.snapshot.clone();
        snapshot.sha256.clear();
        snapshot.sha256 = digest(&snapshot)?;
        Ok(snapshot)
    }
    pub fn revoke(&mut self, source: &str, destination: &str, scope: &str) -> Result<(), String> {
        if !self.policy.edges.iter().any(|edge| {
            edge.source == source && edge.destination == destination && edge.scope == scope
        }) {
            return Err("cannot revoke an undeclared edge".into());
        }
        let key = (source.into(), destination.into(), scope.into());
        if !self.snapshot.revoked.contains(&key) {
            self.snapshot.revoked.push(key);
        }
        Ok(())
    }
    /// `transmit` is an operator-bound authenticated adapter. Remote envelopes
    /// never choose endpoints, supply credentials or become executable code.
    /// The adapter must obey the supplied absolute deadline and cancellation.
    pub fn forward<F>(
        &mut self,
        source: &str,
        destination: &str,
        envelope: &KnowledgeEnvelope,
        transmit: F,
    ) -> Result<ForwardReceipt, String>
    where
        F: FnOnce(&KnowledgeEnvelope, Instant, &AtomicBool) -> Result<(), String>,
    {
        envelope.validate()?;
        if self.cancelled.load(Ordering::Relaxed) || Instant::now() >= self.deadline {
            return Err("network cancelled or expired before dispatch".into());
        }
        let edge = self
            .policy
            .edges
            .iter()
            .find(|edge| {
                edge.source == source
                    && edge.destination == destination
                    && edge.scope == envelope.record.scope
            })
            .ok_or("network edge is not explicitly registered")?;
        let key = (
            source.into(),
            destination.into(),
            envelope.record.scope.clone(),
        );
        if !edge.source_granted
            || !edge.destination_granted
            || self.snapshot.revoked.contains(&key)
            || envelope.route.last().map(String::as_str) != Some(source)
            || envelope.route.iter().any(|id| id == destination)
            || envelope.route.len() > self.policy.limits.hops
        {
            return Err("mutual consent, custody, revocation or hop limit rejected".into());
        }
        if envelope.route.len() > 1 {
            let incoming = digest(envelope)?;
            let record_sha256 = envelope.record.digest()?;
            if !self.snapshot.receipts.iter().any(|receipt| {
                receipt.outcome == "delivered-inert"
                    && receipt.destination == source
                    && receipt.scope == envelope.record.scope
                    && receipt.envelope_sha256 == incoming
                    && receipt.record_sha256 == record_sha256
            }) {
                return Err(
                    "forwarded custody requires an observed successful exact preceding hop".into(),
                );
            }
        }
        let mut forwarded = envelope.clone();
        forwarded.route.push(destination.into());
        let bytes = serde_json::to_vec(&forwarded).map_err(|e| e.to_string())?;
        if bytes.len() > self.policy.limits.payload_bytes
            || self.snapshot.receipts.len() >= self.policy.limits.attempts
            || self
                .spent_bytes
                .checked_add(bytes.len())
                .is_none_or(|n| n > self.policy.limits.total_bytes)
        {
            return Err("aggregate network budget exhausted before dispatch".into());
        }
        self.spent_bytes += bytes.len();
        let mut receipt = ForwardReceipt {
            sequence: self.snapshot.receipts.len() + 1,
            source: source.into(),
            destination: destination.into(),
            scope: envelope.record.scope.clone(),
            consent_epoch: edge.epoch,
            envelope_sha256: digest(&forwarded)?,
            record_sha256: envelope.record.digest()?,
            reserved_bytes: bytes.len(),
            outcome: "delivery-unknown".into(),
            previous_sha256: self
                .snapshot
                .receipts
                .last()
                .map(|r| r.sha256.clone())
                .unwrap_or_else(|| "0".repeat(64)),
            sha256: String::new(),
        };
        let result = catch_unwind(AssertUnwindSafe(|| {
            transmit(&forwarded, self.deadline, &self.cancelled)
        }));
        let timely = Instant::now() < self.deadline && !self.cancelled.load(Ordering::Relaxed);
        let confirmed = matches!(&result, Ok(Ok(()))) && timely;
        if confirmed {
            receipt.outcome = "delivered-inert".into();
        }
        receipt.sha256 = digest(&receipt)?;
        self.snapshot.receipts.push(receipt.clone());
        if !confirmed {
            return Err("delivery unconfirmed, cancelled, late or adapter panicked; attempt remains charged".into());
        }
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy(attempts: usize) -> NetworkPolicy {
        NetworkPolicy {
            schema: "symbiote.network-policy/1".into(),
            coordinator: "coordinator".into(),
            edges: [("a", "b"), ("b", "c")]
                .into_iter()
                .map(|(a, b)| EdgeConsent {
                    source: a.into(),
                    destination: b.into(),
                    scope: "demo".into(),
                    source_granted: true,
                    destination_granted: true,
                    epoch: 1,
                })
                .collect(),
            limits: NetworkLimits {
                attempts,
                payload_bytes: 4096,
                total_bytes: 8192,
                hops: 2,
            },
        }
    }
    fn envelope() -> KnowledgeEnvelope {
        KnowledgeEnvelope::local(KnowledgeRecord { id:"finding".into(),revision:1,source:"a".into(),scope:"demo".into(),
            schema_fingerprint:symbiote_memory::knowledge::affine_schema_fingerprint(2).unwrap(),
            payload:serde_json::json!({"kind":"affine","width":2,"coefficients":3,"bias":false}),provenance:"local evaluated fixture".into() },"a").unwrap()
    }
    fn open(policy: NetworkPolicy, prior: Option<NetworkSnapshot>) -> SymbioticNetwork {
        let expected = prior.as_ref().map(|snapshot| snapshot.sha256.clone());
        SymbioticNetwork::open(
            policy,
            prior,
            expected.as_deref(),
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap()
    }
    #[test]
    fn multi_hop_preserves_inert_origin_and_requires_each_edge() {
        let mut network = open(policy(2), None);
        let mut next = None;
        network
            .forward("a", "b", &envelope(), |body, _, _| {
                next = Some(body.clone());
                Ok(())
            })
            .unwrap();
        let second = network
            .forward("b", "c", &next.unwrap(), |body, _, _| {
                assert_eq!(body.route, ["a", "b", "c"]);
                assert_eq!(body.record.source, "a");
                Ok(())
            })
            .unwrap();
        assert_eq!(second.sequence, 2);
        assert_eq!(second.outcome, "delivered-inert");
        assert!(network
            .forward("a", "c", &envelope(), |_, _, _| panic!("unconsented link"))
            .is_err());
        open(policy(2), Some(network.snapshot().unwrap()));
    }
    #[test]
    fn denied_failed_and_reopened_sessions_never_refund_or_restore_consent() {
        let mut network = open(policy(1), None);
        assert!(network
            .forward("a", "b", &envelope(), |_, _, _| Err("disconnect".into()))
            .is_err());
        let mut reopened = open(policy(1), Some(network.snapshot().unwrap()));
        assert!(reopened
            .forward("a", "b", &envelope(), |_, _, _| panic!("refunded attempt"))
            .is_err());
        let mut network = open(policy(2), None);
        network.revoke("a", "b", "demo").unwrap();
        let mut reopened = open(policy(2), Some(network.snapshot().unwrap()));
        assert!(reopened
            .forward("a", "b", &envelope(), |_, _, _| panic!(
                "revived denied edge"
            ))
            .is_err());
        let mut changed = policy(2);
        changed.edges[0].destination_granted = false;
        assert!(open(changed, None)
            .forward("a", "b", &envelope(), |_, _, _| panic!(
                "unilateral consent"
            ))
            .is_err());
    }
    #[test]
    fn changed_policy_tampered_history_cycles_and_cancel_fail_before_dispatch() {
        let mut network = open(policy(2), None);
        network
            .forward("a", "b", &envelope(), |_, _, _| Ok(()))
            .unwrap();
        let mut snapshot = network.snapshot().unwrap();
        let pin = snapshot.sha256.clone();
        snapshot.receipts[0].reserved_bytes += 1;
        assert!(SymbioticNetwork::open(
            policy(2),
            Some(snapshot),
            Some(&pin),
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false))
        )
        .is_err());
        let mut changed = policy(2);
        changed.edges[0].epoch = 2;
        assert!(SymbioticNetwork::open(
            changed,
            Some(network.snapshot().unwrap()),
            Some(&pin),
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false))
        )
        .is_err());
        let flag = Arc::new(AtomicBool::new(true));
        let mut network =
            SymbioticNetwork::open(policy(2), None, None, Duration::from_secs(1), flag).unwrap();
        assert!(network
            .forward("a", "b", &envelope(), |_, _, _| panic!("cancel ignored"))
            .is_err());
        let mut cycle = envelope();
        cycle.route.push("a".into());
        assert!(cycle.validate().is_err());
    }
    #[test]
    fn deleting_revocation_or_forging_custody_cannot_reopen_consent() {
        let mut network = open(policy(2), None);
        network.revoke("a", "b", "demo").unwrap();
        let mut snapshot = network.snapshot().unwrap();
        let pin = snapshot.sha256.clone();
        snapshot.revoked.clear();
        snapshot.sha256.clear();
        snapshot.sha256 = digest(&snapshot).unwrap();
        assert!(SymbioticNetwork::open(
            policy(2),
            Some(snapshot),
            Some(&pin),
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false))
        )
        .is_err());
        let mut network = open(policy(2), None);
        let mut forged = envelope();
        forged.route.push("b".into());
        assert!(network
            .forward("b", "c", &forged, |_, _, _| panic!("invented custody"))
            .is_err());
    }
    #[test]
    fn adapter_panic_and_late_cancellation_charge_unknown_delivery() {
        let mut network = open(policy(1), None);
        assert!(network
            .forward("a", "b", &envelope(), |_, _, _| panic!(
                "owned adapter failure"
            ))
            .is_err());
        assert_eq!(
            network.snapshot().unwrap().receipts[0].outcome,
            "delivery-unknown"
        );
        let mut network = open(policy(1), None);
        assert!(network
            .forward("a", "b", &envelope(), |_, _, flag| {
                flag.store(true, Ordering::Relaxed);
                Ok(())
            })
            .is_err());
        assert_eq!(
            network.snapshot().unwrap().receipts[0].outcome,
            "delivery-unknown"
        );
    }
}
