//! Actual application-frame counters and declared logical prices. TLS records,
//! process resources and audit I/O are separate laboratory measurements.
use super::policy::Quota;
use serde::{Deserialize, Serialize};
use symbiote_protocol::{SecureTraffic, SecureTrafficSnapshot};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(super) struct Bill {
    pub(super) acquisitions: u64,
    pub(super) observation_purchase_attempts: u64,
    pub(super) rpc_requests: u64,
    pub(super) sessions: u64,
    pub(super) rpc_sent_bytes: u64,
    pub(super) rpc_received_bytes: u64,
    pub(super) negotiation_sent_bytes: u64,
    pub(super) negotiation_received_bytes: u64,
    pub(super) verified_receipts: u64,
    pub(super) receipt_verification_attempts: u64,
    pub(super) adopted_edges: u64,
    pub(super) received_attempts: u64,
    pub(super) route_queries: u64,
    pub(super) model_work: u64,
    pub(super) exported_bytes: u64,
}
impl Bill {
    pub(super) fn sent(&self) -> u64 {
        self.rpc_sent_bytes + self.negotiation_sent_bytes
    }
    pub(super) fn received(&self) -> u64 {
        self.rpc_received_bytes + self.negotiation_received_bytes
    }
    pub(super) fn total(&self, price: u64) -> u64 {
        self.observation_purchase_attempts * price
            + self.rpc_requests
            + self.sessions * 2
            + self.sent().div_ceil(1024)
            + self.received().div_ceil(1024)
            + self.receipt_verification_attempts * 2
            + self.adopted_edges
            + self.route_queries
            + self.model_work
            + self.exported_bytes.div_ceil(1024)
    }
    pub(super) fn remaining(&self, edges: usize) -> Result<Quota, String> {
        let traffic = self.sent() + self.received();
        if self.observation_purchase_attempts > edges as u64
            || self.acquisitions > self.observation_purchase_attempts
            || self.rpc_requests > 256
            || self.sessions > 128
            || traffic > 1_048_576
            || self.received_attempts > 3
            || self.adopted_edges > edges as u64
            || self.model_work > 100_000
        {
            return Err("participant resource budget exhausted".into());
        }
        Ok(Quota {
            acquisitions: edges - self.observation_purchase_attempts as usize,
            attempts: 3 - self.received_attempts as usize,
            adopted_edges: edges - self.adopted_edges as usize,
            model_work: 100_000 - self.model_work as usize,
            requests: 256 - self.rpc_requests as usize,
            connections: 128 - self.sessions as usize,
            traffic: 1_048_576 - traffic as usize,
        })
    }
    pub(super) fn merge(&mut self, other: &Self) {
        self.acquisitions += other.acquisitions;
        self.observation_purchase_attempts += other.observation_purchase_attempts;
        self.rpc_requests += other.rpc_requests;
        self.sessions += other.sessions;
        self.rpc_sent_bytes += other.rpc_sent_bytes;
        self.rpc_received_bytes += other.rpc_received_bytes;
        self.negotiation_sent_bytes += other.negotiation_sent_bytes;
        self.negotiation_received_bytes += other.negotiation_received_bytes;
        self.verified_receipts += other.verified_receipts;
        self.receipt_verification_attempts += other.receipt_verification_attempts;
        self.adopted_edges += other.adopted_edges;
        self.received_attempts += other.received_attempts;
        self.route_queries += other.route_queries;
        self.model_work += other.model_work;
        self.exported_bytes += other.exported_bytes;
    }
}
pub(super) fn difference(
    after: SecureTrafficSnapshot,
    before: SecureTrafficSnapshot,
) -> Result<SecureTrafficSnapshot, String> {
    Ok(SecureTrafficSnapshot {
        rpc_sent_bytes: after
            .rpc_sent_bytes
            .checked_sub(before.rpc_sent_bytes)
            .ok_or("traffic counter regressed")?,
        rpc_received_bytes: after
            .rpc_received_bytes
            .checked_sub(before.rpc_received_bytes)
            .ok_or("traffic counter regressed")?,
        negotiation_sent_bytes: after
            .negotiation_sent_bytes
            .checked_sub(before.negotiation_sent_bytes)
            .ok_or("traffic counter regressed")?,
        negotiation_received_bytes: after
            .negotiation_received_bytes
            .checked_sub(before.negotiation_received_bytes)
            .ok_or("traffic counter regressed")?,
        connection_attempts: after
            .connection_attempts
            .checked_sub(before.connection_attempts)
            .ok_or("connection counter regressed")?,
    })
}
pub(super) fn add_traffic(bill: &mut Bill, snapshot: SecureTrafficSnapshot) {
    bill.rpc_sent_bytes += snapshot.rpc_sent_bytes;
    bill.rpc_received_bytes += snapshot.rpc_received_bytes;
    bill.negotiation_sent_bytes += snapshot.negotiation_sent_bytes;
    bill.negotiation_received_bytes += snapshot.negotiation_received_bytes;
    bill.sessions += snapshot.connection_attempts;
}
pub(super) struct Meter {
    pub(super) counters: Bill,
    pub(super) server_start: SecureTrafficSnapshot,
    pub(super) outgoing: Vec<SecureTraffic>,
}
impl Meter {
    pub(super) fn new(server_start: SecureTrafficSnapshot) -> Self {
        Self {
            counters: Bill::default(),
            server_start,
            outgoing: Vec::new(),
        }
    }
    pub(super) fn snapshot(&self, server: &SecureTraffic, work: usize) -> Result<Bill, String> {
        let mut bill = self.counters.clone();
        bill.model_work = work as u64;
        add_traffic(&mut bill, difference(server.snapshot(), self.server_start)?);
        for traffic in &self.outgoing {
            add_traffic(&mut bill, traffic.snapshot());
        }
        Ok(bill)
    }
}
