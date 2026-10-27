//! Inert observation envelopes. Digest agreement is integrity metadata; only the
//! explicitly pinned authority can authenticate an issued receipt.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use symbiote_memory::knowledge::graph::{
    graph_receipt_digest, graph_schema_fingerprint, GraphAcquisition,
};
use symbiote_reasoning::planning::GraphSchema;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    pub(super) schema: String,
    pub(super) authority_id: String,
    pub(super) context: String,
    pub(super) schema_fingerprint: String,
    pub(super) observer_identity: String,
    pub(super) sequence: u64,
    pub(super) id: String,
    pub(super) edge_id: usize,
    pub(super) cost: u16,
}
impl Receipt {
    pub(super) fn value(&self) -> Result<Value, String> {
        let value = serde_json::to_value(self).map_err(|e| e.to_string())?;
        if serde_json::to_vec(&value).map_err(|e| e.to_string())?.len() > 2048 {
            return Err("single observation receipt exceeds its frozen 2048-byte bound".into());
        }
        Ok(value)
    }
    pub(super) fn digest(&self) -> Result<String, String> {
        graph_receipt_digest(&self.value()?)
    }
    pub(super) fn acquisition(&self) -> Result<GraphAcquisition, String> {
        Ok(GraphAcquisition {
            id: self.id.clone(),
            edge_id: self.edge_id,
            cost: self.cost,
            receipt_sha256: self.digest()?,
            receipt: self.value()?,
        })
    }
    pub(super) fn applicable(
        &self,
        context: &str,
        schema: &GraphSchema,
        observer: &str,
        edge_id: usize,
    ) -> Result<(), String> {
        self.value()?;
        let edge = schema
            .edges
            .get(edge_id)
            .ok_or("received edge outside declared schema")?;
        if self.schema != "symbiote.graph-observation/1"
            || self.context != context
            || self.schema_fingerprint != graph_schema_fingerprint(schema)?
            || self.observer_identity != observer
            || self.edge_id != edge_id
            || self.cost < edge.lower
            || self.cost > edge.upper
        {
            return Err("received observation is not applicable to this exact owner/context/schema/frontier".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Verification {
    pub(super) authentic: bool,
    pub(super) applicable: bool,
    pub(super) receipt_sha256: String,
    pub(super) reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use symbiote_memory::knowledge::graph::{GraphMap, GraphObservation};
    use symbiote_reasoning::planning::Edge;
    fn schema() -> GraphSchema {
        GraphSchema {
            nodes: 8,
            edges: (0..8)
                .flat_map(|from| {
                    (from + 1..8).map(move |to| Edge {
                        from,
                        to,
                        lower: 1,
                        upper: 9,
                    })
                })
                .collect(),
        }
    }
    fn receipt(observer: char, edge_id: usize, cost: u16, sequence: u64) -> Receipt {
        let mut receipt = Receipt {
            schema: "symbiote.graph-observation/1".into(),
            authority_id: "d".repeat(64),
            context: format!("frontier-context-{}", "e".repeat(64)),
            schema_fingerprint: graph_schema_fingerprint(&schema()).unwrap(),
            observer_identity: format!("symbiote-{}", observer.to_string().repeat(24)),
            sequence,
            id: String::new(),
            edge_id,
            cost,
        };
        receipt.id = graph_receipt_digest(&serde_json::to_value(&receipt).unwrap()).unwrap();
        receipt
    }
    #[test]
    fn full_twenty_eight_edge_exports_have_equal_local_and_peer_bookkeeping_lengths() {
        let schema = schema();
        assert_eq!(schema.edges.len(), 28);
        let mut local = Vec::new();
        let mut peer = Vec::new();
        for edge in 0..28 {
            let cost = (edge % 9 + 1) as u16;
            let own = receipt('a', edge, cost, 1_000_000_000 + edge as u64);
            let other = receipt('b', edge, cost, 1_000_000_100 + edge as u64);
            own.applicable(&own.context, &schema, &own.observer_identity, edge)
                .unwrap();
            other
                .applicable(&other.context, &schema, &other.observer_identity, edge)
                .unwrap();
            assert_eq!(
                serde_json::to_vec(&own.value().unwrap()).unwrap().len(),
                serde_json::to_vec(&other.value().unwrap()).unwrap().len()
            );
            local.push(own.acquisition().unwrap());
            peer.push(other.acquisition().unwrap());
        }
        assert_eq!(local.chunks(8).len(), peer.chunks(8).len());
        for (left, right) in local.chunks(8).zip(peer.chunks(8)) {
            let left = json!({"acquisitions":left,"next":Some(8)});
            let right = json!({"acquisitions":right,"next":Some(8)});
            let first = serde_json::to_vec(&left).unwrap();
            let second = serde_json::to_vec(&right).unwrap();
            assert_eq!(first.len(), second.len());
            assert!(first.len() < 15_000);
        }
        let map = GraphMap::new(
            schema,
            local
                .iter()
                .map(|entry| GraphObservation {
                    edge_id: entry.edge_id,
                    cost: entry.cost,
                })
                .collect(),
        )
        .unwrap();
        let record = serde_json::json!({"record":{"id":"map-frontier-context-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","revision":1,"source":"symbiote-aaaaaaaaaaaaaaaaaaaaaaaa","scope":"frontier-context-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","schema_fingerprint":graph_schema_fingerprint(&map.schema).unwrap(),"payload":map.to_payload().unwrap(),"provenance":"Native stationary graph map; exact per-edge observation origins retained in authenticated inert envelopes."},"training_tasks":[{"id":"main","input":7},{"id":"warmup","input":1}]});
        assert!(serde_json::to_vec(&record).unwrap().len() < 15_000);
    }
}
