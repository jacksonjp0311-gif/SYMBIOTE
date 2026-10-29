//! Pure bounded views of actual ledger bytes. These validate native semantics,
//! not arbitrary remote honesty; callers must separately authenticate the owner,
//! operator authority, scope and current epoch. No path from evidence is opened.
use crate::knowledge::{KnowledgeAnchor, KnowledgeRecord, KnowledgeStore};
use crate::operational::{self, OperationalEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const MAX_WITNESS_BYTES: usize = 56 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerWitness {
    pub schema: String,
    pub identity: String,
    pub knowledge: String,
    pub operations: String,
    pub registration: String,
}
pub struct WitnessView {
    pub knowledge_rows: Vec<Value>,
    pub operation_rows: Vec<Value>,
    pub events: Vec<OperationalEvent>,
    pub identity: String,
}
impl LedgerWitness {
    pub fn validate(&self) -> Result<WitnessView, String> {
        if self.identity.len() > 128
            || [
                self.knowledge.len(),
                self.operations.len(),
                self.registration.len(),
            ]
            .into_iter()
            .try_fold(0usize, |sum, n| sum.checked_add(n))
            .is_none_or(|n| n > MAX_WITNESS_BYTES)
        {
            return Err("complete ledger witness raw bytes exceed bound".into());
        }
        if self.schema != "symbiote.ledger-witness/1"
            || serde_json::to_vec(self).map_err(|e| e.to_string())?.len() > MAX_WITNESS_BYTES
        {
            return Err("unsupported or oversized complete ledger witness".into());
        }
        KnowledgeStore::validate_snapshot(self.knowledge.as_bytes(), &self.identity)?;
        operational::validate_snapshot(
            self.operations.as_bytes(),
            &self.identity,
            self.registration.as_bytes(),
        )?;
        let parse = |text: &str| -> Result<Vec<Value>, String> {
            text.lines()
                .map(|line| serde_json::from_str(line).map_err(|e| e.to_string()))
                .collect()
        };
        let knowledge_rows = parse(&self.knowledge)?;
        let operation_rows = parse(&self.operations)?;
        let events = operation_rows
            .iter()
            .skip(1)
            .map(|row| serde_json::from_value(row["payload"].clone()).map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?;
        Ok(WitnessView {
            knowledge_rows,
            operation_rows,
            events,
            identity: self.identity.clone(),
        })
    }
}
impl WitnessView {
    pub fn anchor(&self, records: usize) -> Result<KnowledgeAnchor, String> {
        let row = self
            .knowledge_rows
            .get(records.checked_sub(1).ok_or("zero witness anchor")?)
            .ok_or("absent witness anchor")?;
        Ok(KnowledgeAnchor {
            identity: self.identity.clone(),
            records,
            head_sha256: row["sha256"]
                .as_str()
                .ok_or("witness anchor digest absent")?
                .into(),
        })
    }
    pub fn active_at(&self, anchor: &KnowledgeAnchor) -> Result<Vec<KnowledgeRecord>, String> {
        if &self.anchor(anchor.records)? != anchor {
            return Err("witness anchor is not its exact prefix".into());
        }
        let mut active = BTreeMap::new();
        for row in self.knowledge_rows.iter().take(anchor.records).skip(1) {
            let event = &row["payload"];
            match event["event"].as_str() {
                Some("promote" | "promote_graph") => {
                    let record: KnowledgeRecord = serde_json::from_value(event["record"].clone())
                        .map_err(|e| e.to_string())?;
                    active.insert(record.id.clone(), record);
                }
                Some("revoke") => {
                    active.remove(event["id"].as_str().ok_or("revoke id absent")?);
                }
                _ => return Err("unsupported validated witness knowledge event".into()),
            }
        }
        Ok(active.into_values().collect())
    }
    pub fn current_anchor(&self) -> Result<KnowledgeAnchor, String> {
        self.anchor(self.knowledge_rows.len())
    }
}
