use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::VecDeque;

/// An authorized observation, not a learning or correctness certificate.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Telemetry {
    pub agent_id: String,
    pub sequence: u64,
    pub task: String,
    pub action: String,
    pub tool: Option<String>,
    pub success: bool,
    pub resource_units: u64,
    pub confidence: Option<f64>,
    pub feedback: Value,
    pub error: Option<String>,
    pub recovered: bool,
}

impl Telemetry {
    pub fn validate(&self) -> Result<(), String> {
        if self.agent_id.is_empty() || self.agent_id.len() > 128 {
            return Err("invalid telemetry identity".into());
        }
        if self.task.len() > 256 || self.action.len() > 256 {
            return Err("telemetry label budget exceeded".into());
        }
        if self
            .confidence
            .is_some_and(|v| !v.is_finite() || !(0.0..=1.0).contains(&v))
        {
            return Err("confidence must be finite and within [0,1]".into());
        }
        if serde_json::to_vec(self).map_err(|e| e.to_string())?.len() > 16_384 {
            return Err("telemetry byte budget exceeded".into());
        }
        Ok(())
    }
}

/// Implementations collect only signals covered by an established authorization.
pub trait Sensor {
    fn collect(&mut self) -> Result<Vec<Telemetry>, String>;
}

/// Bounded per-partner residue memory. Old records are evicted irrespective of weight.
#[derive(Clone, Debug)]
pub struct EchoBuffer {
    capacity: usize,
    records: VecDeque<Telemetry>,
}

impl EchoBuffer {
    pub fn new(capacity: usize) -> Result<Self, String> {
        if !(2..=4096).contains(&capacity) {
            return Err("echo capacity must be in 2..=4096".into());
        }
        Ok(Self {
            capacity,
            records: VecDeque::with_capacity(capacity),
        })
    }

    pub fn push(&mut self, record: Telemetry) -> Result<(), String> {
        record.validate()?;
        if let Some(last) = self.records.back() {
            if last.agent_id != record.agent_id || record.sequence <= last.sequence {
                return Err("echo identity mismatch or nonmonotonic sequence".into());
            }
        }
        if self.records.len() == self.capacity {
            self.records.pop_front();
        }
        self.records.push_back(record);
        Ok(())
    }

    pub fn records(&self) -> &VecDeque<Telemetry> {
        &self.records
    }
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn success_rate(&self) -> Option<f64> {
        if self.records.is_empty() {
            return None;
        }
        Some(self.records.iter().filter(|r| r.success).count() as f64 / self.records.len() as f64)
    }

    /// Absolute difference between older and newer half-window success rates.
    /// This is a reassessment signal, not evidence of learning or causal influence.
    pub fn drift(&self) -> Option<f64> {
        if self.records.len() < 2 {
            return None;
        }
        let middle = self.records.len() / 2;
        let old = self
            .records
            .iter()
            .take(middle)
            .filter(|r| r.success)
            .count() as f64
            / middle as f64;
        let new = self
            .records
            .iter()
            .skip(middle)
            .filter(|r| r.success)
            .count() as f64
            / (self.records.len() - middle) as f64;
        Some((new - old).abs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(sequence: u64, success: bool) -> Telemetry {
        Telemetry {
            agent_id: "agent".into(),
            sequence,
            task: "finite".into(),
            action: "predict".into(),
            tool: None,
            success,
            resource_units: 1,
            confidence: None,
            feedback: Value::Null,
            error: None,
            recovered: false,
        }
    }
    #[test]
    fn fifo_is_bounded_and_reports_observable_drift() {
        let mut buffer = EchoBuffer::new(4).unwrap();
        for i in 0..6 {
            buffer.push(record(i, i >= 4)).unwrap();
        }
        assert_eq!(buffer.len(), 4);
        assert_eq!(buffer.records().front().unwrap().sequence, 2);
        assert_eq!(buffer.success_rate(), Some(0.5));
        assert_eq!(buffer.drift(), Some(1.0));
    }
    #[test]
    fn rejects_replay_identity_bad_confidence_and_unbounded_capacity() {
        assert!(EchoBuffer::new(0).is_err());
        assert!(EchoBuffer::new(4097).is_err());
        let mut buffer = EchoBuffer::new(2).unwrap();
        buffer.push(record(1, true)).unwrap();
        assert!(buffer.push(record(1, true)).is_err());
        let mut wrong = record(2, true);
        wrong.agent_id = "other".into();
        assert!(buffer.push(wrong).is_err());
        let mut bad = record(2, true);
        bad.confidence = Some(f64::NAN);
        assert!(buffer.push(bad).is_err());
        assert_eq!(buffer.len(), 1);
    }
}
