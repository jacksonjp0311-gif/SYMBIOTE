use super::{label, Config};
use serde::{Deserialize, Serialize};
use symbiote_memory::knowledge::KnowledgeRecord;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Offer {
    pub record: KnowledgeRecord,
    /// Sender-declared training queries; this declaration is not remote attestation.
    pub training_inputs: Vec<u16>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub(super) enum Operation {
    #[serde(rename = "capabilities")]
    Capabilities,
    #[serde(rename = "knowledge.list")]
    List {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        after: Option<String>,
    },
    #[serde(rename = "knowledge.read")]
    Read { artifact: String },
    #[serde(rename = "knowledge.predict")]
    Predict { artifact: String, input: u16 },
    #[serde(rename = "candidate.submit")]
    Submit { offer: Box<Offer> },
    #[serde(rename = "candidate.status")]
    CandidateStatus { candidate: String },
    #[serde(rename = "outcome.read")]
    OutcomeRead {
        candidate: String,
        request_sha256: String,
        challenge: String,
    },
}
impl Operation {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Capabilities => "capabilities",
            Self::List { .. } => "knowledge.list",
            Self::Read { .. } => "knowledge.read",
            Self::Predict { .. } => "knowledge.predict",
            Self::Submit { .. } => "candidate.submit",
            Self::CandidateStatus { .. } => "candidate.status",
            Self::OutcomeRead { .. } => "outcome.read",
        }
    }
    pub fn artifact(&self) -> Option<&str> {
        match self {
            Self::Read { artifact } | Self::Predict { artifact, .. } => Some(artifact),
            Self::Submit { offer } => Some(&offer.record.id),
            _ => None,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub schema: String,
    pub scope: String,
    pub request_id: String,
    pub body: Operation,
}
impl Request {
    pub fn validate(&self, config: &Config) -> Result<(), String> {
        if self.schema != "symbiote.service-request/1"
            || !label(&self.request_id)
            || !label(&self.scope)
        {
            return Err("service request version, context or idempotency key rejected".into());
        }
        let context = config.context(&self.scope)?;
        if let Operation::List { after: Some(after) } = &self.body {
            if !label(after) {
                return Err("knowledge pagination cursor rejected".into());
            }
        }
        if self.body.artifact().is_some_and(|id| !label(id)) {
            return Err("service artifact identifier rejected".into());
        }
        if let Operation::Submit { offer } = &self.body {
            offer
                .record
                .validate()
                .map_err(|_| "unsupported or invalid inert knowledge payload")?;
            if offer.record.scope != self.scope
                || offer.record.schema_fingerprint != context.schema_fingerprint
                || offer.training_inputs.len() > 256
                || offer
                    .training_inputs
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != offer.training_inputs.len()
            {
                return Err(
                    "candidate context, schema or declared training inputs rejected".into(),
                );
            }
            if serde_json::to_vec(self)
                .map_err(|_| "cannot canonicalize request")?
                .len()
                > config.limits.max_offer_bytes
            {
                return Err("candidate exceeds the configured quarantine object budget".into());
            }
        }
        if let Operation::CandidateStatus { candidate } = &self.body {
            if !super::config::sha(candidate) {
                return Err("candidate digest rejected".into());
            }
        }
        if let Operation::OutcomeRead {
            candidate,
            request_sha256,
            challenge,
        } = &self.body
        {
            if [candidate, request_sha256, challenge]
                .iter()
                .any(|s| !super::config::sha(s))
            {
                return Err("outcome evidence digest/challenge rejected".into());
            }
        }
        Ok(())
    }
}
