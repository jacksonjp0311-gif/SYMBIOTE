pub use crate::service::observation::Observation;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
pub use symbiote_memory::knowledge::KnowledgeAnchor;
pub use symbiote_reasoning::structural::AffineQueryPolicy;

/// Stable error categories; diagnostics are for humans, never control flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Malformed,
    Authorization,
    IncompatibleSchema,
    Uncertain,
    Contradiction,
    Revoked,
    BudgetExhausted,
    Cancelled,
    DeadlineExceeded,
    Storage,
    OwnerBusy,
    AlreadyExists,
    NotFound,
    Closed,
    Hold,
    EventSink,
    CommittedEventSink,
}
#[derive(Clone, Debug, Serialize)]
pub struct EngineError {
    pub kind: ErrorKind,
    pub operation: &'static str,
    pub diagnostic: String,
    pub committed: Option<KnowledgeAnchor>,
}
impl EngineError {
    pub(crate) fn new(
        kind: ErrorKind,
        operation: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            operation,
            diagnostic: message.into(),
            committed: None,
        }
    }
}
impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} during {}: {}",
            self.kind, self.operation, self.diagnostic
        )
    }
}
impl std::error::Error for EngineError {}
pub type Result<T> = std::result::Result<T, EngineError>;

/// Caller-pinned authorization. An adapter's self-description is not permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDescriptor {
    pub source_id: String,
    pub scope: String,
    pub epoch: String,
    pub commitment: String,
    pub width: u8,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineConfig {
    pub schema: String,
    pub authorized_sources: Vec<SourceDescriptor>,
    pub max_queries_per_episode: usize,
    pub max_gf2_work_per_episode: usize,
    pub max_duration_ms: u64,
}
impl EngineConfig {
    pub fn new(authorized_sources: Vec<SourceDescriptor>) -> Self {
        Self {
            schema: "symbiote.engine-config/1".into(),
            authorized_sources,
            max_queries_per_episode: 256,
            max_gf2_work_per_episode: 1_000_000,
            max_duration_ms: 60_000,
        }
    }
}
#[derive(Clone, Debug)]
pub struct EpisodeOptions {
    pub source: SourceDescriptor,
    pub max_queries: usize,
    pub max_gf2_work: usize,
    pub heldout_cases: usize,
    pub duration: Duration,
    pub query_policy: AffineQueryPolicy,
}
impl EpisodeOptions {
    pub fn bounded(source: SourceDescriptor) -> Self {
        Self {
            source,
            max_queries: 256,
            max_gf2_work: 1_000_000,
            heldout_cases: 1,
            duration: Duration::from_secs(30),
            query_policy: AffineQueryPolicy::Reference,
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EpisodeUsage {
    pub source_calls: usize,
    pub gf2_work_units: usize,
    pub evaluation_cases: usize,
}

/// Cooperative in-process cancellation. No thread/process is silently spawned.
#[derive(Clone, Debug, Default)]
pub struct Cancellation {
    pub(crate) flag: Arc<AtomicBool>,
}
impl Cancellation {
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release)
    }
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }
}
/// Callback implementations must return by the deadline and honor cancellation.
/// A native Rust callback cannot be forcibly preempted by this library.
pub struct ObservationRequest<'a> {
    pub input: u16,
    pub sequence: usize,
    pub source: &'a SourceDescriptor,
    pub cancellation: &'a Cancellation,
    pub deadline: Instant,
}
#[derive(Clone, Debug)]
pub struct SourceError {
    pub kind: ErrorKind,
    pub diagnostic: String,
}
impl SourceError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            diagnostic: message.into(),
        }
    }
}
pub trait ObservationSource {
    fn descriptor(&self) -> SourceDescriptor;
    fn observe(
        &mut self,
        request: ObservationRequest<'_>,
    ) -> std::result::Result<Observation, SourceError>;
}
#[derive(Clone, Debug)]
pub struct SinkError {
    pub diagnostic: String,
}
impl SinkError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            diagnostic: message.into(),
        }
    }
}
pub trait EventSink {
    fn event(&mut self, event: &EngineEvent) -> std::result::Result<(), SinkError>;
}
/// Explicit sink for callers that intentionally discard presentation events.
#[derive(Default)]
pub struct NoopSink;
impl EventSink for NoopSink {
    fn event(&mut self, _: &EngineEvent) -> std::result::Result<(), SinkError> {
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum EngineEvent {
    EpisodeStarted {
        episode_id: String,
        source: SourceDescriptor,
        before: KnowledgeAnchor,
    },
    InferenceProgress {
        phase: String,
        details: Value,
    },
    CandidateReady {
        episode_id: String,
        record_sha256: String,
        usage: EpisodeUsage,
    },
    Evaluated {
        episode_id: String,
        cases: usize,
    },
    Retained {
        receipt: LearningReceipt,
    },
    Prediction {
        prediction: Prediction,
    },
    Revoked {
        artifact: String,
        before: KnowledgeAnchor,
        after: KnowledgeAnchor,
    },
    Failed {
        episode_id: String,
        kind: ErrorKind,
        usage: EpisodeUsage,
    },
}
#[derive(Clone, Debug, Serialize)]
pub struct LearningReceipt {
    pub episode_id: String,
    pub owner: String,
    pub artifact: String,
    pub record_sha256: String,
    pub before: KnowledgeAnchor,
    pub after: KnowledgeAnchor,
    pub reused: bool,
    pub usage: EpisodeUsage,
    pub conditional: bool,
    pub baseline_status: &'static str,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Abstention {
    OutsideApplicability,
    NoRetainedModel,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredictionBasis {
    Observed,
    ConditionalAffine,
    Abstained(Abstention),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Applicability {
    pub source: SourceDescriptor,
    pub schema_fingerprint: String,
    pub conditional_family: String,
    pub physical_certificate_authorized: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Prediction {
    pub owner: String,
    pub artifact: String,
    pub record_sha256: String,
    pub knowledge_at: KnowledgeAnchor,
    pub input: u16,
    pub answer: Option<u8>,
    pub basis: PredictionBasis,
    pub applicability: Applicability,
}
/// Inert exported bytes. Receiving or deserializing them never grants trust.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub schema: String,
    pub sender: String,
    pub source: SourceDescriptor,
    pub record: symbiote_memory::knowledge::KnowledgeRecord,
    pub record_sha256: String,
    pub training_inputs: Vec<u16>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Inspection {
    pub owner: String,
    pub policy_sha256: String,
    pub knowledge: KnowledgeAnchor,
    pub operational_head_sha256: String,
    pub active_artifacts: Vec<String>,
    pub cancelled: bool,
    pub pending_episode: Option<String>,
    pub startup_gf2_work_units: usize,
}

/// Compile-time package/source identity; version alone is not qualification.
#[derive(Clone, Debug, Serialize)]
pub struct EngineVersion {
    pub version: &'static str,
    pub build_source_commit: &'static str,
    pub family: &'static str,
    pub maximum_width: u8,
}
pub fn version() -> EngineVersion {
    EngineVersion {
        version: env!("CARGO_PKG_VERSION"),
        build_source_commit: option_env!("SYMBIOTE_SOURCE_COMMIT").unwrap_or("unknown"),
        family: "finite-affine-boolean/v1",
        maximum_width: 8,
    }
}

impl Artifact {
    /// Bounded inert decoding. Successful decoding is not evaluation or trust.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 16 * 1024 {
            return Err(EngineError::new(
                ErrorKind::BudgetExhausted,
                "artifact_decode",
                "artifact exceeds16KiB",
            ));
        }
        let artifact: Self = serde_json::from_slice(bytes).map_err(|e| {
            EngineError::new(ErrorKind::Malformed, "artifact_decode", e.to_string())
        })?;
        artifact.validate_shape()?;
        Ok(artifact)
    }
    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        let bytes = serde_json::to_vec(self).map_err(|e| {
            EngineError::new(ErrorKind::Malformed, "artifact_encode", e.to_string())
        })?;
        if bytes.len() > 16 * 1024 {
            return Err(EngineError::new(
                ErrorKind::BudgetExhausted,
                "artifact_encode",
                "artifact exceeds16KiB",
            ));
        }
        Ok(bytes)
    }
    pub(crate) fn validate_shape(&self) -> Result<()> {
        if self.schema != "symbiote.engine-artifact/1"
            || !super::source_valid(&self.source)
            || self.source.scope != self.record.scope
            || self.sender != self.record.source
            || self.training_inputs.len() > 256
            || self
                .training_inputs
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.training_inputs.len()
            || self
                .training_inputs
                .iter()
                .any(|i| *i >= (1u16 << self.source.width))
        {
            return Err(EngineError::new(
                ErrorKind::Malformed,
                "artifact",
                "invalid inert artifact metadata/training boundary",
            ));
        }
        if !matches!(
            self.record.typed_payload().map_err(|e| EngineError::new(
                ErrorKind::IncompatibleSchema,
                "artifact",
                e
            ))?,
            symbiote_memory::knowledge::KnowledgePayload::Affine { .. }
        ) {
            return Err(EngineError::new(
                ErrorKind::IncompatibleSchema,
                "artifact",
                "embedding supports finite affine payloads",
            ));
        }
        if self.record.schema_fingerprint
            != symbiote_memory::knowledge::affine_schema_fingerprint(self.source.width)
                .map_err(|e| EngineError::new(ErrorKind::IncompatibleSchema, "artifact", e))?
        {
            return Err(EngineError::new(
                ErrorKind::IncompatibleSchema,
                "artifact",
                "artifact source width does not match its schema",
            ));
        }
        self.record
            .validate()
            .map_err(|e| EngineError::new(ErrorKind::Malformed, "artifact", e))?;
        if self
            .record
            .digest()
            .map_err(|e| EngineError::new(ErrorKind::Malformed, "artifact", e))?
            != self.record_sha256
        {
            return Err(EngineError::new(
                ErrorKind::Malformed,
                "artifact",
                "artifact digest differs",
            ));
        }
        Ok(())
    }
}
