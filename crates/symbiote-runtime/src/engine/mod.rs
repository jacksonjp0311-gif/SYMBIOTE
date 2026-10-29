//! Typed, finite embedding API. The host owns paths, explicit source authority,
//! callbacks and supervision. No presentation, process spawning or global input
//! is performed here. Affine answers remain conditional on the declared family.
pub mod counters;
pub mod exchange;
mod journal;
pub mod recovery;
mod types;
use crate::service::observation::{self, InferenceFailure, ObservationPermit, Usage};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};
use symbiote_memory::{
    knowledge::{
        affine_schema_fingerprint, assess, Assessment, KnowledgeRecord, KnowledgeStore,
        MemoryWriteError, TrialCosts, TrialEvidence,
    },
    operational::OperationalJournal,
    EngineOwnerError, Store,
};
use symbiote_reasoning::structural::CompactAffineLearner;
pub use types::*;
const SERVICE: &str = "embedding-engine/v1";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Audit {
    pub(crate) schema: String,
    pub(crate) owner: String,
    pub(crate) episode: String,
    pub(crate) source: SourceDescriptor,
    pub(crate) policy_sha256: String,
    pub(crate) queries: Vec<Observation>,
    pub(crate) training: usize,
    pub(crate) snapshot: Value,
    pub(crate) incoming_artifact_sha256: Option<String>,
}
pub(crate) struct Pending {
    pub(crate) episode: String,
    pub(crate) source: SourceDescriptor,
    pub(crate) before: KnowledgeAnchor,
    pub(crate) audit: Option<Audit>,
    pub(crate) record_sha256: Option<String>,
    pub(crate) usage: EpisodeUsage,
    pub(crate) reused: Option<bool>,
    pub(crate) evaluated_cases: Option<usize>,
}
pub(crate) struct EngineState {
    pub(crate) owner: Arc<Store>,
    pub(crate) knowledge: KnowledgeStore,
    pub(crate) journal: OperationalJournal,
    pub(crate) config: EngineConfig,
    pub(crate) policy_sha256: String,
    pub(crate) pending: Option<Pending>,
    pub(crate) replay_gf2_work: usize,
    pub(crate) poisoned: bool,
}
pub struct Engine {
    pub(crate) inner: Option<EngineState>,
    cancellation: Cancellation,
}
/// Opaque receiver-local observations, not a deserializable trust token.
pub struct Candidate {
    pub(crate) owner: String,
    pub(crate) policy: String,
    pub(crate) episode: String,
    pub(crate) before: KnowledgeAnchor,
    pub(crate) record: KnowledgeRecord,
    pub(crate) audit: Audit,
    pub(crate) evidence: TrialEvidence,
    pub(crate) usage: EpisodeUsage,
    pub(crate) reused: bool,
    pub(crate) deadline: Instant,
}
impl Candidate {
    pub fn record(&self) -> &KnowledgeRecord {
        &self.record
    }
    pub fn usage(&self) -> &EpisodeUsage {
        &self.usage
    }
}
/// Only this engine's evaluated candidate may cross its retention boundary.
pub struct EvaluatedCandidate {
    pub(crate) candidate: Candidate,
    pub(crate) assessment: Option<Assessment>,
}
impl EvaluatedCandidate {
    pub fn record(&self) -> &KnowledgeRecord {
        &self.candidate.record
    }
    pub fn usage(&self) -> &EpisodeUsage {
        &self.candidate.usage
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct ClosedEngine {
    pub state: PathBuf,
    pub owner: String,
    pub knowledge: KnowledgeAnchor,
    pub(crate) pins: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub snapshot: PathBuf,
    pub owner: String,
    pub manifest_sha256: String,
    pub original_state: PathBuf,
}
#[derive(Clone, Debug, Serialize)]
pub struct RestoreReceipt {
    pub owner: String,
    pub manifest_sha256: String,
    pub restore_mapping_sha256: String,
    pub network_started: bool,
    pub rollback_discards_later_learning: bool,
}
pub(crate) fn digest<T: Serialize>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| EngineError::new(ErrorKind::Malformed, "serialize", e.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
fn label(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 128
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:/-".contains(&c))
}
fn hash(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn storage(operation: &'static str, message: String) -> EngineError {
    EngineError::new(ErrorKind::Storage, operation, message)
}
fn memory_write(operation: &'static str, error: MemoryWriteError) -> EngineError {
    match error {
        MemoryWriteError::Capacity(message) => {
            EngineError::new(ErrorKind::BudgetExhausted, operation, message)
        }
        MemoryWriteError::Invalid(message) => {
            EngineError::new(ErrorKind::Contradiction, operation, message)
        }
        MemoryWriteError::Integrity(message) => {
            EngineError::new(ErrorKind::Hold, operation, message)
        }
        MemoryWriteError::Storage(message) => storage(operation, message),
        error => storage(operation, error.to_string()),
    }
}
fn absolute(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(EngineError::new(
            ErrorKind::Malformed,
            "path",
            "caller must provide an absolute path",
        ));
    }
    Ok(())
}
fn source_valid(source: &SourceDescriptor) -> bool {
    label(&source.source_id)
        && label(&source.scope)
        && label(&source.epoch)
        && hash(&source.commitment)
        && (1..=8).contains(&source.width)
}
fn config_valid(config: &EngineConfig) -> Result<()> {
    if config.schema != "symbiote.engine-config/1"
        || config.authorized_sources.is_empty()
        || config.authorized_sources.len() > 8
        || !config.authorized_sources.iter().all(source_valid)
        || config
            .authorized_sources
            .iter()
            .map(|s| &s.scope)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != config.authorized_sources.len()
        || !(1..=256).contains(&config.max_queries_per_episode)
        || !(1..=1_000_000).contains(&config.max_gf2_work_per_episode)
        || !(1..=60_000).contains(&config.max_duration_ms)
    {
        return Err(EngineError::new(
            ErrorKind::Malformed,
            "config",
            "invalid explicit bounded engine configuration",
        ));
    }
    Ok(())
}
fn emit(sink: &mut impl EventSink, event: EngineEvent) -> Result<()> {
    sink.event(&event)
        .map_err(|e| EngineError::new(ErrorKind::EventSink, "event_sink", e.diagnostic))
}
fn inferred_error(error: InferenceFailure) -> EngineError {
    let kind = match &error {
        InferenceFailure::Malformed(_) => ErrorKind::Malformed,
        InferenceFailure::IncompatibleSchema(_) => ErrorKind::IncompatibleSchema,
        InferenceFailure::Uncertain(_) => ErrorKind::Uncertain,
        InferenceFailure::Contradiction(_) => ErrorKind::Contradiction,
        InferenceFailure::BudgetExhausted(_) => ErrorKind::BudgetExhausted,
        InferenceFailure::Cancelled => ErrorKind::Cancelled,
        InferenceFailure::DeadlineExceeded => ErrorKind::DeadlineExceeded,
        InferenceFailure::Source(_) => ErrorKind::Authorization,
        InferenceFailure::EventSink(_) => ErrorKind::EventSink,
    };
    EngineError::new(kind, "infer", error.to_string())
}
struct SourceBridge<'a, S: ObservationSource> {
    source: &'a mut S,
    expected: SourceDescriptor,
    cancellation: Cancellation,
    sequence: usize,
    failure: Option<EngineError>,
}
impl<S: ObservationSource> observation::ObservationSource for SourceBridge<'_, S> {
    fn width(&self) -> u8 {
        self.expected.width
    }
    fn observe(
        &mut self,
        input: u16,
        _: &std::sync::atomic::AtomicBool,
        deadline: Instant,
    ) -> std::result::Result<Observation, String> {
        let result = (|| {
            if self.source.descriptor() != self.expected {
                return Err(EngineError::new(
                    ErrorKind::Authorization,
                    "observe",
                    "source descriptor changed or is not authorized",
                ));
            }
            let observation = self
                .source
                .observe(ObservationRequest {
                    input,
                    sequence: self.sequence,
                    source: &self.expected,
                    cancellation: &self.cancellation,
                    deadline,
                })
                .map_err(|e| EngineError::new(e.kind, "observe", e.diagnostic))?;
            if self.source.descriptor() != self.expected {
                return Err(EngineError::new(
                    ErrorKind::Authorization,
                    "observe",
                    "source descriptor changed after callback",
                ));
            }
            self.sequence += 1;
            Ok(observation)
        })();
        result.map_err(|error| {
            let text = error.to_string();
            self.failure = Some(error);
            text
        })
    }
}
impl Engine {
    pub fn initialize(path: &Path, config: EngineConfig) -> Result<Self> {
        absolute(path)?;
        config_valid(&config)?;
        fs::create_dir(path).map_err(|e| {
            EngineError::new(
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    ErrorKind::AlreadyExists
                } else {
                    ErrorKind::Storage
                },
                "initialize",
                e.to_string(),
            )
        })?;
        Self::load(path, None, config)
    }
    pub fn open(path: &Path, expected_owner: &str, config: EngineConfig) -> Result<Self> {
        absolute(path)?;
        config_valid(&config)?;
        for name in [
            "ledger.jsonl",
            "knowledge.jsonl",
            "operations.jsonl",
            "operations-owner.json",
        ] {
            let meta = fs::symlink_metadata(path.join(name)).map_err(|e| {
                EngineError::new(
                    if e.kind() == std::io::ErrorKind::NotFound {
                        ErrorKind::NotFound
                    } else {
                        ErrorKind::Storage
                    },
                    "open",
                    e.to_string(),
                )
            })?;
            if !meta.is_file() || meta.file_type().is_symlink() {
                return Err(EngineError::new(
                    ErrorKind::Storage,
                    "open",
                    "owner history must be regular existing files",
                ));
            }
        }
        if !label(expected_owner) {
            return Err(EngineError::new(
                ErrorKind::Malformed,
                "open",
                "expected owner identity is required",
            ));
        }
        Self::load(path, Some(expected_owner), config)
    }
    fn load(path: &Path, expected: Option<&str>, config: EngineConfig) -> Result<Self> {
        let opened = if expected.is_none() {
            Store::initialize_engine(path)
        } else {
            Store::open_engine(path)
        };
        let owner = Arc::new(opened.map_err(|error| match error {
            EngineOwnerError::Admission(message) => {
                EngineError::new(ErrorKind::Hold, "open_owner", message)
            }
            EngineOwnerError::Storage(message) => storage("open_owner", message),
            error => storage("open_owner", error.to_string()),
        })?);
        if expected.is_some_and(|e| e != owner.identity()) {
            return Err(EngineError::new(
                ErrorKind::Authorization,
                "open",
                "persistent owner differs",
            ));
        }
        let knowledge = KnowledgeStore::open_engine(path, owner.identity())
            .map_err(|e| storage("open_knowledge", e))?;
        let policy_sha256 = digest(
            &serde_json::to_value(&config)
                .map_err(|e| EngineError::new(ErrorKind::Malformed, "config", e.to_string()))?,
        )?;
        if expected.is_some() {
            let bytes = fs::read(path.join("operations-owner.json"))
                .map_err(|e| storage("open_registration", e.to_string()))?;
            if bytes.len() > 4096 {
                return Err(EngineError::new(
                    ErrorKind::Storage,
                    "open_registration",
                    "owner registration exceeds bound",
                ));
            }
            let saved: Value = serde_json::from_slice(&bytes)
                .map_err(|e| storage("open_registration", e.to_string()))?;
            if saved["service_id"] != SERVICE {
                return Err(EngineError::new(
                    ErrorKind::IncompatibleSchema,
                    "open",
                    "state is not an embedding-engine owner",
                ));
            }
            if saved["owner_identity"] != owner.identity()
                || saved["policy_digest"] != policy_sha256
            {
                return Err(EngineError::new(
                    ErrorKind::Authorization,
                    "open",
                    "saved owner/policy does not match explicit configuration",
                ));
            }
        }
        let journal = OperationalJournal::open(Arc::clone(&owner), SERVICE, &policy_sha256)
            .map_err(|e| storage("open_journal", e))?;
        let mut state = EngineState {
            owner,
            knowledge,
            journal,
            config,
            policy_sha256,
            pending: None,
            replay_gf2_work: 0,
            poisoned: false,
        };
        journal::replay(&mut state)?;
        exchange::validate(&state)?;
        Ok(Self {
            inner: Some(state),
            cancellation: Cancellation::default(),
        })
    }
    pub(crate) fn state(&self) -> Result<&EngineState> {
        self.inner
            .as_ref()
            .ok_or_else(|| EngineError::new(ErrorKind::Closed, "state", "engine is closed"))
    }
    pub(crate) fn state_mut(&mut self) -> Result<&mut EngineState> {
        self.inner
            .as_mut()
            .ok_or_else(|| EngineError::new(ErrorKind::Closed, "state", "engine is closed"))
    }
    pub fn identity(&self) -> Result<&str> {
        Ok(self.state()?.owner.identity())
    }
    pub fn policy_sha256(&self) -> Result<&str> {
        Ok(&self.state()?.policy_sha256)
    }
    pub fn cancellation(&self) -> Cancellation {
        self.cancellation.clone()
    }
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
    fn check(&self, deadline: Option<Instant>) -> Result<()> {
        if self.state()?.poisoned {
            return Err(EngineError::new(ErrorKind::Hold,"control","owner history has an integrity or completion fault; inspect/restore preserved state"));
        }
        if self.cancellation.is_cancelled() {
            return Err(EngineError::new(
                ErrorKind::Cancelled,
                "control",
                "engine cancellation was requested",
            ));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(EngineError::new(
                ErrorKind::DeadlineExceeded,
                "control",
                "absolute episode deadline elapsed",
            ));
        }
        Ok(())
    }
    pub fn inspect(&self) -> Result<Inspection> {
        let s = self.state()?;
        Ok(Inspection {
            owner: s.owner.identity().into(),
            policy_sha256: s.policy_sha256.clone(),
            knowledge: s.knowledge.history_anchor(),
            operational_head_sha256: s.journal.head_sha256().into(),
            active_artifacts: s.knowledge.active().into_iter().map(|r| r.id).collect(),
            cancelled: self.cancellation.is_cancelled(),
            pending_episode: s.pending.as_ref().map(|p| p.episode.clone()),
            startup_gf2_work_units: s.replay_gf2_work,
        })
    }
    fn options(&self, options: &EpisodeOptions) -> Result<Instant> {
        self.check(None)?;
        let state = self.state()?;
        if !state.config.authorized_sources.contains(&options.source) {
            return Err(EngineError::new(
                ErrorKind::Authorization,
                "episode",
                "source/scope/epoch/commitment not explicitly authorized",
            ));
        }
        if options.max_queries == 0
            || options.max_queries > state.config.max_queries_per_episode
            || options.max_gf2_work == 0
            || options.max_gf2_work > state.config.max_gf2_work_per_episode
            || options.duration.is_zero()
            || options.duration.as_millis() > u128::from(state.config.max_duration_ms)
            || !(1..=4).contains(&options.heldout_cases)
        {
            return Err(EngineError::new(
                ErrorKind::BudgetExhausted,
                "episode",
                "requested episode exceeds configured finite ceilings",
            ));
        }
        Instant::now()
            .checked_add(options.duration)
            .ok_or_else(|| EngineError::new(ErrorKind::Malformed, "episode", "deadline overflow"))
    }
    fn fail(&mut self, error: EngineError, sink: &mut impl EventSink) -> EngineError {
        if let Ok(state) = self.state_mut() {
            if let Some(p) = state.pending.take() {
                let at = state.knowledge.history_anchor();
                if at != p.before {
                    state.pending = Some(p);
                    let mut hold=EngineError::new(ErrorKind::Hold,"failure","knowledge committed before failure; inspect/restore exact committed state, never retry blindly");
                    hold.committed = Some(at);
                    return hold;
                }
                if let Err(storage) = journal::append(
                    state,
                    &p.source.scope,
                    journal::Entry::Failed {
                        episode: p.episode.clone(),
                        kind: error.kind,
                        usage: p.usage.clone(),
                        knowledge_at: at,
                    },
                ) {
                    state.pending = Some(p);
                    return storage;
                }
                let _ = sink.event(&EngineEvent::Failed {
                    episode_id: p.episode,
                    kind: error.kind,
                    usage: p.usage,
                });
            }
        }
        error
    }
    pub fn observe_infer(
        &mut self,
        source: &mut impl ObservationSource,
        options: &EpisodeOptions,
        sink: &mut impl EventSink,
    ) -> Result<Candidate> {
        self.observe_candidate(None, source, options, sink)
    }
    pub fn evaluate_artifact(
        &mut self,
        artifact: &Artifact,
        source: &mut impl ObservationSource,
        options: &EpisodeOptions,
        sink: &mut impl EventSink,
    ) -> Result<EvaluatedCandidate> {
        artifact.validate_shape()?;
        artifact
            .record
            .validate()
            .map_err(|e| EngineError::new(ErrorKind::Malformed, "artifact", e))?;
        if artifact.record.scope != options.source.scope
            || artifact.record.schema_fingerprint
                != affine_schema_fingerprint(options.source.width)
                    .map_err(|e| EngineError::new(ErrorKind::IncompatibleSchema, "artifact", e))?
        {
            return Err(EngineError::new(
                ErrorKind::IncompatibleSchema,
                "artifact",
                "artifact is outside the authorized affine applicability",
            ));
        }
        let candidate = self.observe_candidate(Some(artifact), source, options, sink)?;
        self.evaluate(candidate, sink)
    }
    fn observe_candidate(
        &mut self,
        incoming: Option<&Artifact>,
        source: &mut impl ObservationSource,
        options: &EpisodeOptions,
        sink: &mut impl EventSink,
    ) -> Result<Candidate> {
        let deadline = self.options(options)?;
        if source.descriptor() != options.source {
            return Err(EngineError::new(
                ErrorKind::Authorization,
                "observe",
                "adapter does not match explicit source authorization",
            ));
        }
        let state = self.state_mut()?;
        if state.pending.is_some() {
            return Err(EngineError::new(
                ErrorKind::Hold,
                "episode",
                "finish/close the existing episode first",
            ));
        }
        let before = state.knowledge.history_anchor();
        let owner = state.owner.identity().to_string();
        let policy = state.policy_sha256.clone();
        let episode = format!(
            "episode-{}",
            &digest(
                &json!({"owner":owner,"head":state.journal.head_sha256(),"source":options.source,"policy":policy})
            )?[..40]
        );
        let id = if let Some(a) = incoming {
            a.record.id.clone()
        } else {
            format!(
                "observed-{}",
                &digest(&json!({"owner":owner,"source":options.source,"policy":policy}))?[..32]
            )
        };
        let active = state.knowledge.active().into_iter().find(|r| r.id == id);
        if active.is_none() && state.knowledge.highest_revision(&id).is_some() {
            return Err(EngineError::new(
                ErrorKind::Revoked,
                "episode",
                "revoked/superseded knowledge needs explicit operator review",
            ));
        }
        journal::append(
            state,
            &options.source.scope,
            journal::Entry::Started {
                episode: episode.clone(),
                source: options.source.clone(),
                before: before.clone(),
            },
        )?;
        state.pending = Some(Pending {
            episode: episode.clone(),
            source: options.source.clone(),
            before: before.clone(),
            audit: None,
            record_sha256: None,
            usage: EpisodeUsage::default(),
            reused: None,
            evaluated_cases: None,
        });
        if let Err(error) = emit(
            sink,
            EngineEvent::EpisodeStarted {
                episode_id: episode.clone(),
                source: options.source.clone(),
                before: before.clone(),
            },
        ) {
            return Err(self.fail(error, sink));
        }
        let result = (|| {
            if let Some(record) = active {
                if incoming.is_some_and(|a| a.record != record) {
                    return Err(EngineError::new(
                        ErrorKind::Contradiction,
                        "artifact",
                        "active artifact ID names different bytes",
                    ));
                }
                let audit = self.audit_for(&record)?;
                if audit.source != options.source || audit.policy_sha256 != policy {
                    return Err(EngineError::new(
                        ErrorKind::Authorization,
                        "reuse",
                        "retained source/policy changed",
                    ));
                }
                let mut learner =
                    CompactAffineLearner::new(options.source.width, options.max_gf2_work)
                        .map_err(|e| EngineError::new(ErrorKind::IncompatibleSchema, "reuse", e))?;
                for q in audit.queries.iter().take(audit.training) {
                    let observed = learner.observe(q.input, q.output);
                    if let Some(p) = self.state_mut()?.pending.as_mut() {
                        p.usage.gf2_work_units = learner.snapshot().work_units;
                    }
                    observed.map_err(|e| {
                        EngineError::new(
                            if *learner.status()
                                == symbiote_reasoning::structural::AffineStatus::BudgetExhausted
                            {
                                ErrorKind::BudgetExhausted
                            } else {
                                ErrorKind::Contradiction
                            },
                            "reuse",
                            e,
                        )
                    })?;
                }
                let model = learner.identified().ok_or_else(|| {
                    EngineError::new(
                        ErrorKind::Uncertain,
                        "reuse",
                        "retained training does not identify a model",
                    )
                })?;
                if record.payload
                    != json!({"kind":"affine","width":model.width,"coefficients":model.coefficients,"bias":model.bias})
                {
                    return Err(EngineError::new(
                        ErrorKind::Contradiction,
                        "reuse",
                        "retained model differs from exact replay",
                    ));
                }
                let usage = EpisodeUsage {
                    source_calls: 0,
                    gf2_work_units: learner.snapshot().work_units,
                    evaluation_cases: 0,
                };
                let evidence = self.empty_evidence(&record, &audit)?;
                return Ok(Candidate {
                    owner,
                    policy,
                    episode,
                    before,
                    record,
                    audit,
                    evidence,
                    usage,
                    reused: true,
                    deadline,
                });
            }
            let mut usage = Usage::default();
            let cancellation = self.cancellation.clone();
            let mut bridge = SourceBridge {
                source,
                expected: options.source.clone(),
                cancellation: cancellation.clone(),
                sequence: 0,
                failure: None,
            };
            let permit = ObservationPermit {
                schema: "symbiote.observation-permit/1".into(),
                scopes: vec![options.source.scope.clone()],
                max_queries_total: options.max_queries,
                max_gf2_work_total: options.max_gf2_work,
                heldout_cases: options.heldout_cases,
            };
            let inferred = observation::infer_with_policy_typed(
                &mut bridge,
                &permit,
                &mut usage,
                &cancellation.flag,
                deadline,
                options.query_policy,
                |phase, details| {
                    sink.event(&EngineEvent::InferenceProgress {
                        phase: phase.into(),
                        details,
                    })
                    .map_err(|e| e.diagnostic)
                },
            );
            if let Some(p) = self.state_mut()?.pending.as_mut() {
                p.usage = EpisodeUsage {
                    source_calls: usage.queries,
                    gf2_work_units: usage.gf2_work,
                    evaluation_cases: 0,
                };
            }
            let inferred =
                inferred.map_err(|e| bridge.failure.unwrap_or_else(|| inferred_error(e)))?;
            let usage = EpisodeUsage {
                source_calls: usage.queries,
                gf2_work_units: usage.gf2_work,
                evaluation_cases: inferred.cases.len(),
            };
            let audit = Audit {
                schema: "symbiote.engine-observation-audit/1".into(),
                owner: owner.clone(),
                episode: episode.clone(),
                source: options.source.clone(),
                policy_sha256: policy.clone(),
                queries: inferred.queries.clone(),
                training: inferred.training,
                snapshot: inferred.snapshot.clone(),
                incoming_artifact_sha256: incoming.map(|a| a.record_sha256.clone()),
            };
            let payload = json!({"kind":"affine","width":inferred.model.width,"coefficients":inferred.model.coefficients,"bias":inferred.model.bias});
            let record = if let Some(a) = incoming {
                if a.record.payload != payload {
                    return Err(EngineError::new(
                        ErrorKind::Contradiction,
                        "artifact",
                        "candidate contradicts independently acquired exact model",
                    ));
                }
                a.record.clone()
            } else {
                KnowledgeRecord {
                    id,
                    revision: 1,
                    source: owner.clone(),
                    scope: options.source.scope.clone(),
                    schema_fingerprint: affine_schema_fingerprint(options.source.width)
                        .map_err(|e| EngineError::new(ErrorKind::IncompatibleSchema, "infer", e))?,
                    payload,
                    provenance: serde_json::to_string(&audit).map_err(|e| {
                        EngineError::new(ErrorKind::Malformed, "infer", e.to_string())
                    })?,
                }
            };
            record
                .validate()
                .map_err(|e| EngineError::new(ErrorKind::Malformed, "infer", e))?;
            let mut cases = inferred.cases;
            if let Some(a) = incoming {
                cases.retain(|c| !a.training_inputs.contains(&c.input));
            }
            if cases.is_empty() {
                return Err(EngineError::new(
                    ErrorKind::Uncertain,
                    "evaluate",
                    "no independently checked case remains disjoint from declared training",
                ));
            }
            let training_inputs = inferred
                .queries
                .iter()
                .take(inferred.training)
                .map(|q| q.input)
                .collect::<Vec<_>>();
            let acquired = (usage.source_calls + usage.gf2_work_units) as u64;
            let evidence = TrialEvidence {
                evaluator: format!("engine-evaluator/{}", &policy[..24]),
                training_case_ids: (0..training_inputs.len())
                    .map(|i| format!("training-{i}"))
                    .collect(),
                training_inputs,
                cases,
                costs: TrialCosts {
                    acquisition: acquired,
                    verification: usage.evaluation_cases as u64,
                    adoption: 1,
                    baseline: 0,
                    candidate: acquired + usage.evaluation_cases as u64 + 1,
                },
            };
            Ok(Candidate {
                owner,
                policy,
                episode,
                before,
                record,
                audit,
                evidence,
                usage,
                reused: false,
                deadline,
            })
        })();
        let candidate = match result {
            Ok(c) => c,
            Err(e) => return Err(self.fail(e, sink)),
        };
        let hash = candidate
            .record
            .digest()
            .map_err(|e| EngineError::new(ErrorKind::Malformed, "infer", e))?;
        let state = self.state_mut()?;
        journal::append(
            state,
            &candidate.record.scope,
            journal::Entry::Inferred {
                episode: candidate.episode.clone(),
                audit: candidate.audit.clone(),
                record_sha256: hash.clone(),
                reused: candidate.reused,
            },
        )?;
        if let Some(p) = state.pending.as_mut() {
            p.usage = candidate.usage.clone();
            p.audit = Some(candidate.audit.clone());
            p.record_sha256 = Some(hash.clone());
            p.reused = Some(candidate.reused);
        }
        if let Err(e) = emit(
            sink,
            EngineEvent::CandidateReady {
                episode_id: candidate.episode.clone(),
                record_sha256: hash,
                usage: candidate.usage.clone(),
            },
        ) {
            return Err(self.fail(e, sink));
        }
        Ok(candidate)
    }
    fn empty_evidence(&self, record: &KnowledgeRecord, audit: &Audit) -> Result<TrialEvidence> {
        let cases = audit
            .queries
            .iter()
            .skip(audit.training)
            .map(|q| {
                Ok(symbiote_memory::knowledge::TrialCase {
                    id: format!("heldout-{}", q.input),
                    input: q.input,
                    expected: q.output,
                    baseline: None,
                    candidate: record
                        .predict(q.input)
                        .map_err(|e| EngineError::new(ErrorKind::Contradiction, "reuse", e))?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(TrialEvidence {
            evaluator: "engine-retained-replay/v1".into(),
            training_case_ids: Vec::new(),
            training_inputs: Vec::new(),
            cases,
            costs: TrialCosts {
                acquisition: 0,
                verification: 0,
                adoption: 0,
                baseline: 0,
                candidate: 0,
            },
        })
    }
    fn check_candidate(&self, candidate: &Candidate) -> Result<()> {
        self.check(Some(candidate.deadline))?;
        let state = self.state()?;
        if candidate.owner != state.owner.identity()
            || candidate.policy != state.policy_sha256
            || candidate.before != state.knowledge.history_anchor()
            || !state.pending.as_ref().is_some_and(|p| {
                p.episode == candidate.episode
                    && p.record_sha256.as_ref() == candidate.record.digest().ok().as_ref()
            })
        {
            return Err(EngineError::new(
                ErrorKind::Authorization,
                "candidate",
                "candidate seal belongs to another owner, policy or state head",
            ));
        }
        Ok(())
    }
    pub fn evaluate(
        &mut self,
        candidate: Candidate,
        sink: &mut impl EventSink,
    ) -> Result<EvaluatedCandidate> {
        self.check_candidate(&candidate)?;
        let assessment = if candidate.reused {
            None
        } else {
            match assess(&candidate.record, &candidate.evidence) {
                Ok(a) => Some(a),
                Err(e) => {
                    return Err(self.fail(
                        EngineError::new(ErrorKind::Contradiction, "evaluate", e),
                        sink,
                    ))
                }
            }
        };
        journal::append(
            self.state_mut()?,
            &candidate.record.scope,
            journal::Entry::Evaluated {
                episode: candidate.episode.clone(),
                record_sha256: candidate
                    .record
                    .digest()
                    .map_err(|e| EngineError::new(ErrorKind::Malformed, "evaluate", e))?,
                cases: candidate.evidence.cases.len(),
            },
        )?;
        if let Some(p) = self.state_mut()?.pending.as_mut() {
            p.evaluated_cases = Some(candidate.evidence.cases.len());
        }
        if let Err(e) = emit(
            sink,
            EngineEvent::Evaluated {
                episode_id: candidate.episode.clone(),
                cases: candidate.evidence.cases.len(),
            },
        ) {
            return Err(self.fail(e, sink));
        }
        Ok(EvaluatedCandidate {
            candidate,
            assessment,
        })
    }
    pub fn retain(
        &mut self,
        evaluated: EvaluatedCandidate,
        sink: &mut impl EventSink,
    ) -> Result<LearningReceipt> {
        let EvaluatedCandidate {
            candidate,
            assessment,
        } = evaluated;
        self.check_candidate(&candidate)?;
        let state = self.state_mut()?;
        if let Some(assessment) = assessment {
            let capacity = state.knowledge.capacity();
            if capacity.remaining_records == 0 || capacity.remaining_publication_bytes == 0 {
                return Err(EngineError::new(
                    ErrorKind::BudgetExhausted,
                    "retain",
                    "native knowledge history capacity is exhausted; no write attempted",
                ));
            }
            if let Err(error) = state
                .knowledge
                .promote_checked(candidate.record.clone(), assessment)
            {
                if matches!(&error, MemoryWriteError::Integrity(_)) {
                    state.poisoned = true;
                }
                return Err(memory_write("retain", error));
            }
        }
        let after = state.knowledge.history_anchor();
        let receipt = LearningReceipt {
            episode_id: candidate.episode.clone(),
            owner: state.owner.identity().into(),
            artifact: candidate.record.id.clone(),
            record_sha256: candidate
                .record
                .digest()
                .map_err(|e| EngineError::new(ErrorKind::Malformed, "retain", e))?,
            before: candidate.before.clone(),
            after: after.clone(),
            reused: candidate.reused,
            usage: candidate.usage.clone(),
            conditional: true,
            baseline_status: "unknown; no measured economic benefit",
        };
        let scope = candidate.record.scope.clone();
        if let Err(mut e) = journal::append(
            state,
            &scope,
            journal::Entry::Finished {
                episode: candidate.episode,
                record: candidate.record,
                before: candidate.before,
                after: after.clone(),
                reused: candidate.reused,
                usage: candidate.usage,
            },
        ) {
            e.committed = Some(after);
            return Err(e);
        }
        state.pending = None;
        if let Err(mut e) = emit(
            sink,
            EngineEvent::Retained {
                receipt: receipt.clone(),
            },
        ) {
            e.kind = ErrorKind::CommittedEventSink;
            e.committed = Some(receipt.after.clone());
            return Err(e);
        }
        Ok(receipt)
    }
    pub fn run_episode(
        &mut self,
        source: &mut impl ObservationSource,
        options: &EpisodeOptions,
        sink: &mut impl EventSink,
    ) -> Result<LearningReceipt> {
        let candidate = self.observe_infer(source, options, sink)?;
        let evaluated = self.evaluate(candidate, sink)?;
        self.retain(evaluated, sink)
    }
    fn audit_for(&self, record: &KnowledgeRecord) -> Result<Audit> {
        let hash = record
            .digest()
            .map_err(|e| EngineError::new(ErrorKind::Malformed, "inspect", e))?;
        for (_, event) in journal::entries(self.state()?)?.into_iter().rev() {
            if let journal::Entry::Inferred {
                audit,
                record_sha256,
                ..
            } = event
            {
                if record_sha256 == hash {
                    return Ok(audit);
                }
            }
        }
        Err(EngineError::new(
            ErrorKind::Hold,
            "inspect",
            "record lacks its native observation/evaluation audit",
        ))
    }
    pub fn export_artifact(&self, id: &str) -> Result<Artifact> {
        let state = self.state()?;
        let record = state
            .knowledge
            .active()
            .into_iter()
            .find(|r| r.id == id)
            .ok_or_else(|| {
                EngineError::new(ErrorKind::Revoked, "export", "artifact is not active")
            })?;
        if record.source != state.owner.identity() {
            return Err(EngineError::new(
                ErrorKind::Authorization,
                "export",
                "forwarding another owner's record as one's own is not supported",
            ));
        }
        let audit = self.audit_for(&record)?;
        Ok(Artifact {
            schema: "symbiote.engine-artifact/1".into(),
            sender: state.owner.identity().into(),
            source: audit.source,
            record_sha256: record
                .digest()
                .map_err(|e| EngineError::new(ErrorKind::Malformed, "export", e))?,
            record,
            training_inputs: audit
                .queries
                .iter()
                .take(audit.training)
                .map(|q| q.input)
                .collect(),
        })
    }
    pub fn predict(
        &mut self,
        id: &str,
        input: u16,
        sink: &mut impl EventSink,
    ) -> Result<Prediction> {
        self.check(None)?;
        let state = self.state()?;
        if state.pending.is_some() {
            return Err(EngineError::new(
                ErrorKind::Hold,
                "predict",
                "finish or close the pending episode before use",
            ));
        }
        let record = state
            .knowledge
            .active()
            .into_iter()
            .find(|r| r.id == id)
            .ok_or_else(|| {
                EngineError::new(
                    if state.knowledge.highest_revision(id).is_some() {
                        ErrorKind::Revoked
                    } else {
                        ErrorKind::Uncertain
                    },
                    "predict",
                    "requested artifact is not active",
                )
            })?;
        let audit = self.audit_for(&record)?;
        let in_domain = input < (1u16 << audit.source.width);
        let answer = if in_domain {
            record
                .predict_if_certified(input)
                .map_err(|e| EngineError::new(ErrorKind::Contradiction, "predict", e))?
        } else {
            None
        };
        let prediction = Prediction {
            owner: state.owner.identity().into(),
            artifact: id.into(),
            record_sha256: record
                .digest()
                .map_err(|e| EngineError::new(ErrorKind::Malformed, "predict", e))?,
            knowledge_at: state.knowledge.history_anchor(),
            input,
            answer,
            basis: if !in_domain {
                PredictionBasis::Abstained(Abstention::OutsideApplicability)
            } else if audit.queries.iter().any(|q| q.input == input) {
                PredictionBasis::Observed
            } else {
                PredictionBasis::ConditionalAffine
            },
            applicability: Applicability {
                source: audit.source,
                schema_fingerprint: record.schema_fingerprint.clone(),
                conditional_family: symbiote_reasoning::structural::AFFINE_FAMILY.into(),
                physical_certificate_authorized: false,
            },
        };
        journal::append(
            self.state_mut()?,
            &record.scope,
            journal::Entry::Used {
                artifact: id.into(),
                record_sha256: prediction.record_sha256.clone(),
                input,
                answer,
                knowledge_at: prediction.knowledge_at.clone(),
            },
        )?;
        if let Err(mut e) = emit(
            sink,
            EngineEvent::Prediction {
                prediction: prediction.clone(),
            },
        ) {
            e.kind = ErrorKind::CommittedEventSink;
            e.committed = Some(prediction.knowledge_at.clone());
            return Err(e);
        }
        Ok(prediction)
    }
    pub fn revoke(
        &mut self,
        id: &str,
        reason: &str,
        sink: &mut impl EventSink,
    ) -> Result<KnowledgeAnchor> {
        self.check(None)?;
        if reason.trim().is_empty() || reason.len() > 4096 {
            return Err(EngineError::new(
                ErrorKind::Malformed,
                "revoke",
                "bounded revocation reason required",
            ));
        }
        let state = self.state_mut()?;
        if state.pending.is_some() {
            return Err(EngineError::new(
                ErrorKind::Hold,
                "revoke",
                "finish or close the pending episode before revocation",
            ));
        }
        let record = state
            .knowledge
            .active()
            .into_iter()
            .find(|r| r.id == id)
            .ok_or_else(|| {
                EngineError::new(ErrorKind::Revoked, "revoke", "artifact is already inactive")
            })?;
        let before = state.knowledge.history_anchor();
        let capacity = state.knowledge.capacity();
        if capacity.remaining_records == 0 || capacity.remaining_publication_bytes == 0 {
            return Err(EngineError::new(
                ErrorKind::BudgetExhausted,
                "revoke",
                "native knowledge history capacity is exhausted; no write attempted",
            ));
        }
        if let Err(error) = state.knowledge.revoke_checked(id, reason) {
            if matches!(&error, MemoryWriteError::Integrity(_)) {
                state.poisoned = true;
            }
            return Err(memory_write("revoke", error));
        }
        let after = state.knowledge.history_anchor();
        if let Err(mut error) = journal::append(
            state,
            &record.scope,
            journal::Entry::Revoked {
                artifact: id.into(),
                before: before.clone(),
                after: after.clone(),
            },
        ) {
            state.poisoned = true;
            error.committed = Some(after);
            return Err(error);
        }
        if let Err(mut error) = emit(
            sink,
            EngineEvent::Revoked {
                artifact: id.into(),
                before,
                after: after.clone(),
            },
        ) {
            error.kind = ErrorKind::CommittedEventSink;
            error.committed = Some(after);
            return Err(error);
        }
        Ok(after)
    }
    pub fn historical_outcomes(&self) -> Result<Vec<LearningReceipt>> {
        let state = self.state()?;
        journal::entries(state)?
            .into_iter()
            .filter_map(|(_, e)| {
                if let journal::Entry::Finished {
                    episode,
                    record,
                    before,
                    after,
                    reused,
                    usage,
                } = e
                {
                    Some((episode, record, before, after, reused, usage))
                } else {
                    None
                }
            })
            .map(|(episode, record, before, after, reused, usage)| {
                Ok(LearningReceipt {
                    episode_id: episode,
                    owner: state.owner.identity().into(),
                    artifact: record.id.clone(),
                    record_sha256: record
                        .digest()
                        .map_err(|e| EngineError::new(ErrorKind::Malformed, "history", e))?,
                    before,
                    after,
                    reused,
                    usage,
                    conditional: true,
                    baseline_status: "unknown; no measured economic benefit",
                })
            })
            .collect()
    }
    pub fn close(mut self) -> Result<ClosedEngine> {
        if self.state()?.poisoned {
            return Err(EngineError::new(ErrorKind::Hold,"close","owner history has an integrity or completion fault; history preserved for inspection/restore"));
        }
        if self
            .state()?
            .pending
            .as_ref()
            .is_some_and(|p| p.audit.is_none())
        {
            return Err(EngineError::new(ErrorKind::Hold,"close","interrupted inference has unknown work; preserve history and inspect/restore a stopped-owner checkpoint"));
        }
        if self.state()?.pending.is_some() {
            let mut sink = NoopSink;
            let error = self.fail(
                EngineError::new(
                    ErrorKind::Cancelled,
                    "close",
                    "unfinished episode explicitly abandoned by owner",
                ),
                &mut sink,
            );
            if error.kind == ErrorKind::Hold || error.kind == ErrorKind::Storage {
                return Err(error);
            }
        }
        let state = self
            .inner
            .take()
            .ok_or_else(|| EngineError::new(ErrorKind::Closed, "close", "already closed"))?;
        let path = state
            .owner
            .ledger_path()
            .parent()
            .ok_or_else(|| EngineError::new(ErrorKind::Storage, "close", "owner directory absent"))?
            .to_path_buf();
        let mut pins = BTreeMap::new();
        for name in [
            "ledger.jsonl",
            "knowledge.jsonl",
            "operations.jsonl",
            "operations-owner.json",
        ] {
            let bytes = fs::read(path.join(name)).map_err(|e| storage("close", e.to_string()))?;
            pins.insert(name.into(), format!("{:x}", Sha256::digest(bytes)));
        }
        let closed = ClosedEngine {
            state: path,
            owner: state.owner.identity().into(),
            knowledge: state.knowledge.history_anchor(),
            pins,
        };
        drop(state);
        Ok(closed)
    }
    pub fn restore(
        checkpoint: &Checkpoint,
        destination: &Path,
        config: EngineConfig,
    ) -> Result<(Self, RestoreReceipt)> {
        absolute(destination)?;
        absolute(&checkpoint.snapshot)?;
        absolute(&checkpoint.original_state)?;
        config_valid(&config)?;
        let verified =
            symbiote_memory::backup::verify(&checkpoint.snapshot, &checkpoint.manifest_sha256)
                .map_err(|e| storage("restore_preflight", e))?;
        let mut manifest_bytes = Vec::new();
        fs::File::open(checkpoint.snapshot.join("backup-manifest.json"))
            .map_err(|e| storage("restore_preflight", e.to_string()))?
            .take(256 * 1024 + 1)
            .read_to_end(&mut manifest_bytes)
            .map_err(|e| storage("restore_preflight", e.to_string()))?;
        if manifest_bytes.len() > 256 * 1024
            || format!("{:x}", Sha256::digest(&manifest_bytes)) != checkpoint.manifest_sha256
        {
            return Err(EngineError::new(
                ErrorKind::Storage,
                "restore_preflight",
                "verified backup manifest changed",
            ));
        }
        let manifest: symbiote_memory::backup::BackupManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|e| {
                EngineError::new(ErrorKind::Malformed, "restore_preflight", e.to_string())
            })?;
        let original =
            symbiote_memory::backup::normalize_state_location(&checkpoint.original_state)
                .map_err(|e| storage("restore_preflight", e))?;
        let policy = digest(&serde_json::to_value(&config).map_err(|e| {
            EngineError::new(ErrorKind::Malformed, "restore_preflight", e.to_string())
        })?)?;
        if verified.identity != checkpoint.owner
            || manifest.identity != checkpoint.owner
            || manifest.source_state != original
            || manifest.operational_policy_sha256.as_deref() != Some(&policy)
        {
            return Err(EngineError::new(ErrorKind::Authorization, "restore_preflight", "checkpoint owner, source location or immutable policy differs from the verified manifest"));
        }
        match fs::symlink_metadata(&checkpoint.original_state) {
            Ok(_) => {
                let source = symbiote_memory::maintenance::inspect(&checkpoint.original_state)
                    .map_err(|e| storage("restore_preflight", e))?;
                if source.identity.as_deref() == Some(&checkpoint.owner) {
                    if source
                        .locks
                        .iter()
                        .any(|l| l.state == symbiote_memory::maintenance::LockState::Live)
                    {
                        return Err(EngineError::new(
                            ErrorKind::OwnerBusy,
                            "restore_preflight",
                            "the original verified owner is still live",
                        ));
                    }
                    if source
                        .locks
                        .iter()
                        .any(|l| l.state == symbiote_memory::maintenance::LockState::Unknown)
                    {
                        return Err(EngineError::new(
                            ErrorKind::Hold,
                            "restore_preflight",
                            "the original owner writer liveness is unknown",
                        ));
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(storage("restore_preflight", error.to_string())),
        }
        let report = symbiote_memory::backup::restore(
            &checkpoint.snapshot,
            &checkpoint.manifest_sha256,
            destination,
        )
        .map_err(|e| storage("restore", e))?;
        if report.identity != checkpoint.owner {
            return Err(EngineError::new(
                ErrorKind::Authorization,
                "restore",
                "checkpoint owner differs",
            ));
        }
        let pin = symbiote_memory::backup::validate_restore_mapping(
            destination,
            &checkpoint.original_state,
            &checkpoint.owner,
        )
        .map_err(|e| storage("restore", e))?;
        if pin != report.restore_mapping_sha256 {
            return Err(EngineError::new(
                ErrorKind::Storage,
                "restore",
                "restore mapping differs",
            ));
        }
        let engine = Self::open(destination, &checkpoint.owner, config)?;
        Ok((
            engine,
            RestoreReceipt {
                owner: report.identity,
                manifest_sha256: report.manifest_sha256,
                restore_mapping_sha256: pin,
                network_started: false,
                rollback_discards_later_learning: true,
            },
        ))
    }
}
impl ClosedEngine {
    pub fn checkpoint(&self, destination: &Path) -> Result<Checkpoint> {
        absolute(destination)?;
        let report = symbiote_memory::backup::create(
            &self.state,
            destination,
            &symbiote_memory::backup::BackupOptions::default(),
        )
        .map_err(|e| storage("checkpoint", e))?;
        if report.identity != self.owner {
            return Err(EngineError::new(
                ErrorKind::Authorization,
                "checkpoint",
                "closed owner changed",
            ));
        }
        let manifest: symbiote_memory::backup::BackupManifest = serde_json::from_slice(
            &fs::read(destination.join("backup-manifest.json"))
                .map_err(|e| storage("checkpoint", e.to_string()))?,
        )
        .map_err(|e| EngineError::new(ErrorKind::Malformed, "checkpoint", e.to_string()))?;
        if self
            .pins
            .iter()
            .any(|(name, sha)| manifest.files.get(name).map(|p| &p.sha256) != Some(sha))
        {
            return Err(EngineError::new(ErrorKind::Hold,"checkpoint","owner history advanced after close; snapshot preserved without claiming the closed head"));
        }
        Ok(Checkpoint {
            snapshot: destination.to_path_buf(),
            owner: self.owner.clone(),
            manifest_sha256: report.manifest_sha256,
            original_state: self.state.clone(),
        })
    }
}
