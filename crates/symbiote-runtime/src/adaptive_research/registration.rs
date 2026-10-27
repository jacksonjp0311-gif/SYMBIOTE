//! Primary registration is checked before the generator can produce a world.
//! The candidate binary/source binding has no runtime Git dependency.
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use symbiote_protocol::fresh_capability;

pub(super) const PROTOCOL_ID: &str = "SYMBIOTE-PROSPECTIVE-FRONTIER-004";
pub(super) const PROTOCOL_SHA256: &str =
    "d3e8454147b67fec510712eac094d0f946e683cd5472e3304ba912f1fea1c567";
const BASE: &str = "8dbbd4a7550a88f7f6b91b7aa287665dbc481ef1";
pub(super) const SOURCE_COMMIT: &str = match option_env!("SYMBIOTE_SOURCE_COMMIT") {
    Some(commit) => commit,
    None => "unknown",
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Runner {
    pub(super) os: String,
    pub(super) architecture: String,
    pub(super) toolchain: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Registration {
    pub(super) schema: String,
    pub(super) protocol_id: String,
    pub(super) protocol_sha256: String,
    pub(super) base_release_commit: String,
    pub(super) candidate_source_commit: String,
    pub(super) candidate_binary_sha256: String,
    pub(super) run_id: String,
    pub(super) registered_at: String,
    pub(super) artifact_directory: PathBuf,
    pub(super) state_directory: PathBuf,
    pub(super) receipt_path: PathBuf,
    pub(super) runner: Runner,
}
pub(super) struct EvaluationPermit {
    pub(super) registration: Registration,
    pub(super) mode: &'static str,
    pub(super) registration_sha256: String,
    _private: (),
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
pub(super) fn binary_sha256() -> Result<String, String> {
    let mut file = fs::File::open(
        std::env::current_exe().map_err(|_| "cannot identify candidate executable")?,
    )
    .map_err(|_| "cannot open candidate executable")?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| "cannot hash candidate executable")?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn resolved(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("experiment artifact paths must be absolute".into());
    }
    fs::canonicalize(path)
        .map_err(|_| "experiment path must exist before registration authorization".into())
}
fn validate_paths(
    registration: &Registration,
    state: &Path,
    receipts: &Path,
) -> Result<(), String> {
    let temporary = resolved(&std::env::temp_dir())?;
    let artifacts = resolved(&registration.artifact_directory)?;
    if artifacts == temporary || !artifacts.starts_with(&temporary) {
        return Err(
            "experiment must own a dedicated artifact directory inside the OS temporary directory"
                .into(),
        );
    }
    let registered_state = resolved(&registration.state_directory)?;
    let actual_state = resolved(state)?;
    if actual_state != registered_state || !actual_state.starts_with(&artifacts) {
        return Err("registered state does not match its owned experiment directory".into());
    }
    if !receipts.is_absolute()
        || !registration.receipt_path.is_absolute()
        || receipts.file_name() != registration.receipt_path.file_name()
    {
        return Err("registered receipt path differs from requested output".into());
    }
    let expected_parent = resolved(
        registration
            .receipt_path
            .parent()
            .ok_or("registered receipt parent missing")?,
    )?;
    let actual_parent = resolved(
        receipts
            .parent()
            .ok_or("requested receipt parent missing")?,
    )?;
    if expected_parent != actual_parent
        || !actual_parent.starts_with(&artifacts)
        || receipts.exists()
    {
        return Err("receipt output must be absent at its exact registered artifact path".into());
    }
    if fs::read_dir(&actual_state)
        .map_err(|_| "cannot inspect initial experiment state")?
        .next()
        .is_some()
    {
        return Err("primary/reproduction state must be fresh; existing state is preserved".into());
    }
    Ok(())
}
fn compiled_protocol() -> Result<(), String> {
    let source =
        include_str!("../../../../docs/RESEARCH_V05_PROTOCOL_004.md").replace("\r\n", "\n");
    if format!("{:x}", Sha256::digest(source.as_bytes())) != PROTOCOL_SHA256 {
        return Err("compiled prospective protocol does not match its preregistered hash".into());
    }
    Ok(())
}
pub(super) fn primary(
    state: &Path,
    receipts: &Path,
    path: &Path,
) -> Result<EvaluationPermit, String> {
    compiled_protocol()?;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| "primary registration file unavailable")?
        .take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|_| "primary registration read failed")?;
    if bytes.len() > 16_384 {
        return Err("primary registration exceeds its byte budget".into());
    }
    let registration: Registration =
        serde_json::from_slice(&bytes).map_err(|_| "primary registration schema rejected")?;
    if registration.schema != "symbiote.primary-registration/1"
        || registration.protocol_id != PROTOCOL_ID
        || registration.protocol_sha256 != PROTOCOL_SHA256
        || registration.base_release_commit != BASE
        || !hex(&registration.candidate_source_commit, 40)
        || registration.candidate_source_commit != SOURCE_COMMIT
        || !hex(&registration.candidate_binary_sha256, 64)
        || registration.candidate_binary_sha256 != binary_sha256()?
        || registration.run_id.is_empty()
        || registration.run_id.len() > 128
        || registration.registered_at.is_empty()
        || registration.registered_at.len() > 128
        || registration.runner.os != std::env::consts::OS
        || registration.runner.architecture != std::env::consts::ARCH
        || registration.runner.toolchain.is_empty()
        || registration.runner.toolchain.len() > 256
    {
        return Err("HOLD: primary registration does not bind this protocol, frozen source, binary and runner".into());
    }
    validate_paths(&registration, state, receipts)?;
    let registration_sha256 = format!("{:x}", Sha256::digest(&bytes));
    let marker = json!({"schema":"symbiote.primary-started/1","registration_sha256":registration_sha256,"run_id":registration.run_id,"protocol_sha256":PROTOCOL_SHA256,"candidate_source_commit":SOURCE_COMMIT,"candidate_binary_sha256":registration.candidate_binary_sha256});
    let mut file=OpenOptions::new().write(true).create_new(true).open(registration.artifact_directory.join("primary-started.json")).map_err(|_|"HOLD: primary already started or its immutable start marker cannot be created; no retry is authorized")?;
    file.write_all(&serde_json::to_vec(&marker).map_err(|e| e.to_string())?)
        .and_then(|_| file.sync_all())
        .map_err(|_| "primary start marker could not be committed")?;
    Ok(EvaluationPermit {
        registration,
        mode: "primary",
        registration_sha256,
        _private: (),
    })
}
pub(super) fn reproduction(state: &Path, receipts: &Path) -> Result<EvaluationPermit, String> {
    compiled_protocol()?;
    let state_parent = state.parent().ok_or("reproduction state parent missing")?;
    let registration = Registration {
        schema: "symbiote.primary-registration/1".into(),
        protocol_id: PROTOCOL_ID.into(),
        protocol_sha256: PROTOCOL_SHA256.into(),
        base_release_commit: BASE.into(),
        candidate_source_commit: SOURCE_COMMIT.into(),
        candidate_binary_sha256: binary_sha256()?,
        run_id: format!("reproduction-{}", fresh_capability()?),
        registered_at: "explicit-reproduction".into(),
        artifact_directory: state_parent.into(),
        state_directory: state.into(),
        receipt_path: receipts.into(),
        runner: Runner {
            os: std::env::consts::OS.into(),
            architecture: std::env::consts::ARCH.into(),
            toolchain: "binary-reproduction; build toolchain not asserted".into(),
        },
    };
    validate_paths(&registration, state, receipts)?;
    let bytes = serde_json::to_vec(&registration).map_err(|e| e.to_string())?;
    let registration_sha256 = format!("{:x}", Sha256::digest(&bytes));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(
            registration
                .artifact_directory
                .join("reproduction-registration.json"),
        )
        .map_err(|_| "reproduction requires a fresh artifact directory")?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "reproduction registration could not be committed")?;
    Ok(EvaluationPermit {
        registration,
        mode: "reproduction",
        registration_sha256,
        _private: (),
    })
}
