//! Offline, byte-preserving backups of exactly one owner store.
//!
//! The externally retained manifest digest is the rollback anchor. SHA256 is
//! integrity evidence, not protection against an attacker rewriting all state
//! and the independently retained digest. No service or credential is activated.
use crate::{knowledge::KnowledgeRecord, maintenance, Store};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

const MANIFEST: &str = "backup-manifest.json";
const INCOMPLETE: &str = "restore-incomplete.json";
const MAX_FILES: usize = 128;
const MAX_TOTAL: usize = 32 * 1024 * 1024;
const MAX_META: usize = 256 * 1024;
const MAX_MAPPING: usize = 2 * MAX_META + 16 * 1024;
const REGISTRY: &str = "public-dependencies/graph-contexts.json";

#[derive(Clone, Debug, Default)]
pub struct BackupOptions {
    /// Explicit opt-in for the research runtime's known public registry only.
    /// Generic GraphMap records do not require this research dependency.
    pub graph_context_registry: Option<RegistryDependency>,
}
#[derive(Clone, Debug)]
pub struct RegistryDependency {
    pub path: PathBuf,
    pub expected_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationDependency {
    pub kind: String,
    pub locator: Option<String>,
    pub sha256: Option<String>,
    pub requirement: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileFingerprint {
    pub bytes: usize,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    pub schema: String,
    pub version: u32,
    pub operating_system: String,
    pub identity: String,
    pub source_state: String,
    pub files: BTreeMap<String, FileFingerprint>,
    pub ledger_formats: BTreeMap<String, u32>,
    pub operational_policy_sha256: Option<String>,
    pub operational_head_sha256: Option<String>,
    pub activation_dependencies: Vec<ActivationDependency>,
    pub scope: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct BackupReport {
    pub schema: &'static str,
    pub identity: String,
    pub manifest_sha256: String,
    pub files: usize,
    pub bytes: usize,
    pub activation_dependencies: Vec<ActivationDependency>,
    pub network_started: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct RestoreReport {
    pub schema: &'static str,
    pub identity: String,
    pub destination: String,
    pub manifest_sha256: String,
    pub restore_mapping_sha256: String,
    pub activation_dependencies: Vec<ActivationDependency>,
    pub requires_activation: bool,
    pub network_started: bool,
}
/// Integrity-checked restore metadata, not evidence of operator approval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RestoreMappingInfo {
    pub sha256: String,
    pub source_state: String,
    pub restored_state: String,
    pub destination_matches: bool,
    pub operational_policy_sha256: Option<String>,
    pub operational_head_sha256: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreMapping {
    schema: String,
    identity: String,
    source_state: String,
    restored_state: String,
    manifest_sha256: String,
    /// Original manifest bytes, not a reformatted or silently upgraded object.
    manifest_json: String,
}
type Files = BTreeMap<String, Vec<u8>>;

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn marker_name(digest: &str) -> String {
    format!("restored-owner-{digest}.json")
}
fn is_marker(name: &str) -> bool {
    name.strip_prefix("restored-owner-")
        .and_then(|v| v.strip_suffix(".json"))
        .is_some_and(is_hash)
}
fn reservation(directory: &Path) -> Result<PathBuf, String> {
    let absolute = if directory.is_absolute() {
        directory.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(directory)
    };
    let normalized = PathBuf::from(location(&absolute)?);
    let name = normalized
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or("restore needs a named UTF-8 destination")?;
    Ok(normalized
        .parent()
        .ok_or("restore destination parent missing")?
        .join(format!(".{name}.symbiote-restore-reservation")))
}
fn exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}
/// Normal writers never activate an incomplete or still-reserved restore.
pub(crate) fn writer_admission(directory: &Path) -> Result<(), String> {
    if exists(&directory.join(INCOMPLETE))? || exists(&reservation(directory)?)? {
        return Err("HOLD: incomplete/reserved restore cannot become an active owner store; preserve its evidence".into());
    }
    Ok(())
}
fn linked(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}
fn existing_directory(path: &Path) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    // Resolve only the OS's trusted temporary alias (/var on macOS).
    let temporary = std::env::temp_dir();
    let inspected = match absolute.strip_prefix(&temporary) {
        Ok(tail) => temporary
            .canonicalize()
            .map_err(|e| e.to_string())?
            .join(tail),
        Err(_) => absolute,
    };
    for ancestor in inspected.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|e| e.to_string())?;
        if linked(&metadata) || !metadata.is_dir() {
            return Err("backup paths must not cross symbolic links or reparse points".into());
        }
    }
    inspected.canonicalize().map_err(|e| e.to_string())
}
fn location(path: &Path) -> Result<String, String> {
    if !path.is_absolute() {
        return Err("restore mapping requires an absolute source path as metadata".into());
    }
    // Resolve only the independently trusted OS temporary prefix, never the
    // source store itself. It may already be gone. This covers macOS /var and
    // Windows runner short-name aliases without following arbitrary old paths.
    let temporary = std::env::temp_dir();
    let normalized_prefix = path
        .strip_prefix(&temporary)
        .ok()
        .map(|tail| {
            temporary
                .canonicalize()
                .map(|base| base.join(tail))
                .map_err(|e| e.to_string())
        })
        .transpose()?;
    let path = normalized_prefix.as_deref().unwrap_or(path);
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !result.pop() {
                    return Err("path escapes its root".into());
                }
            }
            other => result.push(other.as_os_str()),
        }
    }
    let value = result
        .to_str()
        .ok_or("state path is not UTF-8")?
        .to_string();
    #[cfg(windows)]
    {
        Ok(value
            .strip_prefix(r"\\?\")
            .unwrap_or(&value)
            .to_ascii_lowercase())
    }
    #[cfg(not(windows))]
    {
        Ok(value)
    }
}
/// Normalize path metadata without opening or canonicalizing that owner store.
/// Only the trusted OS temporary prefix is resolved, as in backup creation.
pub fn normalize_state_location(path: &Path) -> Result<String, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    location(&absolute)
}
fn new_path(path: &Path) -> Result<PathBuf, String> {
    let parent = existing_directory(path.parent().ok_or("new destination parent missing")?)?;
    let name = path.file_name().ok_or("new destination name missing")?;
    let result = parent.join(name);
    if exists(&result)? {
        return Err("destination is occupied; no existing file or directory is overwritten".into());
    }
    Ok(result)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())
}
fn credential_free(bytes: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "owner metadata must be UTF-8")?;
    if [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
    ]
    .iter()
    .any(|needle| text.contains(needle))
    {
        return Err("private key material cannot enter an owner backup".into());
    }
    Ok(())
}
fn known_file(name: &str) -> bool {
    [
        "ledger.jsonl",
        "knowledge.jsonl",
        "operations.jsonl",
        "operations-owner.json",
        "state-layout.json",
        "maintenance-audit.jsonl",
        REGISTRY,
        "graph/contexts.json",
    ]
    .contains(&name)
        || is_marker(name)
        || name
            .strip_prefix("migration-backup-v1/")
            .is_some_and(|tail| {
                [
                    "manifest.json",
                    "ledger.jsonl",
                    "knowledge.jsonl",
                    "operations.jsonl",
                    "operations-owner.json",
                ]
                .contains(&tail)
            })
}
fn gather(directory: &Path) -> Result<Files, String> {
    inventory(directory, false)
}
fn inventory(directory: &Path, allow_incomplete: bool) -> Result<Files, String> {
    fn visit(
        root: &Path,
        path: &Path,
        files: &mut Files,
        allow_incomplete: bool,
    ) -> Result<(), String> {
        for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
            if linked(&metadata) {
                return Err("backup refuses symbolic links and reparse points".into());
            }
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("backup path is not UTF-8")?
                .replace('\\', "/");
            if ["maintenance.guard", "writer.lock", "knowledge.writer.lock"]
                .contains(&relative.as_str())
            {
                continue;
            }
            if allow_incomplete && relative == INCOMPLETE {
                continue;
            }
            if metadata.is_dir() {
                if !["migration-backup-v1", "graph", "public-dependencies"]
                    .contains(&relative.as_str())
                {
                    return Err(format!("unsupported descendant/child store {relative}; one-owner backup never silently omits it"));
                }
                visit(root, &entry.path(), files, allow_incomplete)?;
            } else {
                if !known_file(&relative) {
                    return Err(format!(
                        "unknown critical sidecar {relative}; completeness cannot be promised"
                    ));
                }
                let bytes = maintenance::read_regular(&entry.path(), crate::MAX_LEDGER_BYTES)?
                    .ok_or("state sidecar disappeared")?;
                credential_free(&bytes)?;
                files.insert(relative, bytes);
                if files.len() > MAX_FILES
                    || files.values().map(Vec::len).sum::<usize>() > MAX_TOTAL
                {
                    return Err("owner snapshot budget exceeded".into());
                }
            }
        }
        Ok(())
    }
    let mut files = Files::new();
    visit(directory, directory, &mut files, allow_incomplete)?;
    Ok(files)
}
fn records(files: &Files, identity: &str) -> Result<Vec<KnowledgeRecord>, String> {
    let Some(bytes) = files.get("knowledge.jsonl") else {
        return Ok(Vec::new());
    };
    crate::knowledge::KnowledgeStore::validate_snapshot(bytes, identity)?;
    let mut records = Vec::new();
    for line in std::str::from_utf8(bytes)
        .map_err(|e| e.to_string())?
        .lines()
    {
        let row: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
        if matches!(
            row["payload"]["event"].as_str(),
            Some("promote" | "promote_graph")
        ) {
            records.push(
                serde_json::from_value(row["payload"]["record"].clone())
                    .map_err(|e| e.to_string())?,
            );
        }
    }
    Ok(records)
}
fn validate_files(files: &Files) -> Result<String, String> {
    let identity = Store::validate_snapshot(
        files
            .get("ledger.jsonl")
            .ok_or("one-owner backup requires its original identity ledger")?,
    )?;
    let history = records(files, &identity)?;
    for (name, bytes) in files.iter().filter(|(name, _)| is_marker(name)) {
        if bytes.len() > MAX_MAPPING {
            return Err("historical restore marker exceeds its bound".into());
        }
        if name != &marker_name(&hash(bytes)) {
            return Err("historical restore marker filename/content differs".into());
        }
        let mapping: RestoreMapping = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if mapping.schema != "symbiote.restored-owner/1"
            || mapping.identity != identity
            || mapping.manifest_json.len() > MAX_META
            || hash(mapping.manifest_json.as_bytes()) != mapping.manifest_sha256
        {
            return Err("historical restore marker belongs to another owner or manifest".into());
        }
        let historical: BackupManifest =
            serde_json::from_str(&mapping.manifest_json).map_err(|e| e.to_string())?;
        check_manifest(&historical)?;
        if historical.identity != identity {
            return Err("historical restore manifest belongs to another owner".into());
        }
    }
    match (
        files.get("operations.jsonl"),
        files.get("operations-owner.json"),
    ) {
        (Some(bytes), Some(registration)) => {
            crate::operational::validate_snapshot(bytes, &identity, registration)?;
            let mut prepared = BTreeMap::<String, KnowledgeRecord>::new();
            for line in std::str::from_utf8(bytes)
                .map_err(|e| e.to_string())?
                .lines()
            {
                let row: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
                let event = &row["payload"];
                match event["event"].as_str() {
                    Some("evaluation_prepared") => {
                        let record: KnowledgeRecord =
                            serde_json::from_value(event["record"].clone())
                                .map_err(|e| e.to_string())?;
                        prepared.insert(
                            event["candidate_id"]
                                .as_str()
                                .ok_or("prepared candidate missing")?
                                .into(),
                            record,
                        );
                    }
                    Some("evaluation_completed") => {
                        let record = prepared
                            .get(
                                event["candidate_id"]
                                    .as_str()
                                    .ok_or("completed candidate missing")?,
                            )
                            .ok_or("completed operation lost its preparation")?;
                        if !history.iter().any(|prior| prior == record)
                            || record.digest()?
                                != event["record_sha256"]
                                    .as_str()
                                    .ok_or("completed digest missing")?
                        {
                            return Err("HOLD: completed operation lacks its exact historical knowledge promotion; valid-prefix rollback rejected".into());
                        }
                    }
                    _ => {}
                }
            }
        }
        (None, None) => {}
        _ => return Err("operational owner marker/journal pair is incomplete".into()),
    }
    Ok(identity)
}
fn registry(files: &Files, identity: &str) -> Result<(), String> {
    let history = records(files, identity)?;
    let required: Vec<_> = history
        .iter()
        .filter(|r| r.scope.strip_prefix("graph-context-").is_some_and(is_hash))
        .collect();
    let bytes = files
        .get(REGISTRY)
        .or_else(|| files.get("graph/contexts.json"));
    let Some(bytes) = bytes else {
        if required.is_empty() {
            return Ok(());
        }
        return Err("native graph research contexts require an explicitly pinned registry dependency; generic GraphMap stores do not".into());
    };
    if bytes.len() > 16384 {
        return Err("graph context registry exceeds its known runtime bound".into());
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let keys: BTreeSet<_> = value
        .as_object()
        .ok_or("registry object missing")?
        .keys()
        .map(String::as_str)
        .collect();
    let contexts = value["contexts"]
        .as_array()
        .ok_or("registry context list missing")?;
    let labels: BTreeSet<_> = contexts.iter().filter_map(Value::as_str).collect();
    let native_schema = json!({"nodes":4,"edges":[{"from":0,"to":1,"lower":1,"upper":3},{"from":1,"to":3,"lower":1,"upper":3},{"from":0,"to":2,"lower":1,"upper":3},{"from":2,"to":3,"lower":1,"upper":3}]});
    let expected_fingerprint = crate::digest(
        &json!({"kind":"finite-positive-cost-directed-graph","version":1,"query_encoding":"start*nodes+goal","schema":native_schema}),
    )?;
    if keys
        != BTreeSet::from([
            "schema",
            "controller_identity",
            "schema_fingerprint",
            "contexts",
        ])
        || value["schema"] != "symbiote.graph-contexts/1"
        || contexts.len() != 81
        || labels.len() != 81
        || labels
            .iter()
            .any(|v| !v.strip_prefix("graph-context-").is_some_and(is_hash))
        || !value["schema_fingerprint"].as_str().is_some_and(is_hash)
        || value["schema_fingerprint"] != expected_fingerprint
        || !value["controller_identity"].as_str().is_some_and(|v| {
            !v.is_empty()
                && v.len() <= 128
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
        })
        || required.iter().any(|r| {
            !labels.contains(r.scope.as_str())
                || value["schema_fingerprint"] != r.schema_fingerprint
        })
        || (files.contains_key("graph/contexts.json") && value["controller_identity"] != identity)
    {
        return Err(
            "native graph context registry owner/schema/labels do not match retained models".into(),
        );
    }
    Ok(())
}
fn dependencies(files: &Files) -> Result<Vec<ActivationDependency>, String> {
    let mut result = vec![ActivationDependency{kind:"operator-activation".into(),locator:None,sha256:None,requirement:"restoration is offline; provision a reviewed public policy, public CA/certificate and fresh private credentials before any service activation; old private key is not required".into()}];
    if let Some(bytes) = files.get("operations.jsonl") {
        let mut policy = None;
        let mut fixtures = BTreeSet::new();
        for line in std::str::from_utf8(bytes)
            .map_err(|e| e.to_string())?
            .lines()
        {
            let row: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
            let event = &row["payload"];
            if let Some(value) = event["policy_digest"].as_str() {
                policy = Some(value.to_string());
            }
            if let Some(value) = event["fixture_sha256"].as_str() {
                fixtures.insert(value.to_string());
            }
        }
        if let Some(policy) = policy {
            result.push(ActivationDependency{kind:"public-policy".into(),locator:None,sha256:Some(policy),requirement:"supply the approved original public manifest and public CA; relocation/rotation must explicitly advance policy, never rewrite its old paths".into()});
        }
        for pin in fixtures {
            result.push(ActivationDependency{kind:"local-truth-fixture".into(),locator:None,sha256:Some(pin),requirement:"provide this independently pinned local fixture before evaluating pending or new artifacts; no external fixture was copied".into()});
        }
    }
    if let Some(bytes) = files
        .get(REGISTRY)
        .or_else(|| files.get("graph/contexts.json"))
    {
        result.push(ActivationDependency{kind:"native-graph-context-registry".into(),locator:Some(if files.contains_key(REGISTRY){REGISTRY}else{"graph/contexts.json"}.into()),sha256:Some(hash(bytes)),requirement:"known research context registry preserved; complete multi-owner research runtime remains outside this single-owner backup scope".into()});
    }
    if result.len() > 128 {
        return Err("activation dependency budget exceeded".into());
    }
    Ok(result)
}
fn ledger_formats(files: &BTreeMap<String, FileFingerprint>) -> BTreeMap<String, u32> {
    ["ledger.jsonl", "knowledge.jsonl", "operations.jsonl"]
        .into_iter()
        .filter(|name| files.contains_key(*name))
        .map(|name| (name.into(), 1))
        .collect()
}
fn operational_anchor(files: &Files) -> Result<(Option<String>, Option<String>), String> {
    let Some(bytes) = files.get("operations.jsonl") else {
        return Ok((None, None));
    };
    let mut policy = None;
    let mut head = None;
    for line in std::str::from_utf8(bytes)
        .map_err(|e| e.to_string())?
        .lines()
    {
        let row: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
        if let Some(value) = row["payload"]["policy_digest"].as_str() {
            policy = Some(value.into());
        }
        head = Some(
            row["sha256"]
                .as_str()
                .ok_or("operational head digest missing")?
                .into(),
        );
    }
    Ok((policy, head))
}
fn report(manifest: &BackupManifest, pin: &str) -> BackupReport {
    BackupReport {
        schema: "symbiote.owner-backup-report/1",
        identity: manifest.identity.clone(),
        manifest_sha256: pin.into(),
        files: manifest.files.len(),
        bytes: manifest.files.values().map(|v| v.bytes).sum(),
        activation_dependencies: manifest.activation_dependencies.clone(),
        network_started: false,
    }
}
fn check_manifest(manifest: &BackupManifest) -> Result<(), String> {
    if manifest.schema != "symbiote.owner-backup/1"
        || manifest.version != 1
        || manifest.operating_system != std::env::consts::OS
        || manifest.files.is_empty()
        || manifest.files.len() > MAX_FILES
        || manifest.ledger_formats != ledger_formats(&manifest.files)
        || manifest.files.contains_key("operations.jsonl")
            != manifest.operational_policy_sha256.is_some()
        || manifest.files.contains_key("operations.jsonl")
            != manifest.operational_head_sha256.is_some()
        || manifest
            .operational_policy_sha256
            .as_deref()
            .is_some_and(|value| !is_hash(value))
        || manifest
            .operational_head_sha256
            .as_deref()
            .is_some_and(|value| !is_hash(value))
        || manifest.files.iter().any(|(name, pin)| {
            !known_file(name) || !is_hash(&pin.sha256) || pin.bytes > crate::MAX_LEDGER_BYTES
        })
        || manifest.activation_dependencies.len() > 128
        || manifest.activation_dependencies.iter().any(|d| {
            d.kind.is_empty()
                || d.kind.len() > 128
                || d.locator.as_ref().is_some_and(|v| v.len() > 4096)
                || d.requirement.is_empty()
                || d.requirement.len() > 2048
                || d.sha256.as_deref().is_some_and(|v| !is_hash(v))
        })
        || location(Path::new(&manifest.source_state))? != manifest.source_state
    {
        return Err("unsupported, cross-OS or over-budget single-owner backup manifest".into());
    }
    manifest.files.values().try_fold(0_usize, |total, pin| {
        total
            .checked_add(pin.bytes)
            .filter(|next| *next <= MAX_TOTAL)
            .ok_or("backup byte budget overflow")
    })?;
    Ok(())
}
fn fingerprint(files: &Files) -> BTreeMap<String, FileFingerprint> {
    files
        .iter()
        .map(|(name, bytes)| {
            (
                name.clone(),
                FileFingerprint {
                    bytes: bytes.len(),
                    sha256: hash(bytes),
                },
            )
        })
        .collect()
}
fn copy_files(directory: &Path, files: &Files) -> Result<(), String> {
    for (name, bytes) in files {
        let path = directory.join(name);
        fs::create_dir_all(path.parent().ok_or("snapshot file parent missing")?)
            .map_err(|e| e.to_string())?;
        write_new(&path, bytes)?;
    }
    Ok(())
}
fn load_backup(
    directory: &Path,
    expected: &str,
) -> Result<(BackupManifest, Vec<u8>, Files), String> {
    let directory = existing_directory(directory)?;
    if !is_hash(expected) || exists(&directory.join("backup-incomplete.json"))? {
        return Err("backup is incomplete or its external manifest pin is invalid".into());
    }
    for entry in fs::read_dir(&directory).map_err(|e| e.to_string())? {
        let name = entry.map_err(|e| e.to_string())?.file_name();
        if name != MANIFEST && name != "files" {
            return Err("unknown backup envelope sidecar".into());
        }
    }
    let raw = maintenance::read_regular(&directory.join(MANIFEST), MAX_META)?
        .ok_or("committed backup manifest missing")?;
    credential_free(&raw)?;
    if hash(&raw) != expected {
        return Err("backup manifest differs from its externally retained digest".into());
    }
    let manifest: BackupManifest = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    check_manifest(&manifest)?;
    let files_dir = existing_directory(&directory.join("files"))?;
    if maintenance::inspect(&files_dir)?
        .locks
        .iter()
        .any(|lock| lock.state != maintenance::LockState::Absent)
    {
        return Err("backup evidence directory has an active, stale or unknown writer; refusing an activation race".into());
    }
    let files = gather(&files_dir)?;
    if fingerprint(&files) != manifest.files || validate_files(&files)? != manifest.identity {
        return Err("backup file set, bytes or owner differs from its manifest".into());
    }
    if operational_anchor(&files)?
        != (
            manifest.operational_policy_sha256.clone(),
            manifest.operational_head_sha256.clone(),
        )
    {
        return Err("manifest operational policy/head differs from copied history".into());
    }
    registry(&files, &manifest.identity)?;
    if maintenance::validate_offline_state(&files_dir)? != manifest.identity {
        return Err("backup metadata owner differs".into());
    }
    Ok((manifest, raw, files))
}

/// Snapshot exactly one quiescent owner, refusing unrecognized descendant state.
pub fn create(
    source: &Path,
    destination: &Path,
    options: &BackupOptions,
) -> Result<BackupReport, String> {
    let source = existing_directory(source)?;
    writer_admission(&source)?;
    let _guard = maintenance::offline_guard(&source)?;
    let identity = maintenance::validate_offline_state(&source)?;
    let mut files = gather(&source)?;
    if let Some(dependency) = &options.graph_context_registry {
        let bytes = maintenance::read_regular(&dependency.path, 16384)?
            .ok_or("explicit registry dependency missing")?;
        if !is_hash(&dependency.expected_sha256) || hash(&bytes) != dependency.expected_sha256 {
            return Err("explicit registry dependency pin mismatch".into());
        }
        credential_free(&bytes)?;
        if files.get(REGISTRY).is_some_and(|prior| prior != &bytes) {
            return Err("explicit registry conflicts with retained dependency".into());
        }
        files.insert(REGISTRY.into(), bytes);
    }
    if validate_files(&files)? != identity {
        return Err("mixed-owner snapshot refused".into());
    }
    registry(&files, &identity)?;
    let fingerprints = fingerprint(&files);
    let (operational_policy_sha256, operational_head_sha256) = operational_anchor(&files)?;
    let manifest = BackupManifest {
        schema: "symbiote.owner-backup/1".into(), version: 1,
        operating_system: std::env::consts::OS.into(), identity, source_state: location(&source)?,
        ledger_formats: ledger_formats(&fingerprints), operational_policy_sha256, operational_head_sha256,
        files: fingerprints, activation_dependencies: dependencies(&files)?,
        scope: "one owner only; child stores, unknown sidecars and credentials are never silently omitted; external dependencies require explicit provisioning; same-OS restore only".into(),
    };
    check_manifest(&manifest)?;
    let raw = serde_json::to_vec(&manifest).map_err(|e| e.to_string())?;
    if raw.len() > MAX_META {
        return Err("backup manifest budget exceeded".into());
    }
    let destination = new_path(destination)?;
    if destination.starts_with(&source) {
        return Err("backup destination must be outside its source owner tree".into());
    }
    fs::create_dir(&destination).map_err(|e| e.to_string())?;
    write_new(
        &destination.join("backup-incomplete.json"),
        b"{\"schema\":\"symbiote.backup-incomplete/1\"}\n",
    )?;
    copy_files(&destination.join("files"), &files)?;
    write_new(&destination.join(MANIFEST), &raw)?;
    fs::remove_file(destination.join("backup-incomplete.json")).map_err(|e| e.to_string())?;
    let pin = hash(&raw);
    verify(&destination, &pin)
}
/// Read-only verification; the digest must come from the separately retained receipt.
pub fn verify(snapshot: &Path, expected_manifest_sha256: &str) -> Result<BackupReport, String> {
    let (manifest, _, _) = load_backup(snapshot, expected_manifest_sha256)?;
    Ok(report(&manifest, expected_manifest_sha256))
}
/// Restore into a new reserved destination. Failure leaves explicit inactive
/// evidence; neither stale locks nor interrupted reservations are auto-cleared.
pub fn restore(
    snapshot: &Path,
    expected_manifest_sha256: &str,
    destination: &Path,
) -> Result<RestoreReport, String> {
    restore_internal(snapshot, expected_manifest_sha256, destination, || Ok(()))
}
fn restore_internal(
    snapshot: &Path,
    expected_manifest_sha256: &str,
    destination: &Path,
    before_publish: impl FnOnce() -> Result<(), String>,
) -> Result<RestoreReport, String> {
    let (manifest, raw, files) = load_backup(snapshot, expected_manifest_sha256)?;
    let destination = new_path(destination)?;
    if destination.starts_with(existing_directory(snapshot)?) {
        return Err("restore destination must be outside its immutable backup envelope".into());
    }
    let reserved = reservation(&destination)?;
    let reservation_bytes = serde_json::to_vec(&json!({"schema":"symbiote.restore-reservation/1","destination":location(&destination)?,"manifest_sha256":expected_manifest_sha256})).map_err(|e|e.to_string())?;
    write_new(&reserved, &reservation_bytes)?;
    if let Err(error) = fs::create_dir(&destination) {
        if maintenance::read_regular(&reserved, MAX_META)?.as_deref()
            == Some(reservation_bytes.as_slice())
        {
            fs::remove_file(&reserved).map_err(|e| e.to_string())?;
        }
        return Err(format!(
            "new restore destination could not be reserved: {error}"
        ));
    }
    write_new(&destination.join(INCOMPLETE), &reservation_bytes)?;
    let guard = maintenance::offline_guard(&destination)?;
    copy_files(&destination, &files)?;
    if maintenance::validate_offline_state(&destination)? != manifest.identity
        || validate_files(&files)? != manifest.identity
    {
        return Err("restored owner replay failed; destination remains inactive".into());
    }
    before_publish()?;
    let mapping = RestoreMapping {
        schema: "symbiote.restored-owner/1".into(),
        identity: manifest.identity.clone(),
        source_state: manifest.source_state.clone(),
        restored_state: location(&destination)?,
        manifest_sha256: expected_manifest_sha256.into(),
        manifest_json: String::from_utf8(raw).map_err(|e| e.to_string())?,
    };
    let mapping_bytes = serde_json::to_vec(&mapping).map_err(|e| e.to_string())?;
    let mapping_pin = hash(&mapping_bytes);
    write_new(&destination.join(marker_name(&mapping_pin)), &mapping_bytes)?;
    // Inspect the verified mapping before publishing either admission marker.
    validate_mapping_files(&destination, &mapping, &mapping_pin)?;
    fs::remove_file(destination.join(INCOMPLETE)).map_err(|e| e.to_string())?;
    drop(guard);
    if maintenance::read_regular(&reserved, MAX_META)?.as_deref()
        != Some(reservation_bytes.as_slice())
    {
        return Err("restore reservation changed; publication refused".into());
    }
    fs::remove_file(reserved).map_err(|e| e.to_string())?;
    Ok(RestoreReport {
        schema: "symbiote.owner-restore-report/1",
        identity: manifest.identity,
        destination: location(&destination)?,
        manifest_sha256: expected_manifest_sha256.into(),
        restore_mapping_sha256: mapping_pin,
        activation_dependencies: manifest.activation_dependencies,
        requires_activation: true,
        network_started: false,
    })
}
fn validate_mapping_files(
    directory: &Path,
    mapping: &RestoreMapping,
    mapping_pin: &str,
) -> Result<(), String> {
    if mapping.schema != "symbiote.restored-owner/1"
        || !is_hash(mapping_pin)
        || hash(mapping.manifest_json.as_bytes()) != mapping.manifest_sha256
    {
        return Err("restore mapping manifest pin mismatch".into());
    }
    let manifest: BackupManifest =
        serde_json::from_str(&mapping.manifest_json).map_err(|e| e.to_string())?;
    check_manifest(&manifest)?;
    if manifest.identity != mapping.identity
        || manifest.source_state != mapping.source_state
        || mapping.restored_state != location(directory)?
    {
        return Err("restore mapping owner/source/destination mismatch".into());
    }
    let mut actual = inventory(directory, true)?;
    actual.remove(&marker_name(mapping_pin));
    if fingerprint(&actual) != manifest.files {
        return Err("restored owner gained or lost an unregistered critical sidecar".into());
    }
    let mut files = Files::new();
    for (name, pin) in &manifest.files {
        let bytes = maintenance::read_regular(&directory.join(name), crate::MAX_LEDGER_BYTES)?
            .ok_or("copied restore file missing")?;
        if bytes.len() != pin.bytes || hash(&bytes) != pin.sha256 {
            return Err("copied restore bytes advanced or changed before relocation; refusing stale mapping".into());
        }
        files.insert(name.clone(), bytes);
    }
    if validate_files(&files)? != mapping.identity
        || maintenance::validate_offline_state(directory)? != mapping.identity
    {
        return Err("restored state owner mismatch".into());
    }
    if operational_anchor(&files)?
        != (
            manifest.operational_policy_sha256,
            manifest.operational_head_sha256,
        )
    {
        return Err("restored operational policy/head no longer matches its manifest".into());
    }
    registry(&files, &mapping.identity)
}
/// Verify relocation without opening or reading the old source directory. The
/// old path is immutable metadata; copied bytes must still precede any mutation.
pub fn validate_restore_mapping(
    new_state: &Path,
    prior_state: &Path,
    expected_identity: &str,
) -> Result<String, String> {
    validate_restore_mapping_excluding(new_state, prior_state, expected_identity, &BTreeSet::new())
}

fn read_mappings(
    directory: &Path,
    expected_identity: &str,
) -> Result<Vec<(String, RestoreMapping)>, String> {
    let mut result = Vec::new();
    let mut count = 0_usize;
    for entry in fs::read_dir(directory).map_err(|e| e.to_string())? {
        count += 1;
        if count > MAX_FILES + 8 {
            return Err("restore metadata discovery exceeds its entry bound".into());
        }
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or("restore marker name is not UTF-8")?
            .to_string();
        if !is_marker(&name) {
            if name.starts_with("restored-owner-") {
                return Err("unrecognized restore marker filename".into());
            }
            continue;
        }
        let bytes = maintenance::read_regular(&entry.path(), MAX_MAPPING)?
            .ok_or("restore marker missing")?;
        let pin = hash(&bytes);
        if name != marker_name(&pin) {
            return Err("restore marker content/name pin mismatch".into());
        }
        let mapping: RestoreMapping = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if mapping.schema != "symbiote.restored-owner/1"
            || mapping.identity != expected_identity
            || mapping.manifest_json.len() > MAX_META
            || hash(mapping.manifest_json.as_bytes()) != mapping.manifest_sha256
            || location(Path::new(&mapping.source_state))? != mapping.source_state
            || location(Path::new(&mapping.restored_state))? != mapping.restored_state
        {
            return Err("restore metadata owner/schema/locations/manifest pin mismatch".into());
        }
        let manifest: BackupManifest =
            serde_json::from_str(&mapping.manifest_json).map_err(|e| e.to_string())?;
        check_manifest(&manifest)?;
        if manifest.identity != expected_identity || manifest.source_state != mapping.source_state {
            return Err("restore metadata manifest owner/source mismatch".into());
        }
        result.push((pin, mapping));
    }
    Ok(result)
}

/// Enumerate ALL owner restore metadata without reapplying a stale
/// copied-byte snapshot after a legitimate policy transition. The service must
/// bind each mapping to its typed, explicit relocation review. A foreign-path
/// unreviewed marker is HOLD, not permission to ignore a moved restored store.
pub fn restore_mappings(
    new_state: &Path,
    expected_identity: &str,
) -> Result<Vec<RestoreMappingInfo>, String> {
    let directory = existing_directory(new_state)?;
    writer_admission(&directory)?;
    let current = location(&directory)?;
    let mut result = Vec::new();
    for (sha256, mapping) in read_mappings(&directory, expected_identity)? {
        let manifest: BackupManifest =
            serde_json::from_str(&mapping.manifest_json).map_err(|e| e.to_string())?;
        result.push(RestoreMappingInfo {
            sha256,
            source_state: mapping.source_state,
            destination_matches: mapping.restored_state == current,
            restored_state: mapping.restored_state,
            operational_policy_sha256: manifest.operational_policy_sha256,
            operational_head_sha256: manifest.operational_head_sha256,
        });
    }
    Ok(result)
}

/// Explicit review of a new restoration. `consumed` must be obtained from fully
/// typed local policy history. Validate all marker metadata before filtering;
/// only already-reviewed hashes bypass the stale full-byte comparison.
pub fn validate_restore_mapping_excluding(
    new_state: &Path,
    prior_state: &Path,
    expected_identity: &str,
    consumed: &BTreeSet<String>,
) -> Result<String, String> {
    let directory = existing_directory(new_state)?;
    writer_admission(&directory)?;
    let prior = location(prior_state)?;
    let current = location(&directory)?;
    let mut found = Vec::new();
    for (pin, mapping) in read_mappings(&directory, expected_identity)? {
        if consumed.contains(&pin) {
            continue;
        }
        if mapping.restored_state == current && mapping.source_state == prior {
            validate_mapping_files(&directory, &mapping, &pin)?;
            found.push(pin);
        }
    }
    if found.len() != 1 {
        return Err(
            "exactly one verified owner/source/destination restore mapping is required".into(),
        );
    }
    Ok(found.remove(0))
}

#[cfg(test)]
mod tests;
