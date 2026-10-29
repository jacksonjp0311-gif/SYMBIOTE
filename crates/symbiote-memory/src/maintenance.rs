//! Cooperative state lifecycle, stale-writer recovery and byte-preserving registration.
//!
//! Normal writers and maintenance share one short-lived gate. PID liveness is
//! conservative: unknown ownership is HOLD, never permission to remove a lock.
//! Maintenance does not terminate processes, repair corrupt evidence or rewrite
//! either learning ledger. Privileged filesystem attackers are outside this model.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

const GATE: &str = "maintenance.guard";
const WRITERS: [&str; 2] = ["writer.lock", "knowledge.writer.lock"];
const LEGACY_LEDGERS: [&str; 3] = ["ledger.jsonl", "knowledge.jsonl", "operations.jsonl"];
const LEDGERS: [&str; 4] = [
    "ledger.jsonl",
    "knowledge.jsonl",
    "operations.jsonl",
    "strategy.jsonl",
];
const LAYOUT: &str = "state-layout.json";
const BACKUP: &str = "migration-backup-v1";
const FEATURE_BACKUP: &str = "migration-backup-v2";
pub(crate) const FORMAT_UPGRADE: &str = "format-upgrade-incomplete.json";
const PREVIOUS_LAYOUT: &str = "previous-state-layout.json";
const AUDIT: &str = "maintenance-audit.jsonl";
const MAX_LOCK_BYTES: usize = 4096;
const MAX_METADATA_BYTES: usize = 16 * 1024;
const MAX_AUDIT_BYTES: usize = 1024 * 1024;
const MAX_AUDIT_RECORDS: usize = 1024;
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockState {
    Absent,
    Live,
    Dead,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
pub struct LockInspection {
    pub name: String,
    pub process: Option<u32>,
    pub state: LockState,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Inspection {
    pub schema: &'static str,
    pub status: &'static str,
    pub state_exists: bool,
    pub layout_registered: bool,
    pub layout_version: Option<u32>,
    pub identity: Option<String>,
    pub ledger_files: Vec<String>,
    pub ledger_integrity: &'static str,
    pub locks: Vec<LockInspection>,
    pub state_modified: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RecoveryReport {
    pub schema: &'static str,
    pub status: &'static str,
    pub recovered_locks: Vec<String>,
    pub ledgers_modified: bool,
    pub processes_terminated: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct MigrationReport {
    pub schema: &'static str,
    pub status: &'static str,
    pub changed: bool,
    pub layout_version: u32,
    pub identity: String,
    pub backup_directory: String,
    pub registered_ledger_sha256: BTreeMap<String, String>,
    pub ledger_bytes_changed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateLayout {
    schema: String,
    layout_version: u32,
    identity: String,
    /// The JSONL encodings remain v1. Optional promotion_policy=2 is an
    /// admission-policy extension; legacy missing policy fields keep their hash.
    ledger_formats: BTreeMap<String, u32>,
    promotion_policy: u32,
    backup_directory: String,
    snapshot_sha256: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    sidecar_sha256: BTreeMap<String, String>,
}

/// Persistent preparation is written before feature-registration mutations.
/// Resume accepts only these exact source bytes and the old or planned layout.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpgradePlan {
    schema: String,
    identity: String,
    target: StateLayout,
    previous_layout_json: Option<String>,
    source_sha256: BTreeMap<String, String>,
    sha256: String,
}
impl UpgradePlan {
    fn hash(&self) -> Result<String, String> {
        Ok(hash(
            &serde_json::to_vec(&(
                &self.schema,
                &self.identity,
                &self.target,
                &self.previous_layout_json,
                &self.source_sha256,
            ))
            .map_err(|e| e.to_string())?,
        ))
    }
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn owner_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
}

pub(crate) fn read_regular(path: &Path, limit: usize) -> Result<Option<Vec<u8>>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    if !metadata.file_type().is_file() || metadata.len() > limit as u64 {
        return Err(format!("{} is not a bounded regular file", path.display()));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("state file grew beyond its byte budget".into());
    }
    Ok(Some(bytes))
}

fn ensure_directory(directory: &Path) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(directory).map_err(|e| format!("state directory unavailable: {e}"))?;
    if !metadata.file_type().is_dir() {
        return Err("state must be an existing regular directory, not a symbolic link".into());
    }
    Ok(())
}

fn parse_layout(bytes: &[u8]) -> Result<StateLayout, String> {
    let layout: StateLayout =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid state-layout metadata: {e}"))?;
    let legacy = layout.schema == "symbiote.state-layout/1"
        && layout.layout_version == 1
        && layout.backup_directory == BACKUP
        && layout.sidecar_sha256.is_empty();
    let feature = layout.schema == "symbiote.state-layout/2"
        && layout.layout_version == 2
        && layout.backup_directory == FEATURE_BACKUP
        && layout.ledger_formats.contains_key("ledger.jsonl")
        && layout
            .ledger_formats
            .contains_key(crate::strategy::STRATEGY_FILE)
        && layout
            .sidecar_sha256
            .contains_key(crate::strategy::STRATEGY_OWNER_FILE)
        && layout.ledger_formats.contains_key("operations.jsonl")
            == layout
                .sidecar_sha256
                .contains_key(crate::operational::OWNER_FILE)
        && layout.sidecar_sha256.iter().all(|(name, pin)| {
            [
                crate::strategy::STRATEGY_OWNER_FILE,
                crate::operational::OWNER_FILE,
                PREVIOUS_LAYOUT,
            ]
            .contains(&name.as_str())
                && hex_digest(pin)
        });
    if !(legacy || feature)
        || layout.promotion_policy != 2
        || !owner_label(&layout.identity)
        || layout.ledger_formats.is_empty()
        || layout.ledger_formats.len() > LEDGERS.len()
        || layout
            .ledger_formats
            .keys()
            .ne(layout.snapshot_sha256.keys())
        || layout.ledger_formats.iter().any(|(name, version)| {
            !(if legacy {
                &LEGACY_LEDGERS[..]
            } else {
                &LEDGERS[..]
            })
            .contains(&name.as_str())
                || *version != 1
        })
        || layout
            .snapshot_sha256
            .values()
            .any(|value| !hex_digest(value))
    {
        return Err("unsupported state layout, ledger format or promotion policy; preserve state and use a compatible version".into());
    }
    Ok(layout)
}

fn read_layout(directory: &Path) -> Result<Option<StateLayout>, String> {
    let Some(bytes) = read_regular(&directory.join(LAYOUT), MAX_METADATA_BYTES)? else {
        return Ok(None);
    };
    let layout = parse_layout(&bytes)?;
    for name in layout.ledger_formats.keys() {
        let metadata = fs::symlink_metadata(directory.join(name))
            .map_err(|_| format!("registered ledger {name} is missing; refusing to reset state"))?;
        if !metadata.file_type().is_file() {
            return Err(format!("registered ledger {name} must be a regular file"));
        }
    }
    Ok(Some(layout))
}

pub(crate) fn validate_layout_identity(directory: &Path, identity: &str) -> Result<(), String> {
    if read_layout(directory)?.is_some_and(|layout| layout.identity != identity) {
        return Err("state-layout identity differs from the learning ledger".into());
    }
    Ok(())
}

/// A legacy registered owner may prepare an empty strategy journal/marker pair,
/// but learning mutations require deliberate feature-format registration first.
/// The caller retains the original Store lease, so migration cannot race it.
pub(crate) fn validate_strategy_learning_admission(directory: &Path) -> Result<(), String> {
    super::backup::writer_admission(directory)?;
    if let Some(layout) = read_layout(directory)? {
        if layout.layout_version != 2
            || layout.ledger_formats.get(crate::strategy::STRATEGY_FILE) != Some(&1)
        {
            return Err("HOLD: registered legacy owner must explicitly migrate to state-layout/2 before strategy learning mutations".into());
        }
    }
    Ok(())
}

pub(crate) fn validate_knowledge_owner(directory: &Path, identity: &str) -> Result<(), String> {
    validate_knowledge_owner_admission(directory, identity, false)
}

pub(crate) fn validate_engine_knowledge_owner(
    directory: &Path,
    identity: &str,
) -> Result<(), String> {
    validate_knowledge_owner_admission(directory, identity, true)
}

fn validate_knowledge_owner_admission(
    directory: &Path,
    identity: &str,
    engine: bool,
) -> Result<(), String> {
    validate_layout_identity(directory, identity)?;
    let original = read_regular(&directory.join("ledger.jsonl"), super::MAX_LEDGER_BYTES)?;
    if original.is_none()
        && (directory.join("operations.jsonl").exists()
            || directory.join(super::operational::OWNER_FILE).exists()
            || directory.join(super::strategy::STRATEGY_FILE).exists()
            || directory
                .join(super::strategy::STRATEGY_OWNER_FILE)
                .exists())
    {
        return Err("operational or strategy state exists without its original identity ledger; refusing structural owner initialization".into());
    }
    if let Some(bytes) = original {
        let (owner, registration) = super::Store::validate_owner_snapshot(&bytes)?;
        if owner != identity {
            return Err("structural knowledge owner differs from original identity ledger; refusing to create or modify state".into());
        }
        if engine != registration.is_some() {
            return Err(
                "knowledge writer admission differs from the registered owner namespace".into(),
            );
        }
    } else if engine {
        return Err("engine knowledge requires its explicitly registered identity ledger".into());
    }
    Ok(())
}

fn lock_bytes() -> Result<Vec<u8>, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes Unix epoch")?;
    let sequence = super::TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nonce = super::digest(&(now.as_nanos().to_string(), std::process::id(), sequence))?;
    Ok(format!("process={}\nnonce={nonce}\n", std::process::id()).into_bytes())
}

pub(crate) struct WriterLock {
    path: PathBuf,
    owned_bytes: Vec<u8>,
}
impl Drop for WriterLock {
    fn drop(&mut self) {
        // Do not remove a replacement lock belonging to another owner.
        if read_regular(&self.path, MAX_LOCK_BYTES)
            .ok()
            .flatten()
            .as_deref()
            == Some(self.owned_bytes.as_slice())
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn owned_lock(path: PathBuf) -> Result<WriterLock, String> {
    let bytes = lock_bytes()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| {
            format!(
                "exclusive lock {} unavailable (live, stale or maintenance owner): {e}",
                path.display()
            )
        })?;
    let result = file.write_all(&bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(&path);
        return Err(error.to_string());
    }
    Ok(WriterLock {
        path,
        owned_bytes: bytes,
    })
}

fn gate(directory: &Path) -> Result<WriterLock, String> {
    ensure_directory(directory)?;
    owned_lock(directory.join(GATE)).map_err(|error| format!("maintenance gate unavailable; do not break it while another process may operate: {error}"))
}

/// Hold the second returned guard until the constructor has validated cross-
/// ledger ownership and committed any first Genesis record. Distinct writer
/// locks alone do not serialize the two stores' shared identity initialization.
pub(crate) fn writer_lock(
    directory: &Path,
    name: &str,
) -> Result<(WriterLock, WriterLock), String> {
    if !WRITERS.contains(&name) {
        return Err("unsupported writer lock name".into());
    }
    super::backup::writer_admission(directory)?;
    let initialization_gate = gate(directory)?;
    super::backup::writer_admission(directory)?;
    read_layout(directory)?;
    let writer = owned_lock(directory.join(name))?;
    Ok((writer, initialization_gate))
}

/// A backup/restore caller retains this guard while copying a coherent owner
/// snapshot. No stale or uncertain writer is silently recovered here.
pub(crate) fn offline_guard(directory: &Path) -> Result<WriterLock, String> {
    let guard = gate(directory)?;
    quiescent_locks(directory, false)?;
    Ok(guard)
}

/// Pure typed replay of all registered owner state and immutable migration
/// evidence. The caller holds `offline_guard` when coherence is required.
pub(crate) fn validate_offline_state(directory: &Path) -> Result<String, String> {
    ensure_directory(directory)?;
    reject_pending_upgrade(directory)?;
    let layout = read_layout(directory)?;
    audit_rows(directory)?;
    let (identity, _) = validated_snapshots(directory)?;
    if let Some(layout) = layout {
        if layout.identity != identity {
            return Err("backup layout identity differs from typed owner ledgers".into());
        }
        backup_matches(directory, &layout)?;
    }
    Ok(identity)
}

fn parse_pid(bytes: &[u8]) -> Result<u32, String> {
    if bytes.last() != Some(&b'\n') {
        return Err("partial writer ownership record lacks its final newline".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "lock ownership is not UTF-8")?;
    let lines: Vec<_> = text.lines().collect();
    if lines.is_empty()
        || lines.len() > 2
        || (lines.len() == 2 && !lines[1].strip_prefix("nonce=").is_some_and(hex_digest))
    {
        return Err("unrecognized or partial writer ownership record".into());
    }
    let pid = lines[0]
        .strip_prefix("process=")
        .ok_or("missing writer process identity")?
        .parse::<u32>()
        .map_err(|_| "invalid writer process identity")?;
    if pid == 0 || pid > 2_147_483_647 {
        return Err("writer process identity must be 1..=i32::MAX".into());
    }
    Ok(pid)
}

#[cfg(windows)]
fn process_state(pid: u32) -> LockState {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }
    // SAFETY: these read-only Win32 calls receive a bounded numeric PID, request
    // SYNCHRONIZE only, wait for zero time and close exactly the returned handle.
    // No termination, memory access, handle inheritance or pointer dereference occurs.
    unsafe {
        let handle = OpenProcess(0x0010_0000, 0, pid);
        if handle.is_null() {
            return if std::io::Error::last_os_error().raw_os_error() == Some(87) {
                LockState::Dead
            } else {
                LockState::Unknown
            };
        }
        let state = match WaitForSingleObject(handle, 0) {
            0 => LockState::Dead,
            258 => LockState::Live,
            _ => LockState::Unknown,
        };
        if CloseHandle(handle) == 0 {
            return LockState::Unknown;
        }
        state
    }
}

#[cfg(unix)]
fn process_state(pid: u32) -> LockState {
    unsafe extern "C" {
        fn kill(pid: std::ffi::c_int, signal: std::ffi::c_int) -> std::ffi::c_int;
    }
    let Ok(pid) = std::ffi::c_int::try_from(pid) else {
        return LockState::Unknown;
    };
    // SAFETY: signal zero performs a process-existence/permission check without
    // sending a signal. Only a strictly positive validated PID reaches this call.
    let result = unsafe { kill(pid, 0) };
    if result == 0 {
        return LockState::Live;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(3) => LockState::Dead,
        Some(1) => LockState::Live,
        _ => LockState::Unknown,
    }
}

#[cfg(not(any(unix, windows)))]
fn process_state(_pid: u32) -> LockState {
    LockState::Unknown
}

fn inspect_lock(directory: &Path, name: &str) -> Result<(LockInspection, Option<Vec<u8>>), String> {
    let Some(bytes) = read_regular(&directory.join(name), MAX_LOCK_BYTES)? else {
        return Ok((
            LockInspection {
                name: name.into(),
                process: None,
                state: LockState::Absent,
                detail: "no lock".into(),
            },
            None,
        ));
    };
    let (process, state, detail) = match parse_pid(&bytes) {
        Ok(pid) => {
            let state = if pid == std::process::id() {
                LockState::Live
            } else {
                process_state(pid)
            };
            (
                Some(pid),
                state,
                "PID existence is checked conservatively; PID reuse keeps recovery on HOLD".into(),
            )
        }
        Err(error) => (None, LockState::Unknown, error),
    };
    Ok((
        LockInspection {
            name: name.into(),
            process,
            state,
            detail,
        },
        Some(bytes),
    ))
}

/// Nonmutating inspection of typed committed ledger snapshots, layout identity
/// and maintenance-audit integrity. Concurrent atomic writes can leave a valid
/// older snapshot; this does not certify remote truth or quiescent processes.
pub fn inspect(directory: &Path) -> Result<Inspection, String> {
    if !directory.exists() {
        return Ok(Inspection {
            schema: "symbiote.maintenance-inspection/1",
            status: "EMPTY",
            state_exists: false,
            layout_registered: false,
            layout_version: None,
            identity: None,
            ledger_files: Vec::new(),
            ledger_integrity: "not_present",
            locks: Vec::new(),
            state_modified: false,
        });
    }
    ensure_directory(directory)?;
    reject_pending_upgrade(directory)?;
    let layout = read_layout(directory)?;
    let mut locks = Vec::new();
    for name in [GATE, WRITERS[0], WRITERS[1]] {
        locks.push(inspect_lock(directory, name)?.0);
    }
    let mut ledgers = Vec::new();
    for name in LEDGERS {
        if read_regular(&directory.join(name), super::MAX_LEDGER_BYTES)?.is_some() {
            ledgers.push(name.into());
        }
    }
    audit_rows(directory)?;
    let has_operational_registration = read_regular(
        &directory.join(super::operational::OWNER_FILE),
        super::operational::MAX_OWNER_BYTES,
    )?
    .is_some();
    let has_strategy_registration =
        read_regular(&directory.join(crate::strategy::STRATEGY_OWNER_FILE), 2048)?.is_some();
    let validated_identity =
        if ledgers.is_empty() && !has_operational_registration && !has_strategy_registration {
            None
        } else {
            Some(validated_snapshots(directory)?.0)
        };
    if layout
        .as_ref()
        .is_some_and(|layout| validated_identity.as_ref() != Some(&layout.identity))
    {
        return Err("state-layout identity differs from the validated learning ledgers".into());
    }
    Ok(Inspection {
        schema: "symbiote.maintenance-inspection/1",
        status: if locks.iter().any(|lock| lock.state != LockState::Absent) {
            "ATTENTION"
        } else {
            "PASS"
        },
        state_exists: true,
        layout_registered: layout.is_some(),
        layout_version: layout.as_ref().map(|v| v.layout_version),
        identity: validated_identity.or_else(|| layout.map(|v| v.identity)),
        ledger_integrity: if ledgers.is_empty() {
            "not_present"
        } else {
            "verified_snapshot"
        },
        ledger_files: ledgers,
        locks,
        state_modified: false,
    })
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditRecord {
    sequence: usize,
    previous: String,
    event: Value,
    sha256: String,
}
impl AuditRecord {
    fn hash(&self) -> Result<String, String> {
        super::digest(&(self.sequence, &self.previous, &self.event))
    }
}

fn audit_rows(directory: &Path) -> Result<Vec<AuditRecord>, String> {
    let Some(bytes) = read_regular(&directory.join(AUDIT), MAX_AUDIT_BYTES)? else {
        return Ok(Vec::new());
    };
    if bytes.is_empty() || bytes.last() != Some(&b'\n') {
        return Err(
            "maintenance audit is empty or truncated; preserve it for investigation".into(),
        );
    }
    let mut rows = Vec::new();
    let mut previous = ZERO.to_string();
    for (sequence, line) in std::str::from_utf8(&bytes)
        .map_err(|e| e.to_string())?
        .lines()
        .enumerate()
    {
        if sequence >= MAX_AUDIT_RECORDS || line.len() > MAX_METADATA_BYTES {
            return Err("maintenance audit exceeds record budget".into());
        }
        let row: AuditRecord =
            serde_json::from_str(line).map_err(|e| format!("invalid maintenance audit: {e}"))?;
        if row.sequence != sequence || row.previous != previous || row.sha256 != row.hash()? {
            return Err("maintenance audit hash chain mismatch".into());
        }
        previous = row.sha256.clone();
        rows.push(row);
    }
    Ok(rows)
}

pub(crate) fn atomic_replace(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let sequence = super::TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = directory.join(format!(
        ".maintenance.{}.{sequence}.tmp",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        file.write_all(bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);
        fs::rename(&temporary, directory.join(name))
            .map_err(|e| format!("atomic maintenance write: {e}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn append_audit(directory: &Path, event: Value) -> Result<(), String> {
    let mut rows = audit_rows(directory)?;
    if rows.len() >= MAX_AUDIT_RECORDS {
        return Err("maintenance audit record budget exhausted".into());
    }
    let mut row = AuditRecord {
        sequence: rows.len(),
        previous: rows
            .last()
            .map(|r| r.sha256.as_str())
            .unwrap_or(ZERO)
            .into(),
        event,
        sha256: String::new(),
    };
    row.sha256 = row.hash()?;
    if serde_json::to_vec(&row).map_err(|e| e.to_string())?.len() > MAX_METADATA_BYTES {
        return Err("maintenance audit record byte budget exhausted".into());
    }
    rows.push(row);
    let mut bytes = Vec::new();
    for row in rows {
        serde_json::to_writer(&mut bytes, &row).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
    }
    if bytes.len() > MAX_AUDIT_BYTES {
        return Err("maintenance audit byte budget exhausted".into());
    }
    atomic_replace(directory, AUDIT, &bytes)
}

fn quiescent_locks(directory: &Path, allow_dead: bool) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut dead = Vec::new();
    for name in WRITERS {
        let (inspection, bytes) = inspect_lock(directory, name)?;
        match inspection.state {
            LockState::Absent => {}
            LockState::Dead if allow_dead => {
                dead.push((name.into(), bytes.ok_or("lock disappeared")?))
            }
            LockState::Dead => {
                return Err(format!(
                    "HOLD: stale {name} must be recovered before migration"
                ))
            }
            LockState::Live => {
                return Err(format!(
                    "HOLD: {name} is owned by live process {}; no lock removed",
                    inspection.process.unwrap_or(0)
                ))
            }
            LockState::Unknown => {
                return Err(format!(
                    "HOLD: {name} ownership/liveness is uncertain; no lock removed"
                ))
            }
        }
    }
    Ok(dead)
}

/// Removes only stale cooperative writer locks after proving both owners absent.
/// A stale maintenance gate itself requires explicit quiescent operator recovery.
pub fn recover(directory: &Path) -> Result<RecoveryReport, String> {
    let _gate = gate(directory)?;
    reject_pending_upgrade(directory)?;
    read_layout(directory)?;
    audit_rows(directory)?;
    let dead = quiescent_locks(directory, true)?;
    let operation = hash(&lock_bytes()?);
    let planned: BTreeMap<_, _> = dead
        .iter()
        .map(|(name, bytes)| (name.clone(), hash(bytes)))
        .collect();
    append_audit(
        directory,
        json!({"operation":"recover","phase":"prepared","operation_id":operation,"lock_sha256":planned,"ledgers_modified":false}),
    )?;
    let mut recovered = Vec::new();
    for (name, original) in dead {
        let path = directory.join(&name);
        if read_regular(&path, MAX_LOCK_BYTES)?.as_deref() != Some(original.as_slice()) {
            return Err("HOLD: lock changed after liveness inspection; recovery stopped".into());
        }
        fs::remove_file(&path)
            .map_err(|e| format!("failed to remove verified-stale lock {name}: {e}"))?;
        recovered.push(name);
    }
    append_audit(
        directory,
        json!({"operation":"recover","phase":"completed","operation_id":operation,"recovered_locks":recovered,"ledgers_modified":false}),
    )?;
    Ok(RecoveryReport {
        schema: "symbiote.recovery/1",
        status: "PASS",
        recovered_locks: recovered,
        ledgers_modified: false,
        processes_terminated: 0,
    })
}

fn validated_snapshots(directory: &Path) -> Result<(String, BTreeMap<String, Vec<u8>>), String> {
    let mut snapshots = BTreeMap::new();
    for name in LEDGERS {
        if let Some(bytes) = read_regular(&directory.join(name), super::MAX_LEDGER_BYTES)? {
            snapshots.insert(name.into(), bytes);
        }
    }
    let operational_registration = read_regular(
        &directory.join(super::operational::OWNER_FILE),
        super::operational::MAX_OWNER_BYTES,
    )?;
    if snapshots.contains_key("operations.jsonl") != operational_registration.is_some() {
        return Err("HOLD: operational journal/owner registration pair is incomplete; preserve state and restore history".into());
    }
    let strategy_registration =
        read_regular(&directory.join(crate::strategy::STRATEGY_OWNER_FILE), 2048)?;
    if snapshots.contains_key(crate::strategy::STRATEGY_FILE) != strategy_registration.is_some() {
        return Err(
            "HOLD: strategy journal/owner registration pair is incomplete; preserve state".into(),
        );
    }
    if snapshots.is_empty() {
        return Err("no learning ledgers to register; run a demonstration first".into());
    }
    if (snapshots.contains_key("operations.jsonl") || strategy_registration.is_some())
        && !snapshots.contains_key("ledger.jsonl")
    {
        return Err(
            "operational or strategy journal is missing its original identity ledger; refusing owner reset"
                .into(),
        );
    }
    let identity = if let Some(bytes) = snapshots.get("ledger.jsonl") {
        super::Store::validate_snapshot(bytes)?
    } else {
        let bytes = snapshots
            .get("knowledge.jsonl")
            .ok_or("knowledge ledger missing")?;
        let first = std::str::from_utf8(bytes)
            .map_err(|e| e.to_string())?
            .lines()
            .next()
            .ok_or("knowledge genesis missing")?;
        let value: Value = serde_json::from_str(first).map_err(|e| e.to_string())?;
        value["payload"]["identity"]
            .as_str()
            .ok_or("knowledge identity missing")?
            .to_string()
    };
    if !owner_label(&identity) {
        return Err("invalid persistent migration identity".into());
    }
    if let Some(bytes) = snapshots.get("knowledge.jsonl") {
        super::knowledge::KnowledgeStore::validate_snapshot(bytes, &identity)?;
    }
    if let Some(bytes) = snapshots.get("operations.jsonl") {
        super::operational::validate_snapshot(
            bytes,
            &identity,
            operational_registration
                .as_ref()
                .ok_or("operational registration missing")?,
        )?;
    }
    if let Some(bytes) = snapshots.get(crate::strategy::STRATEGY_FILE) {
        let owner = snapshots
            .get("ledger.jsonl")
            .ok_or("strategy owner identity ledger missing")?;
        let genesis = owner
            .split_inclusive(|byte| *byte == b'\n')
            .next()
            .ok_or("owner genesis missing")?;
        crate::strategy::StrategyLedger::validate_snapshot(
            bytes,
            strategy_registration
                .as_deref()
                .ok_or("strategy registration missing")?,
            &identity,
            &hash(genesis),
        )?;
    }
    Ok((identity, snapshots))
}

fn backup_matches(directory: &Path, layout: &StateLayout) -> Result<(), String> {
    let backup = directory.join(&layout.backup_directory);
    ensure_directory(&backup)?;
    let raw = read_regular(&backup.join("manifest.json"), MAX_METADATA_BYTES)?
        .ok_or("migration backup manifest missing")?;
    let recorded: StateLayout =
        serde_json::from_slice(&raw).map_err(|e| format!("invalid backup manifest: {e}"))?;
    if recorded != *layout {
        return Err("migration backup manifest does not match layout".into());
    }
    for (name, expected) in &layout.snapshot_sha256 {
        let bytes = read_regular(&backup.join(name), super::MAX_LEDGER_BYTES)?
            .ok_or("migration backup ledger missing")?;
        if hash(&bytes) != *expected {
            return Err("migration backup checksum mismatch".into());
        }
    }
    for (name, expected) in &layout.sidecar_sha256 {
        let bytes = read_regular(&backup.join(name), super::MAX_LEDGER_BYTES)?
            .ok_or("migration backup sidecar missing")?;
        if hash(&bytes) != *expected {
            return Err("migration backup sidecar checksum mismatch".into());
        }
    }
    if layout.ledger_formats.contains_key("operations.jsonl") {
        let operations = read_regular(&backup.join("operations.jsonl"), super::MAX_LEDGER_BYTES)?
            .ok_or("operational backup ledger missing")?;
        let registration = read_regular(
            &backup.join(super::operational::OWNER_FILE),
            super::operational::MAX_OWNER_BYTES,
        )?
        .ok_or("operational backup owner registration missing")?;
        super::operational::validate_snapshot(&operations, &layout.identity, &registration)?;
    }
    if layout.layout_version == 2 {
        let (owner, snapshots) = validated_snapshots(&backup)?;
        if owner != layout.identity || snapshots.keys().ne(layout.snapshot_sha256.keys()) {
            return Err("feature migration backup differs from registered owner ledgers".into());
        }
        if let Some(raw) = read_regular(&backup.join(PREVIOUS_LAYOUT), MAX_METADATA_BYTES)? {
            let prior = parse_layout(&raw)?;
            if prior.identity != layout.identity || prior.layout_version != 1 {
                return Err("feature migration backup has a foreign historical layout".into());
            }
            backup_matches(directory, &prior)?;
        }
    }
    Ok(())
}

const MAX_UPGRADE_BYTES: usize = 64 * 1024;
fn parse_upgrade(bytes: &[u8]) -> Result<UpgradePlan, String> {
    let plan: UpgradePlan = serde_json::from_slice(bytes)
        .map_err(|e| format!("HOLD: invalid format-upgrade preparation: {e}"))?;
    let target = parse_layout(&serde_json::to_vec(&plan.target).map_err(|e| e.to_string())?)?;
    if plan.schema != "symbiote.format-upgrade/1"
        || plan.sha256 != plan.hash()?
        || plan.identity != target.identity
        || target.layout_version != 2
        || plan.source_sha256.is_empty()
        || plan.source_sha256.len() > 6
        || plan.source_sha256.iter().any(|(name, pin)| {
            !(LEDGERS.contains(&name.as_str())
                || [
                    crate::operational::OWNER_FILE,
                    crate::strategy::STRATEGY_OWNER_FILE,
                ]
                .contains(&name.as_str()))
                || !hex_digest(pin)
        })
        || target
            .snapshot_sha256
            .iter()
            .any(|(name, pin)| plan.source_sha256.get(name) != Some(pin))
        || plan
            .source_sha256
            .keys()
            .filter(|name| LEDGERS.contains(&name.as_str()))
            .ne(target.snapshot_sha256.keys())
        || plan
            .source_sha256
            .iter()
            .filter(|(name, _)| !LEDGERS.contains(&name.as_str()))
            .any(|(name, pin)| target.sidecar_sha256.get(name) != Some(pin))
    {
        return Err("HOLD: altered or unsupported format-upgrade preparation".into());
    }
    match &plan.previous_layout_json {
        Some(raw) => {
            let prior = parse_layout(raw.as_bytes())?;
            if raw.len() > MAX_METADATA_BYTES
                || prior.layout_version != 1
                || prior.identity != plan.identity
                || target.sidecar_sha256.get(PREVIOUS_LAYOUT) != Some(&hash(raw.as_bytes()))
            {
                return Err("HOLD: format-upgrade historical layout differs".into());
            }
        }
        None if target.sidecar_sha256.contains_key(PREVIOUS_LAYOUT) => {
            return Err("HOLD: upgrade lost its historical layout bytes".into())
        }
        None => {}
    }
    let mut expected_sidecars: BTreeMap<_, _> = plan
        .source_sha256
        .iter()
        .filter(|(name, _)| !LEDGERS.contains(&name.as_str()))
        .map(|(name, pin)| (name.clone(), pin.clone()))
        .collect();
    if let Some(raw) = &plan.previous_layout_json {
        expected_sidecars.insert(PREVIOUS_LAYOUT.into(), hash(raw.as_bytes()));
    }
    if target.sidecar_sha256 != expected_sidecars {
        return Err("HOLD: format-upgrade sidecars differ from exact prepared source files".into());
    }
    if !plan
        .source_sha256
        .contains_key(crate::strategy::STRATEGY_OWNER_FILE)
        || !plan.source_sha256.contains_key("ledger.jsonl")
    {
        return Err("HOLD: upgrade lacks its exact original owner/strategy pair".into());
    }
    Ok(plan)
}
fn reject_pending_upgrade(directory: &Path) -> Result<(), String> {
    if let Some(bytes) = read_regular(&directory.join(FORMAT_UPGRADE), MAX_UPGRADE_BYTES)? {
        parse_upgrade(&bytes)?;
        return Err("HOLD: interrupted format upgrade; only explicit migrate may validate and resume its exact planned bytes".into());
    }
    Ok(())
}
fn feature_sources(
    directory: &Path,
    snapshots: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut result = snapshots.clone();
    for name in [
        crate::operational::OWNER_FILE,
        crate::strategy::STRATEGY_OWNER_FILE,
    ] {
        if let Some(bytes) = read_regular(&directory.join(name), MAX_METADATA_BYTES)? {
            result.insert(name.into(), bytes);
        }
    }
    Ok(result)
}
fn resume_feature_upgrade(directory: &Path, plan_bytes: &[u8]) -> Result<MigrationReport, String> {
    let plan = parse_upgrade(plan_bytes)?;
    let (identity, snapshots) = validated_snapshots(directory)?;
    let sources = feature_sources(directory, &snapshots)?;
    let source_hashes: BTreeMap<_, _> = sources
        .iter()
        .map(|(name, bytes)| (name.clone(), hash(bytes)))
        .collect();
    if identity != plan.identity || source_hashes != plan.source_sha256 {
        return Err("HOLD: source bytes changed after format-upgrade preparation; no upgrade writes allowed".into());
    }
    let target_bytes = serde_json::to_vec_pretty(&plan.target).map_err(|e| e.to_string())?;
    let current = read_regular(&directory.join(LAYOUT), MAX_METADATA_BYTES)?;
    if current.as_deref() != Some(target_bytes.as_slice())
        && current.as_deref() != plan.previous_layout_json.as_ref().map(|s| s.as_bytes())
    {
        return Err(
            "HOLD: owner layout differs from both exact prepared and planned layout bytes".into(),
        );
    }
    if let Some(raw) = &plan.previous_layout_json {
        backup_matches(directory, &parse_layout(raw.as_bytes())?)?;
    }
    let mut files = sources;
    if let Some(raw) = &plan.previous_layout_json {
        files.insert(PREVIOUS_LAYOUT.into(), raw.as_bytes().to_vec());
    }
    files.insert("manifest.json".into(), target_bytes.clone());
    let backup = directory.join(FEATURE_BACKUP);
    if backup.exists() {
        ensure_directory(&backup)?;
        for entry in fs::read_dir(&backup).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry
                .file_name()
                .to_str()
                .ok_or("upgrade backup entry is not UTF8")?
                .to_string();
            let expected = files
                .get(&name)
                .ok_or("HOLD: unexpected feature-upgrade backup material")?;
            if read_regular(&entry.path(), super::MAX_LEDGER_BYTES)?.as_deref()
                != Some(expected.as_slice())
            {
                return Err(
                    "HOLD: interrupted feature-upgrade backup differs from exact planned bytes"
                        .into(),
                );
            }
        }
    }
    let already_completed = audit_rows(directory)?.iter().any(|row| {
        row.event["operation_id"].as_str() == Some(&plan.sha256)
            && row.event["phase"].as_str() == Some("completed")
    });
    if !already_completed {
        append_audit(
            directory,
            json!({"operation":"format_upgrade","phase":"prepared","operation_id":plan.sha256,"identity":identity,"layout_version":2,"ledger_bytes_changed":false}),
        )?;
    }
    if !backup.exists() {
        fs::create_dir(&backup).map_err(|e| e.to_string())?;
    }
    for (name, bytes) in &files {
        let path = backup.join(name);
        if read_regular(&path, super::MAX_LEDGER_BYTES)?.is_none() {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|e| e.to_string())?;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|e| e.to_string())?;
        }
    }
    backup_matches(directory, &plan.target)?;
    if current.as_deref() != Some(target_bytes.as_slice()) {
        atomic_replace(directory, LAYOUT, &target_bytes)?;
    }
    if !already_completed {
        append_audit(
            directory,
            json!({"operation":"format_upgrade","phase":"completed","operation_id":plan.sha256,"identity":identity,"layout_version":2,"layout_sha256":hash(&target_bytes),"ledger_bytes_changed":false}),
        )?;
    }
    if read_regular(&directory.join(FORMAT_UPGRADE), MAX_UPGRADE_BYTES)?.as_deref()
        != Some(plan_bytes)
    {
        return Err(
            "HOLD: format-upgrade preparation changed before completion; preserve evidence".into(),
        );
    }
    fs::remove_file(directory.join(FORMAT_UPGRADE)).map_err(|e| {
        format!("upgrade complete but preparation marker could not be cleared: {e}")
    })?;
    Ok(MigrationReport {
        schema: "symbiote.migration/1",
        status: "PASS",
        changed: true,
        layout_version: 2,
        identity,
        backup_directory: FEATURE_BACKUP.into(),
        registered_ledger_sha256: plan.target.snapshot_sha256,
        ledger_bytes_changed: false,
    })
}

/// Registers the existing v1 ledger encodings with explicit layout/policy metadata.
/// Both original byte streams remain unchanged and immutable backup copies are
/// checked. This is an additive state-layout migration, not an invented new encoding.
pub fn migrate(directory: &Path) -> Result<MigrationReport, String> {
    migrate_with_preparation_hook(directory, || Ok(()))
}

fn migrate_with_preparation_hook(
    directory: &Path,
    after_preparation: impl FnOnce() -> Result<(), String>,
) -> Result<MigrationReport, String> {
    let _gate = gate(directory)?;
    let existing = read_layout(directory)?;
    audit_rows(directory)?;
    quiescent_locks(directory, false)?;
    if let Some(plan) = read_regular(&directory.join(FORMAT_UPGRADE), MAX_UPGRADE_BYTES)? {
        return resume_feature_upgrade(directory, &plan);
    }
    let (identity, snapshots) = validated_snapshots(directory)?;
    if snapshots.contains_key(crate::strategy::STRATEGY_FILE)
        && existing
            .as_ref()
            .is_none_or(|layout| layout.layout_version != 2)
    {
        if let Some(layout) = &existing {
            backup_matches(directory, layout)?;
        }
        let sources = feature_sources(directory, &snapshots)?;
        let previous_layout_json = read_regular(&directory.join(LAYOUT), MAX_METADATA_BYTES)?
            .map(String::from_utf8)
            .transpose()
            .map_err(|e| e.to_string())?;
        let mut sidecars: BTreeMap<_, _> = sources
            .iter()
            .filter(|(name, _)| !LEDGERS.contains(&name.as_str()))
            .map(|(name, bytes)| (name.clone(), hash(bytes)))
            .collect();
        if let Some(raw) = &previous_layout_json {
            sidecars.insert(PREVIOUS_LAYOUT.into(), hash(raw.as_bytes()));
        }
        let target = StateLayout {
            schema: "symbiote.state-layout/2".into(),
            layout_version: 2,
            identity: identity.clone(),
            ledger_formats: snapshots.keys().map(|name| (name.clone(), 1)).collect(),
            promotion_policy: 2,
            backup_directory: FEATURE_BACKUP.into(),
            snapshot_sha256: snapshots
                .iter()
                .map(|(name, bytes)| (name.clone(), hash(bytes)))
                .collect(),
            sidecar_sha256: sidecars,
        };
        let mut plan = UpgradePlan {
            schema: "symbiote.format-upgrade/1".into(),
            identity,
            target,
            previous_layout_json,
            source_sha256: sources
                .iter()
                .map(|(name, bytes)| (name.clone(), hash(bytes)))
                .collect(),
            sha256: String::new(),
        };
        plan.sha256 = plan.hash()?;
        let bytes = serde_json::to_vec_pretty(&plan).map_err(|e| e.to_string())?;
        parse_upgrade(&bytes)?;
        atomic_replace(directory, FORMAT_UPGRADE, &bytes)?;
        after_preparation()?;
        return resume_feature_upgrade(directory, &bytes);
    }
    if let Some(layout) = existing {
        if layout.identity != identity {
            return Err("state-layout identity mismatch".into());
        }
        backup_matches(directory, &layout)?;
        append_audit(
            directory,
            json!({"operation":"migrate","phase":"already_current","identity":identity,"layout_version":layout.layout_version,"ledger_bytes_changed":false}),
        )?;
        return Ok(MigrationReport {
            schema: "symbiote.migration/1",
            status: "PASS",
            changed: false,
            layout_version: layout.layout_version,
            identity,
            backup_directory: layout.backup_directory,
            registered_ledger_sha256: layout.snapshot_sha256,
            ledger_bytes_changed: false,
        });
    }
    let hashes: BTreeMap<_, _> = snapshots
        .iter()
        .map(|(name, bytes)| (name.clone(), hash(bytes)))
        .collect();
    let layout = StateLayout {
        schema: "symbiote.state-layout/1".into(),
        layout_version: 1,
        identity: identity.clone(),
        ledger_formats: snapshots.keys().map(|name| (name.clone(), 1)).collect(),
        promotion_policy: 2,
        backup_directory: BACKUP.into(),
        snapshot_sha256: hashes.clone(),
        sidecar_sha256: BTreeMap::new(),
    };
    let operation = hash(&lock_bytes()?);
    append_audit(
        directory,
        json!({"operation":"migrate","phase":"prepared","operation_id":operation,"identity":identity,"ledger_sha256":hashes,"ledger_bytes_changed":false}),
    )?;
    let backup = directory.join(BACKUP);
    if !backup.exists() {
        fs::create_dir(&backup).map_err(|e| e.to_string())?;
    }
    ensure_directory(&backup)?;
    for entry in fs::read_dir(&backup).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or("unexpected backup entry")?
            .to_string();
        if !LEDGERS.contains(&name.as_str())
            && name != "manifest.json"
            && name != super::operational::OWNER_FILE
        {
            return Err("unexpected migration backup material; preserve it and investigate".into());
        }
    }
    let mut backup_files = snapshots.clone();
    if snapshots.contains_key("operations.jsonl") {
        let registration = read_regular(
            &directory.join(super::operational::OWNER_FILE),
            super::operational::MAX_OWNER_BYTES,
        )?
        .ok_or("operational owner registration missing during migration")?;
        backup_files.insert(super::operational::OWNER_FILE.into(), registration);
    }
    for (name, bytes) in &backup_files {
        let path = backup.join(name);
        if let Some(existing) = read_regular(&path, super::MAX_LEDGER_BYTES)? {
            if existing != *bytes {
                return Err(
                    "partial migration backup differs from current ledger; do not overwrite it"
                        .into(),
                );
            }
        } else {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|e| e.to_string())?;
            file.write_all(bytes).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
        }
    }
    let layout_bytes = serde_json::to_vec_pretty(&layout).map_err(|e| e.to_string())?;
    let manifest = backup.join("manifest.json");
    if let Some(bytes) = read_regular(&manifest, MAX_METADATA_BYTES)? {
        let recorded: StateLayout = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if recorded != layout {
            return Err("partial migration has a different backup manifest".into());
        }
    } else {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&manifest)
            .map_err(|e| e.to_string())?;
        file.write_all(&layout_bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
    }
    backup_matches(directory, &layout)?;
    atomic_replace(directory, LAYOUT, &layout_bytes)?;
    append_audit(
        directory,
        json!({"operation":"migrate","phase":"completed","operation_id":operation,"identity":identity,"layout_sha256":hash(&layout_bytes),"ledger_bytes_changed":false}),
    )?;
    Ok(MigrationReport {
        schema: "symbiote.migration/1",
        status: "PASS",
        changed: true,
        layout_version: 1,
        identity,
        backup_directory: BACKUP.into(),
        registered_ledger_sha256: hashes,
        ledger_bytes_changed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let root = std::env::temp_dir().canonicalize().unwrap();
            let path = root.join(format!(
                "symbiote-maintenance-{}-{}",
                std::process::id(),
                super::super::TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            if let (Ok(path), Ok(root)) =
                (self.0.canonicalize(), std::env::temp_dir().canonicalize())
            {
                if path.parent() == Some(root.as_path())
                    && path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .is_some_and(|s| s.starts_with("symbiote-maintenance-"))
                {
                    let _ = fs::remove_dir_all(path);
                }
            }
        }
    }
    #[test]
    fn genesis_initialization_and_structural_owner_checks_are_one_guarded_operation() {
        use std::sync::{Arc, Barrier};
        let dir = Directory::new();
        let reached_boundary = Arc::new(Barrier::new(2));
        let release_genesis = Arc::new(Barrier::new(2));
        let path = dir.0.clone();
        let reached = Arc::clone(&reached_boundary);
        let release = Arc::clone(&release_genesis);
        let original = std::thread::spawn(move || {
            super::super::Store::open_with_initialization_hook(&path, || {
                reached.wait();
                release.wait();
            })
        });
        reached_boundary.wait();
        let competing = super::super::knowledge::KnowledgeStore::open(&dir.0, "different-owner");
        release_genesis.wait();
        let original = original.join().unwrap().unwrap();
        assert!(
            competing.is_err(),
            "a competing first structural writer must not commit another owner while Genesis is initializing"
        );
        assert!(!dir.0.join("knowledge.jsonl").exists());
        assert!(super::super::knowledge::KnowledgeStore::open(&dir.0, "different-owner").is_err());
        assert_eq!(
            super::super::knowledge::KnowledgeStore::open(&dir.0, original.identity())
                .unwrap()
                .identity(),
            original.identity()
        );
    }
    #[test]
    fn normal_writers_and_maintenance_share_the_same_creation_gate() {
        let dir = Directory::new();
        let owner = super::super::Store::open(&dir.0)
            .unwrap()
            .identity()
            .to_string();
        let _gate = gate(&dir.0).unwrap();
        assert!(super::super::Store::open(&dir.0).is_err());
        assert!(super::super::knowledge::KnowledgeStore::open(&dir.0, &owner).is_err());
        assert!(recover(&dir.0).is_err());
        assert!(migrate(&dir.0).is_err());
        assert!(!dir.0.join("writer.lock").exists());
        assert!(!dir.0.join("knowledge.writer.lock").exists());
    }
    #[test]
    fn matching_partial_backup_resumes_without_rewriting_evidence() {
        let dir = Directory::new();
        let store = super::super::Store::open(&dir.0).unwrap();
        drop(store);
        let original = fs::read(dir.0.join("ledger.jsonl")).unwrap();
        fs::create_dir(dir.0.join(BACKUP)).unwrap();
        fs::write(dir.0.join(BACKUP).join("ledger.jsonl"), &original).unwrap();
        assert!(migrate(&dir.0).unwrap().changed);
        assert_eq!(fs::read(dir.0.join("ledger.jsonl")).unwrap(), original);
        assert_eq!(
            fs::read(dir.0.join(BACKUP).join("ledger.jsonl")).unwrap(),
            original
        );
        assert!(!migrate(&dir.0).unwrap().changed);
        assert_eq!(audit_rows(&dir.0).unwrap().len(), 3);
    }
    #[test]
    fn incompatible_partial_backup_or_corrupt_audit_stops_migration() {
        let dir = Directory::new();
        drop(super::super::Store::open(&dir.0).unwrap());
        let original = fs::read(dir.0.join("ledger.jsonl")).unwrap();
        fs::create_dir(dir.0.join(BACKUP)).unwrap();
        fs::write(
            dir.0.join(BACKUP).join("ledger.jsonl"),
            b"different original evidence",
        )
        .unwrap();
        assert!(migrate(&dir.0).is_err());
        assert!(!dir.0.join(LAYOUT).exists());
        assert_eq!(fs::read(dir.0.join("ledger.jsonl")).unwrap(), original);
        fs::write(dir.0.join(AUDIT), b"truncated maintenance audit").unwrap();
        assert!(recover(&dir.0).unwrap_err().contains("audit"));
        assert!(migrate(&dir.0).unwrap_err().contains("audit"));
        assert_eq!(fs::read(dir.0.join("ledger.jsonl")).unwrap(), original);
    }
    #[test]
    fn ownership_parsing_rejects_process_group_and_partial_records_before_os_calls() {
        for bytes in [
            "process=0\n",
            "process=2147483648\n",
            "process=4294967295\n",
            "process=-1\n",
            "process= 1\n",
            "process=1\n\n",
            "process=12",
            "process=1\nnonce=x\n",
        ] {
            assert!(parse_pid(bytes.as_bytes()).is_err(), "{bytes:?}");
        }
        assert_eq!(parse_pid(b"process=1\n").unwrap(), 1);
        assert_eq!(parse_pid(b"process=2147483647\n").unwrap(), 2_147_483_647);
    }

    #[test]
    fn interrupted_feature_registration_blocks_writers_and_resumes_exact_bytes() {
        use crate::strategy::{StrategyLedger, STRATEGY_FILE, STRATEGY_OWNER_FILE};
        use std::sync::Arc;
        let dir = Directory::new();
        let owner = crate::Store::open(&dir.0).unwrap().identity().to_string();
        migrate(&dir.0).unwrap();
        let legacy_layout = fs::read(dir.0.join(LAYOUT)).unwrap();
        let legacy_backup = fs::read(dir.0.join(BACKUP).join("manifest.json")).unwrap();
        drop(StrategyLedger::open(Arc::new(crate::Store::open(&dir.0).unwrap())).unwrap());
        let identity_bytes = fs::read(dir.0.join("ledger.jsonl")).unwrap();
        let strategy_bytes = fs::read(dir.0.join(STRATEGY_FILE)).unwrap();
        let owner_marker = fs::read(dir.0.join(STRATEGY_OWNER_FILE)).unwrap();
        let audit_before = fs::read(dir.0.join(AUDIT)).unwrap();
        assert!(migrate_with_preparation_hook(&dir.0, || Err(
            "injected stop after durable preparation".into()
        ))
        .is_err());
        let prepared = fs::read(dir.0.join(FORMAT_UPGRADE)).unwrap();
        assert!(!dir.0.join(FEATURE_BACKUP).exists());
        assert!(crate::Store::open(&dir.0).is_err());
        assert!(crate::knowledge::KnowledgeStore::open(&dir.0, &owner).is_err());
        assert!(inspect(&dir.0).is_err());
        assert!(recover(&dir.0).is_err());
        assert_eq!(fs::read(dir.0.join(AUDIT)).unwrap(), audit_before);
        assert_eq!(fs::read(dir.0.join(LAYOUT)).unwrap(), legacy_layout);
        let mut altered: Value = serde_json::from_slice(&prepared).unwrap();
        altered["sha256"] = json!("0".repeat(64));
        let altered = serde_json::to_vec(&altered).unwrap();
        fs::write(dir.0.join(FORMAT_UPGRADE), &altered).unwrap();
        assert!(migrate(&dir.0).is_err());
        assert_eq!(fs::read(dir.0.join(FORMAT_UPGRADE)).unwrap(), altered);
        assert_eq!(fs::read(dir.0.join(AUDIT)).unwrap(), audit_before);
        assert_eq!(fs::read(dir.0.join(LAYOUT)).unwrap(), legacy_layout);
        fs::write(dir.0.join(FORMAT_UPGRADE), &prepared).unwrap();
        let mut altered_owner = owner_marker.clone();
        altered_owner.push(b'\n');
        fs::write(dir.0.join(STRATEGY_OWNER_FILE), &altered_owner).unwrap();
        assert!(migrate(&dir.0).is_err());
        assert_eq!(fs::read(dir.0.join(AUDIT)).unwrap(), audit_before);
        assert_eq!(fs::read(dir.0.join(LAYOUT)).unwrap(), legacy_layout);
        fs::write(dir.0.join(STRATEGY_OWNER_FILE), &owner_marker).unwrap();
        // A crash during immutable backup copying resumes only matching bytes.
        fs::create_dir(dir.0.join(FEATURE_BACKUP)).unwrap();
        fs::write(
            dir.0.join(FEATURE_BACKUP).join("ledger.jsonl"),
            b"different partial backup",
        )
        .unwrap();
        assert!(migrate(&dir.0).is_err());
        assert_eq!(fs::read(dir.0.join(AUDIT)).unwrap(), audit_before);
        assert_eq!(fs::read(dir.0.join(LAYOUT)).unwrap(), legacy_layout);
        fs::write(
            dir.0.join(FEATURE_BACKUP).join("ledger.jsonl"),
            &identity_bytes,
        )
        .unwrap();
        let report = migrate(&dir.0).unwrap();
        assert_eq!(report.layout_version, 2);
        assert!(report.changed);
        assert!(!dir.0.join(FORMAT_UPGRADE).exists());
        assert_eq!(
            fs::read(dir.0.join("ledger.jsonl")).unwrap(),
            identity_bytes
        );
        assert_eq!(fs::read(dir.0.join(STRATEGY_FILE)).unwrap(), strategy_bytes);
        assert_eq!(
            fs::read(dir.0.join(STRATEGY_OWNER_FILE)).unwrap(),
            owner_marker
        );
        assert_eq!(
            fs::read(dir.0.join(BACKUP).join("manifest.json")).unwrap(),
            legacy_backup
        );
        assert_eq!(
            fs::read(dir.0.join(FEATURE_BACKUP).join(PREVIOUS_LAYOUT)).unwrap(),
            legacy_layout
        );
        assert_eq!(crate::Store::open(&dir.0).unwrap().identity(), owner);
        // Also exercise the cutpoint after layout + completion audit, before
        // removal of the preparation marker. Resume adds no duplicate history.
        let completed_audit = fs::read(dir.0.join(AUDIT)).unwrap();
        let completed_layout = fs::read(dir.0.join(LAYOUT)).unwrap();
        fs::write(dir.0.join(FORMAT_UPGRADE), &prepared).unwrap();
        assert!(crate::Store::open(&dir.0).is_err());
        assert!(migrate(&dir.0).unwrap().changed);
        assert_eq!(fs::read(dir.0.join(AUDIT)).unwrap(), completed_audit);
        assert_eq!(fs::read(dir.0.join(LAYOUT)).unwrap(), completed_layout);
        assert!(!migrate(&dir.0).unwrap().changed);
    }
}
