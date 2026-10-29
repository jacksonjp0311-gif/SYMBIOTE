//! Explicit stopped-owner lock recovery. No PID or success assertion supplied by
//! the caller can replace the maintenance layer's actual OS liveness checks.
use super::*;
use symbiote_memory::maintenance::{self, LockState};

#[derive(Clone, Debug, Serialize)]
pub struct RecoveryReceipt {
    pub schema: &'static str,
    pub owner: String,
    pub recovered_locks: Vec<String>,
    pub ledgers_modified: bool,
    pub processes_terminated: usize,
    pub interrupted_episode_resolution: &'static str,
}
impl Engine {
    /// Recover only locks whose recorded process is proven dead by the OS.
    /// This does not complete an interrupted episode, adopt pending knowledge,
    /// initialize missing state, kill processes, or discard unknown history.
    pub fn recover_stopped_owner(path: &Path, expected_owner: &str) -> Result<RecoveryReceipt> {
        if !path.is_absolute()
            || !path.is_dir()
            || path
                .symlink_metadata()
                .map_err(|e| EngineError::new(ErrorKind::Storage, "recover", e.to_string()))?
                .file_type()
                .is_symlink()
        {
            return Err(EngineError::new(
                ErrorKind::Malformed,
                "recover",
                "existing absolute owner directory required",
            ));
        }
        let inspected = maintenance::inspect(path)
            .map_err(|e| EngineError::new(ErrorKind::Storage, "recover", e))?;
        if inspected.identity.as_deref() != Some(expected_owner) {
            return Err(EngineError::new(
                ErrorKind::Authorization,
                "recover",
                "owner identity differs from the caller's expected owner",
            ));
        }
        if inspected.locks.iter().any(|l| l.state == LockState::Live) {
            return Err(EngineError::new(
                ErrorKind::OwnerBusy,
                "recover",
                "a recorded owner writer is still live",
            ));
        }
        if inspected
            .locks
            .iter()
            .any(|l| l.state == LockState::Unknown)
        {
            return Err(EngineError::new(
                ErrorKind::Hold,
                "recover",
                "writer liveness is unknown; no lock was removed",
            ));
        }
        let recovered = maintenance::recover(path)
            .map_err(|e| EngineError::new(ErrorKind::Storage, "recover", e))?;
        if recovered.ledgers_modified || recovered.processes_terminated != 0 {
            return Err(EngineError::new(
                ErrorKind::Hold,
                "recover",
                "maintenance exceeded the stopped-lock recovery contract",
            ));
        }
        Ok(RecoveryReceipt{schema:"symbiote.engine-stopped-owner-recovery/1",owner:expected_owner.into(),recovered_locks:recovered.recovered_locks,
            ledgers_modified:false,processes_terminated:0,interrupted_episode_resolution:"not inferred; reopen validates exact committed history and may require explicit recovery/restore review"})
    }
}
