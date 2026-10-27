//! Prospective frontier exchange. Primary generation requires an immutable
//! operator registration; development uses only hardcoded released fixtures.
mod actor;
mod admission;
mod authority;
mod cohort;
mod controller;
mod evidence;
mod meter;
mod model;
mod policy;
mod process;
mod profile_audit;
mod registration;
mod replay_setup;
mod summary;
mod wire;

#[cfg(debug_assertions)]
use serde::Deserialize;
use serde_json::Value;
#[cfg(debug_assertions)]
use std::io::{BufRead, Read};
use std::path::Path;
#[cfg(debug_assertions)]
use std::path::PathBuf;

pub(crate) fn run_primary(
    state: &Path,
    receipts: &Path,
    registration: &Path,
) -> Result<Value, String> {
    controller::prospective(registration::primary(state, receipts, registration)?)
}
pub(crate) fn run_reproduction(
    state: &Path,
    receipts: &Path,
    setup: Option<(&Path, &str)>,
) -> Result<Value, String> {
    controller::prospective(registration::reproduction(state, receipts, setup)?)
}
pub(crate) fn serve_from_stdin() -> Result<(), String> {
    process::run_child(|bootstrap, owner| match &bootstrap.role {
        wire::Role::Authority { .. } => authority::create(bootstrap, owner),
        wire::Role::Learner { .. } => actor::create(bootstrap, owner),
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(debug_assertions)]
struct DevelopmentPaths {
    state: PathBuf,
    receipts: PathBuf,
    #[serde(default)]
    setup_catalogue: Option<PathBuf>,
    #[serde(default)]
    setup_sha256: Option<String>,
}
#[cfg(debug_assertions)]
pub(crate) fn development_from_stdin() -> Result<(), String> {
    if !cfg!(debug_assertions) {
        return Err("manual development probe is unavailable in release binaries".into());
    }
    let (input_ready, deadline) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if matches!(
            deadline.recv_timeout(std::time::Duration::from_secs(5)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            std::process::exit(74);
        }
    });
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(2049)
        .read_until(b'\n', &mut input)
        .map_err(|_| "manual development path input failed")?;
    if input.len() > 2048 || input.last() != Some(&b'\n') {
        return Err("manual development path input exceeded its bound".into());
    }
    let paths: DevelopmentPaths = serde_json::from_slice(&input)
        .map_err(|_| "manual development accepts only bounded state/receipt paths")?;
    let _ = input_ready.send(());
    let setup = match (&paths.setup_catalogue, &paths.setup_sha256) {
        (Some(path), Some(hash)) => Some((path.as_path(), hash.as_str())),
        (None, None) => None,
        _ => return Err("manual setup requires both catalogue and SHA256".into()),
    };
    let report = controller::development(&paths.state, &paths.receipts, setup)?;
    println!(
        "{}",
        serde_json::to_string(&report).map_err(|_| "development receipt serialization failed")?
    );
    Ok(())
}
