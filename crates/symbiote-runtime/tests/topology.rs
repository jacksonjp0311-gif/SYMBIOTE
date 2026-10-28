//! Native topology engineering fixture; interacting nodes are not independent samples.
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

/// Keep the original 30-second fixture envelope, including validation and cleanup.
/// Wall time additionally rejects host suspension or a backwards clock; elapsed
/// monotonic time alone is not a promise about every platform's sleep clock.
struct FixtureBudget {
    started: Instant,
    wall_started: SystemTime,
    wall_previous: SystemTime,
    limit: Duration,
}
impl FixtureBudget {
    fn new() -> Self {
        let wall_started = SystemTime::now();
        Self {
            started: Instant::now(),
            wall_started,
            wall_previous: wall_started,
            limit: Duration::from_secs(30),
        }
    }
    fn check(&mut self) -> Result<(), String> {
        self.check_at(Instant::now(), SystemTime::now())
    }
    fn check_at(&mut self, now: Instant, wall_now: SystemTime) -> Result<(), String> {
        let elapsed = now
            .checked_duration_since(self.started)
            .ok_or("topology fixture monotonic clock moved backwards")?;
        if wall_now < self.wall_previous {
            return Err("topology fixture wall clock moved backwards".into());
        }
        let wall_elapsed = wall_now
            .duration_since(self.wall_started)
            .map_err(|_| "topology fixture wall clock precedes its start")?;
        if elapsed >= self.limit || wall_elapsed >= self.limit {
            return Err(format!(
                "topology fixture exceeded its 30-second envelope: monotonic={elapsed:?}, wall={wall_elapsed:?}"
            ));
        }
        self.wall_previous = wall_now;
        Ok(())
    }
}

fn stop_owned(child: &mut Child) -> Result<(), String> {
    if child
        .try_wait()
        .map_err(|error| error.to_string())?
        .is_some()
    {
        return Ok(());
    }
    child.kill().map_err(|error| error.to_string())?;
    let started = Instant::now();
    let wall_started = SystemTime::now();
    loop {
        if child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Ok(());
        }
        if started.elapsed() >= Duration::from_secs(5)
            || wall_started
                .elapsed()
                .map_or(true, |elapsed| elapsed >= Duration::from_secs(5))
        {
            return Err("topology owned-child cleanup did not finish within five seconds".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn wait_owned(child: &mut Child, budget: &mut FixtureBudget) -> Result<ExitStatus, String> {
    let result = (|| loop {
        // Check before accepting an exit. After host suspension the child may
        // already have exited; checking only a still-running child misses that gap.
        budget.check()?;
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            budget.check()?;
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(10));
    })();
    if result.is_err() {
        stop_owned(child).map_err(|error| format!("{result:?}; cleanup failed: {error}"))?;
    }
    result
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "symbiote-native-topology-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn three_owned_tls_agents_forward_validate_retain_and_revoke_with_negative_costs() {
    let mut budget = FixtureBudget::new();
    let directory = Directory::new();
    let state = directory.0.join("state");
    let receipts = directory.0.join("receipts");
    let stdout = fs::File::create(directory.0.join("stdout.json")).unwrap();
    let stderr = fs::File::create(directory.0.join("stderr.txt")).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .arg("topology-research")
        .args([
            "--state",
            state.to_str().unwrap(),
            "--receipts",
            receipts.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .unwrap();
    let status = wait_owned(&mut child, &mut budget).unwrap();
    assert!(
        status.success(),
        "{}",
        fs::read_to_string(directory.0.join("stderr.txt")).unwrap()
    );
    let mut bytes = Vec::new();
    fs::File::open(receipts.join("summary.json"))
        .unwrap()
        .take(262_145)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 262_144);
    let report: Value = serde_json::from_slice(&bytes).unwrap();
    budget.check().unwrap();
    assert_eq!(report["status"], "ENGINEERING_PASS");
    assert_eq!(report["successful_inert_hops"], 6);
    assert_eq!(report["identities"].as_array().unwrap().len(), 3);
    let initial = report["initial_pids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect::<BTreeSet<_>>();
    let restarted = report["restarted_pids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(initial.len(), 3);
    assert_eq!(restarted.len(), 3);
    assert!(initial.is_disjoint(&restarted));
    for delivery in report["deliveries"].as_array().unwrap() {
        assert_eq!(delivery["delivered"], true);
        assert_eq!(delivery["acknowledgment"]["quarantined"], true);
        assert_eq!(delivery["acknowledgment"]["promoted"], false);
        assert_eq!(
            delivery["source_identity"],
            delivery["acknowledgment"]["authenticated_source"]
        );
    }
    assert_eq!(report["no_direct_a_c_tls_grant"]["tls_denied"], true);
    assert_eq!(report["tls_revocation_denial"]["tls_denied"], true);
    for proof in [
        &report["no_direct_a_c_tls_grant"],
        &report["tls_revocation_denial"],
    ] {
        assert_eq!(proof["admission_verdict"], "VERIFIED_SERVER_POLICY_DENIAL");
        assert_eq!(proof["source_probe"]["tls_denied"], false);
        assert_eq!(
            proof["source_probe"]["admission_verdict"],
            "HOLD_UNVERIFIED_CONNECT_FAILURE"
        );
        assert_eq!(proof["live_before"]["pid"], proof["live_after"]["pid"]);
        assert_eq!(
            proof["live_before"]["listener_instance"],
            proof["live_after"]["listener_instance"]
        );
        assert_eq!(
            proof["receiver_after"]["session_failures"]
                .as_u64()
                .unwrap(),
            proof["receiver_before"]["session_failures"]
                .as_u64()
                .unwrap()
                + 1
        );
        assert_eq!(
            proof["receiver_before"]["quarantined"],
            proof["receiver_after"]["quarantined"]
        );
        assert!(!proof["source_probe"]["connect_error"]
            .as_str()
            .unwrap()
            .is_empty());
    }
    assert_eq!(report["persisted_revocation_denial"]["delivered"], false);
    assert_eq!(report["reopened_revocation_denial"]["delivered"], false);
    assert_eq!(
        report["charged_failed_delivery"]["snapshot"]["receipts"]
            .as_array()
            .unwrap()
            .len(),
        7
    );
    assert_eq!(
        report["charged_failed_delivery"]["snapshot"]["receipts"][6]["outcome"],
        "delivery-unknown"
    );
    assert_eq!(report["aggregate_exhaustion_denial"]["delivered"], false);
    assert_eq!(
        report["network_snapshot"]["receipts"]
            .as_array()
            .unwrap()
            .len(),
        7
    );
    for (before, after) in report["before_restart"]
        .as_array()
        .unwrap()
        .iter()
        .zip(report["after_restart"].as_array().unwrap())
    {
        assert_eq!(before["identity"], after["identity"]);
        assert_eq!(before["history_anchor"], after["history_anchor"]);
        assert_eq!(before["knowledge_records"], 2);
        assert_eq!(after["knowledge_records"], 2);
        assert_eq!(after["retained_predictions"], serde_json::json!([1, 3]));
        assert_eq!(after["meter"]["source_warmup_oracle_calls"], 0);
        assert_eq!(after["meter"]["validation_oracle_calls"], 0);
        assert_eq!(after["meter"]["evaluation_oracle_calls"], 0);
        assert_eq!(after["meter"]["fresh_promotions"], 0);
        assert!(
            before["meter"]["secure_plaintext_quote_bytes"]
                .as_u64()
                .unwrap()
                <= 4 * 1024 * 1024
        );
    }
    assert!(report["aggregate_cost_saving_work_units"].as_i64().unwrap() < 0);
    assert_eq!(
        report["all_participants_positive_complete_cost_benefit"],
        false
    );
    // Every source's warmup is charged once, independently from receiver verification.
    let warmup: u64 = report["before_restart"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["meter"]["source_warmup_oracle_calls"].as_u64().unwrap())
        .sum();
    let verification: u64 = report["before_restart"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["meter"]["validation_oracle_calls"].as_u64().unwrap())
        .sum();
    assert_eq!(warmup, 4);
    assert_eq!(verification, 8);
    for entry in walk(&state) {
        budget.check().unwrap();
        let text = fs::read_to_string(entry).unwrap();
        assert!(!text.contains("PRIVATE KEY"));
    }
    budget.check().unwrap();
    let digest_before = fs::read(receipts.join("summary.json")).unwrap();
    let mut retry = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .arg("topology-research")
        .args([
            "--state",
            state.to_str().unwrap(),
            "--receipts",
            receipts.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(fs::File::create(directory.0.join("retry.stdout")).unwrap())
        .stderr(fs::File::create(directory.0.join("retry.stderr")).unwrap())
        .spawn()
        .unwrap();
    assert!(!wait_owned(&mut retry, &mut budget).unwrap().success());
    assert_eq!(
        fs::read(receipts.join("summary.json")).unwrap(),
        digest_before
    );
    budget.check().unwrap();
    fs::remove_dir_all(&directory.0).unwrap();
    drop(directory);
    budget.check().unwrap();
}

#[test]
fn host_sleep_and_clock_regressions_cannot_extend_the_fixture_budget() {
    let mut budget = FixtureBudget::new();
    let monotonic = budget.started;
    let wall = budget.wall_started;
    budget
        .check_at(
            monotonic + Duration::from_secs(1),
            wall + Duration::from_secs(1),
        )
        .unwrap();
    assert!(budget
        .check_at(
            monotonic + Duration::from_secs(2),
            wall + Duration::from_secs(31)
        )
        .is_err());
    assert!(budget
        .check_at(monotonic + Duration::from_secs(2), wall)
        .is_err());
    assert!(budget
        .check_at(
            monotonic + Duration::from_secs(31),
            wall + Duration::from_secs(2)
        )
        .is_err());
}

#[test]
fn an_already_exited_child_cannot_bypass_an_expired_fixture_budget() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut budget = FixtureBudget::new();
    assert!(wait_owned(&mut child, &mut budget).unwrap().success());
    budget.wall_started -= Duration::from_secs(31);
    assert!(wait_owned(&mut child, &mut budget).is_err());
}
fn walk(path: &std::path::Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            files.extend(walk(&entry.path()));
        } else {
            files.push(entry.path());
        }
    }
    files
}
