//! Owned native-process lifecycle only. No data selects an executable or command.
//! Configuration is secret stdin data; readiness and diagnostics contain no PEM.
use super::wire::{Bootstrap, PublicEndpoint, SCOPE};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use symbiote_memory::Store;
use symbiote_protocol::{fresh_capability, SecureServerHandle};
#[path = "metrics.rs"]
mod metrics;

const CONFIG_LIMIT: usize = 256 * 1024;
const READY_LIMIT: usize = 2048;
const LOG_LIMIT: usize = 4096;
const STOP_SUMMARY_LIMIT: usize = 2048;
const STARTUP: Duration = Duration::from_secs(5);
const STOP: Duration = Duration::from_secs(3);
const CAMPAIGN: Duration = Duration::from_secs(1800);

pub(super) fn parent_resources() -> Value {
    metrics::current("controller-receipt")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ready {
    pub(super) schema: String,
    pub(super) identity: String,
    pub(super) pid: u32,
    pub(super) instance_nonce: String,
    pub(super) address: SocketAddr,
    pub(super) certificate_sha256: String,
}
impl Ready {
    pub(super) fn endpoint(&self) -> PublicEndpoint {
        PublicEndpoint {
            identity: self.identity.clone(),
            address: self.address,
            pin: self.certificate_sha256.clone(),
            scope: SCOPE.into(),
        }
    }
    fn validate(&self, bootstrap: &Bootstrap, pid: u32) -> Result<(), String> {
        if self.schema != "symbiote.adaptive-ready/1"
            || self.identity != bootstrap.expected_identity
            || self.pid != pid
            || self.identity == bootstrap.controller_identity
            || self.certificate_sha256 != bootstrap.material.pin
            || !self.address.ip().is_loopback()
            || self.address.port() == 0
            || self.instance_nonce.len() != 64
            || !self
                .instance_nonce
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("owned adaptive child readiness identity, PID or leaf pin rejected".into());
        }
        Ok(())
    }
}
pub(super) struct Running {
    pub(super) server: SecureServerHandle,
    /// Actor sets a deadline at begin and clears it only after finish. The
    /// supervisor never sends future worlds or outcome labels to control it.
    pub(super) world_deadline: Arc<Mutex<Option<Instant>>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StopSummary {
    schema: String,
    identity: String,
    pid: u32,
    instance_nonce: String,
    application_requests: u64,
    connections: u64,
    session_failures: u64,
}
fn parse_stop_summary(bytes: &[u8], ready: &Ready) -> Result<Value, String> {
    if bytes.len() > STOP_SUMMARY_LIMIT
        || bytes.last() != Some(&b'\n')
        || bytes[..bytes.len().saturating_sub(1)].contains(&b'\n')
    {
        return Err("owned adaptive stop summary must be one bounded complete JSONL frame".into());
    }
    let summary: StopSummary = serde_json::from_slice(bytes)
        .map_err(|_| "owned adaptive stop summary rejected; contents withheld")?;
    if summary.schema != "symbiote.adaptive-stop/1"
        || summary.identity != ready.identity
        || summary.pid != ready.pid
        || summary.instance_nonce != ready.instance_nonce
        || summary.application_requests > 10_000
        || summary.connections > 10_000
        || summary.session_failures > summary.connections
        || (summary.application_requests > 0 && summary.connections == 0)
    {
        return Err("owned adaptive stop counters or readiness binding rejected".into());
    }
    serde_json::to_value(summary).map_err(|_| "cannot canonicalize owned stop metadata".into())
}

fn bounded_line(reader: &mut impl BufRead, limit: usize) -> Result<Vec<u8>, String> {
    let mut line = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|_| "owned process control stream failed")?;
        if available.is_empty() {
            return Err("owned process control stream ended before a complete frame".into());
        }
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len() + count > limit {
            return Err("owned process control frame exceeded its byte budget".into());
        }
        line.extend_from_slice(&available[..count]);
        let complete = available[count - 1] == b'\n';
        reader.consume(count);
        if complete {
            return Ok(line);
        }
    }
}
fn terminate_owned(child: &mut Child) -> Result<(), String> {
    match child
        .try_wait()
        .map_err(|_| "owned adaptive child liveness is unknown; lifecycle is HOLD")?
    {
        Some(_) => Ok(()),
        None => {
            if child.kill().is_err() && !matches!(child.try_wait(), Ok(Some(_))) {
                return Err("owned adaptive child cancellation failed; lifecycle is HOLD".into());
            }
            child
                .wait()
                .map_err(|_| "cannot join the cancelled owned adaptive child")?;
            Ok(())
        }
    }
}

pub(super) struct SupervisedProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<JoinHandle<Result<Vec<u8>, String>>>,
    stderr: Option<JoinHandle<Result<Vec<u8>, String>>>,
    ready: Ready,
    resource_cache: Mutex<metrics::Snapshot>,
    reaped: bool,
    stop_summary: Option<Value>,
}
impl SupervisedProcess {
    pub(super) fn spawn(bootstrap: &Bootstrap) -> Result<Self, String> {
        bootstrap.validate()?;
        if symbiote_memory::maintenance::inspect(&bootstrap.state)?
            .identity
            .as_deref()
            != Some(bootstrap.expected_identity.as_str())
        {
            return Err(
                "adaptive child state does not match its prepared persistent identity".into(),
            );
        }
        let mut frame = serde_json::to_vec(bootstrap)
            .map_err(|_| "cannot encode private adaptive bootstrap")?;
        frame.push(b'\n');
        if frame.len() > CONFIG_LIMIT {
            return Err("adaptive bootstrap exceeded the bounded stdin budget".into());
        }
        let executable =
            std::env::current_exe().map_err(|_| "cannot locate the native adaptive executable")?;
        let mut command = Command::new(executable);
        command
            .arg("__adaptive-participant")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let mut child = command
            .spawn()
            .map_err(|_| "owned native adaptive process could not start")?;
        let mut input = child
            .stdin
            .take()
            .ok_or("owned adaptive stdin unavailable")?;
        let output = child
            .stdout
            .take()
            .ok_or("owned adaptive stdout unavailable")?;
        let errors = child
            .stderr
            .take()
            .ok_or("owned adaptive stderr unavailable")?;
        let (tx, rx) = mpsc::sync_channel(1);
        let writer = thread::spawn(move || {
            let result = input.write_all(&frame).and_then(|()| input.flush());
            let _ = tx.try_send(
                result
                    .map(|()| input)
                    .map_err(|_| "adaptive private bootstrap write failed".to_string()),
            );
        });
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let stdout = thread::spawn(move || {
            let mut reader = BufReader::new(output);
            let ready = bounded_line(&mut reader, READY_LIMIT).and_then(|line| {
                serde_json::from_slice::<Ready>(&line)
                    .map_err(|_| "adaptive readiness frame rejected".to_string())
            });
            let _ = ready_tx.try_send(ready);
            let mut tail = Vec::new();
            reader
                .take((LOG_LIMIT + 1) as u64)
                .read_to_end(&mut tail)
                .map_err(|_| "adaptive stdout reader failed")?;
            if tail.len() > LOG_LIMIT {
                return Err("adaptive stdout exceeded its byte budget".into());
            }
            Ok(tail)
        });
        let stderr = thread::spawn(move || {
            let mut bytes = Vec::new();
            errors
                .take((LOG_LIMIT + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| "adaptive stderr reader failed")?;
            if bytes.len() > LOG_LIMIT {
                return Err("adaptive stderr exceeded its byte budget".into());
            }
            Ok(bytes)
        });
        let startup = (|| {
            let deadline = Instant::now() + STARTUP;
            let input = rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|_| "owned adaptive startup write deadline exceeded")??;
            let ready = ready_rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|_| "owned adaptive readiness deadline exceeded")??;
            ready.validate(bootstrap, child.id())?;
            Ok((input, ready))
        })();
        match startup {
            Ok((input, ready)) => {
                let _ = writer.join();
                let resources = metrics::owned(&child, "after-readiness");
                Ok(Self {
                    child,
                    stdin: Some(input),
                    stdout: Some(stdout),
                    stderr: Some(stderr),
                    ready,
                    resource_cache: Mutex::new(resources),
                    reaped: false,
                    stop_summary: None,
                })
            }
            Err(error) => {
                terminate_owned(&mut child)?;
                let _ = writer.join();
                let _ = stdout.join();
                let _ = stderr.join();
                Err(error)
            }
        }
    }
    pub(super) fn ready(&self) -> &Ready {
        &self.ready
    }
    pub(super) fn endpoint(&self) -> PublicEndpoint {
        self.ready.endpoint()
    }
    fn observe_resources(&self, stage: &'static str) {
        if self.reaped && !metrics::after_reap_supported() {
            return;
        }
        let stage = if self.reaped {
            "after-exit-owned-handle"
        } else {
            stage
        };
        let snapshot = metrics::owned(&self.child, stage);
        if let Ok(mut cached) = self.resource_cache.lock() {
            cached.merge(snapshot, stage);
        }
    }
    /// OS-reported high-water counters, never a maximum of periodic samples.
    /// Linux never reopens /proc after this owned child has been reaped.
    pub(super) fn resources(&self) -> Value {
        self.observe_resources("live-owned-process");
        self.resource_cache.lock().map(|cached|cached.json(self.reaped)).unwrap_or_else(|_|json!({"schema":"symbiote.owned-process-resources/1","pid":self.child.id(),"memory_available":false,"cpu_available":false,"peak_resident_bytes":null,"resident_bytes_at_capture":null,"reason":"resource cache poisoned","process_reaped":self.reaped}))
    }
    pub(super) fn shutdown_summary(&self) -> Option<&Value> {
        self.stop_summary.as_ref()
    }
    pub(super) fn shutdown(&mut self) -> Result<(), String> {
        self.observe_resources("before-shutdown");
        if let Some(mut input) = self.stdin.take() {
            let _ = input.write_all(b"{\"command\":\"shutdown\"}\n");
            drop(input);
        }
        let deadline = Instant::now() + STOP;
        let status = loop {
            self.observe_resources("before-reap");
            match self
                .child
                .try_wait()
                .map_err(|_| "cannot determine owned adaptive child status")?
            {
                Some(status) => {
                    self.reaped = true;
                    self.observe_resources("after-exit-owned-handle");
                    break status;
                }
                None if Instant::now() >= deadline => {
                    self.observe_resources("before-forced-stop");
                    // Do not query a PID after any operation that may reap it,
                    // including an uncertain forced-termination outcome.
                    self.reaped = true;
                    terminate_owned(&mut self.child)?;
                    self.observe_resources("after-exit-owned-handle");
                    self.join_readers()?;
                    return Err("owned adaptive shutdown deadline exceeded; process killed and joined; inspect and recover its state explicitly".into());
                }
                None => thread::sleep(Duration::from_millis(10)),
            }
        };
        self.join_readers()?;
        if !status.success() {
            return Err("owned adaptive child exited unsuccessfully; committed state preserved, stale locks require explicit recovery".into());
        }
        Ok(())
    }
    fn join_readers(&mut self) -> Result<(), String> {
        if let Some(reader) = self.stdout.take() {
            let bytes = reader
                .join()
                .map_err(|_| "adaptive stdout reader panicked")??;
            self.stop_summary = Some(parse_stop_summary(&bytes, &self.ready)?);
        }
        if let Some(reader) = self.stderr.take() {
            let bytes = reader
                .join()
                .map_err(|_| "adaptive stderr reader panicked")??;
            if !bytes.is_empty() {
                return Err("adaptive child emitted a diagnostic; its contents are withheld to protect private bootstrap data".into());
            }
        }
        Ok(())
    }
}
impl Drop for SupervisedProcess {
    fn drop(&mut self) {
        self.observe_resources("before-owner-drop");
        match self.child.try_wait() {
            Ok(None) => {
                let _ = self.shutdown();
                self.reaped = true;
                if terminate_owned(&mut self.child).is_err() {
                    return;
                }
                let _ = self.join_readers();
            }
            Ok(Some(_)) => {
                self.reaped = true;
                let _ = self.join_readers();
            }
            Err(_) => {}
        }
    }
}

pub(super) fn run_child(
    factory: impl FnOnce(Bootstrap, Arc<Store>) -> Result<Running, String>,
) -> Result<(), String> {
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let startup_watchdog = thread::spawn(move || {
        if matches!(
            started_rx.recv_timeout(STARTUP),
            Err(mpsc::RecvTimeoutError::Timeout)
        ) {
            std::process::exit(70);
        }
    });
    let mut input = BufReader::new(std::io::stdin().lock());
    let bytes = bounded_line(&mut input, CONFIG_LIMIT)?;
    let bootstrap: Bootstrap =
        serde_json::from_slice(&bytes).map_err(|_| "owned adaptive bootstrap rejected")?;
    bootstrap.validate()?;
    if symbiote_memory::maintenance::inspect(&bootstrap.state)?
        .identity
        .as_deref()
        != Some(bootstrap.expected_identity.as_str())
    {
        return Err(
            "adaptive child state does not match its preauthorized durable identity".into(),
        );
    }
    let owner = Arc::new(Store::open(&bootstrap.state)?);
    if owner.identity() != bootstrap.expected_identity
        || owner.identity() == bootstrap.controller_identity
    {
        return Err(
            "adaptive private identity aliases its controller or differs from its provisioned role"
                .into(),
        );
    }
    let identity = owner.identity().to_string();
    let pin = bootstrap.material.pin.clone();
    let mut running = factory(bootstrap, Arc::clone(&owner))?;
    if running.server.server_id() != identity
        || running.server.certificate_sha256() != pin
        || !running.server.address().ip().is_loopback()
    {
        return Err(
            "adaptive factory server is not bound to its owned identity and certificate".into(),
        );
    }
    let (finished_tx, finished_rx) = mpsc::sync_channel(1);
    let world_deadline = Arc::clone(&running.world_deadline);
    let watchdog = thread::spawn(move || {
        let campaign = Instant::now() + CAMPAIGN;
        loop {
            match finished_rx.recv_timeout(Duration::from_millis(20)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            let now = Instant::now();
            if now >= campaign {
                std::process::exit(71);
            }
            match world_deadline.lock() {
                Ok(deadline) => {
                    if deadline.is_some_and(|deadline| now >= deadline) {
                        std::process::exit(72);
                    }
                }
                Err(_) => std::process::exit(73),
            }
        }
    });
    let ready = Ready {
        schema: "symbiote.adaptive-ready/1".into(),
        identity,
        pid: std::process::id(),
        instance_nonce: fresh_capability()?,
        address: running.server.address(),
        certificate_sha256: pin,
    };
    println!(
        "{}",
        serde_json::to_string(&ready).map_err(|_| "cannot encode public adaptive readiness")?
    );
    std::io::stdout()
        .flush()
        .map_err(|_| "cannot flush public adaptive readiness")?;
    let _ = started_tx.try_send(());
    let _ = startup_watchdog.join();
    let normal = bounded_line(&mut input, 128)
        .ok()
        .and_then(|line| serde_json::from_slice::<Value>(&line).ok())
        .is_some_and(|command| command == json!({"command":"shutdown"}));
    running.server.shutdown()?;
    let summary = StopSummary {
        schema: "symbiote.adaptive-stop/1".into(),
        identity: ready.identity.clone(),
        pid: ready.pid,
        instance_nonce: ready.instance_nonce.clone(),
        application_requests: running.server.request_count(),
        connections: running.server.connection_count(),
        session_failures: running.server.session_failures(),
    };
    drop(running);
    drop(owner);
    let _ = finished_tx.try_send(());
    let _ = watchdog.join();
    if !normal {
        return Err("adaptive owner pipe ended without an explicit shutdown".into());
    }
    println!(
        "{}",
        serde_json::to_string(&summary)
            .map_err(|_| "cannot encode owned adaptive stop counters")?
    );
    std::io::stdout()
        .flush()
        .map_err(|_| "cannot flush owned adaptive stop counters")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::policy::Arm;
    use super::super::wire::{Grant, LabCa, OfferMode, Role, CONTROL_OPS};
    use super::*;
    fn bootstrap() -> (std::path::PathBuf, Bootstrap) {
        let path = std::env::temp_dir().join(format!(
            "symbiote-process-boundaries-{}",
            fresh_capability().unwrap()
        ));
        let controller = Store::open(&path.join("controller"))
            .unwrap()
            .identity()
            .to_string();
        let identity = Store::open(&path.join("participant"))
            .unwrap()
            .identity()
            .to_string();
        let ca = LabCa::new().unwrap();
        let owner = ca.leaf().unwrap();
        let material = ca.leaf().unwrap();
        use sha2::{Digest, Sha256};
        // Public released-v0.4 reference only; no prospective world is generated.
        let protocol_sha256 = format!(
            "{:x}",
            Sha256::digest(b"8dbbd4a7550a88f7f6b91b7aa287665dbc481ef1")
        );
        let bootstrap = Bootstrap {
            state: path.join("participant"),
            expected_identity: identity,
            controller_identity: controller.clone(),
            material,
            ca_pem: ca.pem,
            grants: vec![Grant {
                identity: controller,
                pin: owner.pin,
                scope: SCOPE.into(),
                operations: CONTROL_OPS
                    .iter()
                    .map(|operation| (*operation).into())
                    .collect(),
            }],
            role: Role::Learner {
                arm: Arm::Isolated,
                observation_price: 100,
                offer_mode: OfferMode::CurrentWarmup,
                inactive: true,
            },
            protocol_sha256,
        };
        (path, bootstrap)
    }
    #[test]
    fn control_frames_reject_partial_and_oversize_input_without_echoing_secrets() {
        assert!(bounded_line(&mut std::io::Cursor::new(b"secret-without-newline"), 128).is_err());
        assert!(bounded_line(&mut std::io::Cursor::new(vec![b'x'; 129]), 128).is_err());
        assert_eq!(
            bounded_line(
                &mut std::io::Cursor::new(b"{\"command\":\"shutdown\"}\n"),
                128
            )
            .unwrap(),
            b"{\"command\":\"shutdown\"}\n"
        );
    }
    #[test]
    fn readiness_binds_owned_pid_private_identity_pin_and_public_loopback_metadata() {
        let (path, bootstrap) = bootstrap();
        bootstrap.validate().unwrap();
        let ready = Ready {
            schema: "symbiote.adaptive-ready/1".into(),
            identity: bootstrap.expected_identity.clone(),
            pid: 41,
            instance_nonce: fresh_capability().unwrap(),
            address: "127.0.0.1:4321".parse().unwrap(),
            certificate_sha256: bootstrap.material.pin.clone(),
        };
        ready.validate(&bootstrap, 41).unwrap();
        assert_eq!(ready.endpoint().identity, bootstrap.expected_identity);
        for fault in ["pid", "identity", "pin", "address", "nonce", "version"] {
            let mut bad = ready.clone();
            match fault {
                "pid" => bad.pid = 42,
                "identity" => bad.identity = bootstrap.controller_identity.clone(),
                "pin" => bad.certificate_sha256 = "0".repeat(64),
                "address" => bad.address = "192.0.2.1:4321".parse().unwrap(),
                "nonce" => bad.instance_nonce = "short".into(),
                _ => bad.schema = "unknown/1".into(),
            };
            let error = bad.validate(&bootstrap, 41).unwrap_err();
            assert!(!error.contains("PRIVATE KEY"));
        }
        let mut raw = serde_json::to_value(&ready).unwrap();
        raw["private_key_pem"] = json!(bootstrap.material.private_key_pem);
        assert!(serde_json::from_value::<Ready>(raw).is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn unprepared_identity_and_wrong_certificate_pin_fail_before_process_launch() {
        let (path, mut bootstrap) = bootstrap();
        let missing = path.join("unprepared-state");
        bootstrap.state = missing.clone();
        assert!(SupervisedProcess::spawn(&bootstrap).is_err());
        assert!(!missing.exists());
        bootstrap.state = path.join("participant");
        bootstrap.material.pin = "0".repeat(64);
        assert!(SupervisedProcess::spawn(&bootstrap).is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn owned_handle_termination_is_joined_and_safe_to_repeat_after_exit() {
        // The test harness rejects this unknown flag before executing any test,
        // generator or actor. Only this freshly owned process can be killed.
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--symbiote-owned-lifecycle-probe")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert_ne!(child.id(), std::process::id());
        terminate_owned(&mut child).unwrap();
        assert!(child.try_wait().unwrap().is_some());
        terminate_owned(&mut child).unwrap();
    }
    #[test]
    fn owned_resource_probe_helper() {
        if std::env::var("SYMBIOTE_OWNED_RESOURCE_PROBE").as_deref() != Ok("1") {
            return;
        }
        let mut bytes = vec![0u8; 8 * 1024 * 1024];
        for page in (0..bytes.len()).step_by(4096) {
            bytes[page] = 1;
        }
        std::hint::black_box(&bytes);
        println!("SYMBIOTE_OWNED_RESOURCE_READY");
        std::io::stdout().flush().unwrap();
        let _ = std::io::stdin().read_exact(&mut [0u8; 1]);
        std::hint::black_box(bytes);
    }
    #[test]
    fn actual_owned_child_resource_snapshot_survives_shutdown_without_pid_requery() {
        let module = module_path!().split_once("::").unwrap().1;
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("{module}::owned_resource_probe_helper"),
                "--nocapture",
            ])
            .env("SYMBIOTE_OWNED_RESOURCE_PROBE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut ready = false;
        for _ in 0..8 {
            let mut line = String::new();
            if output.read_line(&mut line).unwrap() == 0 {
                break;
            }
            if line.trim() == "SYMBIOTE_OWNED_RESOURCE_READY" {
                ready = true;
                break;
            }
        }
        assert!(
            ready,
            "manual memory probe must be ready before sampling OS counters"
        );
        let snapshot = metrics::owned(&child, "manual-probe-ready");
        let input = child.stdin.take();
        let mut owned = SupervisedProcess {
            ready: Ready {
                schema: "manual-resource-probe/1".into(),
                identity: "manual-probe".into(),
                pid: child.id(),
                instance_nonce: "0".repeat(64),
                address: "127.0.0.1:1".parse().unwrap(),
                certificate_sha256: "0".repeat(64),
            },
            child,
            stdin: input,
            stdout: None,
            stderr: None,
            resource_cache: Mutex::new(snapshot),
            reaped: false,
            stop_summary: None,
        };
        let before = owned.resources();
        assert_eq!(before["pid"], owned.child.id());
        assert_eq!(before["sampled_peak"], false);
        if cfg!(any(windows, target_os = "linux")) {
            assert_eq!(before["memory_available"], true, "{before}");
            assert!(before["peak_resident_bytes"].as_u64().unwrap() > 0);
            assert!(before["resident_bytes_at_capture"].as_u64().unwrap() > 0);
            assert_eq!(before["peak_is_os_reported"], true);
        } else {
            assert_eq!(before["memory_available"], false);
            assert!(before["peak_resident_bytes"].is_null());
        }
        if cfg!(windows) {
            assert_eq!(before["cpu_available"], true);
            assert!(before["cpu_user_100ns"].is_u64());
            assert!(before["cpu_kernel_100ns"].is_u64());
        }
        owned.shutdown().unwrap();
        let after = owned.resources();
        assert_eq!(after["process_reaped"], true);
        if cfg!(any(windows, target_os = "linux")) {
            assert_eq!(after["memory_available"], true, "{after}");
            assert!(after["peak_resident_bytes"].as_u64().unwrap() > 0);
        }
        if cfg!(target_os = "linux") {
            assert_ne!(after["memory_capture"], "after-exit-owned-handle");
            assert_eq!(after["lifetime_peak_complete"], false);
        }
        drop(output);
    }
    #[test]
    fn controller_resources_are_labeled_separately_from_child_and_system_memory() {
        let snapshot = parent_resources();
        assert_eq!(snapshot["pid"], std::process::id());
        assert_eq!(snapshot["process_reaped"], false);
        assert_eq!(snapshot["lifetime_peak_complete"], false);
        assert!(snapshot["scope"]
            .as_str()
            .unwrap()
            .contains("controller process only"));
        if cfg!(any(windows, target_os = "linux")) {
            assert!(snapshot["peak_resident_bytes"].as_u64().unwrap() > 0);
        } else {
            assert!(snapshot["peak_resident_bytes"].is_null());
        }
    }
    #[test]
    fn final_counter_frame_is_strictly_bounded_and_bound_to_its_owned_instance() {
        let ready = Ready {
            schema: "symbiote.adaptive-ready/1".into(),
            identity: "owned-child".into(),
            pid: 42,
            instance_nonce: "1".repeat(64),
            address: "127.0.0.1:4321".parse().unwrap(),
            certificate_sha256: "2".repeat(64),
        };
        let summary = json!({"schema":"symbiote.adaptive-stop/1","identity":ready.identity,"pid":ready.pid,"instance_nonce":ready.instance_nonce,"application_requests":0,"connections":0,"session_failures":0});
        let encode = |value: &Value| {
            let mut bytes = serde_json::to_vec(value).unwrap();
            bytes.push(b'\n');
            bytes
        };
        assert_eq!(
            parse_stop_summary(&encode(&summary), &ready).unwrap(),
            summary
        );
        for field in [
            "schema",
            "identity",
            "pid",
            "instance_nonce",
            "session_failures",
            "application_requests",
            "private_key_pem",
        ] {
            let mut invalid = summary.clone();
            invalid[field] = match field {
                "pid" => json!(43),
                "session_failures" | "application_requests" => json!(1),
                _ => json!("unexpected or private data"),
            };
            assert!(parse_stop_summary(&encode(&invalid), &ready).is_err());
        }
        let frame = encode(&summary);
        assert!(parse_stop_summary(&[frame.clone(), frame.clone()].concat(), &ready).is_err());
        assert!(parse_stop_summary(&frame[..frame.len() - 1], &ready).is_err());
        assert!(parse_stop_summary(&[], &ready).is_err());
        assert!(parse_stop_summary(&vec![b'x'; STOP_SUMMARY_LIMIT + 1], &ready).is_err());
    }
}
