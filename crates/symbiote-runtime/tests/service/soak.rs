//! Explicitly selected local continuity campaign. Never run by normal tests.
//! The two learned fixtures remain fixed; cycles are soak observations.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{mpsc, Mutex};

const EXPECTED_STARTS: u64 = 10;
const COMMAND_BYTES: usize = 256 * 1024;
const ARTIFACT_BYTES: u64 = 60 * 1024 * 1024;

fn artifact_size(path: &Path) -> u64 {
    let info = fs::symlink_metadata(path).unwrap();
    assert!(!info.file_type().is_symlink());
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        assert_eq!(info.file_attributes() & 0x400, 0);
    }
    if info.is_file() {
        return info.len();
    }
    fs::read_dir(path)
        .unwrap()
        .map(|entry| artifact_size(&entry.unwrap().path()))
        .sum()
}

#[derive(Clone, Copy)]
struct Mode {
    name: &'static str,
    cycles: usize,
    spacing_ms: u64,
    window_ms: u64,
    outer_seconds: u64,
    rotations: [usize; 4],
    denials: [usize; 2],
    lost: usize,
    restore: usize,
}
impl Mode {
    fn hour() -> Self {
        Self {
            name: "HOUR_QUALIFICATION",
            cycles: 120,
            spacing_ms: 30_000,
            window_ms: 3_600_000,
            outer_seconds: 3900,
            rotations: [18, 38, 78, 101],
            denials: [30, 90],
            lost: 50,
            restore: 60,
        }
    }
    fn fixture() -> Self {
        Self {
            name: "ENGINEERING_FIXTURE_NOT_HOUR_QUALIFICATION",
            cycles: 12,
            spacing_ms: 0,
            window_ms: 0,
            outer_seconds: 180,
            rotations: [2, 4, 8, 10],
            denials: [3, 9],
            lost: 5,
            restore: 6,
        }
    }
    fn keys(self) -> usize {
        self.cycles * 4 + 3
    }
}

struct BoundedOutput {
    output: Output,
    outcome: &'static str,
}
type SharedCapture = Arc<Mutex<(Vec<u8>, Vec<u8>, usize)>>;

fn bounded_output(command: &mut Command) -> BoundedOutput {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let capture = Arc::new(Mutex::new((Vec::<u8>::new(), Vec::<u8>::new(), 0usize)));
    let over = Arc::new(AtomicBool::new(false));
    fn reader<R: Read + Send + 'static>(
        mut pipe: R,
        capture: SharedCapture,
        over: Arc<AtomicBool>,
        stderr: bool,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut block = [0u8; 8192];
            loop {
                let count = match pipe.read(&mut block) {
                    Ok(0) => break,
                    Ok(count) => count,
                    Err(_) => {
                        over.store(true, Ordering::Release);
                        break;
                    }
                };
                let mut all = capture.lock().unwrap();
                let keep = count.min(COMMAND_BYTES.saturating_sub(all.2));
                if stderr {
                    all.1.extend_from_slice(&block[..keep]);
                } else {
                    all.0.extend_from_slice(&block[..keep]);
                }
                all.2 += keep;
                if keep != count {
                    over.store(true, Ordering::Release);
                }
            }
        })
    }
    let stdout = reader(
        child.stdout.take().unwrap(),
        Arc::clone(&capture),
        Arc::clone(&over),
        false,
    );
    let stderr = reader(
        child.stderr.take().unwrap(),
        Arc::clone(&capture),
        Arc::clone(&over),
        true,
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut outcome = "completed";
    while child.try_wait().unwrap().is_none() {
        if over.load(Ordering::Acquire) {
            outcome = "output-budget";
            child.kill().unwrap();
            break;
        }
        if Instant::now() >= deadline {
            outcome = "timeout";
            child.kill().unwrap();
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let status = child.wait().unwrap();
    stdout.join().unwrap();
    stderr.join().unwrap();
    if over.load(Ordering::Acquire) {
        outcome = "output-budget";
    }
    let mut all = capture.lock().unwrap();
    BoundedOutput {
        output: Output {
            status,
            stdout: std::mem::take(&mut all.0),
            stderr: std::mem::take(&mut all.1),
        },
        outcome,
    }
}

fn configured_command(
    fixture: &Fixture,
    manifest: &str,
    command: &str,
    args: &[&str],
) -> BoundedOutput {
    bounded_output(
        Command::new(env!("CARGO_BIN_EXE_symbiote"))
            .args([command, "--json", "--config"])
            .arg(fixture.dir.0.join(manifest))
            .args(args),
    )
}
fn transition(fixture: &Fixture, old: &Path, anchor: &Value, reviewed: bool) -> BoundedOutput {
    let mut args = vec![
        "--previous-config",
        old.to_str().unwrap(),
        "--expected-policy",
        anchor["policy_sha256"].as_str().unwrap(),
        "--expected-head",
        anchor["journal_head_sha256"].as_str().unwrap(),
        "--reason",
        "explicit offline soak policy",
    ];
    if reviewed {
        args.push("--review-permission-change");
    }
    configured_command(fixture, "server.json", "policy-transition", &args)
}

struct Evidence {
    root: PathBuf,
    events: File,
    sequence: usize,
    keys: BTreeSet<(String, String)>,
    report: Value,
    started: Instant,
    mode: Mode,
    active_ready: Option<(u32, Instant, bool)>,
    main_span_ms: u128,
    last_event_ms: u128,
    last_request_ms: u128,
    last_stop_ms: u128,
}
impl Evidence {
    fn new(mode: Mode) -> Self {
        let requested = PathBuf::from(
            std::env::var_os("SYMBIOTE_SOAK_ARTIFACTS")
                .expect("explicit runner-owned soak artifact directory required"),
        );
        assert!(requested.is_absolute());
        let parent = fs::canonicalize(requested.parent().unwrap()).unwrap();
        assert!(parent.starts_with(fs::canonicalize(std::env::temp_dir()).unwrap()));
        let root = parent.join(requested.file_name().unwrap());
        assert!(!root.exists(), "soak output must be fresh, even if empty");
        fs::create_dir(&root).unwrap();
        for name in [
            "outputs",
            "public-policies",
            "public-certificates",
            "public-fixtures",
            "owners",
        ] {
            fs::create_dir(root.join(name)).unwrap();
        }
        let events = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("events.jsonl"))
            .unwrap();
        let native = fs::read(env!("CARGO_BIN_EXE_symbiote")).unwrap();
        let test = fs::read(std::env::current_exe().unwrap()).unwrap();
        let report = json!({
            "schema":"symbiote.local-soak/1", "version":env!("CARGO_PKG_VERSION"),
            "status":"HOLD", "mode":mode.name,"cycles_expected":mode.cycles, "cycles_completed":0,
            "request_keys_expected":mode.keys(), "request_keys_recorded":0,
            "owner_identities":[], "cycles":[], "credential_rotations":[], "denials":[],
            "service_starts":0, "owned_stops":0, "service_starts_expected":EXPECTED_STARTS,
            "models_retained":0, "model_digests":[], "lost_reply":null,
            "midpoint_restore":null, "first_failure":null,
            "native_binary_sha256":hash(&native), "test_binary_sha256":hash(&test),
            "events_file":"events.jsonl", "current_server_state":"owners/server-initial",
            "client_state":"owners/client", "server_leaf_certificates":2,
            "server_leaf_reuse":true, "automatic_certificate_renewal":false,
            "scope":"one PC; loopback TLS; fixed affine and three-node graph fixtures; cycles are not independent research samples; two-host validation remains open"
        });
        let mut result = Self {
            root,
            events,
            sequence: 0,
            keys: BTreeSet::new(),
            report,
            started: Instant::now(),
            mode,
            active_ready: None,
            main_span_ms: 0,
            last_event_ms: 0,
            last_request_ms: 0,
            last_stop_ms: 0,
        };
        result.event("started", json!({"native_binary_sha256":result.report["native_binary_sha256"],"test_binary_sha256":result.report["test_binary_sha256"]}));
        result
    }
    fn write(&self, relative: &str, bytes: &[u8]) {
        assert!(bytes.len() <= 1024 * 1024, "single evidence write bound");
        assert!(
            artifact_size(&self.root) + bytes.len() as u64 <= ARTIFACT_BYTES - 1024 * 1024,
            "native artifact/final-report reserve"
        );
        assert!(!relative.contains("..") && !Path::new(relative).is_absolute());
        assert!(!bytes
            .windows(b"-----BEGIN PRIVATE KEY-----".len())
            .any(|part| part == b"-----BEGIN PRIVATE KEY-----"));
        assert!(!bytes
            .windows(b"-----BEGIN EC PRIVATE KEY-----".len())
            .any(|part| part == b"-----BEGIN EC PRIVATE KEY-----"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.root.join(relative))
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
    fn event(&mut self, kind: &str, value: Value) {
        self.event_at(kind, value, Instant::now());
    }
    fn event_at(&mut self, kind: &str, value: Value, observed: Instant) {
        assert!(
            self.started.elapsed() < Duration::from_secs(self.mode.outer_seconds),
            "fixed native outer deadline"
        );
        self.last_event_ms = observed.duration_since(self.started).as_millis();
        let row = json!({"sequence":self.sequence,"kind":kind,"elapsed_ms":self.last_event_ms,"data":value});
        let mut bytes = serde_json::to_vec(&row).unwrap();
        bytes.push(b'\n');
        assert!(
            artifact_size(&self.root) + bytes.len() as u64 <= ARTIFACT_BYTES - 1024 * 1024,
            "native event byte bound"
        );
        self.events.write_all(&bytes).unwrap();
        self.events.sync_all().unwrap();
        self.sequence += 1;
    }
    fn output(&mut self, label: &str, bounded: BoundedOutput, expect_success: bool) -> Value {
        let output = bounded.output;
        let prefix = format!("outputs/{:04}-{label}", self.sequence);
        let stdout = format!("{prefix}.stdout");
        let stderr = format!("{prefix}.stderr");
        self.write(&stdout, &output.stdout);
        self.write(&stderr, &output.stderr);
        let value = json!({"label":label,"exit_code":output.status.code(),"success":output.status.success(),"outcome":bounded.outcome,
            "stdout":stdout,"stdout_sha256":hash(&output.stdout),"stderr":stderr,"stderr_sha256":hash(&output.stderr)});
        self.event("native-command", value.clone());
        assert_eq!(
            bounded.outcome, "completed",
            "{label}: bounded process failure"
        );
        assert_eq!(
            output.status.success(),
            expect_success,
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if expect_success {
            serde_json::from_slice(&output.stdout).unwrap()
        } else {
            value
        }
    }
    fn command(&mut self, label: &str, args: &[OsString], expect_success: bool) -> Value {
        self.event("command-input",json!({"label":label,"arguments":args.iter().map(|v|v.to_string_lossy()).collect::<Vec<_>>()}));
        let output = bounded_output(
            Command::new(env!("CARGO_BIN_EXE_symbiote"))
                .args(args)
                .arg("--json"),
        );
        self.output(label, output, expect_success)
    }
    fn configured(
        &mut self,
        fixture: &Fixture,
        label: &str,
        command: &str,
        args: &[&str],
    ) -> Value {
        self.output(
            label,
            configured_command(fixture, "server.json", command, args),
            true,
        )
    }
    fn request_key(&mut self, request: &Value, duplicate: bool) {
        let key = (
            request["scope"].as_str().unwrap().to_string(),
            request["request_id"].as_str().unwrap().to_string(),
        );
        if duplicate {
            assert!(self.keys.contains(&key));
        } else {
            assert!(self.keys.insert(key));
        }
        assert!(self.keys.len() <= self.mode.keys());
    }
    fn api(&mut self, fixture: &Fixture, label: &str, request: &Value, duplicate: bool) -> Value {
        self.request_key(request, duplicate);
        self.event(
            "tls-request",
            json!({"label":label,"request":request,"explicit_duplicate":duplicate}),
        );
        self.last_request_ms = self.last_event_ms;
        let path = fixture.dir.0.join("request.json");
        fs::write(&path, serde_json::to_vec(request).unwrap()).unwrap();
        let result = bounded_output(
            Command::new(env!("CARGO_BIN_EXE_symbiote"))
                .args(["connect", "--json", "--config"])
                .arg(fixture.dir.0.join("client.json"))
                .args(["--peer", "partner", "--request"])
                .arg(path),
        );
        let reply = self.output(label, result, true);
        self.event("tls-response", json!({"label":label,"response":reply}));
        reply
    }
    fn start(&mut self, fixture: &Fixture, label: &str) -> ServiceProcess {
        self.assert_native();
        assert!(self.active_ready.is_none());
        let mut child = Command::new(env!("CARGO_BIN_EXE_symbiote"))
            .args(["serve", "--json", "--config"])
            .arg(fixture.dir.0.join("server.json"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let (send, receive) = mpsc::channel();
        let readiness = thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = loop {
                let available = reader.fill_buf().unwrap();
                if available.is_empty() {
                    break Err("service ended before readiness");
                }
                let count = available
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(available.len(), |n| n + 1);
                if bytes.len() + count > 32768 {
                    break Err("readiness frame too large");
                }
                let end = available[count - 1] == b'\n';
                bytes.extend_from_slice(&available[..count]);
                reader.consume(count);
                if end {
                    break Ok(serde_json::from_slice::<Value>(&bytes).unwrap());
                }
            };
            let _ = send.send((reader, result));
        });
        let received = receive.recv_timeout(Duration::from_secs(5));
        if received.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let (output, ready) = received.expect("owned service readiness exceeded5seconds");
        readiness.join().unwrap();
        let ready = ready.expect("owned service readiness failed");
        assert_eq!(ready["schema"], "symbiote.service-ready/1");
        let service = ServiceProcess {
            child,
            input,
            output,
            ready,
        };
        assert_eq!(service.ready["identity"], fixture.ids[0]);
        assert_eq!(
            service.ready["pid"].as_u64(),
            Some(u64::from(service.child.id()))
        );
        assert_ne!(service.child.id(), std::process::id());
        self.report["service_starts"] = json!(self.report["service_starts"].as_u64().unwrap() + 1);
        let observed = Instant::now();
        self.active_ready = Some((service.child.id(), observed, label != "bootstrap"));
        self.event_at("owned-listener-started",json!({"label":label,"spawn_ordinal":self.report["service_starts"],"ready":service.ready}),observed);
        service
    }
    fn stopped(&mut self, service: &mut ServiceProcess, label: &str) -> Value {
        let result = service.stop();
        let stopped = Instant::now();
        let (pid, ready, main) = self.active_ready.take().unwrap();
        assert_eq!(pid, service.child.id());
        self.last_stop_ms = stopped.duration_since(self.started).as_millis();
        let span = self.last_stop_ms - ready.duration_since(self.started).as_millis();
        if main {
            self.main_span_ms += span;
        }
        assert_eq!(result["identity"], self.report["owner_identities"][0]);
        assert_eq!(service.child.try_wait().unwrap().unwrap().code(), Some(0));
        self.report["owned_stops"] = json!(self.report["owned_stops"].as_u64().unwrap() + 1);
        self.event_at(
            "owned-listener-stopped",
            json!({"label":label,"pid":service.child.id(),"stop":result,"exit_code":0,"ready_to_wait_ms":span,"main_listener":main}),
            stopped,
        );
        result
    }
    fn assert_native(&self) {
        assert_eq!(
            hash(&fs::read(env!("CARGO_BIN_EXE_symbiote")).unwrap()),
            self.report["native_binary_sha256"].as_str().unwrap(),
            "registered native binary changed"
        );
    }
    fn public_policy(&self, fixture: &Fixture, label: &str) {
        for (role, value) in [("server", &fixture.server), ("client", &fixture.client)] {
            self.write(
                &format!("public-policies/{label}-{role}.json"),
                &serde_json::to_vec_pretty(value).unwrap(),
            );
        }
    }
    fn finish(&mut self, failure: Option<String>) {
        self.report["main_listener_span_ms"] = json!(self.main_span_ms);
        self.report["request_keys_recorded"] = json!(self.keys.len());
        self.report["request_keys"] = json!(self
            .keys
            .iter()
            .map(|(scope, id)| json!({"scope":scope,"request_id":id}))
            .collect::<Vec<_>>());
        self.report["elapsed_ms"] = json!(self.started.elapsed().as_millis());
        self.report["first_failure"] = json!(failure);
        self.report["status"] = json!(if failure.is_none() { "PASS" } else { "HOLD" });
        self.event("finished",json!({"status":self.report["status"],"cycles_completed":self.report["cycles_completed"]}));
        self.report["events_sha256"] =
            json!(hash(&fs::read(self.root.join("events.jsonl")).unwrap()));
        let mut files = Vec::new();
        for prefix in ["owners", "midpoint-backup"] {
            let path = self.root.join(prefix);
            if path.exists() {
                state_files(&self.root, &path, &mut files);
            }
        }
        self.report["owner_files"] = json!(files);
        self.write(
            "soak-report.json",
            &serde_json::to_vec_pretty(&self.report).unwrap(),
        );
    }
}

fn state_files(root: &Path, path: &Path, files: &mut Vec<Value>) {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(!metadata.file_type().is_symlink());
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        assert_eq!(metadata.file_attributes() & 0x400, 0);
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            state_files(root, &entry.unwrap().path(), files);
        }
        return;
    }
    let name = path.file_name().unwrap().to_str().unwrap();
    assert!(
        [
            "ledger.jsonl",
            "knowledge.jsonl",
            "operations.jsonl",
            "operations-owner.json",
            "state-layout.json",
            "maintenance-audit.jsonl",
            "writer.lock",
            "knowledge.writer.lock",
            "maintenance.guard",
            "restore-incomplete.json",
            "backup-manifest.json",
            "backup-incomplete.json"
        ]
        .contains(&name)
            || name.starts_with("restored-owner-") && name.ends_with(".json"),
        "unexpected owner sidecar is not an allowlisted soak artifact"
    );
    assert!(metadata.is_file() && metadata.len() <= 4 * 1024 * 1024);
    let bytes = fs::read(path).unwrap();
    assert!(!bytes
        .windows(b"-----BEGIN PRIVATE KEY-----".len())
        .any(|part| part == b"-----BEGIN PRIVATE KEY-----"));
    files.push(json!({"path":path.strip_prefix(root).unwrap().to_string_lossy().replace('\\',"/"),"bytes":bytes.len(),"sha256":hash(&bytes)}));
}

struct Continuity {
    server: PathBuf,
    client: PathBuf,
    server_owner: Vec<u8>,
    client_owner: Vec<u8>,
    knowledge: Vec<u8>,
    server_ops: Vec<u8>,
    client_ops: Vec<u8>,
    ids: Vec<String>,
    digests: Vec<String>,
}
impl Continuity {
    fn check(&mut self) -> Value {
        assert_eq!(
            fs::read(self.server.join("ledger.jsonl")).unwrap(),
            self.server_owner
        );
        assert_eq!(
            fs::read(self.client.join("ledger.jsonl")).unwrap(),
            self.client_owner
        );
        assert_eq!(
            fs::read(self.server.join("knowledge.jsonl")).unwrap(),
            self.knowledge
        );
        let server = fs::read(self.server.join("operations.jsonl")).unwrap();
        let client = fs::read(self.client.join("operations.jsonl")).unwrap();
        assert!(server.starts_with(&self.server_ops));
        assert!(client.starts_with(&self.client_ops));
        self.server_ops = server;
        self.client_ops = client;
        json!({"server_owner_sha256":hash(&self.server_owner),"client_owner_sha256":hash(&self.client_owner),
            "knowledge_sha256":hash(&self.knowledge),"server_operations_sha256":hash(&self.server_ops),
            "client_operations_sha256":hash(&self.client_ops),"server_operation_records":self.server_ops.iter().filter(|v|**v==b'\n').count(),
            "model_digests":self.digests,"models_retained":2})
    }
    fn verify_offline(&self) {
        let owner = Store::open(&self.server).unwrap();
        let knowledge = KnowledgeStore::open(&self.server, owner.identity()).unwrap();
        let active = knowledge.active();
        assert_eq!(active.len(), 2);
        for (id, digest) in self.ids.iter().zip(&self.digests) {
            assert_eq!(
                active
                    .iter()
                    .find(|record| &record.id == id)
                    .unwrap()
                    .digest()
                    .unwrap(),
                *digest
            );
        }
    }
}
fn actual_state(fixture: &Fixture) -> PathBuf {
    fixture
        .dir
        .0
        .join(fixture.server["state"].as_str().unwrap())
}
fn payloads(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["payload"].clone())
        .collect()
}

fn initialize(fixture: &mut Fixture, evidence: &mut Evidence) -> Continuity {
    evidence.report["owner_identities"] = json!(fixture.ids);
    assert_ne!(fixture.ids[0], fixture.ids[1]);
    for role in ["server", "client"] {
        let source = fixture.dir.0.join(format!("{role}-state"));
        let target = evidence.root.join("owners").join(if role == "server" {
            "server-initial"
        } else {
            "client"
        });
        assert!(
            source.starts_with(&fixture.dir.0)
                && target.starts_with(&evidence.root)
                && !target.exists()
        );
        fs::rename(source, &target).unwrap();
        if role == "server" {
            fixture.server["state"] = json!(target);
        } else {
            fixture.client["state"] = json!(target);
        }
    }
    fixture.save();
    evidence.public_policy(fixture, "initial");
    for name in ["ca.pem", "server.pem", "client.pem", "observer.pem"] {
        evidence.write(
            &format!("public-certificates/{name}"),
            &fs::read(fixture.dir.0.join(name)).unwrap(),
        );
    }
    for name in ["affine-truth.json", "graph-truth.json"] {
        evidence.write(
            &format!("public-fixtures/{name}"),
            &fs::read(fixture.dir.0.join(name)).unwrap(),
        );
    }
    evidence.event("fixture",json!({"owner_identities":fixture.ids,"private_fixture_directory":fixture.dir.0,
        "credential_files_preserved":false,"server_leaf_reuse":["server.pem","observer.pem"],"client_leaf":"client.pem"}));
    let mut service = evidence.start(fixture, "bootstrap");
    let mut candidates = Vec::new();
    for is_graph in [false, true] {
        let request = fixture.offer(is_graph);
        let reply = evidence.api(
            fixture,
            if is_graph {
                "submit-graph"
            } else {
                "submit-affine"
            },
            &request,
            false,
        );
        assert_eq!(reply["status"], "QUARANTINED");
        assert_eq!(reply["promoted"], false);
        candidates.push(reply["candidate"].as_str().unwrap().to_string());
    }
    assert_eq!(
        evidence.stopped(&mut service, "bootstrap")["active_knowledge"],
        0
    );
    let mut ids = Vec::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let evaluated = evidence.configured(
            fixture,
            &format!("initial-evaluation-{index}"),
            "evaluate",
            &["--candidate", candidate],
        );
        assert_eq!(evaluated["status"], "PROMOTED");
        ids.push(evaluated["artifact"].as_str().unwrap().to_string());
    }
    let server = actual_state(fixture);
    let client = fixture
        .dir
        .0
        .join(fixture.client["state"].as_str().unwrap());
    let digests = {
        let owner = Store::open(&server).unwrap();
        let knowledge = KnowledgeStore::open(&server, owner.identity()).unwrap();
        ids.iter()
            .map(|id| {
                knowledge
                    .active()
                    .iter()
                    .find(|record| &record.id == id)
                    .unwrap()
                    .digest()
                    .unwrap()
            })
            .collect::<Vec<_>>()
    };
    evidence.report["model_digests"] = json!(digests);
    evidence.report["models_retained"] = json!(2);
    Continuity {
        server_owner: fs::read(server.join("ledger.jsonl")).unwrap(),
        client_owner: fs::read(client.join("ledger.jsonl")).unwrap(),
        knowledge: fs::read(server.join("knowledge.jsonl")).unwrap(),
        server_ops: fs::read(server.join("operations.jsonl")).unwrap(),
        client_ops: fs::read(client.join("operations.jsonl")).unwrap(),
        server,
        client,
        ids,
        digests,
    }
}

fn rotate(fixture: &mut Fixture, evidence: &mut Evidence, after: usize) -> String {
    let anchor_server = evidence.configured(
        fixture,
        &format!("rotation-{after}-server-anchor"),
        "policy-status",
        &[],
    );
    let anchor_client = evidence.output(
        &format!("rotation-{after}-client-anchor"),
        configured_command(fixture, "client.json", "policy-status", &[]),
        true,
    );
    let old_server = fixture.dir.0.join(format!("old-server-{after}.json"));
    let old_client = fixture.dir.0.join(format!("old-client-{after}.json"));
    fs::copy(fixture.dir.0.join("server.json"), &old_server).unwrap();
    fs::copy(fixture.dir.0.join("client.json"), &old_client).unwrap();
    let old_pin = fixture.server["certificate_sha256"]
        .as_str()
        .unwrap()
        .to_string();
    let name = if [evidence.mode.rotations[0], evidence.mode.rotations[2]].contains(&after) {
        "observer"
    } else {
        "server"
    };
    let identity = TlsIdentity::from_pem_files(
        &fixture.dir.0.join(format!("{name}.pem")),
        &fixture.dir.0.join(format!("{name}.key")),
    )
    .unwrap();
    fixture.server["certificate"] = json!(format!("{name}.pem"));
    fixture.server["private_key"] = json!(format!("{name}.key"));
    fixture.server["certificate_sha256"] = json!(identity.certificate_sha256());
    fixture.client["peers"][0]["certificate_sha256"] = json!(identity.certificate_sha256());
    fixture.client["peers"][0]["server_name"] = json!(format!("{name}.symbiote.test"));
    fixture.save();
    let server = evidence.output(
        &format!("rotation-{after}-server"),
        transition(fixture, &old_server, &anchor_server, false),
        true,
    );
    let client = evidence.output(
        &format!("rotation-{after}-client"),
        configured_command(
            fixture,
            "client.json",
            "policy-transition",
            &[
                "--previous-config",
                old_client.to_str().unwrap(),
                "--expected-policy",
                anchor_client["policy_sha256"].as_str().unwrap(),
                "--expected-head",
                anchor_client["journal_head_sha256"].as_str().unwrap(),
                "--reason",
                "explicit soak server-leaf pin rotation",
            ],
        ),
        true,
    );
    evidence.public_policy(fixture, &format!("rotation-{after}"));
    evidence.report["credential_rotations"].as_array_mut().unwrap().push(json!({"after_cycle":after,"previous_pin":old_pin,
        "current_pin":identity.certificate_sha256(),"server_transition":server,"client_transition":client,"stale_pin_rejection":null}));
    old_pin
}

fn denial(fixture: &Fixture, evidence: &mut Evidence, after: usize) {
    let denied = evidence.configured(
        fixture,
        &format!("denial-{after}"),
        "peer-revoke",
        &[
            "--peer",
            "partner",
            "--reason",
            "fixed soak containment checkpoint",
        ],
    );
    assert_eq!(denied["peer"], fixture.ids[1]);
    assert_eq!(denied["denied"], true);
    let stopped = evidence.configured(fixture, &format!("denied-serve-{after}"), "serve", &[]);
    assert_eq!(stopped["schema"], "symbiote.service-stop/1");
    assert_eq!(stopped["status"], "STOPPED");
    assert_eq!(stopped["reason"], "no-authorized-peers");
    assert_eq!(stopped["listener_opened"], false);
    assert_eq!(stopped["requests"], 0);
    assert_eq!(stopped["connections"], 0);
    let anchor = evidence.configured(
        fixture,
        &format!("regrant-anchor-{after}"),
        "policy-status",
        &[],
    );
    let regrant = evidence.configured(
        fixture,
        &format!("regrant-{after}"),
        "peer-regrant",
        &[
            "--peer",
            "partner",
            "--expected-policy",
            anchor["policy_sha256"].as_str().unwrap(),
            "--expected-head",
            anchor["journal_head_sha256"].as_str().unwrap(),
            "--reason",
            "fixed soak reviewed regrant",
            "--review-permission-change",
        ],
    );
    assert_eq!(regrant["peer"], fixture.ids[1]);
    assert_eq!(regrant["denied"], false);
    evidence.report["denials"].as_array_mut().unwrap().push(
        json!({"after_cycle":after,"denial":denied,"denied_service":stopped,"regrant":regrant}),
    );
}

fn lost_reply(
    fixture: &Fixture,
    evidence: &mut Evidence,
    service: &mut ServiceProcess,
) -> ServiceProcess {
    let mut request = fixture.offer(false);
    request["request_id"] = json!(format!("soak-lost-submit-{}", evidence.mode.lost));
    evidence.request_key(&request, false);
    evidence.event("lost-reply-request", request.clone());
    let backend = fixture.endpoint("affine-context/v1", "candidate.submit");
    let upstream = fixture.direct_client(&fixture.ids[1]);
    let ca = fs::read(fixture.dir.0.join("ca.pem")).unwrap();
    let config = SecureServerConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        fixture.ids[0].clone(),
        TlsIdentity::from_pem_files(
            &fixture
                .dir
                .0
                .join(fixture.server["certificate"].as_str().unwrap()),
            &fixture
                .dir
                .0
                .join(fixture.server["private_key"].as_str().unwrap()),
        )
        .unwrap(),
        &ca,
        vec![SecurePeerGrant {
            id: fixture.ids[1].clone(),
            certificate_sha256: fixture.client["certificate_sha256"]
                .as_str()
                .unwrap()
                .into(),
            scopes: BTreeMap::from([("affine-context/v1".into(), vec!["candidate.submit".into()])]),
        }],
        SecureLimits::default(),
    )
    .unwrap();
    let committed = Arc::new(Mutex::new(None::<Value>));
    let writer = Arc::clone(&committed);
    let withheld = Arc::new(AtomicBool::new(false));
    let witness = Arc::clone(&withheld);
    let mut proxy = spawn_secure_server(config, move |_, operation, payload| {
        let mut client = SecureClient::connect(&backend, &upstream)?;
        let reply = client.call(operation, &payload)?;
        client.revoke()?;
        *writer.lock().map_err(|_| "soak witness unavailable")? = Some(reply.clone());
        if !witness.swap(true, Ordering::AcqRel) {
            thread::sleep(Duration::from_millis(800));
        }
        Ok(reply)
    })
    .unwrap();
    let mut endpoint = fixture.endpoint("affine-context/v1", "candidate.submit");
    endpoint.address = proxy.address();
    endpoint.server_name = fixture.client["peers"][0]["server_name"]
        .as_str()
        .unwrap()
        .into();
    let mut client =
        SecureClient::connect(&endpoint, &fixture.direct_client(&fixture.ids[1])).unwrap();
    let error = client
        .call("candidate.submit", &request)
        .expect_err("one genuinely committed reply must be withheld");
    assert!(withheld.load(Ordering::Acquire));
    let expected = committed.lock().unwrap().clone().unwrap();
    assert_eq!(expected["status"], "QUARANTINED");
    let candidate = expected["candidate"].as_str().unwrap();
    let path = actual_state(fixture).join("operations.jsonl");
    let before = fs::read(&path).unwrap();
    assert_eq!(
        payloads(&path)
            .iter()
            .filter(|event| event["event"] == "quarantined" && event["candidate_id"] == candidate)
            .count(),
        1
    );
    let pid = service.child.id();
    assert!(service.child.try_wait().unwrap().is_none());
    service.child.kill().unwrap();
    let exit = service.child.wait().unwrap();
    let stopped = Instant::now();
    let (active_pid, ready, main) = evidence.active_ready.take().unwrap();
    assert_eq!(active_pid, pid);
    assert!(main);
    evidence.last_stop_ms = stopped.duration_since(evidence.started).as_millis();
    let span = evidence.last_stop_ms - ready.duration_since(evidence.started).as_millis();
    evidence.main_span_ms += span;
    assert!(!exit.success());
    service.input.take();
    evidence.report["owned_stops"] = json!(evidence.report["owned_stops"].as_u64().unwrap() + 1);
    evidence.event_at(
        "owned-listener-killed-and-joined",
        json!({"cycle":evidence.mode.lost,"pid":pid,"exit_code":exit.code(),"joined":true,"ready_to_wait_ms":span,"main_listener":true}),
        stopped,
    );
    proxy.shutdown().unwrap();
    let recovery = evidence.command(
        "recover-owned-crash",
        &[
            "recover".into(),
            "--state".into(),
            actual_state(fixture).into_os_string(),
        ],
        true,
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    let restarted = evidence.start(fixture, "after-owned-crash");
    let retried = evidence.api(fixture, "lost-submit-exact-retry", &request, true);
    assert_eq!(retried, expected);
    assert_eq!(fs::read(&path).unwrap(), before);
    evidence.report["lost_reply"] = json!({"cycle":evidence.mode.lost,"request":request,"first_call_error":error,"committed_response":expected,
        "owned_crash":{"pid":pid,"exit_code":exit.code(),"joined":true},"recovery":recovery,"retry_response":retried,
        "candidate":candidate,"quarantine_rows":1,"journal_sha256_before_crash":hash(&before),"journal_sha256_after_retry":hash(&fs::read(&path).unwrap()),
        "candidate_evaluated":false});
    restarted
}

fn relocate(fixture: &mut Fixture, evidence: &mut Evidence, continuity: &mut Continuity) {
    let old_config = fixture.dir.0.join("before-restore-server.json");
    fs::copy(fixture.dir.0.join("server.json"), &old_config).unwrap();
    let anchor = evidence.configured(fixture, "midpoint-policy-anchor", "policy-status", &[]);
    let source = continuity.server.clone();
    let backup_path = evidence.root.join("midpoint-backup");
    let backup = evidence.command(
        "midpoint-backup",
        &[
            "backup-state".into(),
            "--state".into(),
            source.clone().into_os_string(),
            "--backup".into(),
            backup_path.clone().into_os_string(),
        ],
        true,
    );
    let pin = backup["manifest_sha256"].as_str().unwrap();
    let verified = evidence.command(
        "midpoint-verify",
        &[
            "verify-backup".into(),
            "--backup".into(),
            backup_path.clone().into_os_string(),
            "--manifest-sha256".into(),
            pin.into(),
        ],
        true,
    );
    let target = evidence.root.join("owners/server-restored");
    let restored = evidence.command(
        "midpoint-restore",
        &[
            "restore-state".into(),
            "--backup".into(),
            backup_path.into_os_string(),
            "--manifest-sha256".into(),
            pin.into(),
            "--state".into(),
            target.clone().into_os_string(),
        ],
        true,
    );
    fixture.server["state"] = json!(target);
    fixture.save();
    let blocked = evidence.output(
        "midpoint-unreviewed-peers",
        configured_command(fixture, "server.json", "peers", &[]),
        false,
    );
    let moved = evidence.root.join("owners/server-pre-restore");
    assert!(
        source.starts_with(&evidence.root) && moved.starts_with(&evidence.root) && !moved.exists()
    );
    fs::rename(&source, &moved).unwrap();
    let activation = evidence.configured(
        fixture,
        "midpoint-reviewed-relocation",
        "policy-transition",
        &[
            "--previous-config",
            old_config.to_str().unwrap(),
            "--expected-policy",
            anchor["policy_sha256"].as_str().unwrap(),
            "--expected-head",
            anchor["journal_head_sha256"].as_str().unwrap(),
            "--reason",
            "fixed midpoint soak backup relocation",
            "--review-relocation",
        ],
    );
    assert_eq!(
        activation["relocation"]["restore_mapping_sha256"],
        restored["restore_mapping_sha256"]
    );
    assert!(!source.exists());
    continuity.server = target;
    evidence.report["current_server_state"] = json!("owners/server-restored");
    let pending = evidence.report["lost_reply"]["candidate"].as_str().unwrap();
    assert_eq!(
        payloads(&continuity.server.join("operations.jsonl"))
            .iter()
            .filter(
                |event| event["event"] == "evaluation_rejected" && event["candidate_id"] == pending
            )
            .count(),
        1
    );
    evidence.public_policy(fixture, "midpoint-restored");
    evidence.report["midpoint_restore"] = json!({"after_cycle":evidence.mode.restore,"backup":backup,"verification":verified,"restore":restored,
        "unreviewed_activation":blocked,"activation":activation,"old_source_absent":!source.exists(),"pending_lost_candidate_rejected":pending,"new_learning_promotions":0});
}

fn wait_slot(
    service: &mut ServiceProcess,
    due: Instant,
    mode: Mode,
    evidence: &mut Evidence,
    cycle: usize,
) -> (u128, u64) {
    let mut previous = Instant::now();
    let mut maximum = 0;
    let mut polls = 0;
    let mut logged = None::<Instant>;
    loop {
        let now = Instant::now();
        maximum = maximum.max(now.duration_since(previous).as_millis());
        previous = now;
        assert!(
            service.child.try_wait().unwrap().is_none(),
            "owned listener exited during idle"
        );
        polls += 1;
        if logged.is_none_or(|last| now.duration_since(last) >= Duration::from_secs(1))
            || now >= due
        {
            evidence.event_at(
                "listener-alive",
                json!({"cycle":cycle,"pid":service.child.id()}),
                now,
            );
            logged = Some(now);
        }
        assert!(maximum <= 5000, "observed idle poll gap exceeded5seconds");
        if now >= due {
            if mode.spacing_ms > 0 {
                assert!(
                    now.duration_since(due) <= Duration::from_secs(5),
                    "missed fixed slot; no catchup"
                );
            }
            break;
        }
        thread::sleep(Duration::from_millis(100).min(due.duration_since(now)));
    }
    (maximum, polls)
}

fn campaign(fixture: &mut Fixture, evidence: &mut Evidence) {
    let mode = evidence.mode;
    let mut continuity = initialize(fixture, evidence);
    assert!(
        evidence.started.elapsed() < Duration::from_secs(60),
        "initial setup budget"
    );
    let mut service = evidence.start(fixture, "main-initial");
    let anchor = evidence.active_ready.as_ref().unwrap().1;
    let origin_ms = anchor.duration_since(evidence.started).as_millis();
    evidence.report["measurement_started_elapsed_ms"] = json!(origin_ms);
    evidence.report["schedule"] = json!({"spacing_ms":mode.spacing_ms,"window_ms":mode.window_ms,"rotations":mode.rotations,"denials":mode.denials,"lost_cycle":mode.lost,"restore_after":mode.restore,"late_limit_ms":5000,"maintenance_gap_limit_ms":20000});
    evidence.report["maintenance_gaps"] = json!([]);
    let mut stale_pin = None;
    let mut max_poll = 0;
    let mut polls = 0u64;
    for cycle in 1..=mode.cycles {
        let due_ms = mode.spacing_ms * cycle as u64;
        let (gap, count) = wait_slot(
            &mut service,
            anchor + Duration::from_millis(due_ms),
            mode,
            evidence,
            cycle,
        );
        max_poll = max_poll.max(gap);
        polls += count;
        let mut started_ms = None;
        let ready = service.ready.clone();
        if let Some(pin) = stale_pin.take() {
            let mut endpoint = fixture.endpoint("affine-context/v1", "knowledge.predict");
            endpoint.server_name = fixture.client["peers"][0]["server_name"]
                .as_str()
                .unwrap()
                .into();
            endpoint.server_certificate_sha256 = pin;
            let before = fs::read(continuity.server.join("operations.jsonl")).unwrap();
            let error = SecureClient::connect(&endpoint, &fixture.direct_client(&fixture.ids[1]))
                .err()
                .expect("old leaf pin must be rejected");
            assert!(
                error.to_lowercase().contains("pin")
                    || error.to_lowercase().contains("certificate"),
                "stale pin failed at unrelated stage: {error}"
            );
            assert_eq!(
                fs::read(continuity.server.join("operations.jsonl")).unwrap(),
                before
            );
            evidence.report["credential_rotations"]
                .as_array_mut()
                .unwrap()
                .last_mut()
                .unwrap()["stale_pin_rejection"] = json!({"before_cycle":cycle,"error":error,"journal_sha256":hash(&before),"application_mutation":false});
        }
        let mut responses = Vec::new();
        for (index, (scope, input, expected)) in [
            (
                "affine-context/v1",
                ((cycle - 1) % 8) as u16,
                ((((cycle - 1) % 8) & 3).count_ones() % 2) as u8,
            ),
            (
                "graph-context/v1",
                [1u16, 2, 5][(cycle - 1) % 3],
                [1u8, 3, 2][(cycle - 1) % 3],
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let id = &continuity.ids[index];
            for (operation, body) in [
                ("read", json!({"operation":"knowledge.read","artifact":id})),
                (
                    "predict",
                    json!({"operation":"knowledge.predict","artifact":id,"input":input}),
                ),
            ] {
                let request =
                    fixture.request(scope, &format!("soak-{cycle:03}-{index}-{operation}"), body);
                let reply = evidence.api(
                    fixture,
                    &format!("cycle-{cycle}-{index}-{operation}"),
                    &request,
                    false,
                );
                if started_ms.is_none() {
                    started_ms = Some(evidence.last_request_ms - origin_ms);
                }
                if operation == "read" {
                    let record: KnowledgeRecord =
                        serde_json::from_value(reply["record"].clone()).unwrap();
                    assert_eq!(record.digest().unwrap(), continuity.digests[index]);
                } else {
                    assert_eq!(reply["prediction"], expected);
                    assert_eq!(reply["conditional"], true);
                    assert_eq!(reply["physical_certificate_authorized"], false);
                }
                responses.push(json!({"request":request,"response":reply}));
            }
        }
        let started_ms = started_ms.unwrap();
        let finished_ms = evidence.last_event_ms - origin_ms;
        if mode.spacing_ms > 0 {
            assert!(
                (due_ms as u128..=due_ms as u128 + 5000).contains(&started_ms),
                "first actual request missed fixed slot"
            );
        }
        if cycle == mode.lost {
            let maintenance = Instant::now();
            service = lost_reply(fixture, evidence, &mut service);
            let elapsed = maintenance.elapsed().as_millis();
            assert!(elapsed <= 20000, "crash maintenance gap");
            let observed_gap = evidence
                .active_ready
                .as_ref()
                .unwrap()
                .1
                .duration_since(evidence.started)
                .as_millis()
                - evidence.last_stop_ms;
            evidence.report["maintenance_gaps"]
                .as_array_mut()
                .unwrap()
                .push(
                    json!({"after_cycle":cycle,"reason":"lost-reply-crash","elapsed_ms":observed_gap}),
                );
        }
        let witness = continuity.check();
        evidence.report["cycles"].as_array_mut().unwrap().push(json!({"cycle":cycle,"due_ms":due_ms,"started_ms":started_ms,"finished_ms":finished_ms,"ready":ready,"responses":responses,"continuity":witness,"idle_poll_count":count,"max_idle_poll_gap_ms":gap}));
        evidence.report["cycles_completed"] = json!(cycle);
        evidence.event("cycle-completed",json!({"cycle":cycle,"models_retained":2,"measurement_ms":anchor.elapsed().as_millis()}));
        if mode.rotations.contains(&cycle) || mode.denials.contains(&cycle) || cycle == mode.restore
        {
            let maintenance = Instant::now();
            evidence.stopped(&mut service, &format!("maintenance-{cycle}"));
            continuity.verify_offline();
            if mode.rotations.contains(&cycle) {
                stale_pin = Some(rotate(fixture, evidence, cycle));
            }
            if mode.denials.contains(&cycle) {
                denial(fixture, evidence, cycle);
            }
            if cycle == mode.restore {
                relocate(fixture, evidence, &mut continuity);
            }
            continuity.check();
            continuity.verify_offline();
            service = evidence.start(fixture, &format!("after-maintenance-{cycle}"));
            let elapsed = maintenance.elapsed().as_millis();
            assert!(elapsed <= 20000, "planned maintenance gap");
            let observed_gap = evidence
                .active_ready
                .as_ref()
                .unwrap()
                .1
                .duration_since(evidence.started)
                .as_millis()
                - evidence.last_stop_ms;
            evidence.report["maintenance_gaps"]
                .as_array_mut()
                .unwrap()
                .push(
                    json!({"after_cycle":cycle,"reason":"operator-lifecycle","elapsed_ms":observed_gap}),
                );
        }
    }
    let finish = Instant::now();
    evidence.stopped(&mut service, "measurement-final");
    evidence.report["measurement_elapsed_ms"] = json!(evidence.last_event_ms - origin_ms);
    continuity.verify_offline();
    assert_eq!(evidence.keys.len(), mode.keys());
    assert_eq!(
        evidence.report["credential_rotations"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    assert_eq!(evidence.report["denials"].as_array().unwrap().len(), 2);
    assert_eq!(evidence.report["service_starts"], EXPECTED_STARTS);
    assert_eq!(evidence.report["owned_stops"], EXPECTED_STARTS);
    assert!(!fixture.dir.0.join("MUST-NOT-EXECUTE").exists());
    if mode.window_ms > 0 {
        assert!(anchor.elapsed() >= Duration::from_millis(mode.window_ms));
        assert!(
            evidence.main_span_ms >= 3_540_000,
            "nonvacuous live listener spans"
        );
    }
    evidence.report["final_continuity"] = continuity.check();
    evidence.report["identity_and_model_continuity"] = json!(true);
    evidence.report["max_idle_poll_gap_ms"] = json!(max_poll);
    evidence.report["idle_poll_count"] = json!(polls);
    evidence.report["stale_tls_probe_attempts"] = json!(4);
    evidence.report["qualification"] = json!(if mode.window_ms > 0 {
        "ONE_HOST_BOUNDED_HOUR"
    } else {
        "NOT_HOUR_QUALIFIED"
    });
    assert!(
        finish.elapsed() < Duration::from_secs(60),
        "final verification budget"
    );
    evidence.assert_native();
}

fn execute_mode(mode: Mode) {
    let mut evidence = Evidence::new(mode);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        for config in [&mut fixture.server, &mut fixture.client] {
            config["limits"]["max_requests"] = json!(1024);
            config["limits"]["max_connections"] = json!(1024);
            config["limits"]["per_peer_requests"] = json!(1024);
            config["limits"]["lifetime_ms"] = json!(600000);
        }
        fixture.save();
        campaign(&mut fixture, &mut evidence);
    }));
    let failure = outcome.err().map(|error| {
        error
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| error.downcast_ref::<&str>().map(|v| v.to_string()))
            .unwrap_or_else(|| "native soak panic without string payload".into())
    });
    evidence.finish(failure.clone());
    assert!(
        failure.is_none(),
        "soak HOLD; evidence at{}",
        evidence.root.display()
    );
}

#[test]
#[ignore = "once-only registered hour; never ordinary test discovery"]
fn hour_120_cycle_local_soak() {
    execute_mode(Mode::hour());
}

#[test]
#[ignore = "separate engineering fixture; never qualifies an hour"]
fn short_local_soak_fixture() {
    execute_mode(Mode::fixture());
}

#[test]
fn schedule_is_a_full_hour_with_distinct_fixture_and_bounded_lifetime_segments() {
    let hour = Mode::hour();
    assert_eq!(hour.cycles as u64 * hour.spacing_ms, 3_600_000);
    assert_eq!(hour.keys(), 483);
    assert_eq!(hour.rotations, [18, 38, 78, 101]);
    assert_eq!(Mode::fixture().keys(), 51);
    assert_eq!(Mode::fixture().window_ms, 0);
    let points = [0, 18, 30, 38, 50, 60, 78, 90, 101, 120];
    assert!(points.windows(2).all(|p| (p[1] - p[0]) * 30 <= 570));
}
