//! Explicitly selected local continuity campaign. Never run by normal tests.
//! The two learned fixtures remain fixed; cycles are endurance observations.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Mutex;

const CYCLES: usize = 24;
const EXPECTED_KEYS: usize = 99;
const EXPECTED_STARTS: u64 = 26;

struct Evidence {
    root: PathBuf,
    events: File,
    sequence: usize,
    keys: BTreeSet<(String, String)>,
    report: Value,
    started: Instant,
}
impl Evidence {
    fn new() -> Self {
        let requested = PathBuf::from(
            std::env::var_os("SYMBIOTE_ENDURANCE_ARTIFACTS")
                .expect("explicit runner-owned endurance artifact directory required"),
        );
        assert!(requested.is_absolute());
        let parent = fs::canonicalize(requested.parent().unwrap()).unwrap();
        assert!(parent.starts_with(fs::canonicalize(std::env::temp_dir()).unwrap()));
        let root = parent.join(requested.file_name().unwrap());
        assert!(
            !root.exists(),
            "endurance output must be fresh, even if empty"
        );
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
            "schema":"symbiote.local-endurance/1", "version":env!("CARGO_PKG_VERSION"),
            "status":"HOLD", "cycles_expected":CYCLES, "cycles_completed":0,
            "request_keys_expected":EXPECTED_KEYS, "request_keys_recorded":0,
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
        };
        result.event("started", json!({"native_binary_sha256":result.report["native_binary_sha256"],"test_binary_sha256":result.report["test_binary_sha256"]}));
        result
    }
    fn write(&self, relative: &str, bytes: &[u8]) {
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
        let row = json!({"sequence":self.sequence,"kind":kind,"elapsed_ms":self.started.elapsed().as_millis(),"data":value});
        let mut bytes = serde_json::to_vec(&row).unwrap();
        bytes.push(b'\n');
        self.events.write_all(&bytes).unwrap();
        self.events.sync_all().unwrap();
        self.sequence += 1;
    }
    fn output(&mut self, label: &str, output: Output, expect_success: bool) -> Value {
        let prefix = format!("outputs/{:04}-{label}", self.sequence);
        let stdout = format!("{prefix}.stdout");
        let stderr = format!("{prefix}.stderr");
        self.write(&stdout, &output.stdout);
        self.write(&stderr, &output.stderr);
        let value = json!({"label":label,"exit_code":output.status.code(),"success":output.status.success(),
            "stdout":stdout,"stdout_sha256":hash(&output.stdout),"stderr":stderr,"stderr_sha256":hash(&output.stderr)});
        self.event("native-command", value.clone());
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
        let output = Command::new(env!("CARGO_BIN_EXE_symbiote"))
            .args(args)
            .arg("--json")
            .output()
            .unwrap();
        self.output(label, output, expect_success)
    }
    fn configured(
        &mut self,
        fixture: &Fixture,
        label: &str,
        command: &str,
        args: &[&str],
    ) -> Value {
        self.output(label, fixture.command(command, args), true)
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
        assert!(self.keys.len() <= EXPECTED_KEYS);
    }
    fn api(&mut self, fixture: &Fixture, label: &str, request: &Value, duplicate: bool) -> Value {
        self.request_key(request, duplicate);
        self.event(
            "tls-request",
            json!({"label":label,"request":request,"explicit_duplicate":duplicate}),
        );
        let reply = self.output(label, fixture.call(request), true);
        self.event("tls-response", json!({"label":label,"response":reply}));
        reply
    }
    fn start(&mut self, fixture: &Fixture, label: &str) -> ServiceProcess {
        self.assert_native();
        let service = ServiceProcess::start(fixture);
        assert_eq!(service.ready["identity"], fixture.ids[0]);
        assert_eq!(
            service.ready["pid"].as_u64(),
            Some(u64::from(service.child.id()))
        );
        assert_ne!(service.child.id(), std::process::id());
        self.report["service_starts"] = json!(self.report["service_starts"].as_u64().unwrap() + 1);
        self.event("owned-listener-started",json!({"label":label,"spawn_ordinal":self.report["service_starts"],"ready":service.ready}));
        service
    }
    fn stopped(&mut self, service: &mut ServiceProcess, label: &str) -> Value {
        let result = service.stop();
        assert_eq!(result["identity"], self.report["owner_identities"][0]);
        assert_eq!(service.child.try_wait().unwrap().unwrap().code(), Some(0));
        self.report["owned_stops"] = json!(self.report["owned_stops"].as_u64().unwrap() + 1);
        self.event(
            "owned-listener-stopped",
            json!({"label":label,"pid":service.child.id(),"stop":result,"exit_code":0}),
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
            "endurance-report.json",
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
        "unexpected owner sidecar is not an allowlisted endurance artifact"
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
        json!({"server_owner_sha256":hash(&self.server_owner),"client_owner_sha256":hash(&self.client_owner),
            "knowledge_sha256":hash(&self.knowledge),"server_operations_sha256":hash(&self.server_ops),
            "client_operations_sha256":hash(&self.client_ops),"server_operation_records":self.server_ops.iter().filter(|v|**v==b'\n').count(),
            "model_digests":self.digests,"models_retained":active.len()})
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
    let name = if [4, 16].contains(&after) {
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
                "explicit endurance server-leaf pin rotation",
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
            "fixed endurance containment checkpoint",
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
            "fixed endurance reviewed regrant",
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
    request["request_id"] = json!("endurance-lost-submit-10");
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
        *writer.lock().map_err(|_| "endurance witness unavailable")? = Some(reply.clone());
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
    assert!(!exit.success());
    service.input.take();
    evidence.report["owned_stops"] = json!(evidence.report["owned_stops"].as_u64().unwrap() + 1);
    evidence.event(
        "owned-listener-killed-and-joined",
        json!({"cycle":10,"pid":pid,"exit_code":exit.code(),"joined":true}),
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
    let restarted = evidence.start(fixture, "cycle-10-after-owned-crash");
    let retried = evidence.api(fixture, "lost-submit-exact-retry", &request, true);
    assert_eq!(retried, expected);
    assert_eq!(fs::read(&path).unwrap(), before);
    evidence.report["lost_reply"] = json!({"cycle":10,"request":request,"first_call_error":error,"committed_response":expected,
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
        fixture.command("peers", &[]),
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
            "fixed midpoint endurance backup relocation",
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
    evidence.report["midpoint_restore"] = json!({"after_cycle":12,"backup":backup,"verification":verified,"restore":restored,
        "unreviewed_activation":blocked,"activation":activation,"old_source_absent":!source.exists(),"pending_lost_candidate_rejected":pending,"new_learning_promotions":0});
}

fn campaign(fixture: &mut Fixture, evidence: &mut Evidence) {
    let mut continuity = initialize(fixture, evidence);
    let mut stale_pin = None;
    for cycle in 1..=CYCLES {
        let mut service = evidence.start(fixture, &format!("cycle-{cycle}"));
        if let Some(pin) = stale_pin.take() {
            let mut endpoint = fixture.endpoint("affine-context/v1", "knowledge.predict");
            endpoint.server_name = fixture.client["peers"][0]["server_name"]
                .as_str()
                .unwrap()
                .into();
            endpoint.server_certificate_sha256 = pin;
            let before = fs::read(continuity.server.join("operations.jsonl")).unwrap();
            let rejected =
                SecureClient::connect(&endpoint, &fixture.direct_client(&fixture.ids[1]))
                    .err()
                    .expect("old leaf pin must fail");
            assert_eq!(
                fs::read(continuity.server.join("operations.jsonl")).unwrap(),
                before
            );
            evidence.report["credential_rotations"]
                .as_array_mut()
                .unwrap()
                .last_mut()
                .unwrap()["stale_pin_rejection"] = json!({"before_cycle":cycle,"error":rejected,"journal_sha256":hash(&before),"application_mutation":false});
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
                let request = fixture.request(
                    scope,
                    &format!("endurance-{cycle:02}-{index}-{operation}"),
                    body,
                );
                let reply = evidence.api(
                    fixture,
                    &format!("cycle-{cycle}-{index}-{operation}"),
                    &request,
                    false,
                );
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
        if cycle == 10 {
            service = lost_reply(fixture, evidence, &mut service);
        }
        let ready = service.ready.clone();
        let stopped = evidence.stopped(&mut service, &format!("cycle-{cycle}"));
        let witness = continuity.check();
        evidence.report["cycles"].as_array_mut().unwrap().push(json!({"cycle":cycle,"ready":ready,"responses":responses,"stop":stopped,"continuity":witness}));
        evidence.report["cycles_completed"] = json!(cycle);
        evidence.event(
            "cycle-completed",
            json!({"cycle":cycle,"models_retained":2}),
        );
        if [4, 8, 16, 20].contains(&cycle) {
            stale_pin = Some(rotate(fixture, evidence, cycle));
        }
        if [6, 18].contains(&cycle) {
            denial(fixture, evidence, cycle);
        }
        if cycle == 12 {
            relocate(fixture, evidence, &mut continuity);
        }
        continuity.check();
    }
    assert_eq!(evidence.keys.len(), EXPECTED_KEYS);
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
    let final_state = continuity.check();
    evidence.report["final_continuity"] = final_state;
    evidence.report["identity_and_model_continuity"] = json!(true);
    evidence.assert_native();
}

#[test]
#[ignore = "registered fixed local endurance campaign; select explicitly after source/protocol freeze"]
fn mixed_family_24_cycle_local_campaign() {
    let mut evidence = Evidence::new();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        campaign(&mut fixture, &mut evidence);
    }));
    let failure = outcome.err().map(|error| {
        error
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| error.downcast_ref::<&str>().map(|v| v.to_string()))
            .unwrap_or_else(|| "native test panic without string payload".into())
    });
    evidence.finish(failure.clone());
    assert!(
        failure.is_none(),
        "endurance HOLD; preserved evidence at {}",
        evidence.root.display()
    );
}
