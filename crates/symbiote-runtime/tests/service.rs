use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};
use symbiote_memory::knowledge::graph::graph_schema_fingerprint;
use symbiote_memory::{
    knowledge::{affine_schema_fingerprint, KnowledgeRecord, KnowledgeStore},
    Store,
};
use symbiote_protocol::{
    spawn_secure_server, SecureClient, SecureEndpoint, SecureLimits, SecurePeerGrant,
    SecureServerConfig, TlsClientConfig, TlsIdentity,
};
use symbiote_reasoning::planning::{Edge, GraphSchema};

#[path = "service/cognitive.rs"]
mod cognitive;
#[path = "service/endurance.rs"]
mod endurance;
#[path = "service/outcomes.rs"]
mod outcomes;
#[path = "service/soak.rs"]
mod soak;

static NEXT: AtomicU64 = AtomicU64::new(0);
// These integration tests launch native services with real 500ms I/O and 15s
// lifetimes. Bound test groups rather than widening production limits on hosts
// where the test runner starts many groups at once. Nested fixtures on the same
// test thread share a slot, so a test can own several peers without deadlocking.
static NATIVE_FIXTURE_GROUPS: Mutex<usize> = Mutex::new(0);
static NATIVE_FIXTURE_READY: Condvar = Condvar::new();
thread_local! {
    static NATIVE_FIXTURE_SLOT: std::cell::RefCell<Weak<NativeFixtureSlot>> = const { std::cell::RefCell::new(Weak::new()) };
}
struct NativeFixtureSlot;
impl Drop for NativeFixtureSlot {
    fn drop(&mut self) {
        let mut active = NATIVE_FIXTURE_GROUPS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *active = active.checked_sub(1).expect("fixture slot accounting");
        NATIVE_FIXTURE_READY.notify_one();
    }
}
fn native_fixture_slot() -> Arc<NativeFixtureSlot> {
    NATIVE_FIXTURE_SLOT.with(|current| {
        if let Some(slot) = current.borrow().upgrade() {
            return slot;
        }
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut active = NATIVE_FIXTURE_GROUPS.lock().unwrap();
        while *active >= 2 {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("native fixture group admission exceeded its test-only bound");
            let (next, _) = NATIVE_FIXTURE_READY
                .wait_timeout(active, remaining)
                .unwrap();
            active = next;
        }
        *active += 1;
        drop(active);
        let slot = Arc::new(NativeFixtureSlot);
        *current.borrow_mut() = Arc::downgrade(&slot);
        slot
    })
}
#[test]
fn nested_native_fixtures_share_a_slot_and_release_it_after_the_last_owner() {
    let first = native_fixture_slot();
    let nested = native_fixture_slot();
    assert!(Arc::ptr_eq(&first, &nested));
    drop(first);
    assert!(NATIVE_FIXTURE_SLOT.with(|slot| slot.borrow().upgrade().is_some()));
    drop(nested);
    assert!(NATIVE_FIXTURE_SLOT.with(|slot| slot.borrow().upgrade().is_none()));
}
thread_local! {
    static COGNITION_BINARY: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}
fn native_binary() -> PathBuf {
    COGNITION_BINARY
        .with(|selected| selected.borrow().clone())
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_symbiote")))
}
struct CognitionBinaryGuard(Option<PathBuf>);
impl Drop for CognitionBinaryGuard {
    fn drop(&mut self) {
        COGNITION_BINARY.with(|selected| *selected.borrow_mut() = self.0.take());
    }
}
fn cognition_binary_override() -> CognitionBinaryGuard {
    let selected = std::env::var_os("SYMBIOTE_COGNITION_TEST_BINARY").map(|path| {
        let path = fs::canonicalize(path).expect("explicit public cognition binary must exist");
        assert!(
            path.is_file(),
            "public cognition binary must be a regular file"
        );
        path
    });
    CognitionBinaryGuard(COGNITION_BINARY.with(|current| current.replace(selected)))
}
#[test]
fn cognition_binary_selection_cannot_change_another_fixture_thread() {
    let original = native_binary();
    let selected = original.with_file_name("thread-local-only-placeholder");
    let guard = CognitionBinaryGuard(
        COGNITION_BINARY.with(|current| current.replace(Some(selected.clone()))),
    );
    assert_eq!(native_binary(), selected);
    let other = thread::spawn(native_binary).join().unwrap();
    assert_eq!(other, PathBuf::from(env!("CARGO_BIN_EXE_symbiote")));
    drop(guard);
    assert_eq!(native_binary(), original);
}
const OPS: &[&str] = &[
    "capabilities",
    "knowledge.list",
    "knowledge.read",
    "knowledge.predict",
    "candidate.submit",
    "candidate.status",
];
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "symbiote-service-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn private_ip() -> IpAddr {
    if let Ok(value) = std::env::var("SYMBIOTE_TEST_PRIVATE_IP") {
        let address: Ipv4Addr = value.parse().unwrap();
        assert!(address.is_private());
        return IpAddr::V4(address);
    }
    let probe = UdpSocket::bind("0.0.0.0:0").unwrap();
    // UDP connect selects the local route without transmitting any packet.
    probe.connect("192.0.2.1:9").unwrap();
    let address = probe.local_addr().unwrap().ip();
    assert!(matches!(address,IpAddr::V4(ip) if ip.is_private()),"non-loopback gate requires an explicitly available private interface; set SYMBIOTE_TEST_PRIVATE_IP");
    address
}
fn unused_address(ip: IpAddr) -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::new(ip, 0)).unwrap();
    listener.local_addr().unwrap()
}
fn graph() -> GraphSchema {
    GraphSchema {
        nodes: 3,
        edges: vec![
            Edge {
                from: 0,
                to: 1,
                lower: 1,
                upper: 9,
            },
            Edge {
                from: 1,
                to: 2,
                lower: 1,
                upper: 9,
            },
            Edge {
                from: 0,
                to: 2,
                lower: 1,
                upper: 9,
            },
        ],
    }
}

struct Fixture {
    dir: Directory,
    server: Value,
    client: Value,
    ids: [String; 2],
    _native_slot: Arc<NativeFixtureSlot>,
}
impl Fixture {
    fn new(ip: IpAddr) -> Self {
        let native_slot = native_fixture_slot();
        let dir = Directory::new();
        let ids = ["server-state", "client-state"].map(|name| {
            let store = Store::open(&dir.0.join(name)).unwrap();
            store.identity().to_string()
        });
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate().unwrap();
        let ca = params.self_signed(&key).unwrap();
        let issuer = rcgen::Issuer::from_params(&params, key);
        fs::write(dir.0.join("ca.pem"), ca.pem()).unwrap();
        let mut pins = Vec::new();
        for role in ["server", "client", "observer"] {
            let mut params = CertificateParams::new(vec![format!("{role}.symbiote.test")]).unwrap();
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            let key = KeyPair::generate().unwrap();
            let certificate = params.signed_by(&key, &issuer).unwrap();
            let cert = certificate.pem();
            let private_key = key.serialize_pem();
            pins.push(
                TlsIdentity::from_pem(cert.as_bytes(), private_key.as_bytes())
                    .unwrap()
                    .certificate_sha256()
                    .to_string(),
            );
            fs::write(dir.0.join(format!("{role}.pem")), cert).unwrap();
            fs::write(dir.0.join(format!("{role}.key")), private_key).unwrap();
        }
        let affine = json!({"schema":"symbiote.local-truth/1","scope":"affine-context/v1","family":{"kind":"affine","width":3,"outputs":(0..8u16).map(|input|((input&3).count_ones()%2)as u8).collect::<Vec<_>>()}});
        let graph_truth = json!({"schema":"symbiote.local-truth/1","scope":"graph-context/v1","family":{"kind":"graph","schema":graph(),"costs":[1,2,5]}});
        let mut contexts = Vec::new();
        for (name, scope, fingerprint, fixture) in [
            (
                "affine",
                "affine-context/v1",
                affine_schema_fingerprint(3).unwrap(),
                affine,
            ),
            (
                "graph",
                "graph-context/v1",
                graph_schema_fingerprint(&graph()).unwrap(),
                graph_truth,
            ),
        ] {
            let bytes = serde_json::to_vec(&fixture).unwrap();
            fs::write(dir.0.join(format!("{name}-truth.json")), &bytes).unwrap();
            contexts.push(json!({"scope":scope,"schema_fingerprint":fingerprint,"truth_fixture":format!("{name}-truth.json"),"truth_sha256":hash(&bytes)}));
        }
        let addresses = [unused_address(ip), unused_address(ip)];
        let create = |index: usize| {
            let role = if index == 0 { "server" } else { "client" };
            let other = 1 - index;
            let other_role = if other == 0 { "server" } else { "client" };
            json!({"schema":"symbiote.service-config/1","state":format!("{role}-state"),"identity":ids[index],"certificate":format!("{role}.pem"),"private_key":format!("{role}.key"),"certificate_sha256":pins[index],"ca_certificate":"ca.pem","bind_address":addresses[index],"peers":[{"alias":"partner","id":ids[other],"address":addresses[other],"server_name":format!("{other_role}.symbiote.test"),"certificate_sha256":pins[other],"access":contexts.iter().map(|context|json!({"scope":context["scope"],"operations":OPS,"artifacts":["*"]})).collect::<Vec<_>>()}],"contexts":contexts,"limits":{"max_requests":64,"max_connections":64,"max_frame_bytes":32768,"timeout_ms":500,"lifetime_ms":15000,"per_peer_requests":64,"max_offers":16,"max_offer_bytes":16384,"model_work":200000}})
        };
        let fixture = Self {
            server: create(0),
            client: create(1),
            dir,
            ids,
            _native_slot: native_slot,
        };
        fixture.save();
        fixture
    }
    fn save(&self) {
        for (name, config) in [("server", &self.server), ("client", &self.client)] {
            fs::write(
                self.dir.0.join(format!("{name}.json")),
                serde_json::to_vec_pretty(config).unwrap(),
            )
            .unwrap();
        }
    }
    fn command(&self, command: &str, args: &[&str]) -> Output {
        Command::new(native_binary())
            .args([command, "--json", "--config"])
            .arg(self.dir.0.join("server.json"))
            .args(args)
            .output()
            .unwrap()
    }
    fn request(&self, scope: &str, id: &str, body: Value) -> Value {
        json!({"schema":"symbiote.service-request/1","scope":scope,"request_id":id,"body":body})
    }
    fn call(&self, request: &Value) -> Output {
        let path = self.dir.0.join("request.json");
        fs::write(&path, serde_json::to_vec(request).unwrap()).unwrap();
        Command::new(native_binary())
            .args(["connect", "--json", "--config"])
            .arg(self.dir.0.join("client.json"))
            .args(["--peer", "partner", "--request"])
            .arg(path)
            .output()
            .unwrap()
    }
    fn offer(&self, graph_map: bool) -> Value {
        let record = if graph_map {
            KnowledgeRecord {
                id: "upstream-graph".into(),
                revision: 1,
                source: "claimed-origin-is-untrusted".into(),
                scope: "graph-context/v1".into(),
                schema_fingerprint: graph_schema_fingerprint(&graph()).unwrap(),
                payload: json!({"kind":"graph-map","schema":graph(),"observations":[{"edge_id":0,"cost":1},{"edge_id":1,"cost":2},{"edge_id":2,"cost":5}]}),
                provenance: "inert native graph map".into(),
            }
        } else {
            KnowledgeRecord {
                id: "upstream-affine".into(),
                revision: 1,
                source: "claimed-origin-is-untrusted".into(),
                scope: "affine-context/v1".into(),
                schema_fingerprint: affine_schema_fingerprint(3).unwrap(),
                payload: json!({"kind":"affine","width":3,"coefficients":3,"bias":false}),
                provenance: format!(
                    "inert text: powershell New-Item {}",
                    self.dir.0.join("MUST-NOT-EXECUTE").display()
                ),
            }
        };
        self.request(&record.scope,if graph_map{"offer-graph"}else{"offer-affine"},json!({"operation":"candidate.submit","offer":{"record":record,"training_inputs":if graph_map{vec![1u16]}else{vec![0,1,2,4]}}}))
    }
    fn direct_client(&self, id: &str) -> TlsClientConfig {
        TlsClientConfig::new(
            id.into(),
            TlsIdentity::from_pem_files(
                &self.dir.0.join("client.pem"),
                &self.dir.0.join("client.key"),
            )
            .unwrap(),
            &fs::read(self.dir.0.join("ca.pem")).unwrap(),
        )
        .unwrap()
    }
    fn endpoint(&self, scope: &str, operation: &str) -> SecureEndpoint {
        SecureEndpoint {
            server_id: self.ids[0].clone(),
            address: self.server["bind_address"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            server_name: "server.symbiote.test".into(),
            server_certificate_sha256: self.server["certificate_sha256"].as_str().unwrap().into(),
            scope: scope.into(),
            operations: vec![operation.into()],
            limits: SecureLimits {
                max_requests: 64,
                max_connections: 64,
                max_frame_bytes: 32768,
                timeout: Duration::from_millis(500),
            },
        }
    }
}
fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn rejected(output: Output) -> Value {
    assert!(!output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["status"], "REJECTED");
    response
}
struct ServiceProcess {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    ready: Value,
}
impl ServiceProcess {
    fn start(fixture: &Fixture) -> Self {
        Self::start_config(&fixture.dir.0.join("server.json"))
    }
    fn start_config(path: &Path) -> Self {
        let mut child = Command::new(native_binary())
            .args(["serve", "--json", "--config"])
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        assert!(!line.is_empty(), "service exited before readiness: {}", {
            let mut text = String::new();
            child
                .stderr
                .as_mut()
                .unwrap()
                .read_to_string(&mut text)
                .unwrap();
            text
        });
        let ready: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(ready["schema"], "symbiote.service-ready/1");
        Self {
            child,
            input,
            output,
            ready,
        }
    }
    fn stop(&mut self) -> Value {
        if let Some(mut input) = self.input.take() {
            if self.child.try_wait().unwrap().is_none() {
                input.write_all(b"{\"command\":\"shutdown\"}\n").unwrap();
            }
        }
        let deadline = Instant::now() + Duration::from_secs(4);
        while self.child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            self.child.try_wait().unwrap().is_some(),
            "owned service missed shutdown bound"
        );
        let status = self.child.wait().unwrap();
        let mut errors = String::new();
        self.child
            .stderr
            .as_mut()
            .unwrap()
            .read_to_string(&mut errors)
            .unwrap();
        assert!(status.success(), "{errors}");
        let mut receipt = String::new();
        self.output.read_to_string(&mut receipt).unwrap();
        serde_json::from_str(&receipt).unwrap()
    }
}
impl Drop for ServiceProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            if let Some(mut input) = self.input.take() {
                let _ = input.write_all(b"{\"command\":\"shutdown\"}\n");
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
            }
            let _ = self.child.wait();
        }
    }
}

#[test]
fn configured_private_ip_service_quarantines_then_locally_evaluates_native_affine_and_graph() {
    let fixture = Fixture::new(private_ip());
    let mut service = ServiceProcess::start(&fixture);
    assert_ne!(service.ready["pid"], std::process::id());
    assert!(!fixture
        .endpoint("affine-context/v1", "capabilities")
        .address
        .ip()
        .is_loopback());
    let mut candidates = Vec::new();
    for graph_map in [false, true] {
        let request = fixture.offer(graph_map);
        let receipt = success(fixture.call(&request));
        assert_eq!(receipt["status"], "QUARANTINED");
        assert_eq!(receipt["promoted"], false);
        assert_eq!(
            success(fixture.call(&request)),
            receipt,
            "repeated canonical request returns identical receipt"
        );
        candidates.push(receipt["candidate"].as_str().unwrap().to_string());
    }
    assert!(!fixture.dir.0.join("MUST-NOT-EXECUTE").exists());
    assert!(
        !fixture
            .command("evaluate", &["--candidate", &candidates[0]])
            .status
            .success(),
        "offline evaluation must not acquire live service writer"
    );
    let stopped = service.stop();
    assert_eq!(
        stopped["active_knowledge"], 0,
        "received data alone is not learning"
    );
    let mut artifacts = Vec::new();
    for candidate in &candidates {
        let evaluated = success(fixture.command("evaluate", &["--candidate", candidate]));
        assert_eq!(evaluated["status"], "PROMOTED");
        assert_eq!(evaluated["promoted"], true);
        assert_eq!(
            success(fixture.command("evaluate", &["--candidate", candidate])),
            evaluated,
            "evaluation reply survives repeated invocation"
        );
        artifacts.push(evaluated["artifact"].as_str().unwrap().to_string());
    }
    {
        let owner = Store::open(&fixture.dir.0.join("server-state")).unwrap();
        let knowledge =
            KnowledgeStore::open(&fixture.dir.0.join("server-state"), owner.identity()).unwrap();
        assert_eq!(knowledge.active().len(), 2);
        for record in knowledge.active() {
            assert_eq!(record.source, fixture.ids[1]);
            assert!(record.id.starts_with("service-"));
            assert!(record.provenance.contains("claimed-origin-is-untrusted"));
        }
    }
    let mut restarted = ServiceProcess::start(&fixture);
    let prediction = success(fixture.call(&fixture.request(
        "affine-context/v1",
        "retained-query",
        json!({"operation":"knowledge.predict","artifact":artifacts[0],"input":3}),
    )));
    assert_eq!(prediction["prediction"], 0);
    assert_eq!(prediction["physical_certificate_authorized"], false);
    let route = success(fixture.call(&fixture.request(
        "graph-context/v1",
        "retained-route",
        json!({"operation":"knowledge.predict","artifact":artifacts[1],"input":2}),
    )));
    assert_eq!(route["prediction"], 3);
    let read = success(fixture.call(&fixture.request(
        "affine-context/v1",
        "read-model",
        json!({"operation":"knowledge.read","artifact":artifacts[0]}),
    )));
    assert_eq!(read["record"]["source"], fixture.ids[1]);
    assert!(!String::from_utf8_lossy(&serde_json::to_vec(&read).unwrap()).contains("PRIVATE KEY"));
    assert_eq!(
        success(fixture.call(&fixture.offer(false)))["candidate"],
        candidates[0]
    );
    restarted.stop();
}

#[test]
fn real_service_rejects_tls_identity_context_and_artifact_boundary_violations() {
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    fixture.server["peers"][0]["access"][0]["artifacts"] = json!(["approved-artifact"]);
    fixture.save();
    let mut service = ServiceProcess::start(&fixture);
    for fault in ["pin", "name", "id", "scope"] {
        let mut endpoint = fixture.endpoint("affine-context/v1", "capabilities");
        match fault {
            "pin" => endpoint.server_certificate_sha256 = "0".repeat(64),
            "name" => endpoint.server_name = "wrong.symbiote.test".into(),
            "id" => endpoint.server_id = "unconfigured-service".into(),
            _ => endpoint.scope = "unauthorized-context/v1".into(),
        }
        assert!(
            SecureClient::connect(&endpoint, &fixture.direct_client(&fixture.ids[1])).is_err(),
            "{fault}"
        );
    }
    assert!(SecureClient::connect(
        &fixture.endpoint("affine-context/v1", "capabilities"),
        &fixture.direct_client("unconfigured-client")
    )
    .is_err());
    let foreign = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let wrong_ca = TlsClientConfig::new(
        fixture.ids[1].clone(),
        TlsIdentity::from_pem_files(
            &fixture.dir.0.join("client.pem"),
            &fixture.dir.0.join("client.key"),
        )
        .unwrap(),
        &fs::read(foreign.dir.0.join("ca.pem")).unwrap(),
    )
    .unwrap();
    assert!(SecureClient::connect(
        &fixture.endpoint("affine-context/v1", "capabilities"),
        &wrong_ca
    )
    .is_err());
    let wrong_client_ca = TlsClientConfig::new(
        fixture.ids[1].clone(),
        TlsIdentity::from_pem_files(
            &foreign.dir.0.join("client.pem"),
            &foreign.dir.0.join("client.key"),
        )
        .unwrap(),
        &fs::read(fixture.dir.0.join("ca.pem")).unwrap(),
    )
    .unwrap();
    assert!(SecureClient::connect(
        &fixture.endpoint("affine-context/v1", "capabilities"),
        &wrong_client_ca
    )
    .is_err());
    let endpoint = fixture.endpoint("affine-context/v1", "knowledge.read");
    let mut client =
        SecureClient::connect(&endpoint, &fixture.direct_client(&fixture.ids[1])).unwrap();
    let denied = client
        .call(
            "knowledge.read",
            &fixture.request(
                "affine-context/v1",
                "forbidden-read",
                json!({"operation":"knowledge.read","artifact":"private-artifact"}),
            ),
        )
        .unwrap_err();
    assert!(denied.contains("allowlist"));
    let receipt = service.stop();
    assert_eq!(receipt["active_knowledge"], 0);
    assert!(receipt["failed_sessions"].as_u64().unwrap() >= 7);
}

#[test]
fn remote_payloads_cannot_supply_evaluators_code_or_conflicting_idempotency_bodies() {
    let fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut service = ServiceProcess::start(&fixture);
    for field in ["evaluator_url", "trial_evidence", "execute"] {
        let mut request = fixture.offer(false);
        request["body"]["offer"][field] = json!("untrusted supplied authority or command");
        let mut client = SecureClient::connect(
            &fixture.endpoint("affine-context/v1", "candidate.submit"),
            &fixture.direct_client(&fixture.ids[1]),
        )
        .unwrap();
        assert!(
            client.call("candidate.submit", &request).is_err(),
            "{field}"
        );
    }
    let request = fixture.offer(false);
    let receipt = success(fixture.call(&request));
    let mut conflicting = request.clone();
    conflicting["body"]["offer"]["training_inputs"] = json!([]);
    assert!(!fixture.call(&conflicting).status.success());
    assert_eq!(success(fixture.call(&request)), receipt);
    service.stop();
    assert!(!fixture.dir.0.join("MUST-NOT-EXECUTE").exists());
    let journal = fs::read_to_string(fixture.dir.0.join("server-state/operations.jsonl")).unwrap();
    assert_eq!(
        journal.lines().count(),
        2,
        "genesis plus one atomic quarantine/reply event"
    );
    let mut restarted = ServiceProcess::start(&fixture);
    assert_eq!(success(fixture.call(&request)), receipt);
    assert_eq!(restarted.stop()["active_knowledge"], 0);
}

#[test]
fn local_fixture_counterexamples_reject_incorrect_models_without_promotion() {
    let fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut service = ServiceProcess::start(&fixture);
    let mut candidates = Vec::new();
    for graph in [false, true] {
        let mut request = fixture.offer(graph);
        if graph {
            request["body"]["offer"]["record"]["payload"]["observations"][0]["cost"] = json!(2);
        } else {
            request["body"]["offer"]["record"]["payload"]["coefficients"] = json!(7);
        }
        candidates.push(
            success(fixture.call(&request))["candidate"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    service.stop();
    for candidate in candidates {
        let response = rejected(fixture.command("evaluate", &["--candidate", &candidate]));
        assert_eq!(response["status"], "REJECTED");
        assert_eq!(response["promoted"], false);
        assert_eq!(
            rejected(fixture.command("evaluate", &["--candidate", &candidate])),
            response
        );
    }
    let mut restarted = ServiceProcess::start(&fixture);
    assert_eq!(restarted.stop()["active_knowledge"], 0);
}

#[test]
fn durable_peer_denial_overrides_configured_grants_in_both_directions() {
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let observer = Store::open(&fixture.dir.0.join("observer-state"))
        .unwrap()
        .identity()
        .to_string();
    let observer_pin = TlsIdentity::from_pem_files(
        &fixture.dir.0.join("observer.pem"),
        &fixture.dir.0.join("observer.key"),
    )
    .unwrap()
    .certificate_sha256()
    .to_string();
    let mut grant = fixture.server["peers"][0].clone();
    grant["alias"] = json!("observer");
    grant["id"] = json!(observer);
    grant["certificate_sha256"] = json!(observer_pin);
    fixture.server["peers"].as_array_mut().unwrap().push(grant);
    fixture.save();
    let mut service = ServiceProcess::start(&fixture);
    assert!(!fixture
        .command(
            "peer-revoke",
            &["--peer", "partner", "--reason", "operator test"]
        )
        .status
        .success());
    service.stop();
    assert!(!fixture
        .command(
            "peer-revoke",
            &["--peer", "unknown", "--reason", "operator test"]
        )
        .status
        .success());
    let denial = success(fixture.command(
        "peer-revoke",
        &["--peer", "partner", "--reason", "operator test"],
    ));
    assert_eq!(denial["persistent"], true);
    assert_eq!(
        success(fixture.command(
            "peer-revoke",
            &["--peer", "partner", "--reason", "operator test"]
        ))["already_denied"],
        true
    );
    let mut restarted = ServiceProcess::start(&fixture);
    assert!(SecureClient::connect(
        &fixture.endpoint("affine-context/v1", "capabilities"),
        &fixture.direct_client(&fixture.ids[1])
    )
    .is_err());
    let observer_client = TlsClientConfig::new(
        observer,
        TlsIdentity::from_pem_files(
            &fixture.dir.0.join("observer.pem"),
            &fixture.dir.0.join("observer.key"),
        )
        .unwrap(),
        &fs::read(fixture.dir.0.join("ca.pem")).unwrap(),
    )
    .unwrap();
    let mut authorized = SecureClient::connect(
        &fixture.endpoint("affine-context/v1", "capabilities"),
        &observer_client,
    )
    .unwrap();
    assert_eq!(
        authorized
            .call(
                "capabilities",
                &fixture.request(
                    "affine-context/v1",
                    "observer-caps",
                    json!({"operation":"capabilities"})
                )
            )
            .unwrap()["identity"],
        fixture.ids[0]
    );
    authorized.revoke().unwrap();
    restarted.stop();
    let denied = Command::new(native_binary())
        .args(["peer-revoke", "--json", "--config"])
        .arg(fixture.dir.0.join("client.json"))
        .args(["--peer", "partner", "--reason", "outbound operator denial"])
        .output()
        .unwrap();
    assert!(denied.status.success());
    assert!(!fixture
        .call(&fixture.request(
            "affine-context/v1",
            "denied-caps",
            json!({"operation":"capabilities"})
        ))
        .status
        .success());
    let listed = Command::new(native_binary())
        .args(["peers", "--json", "--config"])
        .arg(fixture.dir.0.join("client.json"))
        .output()
        .unwrap();
    assert_eq!(success(listed)["peers"][0]["denied"], true);
}

#[test]
fn finite_offer_request_connection_stall_and_owner_cancellation_budgets_hold() {
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    fixture.server["limits"]["max_offers"] = json!(1);
    fixture.server["limits"]["per_peer_requests"] = json!(3);
    fixture.save();
    let mut service = ServiceProcess::start(&fixture);
    let first = success(fixture.call(&fixture.offer(false)));
    assert!(!fixture.call(&fixture.offer(true)).status.success());
    assert_eq!(success(fixture.call(&fixture.offer(false))), first);
    assert!(!fixture
        .call(&fixture.request(
            "affine-context/v1",
            "over-peer-budget",
            json!({"operation":"capabilities"})
        ))
        .status
        .success());
    service.input.take();
    assert_eq!(service.stop()["reason"], "owner-eof");
    let mut restarted = ServiceProcess::start(&fixture);
    assert!(!fixture.call(&fixture.offer(true)).status.success());
    assert_eq!(success(fixture.call(&fixture.offer(false))), first);
    restarted.stop();
    let mut stalled = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    stalled.server["limits"]["max_connections"] = json!(1);
    stalled.server["limits"]["timeout_ms"] = json!(100);
    stalled.save();
    let mut server = ServiceProcess::start(&stalled);
    let began = Instant::now();
    let mut stream = std::net::TcpStream::connect(
        stalled
            .endpoint("affine-context/v1", "capabilities")
            .address,
    )
    .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let result = stream.read(&mut [0; 1]);
    assert!(
        matches!(result, Ok(0))
            || result.as_ref().is_err_and(|error| matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ))
    );
    assert!(began.elapsed() < Duration::from_secs(2));
    assert!(SecureClient::connect(
        &stalled.endpoint("affine-context/v1", "capabilities"),
        &stalled.direct_client(&stalled.ids[1])
    )
    .is_err());
    let stopped = server.stop();
    assert_eq!(stopped["connections"], 1);
    assert_eq!(stopped["failed_sessions"], 1);
    let mut lease = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    lease.server["limits"]["lifetime_ms"] = json!(1000);
    lease.save();
    let began = Instant::now();
    let mut limited = ServiceProcess::start(&lease);
    thread::sleep(Duration::from_millis(1200));
    limited.input.take();
    assert_eq!(limited.stop()["reason"], "lifetime-budget");
    assert!(began.elapsed() < Duration::from_secs(4));
}

#[test]
fn immutable_policy_and_truth_pins_fail_closed_after_initial_registration() {
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut service = ServiceProcess::start(&fixture);
    let candidate = success(fixture.call(&fixture.offer(false)))["candidate"]
        .as_str()
        .unwrap()
        .to_string();
    service.stop();
    let original = fs::read(fixture.dir.0.join("server-state/operations.jsonl")).unwrap();
    fs::write(fixture.dir.0.join("affine-truth.json"), b"tampered truth").unwrap();
    assert!(!fixture
        .command("evaluate", &["--candidate", &candidate])
        .status
        .success());
    assert_eq!(
        fs::read(fixture.dir.0.join("server-state/operations.jsonl")).unwrap(),
        original,
        "lost fixture authority must not label a candidate scientifically rejected"
    );
    fixture.server["limits"]["max_offers"] = json!(15);
    fixture.save();
    assert!(!fixture.command("serve", &[]).status.success());
    assert_eq!(
        fs::read(fixture.dir.0.join("server-state/operations.jsonl")).unwrap(),
        original
    );
}

#[test]
fn lost_reply_and_actual_service_crash_preserve_one_idempotent_quarantine_receipt() {
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let backend = fixture.endpoint("affine-context/v1", "candidate.submit");
    let upstream = fixture.direct_client(&fixture.ids[1]);
    let ca = fs::read(fixture.dir.0.join("ca.pem")).unwrap();
    let proxy_config = SecureServerConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        fixture.ids[0].clone(),
        TlsIdentity::from_pem_files(
            &fixture.dir.0.join("server.pem"),
            &fixture.dir.0.join("server.key"),
        )
        .unwrap(),
        &ca,
        vec![SecurePeerGrant {
            id: fixture.ids[1].clone(),
            certificate_sha256: fixture.client["certificate_sha256"]
                .as_str()
                .unwrap()
                .into(),
            scopes: std::collections::BTreeMap::from([(
                "affine-context/v1".into(),
                vec!["candidate.submit".into()],
            )]),
        }],
        SecureLimits::default(),
    )
    .unwrap();
    let withheld = Arc::new(AtomicBool::new(false));
    let forwarded = Arc::clone(&withheld);
    let mut proxy = spawn_secure_server(proxy_config, move |_, operation, payload| {
        let mut client = SecureClient::connect(&backend, &upstream)?;
        let receipt = client.call(operation, &payload)?;
        client.revoke()?;
        if !forwarded.swap(true, Ordering::AcqRel) {
            thread::sleep(Duration::from_millis(800));
        }
        Ok(receipt)
    })
    .unwrap();
    fixture.client["peers"][0]["address"] = json!(proxy.address());
    fixture.save();
    let mut server = ServiceProcess::start(&fixture);
    let request = fixture.offer(false);
    let lost = fixture.call(&request);
    assert!(
        !lost.status.success(),
        "the authorized proxy withholds only the first committed reply past the client deadline"
    );
    assert!(withheld.load(Ordering::Acquire));
    let bytes = fs::read(fixture.dir.0.join("server-state/operations.jsonl")).unwrap();
    let last: Value = serde_json::from_slice(
        bytes
            .split(|byte| *byte == b'\n')
            .rfind(|line| !line.is_empty())
            .unwrap(),
    )
    .unwrap();
    let expected = last["payload"]["response"].clone();
    assert_eq!(expected["status"], "QUARANTINED");
    server.child.kill().unwrap();
    server.child.wait().unwrap();
    server.input.take();
    let recovery = Command::new(native_binary())
        .args(["recover", "--json", "--state"])
        .arg(fixture.dir.0.join("server-state"))
        .output()
        .unwrap();
    assert!(
        recovery.status.success(),
        "{}",
        String::from_utf8_lossy(&recovery.stderr)
    );
    assert_eq!(
        fs::read(fixture.dir.0.join("server-state/operations.jsonl")).unwrap(),
        bytes
    );
    let mut restarted = ServiceProcess::start(&fixture);
    assert_eq!(success(fixture.call(&request)), expected);
    assert_eq!(restarted.stop()["active_knowledge"], 0);
    proxy.shutdown().unwrap();
    let journal = fs::read_to_string(fixture.dir.0.join("server-state/operations.jsonl")).unwrap();
    assert_eq!(
        journal.lines().count(),
        2,
        "retry must not append a second quarantine mutation"
    );
}

#[test]
fn evaluation_intent_recovery_commits_once_and_retains_original_lost_ack_result() {
    use symbiote_memory::knowledge::{assess, TrialCase, TrialCosts, TrialEvidence};
    use symbiote_memory::operational::{OperationalEvent, OperationalJournal};
    for (committed_before_interruption, denied_before_recovery) in
        [(false, true), (true, true), (false, false), (true, false)]
    {
        let fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let mut server = ServiceProcess::start(&fixture);
        let candidate = success(fixture.call(&fixture.offer(false)))["candidate"]
            .as_str()
            .unwrap()
            .to_string();
        server.stop();
        let policy=hash(&serde_json::to_vec(&json!({"manifest":fixture.server,"ca_sha256":hash(&fs::read(fixture.dir.0.join("ca.pem")).unwrap())})).unwrap());
        let owner = Arc::new(Store::open(&fixture.dir.0.join("server-state")).unwrap());
        let mut knowledge =
            KnowledgeStore::open(&fixture.dir.0.join("server-state"), owner.identity()).unwrap();
        let mut journal =
            OperationalJournal::open(Arc::clone(&owner), "configured-service/v1", &policy).unwrap();
        let offer = fixture.offer(false);
        let original: KnowledgeRecord =
            serde_json::from_value(offer["body"]["offer"]["record"].clone()).unwrap();
        let fixture_pin = fixture.server["contexts"][0]["truth_sha256"]
            .as_str()
            .unwrap();
        let namespace=hash(&serde_json::to_vec(&json!({"peer":fixture.ids[1],"scope":original.scope,"schema":original.schema_fingerprint})).unwrap());
        let record=KnowledgeRecord{id:format!("service-{}",&namespace[..32]),revision:1,source:fixture.ids[1].clone(),scope:original.scope.clone(),schema_fingerprint:original.schema_fingerprint.clone(),payload:original.payload.clone(),provenance:format!("Authenticated sender {}; original inert record {} revision {} SHA256 {}; claimed source {} is preserved as untrusted provenance. Locally checked against fixture SHA256 {fixture_pin}.",fixture.ids[1],original.id,original.revision,original.digest().unwrap(),original.source)};
        let response = json!({"schema":"symbiote.service-evaluation/1","status":"PROMOTED","promoted":true,"artifact":record.id,"revision":1,"record_sha256":record.digest().unwrap(),"fixture_sha256":fixture_pin,"validated_cases":4,"model_work_units":8,"truth_basis":"operator-pinned local finite fixture; no remote truth or generalization claim"});
        journal
            .append(OperationalEvent::EvaluationPrepared {
                candidate_id: candidate.clone(),
                record: record.clone(),
                fixture_sha256: fixture_pin.into(),
                response: response.clone(),
            })
            .unwrap();
        if committed_before_interruption {
            let evidence = TrialEvidence {
                evaluator: format!("local-fixture/{}", &fixture_pin[..24]),
                training_case_ids: [0, 1, 2, 4]
                    .map(|input| format!("declared-training-{input}"))
                    .to_vec(),
                training_inputs: vec![0, 1, 2, 4],
                cases: [3, 5, 6, 7]
                    .map(|input| {
                        let expected = ((input & 3u16).count_ones() % 2) as u8;
                        TrialCase {
                            id: format!("fixture-case-{input}"),
                            input,
                            expected,
                            baseline: None,
                            candidate: expected,
                        }
                    })
                    .to_vec(),
                costs: TrialCosts {
                    acquisition: 0,
                    verification: 8,
                    adoption: 1,
                    baseline: 0,
                    candidate: 9,
                },
            };
            let assessment = assess(&record, &evidence).unwrap();
            knowledge.promote(record.clone(), assessment).unwrap();
        }
        drop(journal);
        drop(knowledge);
        drop(owner);
        if denied_before_recovery {
            let denial = success(fixture.command(
                "peer-revoke",
                &[
                    "--peer",
                    &fixture.ids[1],
                    "--reason",
                    "operator denied before recovery",
                ],
            ));
            assert_eq!(denial["persistent"], true);
            let owner = Store::open(&fixture.dir.0.join("server-state")).unwrap();
            let knowledge =
                KnowledgeStore::open(&fixture.dir.0.join("server-state"), owner.identity())
                    .unwrap();
            assert_eq!(
                knowledge.active().len(),
                usize::from(committed_before_interruption),
                "denying a peer must not first promote its pending candidate"
            );
            drop(knowledge);
            drop(owner);
            let restarted = success(fixture.command("serve", &[]));
            assert_eq!(
                restarted["active_knowledge"],
                usize::from(committed_before_interruption)
            );
            assert_eq!(restarted["reason"], "no-authorized-peers");
            assert_eq!(restarted["listener_opened"], false);
            continue;
        }
        // Exact durable cutpoints around the separate knowledge commit: no
        // completion record has been written in either interrupted state.
        let mut recovered = ServiceProcess::start(&fixture);
        let forecast = success(fixture.call(&fixture.request(
            "affine-context/v1",
            "recovered-prediction",
            json!({"operation":"knowledge.predict","artifact":record.id,"input":3}),
        )));
        assert_eq!(forecast["prediction"], 0);
        recovered.stop();
        assert_eq!(
            success(fixture.command("evaluate", &["--candidate", &candidate])),
            response,
            "recovery must preserve the original promoted:true reply"
        );
        let owner = Store::open(&fixture.dir.0.join("server-state")).unwrap();
        let knowledge =
            KnowledgeStore::open(&fixture.dir.0.join("server-state"), owner.identity()).unwrap();
        assert_eq!(knowledge.active().len(), 1);
        assert_eq!(knowledge.highest_revision(&record.id), Some(1));
        let content =
            fs::read_to_string(fixture.dir.0.join("server-state/operations.jsonl")).unwrap();
        assert_eq!(
            content.lines().count(),
            4,
            "genesis, quarantine, prepared, completed exactly once"
        );
    }
}

#[test]
fn missing_registered_service_knowledge_is_not_silently_reinitialized() {
    let fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut server = ServiceProcess::start(&fixture);
    let candidate = success(fixture.call(&fixture.offer(false)))["candidate"]
        .as_str()
        .unwrap()
        .to_string();
    server.stop();
    assert_eq!(
        success(fixture.command("evaluate", &["--candidate", &candidate]))["promoted"],
        true
    );
    let knowledge = fixture.dir.0.join("server-state/knowledge.jsonl");
    let journal = fixture.dir.0.join("server-state/operations.jsonl");
    let original = fs::read(&journal).unwrap();
    fs::remove_file(&knowledge).unwrap();
    let result = fixture.command("peers", &[]);
    assert!(
        !result.status.success(),
        "missing registered knowledge must produce HOLD"
    );
    assert!(
        !knowledge.exists(),
        "recovery must not replace lost knowledge with an empty ledger"
    );
    assert_eq!(fs::read(journal).unwrap(), original);
}

#[test]
fn surviving_completed_operations_reject_a_valid_older_learning_prefix() {
    let fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut server = ServiceProcess::start(&fixture);
    let candidate = success(fixture.call(&fixture.offer(false)))["candidate"]
        .as_str()
        .unwrap()
        .to_string();
    server.stop();
    let knowledge = fixture.dir.0.join("server-state/knowledge.jsonl");
    let genesis = fs::read(&knowledge).unwrap();
    let promotion = success(fixture.command("evaluate", &["--candidate", &candidate]));
    assert_eq!(promotion["promoted"], true);
    assert_ne!(fs::read(&knowledge).unwrap(), genesis);
    let journal = fixture.dir.0.join("server-state/operations.jsonl");
    let operations = fs::read(&journal).unwrap();
    // A restored valid prefix still has an intact hash chain and correct owner,
    // but the surviving operational history proves a promotion is missing.
    fs::write(&knowledge, &genesis).unwrap();
    let listed = fixture.command("peers", &[]);
    assert!(!listed.status.success(),"completed operational promotion must anchor learning history against valid-prefix rollback");
    let replayed = fixture.command("evaluate", &["--candidate", &candidate]);
    assert!(
        !replayed.status.success(),
        "lost learning must not return a surviving promoted:true receipt"
    );
    assert_eq!(fs::read(&knowledge).unwrap(), genesis);
    assert_eq!(fs::read(&journal).unwrap(), operations);
}

#[test]
fn completed_operational_history_allows_a_legitimate_later_knowledge_revocation() {
    let fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut server = ServiceProcess::start(&fixture);
    let candidate = success(fixture.call(&fixture.offer(false)))["candidate"]
        .as_str()
        .unwrap()
        .to_string();
    server.stop();
    let completed = success(fixture.command("evaluate", &["--candidate", &candidate]));
    let id = completed["artifact"].as_str().unwrap();
    {
        let owner = Store::open(&fixture.dir.0.join("server-state")).unwrap();
        let mut knowledge =
            KnowledgeStore::open(&fixture.dir.0.join("server-state"), owner.identity()).unwrap();
        knowledge
            .revoke(
                id,
                "operator ended active use; historical promotion remains auditable",
            )
            .unwrap();
        assert!(knowledge.active().is_empty());
    }
    assert!(
        fixture.command("peers", &[]).status.success(),
        "historical completion does not require a currently active artifact"
    );
    assert_eq!(
        success(fixture.command("evaluate", &["--candidate", &candidate])),
        completed,
        "past acknowledgement remains historical, without relearning revoked knowledge"
    );
}

fn configured_command(fixture: &Fixture, manifest: &str, command: &str, args: &[&str]) -> Output {
    Command::new(native_binary())
        .args([command, "--json", "--config"])
        .arg(fixture.dir.0.join(manifest))
        .args(args)
        .output()
        .unwrap()
}
fn save_old_policy(fixture: &Fixture) -> PathBuf {
    let path = fixture.dir.0.join("previous.json");
    fs::write(&path, serde_json::to_vec_pretty(&fixture.server).unwrap()).unwrap();
    path
}
fn transition(fixture: &Fixture, old: &Path, anchor: &Value, reviewed: bool) -> Output {
    let mut args = vec![
        "--previous-config",
        old.to_str().unwrap(),
        "--expected-policy",
        anchor["policy_sha256"].as_str().unwrap(),
        "--expected-head",
        anchor["journal_head_sha256"].as_str().unwrap(),
        "--reason",
        "explicit offline test policy",
    ];
    if reviewed {
        args.push("--review-permission-change");
    }
    fixture.command("policy-transition", &args)
}
fn assert_service_prefixes(fixture: &Fixture, ledger: &[u8], marker: &[u8], operations: &[u8]) {
    let state = fixture.dir.0.join("server-state");
    assert_eq!(fs::read(state.join("ledger.jsonl")).unwrap(), ledger);
    assert_eq!(
        fs::read(state.join("operations-owner.json")).unwrap(),
        marker
    );
    assert!(fs::read(state.join("operations.jsonl"))
        .unwrap()
        .starts_with(operations));
}

#[test]
fn offline_rotation_after_lost_private_key_preserves_identity_and_rejects_old_tls_pin() {
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    success(fixture.command("peers", &[]));
    let anchor = success(fixture.command("policy-status", &[]));
    let previous = save_old_policy(&fixture);
    let state = fixture.dir.0.join("server-state");
    let ledger = fs::read(state.join("ledger.jsonl")).unwrap();
    let marker = fs::read(state.join("operations-owner.json")).unwrap();
    let operations = fs::read(state.join("operations.jsonl")).unwrap();
    let knowledge = fs::read(state.join("knowledge.jsonl")).unwrap();
    let old_pin = fixture.server["certificate_sha256"]
        .as_str()
        .unwrap()
        .to_string();
    let replacement = TlsIdentity::from_pem_files(
        &fixture.dir.0.join("observer.pem"),
        &fixture.dir.0.join("observer.key"),
    )
    .unwrap();
    fixture.server["certificate"] = json!("observer.pem");
    fixture.server["private_key"] = json!("observer.key");
    fixture.server["certificate_sha256"] = json!(replacement.certificate_sha256());
    fixture.save();
    fs::remove_file(fixture.dir.0.join("server.key")).unwrap();
    assert_eq!(
        success(configured_command(
            &fixture,
            "previous.json",
            "policy-status",
            &[]
        ))["identity"],
        fixture.ids[0]
    );
    let changed = success(transition(&fixture, &previous, &anchor, false));
    assert_eq!(changed["learning_promotions"], 0);
    assert_ne!(changed["policy_sha256"], anchor["policy_sha256"]);
    assert_service_prefixes(&fixture, &ledger, &marker, &operations);
    assert_eq!(fs::read(state.join("knowledge.jsonl")).unwrap(), knowledge);
    assert!(
        !configured_command(&fixture, "previous.json", "policy-status", &[])
            .status
            .success()
    );
    for _ in 0..2 {
        let mut service = ServiceProcess::start(&fixture);
        let mut endpoint = fixture.endpoint("affine-context/v1", "capabilities");
        endpoint.server_name = "observer.symbiote.test".into();
        let client = fixture.direct_client(&fixture.ids[1]);
        let mut old_endpoint = endpoint.clone();
        old_endpoint.server_certificate_sha256 = old_pin.clone();
        assert!(SecureClient::connect(&old_endpoint, &client).is_err());
        let mut connection = SecureClient::connect(&endpoint, &client).unwrap();
        let reply = connection
            .call(
                "capabilities",
                &fixture.request(
                    "affine-context/v1",
                    "new-certificate",
                    json!({"operation":"capabilities"}),
                ),
            )
            .unwrap();
        assert_eq!(reply["identity"], fixture.ids[0]);
        connection.revoke().unwrap();
        service.stop();
    }
    let raw = fs::read_to_string(state.join("operations.jsonl")).unwrap();
    assert!(!raw.contains("PRIVATE KEY"));
    assert!(!raw.contains("BEGIN CERTIFICATE"));
}

#[test]
fn policy_expansion_requires_review_and_stale_or_foreign_anchors_do_not_write() {
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    success(fixture.command("peers", &[]));
    let anchor = success(fixture.command("policy-status", &[]));
    let previous = save_old_policy(&fixture);
    let path = fixture.dir.0.join("server-state/operations.jsonl");
    let original = fs::read(&path).unwrap();
    fixture.server["limits"]["max_requests"] = json!(65);
    fixture.save();
    assert!(!transition(&fixture, &previous, &anchor, false)
        .status
        .success());
    assert_eq!(fs::read(&path).unwrap(), original);
    let mut stale = anchor.clone();
    stale["journal_head_sha256"] = json!("0".repeat(64));
    assert!(!transition(&fixture, &previous, &stale, true)
        .status
        .success());
    assert_eq!(fs::read(&path).unwrap(), original);
    stale = anchor.clone();
    stale["policy_sha256"] = json!("f".repeat(64));
    assert!(!transition(&fixture, &previous, &stale, true)
        .status
        .success());
    assert_eq!(fs::read(&path).unwrap(), original);
    let accepted = success(transition(&fixture, &previous, &anchor, true));
    assert_eq!(
        accepted["reviewed_permission_changes"],
        json!(["budget:max_requests"])
    );
    let committed = fs::read(&path).unwrap();
    assert!(!transition(&fixture, &previous, &anchor, true)
        .status
        .success());
    assert_eq!(fs::read(&path).unwrap(), committed);
    let mut foreign = fixture.server.clone();
    foreign["identity"] = json!("symbiote-aaaaaaaaaaaaaaaaaaaaaaaa");
    fs::write(
        fixture.dir.0.join("foreign.json"),
        serde_json::to_vec(&foreign).unwrap(),
    )
    .unwrap();
    assert!(
        !configured_command(&fixture, "foreign.json", "policy-status", &[])
            .status
            .success()
    );
    assert_eq!(fs::read(&path).unwrap(), committed);
}

#[test]
fn rotation_retains_denial_and_reviewed_regrant_never_resurrects_old_candidates() {
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut service = ServiceProcess::start(&fixture);
    let candidate = success(fixture.call(&fixture.offer(false)))["candidate"]
        .as_str()
        .unwrap()
        .to_string();
    service.stop();
    success(fixture.command(
        "peer-revoke",
        &["--peer", "partner", "--reason", "operator denied"],
    ));
    let anchor = success(fixture.command("policy-status", &[]));
    let previous = save_old_policy(&fixture);
    fixture.server["limits"]["per_peer_requests"] = json!(63);
    fixture.save();
    success(transition(&fixture, &previous, &anchor, false));
    let status = success(fixture.command("policy-status", &[]));
    assert_eq!(status["denied_peers"].as_array().unwrap().len(), 1);
    assert_eq!(
        success(fixture.command("serve", &[]))["listener_opened"],
        false
    );
    let old_result = rejected(fixture.command("evaluate", &["--candidate", &candidate]));
    assert_eq!(old_result["status"], "REJECTED");
    let args = [
        "--peer",
        "partner",
        "--expected-policy",
        status["policy_sha256"].as_str().unwrap(),
        "--expected-head",
        status["journal_head_sha256"].as_str().unwrap(),
        "--reason",
        "reviewed operator regrant",
    ];
    assert!(!fixture.command("peer-regrant", &args).status.success());
    let mut approved = args.to_vec();
    approved.push("--review-permission-change");
    success(fixture.command("peer-regrant", &approved));
    assert!(!fixture.command("peer-regrant", &approved).status.success());
    let mut service = ServiceProcess::start(&fixture);
    assert_eq!(
        success(fixture.call(&fixture.request(
            "affine-context/v1",
            "regranted-capabilities",
            json!({"operation":"capabilities"})
        )))["identity"],
        fixture.ids[0]
    );
    service.stop();
    assert_eq!(
        rejected(fixture.command("evaluate", &["--candidate", &candidate])),
        old_result
    );
    let owner = Store::open(&fixture.dir.0.join("server-state")).unwrap();
    assert!(
        KnowledgeStore::open(&fixture.dir.0.join("server-state"), owner.identity())
            .unwrap()
            .active()
            .is_empty()
    );
}

fn seed_pending_local_evaluation(fixture: &Fixture, candidate: &str, committed: bool) -> Value {
    use symbiote_memory::knowledge::{assess, TrialCase, TrialCosts, TrialEvidence};
    use symbiote_memory::operational::{OperationalEvent, OperationalJournal};
    let anchor = success(fixture.command("policy-status", &[]));
    let owner = Arc::new(Store::open(&fixture.dir.0.join("server-state")).unwrap());
    let mut knowledge =
        KnowledgeStore::open(&fixture.dir.0.join("server-state"), owner.identity()).unwrap();
    let mut journal = OperationalJournal::open(
        Arc::clone(&owner),
        "configured-service/v1",
        anchor["policy_sha256"].as_str().unwrap(),
    )
    .unwrap();
    let offer = fixture.offer(false);
    let original: KnowledgeRecord =
        serde_json::from_value(offer["body"]["offer"]["record"].clone()).unwrap();
    let pin = fixture.server["contexts"][0]["truth_sha256"]
        .as_str()
        .unwrap();
    let namespace=hash(&serde_json::to_vec(&json!({"peer":fixture.ids[1],"scope":original.scope,"schema":original.schema_fingerprint})).unwrap());
    let record=KnowledgeRecord{id:format!("service-{}",&namespace[..32]),revision:1,source:fixture.ids[1].clone(),scope:original.scope.clone(),schema_fingerprint:original.schema_fingerprint.clone(),payload:original.payload.clone(),provenance:format!("Authenticated sender {}; original inert record {} revision {} SHA256 {}; claimed source {} is preserved as untrusted provenance. Locally checked against fixture SHA256 {pin}.",fixture.ids[1],original.id,original.revision,original.digest().unwrap(),original.source)};
    let response = json!({"schema":"symbiote.service-evaluation/1","status":"PROMOTED","promoted":true,"artifact":record.id,"revision":1,"record_sha256":record.digest().unwrap(),"fixture_sha256":pin,"validated_cases":4,"model_work_units":8,"truth_basis":"operator-pinned local finite fixture; no remote truth or generalization claim"});
    journal
        .append(OperationalEvent::EvaluationPrepared {
            candidate_id: candidate.into(),
            record: record.clone(),
            fixture_sha256: pin.into(),
            response: response.clone(),
        })
        .unwrap();
    if committed {
        let evidence = TrialEvidence {
            evaluator: format!("local-fixture/{}", &pin[..24]),
            training_case_ids: [0, 1, 2, 4]
                .map(|input| format!("declared-training-{input}"))
                .to_vec(),
            training_inputs: vec![0, 1, 2, 4],
            cases: [3, 5, 6, 7]
                .map(|input| {
                    let expected = ((input & 3u16).count_ones() % 2) as u8;
                    TrialCase {
                        id: format!("fixture-case-{input}"),
                        input,
                        expected,
                        baseline: None,
                        candidate: expected,
                    }
                })
                .to_vec(),
            costs: TrialCosts {
                acquisition: 0,
                verification: 8,
                adoption: 1,
                baseline: 0,
                candidate: 9,
            },
        };
        knowledge
            .promote(record.clone(), assess(&record, &evidence).unwrap())
            .unwrap();
    }
    response
}

#[test]
fn restrictive_policy_transition_closes_both_learning_commit_cutpoints_before_recovery() {
    for committed in [false, true] {
        let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let mut server = ServiceProcess::start(&fixture);
        let candidate = success(fixture.call(&fixture.offer(false)))["candidate"]
            .as_str()
            .unwrap()
            .to_string();
        server.stop();
        let expected_response = seed_pending_local_evaluation(&fixture, &candidate, committed);
        let anchor = success(fixture.command("policy-status", &[])); // must not recover before restriction
        let previous = save_old_policy(&fixture);
        let state = fixture.dir.0.join("server-state");
        let knowledge = fs::read(state.join("knowledge.jsonl")).unwrap();
        let ops = fs::read(state.join("operations.jsonl")).unwrap();
        let marker = fs::read(state.join("operations-owner.json")).unwrap();
        let ledger = fs::read(state.join("ledger.jsonl")).unwrap();
        fixture.server["contexts"].as_array_mut().unwrap().remove(0);
        fixture.server["peers"][0]["access"]
            .as_array_mut()
            .unwrap()
            .remove(0);
        fixture.save();
        success(transition(&fixture, &previous, &anchor, false));
        assert_service_prefixes(&fixture, &ledger, &marker, &ops);
        assert_eq!(
            fs::read(state.join("knowledge.jsonl")).unwrap(),
            knowledge,
            "restriction performs no new learning commit"
        );
        let evaluated = fixture.command("evaluate", &["--candidate", &candidate]);
        let reply = if committed {
            success(evaluated)
        } else {
            rejected(evaluated)
        };
        if committed {
            assert_eq!(reply, expected_response);
        } else {
            assert_eq!(reply["status"], "REJECTED");
            assert_eq!(reply["promoted"], false);
        }
        let mut server = ServiceProcess::start(&fixture);
        assert_eq!(
            success(fixture.call(&fixture.request(
                "graph-context/v1",
                "surviving-context",
                json!({"operation":"capabilities"})
            )))["identity"],
            fixture.ids[0]
        );
        assert!(!fixture
            .call(&fixture.request(
                "affine-context/v1",
                "removed-context",
                json!({"operation":"capabilities"})
            ))
            .status
            .success());
        server.stop();
        assert_eq!(fs::read(state.join("knowledge.jsonl")).unwrap(), knowledge);
    }
}

#[test]
fn a_scope_cannot_be_redefined_even_after_removal_and_reviewed_readdition() {
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    success(fixture.command("peers", &[]));
    let original = fixture.server.clone();
    let previous = save_old_policy(&fixture);
    let anchor = success(fixture.command("policy-status", &[]));
    let path = fixture.dir.0.join("server-state/operations.jsonl");
    let before = fs::read(&path).unwrap();
    fixture.server["contexts"][0]["truth_sha256"] = json!("a".repeat(64));
    fixture.save();
    assert!(!transition(&fixture, &previous, &anchor, true)
        .status
        .success());
    assert_eq!(fs::read(&path).unwrap(), before);
    fixture.server = original.clone();
    fixture.server["contexts"].as_array_mut().unwrap().remove(0);
    fixture.server["peers"][0]["access"]
        .as_array_mut()
        .unwrap()
        .remove(0);
    fixture.save();
    success(transition(&fixture, &previous, &anchor, false));
    let current = success(fixture.command("policy-status", &[]));
    save_old_policy(&fixture);
    fixture.server = original;
    fixture.server["contexts"][0]["truth_sha256"] = json!("b".repeat(64));
    fixture.save();
    let before = fs::read(&path).unwrap();
    assert!(!transition(&fixture, &previous, &current, true)
        .status
        .success());
    assert_eq!(
        fs::read(&path).unwrap(),
        before,
        "removed contexts retain their original meaning in policy history"
    );
}

#[test]
fn remote_json_cannot_open_a_local_policy_transaction() {
    let fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut server = ServiceProcess::start(&fixture);
    let state = fixture.dir.0.join("server-state");
    let before = fs::read(state.join("operations.jsonl")).unwrap();
    let client = fixture.direct_client(&fixture.ids[1]);
    let mut session = SecureClient::connect(
        &fixture.endpoint("affine-context/v1", "candidate.submit"),
        &client,
    )
    .unwrap();
    let body=fixture.request("affine-context/v1","remote-policy-attempt",json!({"operation":"policy-transition","reviewed_permission_change":true,"new_policy":{"grants":"*"}}));
    assert!(session.call("candidate.submit", &body).is_err());
    drop(session);
    server.stop();
    assert_eq!(fs::read(state.join("operations.jsonl")).unwrap(), before);
    assert!(
        success(fixture.command("policy-status", &[]))["denied_peers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn reviewed_verified_restore_relocation_uses_only_destination_when_source_and_old_key_are_gone() {
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    success(fixture.command("peers", &[]));
    let anchor = success(fixture.command("policy-status", &[]));
    let previous = save_old_policy(&fixture);
    let source = fixture.dir.0.join("server-state");
    let snapshot = fixture.dir.0.join("verified-backup");
    let report = symbiote_memory::backup::create(
        &source,
        &snapshot,
        &symbiote_memory::backup::BackupOptions::default(),
    )
    .unwrap();
    let restored = fixture.dir.0.join("restored-state");
    let mapping =
        symbiote_memory::backup::restore(&snapshot, &report.manifest_sha256, &restored).unwrap();
    let prior_bytes = fs::read(restored.join("operations.jsonl")).unwrap();
    let marker = fs::read(restored.join("operations-owner.json")).unwrap();
    let ledger = fs::read(restored.join("ledger.jsonl")).unwrap();
    fixture.server["state"] = json!(restored);
    let replacement = TlsIdentity::from_pem_files(
        &fixture.dir.0.join("observer.pem"),
        &fixture.dir.0.join("observer.key"),
    )
    .unwrap();
    fixture.server["certificate"] = json!("observer.pem");
    fixture.server["private_key"] = json!("observer.key");
    fixture.server["certificate_sha256"] = json!(replacement.certificate_sha256());
    fixture.save();
    fs::remove_file(fixture.dir.0.join("server.key")).unwrap();
    assert!(source.starts_with(&fixture.dir.0));
    fs::remove_dir_all(&source).unwrap();
    assert!(
        !transition(&fixture, &previous, &anchor, false)
            .status
            .success(),
        "ordinary rotation cannot silently relocate"
    );
    assert_eq!(
        fs::read(restored.join("operations.jsonl")).unwrap(),
        prior_bytes
    );
    let changed = success(fixture.command(
        "policy-transition",
        &[
            "--previous-config",
            previous.to_str().unwrap(),
            "--expected-policy",
            anchor["policy_sha256"].as_str().unwrap(),
            "--expected-head",
            anchor["journal_head_sha256"].as_str().unwrap(),
            "--reason",
            "reviewed verified restore relocation",
            "--review-relocation",
        ],
    ));
    assert_eq!(
        changed["relocation"]["restore_mapping_sha256"],
        mapping.restore_mapping_sha256
    );
    assert_eq!(
        fs::read(restored.join("operations-owner.json")).unwrap(),
        marker
    );
    assert_eq!(fs::read(restored.join("ledger.jsonl")).unwrap(), ledger);
    assert!(fs::read(restored.join("operations.jsonl"))
        .unwrap()
        .starts_with(&prior_bytes));
    assert!(
        !source.exists(),
        "relocation must not reopen or recreate original source state"
    );
    let mut server = ServiceProcess::start(&fixture);
    let mut endpoint = fixture.endpoint("affine-context/v1", "capabilities");
    endpoint.server_name = "observer.symbiote.test".into();
    let mut session =
        SecureClient::connect(&endpoint, &fixture.direct_client(&fixture.ids[1])).unwrap();
    assert_eq!(
        session
            .call(
                "capabilities",
                &fixture.request(
                    "affine-context/v1",
                    "restored-live",
                    json!({"operation":"capabilities"})
                )
            )
            .unwrap()["identity"],
        fixture.ids[0]
    );
    session.revoke().unwrap();
    server.stop();
    assert!(!source.exists());
}

#[test]
fn offline_denial_does_not_require_a_working_local_private_key() {
    let fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    success(fixture.command("peers", &[]));
    fs::remove_file(fixture.dir.0.join("server.key")).unwrap();
    assert_eq!(
        success(fixture.command(
            "peer-revoke",
            &[
                "--peer",
                "partner",
                "--reason",
                "lost key incident containment"
            ]
        ))["denied"],
        true
    );
    assert_eq!(
        success(fixture.command("policy-status", &[]))["denied_peers"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

fn absolute_service_material(fixture: &mut Fixture) {
    for field in ["certificate", "private_key", "ca_certificate"] {
        fixture.server[field] = json!(fixture.dir.0.join(fixture.server[field].as_str().unwrap()));
    }
    for context in fixture.server["contexts"].as_array_mut().unwrap() {
        context["truth_fixture"] = json!(fixture
            .dir
            .0
            .join(context["truth_fixture"].as_str().unwrap()));
    }
    fixture.save();
}
fn public_config_command(path: &Path, command: &str, args: &[&str]) -> Output {
    Command::new(native_binary())
        .args([command, "--json", "--config"])
        .arg(path)
        .args(args)
        .output()
        .unwrap()
}
fn assert_unreviewed_service_inactive(path: &Path, fixture: &Fixture) {
    let request = fixture.dir.0.join("unreviewed-request.json");
    fs::write(
        &request,
        serde_json::to_vec(&fixture.request(
            "affine-context/v1",
            "unreviewed-request",
            json!({"operation":"capabilities"}),
        ))
        .unwrap(),
    )
    .unwrap();
    for (command, args) in [
        ("peers", vec![]),
        ("serve", vec![]),
        (
            "evaluate",
            vec![
                "--candidate",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ],
        ),
        (
            "peer-revoke",
            vec![
                "--peer",
                "partner",
                "--reason",
                "must not mutate unreviewed restore",
            ],
        ),
        (
            "connect",
            vec!["--peer", "partner", "--request", request.to_str().unwrap()],
        ),
    ] {
        let result = public_config_command(path, command, &args);
        assert!(
            !result.status.success(),
            "unreviewed restore must reject {command}; stdout={}",
            String::from_utf8_lossy(&result.stdout)
        );
        assert!(
            format!(
                "{} {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            )
            .to_ascii_lowercase()
            .contains("restore"),
            "{command} must fail specifically at restored activation guard"
        );
    }
    let inspected = success(public_config_command(path, "policy-status", &[]));
    let denied = public_config_command(
        path,
        "peer-regrant",
        &[
            "--peer",
            "partner",
            "--expected-policy",
            inspected["policy_sha256"].as_str().unwrap(),
            "--expected-head",
            inspected["journal_head_sha256"].as_str().unwrap(),
            "--reason",
            "must not regrant unreviewed restore",
            "--review-permission-change",
        ],
    );
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr)
        .to_ascii_lowercase()
        .contains("restore"));
    let mut proposed: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    proposed["limits"]["per_peer_requests"] = json!(63);
    let ordinary = path.with_file_name("unreviewed-ordinary-policy.json");
    fs::write(&ordinary, serde_json::to_vec(&proposed).unwrap()).unwrap();
    let rejected = public_config_command(
        &ordinary,
        "policy-transition",
        &[
            "--previous-config",
            path.to_str().unwrap(),
            "--expected-policy",
            inspected["policy_sha256"].as_str().unwrap(),
            "--expected-head",
            inspected["journal_head_sha256"].as_str().unwrap(),
            "--reason",
            "ordinary rotation cannot activate a restored owner",
        ],
    );
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr)
        .to_ascii_lowercase()
        .contains("restore"));
}

#[test]
fn restored_relative_manifest_requires_review_for_each_restore_even_when_policy_digest_is_unchanged(
) {
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    absolute_service_material(&mut fixture);
    success(fixture.command("peers", &[]));
    let original_state = fixture.dir.0.join("server-state");
    let mut previous_config = fixture.dir.0.join("server.json");
    let mut previous_state = original_state.clone();
    let first_parent = fixture.dir.0.join("relative-restored-1");
    for round in 1..=3 {
        let next_parent = if round == 3 {
            first_parent.clone()
        } else {
            fixture.dir.0.join(format!("relative-restored-{round}"))
        };
        fs::create_dir_all(&next_parent).unwrap();
        let target = next_parent.join("server-state");
        if target.exists() {
            assert!(target.starts_with(&fixture.dir.0));
            fs::remove_dir_all(&target).unwrap();
        }
        let snapshot = fixture.dir.0.join(format!("relative-backup-{round}"));
        let saved = symbiote_memory::backup::create(
            &previous_state,
            &snapshot,
            &symbiote_memory::backup::BackupOptions::default(),
        )
        .unwrap();
        let restored =
            symbiote_memory::backup::restore(&snapshot, &saved.manifest_sha256, &target).unwrap();
        let next_config = next_parent.join("server.json");
        fs::copy(&previous_config, &next_config).unwrap();
        assert_eq!(
            fs::read(&previous_config).unwrap(),
            fs::read(&next_config).unwrap(),
            "same public manifest bytes must not imply approved relocation"
        );
        let original_ops = fs::read(target.join("operations.jsonl")).unwrap();
        let original_knowledge = fs::read(target.join("knowledge.jsonl")).unwrap();
        assert_unreviewed_service_inactive(&next_config, &fixture);
        let status = success(public_config_command(&next_config, "policy-status", &[]));
        assert_eq!(status["activation_required"], true);
        assert_eq!(
            status["unconsumed_restore_mappings"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            fs::read(target.join("operations.jsonl")).unwrap(),
            original_ops
        );
        assert_eq!(
            fs::read(target.join("knowledge.jsonl")).unwrap(),
            original_knowledge
        );
        if round == 1 {
            assert!(previous_state.starts_with(&fixture.dir.0));
            fs::remove_dir_all(&previous_state).unwrap();
        }
        let approved = success(public_config_command(
            &next_config,
            "policy-transition",
            &[
                "--previous-config",
                previous_config.to_str().unwrap(),
                "--expected-policy",
                status["policy_sha256"].as_str().unwrap(),
                "--expected-head",
                status["journal_head_sha256"].as_str().unwrap(),
                "--reason",
                "explicit same-policy restored activation review",
                "--review-relocation",
            ],
        ));
        assert_eq!(
            approved["previous_policy_sha256"], approved["policy_sha256"],
            "relocation is meaningful even with identical policy bytes"
        );
        assert_eq!(
            approved["relocation"]["restore_mapping_sha256"],
            restored.restore_mapping_sha256
        );
        let activated = success(public_config_command(&next_config, "policy-status", &[]));
        assert_eq!(activated["activation_required"], false);
        success(public_config_command(&next_config, "peers", &[]));
        assert!(fs::read(target.join("operations.jsonl"))
            .unwrap()
            .starts_with(&original_ops));
        if round == 1 || round == 3 {
            let mut server = ServiceProcess::start_config(&next_config);
            assert_eq!(
                success(fixture.call(&fixture.request(
                    "affine-context/v1",
                    &format!("reviewed-round-{round}"),
                    json!({"operation":"capabilities"})
                )))["identity"],
                fixture.ids[0]
            );
            server.stop();
        }
        previous_config = next_config;
        previous_state = target;
    }
    assert!(
        !original_state.exists(),
        "review never recreated original missing source state"
    );
}

#[test]
fn moved_unreviewed_restore_cannot_activate_under_original_config_or_consume_foreign_destination() {
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    absolute_service_material(&mut fixture);
    success(fixture.command("peers", &[]));
    let source = fixture.dir.0.join("server-state");
    let snapshot = fixture.dir.0.join("moved-backup");
    let saved = symbiote_memory::backup::create(
        &source,
        &snapshot,
        &symbiote_memory::backup::BackupOptions::default(),
    )
    .unwrap();
    let staging = fixture.dir.0.join("restored-staging");
    symbiote_memory::backup::restore(&snapshot, &saved.manifest_sha256, &staging).unwrap();
    let preserved = fixture.dir.0.join("preserved-original");
    fs::rename(&source, &preserved).unwrap();
    fs::rename(&staging, &source).unwrap();
    let operations = fs::read(source.join("operations.jsonl")).unwrap();
    let knowledge = fs::read(source.join("knowledge.jsonl")).unwrap();
    let config = fixture.dir.0.join("server.json");
    assert_unreviewed_service_inactive(&config, &fixture);
    let status = success(fixture.command("policy-status", &[]));
    assert_eq!(status["activation_required"], true);
    assert!(!fixture
        .command(
            "policy-transition",
            &[
                "--previous-config",
                config.to_str().unwrap(),
                "--expected-policy",
                status["policy_sha256"].as_str().unwrap(),
                "--expected-head",
                status["journal_head_sha256"].as_str().unwrap(),
                "--reason",
                "renamed tree cannot bypass destination proof",
                "--review-relocation"
            ]
        )
        .status
        .success());
    assert_eq!(
        fs::read(source.join("operations.jsonl")).unwrap(),
        operations
    );
    assert_eq!(fs::read(source.join("knowledge.jsonl")).unwrap(), knowledge);
    assert_eq!(
        fs::read(preserved.join("operations.jsonl")).unwrap(),
        operations
    );
}

#[test]
fn maximum_service_manifest_rotates_maximum_public_snapshots_then_narrows_without_rewriting_history(
) {
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let template = fixture.server["peers"][0].clone();
    for index in 1..32 {
        let mut peer = template.clone();
        peer["alias"] = json!(format!("operator-peer-{index}"));
        peer["id"] = json!(format!("operator-peer-identity-{index}"));
        peer["certificate_sha256"] = json!(format!("{:064x}", index + 100));
        peer["access"].as_array_mut().unwrap().truncate(1);
        peer["access"][0]["artifacts"] = json!((0..32)
            .map(|item| format!("artifact-{index}-{item}"))
            .collect::<Vec<_>>());
        fixture.server["peers"].as_array_mut().unwrap().push(peer);
    }
    for peer in 1..32 {
        for artifact in 0..32 {
            let length = serde_json::to_vec(&fixture.server).unwrap().len();
            if length == 65_536 {
                break;
            }
            let value = fixture.server["peers"][peer]["access"][0]["artifacts"][artifact]
                .as_str()
                .unwrap()
                .to_string();
            let extra = (65_536 - length).min(128 - value.len());
            fixture.server["peers"][peer]["access"][0]["artifacts"][artifact] =
                json!(format!("{value}{}", "x".repeat(extra)));
        }
    }
    let raw = serde_json::to_vec(&fixture.server).unwrap();
    assert_eq!(
        raw.len(),
        65_536,
        "exact original maximum manifest admission"
    );
    fs::write(fixture.dir.0.join("server.json"), &raw).unwrap();
    success(fixture.command("peers", &[]));
    let state = fixture.dir.0.join("server-state");
    let marker = fs::read(state.join("operations-owner.json")).unwrap();
    let anchor = success(fixture.command("policy-status", &[]));
    assert!(serde_json::to_vec(&anchor["public_policy"]).unwrap().len() > 65_536);
    let previous = save_old_policy(&fixture); // use compact bytes: the 64KiB limit applies to input bytes, not pretty printing.
    fs::write(&previous, &raw).unwrap();
    let prefix = fs::read(state.join("operations.jsonl")).unwrap();
    fixture.server["limits"]["per_peer_requests"] = json!(63);
    fs::write(
        fixture.dir.0.join("server.json"),
        serde_json::to_vec(&fixture.server).unwrap(),
    )
    .unwrap();
    success(transition(&fixture, &previous, &anchor, false));
    assert!(fs::read(state.join("operations.jsonl"))
        .unwrap()
        .starts_with(&prefix));
    assert_eq!(
        fs::read(state.join("operations-owner.json")).unwrap(),
        marker
    );
    let anchor = success(fixture.command("policy-status", &[]));
    fs::write(&previous, serde_json::to_vec(&fixture.server).unwrap()).unwrap();
    fixture.server["peers"].as_array_mut().unwrap().truncate(1);
    fixture.save();
    success(transition(&fixture, &previous, &anchor, false));
    success(fixture.command("peers", &[]));
    let mut server = ServiceProcess::start(&fixture);
    assert_eq!(
        success(fixture.call(&fixture.request(
            "affine-context/v1",
            "after-large-policy",
            json!({"operation":"capabilities"})
        )))["identity"],
        fixture.ids[0]
    );
    server.stop();
}

#[test]
fn operator_peer_ids_win_alias_collisions_without_changing_authenticated_artifact_grants() {
    use symbiote_memory::knowledge::{assess, TrialCase, TrialCosts, TrialEvidence};
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut peer_b = fixture.server["peers"][0].clone();
    for access in peer_b["access"].as_array_mut().unwrap() {
        access["artifacts"] = json!(["b-allowed-only"]);
    }
    let mut peer_a = peer_b.clone();
    peer_a["id"] = json!("operator-peer-A");
    peer_a["alias"] = json!(fixture.ids[1]);
    peer_a["certificate_sha256"] = json!(TlsIdentity::from_pem_files(
        &fixture.dir.0.join("observer.pem"),
        &fixture.dir.0.join("observer.key")
    )
    .unwrap()
    .certificate_sha256());
    peer_a["server_name"] = json!("observer.symbiote.test");
    for access in peer_a["access"].as_array_mut().unwrap() {
        access["artifacts"] = json!(["*"]);
    }
    fixture.server["peers"] = json!([peer_a, peer_b]);
    fixture.save();
    {
        let owner = Store::open(&fixture.dir.0.join("server-state")).unwrap();
        let record = KnowledgeRecord {
            id: "b-forbidden".into(),
            revision: 1,
            source: "manual-lab-source".into(),
            scope: "affine-context/v1".into(),
            schema_fingerprint: affine_schema_fingerprint(3).unwrap(),
            payload: json!({"kind":"affine","width":3,"coefficients":3,"bias":false}),
            provenance: "Manual finite native artifact grant fixture".into(),
        };
        let evidence = TrialEvidence {
            evaluator: "manual-local-lab".into(),
            training_case_ids: vec!["train-zero".into()],
            training_inputs: vec![0],
            cases: (1u16..8)
                .map(|input| {
                    let expected = ((input & 3).count_ones() % 2) as u8;
                    TrialCase {
                        id: format!("case-{input}"),
                        input,
                        expected,
                        baseline: None,
                        candidate: expected,
                    }
                })
                .collect(),
            costs: TrialCosts {
                acquisition: 0,
                verification: 7,
                adoption: 1,
                baseline: 20,
                candidate: 8,
            },
        };
        KnowledgeStore::open(&fixture.dir.0.join("server-state"), owner.identity())
            .unwrap()
            .promote(record.clone(), assess(&record, &evidence).unwrap())
            .unwrap();
    }
    let mut service = ServiceProcess::start(&fixture);
    let mut a = SecureClient::connect(
        &fixture.endpoint("affine-context/v1", "knowledge.read"),
        &TlsClientConfig::new(
            "operator-peer-A".into(),
            TlsIdentity::from_pem_files(
                &fixture.dir.0.join("observer.pem"),
                &fixture.dir.0.join("observer.key"),
            )
            .unwrap(),
            &fs::read(fixture.dir.0.join("ca.pem")).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let request = fixture.request(
        "affine-context/v1",
        "a-broad-read",
        json!({"operation":"knowledge.read","artifact":"b-forbidden"}),
    );
    assert_eq!(
        a.call("knowledge.read", &request).unwrap()["record"]["id"],
        "b-forbidden"
    );
    a.revoke().unwrap();
    let mut b = SecureClient::connect(
        &fixture.endpoint("affine-context/v1", "knowledge.read"),
        &fixture.direct_client(&fixture.ids[1]),
    )
    .unwrap();
    assert!(
        b.call(
            "knowledge.read",
            &fixture.request(
                "affine-context/v1",
                "b-narrow-read",
                json!({"operation":"knowledge.read","artifact":"b-forbidden"})
            )
        )
        .is_err(),
        "authenticated B must not inherit A's broad alias-colliding grant"
    );
    drop(b);
    service.stop();
    let denial = success(fixture.command(
        "peer-revoke",
        &[
            "--peer",
            &fixture.ids[1],
            "--reason",
            "exact identity target",
        ],
    ));
    assert_eq!(denial["peer"], fixture.ids[1]);
    let peers = success(fixture.command("peers", &[]));
    assert_eq!(peers["peers"][0]["denied"], false);
    assert_eq!(peers["peers"][1]["denied"], true);
    let status = success(fixture.command("policy-status", &[]));
    let regrant = success(fixture.command(
        "peer-regrant",
        &[
            "--peer",
            &fixture.ids[1],
            "--expected-policy",
            status["policy_sha256"].as_str().unwrap(),
            "--expected-head",
            status["journal_head_sha256"].as_str().unwrap(),
            "--reason",
            "reviewed exact identity target",
            "--review-permission-change",
        ],
    ));
    assert_eq!(regrant["peer"], fixture.ids[1]);

    let request_path = fixture.dir.0.join("alias-contract-request.json");
    fs::write(
        &request_path,
        serde_json::to_vec(&fixture.request(
            "affine-context/v1",
            "alias-contract-connect",
            json!({"operation":"capabilities"}),
        ))
        .unwrap(),
    )
    .unwrap();
    for (index, certificate, key, expected, selector) in [
        (
            0,
            "observer.pem",
            "observer.key",
            "A",
            fixture.ids[1].as_str(),
        ),
        (1, "client.pem", "client.key", "B", "partner"),
    ] {
        let address = fixture.server["peers"][index]["address"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let remote_id = fixture.server["peers"][index]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let config = SecureServerConfig::new(
            address,
            remote_id,
            TlsIdentity::from_pem_files(&fixture.dir.0.join(certificate), &fixture.dir.0.join(key))
                .unwrap(),
            &fs::read(fixture.dir.0.join("ca.pem")).unwrap(),
            vec![SecurePeerGrant {
                id: fixture.ids[0].clone(),
                certificate_sha256: fixture.server["certificate_sha256"]
                    .as_str()
                    .unwrap()
                    .into(),
                scopes: std::collections::BTreeMap::from([(
                    "affine-context/v1".into(),
                    vec!["capabilities".into()],
                )]),
            }],
            SecureLimits {
                max_requests: 4,
                max_connections: 4,
                max_frame_bytes: 32768,
                timeout: Duration::from_millis(500),
            },
        )
        .unwrap();
        let mut partner = spawn_secure_server(config, move |session, _, _| {
            Ok(json!({"selected":expected,"authenticated_peer":session.peer_id}))
        })
        .unwrap();
        assert_eq!(success(fixture.command("connect",&["--peer",selector,"--request",request_path.to_str().unwrap()]))["selected"],expected,
            "connect preserves its alias-only selection contract even when an alias equals another peer ID");
        partner.shutdown().unwrap();
    }
}

#[test]
fn consumed_restore_metadata_cannot_be_deleted_or_rehashed_into_different_paths() {
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    absolute_service_material(&mut fixture);
    success(fixture.command("peers", &[]));
    let source = fixture.dir.0.join("server-state");
    let snapshot = fixture.dir.0.join("metadata-backup");
    let saved = symbiote_memory::backup::create(
        &source,
        &snapshot,
        &symbiote_memory::backup::BackupOptions::default(),
    )
    .unwrap();
    let parent = fixture.dir.0.join("metadata-restored");
    fs::create_dir(&parent).unwrap();
    let restored = parent.join("server-state");
    let mapping =
        symbiote_memory::backup::restore(&snapshot, &saved.manifest_sha256, &restored).unwrap();
    let config = parent.join("server.json");
    fs::copy(fixture.dir.0.join("server.json"), &config).unwrap();
    let status = success(public_config_command(&config, "policy-status", &[]));
    success(public_config_command(
        &config,
        "policy-transition",
        &[
            "--previous-config",
            fixture.dir.0.join("server.json").to_str().unwrap(),
            "--expected-policy",
            status["policy_sha256"].as_str().unwrap(),
            "--expected-head",
            status["journal_head_sha256"].as_str().unwrap(),
            "--reason",
            "approved metadata fixture restore",
            "--review-relocation",
        ],
    ));
    let marker = restored.join(format!(
        "restored-owner-{}.json",
        mapping.restore_mapping_sha256
    ));
    let original = fs::read(&marker).unwrap();
    let operations = fs::read(restored.join("operations.jsonl")).unwrap();
    let knowledge = fs::read(restored.join("knowledge.jsonl")).unwrap();
    fs::remove_file(&marker).unwrap();
    assert!(
        !public_config_command(&config, "peers", &[])
            .status
            .success(),
        "consumed marker loss must not erase its activation binding"
    );
    let mut forged: Value = serde_json::from_slice(&original).unwrap();
    forged["restored_state"] = json!(symbiote_memory::backup::normalize_state_location(
        &fixture.dir.0.join("different-restored-destination")
    )
    .unwrap());
    let bytes = serde_json::to_vec(&forged).unwrap();
    let renamed = restored.join(format!("restored-owner-{}.json", hash(&bytes)));
    fs::write(&renamed, &bytes).unwrap();
    assert_eq!(
        symbiote_memory::backup::restore_mappings(&restored, &fixture.ids[0])
            .unwrap()
            .len(),
        1,
        "forged metadata is structurally valid and fully rehashed"
    );
    assert!(
        !public_config_command(&config, "peers", &[])
            .status
            .success(),
        "the original consumed digest/path binding still must match"
    );
    assert_eq!(
        fs::read(restored.join("operations.jsonl")).unwrap(),
        operations
    );
    assert_eq!(
        fs::read(restored.join("knowledge.jsonl")).unwrap(),
        knowledge
    );
    fs::remove_file(renamed).unwrap();
    fs::write(&marker, &original).unwrap();
    success(public_config_command(&config, "peers", &[]));
}

#[test]
fn nested_unactivated_restores_hold_without_implicitly_approving_ancestor_mappings() {
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    absolute_service_material(&mut fixture);
    success(fixture.command("peers", &[]));
    let mut source = fixture.dir.0.join("server-state");
    let mut previous = fixture.dir.0.join("server.json");
    for index in 0..2 {
        let snapshot = fixture.dir.0.join(format!("unactivated-backup-{index}"));
        let saved = symbiote_memory::backup::create(
            &source,
            &snapshot,
            &symbiote_memory::backup::BackupOptions::default(),
        )
        .unwrap();
        let parent = fixture.dir.0.join(format!("unactivated-restore-{index}"));
        fs::create_dir(&parent).unwrap();
        let destination = parent.join("server-state");
        symbiote_memory::backup::restore(&snapshot, &saved.manifest_sha256, &destination).unwrap();
        let config = parent.join("server.json");
        fs::copy(&previous, &config).unwrap();
        if index == 1 {
            let status = success(public_config_command(&config, "policy-status", &[]));
            assert_eq!(
                status["unconsumed_restore_mappings"]
                    .as_array()
                    .unwrap()
                    .len(),
                2
            );
            let operations = fs::read(destination.join("operations.jsonl")).unwrap();
            assert_unreviewed_service_inactive(&config, &fixture);
            let rejected = public_config_command(
                &config,
                "policy-transition",
                &[
                    "--previous-config",
                    previous.to_str().unwrap(),
                    "--expected-policy",
                    status["policy_sha256"].as_str().unwrap(),
                    "--expected-head",
                    status["journal_head_sha256"].as_str().unwrap(),
                    "--reason",
                    "cannot approve unreviewed ancestor implicitly",
                    "--review-relocation",
                ],
            );
            assert!(!rejected.status.success());
            assert!(String::from_utf8_lossy(&rejected.stderr).contains("nested unactivated"));
            assert_eq!(
                fs::read(destination.join("operations.jsonl")).unwrap(),
                operations
            );
        }
        source = destination;
        previous = config;
    }
}

#[test]
fn unregistered_restored_owner_cannot_initialize_service_history_before_review() {
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    absolute_service_material(&mut fixture);
    let source = fixture.dir.0.join("server-state");
    assert!(!source.join("operations.jsonl").exists());
    assert!(!source.join("knowledge.jsonl").exists());
    let snapshot = fixture.dir.0.join("unregistered-owner-backup");
    let saved = symbiote_memory::backup::create(
        &source,
        &snapshot,
        &symbiote_memory::backup::BackupOptions::default(),
    )
    .unwrap();
    let parent = fixture.dir.0.join("unregistered-owner-restored");
    fs::create_dir(&parent).unwrap();
    let restored = parent.join("server-state");
    symbiote_memory::backup::restore(&snapshot, &saved.manifest_sha256, &restored).unwrap();
    let config = parent.join("server.json");
    fs::copy(fixture.dir.0.join("server.json"), &config).unwrap();
    let ledger = fs::read(restored.join("ledger.jsonl")).unwrap();
    assert!(!public_config_command(&config, "peers", &[])
        .status
        .success());
    assert!(!public_config_command(&config, "serve", &[])
        .status
        .success());
    for name in [
        "knowledge.jsonl",
        "operations.jsonl",
        "operations-owner.json",
    ] {
        assert!(
            !restored.join(name).exists(),
            "unreviewed startup must not initialize {name}"
        );
    }
    assert_eq!(fs::read(restored.join("ledger.jsonl")).unwrap(), ledger);
}
