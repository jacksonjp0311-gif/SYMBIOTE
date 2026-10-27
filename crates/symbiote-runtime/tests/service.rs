use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
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

static NEXT: AtomicU64 = AtomicU64::new(0);
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
}
impl Fixture {
    fn new(ip: IpAddr) -> Self {
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
        Command::new(env!("CARGO_BIN_EXE_symbiote"))
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
        Command::new(env!("CARGO_BIN_EXE_symbiote"))
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
        "{}",
        String::from_utf8_lossy(&output.stderr)
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
        let mut child = Command::new(env!("CARGO_BIN_EXE_symbiote"))
            .args(["serve", "--json", "--config"])
            .arg(fixture.dir.0.join("server.json"))
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
    let denied = Command::new(env!("CARGO_BIN_EXE_symbiote"))
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
    let listed = Command::new(env!("CARGO_BIN_EXE_symbiote"))
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
    let recovery = Command::new(env!("CARGO_BIN_EXE_symbiote"))
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
