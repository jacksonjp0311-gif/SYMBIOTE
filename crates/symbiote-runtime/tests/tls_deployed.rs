use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use symbiote_memory::Store;
use symbiote_protocol::{SecureClient, SecureEndpoint, SecureLimits, TlsClientConfig, TlsIdentity};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "symbiote-tls-deployed-{}-{}",
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

struct Fixture {
    directory: Directory,
    manifest: Value,
    roles: Value,
}
impl Fixture {
    fn new() -> Self {
        let directory = Directory::new();
        let state = directory.0.join("state");
        let prepared = Command::new(env!("CARGO_BIN_EXE_symbiote"))
            .args(["prepare-tls-state", "--json", "--state"])
            .arg(&state)
            .output()
            .unwrap();
        assert!(
            prepared.status.success(),
            "{}",
            String::from_utf8_lossy(&prepared.stderr)
        );
        let preparation: Value = serde_json::from_slice(&prepared.stdout).unwrap();
        assert_eq!(preparation["network_requests"], 0);
        assert_eq!(preparation["learning_artifacts_created"], 0);
        assert_eq!(preparation["certificates_created"], 0);
        let roles = preparation["roles"].clone();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::from_params(&ca_params, ca_key);
        fs::write(directory.0.join("ca.pem"), ca.pem()).unwrap();
        let mut manifest = json!({"schema":"symbiote.tls-deployment/1","scope":"boolean-affine/v1","ca_certificate":"ca.pem","limits":{"max_requests":128,"max_connections":64,"max_frame_bytes":32768,"timeout_ms":1000}});
        for role in [
            "controller",
            "exact",
            "linear",
            "oracle_exact",
            "oracle_linear",
        ] {
            let mut params = CertificateParams::new(vec![format!("{role}.symbiote.test")]).unwrap();
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = match role {
                "controller" => vec![ExtendedKeyUsagePurpose::ClientAuth],
                "exact" | "linear" => vec![
                    ExtendedKeyUsagePurpose::ClientAuth,
                    ExtendedKeyUsagePurpose::ServerAuth,
                ],
                _ => vec![ExtendedKeyUsagePurpose::ServerAuth],
            };
            let key = KeyPair::generate().unwrap();
            let cert = params.signed_by(&key, &issuer).unwrap();
            let cert_pem = cert.pem();
            let key_pem = key.serialize_pem();
            let identity = TlsIdentity::from_pem(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap();
            fs::write(directory.0.join(format!("{role}.pem")), cert_pem).unwrap();
            fs::write(directory.0.join(format!("{role}.key")), key_pem).unwrap();
            let id = roles[role]["id"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| format!("test-{role}"));
            let mut entry = json!({"id":id,"certificate":format!("{role}.pem"),"private_key":format!("{role}.key"),"certificate_sha256":identity.certificate_sha256()});
            if role != "controller" {
                entry["server_name"] = json!(format!("{role}.symbiote.test"));
                entry["bind_address"] = json!("127.0.0.1:0");
            }
            manifest[role] = entry;
        }
        let fixture = Self {
            directory,
            manifest,
            roles,
        };
        fixture.save();
        fixture
    }
    fn state(&self) -> PathBuf {
        self.directory.0.join("state")
    }
    fn save(&self) {
        fs::write(
            self.directory.0.join("tls.json"),
            serde_json::to_vec_pretty(&self.manifest).unwrap(),
        )
        .unwrap();
    }
    fn run(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_symbiote"))
            .args(["network-research", "--json", "--state"])
            .arg(self.state())
            .arg("--receipts")
            .arg(self.directory.0.join("report.json"))
            .arg("--tls-config")
            .arg(self.directory.0.join("tls.json"))
            .output()
            .unwrap()
    }
    fn ledger_bytes(&self) -> Vec<Vec<u8>> {
        [
            self.state(),
            self.state().join("network-tls/exact"),
            self.state().join("network-tls/linear"),
        ]
        .iter()
        .map(|path| fs::read(path.join("ledger.jsonl")).unwrap())
        .collect()
    }
    fn assert_no_learning(&self) {
        for role in ["exact", "linear"] {
            let path = self
                .state()
                .join("network-tls")
                .join(role)
                .join("knowledge.jsonl");
            if path.exists() {
                assert_eq!(
                    fs::read_to_string(path).unwrap().lines().count(),
                    1,
                    "only the knowledge genesis may exist after rejection"
                );
            }
        }
        assert!(!self.directory.0.join("report.json").exists());
    }
}

#[test]
fn real_tls_native_agents_bind_private_identities_exchange_and_retain_after_restart() {
    let fixture = Fixture::new();
    let initial = fixture.ledger_bytes();
    let output = fixture.run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "symbiote.tls-network-research/1");
    assert_eq!(report["transport"]["protocol"], "symbiote/2");
    for flag in [
        "mutual_authentication",
        "explicit_ca_and_leaf_pins",
        "persistent_identity_bound",
        "revoked_session_rejected",
        "certificate_revocation_rejected",
    ] {
        assert_eq!(report["transport"][flag], true, "{flag}");
    }
    assert_eq!(report["transport"]["plaintext_fallback"], false);
    for flag in [
        "forged_receipt_rejected",
        "cross_domain_receipt_rejected",
        "duplicate_receipt_rejected",
        "restart_retained_predictions",
        "process_separation",
    ] {
        assert_eq!(report[flag], true, "{flag}");
    }
    assert_eq!(report["restart_acquisition_requests"], 0);
    assert_eq!(report["restart_verification_requests"], 0);
    assert_eq!(report["restart_assessment_requests"], 0);
    for (i, role) in ["exact", "linear"].into_iter().enumerate() {
        assert_eq!(
            report["participants"][i]["identity"],
            fixture.roles[role]["id"]
        );
        assert_eq!(
            report["participants"][i]["authenticated_id"],
            fixture.roles[role]["id"]
        );
        assert_ne!(report["participants"][i]["pid"], report["controller_pid"]);
        assert_ne!(
            report["participants"][i]["instance_nonce"],
            report["participants"][i]["restart_instance_nonce"]
        );
        assert_eq!(report["participants"][i]["promotion"]["correct"], 11);
    }
    assert_ne!(
        report["participants"][0]["pid"],
        report["participants"][1]["pid"]
    );
    assert_eq!(
        fixture.ledger_bytes(),
        initial,
        "role preparation must preserve private identities"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE KEY"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE KEY"));
    let again = fixture.run();
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    let repeated: Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(repeated["identity"], report["identity"]);
    assert_eq!(repeated["participants"][0]["promotion"]["promoted"], false);
    assert_eq!(repeated["participants"][1]["promotion"]["promoted"], false);
}

#[test]
fn wrong_pin_durable_identity_scope_and_nonlocal_bind_fail_without_learning() {
    for fault in ["pin", "identity", "scope", "bind", "unknown-field"] {
        let mut fixture = Fixture::new();
        let original = fixture.ledger_bytes();
        match fault {
            "pin" => fixture.manifest["exact"]["certificate_sha256"] = json!("0".repeat(64)),
            "identity" => {
                fixture.manifest["exact"]["id"] = json!("symbiote-000000000000000000000000")
            }
            "scope" => fixture.manifest["scope"] = json!("another-scope/v1"),
            "bind" => fixture.manifest["exact"]["bind_address"] = json!("0.0.0.0:0"),
            _ => fixture.manifest["unrecognized_option"] = json!(true),
        }
        fixture.save();
        let output = fixture.run();
        assert!(!output.status.success(), "{fault}");
        assert_eq!(fixture.ledger_bytes(), original);
        fixture.assert_no_learning();
        assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE KEY"));
    }
}

#[test]
fn wrong_ca_and_certificate_name_are_rejected_without_plaintext_fallback() {
    for fault in ["ca", "name"] {
        let mut fixture = Fixture::new();
        let original = fixture.ledger_bytes();
        if fault == "ca" {
            let foreign = Fixture::new();
            fs::copy(
                foreign.directory.0.join("ca.pem"),
                fixture.directory.0.join("foreign-ca.pem"),
            )
            .unwrap();
            fixture.manifest["ca_certificate"] = json!("foreign-ca.pem");
        } else {
            fixture.manifest["exact"]["server_name"] = json!("wrong.symbiote.test");
        }
        fixture.save();
        let began = Instant::now();
        let output = fixture.run();
        assert!(!output.status.success(), "{fault}");
        assert!(began.elapsed() < Duration::from_secs(12));
        assert_eq!(fixture.ledger_bytes(), original);
        fixture.assert_no_learning();
        assert!(
            Store::open(&fixture.state().join("network-tls/exact")).is_ok(),
            "rejected TLS must still shut down its owned child cleanly"
        );
    }
}

#[test]
fn duplicate_roles_mismatched_keys_and_oversized_credentials_fail_without_learning() {
    for fault in [
        "certificate-alias",
        "identity-alias",
        "mismatched-key",
        "certificate-budget",
        "key-budget",
        "manifest-budget",
    ] {
        let mut fixture = Fixture::new();
        let original = fixture.ledger_bytes();
        match fault {
            "certificate-alias" => {
                for field in ["certificate", "private_key", "certificate_sha256"] {
                    fixture.manifest["linear"][field] = fixture.manifest["exact"][field].clone();
                }
            }
            "identity-alias" => {
                fixture.manifest["linear"]["id"] = fixture.manifest["exact"]["id"].clone();
            }
            "mismatched-key" => {
                fixture.manifest["exact"]["private_key"] = json!("linear.key");
            }
            "certificate-budget" => {
                fs::write(fixture.directory.0.join("exact.pem"), vec![b'X'; 65_537]).unwrap();
            }
            "key-budget" => {
                fs::write(fixture.directory.0.join("exact.key"), vec![b'X'; 16_385]).unwrap();
            }
            "manifest-budget" => {}
            _ => unreachable!(),
        }
        fixture.save();
        if fault == "manifest-budget" {
            fs::write(fixture.directory.0.join("tls.json"), vec![b' '; 16_385]).unwrap();
        }
        let output = fixture.run();
        assert!(!output.status.success(), "{fault}");
        assert_eq!(fixture.ledger_bytes(), original, "{fault}");
        fixture.assert_no_learning();
        for stream in [&output.stdout, &output.stderr] {
            assert!(
                !String::from_utf8_lossy(stream).contains("PRIVATE KEY"),
                "credential content leaked after {fault}"
            );
        }
    }
}

struct RawTlsChild {
    child: Child,
    input: Option<ChildStdin>,
    ready: Value,
}
impl Drop for RawTlsChild {
    fn drop(&mut self) {
        if let Some(mut input) = self.input.take() {
            let _ = input.write_all(b"{\"command\":\"shutdown\"}\n");
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while self.child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        if self.child.try_wait().unwrap().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}
fn raw_child(fixture: &Fixture) -> RawTlsChild {
    let config = json!({"version":2,"id":fixture.roles["exact"]["id"],"controller":fixture.roles["controller"]["id"],"peer":fixture.roles["linear"]["id"],"token":"","oracle":{"id":"test-oracle_exact","address":"127.0.0.1:9","token":""},"state":fixture.state().join("network-tls/exact"),"source_domain":"test-source","target_domain":"test-target","width":4,"linear":false,"lease_ms":10000,"fault":"","tls":{
        "material":{"certificate_pem":fs::read_to_string(fixture.directory.0.join("exact.pem")).unwrap(),"private_key_pem":fs::read_to_string(fixture.directory.0.join("exact.key")).unwrap(),"certificate_sha256":fixture.manifest["exact"]["certificate_sha256"]},
        "ca_pem":fs::read_to_string(fixture.directory.0.join("ca.pem")).unwrap(),"controller_pin":fixture.manifest["controller"]["certificate_sha256"],"bind_address":"127.0.0.1:0","server_name":"exact.symbiote.test","oracle_pin":fixture.manifest["oracle_exact"]["certificate_sha256"],"oracle_server_name":"oracle_exact.symbiote.test","limits":{"max_requests":64,"max_connections":32,"max_frame_bytes":32768,"timeout_ms":150}}});
    let mut child = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .arg("__research-partner")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    serde_json::to_writer(&mut input, &config).unwrap();
    input.write_all(b"\n").unwrap();
    input.flush().unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let ready: Value = serde_json::from_str(&line).unwrap();
    RawTlsChild {
        child,
        input: Some(input),
        ready,
    }
}

#[test]
fn actual_tls_child_times_out_unauthenticated_socket_then_serves_pinned_controller() {
    let fixture = Fixture::new();
    let partner = raw_child(&fixture);
    let address = partner.ready["address"].as_str().unwrap().parse().unwrap();
    let began = Instant::now();
    let mut stalled = TcpStream::connect(address).unwrap();
    stalled
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let result = stalled.read(&mut [0; 1]);
    assert!(
        matches!(result, Ok(0))
            || result.as_ref().is_err_and(|e| [
                std::io::ErrorKind::ConnectionReset,
                std::io::ErrorKind::ConnectionAborted
            ]
            .contains(&e.kind()))
    );
    assert!(began.elapsed() < Duration::from_secs(2));
    let ca = fs::read(fixture.directory.0.join("ca.pem")).unwrap();
    let client = TlsClientConfig::new(
        fixture.roles["controller"]["id"].as_str().unwrap().into(),
        TlsIdentity::from_pem_files(
            &fixture.directory.0.join("controller.pem"),
            &fixture.directory.0.join("controller.key"),
        )
        .unwrap(),
        &ca,
    )
    .unwrap();
    let endpoint = SecureEndpoint {
        server_id: fixture.roles["exact"]["id"].as_str().unwrap().into(),
        address,
        server_name: "exact.symbiote.test".into(),
        server_certificate_sha256: fixture.manifest["exact"]["certificate_sha256"]
            .as_str()
            .unwrap()
            .into(),
        scope: "boolean-affine/v1".into(),
        operations: vec!["status".into()],
        limits: SecureLimits {
            max_requests: 64,
            max_connections: 32,
            max_frame_bytes: 32768,
            timeout: Duration::from_secs(1),
        },
    };
    let mut connection = SecureClient::connect(&endpoint, &client).unwrap();
    assert_eq!(
        connection.call("status", &json!({})).unwrap()["identity"],
        fixture.roles["exact"]["id"]
    );
    connection.revoke().unwrap();
}

#[test]
fn certificate_from_same_ca_cannot_impersonate_the_authorized_controller() {
    let fixture = Fixture::new();
    let partner = raw_child(&fixture);
    let ca = fs::read(fixture.directory.0.join("ca.pem")).unwrap();
    let endpoint = SecureEndpoint {
        server_id: fixture.roles["exact"]["id"].as_str().unwrap().into(),
        address: partner.ready["address"].as_str().unwrap().parse().unwrap(),
        server_name: "exact.symbiote.test".into(),
        server_certificate_sha256: fixture.manifest["exact"]["certificate_sha256"]
            .as_str()
            .unwrap()
            .into(),
        scope: "boolean-affine/v1".into(),
        operations: vec!["status".into()],
        limits: SecureLimits::default(),
    };
    let impersonator = TlsClientConfig::new(
        fixture.roles["controller"]["id"].as_str().unwrap().into(),
        TlsIdentity::from_pem_files(
            &fixture.directory.0.join("exact.pem"),
            &fixture.directory.0.join("exact.key"),
        )
        .unwrap(),
        &ca,
    )
    .unwrap();
    assert!(SecureClient::connect(&endpoint, &impersonator).is_err());
    let authorized = TlsClientConfig::new(
        fixture.roles["controller"]["id"].as_str().unwrap().into(),
        TlsIdentity::from_pem_files(
            &fixture.directory.0.join("controller.pem"),
            &fixture.directory.0.join("controller.key"),
        )
        .unwrap(),
        &ca,
    )
    .unwrap();
    let mut client = SecureClient::connect(&endpoint, &authorized).unwrap();
    assert_eq!(
        client.call("status", &json!({})).unwrap()["active_models"],
        0
    );
    client.revoke().unwrap();
}

#[test]
fn preparation_is_idempotent_and_refuses_copied_role_identity_without_reset() {
    let fixture = Fixture::new();
    let original = fixture.ledger_bytes();
    let prepare = || {
        Command::new(env!("CARGO_BIN_EXE_symbiote"))
            .args(["prepare-tls-state", "--json", "--state"])
            .arg(fixture.state())
            .output()
            .unwrap()
    };
    let again = prepare();
    assert!(again.status.success());
    let repeat: Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(repeat["roles"], fixture.roles);
    assert_eq!(fixture.ledger_bytes(), original);
    fixture.assert_no_learning();
    fs::copy(
        fixture.state().join("network-tls/exact/ledger.jsonl"),
        fixture.state().join("network-tls/linear/ledger.jsonl"),
    )
    .unwrap();
    let copied = fixture.ledger_bytes();
    assert!(!prepare().status.success());
    assert_eq!(fixture.ledger_bytes(), copied);
    fixture.assert_no_learning();
}

#[test]
fn tls_cli_rejects_wrong_commands_duplicates_faults_and_missing_configuration() {
    let directory = Directory::new();
    let absent_state = directory.0.join("untouched-state");
    for args in [
        vec!["demo", "--tls-config", "tls.json"],
        vec!["research", "--tls-config", "tls.json"],
        vec!["status", "--tls-config", "tls.json"],
        vec!["prepare-tls-state", "--tls-config", "tls.json"],
        vec![
            "network-research",
            "--tls-config",
            "one.json",
            "--tls-config",
            "two.json",
        ],
        vec![
            "network-research",
            "--tls-config",
            "tls.json",
            "--fault",
            "startup-timeout",
        ],
        vec!["network-research", "--tls-config"],
        vec!["network-research", "--tls-config", "missing.json"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_symbiote"))
            .args(["--state"])
            .arg(&absent_state)
            .args(&args)
            .output()
            .unwrap();
        assert!(!result.status.success(), "{args:?}");
        assert!(
            !absent_state.exists(),
            "invalid TLS options must fail before state mutation: {args:?}"
        );
    }
}
