//! Operational native cognition checks; no study sample or generalized benefit claims.
use super::*;

struct CognitiveFixture {
    fixture: Fixture,
    actor: Value,
    policy: Value,
}
impl CognitiveFixture {
    fn new(wrong_affine: bool) -> Self {
        Self::new_with_grant(wrong_affine, true)
    }
    fn new_with_grant(wrong_affine: bool, read_allowed: bool) -> Self {
        let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let actor_id = {
            let store = Store::open(&fixture.dir.0.join("actor-state")).unwrap();
            store.identity().to_string()
        };
        let pin = TlsIdentity::from_pem_files(
            &fixture.dir.0.join("observer.pem"),
            &fixture.dir.0.join("observer.key"),
        )
        .unwrap()
        .certificate_sha256()
        .to_string();
        let address = unused_address(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let contexts = fixture.client["contexts"].clone();
        for config in [&mut fixture.server, &mut fixture.client] {
            config["peers"].as_array_mut().unwrap().push(json!({"alias":"actor","id":actor_id,"address":address,
                "server_name":"observer.symbiote.test","certificate_sha256":pin,"access":contexts.as_array().unwrap().iter().map(|context|json!({"scope":context["scope"],"operations":OPS,"artifacts":["*"]})).collect::<Vec<_>>()}));
        }
        if wrong_affine {
            let truth = json!({"schema":"symbiote.local-truth/1","scope":"affine-context/v1","family":{"kind":"affine","width":3,
                "outputs":(0..8u16).map(|input|((input&5).count_ones()%2)as u8).collect::<Vec<_>>()}});
            let bytes = serde_json::to_vec(&truth).unwrap();
            fs::write(fixture.dir.0.join("other-affine-truth.json"), &bytes).unwrap();
            fixture.server["contexts"][0]["truth_fixture"] = json!("other-affine-truth.json");
            fixture.server["contexts"][0]["truth_sha256"] = json!(hash(&bytes));
        }
        fixture.save();
        let mut actor = fixture.client.clone();
        actor["state"] = json!("actor-state");
        actor["identity"] = json!(actor_id);
        actor["certificate"] = json!("observer.pem");
        actor["private_key"] = json!("observer.key");
        actor["certificate_sha256"] = json!(pin);
        actor["bind_address"] = json!(address);
        actor["peers"]=json!([("first",&fixture.server,"server"),("second",&fixture.client,"client")].into_iter().map(|(alias,config,role)|json!({
            "alias":alias,"id":config["identity"],"address":config["bind_address"],"server_name":format!("{role}.symbiote.test"),"certificate_sha256":config["certificate_sha256"],
            "access":contexts.as_array().unwrap().iter().map(|context|json!({"scope":context["scope"],"operations":OPS,"artifacts":["*"]})).collect::<Vec<_>>()})).collect::<Vec<_>>());
        if !read_allowed {
            for peer in actor["peers"].as_array_mut().unwrap() {
                for access in peer["access"].as_array_mut().unwrap() {
                    access["artifacts"] = json!(["no-native-source"]);
                }
            }
        }
        fs::write(
            fixture.dir.0.join("actor.json"),
            serde_json::to_vec(&actor).unwrap(),
        )
        .unwrap();
        let peers = success(configured_command(&fixture, "actor.json", "peers", &[]));
        let policy = json!({"schema":"symbiote.cognition-policy/1","expected_identity":actor_id,"service_policy_sha256":peers["policy_sha256"],
            "max_episodes":4,"max_duration_ms":12000,"interval_ms":5,"max_rpc_attempts":64,"max_model_work":200000,
            "max_plaintext_bytes":67108864,"max_candidates_per_episode":1,"max_contributions_per_episode":2,
            "peers":["first","second"],"scopes":["affine-context/v1","graph-context/v1"],"contribute":true});
        let result = Self {
            fixture,
            actor,
            policy,
        };
        result.save();
        result.seed(wrong_affine);
        result
    }
    fn save(&self) {
        fs::write(
            self.fixture.dir.0.join("actor.json"),
            serde_json::to_vec(&self.actor).unwrap(),
        )
        .unwrap();
        fs::write(
            self.fixture.dir.0.join("run-policy.json"),
            serde_json::to_vec(&self.policy).unwrap(),
        )
        .unwrap();
    }
    fn seed(&self, wrong_affine: bool) {
        let mut first = ServiceProcess::start(&self.fixture);
        let mut offer = self.fixture.offer(false);
        if wrong_affine {
            offer["body"]["offer"]["record"]["payload"]["coefficients"] = json!(5);
        }
        let candidate = success(self.fixture.call(&offer))["candidate"]
            .as_str()
            .unwrap()
            .to_string();
        first.stop();
        assert_eq!(
            success(
                self.fixture
                    .command("evaluate", &["--candidate", &candidate])
            )["status"],
            "PROMOTED"
        );
        let mut second = ServiceProcess::start_config(&self.fixture.dir.0.join("client.json"));
        let path = self.fixture.dir.0.join("seed-graph.json");
        fs::write(
            &path,
            serde_json::to_vec(&self.fixture.offer(true)).unwrap(),
        )
        .unwrap();
        let candidate = success(configured_command(
            &self.fixture,
            "server.json",
            "connect",
            &["--peer", "partner", "--request", path.to_str().unwrap()],
        ))["candidate"]
            .as_str()
            .unwrap()
            .to_string();
        second.stop();
        assert_eq!(
            success(configured_command(
                &self.fixture,
                "client.json",
                "evaluate",
                &["--candidate", &candidate]
            ))["status"],
            "PROMOTED"
        );
    }
    fn run(&self, tag: &str, eof: bool) -> Value {
        self.save();
        let receipts = self.fixture.dir.0.join(tag);
        let stdout =
            fs::File::create(self.fixture.dir.0.join(format!("{tag}-stdout.jsonl"))).unwrap();
        let stderr =
            fs::File::create(self.fixture.dir.0.join(format!("{tag}-stderr.txt"))).unwrap();
        let mut process = Command::new(env!("CARGO_BIN_EXE_symbiote"))
            .args(["run", "--json", "--config"])
            .arg(self.fixture.dir.0.join("actor.json"))
            .arg("--run-policy")
            .arg(self.fixture.dir.0.join("run-policy.json"))
            .arg("--receipts")
            .arg(&receipts)
            .stdin(Stdio::piped())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .unwrap();
        let input = process.stdin.take();
        let held_input = if eof {
            drop(input);
            None
        } else {
            input
        };
        let deadline = Instant::now() + Duration::from_secs(16);
        let status = loop {
            if let Some(status) = process.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                let _ = process.kill();
                let _ = process.wait();
                panic!("owned cognitive process exceeded deadline");
            }
            thread::sleep(Duration::from_millis(5));
        };
        drop(held_input);
        assert!(
            status.success(),
            "{}\n{}",
            fs::read_to_string(self.fixture.dir.0.join(format!("{tag}-stderr.txt"))).unwrap(),
            fs::read_to_string(self.fixture.dir.0.join(format!("{tag}-stdout.jsonl"))).unwrap()
        );
        serde_json::from_slice(&fs::read(receipts.join("summary.json")).unwrap()).unwrap()
    }
    fn events(&self, tag: &str) -> Vec<Value> {
        fs::read_to_string(self.fixture.dir.0.join(tag).join("events.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

#[test]
fn native_cognition_learns_two_families_cross_contributes_and_restarts_without_relearning() {
    let fixture = CognitiveFixture::new(false);
    let mut first = ServiceProcess::start(&fixture.fixture);
    let mut second = ServiceProcess::start_config(&fixture.fixture.dir.0.join("client.json"));
    let report = fixture.run("native-first", false);
    assert_eq!(report["fresh_promotions"], 2);
    assert_eq!(report["active_models"], 2);
    assert_eq!(report["quarantined_contributions"], 2);
    assert_eq!(report["partner_benefits_verified"], 0);
    let again = fixture.run("native-restart", false);
    assert_eq!(again["fresh_promotions"], 0);
    assert_eq!(again["active_models"], 2);
    assert_eq!(again["quarantined_contributions"], 0);
    assert_eq!(
        again["initial_knowledge_anchor"],
        again["final_knowledge_anchor"]
    );
    assert!(fixture
        .events("native-restart")
        .iter()
        .any(|event| event["phase"] == "LEARN" && event["details"]["status"] == "REUSED"));
    first.stop();
    second.stop();
    for event in fixture.events("native-first").iter().filter(|event| {
        event["phase"] == "CONTRIBUTE" && event["details"]["quarantined_offer"] == true
    }) {
        let details = &event["details"];
        let target = details["peer"].as_str().unwrap();
        let candidate = details["response"]["candidate"].as_str().unwrap();
        let manifest = if target == fixture.fixture.ids[0] {
            "server"
        } else {
            "client"
        };
        let result = success(configured_command(
            &fixture.fixture,
            &format!("{manifest}.json"),
            "evaluate",
            &["--candidate", candidate],
        ));
        assert_eq!(result["status"], "PROMOTED");
        fs::write(
            fixture
                .fixture
                .dir
                .0
                .join(format!("peer-evaluation-{manifest}.json")),
            serde_json::to_vec_pretty(&result).unwrap(),
        )
        .unwrap();
        let identity = &fixture.fixture.ids[usize::from(manifest == "client")];
        let knowledge = KnowledgeStore::open(
            &fixture.fixture.dir.0.join(format!("{manifest}-state")),
            identity,
        )
        .unwrap();
        assert_eq!(knowledge.active().len(), 2);
    }
    assert!(!fixture.fixture.dir.0.join("MUST-NOT-EXECUTE").exists());
    let operations =
        fs::read_to_string(fixture.fixture.dir.0.join("actor-state/operations.jsonl")).unwrap();
    assert_eq!(
        operations
            .lines()
            .filter(|line| line.contains("\"outcome\":\"verified_novel\""))
            .count(),
        2
    );
    assert!(
        success(configured_command(
            &fixture.fixture,
            "actor.json",
            "peers",
            &[]
        ))["network_requests"]
            == 0
    );
    retain_public_artifacts(&fixture);
}

#[test]
fn embedded_cognition_honors_host_cancellation_and_releases_the_owner() {
    let fixture = CognitiveFixture::new(false);
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let result = symbiote_runtime::service::run_with_cancel(
        &fixture.fixture.dir.0.join("actor.json"),
        &fixture.fixture.dir.0.join("run-policy.json"),
        &fixture.fixture.dir.0.join("embedded-cancelled"),
        cancelled,
    )
    .unwrap();
    assert_eq!(result["reason"], "cancelled");
    assert_eq!(result["episodes"], 0);
    assert_eq!(result["fresh_promotions"], 0);
    assert_eq!(result["quarantined_contributions"], 0);
    assert_eq!(
        result["initial_knowledge_anchor"],
        result["final_knowledge_anchor"]
    );
    let owner = Store::open(&fixture.fixture.dir.0.join("actor-state")).unwrap();
    assert_eq!(owner.identity(), result["identity"].as_str().unwrap());
}

#[test]
fn native_cognition_rejects_wrong_transfer_and_respects_owner_eof_and_rpc_budget() {
    let mut fixture = CognitiveFixture::new(true);
    fixture.policy["contribute"] = json!(false);
    let mut first = ServiceProcess::start(&fixture.fixture);
    let mut second = ServiceProcess::start_config(&fixture.fixture.dir.0.join("client.json"));
    let report = fixture.run("native-counterexample", false);
    assert_eq!(report["fresh_promotions"], 1);
    assert_eq!(report["active_models"], 1);
    assert!(fixture
        .events("native-counterexample")
        .iter()
        .any(|event| event["phase"] == "LEARN" && event["details"]["status"] == "REJECTED"));
    let eof = fixture.run("native-eof", true);
    assert_eq!(eof["fresh_promotions"], 0);
    assert!(eof["reason"] == "owner-eof" || eof["reason"] == "cancelled:before-rpc");
    fixture.policy["max_rpc_attempts"] = json!(1);
    let bounded = fixture.run("native-rpc-bound", false);
    assert_eq!(bounded["budget"]["rpc_attempts"], 1);
    assert_eq!(bounded["fresh_promotions"], 0);
    assert_eq!(bounded["reason"], "budget:global-rpc-or-plaintext");
    first.stop();
    second.stop();
}

#[test]
fn native_cognition_preserves_denials_and_cannot_read_outside_artifact_grants() {
    let denied = CognitiveFixture::new(false);
    for peer in ["first", "second"] {
        assert_eq!(
            success(configured_command(
                &denied.fixture,
                "actor.json",
                "peer-revoke",
                &["--peer", peer, "--reason", "native test operator denial"]
            ))["persistent"],
            true
        );
    }
    let report = denied.run("native-denied", false);
    assert_eq!(report["episodes"], 0);
    assert_eq!(report["fresh_promotions"], 0);
    assert_eq!(
        report["outbound_plaintext_traffic"]["connection_attempts"],
        0
    );
    assert_eq!(report["reason"], "no-eligible-authorized-partners");
    let outside = CognitiveFixture::new_with_grant(false, false);
    let mut first = ServiceProcess::start(&outside.fixture);
    let mut second = ServiceProcess::start_config(&outside.fixture.dir.0.join("client.json"));
    let report = outside.run("native-out-of-grant", false);
    assert_eq!(report["fresh_promotions"], 0);
    assert_eq!(report["active_models"], 0);
    assert!(outside
        .events("native-out-of-grant")
        .iter()
        .any(|event| event["phase"] == "REASSESS"
            && event["details"]["error"]
                .as_str()
                .is_some_and(|error| error.contains("allowlist"))));
    first.stop();
    second.stop();
}

#[test]
fn native_cognition_reserves_global_model_budget_before_graph_evaluation() {
    let mut fixture = CognitiveFixture::new(false);
    fixture.policy["max_model_work"] = json!(1024);
    fixture.policy["contribute"] = json!(false);
    let mut first = ServiceProcess::start(&fixture.fixture);
    let mut second = ServiceProcess::start_config(&fixture.fixture.dir.0.join("client.json"));
    let report = fixture.run("native-model-bound", false);
    assert_eq!(report["reason"], "budget:global-model-work");
    assert!(report["budget"]["model_work_reserved"].as_u64().unwrap() <= 1024);
    assert!(report["fresh_promotions"].as_u64().unwrap() <= 1);
    first.stop();
    second.stop();
    let identity = fixture.actor["identity"].as_str().unwrap();
    let store = KnowledgeStore::open(&fixture.fixture.dir.0.join("actor-state"), identity).unwrap();
    assert!(store
        .active()
        .iter()
        .all(|record| record.scope != "graph-context/v1"));
}

#[test]
fn native_reused_receipts_path_rejects_before_creating_owner_service_registration() {
    let fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let policy_sha=hash(&serde_json::to_vec(&json!({"manifest":fixture.server,"ca_sha256":hash(&fs::read(fixture.dir.0.join("ca.pem")).unwrap())})).unwrap());
    let policy = json!({"schema":"symbiote.cognition-policy/1","expected_identity":fixture.ids[0],"service_policy_sha256":policy_sha,
        "max_episodes":1,"max_duration_ms":1000,"interval_ms":0,"max_rpc_attempts":1,"max_model_work":1024,"max_plaintext_bytes":67108864,
        "max_candidates_per_episode":1,"max_contributions_per_episode":0,"peers":["partner"],"scopes":["affine-context/v1"],"contribute":false});
    let policy_path = fixture.dir.0.join("run-policy.json");
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let receipts = fixture.dir.0.join("existing-receipts");
    fs::create_dir(&receipts).unwrap();
    let state = fixture.dir.0.join("server-state");
    let original = fs::read(state.join("ledger.jsonl")).unwrap();
    assert!(!state.join("knowledge.jsonl").exists());
    assert!(!state.join("operations.jsonl").exists());
    let output = configured_command(
        &fixture,
        "server.json",
        "run",
        &[
            "--run-policy",
            policy_path.to_str().unwrap(),
            "--receipts",
            receipts.to_str().unwrap(),
        ],
    );
    assert!(!output.status.success());
    assert_eq!(fs::read(state.join("ledger.jsonl")).unwrap(), original);
    assert!(!state.join("knowledge.jsonl").exists());
    assert!(!state.join("operations.jsonl").exists());
    assert!(!state.join("operations-owner.json").exists());
}

fn retain_public_artifacts(fixture: &CognitiveFixture) {
    let Some(destination) = std::env::var_os("SYMBIOTE_COGNITION_ARTIFACTS") else {
        return;
    };
    let destination = PathBuf::from(destination);
    assert!(
        !destination.exists(),
        "cognitive evidence destination must be fresh"
    );
    fs::create_dir(&destination).unwrap();
    let mut entries = Vec::new();
    fn copy(source: &Path, destination: &Path, relative: &Path, entries: &mut Vec<Value>) {
        if source.is_dir() {
            fs::create_dir_all(destination).unwrap();
            for entry in fs::read_dir(source).unwrap() {
                let entry = entry.unwrap();
                copy(
                    &entry.path(),
                    &destination.join(entry.file_name()),
                    &relative.join(entry.file_name()),
                    entries,
                );
            }
            return;
        }
        let bytes = fs::read(source).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains("-----BEGIN PRIVATE KEY-----")
                && !text.contains("-----BEGIN RSA PRIVATE KEY-----")
        );
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        entries.push(
            json!({"path":relative.to_string_lossy(),"bytes":bytes.len(),"sha256":hash(&bytes)}),
        );
    }
    for name in [
        "actor-state",
        "server-state",
        "client-state",
        "native-first",
        "native-restart",
        "actor.json",
        "server.json",
        "client.json",
        "run-policy.json",
        "affine-truth.json",
        "graph-truth.json",
        "ca.pem",
        "server.pem",
        "client.pem",
        "observer.pem",
        "peer-evaluation-server.json",
        "peer-evaluation-client.json",
        "native-first-stdout.jsonl",
        "native-restart-stdout.jsonl",
        "native-first-stderr.txt",
        "native-restart-stderr.txt",
    ] {
        copy(
            &fixture.fixture.dir.0.join(name),
            &destination.join(name),
            Path::new(name),
            &mut entries,
        );
    }
    fs::write(destination.join("artifact-manifest.json"),serde_json::to_vec_pretty(&json!({"schema":"symbiote.cognition-engineering-artifacts/1","files":entries,
        "status":"operational integration evidence; no new independent scientific sample","private_keys_copied":false})).unwrap()).unwrap();
}
