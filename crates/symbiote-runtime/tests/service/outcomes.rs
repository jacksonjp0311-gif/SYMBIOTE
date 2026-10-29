//! Two ordinary native engines: receiver goals, not harness-written success.
use super::*;

struct Running {
    child: Child,
    input: Option<ChildStdin>,
    root: PathBuf,
    tag: String,
    pid: u32,
}
impl Running {
    fn start(f: &Fixture, role: &str, tag: &str) -> Self {
        let mut child = Command::new(native_binary())
            .args(["run", "--json", "--config"])
            .arg(f.dir.0.join(format!("{role}.json")))
            .arg("--run-policy")
            .arg(f.dir.0.join(format!("{role}-policy.json")))
            .arg("--receipts")
            .arg(f.dir.0.join(tag))
            .stdin(Stdio::piped())
            .stdout(fs::File::create(f.dir.0.join(format!("{tag}-stdout.jsonl"))).unwrap())
            .stderr(fs::File::create(f.dir.0.join(format!("{tag}-stderr.txt"))).unwrap())
            .spawn()
            .unwrap();
        let pid = child.id();
        let input = child.stdin.take();
        Self {
            child,
            input,
            root: f.dir.0.clone(),
            tag: tag.into(),
            pid,
        }
    }
    fn wait(&mut self) -> Value {
        let until = Instant::now() + Duration::from_secs(16);
        while self.child.try_wait().unwrap().is_none() && Instant::now() < until {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            self.child.try_wait().unwrap().is_some(),
            "native outcome process exceeded bound"
        );
        let status = self.child.wait().unwrap();
        drop(self.input.take());
        assert!(
            status.success(),
            "native {} failed: {}\n{}",
            self.tag,
            fs::read_to_string(self.root.join(format!("{}-stderr.txt", self.tag))).unwrap(),
            fs::read_to_string(self.root.join(format!("{}-stdout.jsonl", self.tag))).unwrap()
        );
        serde_json::from_slice(&fs::read(self.root.join(&self.tag).join("summary.json")).unwrap())
            .unwrap()
    }
    fn stop(&mut self) -> Value {
        if let Some(mut input) = self.input.take() {
            if self.child.try_wait().unwrap().is_none() {
                input.write_all(b"{\"command\":\"shutdown\"}\n").unwrap();
            }
        }
        self.wait()
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
fn events(f: &Fixture, tag: &str) -> Vec<Value> {
    fs::read_to_string(f.dir.0.join(tag).join("events.jsonl"))
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}
fn rows(f: &Fixture, role: &str) -> Vec<Value> {
    fs::read_to_string(f.dir.0.join(format!("{role}-state/operations.jsonl")))
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}
fn channel_rows(f: &Fixture, phase: &str) -> Vec<Value> {
    rows(f, "client")
        .into_iter()
        .filter(|r| {
            r["payload"]["decision"]["details"]["schema"] == "symbiote.contribution-channel/1"
                && r["payload"]["decision"]["details"]["event"]["phase"] == phase
        })
        .collect()
}
fn fixture() -> Fixture {
    let mut f = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    for cfg in [&mut f.server, &mut f.client] {
        let context = cfg["contexts"][0].clone();
        cfg["contexts"] = json!([context]);
        let mut access = cfg["peers"][0]["access"][0].clone();
        access["operations"]
            .as_array_mut()
            .unwrap()
            .push(json!("outcome.read"));
        cfg["peers"][0]["access"] = json!([access]);
        cfg["limits"]["max_frame_bytes"] = json!(65536);
        cfg["limits"]["model_work"] = json!(1_000_000);
    }
    let source = json!({"schema":"symbiote.local-truth/3","scope":"affine-context/v1","family":{"kind":"affine","width":3,"outputs":(0..8u16).map(|x|((x&3).count_ones()%2)as u8).collect::<Vec<_>>()}});
    let bytes = serde_json::to_vec(&source).unwrap();
    fs::write(f.dir.0.join("source.json"), &bytes).unwrap();
    f.client["contexts"][0]["truth_fixture"] = json!("source.json");
    f.client["contexts"][0]["truth_sha256"] = json!(hash(&bytes));
    f.save();
    let mut policies = Vec::new();
    for (role, cfg) in [("server", &f.server), ("client", &f.client)] {
        let pins = success(configured_command(
            &f,
            &format!("{role}.json"),
            "peers",
            &[],
        ));
        policies.push((role,json!({"schema":"symbiote.cognition-policy/1","expected_identity":cfg["identity"],"service_policy_sha256":pins["policy_sha256"],"max_episodes":if role=="server"{128}else{8},"max_duration_ms":12000,"interval_ms":if role=="server"{20}else{100},"max_rpc_attempts":64,"max_model_work":1_000_000,"max_plaintext_bytes":67108864,"max_candidates_per_episode":1,"max_contributions_per_episode":if role=="client"{1}else{0},"peers":["partner"],"scopes":["affine-context/v1"],"contribute":role=="client"})));
    }
    let receiver_pin = policies[0].1["service_policy_sha256"].clone();
    let fixture_pin = f.server["contexts"][0]["truth_sha256"].clone();
    policies[0].1["outcomes"] = json!({"schema":"symbiote.contribution-policy/1","receiver":{"peer":"partner","scope":"affine-context/v1","fixture_sha256":fixture_pin,"goal":7,"max_candidates_per_episode":1}});
    policies[1].1["observation"] = json!({"schema":"symbiote.observation-permit/1","scopes":["affine-context/v1"],"max_queries_total":8,"max_gf2_work_total":100000,"heldout_cases":1});
    policies[1].1["outcomes"] = json!({"schema":"symbiote.contribution-policy/1","sender":{"peer":"partner","scope":"affine-context/v1","receiver_policy_sha256":receiver_pin,"fixture_sha256":fixture_pin,"goal":7,"max_polls":12}});
    for (role, p) in policies {
        fs::write(
            f.dir.0.join(format!("{role}-policy.json")),
            serde_json::to_vec(&p).unwrap(),
        )
        .unwrap();
    }
    f
}
fn copy_public(source: &Path, dest: &Path) {
    fs::create_dir_all(dest).unwrap();
    for e in fs::read_dir(source).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|s| s == "key")
            || p.file_name()
                .is_some_and(|s| s.to_string_lossy().contains("lock"))
        {
            continue;
        }
        let target = dest.join(p.file_name().unwrap());
        if p.is_dir() {
            copy_public(&p, &target);
        } else {
            fs::copy(p, target).unwrap();
        }
    }
}
#[test]
fn zero_contribution_allowance_never_sends_a_receiver_channel_offer() {
    let f = fixture();
    let policy = f.dir.0.join("client-policy.json");
    let mut v: Value = serde_json::from_slice(&fs::read(&policy).unwrap()).unwrap();
    v["max_contributions_per_episode"] = json!(0);
    fs::write(policy, serde_json::to_vec(&v).unwrap()).unwrap();
    let mut receiver = Running::start(&f, "server", "zero-receiver");
    thread::sleep(Duration::from_millis(120));
    let mut sender = Running::start(&f, "client", "zero-sender");
    let summary = sender.wait();
    receiver.stop();
    assert_eq!(summary["fresh_promotions"], 1);
    assert_eq!(summary["quarantined_contributions"], 0);
    assert_eq!(summary["receiver_outcomes_verified"], 0);
    assert!(!rows(&f, "server")
        .iter()
        .any(|r| r["payload"]["event"] == "quarantined"));
}
#[test]
fn two_native_agents_reconcile_receiver_owned_outcome_and_restart() {
    let _selected = cognition_binary_override();
    let f = fixture();
    let mut receiver = Running::start(&f, "server", "receiver-first");
    thread::sleep(Duration::from_millis(120));
    let mut sender = Running::start(&f, "client", "sender-first");
    let first = sender.wait();
    let receiver_first = receiver.stop();
    assert_eq!(first["receiver_outcomes_verified"], 1);
    assert_eq!(first["receiver_capability_outcomes_verified"], 1);
    assert_eq!(first["partner_benefits_verified"], 0);
    assert_eq!(first["fresh_promotions"], 1);
    assert_eq!(
        first["learning_counters"]["promotions"],
        json!({"ordinary_learning":1,"receiver_role":0,"total_new":1})
    );
    assert_eq!(
        receiver_first["fresh_promotions"], 0,
        "legacy ordinary-learning-only field stays readable"
    );
    assert_eq!(
        receiver_first["learning_counters"]["promotions"],
        json!({"ordinary_learning":0,"receiver_role":1,"total_new":1})
    );
    assert_eq!(
        receiver_first["learning_counters"]["current_active_local"]["capability_outcomes"]
            ["receiver_role"],
        1
    );
    assert_eq!(
        first["learning_counters"]["completed_outcomes"]["partner_receiver"],
        1
    );
    assert_eq!(first["learning_counters"]["measured_benefits"]["total"], 0);
    let reconciled = channel_rows(&f, "reconciled");
    assert_eq!(reconciled.len(), 1);
    assert_eq!(
        reconciled[0]["payload"]["decision"]["details"]["event"]["cost_benefit_verified"],
        false
    );
    let received = events(&f, "sender-first")
        .into_iter()
        .find(|e| e["phase"] == "OUTCOME_RECEIVED" && e["details"]["response"]["status"] == "USED")
        .expect("actual API response includes complete receiver witness");
    let proof = &received["details"]["response"]["proof"];
    assert_eq!(proof["sender"], f.ids[1]);
    assert_eq!(proof["receiver"], f.ids[0]);
    assert!(!proof["ledgers"]["operations"].as_str().unwrap().is_empty());
    let receiver_rows = rows(&f, "server");
    assert!(receiver_rows
        .iter()
        .any(|r| r["payload"]["decision"]["details"]["event"]["phase"] == "store_use"));
    let outcome = receiver_rows
        .iter()
        .find(|r| {
            r["payload"]["decision"]["details"]["schema"] == "symbiote.learning-feedback/1"
                && r["payload"]["decision"]["details"]["event"]["phase"] == "outcome"
        })
        .unwrap();
    assert_eq!(
        outcome["payload"]["decision"]["details"]["event"]["outcome"]["baseline"]["kind"],
        "unknown"
    );
    assert_eq!(
        outcome["payload"]["decision"]["details"]["event"]["outcome"]["verified_benefit"],
        false
    );
    let mut receiver2 = Running::start(&f, "server", "receiver-restart");
    thread::sleep(Duration::from_millis(120));
    let mut sender2 = Running::start(&f, "client", "sender-restart");
    let restart = sender2.wait();
    let receiver_restart = receiver2.stop();
    assert_eq!(restart["observation_usage"]["queries"], 0);
    assert_eq!(restart["fresh_promotions"], 0);
    assert_eq!(restart["learning_counters"]["promotions"]["total_new"], 0);
    assert_eq!(
        receiver_restart["learning_counters"]["promotions"]["total_new"],
        0
    );
    assert_eq!(
        restart["learning_counters"]["reused_records"]["ordinary_learning"],
        1
    );
    assert_eq!(
        receiver_restart["learning_counters"]["reused_records"]["total"], 0,
        "mere reopen/replay grants no reuse credit"
    );
    assert_eq!(
        restart["learning_counters"]["completed_outcomes"]["total"],
        0
    );
    assert_eq!(
        restart["learning_counters"]["durable_history_completed_outcomes"]["partner_receiver"],
        1
    );
    assert_eq!(
        receiver_restart["learning_counters"]["durable_history_completed_outcomes"]
            ["receiver_role"],
        1
    );
    assert_eq!(restart["receiver_outcomes_verified"], 0);
    assert_eq!(channel_rows(&f, "reconciled").len(), 1);
    assert!(!events(&f, "sender-restart")
        .iter()
        .any(|e| e["phase"] == "OUTCOME_RECEIVED"));
    assert_ne!(sender.pid, sender2.pid);
    assert_ne!(receiver.pid, receiver2.pid);
    if let Some(dest) = std::env::var_os("SYMBIOTE_OUTCOME_ARTIFACTS").map(PathBuf::from) {
        assert!(!dest.exists());
        copy_public(&f.dir.0, &dest);
        let native = dest.join("symbiote-native.exe");
        fs::copy(native_binary(), &native).unwrap();
        let driver = dest.join("service-tests.exe");
        fs::copy(std::env::current_exe().unwrap(), &driver).unwrap();
        fn census(root: &Path, p: &Path, out: &mut Vec<Value>) {
            for e in fs::read_dir(p).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    census(root, &p, out);
                } else {
                    let b = fs::read(&p).unwrap();
                    out.push(json!({"path":p.strip_prefix(root).unwrap().to_string_lossy().replace('\\',"/"),"bytes":b.len(),"sha256":hash(&b)}));
                }
            }
        }
        let mut files = Vec::new();
        census(&dest, &dest, &mut files);
        files.sort_by_key(|r| r["path"].as_str().unwrap().to_string());
        fs::write(dest.join("outcome-artifacts.json"),serde_json::to_vec_pretty(&json!({"schema":"symbiote.receiver-outcome-native-proof/1","status":"PASS","native_sha256":hash(&fs::read(native).unwrap()),"driver_sha256":hash(&fs::read(driver).unwrap()),"first":first,"restart":restart,"receiver_first":receiver_first,"receiver_restart":receiver_restart,"pids":[sender.pid,receiver.pid,sender2.pid,receiver2.pid],"files":files,"private_keys_copied":false,"limitation":"trusted operator-pinned evaluator; receiver-owned use of a retained validation case, no unanswered task or measured economic gain"})).unwrap()).unwrap();
    }
}
