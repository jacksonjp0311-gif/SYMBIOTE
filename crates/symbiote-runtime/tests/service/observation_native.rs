//! Active local observation uses no imported record, language model or peer.
use super::*;

fn fixture(width: u8, queries: usize) -> CognitiveFixture {
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let scope = "own-affine-observation/v1";
    let outputs: Vec<_> = (0..(1u16 << width))
        .map(|input| ((input & 3).count_ones() % 2) as u8)
        .collect();
    let truth = json!({"schema":"symbiote.local-truth/3","scope":scope,"family":{"kind":"affine","width":width,"outputs":outputs}});
    let bytes = serde_json::to_vec(&truth).unwrap();
    fs::write(fixture.dir.0.join("observation-truth.json"), &bytes).unwrap();
    fixture.server["contexts"] = json!([{"scope":scope,"schema_fingerprint":affine_schema_fingerprint(width).unwrap(),"truth_fixture":"observation-truth.json","truth_sha256":hash(&bytes)}]);
    fixture.server["peers"] = json!([]);
    fixture.save();
    let actor = fixture.server.clone();
    fs::write(
        fixture.dir.0.join("actor.json"),
        serde_json::to_vec(&actor).unwrap(),
    )
    .unwrap();
    let peers = success(configured_command(&fixture, "actor.json", "peers", &[]));
    let policy = json!({"schema":"symbiote.cognition-policy/1","expected_identity":actor["identity"],"service_policy_sha256":peers["policy_sha256"],
        "max_episodes":2,"max_duration_ms":12000,"interval_ms":0,"max_rpc_attempts":16,"max_model_work":200000,
        "max_plaintext_bytes":1024,"max_candidates_per_episode":1,"max_contributions_per_episode":0,"peers":[],"scopes":[scope],"contribute":false,
        "observation":{"schema":"symbiote.observation-permit/1","scopes":[scope],"max_queries_total":queries,"max_gf2_work_total":100000,"heldout_cases":1}});
    let result = CognitiveFixture {
        fixture,
        actor,
        policy,
    };
    result.save();
    result
}

#[test]
fn normal_native_active_observation_learns_from_empty_and_restarts_without_queries() {
    let _binary = cognition_binary_override();
    let artifacts = std::env::var_os("SYMBIOTE_OBSERVATION_ARTIFACTS").map(PathBuf::from);
    if let Some(root) = &artifacts {
        assert!(!root.exists());
        fs::create_dir_all(root).unwrap();
    }
    let mut reports = Vec::new();
    for width in [3, 8] {
        let fixture = fixture(width, 16);
        let first = fixture.run("observation-first", false);
        assert_eq!(first["fresh_promotions"], 1);
        assert_eq!(first["active_models"], 1);
        assert_eq!(first["observation_usage"]["queries"], u64::from(width) + 2);
        assert_eq!(
            first["outbound_plaintext_traffic"]["connection_attempts"],
            0
        );
        let events = fixture.events("observation-first");
        assert_eq!(
            events
                .iter()
                .filter(|event| event["phase"] == "EXCHANGE")
                .count(),
            0
        );
        let learning = events
            .iter()
            .find(|event| event["phase"] == "LEARN")
            .unwrap();
        assert_eq!(learning["details"]["status"], "FRESH_PROMOTION");
        assert_eq!(
            learning["details"]["snapshot"]["schema"],
            "symbiote.affine-gf2-snapshot/1"
        );
        let again = fixture.run("observation-restart", false);
        assert_eq!(again["fresh_promotions"], 0);
        assert_eq!(again["active_models"], 1);
        assert_eq!(again["observation_usage"]["queries"], 0);
        assert_eq!(
            first["final_knowledge_anchor"],
            again["final_knowledge_anchor"]
        );
        let retained = fixture
            .events("observation-restart")
            .into_iter()
            .find(|event| event["phase"] == "LEARN")
            .unwrap();
        let first_pid = events
            .iter()
            .find(|event| event["phase"] == "READY")
            .unwrap()["details"]["pid"]
            .clone();
        let next_pid = fixture
            .events("observation-restart")
            .iter()
            .find(|event| event["phase"] == "READY")
            .unwrap()["details"]["pid"]
            .clone();
        assert_ne!(first_pid, next_pid);
        assert_eq!(retained["details"]["status"], "REUSED");
        assert!(!retained["details"]["retained_predictions"]
            .as_array()
            .unwrap()
            .is_empty());
        let knowledge = KnowledgeStore::open(
            &fixture.fixture.dir.0.join("server-state"),
            fixture.actor["identity"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(knowledge.active().len(), 1);
        for input in 0..(1u16 << width) {
            assert_eq!(
                knowledge.active()[0].predict(input).unwrap(),
                ((input & 3).count_ones() % 2) as u8
            );
        }
        assert!(knowledge.active()[0].provenance.len() <= 4096);
        drop(knowledge);
        reports.push(json!({"width":width,"directory":format!("width-{width}"),"first":first,"restart":again,"first_pid":first_pid,"restart_pid":next_pid}));
        if let Some(root) = &artifacts {
            super::graph_reciprocal::copy_public(
                &fixture.fixture.dir.0,
                &root.join(format!("width-{width}")),
            );
        }
    }
    if let Some(root) = artifacts {
        let (native_snapshot, service_snapshot) = super::graph_reciprocal::copy_binaries(&root);
        fn census(root: &Path, path: &Path, files: &mut Vec<Value>) {
            for entry in fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    census(root, &path, files);
                } else {
                    let bytes = fs::read(&path).unwrap();
                    files.push(json!({"path":path.strip_prefix(root).unwrap().to_string_lossy().replace('\\',"/"),"bytes":bytes.len(),"sha256":hash(&bytes)}));
                }
            }
        }
        let mut files = Vec::new();
        census(&root, &root, &mut files);
        files.sort_by_key(|file| file["path"].as_str().unwrap().to_string());
        fs::write(root.join("artifact-manifest.json"),serde_json::to_vec_pretty(&json!({"schema":"symbiote.observation-native-artifacts/1","native_binary":native_snapshot,"native_binary_sha256":hash(&fs::read(&native_snapshot).unwrap()),"service_tests":service_snapshot,"service_tests_sha256":hash(&fs::read(&service_snapshot).unwrap()),"files":files,"cases":reports,"private_keys_copied":false})).unwrap()).unwrap();
    }
}

#[test]
fn active_observation_budget_stops_without_promoting_unverified_knowledge() {
    let fixture = fixture(3, 2);
    let report = fixture.run("observation-bounded", false);
    assert_eq!(report["fresh_promotions"], 0);
    assert_eq!(report["active_models"], 0);
    assert_eq!(report["observation_usage"]["queries"], 2);
    assert!(report["reason"].as_str().unwrap().starts_with("budget:"));
    let events = fixture.events("observation-bounded");
    assert_eq!(
        events
            .iter()
            .filter(|event| event["phase"] == "OBSERVE")
            .count(),
        2
    );
    assert!(!events.iter().any(|event| event["phase"] == "LEARN"));
}
