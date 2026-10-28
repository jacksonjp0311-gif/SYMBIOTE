//! Generic smoke and separately registered once-only finite engineering cohort.
use super::*;
use symbiote_runtime::graph_transfer::{branch_orders, Measurement, ParallelWorld};

const SCOPES: [&str; 2] = ["reciprocal-x/v1", "reciprocal-y/v1"];

fn value_file(path: &Path, value: &Value) {
    let bytes = serde_json::to_vec_pretty(value).unwrap();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
}
fn partial_fixture(worlds: &[ParallelWorld; 2]) -> CognitiveFixture {
    let mut fixture = Fixture::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let contexts:Vec<_>=worlds.iter().enumerate().map(|(i,world)|{
        let bytes=serde_json::to_vec(&world.fixture(SCOPES[i])).unwrap();
        fs::write(fixture.dir.0.join(format!("partial-{i}.json")),&bytes).unwrap();
        json!({"scope":SCOPES[i],"schema_fingerprint":graph_schema_fingerprint(&world.schema).unwrap(),
            "truth_fixture":format!("partial-{i}.json"),"truth_sha256":hash(&bytes)})
    }).collect();
    let access: Vec<_> = contexts
        .iter()
        .map(|context| json!({"scope":context["scope"],"operations":OPS,"artifacts":["*"]}))
        .collect();
    let actor_id = Store::open(&fixture.dir.0.join("actor-state"))
        .unwrap()
        .identity()
        .to_string();
    let pin = TlsIdentity::from_pem_files(
        &fixture.dir.0.join("observer.pem"),
        &fixture.dir.0.join("observer.key"),
    )
    .unwrap()
    .certificate_sha256()
    .to_string();
    let address = unused_address(IpAddr::V4(Ipv4Addr::LOCALHOST));
    for config in [&mut fixture.server, &mut fixture.client] {
        config["contexts"] = json!(contexts);
        config["peers"][0]["access"] = json!(access);
        config["peers"]
            .as_array_mut()
            .unwrap()
            .push(json!({"alias":"actor","id":actor_id,"address":address,
            "server_name":"observer.symbiote.test","certificate_sha256":pin,"access":access}));
        config["limits"]["lifetime_ms"] = json!(60_000);
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
        "alias":alias,"id":config["identity"],"address":config["bind_address"],"server_name":format!("{role}.symbiote.test"),"certificate_sha256":config["certificate_sha256"],"access":access
    })).collect::<Vec<_>>());
    fs::write(
        fixture.dir.0.join("actor.json"),
        serde_json::to_vec(&actor).unwrap(),
    )
    .unwrap();
    let peers = success(configured_command(&fixture, "actor.json", "peers", &[]));
    let policy = json!({"schema":"symbiote.cognition-policy/1","expected_identity":actor_id,"service_policy_sha256":peers["policy_sha256"],
        "max_episodes":4,"max_duration_ms":12000,"interval_ms":5,"max_rpc_attempts":64,"max_model_work":200000,
        "max_plaintext_bytes":67108864,"max_candidates_per_episode":1,"max_contributions_per_episode":2,
        "peers":["first","second"],"scopes":SCOPES,"contribute":true});
    let result = CognitiveFixture {
        fixture,
        actor,
        policy,
    };
    result.save();
    result
}
fn request_map(
    fixture: &Fixture,
    index: usize,
    map: &symbiote_memory::knowledge::graph::GraphMap,
    training: &[u16],
    id: &str,
) -> Value {
    let record = KnowledgeRecord {
        id: id.into(),
        revision: 1,
        source: "metered-source-discovery".into(),
        scope: SCOPES[index].into(),
        schema_fingerprint: graph_schema_fingerprint(&map.schema).unwrap(),
        payload: map.to_payload().unwrap(),
        provenance:
            "bounded exact discovery; complete metered trace accompanies the engineering receipt"
                .into(),
    };
    fixture.request(SCOPES[index],id,json!({"operation":"candidate.submit","offer":{"record":record,"training_inputs":training}}))
}
fn cli_request(fixture: &Fixture, from: &str, request: &Value) -> Value {
    let path = fixture.dir.0.join("partial-request.json");
    fs::write(&path, serde_json::to_vec(request).unwrap()).unwrap();
    success(configured_command(
        fixture,
        &format!("{from}.json"),
        "connect",
        &["--peer", "partner", "--request", path.to_str().unwrap()],
    ))
}
fn traffic_units(value: &Value) -> u64 {
    [
        "rpc_sent_bytes",
        "rpc_received_bytes",
        "negotiation_sent_bytes",
        "negotiation_received_bytes",
    ]
    .iter()
    .map(|key| value[*key].as_u64().unwrap())
    .sum()
}
fn execution_units(value: &Value, price: u64) -> u64 {
    value["lookups"].as_array().unwrap().len() as u64 * price
        + value["provider_checks"].as_u64().unwrap()
        + value["direct_model_work"].as_u64().unwrap()
        + value["graph_forecast_work"].as_u64().unwrap()
}
fn client_units(value: &Value) -> u64 {
    traffic_units(&value["client_execution"]["plaintext_traffic"])
        + value["client_execution"]["graph_forecast_work"]
            .as_u64()
            .unwrap()
}
fn stop_units(value: &Value) -> u64 {
    traffic_units(&value["plaintext_traffic"]) + value["graph_forecast_work"].as_u64().unwrap()
}
fn actor_units(value: &Value, price: u64) -> u64 {
    execution_units(&value["graph_execution"], price)
        + traffic_units(&value["outbound_plaintext_traffic"])
        + traffic_units(&value["inbound_plaintext_traffic"])
        + value["inbound_graph_forecast_work"].as_u64().unwrap()
        + value["fresh_promotions"].as_u64().unwrap()
}
fn evaluated_lookups(value: &Value) -> usize {
    let candidate = value["graph_measurement"]["lookups"].as_array().unwrap();
    assert_eq!(candidate.len(), 3);
    assert_eq!(value["feedback_baseline"]["kind"], "unknown");
    let measured = &value["evaluation_record"]["measured_task_baseline"];
    let baseline: Measurement = serde_json::from_value(measured["measurement"].clone()).unwrap();
    let price = value["evaluation_record"]["oracle_price"].as_u64().unwrap();
    assert_eq!(measured["units"], baseline.units(price).unwrap());
    assert_eq!(
        measured["evidence_sha256"],
        hash(&serde_json::to_vec(&measured["measurement"]).unwrap())
    );
    candidate.len() + baseline.lookups.len()
}
fn assert_timing(summary: &Value, first: bool) {
    let timing = &summary["stage_timing"];
    assert_eq!(timing["schema"], "symbiote.stage-timing/1");
    assert_eq!(timing["logical_cost_or_reward_input"], false);
    assert_eq!(timing["overlapping_totals_are_additive"], false);
    for stage in [
        "compute",
        "lock_wait",
        "io",
        "evaluation",
        "replay",
        "shutdown",
    ] {
        if !first && stage == "evaluation" {
            continue;
        }
        let row = timing["stages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["stage"] == stage)
            .unwrap();
        assert!(
            row["completed"].as_u64().unwrap() > 0,
            "stage {stage} nevercompleted: {timing}"
        );
        assert!(row["monotonic_elapsed_ns"].as_u64().unwrap() > 0);
    }
}

fn run_cell(
    cheap: [usize; 2],
    labels: Vec<usize>,
    price: u64,
    destination: Option<&Path>,
) -> Value {
    run_cell_mode(cheap, labels, price, destination, false)
}
fn run_cell_mode(
    cheap: [usize; 2],
    labels: Vec<usize>,
    price: u64,
    destination: Option<&Path>,
    normal: bool,
) -> Value {
    let mut worlds = [
        ParallelWorld::new(cheap[0], labels.clone(), price).unwrap(),
        ParallelWorld::new(cheap[1], labels.clone(), price).unwrap(),
    ];
    if normal {
        for world in &mut worlds {
            world.contract.experiment_authorized = false;
            world.contract.max_experimental_offers = 0;
        }
    }
    let mut fixture = partial_fixture(&worlds);
    if normal {
        fixture.policy["capability_contributions"] = json!(true);
        fixture.save();
    }
    let mut sources = Vec::new();
    let mut maps = Vec::new();
    for (i, world) in worlds.iter().enumerate() {
        let (map, discovery) = world.discover().unwrap();
        let role = if i == 0 { "server" } else { "client" };
        let from = if i == 0 { "client" } else { "server" };
        let mut service =
            ServiceProcess::start_config(&fixture.fixture.dir.0.join(format!("{role}.json")));
        let submit = cli_request(
            &fixture.fixture,
            from,
            &request_map(
                &fixture.fixture,
                i,
                &map,
                &world.contract.training_inputs,
                &format!("source-{i}"),
            ),
        );
        let stopped = service.stop();
        let evaluation = success(configured_command(
            &fixture.fixture,
            &format!("{role}.json"),
            "evaluate",
            &["--candidate", submit["candidate"].as_str().unwrap()],
        ));
        assert_eq!(evaluation["status"], "PROMOTED");
        assert_eq!(
            evaluation["execution_meter"]["lookups"]
                .as_array()
                .unwrap()
                .len(),
            evaluated_lookups(&evaluation)
        );
        sources.push(json!({"scope":SCOPES[i],"role":role,"from":from,"source_map":map,"source_discovery":discovery,"submit":submit,"service_stop":stopped,"evaluation":evaluation}));
        maps.push(map);
    }
    let mut first = ServiceProcess::start(&fixture.fixture);
    let mut second = ServiceProcess::start_config(&fixture.fixture.dir.0.join("client.json"));
    let first_ready = [first.ready.clone(), second.ready.clone()];
    let native_first = fixture.run("native-first", false);
    assert_timing(&native_first, true);
    let events = fixture.events("native-first");
    assert_eq!(
        native_first["fresh_promotions"],
        2,
        "native summary: {native_first}; events: {}",
        json!(fixture.events("native-first"))
    );
    assert_eq!(native_first["active_models"], 2);
    assert_eq!(native_first["quarantined_contributions"], 2);
    assert_eq!(native_first["partner_benefits_verified"], 0);
    assert_eq!(
        native_first["graph_execution"]["lookups"]
            .as_array()
            .unwrap()
            .len(),
        events
            .iter()
            .filter(|event| event["phase"] == "LEARN"
                && event["details"]["status"] == "FRESH_PROMOTION")
            .map(|event| evaluated_lookups(&event["details"]["response"]))
            .sum::<usize>()
    );
    let first_stops = [first.stop(), second.stop()];
    let experiments: Vec<_> = events
        .iter()
        .filter(|event| event["phase"] == "EXPERIMENT")
        .collect();
    assert_eq!(experiments.len(), if normal { 0 } else { 2 });
    assert_eq!(
        events
            .iter()
            .filter(|event| event["phase"] == "CAPABILITY_OPPORTUNITY")
            .count(),
        if normal { 2 } else { 0 }
    );
    assert!(experiments
        .iter()
        .all(|event| event["details"]["gain_qualified"] == false));
    let contributions: Vec<_> = events
        .iter()
        .filter(|event| {
            event["phase"] == "CONTRIBUTE" && event["details"]["quarantined_offer"] == true
        })
        .collect();
    let mut returns = Vec::new();
    for event in contributions {
        let details = &event["details"];
        let role = if details["peer"] == fixture.fixture.ids[0] {
            "server"
        } else {
            "client"
        };
        let evaluated = success(configured_command(
            &fixture.fixture,
            &format!("{role}.json"),
            "evaluate",
            &[
                "--candidate",
                details["response"]["candidate"].as_str().unwrap(),
            ],
        ));
        assert_eq!(evaluated["status"], "PROMOTED");
        assert_eq!(
            evaluated["execution_meter"]["lookups"]
                .as_array()
                .unwrap()
                .len(),
            evaluated_lookups(&evaluated)
        );
        returns.push(json!({"role":role,"scope":details["scope"],"evaluation":evaluated}));
    }
    let mut retained = Vec::new();
    for returned in &returns {
        let role = returned["role"].as_str().unwrap();
        let from = if role == "server" { "client" } else { "server" };
        let i = usize::from(returned["scope"] == SCOPES[1]);
        let mut service =
            ServiceProcess::start_config(&fixture.fixture.dir.0.join(format!("{role}.json")));
        let ready = service.ready.clone();
        assert_ne!(
            ready["pid"],
            first_ready[usize::from(role == "client")]["pid"]
        );
        let request=fixture.fixture.request(SCOPES[i],"retained-partial-route",json!({"operation":"knowledge.predict","artifact":returned["evaluation"]["artifact"],"input":worlds[i].contract.heldout_inputs[0]}));
        let prediction = cli_request(&fixture.fixture, from, &request);
        assert_eq!(prediction["prediction"], 3);
        assert_eq!(prediction["conditional"], true);
        if normal {
            assert_eq!(
                prediction["learning_feedback"]["quality"],
                "capability_extended"
            );
            assert_eq!(prediction["learning_feedback"]["uses"], 1);
            assert_eq!(prediction["learning_feedback"]["verified_benefit"], false);
            assert_eq!(
                prediction["learning_feedback"]["measured_net"],
                Value::Null,
                "independent partner ownership does not reveal its unmeasured full economics"
            );
        }
        retained.push(json!({"role":role,"from":from,"scope":SCOPES[i],"ready":ready,"prediction":prediction,"service_stop":service.stop()}));
    }
    let mut first = ServiceProcess::start(&fixture.fixture);
    let mut second = ServiceProcess::start_config(&fixture.fixture.dir.0.join("client.json"));
    let native_restart = fixture.run("native-restart", false);
    let restart_first_sense = fixture
        .events("native-restart")
        .into_iter()
        .find(|event| event["phase"] == "SENSE")
        .expect("reopened native run must make an actual choice");
    assert_timing(&native_restart, false);
    assert_eq!(native_restart["fresh_promotions"], 0);
    assert_eq!(native_restart["active_models"], 2);
    assert_eq!(native_restart["quarantined_contributions"], 0);
    assert_eq!(
        native_restart["graph_execution"]["lookups"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        native_first["final_knowledge_anchor"],
        native_restart["final_knowledge_anchor"]
    );
    let restart_stops = [first.stop(), second.stop()];
    let bound_verification = if normal {
        use symbiote_memory::operational::OperationalJournal;
        use symbiote_runtime::service::feedback;
        let forecast_before = symbiote_memory::knowledge::graph::forecast_work_units().unwrap();
        let state_path = fixture.fixture.dir.0.join("actor-state");
        let owner = Arc::new(Store::open(&state_path).unwrap());
        let knowledge = KnowledgeStore::open(&state_path, owner.identity()).unwrap();
        let journal = OperationalJournal::open(
            Arc::clone(&owner),
            "configured-service/v1",
            fixture.policy["service_policy_sha256"].as_str().unwrap(),
        )
        .unwrap();
        let index = feedback::replay_index(&journal, &knowledge).unwrap();
        assert_eq!(index.experiences.len(), 2);
        let mut receipts = Vec::new();
        for experience in &index.experiences {
            let measurement_sha = index
                .scoped_measurement_sha256(&experience.binding.exchange_id)
                .unwrap()
                .expect("normal actual use has a measured finite window");
            let verified = symbiote_runtime::reciprocal::bound_scoped_benefit(
                &journal,
                &knowledge,
                &experience.binding,
                &measurement_sha,
            );
            assert_eq!(verified, price == 100000);
            assert!(!symbiote_runtime::reciprocal::bound_scoped_benefit(
                &journal,
                &knowledge,
                &experience.binding,
                &"0".repeat(64),
            ));
            let mut foreign = experience.binding.clone();
            foreign.request_sha256 = "0".repeat(64);
            assert!(!symbiote_runtime::reciprocal::bound_scoped_benefit(
                &journal,
                &knowledge,
                &foreign,
                &measurement_sha,
            ));
            receipts.push(json!({"binding":experience.binding,"measurement_sha256":measurement_sha,
                "verified_scoped_benefit":verified,"wrong_measurement_rejected":true,"wrong_binding_rejected":true}));
        }
        json!({"schema":"symbiote.normal-bound-verification/1","receipts":receipts,
            "separate_host_audit_graph_work":symbiote_memory::knowledge::graph::forecast_work_units().unwrap()-forecast_before,
            "accounting":"post-process acceptance audit, outside native received-task windows; not a native participant saving"})
    } else {
        Value::Null
    };
    let feedback_events: Vec<Value> =
        fs::read_to_string(fixture.fixture.dir.0.join("actor-state/operations.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|line| {
                line["payload"]["decision"]["details"]["schema"] == "symbiote.learning-feedback/1"
            })
            .collect();
    // A real wrong-map quarantine and independent receiver rejection, after all
    // positive interactions. Its extra work belongs to the research control.
    let mut wrong = maps[1].clone();
    wrong.observations[0].cost = 2;
    let mut service = ServiceProcess::start(&fixture.fixture);
    let wrong_submit = cli_request(
        &fixture.fixture,
        "client",
        &request_map(
            &fixture.fixture,
            1,
            &wrong,
            &worlds[1].contract.training_inputs,
            "wrong-map-control",
        ),
    );
    let wrong_stop = service.stop();
    let wrong_evaluation = rejected(configured_command(
        &fixture.fixture,
        "server.json",
        "evaluate",
        &["--candidate", wrong_submit["candidate"].as_str().unwrap()],
    ));
    assert_eq!(wrong_evaluation["status"], "REJECTED");
    assert_eq!(wrong_evaluation["promoted"], false);
    assert_eq!(
        wrong_evaluation["execution_meter"]["lookups"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let mut common = [0u64; 3];
    for (i, source) in sources.iter().enumerate() {
        let owner = i + 1;
        let caller = if i == 0 { 2 } else { 1 };
        let discovery: Measurement =
            serde_json::from_value(source["source_discovery"].clone()).unwrap();
        common[owner] += discovery.units(price).unwrap()
            + execution_units(&source["evaluation"]["execution_meter"], price)
            + 1
            + stop_units(&source["service_stop"]);
        common[caller] += client_units(&source["submit"]);
    }
    let mut exchange = common;
    exchange[0] += actor_units(&native_first, price) + actor_units(&native_restart, price);
    for i in 0..2 {
        exchange[i + 1] += stop_units(&first_stops[i]) + stop_units(&restart_stops[i]);
    }
    for returned in &returns {
        let i = if returned["role"] == "server" { 1 } else { 2 };
        exchange[i] += execution_units(&returned["evaluation"]["execution_meter"], price) + 1;
    }
    for item in &retained {
        let i = if item["role"] == "server" { 1 } else { 2 };
        let caller = if i == 1 { 2 } else { 1 };
        exchange[i] += stop_units(&item["service_stop"]);
        exchange[caller] += client_units(&item["prediction"]);
    }
    let orders = branch_orders(&labels);
    let mut world_reports = Vec::new();
    for (i, world) in worlds.iter().enumerate() {
        let greedy = world.control(None, None).unwrap();
        let fixed:Vec<_>=orders.iter().map(|order|json!({"order":order,"measurement":world.control(Some(order),None).unwrap()})).collect();
        let equal = world.control_queries(3).unwrap();
        world_reports.push(json!({"scope":SCOPES[i],"cheap_index":cheap[i],"labels":labels,"controls":{"greedy":greedy,"fixed_orders":fixed,"equal_query":{"query_limit":3,"measurement":equal}}}));
    }
    let mut participants = Vec::new();
    for (role, index, targets) in [
        ("actor", 0, vec![0, 1]),
        ("server", 1, vec![1]),
        ("client", 2, vec![0]),
    ] {
        let mut remaining = exchange[index].saturating_sub(common[index]);
        let budget = remaining;
        let mut matched = Vec::new();
        for i in &targets {
            let measured = worlds[*i].control(None, Some(remaining)).unwrap();
            let spent = measured.units(price).unwrap();
            assert!(spent <= remaining);
            matched.push(json!({"scope":SCOPES[*i],"budget":remaining,"measurement":measured}));
            remaining -= spent;
        }
        let greedy = common[index]
            + targets
                .iter()
                .map(|i| {
                    serde_json::from_value::<Measurement>(
                        world_reports[*i]["controls"]["greedy"].clone(),
                    )
                    .unwrap()
                    .units(price)
                    .unwrap()
                })
                .sum::<u64>();
        let fixed: Vec<_> = (0..orders.len())
            .map(|order| {
                common[index]
                    + targets
                        .iter()
                        .map(|i| {
                            serde_json::from_value::<Measurement>(
                                world_reports[*i]["controls"]["fixed_orders"][order]["measurement"]
                                    .clone(),
                            )
                            .unwrap()
                            .units(price)
                            .unwrap()
                        })
                        .sum::<u64>()
            })
            .collect();
        participants.push(json!({"role":role,"target_scopes":targets.iter().map(|i|SCOPES[*i]).collect::<Vec<_>>(),"common_source_units":common[index],"exchange_units":exchange[index],"greedy_units":greedy,"fixed_units":fixed,"matched_resource_budget":budget,"matched_resource":matched}));
    }
    let report = json!({"schema":"symbiote.partial-graph-cell/1","mode":if normal{"normal_capability_goal"}else{"registered_experiment"},"oracle_price":price,"labels":labels,"cheap_indices":cheap,
        "identity":fixture.actor["identity"],"partner_identities":fixture.fixture.ids,"worlds":world_reports,"sources":sources,
        "native_first":native_first,"native_restart":native_restart,"restart_first_sense":restart_first_sense,"feedback_events":feedback_events,"bound_verification":bound_verification,"first_ready":first_ready,"first_stops":first_stops,"restart_stops":restart_stops,
        "return_evaluations":returns,"retained_predictions":retained,"wrong_control":{"submit":wrong_submit,"service_stop":wrong_stop,"evaluation":wrong_evaluation},
        "participants":participants,"scientific_samples":0,"operational_status":"PASS_REQUIRES_INDEPENDENT_CONSUMER","generalized_benefit":false});
    if let Some(destination) = destination {
        copy_public(&fixture.fixture.dir.0, destination);
        value_file(&destination.join("cell.json"), &report);
    }
    report
}

pub(super) fn copy_public(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    let mut entries: Vec<_> = fs::read_dir(source)
        .unwrap()
        .map(|entry| entry.unwrap())
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let kind = entry.file_type().unwrap();
        assert!(!kind.is_symlink());
        if path.extension().is_some_and(|extension| extension == "key") {
            continue;
        }
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            copy_public(&path, &target);
        } else {
            assert!(kind.is_file());
            let bytes = fs::read(&path).unwrap();
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)
                .unwrap();
            file.write_all(&bytes).unwrap();
            file.sync_all().unwrap();
        }
    }
}
pub(super) fn copy_binaries(root: &Path) -> (PathBuf, PathBuf) {
    let destination = root.join("executables");
    fs::create_dir(&destination).unwrap();
    let mut copied = Vec::new();
    for (source, name) in [
        (
            native_binary(),
            if cfg!(windows) {
                "symbiote.exe"
            } else {
                "symbiote"
            },
        ),
        (
            std::env::current_exe().unwrap(),
            if cfg!(windows) {
                "service-tests.exe"
            } else {
                "service-tests"
            },
        ),
    ] {
        let bytes = fs::read(&source).unwrap();
        let expected = hash(&bytes);
        let target = destination.join(name);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        assert_eq!(hash(&fs::read(&target).unwrap()), expected);
        assert_eq!(
            hash(&fs::read(&source).unwrap()),
            expected,
            "qualified executable changed while copying"
        );
        copied.push(target);
    }
    (copied.remove(0), copied.remove(0))
}
fn manifest(root: &Path, report: &Value) {
    let (native_snapshot, service_snapshot) = copy_binaries(root);
    fn walk(root: &Path, path: &Path, files: &mut Vec<Value>) {
        let mut entries: Vec<_> = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, files);
            } else {
                let bytes = fs::read(&path).unwrap();
                files.push(json!({"path":path.strip_prefix(root).unwrap().to_string_lossy().replace('\\',"/"),"bytes":bytes.len(),"sha256":hash(&bytes)}));
            }
        }
    }
    let mut files = Vec::new();
    walk(root, root, &mut files);
    assert!(
        files
            .iter()
            .map(|file| file["bytes"].as_u64().unwrap())
            .sum::<u64>()
            <= 134217728
    );
    value_file(
        &root.join("artifact-manifest.json"),
        &json!({"schema":"symbiote.partial-graph-native-artifacts/1","files":files,"native_binary":native_snapshot,"native_binary_sha256":hash(&fs::read(&native_snapshot).unwrap()),"service_tests":service_snapshot,"service_tests_sha256":hash(&fs::read(&service_snapshot).unwrap()),"private_keys_copied":false,"report":report}),
    );
}

#[test]
fn partial_graph_native_reciprocity_smoke() {
    let _binary = cognition_binary_override();
    let destination = std::env::var_os("SYMBIOTE_GRAPH_RECIPROCAL_ARTIFACTS").map(PathBuf::from);
    if let Some(path) = &destination {
        assert!(!path.exists());
        fs::create_dir_all(path).unwrap();
    }
    let report = run_cell(
        [1, 0],
        vec![1, 2],
        100000,
        destination
            .as_ref()
            .map(|path| path.join("cell-000"))
            .as_deref(),
    );
    if let Some(path) = destination {
        manifest(&path, &report);
    }
}

#[test]
fn normal_capability_reciprocity_and_durable_feedback_smoke() {
    let _binary = cognition_binary_override();
    let destination = std::env::var_os("SYMBIOTE_NORMAL_FEEDBACK_ARTIFACTS").map(PathBuf::from);
    if let Some(root) = &destination {
        assert!(!root.exists());
        fs::create_dir_all(root).unwrap();
    }
    let mut reports = Vec::new();
    for (index, price) in [100000, 1].into_iter().enumerate() {
        let cell = destination
            .as_ref()
            .map(|root| root.join(format!("cell-{index:03}")));
        let report = run_cell_mode([1, 1], vec![1, 2], price, cell.as_deref(), true);
        assert_eq!(report["native_first"]["quarantined_contributions"], 2);
        assert_eq!(report["native_restart"]["fresh_promotions"], 0);
        let outcomes: Vec<_> = report["feedback_events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| &event["payload"]["decision"]["details"]["event"])
            .filter(|event| event["phase"] == "outcome")
            .collect();
        assert_eq!(
            outcomes.len(),
            2,
            "both actual received models need their own durable outcome"
        );
        for event in outcomes {
            let outcome = &event["outcome"];
            assert_eq!(outcome["uses"], 1);
            assert_eq!(outcome["quality"], "capability_extended");
            assert_eq!(outcome["baseline"]["kind"], "measured");
            let net = outcome["measured_net"]
                .as_i64()
                .expect("finite received-task window is actually measured");
            assert_eq!(
                net > 0,
                price == 100000,
                "price {price}, actual scoped feedback {outcome}"
            );
            assert_eq!(outcome["verified_benefit"], price == 100000);
        }
        let next = &report["restart_first_sense"]["details"]["profile"];
        if price == 100000 {
            assert!(
                next["feedback_prefer"].as_u64().unwrap_or(0) > 0,
                "actual reopened choice must use favorable measured feedback: {next}"
            );
        } else {
            assert_eq!(
                next["feedback_defer"].as_u64().unwrap_or(0),
                0,
                "actual reopened choice must delay the costly learned contexts: {next}"
            );
            assert!(report["native_first"]["profiles"]
                .as_array()
                .unwrap()
                .iter()
                .any(|profile| profile["feedback_defer"].as_u64().unwrap_or(0) > 0));
        }
        reports.push(report);
    }
    if let Some(root) = destination {
        manifest(
            &root,
            &json!({"schema":"symbiote.normal-capability-smoke/1","cases":reports,"scientific_samples":0}),
        );
    }
}

#[test]
#[ignore = "once-only registered engineering cohort; bounded outer process wrapper required"]
fn registered_partial_graph_reciprocal_cohort() {
    let registration_path = PathBuf::from(
        std::env::var_os("SYMBIOTE_GRAPH_RECIPROCAL_REGISTRATION")
            .expect("external registration required"),
    );
    let bytes = fs::read(&registration_path).unwrap();
    assert_eq!(
        hash(&bytes),
        std::env::var("SYMBIOTE_GRAPH_RECIPROCAL_REGISTRATION_SHA256").unwrap()
    );
    let registration: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        registration["schema"],
        "symbiote.reciprocal-engineering-registration/1"
    );
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert_eq!(
        hash(&fs::read(repository.join("docs/RECIPROCAL_ENGINEERING_PROTOCOL_001.md")).unwrap()),
        registration["protocol_sha256"]
    );
    let head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&repository)
        .output()
        .unwrap();
    assert!(head.status.success());
    assert_eq!(
        String::from_utf8(head.stdout).unwrap().trim(),
        registration["source_commit"].as_str().unwrap()
    );
    let status = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(&repository)
        .output()
        .unwrap();
    assert!(status.status.success() && status.stdout.is_empty());
    for (name, path) in [
        (
            "native",
            PathBuf::from(registration["binaries"]["native"]["path"].as_str().unwrap()),
        ),
        ("service_tests", std::env::current_exe().unwrap()),
    ] {
        assert_eq!(
            hash(&fs::read(path).unwrap()),
            registration["binaries"][name]["sha256"]
        );
    }
    assert_eq!(
        registration["cohort"],
        json!({"cell_count":64,"labelings":[[1,2,3,4],[3,1,4,2]],"oracle_prices":[1,100000],"fixed_branch_orders":24,"deadline_seconds":1200,"receipt_bytes":134217728})
    );
    let native = PathBuf::from(registration["binaries"]["native"]["path"].as_str().unwrap());
    let _binary =
        CognitionBinaryGuard(COGNITION_BINARY.with(|current| current.replace(Some(native))));
    let root = PathBuf::from(
        std::env::var_os("SYMBIOTE_GRAPH_RECIPROCAL_ARTIFACTS")
            .expect("fresh artifact path required"),
    );
    assert!(!root.exists());
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("registration.json"), &bytes).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1200);
    let mut cells = Vec::new();
    for price in [1, 100000] {
        for labels in [vec![1, 2, 3, 4], vec![3, 1, 4, 2]] {
            for x in 0..4 {
                for y in 0..4 {
                    assert!(
                        Instant::now() < deadline,
                        "registered engineering deadline reached"
                    );
                    let relative = format!("cell-{:03}", cells.len());
                    let report =
                        run_cell([x, y], labels.clone(), price, Some(&root.join(&relative)));
                    cells.push(json!({"path":format!("{relative}/cell.json"),"sha256":hash(&fs::read(root.join(&relative).join("cell.json")).unwrap()),"oracle_price":report["oracle_price"],"cheap_indices":report["cheap_indices"],"labels":report["labels"]}));
                    value_file(
                        &root.join(format!("completed-{:03}.json", cells.len())),
                        &json!({"completed":cells.len(),"last":cells.last()}),
                    );
                }
            }
        }
    }
    let report = json!({"schema":"symbiote.partial-graph-cohort/1","cells":cells,"completed":64,"status":"COMPLETE_REQUIRES_INDEPENDENT_CONSUMER","scientific_samples":0,"registration_sha256":hash(&bytes)});
    value_file(&root.join("cohort.json"), &report);
    manifest(&root, &report);
}
