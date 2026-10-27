//! Admission regressions on a manual released-domain diamond. No prospective
//! generator, seed list, EvaluationPermit or cohort runner is called here.
use super::super::authority;
use super::super::wire::{AuthorityWorld, Grant, LabCa, Material, AUTHORITY_OPS, CONTROL_OPS};
use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use symbiote_protocol::{fresh_capability, SecureServerConfig};
use symbiote_reasoning::planning::Edge;

const CONTEXT: &str = "manual-released-diamond";
const COSTS: [u16; 4] = [1, 1, 3, 3];
fn diamond() -> GraphSchema {
    GraphSchema {
        nodes: 4,
        edges: vec![
            Edge {
                from: 0,
                to: 1,
                lower: 1,
                upper: 3,
            },
            Edge {
                from: 1,
                to: 3,
                lower: 1,
                upper: 3,
            },
            Edge {
                from: 0,
                to: 2,
                lower: 1,
                upper: 3,
            },
            Edge {
                from: 2,
                to: 3,
                lower: 1,
                upper: 3,
            },
        ],
    }
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = std::env::temp_dir().canonicalize().unwrap();
        let path = root.join(format!(
            "symbiote-actor-admission-{}",
            fresh_capability().unwrap()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if let (Ok(path), Ok(root)) = (self.0.canonicalize(), std::env::temp_dir().canonicalize()) {
            if path.parent() == Some(root.as_path())
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("symbiote-actor-admission-"))
            {
                let _ = std::fs::remove_dir_all(path);
            }
        }
    }
}

struct Manual {
    controller: String,
    peer: String,
    receiver: Arc<Store>,
    controller_client: TlsClientConfig,
    peer_client: TlsClientConfig,
    receiver_client: TlsClientConfig,
    controller_material: Material,
    peer_material: Material,
    receiver_material: Material,
    authority_material: Material,
    ca: String,
    endpoint: PublicEndpoint,
    authority: Running,
    directory: Directory,
}
impl Manual {
    fn new() -> Self {
        let directory = Directory::new();
        let controller = Store::open(&directory.0.join("controller"))
            .unwrap()
            .identity()
            .to_string();
        let peer = Store::open(&directory.0.join("peer"))
            .unwrap()
            .identity()
            .to_string();
        let receiver = Arc::new(Store::open(&directory.0.join("receiver")).unwrap());
        let owner = Arc::new(Store::open(&directory.0.join("authority")).unwrap());
        let ca = LabCa::new().unwrap();
        let controller_material = ca.leaf().unwrap();
        let peer_material = ca.leaf().unwrap();
        let receiver_material = ca.leaf().unwrap();
        let authority_material = ca.leaf().unwrap();
        let clients = |id: &str, material: &Material| {
            TlsClientConfig::new(id.into(), material.identity().unwrap(), ca.pem.as_bytes())
                .unwrap()
        };
        let controller_client = clients(&controller, &controller_material);
        let peer_client = clients(&peer, &peer_material);
        let receiver_client = clients(receiver.identity(), &receiver_material);
        let grants = [
            (
                controller.as_str(),
                &controller_material,
                vec!["begin", "calibrate", "audit", "judge"],
            ),
            (
                receiver.identity(),
                &receiver_material,
                AUTHORITY_OPS.to_vec(),
            ),
            (peer.as_str(), &peer_material, AUTHORITY_OPS.to_vec()),
        ]
        .into_iter()
        .map(|(identity, material, operations)| Grant {
            identity: identity.into(),
            pin: material.pin.clone(),
            scope: SCOPE.into(),
            operations: operations.into_iter().map(str::to_string).collect(),
        })
        .collect();
        let allowed = BTreeMap::from([
            (
                receiver.identity().to_string(),
                vec![receiver.identity().to_string(), peer.clone()],
            ),
            (
                peer.clone(),
                vec![peer.clone(), receiver.identity().to_string()],
            ),
        ]);
        let bootstrap = Bootstrap {
            state: directory.0.join("authority"),
            expected_identity: owner.identity().into(),
            controller_identity: controller.clone(),
            material: authority_material.clone(),
            ca_pem: ca.pem.clone(),
            grants,
            role: Role::Authority {
                worlds: vec![AuthorityWorld {
                    context: CONTEXT.into(),
                    schema: diamond(),
                    costs: COSTS.to_vec(),
                }],
                allowed_observers: allowed,
            },
            protocol_sha256: PROTOCOL_SHA256.into(),
        };
        let authority = authority::create(bootstrap, owner).unwrap();
        let endpoint = PublicEndpoint {
            identity: authority.server.server_id().into(),
            address: authority.server.address(),
            pin: authority.server.certificate_sha256().into(),
            scope: SCOPE.into(),
        };
        let result = Self {
            controller,
            peer,
            receiver,
            controller_client,
            peer_client,
            receiver_client,
            controller_material,
            peer_material,
            receiver_material,
            authority_material,
            ca: ca.pem,
            endpoint,
            authority,
            directory,
        };
        result.call(&result.controller_client,"begin",&json!({"context":CONTEXT,"observers":[result.receiver.identity(),result.peer],"training_inputs":BTreeMap::from([(result.receiver.identity().to_string(),vec![3u16]),(result.peer.clone(),vec![3u16])])})).unwrap();
        result
    }
    fn call(
        &self,
        client: &TlsClientConfig,
        operation: &str,
        payload: &Value,
    ) -> Result<Value, String> {
        rpc(&self.endpoint, client, operation, payload)
    }
    fn observe(&self, peer: bool, edge: usize) -> Receipt {
        serde_json::from_value(
            self.call(
                if peer {
                    &self.peer_client
                } else {
                    &self.receiver_client
                },
                "observe",
                &json!({"context":CONTEXT,"edge_id":edge}),
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn calibrate(&self, receipt: &Receipt) {
        let verdict: Verification = serde_json::from_value(
            self.call(
                &self.controller_client,
                "calibrate",
                &json!({"receipt":receipt}),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(verdict.authentic && verdict.applicable);
        assert_eq!(verdict.receipt_sha256, receipt.digest().unwrap());
    }
    fn actor(&self) -> Actor {
        let policy=body_digest(&json!({"protocol":PROTOCOL_SHA256,"arm":Arm::Prospective,"price":100,"family":"unrestricted-exact-DAG/common-ingestion/v1"})).unwrap();
        let journal = OperationalJournal::open(
            Arc::clone(&self.receiver),
            self.receiver.identity(),
            &policy,
        )
        .unwrap();
        let knowledge =
            KnowledgeStore::open(&self.directory.0.join("receiver"), self.receiver.identity())
                .unwrap();
        Actor {
            owner: Arc::clone(&self.receiver),
            knowledge,
            journal,
            controller: self.controller.clone(),
            arm: Arm::Prospective,
            price: 100,
            offer_mode: OfferMode::CurrentWarmup,
            inactive: false,
            client: self.receiver_client.clone(),
            registry: Vec::new(),
            oracle: Some(self.endpoint.clone()),
            fixed_peer: None,
            previous_warmup: None,
            current: None,
            server: SecureTraffic::default(),
            world_deadline: Arc::new(Mutex::new(None)),
        }
    }
    fn learner_bootstrap(&self) -> Bootstrap {
        Bootstrap {
            state: self.directory.0.join("receiver"),
            expected_identity: self.receiver.identity().into(),
            controller_identity: self.controller.clone(),
            material: self.receiver_material.clone(),
            ca_pem: self.ca.clone(),
            grants: vec![Grant {
                identity: self.controller.clone(),
                pin: self.controller_material.pin.clone(),
                scope: SCOPE.into(),
                operations: CONTROL_OPS
                    .iter()
                    .map(|operation| (*operation).into())
                    .collect(),
            }],
            role: Role::Learner {
                arm: Arm::Prospective,
                observation_price: 100,
                offer_mode: OfferMode::CurrentWarmup,
                inactive: false,
            },
            protocol_sha256: PROTOCOL_SHA256.into(),
        }
    }
    fn fake_peer(&self, value: Value, edge: usize) -> symbiote_protocol::SecureServerHandle {
        let config = SecureServerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            self.peer.clone(),
            self.peer_material.identity().unwrap(),
            self.ca.as_bytes(),
            vec![Grant {
                identity: self.receiver.identity().into(),
                pin: self.receiver_material.pin.clone(),
                scope: SCOPE.into(),
                operations: vec!["request-edge".into()],
            }
            .secure()],
            symbiote_protocol::SecureLimits::default(),
        )
        .unwrap()
        .with_operation_frame_limits(BTreeMap::from([("request-edge".into(), 4096)]))
        .unwrap();
        spawn_secure_server_metered(config, 1024, move |_, operation, payload| {
            assert_eq!(operation, "request-edge");
            assert_eq!(payload["context"], CONTEXT);
            assert_eq!(payload["edge_id"], edge);
            Ok(value.clone())
        })
        .unwrap()
    }
}
impl Drop for Manual {
    fn drop(&mut self) {
        let _ = self.authority.server.shutdown();
    }
}
fn rpc(
    endpoint: &PublicEndpoint,
    client: &TlsClientConfig,
    operation: &str,
    payload: &Value,
) -> Result<Value, String> {
    let mut connection = SecureClient::connect_with_metering(
        &endpoint.endpoint(operation, 16_384)?,
        client,
        SecureTraffic::default(),
        1024,
    )?;
    let result = connection.call(operation, payload);
    let _ = connection.cancel();
    result
}
fn current(actor: &Actor, own: Receipt, algorithm: Algorithm) -> Current {
    let mut model = ExactModel::new(diamond(), algorithm).unwrap();
    model.ingest(own.edge_id, own.cost).unwrap();
    let assessment = model.assess(0, 3).unwrap();
    Current {
        context: CONTEXT.into(),
        model,
        warmup_edge: 0,
        prelude: false,
        warmup: Some(own.clone()),
        receipts: BTreeMap::from([(0, own)]),
        assessment: Some(assessment),
        advertisements: None,
        attempted: BTreeSet::new(),
        forecasts: BTreeMap::new(),
        meter: Meter::new(actor.server.snapshot()),
        finished: false,
        abstention: None,
        promotion: "not-evaluated".into(),
        served: BTreeSet::new(),
        contribution_meters: Vec::new(),
        metadata_outcomes: Vec::new(),
        source_response_ambiguous: false,
    }
}
fn assessment(value: &Current) -> Value {
    value.assessment.as_ref().map(|assessment|json!({"candidate":assessment.candidate,"certified":assessment.certified,"next":assessment.next,"work_delta":assessment.work_delta})).unwrap_or(Value::Null)
}
fn attach_peer(actor: &mut Actor, server: &symbiote_protocol::SecureServerHandle, peer: &str) {
    actor.registry = vec![Descriptor {
        identity: peer.into(),
        authorized: true,
        compatible: true,
        endpoint: Some(PublicEndpoint {
            identity: peer.into(),
            address: server.address(),
            pin: server.certificate_sha256().into(),
            scope: SCOPE.into(),
        }),
    }];
}
fn assert_unchanged_failure(
    actor: &Actor,
    current: &Current,
    state: &Value,
    previous_assessment: &Value,
    receipt_count: usize,
) {
    assert_eq!(&current.model.state(), state);
    assert_eq!(&assessment(current), previous_assessment);
    assert_eq!(current.receipts.len(), receipt_count);
    let bill = actor.bill(current).unwrap();
    assert_eq!(bill.received_attempts, 1);
    assert_eq!(bill.receipt_verification_attempts, 1);
    assert_eq!(bill.verified_receipts, 0);
    assert_eq!(bill.adopted_edges, 0);
    assert_eq!(bill.route_queries, 0);
    let mut without_fee = bill.clone();
    without_fee.receipt_verification_attempts = 0;
    assert_eq!(
        bill.total(actor.price) - without_fee.total(actor.price),
        2,
        "failed receipt inspection consumes the declared two-unit verification fee"
    );
}

#[test]
fn malformed_non_null_artifact_consumes_verification_fee_without_reasoning_change() {
    for algorithm in [Algorithm::Dijkstra, Algorithm::SimplePaths] {
        let fixture = Manual::new();
        let mut actor = fixture.actor();
        let mut state = current(&actor, fixture.observe(false, 0), algorithm);
        let edge = state.assessment.as_ref().unwrap().next.unwrap();
        let genuine = fixture.observe(true, edge);
        fixture.calibrate(&genuine);
        let mut peer = fixture.fake_peer(json!({"non_null":"malformed-receipt"}), edge);
        attach_peer(&mut actor, &peer, &fixture.peer);
        let before = state.model.state();
        let previous_assessment = assessment(&state);
        let receipts = state.receipts.len();
        let (outcome, digest) = actor
            .attempt(&mut state, &fixture.peer, "manual-offer", edge)
            .unwrap();
        assert_eq!(outcome, PartnerInteractionOutcome::VerificationFailed);
        assert!(digest.is_none());
        assert_unchanged_failure(&actor, &state, &before, &previous_assessment, receipts);
        let audit = fixture
            .call(&fixture.controller_client, "audit", &json!({}))
            .unwrap();
        assert_eq!(
            audit["per_actor"][fixture.receiver.identity()]["verify"],
            0,
            "malformed artifacts never reach authority verification"
        );
        peer.shutdown().unwrap();
    }
}

#[test]
fn lost_genuine_authority_verdict_consumes_fee_without_partial_adoption() {
    for algorithm in [Algorithm::Dijkstra, Algorithm::SimplePaths] {
        let fixture = Manual::new();
        let mut actor = fixture.actor();
        let mut state = current(&actor, fixture.observe(false, 0), algorithm);
        let edge = state.assessment.as_ref().unwrap().next.unwrap();
        let genuine = fixture.observe(true, edge);
        fixture.calibrate(&genuine);
        let mut peer = fixture.fake_peer(genuine.value().unwrap(), edge);
        attach_peer(&mut actor, &peer, &fixture.peer);
        let config = SecureServerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            fixture.endpoint.identity.clone(),
            fixture.authority_material.identity().unwrap(),
            fixture.ca.as_bytes(),
            vec![Grant {
                identity: fixture.receiver.identity().into(),
                pin: fixture.receiver_material.pin.clone(),
                scope: SCOPE.into(),
                operations: vec!["verify".into()],
            }
            .secure()],
            symbiote_protocol::SecureLimits::default(),
        )
        .unwrap()
        .with_operation_frame_limits(BTreeMap::from([("verify".into(), 4096)]))
        .unwrap();
        let upstream = fixture.endpoint.clone();
        let client = fixture.receiver_client.clone();
        let verified = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&verified);
        let mut lost = spawn_secure_server_metered(config, 1024, move |_, operation, payload| {
            assert_eq!(operation, "verify");
            let verdict = rpc(&upstream, &client, operation, &payload)?;
            assert_eq!(verdict["authentic"], true);
            assert_eq!(verdict["applicable"], true);
            observed.store(true, Ordering::Release);
            std::thread::sleep(Duration::from_millis(2250));
            Ok(verdict)
        })
        .unwrap();
        actor.oracle = Some(PublicEndpoint {
            identity: fixture.endpoint.identity.clone(),
            address: lost.address(),
            pin: lost.certificate_sha256().into(),
            scope: SCOPE.into(),
        });
        let before = state.model.state();
        let previous_assessment = assessment(&state);
        let receipts = state.receipts.len();
        let (outcome, digest) = actor
            .attempt(&mut state, &fixture.peer, "manual-offer", edge)
            .unwrap();
        assert_eq!(outcome, PartnerInteractionOutcome::TransportFailed);
        assert_eq!(digest, Some(genuine.digest().unwrap()));
        assert!(
            verified.load(Ordering::Acquire),
            "a genuine positive authority verdict must exist before the fixture loses its reply"
        );
        assert_unchanged_failure(&actor, &state, &before, &previous_assessment, receipts);
        lost.shutdown().unwrap();
        peer.shutdown().unwrap();
    }
}

#[test]
fn registered_native_actor_holds_when_learned_ledger_is_deleted_or_replaced_by_directory() {
    let fixture = Manual::new();
    let mut running = create(fixture.learner_bootstrap(), Arc::clone(&fixture.receiver)).unwrap();
    running.server.shutdown().unwrap();
    drop(running);
    let receipts = (0..4)
        .map(|edge| fixture.observe(false, edge))
        .collect::<Vec<_>>();
    for receipt in &receipts {
        fixture.calibrate(receipt);
    }
    let map = GraphMap::new(
        diamond(),
        receipts
            .iter()
            .map(|receipt| GraphObservation {
                edge_id: receipt.edge_id,
                cost: receipt.cost,
            })
            .collect(),
    )
    .unwrap();
    let record=KnowledgeRecord{id:"manual-learned-diamond".into(),revision:1,source:fixture.receiver.identity().into(),scope:CONTEXT.into(),schema_fingerprint:graph_schema_fingerprint(&diamond()).unwrap(),payload:map.to_payload().unwrap(),provenance:"Actual native-authority observations on the released-domain manual diamond; local independent route cases for ledger-loss regression only".into()};
    let cases = [(1u16, 1u8), (7, 1), (2, 3), (11, 3)]
        .into_iter()
        .map(|(input, expected)| TrialCase {
            id: format!("manual-independent-route-{input}"),
            input,
            expected,
            baseline: None,
            candidate: map.predict(input).unwrap().unwrap(),
        })
        .collect();
    let evidence = GraphTrialEvidence {
        evaluator: "manual-local-route-evaluator".into(),
        acquisitions: receipts
            .iter()
            .map(Receipt::acquisition)
            .collect::<Result<_, _>>()
            .unwrap(),
        training_tasks: vec![GraphTrainingTask {
            id: "manual-main-route".into(),
            input: 3,
        }],
        cases,
        costs: TrialCosts {
            acquisition: 400,
            verification: 4,
            adoption: 1,
            baseline: 0,
            candidate: 405,
        },
    };
    {
        let mut knowledge = KnowledgeStore::open(
            &fixture.directory.0.join("receiver"),
            fixture.receiver.identity(),
        )
        .unwrap();
        let assessment = assess_graph(&record, &evidence).unwrap();
        knowledge.promote_graph(record, assessment).unwrap();
        assert_eq!(knowledge.active().len(), 1);
    }
    let state = fixture.directory.0.join("receiver");
    let learning = std::fs::read(state.join("knowledge.jsonl")).unwrap();
    assert!(
        learning
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .count()
            > 1
    );
    let journal = std::fs::read(state.join("operations.jsonl")).unwrap();
    let marker = std::fs::read(state.join("operations-owner.json")).unwrap();
    let identity = std::fs::read(state.join("ledger.jsonl")).unwrap();
    std::fs::remove_file(state.join("knowledge.jsonl")).unwrap();
    for directory_replacement in [false, true] {
        if directory_replacement {
            std::fs::create_dir(state.join("knowledge.jsonl")).unwrap();
        }
        let error = create(fixture.learner_bootstrap(), Arc::clone(&fixture.receiver))
            .err()
            .unwrap();
        assert!(error.contains("HOLD") && error.contains("knowledge ledger missing"));
        assert_eq!(
            std::fs::read(state.join("operations.jsonl")).unwrap(),
            journal
        );
        assert_eq!(
            std::fs::read(state.join("operations-owner.json")).unwrap(),
            marker
        );
        assert_eq!(std::fs::read(state.join("ledger.jsonl")).unwrap(), identity);
        assert!(!state.join("knowledge.jsonl").is_file());
    }
}
