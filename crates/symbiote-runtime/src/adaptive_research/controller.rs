//! Frozen paired experiment controller. Private labels remain outside learners.
use super::cohort::{self, SetupWork, Truth, World};
use super::meter::Bill;
use super::model::{Algorithm, ExactModel};
use super::policy::Arm;
use super::process::SupervisedProcess;
use super::registration::{EvaluationPermit, PROTOCOL_ID, PROTOCOL_SHA256, SOURCE_COMMIT};
use super::wire::{
    AuthorityWorld, Bootstrap, Descriptor, Grant, LabCa, Material, OfferMode, PublicEndpoint, Role,
    AUTHORITY_OPS, CONTROL_OPS, PEER_OPS, SCOPE,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use symbiote_memory::operational::body_digest;
use symbiote_memory::Store;
use symbiote_protocol::{
    fresh_capability, SecureClient, SecureTraffic, SecureTrafficSnapshot, TlsClientConfig,
};

const AUTH_CONTROL: &[&str] = &["begin", "judge", "audit", "calibrate"];
struct Node {
    bootstrap: Bootstrap,
    process: Option<SupervisedProcess>,
    last_stop: Option<Value>,
}
impl Node {
    fn launch(&mut self) -> Result<(), String> {
        if self.process.is_some() {
            return Err("owned process already launched".into());
        }
        self.process = Some(SupervisedProcess::spawn(&self.bootstrap)?);
        Ok(())
    }
    fn endpoint(&self) -> Result<PublicEndpoint, String> {
        Ok(self
            .process
            .as_ref()
            .ok_or("owned process unavailable")?
            .endpoint()
            .clone())
    }
    fn stop(&mut self) -> Result<(), String> {
        if let Some(mut process) = self.process.take() {
            let ready = json!(process.ready());
            let before = process.resources();
            let result = process.shutdown();
            self.last_stop = Some(
                json!({"ready":ready,"resources_before_shutdown":before,"resources_after_shutdown":process.resources(),"summary":process.shutdown_summary(),"successful_shutdown":result.is_ok()}),
            );
            result?;
        }
        Ok(())
    }
}
struct Campaign {
    arm: Arm,
    price: u64,
    roles: Vec<Node>,
    authority: Node,
    controller: TlsClientConfig,
    setup: Vec<Bill>,
    prelude_context: String,
    unconfigured: bool,
    failed: bool,
    restarts: usize,
    lifecycle: Vec<Value>,
}
fn grant(identity: &str, material: &Material, operations: &[&str]) -> Grant {
    Grant {
        identity: identity.into(),
        pin: material.pin.clone(),
        scope: SCOPE.into(),
        operations: operations
            .iter()
            .map(|operation| (*operation).into())
            .collect(),
    }
}
fn new_owner(path: &Path) -> Result<String, String> {
    let owner = Store::open(path)?;
    Ok(owner.identity().into())
}
fn reverse_bill(traffic: SecureTrafficSnapshot) -> Bill {
    Bill {
        rpc_requests: 1,
        sessions: traffic.connection_attempts,
        rpc_sent_bytes: traffic.rpc_received_bytes,
        rpc_received_bytes: traffic.rpc_sent_bytes,
        negotiation_sent_bytes: traffic.negotiation_received_bytes,
        negotiation_received_bytes: traffic.negotiation_sent_bytes,
        ..Bill::default()
    }
}
fn call(
    client: &TlsClientConfig,
    endpoint: &PublicEndpoint,
    operation: &str,
    payload: &Value,
    frame: usize,
) -> Result<(Value, SecureTrafficSnapshot), String> {
    let traffic = SecureTraffic::default();
    let mut connection = SecureClient::connect_with_metering(
        &endpoint.endpoint(operation, frame)?,
        client,
        traffic.clone(),
        1024,
    )?;
    let response = connection.call(operation, payload);
    let closed = connection.cancel();
    closed?;
    Ok((response?, traffic.snapshot()))
}
fn role_call(
    campaign: &Campaign,
    index: usize,
    operation: &str,
    payload: &Value,
) -> Result<(Value, SecureTrafficSnapshot), String> {
    call(
        &campaign.controller,
        &campaign.roles[index].endpoint()?,
        operation,
        payload,
        16_384,
    )
}
fn authority_call(campaign: &Campaign, operation: &str, payload: &Value) -> Result<Value, String> {
    Ok(call(
        &campaign.controller,
        &campaign.authority.endpoint()?,
        operation,
        payload,
        16_384,
    )?
    .0)
}
fn algorithm(seed_index: usize, role: usize) -> Algorithm {
    if (seed_index + role).is_multiple_of(2) {
        Algorithm::Dijkstra
    } else {
        Algorithm::SimplePaths
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JudgeFlag {
    input: u16,
    certified: bool,
    correct: bool,
    abstained: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JudgeVerdict {
    schema: String,
    authority_id: String,
    context: String,
    request_sha256: String,
    results: Vec<JudgeFlag>,
    receipt_sha256: String,
}
fn check_judge(context: &str, routes: &[Value], value: &Value) -> Result<(), String> {
    let verdict: JudgeVerdict = serde_json::from_value(value.clone())
        .map_err(|_| "native judge verdict schema malformed")?;
    let mut body = value.clone();
    body.as_object_mut()
        .ok_or("judge verdict object missing")?
        .remove("receipt_sha256");
    if verdict.schema != "symbiote.authority-judge/1"
        || verdict.context != context
        || verdict.authority_id.len() != 64
        || verdict.request_sha256 != body_digest(&json!({"context":context,"routes":routes}))?
        || verdict.receipt_sha256 != body_digest(&body)?
        || verdict.results.len() != routes.len()
    {
        return Err("native judge verdict binding/digest/count mismatch".into());
    }
    for (claim, result) in routes.iter().zip(verdict.results) {
        if claim["input"].as_u64() != Some(u64::from(result.input))
            || result.abstained != claim["route"].is_null()
            || result.certified == result.abstained
        {
            return Err("native judge result does not bind its actual route claim".into());
        }
        if result.certified && !result.correct {
            return Err(
                "HOLD: independent native judge rejected a conditional route certificate".into(),
            );
        }
    }
    Ok(())
}
fn warmups(world: &World) -> Result<([usize; 5], u64), String> {
    let mut model = ExactModel::new(world.schema.clone(), algorithm(world.seed_index, 0))?;
    let assessment = model.assess(0, world.nodes - 1)?;
    let path = assessment
        .candidate
        .ok_or("public lower-bound topology has no main path")?;
    let first = *path
        .edges
        .first()
        .ok_or("public optimistic route has no edge")?;
    let second = path
        .edges
        .get(1)
        .copied()
        .or_else(|| (0..world.schema.edges.len()).find(|edge| *edge != first))
        .ok_or("complementary public warmup unavailable")?;
    Ok(([first, second, first, 0, second], model.work() as u64))
}
fn training(world: &World, warmup: usize) -> Vec<u16> {
    let edge = &world.schema.edges[warmup];
    BTreeSet::from([
        (world.nodes - 1) as u16,
        (edge.from * world.nodes + edge.to) as u16,
    ])
    .into_iter()
    .collect()
}
struct IdentitySetup<'a> {
    ca: &'a LabCa,
    controller_material: &'a Material,
    controller_identity: &'a str,
    role_genesis: Option<&'a [Vec<u8>]>,
}
fn campaign(
    state: &Path,
    worlds: &[World],
    arm: Arm,
    price: u64,
    identities: &IdentitySetup<'_>,
) -> Result<Campaign, String> {
    let IdentitySetup {
        ca,
        controller_material,
        controller_identity,
        role_genesis,
    } = identities;
    let controller_identity = *controller_identity;
    let root = state
        .join("campaigns")
        .join(if price == 100 { "normal" } else { "cheap" })
        .join(arm.name());
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let role_paths = (0..5)
        .map(|role| root.join(format!("participant-{role}")))
        .collect::<Vec<_>>();
    if let Some(genesis) = role_genesis {
        if genesis.len() != 5 {
            return Err(
                "paired counterfactual setup requires exactly five role genesis records".into(),
            );
        }
        for (path, bytes) in role_paths.iter().zip(*genesis) {
            fs::create_dir_all(path).map_err(|e| e.to_string())?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path.join("ledger.jsonl"))
                .map_err(|_| "counterfactual genesis destination already exists")?;
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|e| e.to_string())?;
        }
    }
    let role_ids = role_paths
        .iter()
        .map(|path| new_owner(path))
        .collect::<Result<Vec<_>, _>>()?;
    let authority_path = root.join("authority");
    let authority_id = new_owner(&authority_path)?;
    let materials = (0..5).map(|_| ca.leaf()).collect::<Result<Vec<_>, _>>()?;
    let authority_material = ca.leaf()?;
    let mut all = BTreeSet::from([controller_identity.to_string(), authority_id.clone()]);
    for identity in &role_ids {
        if !all.insert(identity.clone()) {
            return Err("private arm/regime native identities alias".into());
        }
    }
    let mut allowed = BTreeMap::new();
    allowed.insert(
        role_ids[0].clone(),
        [0, 1, 2, 4]
            .into_iter()
            .map(|role| role_ids[role].clone())
            .collect(),
    );
    for role in [1, 2, 4] {
        allowed.insert(
            role_ids[role].clone(),
            vec![role_ids[role].clone(), role_ids[0].clone()],
        );
    }
    let prelude_context = format!("frontier-prelude-{}", fresh_capability()?);
    let mut authority_worlds = worlds
        .iter()
        .map(|world| AuthorityWorld {
            context: world.context.clone(),
            schema: world.schema.clone(),
            costs: world.costs.clone(),
        })
        .collect::<Vec<_>>();
    authority_worlds.push(AuthorityWorld {
        context: prelude_context.clone(),
        schema: worlds[0].schema.clone(),
        costs: worlds[0]
            .schema
            .edges
            .iter()
            .map(|edge| edge.lower)
            .collect(),
    });
    let mut authority_grants = vec![grant(
        controller_identity,
        controller_material,
        AUTH_CONTROL,
    )];
    for role in [0, 1, 2, 4] {
        authority_grants.push(grant(&role_ids[role], &materials[role], AUTHORITY_OPS));
    }
    let authority = Node {
        bootstrap: Bootstrap {
            state: authority_path,
            expected_identity: authority_id,
            controller_identity: controller_identity.into(),
            material: authority_material,
            ca_pem: ca.pem.clone(),
            grants: authority_grants,
            role: Role::Authority {
                worlds: authority_worlds,
                allowed_observers: allowed,
            },
            protocol_sha256: PROTOCOL_SHA256.into(),
        },
        process: None,
        last_stop: None,
    };
    let mut roles = Vec::new();
    for role in 0..5 {
        let mut grants = vec![grant(controller_identity, controller_material, CONTROL_OPS)];
        let partners = if role == 0 {
            vec![1, 2, 4]
        } else if role == 3 {
            vec![]
        } else {
            vec![0]
        };
        for peer in partners {
            grants.push(grant(&role_ids[peer], &materials[peer], PEER_OPS));
        }
        roles.push(Node {
            bootstrap: Bootstrap {
                state: role_paths[role].clone(),
                expected_identity: role_ids[role].clone(),
                controller_identity: controller_identity.into(),
                material: materials[role].clone(),
                ca_pem: ca.pem.clone(),
                grants,
                role: Role::Learner {
                    arm,
                    observation_price: price,
                    offer_mode: if role == 4 {
                        OfferMode::PreviousContext
                    } else {
                        OfferMode::CurrentWarmup
                    },
                    inactive: role == 3,
                },
                protocol_sha256: PROTOCOL_SHA256.into(),
            },
            process: None,
            last_stop: None,
        });
    }
    Ok(Campaign {
        arm,
        price,
        roles,
        authority,
        controller: TlsClientConfig::new(
            controller_identity.into(),
            controller_material.identity()?,
            ca.pem.as_bytes(),
        )?,
        setup: vec![Bill::default(); 5],
        prelude_context,
        unconfigured: true,
        failed: false,
        restarts: 0,
        lifecycle: Vec::new(),
    })
}
impl Campaign {
    fn launch(&mut self, restart: bool) -> Result<(), String> {
        if self.authority.process.is_none() {
            self.authority.launch()?;
        }
        for node in &mut self.roles {
            node.launch()?;
        }
        let pids = self
            .roles
            .iter()
            .map(|node| {
                node.process
                    .as_ref()
                    .map(|process| process.ready().pid)
                    .ok_or("native participant not launched")
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if pids.len() != 5
            || pids.contains(&std::process::id())
            || pids.contains(
                &self
                    .authority
                    .process
                    .as_ref()
                    .ok_or("authority missing")?
                    .ready()
                    .pid,
            )
        {
            return Err("native process separation failed".into());
        }
        for role in [0, 1, 2, 4] {
            let mut registry = Vec::new();
            let peers = if role == 0 { vec![1, 2, 4] } else { vec![0] };
            for peer in peers {
                let endpoint = self.roles[peer].endpoint()?;
                registry.push(Descriptor {
                    identity: endpoint.identity.clone(),
                    authorized: true,
                    compatible: true,
                    endpoint: Some(endpoint),
                });
            }
            let mut incompatible = self.roles[3].endpoint()?;
            incompatible.scope = "incompatible-domain/v1".into();
            registry.push(Descriptor {
                identity: incompatible.identity.clone(),
                authorized: true,
                compatible: false,
                endpoint: Some(incompatible),
            });
            registry.push(Descriptor {
                identity: "operator-unauthorized-descriptor".into(),
                authorized: false,
                compatible: true,
                endpoint: None,
            });
            let (_, traffic) = role_call(
                self,
                role,
                "configure",
                &json!({"registry":registry,"oracle":self.authority.endpoint()?}),
            )?;
            self.setup[role].merge(&reverse_bill(traffic));
        }
        self.lifecycle.push(json!({"event":if restart{"planned-between-world-restart"}else{"initial-launch"},"roles":self.roles.iter().enumerate().map(|(role,node)|json!({"evaluator_role":role,"ready":node.process.as_ref().map(|process|process.ready())})).collect::<Vec<_>>(),"authority":self.authority.process.as_ref().map(|process|process.ready())}));
        if restart {
            self.restarts += 1;
        }
        Ok(())
    }
    fn prelude(&mut self, world: &World) -> Result<(), String> {
        let (warmups, _) = warmups(world)?;
        let observer = self.roles[4].bootstrap.expected_identity.clone();
        let train = training(world, warmups[4]);
        authority_call(
            self,
            "begin",
            &json!({"context":self.prelude_context,"observers":[observer],"training_inputs":BTreeMap::from([(observer,train)])}),
        )?;
        role_call(
            self,
            4,
            "begin",
            &json!({"context":self.prelude_context,"schema":world.schema,"algorithm":algorithm(world.seed_index,4),"warmup_edge":warmups[4],"prelude":true}),
        )?;
        role_call(self, 4, "warmup", &json!({}))?;
        let (proof, _) = role_call(
            self,
            4,
            "export-page",
            &json!({"kind":"receipts","offset":0}),
        )?;
        let calibration = authority_call(
            self,
            "calibrate",
            &json!({"receipt":proof["acquisitions"][0]["receipt"]}),
        )?;
        if calibration["authentic"] != true {
            return Err("genuine prelude receipt failed negative-control calibration".into());
        }
        self.lifecycle.push(json!({"event":"genuine-stale-control-calibration","receipt":proof["acquisitions"][0]["receipt"],"verdict":calibration}));
        let (reply, traffic) = role_call(self, 4, "finish", &json!({}))?;
        let mut bill: Bill = serde_json::from_value(reply["bill_before_response"].clone())
            .map_err(|_| "prelude meter missing")?;
        bill.rpc_sent_bytes += traffic.rpc_received_bytes;
        self.setup[4].merge(&bill);
        self.unconfigured = false;
        Ok(())
    }
    fn stop_roles(&mut self) -> Result<(), String> {
        let mut failure = None;
        for node in &mut self.roles {
            if let Err(error) = node.stop() {
                failure.get_or_insert(error);
            }
        }
        self.lifecycle.push(json!({"event":"owned-roles-stopped","roles":self.roles.iter().enumerate().map(|(role,node)|json!({"role":role,"stop":node.last_stop})).collect::<Vec<_>>()}));
        if let Some(stop) = &self.roles[3].last_stop {
            if stop["summary"]["application_requests"] != 0 || stop["summary"]["connections"] != 0 {
                failure.get_or_insert("HOLD: incompatible B3 received a connection or its exact lifecycle counter is unavailable".into());
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    }
    fn stop_all(&mut self) -> Result<(), String> {
        let role_result = self.stop_roles();
        let authority_result = self.authority.stop();
        role_result?;
        authority_result
    }
}

fn world_case(campaign: &mut Campaign, world: &World, truth: &Truth) -> Result<Value, String> {
    let started = Instant::now();
    let (warmup, public_work) = warmups(world)?;
    let observers = [0, 1, 2, 4]
        .into_iter()
        .map(|role| campaign.roles[role].bootstrap.expected_identity.clone())
        .collect::<Vec<_>>();
    let training_inputs = [0, 1, 2, 4]
        .into_iter()
        .map(|role| {
            (
                campaign.roles[role].bootstrap.expected_identity.clone(),
                training(world, warmup[role]),
            )
        })
        .collect::<BTreeMap<_, _>>();
    authority_call(
        campaign,
        "begin",
        &json!({"context":world.context,"observers":observers,"training_inputs":training_inputs}),
    )?;
    for role in [0, 1, 2, 4] {
        role_call(
            campaign,
            role,
            "begin",
            &json!({"context":world.context,"schema":world.schema,"algorithm":algorithm(world.seed_index,role),"warmup_edge":warmup[role],"prelude":false}),
        )?;
    }
    for role in [0, 1, 2, 4] {
        role_call(campaign, role, "warmup", &json!({}))?;
    }
    let mut participants = Vec::new();
    for role in [0, 1, 2, 4] {
        let mut main_status = "not-completed".to_string();
        let mut main_route = Value::Null;
        let mut judge_receipts = Vec::new();
        for decision in 0..=world.schema.edges.len() {
            let draws = if campaign.arm == Arm::Uniform {
                Some(
                    (1..=4)
                        .map(|choices| {
                            Ok((
                                choices.to_string(),
                                cohort::uniform_index(
                                    world,
                                    decision,
                                    campaign.arm.index(),
                                    choices,
                                )?,
                            ))
                        })
                        .collect::<Result<BTreeMap<_, _>, String>>()?,
                )
            } else {
                None
            };
            let (reply, _) = role_call(campaign, role, "advance", &json!({"uniform_draws":draws}))?;
            let status = reply["status"]
                .as_str()
                .ok_or("route advance status missing")?;
            if status != "continue" {
                main_status = status.into();
                main_route = reply["route"].clone();
                break;
            }
        }
        if main_status == "complete" {
            if main_route.is_null() {
                return Err("native completion omitted its actual conditional route".into());
            }
            let routes = vec![json!({"input":world.nodes-1,"route":main_route})];
            let verdict = authority_call(
                campaign,
                "judge",
                &json!({"context":world.context,"routes":routes}),
            )?;
            check_judge(&world.context, &routes, &verdict)?;
            judge_receipts.push(verdict);
        }
        let trained = training(world, warmup[role]);
        let mut forecasts = Vec::new();
        let mut incorrect = 0;
        let mut correct = 0;
        for input in truth.costs.keys().filter(|input| !trained.contains(input)) {
            let (reply, _) = role_call(campaign, role, "forecast", &json!({"input":input}))?;
            let route = reply["route"].clone();
            if !route.is_null() {
                if route["cost"].as_u64() != Some(truth.costs[input]) {
                    incorrect += 1;
                } else {
                    correct += 1;
                }
            }
            forecasts.push(json!({"input":input,"route":route,"reason":reply["reason"]}));
        }
        for page in forecasts.chunks(8) {
            let routes = page
                .iter()
                .map(|claim| json!({"input":claim["input"],"route":claim["route"]}))
                .collect::<Vec<_>>();
            let verdict = authority_call(
                campaign,
                "judge",
                &json!({"context":world.context,"routes":routes}),
            )?;
            check_judge(&world.context, &routes, &verdict)?;
            judge_receipts.push(verdict);
        }
        if incorrect > 0 {
            return Err("HOLD: frozen independent labels rejected a reported route cost".into());
        }
        let (model, _) = role_call(campaign, role, "export-page", &json!({"kind":"model"}))?;
        let mut receipts = Vec::new();
        let mut offset = 0;
        loop {
            let (page, _) = role_call(
                campaign,
                role,
                "export-page",
                &json!({"kind":"receipts","offset":offset}),
            )?;
            receipts.extend(
                page["acquisitions"]
                    .as_array()
                    .ok_or("evidence export page malformed")?
                    .iter()
                    .cloned(),
            );
            if page["next"].is_null() {
                break;
            }
            offset = page["next"]
                .as_u64()
                .ok_or("evidence export pagination invalid")? as usize;
        }
        participants.push(json!({"role":role,"identity":campaign.roles[role].bootstrap.expected_identity,"main_status":main_status,"main_route":main_route,"training_inputs":trained,"heldout_total":forecasts.len(),"heldout_correct":correct,"abstentions":forecasts.len()-correct,"incorrect_certificates":incorrect,"forecasts":forecasts,"judge_receipts":judge_receipts,"record":model["record"],"acquisitions":receipts}));
    }
    // Finish only after every participant can no longer initiate a contribution;
    // all provider replies are then present in the exact traffic counters.
    for (position, role) in [0, 1, 2, 4].into_iter().enumerate() {
        let (reply, traffic) = role_call(campaign, role, "finish", &json!({}))?;
        let mut bill: Bill = serde_json::from_value(reply["bill_before_response"].clone())
            .map_err(|_| "final participant meter malformed")?;
        bill.rpc_sent_bytes += traffic.rpc_received_bytes;
        bill.remaining(world.schema.edges.len())?;
        participants[position]["bill"] = json!(bill);
        participants[position]["cost"] = json!(bill.total(campaign.price));
        participants[position]["promotion"] = reply["promotion"].clone();
        participants[position]["profiles"] = reply["profiles"].clone();
        participants[position]["abstention_reason"] = reply["abstention"].clone();
        participants[position]["metadata_outcomes"] = reply["metadata_outcomes"].clone();
        participants[position]["utility_evaluable"] = json!(!reply["source_response_ambiguous"]
            .as_bool()
            .ok_or("source-purchase ambiguity witness missing")?);
    }
    participants.push(json!({"role":3,"identity":campaign.roles[3].bootstrap.expected_identity,"status":"INCOMPATIBLE_IDLE","agent_api_calls":0,"acquisitions":0,"cost":0,"bill":Bill::default()}));
    participants.sort_by_key(|participant| participant["role"].as_u64());
    Ok(
        json!({"world":world.index,"context":world.context,"nodes":world.nodes,"arm":campaign.arm.name(),"price":campaign.price,"status":"COMPLETED","participants":participants,"public_warmup_planning_work":public_work,"elapsed_ms":started.elapsed().as_millis(),"unauthorized_connection_attempts":0,"incompatible_agent_api_probes":0}),
    )
}

fn offline_pages(campaign: &Campaign) -> Result<Value, String> {
    let mut participants = Vec::new();
    for role in [0, 1, 2, 4] {
        let mut pages = Vec::new();
        let mut payload = json!({"offset":0,"route_offset":0});
        let mut calls = 0;
        let mut meter = Bill::default();
        loop {
            calls += 1;
            if calls > 256 {
                return Err("offline retained pagination exceeded its bound".into());
            }
            let (page, traffic) = role_call(campaign, role, "retained-page", &payload)?;
            meter.merge(&reverse_bill(traffic));
            payload = page["next"].clone();
            pages.push(json!({"identity":page["identity"],"models":page["models"],"profiles":page["profiles"]}));
            if payload.is_null() {
                break;
            }
        }
        participants.push(json!({"role":role,"pages":pages,"rpc_traffic_only":meter}));
    }
    Ok(json!(participants))
}
fn normalize_offline(snapshot: &Value) -> Value {
    json!(snapshot.as_array().map(|roles| roles
        .iter()
        .map(|role| json!({"role":role["role"],"pages":role["pages"]}))
        .collect::<Vec<_>>()))
}
fn retained_counts(snapshot: &Value) -> Result<Value, String> {
    let mut rows = Vec::new();
    let mut scopes = BTreeMap::new();
    for role in snapshot
        .as_array()
        .ok_or("offline participant list missing")?
    {
        let index = role["role"].as_u64().ok_or("offline role missing")?;
        let mut models = BTreeSet::new();
        let mut predictions = BTreeSet::new();
        let mut contexts = BTreeSet::new();
        for page in role["pages"].as_array().ok_or("offline pages missing")? {
            for model in page["models"]
                .as_array()
                .ok_or("offline model list missing")?
            {
                let id = model["id"]
                    .as_str()
                    .ok_or("offline model id missing")?
                    .to_string();
                let digest = model["record_digest"]
                    .as_str()
                    .ok_or("offline model digest missing")?
                    .to_string();
                models.insert((id.clone(), digest));
                contexts.insert(
                    model["scope"]
                        .as_str()
                        .ok_or("offline applicability missing")?
                        .to_string(),
                );
                for prediction in model["routes"].as_array().ok_or("offline routes missing")? {
                    if !prediction["route"].is_null() {
                        predictions.insert((
                            id.clone(),
                            prediction["input"]
                                .as_u64()
                                .ok_or("offline query missing")?,
                        ));
                    }
                }
            }
        }
        scopes.insert(index, contexts);
        rows.push(json!({"role":index,"validated_models":models.len(),"certified_offline_predictions":predictions.len(),"learning_gate":if !models.is_empty()&&!predictions.is_empty(){"DEMONSTRATED"}else{"NOT_DEMONSTRATED"}}));
    }
    let common = scopes
        .get(&0)
        .zip(scopes.get(&1))
        .map_or(0, |(first, second)| first.intersection(second).count());
    Ok(
        json!({"participants":rows,"A_B1_common_validated_contexts":common,"bilateral_learning_gate":if common>0{"DEMONSTRATED"}else{"NOT_DEMONSTRATED"}}),
    )
}
fn oracle_counts(audit: &Value, campaign: &Campaign) -> Result<Value, String> {
    let mut result = BTreeMap::new();
    let actors = audit["per_actor"]
        .as_object()
        .ok_or("required authority audit counters missing")?;
    for role in [0, 1, 2, 4] {
        if !actors.contains_key(&campaign.roles[role].bootstrap.expected_identity) {
            return Err("required native observer missing from authority audit".into());
        }
    }
    for (identity, counts) in actors {
        for field in ["observe", "verify", "assess"] {
            counts[field]
                .as_u64()
                .ok_or("required authority counter malformed")?;
        }
        result.insert(identity.clone(),json!({"observe":counts["observe"],"verify":counts["verify"],"assess":counts["assess"]}));
    }
    Ok(json!(result))
}
fn protected_hashes(campaign: &Campaign) -> Result<Value, String> {
    let mut roles = Vec::new();
    for (role, node) in campaign.roles.iter().enumerate() {
        let mut files = BTreeMap::new();
        for name in [
            "ledger.jsonl",
            "knowledge.jsonl",
            "operations.jsonl",
            "operations-owner.json",
        ] {
            let path = node.bootstrap.state.join(name);
            let digest = if path.exists() {
                Some(format!(
                    "{:x}",
                    Sha256::digest(fs::read(&path).map_err(|e| e.to_string())?)
                ))
            } else {
                None
            };
            files.insert(name, digest);
        }
        roles.push(json!({"role":role,"identity":node.bootstrap.expected_identity,"files":files}));
    }
    Ok(json!(roles))
}
fn restart(campaign: &mut Campaign, planned_index: usize) -> Result<Value, String> {
    let roles_before = campaign
        .roles
        .iter()
        .map(|node| {
            node.process
                .as_ref()
                .map(|process| process.ready().clone())
                .ok_or("restart source child missing")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let before = offline_pages(campaign)?;
    let counters_before = oracle_counts(&authority_call(campaign, "audit", &json!({}))?, campaign)?;
    campaign.stop_roles()?;
    let stopped = campaign
        .roles
        .iter()
        .map(|node| node.last_stop.clone())
        .collect::<Vec<_>>();
    let hashes = protected_hashes(campaign)?;
    for node in &mut campaign.roles {
        node.launch()?;
    }
    let roles_after = campaign
        .roles
        .iter()
        .map(|node| {
            node.process
                .as_ref()
                .map(|process| process.ready().clone())
                .ok_or("restart target child missing")
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (before, after) in roles_before.iter().zip(&roles_after) {
        if before.identity != after.identity
            || before.certificate_sha256 != after.certificate_sha256
            || before.instance_nonce == after.instance_nonce
        {
            return Err(
                "HOLD: restart did not create a fresh owned instance with stable identity and pin"
                    .into(),
            );
        }
    }
    let after = offline_pages(campaign)?;
    let counters_after = oracle_counts(&authority_call(campaign, "audit", &json!({}))?, campaign)?;
    if normalize_offline(&before) != normalize_offline(&after)
        || counters_before != counters_after
        || protected_hashes(campaign)? != hashes
    {
        return Err("HOLD: native offline restart changed identity/profile/knowledge or contacted its authority".into());
    }
    // Restore only operator endpoints/grants. Warmup history and profiles are
    // replayed by the recipient from its own owner-bound journal.
    for role in [0, 1, 2, 4] {
        let peers = if role == 0 { vec![1, 2, 4] } else { vec![0] };
        let mut registry = Vec::new();
        for peer in peers {
            let endpoint = campaign.roles[peer].endpoint()?;
            registry.push(Descriptor {
                identity: endpoint.identity.clone(),
                authorized: true,
                compatible: true,
                endpoint: Some(endpoint),
            });
        }
        let mut incompatible = campaign.roles[3].endpoint()?;
        incompatible.scope = "incompatible-domain/v1".into();
        registry.push(Descriptor {
            identity: incompatible.identity.clone(),
            authorized: true,
            compatible: false,
            endpoint: Some(incompatible),
        });
        registry.push(Descriptor {
            identity: "operator-unauthorized-descriptor".into(),
            authorized: false,
            compatible: true,
            endpoint: None,
        });
        let (_, traffic) = role_call(
            campaign,
            role,
            "configure",
            &json!({"registry":registry,"oracle":campaign.authority.endpoint()?}),
        )?;
        campaign.setup[role].merge(&reverse_bill(traffic));
    }
    campaign.restarts += 1;
    let counts = retained_counts(&after)?;
    let any = counts["participants"].as_array().is_some_and(|roles| {
        roles
            .iter()
            .any(|role| role["learning_gate"] == "DEMONSTRATED")
    });
    let receipt = json!({"after_completed_world":planned_index,"identity_and_profile_bytes_preserved":true,"retained_predictions_preserved":any,"learning":counts,"roles_before":roles_before,"roles_stopped":stopped,"roles_after":roles_after,"protected_file_sha256":hashes,"oracle_before":counters_before,"oracle_after":counters_after,"before":before,"after":after});
    campaign.lifecycle.push(receipt.clone());
    Ok(receipt)
}
pub(super) fn prospective(permit: EvaluationPermit) -> Result<Value, String> {
    let (worlds, setup) = cohort::prospective(&permit)?;
    run_worlds(
        RunConfig {
            state: &permit.registration.state_directory,
            receipts: &permit.registration.receipt_path,
            artifacts: &permit.registration.artifact_directory,
            mode: permit.mode,
            run_id: &permit.registration.run_id,
            registration_sha256: &permit.registration_sha256,
            restart_after: 11,
        },
        worlds,
        setup,
    )
}
#[cfg(debug_assertions)]
pub(super) fn development(state: &Path, receipts: &Path) -> Result<Value, String> {
    let artifacts = state
        .parent()
        .ok_or("development artifact parent missing")?;
    if !state.is_absolute()
        || !receipts.is_absolute()
        || !fs::canonicalize(artifacts)
            .map_err(|e| e.to_string())?
            .starts_with(fs::canonicalize(std::env::temp_dir()).map_err(|e| e.to_string())?)
    {
        return Err(
            "manual development probe must use a dedicated OS temporary artifact directory".into(),
        );
    }
    if fs::read_dir(state)
        .map_err(|e| e.to_string())?
        .next()
        .is_some()
        || receipts.exists()
    {
        return Err("manual development probe requires fresh state/output".into());
    }
    use symbiote_reasoning::planning::{Edge, GraphSchema};
    let schema = GraphSchema {
        nodes: 4,
        edges: [(0, 1), (1, 3), (0, 2), (2, 3)]
            .into_iter()
            .map(|(from, to)| Edge {
                from,
                to,
                lower: 1,
                upper: 3,
            })
            .collect(),
    };
    let worlds = [[1, 3, 2, 2], [2, 1, 3, 2], [3, 2, 1, 3]]
        .into_iter()
        .enumerate()
        .map(|(index, costs)| {
            Ok(World {
                index,
                nodes: 4,
                seed: 17,
                seed_index: index % 2,
                counter: 0,
                canonical_adjacency: "released-v04-diamond-development-fixture".into(),
                context: format!("frontier-context-{}", fresh_capability()?),
                schema: schema.clone(),
                costs: costs.to_vec(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    run_worlds(
        RunConfig {
            state,
            receipts,
            artifacts,
            mode: "development-calibration",
            run_id: "released-v04-manual-fixtures",
            registration_sha256: "not-a-primary-registration",
            restart_after: 0,
        },
        worlds,
        SetupWork::default(),
    )
}
struct RunConfig<'a> {
    state: &'a Path,
    receipts: &'a Path,
    artifacts: &'a Path,
    mode: &'a str,
    run_id: &'a str,
    registration_sha256: &'a str,
    restart_after: usize,
}
fn run_worlds(
    config: RunConfig<'_>,
    worlds: Vec<World>,
    setup_work: SetupWork,
) -> Result<Value, String> {
    let RunConfig {
        state,
        receipts,
        artifacts,
        mode,
        run_id,
        registration_sha256,
        restart_after,
    } = config;
    let started = Instant::now();
    let deadline = started + Duration::from_secs(1800);
    let owner = Arc::new(Store::open(state)?);
    let identity = owner.identity().to_string();
    let truths = worlds
        .iter()
        .map(|world| cohort::freeze_truth(&world.schema, &world.costs))
        .collect::<Result<Vec<_>, _>>()?;
    let frozen = json!({"worlds":worlds,"truths":truths});
    let frozen_digest = body_digest(&frozen)?;
    let mut frozen_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(artifacts.join("frozen-environments.json"))
        .map_err(|_| "frozen environment output already exists")?;
    frozen_file
        .write_all(&serde_json::to_vec(&frozen).map_err(|e| e.to_string())?)
        .and_then(|_| frozen_file.sync_all())
        .map_err(|e| e.to_string())?;
    let ca = LabCa::new()?;
    let controller_material = ca.leaf()?;
    let mut campaigns = Vec::new();
    let mut role_genesis = None::<Vec<Vec<u8>>>;
    for price in [100, 1] {
        for arm in Arm::ALL {
            let next = campaign(
                state,
                &worlds,
                arm,
                price,
                &IdentitySetup {
                    ca: &ca,
                    controller_material: &controller_material,
                    controller_identity: &identity,
                    role_genesis: role_genesis.as_deref(),
                },
            )?;
            if role_genesis.is_none() {
                role_genesis = Some(
                    next.roles
                        .iter()
                        .map(|node| {
                            fs::read(node.bootstrap.state.join("ledger.jsonl"))
                                .map_err(|e| e.to_string())
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
            campaigns.push(next);
        }
    }
    fn genesis(path: &Path, identity: &str) -> Result<Value, String> {
        let bytes = fs::read(path.join("ledger.jsonl")).map_err(|e| e.to_string())?;
        let text = String::from_utf8(bytes).map_err(|_| "fresh simulation genesis is not UTF8")?;
        if text.lines().count() != 1 {
            return Err("initial simulation catalogue must contain genesis-only state".into());
        }
        Ok(json!({"identity":identity,"genesis_jsonl":text}))
    }
    let mut catalogue_groups = Vec::new();
    for campaign in &campaigns {
        let mut roles = Vec::new();
        for (role, node) in campaign.roles.iter().enumerate() {
            roles.push(json!({"role":role,"genesis":genesis(&node.bootstrap.state,&node.bootstrap.expected_identity)?}));
        }
        catalogue_groups.push(json!({"arm":campaign.arm.name(),"price":campaign.price,"roles":roles,"authority":genesis(&campaign.authority.bootstrap.state,&campaign.authority.bootstrap.expected_identity)?}));
    }
    let mut identities = BTreeSet::from([identity.clone()]);
    for campaign in &campaigns {
        identities.insert(campaign.authority.bootstrap.expected_identity.clone());
        for role in 0..5 {
            if campaign.roles[role].bootstrap.expected_identity
                != campaigns[0].roles[role].bootstrap.expected_identity
            {
                return Err(
                    "paired role identity changed across counterfactual profile namespaces".into(),
                );
            }
            identities.insert(campaign.roles[role].bootstrap.expected_identity.clone());
        }
    }
    if identities.len() != 14 {
        return Err("operator setup must have five paired role identities, eight distinct authorities, and a controller".into());
    }
    let catalogue = json!({"schema":"symbiote.simulation-genesis-catalogue/1","identity_count":14,"state_path_count":49,"counterfactual_learner_identities":5,"isolated_learner_profiles":40,"controller":genesis(state,&identity)?,"groups":catalogue_groups,"contains_private_keys":false,"contains_learned_records":false});
    let catalogue_digest = body_digest(&catalogue)?;
    let mut catalogue_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(artifacts.join("simulation-genesis-catalogue.json"))
        .map_err(|_| "initial simulation catalogue already exists")?;
    catalogue_file
        .write_all(&serde_json::to_vec_pretty(&catalogue).map_err(|e| e.to_string())?)
        .and_then(|_| catalogue_file.sync_all())
        .map_err(|e| e.to_string())?;
    let mut journal = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(artifacts.join("case-receipts.jsonl"))
        .map_err(|_| "case journal already exists")?;
    let mut cases = Vec::new();
    let mut failures = Vec::new();
    let mut capped = false;
    for regime in 0..2 {
        for world in &worlds {
            if Instant::now() >= deadline {
                capped = true;
            }
            if !capped && world.index == restart_after + 1 {
                for arm in 0..4 {
                    let campaign = &mut campaigns[regime * 4 + arm];
                    if !campaign.failed && campaign.authority.process.is_some() {
                        if let Err(error) = restart(campaign, restart_after) {
                            campaign.failed = true;
                            failures.push(json!({"phase":"planned-restart","price":campaign.price,"arm":campaign.arm.name(),"error":error}));
                            if let Err(cleanup) = campaign.stop_all() {
                                failures.push(json!({"phase":"planned-restart-cleanup","price":campaign.price,"arm":campaign.arm.name(),"error":cleanup}));
                            }
                        }
                    }
                }
            }
            for offset in 0..4 {
                let arm = (world.index + offset) % 4;
                let campaign = &mut campaigns[regime * 4 + arm];
                if Instant::now() >= deadline {
                    capped = true;
                }
                let case = if capped || campaign.failed {
                    json!({"world":world.index,"context":world.context,"price":campaign.price,"arm":campaign.arm.name(),"status":"NOT_RUN","reason":if capped{"primary-1800s-cap"}else{"owned-campaign-failed-no-unregistered-retry"}})
                } else {
                    let result = (|| {
                        if campaign.authority.process.is_none() {
                            campaign.launch(false)?;
                        }
                        if campaign.unconfigured {
                            campaign.prelude(&worlds[0])?;
                        }
                        world_case(campaign, world, &truths[world.index])
                    })();
                    match result {
                        Ok(case) => case,
                        Err(error) => {
                            campaign.failed = true;
                            failures.push(json!({"world":world.index,"price":campaign.price,"arm":campaign.arm.name(),"error":error}));
                            if let Err(cleanup) = campaign.stop_all() {
                                failures.push(json!({"phase":"case-error-cleanup","world":world.index,"price":campaign.price,"arm":campaign.arm.name(),"error":cleanup}));
                            }
                            json!({"world":world.index,"context":world.context,"price":campaign.price,"arm":campaign.arm.name(),"status":"FAILED","reason":error,"actual_meter_status":"partial-or-unavailable; no utility success inferred"})
                        }
                    }
                };
                let mut bytes = serde_json::to_vec(&case).map_err(|e| e.to_string())?;
                bytes.push(b'\n');
                journal
                    .write_all(&bytes)
                    .and_then(|_| journal.sync_all())
                    .map_err(|e| e.to_string())?;
                cases.push(case);
            }
        }
    }
    let mut campaign_reports = Vec::new();
    for campaign in &mut campaigns {
        let audit = if !capped && campaign.authority.process.is_some() {
            match authority_call(campaign, "audit", &json!({})) {
                Ok(audit) => {
                    if let Err(error) = oracle_counts(&audit, campaign) {
                        campaign.failed = true;
                        failures.push(json!({"phase":"required-authority-audit","arm":campaign.arm.name(),"price":campaign.price,"error":error}));
                    }
                    Some(audit)
                }
                Err(error) => {
                    campaign.failed = true;
                    failures.push(json!({"phase":"required-authority-audit","arm":campaign.arm.name(),"price":campaign.price,"error":error}));
                    None
                }
            }
        } else {
            None
        };
        let restart_proof = if !capped && !campaign.failed && campaign.authority.process.is_some() {
            match restart(campaign, worlds.len() - 1) {
                Ok(proof) => Some(proof),
                Err(error) => {
                    campaign.failed = true;
                    failures.push(json!({"phase":"final-offline-restart","arm":campaign.arm.name(),"price":campaign.price,"error":error}));
                    None
                }
            }
        } else {
            None
        };
        let resources=campaign.roles.iter().enumerate().map(|(role,node)|json!({"role":role,"resources":node.process.as_ref().map(|process|process.resources()),"state":node.bootstrap.state,"identity":node.bootstrap.expected_identity})).collect::<Vec<_>>();
        if let Err(error) = campaign.stop_all() {
            campaign.failed = true;
            failures.push(json!({"phase":"shutdown","arm":campaign.arm.name(),"price":campaign.price,"error":error}));
        }
        let mut profile_audits = Vec::new();
        for role in 0..5 {
            let neighbors = if role == 0 {
                vec![1, 2, 4]
            } else if role == 3 {
                vec![]
            } else {
                vec![0]
            };
            let registry = neighbors
                .into_iter()
                .map(|peer| super::policy::RegistryPeer {
                    identity: campaign.roles[peer].bootstrap.expected_identity.clone(),
                    authorized: true,
                    compatible: true,
                })
                .collect::<Vec<_>>();
            match super::profile_audit::inspect(
                &campaign.roles[role].bootstrap.state,
                &campaign.roles[role].bootstrap.expected_identity,
                campaign.arm,
                campaign.price,
                &registry,
                &worlds,
                restart_after,
            ) {
                Ok(audit) => profile_audits.push(json!({"role":role,"audit":audit})),
                Err(error) => {
                    campaign.failed = true;
                    failures.push(json!({"phase":"private-profile-audit","arm":campaign.arm.name(),"price":campaign.price,"role":role,"error":error}));
                    profile_audits.push(json!({"role":role,"audit":{"status":"HOLD"}}));
                }
            }
        }
        let setup_cost = campaign
            .setup
            .iter()
            .map(|bill| bill.total(campaign.price))
            .sum::<u64>();
        let task_cases = cases
            .iter()
            .filter(|case| {
                case["status"] == "COMPLETED"
                    && case["arm"] == campaign.arm.name()
                    && case["price"] == campaign.price
            })
            .collect::<Vec<_>>();
        let task_cost = task_cases
            .iter()
            .map(|case| {
                case["participants"].as_array().map_or(0, |rows| {
                    rows.iter()
                        .filter_map(|role| role["cost"].as_u64())
                        .sum::<u64>()
                })
            })
            .sum::<u64>();
        campaign_reports.push(json!({"arm":campaign.arm.name(),"price":campaign.price,"authority_identity":campaign.authority.bootstrap.expected_identity,"participant_states":resources,"setup_bills":campaign.setup,"setup_cost":setup_cost,"completed_worlds":task_cases.len(),"completed_task_cost":task_cost,"completed_whole_system_logical_cost_with_setup":task_cost+setup_cost,"profile_audits":profile_audits,"planned_profile_restarts":campaign.restarts,"lifecycle":campaign.lifecycle,"final_restart":restart_proof,"authority_audit":audit,"authority_stop":campaign.authority.last_stop,"failed":campaign.failed}));
    }
    let status =
        if failures.is_empty() && !capped && cases.iter().all(|case| case["status"] == "COMPLETED")
        {
            "PASS"
        } else {
            "HOLD"
        };
    let prospective = campaign_reports
        .iter()
        .find(|campaign| campaign["arm"] == "prospective-frontier" && campaign["price"] == 100);
    let retained = prospective.is_some_and(|campaign| {
        campaign["final_restart"]["learning"]["A_B1_common_validated_contexts"]
            .as_u64()
            .is_some_and(|count| count > 0)
    });
    let profile_use = prospective
        .and_then(|campaign| campaign["profile_audits"].as_array())
        .is_some_and(|rows| {
            rows.iter().any(|row| {
                row["role"] == 0 && row["audit"]["prior_profile_use_gate"] == "DEMONSTRATED"
            })
        });
    let report = json!({"schema":"symbiote.adaptive-research/1","version":env!("CARGO_PKG_VERSION"),"mode":mode,"status":status,"run_id":run_id,"registration_sha256":registration_sha256,"protocol_id":PROTOCOL_ID,"protocol_sha256":PROTOCOL_SHA256,"source_commit":SOURCE_COMMIT,"identity":identity,"world_count":worlds.len(),"price_regimes":2,"comparison_arms":4,"cases_expected":worlds.len()*8,"cases_recorded":cases.len(),"frozen_environments_sha256":frozen_digest,"initial_simulation_genesis_sha256":catalogue_digest,"native_learner_profiles":40,"native_learner_logical_identities":5,"native_authority_profiles":8,"learning_gate":{"prospective_normal_shared_retained_context":if retained{"DEMONSTRATED"}else{"NOT_DEMONSTRATED"},"central_A_prior_profile_use_after_restart":if profile_use{"DEMONSTRATED"}else{"NOT_DEMONSTRATED"},"status":if retained&&profile_use&&status=="PASS"{"DEMONSTRATED"}else{"NOT_DEMONSTRATED"}},"controller_resources":super::process::parent_resources(),"generator_setup_work":setup_work,"judge_setup_work":truths.iter().map(|truth|truth.path_work).sum::<u64>(),"cases":cases,"comparisons":super::summary::summarize(&cases,worlds.len()),"campaigns":campaign_reports,"failures":failures,"campaign_cap_reached":capped,"elapsed_ms":started.elapsed().as_millis(),"logical_cost_scope":"all participant application RPC/session/full-JSONL negotiation+RPC bytes/acquisition/verification attempts/adoption/live-model-work/export categories; TLS records, OS, controller/judge and audit-I/O reported separately; replay RPCs are separate validation overhead","limits":["fixed synthetic DAG family; no arbitrary-remote-truth or cross-domain-generalization claim","normal and cheap reuse the same worlds; not independent additional environments","five role identities are matched across counterfactual profiles; their initial order varies across fresh setups","per-process peaks are not a simultaneous system memory peak"]});
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(receipts)
        .map_err(|_| "final receipt exists or cannot be created; original output preserved")?;
    output
        .write_all(&serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?)
        .and_then(|_| output.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_authority_bootstrap_roundtrips_on_a_released_diamond_fixture() {
        use symbiote_reasoning::planning::{Edge, GraphSchema};
        let root = std::env::temp_dir().join(format!(
            "symbiote-native-bootstrap-check-{}",
            fresh_capability().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        let owner = Store::open(&root.join("root")).unwrap();
        let ca = LabCa::new().unwrap();
        let material = ca.leaf().unwrap();
        let schema = GraphSchema {
            nodes: 4,
            edges: [(0, 1), (1, 3), (0, 2), (2, 3)]
                .into_iter()
                .map(|(from, to)| Edge {
                    from,
                    to,
                    lower: 1,
                    upper: 3,
                })
                .collect(),
        };
        let world = World {
            index: 0,
            nodes: 4,
            seed: 17,
            seed_index: 0,
            counter: 0,
            canonical_adjacency: "manual".into(),
            context: format!("frontier-context-{}", fresh_capability().unwrap()),
            schema,
            costs: vec![1, 3, 2, 2],
        };
        let campaign = campaign(
            &root.join("state"),
            &[world],
            Arm::Isolated,
            100,
            &IdentitySetup {
                ca: &ca,
                controller_material: &material,
                controller_identity: owner.identity(),
                role_genesis: None,
            },
        )
        .unwrap();
        let bootstrap: Bootstrap =
            serde_json::from_value(serde_json::to_value(&campaign.authority.bootstrap).unwrap())
                .unwrap();
        let native_owner = Arc::new(Store::open(&bootstrap.state).unwrap());
        let mut running = super::super::authority::create(bootstrap, native_owner).unwrap();
        running.server.shutdown().unwrap();
        drop(running);
        for node in &campaign.roles {
            let bootstrap: Bootstrap =
                serde_json::from_value(serde_json::to_value(&node.bootstrap).unwrap()).unwrap();
            let owner = Arc::new(Store::open(&bootstrap.state).unwrap());
            let mut running = super::super::actor::create(bootstrap, owner).unwrap();
            running.server.shutdown().unwrap();
            drop(running);
        }
        drop(campaign);
        drop(owner);
        fs::remove_dir_all(root).unwrap();
    }
}
