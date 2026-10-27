//! Trusted synthetic observation authority, isolated in its own native child.
//! Hidden weights enter only through the process owner's bounded stdin bootstrap.
//! Learners receive genuine observations or assessment verdicts, never judge labels.
use super::cohort::{freeze_truth, Truth};
use super::evidence::{Receipt, Verification};
use super::process::Running;
use super::wire::{label, Bootstrap, Role, SCOPE};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use symbiote_memory::knowledge::graph::{
    decode_query, graph_receipt_digest, graph_schema_fingerprint,
};
use symbiote_memory::knowledge::{KnowledgePayload, KnowledgeRecord};
use symbiote_memory::Store;
use symbiote_protocol::{
    fresh_capability, spawn_secure_server_metered, SecureSession, SecureTraffic,
};
use symbiote_reasoning::planning::{GraphSchema, GRAPH_FAMILY};

const MAX_WORLDS: usize = 25;
const MAX_OBSERVERS: usize = 40;
const MAX_ISSUED: usize = 4096;
const MAX_JOBS: usize = 128;
const ACTOR_REQUESTS: u64 = 4096;
const ACTOR_OPERATION_REQUESTS: u64 = 1024;
const FIRST_SEQUENCE: u64 = 1_000_000_000;

#[derive(Clone, Default, Serialize)]
struct Counters {
    requests: u64,
    observe: u64,
    verify: u64,
    assess: u64,
    judge: u64,
    calibrate: u64,
    invalid: u64,
}
struct World {
    schema: GraphSchema,
    fingerprint: String,
    weights: Vec<u16>,
    truth: Truth,
}
struct Active {
    context: String,
    training: BTreeSet<u16>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Begin {
    context: String,
    observers: Vec<String>,
    training_inputs: BTreeMap<String, Vec<u16>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observe {
    context: String,
    edge_id: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Verify {
    receipt: Receipt,
    context: String,
    schema_fingerprint: String,
    observer_identity: String,
    edge_id: usize,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryRoute {
    input: u16,
    route: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteClaim {
    nodes: Vec<usize>,
    edges: Vec<usize>,
    cost: u64,
    cost_basis: String,
    family: String,
    conditional: bool,
}
#[derive(Clone, Serialize)]
struct RouteResult {
    input: u16,
    certified: bool,
    correct: bool,
    abstained: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Judge {
    context: String,
    routes: Vec<QueryRoute>,
}
#[derive(Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case", deny_unknown_fields)]
enum Assess {
    Begin {
        context: String,
        record: KnowledgeRecord,
        receipt_ids: Vec<String>,
    },
    Routes {
        job_id: String,
        routes: Vec<QueryRoute>,
    },
    Finish {
        job_id: String,
    },
}
struct Job {
    observer: String,
    context: String,
    record: KnowledgeRecord,
    record_digest: String,
    required: BTreeSet<u16>,
    taskset_digest: String,
    results: BTreeMap<u16, RouteResult>,
    completed: bool,
}

struct Authority {
    _owner: Arc<Store>,
    identity: String,
    controller: String,
    epoch: String,
    worlds: BTreeMap<String, World>,
    allowed: BTreeMap<String, BTreeSet<String>>,
    active: BTreeMap<String, Active>,
    begun: BTreeSet<(String, String)>,
    issued: BTreeMap<String, Receipt>,
    observed: BTreeSet<(String, String, usize)>,
    evaluated_receipts: BTreeSet<(String, String, String)>,
    jobs: BTreeMap<String, Job>,
    assessment_contexts: BTreeSet<(String, String)>,
    counters: BTreeMap<String, Counters>,
    setup_work: u64,
    traffic: Option<SecureTraffic>,
}

fn decode<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, String> {
    serde_json::from_value(value)
        .map_err(|_| "authority request has an unsupported or malformed schema".into())
}
fn empty(value: &Value) -> Result<(), String> {
    if value.as_object().is_none_or(|object| !object.is_empty()) {
        return Err("authority audit accepts only an empty object".into());
    }
    Ok(())
}
fn sha(value: &Value) -> Result<String, String> {
    graph_receipt_digest(value)
}

impl Authority {
    fn new(bootstrap: Bootstrap, owner: Arc<Store>) -> Result<Self, String> {
        bootstrap.validate()?;
        if bootstrap.expected_identity != owner.identity() {
            return Err("authority owner differs from its provisioned identity".into());
        }
        let Role::Authority {
            worlds,
            allowed_observers,
        } = bootstrap.role
        else {
            return Err("authority factory requires the authority role".into());
        };
        if worlds.is_empty()
            || worlds.len() > MAX_WORLDS
            || allowed_observers.is_empty()
            || allowed_observers.len() > MAX_OBSERVERS
        {
            return Err(
                "authority world/observer configuration exceeds its declared bounds".into(),
            );
        }
        let configured: BTreeSet<_> = bootstrap
            .grants
            .iter()
            .filter(|grant| {
                grant.scope == SCOPE
                    && ["observe", "verify", "assess"].iter().all(|operation| {
                        grant.operations.iter().any(|allowed| allowed == operation)
                    })
            })
            .map(|grant| grant.identity.clone())
            .collect();
        let observer_ids: BTreeSet<_> = allowed_observers.keys().cloned().collect();
        let mut allowed = BTreeMap::new();
        for (receiver, sources) in allowed_observers {
            let source_count = sources.len();
            let sources: BTreeSet<_> = sources.iter().cloned().collect();
            if !label(&receiver)
                || receiver == bootstrap.controller_identity
                || receiver == bootstrap.expected_identity
                || !configured.contains(&receiver)
                || sources.is_empty()
                || sources.len() > 5
                || sources.len() != source_count
                || !sources.contains(&receiver)
                || sources.iter().any(|source| !observer_ids.contains(source))
            {
                return Err("authority source grants must bind configured observer identities within explicit campaign groups".into());
            }
            allowed.insert(receiver, sources);
        }
        let mut known = BTreeMap::new();
        let mut setup_work = 0_u64;
        for world in worlds {
            let fingerprint = graph_schema_fingerprint(&world.schema)?;
            if !label(&world.context)
                || known.contains_key(&world.context)
                || world.schema.edges.len() > 28
                || world.costs.len() != world.schema.edges.len()
                || world
                    .schema
                    .edges
                    .iter()
                    .zip(&world.costs)
                    .any(|(edge, cost)| *cost < edge.lower || *cost > edge.upper)
            {
                return Err(
                    "authority world context, bounded topology or private cost shape is invalid"
                        .into(),
                );
            }
            let mut incoming = vec![0_usize; world.schema.nodes];
            for edge in &world.schema.edges {
                incoming[edge.to] += 1;
            }
            let mut frontier = (0..world.schema.nodes)
                .filter(|node| incoming[*node] == 0)
                .collect::<Vec<_>>();
            let mut visited = 0;
            while let Some(node) = frontier.pop() {
                visited += 1;
                for edge in &world.schema.edges {
                    if edge.from == node {
                        incoming[edge.to] -= 1;
                        if incoming[edge.to] == 0 {
                            frontier.push(edge.to);
                        }
                    }
                }
            }
            if visited != world.schema.nodes {
                return Err("authority requires a declared directed acyclic graph".into());
            }
            let truth = freeze_truth(&world.schema, &world.costs)?;
            setup_work = setup_work
                .checked_add(truth.path_work)
                .ok_or("authority setup work overflow")?;
            known.insert(
                world.context,
                World {
                    schema: world.schema,
                    fingerprint,
                    weights: world.costs,
                    truth,
                },
            );
        }
        Ok(Self {
            identity: owner.identity().into(),
            _owner: owner,
            controller: bootstrap.controller_identity,
            epoch: fresh_capability()?,
            worlds: known,
            allowed,
            active: BTreeMap::new(),
            begun: BTreeSet::new(),
            issued: BTreeMap::new(),
            observed: BTreeSet::new(),
            evaluated_receipts: BTreeSet::new(),
            jobs: BTreeMap::new(),
            assessment_contexts: BTreeSet::new(),
            counters: BTreeMap::new(),
            setup_work,
            traffic: None,
        })
    }

    fn handle(
        &mut self,
        session: &SecureSession,
        operation: &str,
        payload: Value,
    ) -> Result<Value, String> {
        if session.scope != SCOPE
            || (session.peer_id != self.controller && !self.allowed.contains_key(&session.peer_id))
        {
            return Err("authority caller lacks an explicitly configured identity/scope".into());
        }
        let counters = self.counters.entry(session.peer_id.clone()).or_default();
        counters.requests = counters
            .requests
            .checked_add(1)
            .ok_or("authority actor counter overflow")?;
        let operation_count = match operation {
            "observe" => Some(&mut counters.observe),
            "verify" => Some(&mut counters.verify),
            "assess" => Some(&mut counters.assess),
            "judge" => Some(&mut counters.judge),
            "calibrate" => Some(&mut counters.calibrate),
            _ => None,
        };
        let exhausted = if let Some(count) = operation_count {
            *count += 1;
            *count > ACTOR_OPERATION_REQUESTS
        } else {
            false
        };
        if counters.requests > ACTOR_REQUESTS || exhausted {
            counters.invalid += 1;
            return Err("authority actor request budget exhausted".into());
        }
        let result = self.dispatch(&session.peer_id, operation, payload);
        if result.is_err() {
            self.counters
                .get_mut(&session.peer_id)
                .ok_or("authority counter missing")?
                .invalid += 1;
        }
        result
    }

    fn dispatch(&mut self, peer: &str, operation: &str, payload: Value) -> Result<Value, String> {
        match operation {
            "begin" if peer == self.controller => self.begin(decode(payload)?),
            "observe" if self.allowed.contains_key(peer) => self.observe(peer, decode(payload)?),
            "verify" if self.allowed.contains_key(peer) => {
                serde_json::to_value(self.verify(peer, decode(payload)?)?)
                    .map_err(|_| "authority verification encoding failed".into())
            }
            "assess" if self.allowed.contains_key(peer) => self.assess(peer, decode(payload)?),
            "judge" if peer == self.controller => self.judge(decode(payload)?),
            "calibrate" if peer == self.controller => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Calibration {
                    receipt: Receipt,
                }
                let request: Calibration = decode(payload)?;
                let receipt = request.receipt;
                let authentic = self.authentic(&receipt);
                let applicable = authentic
                    && self.worlds.get(&receipt.context).is_some_and(|world| {
                        receipt.schema_fingerprint == world.fingerprint
                            && self.allowed.contains_key(&receipt.observer_identity)
                            && receipt
                                .applicable(
                                    &receipt.context,
                                    &world.schema,
                                    &receipt.observer_identity,
                                    receipt.edge_id,
                                )
                                .is_ok()
                    });
                serde_json::to_value(Verification {
                    authentic,
                    applicable,
                    receipt_sha256: receipt.digest()?,
                    reason: if applicable {
                        "genuine registered receipt calibrated in its original context"
                    } else {
                        "receipt calibration failed"
                    }
                    .into(),
                })
                .map_err(|_| "authority calibration encoding failed".into())
            }
            "audit" if peer == self.controller => {
                empty(&payload)?;
                Ok(
                    json!({"schema":"symbiote.authority-audit/1","identity":self.identity,"authority_id":self.epoch,"issued":self.issued.len(),"setup_work":self.setup_work,"per_actor":self.counters,"traffic":self.traffic.as_ref().map(SecureTraffic::snapshot),"expected_labels_returned_to_learners":0}),
                )
            }
            _ => Err("authority operation is outside this caller's explicit role".into()),
        }
    }

    fn begin(&mut self, request: Begin) -> Result<Value, String> {
        let world = self
            .worlds
            .get(&request.context)
            .ok_or("authority begin names an unregistered context")?;
        let observers: BTreeSet<_> = request.observers.iter().cloned().collect();
        if observers.is_empty()
            || observers.len() != request.observers.len()
            || observers.len() > MAX_OBSERVERS
            || observers.iter().any(|observer| {
                !self.allowed.contains_key(observer)
                    || self
                        .begun
                        .contains(&(observer.clone(), request.context.clone()))
            })
            || request
                .training_inputs
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
                != observers
        {
            return Err("authority begin must predeclare unique authorized observers and their unchanged context task sets".into());
        }
        let main =
            u16::try_from(world.schema.nodes - 1).map_err(|_| "authority main query overflow")?;
        let mut staged = Vec::new();
        for observer in observers {
            let inputs = request
                .training_inputs
                .get(&observer)
                .ok_or("training set missing")?;
            let training: BTreeSet<_> = inputs.iter().copied().collect();
            if training.len() != inputs.len()
                || training.is_empty()
                || training.len() > 28
                || !training.contains(&main)
                || training.iter().any(|input| {
                    decode_query(world.schema.nodes, *input).is_err()
                        || !world.truth.costs.contains_key(input)
                })
            {
                return Err("authority training tasks must be bounded unique public reachable pairs including the main route".into());
            }
            staged.push((
                observer,
                Active {
                    context: request.context.clone(),
                    training,
                },
            ));
        }
        for (observer, active) in staged {
            self.begun
                .insert((observer.clone(), request.context.clone()));
            self.active.insert(observer, active);
        }
        Ok(json!({"configured":true,"context":request.context,"observers":request.observers.len()}))
    }

    fn active_world(&self, peer: &str, context: &str) -> Result<&World, String> {
        if self
            .active
            .get(peer)
            .is_none_or(|active| active.context != context)
        {
            return Err("authority context is not the observer's currently pinned context".into());
        }
        self.worlds
            .get(context)
            .ok_or_else(|| "authority context missing".into())
    }

    fn observe(&mut self, peer: &str, request: Observe) -> Result<Value, String> {
        let world = self.active_world(peer, &request.context)?;
        let cost = *world
            .weights
            .get(request.edge_id)
            .ok_or("observation edge outside the declared topology")?;
        if self.issued.len() >= MAX_ISSUED
            || self
                .observed
                .contains(&(peer.into(), request.context.clone(), request.edge_id))
        {
            return Err("authority repeated observation or issued-evidence budget rejected".into());
        }
        let mut receipt = Receipt {
            schema: "symbiote.graph-observation/1".into(),
            authority_id: self.epoch.clone(),
            context: request.context.clone(),
            schema_fingerprint: world.fingerprint.clone(),
            observer_identity: peer.into(),
            sequence: FIRST_SEQUENCE
                + u64::try_from(self.issued.len()).map_err(|_| "authority sequence overflow")?,
            id: String::new(),
            edge_id: request.edge_id,
            cost,
        };
        let mut body = receipt.value()?;
        body.as_object_mut()
            .ok_or("receipt encoding failed")?
            .remove("id");
        receipt.id = sha(&body)?;
        let value = receipt.value()?;
        self.observed
            .insert((peer.into(), request.context, request.edge_id));
        self.issued.insert(receipt.id.clone(), receipt);
        Ok(value)
    }

    fn authentic(&self, receipt: &Receipt) -> bool {
        receipt.authority_id == self.epoch && self.issued.get(&receipt.id) == Some(receipt)
    }
    fn verify(&mut self, peer: &str, request: Verify) -> Result<Verification, String> {
        request.receipt.value()?;
        let authentic = self.authentic(&request.receipt);
        let key = (
            peer.into(),
            request.context.clone(),
            request.receipt.id.clone(),
        );
        let repeated = self.evaluated_receipts.contains(&key);
        let applicable = authentic
            && !repeated
            && self
                .allowed
                .get(peer)
                .is_some_and(|allowed| allowed.contains(&request.observer_identity))
            && self
                .active_world(peer, &request.context)
                .is_ok_and(|world| {
                    request.schema_fingerprint == world.fingerprint
                        && request
                            .receipt
                            .applicable(
                                &request.context,
                                &world.schema,
                                &request.observer_identity,
                                request.edge_id,
                            )
                            .is_ok()
                });
        if self.evaluated_receipts.len() >= MAX_ISSUED {
            return Err("authority receipt verification history budget exhausted".into());
        }
        self.evaluated_receipts.insert(key);
        Ok(Verification {authentic,applicable,receipt_sha256:request.receipt.digest()?,reason:if applicable {"registered receipt matches current authorized source/schema/context/frontier"} else if repeated {"receipt already evaluated for this receiver/context"} else {"receipt is unauthenticated or inapplicable to this exact receiver/context/schema/source/frontier"}.into()})
    }

    fn route(world: &World, query: &QueryRoute) -> Result<RouteResult, String> {
        let (start, goal) = decode_query(world.schema.nodes, query.input)?;
        if query.route.is_null() {
            return Ok(RouteResult {
                input: query.input,
                certified: false,
                correct: false,
                abstained: true,
            });
        }
        let claim: RouteClaim = decode(query.route.clone())?;
        let mut correct = claim.nodes.len() == claim.edges.len() + 1
            && claim.nodes.len() <= world.schema.nodes
            && claim.nodes.first() == Some(&start)
            && claim.nodes.last() == Some(&goal)
            && claim.nodes.iter().copied().collect::<BTreeSet<_>>().len() == claim.nodes.len()
            && claim.conditional
            && claim.family == GRAPH_FAMILY
            && claim.cost_basis == "observed_edge_costs";
        let mut cost = 0_u64;
        for (position, id) in claim.edges.iter().enumerate() {
            let Some(edge) = world.schema.edges.get(*id) else {
                correct = false;
                break;
            };
            if claim.nodes.get(position) != Some(&edge.from)
                || claim.nodes.get(position + 1) != Some(&edge.to)
            {
                correct = false;
            }
            cost = cost
                .checked_add(u64::from(world.weights[*id]))
                .ok_or("route cost overflow")?;
        }
        correct &= cost == claim.cost && world.truth.costs.get(&query.input) == Some(&claim.cost);
        Ok(RouteResult {
            input: query.input,
            certified: true,
            correct,
            abstained: false,
        })
    }

    fn judge(&self, request: Judge) -> Result<Value, String> {
        let world = self
            .worlds
            .get(&request.context)
            .ok_or("judge context is not registered")?;
        if request.routes.is_empty() || request.routes.len() > 8 {
            return Err("judge page requires1..8 route claims".into());
        }
        let mut inputs = BTreeSet::new();
        let mut results = Vec::new();
        for query in &request.routes {
            if !inputs.insert(query.input) {
                return Err("judge page duplicates a route task".into());
            }
            results.push(Self::route(world, query)?);
        }
        let request_sha256 = sha(
            &json!({"context":request.context,"routes":request.routes.iter().map(|query| json!({"input":query.input,"route":query.route})).collect::<Vec<_>>()}),
        )?;
        let mut response = json!({"schema":"symbiote.authority-judge/1","authority_id":self.epoch,"context":request.context,"request_sha256":request_sha256,"results":results});
        let receipt_sha256 = sha(&response)?;
        response["receipt_sha256"] = json!(receipt_sha256);
        Ok(response)
    }

    fn assess(&mut self, peer: &str, request: Assess) -> Result<Value, String> {
        match request {
            Assess::Begin {
                context,
                record,
                receipt_ids,
            } => self.assess_begin(peer, context, record, receipt_ids),
            Assess::Routes { job_id, routes } => self.assess_routes(peer, &job_id, routes),
            Assess::Finish { job_id } => self.assess_finish(peer, &job_id),
        }
    }
    fn assess_begin(
        &mut self,
        peer: &str,
        context: String,
        record: KnowledgeRecord,
        receipt_ids: Vec<String>,
    ) -> Result<Value, String> {
        let world = self.active_world(peer, &context)?;
        record.validate()?;
        let KnowledgePayload::GraphMap(map) = record.typed_payload()? else {
            return Err("authority graph assessment requires graph-map knowledge".into());
        };
        if record.source != peer
            || record.scope != context
            || record.schema_fingerprint != world.fingerprint
            || map.schema != world.schema
            || self
                .assessment_contexts
                .contains(&(peer.into(), context.clone()))
            || self.jobs.len() >= MAX_JOBS
            || receipt_ids.len() != map.observations.len()
            || receipt_ids.len() > 28
        {
            return Err("assessment must bind one owner/context/schema and unique bounded current-context job".into());
        }
        let mut observations = BTreeMap::new();
        let mut ids = BTreeSet::new();
        for id in receipt_ids {
            let receipt = self
                .issued
                .get(&id)
                .ok_or("assessment receipt was not issued by this authority epoch")?;
            if !ids.insert(id)
                || !self.authentic(receipt)
                || !self
                    .allowed
                    .get(peer)
                    .is_some_and(|allowed| allowed.contains(&receipt.observer_identity))
                || receipt.context != context
                || receipt.schema_fingerprint != world.fingerprint
                || observations.insert(receipt.edge_id, receipt.cost).is_some()
            {
                return Err(
                    "assessment receipt provenance, exact applicability or uniqueness rejected"
                        .into(),
                );
            }
        }
        if observations
            != map
                .observations
                .iter()
                .map(|observation| (observation.edge_id, observation.cost))
                .collect()
        {
            return Err("assessment map differs from its genuine registered observations".into());
        }
        let training = &self
            .active
            .get(peer)
            .ok_or("assessment active tasks missing")?
            .training;
        let required = world
            .truth
            .costs
            .keys()
            .filter(|input| !training.contains(input))
            .copied()
            .collect::<BTreeSet<_>>();
        if required.is_empty() {
            return Err("assessment cannot promote without held-out route tasks".into());
        }
        let record_digest = record.digest()?;
        let taskset_digest = sha(&json!(required))?;
        let job_id = fresh_capability()?;
        let response = json!({"job_id":job_id,"record_digest":record_digest,"taskset_digest":taskset_digest,"required":required.len()});
        self.assessment_contexts
            .insert((peer.into(), context.clone()));
        self.jobs.insert(
            job_id,
            Job {
                observer: peer.into(),
                context,
                record,
                record_digest,
                required,
                taskset_digest,
                results: BTreeMap::new(),
                completed: false,
            },
        );
        Ok(response)
    }
    fn assess_routes(
        &mut self,
        peer: &str,
        job_id: &str,
        routes: Vec<QueryRoute>,
    ) -> Result<Value, String> {
        let job = self.jobs.get(job_id).ok_or("assessment job is unknown")?;
        if job.observer != peer || job.completed || routes.is_empty() || routes.len() > 8 {
            return Err("assessment route page must bind its owner and1..8 pending claims".into());
        }
        let world = self.active_world(peer, &job.context)?;
        let mut staged = BTreeMap::new();
        for query in routes {
            if !job.required.contains(&query.input)
                || job.results.contains_key(&query.input)
                || staged.contains_key(&query.input)
            {
                return Err(
                    "assessment page repeats or substitutes a predeclared held-out route".into(),
                );
            }
            let mut result = Self::route(world, &query)?;
            if result.correct {
                let claim: RouteClaim = decode(query.route)?;
                result.correct = u8::try_from(claim.cost).ok().is_some_and(|cost| {
                    job.record.predict_if_certified(query.input).ok() == Some(Some(cost))
                });
            }
            staged.insert(query.input, result);
        }
        let job = self
            .jobs
            .get_mut(job_id)
            .ok_or("assessment job disappeared")?;
        job.results.extend(staged);
        Ok(
            json!({"job_id":job_id,"accepted":true,"received":job.results.len(),"required":job.required.len()}),
        )
    }
    fn assess_finish(&mut self, peer: &str, job_id: &str) -> Result<Value, String> {
        let job = self.jobs.get(job_id).ok_or("assessment job is unknown")?;
        self.active_world(peer, &job.context)?;
        if job.observer != peer || job.completed {
            return Err("assessment finish is not an owned pending job".into());
        }
        let pass = job.results.len() == job.required.len()
            && job
                .results
                .values()
                .all(|result| result.correct && !result.abstained);
        let mut response = json!({"schema":"symbiote.authority-assessment/1","authority_id":self.epoch,"observer_identity":peer,"context":job.context,"job_id":job_id,"pass":pass,"record_digest":job.record_digest,"taskset_digest":job.taskset_digest,"checked":job.results.len(),"required":job.required.len(),"abstentions":job.results.values().filter(|result| result.abstained).count(),"incorrect_certificates":job.results.values().filter(|result| result.certified && !result.correct).count()});
        response["receipt_sha256"] = json!(sha(&response)?);
        self.jobs
            .get_mut(job_id)
            .ok_or("assessment job disappeared")?
            .completed = true;
        Ok(response)
    }
}

pub(super) fn create(bootstrap: Bootstrap, owner: Arc<Store>) -> Result<Running, String> {
    let server_config = bootstrap
        .server(SCOPE)?
        .with_operation_frame_limits(BTreeMap::from([
            ("observe".into(), 4096),
            ("verify".into(), 4096),
        ]))?;
    let state = Arc::new(Mutex::new(Authority::new(bootstrap, owner)?));
    let handler = Arc::clone(&state);
    let server =
        spawn_secure_server_metered(server_config, 1024, move |session, operation, payload| {
            handler
                .lock()
                .map_err(|_| "authority state poisoned")?
                .handle(session, operation, payload)
        })?;
    state
        .lock()
        .map_err(|_| "authority state poisoned")?
        .traffic = Some(server.traffic());
    Ok(Running {
        server,
        world_deadline: Arc::new(Mutex::new(None)),
    })
}

#[cfg(test)]
mod tests {
    use super::super::wire::{AuthorityWorld, Grant, LabCa, PublicEndpoint};
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use symbiote_memory::knowledge::graph::{GraphMap, GraphObservation};
    use symbiote_protocol::{SecureClient, TlsClientConfig};
    use symbiote_reasoning::planning::Edge;

    struct Fixture {
        directory: PathBuf,
        owner: Arc<Store>,
        bootstrap: Option<Bootstrap>,
        controller: String,
        observers: Vec<String>,
        clients: BTreeMap<String, TlsClientConfig>,
    }
    impl Fixture {
        fn new() -> Self {
            let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "symbiote-authority-development-{}",
                fresh_capability().unwrap()
            ));
            fs::create_dir(&directory).unwrap();
            let owner = Arc::new(Store::open(&directory.join("authority")).unwrap());
            let controller = Store::open(&directory.join("controller"))
                .unwrap()
                .identity()
                .to_string();
            let observers = (0..3)
                .map(|index| {
                    Store::open(&directory.join(format!("observer-{index}")))
                        .unwrap()
                        .identity()
                        .to_string()
                })
                .collect::<Vec<_>>();
            let ca = LabCa::new().unwrap();
            let material = ca.leaf().unwrap();
            let mut grants = Vec::new();
            let mut clients = BTreeMap::new();
            for identity in std::iter::once(&controller).chain(observers.iter()) {
                let leaf = ca.leaf().unwrap();
                clients.insert(
                    identity.clone(),
                    TlsClientConfig::new(
                        identity.clone(),
                        leaf.identity().unwrap(),
                        ca.pem.as_bytes(),
                    )
                    .unwrap(),
                );
                grants.push(Grant {
                    identity: identity.clone(),
                    pin: leaf.pin,
                    scope: SCOPE.into(),
                    operations: if identity == &controller {
                        vec!["begin", "judge", "audit", "calibrate"]
                    } else {
                        vec!["observe", "verify", "assess"]
                    }
                    .into_iter()
                    .map(String::from)
                    .collect(),
                });
            }
            let allowed_observers = BTreeMap::from([
                (
                    observers[0].clone(),
                    vec![observers[0].clone(), observers[1].clone()],
                ),
                (
                    observers[1].clone(),
                    vec![observers[1].clone(), observers[0].clone()],
                ),
                (observers[2].clone(), vec![observers[2].clone()]),
            ]);
            let bootstrap = Bootstrap {
                state: directory.join("authority"),
                expected_identity: owner.identity().into(),
                controller_identity: controller.clone(),
                material,
                ca_pem: ca.pem,
                grants,
                role: Role::Authority {
                    worlds: vec![
                        AuthorityWorld {
                            context: "development-current".into(),
                            schema: diamond(),
                            costs: vec![1, 1, 3, 3],
                        },
                        AuthorityWorld {
                            context: "development-prelude".into(),
                            schema: diamond(),
                            costs: vec![3, 3, 1, 1],
                        },
                    ],
                    allowed_observers,
                },
                protocol_sha256: "e".repeat(64),
            };
            Self {
                directory,
                owner,
                bootstrap: Some(bootstrap),
                controller,
                observers,
                clients,
            }
        }
        fn state(&mut self) -> Authority {
            Authority::new(self.bootstrap.take().unwrap(), Arc::clone(&self.owner)).unwrap()
        }
        fn session(&self, peer: &str) -> SecureSession {
            SecureSession {
                peer_id: peer.into(),
                certificate_sha256: "0".repeat(64),
                scope: SCOPE.into(),
                operations: vec!["observe".into(), "verify".into(), "assess".into()],
                traffic: SecureTraffic::default(),
            }
        }
        fn call(
            &self,
            state: &mut Authority,
            peer: &str,
            operation: &str,
            payload: Value,
        ) -> Result<Value, String> {
            state.handle(&self.session(peer), operation, payload)
        }
        fn begin_value(&self, context: &str) -> Value {
            json!({"context":context,"observers":self.observers,"training_inputs":self.observers.iter().map(|observer| (observer.clone(),vec![3_u16,1_u16])).collect::<BTreeMap<_,_>>()})
        }
        fn begin(&self, state: &mut Authority, context: &str) {
            self.call(state, &self.controller, "begin", self.begin_value(context))
                .unwrap();
        }
        fn observe(
            &self,
            state: &mut Authority,
            observer: &str,
            context: &str,
            edge: usize,
        ) -> Receipt {
            serde_json::from_value(
                self.call(
                    state,
                    observer,
                    "observe",
                    json!({"context":context,"edge_id":edge}),
                )
                .unwrap(),
            )
            .unwrap()
        }
        fn verify(
            &self,
            state: &mut Authority,
            receiver: &str,
            receipt: &Receipt,
            context: &str,
            source: &str,
        ) -> Verification {
            serde_json::from_value(self.call(state,receiver,"verify",json!({"receipt":receipt,"context":context,"schema_fingerprint":graph_schema_fingerprint(&diamond()).unwrap(),"observer_identity":source,"edge_id":receipt.edge_id})).unwrap()).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let (Ok(path), Ok(root)) = (
                self.directory.canonicalize(),
                std::env::temp_dir().canonicalize(),
            ) {
                if path.parent() == Some(root.as_path())
                    && path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("symbiote-authority-development-"))
                {
                    let _ = fs::remove_dir_all(path);
                }
            }
        }
    }
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
    fn full_record(fixture: &Fixture, state: &mut Authority) -> (KnowledgeRecord, Vec<Receipt>) {
        let receipts = (0..4)
            .map(|edge| fixture.observe(state, &fixture.observers[0], "development-current", edge))
            .collect::<Vec<_>>();
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
        let record = KnowledgeRecord {
            id: "development-owned-model".into(),
            revision: 1,
            source: fixture.observers[0].clone(),
            scope: "development-current".into(),
            schema_fingerprint: graph_schema_fingerprint(&diamond()).unwrap(),
            payload: map.to_payload().unwrap(),
            provenance: "Manual released-domain development fixture; no prospective cohort".into(),
        };
        (record, receipts)
    }

    #[test]
    fn registry_distinguishes_genuine_stale_altered_wrong_group_and_repeated_receipts() {
        let mut fixture = Fixture::new();
        let mut state = fixture.state();
        fixture.begin(&mut state, "development-prelude");
        let stale = fixture.observe(&mut state, &fixture.observers[1], "development-prelude", 1);
        let calibration = fixture
            .call(
                &mut state,
                &fixture.controller,
                "calibrate",
                json!({"receipt":stale}),
            )
            .unwrap();
        assert_eq!(calibration["authentic"], true);
        assert_eq!(calibration["applicable"], true);
        fixture.begin(&mut state, "development-current");
        let verified = fixture.verify(
            &mut state,
            &fixture.observers[0],
            &stale,
            "development-current",
            &fixture.observers[1],
        );
        assert!(verified.authentic);
        assert!(!verified.applicable);
        let current = fixture.observe(&mut state, &fixture.observers[1], "development-current", 1);
        let verified = fixture.verify(
            &mut state,
            &fixture.observers[0],
            &current,
            "development-current",
            &fixture.observers[1],
        );
        assert!(verified.authentic && verified.applicable);
        let repeated = fixture.verify(
            &mut state,
            &fixture.observers[0],
            &current,
            "development-current",
            &fixture.observers[1],
        );
        assert!(repeated.authentic && !repeated.applicable);
        let outsider = fixture.observe(&mut state, &fixture.observers[2], "development-current", 2);
        let denied = fixture.verify(
            &mut state,
            &fixture.observers[0],
            &outsider,
            "development-current",
            &fixture.observers[2],
        );
        assert!(denied.authentic && !denied.applicable);
        let mut altered = current.clone();
        altered.cost = 2;
        assert!(
            !fixture
                .verify(
                    &mut state,
                    &fixture.observers[0],
                    &altered,
                    "development-current",
                    &fixture.observers[1]
                )
                .authentic
        );
        let mut old_epoch = current;
        old_epoch.authority_id = "0".repeat(64);
        assert!(
            !fixture
                .verify(
                    &mut state,
                    &fixture.observers[0],
                    &old_epoch,
                    "development-current",
                    &fixture.observers[1]
                )
                .authentic
        );
        assert!(fixture
            .call(
                &mut state,
                &fixture.observers[0],
                "observe",
                json!({"context":"development-prelude","edge_id":0})
            )
            .is_err());
        assert!(fixture
            .call(
                &mut state,
                &fixture.controller,
                "begin",
                fixture.begin_value("development-current")
            )
            .is_err());
    }

    #[test]
    fn assessment_requires_every_predeclared_holdout_and_returns_no_hidden_labels() {
        let mut fixture = Fixture::new();
        let mut state = fixture.state();
        fixture.begin(&mut state, "development-current");
        let (record, receipts) = full_record(&fixture, &mut state);
        let begun = fixture.call(&mut state,&fixture.observers[0],"assess",json!({"stage":"begin","context":"development-current","record":record,"receipt_ids":receipts.iter().map(|receipt| receipt.id.clone()).collect::<Vec<_>>()})).unwrap();
        assert_eq!(begun["required"], 3);
        let job = begun["job_id"].as_str().unwrap();
        let routes = [2_u16,7,11].into_iter().map(|input| json!({"input":input,"route":record.graph_forecast(input).unwrap().unwrap()})).collect::<Vec<_>>();
        assert!(fixture
            .call(
                &mut state,
                &fixture.observers[2],
                "assess",
                json!({"stage":"finish","job_id":job})
            )
            .is_err());
        fixture
            .call(
                &mut state,
                &fixture.observers[0],
                "assess",
                json!({"stage":"routes","job_id":job,"routes":routes}),
            )
            .unwrap();
        assert!(fixture
            .call(
                &mut state,
                &fixture.observers[0],
                "assess",
                json!({"stage":"routes","job_id":job,"routes":[{"input":2,"route":null}]})
            )
            .is_err());
        let result = fixture
            .call(
                &mut state,
                &fixture.observers[0],
                "assess",
                json!({"stage":"finish","job_id":job}),
            )
            .unwrap();
        assert_eq!(result["pass"], true);
        assert_eq!(result["checked"], 3);
        assert_eq!(result["record_digest"], record.digest().unwrap());
        assert!(result.get("expected").is_none());
        assert!(result.get("costs").is_none());
        assert!(result.get("weights").is_none());
        assert!(fixture
            .call(
                &mut state,
                &fixture.observers[0],
                "assess",
                json!({"stage":"finish","job_id":job})
            )
            .is_err());
        assert!(fixture.call(&mut state,&fixture.observers[0],"assess",json!({"stage":"begin","context":"development-current","record":record,"receipt_ids":receipts.iter().map(|receipt| receipt.id.clone()).collect::<Vec<_>>()})).is_err());
    }

    #[test]
    fn missing_or_abstaining_holdouts_withhold_and_invalid_claims_never_issue_certification() {
        for abstain in [false, true] {
            let mut fixture = Fixture::new();
            let mut state = fixture.state();
            fixture.begin(&mut state, "development-current");
            let (record, receipts) = full_record(&fixture, &mut state);
            let begin = fixture.call(&mut state,&fixture.observers[0],"assess",json!({"stage":"begin","context":"development-current","record":record,"receipt_ids":receipts.iter().map(|receipt| receipt.id.clone()).collect::<Vec<_>>()})).unwrap();
            let job = begin["job_id"].as_str().unwrap();
            let mut route =
                serde_json::to_value(record.graph_forecast(2).unwrap().unwrap()).unwrap();
            if abstain {
                route = Value::Null;
            } else {
                route["cost"] = json!(7);
            }
            fixture
                .call(
                    &mut state,
                    &fixture.observers[0],
                    "assess",
                    json!({"stage":"routes","job_id":job,"routes":[{"input":2,"route":route}]}),
                )
                .unwrap();
            let result = fixture
                .call(
                    &mut state,
                    &fixture.observers[0],
                    "assess",
                    json!({"stage":"finish","job_id":job}),
                )
                .unwrap();
            assert_eq!(result["pass"], false);
            assert_eq!(result["checked"], 1);
            assert_eq!(result["required"], 3);
            if abstain {
                assert_eq!(result["abstentions"], 1);
            } else {
                assert_eq!(result["incorrect_certificates"], 1);
            }
        }
    }

    #[test]
    fn invalid_requests_consume_actor_budget_without_observations_or_identity_spoofing() {
        let mut fixture = Fixture::new();
        let mut state = fixture.state();
        for _ in 0..ACTOR_OPERATION_REQUESTS {
            assert!(fixture.call(&mut state,&fixture.observers[0],"observe",json!({"context":"unregistered","edge_id":0,"observer_identity":fixture.observers[1]})).is_err());
        }
        assert!(fixture
            .call(
                &mut state,
                &fixture.observers[0],
                "observe",
                json!({"context":"development-current","edge_id":0})
            )
            .unwrap_err()
            .contains("budget"));
        let counters = &state.counters[&fixture.observers[0]];
        assert_eq!(counters.observe, ACTOR_OPERATION_REQUESTS + 1);
        assert_eq!(counters.invalid, ACTOR_OPERATION_REQUESTS + 1);
        assert!(state.issued.is_empty());
        assert!(fixture
            .call(
                &mut state,
                &fixture.observers[1],
                "judge",
                json!({"context":"development-current","routes":[]})
            )
            .is_err());
    }

    #[test]
    fn real_tls_uses_authenticated_observer_and_strict_operation_frame_caps() {
        let mut fixture = Fixture::new();
        let mut running = create(
            fixture.bootstrap.take().unwrap(),
            Arc::clone(&fixture.owner),
        )
        .unwrap();
        let endpoint = PublicEndpoint {
            identity: running.server.server_id().into(),
            address: running.server.address(),
            pin: running.server.certificate_sha256().into(),
            scope: SCOPE.into(),
        };
        let call = |identity: &str, operation: &str, payload: &Value| -> Result<Value, String> {
            let mut client = SecureClient::connect_with_metering(
                &endpoint.endpoint(operation, 16_384)?,
                &fixture.clients[identity],
                SecureTraffic::default(),
                1024,
            )?;
            if operation == "observe" || operation == "verify" {
                assert_eq!(client.agreement().max_frame_bytes, 4096);
            }
            let result = client.call(operation, payload);
            let _ = client.cancel();
            result
        };
        call(
            &fixture.controller,
            "begin",
            &fixture.begin_value("development-current"),
        )
        .unwrap();
        assert!(call(&fixture.observers[0],"observe",&json!({"context":"development-current","edge_id":0,"observer_identity":fixture.observers[1]})).is_err());
        let receipt = call(
            &fixture.observers[0],
            "observe",
            &json!({"context":"development-current","edge_id":0}),
        )
        .unwrap();
        assert_eq!(receipt["observer_identity"], fixture.observers[0]);
        assert_eq!(receipt["cost"], 1);
        assert!(call(
            &fixture.observers[0],
            "judge",
            &json!({"context":"development-current","routes":[]})
        )
        .is_err());
        let audit = call(&fixture.controller, "audit", &json!({})).unwrap();
        assert_eq!(audit["per_actor"][&fixture.observers[0]]["observe"], 2);
        assert_eq!(audit["per_actor"][&fixture.observers[0]]["invalid"], 1);
        assert_eq!(audit["expected_labels_returned_to_learners"], 0);
        assert!(audit.get("weights").is_none());
        assert!(audit.get("costs").is_none());
        running.server.shutdown().unwrap();
    }
}
