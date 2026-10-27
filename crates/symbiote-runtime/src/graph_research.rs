//! Predeclared finite graph experiment. The two learners use real authorized
//! loopback endpoints in this process; this is not a process-isolation claim.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use symbiote_memory::knowledge::graph::{
    assess_graph, encode_query, graph_receipt_digest, graph_schema_fingerprint, GraphAcquisition,
    GraphMap, GraphObservation, GraphTrainingTask, GraphTrialEvidence,
};
use symbiote_memory::knowledge::{KnowledgeRecord, KnowledgeStore, TrialCase, TrialCosts};
use symbiote_memory::{maintenance, Store};
use symbiote_protocol::{fresh_capability, spawn_scoped_server, Client, Endpoint, ServerConfig};
use symbiote_reasoning::planning::{Edge, GraphSchema, Route, RouteLearner, GRAPH_FAMILY};

const SCOPE: &str = "finite-graph-routing/v1";
const CONTROLLER: &str = "graph-laboratory";
const IDS: [&str; 2] = ["graph-dijkstra", "graph-paths"];
const HOLDOUT: [(usize, usize); 2] = [(1, 3), (2, 3)];
const OPS: &[&str] = &[
    "reset",
    "advertise",
    "warmup",
    "advance",
    "bundle",
    "adopt",
    "forecast",
    "export",
    "stats",
];
const WORK_LIMIT: usize = 10_000;

fn schema() -> GraphSchema {
    GraphSchema {
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
    }
}
fn opaque_label(label: &str) -> bool {
    label.strip_prefix("graph-context-").is_some_and(|suffix| {
        suffix.len() == 64
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Contexts {
    schema: String,
    controller_identity: String,
    schema_fingerprint: String,
    contexts: Vec<String>,
}
impl Contexts {
    fn new(controller: &str) -> Result<Self, String> {
        let contexts = (0..81)
            .map(|_| fresh_capability().map(|id| format!("graph-context-{id}")))
            .collect::<Result<Vec<_>, _>>()?;
        let result = Self {
            schema: "symbiote.graph-contexts/1".into(),
            controller_identity: controller.into(),
            schema_fingerprint: graph_schema_fingerprint(&schema())?,
            contexts,
        };
        result.validate(controller)?;
        Ok(result)
    }
    fn validate(&self, controller: &str) -> Result<(), String> {
        if self.schema != "symbiote.graph-contexts/1"
            || self.controller_identity != controller
            || self.schema_fingerprint != graph_schema_fingerprint(&schema())?
            || self.contexts.len() != 81
            || self.contexts.iter().any(|label| !opaque_label(label))
            || self.contexts.iter().collect::<BTreeSet<_>>().len() != 81
        {
            return Err(
                "graph context manifest is invalid, changed-owner or incompatible with this schema"
                    .into(),
            );
        }
        Ok(())
    }
    fn read(path: &Path, controller: &str) -> Result<Self, String> {
        let mut bytes = Vec::new();
        fs::File::open(path)
            .map_err(|e| e.to_string())?
            .take(16_385)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 16_384 {
            return Err("graph context manifest exceeds its size budget".into());
        }
        let result: Self =
            serde_json::from_slice(&bytes).map_err(|_| "graph context manifest is malformed")?;
        result.validate(controller)?;
        Ok(result)
    }
    fn open(path: &Path, controller: &str) -> Result<Self, String> {
        if path.exists() {
            return Self::read(path, controller);
        }
        let parent = path.parent().ok_or("graph manifest parent missing")?;
        if [
            parent.join("dijkstra/knowledge.jsonl"),
            parent.join("paths/knowledge.jsonl"),
        ]
        .iter()
        .any(|path| path.exists())
        {
            return Err("graph context manifest missing beside existing knowledge; refusing to regenerate labels".into());
        }
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let contexts = Self::new(controller)?;
        let bytes = serde_json::to_vec(&contexts).map_err(|e| e.to_string())?;
        let temporary = parent.join(format!("contexts-{}.pending", fresh_capability()?));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        drop(file);
        // The controller's Store writer lock excludes competing experiment writers.
        // A hard-link publishes the fully flushed file without replacing an existing manifest.
        fs::hard_link(&temporary, path).map_err(|e| e.to_string())?;
        fs::remove_file(&temporary).map_err(|e| e.to_string())?;
        Ok(contexts)
    }
    fn label(&self, world: usize) -> &str {
        &self.contexts[world]
    }
    fn world(&self, label: &str) -> Result<usize, String> {
        self.contexts
            .iter()
            .position(|known| known == label)
            .ok_or_else(|| "unknown opaque graph context; retained mapping changed".into())
    }
}
fn weights(mut id: usize) -> [u16; 4] {
    let mut result = [0; 4];
    for cost in &mut result {
        *cost = (id % 3 + 1) as u16;
        id /= 3;
    }
    result
}
fn bytes(value: &Value) -> Result<u64, String> {
    u64::try_from(serde_json::to_vec(value).map_err(|e| e.to_string())?.len())
        .map_err(|_| "JSON size overflow".into())
}
fn kib(count: u64) -> u64 {
    count.div_ceil(1024)
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Meter {
    acquisitions: u64,
    endpoint_requests: u64,
    oracle_requests: u64,
    sessions: u64,
    sent_bytes: u64,
    received_bytes: u64,
    verified_receipts: u64,
    adopted_edges: u64,
    route_queries: u64,
    model_work: u64,
    exported_bytes: u64,
}
impl Meter {
    fn check(&self) -> Result<(), String> {
        if self.acquisitions > 4
            || self.endpoint_requests > 32
            || self.oracle_requests > 16
            || self.model_work > WORK_LIMIT as u64
            || self.sent_bytes > 65_536
            || self.received_bytes > 65_536
        {
            return Err("predeclared graph participant budget exhausted".into());
        }
        Ok(())
    }
    fn total(&self, acquisition_price: u64) -> u64 {
        self.acquisitions * acquisition_price
            + self.endpoint_requests
            + self.oracle_requests
            + self.sessions * 2
            + kib(self.sent_bytes)
            + kib(self.received_bytes)
            + self.verified_receipts * 2
            + self.adopted_edges
            + self.route_queries
            + self.model_work
            + kib(self.exported_bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    authority_id: String,
    context: String,
    schema_fingerprint: String,
    observer_identity: String,
    sequence: u64,
    id: String,
    edge_id: usize,
    cost: u16,
}
impl Receipt {
    fn acquisition(&self) -> Result<GraphAcquisition, String> {
        let receipt = serde_json::to_value(self).map_err(|e| e.to_string())?;
        Ok(GraphAcquisition {
            id: self.id.clone(),
            edge_id: self.edge_id,
            cost: self.cost,
            receipt_sha256: graph_receipt_digest(&receipt)?,
            receipt,
        })
    }
}
struct Authority {
    contexts: Arc<Contexts>,
    epoch: String,
    sequence: u64,
    issued: BTreeMap<String, Receipt>,
}
impl Authority {
    fn new(contexts: Arc<Contexts>) -> Result<Self, String> {
        Ok(Self {
            epoch: fresh_capability()?,
            contexts,
            sequence: 0,
            issued: BTreeMap::new(),
        })
    }
    fn issue(&mut self, observer: &str, context: &str, edge: usize) -> Result<Receipt, String> {
        let world = self.contexts.world(context)?;
        let cost = *weights(world)
            .get(edge)
            .ok_or("edge outside pinned graph")?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("receipt sequence exhausted")?;
        let mut receipt = Receipt {
            schema: "symbiote.graph-observation/1".into(),
            authority_id: self.epoch.clone(),
            context: context.into(),
            schema_fingerprint: graph_schema_fingerprint(&schema())?,
            observer_identity: observer.into(),
            sequence: self.sequence,
            id: String::new(),
            edge_id: edge,
            cost,
        };
        receipt.id =
            graph_receipt_digest(&serde_json::to_value(&receipt).map_err(|e| e.to_string())?)?;
        self.issued.insert(receipt.id.clone(), receipt.clone());
        Ok(receipt)
    }
    fn verify(
        &self,
        receipts: &[Receipt],
        expected_context: &str,
        observers: &[&str],
    ) -> Result<(), String> {
        self.contexts.world(expected_context)?;
        if receipts.is_empty() || receipts.len() > 4 {
            return Err("bounded graph receipt bundle required".into());
        }
        let mut ids = BTreeSet::new();
        let mut edges = BTreeSet::new();
        for receipt in receipts {
            if receipt.schema != "symbiote.graph-observation/1"
                || receipt.authority_id != self.epoch
                || receipt.context != expected_context
                || receipt.schema_fingerprint != graph_schema_fingerprint(&schema())?
                || !observers.contains(&receipt.observer_identity.as_str())
                || !ids.insert(&receipt.id)
                || !edges.insert(receipt.edge_id)
                || self.issued.get(&receipt.id) != Some(receipt)
            {
                return Err("graph receipt is forged, repeated, wrong-source, cross-context or stale-authority".into());
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct OracleCounts {
    observe: AtomicU64,
    verify: AtomicU64,
}
impl OracleCounts {
    fn snapshot(&self) -> Value {
        json!({"observe":self.observe.load(Ordering::SeqCst),"verify":self.verify.load(Ordering::SeqCst)})
    }
}

/// An independently implemented Bellman-Ford judge. No optimistic learner or
/// durable model is used to obtain expected costs or validate actual paths.
fn judge(
    weights: &[u16; 4],
    start: usize,
    goal: usize,
    route: Option<&Route>,
) -> Result<u8, String> {
    let topology = schema();
    let mut distances = [u64::MAX / 2; 4];
    distances[start] = 0;
    for _ in 0..3 {
        for (edge, cost) in topology.edges.iter().zip(weights) {
            distances[edge.to] = distances[edge.to].min(distances[edge.from] + u64::from(*cost));
        }
    }
    if let Some(route) = route {
        if route.nodes.first() != Some(&start)
            || route.nodes.last() != Some(&goal)
            || route.nodes.len() != route.edges.len() + 1
            || route.edges.len() > 3
        {
            return Err("independent judge rejected malformed path".into());
        }
        let mut actual = 0_u64;
        for (step, id) in route.edges.iter().enumerate() {
            let edge = topology
                .edges
                .get(*id)
                .ok_or("route uses undeclared edge")?;
            if edge.from != route.nodes[step] || edge.to != route.nodes[step + 1] {
                return Err("route edges do not connect".into());
            }
            actual += u64::from(weights[*id]);
        }
        if actual != route.cost || actual != distances[goal] {
            return Err("independent judge rejected incorrect certified shortest route".into());
        }
    }
    u8::try_from(distances[goal]).map_err(|_| "no bounded reachable route".into())
}

/// Independent simple-path enumeration, including exact optimistic lower bounds.
/// Reverse topology iteration deliberately gives a different deterministic tie break.
struct Paths {
    observed: BTreeMap<usize, u16>,
    work: usize,
    contradicted: bool,
}
impl Paths {
    fn search(
        &mut self,
        start: usize,
        goal: usize,
    ) -> Result<(Option<Route>, Option<usize>), String> {
        if self.contradicted {
            return Err("stationary graph observations contradicted".into());
        }
        let topology = schema();
        let mut candidates = Vec::new();
        struct Search<'a> {
            topology: &'a GraphSchema,
            observed: &'a BTreeMap<usize, u16>,
            work: &'a mut usize,
            goal: usize,
            out: &'a mut Vec<Route>,
        }
        impl Search<'_> {
            fn visit(
                &mut self,
                node: usize,
                nodes: &mut Vec<usize>,
                edges: &mut Vec<usize>,
                cost: u64,
            ) -> Result<(), String> {
                if node == self.goal {
                    self.out.push(Route {
                        nodes: nodes.clone(),
                        edges: edges.clone(),
                        cost,
                        cost_basis: "optimistic_interval_lower_bounds",
                        family: GRAPH_FAMILY,
                        conditional: true,
                    });
                    return Ok(());
                }
                for id in (0..self.topology.edges.len()).rev() {
                    if *self.work >= WORK_LIMIT {
                        return Err("path-enumeration work budget exhausted".into());
                    }
                    *self.work += 1;
                    let edge = &self.topology.edges[id];
                    if edge.from != node || nodes.contains(&edge.to) {
                        continue;
                    }
                    nodes.push(edge.to);
                    edges.push(id);
                    self.visit(
                        edge.to,
                        nodes,
                        edges,
                        cost + u64::from(self.observed.get(&id).copied().unwrap_or(edge.lower)),
                    )?;
                    nodes.pop();
                    edges.pop();
                }
                Ok(())
            }
        }
        Search {
            topology: &topology,
            observed: &self.observed,
            work: &mut self.work,
            goal,
            out: &mut candidates,
        }
        .visit(start, &mut vec![start], &mut Vec::new(), 0)?;
        let Some(mut best) = candidates
            .into_iter()
            .min_by(|a, b| a.cost.cmp(&b.cost).then_with(|| b.edges.cmp(&a.edges)))
        else {
            return Ok((None, None));
        };
        let next = best
            .edges
            .iter()
            .find(|id| !self.observed.contains_key(id))
            .copied();
        if next.is_none() {
            best.cost_basis = "observed_edge_costs";
            return Ok((Some(best), None));
        }
        Ok((None, next))
    }
}
enum Learner {
    Dijkstra(RouteLearner),
    Paths(Paths),
}
impl Learner {
    fn new(index: usize) -> Result<Self, String> {
        if index == 0 {
            return Ok(Self::Dijkstra(RouteLearner::new(schema(), WORK_LIMIT)?));
        }
        Ok(Self::Paths(Paths {
            observed: BTreeMap::new(),
            work: 0,
            contradicted: false,
        }))
    }
    fn work(&self) -> usize {
        match self {
            Self::Dijkstra(learner) => learner.model_work(),
            Self::Paths(learner) => learner.work,
        }
    }
    fn observe(&mut self, id: usize, cost: u16) -> Result<(), String> {
        match self {
            Self::Dijkstra(learner) => learner.observe(id, cost),
            Self::Paths(learner) => {
                let edge = schema()
                    .edges
                    .get(id)
                    .cloned()
                    .ok_or("unknown graph edge")?;
                if learner.contradicted
                    || cost < edge.lower
                    || cost > edge.upper
                    || learner.observed.get(&id).is_some_and(|old| *old != cost)
                {
                    learner.contradicted = true;
                    return Err("stationary graph observation contradicted".into());
                }
                if !learner.observed.contains_key(&id) && learner.work >= WORK_LIMIT {
                    return Err("path observation work budget exhausted before update".into());
                }
                if learner.observed.insert(id, cost).is_none() {
                    learner.work += 1;
                }
                Ok(())
            }
        }
    }
    fn assess(
        &mut self,
        start: usize,
        goal: usize,
    ) -> Result<(Option<Route>, Option<usize>), String> {
        match self {
            Self::Dijkstra(learner) => {
                let assessment = learner.assess(start, goal)?;
                if assessment.status != "supported" {
                    return Err(format!("route model {}", assessment.status));
                }
                Ok((assessment.certified, assessment.next_observation))
            }
            Self::Paths(learner) => learner.search(start, goal),
        }
    }
}

struct Agent {
    index: usize,
    identity: String,
    peer_identity: String,
    oracle: Endpoint,
    context: String,
    learner: Learner,
    observations: BTreeMap<usize, Receipt>,
    meter: Meter,
}
impl Agent {
    fn oracle(&mut self, operation: &str, payload: &Value) -> Result<Value, String> {
        if self.meter.oracle_requests >= 16
            || bytes(payload)? > 65_536_u64.saturating_sub(self.meter.sent_bytes)
        {
            return Err("graph authority request budget exhausted before request".into());
        }
        self.meter.oracle_requests += 1;
        self.meter.sessions += 1;
        self.meter.sent_bytes += bytes(payload)?;
        let mut client =
            Client::connect_scoped(&self.oracle, IDS[self.index], &["observe", "verify"], SCOPE)?;
        let result = client.call(operation, payload);
        let revoked = client.revoke();
        let result = result?;
        revoked?;
        self.meter.received_bytes += bytes(&result)?;
        self.meter.check()?;
        Ok(result)
    }
    fn observe(&mut self, edge: usize) -> Result<(), String> {
        if self.observations.contains_key(&edge) {
            return Err("observation policy repeated a known edge".into());
        }
        if self.meter.acquisitions >= 4 {
            return Err("local graph observation budget exhausted".into());
        }
        let value = self.oracle("observe", &json!({"context":self.context,"edge_id":edge}))?;
        let receipt: Receipt = serde_json::from_value(value).map_err(|e| e.to_string())?;
        if receipt.context != self.context
            || receipt.schema_fingerprint != graph_schema_fingerprint(&schema())?
            || receipt.observer_identity != self.identity
            || receipt.edge_id != edge
        {
            return Err("oracle reply binding mismatch".into());
        }
        self.learner.observe(edge, receipt.cost)?;
        self.observations.insert(edge, receipt);
        self.meter.acquisitions += 1;
        Ok(())
    }
    fn assess(
        &mut self,
        start: usize,
        goal: usize,
    ) -> Result<(Option<Route>, Option<usize>), String> {
        self.meter.route_queries += 1;
        let result = self.learner.assess(start, goal)?;
        self.meter.model_work = self.learner.work() as u64;
        self.meter.check()?;
        Ok(result)
    }
    fn operation(&mut self, operation: &str, payload: Value) -> Result<Value, String> {
        if operation == "stats" {
            return Ok(json!(self.meter));
        }
        if operation == "reset" {
            let context = payload["context"].as_str().ok_or("context missing")?;
            if !opaque_label(context) {
                return Err("invalid opaque graph context".into());
            }
            self.context = context.into();
            self.learner = Learner::new(self.index)?;
            self.observations.clear();
            self.meter = Meter {
                sessions: 1,
                ..Meter::default()
            };
        }
        if self.meter.endpoint_requests >= 32
            || bytes(&payload)? > 65_536_u64.saturating_sub(self.meter.received_bytes)
        {
            return Err("graph participant request budget exhausted before operation".into());
        }
        self.meter.endpoint_requests += 1;
        self.meter.received_bytes += bytes(&payload)?;
        let result = self.dispatch(operation, payload)?;
        self.meter.sent_bytes += bytes(&result)?;
        self.meter.model_work = self.learner.work() as u64;
        self.meter.check()?;
        Ok(result)
    }
    fn dispatch(&mut self, operation: &str, payload: Value) -> Result<Value, String> {
        match operation {
            "reset" => Ok(json!({"fresh_model":true})),
            "advertise" => Ok(
                json!({"identity":self.identity,"schema_fingerprint":graph_schema_fingerprint(&schema())?,"task":[0,3],"frontier":if self.index==0{0}else{2},"exchange_eligible":true}),
            ),
            "warmup" => {
                let edge = if self.index == 0 { 0 } else { 2 };
                self.observe(edge)?;
                let goal = if self.index == 0 { 1 } else { 2 };
                let (route, _) = self.assess(0, goal)?;
                Ok(json!({"certified":route.is_some()}))
            }
            "advance" => {
                let (route, next) = self.assess(0, 3)?;
                if let Some(route) = route {
                    return Ok(json!({"complete":true,"route":route}));
                }
                let edge = next.ok_or("exact learner has no supported route frontier")?;
                self.observe(edge)?;
                Ok(json!({"complete":false}))
            }
            "bundle" => Ok(json!(self
                .observations
                .values()
                .cloned()
                .collect::<Vec<_>>())),
            "adopt" => {
                let receipts: Vec<Receipt> =
                    serde_json::from_value(payload).map_err(|e| e.to_string())?;
                if receipts.is_empty()
                    || receipts.len() > 4
                    || receipts
                        .iter()
                        .any(|r| r.observer_identity != self.peer_identity)
                {
                    return Err("exchange origin is not the authorized peer".into());
                }
                let verified = self.oracle(
                    "verify",
                    &json!({"context":self.context,"receipts":receipts,"peer_only":true}),
                )?;
                if verified["verified"] != true
                    || verified["digest"] != graph_receipt_digest(&json!(receipts))?
                {
                    return Err("independent graph receipt validation failed".into());
                }
                // Check all contradictions before making any persistent or model update.
                for receipt in &receipts {
                    if self
                        .observations
                        .get(&receipt.edge_id)
                        .is_some_and(|old| old.cost != receipt.cost)
                    {
                        return Err("received observation contradicts retained edge".into());
                    }
                }
                self.meter.verified_receipts += receipts.len() as u64;
                for receipt in receipts {
                    if !self.observations.contains_key(&receipt.edge_id) {
                        self.learner.observe(receipt.edge_id, receipt.cost)?;
                        self.observations.insert(receipt.edge_id, receipt);
                        self.meter.adopted_edges += 1;
                    }
                }
                Ok(json!({"adopted":true}))
            }
            "forecast" => {
                let start = payload["start"].as_u64().ok_or("start missing")? as usize;
                let goal = payload["goal"].as_u64().ok_or("goal missing")? as usize;
                encode_query(4, start, goal)?;
                let (route, _) = self.assess(start, goal)?;
                Ok(json!(route))
            }
            "export" => {
                let map = GraphMap::new(
                    schema(),
                    self.observations
                        .values()
                        .map(|r| GraphObservation {
                            edge_id: r.edge_id,
                            cost: r.cost,
                        })
                        .collect(),
                )?;
                let evidence = self
                    .observations
                    .values()
                    .map(Receipt::acquisition)
                    .collect::<Result<Vec<_>, _>>()?;
                let result = json!({"map":map,"acquisitions":evidence});
                self.meter.exported_bytes = bytes(&result)?;
                Ok(result)
            }
            _ => Err("unsupported graph operation".into()),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRoute {
    nodes: Vec<usize>,
    edges: Vec<usize>,
    cost: u64,
    cost_basis: String,
    family: String,
    conditional: bool,
}
fn route(value: &Value) -> Result<Option<Route>, String> {
    if value.is_null() {
        return Ok(None);
    }
    let wire: WireRoute = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    if wire.cost_basis != "observed_edge_costs" || wire.family != GRAPH_FAMILY || !wire.conditional
    {
        return Err("forecast does not carry a supported conditional certificate".into());
    }
    Ok(Some(Route {
        nodes: wire.nodes,
        edges: wire.edges,
        cost: wire.cost,
        cost_basis: "observed_edge_costs",
        family: GRAPH_FAMILY,
        conditional: true,
    }))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Export {
    map: GraphMap,
    acquisitions: Vec<GraphAcquisition>,
}
struct Arm {
    meters: [Meter; 2],
    forecasts: [Vec<Value>; 2],
    exports: [Export; 2],
    coverage: [usize; 2],
}
fn connect(endpoint: &Endpoint) -> Result<Client, String> {
    Client::connect_scoped(endpoint, CONTROLLER, OPS, SCOPE)
}

fn execute_arm(
    endpoints: &[Endpoint; 2],
    world_id: usize,
    context: &str,
    exchange: bool,
) -> Result<Arm, String> {
    let mut clients = [connect(&endpoints[0])?, connect(&endpoints[1])?];
    for client in &mut clients {
        client.call("reset", &json!({"context":context}))?;
    }
    if exchange {
        // The fixed advertisements precede all cost observation and contain no costs.
        let advertisements = [
            clients[0].call("advertise", &json!({}))?,
            clients[1].call("advertise", &json!({}))?,
        ];
        if advertisements[0]["frontier"] != 0
            || advertisements[1]["frontier"] != 2
            || advertisements
                .iter()
                .any(|a| a["exchange_eligible"] != true)
        {
            return Err("predeclared structural exchange opportunity is absent".into());
        }
    }
    for client in &mut clients {
        if client.call("warmup", &json!({}))?["certified"] != true {
            return Err("warmup was not certified".into());
        }
    }
    if exchange {
        let left = clients[0].call("bundle", &json!({}))?;
        let right = clients[1].call("bundle", &json!({}))?;
        clients[0].call("adopt", &right)?;
        clients[1].call("adopt", &left)?;
    }
    let mut forecasts = [Vec::new(), Vec::new()];
    let mut coverage = [0, 0];
    let mut exports = Vec::new();
    let mut meters = Vec::new();
    for (index, client) in clients.iter_mut().enumerate() {
        let mut complete = false;
        for _ in 0..=4 {
            let result = client.call("advance", &json!({}))?;
            if result["complete"] == true {
                let prediction = route(&result["route"])?;
                judge(&weights(world_id), 0, 3, prediction.as_ref())?;
                complete = true;
                break;
            }
        }
        if !complete {
            return Err("finite training policy exhausted its declared observation budget".into());
        }
        for (start, goal) in HOLDOUT {
            let value = client.call("forecast", &json!({"start":start,"goal":goal}))?;
            let prediction = route(&value)?;
            judge(&weights(world_id), start, goal, prediction.as_ref())?;
            coverage[index] += usize::from(prediction.is_some());
            forecasts[index].push(value);
        }
        exports.push(
            serde_json::from_value::<Export>(client.call("export", &json!({}))?)
                .map_err(|e| e.to_string())?,
        );
        meters.push(
            serde_json::from_value::<Meter>(client.call("stats", &json!({}))?)
                .map_err(|e| e.to_string())?,
        );
        client.revoke()?;
    }
    Ok(Arm {
        meters: meters.try_into().map_err(|_| "meter count")?,
        forecasts,
        exports: exports.try_into().map_err(|_| "export count")?,
        coverage,
    })
}

fn config(id: &str, client_id: &str, operations: &[&str]) -> Result<ServerConfig, String> {
    Ok(ServerConfig {
        id: id.into(),
        token: fresh_capability()?,
        client_id: client_id.into(),
        operations: operations.iter().map(|op| (*op).into()).collect(),
        max_requests: 10_000,
        max_frame_bytes: 65_536,
        timeout: Duration::from_secs(2),
    })
}

fn comparison(
    isolated: usize,
    exchange: usize,
    isolated_cost: u64,
    exchange_cost: u64,
) -> &'static str {
    if exchange > isolated {
        return "improved_coverage";
    }
    if exchange < isolated {
        return "lower_coverage";
    }
    match exchange_cost.cmp(&isolated_cost) {
        std::cmp::Ordering::Less => "equal_coverage_lower_cost",
        std::cmp::Ordering::Equal => "neutral",
        std::cmp::Ordering::Greater => "equal_coverage_higher_cost",
    }
}
fn record_id(world: usize) -> String {
    format!("route-graph-world-{world:03}")
}
fn validated_records(
    store: &KnowledgeStore,
    source: &str,
    contexts: &Contexts,
) -> Result<Vec<KnowledgeRecord>, String> {
    let records = store.active();
    let fingerprint = graph_schema_fingerprint(&schema())?;
    for record in &records {
        let id = contexts.world(&record.scope)?;
        if record.id != record_id(id)
            || record.source != source
            || record.schema_fingerprint != fingerprint
        {
            return Err("persisted graph model has wrong exact context, peer or schema".into());
        }
        let payload: GraphMap = match record.typed_payload()? {
            symbiote_memory::knowledge::KnowledgePayload::GraphMap(map) => map,
            _ => return Err("graph state contains an unrelated model family".into()),
        };
        if payload.schema != schema() {
            return Err("persisted graph topology does not match the experiment".into());
        }
    }
    Ok(records)
}
fn snapshot(stores: &[KnowledgeStore; 2], contexts: &Contexts) -> Result<Value, String> {
    let mut peers = Vec::new();
    for (index, store) in stores.iter().enumerate() {
        let mut models = Vec::new();
        for record in validated_records(store, IDS[1 - index], contexts)? {
            let mut forecasts = Vec::new();
            for (start, goal) in HOLDOUT {
                forecasts.push(json!(record.graph_forecast(encode_query(4, start, goal)?)?));
            }
            models.push(json!({"id":record.id,"context":record.scope,"forecasts":forecasts}));
        }
        peers.push(json!({"agent":IDS[index],"models":models}));
    }
    Ok(json!(peers))
}

fn promote(
    store: &mut KnowledgeStore,
    index: usize,
    world_id: usize,
    context: &str,
    arm: &Arm,
    baseline: &Arm,
    price: u64,
) -> Result<&'static str, String> {
    if arm.coverage[index] != HOLDOUT.len() {
        return Ok("withheld_abstention");
    }
    let export = &arm.exports[index];
    let payload = export.map.to_payload()?;
    let active = store
        .active()
        .into_iter()
        .find(|r| r.id == record_id(world_id));
    if active
        .as_ref()
        .is_some_and(|record| record.payload == payload)
    {
        return Ok("already_retained");
    }
    let record=KnowledgeRecord{id:record_id(world_id),revision:store.highest_revision(&record_id(world_id)).unwrap_or(0)+1,
        source:IDS[1-index].into(),scope:context.into(),schema_fingerprint:graph_schema_fingerprint(&schema())?,payload,
        provenance:"Predeclared graph cohort: own and authorized peer edge receipts; both fixed held-out route queries independently judged. Stationary graph context only.".into()};
    let mut cases = Vec::new();
    for (position, (start, goal)) in HOLDOUT.into_iter().enumerate() {
        let input = encode_query(4, start, goal)?;
        let prediction = route(&arm.forecasts[index][position])?
            .ok_or("promotion cannot omit a held-out query")?;
        let expected = judge(&weights(world_id), start, goal, Some(&prediction))?;
        cases.push(TrialCase {
            id: format!("heldout-{start}-{goal}"),
            input,
            expected,
            baseline: active
                .as_ref()
                .map(|r| r.predict_if_certified(input))
                .transpose()?
                .flatten(),
            candidate: prediction.cost as u8,
        });
    }
    let meter = &arm.meters[index];
    let evidence = GraphTrialEvidence {
        evaluator: "independent-bellman-ford-judge".into(),
        acquisitions: export.acquisitions.clone(),
        training_tasks: vec![
            GraphTrainingTask {
                id: "warmup".into(),
                input: encode_query(4, 0, if index == 0 { 1 } else { 2 })?,
            },
            GraphTrainingTask {
                id: "acquisition-task".into(),
                input: encode_query(4, 0, 3)?,
            },
        ],
        cases,
        costs: TrialCosts {
            acquisition: meter.acquisitions * price,
            verification: meter.verified_receipts * 2 + meter.oracle_requests,
            adoption: meter.adopted_edges,
            baseline: baseline.meters[index].total(price),
            candidate: meter.total(price),
        },
    };
    let assessment = assess_graph(&record, &evidence)?;
    store.promote_graph(record, assessment)?;
    Ok("promoted")
}

fn oracle_call(endpoint: &Endpoint, client_id: &str, payload: &Value) -> Result<Value, String> {
    let mut client = Client::connect_scoped(endpoint, client_id, &["observe", "verify"], SCOPE)?;
    let value = client.call("verify", payload);
    if value.is_ok() {
        client.revoke()?;
    }
    value
}
fn negative_controls(
    oracle: &Endpoint,
    authority: &Arc<Mutex<Authority>>,
    identities: &[String; 2],
    contexts: &Arc<Contexts>,
) -> Result<Value, String> {
    let context = contexts.label(80);
    let receipt =
        authority
            .lock()
            .map_err(|_| "authority poisoned")?
            .issue(&identities[1], context, 2)?;
    let own =
        authority
            .lock()
            .map_err(|_| "authority poisoned")?
            .issue(&identities[0], context, 0)?;
    let base = json!({"context":context,"receipts":[receipt],"peer_only":true});
    if oracle_call(oracle, IDS[0], &base)?["verified"] != true {
        return Err("genuine receipt negative-control calibration failed".into());
    }
    let mut controls = BTreeMap::new();
    let mut forged = base.clone();
    forged["receipts"][0]["cost"] = json!(9);
    controls.insert("forged", oracle_call(oracle, IDS[0], &forged).is_err());
    let mut cross = base.clone();
    cross["receipts"][0]["context"] = json!(contexts.label(79));
    controls.insert(
        "wrong_context",
        oracle_call(oracle, IDS[0], &cross).is_err(),
    );
    let mut duplicate = base.clone();
    duplicate["receipts"] = json!([receipt, receipt]);
    controls.insert(
        "duplicate",
        oracle_call(oracle, IDS[0], &duplicate).is_err(),
    );
    let mut wrong = base.clone();
    wrong["receipts"] = json!([own]);
    controls.insert("wrong_source", oracle_call(oracle, IDS[0], &wrong).is_err());
    let mut previous = Authority::new(contexts.clone())?;
    let old = previous.issue(&identities[1], context, 2)?;
    previous.verify(std::slice::from_ref(&old), context, &[&identities[1]])?;
    let mut stale = base;
    stale["receipts"] = json!([old]);
    controls.insert(
        "previous_authority",
        oracle_call(oracle, IDS[0], &stale).is_err(),
    );
    if controls.values().any(|passed| !*passed) {
        return Err("authenticated graph negative control failed".into());
    }
    Ok(json!(controls))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForecastConfig {
    contexts_path: PathBuf,
    stores: [PathBuf; 2],
    identities: [String; 2],
    controller_identity: String,
}
fn bounded_line(reader: &mut impl BufRead, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let count = reader
        .take(limit as u64 + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(|e| e.to_string())?;
    if count == 0 || count > limit || bytes.last() != Some(&b'\n') {
        return Err("bounded complete JSON line required".into());
    }
    Ok(bytes)
}
fn forecast_watchdog(timeout: Duration) -> mpsc::Sender<()> {
    let (finished, watchdog) = mpsc::channel();
    thread::spawn(move || {
        if matches!(
            watchdog.recv_timeout(timeout),
            Err(mpsc::RecvTimeoutError::Timeout)
        ) {
            std::process::exit(73);
        }
    });
    finished
}
pub(crate) fn forecast_from_stdin() -> Result<(), String> {
    let input_finished = forecast_watchdog(Duration::from_secs(3));
    let request = bounded_line(&mut std::io::stdin().lock(), 4096)?;
    let _ = input_finished.send(());
    let finished = forecast_watchdog(Duration::from_secs(15));
    let config: ForecastConfig =
        serde_json::from_slice(&request).map_err(|_| "invalid graph forecast configuration")?;
    if config.identities[0] == config.identities[1]
        || config
            .identities
            .iter()
            .any(|id| id == &config.controller_identity)
    {
        return Err("graph private owner identities alias".into());
    }
    let contexts = Contexts::read(&config.contexts_path, &config.controller_identity)?;
    let mut stores = Vec::new();
    for (index, path) in config.stores.iter().enumerate() {
        let inspection = maintenance::inspect(path)?;
        if inspection.identity.as_deref() != Some(config.identities[index].as_str()) {
            return Err("offline graph model owner changed".into());
        }
        stores.push(KnowledgeStore::open(path, &config.identities[index])?);
    }
    let stores: [KnowledgeStore; 2] = stores.try_into().map_err(|_| "forecast store count")?;
    let report = json!({"schema":"symbiote.graph-offline/1","pid":std::process::id(),"models":snapshot(&stores,&contexts)?,"oracle_endpoints_available":0});
    drop(stores);
    let mut output = serde_json::to_vec(&report).map_err(|e| e.to_string())?;
    output.push(b'\n');
    if output.len() > 128 * 1024 {
        return Err("offline graph result exceeds its output budget".into());
    }
    let result = std::io::stdout()
        .write_all(&output)
        .map_err(|e| e.to_string());
    let _ = finished.send(());
    result
}
fn terminate(child: &mut Child) -> Result<(), String> {
    if child.try_wait().map_err(|e| e.to_string())?.is_none() {
        if let Err(error) = child.kill() {
            if child.try_wait().map_err(|e| e.to_string())?.is_none() {
                return Err(format!(
                    "owned graph forecast process could not be terminated: {error}"
                ));
            }
        }
    }
    child.wait().map_err(|e| e.to_string())?;
    Ok(())
}
struct OwnedForecastChild(Child);
impl std::ops::Deref for OwnedForecastChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}
impl std::ops::DerefMut for OwnedForecastChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}
impl Drop for OwnedForecastChild {
    fn drop(&mut self) {
        let _ = terminate(&mut self.0);
    }
}
fn offline_replay(config: ForecastConfig) -> Result<Value, String> {
    let mut command = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    command
        .arg("__graph-forecast")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = OwnedForecastChild(command.spawn().map_err(|e| e.to_string())?);
    let owned_pid = child.id();
    let mut stdin = child.stdin.take().ok_or("forecast stdin missing")?;
    let mut stdout = child.stdout.take().ok_or("forecast stdout missing")?;
    let mut stderr = child.stderr.take().ok_or("forecast stderr missing")?;
    let mut request = serde_json::to_vec(&config).map_err(|e| e.to_string())?;
    request.push(b'\n');
    if request.len() > 4096 {
        terminate(&mut child)?;
        return Err("graph forecast request exceeds input budget".into());
    }
    let (sender, receiver) = mpsc::channel();
    let writer = thread::spawn(move || {
        let result = stdin.write_all(&request);
        drop(stdin);
        let _ = sender.send(result);
    });
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .by_ref()
            .take(128 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let error_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr
            .by_ref()
            .take(4097)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    if receiver
        .recv_timeout(Duration::from_secs(2))
        .map_err(|_| "offline graph input deadline")?
        .is_err()
    {
        terminate(&mut child)?;
        return Err("offline graph input failed".into());
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if Instant::now() >= deadline {
            terminate(&mut child)?;
            writer.join().map_err(|_| "forecast writer panicked")?;
            reader
                .join()
                .map_err(|_| "forecast reader panicked")?
                .map_err(|e| e.to_string())?;
            error_reader
                .join()
                .map_err(|_| "forecast error reader panicked")?
                .map_err(|e| e.to_string())?;
            return Err("offline graph process exceeded its deadline".into());
        }
        thread::sleep(Duration::from_millis(5));
    };
    writer.join().map_err(|_| "forecast writer panicked")?;
    let output = reader
        .join()
        .map_err(|_| "forecast reader panicked")?
        .map_err(|e| e.to_string())?;
    let errors = error_reader
        .join()
        .map_err(|_| "forecast error reader panicked")?
        .map_err(|e| e.to_string())?;
    if !status.success() || output.len() > 128 * 1024 || errors.len() > 4096 {
        return Err("offline graph replay failed within its bounded output contract".into());
    }
    let report: Value = serde_json::from_slice(&output)
        .map_err(|_| "offline graph replay produced invalid JSON")?;
    if report["pid"] != owned_pid {
        return Err("offline graph replay process identity mismatched its owned child".into());
    }
    Ok(report)
}

pub(crate) fn run(state: &Path, receipts: &Path) -> Result<Value, String> {
    let started = Instant::now();
    let controller = Store::open(state)?;
    let controller_identity = controller.identity().to_owned();
    let paths = [state.join("graph/dijkstra"), state.join("graph/paths")];
    let contexts_path = state.join("graph/contexts.json");
    let contexts = Arc::new(Contexts::open(&contexts_path, &controller_identity)?);
    for path in &paths {
        if maintenance::inspect(path)?.identity.as_deref() == Some(controller_identity.as_str()) {
            return Err(
                "graph private store aliases the controller owner; existing bytes preserved".into(),
            );
        }
    }
    let owners = [Store::open(&paths[0])?, Store::open(&paths[1])?];
    let identities = [
        owners[0].identity().to_owned(),
        owners[1].identity().to_owned(),
    ];
    if identities[0] == identities[1] || identities.iter().any(|id| id == &controller_identity) {
        return Err(
            "graph private store owner identities alias; existing evidence preserved".into(),
        );
    }
    let mut stores = [
        KnowledgeStore::open(&paths[0], &identities[0])?,
        KnowledgeStore::open(&paths[1], &identities[1])?,
    ];
    for (index, store) in stores.iter().enumerate() {
        validated_records(store, IDS[1 - index], &contexts)?;
    }
    let authority = Arc::new(Mutex::new(Authority::new(contexts.clone())?));
    let counters = Arc::new(OracleCounts::default());
    let mut oracles = Vec::new();
    for index in 0..2 {
        let authority = authority.clone();
        let counts = counters.clone();
        let own = identities[index].clone();
        let peer = identities[1 - index].clone();
        oracles.push(spawn_scoped_server(config(&format!("graph-oracle-{index}"),IDS[index],&["observe","verify"])?,SCOPE,move|operation,payload|{
            let context=payload["context"].as_str().ok_or("oracle context missing")?;
            match operation{
                "observe"=>{counts.observe.fetch_add(1,Ordering::SeqCst);let edge=payload["edge_id"].as_u64().ok_or("oracle edge missing")? as usize;Ok(json!(authority.lock().map_err(|_|"authority poisoned")?.issue(&own,context,edge)?))},
                "verify"=>{counts.verify.fetch_add(1,Ordering::SeqCst);let receipts:Vec<Receipt>=serde_json::from_value(payload["receipts"].clone()).map_err(|e|e.to_string())?;
                    let observers=if payload["peer_only"]==true{vec![peer.as_str()]}else{vec![own.as_str(),peer.as_str()]};
                    authority.lock().map_err(|_|"authority poisoned")?.verify(&receipts,context,&observers)?;Ok(json!({"verified":true,"digest":graph_receipt_digest(&json!(receipts))?}))},
                _=>Err("oracle operation not authorized".into())
            }
        })?);
    }
    let mut services = Vec::new();
    for index in 0..2 {
        let agent = Arc::new(Mutex::new(Agent {
            index,
            identity: identities[index].clone(),
            peer_identity: identities[1 - index].clone(),
            oracle: oracles[index].endpoint().clone(),
            context: String::new(),
            learner: Learner::new(index)?,
            observations: BTreeMap::new(),
            meter: Meter::default(),
        }));
        services.push(spawn_scoped_server(
            config(IDS[index], CONTROLLER, OPS)?,
            SCOPE,
            move |operation, payload| {
                agent
                    .lock()
                    .map_err(|_| "graph participant poisoned")?
                    .operation(operation, payload)
            },
        )?);
    }
    let endpoints = [
        services[0].endpoint().clone(),
        services[1].endpoint().clone(),
    ];
    let mut regimes = Vec::new();
    let mut promotions = ["promoted", "already_retained", "withheld_abstention"]
        .into_iter()
        .map(|label| (label.into(), 0))
        .collect::<BTreeMap<String, u64>>();
    for (name, price) in [("normal", 100), ("cheap_observation", 1)] {
        let mut cases = Vec::new();
        let mut classes = [
            "improved_coverage",
            "equal_coverage_lower_cost",
            "neutral",
            "equal_coverage_higher_cost",
            "lower_coverage",
        ]
        .into_iter()
        .map(|label| (label.into(), 0))
        .collect::<BTreeMap<String, u64>>();
        let mut bilateral = 0;
        let mut isolated_total = 0;
        let mut exchange_total = 0;
        for world_id in 0..81 {
            let isolated = execute_arm(&endpoints, world_id, contexts.label(world_id), false)?;
            let exchange = execute_arm(&endpoints, world_id, contexts.label(world_id), true)?;
            let mut participants = Vec::new();
            let mut both = true;
            for index in 0..2 {
                let base = isolated.meters[index].total(price);
                let candidate = exchange.meters[index].total(price);
                isolated_total += base;
                exchange_total += candidate;
                let class = comparison(
                    isolated.coverage[index],
                    exchange.coverage[index],
                    base,
                    candidate,
                );
                *classes.entry(class.into()).or_default() += 1;
                both &= exchange.coverage[index] >= isolated.coverage[index]
                    && (exchange.coverage[index] > isolated.coverage[index] || candidate < base);
                let promotion = if name == "normal" {
                    let outcome = promote(
                        &mut stores[index],
                        index,
                        world_id,
                        contexts.label(world_id),
                        &exchange,
                        &isolated,
                        price,
                    )?;
                    *promotions.entry(outcome.into()).or_default() += 1;
                    Some(outcome)
                } else {
                    None
                };
                participants.push(json!({"agent":IDS[index],"isolated_cost":base,"exchange_cost":candidate,"comparison":class,
                    "isolated":isolated.meters[index],"exchange":exchange.meters[index],"isolated_heldout_correct":isolated.coverage[index],
                    "exchange_heldout_correct":exchange.coverage[index],"heldout_total":2,"isolated_abstentions":2-isolated.coverage[index],"exchange_abstentions":2-exchange.coverage[index],
                    "isolated_forecasts":isolated.forecasts[index],"exchange_forecasts":exchange.forecasts[index],"promotion":promotion}));
            }
            bilateral += usize::from(both);
            cases.push(json!({"world":world_id,"context":contexts.label(world_id),"costs":weights(world_id),"participants":participants}));
        }
        regimes.push(json!({"name":name,"observation_price":price,"worlds":81,"participant_comparisons":162,"isolated_cost":isolated_total,"exchange_cost":exchange_total,"classes":classes,"bilateral_benefit_worlds":bilateral,"cases":cases}));
    }
    let negative_controls =
        negative_controls(&oracles[0].endpoint(), &authority, &identities, &contexts)?;
    let expected = snapshot(&stores, &contexts)?;
    let example = stores[0].active().first().map(
        |record| json!({"agent":IDS[0],"state":paths[0],"artifact":record.id,"from":1,"to":3}),
    );
    let active = [stores[0].active().len(), stores[1].active().len()];
    if active.contains(&0) {
        return Err(
            "graph experiment produced no complete held-out validated durable models".into(),
        );
    }
    let ledger_before = [
        fs::read(paths[0].join("knowledge.jsonl")).map_err(|e| e.to_string())?,
        fs::read(paths[1].join("knowledge.jsonl")).map_err(|e| e.to_string())?,
    ];
    drop(stores);
    drop(owners);
    let before = counters.snapshot();
    let replay = offline_replay(ForecastConfig {
        contexts_path,
        stores: paths.clone(),
        identities: identities.clone(),
        controller_identity: controller_identity.clone(),
    })?;
    let after = counters.snapshot();
    let restart_requests = json!({"observe":after["observe"].as_u64().ok_or("missing observation counter")?.checked_sub(before["observe"].as_u64().ok_or("missing observation counter")?).ok_or("observation counter regressed")?,
        "verify":after["verify"].as_u64().ok_or("missing verification counter")?.checked_sub(before["verify"].as_u64().ok_or("missing verification counter")?).ok_or("verification counter regressed")?});
    if before != after
        || replay["oracle_endpoints_available"] != 0
        || replay["pid"] == json!(std::process::id())
        || replay["models"] != expected
    {
        return Err(
            "actual offline graph replay did not preserve exact routes without oracle access"
                .into(),
        );
    }
    for index in 0..2 {
        if fs::read(paths[index].join("knowledge.jsonl")).map_err(|e| e.to_string())?
            != ledger_before[index]
        {
            return Err("offline graph replay changed durable ledger bytes".into());
        }
    }
    let protocol = include_str!("../../../docs/RESEARCH_V04_PROTOCOL.md").replace("\r\n", "\n");
    let protocol_sha256 = format!("{:x}", Sha256::digest(protocol.as_bytes()));
    let report = json!({"schema":"symbiote.graph-research/1","version":env!("CARGO_PKG_VERSION"),"status":"PASS","protocol_sha256":protocol_sha256,
        "protocol":"docs/RESEARCH_V04_PROTOCOL.md","scope":"all81 four-edge diamond worlds; stationary intervals1..3; fixed held-out1→3,2→3",
        "heldout_queries":[[1,3],[2,3]],"training_tasks":{"dijkstra":[[0,1],[0,3]],"paths":[[0,2],[0,3]]},
        "benchmark_initial_state":"fresh empty model perarm; persistent models do not influence paired acquisition",
        "identity":controller_identity,"process_id":std::process::id(),"endpoint_process_separation":false,
        "participants":[{"agent":IDS[0],"algorithm":"optimistic-dijkstra-exact-interval","identity":identities[0],"active_models":active[0]},
                        {"agent":IDS[1],"algorithm":"exhaustive-simple-paths-reverse-order","identity":identities[1],"active_models":active[1]}],
        "regimes":regimes,"promotions":promotions,"negative_controls":negative_controls,"incorrect_certificates":0,
        "state_directories":[{"agent":IDS[0],"state":paths[0]},{"agent":IDS[1],"state":paths[1]}],"example_query":example,
        "restart_retained_predictions":true,"restart_process_id":replay["pid"],"restart_oracle_requests":restart_requests,
        "oracle_requests_before_restart":before,"oracle_requests_after_restart":after,"offline_models":replay["models"],"elapsed_ms":started.elapsed().as_millis(),
        "cost_scope":"declared logical participant application-cost model; all cohort API/session/application-bytes/acquisition/verification/adoption/route-work/export categories; excludes OS,TCP/HMAC framing,controller,judge,audit-I/O and replay laboratory overhead",
        "limitations":["graph endpoint cohort shares one controller process; separate-process proof remains the v0.3 affine experiment","finite topology and cost family only; no universal reciprocal advantage","trusted local authority and stationary context; raw digests cannot establish arbitrary remote honesty","cheap and normal regimes reuse the same81worlds; not162 independent environments"]});
    if let Some(parent) = receipts.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(
        receipts,
        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_path_certificates_hold_in_every_remaining_world() {
        for actual in 0..81 {
            let actual_costs = weights(actual);
            let mut learner = Learner::new(1).unwrap();
            learner.observe(2, actual_costs[2]).unwrap();
            for _ in 0..=4 {
                let (route, next) = learner.assess(0, 3).unwrap();
                if let Some(route) = route {
                    let Learner::Paths(paths) = &learner else {
                        unreachable!()
                    };
                    for completion in 0..81 {
                        let costs = weights(completion);
                        if paths
                            .observed
                            .iter()
                            .all(|(edge, cost)| costs[*edge] == *cost)
                        {
                            judge(&costs, 0, 3, Some(&route)).unwrap();
                        }
                    }
                    break;
                }
                let edge = next.expect("finite exact path learner must expose an unknown frontier");
                learner.observe(edge, actual_costs[edge]).unwrap();
            }
        }
    }

    #[test]
    fn contradictory_costs_preserve_evidence_and_abstain_in_both_algorithms() {
        for index in 0..2 {
            let mut learner = Learner::new(index).unwrap();
            learner.observe(0, 1).unwrap();
            assert!(learner.observe(0, 2).is_err());
            assert!(learner.assess(0, 3).is_err());
            match learner {
                Learner::Dijkstra(learner) => assert_eq!(learner.observations(), &[(0, 1)]),
                Learner::Paths(learner) => assert_eq!(learner.observed.get(&0), Some(&1)),
            }
        }
    }

    #[test]
    fn authority_epoch_rotation_does_not_reauthenticate_a_historical_receipt() {
        let contexts = Arc::new(Contexts::new("controller-identity").unwrap());
        let mut old = Authority::new(contexts.clone()).unwrap();
        let current = Authority::new(contexts.clone()).unwrap();
        let receipt = old
            .issue("peer-owned-identity", contexts.label(0), 0)
            .unwrap();
        old.verify(
            std::slice::from_ref(&receipt),
            contexts.label(0),
            &["peer-owned-identity"],
        )
        .unwrap();
        assert!(current
            .verify(&[receipt], contexts.label(0), &["peer-owned-identity"])
            .is_err());
    }

    #[test]
    fn exhausted_request_and_work_budgets_do_not_perform_the_next_operation() {
        let mut learner = Learner::Paths(Paths {
            observed: BTreeMap::new(),
            work: WORK_LIMIT,
            contradicted: false,
        });
        assert!(learner.observe(0, 1).is_err());
        assert!(learner.assess(0, 3).is_err());
        assert_eq!(learner.work(), WORK_LIMIT);
        let Learner::Paths(paths) = learner else {
            unreachable!()
        };
        assert!(paths.observed.is_empty());
        let mut agent = Agent {
            index: 0,
            identity: "own".into(),
            peer_identity: "peer".into(),
            oracle: Endpoint {
                id: "unused".into(),
                address: "127.0.0.1:1".parse().unwrap(),
                token: "unused-never-sent-capability".into(),
            },
            context: String::new(),
            learner: Learner::new(0).unwrap(),
            observations: BTreeMap::new(),
            meter: Meter {
                endpoint_requests: 32,
                oracle_requests: 16,
                ..Meter::default()
            },
        };
        assert!(agent.operation("warmup", json!({})).is_err());
        assert!(agent.oracle("observe", &json!({})).is_err());
        assert_eq!(agent.meter.endpoint_requests, 32);
        assert_eq!(agent.meter.oracle_requests, 16);
        assert!(agent.observations.is_empty());
    }
}
