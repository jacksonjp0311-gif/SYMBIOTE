//! Evidence-conditioned exchange between two independently implemented learners.
//! Trusted laboratory observation receipts are a stated assumption, not a proof
//! of arbitrary remote honesty. All costs are declared logical resource units.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use symbiote_memory::knowledge::{
    affine_schema_fingerprint, assess, KnowledgeRecord, KnowledgeStore, TrialCase, TrialCosts,
    TrialEvidence,
};
use symbiote_memory::Store;
use symbiote_protocol::{spawn_scoped_server, Client, ServerConfig};
use symbiote_reasoning::structural::{AffineLearner, AffineStrategy};

const SCOPE: &str = "boolean-affine/v1";
const OPS: &[&str] = &["next", "observe", "bundle", "adopt", "forecast", "control"];
const BUDGET: usize = 2_000_000;
const OBSERVATION_COST: u64 = 100;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationReceipt {
    id: String,
    domain: String,
    schema: String,
    input: u16,
    output: u8,
}

/// Read-only verification of receipts actually issued by the separate lab oracle.
/// Agents cannot register witnesses or read oracle parameters through this API.
#[derive(Default)]
struct Authority {
    issued: BTreeMap<String, ObservationReceipt>,
    next: u64,
}
impl Authority {
    fn issue(
        &mut self,
        domain: &str,
        width: u8,
        input: u16,
        output: u8,
    ) -> Result<ObservationReceipt, String> {
        self.next = self
            .next
            .checked_add(1)
            .ok_or("oracle receipt budget exhausted")?;
        let body = json!([domain, width, input, output, self.next]);
        let id = format!("{:x}", Sha256::digest(body.to_string().as_bytes()));
        let receipt = ObservationReceipt {
            id: id.clone(),
            domain: domain.into(),
            schema: affine_schema_fingerprint(width)?,
            input,
            output,
        };
        self.issued.insert(id, receipt.clone());
        Ok(receipt)
    }
    fn verify(
        &self,
        receipts: &[ObservationReceipt],
        domain: &str,
        width: u8,
    ) -> Result<(), String> {
        if receipts.is_empty() || receipts.len() > usize::from(width) + 1 {
            return Err("bounded independent observation bundle required".into());
        }
        let schema = affine_schema_fingerprint(width)?;
        let mut ids = BTreeSet::new();
        let mut inputs = BTreeSet::new();
        for receipt in receipts {
            if receipt.domain != domain
                || receipt.schema != schema
                || receipt.input >= 1 << width
                || receipt.output > 1
                || !ids.insert(&receipt.id)
                || !inputs.insert(receipt.input)
                || self.issued.get(&receipt.id) != Some(receipt)
            {
                return Err(
                    "observation receipt is forged, repeated, cross-domain or outside schema"
                        .into(),
                );
            }
        }
        Ok(())
    }
}

/// Independently implemented Gaussian-elimination learner used by the partner.
/// It never calls AffineLearner or receives true coefficient values.
struct LinearLearner {
    width: u8,
    rows: Vec<Option<(u16, u8)>>,
    observations: Vec<(u16, u8)>,
}
impl LinearLearner {
    fn new(width: u8) -> Self {
        Self {
            width,
            rows: vec![None; usize::from(width) + 1],
            observations: Vec::new(),
        }
    }
    fn reduce(&self, mut row: u16, mut output: u8) -> (u16, u8) {
        for (column, basis) in self.rows.iter().enumerate() {
            if row & (1 << column) != 0 {
                if let Some((known, value)) = basis {
                    row ^= known;
                    output ^= value;
                }
            }
        }
        (row, output)
    }
    fn observe(&mut self, input: u16, output: u8) -> Result<(), String> {
        if input >= 1 << self.width || output > 1 {
            return Err("linear observation outside schema".into());
        }
        let (row, value) = self.reduce(input | (1 << self.width), output);
        if row == 0 && value != 0 {
            return Err("linear family contradicted".into());
        }
        if row != 0 {
            self.rows[row.trailing_zeros() as usize] = Some((row, value));
        }
        if !self.observations.contains(&(input, output)) {
            self.observations.push((input, output));
        }
        Ok(())
    }
    fn next(&self) -> Option<u16> {
        (0..1 << self.width).find(|input| self.reduce(input | (1 << self.width), 0).0 != 0)
    }
    fn predict(&self, input: u16) -> Option<u8> {
        let (row, output) = self.reduce(input | (1 << self.width), 0);
        if row == 0 {
            return Some(output);
        }
        None
    }
    fn strategy(&self) -> Result<AffineStrategy, String> {
        if self.rows.iter().any(Option::is_none) {
            return Err("partner has not identified a complete affine model".into());
        }
        let mut solution = 0_u16;
        for column in (0..self.rows.len()).rev() {
            let (row, output) = self.rows[column].ok_or("missing linear basis")?;
            let known = ((row & solution).count_ones() & 1) as u8;
            if output ^ known != 0 {
                solution |= 1 << column;
            }
        }
        AffineStrategy::new(
            self.width,
            solution & ((1 << self.width) - 1),
            solution & (1 << self.width) != 0,
        )
    }
}

enum Learner {
    Enumerated(AffineLearner),
    Linear(LinearLearner),
}
impl Learner {
    fn new(width: u8, linear: bool) -> Result<Self, String> {
        if linear {
            return Ok(Self::Linear(LinearLearner::new(width)));
        }
        Ok(Self::Enumerated(AffineLearner::new(width, BUDGET)?))
    }
    fn next(&mut self) -> Result<Option<u16>, String> {
        match self {
            Self::Enumerated(m) => m.choose_query(),
            Self::Linear(m) => Ok(m.next()),
        }
    }
    fn observe(&mut self, input: u16, output: u8) -> Result<(), String> {
        match self {
            Self::Enumerated(m) => m.observe(input, output),
            Self::Linear(m) => m.observe(input, output),
        }
    }
    fn predict(&mut self, input: u16) -> Result<Option<u8>, String> {
        match self {
            Self::Enumerated(m) => m.predict(input),
            Self::Linear(m) => Ok(m.predict(input)),
        }
    }
    fn strategy(&self) -> Result<AffineStrategy, String> {
        match self {
            Self::Enumerated(m) => m
                .identified()
                .ok_or_else(|| "affine model is not identified".into()),
            Self::Linear(m) => m.strategy(),
        }
    }
}

/// Oracle backends intentionally implement the same declared grammar differently.
enum Environment {
    Circuit {
        width: u8,
        wires: Vec<usize>,
        inverted: bool,
    },
    Arithmetic {
        width: u8,
        mask: u16,
        offset: u8,
    },
}
impl Environment {
    fn observe(&self, input: u16) -> Result<u8, String> {
        match self {
            Self::Circuit {
                width,
                wires,
                inverted,
            } => {
                if input >= 1 << width {
                    return Err("circuit input outside schema".into());
                }
                let mut signal = u8::from(*inverted);
                for wire in wires {
                    signal ^= ((input >> wire) & 1) as u8;
                }
                Ok(signal)
            }
            Self::Arithmetic {
                width,
                mask,
                offset,
            } => {
                if input >= 1 << width {
                    return Err("arithmetic input outside schema".into());
                }
                let mut x = input;
                let mut coefficients = *mask;
                let mut sum = usize::from(*offset);
                while x != 0 || coefficients != 0 {
                    sum += usize::from((x % 2) * (coefficients % 2));
                    x /= 2;
                    coefficients /= 2;
                }
                Ok((sum % 2) as u8)
            }
        }
    }
}

/// Independent evaluator uses a truth table materialized before learning begins.
struct Judge {
    expected: Vec<u8>,
}
impl Judge {
    fn new(width: u8, coefficients: u16, bias: bool) -> Self {
        let expected = (0..1 << width)
            .map(|input: u16| {
                let binary_input = format!("{input:0width$b}", width = usize::from(width));
                let binary_weights = format!("{coefficients:0width$b}", width = usize::from(width));
                let sum = binary_input
                    .bytes()
                    .zip(binary_weights.bytes())
                    .filter(|(a, b)| *a == b'1' && *b == b'1')
                    .count()
                    + usize::from(bias);
                (sum % 2) as u8
            })
            .collect();
        Self { expected }
    }
    fn expected(&self, input: u16) -> u8 {
        self.expected[usize::from(input)]
    }
}

struct Service {
    domain: String,
    target_domain: String,
    width: u8,
    linear: bool,
    environment: Environment,
    learner: Learner,
    received: Option<Learner>,
    transcript: Vec<ObservationReceipt>,
    authority: Arc<Mutex<Authority>>,
}
impl Service {
    fn handle(&mut self, operation: &str, payload: Value) -> Result<Value, String> {
        if operation == "next" {
            return Ok(json!({"input":self.learner.next()?}));
        }
        if operation == "observe" || operation == "control" {
            let raw = payload["input"].as_u64().ok_or("input required")?;
            let input = u16::try_from(raw).map_err(|_| "input too large")?;
            let output = self.environment.observe(input)?;
            let receipt = self
                .authority
                .lock()
                .map_err(|_| "oracle authority unavailable")?
                .issue(&self.domain, self.width, input, output)?;
            if operation == "observe" {
                self.learner.observe(input, output)?;
                self.transcript.push(receipt.clone());
            }
            return Ok(json!(receipt));
        }
        if operation == "bundle" {
            return Ok(json!(self.transcript));
        }
        if operation == "adopt" {
            let receipts: Vec<ObservationReceipt> =
                serde_json::from_value(payload).map_err(|e| e.to_string())?;
            self.authority
                .lock()
                .map_err(|_| "oracle authority unavailable")?
                .verify(&receipts, &self.target_domain, self.width)?;
            let mut proposed = Learner::new(self.width, self.linear)?;
            for receipt in &receipts {
                proposed.observe(receipt.input, receipt.output)?;
            }
            let strategy = proposed.strategy()?;
            self.received = Some(proposed);
            return Ok(
                json!({"strategy":strategy,"verified_observations":receipts.len(),"status":"PROVISIONAL","basis":"oracle-attested observations replayed into complete hypothesis family; durable promotion still requires independent held-out evaluation"}),
            );
        }
        if operation == "forecast" {
            let inputs: Vec<u16> =
                serde_json::from_value(payload["inputs"].clone()).map_err(|e| e.to_string())?;
            if inputs.len() > 256 || inputs.iter().any(|x| *x >= 1 << self.width) {
                return Err("forecast request outside bounded schema".into());
            }
            let received = self
                .received
                .as_mut()
                .ok_or("no evaluated received model")?;
            let outputs: Result<Vec<Option<u8>>, String> =
                inputs.iter().map(|x| received.predict(*x)).collect();
            return Ok(
                json!({"outputs":outputs?,"epistemic_status":"conditional on declared stationary affine family"}),
            );
        }
        Err("unsupported research operation".into())
    }
}

fn fit(client: &mut Client, width: u8) -> Result<Vec<ObservationReceipt>, String> {
    for _ in 0..=width {
        let next = client.call("next", &json!({}))?;
        let Some(input) = next["input"].as_u64() else {
            break;
        };
        client.call("observe", &json!({"input":input}))?;
    }
    if !client.call("next", &json!({}))?["input"].is_null() {
        return Err("source model did not converge within declared query bound".into());
    }
    serde_json::from_value(client.call("bundle", &json!({}))?).map_err(|e| e.to_string())
}

fn isolated_target(
    client: &mut Client,
    width: u8,
    linear: bool,
) -> Result<(Learner, usize), String> {
    let mut learner = Learner::new(width, linear)?;
    let mut queries = 0;
    while let Some(input) = learner.next()? {
        let receipt: ObservationReceipt =
            serde_json::from_value(client.call("control", &json!({"input":input}))?)
                .map_err(|e| e.to_string())?;
        learner.observe(input, receipt.output)?;
        queries += 1;
        if queries > usize::from(width) + 1 {
            return Err("isolated learner exceeded exact sample bound".into());
        }
    }
    Ok((learner, queries))
}

#[allow(clippy::too_many_arguments)]
fn evaluate_transfer(
    receiver: &mut Client,
    oracle_client: &mut Client,
    judge: &Judge,
    bundle: &[ObservationReceipt],
    own_queries: usize,
    width: u8,
    linear: bool,
    source: &str,
    scope: &str,
    store: &mut KnowledgeStore,
) -> Result<Value, String> {
    let adopted = receiver.call("adopt", &json!(bundle))?;
    let strategy: AffineStrategy =
        serde_json::from_value(adopted["strategy"].clone()).map_err(|e| e.to_string())?;
    let training_inputs: BTreeSet<u16> = bundle.iter().map(|r| r.input).collect();
    let heldout: Vec<u16> = (0..1 << width)
        .filter(|x| !training_inputs.contains(x))
        .collect();
    let answer = receiver.call("forecast", &json!({"inputs":heldout}))?;
    let outputs: Vec<Option<u8>> =
        serde_json::from_value(answer["outputs"].clone()).map_err(|e| e.to_string())?;
    if outputs.len() != heldout.len() {
        return Err("incomplete forecast response".into());
    }
    let (mut isolated, isolated_queries) = isolated_target(oracle_client, width, linear)?;
    let wire_bytes = serde_json::to_vec(bundle).map_err(|e| e.to_string())?.len();
    let acquisition = own_queries as u64 * OBSERVATION_COST;
    let verification = bundle.len() as u64;
    let adoption = 1 + (wire_bytes as u64).div_ceil(1024);
    let prediction_cost = heldout.len() as u64;
    let baseline_cost = acquisition + isolated_queries as u64 * OBSERVATION_COST + prediction_cost;
    let candidate_cost = acquisition + verification + adoption + prediction_cost;
    let mut cases = Vec::new();
    for ((input, prediction), index) in heldout.iter().zip(outputs).zip(0..) {
        cases.push(TrialCase {
            id: format!("holdout-{index}"),
            input: *input,
            expected: judge.expected(*input),
            baseline: isolated.predict(*input)?,
            candidate: prediction.ok_or("received model abstained after complete proof")?,
        });
    }
    let id = format!("{source}-{scope}").replace('/', "-");
    let record = KnowledgeRecord { id: id.clone(), revision: store.highest_revision(&id).unwrap_or(0) + 1, source: source.into(), scope: scope.into(), schema_fingerprint: affine_schema_fingerprint(width)?, payload: json!(strategy), provenance: "Received genuine lab-oracle observation receipts, independently verified exact domain/schema; identified via full native hypothesis family and judged on disjoint inputs".into() };
    let evidence = TrialEvidence {
        evaluator: "independent-materialized-truth-table/v1".into(),
        training_case_ids: bundle.iter().map(|r| r.id.clone()).collect(),
        training_inputs: bundle.iter().map(|r| r.input).collect(),
        cases,
        costs: TrialCosts {
            acquisition,
            verification,
            adoption,
            baseline: baseline_cost,
            candidate: candidate_cost,
        },
    };
    let assessment = assess(&record, &evidence)?;
    let exists = store
        .active()
        .iter()
        .any(|old| old.id == id && old.payload == record.payload);
    if !exists {
        store.promote(record, assessment.clone())?;
    }
    Ok(
        json!({"agent":if linear {"partner-linear"} else {"symbiote-exact"},"scope":scope,"width":width,"correct":assessment.candidate_correct,"isolated_correct":assessment.baseline_correct,"total":assessment.independent_cases,"isolated_cost":baseline_cost,"exchange_cost":candidate_cost,"own_oracle_queries":own_queries,"isolated_additional_oracle_queries":isolated_queries,"verified_received_observations":bundle.len(),"wire_bytes":wire_bytes,"cost_breakdown":{"acquisition":acquisition,"verification":verification,"adoption_and_transfer":adoption,"prediction":prediction_cost},"promoted":!exists,"already_retained":exists,"conditional_family":SCOPE}),
    )
}

fn parameters(width: u8, seed: u16, second: bool) -> (u16, bool) {
    let mask = (1_u16 << width) - 1;
    let coefficients = (seed
        .wrapping_mul(if second { 29 } else { 17 })
        .wrapping_add(if second { 5 } else { 3 })
        & mask)
        .max(1);
    (coefficients, (seed + u16::from(second)) & 1 != 0)
}

fn negative_controls() -> Result<Value, String> {
    let mut authority = Authority::default();
    let receipt = authority.issue("negative-alpha", 3, 0, 0)?;
    let mut forged = receipt.clone();
    forged.output ^= 1;
    let forged_rejected = authority.verify(&[forged], "negative-alpha", 3).is_err();
    let cross_domain_rejected = authority
        .verify(std::slice::from_ref(&receipt), "negative-beta", 3)
        .is_err();
    let repeated_rejected = authority
        .verify(&[receipt.clone(), receipt], "negative-alpha", 3)
        .is_err();
    let mut learner = AffineLearner::new(3, BUDGET)?;
    let untrusted = AffineStrategy::new(3, 0, false)?;
    learner.set_hint(&untrusted)?;
    let hint_abstained = learner.predict(3)?.is_none();
    let mut wrong_family = LinearLearner::new(3);
    for input in [0, 1, 2, 4] {
        wrong_family.observe(input, 0)?;
    }
    let record = KnowledgeRecord {
        id: "negative-wrong-family".into(),
        revision: 1,
        source: "negative-partner".into(),
        scope: "negative-domain".into(),
        schema_fingerprint: affine_schema_fingerprint(3)?,
        payload: json!(wrong_family.strategy()?),
        provenance: "Deliberate AND-world wrong-family negative control".into(),
    };
    let wrong_evidence = TrialEvidence {
        evaluator: "independent-and-judge".into(),
        training_case_ids: vec!["t0".into(), "t1".into(), "t2".into(), "t4".into()],
        training_inputs: vec![0, 1, 2, 4],
        cases: vec![TrialCase {
            id: "unseen3".into(),
            input: 3,
            expected: 1,
            baseline: None,
            candidate: 0,
        }],
        costs: TrialCosts {
            acquisition: 400,
            verification: 4,
            adoption: 2,
            baseline: 801,
            candidate: 407,
        },
    };
    let wrong_family_rejected = assess(&record, &wrong_evidence).is_err();
    let cheap_record = KnowledgeRecord {
        id: "negative-cheap-observations".into(),
        provenance:
            "Cheap fresh observations can make exchange more expensive; expected no-gain control"
                .into(),
        ..record
    };
    let cheap_evidence = TrialEvidence {
        evaluator: "independent-zero-judge".into(),
        training_case_ids: vec!["t0".into(), "t1".into(), "t2".into(), "t4".into()],
        training_inputs: vec![0, 1, 2, 4],
        cases: [3, 5, 6, 7]
            .into_iter()
            .map(|input| TrialCase {
                id: format!("h{input}"),
                input,
                expected: 0,
                baseline: Some(0),
                candidate: 0,
            })
            .collect(),
        costs: TrialCosts {
            acquisition: 4,
            verification: 4,
            adoption: 2,
            baseline: 12,
            candidate: 14,
        },
    };
    let no_gain_rejected = assess(&cheap_record, &cheap_evidence).is_err();
    if ![
        forged_rejected,
        cross_domain_rejected,
        repeated_rejected,
        hint_abstained,
        wrong_family_rejected,
        no_gain_rejected,
    ]
    .iter()
    .all(|x| *x)
    {
        return Err("a required negative-control gate failed".into());
    }
    Ok(
        json!({"forged_receipt_rejected":forged_rejected,"cross_domain_receipt_rejected":cross_domain_rejected,"repeated_evidence_rejected":repeated_rejected,"hint_only_abstains":hint_abstained,"wrong_family_unseen_failure_blocks_promotion":wrong_family_rejected,"cheap_observation_no_gain_blocks_promotion":no_gain_rejected}),
    )
}

pub fn run(state: &Path, receipts: &Path) -> Result<Value, String> {
    let negative_controls = negative_controls()?;
    let own_identity = Store::open(state)?;
    let partner_dir = state.join("research-partner");
    let partner_identity = Store::open(&partner_dir)?;
    let mut own_store = KnowledgeStore::open(state, own_identity.identity())?;
    let mut partner_store = KnowledgeStore::open(&partner_dir, partner_identity.identity())?;
    let mut results = Vec::new();
    let mut pairs = 0;
    for width in 3..=8 {
        for seed in [7_u16, 19, 43, 101] {
            let domain_a = format!("affine-{width}-{seed}-alpha");
            let domain_b = format!("affine-{width}-{seed}-beta");
            let (coeff_a, bias_a) = parameters(width, seed, false);
            let (coeff_b, bias_b) = parameters(width, seed, true);
            let judge_a = Judge::new(width, coeff_a, bias_a);
            let judge_b = Judge::new(width, coeff_b, bias_b);
            let authority = Arc::new(Mutex::new(Authority::default()));
            let circuit = Environment::Circuit {
                width,
                wires: (0..usize::from(width))
                    .filter(|i| coeff_a & (1 << i) != 0)
                    .collect(),
                inverted: bias_a,
            };
            let arithmetic = Environment::Arithmetic {
                width,
                mask: coeff_b,
                offset: u8::from(bias_b),
            };
            let service_a = Arc::new(Mutex::new(Service {
                domain: domain_a.clone(),
                target_domain: domain_b.clone(),
                width,
                linear: false,
                environment: circuit,
                learner: Learner::new(width, false)?,
                received: None,
                transcript: Vec::new(),
                authority: Arc::clone(&authority),
            }));
            let service_b = Arc::new(Mutex::new(Service {
                domain: domain_b.clone(),
                target_domain: domain_a.clone(),
                width,
                linear: true,
                environment: arithmetic,
                learner: Learner::new(width, true)?,
                received: None,
                transcript: Vec::new(),
                authority,
            }));
            let config = |id: &str| ServerConfig {
                id: id.into(),
                token: format!("simulation-research-consent-{id}"),
                client_id: "research-controller".into(),
                operations: OPS.iter().map(|s| s.to_string()).collect(),
                max_requests: 100,
                max_frame_bytes: 32768,
                timeout: Duration::from_secs(10),
            };
            let a = Arc::clone(&service_a);
            let b = Arc::clone(&service_b);
            let mut server_a = spawn_scoped_server(config("affine-alpha"), SCOPE, move |op, p| {
                a.lock()
                    .map_err(|_| "alpha state unavailable")?
                    .handle(op, p)
            })?;
            let mut server_b = spawn_scoped_server(config("affine-beta"), SCOPE, move |op, p| {
                b.lock()
                    .map_err(|_| "beta state unavailable")?
                    .handle(op, p)
            })?;
            let mut client_a =
                Client::connect_scoped(&server_a.endpoint(), "research-controller", OPS, SCOPE)?;
            let mut client_b =
                Client::connect_scoped(&server_b.endpoint(), "research-controller", OPS, SCOPE)?;
            let bundle_a = fit(&mut client_a, width)?;
            let bundle_b = fit(&mut client_b, width)?;
            results.push(evaluate_transfer(
                &mut client_a,
                &mut client_b,
                &judge_b,
                &bundle_b,
                bundle_a.len(),
                width,
                false,
                "partner-linear",
                &domain_b,
                &mut own_store,
            )?);
            results.push(evaluate_transfer(
                &mut client_b,
                &mut client_a,
                &judge_a,
                &bundle_a,
                bundle_b.len(),
                width,
                true,
                "symbiote-exact",
                &domain_a,
                &mut partner_store,
            )?);
            client_a.revoke()?;
            client_b.revoke()?;
            server_a.shutdown()?;
            server_b.shutdown()?;
            pairs += 1;
        }
    }
    let sum = |field: &str| {
        results
            .iter()
            .map(|r| r[field].as_u64().unwrap_or(0))
            .sum::<u64>()
    };
    let promoted = results.iter().filter(|r| r["promoted"] == true).count();
    let report = json!({
        "schema":"symbiote.research/1", "version":env!("CARGO_PKG_VERSION"), "status":"PASS",
        "experiment":"oracle-attested reciprocal observation exchange",
        "scope":"Boolean affine, widths3..8, predefined seeds7/19/43/101",
        "cases":pairs, "passed":pairs, "failed":0,
        "identity":own_identity.identity(), "partner_identity":partner_identity.identity(),
        "promoted":promoted, "already_retained":results.len()-promoted,
        "participants":results,
        "aggregate":{"correct":sum("correct"),"isolated_correct":sum("isolated_correct"),"heldout_predictions":sum("total"),"isolated_cost":sum("isolated_cost"),"exchange_cost":sum("exchange_cost")},
        "negative_controls":negative_controls,
        "cost_model":{"expensive_oracle_observation":100,"receipt_registry_verification":1,"prediction":1,"transfer_per_started_kib":1,"adoption":1,"units":"declared simulation resource units, not wall-clock or monetary savings"},
        "assumptions":[
            "trusted independent local laboratory oracle registry authenticates actual observations",
            "stationary Boolean affine family and exact coordinate schema",
            "same-host TCP, no secure nonlocal transport claim",
            "all declared source-acquisition, verification, adoption, transfer and prediction components counted; CPU/controller/evaluator work not priced",
            "two independently implemented native learners share one test controller process",
            "held-out inputs unique within each task; repeated laws across seeded contexts are not independent statistical samples",
            "research reruns regenerate the experiment; offline predict/status separately uses persisted knowledge"
        ],
        "conclusion":"Genuine observation exchange avoids duplicated expensive observations under the stated oracle-attestation and cost assumptions; no general transfer, adversarial remote honesty or autonomous self-improvement claim."
    });
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
    fn all_executed_negative_controls_block_invalid_promotion() {
        let controls = negative_controls().unwrap();
        assert_eq!(controls.as_object().unwrap().len(), 6);
        assert!(controls.as_object().unwrap().values().all(|v| v == true));
    }
    #[test]
    fn independent_implementations_and_judge_agree_on_all_small_functions() {
        for width in 1..=4 {
            for coefficients in 0..1 << width {
                for bias in [false, true] {
                    let judge = Judge::new(width, coefficients, bias);
                    let mut model = LinearLearner::new(width);
                    while let Some(input) = model.next() {
                        model.observe(input, judge.expected(input)).unwrap();
                    }
                    for input in 0..1 << width {
                        assert_eq!(model.predict(input), Some(judge.expected(input)));
                        assert_eq!(
                            model.strategy().unwrap().predict(input).unwrap(),
                            judge.expected(input)
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn oracle_registry_rejects_modified_cross_domain_and_duplicate_evidence() {
        let mut authority = Authority::default();
        let receipt = authority.issue("alpha", 3, 0, 0).unwrap();
        assert!(authority
            .verify(std::slice::from_ref(&receipt), "alpha", 3)
            .is_ok());
        let mut altered = receipt.clone();
        altered.output = 1;
        assert!(authority.verify(&[altered], "alpha", 3).is_err());
        assert!(authority
            .verify(std::slice::from_ref(&receipt), "beta", 3)
            .is_err());
        assert!(authority
            .verify(&[receipt.clone(), receipt], "alpha", 3)
            .is_err());
    }
    #[test]
    fn wrong_family_can_match_basis_then_fail_unseen_input() {
        let mut learner = LinearLearner::new(3);
        for input in [0, 1, 2, 4] {
            learner.observe(input, u8::from(input & 3 == 3)).unwrap();
        }
        assert_eq!(learner.predict(3), Some(0));
        assert!(learner.observe(3, 1).is_err());
        // A basis agreement is conditional on the family, not physical truth.
        assert_ne!(learner.strategy().unwrap().predict(3).unwrap(), 1);
    }
}
