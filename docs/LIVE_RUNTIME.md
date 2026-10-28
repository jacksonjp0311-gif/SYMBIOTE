# Configured SYMBIOTE runtime

The `run` path turns an explicitly
configured identity, peer registry and local evaluators into a bounded cognitive
episode. It does not require a language model. Public v1.0.0 and the corrective
1.0.1 candidate have separate qualification; see the [release audit](V1_RELEASE_AUDIT.md)
and [corrective account](CORRECTIVE_RELEASE_101.md).

## Operator setup

Prepare identities and TLS grants using [the service guide](SERVICE.md). The
service configuration names the owner store, private credentials, exact peer
identities and certificate pins, scopes, artifact permissions and independently
pinned local evaluation fixtures. An exposed endpoint is not authorization.

Write a separate `symbiote.cognition-policy/1` policy for the run. It can narrow
the service configuration. It cannot introduce a peer, credential, evaluator or
scope. Obtain the actual owner and policy digest with `policy-status`.

```json
{
  "schema": "symbiote.cognition-policy/1",
  "expected_identity": "COPY_THE_PREPARED_OWNER_ID",
  "service_policy_sha256": "COPY_THE_CURRENT_64_CHARACTER_POLICY_SHA256",
  "max_episodes": 8,
  "max_duration_ms": 60000,
  "interval_ms": 500,
  "max_rpc_attempts": 48,
  "max_model_work": 1000000,
  "max_plaintext_bytes": 16777216,
  "max_candidates_per_episode": 2,
  "max_contributions_per_episode": 2,
  "peers": ["first-partner", "second-partner"],
  "scopes": ["affine-context/v1", "graph-context/v1"],
  "contribute": true
}
```

Use aliases and scopes that actually exist in your service configuration; the
strings above are examples. Keep each owner offline while provisioning or
rotating its policy. Then run:

```powershell
symbiote run --config .\agent.json --run-policy .\run-policy.json --receipts .\run-receipts
```

The receipts directory must be new; it contains `events.jsonl` and `summary.json`. The foreground process publishes bounded
JSONL readiness, actions and final status. The operator's input pipe controls its
lifetime; a shutdown request or EOF stops the owned listener. Configured episode,
time and resource limits also bound the run. A hard host/process termination is
covered by explicit stale-writer recovery, not a claim of power-loss durability.

If a previous local evaluation was interrupted, `run` holds before opening its
listener or evaluating/promoting the pending work. Complete the explicit
configured-service evaluation/recovery procedure first, then start a new run
with a fresh receipts directory. Startup cannot spend an episode's unreserved
evaluation budget or count recovered old learning as a new result.

## Cognitive and trust boundaries

- **Sense:** collect actual authorized capabilities and artifact metadata.
- **Model:** compare scopes, schemas, active knowledge and durable prior outcomes.
- **Connect and exchange:** authenticate the configured identity over TLS; reserve
  request and plaintext-frame budgets before admission.
- **Verify and learn:** quarantine inert offers, evaluate against the configured
  independent local fixture, and count only fresh durable promotions as learning.
- **Contribute:** offer a useful already-validated model to another permitted
  participant. An accepted quarantine is not proof that the partner adopted it.
- **Measure:** before a contribution payload, record a value decision from the
  observed schema, inventory, authorizations and family check counts. An
  unqualified gain is not utility zero. `Connect` does not send knowledge.
  Full-fixture affine and graph checks cost more than their isolated lower
  bounds, so those offers are deferred and no payload is sent. Quarantine and
  promotion remain delivery, not benefit. Current benefit requires the exact
  causal chain, receiver ledger witness and measured later outcome.
  `partner_benefits_verified` stays 0.
- **Reassess:** retain decisions, transport/application outcomes, failures and
  learning receipts. Later choices can use this history without resetting identity.

An old replayed `PROMOTED` receipt is not another learning event. Telemetry and
successful communication alone are not learning either. Peer selection scores
are fallible rankings; they authorize neither a connection nor a certificate.
Only the operator's grants authorize access, and only the receiver's local
evaluation governs its knowledge.

The current evaluator supports explicitly declared finite affine and positive
graph families. It does not prove arbitrary remote honesty or AI behavior.
Plaintext application/negotiation counters exclude TLS cryptographic wire
overhead. Independent two-host deployment remains open under the current
single-PC authorization.

## Observation-driven learning

For the easiest local start, use `symbiote observe-demo --state state/observation`
twice. The first process chooses observations; the second uses the retained
conditional model with no source queries. No credentials or network are needed.

A configured operator source uses a separately pinned fixture, for example:

```json
{
  "schema": "symbiote.local-truth/3",
  "scope": "affine/v1",
  "family": {
    "kind": "affine",
    "width": 3,
    "outputs": [0, 1, 1, 0, 0, 1, 1, 0]
  }
}
```

This example is a deterministic laboratory source. Its complete table is private
to the adapter; the learner obtains values only through admitted observations.
Bind the file's SHA256 and matching affine schema to the service context. Add
this field to a cognition policy whose `scopes` contains `affine/v1`:

```json
"observation": {
  "schema": "symbiote.observation-permit/1",
  "scopes": ["affine/v1"],
  "max_queries_total": 8,
  "max_gf2_work_total": 100000,
  "heldout_cases": 1
}
```

Use `peers: []` and `contribute: false` for local observation alone. The configured
owner still needs its valid service configuration; the standalone command avoids
that setup. Query and work ceilings must fit the narrower run/service budgets.
The retained model is conditional on the declared stationary affine family.

## Optional normal capability contribution

The corrective runtime adds an explicitly opted-in objective. In a policy that
already enables contribution, set:

```json
"contribute": true,
"capability_contributions": true
```

The recipient must authorize `candidate.submit`; the sender must authorize the
same peer and context. Both use independently pinned `symbiote.local-truth/2`
graph task contracts. The private fixture contains the graph schema and private
edge costs, plus:

```json
"task_contract": {
  "schema": "symbiote.partial-graph-task/1",
  "training_inputs": [5, 41],
  "heldout_inputs": [6],
  "oracle_price": 100000,
  "experiment_authorized": false,
  "max_experimental_offers": 0
}
```

These encoded pairs are an example for seven nodes (`input = from*nodes + to`):
training 0→5 and 5→6, held-out 0→6. They must match the actual independently
configured graph and have disjoint training/target sets. Only prices 1 and
100000 are supported in this bounded engineering family. A price is a declared
simulated observation cost, not money or elapsed time.

Capabilities publish the pinned scope/schema/fixture identifiers and target
inputs, never edge costs or an answer table. The normal engine checks whether
the recipient's compatible inventory already certifies that target. A bounded
offer carries inert partial knowledge; the recipient independently observes the
transferred edges and decides whether to adopt. A useful fresh certificate is
reported separately from cost benefit. With the flag absent or false, the old
economic gate continues to decline the full-fixture transfers. Neither path
counts delivery as verified partner benefit.
