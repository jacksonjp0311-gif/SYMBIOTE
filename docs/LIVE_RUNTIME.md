# Configured SYMBIOTE runtime

The new `run` path is being qualified for the v1 candidate. It turns an explicitly
configured identity, peer registry and local evaluators into a bounded cognitive
episode. It does not require a language model. Until the new integration and
release gates pass, the published v0.5.1 remains the verified public release.

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
- **Measure:** record whether a receiver-originated reciprocal receipt verified
  a strict improvement over an equal-resource isolated control. With no receipt,
  the episode's decision is `OBSERVE` and partner benefit stays unverified.
  The value function can decline a redundant proposal; this episode does not
  use that decline to suppress an already qualified inert offer.
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
