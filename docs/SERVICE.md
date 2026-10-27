# Configured native knowledge service

The v0.5 development service exposes SYMBIOTE's retained affine and graph knowledge
over operator-configured TLS 1.3. It accepts inert candidate artifacts into durable
quarantine. Only a local operator command can evaluate and promote them, using a
pinned local truth fixture and the native finite-domain evaluators.

The service supports explicit non-loopback addresses. Its integration tests run
separate native processes over an available private IP, with no loopback substitute.
This is controlled software verification, not an external security audit or proof
that an authenticated partner tells the truth.

## Start with identities and credentials

```text
symbiote prepare-service --state node-a/state
symbiote prepare-service --state node-b/state
```

Preparation creates a persistent identity only. It does not start a listener,
create learning artifacts, issue certificates or contact another agent. Repeating
it retains the identity. Copy the returned public IDs into each operator manifest.

Provision distinct keys and certificates through your authorized CA. A node that
both serves and connects needs server-auth and client-auth usages. Server DNS/IP
SANs must match the configured TLS names. The `serve` and `connect` commands never
generate credentials, enroll an unknown certificate, load system roots or fall
back to the loopback protocol. Other explicitly owned laboratory commands have
their own ephemeral test credentials; they do not provision this service.

Protect the private files with the host's access controls and keep them outside
Git. These processes are not sandboxes against another process with the same
account's filesystem privileges. Certificate pins are SHA256 of leaf DER bytes,
written as 64 hexadecimal characters without colons. For example,
`openssl x509 -in node-a.pem -noout -fingerprint -sha256` prints the public
fingerprint; remove its separators. No private key belongs in command arguments.

## Operator manifest

Save this as `node-a/service.json`, replacing the bracketed identity/pin values and
the example private addresses with your authorized deployment. Paths are relative
to the manifest. Node B needs its own manifest with the corresponding identity,
credentials, bind address and explicitly authorized peer entry for A.

```json
{
  "schema": "symbiote.service-config/1",
  "state": "state",
  "identity": "[prepared node A identity]",
  "certificate": "node-a.pem",
  "private_key": "node-a.key",
  "certificate_sha256": "[node A leaf DER SHA256]",
  "ca_certificate": "ca.pem",
  "bind_address": "10.1.0.11:7443",
  "peers": [{
    "alias": "node-b",
    "id": "[prepared node B identity]",
    "address": "10.1.0.12:7444",
    "server_name": "node-b.example.internal",
    "certificate_sha256": "[node B leaf DER SHA256]",
    "access": [{
      "scope": "affine-context/v1",
      "operations": [
        "capabilities", "knowledge.list", "knowledge.read",
        "knowledge.predict", "candidate.submit", "candidate.status"
      ],
      "artifacts": ["*"]
    }]
  }],
  "contexts": [{
    "scope": "affine-context/v1",
    "schema_fingerprint": "e3efcffd628a1bca9c5e277175c179bb15083107aa9915423bf5c45000761047",
    "truth_fixture": "affine-truth.json",
    "truth_sha256": "[SHA256 of the exact local fixture file bytes]"
  }],
  "limits": {
    "max_requests": 64,
    "max_connections": 64,
    "max_frame_bytes": 32768,
    "timeout_ms": 500,
    "lifetime_ms": 60000,
    "per_peer_requests": 64,
    "max_offers": 16,
    "max_offer_bytes": 16384,
    "model_work": 200000
  }
}
```

The shown schema fingerprint is the native three-bit affine input schema: unsigned
inputs `0..7`, least-significant-bit coordinate order. It is not a truth assertion.
Other native fingerprints come from `affine_schema_fingerprint(width)` or
`graph_schema_fingerprint(schema)` in `symbiote-memory`.

Each peer entry is an operator-owned pin-to-ID mapping and an explicit endpoint.
It permits only its listed operations in exact contexts. `artifacts` accepts exact
IDs; `"*"` explicitly authorizes all artifacts in that context. There are no partial
globs. The access entries constrain inbound requests and outbound calls to that
peer. Registry entries are never contacted automatically. `connect --peer` selects an
exact alias, preserving the existing outbound contract. Local `peer-revoke` and
`peer-regrant` accept an ID or alias and prefer an exact ID on collision.
Authenticated sessions use exact IDs and their own artifact grants only.

The first configured service/client command registers the original policy digest,
bound to the prepared identity, canonical manifest and CA bytes. It may initialize
the knowledge and operational ledgers. Unapproved manifest edits fail HOLD. Durable
peer denial is an additional override that survives restart and certificate
rotation. [Offline lifecycle commands](SERVICE_LIFECYCLE.md) append checked policy
history and explicit reviewed regrants while preserving the original owner marker
and receipt bytes. There is no automatic renewal or silent trust replacement; do
not delete journals to change policy.

For query/export-only contexts, set both `truth_fixture` and `truth_sha256` to
`null`. Such a context cannot promote an offered artifact through evaluation.

## Local truth is explicit

An example `affine-truth.json` for the displayed schema is:

```json
{
  "schema": "symbiote.local-truth/1",
  "scope": "affine-context/v1",
  "family": {
    "kind": "affine",
    "width": 3,
    "outputs": [0, 1, 1, 0, 0, 1, 1, 0]
  }
}
```

Hash the actual saved file, including its whitespace. PowerShell:
`(Get-FileHash -Algorithm SHA256 .\affine-truth.json).Hash.ToLowerInvariant()`.
On Linux use `sha256sum affine-truth.json`; on macOS use
`shasum -a 256 affine-truth.json`.

Affine fixtures must cover every input in the declared width. A graph fixture uses
`"family":{"kind":"graph","schema":GRAPH_SCHEMA,"costs":[...]}`, where the
complete edge-cost list follows the exact schema edge order. Durable native graphs
are bounded to 2–12 nodes, 56 edges and positive integer costs 1–9. Offered edge
observations are checked against these local values. Native conservative route
certificates are then compared with routes from the complete local graph.

These fixtures are trusted because the operator chose them, not because they were
received from an authenticated peer. Digests bind exact bytes; they are not digital
signatures. Graph observation envelopes created after local checking explicitly
identify the local fixture as their authority. No peer-supplied evaluator, expected
label, authority URL or raw `TrialEvidence` is accepted.

## Serve, discover and query

```text
symbiote serve --config node-a/service.json
symbiote peers --config node-b/service.json
symbiote connect --config node-b/service.json --peer node-a --request capabilities.json
```

`peers` lists the explicit registry and durable deny state with zero network
requests. It does not scan or attach to an agent. Node B's peer alias in its own
manifest must be `node-a` for the command above. `connect` makes one typed RPC and
exits. It cannot accept an endpoint or command from a received artifact.

`capabilities.json`:

```json
{
  "schema": "symbiote.service-request/1",
  "scope": "affine-context/v1",
  "request_id": "inspect-capabilities-1",
  "body": { "operation": "capabilities" }
}
```

Use the same envelope for these native bodies:

| Body | Result |
|---|---|
| `{"operation":"knowledge.list"}` | Authorized artifact metadata, with `next_after` pagination |
| `{"operation":"knowledge.list","after":"ARTIFACT_ID"}` | Next metadata page |
| `{"operation":"knowledge.read","artifact":"ARTIFACT_ID"}` | Inert retained record and digest |
| `{"operation":"knowledge.predict","artifact":"ARTIFACT_ID","input":3}` | Conditional affine prediction, graph route/cost or abstention |
| `{"operation":"candidate.status","candidate":"CANDIDATE_SHA256"}` | The submitting peer's quarantined/evaluation status |

A graph query encodes `from * nodes + to`. Prediction responses preserve the finite
family's conditional status and never authorize a physical-world certificate.
Scope, schema and per-artifact permissions are enforced again in the handler after
TLS authentication. An authorized certificate cannot read unrelated contexts.

`serve` prints a bounded public readiness record and a final stop receipt. The
operator can send `{"command":"shutdown"}` plus newline on its owned stdin.
Owner-pipe EOF cancels the service; its configured lifetime also stops it. The
application never treats remote payload text as this owner-control channel.

## Quarantine and evaluate

To submit an artifact, use a `candidate.submit` body containing
`"offer":{"record":KNOWLEDGE_RECORD,"training_inputs":[...]}`. `record` uses the
native `KnowledgeRecord` schema and only the supported `affine` or `graph-map`
payload grammar. Unknown fields and executable expressions fail. Training inputs
are sender declarations, not attestations about an arbitrary agent's training.
Local affine validation checks the complete fixture, including those inputs.

Submission returns `QUARANTINED`, a candidate digest and `promoted:false`. The
canonical received record and claimed provenance are retained separately from the
actual certificate-authenticated sender. A telemetry observation or quarantine
receipt is not proof of learning.

Stop the serving process before these local operator commands:

```text
symbiote evaluate --config node-a/service.json --candidate CANDIDATE_SHA256
symbiote peer-revoke --config node-a/service.json --peer node-b --reason "operator withdrew authorization"
```

The same owner lock prevents offline commands from racing a live service. Evaluation
checks the pinned fixture and the native coverage/regression gate. It promotes
only a supported correct model that extends validated coverage or meets the
existing equal-coverage cost gate. This service charges validation work and makes
no paired cost advantage claim. An already retained equivalent model is reported
as retained, not new learning. Counterexamples produce a durable `REJECTED` receipt
and a failing CLI exit status.

Local artifact IDs are namespaced by the authenticated sender, exact context and
schema. Upstream artifact IDs, revisions, record digests and claimed origin stay
in quarantine and provenance. They cannot select a different sender's local
identity or bypass revision/alias history. Peer denial also blocks future local
evaluation of that peer's pending offers. It does not revoke previously validated
knowledge; that is a separate knowledge decision.

Denial commits before interrupted evaluation recovery. A still-uncommitted intent
from that sender is rejected without promotion; an already committed matching
record retains its original historical receipt. If every configured peer is
denied, `serve` reports `STOPPED` with `no-authorized-peers` and opens no listener.

## Durability and limits

`operations.jsonl` is an owner-bound typed hash-chain journal, separate from the
learning ledger. `operations-owner.json` records its registration before first
creation. A missing registered journal, missing registration, malformed event,
identity mismatch or altered policy produces HOLD. An interrupted first registration
also holds. Deleting all state or rewriting both registration and history is
outside this cooperative filesystem integrity model.

Once operational registration exists, a missing knowledge ledger also produces
HOLD. The service does not replace lost validated experience with an empty file.
Completed evaluations must match their exact historical learning promotion.
Restoring only the knowledge ledger to a valid older prefix therefore produces
HOLD while the surviving operational journal records the missing commit.
Legitimate later revocation or a newer revision preserves that historical match.
Cached promotion replies describe the original operation; use `knowledge.list`
or `knowledge.read` to inspect current active knowledge.

The idempotency binding includes actual sender, operation, scope, request ID and
canonical request hash. Identical retries return the original saved quarantine
receipt; different content with the same key fails. Local evaluation writes its
complete promotion intent and planned reply before changing the learning ledger.
Recovery commits an unchanged pending intent once, or acknowledges a matching
already committed record. Conflicting/advanced state or changed truth is HOLD.
It preserves the original `promoted:true` reply after a lost acknowledgement.

Abrupt process loss requires explicit native `recover --state DIR`, which verifies
dead ownership and preserves journal/learning bytes. It never silently deletes
unknown locks. See [memory lifecycle](MEMORY_LIFECYCLE.md).

| Resource | Supported bound |
|---|---|
| Registry | 32 peers and 8 exact contexts |
| Configuration / request file | 64 KiB each |
| Certificate/CA / private-key PEM | 64 KiB / 16 KiB |
| Transport requests / accepted connections | 1–1024 each per process, including failed handshakes |
| Frame / protocol timeout | 1–64 KiB / 50–3000 ms; offer plus response headroom must fit |
| Lifetime | 1–600 seconds per service process |
| Durable offers | 1–64; up to 32 KiB per canonical complete offer |
| Operational journal | 4 MiB, 4096 records, bounded typed bodies/replies |
| Reasoning work | 1024–1,000,000 declared units; native graph queries charge 1024, affine queries 1 |

Request, connection, per-peer and query-work counters are process-local. Restart
does not reset durable offer, revision, deny or idempotency history. Limits bound
the admitted work; they do not provide comprehensive denial-of-service protection
or preempt arbitrary native code or kernel filesystem calls. Handlers implement
only fixed finite algorithms and bounded local persistence.

```text
cargo test -p symbiote-runtime --test service --locked
cargo clippy -p symbiote-runtime --bin symbiote --test service --locked -- -D warnings
```

The tests exercise actual private-IP TLS service/client processes, certificate and
permission failures, quarantine without execution, affine/graph counterexamples,
durable denial, budget exhaustion, cancellation and restart. An authorized fixture
proxy withholds a committed reply, the owned service is killed and explicitly
recovered, and retry returns the same durable receipt. Separate controlled durable
cutpoints before and after knowledge commit check promotion-intent reconciliation
and preservation of the original lost-acknowledgement result. No result establishes
general intelligence, arbitrary remote truth or production security certification.


Offline certificate rotation, policy restrictions and reviewed peer regrant are
documented in [Service lifecycle](SERVICE_LIFECYCLE.md). They preserve the
original owner/genesis and append policy history; manual manifest replacement
without a matching local transition continues to fail closed.
