# Symbiotic protocol v1

SYMBIOTE v0.1.0 discovers two explicitly configured simulated partners on OS-assigned TCP loopback ports. `symbiote-protocol` supplies a real framed transport, mutually authorized sessions, a telemetry interface, and bounded observation memory. The runtime does not scan the network, attach to arbitrary agents, or infer permission from an open API.

## Wire contract and authorization

The protocol version is `symbiote/1`, the exchange format is JSONL, and the sole supported scope is `finite-boolean-v1`. Each endpoint has an operator-configured identity, allowed client identity, shared capability secret, operation allowlist, and budgets. Endpoint debug output redacts the secret. Secrets are never transmitted or written to receipts by this crate.

1. The client sends a bounded greeting containing the expected identities, version, and a fresh client nonce; it sends no authentication secret.
2. The server checks those identities and sends a fresh server nonce plus HMAC-SHA256 proof over the protocol domain, both identities, scope, and both nonces.
3. The client verifies that proof against its configured endpoint secret before sending its own HMAC-SHA256 proof. The client proof binds the server nonce, identities, scope, format, operation proposal, and requested budgets. Client/server proof domains differ.
4. The server verifies the client proof, intersects the operation allowlists, and negotiates the smaller budgets. The client rejects any agreement exceeding its authorization. Empty operation intersections fail.
5. Requests use strictly increasing IDs. Dispatch requires an active session, matching protocol version, a negotiated operation, and remaining server budget. JSON payloads remain data: the protocol contains no transferred-code or instruction execution path.

Nonces combine nanosecond system time, a per-process atomic counter, and process ID. They provide session freshness, rather than secret randomness. Proof comparison avoids early exit on equal-length values; the HMAC implementation is checked against a standard known-answer vector. The v0.1 trust boundary is an explicitly configured, trusted local host. It provides neither TLS nor independently certified cryptographic identity. The shared capability secret must be kept private by production adapters; the simulated partner credentials are test configuration. Privileged host attackers are outside this release's threat model.

## Bounds, cancellation, and recovery

| Resource | Enforcement |
|---|---|
| Network destination | Only loopback addresses accepted by client and server |
| Frame bytes | Negotiated 1,024–65,536 bytes, including newline; checked before accumulating excess input |
| Application requests | Negotiated 1–10,000; server-wide counter persists across reconnects |
| Operations | At most 32 distinct labels; intersection of explicit allowlists |
| Identities/operation labels | At most 128 ASCII letters, numbers, `.`, `_`, or `-` |
| Capability secret | 16–256 bytes; never included in `Debug` output |
| Connect timeout | Two seconds |
| Frame deadline | Configured 1 ms–30 seconds, applied to total frame receipt rather than reset by each partial byte |
| Writes | Socket write timeout, bounded frame size |
| Echo window | 2–4,096 records per partner; FIFO eviction |
| Telemetry record | At most 16,384 serialized bytes; finite confidence in `[0,1]` |

Server sockets are explicitly returned to blocking mode after accept because Windows can inherit the listener's nonblocking flag. Partial, oversized, malformed, stalled, or unauthorized input ends that session. The listener remains available for subsequent connections. Invalid traffic does not call the application handler. Client errors close the client socket and are returned to the caller.

`Client::cancel()` immediately closes its socket. `Client::revoke()` requests revocation of that session and closes it. `ServerHandle::revoke()` terminally revokes every session on that endpoint instance; active sockets are closed. `ServerHandle::shutdown()` stops accepting work, closes the active socket, and joins the server. `revoke()` on the client and `shutdown()` on the server return errors that callers should report. Dropping either object performs best-effort cleanup.

The server processes one session at a time. An unauthenticated peer can delay another client until its bounded frame deadline; this is not a high-throughput or hostile multitenant server. Trusted Rust handlers execute inline and must terminate within their application budget: transport deadlines and cancellation cannot preempt arbitrary Rust code already running. Peer revocation does not undo a previously completed application mutation. Authentication failures, transport failures, and exchange rejection are errors, not learning receipts.

## Sensor and observation state

`Sensor::collect()` is an extensible Rust interface returning validated `Telemetry` records. Each record carries partner identity, monotonic sequence, task/action, optional tool, success, resource use, optional confidence, structured feedback, optional error, and recovery signal. A telemetry observation by itself never promotes knowledge.

Each `EchoBuffer` admits one partner identity with strictly increasing sequences. It evicts the oldest record at capacity; persistent high weights cannot crowd out new observations. Its drift indicator is the absolute difference between success rates in the older and newer halves of the current window. This is a descriptive reassessment signal. It proves neither causation nor performance improvement.

## AEFL provenance and adaptation

The conceptual source is [Agentic Echo Field Location at cd432ab](https://github.com/jacksonjp0311-gif/Agentic-Echo-Field-Location/tree/cd432ab4208bbf456ac7b932ed885f2170f680ca), authored by James Paul Jackson. The inspected tree has 93 tracked files and 969,433 Git blob bytes. Its README and architecture identify v1.0; there are no release tags, and a runtime banner also says v0.6. No standalone license or SPDX declaration was found. SYMBIOTE retains pinned references and attribution and implements selected concepts independently in Rust rather than importing that Python application or altering its locked architecture.

The useful concepts are structured residue (`models/echo_record.py`, `core/residue_ingest.py`), bounded buffers (`core/echo_buffer.py`), drift signals (`core/drift_estimator.py`), and auditable telemetry (`models/monitoring_tuple.py`, `telemetry/`). SYMBIOTE deliberately changes buffer eviction to FIFO and defines task-outcome drift instead of similarity to a common field mean. These are adaptations, not numerical ports or claims of AEFL parity.

The AEFL audit found unseeded trace updates despite a configured seed, different random seeds between coupled and uncoupled controls, static weights in active buffers, unused weight/top-k helpers, and shared environmental echoes capable of inflating overlap. Its scalar coherence and topology metrics do not establish task correctness or beneficial transfer. SYMBIOTE therefore keeps overlap, communication, knowledge verification, and measured improvement as separate concepts. Prompt nudges, generated simulations, historical state, and application wrappers remain upstream references rather than active SYMBIOTE source.

## Verification

`cargo test -p symbiote-protocol` exercises real loopback sessions, mutual authorization, standard HMAC output, stale proofs and altered proposals, incorrect identity/token/version, operation enforcement without client-side checks, request replay, reconnect-resistant resource limits, oversized data, unauthenticated stalls, revocation, timeout reporting, bounded telemetry, and deterministic drift. These checks establish the controlled local protocol behavior; they do not validate external agent APIs or production network security.
