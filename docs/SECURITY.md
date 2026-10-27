# Security boundaries and the TLS agent API

Status: controlled engineering verification for the v0.3 development line. The
TLS backend is a native library surface; it does not automatically attach the
runtime to external agents. Successful transport tests are not an external
security audit or evidence of production readiness.

## Two explicit protocols

The original `symbiote/1` protocol remains restricted to configured loopback
endpoints. Its shared-capability authentication and research experiments are
unchanged. It has no confidentiality claim and is not silently upgraded or used
as a fallback for nonlocal connections.

`symbiote/2` is a separate TLS 1.3 API in
`symbiote_protocol::secure`. It permits nonlocal addresses only when the caller
supplies the bind address or endpoint, credentials, trust anchors, certificate
pins and grants. It performs no network scanning, public discovery, credential
generation, default system-root loading or trust-on-first-use enrollment.

## Authentication before application data

Both sides use Rustls with its ring crypto provider. TLS 1.3 is explicitly selected
in the configuration builder, and the required ALPN value is `symbiote/2`.
Resumption, session tickets and early data are disabled. There is no accept-all
certificate verifier, custom signature implementation, or plaintext fallback.

1. The client validates the server certificate path, validity and configured DNS
   name or IP SAN against the caller's explicit CA store. It also requires the
   expected SHA256 fingerprint of the leaf certificate.
2. The server requires a valid client certificate with client-auth usage under its
   configured CA store. A valid CA signature alone grants no application access:
   the leaf certificate fingerprint must appear in the operator's peer registry.
3. That registry binds the fingerprint to one agent identity and a separate
   operation list for each allowed scope. IDs supplied in JSON cannot override
   the identity associated with the authenticated certificate.
4. Only after TLS, ALPN and pin checks succeed does the client send JSON. The
   application handshake agrees on `symbiote/2`, both identities, one exact scope,
   JSONL, operation intersection and bounded frame/request limits.
5. Each application request must carry the negotiated scope and the next sequence
   number. Version, identity, scope, capability or sequence violations end the
   session before dispatch.

Pin checks occur after the standard TLS handshake, before application JSON. Thus
the public client certificate may be presented to a PKI-valid server before a pin
mismatch is detected. Private keys are never transmitted. This design uses
ordinary Rustls PKI validation and an additional application authorization pin;
it does not substitute a custom verifier that skips chain or name checks.

Authentication establishes an authorized channel, not the truth of a partner's
claims. Knowledge still needs its own applicability contract, evaluator,
provenance, promotion gate and rollback history.

## Native interfaces

| Interface | Purpose |
| --- | --- |
| `TlsIdentity::from_pem` / `from_pem_files` | Load bounded explicit certificate chains and exactly one private key |
| `TlsClientConfig::new` | Bind a client identity, its certificate/key and explicit server CA roots |
| `SecurePeerGrant` | Map a client certificate pin to an identity and scope-specific capabilities |
| `SecureServerConfig::new` | Validate explicit bind address, identity, mandatory client trust, grants and limits |
| `spawn_secure_server` | Start the controlled TLS listener with a trusted native handler |
| `SecureEndpoint` | Declare address, TLS server name, expected server ID/pin, scope, operations and limits |
| `SecureClient::connect` / `call` | Establish the authenticated session and exchange inert structured values |
| `SecureClient::revoke` / `cancel` | Close or cancel the current session |
| `SecureClient::cancellation_handle` | Interrupt a blocked client I/O operation from another thread |
| `SecureServerHandle::revoke_peer` / `shutdown` | Revoke a peer for this server instance or stop the listener |

All are exported through the protocol crate as well as its `secure` module.
Certificate pins are 64 hexadecimal SHA256 characters over the complete leaf DER
certificate. Pins are public identifiers, not shared secrets. No PEM private key
is serialized or included in `Debug` output.

The separate `fresh_capability()` helper generates 32 OS-random bytes, encoded as
64 hexadecimal characters. It is suitable for authorized local process channels;
it does not derive capabilities from timestamps, process IDs or fixed seeds.
It never falls back to weaker randomness if the operating-system source fails.

## Enforced resource limits

| Resource | Enforcement |
| --- | --- |
| TLS handshakes/connections | `max_connections`, 1–10,000 accepted sockets per server instance; default 64. Failed and unauthenticated attempts count before TLS processing. Exhaustion closes the listener. |
| Application requests | `max_requests`, 1–10,000 globally per server instance; default 256. Reconnecting cannot reset it. |
| JSONL frames | 1,024–65,536 bytes including newline; default 16,384. Serialization is bounded before writing; excess inbound data is rejected before accumulation. |
| Handshake/frame deadlines | Absolute deadline of 1 ms–30 s, default 2 s. Each underlying TLS socket read/write uses the remaining time; partial bytes cannot reset it. |
| Credentials | Certificate/CA PEM at most 65,536 bytes and eight certificates; private-key PEM at most 16,384 bytes and one key. |
| Authorization registry | At most 128 peers, 16 scopes per peer and 32 operations per scope. Duplicate identities, pins or operations are rejected. |
| Active transport work | One connection/session is serviced at a time; additional accepted connections are never spawned into unbounded worker threads. |

`max_connections` is a server-owned lifetime budget; a client's copy of
`SecureLimits` cannot increase it. Negotiated application limits cannot exceed
either side's proposal. Request and connection counters are inspectable on the
server handle. These limits bound the work admitted by this implementation; they
do not provide comprehensive network denial-of-service protection or replace an
operator's firewall, admission policy and deployment monitoring.

Cancellation closes the underlying socket and is checked before and after I/O,
including when an operating system returns buffered bytes during shutdown.
Revocation accepts only configured peer IDs, so the revocation set is bounded by
the operator's peer registry. It closes an active matching socket and prevents
subsequent authorization checks from admitting more work. Requests admitted
before revocation, including a handler not yet entered or already running, may
run or complete after `revoke_peer` returns. Transport revocation does not
preempt native handlers or roll back completed or in-flight application mutations.

## Operator responsibilities and remaining limits

- Provision a private CA and distinct role-appropriate certificates through the
  operator's approved process. The library does not acquire credentials or infer
  consent from a reachable API. All test certificates are generated in memory by
  a development-only fixture dependency and are not production credentials.
- Protect private keys and maintain the explicit pin/grant registry. Certificate
  rotation requires an updated configured pin; there is no automatic enrollment
  or silent pin replacement.
- Peer revocation is terminal for the current server instance. Persistently
  revoked peers must also be removed from the operator's durable configuration
  before a restart. The transport does not claim durable grant storage.
- Trusted Rust handlers execute synchronously and must terminate under their own
  application budget. TLS/socket deadlines cannot preempt arbitrary native handler
  code. Process isolation or a suitable controlled worker boundary is needed for
  untrusted or potentially nonterminating work.
- TLS sequence protection and per-session request IDs do not deduplicate an
  authorized business request repeated in a new session. Applications must enforce
  their own idempotency, artifact revisions and mutation authorization.
- Transferred payloads are inert JSON values. This module has no code, shell,
  instruction or plugin execution path. A trusted application handler must preserve
  that boundary rather than treating received text as execution authority.
- The current automated tests use real TLS sockets on loopback. Accepting explicit
  nonlocal addresses is implemented, but real external deployment, certificate
  operations, high concurrency and hostile public-network workloads remain
  unverified. No production security certification is claimed.

## Dependency choice and verification

The release dependency audit used cargo-audit 0.22.2 and RustSec database commit
`3279c99911354c400e1d41e47c7d60e39258b147` (2026-10-26). It reported zero known
vulnerabilities and no advisory warnings for this lockfile. The
[machine-readable audit](../experiments/v0.3/dependency-audit.json) is a dated
check of published advisories, not proof that dependencies contain no defects.

The production addition is `rustls` 0.23.46 with default features disabled and
only `ring`/`std` enabled. PEM decoding uses the maintained `PemObject` API in
`rustls-pki-types` 1.15.1 through Rustls's existing re-export, with no separate PEM
dependency. Every parsed section is checked for its permitted credential type;
mixed types, unknown labels, malformed boundaries and extra private keys fail
closed. `rustls-pemfile` was removed before release because
[RUSTSEC-2025-0134](https://rustsec.org/advisories/RUSTSEC-2025-0134.html) identifies
it as unmaintained and recommends this replacement. The crate explicitly selects
TLS 1.3 even if another dependency later re-enables Rustls's additive TLS 1.2
feature. There is no HTTP framework, async executor, system certificate discovery,
AWS-LC or OpenSSL dependency in this backend.

ring avoids AWS-LC's CMake build but still includes a native C/assembly build.
Source builds need the toolchain supported by ring; end users installing a
prebuilt release do not compile it. `rcgen` 0.14.10 is development-only for ephemeral
certificate fixtures, with default features disabled and `crypto`/`ring`/`pem`
enabled. It is not linked into release binaries. The lockfile includes optional,
development and target-specific packages; a lockfile count is not a runtime
dependency count. Inspect the actual production graph with:

```text
cargo tree -p symbiote-protocol --edges normal,build
cargo test -p symbiote-protocol --locked
cargo clippy -p symbiote-protocol --all-targets --locked -- -D warnings
```

The TLS tests exercise real mutual authentication, server/client pin failures,
wrong CA and name, missing or wrong-purpose client certificates, expiry, ALPN,
identity/scope/capability/sequence violations, lifetime request and handshake
budgets, oversized input/output, cancellation, revocation, stalls and slow partial
frames. Existing loopback-v1 and scoped research guards remain in place.

Primary implementation references: [Rustls 0.23.46](https://docs.rs/rustls/0.23.46/rustls/),
[configuration builders](https://docs.rs/rustls/0.23.46/rustls/struct.ConfigBuilder.html),
[PEM parsing](https://docs.rs/rustls-pki-types/1.15.1/rustls_pki_types/pem/trait.PemObject.html), and
[development certificate generation](https://docs.rs/rcgen/0.14.10/rcgen/).
