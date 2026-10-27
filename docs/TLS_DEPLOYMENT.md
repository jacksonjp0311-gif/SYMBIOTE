# TLS for the supervised native experiment

The v0.4 development command runs the existing affine learning experiment over
real TLS 1.3 connections. The controller starts two native child processes. Each
child serves its controller and calls its own laboratory oracle using mandatory
client certificates, explicit CA roots, leaf-certificate pins and scoped grants.
The earlier `network-research` command keeps its original loopback protocol when
`--tls-config` is absent. Supplying a TLS configuration never permits fallback.

This is a controlled integration on explicit loopback endpoints. It establishes
that the process, persistence and evidence checks work through the secure API;
it does not establish external deployment security or a new learning advantage.
The oracle and judge remain trusted synthetic laboratory components.

## Prepare identities

```text
symbiote prepare-tls-state --state state/tls-demo
symbiote prepare-tls-state --state state/tls-demo --json
```

Preparation creates only three durable identity ledgers, with public IDs and state
paths in the result:

| Role | State directory | Certificate use |
|---|---|---|
| `controller` | `state/tls-demo` | Client authentication |
| `exact` | `state/tls-demo/network-tls/exact` | Server and client authentication |
| `linear` | `state/tls-demo/network-tls/linear` | Server and client authentication |
| `oracle_exact` | No private learner store | Server authentication |
| `oracle_linear` | No private learner store | Server authentication |

Preparation makes no network request, generates no certificate and creates no
learning artifact. It is safe to repeat with the same state. Existing conflicting
identities are rejected without reset. The TLS directories are separate from the
earlier experiment's `network/exact` and `network/linear` directories.

## Provision credentials and a manifest

Use your authorized certificate authority to provision five distinct keys and
certificates, with the usages above and appropriate server DNS/IP SANs. SYMBIOTE
does not generate self-signed runtime credentials, search for system roots or
enroll a certificate automatically. Keep keys and the manifest outside Git and
restrict local access to the operator. The same host account can read its own
files and child memory; these native processes are not OS security sandboxes.

The manifest authorizes a fixed role topology: the controller may call the two
learners; each learner may call only its designated oracle. Each role has a
distinct ID and certificate pin. For the first three roles, copy the exact Store
ID from preparation. Oracle IDs are explicit distinct operator labels. Certificate
subjects do not choose or override these IDs: the operator's pin-to-ID mapping
does. There is no per-run remapping to a newly discovered identity.

`certificate_sha256` is the 64-character hexadecimal SHA256 fingerprint of the
leaf certificate's DER bytes, without separators. Your provisioning tool can
provide it. For example, `openssl x509 -in exact.pem -noout -fingerprint -sha256`
prints this fingerprint with colon separators; remove the colons for the manifest.
This uses public certificate data and never prints a private key.

Save a JSON manifest next to the provisioned PEM files. This example describes
every required field; replace the bracketed IDs and fingerprints with your actual
public values. The files are resolved relative to the manifest, and absolute paths
are also accepted.

```json
{
  "schema": "symbiote.tls-deployment/1",
  "scope": "boolean-affine/v1",
  "ca_certificate": "ca.pem",
  "controller": {
    "id": "[prepared controller ID]",
    "certificate": "controller.pem",
    "private_key": "controller.key",
    "certificate_sha256": "[controller leaf SHA256]"
  },
  "exact": {
    "id": "[prepared exact ID]",
    "certificate": "exact.pem",
    "private_key": "exact.key",
    "certificate_sha256": "[exact leaf SHA256]",
    "server_name": "exact.symbiote.test",
    "bind_address": "127.0.0.1:0"
  },
  "linear": {
    "id": "[prepared linear ID]",
    "certificate": "linear.pem",
    "private_key": "linear.key",
    "certificate_sha256": "[linear leaf SHA256]",
    "server_name": "linear.symbiote.test",
    "bind_address": "127.0.0.1:0"
  },
  "oracle_exact": {
    "id": "laboratory-oracle-exact",
    "certificate": "oracle-exact.pem",
    "private_key": "oracle-exact.key",
    "certificate_sha256": "[oracle exact leaf SHA256]",
    "server_name": "oracle-exact.symbiote.test",
    "bind_address": "127.0.0.1:0"
  },
  "oracle_linear": {
    "id": "laboratory-oracle-linear",
    "certificate": "oracle-linear.pem",
    "private_key": "oracle-linear.key",
    "certificate_sha256": "[oracle linear leaf SHA256]",
    "server_name": "oracle-linear.symbiote.test",
    "bind_address": "127.0.0.1:0"
  },
  "limits": {
    "max_requests": 128,
    "max_connections": 64,
    "max_frame_bytes": 32768,
    "timeout_ms": 1000
  }
}
```

Port `0` explicitly authorizes an ephemeral local port. Readiness returns the
actual address through the owned child pipe; CA, hostname, pin and durable-ID
checks still apply. This supervised command rejects non-loopback binds. The
underlying [secure protocol API](SECURITY.md) supports explicit nonlocal library
configurations, which this experiment has not tested.

## Run and inspect

```text
symbiote network-research --state state/tls-demo --tls-config credentials/tls.json
symbiote network-research --state state/tls-demo --tls-config credentials/tls.json --receipts experiments/local/tls-network.json --json
symbiote status --state state/tls-demo/network-tls/exact
symbiote predict --state state/tls-demo/network-tls/linear
```

The runtime first checks all three prepared Store identities against the manifest.
It then loads bounded credentials and sends each child's own credential material,
public CA and narrowly scoped grants through bounded stdin. Neither private keys
nor bearer credentials appear in process arguments, readiness or receipts. Child
processes recheck their actual opened Store identity before creating learning state.
The controller retains its own identity lock until the experiment completes.

Both children learn their source context, exchange genuine observation receipts,
reject altered, duplicate and cross-context receipts, and ask their authenticated
oracle to assess a proposed model on all unseen inputs. They independently promote
validated declarative models, shut down, restart as new OS processes and predict
from durable state without additional acquisition, verification or assessment.
The controller relays the two bundles; learners do not acquire arbitrary direct
connections to one another. Receipt authenticity remains conditional on the
trusted laboratory registry behind each authenticated oracle service.

A successful `symbiote.tls-network-research/1` receipt includes the actual private
identities, child PIDs and instance nonces, certificate pins, operation counters,
retention checks and rejection outcomes. It also checks that a revoked session
cannot be used again. On an owned control-pipe command, a restarted child revokes
its controller's certificate grant, acknowledges completion and rejects a new
connection. This revocation is local to that server instance; durable revocation
and certificate rotation remain operator configuration work.

The experiment still has one four-bit affine context and makes no new paired-cost
comparison. Protocol success does not certify arbitrary received knowledge.

## Bounds, failures and tests

The manifest is limited to 16 KiB. Certificate/CA files are limited to 64 KiB and
eight certificates; private-key files to 16 KiB and one key. Child TLS bootstrap
is limited to 256 KiB, readiness to 4 KiB and control acknowledgements/logs to
4 KiB. No transferred data can provide executable code or a process command.

Per endpoint, this command accepts 64–512 application requests, 32–256 total
accepted connections, 16–64 KiB JSONL frames and 50–3000 ms absolute protocol
deadlines. Connection limits include failed and unauthenticated TLS handshakes.
The child startup, lifetime, owned-pipe cancellation and shutdown bounds remain
in force. These do not preempt a nonterminating trusted Rust handler or provide
hard real-time guarantees under kernel failure.

Failures return errors and do not produce a PASS receipt. A failed TLS handshake
does not activate a legacy server or promote knowledge. Normal owned shutdown
releases locks; abrupt process loss preserves committed ledgers and requires the
same explicit [memory recovery](MEMORY_LIFECYCLE.md) as the earlier experiment.
The legacy laboratory `--fault` injections cannot be combined with TLS mode.

```text
cargo test -p symbiote-runtime --test tls_deployed --locked
cargo test -p symbiote-runtime --test deployed --locked
cargo clippy -p symbiote-runtime --all-targets --locked -- -D warnings
```

Integration fixtures generate ephemeral test certificates using development-only
`rcgen`. Production code contains no certificate generation. Tests run actual child
processes and real TLS sockets, including same-CA certificate impersonation,
wrong CA/name/pin/identity/scope, unauthorized binds, receipt tampering, revocation,
unauthenticated stalls, retained predictions and invalid CLI combinations.
