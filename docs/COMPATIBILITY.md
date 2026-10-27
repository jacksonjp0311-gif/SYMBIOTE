# Compatibility and release policy

The 0.x releases are research previews. Public Rust APIs can change between minor
versions; a stable v1.0 API is a separate acceptance gate. Native releases include
the lockfile used by their build and publish platform-specific ZIPs and SHA256SUMS.
The command `symbiote --version` identifies the installed implementation.

Historical Genesis and affine ledger serializers remain intact. New graph
knowledge uses a distinct typed promotion event. Old binaries cannot read new
event variants and must not run concurrently with a newer writer. Upgrade only
after stopping old processes. Keep a backup, run `inspect-state`, then `migrate`
to register the layout with byte-preserving backups. Migration does not relabel
old evidence or promise downgrade compatibility for newly written graph events.

`symbiote/1` and `symbiote/2` are separate protocols. The runtime uses TLS only
when explicitly configured; a TLS failure never falls back to plaintext. Unsupported
versions, scopes and payload grammars fail. Durable artifacts retain their own
schema fingerprints and stationary context; different graph topology, edge order
or cost bounds require a different schema. Drift requires explicit reassessment
and revocation rather than silently editing old observations.

JSON receipts declare a schema version. Consumers should inspect that version
and the implementation release, tolerate neither missing required evidence nor
an unrecognized promotion policy, and preserve original receipts. A new version
number does not convert a conditional laboratory result into a general claim.

Before stable v1.0, the project must document the supported Rust API, protocol,
state-format migration and platform window, pass the declared failure campaigns,
and demonstrate the complete bounded learning cycle in multiple controlled
environments. See [the roadmap](ROADMAP.md).
