# Verified owner backups

The memory API can snapshot and restore **one offline owner store**. It does not start a service, import a private TLS key, or claim to back up an entire multi-owner research run. Restore currently requires the same operating system.

## Native commands

Stop the owner first. Both the snapshot and restore destination must be new
directories; SYMBIOTE preserves occupied destinations and refuses live, stale or
unknown writer locks. These commands require explicit paths and never start a
service.

```powershell
$saved = .\symbiote.exe backup-state --state .\owner-state --backup .\owner-backup --json | ConvertFrom-Json
# Keep the checksum outside the archive and independently from its contents.
Set-Content -LiteralPath .\owner-backup.sha256 -Value $saved.manifest_sha256 -Encoding utf8
.\symbiote.exe verify-backup --backup .\owner-backup --manifest-sha256 $saved.manifest_sha256
.\symbiote.exe restore-state --backup .\owner-backup --manifest-sha256 $saved.manifest_sha256 --state .\restored-owner
.\symbiote.exe predict --state .\restored-owner
```

Use the independently retained checksum when verifying later; do not calculate
a replacement from an untrusted or altered manifest. Add `--json` for complete
receipts, owner identity, exact byte counts and activation dependencies. Restore
keeps the owner identity and validated learning, but does not install private
credentials or activate a configured service. Follow the explicit
[service relocation procedure](SERVICE_LIFECYCLE.md) before serving from a
restored directory. Do not activate the original and restored identity together.

For the native graph experiment's known public context registry, explicitly
select and pin its bytes:

```powershell
.\symbiote.exe backup-state --state .\one-graph-owner --backup .\graph-owner-backup `
  --graph-context-registry .\graph-contexts.json `
  --graph-context-sha256 $independentlyRetainedRegistrySha256
```

The registry path and checksum must be supplied together. This opt-in does not
expand the backup to other owners, run graph experiments or import arbitrary
external files. Generic retained graph maps do not need this research registry.

## Memory API

```rust
use symbiote_memory::backup::{self, BackupOptions};

let receipt = backup::create(source, snapshot, &BackupOptions::default())?;
// Retain this digest separately from the snapshot directory.
backup::verify(snapshot, &receipt.manifest_sha256)?;
let restored = backup::restore(snapshot, &receipt.manifest_sha256, new_state)?;
```

The snapshot directory contains `backup-manifest.json` and a `files/` tree. The manifest records the owner, original path, format versions, exact byte counts and SHA256 digests, operational policy and journal head, and activation dependencies. Preserve its separately retained digest: an older valid backup must not silently replace the selected snapshot.

Before copying, backup acquires the shared maintenance gate and refuses live, stale, or unknown writer locks. It validates the identity, knowledge and operational ledgers, owner registration, maintenance audit, layout and immutable migration evidence. A completed operational evaluation must have the exact corresponding historical knowledge promotion. Later legitimate revocation does not erase that history.

Unknown sidecars, symbolic links, reparse points and descendant owner stores cause HOLD. Lock files are excluded; credential files are refused. Original ledger, marker, layout, audit and migration-backup bytes are copied unchanged. Repeated backup and restore also preserve historical restore markers unchanged.

Restore requires a new destination and a new reservation. A parent reservation and `restore-incomplete.json` prevent normal memory writers from opening partially restored state. Only successful checksum, typed-replay and history validation publish the owner. An interrupted restore remains inactive; the API never removes stale reservations or repairs evidence automatically. Preserve that directory and its reservation for operator investigation rather than trying to activate it.

Every completed restore adds an immutable `restored-owner-<digest>.json` mapping. This records the source path as metadata, the new path, owner and original manifest bytes. The old source directory can be absent. `validate_restore_mapping(new_state, prior_state, identity)` reads only the restored state, verifies its exact copied bytes and returns the mapping digest. An offline service relocation must explicitly review this mapping before activating the service or changing copied journal bytes. Review appends a policy audit epoch; when byte-identical relative manifests preserve the policy digest, that explicit relocation approval is still required. All unconsumed markers block service activation and peer/policy mutations, including a marker whose recorded destination differs after a directory move. `policy-status` can inspect the pending mappings without recovery. Ordinary rotation remains subject to its same-state rule.

Public policy, local truth fixtures, CA/certificate material and replacement private credentials remain activation dependencies. The original private key is not required. The backup does not copy external files by default or treat transferred observations as independently authenticated truth.

Generic retained `GraphMap` records support offline route predictions directly and need no research registry. The native graph experiment additionally uses its known 81-context `symbiote.graph-contexts/1` registry. A retained native research context requires an explicitly selected registry path and SHA256 through `BackupOptions.graph_context_registry`; its validated public bytes are preserved under `public-dependencies/graph-contexts.json`. The controller tree containing independent graph learners remains outside the single-owner scope and is rejected rather than partially copied.

SHA256 detects byte changes relative to the independently retained manifest. It cannot defend against an attacker replacing all state and that external digest. Filesystem durability across sudden power loss and cross-operating-system relocation are not certified by these tests.
