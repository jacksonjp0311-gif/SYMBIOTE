# Offline service policy lifecycle

A prepared service keeps one persistent identity. Certificate rotation changes
its explicitly provisioned TLS material; it does not create a new agent or erase
learning, denials, candidate receipts or idempotency history. These commands are
local operator actions. The remote protocol has no policy, regrant or execution
operation. Stop the service before changing its policy. A live writer blocks all
offline lifecycle commands.

## Review the current policy

After the service has first registered its configured state (`peers` or `serve`),
inspect the exact policy and journal head without recovering pending evaluations:

```powershell
$before = .\symbiote.exe policy-status --config .\service.json --json | ConvertFrom-Json
$before.policy_sha256
$before.journal_head_sha256
```

The result includes the public manifest and active denials. It contains paths,
identities, certificate pins, grants, context/truth hashes and budgets, never
private-key bytes. Policy inspection and the previous-policy loader do not open
the old private key. Keep the old public manifest and public CA certificate
available even if the old private key has been lost.

## Rotate or restrict a policy

Provision new certificates and private keys through the operator's existing PKI.
Write a separate `service-next.json`; retain `service.json` as the previous public
policy. Check the new certificate pin, peer identities, grants, truth bindings and
resource limits. Ordinary rotation requires both manifests to resolve to the same prepared state
directory and persistent identity. The new credentials must parse and match their declared
pin. This command never generates or renews certificates.

```powershell
.\symbiote.exe policy-transition `
  --previous-config .\service.json --config .\service-next.json `
  --expected-policy $before.policy_sha256 `
  --expected-head $before.journal_head_sha256 `
  --reason "Scheduled certificate rotation"
```

The old key need not exist. Certificate/CA/endpoint rotation is an explicit local
trust decision; peers must independently provision matching changes. Expanding a
peer's operations, artifact allowlist or contexts, adding a peer, or increasing
any resource/time budget additionally requires `--review-permission-change`.
Review those changes before supplying that flag. The receipt lists the detected permission changes. No network request runs
during the transition.

The journal is authoritative. The command does not overwrite either manifest.
After a successful transition, start with `--config service-next.json`. The old
manifest now fails the policy check, and the old peer pin is no longer accepted
by the updated endpoint. No fallback to the previous certificate is attempted.
A stable peer identity does not waive certificate authentication.

## Denial and explicit regrant

Rotation preserves durable denials, including denials of peers removed from the
new registry. Adding a matching grant in a new manifest does not clear a denial.
To regrant a denied peer that is present in the current policy, inspect a fresh
head and explicitly approve the permission change:

```powershell
$current = .\symbiote.exe policy-status --config .\service-next.json --json | ConvertFrom-Json
.\symbiote.exe peer-regrant --config .\service-next.json --peer partner `
  --expected-policy $current.policy_sha256 `
  --expected-head $current.journal_head_sha256 `
  --reason "Partner authorization reviewed and renewed" `
  --review-permission-change
```

Regrant binds the exact latest denial, current policy and journal head. Unknown
peers, stale heads and repeated regrants fail. A rejected old candidate stays
rejected; the partner must submit a new authorized request if appropriate.

## Interruption and audit guarantees

Each policy change atomically appends a checked batch to `operations.jsonl`.
Before the new epoch, the batch closes every nonterminal old-policy candidate.
An exact promotion already present in the learning history receives its original
acknowledgement. All other pending candidates are rejected without a new learning
commit. Regrant likewise closes old pending candidates for that denied peer.
These closures and the lifecycle event become visible together. A transaction
boundary binds the immediately preceding head and the SHA256 of the complete
final lifecycle intent. Only bounded terminal settlements may intervene. A
rehashed final row pointing to an older known head does not match that intent;
a valid prefix ending inside a transaction remains HOLD.

The original `operations-owner.json`, operational genesis, owner ledger and all
existing receipt bytes remain unchanged; old journal bytes remain an exact
prefix. Historical requests are checked under their recorded public policy,
without authorizing those old grants for current requests. Each scope permanently
keeps its original schema and truth hash, even after removal/readdition. A changed
meaning needs a new scope; the review flag cannot reinterpret retained knowledge. A checked transaction
requires the caller's expected old digest and head while holding the owner lock.
An intervening local operation makes that request stale.

A process interruption leaves the old journal or the complete new journal.
Inspect the old/new public manifests to determine which digest is current; do not
rewrite a marker, reset history or silently retry against a different head.
Truncated, missing or inconsistent history remains HOLD. This is a process-crash
and corruption-detection design, not protection against an operator rewriting
all local files or a guarantee against every storage/power-loss failure.

The finite journal permits at most 16 policy transitions. A configuration input
remains at most 64 KiB; its serialized public snapshot, including the CA-digest
wrapper, is at most 68 KiB. Current and historical loading enforce the same
snapshot bound. Only policy-transition rows may use up to 160 KiB for both
snapshots and audit fields. Other rows remain limited to 64 KiB, with their
existing tighter payload limits and the 4 MiB total journal limit unchanged.
This release does not implement automatic enrollment, renewal, online policy
changes, remote administration or private-key backup.

## Explicit verified restore relocation

Restoring a verified backup creates a new stopped directory with the same owner
and exact prior ledger bytes. An ordinary policy rotation rejects a different
state directory. Every unconsumed restore marker also blocks service activation
and policy/peer mutations, even if the restored tree was renamed onto an old
state path or the marker names another destination. A byte-identical relative
manifest is not activation consent. `policy-status` remains a read-only way to
inspect `activation_required` and the pending mappings. The additional `--review-relocation` flag is accepted only with
a verified restore completion mapping that binds the source path, destination
path, owner and copied file hashes. The transition opens only the restored
destination, checks its copied current policy/head, and records the mapping hash
in the new policy event. It never opens the original source Store. Reviewed
relocation may keep the same policy digest when relative manifest bytes are
identical: the new journal epoch records the one-time approval instead. The old
policy/head and exact restored metadata still must match.

Keep the old public manifest byte-equivalent, and point the new manifest at the
restored directory. Inspect/record the prior policy/head before backup; use those
anchors for the transition together with `--review-relocation`. Provision fresh
private TLS credentials separately. The restore mapping is consumed as historical
audit evidence; subsequent ordinary rotations do not silently reapply it. A
restored identity must not be activated concurrently with its original copy.

Backup relocation is currently a same-operating-system workflow. Cross-platform
state portability is not established by these tests. The original directory may
be unavailable: the prior path is verified against restore metadata without
opening or canonicalizing the original Store. The restored destination is locked
and its unchanged copied bytes verified before any policy/learning append.

A consumed marker remains immutable history. Startup verifies its original hash,
owner, source/destination and copied policy/head binding; deleting or rehashing
it does not erase that binding. Normal post-approval journal growth is allowed.
A fresh restore adds a fresh marker requiring a fresh review, including when an
old filesystem path is reused.

Nested restorations made before their source restore was approved remain HOLD;
one review cannot silently approve an unreviewed ancestor. Restore a clean
registered service baseline, approve it, then take the next backup. A generic
owner backup without registered service policy remains useful for offline
prediction, but this lifecycle does not implicitly enroll it as a service.

Local `peer-revoke` and `peer-regrant` arguments resolve an exact peer ID first,
then an alias. Thus an ID wins when an older registry contains an alias equal to
another peer's ID; use the other peer's own exact ID to select it. `connect
--peer` retains its public alias-only contract and selects that exact alias even
when it equals another peer's ID. Authenticated sessions always use exact IDs and
their own artifact grants.
