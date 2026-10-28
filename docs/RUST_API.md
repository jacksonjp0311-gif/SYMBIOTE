# Embedding the native runtime

The public v1.0.0 runtime and subsequent main corrections are qualified separately.
They use the same owner,
authorization and evaluation boundaries as the command-line program. It has no
language-model dependency. No crates.io publication is implied; use the pinned
workspace source.

## Operational entry points

`symbiote_runtime::service` exposes the configured owner operations. Their paths
refer to operator-provisioned files. Errors return `Result<_, String>`; they do
not reset identity, relax grants or initialize a replacement for corrupt state.

| Function | Purpose |
| --- | --- |
| `prepare` | Prepare one new private owner identity |
| `run_with_cancel` | Drive a finite configured cognitive episode with explicit host cancellation; never reads global stdin |
| `run` | CLI owner-control wrapper; reads the process input pipe |
| `serve` | Foreground configured knowledge listener |
| `peers`, `connect` | Inspect the explicit registry or perform one granted request |
| `evaluate` | Evaluate a quarantined candidate against local pinned evidence |
| `peer_revoke`, `peer_regrant` | Explicit persistent denial and reviewed regrant |
| `policy_status`, `policy_transition` | Inspect or explicitly advance an offline policy epoch |

The reusable reasoning, protocol and memory types are documented in their Rust
sources. `symbiote_reasoning::symbiosis` (`decide`, `plan`, `reconcile`) and
`symbiote_memory::reciprocal` are part of that surface.
`symbiote_runtime::reciprocal::redundant_affine_exchange` runs the width-bounded
mechanism check. `attributed_benefit` is true only when that plan sent knowledge
and `confirmed_benefit` reseals the receipt against the receiver ledger. A plan
does not grant access, and a content digest is not verified benefit. Build the
documentation with
`cargo doc --workspace --no-deps --locked`.
Research controllers such as `transfer`, `topology_research` and
`exploration_research` are experimental, versioned receipt producers; they are
not a promise of stable study design or broad scientific applicability.

## Post-v1.0.0 receipt API correction

The tagged benefit helpers accept self-contained claims without sufficient
evidence; see [the release audit](V1_RELEASE_AUDIT.md). On corrected main,
`receiver_benefit_verified(&store, witness)` requires a `PromotionWitness` naming
the exact record, stored evaluation and before/after anchors. `confirmed_benefit`
also validates that witness. `mutual_research_success` takes both receipts and
both receiver store/witness pairs, with crossed identities and initial anchors.
The artifacts may differ between directions. The sender must match the stored
record's source; forwarded credit requires separately supported custody evidence.

The flag-only `durable_benefit_verified` method is removed. Use
`retained_benefit_after_store_reopen(directory, witness)` only after closing all
writers; it opens the existing ledger and verifies retained active knowledge.
It neither initializes missing history nor establishes an OS-process restart.
The producer's `persisted_after_restart` field is informational.

Receipt schema `/2` remains readable, but these Rust signatures intentionally
change. Consumers of pinned source must update their calls. Do not publish this
as a compatible patch without resolving that API break. No crates.io package or
replacement binary release is published by this audit.

## Cancellation and ownership

Pass an `Arc<AtomicBool>` to `run_with_cancel`; the host may set it with release
ordering to stop admission and close the owned listener. Configured request and
episode deadlines still apply to work already admitted. Keep one live writer
per owner directory. The embedding host supplies private credentials, supported
local truth fixtures, a fresh receipts directory and all authorization.

The runtime writes compact progress events to standard output as well as the
receipt files. Embedding hosts should route that output through their normal
process logging. Use `run_with_cancel` in a long-lived host; the CLI `run` wrapper
may retain its blocking stdin watcher until the pipe or process closes.

Finite owner policies bound episodes, duration, requests, model work and declared
plaintext bytes. Hosts invoking protocol callbacks must honor their absolute
deadline and cancellation argument; arbitrary trusted Rust code cannot be
preempted by a socket timeout. TLS wire overhead is separate from plaintext
application accounting.

## API and format window

The candidate is tested first on Windows x86-64 with Rust 1.98.1. Current stable
cross-platform CI and public binary delivery are separate required checks;
unexecuted platforms or earlier compilers are not inferred supported. A declared
minimum compiler is set only after the actual candidate builds on it.

Configuration, wire and receipt schemas carry explicit version strings. Unknown
schemas, fields or typed ledger events fail closed. A compatible release may
add documented operations or optional receipt information; consumers must still
validate the schema and evidence fields required for their claim. Old records
retain their exact bytes. New strategy-bearing histories require explicit
layout-2 migration and cannot be downgraded by deleting unfamiliar rows.

The release compatibility table and qualification receipts determine the final
supported window. Backup/restore remains stopped-owner, same-OS, local-filesystem
operation with an external manifest digest. Independent two-host deployment,
cross-OS restoration, network-filesystem locking, host power-loss durability and
automatic credential renewal remain unqualified.
