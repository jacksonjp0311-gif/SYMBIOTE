# Embedding the native runtime

For new integrations, use the additive v1.1
[`symbiote_runtime::engine` facade](ENGINE_EMBEDDING.md). It supplies typed
errors, caller-owned adapters/budgets/events, explicit new/open, staged learning,
conditional prediction, exact local transfer/outcomes and verified stopped-owner
lifecycle operations. The [independent consumer](../tests/consumer-engine/Cargo.toml)
imports only that surface. [Current release status](V11_ENGINE_STATUS.md) separates
source implementation from packaged qualification.

The entry points below are the preserved legacy service API. Their String-based
errors and CLI-oriented wrappers remain compatible; they are not the new facade
contract. Engine-owned stores reject generic/legacy writers without modification.

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
mechanism check. Legacy `attributed_benefit` is deprecated and always false:
its arguments cannot bind a particular outcome to a particular decision.
Use `bound_attributed_benefit` with the operational journal, receiver store,
exact exchange ID, receipt and promotion witness. It requires the recorded causal
chain, actual subsequent use and measured outcome. A plan does not grant access,
and a content digest is not verified benefit. Build the
documentation with
`cargo doc --workspace --no-deps --locked`.
Research controllers such as `transfer`, `topology_research` and
`exploration_research` are experimental, versioned receipt producers; they are
not a promise of stable study design or broad scientific applicability.

## Post-v1.0.0 receipt API correction

The tagged benefit helpers accept self-contained claims without sufficient
evidence; see [the release audit](V1_RELEASE_AUDIT.md). On corrected main,
`confirmed_benefit(&store, witness)` requires a `PromotionWitness` naming
the exact record, stored evaluation and before/after anchors.
`witnessed_mutual_research_success` takes both receipts and
both receiver store/witness pairs, with crossed identities and initial anchors.
The artifacts may differ between directions. The sender must match the stored
record's source; forwarded credit requires separately supported custody evidence.

The legacy zero-argument `receiver_benefit_verified`, `durable_benefit_verified`
and two-receipt `mutual_research_success` signatures remain for compatibility;
they are deprecated and always return false because their arguments cannot
establish evidence. Use
`retained_benefit_after_store_reopen(directory, witness)` only after closing all
writers; it opens the existing ledger and verifies retained active knowledge.
It neither initializes missing history nor establishes an OS-process restart.
The producer's `persisted_after_restart` field is informational.

Receipt schema `/2` and the v1.0 Rust signatures remain readable/compilable.
Consumers should migrate positive verification to the witnessed APIs. A source
correction alone does not qualify replacement release binaries; qualification
and public delivery are recorded separately. No crates.io publication is implied.

## Observation and feedback additions in 1.0.1

`service::observation::infer_from_source` accepts a bounded `ObservationSource`,
an explicit `ObservationPermit`, a cumulative usage counter, cancellation,
deadline and progress callback. It returns an inert conditional model and audit;
the caller separately controls persistence and adoption. The native runtime uses
the same boundary. `CompactAffineLearner` is additive; `AffineLearner` remains the
enumerating reference and its snapshot format is unchanged.

`service::feedback` records bound decisions, promotions, uses and one-time
outcomes in the existing operational journal. Measured, estimated and unknown
baselines are typed separately. Historical closed outcomes are auditable after
revocation, while positive current benefit still requires the active exact record.
`reciprocal::bound_attributed_benefit` verifies the original stored-assessment
receipt contract. Its baseline must not be replaced by the newer task-window
measurement. For that distinct claim, use `reciprocal::bound_scoped_benefit` with
the exact `Binding` and the measurement SHA returned by the replayed
`FeedbackIndex::scoped_measurement_sha256`. It accepts no caller-supplied cost
numbers and requires the current active record and actual capability-extending
use. `capture_local_execution` binds its non-cloneable counter token to the
owner's exact journal prefix and immediately following SENSE decision; a token
captured late cannot claim work from an earlier SENSE.
See [the corrective release account](CORRECTIVE_RELEASE_101.md) for task-window
accounting and experimental scope. Newly typed histories must not be opened by
an older writer that cannot validate them.

## Unreleased engine additions after v1.0.1

These APIs require the [new main implementation](ENGINE_EVOLUTION_002.md), not
the published v1.0.1 executable. `infer_from_source` keeps its existing signature
and reference query policy. The additive `infer_with_policy` accepts
`AffineQueryPolicy::RankBasis`; hints and width one retain the reference path,
and supported widths stay 1–8. See the native
`crates/symbiote-runtime/examples/independent_observer.rs` embedding for bounded
external observations, a durable freeze and source-free fresh predictions.

`OperationalJournal::open_reference` retains full-prefix serialization;
`event_prefix_sha256_reference` and `prefix_work()` expose comparison and
diagnostic boundaries. The production index is private and derived only from
validated durable history. Its counters are not rewards or a replacement for
the older reasoning cost units. `symbiote_memory::witness::LedgerWitness`
validates a bounded complete ledger snapshot without opening caller-supplied
paths; it establishes ledger consistency, not independent remote honesty.

The configured receiver channel is an explicit policy/grant opt-in rather than
a public remote execution API. Its typed history requires a writer that knows
those events; preserve backups and do not force older writers past unknown rows.
Verified outcome/capability counters remain distinct from economic benefit.
See [receiver permissions and proofs](RECEIVER_OUTCOMES.md).

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
