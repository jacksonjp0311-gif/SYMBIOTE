# Embedding SYMBIOTE

Status: additive v1.1 target API; qualification is governed by
[V11_ENGINE_SUPPORT_CONTRACT.md](V11_ENGINE_SUPPORT_CONTRACT.md). The existing
String-based interfaces remain available. No new crate or runtime dependency is
required. Import `symbiote_runtime::engine`.

## Independent consumer

[tests/consumer-engine](../tests/consumer-engine/Cargo.toml) is a separate Cargo
workspace with its own lockfile and only a path dependency on `symbiote-runtime`.
Its host code imports only documented engine types. Run it with a **new absolute**
output directory:

```text
cargo run --locked --manifest-path tests/consumer-engine/Cargo.toml -- --out ABSOLUTE_NEW_DIRECTORY
```

The equivalent in-workspace example is `embedding_consumer`. The host writes
`acceptance.json` and one final JSON line. It demonstrates two owners, staged
inference/evaluation/retention, exact predictions, cancellation isolation, writer
exclusion, source-off reopen/reuse, revocation and verified checkpoint/restore.
Host presentation is separate from the library. The library does not read stdin,
print, change cwd/environment, exit the process, or spawn background work.

## Explicit lifecycle and authority

`Engine::initialize(path, config)` requires a new absolute directory whose parent
exists. It never replaces existing state. `Engine::open(path, expected_owner,
config)` requires the complete existing owner, knowledge and operational history;
it never initializes a missing ledger. The same owner and immutable configuration
policy digest must match. Source/evaluator changes need explicit operator review;
changing configuration cannot silently reinterpret retained knowledge.

New engine owners append the native identity receipt `EngineOwnerRegistered`
at receipt 1, with namespace `embedding-engine/v1` and minimum writer capability
`symbiote-engine-writer/1`. Generic and older writers refuse that owner instead
of appending legacy learning into it. Unmarked development prototypes return
`Hold` on open, with no automatic migration. Checkpoints preserve the marker;
it is writer-format admission metadata, not authentication or learning credit.

Construct `EngineConfig::new(authorized_sources)`. Each `SourceDescriptor` pins
source identity, scope, epoch, opaque commitment and width. An adapter's claim
alone is not authorization: its descriptor must match the caller's configuration
before and after each callback. The commitment binds declared provenance; it is
not proof that an arbitrary source is honest or stationary.

The host implements `ObservationSource` and `EventSink`. The source receives an
`ObservationRequest` with exact input, sequence, expected descriptor, cancellation
and absolute deadline. It returns one structured binary `Observation` or typed
`SourceError`. The sink receives typed `EngineEvent` values and may fail explicitly.
`NoopSink` intentionally discards presentation events.

Callbacks are cooperative native Rust code. The engine checks cancellation and
deadlines around them, but cannot preempt a callback that blocks, exits or ignores
its contract. Use an explicitly supervised adapter process for hard termination.

## Learning and exact retention

The decomposed path is:

```text
observe_infer(source, options, sink) -> opaque Candidate
evaluate(candidate, sink)          -> opaque EvaluatedCandidate
retain(evaluated, sink)            -> LearningReceipt
```

`run_episode` composes the same steps. `EpisodeOptions::bounded(source)` provides
finite defaults; the host may narrow query, GF(2), duration and held-out bounds.
`AffineQueryPolicy::Reference` retains finite-domain scanning; `RankBasis` is the
existing exact rank policy. No hint supplies observations or prunes support.

The shared inference helper, `CompactAffineLearner`, native `assess` and
`KnowledgeStore` implement these operations. Observations and candidate evaluation
do not promote knowledge. Opaque candidate seals bind owner, policy, episode and
knowledge head. A seal from another engine cannot abort that owner's pending
work or authorize retention. Serialized artifacts are not seals.

Affine widths remain 1–8. Width one active identification consumes its complete
two-input domain, leaving no disjoint held-out observation; that learning path
returns typed `Uncertain` and does not promote. The gate is not weakened to make
this case pass. Retained affine predictions remain conditional on the finite,
stationary declared family and authorized observations.

An active exact model can be reused with zero source calls. Revoked models are
not automatically reacquired. Each new episode requires an explicit host call;
per-episode allowances are not an automatic background learning lease.

`export_artifact(id)` returns inert exact record bytes and their digest.
`Artifact::from_json` performs bounded decoding, not evaluation. `evaluate_artifact`
uses the receiver's own authorized source before native assessment. Receiver
retention preserves the incoming `KnowledgeRecord`, including provenance, exactly;
its independent observation/evaluation audit is stored separately. No transferred
code or instruction is executed. Local exchange grants and causal reconciliation
are exposed separately by `engine::exchange`.

## Prediction, inspection and counters

`predict(artifact_id, input, sink)` commits actual use and returns a typed
`Prediction`: answer, basis, exact record/knowledge anchor and `Applicability`.
The basis distinguishes observed values, conditional affine inference and explicit
abstention outside the domain. Missing models are `Uncertain`; revoked models are
`Revoked`. An unfinished episode must be completed or explicitly closed before
prediction/revocation.

`inspect` reports current identity, policy, active artifacts, pending episode,
cancellation and actual cold replay GF(2) work. `historical_outcomes` returns
completed learning receipts; it does not grant economic credit or assert current
membership. `counters`, `counter_anchor` and `counters_since` provide versioned,
ledger-derived role and history windows. Historical completion and current
validity are separate. Unknown economics do not become measured benefit.

`resources()` reports per-instance knowledge I/O, native capacity and operational
prefix work without reading files or invoking a source. Byte categories overlap:
submitted writes, completed writes and committed publication are not additive.
Physical ledger bytes and the exact canonical rewrite size are separate. These
are application counters, not physical disk activity or whole-process CPU/peak
memory. Certain native capacity exhaustion is typed `BudgetExhausted`; exact
frame admission and operating-system failures may still return `Storage`.

## Errors, close and rollback

`EngineError.kind` is non-exhaustive. Match its typed categories, including
`Malformed`, `Authorization`, `IncompatibleSchema`, `Uncertain`, `Contradiction`,
`Revoked`, `BudgetExhausted`, `Cancelled`, `DeadlineExceeded`, `Storage` and `Hold`;
never parse `diagnostic` text. Additional future categories require a fallback arm.

A sink failure before retention prevents promotion. `CommittedEventSink` includes
an exact `committed` knowledge anchor when persistence succeeded but notification
failed. Inspect that state; do not blindly repeat acquisition. Read, evaluation
and retention failures do not manufacture completion receipts.

`cancellation()` returns an owner-local token; `cancel()` requests cancellation.
`close()` releases that owner's writers and returns `ClosedEngine`. Explicitly
abandoned, known uncommitted candidates are recorded as failed. A dropped process,
panicking callback, incomplete inference or unmatched committed knowledge can
leave a typed HOLD. Opening never deletes rows, clears stale locks or invents the
missing completion. Preserve the files and inspect them; restore a separately
pinned stopped-owner checkpoint when exact repair is unavailable.

`Engine::recover_stopped_owner(path, expected_owner)` only removes writer locks
whose recorded process the existing maintenance layer proves dead. A live writer
returns `OwnerBusy`; unknown liveness returns `Hold`. It does not modify ledgers,
terminate processes, finish interrupted work or reset identity. A subsequent
`open` still validates the committed history and may return `Hold`.

Only `ClosedEngine::checkpoint(new_snapshot_path)` calls the existing verified
backup lifecycle. The closed history must not advance before snapshotting.
Retain the returned manifest SHA independently. `Engine::restore(checkpoint,
new_destination, config)` verifies that pin, copied owner and restore mapping
before opening. It starts no network and explicitly reports that rollback loses
later learning. Restoration is same-OS/local-filesystem support; independent host,
power-loss and network-filesystem durability are not qualified. Writer exclusion
is per owner directory; the host must not treat active original/restored forks
with the same identity as independent agents.

Before creating a restore destination, the engine verifies the pinned backup
manifest, original source location, owner and configuration policy. A mismatched
checkpoint or policy cannot consume a fresh destination. If the original source
still exists with the same owner and a live/unknown writer, restoration refuses
with `OwnerBusy`/`Hold`. A deleted original source may be restored. This check does
not create a global identity registry; the host still supervises stopped owners.

Cold open replays typed engine events and exact affine query/validation audits,
including work snapshots, before accepting derived state. Native assessment and
every knowledge mutation must have their exact committed episode/anchor. A saved
model, attribution and successful usage vector must match that exact replay;
internally rewritten receipt hashes do not replace these checks. Cold GF(2)
reconstruction has a fixed one-million-unit ceiling and is reported
separately from episode work. Capacity failure preserves history rather than
raising limits or discarding records.
