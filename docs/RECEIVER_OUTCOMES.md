# Receiver-owned contribution outcomes

Status: **unreleased development on main**. This additive channel is not part of
published v1.0.1. It leaves that release and its evidence unchanged. The governing
engineering plan is [iteration 002](ENGINE_EVOLUTION_PROTOCOL_002.md).

A sender can now receive evidence that its contribution was independently
validated, adopted and used by another normal SYMBIOTE process. The receiver's
own run policy authorizes evaluation and a local goal. An `outcome.read` request
only reads an existing outcome; it cannot start evaluation or execute a task.

The initial implementation supports exact Boolean affine knowledge at widths
1 through 8, one configured peer and one context per store. Its goal is an input
in that finite domain. It demonstrates use of a retained validation case. It does
not establish performance on an unanswered task or an economic benefit.

## Permissions and isolated stores

Start with the identities, mutually authenticated TLS configuration and explicit
certificate pins in [the service guide](SERVICE.md). Configure both participants
for the same declared affine scope/schema, each with its own state directory,
identity, credentials and authorized peer entry. Keep private keys outside Git.

Both participants must explicitly grant `candidate.submit` and `outcome.read` for
the scope. The outcome grant must have **exactly** `"artifacts": ["*"]`: a proof
contains complete bounded history for that context, including provenance and
validation evidence. A narrow artifact grant is rejected. Use an isolated store;
this initial channel cannot redact an existing multi-context or multi-peer history.

For the normal discovery and learning cycle, extend the peer's existing access
entry on each participant as follows:

```json
{
  "scope": "affine-context/v1",
  "operations": [
    "capabilities", "knowledge.list", "knowledge.read", "knowledge.predict",
    "candidate.submit", "candidate.status", "outcome.read"
  ],
  "artifacts": ["*"]
}
```

The receiver must independently possess an operator-pinned
`symbiote.local-truth/1` affine evaluator fixture. Its fixture SHA is the SHA256
of the exact file bytes. The receiver policy and the sender's expected receiver
policy/fixture pins must agree. The sender's observation source remains separately
authorized; this outcome permission does not authorize source observations.

## Run policy configuration

The enclosing policy remains `symbiote.cognition-policy/1`, described in
[the native runtime guide](LIVE_RUNTIME.md). Add an optional `outcomes` property.
All object fields are strict: unknown fields and unsupported schema versions are
rejected. At least one of `receiver` or `sender` must be present; omit unused roles.
The native two-process proof uses one receiver-only policy and one sender-only
policy. Every named peer alias and scope must also be in the enclosing policy's `peers`
and `scopes` arrays.

For the receiver, insert this property into its run policy. Bracketed pins below
are templates and must be replaced with actual 64-character SHA256 values.

```json
"outcomes": {
  "schema": "symbiote.contribution-policy/1",
  "receiver": {
    "peer": "partner",
    "scope": "affine-context/v1",
    "fixture_sha256": "[receiver local fixture SHA256]",
    "goal": 7,
    "max_candidates_per_episode": 1
  }
}
```

| Receiver field | Meaning and bound |
| --- | --- |
| `peer` | Configured alias of the authorized contributor |
| `scope` | The store's single affine context |
| `fixture_sha256` | Exact receiver context truth pin |
| `goal` | Receiver-owned input, `0 <= goal < 2^width`; choose a validation input absent from the sender's declared training inputs |
| `max_candidates_per_episode` | 1 or 2; cannot exceed the enclosing run policy's candidate allowance |

A receiver-only role runs its own bounded processing loop over that contributor's
quarantine. It can use `contribute: false` and a contribution allowance of zero.
The permission to evaluate comes from this local role, not the sender or a poll.

For the sender, insert:

```json
"outcomes": {
  "schema": "symbiote.contribution-policy/1",
  "sender": {
    "peer": "partner",
    "scope": "affine-context/v1",
    "receiver_policy_sha256": "[receiver current service policy SHA256]",
    "fixture_sha256": "[receiver local fixture SHA256]",
    "goal": 7,
    "max_polls": 12
  }
}
```

| Sender field | Meaning and bound |
| --- | --- |
| `peer` | Configured receiver alias |
| `scope` | The same declared affine context |
| `receiver_policy_sha256` | Receiver's exact current service policy digest, obtainable from its local `peers --json --config ...` output |
| `fixture_sha256` | Expected receiver evaluator fixture pin, not the sender source pin |
| `goal` | Exact expected receiver goal |
| `max_polls` | 1 through 16 attempts per durable contribution decision, counted across restarts |

To send a new contribution, the enclosing sender policy needs `contribute: true`
and a positive `max_contributions_per_episode`. Ordinary contributions and this
channel share that allowance, including attempted sends. A zero allowance sends
no new offer. The sender selects an own-source retained record with a native
observation-query audit; arbitrary received knowledge is not relabeled as its own.

Existing request, connection, duration, byte and work limits still apply. The
focused fixture uses `max_frame_bytes: 65536` and `model_work: 1000000` in each
service configuration, with no larger run-policy work allowance. Outcome handling
reserves bounded verification work and can stop on budget exhaustion. Permission
to read history does not increase any limit automatically.

## Automatic normal-engine loop

After saving valid service and run policies, start the receiver, then the sender
in separate terminals. For a local debug build:

```powershell
cargo build --locked -p symbiote-runtime
.\target\debug\symbiote.exe run --json --config receiver.json --run-policy receiver-policy.json --receipts receiver-run-1
```

```powershell
.\target\debug\symbiote.exe run --json --config sender.json --run-policy sender-policy.json --receipts sender-run-1
```

Use fresh receipt directories for each run. Keep stdin open while running; the
existing shutdown command, cancellation and finite budgets still apply.

1. The sender acquires and retains its own validated affine model through its
   separately permitted observation backend, or reuses that model after restart.
2. It journals a contribution decision and sends the unchanged inert
   `candidate.submit` request, including its observed training/validation inputs.
3. The receiver's local role records its goal before deciding to evaluate. Its
   pinned evaluator independently checks the candidate, then promotes or rejects
   it. Already retained exact knowledge receives no fresh adoption credit.
4. Following a fresh promotion, the receiver actually uses the stored model for
   its goal and journals the use and outcome. Evaluation expected values come
   from the receiver fixture, never the submitted artifact.
5. The sender makes a bounded `outcome.read` request naming the exact candidate,
   original request SHA and a fresh challenge. `PENDING` and `REJECTED` responses
   confer no positive credit. A `USED` response carries complete evidence.
6. The sender verifies the evidence and durably records one reconciliation per
   receiver/promotion. Repeated responses cannot add credit. Completed decisions
   are not automatically polled again on warm runs or restart.

No harness command manually evaluates, predicts or sets success in the native
integration proof. A standalone `serve` process does not acquire this local
receiver role merely because an outcome grant exists.

## Evidence, counts and trust

The `symbiote.contribution-outcome/1` response binds sender, receiver, scope,
original request, candidate, offered and localized records, evaluator fixture,
current service policy, goal, challenge and exchange. Complete knowledge and
operational chains establish this order:

`quarantine -> receiver goal -> receiver decision -> feedback decision -> prepared evaluation -> completed evaluation -> promotion -> stored-model use -> outcome`

The sender checks exact before/after/current knowledge anchors, native assessment,
cost consistency, typed feedback schemas/carrier hashes, the actual predicted
input/output and current active record. The complete proof is retained in bounded
chunks in one checked journal batch, with a digest and one-time credit key.
Restart reconstructs this history; an old reconciliation is historical evidence,
not a claim of newly refreshed remote status.

When the outcome role is enabled, `summary.json` adds:

| Field | Meaning |
| --- | --- |
| `receiver_outcomes_verified` | Newly reconciled successful receiver outcomes in this run |
| `receiver_capability_outcomes_verified` | Subset proving a new supported retained-case capability relative to the receiver's prior knowledge |
| `partner_benefits_verified` | Strict measured cost-benefit count; remains **0** for this initial channel |

The receiver's baseline is explicitly `unknown`, measured net is absent and
`verified_benefit`/`cost_benefit_verified` remain false. Stored evaluation/use cost
components are not a complete wire, replay, process or lifetime cost account.
A capability outcome must not be counted as an economic win.

TLS establishes the authenticated origin of a response. SHA chains and semantic
checks establish consistency with the declared native evidence. Neither proves
honesty of an arbitrary remote evaluator, defeats a privileged full-ledger rewrite
or supplies hardware/process attestation. The trusted operator, pinned evaluator,
fixture and native implementation remain explicit assumptions.

## Rejection and recovery boundaries

Proofs are rejected before export when privacy or completeness checks fail. The
initial envelope allows at most four knowledge rows including genesis and 64
operational events, a complete serialized proof of at most 56 KiB, and a response
plus its reserved overhead within the configured frame limit. The transport
ceiling remains 65,536 bytes. Oversized histories are rejected, never truncated.
Prior policy transitions/relocations, unrelated contexts/peers/source telemetry
and unsupported decision namespaces are outside this first complete-history proof.

Changed policy/fixture pins, wrong participants or request/artifact, stale
challenge, reordered/missing authorization or use, malformed evidence, revoked or
superseded knowledge, narrow grants and exhausted budgets cannot create positive
credit. A wrong transfer closes actual negative feedback without promotion.
Completed evaluation interrupted before use/outcome can continue once without
repeating adoption or use. An unfinished prepared evaluation remains an explicit
recovery HOLD under the existing service recovery rules.

Run the focused software checks with:

```powershell
cargo test --locked -p symbiote-runtime --lib service::outcomes::tests
cargo test --locked -p symbiote-runtime --test service outcomes::
```

The native test
`outcomes::two_native_agents_reconcile_receiver_owned_outcome_and_restart` can
export a fresh sanitized proof tree through `SYMBIOTE_OUTCOME_ARTIFACTS`. It copies
complete API responses, public configurations and journals, process IDs and pinned
executable/test-driver snapshots; private `.key` files are excluded. These are
software/operational checks. The separately frozen unanswered-input experiment
and registered qualification workloads have their own admission and evidence.

## Closed bounded component observation

The once-only engineering workload at source
`bb1b88eaa771be5e201ccfcfe93840c6750eb9d7` closed as
`PASS_ENGINEERING_ONLY` in 35.015 seconds within its 600-second / 128-MiB limits.
The receiver component's contained native test took 4.375 seconds, exited 0 and
had verified cleanup without output truncation. See the
[iteration account](../experiments/engine-evolution-002/README.md) and
[machine-readable summary](../experiments/engine-evolution-002/summary.json).
These are bounded local engineering observations; broader stable qualification
remains HOLD.

| Observed item | Actual result |
| --- | --- |
| Receiver ledger promotion / stored-model use | 1 / 1 |
| Sender new verified outcome / capability counters | 1 / 1 |
| Strict economic benefit counter | 0; unknown baseline and absent measured net |
| Sender own observation | 5 source queries, 203 GF2 row-operation units |
| Sender restart | 0 source queries, 39 GF2 units, 0 new outcomes or capability credits |
| Receiver goal | Input 7 produced 0; receiver validation had already checked inputs 5, 6 and 7 |
| Complete proof | 20,905 bytes stored in 11 chunks; API response 20,974 bytes |
| Receiver history | 2 knowledge rows and 10 operational rows, including each genesis |
| Sender history after restart | 2 knowledge rows and 47 operational rows, including genesis |

Both engines restarted under distinct process IDs with unchanged retained
knowledge anchors. The sender made one contribution and one outcome poll; its
restart neither sent another contribution nor repolled the completed outcome.
Matching sender/receiver plaintext counters recorded 19 first-run and 14 restart
RPC attempts. Those attempts and restart computation remain real costs.

The receiver's ordinary `fresh_promotions` summary field is 0: that field is
updated by the ordinary learning loop, while the separate receiver role made the
one adoption shown by its actual knowledge ledger and changed anchor. The
independent audit derives that adoption from the ledger instead of treating this
summary field as a total across roles.

The assessment records 9 local evaluation/adoption units and one stored-use unit.
Its outcome cost of 10 is not a complete economic account. Incoming wire,
whole-process replay and lifetime costs are not established by those components;
`verified_benefit` stays false. Use of input 7 is a retained-case demonstration,
separate from the independently frozen unanswered-input experiment.

| Immutable content pin | SHA256 |
| --- | --- |
| Workload registration | `89241bf8b120508053a91966e57c02f70343a1f8a3e8aafe3d8a59ec1b385409` |
| Native executable | `ef7cd032820653f36e7e141fecb85426d98349c1bfb96224713b989a0418fc66` |
| Native test driver | `42e745ff0763a9cd69affb948d4aff4af669ea70b4c0b50043babdf3b187278a` |
| Raw receiver artifact manifest | `a4c6bb7a804f1de3b42845e9347d409ec15d78ba2c8198e2f6c5700a909364fe` |
| Whole workload report | `a0dcb9752c578041e745489b80198f42011fd788e377eed674e84b7d45f1cf68` |
| Independent receiver audit JSON | `317501d16544920f932b1fa2d10cac50dbc6bca1c1505478360e324c5462ece0` |
| Independent data-only audit script | `6c26cbd2da444443d7aff657b15d42a0f6e750998c317365c2060f223f65deb9` |

The independent reader rehashed all 135 frozen source files and 37 copied
receiver artifact members, checked full raw causal histories and exact current
policy/fixture bindings, and confirmed byte-identical raw evidence before/after
its read. It did not execute a native engine or rerun a target. Its original
implementation uses the recorded local paths; preserving the script does not by
itself make those paths portable. No private keys or token values were found in
the non-executable raw evidence scanned for the audit.

## Role-aware accounting for the v1.1 target

New development summaries add `learning_counters` with schema
`symbiote.role-learning-counters/1`. Existing `fresh_promotions`,
`receiver_outcomes_verified`, `receiver_capability_outcomes_verified` and
`partner_benefits_verified` keep their historical meaning. In particular,
`fresh_promotions` records ordinary learning paths that completed their existing
success reporting; it remains receiver-role-exclusive. It is not retroactively
redefined as a count of every committed promotion.

The new object binds its initial/final knowledge anchors and operational event
prefixes. Each ordinary observation/learning action and receiver processing action
has a `LEARNING_COUNTERS` checkpoint with its own before/after anchors. A new
promotion counts only when the native store confirms the exact committed record
and assessment between those heads. Final totals must reconcile with every
promotion in the run's actual ledger suffix. A digest supplied without the native
commit cannot increase a count; truncated or mismatched disk/live history boundaries fail.

| Field | Interpretation |
| --- | --- |
| `promotions.ordinary_learning` | Unique committed promotions by ordinary observation or learning actions |
| `promotions.receiver_role` | Unique committed promotions by locally authorized receiver-role processing |
| `promotions.total_new` | Sum of those two disjoint promotion origins |
| `reused_records` | Unique retained record versions actually matched by an ordinary reuse or receiver duplicate-payload decision, split by local role |
| `completed_outcomes` | Newly committed terminal outcomes this run, split into `ordinary_learning`, `receiver_role` and `partner_receiver` origins |
| `capability_outcomes` | Outcome subset with verified capability-extension evidence; deduplicated by exact promotion coordinate |
| `measured_benefits` | Outcome subset backed by a validated measured task window with positive net; unknown economics contribute zero |
| `current_active_local` | Explicit subset of this run's local promoted outcomes/capabilities/benefits whose exact record is still active under the current policy/evaluator |
| `durable_history_completed_outcomes` | All validated terminal outcomes already retained in the owner's journal, including prior runs |

The ordinary and receiver promotion origins are disjoint. Reuse is a separate
operation category: a model promoted earlier in a run may be reused later in that
same run. Do not add reuse or capability/benefit subsets to `total_new`.
Repeated recognition of one retained version in one role counts once per run;
merely opening, reading or replaying a store counts neither a promotion nor a
reuse decision. Restart starts a new event window and cannot re-credit an old
promotion or completed outcome.

Completed outcomes are historical commitments. Later revocation or supersession
does not erase their counts or original quality classification. Instead,
`current_active_local` loses the corresponding active membership. An identical
payload in a superseding version does not by itself establish another capability
outcome. Historical reconciliation with a partner remains a validated response
snapshot; it does not prove that the remote record is still active after that
response. `partner_current_status` states this unobserved boundary explicitly.

These counters describe committed behavior and evidence. They are not independent
scientific samples, generalized capability claims or a replacement for complete
operation-cost measurement. The v1.1 acceptance criteria remain prospective in
[the support contract](V11_ENGINE_SUPPORT_CONTRACT.md).

### Typed embedding inspection

The prospective embedding API exposes read-only typed counters through
`Engine::counters()`, `Engine::counter_anchor()` and
`Engine::counters_since(&anchor)`. The report schema is
`symbiote.engine-learning-counters/1` and its public Rust types live in
`engine::counters`. Consumers use typed fields and `EngineError.kind`; they do not
parse diagnostic strings or supply success flags.

`counters()` covers the durable lifetime, so reopening returns the same historical
totals. To measure one run, capture `counter_anchor()` first and inspect
`counters_since(&anchor)` afterward. Both knowledge and operational prefix
coordinates are validated; a foreign, changed or mixed-prefix anchor is rejected.
A new anchor after completed work yields zero new promotions/outcomes until new
native commits occur. Reading either API appends no event and contacts no source.

The embedding role comes from the exact native inference audit: an incoming
artifact SHA binds a receiver-origin episode to that same retained artifact;
otherwise the record must be owned by the engine. Counted retention requires the
actual Started/Inferred/Evaluated/Finished chain and original knowledge-store
promotion evidence. Reuse requires an unchanged head with the exact active
record. An internally rehashed Finished entry without its real episode/store
commit cannot create credit.

Each historical retention includes a typed `CurrentValidity`: `Active`,
`RevokedOrSuperseded`, `SourceEpochHold` or `PolicyHold`. These statuses keep source,
policy and active-membership questions distinct from historical completion.
Unfinished or unaccounted native commits return an explicit hold instead of an
invented finished total. The typed report uses the same disjoint-origin and
outcome-subset interpretation as the native runtime summary above; it does not
turn a model's retention alone into a completed verified-use outcome.


The embedding counter report keeps local exchange receipts in a separate category:
`partner_outcome_snapshots_recorded` counts unique saved partner responses in the
selected window, `recorded_reconciliations` lists those historical records, and
`durable_history_partner_outcome_snapshots_recorded` counts them across the owner's
full retained history. `current_remote_validity` is the typed
`UnknownWithoutReceiver` status. A saved snapshot is not promoted into current
verified remote capability or measured benefit counts. Call
`reconcile_local_transfer` with the actual receiver handle to check current
membership; revocation makes that live check fail while the historical snapshot
remains recorded. This differs from the native channel's complete-ledger witness
format, so counters from the two interfaces must retain their declared scopes.

### Per-owner resource inspection

`Engine::resources()` returns typed `symbiote.engine-resources/1` diagnostics
without another file read, source call or journal event. Knowledge-store counters
belong to that open store instance: reopening starts a new accounting window and
records the actual cold-read bytes. They report application bytes for full
history serialization, write submission, successful `write_all`, and successful
atomic publication, with publication attempt/failure counts. These byte categories
overlap and must not be summed. The current implementation rewrites its complete
knowledge history for each publication, so cumulative written bytes can exceed
the final file's growth substantially.

A failed `write_all` leaves `failed_partial_write_bytes` unknown (`None`), rather
than claiming that zero bytes reached its temporary file. A completed write whose
later sync or replacement fails counts the complete write but no publication.
`saturated` marks counter overflow. These observations are not physical disk I/O,
an OS crash-durability guarantee, CPU time or peak memory. Common identity-ledger
setup and whole-process measurements remain separate. The resource report also
exposes the operational journal's actual per-instance prefix-work counters.

Capacity inspection preserves the existing limits of 4,096 records, 4 MiB per
knowledge ledger, and 128 KiB per record. Physical `remaining_ledger_bytes` and
compact `remaining_publication_bytes` are separate: accepted trailing JSON
whitespace may occupy the physical limit while the existing compact rewrite
still has room. Cold opening computes that exact compact size once and reports
the additional work as `capacity_quote_serialized_bytes`. Capacity is a bound,
not a promise that the next record, filesystem operation or allocation succeeds.

The live knowledge store pins the SHA256 of the exact bytes it opened, including
accepted JSON whitespace. Before staging a publication and before replacing the
ledger, it checks those bytes again. Missing, replaced, truncated or corrupt
history returns a typed integrity hold and is never repaired from cached state.
Genesis requires an absent ledger. The extra bounded reads and raw-byte hashing
are recorded as `integrity_read_bytes` and `integrity_hashed_bytes`, with check
and failure counts. A cooperative writer lock plus these checks detects external
change; it is not an adversarial OS compare-and-swap guarantee.

`promote_checked`, `promote_graph_checked` and `revoke_checked` return typed
`MemoryWriteError` categories from the actual guard: `Capacity`, `Invalid`,
`Integrity` or `Storage`. Existing string-returning methods wrap the same implementation. A new
record may exceed remaining capacity even when that remainder is nonzero; the
exact serialized publication guard decides this before any file write.

New embedding owners created by v1.1.0 also carry an explicit
`engine_owner_registered` event immediately after their original identity genesis.
Its namespace is `embedding-engine/v1` and its minimum-writer capability is
`symbiote-engine-writer/1`. The latter identifies the required writer format,
independently of the package release version. Earlier writers reject the unknown
event; current generic legacy writers also refuse this namespace. Only explicit
compatible engine constructors admit it. An unmarked prototype owner is held for
an explicitly reviewed future migration, without automatic rewriting. Read-only
inspection and checkpoint/restore preserve and validate the marker.
