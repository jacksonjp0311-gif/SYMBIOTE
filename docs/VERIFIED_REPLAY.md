# Verified prefixes and feedback replay

Status: unreleased engine work. The registered engineering profile is **NOT_RUN**
until final source, executable and registration pins are frozen. Software
correctness checks have passed; no performance result is claimed here. The
published v1.0.1 tag, baseline `0616f9a` and historical evidence remain unchanged.
The prospective workload is [Engine Evolution 002](ENGINE_EVOLUTION_PROTOCOL_002.md).

## Exact prefix identity

The retained boundary digest is:

```text
SHA256(serde_json encoding of Value([event_0, ..., event_n_minus_1]))
```

Events are the typed operational events, excluding genesis. This uses the
project's existing serializer and ordering, rather than introducing another
canonical JSON standard. The empty prefix is the digest of `[]`.

`OperationalJournal` maintains a private SHA-256 state over the opening `[` and
each canonical event, separated by commas. To obtain a prefix digest, construction
clones that state, appends `]`, and finalizes it. Subsequent reads retrieve the
derived digest. Nested objects, Unicode, control characters and escapes retain
the original encoding. Identical event prefixes produce byte-identical `/1`
boundary fields and digests. Historical receipt bytes are not rewritten.

The index is constructed from history that passes the existing owner, policy,
typed-event and receipt-chain checks. A live Store writer guard remains required.
There is no imported or deserialized trusted cache. Missing prefixes fail; a
digest supplied by another caller cannot create an index entry. Hashes bind
content and detect corruption; they do not authenticate arbitrary remote truth
or prevent an owner from rewriting an entire history.

## Publication and recovery

Append validation prepares proposed hash state and prefix digests privately.
The existing atomic journal replacement publishes the complete durable batch
first. Only then are in-memory events, state and index entries advanced.
Validation failures and failures before publication leave the committed prefix
and cache unchanged. Work actually attempted before failure remains visible in
the diagnostic counters. A modeled interruption after durable publication is
resolved by cold reopen and complete history validation.

The existing 4,096-record limit bounds the index to at most 4,096 digest entries,
including the empty prefix. Their payload occupies at most 131,072 bytes.
`index_bytes` reports the index's inline size plus reserved digest capacity;
temporary serialization buffers, journal copies, allocator overhead and process
peak memory are separate. Existing journal byte and record limits are unchanged.

## Reference and startup paths

`OperationalJournal::open_reference` retains the full-serialization calculation
and disables index construction. Owner, policy, chain and durable-write checks
are identical. `event_prefix_sha256_reference` deliberately performs the retained
calculation even on an indexed journal. `replay_index_reference` retains complete
feedback reconstruction for comparisons.

Production startup uses one private `StartupReplay` cursor. The service advances
it for **every** operational event, including unrelated namespaces, with the
historical operator policy applicable at that event. Feedback authority and
semantic checks use the same implementation as the retained reference. Ordinary
service, lifecycle, selection and receiver-outcome validation still run in their
own branches. The cursor rejects skipped or repeated positions, changed owners,
partial completion and reuse after any error.

Historical knowledge anchors remain exact prefixes. Later revocation changes
current membership and recommendations without rewriting earlier decisions.
Promotion attribution, actual use, future-knowledge exclusion and duplicate-credit
checks remain mandatory. Typed feedback carrier validation checks its envelope
and hash; that check alone does not establish authority, learning or benefit.
Historical cognitive profile verification still reconstructs its own prefixes,
so this change does not make all startup work linear.

## Measurement boundary

`prefix_work()` reports journal-instance counts for canonicalized bytes, bytes
supplied to SHA-256, event visits, cache/reference reads, journal bytes read,
durable journal bytes written and committed bytes cloned. It also reports index
memory and diagnostic elapsed time. Reference and indexed work are separate.
These counts exclude hash padding and are not physical disk or whole-process
allocation counters. `feedback::replay_work()` reports thread-local event visits,
stored-use prediction rechecks and replay diagnostics. Saturation is explicit.

The registered profile retains separate vectors for shared history setup, each
arm's full cold open, 32 boundary captures, every-prefix parity and close.
Reference mode avoids upfront index construction; indexed cold costs include it.
A per-arm comparison includes shared setup once. Whole-experiment accounting
includes setup and both arms. Warm savings cannot hide construction, persistence
or comparison costs. The report preserves bytes and work as separate components;
diagnostic elapsed spans are not additive exclusive CPU measurements.

These counters do not alter oracle prices, graph work units, GF(2) operation
counts, permissions, rewards or promotion criteria. Unit checks cover exact
parity, cold reopen, failed publication, corruption, historical policy, revocation,
attribution and duplicate rejection. The ignored registered profile requires its
external registration digest and exact test-executable pin before opening its
specified histories.

## Earlier losses remain losses

The closed 64-cell graph cohort charged its actor **52,118,896** declared units:

| Component | Units |
|---|---:|
| Oracle fees | 48,000,480 |
| Plaintext bytes | 2,991,872 |
| Forecast and replay | 1,068,720 |
| Direct reasoning | 55,392 |
| Provider checks | 2,304 |
| Adoption | 128 |

Its isolated greedy comparison cost 28,846,944 units. Oracle fees dominate that
account. JSON hashing and file-copy CPU were outside its declared unit model.
A cheaper prefix calculation cannot revise those totals, erase the loss, or
establish reciprocal efficiency. Any new local optimization result must retain
its own workload, source pins, accounting boundary and limitations. Broader
generalization, independent-host validation and stable qualification remain open.
