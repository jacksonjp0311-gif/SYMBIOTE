# Verified prefixes and feedback replay

Status: unreleased engine work. The registered [Engine Evolution 002](ENGINE_EVOLUTION_PROTOCOL_002.md)
workload completed in 35.015 seconds with `PASS_ENGINEERING_ONLY`; its prefix
component passed independent data-only replay. The published v1.0.1 tag, baseline
`0616f9a` and historical evidence remain unchanged. See the
[evidence index](../experiments/engine-evolution-002/README.md) and
[summary](../experiments/engine-evolution-002/summary.json).

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

## Registered component measurements

The executed source was `bb1b88eaa771be5e201ccfcfe93840c6750eb9d7`.
Registration SHA-256:
`89241bf8b120508053a91966e57c02f70343a1f8a3e8aafe3d8a59ec1b385409`.
The frozen protocol digest was
`2891ebf675b80a0d45ecbaf1a308a161822d2fe5ccfbfa11121b3a9f0a9b7214`.
The independent audit checked the matching build, preserved executable bytes,
135 source-file byte hashes, receipt chains and actual counter arithmetic without
executing native code or repeating the workload.

Every prefix was recomputed from the raw typed events: 340 distinct prefixes and
680 comparisons against the two arms matched exactly. The 256 reported captures
also matched the expected byte/event counts. The prefix component recorded
383.1756 ms through final closure; its contained process took 1.765 seconds.
Its evidence census was 295,660 bytes. The complete enclosing workload retained
25,510,241 bytes, below its 128 MiB limit; 35.015 seconds was below its 600-second
limit. These are related engineering cases, with zero independent scientific
samples.

Each cell below is one observed run. Paired times are reference / indexed.

| Events | Cold open, ms | 32 digest reads, ms | Indexed storage, bytes | Upfront indexed SHA input bytes | Reference warm SHA input bytes |
|---:|---:|---:|---:|---:|---:|
| 0 | 4.9835 / 4.6276 | 0.0361 / 0.0369 | 400 | 2 | 64 |
| 16 | 5.0314 / 4.9079 | 2.0765 / 0.0253 | 1,296 | 4,509 | 143,776 |
| 64 | 5.2599 / 6.4773 | 12.4845 / 0.0275 | 4,368 | 18,093 | 576,928 |
| 256 | 10.0271 / 9.8050 | 63.0570 / 0.0273 | 16,656 | 72,741 | 2,319,520 |

Indexed warm reads canonicalized and hashed zero additional history bytes.
The reference arm retained 272 bytes of common measurement/index bookkeeping
with digest storage disabled. Indexed memory increased, and the 64-event cold
open was slower; the empty-history warm comparison was also slightly slower.
Filesystem order, caching and clock noise remain part of these observations.

Upfront work was retained. At 256 events, shared history setup took 23.7379 ms,
wrote 298,295 journal bytes across atomic publications and cloned 179,203 committed
bytes. Setup plus cold open, 32 reads and close totaled 97.9451 ms for reference
and 34.6470 ms for indexed. Separate all-prefix comparison work took 161.2433 ms
and 0.2075 ms respectively; it remains included in the complete experimental
record rather than being hidden as free validation.

This measures the `OperationalJournal` boundary-digest accessor, not the complete
`capture_local_execution` function, feedback startup, or cognitive cycle. It
establishes exact digest preservation and fewer repeated canonicalization/hash
operations, with the listed local timings. It does not establish a statistical
hardware speedup, lower peak process memory, or whole-agent efficiency. The
reference is the retained algorithm in the same new executable, not a rerun of
the previously published release.

Raw prefix report SHA-256:
`1d285f01b45ed72e3b6e2f0bb99bc09356cd88aa5e98b3e94fc17077bc5e137c`.
Independent prefix-audit SHA-256:
`98c702b13b72a22c2a6cd1197848c3e189ad4ddcf0718452349de8e04f31999c`.

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
