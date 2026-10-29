# Engine evolution after the corrective baseline

Status: **unreleased main implementation; bounded engineering workload passed**.
The public v1.0.1 tag, executables and qualification archive remain unchanged.
These additions require building this source checkout. A package version is not
evidence that a particular executable contains or qualifies these changes.

The next iteration follows [engineering protocol 002](ENGINE_EVOLUTION_PROTOCOL_002.md),
committed at `03dcddc060f0b701c89c6f96fd6603ae365400bf` before implementation.
That protocol is distinct from the earlier transfer-research Protocol 002.
The frozen implementation is `bb1b88eaa771be5e201ccfcfe93840c6750eb9d7`.
The once-only workload completed in 35.015 seconds on this Windows PC, within
600 seconds and 128 MiB. [Results and exact evidence](../experiments/engine-evolution-002/README.md)
separate software correctness, local optimization, fresh reuse and receiver feedback.

## Changes in the existing engine

1. **Exact verified-prefix reuse.** The operational journal maintains the same
   SHA256 of each canonical JSON event-array prefix. Capture no longer repeatedly
   serializes the complete history. The private index is constructed from a
   validated journal and published only after a successful durable append.
   `open_reference` preserves the complete original calculation for comparison.
   Startup feedback validation now walks events once through the same semantic
   checks, including each historical policy epoch. See [verified replay](VERIFIED_REPLAY.md).
2. **Receiver-originated feedback.** A separately granted `outcome.read` operation
   returns complete bounded ledger evidence. An opt-in receiver evaluates and
   adopts a contribution, executes its own declared goal and produces an outcome;
   the sender verifies and retains one causal reconciliation. The initial envelope
   is one peer/context and affine retained-case use. Unknown economics stay
   unknown: capability outcomes do not increase the strict cost-benefit counter.
   See [receiver outcomes](RECEIVER_OUTCOMES.md).
3. **Optional exact rank-based queries.** `rank-basis-min/v1` tests the augmented
   rows for zero and powers of two instead of scanning every input. It preserves
   reference query choices; hints and width one retain the reference path.
   Supported widths remain unchanged. This saves selection work, not source calls.
4. **Independent observation and fresh reuse.** A native embedding example uses
   the same public inference and durable knowledge APIs against a separate Python
   switchbox process. The source delivers individual authorized observations,
   never a coefficient vector or answer table. Models freeze before fresh inputs
   are revealed; a restarted process commits predictions with the source stopped.
   The external supervisor grades only afterward. See [adapter instructions](../adapters/README.md).

No new crates, dependencies, language-model requirement or remote execution
permission were added. The four-crate architecture and exact reference algorithms
remain. Current source/fixture authority assumptions are explicit; TLS and hashes
cannot certify the honesty of an arbitrary remote evaluator.

## Why these costs were selected

The original 64-cell actor total is still 52,118,896 declared units. Its components
are 48,000,480 oracle fees, 2,991,872 plaintext bytes, 1,068,720 forecast/replay
units, 55,392 direct-model units, 2,304 provider checks and 128 adoptions. Therefore
eliminating all replay would still not erase the historical whole-cost loss.
Canonicalization, hashing and atomic file-copy CPU were outside that unit model.

New measurement keeps these quantities separate: source queries, inference and
validation work, cold replay and prediction, canonical/hash bytes, index memory,
wire bytes, durable state and supervisor/control work. Warm cache savings are
reported alongside construction and cold-open overhead. Unlike units are not
summed to manufacture a scalar saving.

The unregistered mask-199 interoperability fixture passed before the registered
cohort opened. All three structural arms answered its 32 fresh inputs; the answer
cache abstained. Reference learning used 28,439 GF(2) units, rank-based learning
713; both made ten source calls and paid 638 further units for reopen/prediction.
Rank metadata occupied 785 more retained bytes. The isolated rank learner tied.
These are software-smoke results, not execution of the registered four-case study
or evidence of a reciprocal efficiency advantage.

## Registered results

The four width-eight cases each learned from nine training observations and one
distinct validation observation. The source then stopped. Each restarted model
answered all 32 previously unanswered inputs correctly: 128 distinct case/input
pairs per structural arm. Every prediction was committed before labels were
computed. The exact answer cache abstained on all 128; the isolated structural
learner tied. This demonstrates conditional structural reuse beyond a cache of
answers, without establishing an advantage over isolated learning or a benefit
from exchanging an artifact in this particular workload.

Reference inference and validation consumed 28,439 GF(2) work units per case;
the optional rank policy consumed 713. Both used ten source queries and 5,300
plaintext bytes per case. Cold reopening and prediction cost a further
634–642 units in both arms. Rank-policy metadata occupied 785 more retained
bytes per case. These are operation and byte measurements; source computation,
process supervision, persistence and grading are retained separately. They do
not become interchangeable economic units or a whole-engine speedup claim.

All prefixes agreed at histories of 0, 16, 64 and 256 events. At 256 events,
32 reference captures canonicalized and hashed 2,319,520 bytes and visited
8,192 events. Indexed cold construction canonicalized 72,228 bytes, supplied
72,741 bytes to SHA-256, visited 256 events and occupied 16,656 index bytes;
the subsequent 32 captures added no canonicalization, hashing or event visits.
Cold validation, durable setup and close costs remain in the evidence. At an
empty history, the indexed warm capture timing was slightly slower. The profile
is a single local component comparison, not a statistical timing benchmark or
measurement of all service startup work.

The normal native sender learned a model, contributed it, and verified a proof
of the receiver's own evaluation, adoption and actual goal use. It recorded one
verified partner outcome and one capability gain. After both processes restarted,
it added no duplicate credit and made no new observation queries. Strict verified
economic benefits remained zero because costs were unknown. This closes the
initial receiver-feedback path within its one-peer/context proof envelope;
its retained-case task is separate from the frozen fresh-input experiment.

## Checks and reproducible workload

Before registration, the full Windows workspace passed 429 Rust test executions,
130 Python tool tests and 43 release-tool tests, strict all-target Clippy and format
checks. Targeted reasoning, observation, network-adapter, prefix parity, malformed
proof, privacy, revocation and two-native-process tests also pass. The registered
prefix test and historical hour/cohort remain ignored during ordinary discovery.

The untouched baseline's first local parallel suite failed two service fixtures:
one TCP connection deadline and one owner-EOF assertion after lifetime expiry.
Both passed individually at the same limits. A test-only reentrant fixture gate
now bounds concurrent native test groups to two; the full new suite passes without
changing production timeouts or lifetimes. This is not an established explanation
or retrospective fix for the older Windows connection anomaly. Original failed
logs remain under `experiments/local/evolution-baseline-*.txt`.

After a clean implementation commit, build the native runtime, observation example,
memory test and service test with that exact source stamp. Register all executable,
source, protocol and independent-adapter hashes before opening targets:

```text
python tools/engine_evolution.py register --native NATIVE --observer OBSERVER --memory-test MEMORY_TEST_EXE --service-test SERVICE_TEST_EXE --out NEW_OS_TEMP_DIRECTORY
python tools/engine_evolution.py run --registration REGISTRATION_JSON --registration-sha256 EXTERNAL_SHA256
```

The once-only workload is bounded to 600 seconds and 128 MiB evidence. It includes
the exact prefix comparison, four separately sourced width-eight cases with 32
fresh tasks each, an exact answer cache and persistent isolated learner, and the
automatic native receiver-outcome loop. Every failed or interrupted prefix must
remain visible; there is no retry or budget increase to turn a loss into a win.
The completed registration SHA256 is
`89241bf8b120508053a91966e57c02f70343a1f8a3e8aafe3d8a59ec1b385409`;
raw report SHA256 is
`a0dcb9752c578041e745489b80198f42011fd788e377eed674e84b7d45f1cf68`.
The [machine-readable summary](../experiments/engine-evolution-002/summary.json)
pins the four saved executables, source manifest and complete nonbinary archive.
Independent data-only audits checked the saved component evidence without
rerunning targets. The archive includes initial baseline failures and the initial
formatting diff alongside later passing checks; earlier failures are not rewritten.

## Limits that remain

Fresh-task source reuse is conditional within the affine family. The observation
workload does not transfer structural artifacts between peers, and its isolated
structural learner can tie. The separate receiver channel proves retained-case
exchange outcomes, not fresh-task generalization. No complete economic gain,
unfamiliar-domain transfer, independent-host operation, host power-loss durability
or broad stable qualification follows. Published negative controls and historical
HOLDs remain authoritative.

Next work should address the dominant acquisition/control costs and amortize
properly versioned validation across genuinely useful exchanges. Preserve
correctness, accounting, receiver autonomy and exact causal evidence while doing so.
