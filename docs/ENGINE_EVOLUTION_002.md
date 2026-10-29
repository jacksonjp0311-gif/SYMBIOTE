# Engine evolution after the corrective baseline

Status: **unreleased main implementation; registered measurement pending**.
The public v1.0.1 tag, executables and qualification archive remain unchanged.
These additions require building this source checkout. A package version is not
evidence that a particular executable contains or qualifies these changes.

The next iteration follows [engineering protocol 002](ENGINE_EVOLUTION_PROTOCOL_002.md),
committed at `03dcddc060f0b701c89c6f96fd6603ae365400bf` before implementation.
That protocol is distinct from the earlier transfer-research Protocol 002.

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
