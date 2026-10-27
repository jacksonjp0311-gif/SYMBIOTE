# Native exact reasoning

SYMBIOTE's `symbiote-reasoning` crate ports the finite hidden-state support
algorithm in BRUTE's `bgr90/symbolic.py`. It carries every surviving partial
deterministic Moore machine permitted by the declared state bound, rather than
choosing one plausible machine. Nullable observations intersect each state's
allowed emission mask. Unknown edges may reach an existing state or introduce
one fresh state, named in first-visit order. The next-output support is the
union over all these possibilities.

This is an exact set computation within the supplied model family. It is not a
probability distribution, a model of arbitrary agents, or evidence that an
external system is stationary or has a particular number of hidden states.

## Provenance and source

The source repository is
[BRUTE](https://github.com/jacksonjp0311-gif/Brute/tree/9edbc035792ca75d3a3333b8454e5bf31c706eb1).
The audited revision is `9edbc035792ca75d3a3333b8454e5bf31c706eb1`, whose
`RELEASE.json` identifies v0.11.0. The annotated v0.11.0 release tag resolves
to `d8b449d45931145ae9b177a88de3833f54301479`; the audited main revision also
contains later documentation commits. BRUTE itself descends from BGR v0.90.0.

The original source is retained byte-for-byte at
[`reference/brute/symbolic.py`](reference/brute/symbolic.py). Its SHA-256 is
`878a0ee803dec0e5095b561b3110a1c8bc99f6c664f853b137e19fad0cde92eb`.
Its original authorship, comments, and scientific limits are preserved. The
pinned upstream tree supplies no LICENSE, COPYING, or NOTICE file; this
reference is not represented as having an upstream MIT grant. Attribution and
the upstream revision remain separate from the license for newly authored
SYMBIOTE code.

## API

The library exports `symbiote_reasoning::SymbolicLearner` at its crate root.
An observation is `[Option<u8>; 2]`, with each channel containing `Some(0)`,
`Some(1)`, or `None`. Actions are `usize` values zero or one.

```rust
use symbiote_reasoning::SymbolicLearner;

let mut model = SymbolicLearner::new(2, 5_000)?;
model.initialize([Some(0), None])?;
model.observe(0, [Some(1), Some(0)])?;
let support = model.predict_support(1)?;
let conditional_answer = model.conditional_certificate(1)?;
let snapshot = model.snapshot();
# Ok::<(), String>(())
```

`new` accepts a state bound from one through six and a row budget of at least
four. Invalid inputs return explicit errors. A singleton support yields a
conditional answer; multiple possibilities yield abstention. `status()`,
`count()`, `evidence()`, and `snapshot()` expose the current auditable state.

If a complete update would exceed the row budget, the learner discards the
partial result and becomes `budget_exhausted`. If no model fits the evidence,
it becomes `grammar_contradicted`. Both states withhold support and retain
subsequent observations. `reconstruct(Some(new_bound), Some(new_budget))`
replays all evidence into a separate learner. No physical certificate or
external permission is inferred from reconstruction.

## Verification

Run from the repository root:

```powershell
cargo test --locked -p symbiote-reasoning
python tools/parity.py --output experiments/parity.json
```

The parity check executes both the retained, unchanged Python source and the
native Rust executable on identical inputs. The committed receipt records
6,093 cases and 20,843 checkpoints:

* Five fixed cases cover masking, constant outputs, contradictions,
  budget exhaustion, reconstruction, and alternating transitions.
* All 5,832 two-step traces at state bounds one and two cover every initial
  nullable two-bit observation and every action/observation pair.
* Another 256 seeded twelve-step traces exercise larger state bounds, tight
  budgets, and reconstruction.
* An independent complete-machine enumeration checks the 5,832 exhaustive
  cases against every labelled complete machine at bounds one and two.

Compared values include both action supports, conditional answers, status,
model-row counts, evidence count, maximum rows seen, failure reason, and
reconstructed state. Four Rust unit tests additionally verify invalid requests,
masking, budget recovery, and contradiction recovery.

Rust uses an ordered set; Python uses an arbitrary set order. At a budget
interruption their diagnostic count of duplicate successors examined can
differ. That counter is excluded from the parity claim. Neither implementation
retains a partially explored hypothesis set after exhaustion.

## Limits and next port

The full SP8 certification policy is not ported. BRUTE's SAT region backend,
margin-family guard, Y1k resynchronization, calibrated alarms, lookahead policy,
and transfer research arms remain available through pinned upstream links.
The current native port does not reproduce those policies or their published
study results. In particular, successful finite confirmation of a received
artifact does not establish universal correctness; BRUTE v0.11.0 itself
reports failed wrong-family transfer soundness gates.

The next reasoning milestone should compare an additional refusal or
resynchronization guard against unchanged BRUTE fixtures, then assess it under
drifting and wrong-family simulated partners. Increasing state similarity or
the number of observations alone is not a learning or reasoning improvement.

## Exchange value

`symbiosis::decide` answers whether a proposed exchange is worth more than
continuing alone, in one participant's declared units. It does not authorize a
connection. An unqualified gain stays `Uncertain` and is not stored as utility
zero. `Connect` requires both participants' existing grants and does not move a
payload. `measure_affine_exchange` counts oracle queries for every canonical
truth of a small width. On width 3 the true hint, the wrong hint, independent
maximin and the fixed basis each use 4 queries for every truth. That is the
information bound `width + 1`. Checking a transferred affine row against the
full fixture costs `2^width` checks, so the cognitive offer is deferred.
Wrong hints are not certified. This enumeration is a mechanism check, not a
transferable-knowledge study.
