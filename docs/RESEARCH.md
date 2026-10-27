# Genesis research findings

This file preserves the v0.1 interpretation. The subsequent structural experiment
is documented separately in [First Symbiosis research](RESEARCH_V02.md).

Status: actual deterministic software experiments for v0.1.0, not a preregistered
general intelligence study. The plan preceded implementation; algorithm, fixture,
evaluator and author are not independent research teams. Failed controls remain
reported. Raw compact receipts are in `experiments/`.

## Observations

Two services expose complete Boolean tasks with four possible input codes.
Alpha computes the XOR of the two input bits; beta selects the second bit.
Their prediction policies initially cover input 0 and 1 only. The independent
SYMBIOTE process observes that same partial telemetry, maintains conditional
hidden-state hypotheses, requests a table and validates all four API outputs.
The evaluator is deterministic and exhaustive for these fixtures.

The isolated partial-model control scores 16/32 per partner, abstaining on 16.
After promotion the evaluated task models score 32/32 each. Those tables survive
a process exit and reload with the same identity. Restart promotes nothing new
and reuses two artifacts. An offline `predict` reload uses zero network requests.
A wrong artifact is rejected without promotion; a subsequent valid artifact
works. A changed unseen input revokes the affected prior table during full
reassessment. The runtime reports failure instead of silently adopting it. On a
subsequent run, the restored partner can issue a newer revision and regain
promotion after exhaustive evaluation; the original revocation remains auditable.

The same-budget control makes four direct probes per partner without requesting
a knowledge offer and independently constructs a complete table. It also scores
32/32. Therefore additional evidence explains the coverage increase; these
results establish **no sample-efficiency advantage or general transfer advantage**
for the exchange mechanism. SYMBIOTE still demonstrates the requested persistent
learning mechanism: a measured, durable change in future prediction coverage.

Each partner independently validates SYMBIOTE's derived compact expression before
using it. A baseline policy uses a local lookup on 16 tasks and an oracle on 16.
Under the explicit cost model lookup/expression=1 and oracle=10, this costs 176
units. The expression costs 32 prediction units plus 40 validation units, totaling
72. Both complete policies answer all 32 tasks correctly with fallback; autonomous
prediction coverage rises from 16 to 32. This is a simulated operational cost
reduction, not CPU latency or a breakthrough. Partners already possess their own
truth tables; the returned value is a verified compact execution strategy, not new
facts unknown to their oracle. Partner policy adoption is in-memory in v0.1; only
SYMBIOTE's own identity and learning ledger persist across process restarts.

The repeat count amortizes validation but supplies no new independent inputs.
Unique evaluation cases are four per partner. The authenticated API serving probes
also serves the offered table: tests establish behavior against simulator ground
truth, not a guarantee against a dishonest arbitrary remote agent.

## Verification

- Exact original-Python/Rust parity: 6,093 cases and 20,843 checkpoints, no
  mismatches, including 5,832 independently enumerated complete-machine cases.
- 33 native unit/integration tests pass. They cover exact observation masks, contradiction, work-budget
  abstention, replay/reconstruction, incorrect knowledge, evaluation forgery,
  duplicate/aliased revisions, durable rollback, corruption, failed writes,
  contention, authentication/replay, unauthorized operations, bounded frames,
  global request budgets, timeout, cancellation, revocation and process restarts.
- Strict formatting and Clippy checks are required by `tools/verify.py` and CI.
- [parity.json](../experiments/parity.json) and
  [genesis-verification.json](../experiments/genesis-verification.json) record the
  observed software gates. First-run, retained, restart, rejected, drift and ledger
  receipts preserve the underlying experimental events.

The parity suite compares exact status, support, conditional answer, evidence,
model rows, high-water mark, failure and reconstruction. An incidental work counter
at the instant of budget interruption depends on Python set iteration order and
is explicitly excluded; no decision or algorithm is approximated.

## Mathematical model

Each agent i has independent state s_i(t), observations o_i(t), authorized actions
a_i(t), knowledge K_i(t), and measured task performance m_i(t). An exchange
E_(j→i) is inert structured evidence, strategy or hypothesis with provenance and
applicability Ω. Verification V_i is evaluator-specific and may return reject,
abstain or an evidence-bound promotion record.

```
K_A(t+1) = Update(K_A(t), Verify_A(E_B→A))
K_B(t+1) = Update(K_B(t), Verify_B(E_A→B))
```

Update preserves K on rejection/abstention; successful promotion adds a new
version; a counterexample revokes the active version without deleting history.
For a complete, correctly observed deterministic finite domain D, v0.1 checks
∀x∈D: f_candidate(x)=f_oracle(x), zero regression on previously correct predictions,
and increased coverage. Exhaustive equality on D is an established finite fact;
stationarity, honest measurements and applicability beyond D are assumptions.

A prospective reciprocal utility is:

```
Δ_i = measured performance_i(candidate) - performance_i(control)
U = w_A Δ_A + w_B Δ_B - λ(C_A+C_B) - μ I - ν R
```

Here C includes acquisition, verification and adoption cost; I counts incorrect
transfers; R counts harmful regressions. All weights and metrics must be declared
before future studies. A reciprocal-utility gate should require nonnegative
participant-specific net benefits and at least one strict gain for each agent;
an aggregate score must not hide a harmed partner. This is a proposed research
criterion. v0.1 reports coverage and simulated cost separately and does not claim
to optimize or empirically validate a universal utility function.

Established software invariants: candidate data alone cannot promote; complete
finite verification is required; grants are explicit and revocable; rejected
knowledge preserves the ledger state; revoked revisions cannot reactivate;
exact reasoning uncertainty and budget exhaustion cannot become certificates.
These are enforced implementation properties under the documented local trust
model, not theorems of arbitrary-agent safety.

Conjectures for later studies: reciprocal exchange may reduce redundant
exploration, accelerate reusable abstractions, transfer across domains and help
select useful collaborators. This release supplies no evidence for those claims.

## AEFL assessment

Typed residues, bounded per-agent buffers and measured drift are useful engineering
ideas. AEFL's scalar coherence/topology similarity is not correctness. Its original
loop includes unseeded randomness and differently seeded controls; those results
are not imported as paired evidence. Adaptive coupling/topology are deferred until
partner utility can be independently measured. Communication here is explicit;
implicit field alignment does not constitute knowledge transfer.
