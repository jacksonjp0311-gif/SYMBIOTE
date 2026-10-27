# Genesis architecture and migration plan

Prepared after inspection, before implementation, 2026-10-26. This document is the
implementation plan, not evidence that its milestones passed.

BRUTE current main: `9edbc035792ca75d3a3333b8454e5bf31c706eb1`.
BRUTE release: v0.11.0, tag object `f97197b214eae10bb7a98277e60388f52895c5a0`,
release commit `d8b449d45931145ae9b177a88de3833f54301479`.
AEFL: `cd432ab4208bbf456ac7b932ed885f2170f680ca`, README/spec v1.0, no release tag.

## Actual foundation

BRUTE has 890 tracked files, 574,798,515 blob bytes and 41 root entries.
All 410 Python modules were parsed and their imports and definitions inventoried;
78 test files and the experimental/evidence catalog were inspected. Key systems:

| Source | Purpose | Genesis decision |
| --- | --- | --- |
| bgr90/symbolic.py | Exact canonical partial Moore-machine version space, masks, support projection, reconstruction, fail-closed budgets | Retain byte-identical reference; port to Rust with live parity checks |
| bgr89/latent.py | Complete 1–3-state model catalogue, posterior mass and unanimous support | Pinned reference; avoid NumPy and catalogue growth |
| brute/geometry.py, region.py, region_learner.py | SAT constraint regions, tri-state solver outcomes, margin and resynchronization gates | Pinned reference; full SAT/certification-policy port deferred |
| bgr60/generalist.py, memory.py | Typed local functions, query hints, finite skill receipts and revocation | Refactor concepts into explicit scoped finite-table verification and durable ledger |
| bgr87/finite_bayes.py | Exact rational finite Bayesian planning | Reference; not required for first slice |
| bgr88/transfer.py, brute/transfer.py, soundtransfer.py | Soft motif priors and experimental library transfer | Reference; never turn confirmation counts into authority |
| brute/active.py, planner.py, align.py, drift modules | Information-seeking, drift, change points and conservative certification | Reference; implement bounded reassessment, not universal guarantees |
| experiments/, tests/, results/, docs/research/ | Frozen studies, gates, alternate implementations and failures | Immutable pinned links, no altered/relabelled evidence |

BRUTE's v0.11.0 GST sound-transfer gate failed. Wrong-family applicability-tested
transfer produced false certificates. SYMBIOTE must preserve that finding and
evaluate received knowledge independently. The Rust symbolic port establishes
foundation parity only, not parity with the full current SP8 certification policy.

AEFL has 93 tracked files and 969,433 Git blob bytes. Inspecting its kernel exposes
unseeded randomness and similarity-derived topology; neither is adopted as a
reasoning metric. Adapt typed residue, bounded FIFO buffers and measured drift.
Keep communication and verification explicit and separate from implicit coupling.

## Minimal architecture

Four substantive Cargo crates avoid nine small placeholder packages:

1. `symbiote-reasoning`: exact bounded hidden-state reasoning and fixture runner.
2. `symbiote-protocol`: authorized versioned loopback API, connection budgets,
   revocation, extensible telemetry sensors and bounded echo observations.
3. `symbiote-memory`: finite-task evaluator, versioned knowledge, promotion,
   revocation, stable identity and hash-chained persistent change ledger.
4. `symbiote-runtime`: independent process, two simulated endpoints, cognitive
   cycle, reciprocal contributions, restart and isolated-control experiments.

Runtime has no Python or language-model dependency. Only the developer parity
check executes the original self-contained Python reference.

## Execution and acceptance

Initialize an independent private SYMBIOTE repository with pinned provenance.
Classify every upstream path and hash retained sources. Port exact reasoning,
then implement consent-bound telemetry and exchange, independently evaluated
promotion, persistence and reciprocal contributions. Run native unit/integration
tests, Python/Rust parity, counterexamples, failure recovery and process restarts.
Record actual coverage, verification costs and matched-probe controls separately.
Only claim improvements established within the declared four-input finite task;
the experiment cannot establish general intelligence or general transfer benefit.
