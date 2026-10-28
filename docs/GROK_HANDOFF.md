# SYMBIOTE: corrective-release handoff

The corrective 1.0.1 engine descends from BRUTE and remains a four-crate Rust
workspace. Continue the existing engine. Its purpose is persistent learning from
authorized evidence and reciprocal interaction, without a language-model dependency.

Current native source: `6025fff43ad4b508b94977eeff801aeebf549fd9`.
The 128-file `symbiote.source-manifest/2` digest is
`aedf4208a3630b31ec9e7383dd018120d4b021f54e70140e63b4f01e91564aad`.
Release documentation, downloaded executables and their qualification have separate
pins. The new hour passes independent data verification. Public binary/archive delivery remains pending in this working draft.

## What is working

- Ledger-witnessed benefit verification and exact causal attribution. Original
  helper signatures compile but unchecked predicates are deprecated and false.
  Distinguish the legacy stored-assessment receipt from the separately witnessed
  finite-task measurement. Neither an ordinary hash nor a restart flag proves gain.
- Observation-driven exact inference, held-out validation and durable reuse.
  The configured width-3/8 proofs make 5/10 source calls initially and zero after
  process restart. `symbiote observe-demo --state state/observation` uses the same
  inference boundary with a simple owned source and no network setup.
- A compact incremental GF(2) affine solver, parity-checked against the retained
  enumerator. Width remains 1–8; observation promotion requires a distinct held-out
  input. Row operations and enumeration checks are different accounting units.
- Explicit normal capability contributions, independent receiver evaluation and
  actual retained-model use. Own incoming good/harm feedback persists and informs
  the next source choice. Cached declines have bounded reconsideration; inventories
  compare compatible payload meaning rather than mere nonemptiness.
- Stage diagnostics, bounded cancellation, ownership, TLS grants, revocation,
  rollback, migration and stopped-owner backup/restore.

## What the results do not establish

The normal fixture's expensive-query received-task windows gain 94,284 and 93,591
declared units; cheap-query windows lose 5,715 and 6,408. Complete participant costs
lose in both cases. Harmful feedback changes the next choice; favorable preference
persists but does not change that fixture's winner.

The registered 64-cell cohort passes operational reciprocity in 237.344 seconds.
It loses aggregate whole-process comparisons against greedy isolation and all
24 fixed orders. Matched resources reproduce the coverage. The scientific sample
count is zero: related finite engineering cases are not independent discoveries.
No answer-caching advantage, generalized transfer efficiency or whole-agent speedup
is established.

Live outbound `partner_benefits_verified` remains zero without receiver-originated
witnesses. Current return adoption/use is proved by separately authorized receiver
CLI checks and the test harness. It is not an autonomous network return-benefit
protocol. Two-host deployment remains `OPEN_UNAVAILABLE`; broad stable qualification
and generalization remain open. Protocol 002 stays `NOT_RUN` and needs its declared
amendment before targets open. Preserve original HOLDs and negative results.

## Where to work

| Area | Source |
| --- | --- |
| Exact inference and reference algorithms | `crates/symbiote-reasoning/src/structural/compact.rs`, `structural.rs`, `planning.rs` |
| Causal feedback and measurement | `crates/symbiote-runtime/src/service/feedback.rs` |
| Authorized evidence acquisition | `service/observation.rs`, `service/evaluation.rs` |
| Selection, semantic inventory and backoff | `service/selection.rs`, `service/cognitive.rs` |
| Durable evidence and witnessed receipts | `crates/symbiote-memory/src/knowledge.rs`, `reciprocal.rs` |
| Independent engineering consumers | `tools/reciprocal_engineering.py`, `tools/soak_campaign.py` |

Run `cargo test --workspace --locked`, strict workspace Clippy and
`python tools/verify.py`. Registered campaigns require their explicit external
registration, fresh output directory, immutable source/executable pins and existing
bounds. Do not retry or retune a failed cohort into a gain.

Next: reduce or amortize actual evaluation/control overhead without weakening
validation; add an authorized, independently checked receiver-outcome channel;
then test an independently implemented unfamiliar adapter under a new prospective
contract. Keep own observations, conditional inference and outside suggestions
distinct.

Read [the corrective account](CORRECTIVE_RELEASE_101.md), [runtime setup](LIVE_RUNTIME.md),
[API compatibility](RUST_API.md), [release gates](STABLE_RELEASE_GATES.md) and
[roadmap](ROADMAP.md). The prior handoff remains available at its
[immutable source](https://github.com/jacksonjp0311-gif/SYMBIOTE/blob/6025fff43ad4b508b94977eeff801aeebf549fd9/docs/GROK_HANDOFF.md).
