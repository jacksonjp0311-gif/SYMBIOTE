# SYMBIOTE: engine evolution handoff

## Current target — v1.1.0 embeddable engine

Continue the implemented engine; do not rewrite it or add placeholder crates.
The owner's Stable Engine Evolution Plan is represented by the prospective
[support contract](V11_ENGINE_SUPPORT_CONTRACT.md). Read the
[current release-specific table](V11_ENGINE_STATUS.md) and
[implementation ledger](V11_IMPLEMENTATION.md) first; they distinguish completed
source work from qualification and public delivery.

The additive `symbiote_runtime::engine` interface, native `engine` commands and
separate developer workspace are implemented. Use
[embedding](ENGINE_EMBEDDING.md), [CLI](ENGINE_CLI.md),
[compatibility](COMPATIBILITY.md), [fault matrix](V11_FAULT_MATRIX.md),
[registered integration](V11_TRANSFER_PROTOCOL_001.md) and
[publication](V11_PUBLICATION.md) as the concrete interfaces and gates.

Finish in this order: combined software/docs/consumer checks → clean source
freeze → once-only registered integration → four-platform installed staging and
Linux ENOSPC → fresh 60-minute/120-cycle exact staged Windows-image qualification
→ independent evidence review → provisional immutable publication → four-platform
anonymous public acceptance → stable promotion. Preserve failed evidence and
separate source/native/driver/consumer pins. No source rebuild or change during
the hour, tag movement, asset replacement, hidden retry, invented baseline or
relabelled efficiency result is allowed.

The new engine owner marker deliberately rejects older/generic writers, including
the published v1.0.1 executable, before mutation. Unmarked prototype engine stores
hold without automatic migration. Stop owners before checkpoint/restore; backup
rollback discards learning acquired after that backup. In-process callbacks are
cooperative, not safely preemptible. Two-host and power-loss remain unqualified.

Record each completed milestone's source, capability, tests actually run, evidence
pins, failures and next action. Scientific superiority is **NOT_DEMONSTRATED** and
is not a blocker for correct, honestly bounded software delivery.

## Historical pre-v1.1 handoff — preserved baseline

The corrective 1.0.1 engine descends from BRUTE and remains a four-crate Rust
workspace. Continue the existing engine. Its purpose is persistent learning from
authorized evidence and reciprocal interaction, without a language-model dependency.

Current unreleased implementation: `bb1b88eaa771be5e201ccfcfe93840c6750eb9d7`.
The prospective engineering protocol was committed first at
`03dcddc060f0b701c89c6f96fd6603ae365400bf`; the single registered workload passed
in 35.015 seconds. [Results and exact nonbinary evidence](../experiments/engine-evolution-002/README.md)
include independent data-only audits, all cost vectors and the original baseline
parallel failures. Build this checkout to use the additions. The published
v1.0.1 downloads and their qualification below are unchanged.

The additions reuse exact verified prefix hashes, validate feedback through one
ordered startup cursor, add optional exact rank-based query selection, and close
an opt-in receiver-owned outcome channel. A separate Python observation source
feeds the native embedding example without supplying coefficients or tables.
Frozen models reopen and correctly answer 128 fresh case/input pairs per arm;
the isolated structural learner ties. The sender reconciles one actual receiver
capability outcome and gives it no duplicate credit after restart. Unknown costs
still produce zero verified economic benefits. See [the engineering account](ENGINE_EVOLUTION_002.md)
for the limits and [the receiver setup](RECEIVER_OUTCOMES.md) for explicit grants.

Published v1.0.1 baseline qualified native source (F1): `6025fff43ad4b508b94977eeff801aeebf549fd9`.
The 128-file `symbiote.source-manifest/2` digest is
`aedf4208a3630b31ec9e7383dd018120d4b021f54e70140e63b4f01e91564aad`.
Release documentation, downloaded executables and their qualification have separate
pins. The new hour passes independent data verification.
Anonymous public native installation, independent component audits and public evidence-archive delivery pass.

Published `v1.0.1` tag source (F2) is
[`c55fc37fd6de38d7d1af4088bbdce616f0446470`](https://github.com/jacksonjp0311-gif/SYMBIOTE/commit/c55fc37fd6de38d7d1af4088bbdce616f0446470),
from [release workflow 40751115124](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/runs/40751115124).
The actual public Windows executable SHA256 is `a06c14dae36a14eaa2fd121201849f0417cab7dccb48fddd009fddbfbb27db7c`.
Evidence archive SHA256 is `53d302b1dbf719dca0ee7dccbea13259493882f22c91c44bc1d7d6f0f0f7bb9a`, with extracted manifest
`ca3d84140ececebc5ef660e952a4bde5629fadc082db676a392895c1a5866878`. [External receipts and public component audits](../experiments/v1.0.1/public-delivery.json)
bind those later events; they do not relabel F1's cohort/hour. The installed native
and source6025 test driver remain separately identified. The demonstrated operating envelope is a finite, bounded one-host engine.

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

In the published baseline, outbound `partner_benefits_verified` remains zero
without receiver-originated witnesses; return adoption/use was proved through
separately authorized receiver CLI checks. Main now has an opt-in native outcome
channel with receiver-owned processing and separate verified outcome/capability
counters. Its strict economic counter remains zero when costs are unknown.
Two-host deployment remains `OPEN_UNAVAILABLE`; broad stable qualification
and generalization remain open. Protocol 002 stays `NOT_RUN` and needs its declared
amendment before targets open. Preserve original HOLDs and negative results.

## Where to work

| Area | Source |
| --- | --- |
| Exact inference and reference algorithms | `crates/symbiote-reasoning/src/structural/compact.rs`, `structural.rs`, `planning.rs` |
| Causal feedback and measurement | `crates/symbiote-runtime/src/service/feedback.rs` |
| Receiver-owned processing and outcome proof | `crates/symbiote-runtime/src/service/outcomes.rs`, `docs/RECEIVER_OUTCOMES.md` |
| Authorized evidence acquisition | `service/observation.rs`, `service/evaluation.rs` |
| Independent source and frozen prediction | `crates/symbiote-runtime/examples/independent_observer.rs`, `adapters/switchbox_source.py` |
| Selection, semantic inventory and backoff | `service/selection.rs`, `service/cognitive.rs` |
| Durable evidence and witnessed receipts | `crates/symbiote-memory/src/knowledge.rs`, `reciprocal.rs` |
| Independent engineering consumers | `tools/reciprocal_engineering.py`, `tools/soak_campaign.py` |
| New prospective engineering workload | `tools/engine_evolution.py`, `docs/ENGINE_EVOLUTION_PROTOCOL_002.md` |

Run `cargo test --workspace --locked`, strict workspace Clippy and
`python tools/verify.py`. Registered campaigns require their explicit external
registration, fresh output directory, immutable source/executable pins and existing
bounds. Do not retry or retune a failed cohort into a gain.

Next: reduce or amortize dominant acquisition/control costs without weakening
validation. Test a useful exchange with independent validation and reuse across
fresh tasks under a new prospective complete-cost contract. Keep isolated adaptive
and exact cache controls; unrelated domains and independent-host operation remain
open. Preserve the historical cohort losses, the unreleased study's isolated ties,
and the distinction between retained-case exchange and fresh source reuse.

Read [the corrective account](CORRECTIVE_RELEASE_101.md), [runtime setup](LIVE_RUNTIME.md),
[API compatibility](RUST_API.md), [release gates](STABLE_RELEASE_GATES.md) and
[roadmap](ROADMAP.md). The prior handoff remains available at its
[immutable source](https://github.com/jacksonjp0311-gif/SYMBIOTE/blob/6025fff43ad4b508b94977eeff801aeebf549fd9/docs/GROK_HANDOFF.md).
