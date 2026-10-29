<p align="center">
  <img src="docs/assets/symbiote-hero.png" alt="SYMBIOTE — interconnected geometric cores exchanging structured knowledge" width="1200">
</p>

# SYMBIOTE

**Symbiotic Adaptive Intelligence**

A Rust-native reasoning and learning engine that acquires authorized observations,
constructs exact conditional models, independently evaluates exchanged knowledge,
and retains validated capabilities across restarts. Its feedback binds decisions
to actual use and outcomes. The native core requires no language model or Python.

[![Verification](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/workflows/ci.yml/badge.svg)](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/jacksonjp0311-gif/SYMBIOTE)](https://github.com/jacksonjp0311-gif/SYMBIOTE/releases)
[![Rust](https://img.shields.io/badge/language-Rust-c98957?logo=rust&logoColor=white)](Cargo.toml)

[Get started](#get-started) · [How it works](#how-it-works) ·
[Evidence](#evidence-and-limits) · [Roadmap](docs/ROADMAP.md) ·
[Embed in Rust](docs/ENGINE_EMBEDDING.md) · [Engine CLI](docs/ENGINE_CLI.md) ·
[Release status](docs/V11_ENGINE_STATUS.md)

> **v1.1.0: typed, embeddable engine.** This checkout adds a small Rust
> interface, native `engine` commands, independent consumer, role-aware counters,
> and exact transfer/use/outcome binding. Candidate qualification and public
> delivery are tracked in the [current support table](https://github.com/jacksonjp0311-gif/SYMBIOTE/blob/main/docs/V11_ENGINE_STATUS.md).
> This source snapshot precedes qualification and publication; the
> [v1.1 release page](https://github.com/jacksonjp0311-gif/SYMBIOTE/releases/tag/v1.1.0)
> records the actual downloadable artifacts. v1.0.1 remains a separately pinned historical baseline.
> Software qualification and scientific advantage have separate gates. General
> transfer efficiency remains **NOT_DEMONSTRATED**.


## Get started

Download or clone this repository. The release installers select your platform,
verify the downloaded archive against its SHA256 manifest, and install a standalone
binary. Release installation does not need Rust, Python, or a model service.
The commands below install v1.1.0 when its qualified bundles are published;
before publication, use the source-build instructions below.

**Windows — PowerShell**

```powershell
git clone https://github.com/jacksonjp0311-gif/SYMBIOTE.git
cd SYMBIOTE
.\tools\install.ps1 -Version v1.1.0 -AddToPath
symbiote doctor
symbiote demo
```

**Linux or macOS — from the checkout**

```sh
sh tools/install.sh --version v1.1.0
~/.local/bin/symbiote doctor
~/.local/bin/symbiote demo
```

Install a native bundle from its exact tag release. Installers require the matching binary bundle on the
[release page](https://github.com/jacksonjp0311-gif/SYMBIOTE/releases). If a bundle
has not been published for your version or architecture, build from source:

```sh
cargo install --path crates/symbiote-runtime --locked
symbiote demo
```

You can also download a matching archive directly, extract it, and run
`symbiote demo` from its directory (`.\symbiote.exe demo` on Windows). See
[installation and recovery](docs/OPERATIONS.md) for paths and platform details.

## Use it

For an application, start with the [typed Rust interface](docs/ENGINE_EMBEDDING.md).
The independent consumer uses only that interface and its own Cargo workspace:

```sh
cargo run --locked --manifest-path tests/consumer-engine/Cargo.toml -- --out ABSOLUTE_NEW_DIRECTORY
```

It creates two isolated owners, observes, infers, evaluates, retains and predicts;
then closes, reopens and predicts without consulting the source. It also checks
cancellation, writer exclusion, revocation and verified checkpoint/restore.
The embedding host owns adapters, budgets, paths and event presentation. Callbacks
are cooperative; hard termination requires an explicitly supervised process.

The installed v1.1 product exposes the same lifecycle through `symbiote engine`.
Follow the [copyable CLI recipe](docs/ENGINE_CLI.md) for a complete observation,
restart and backup example. Every operation returns structured JSON with typed
errors. Engine-owned directories are distinct from older demonstration stores;
incompatible writers refuse them before changing history.

The existing simple local modes remain available:

```sh
symbiote demo       # Watch the original two-agent learning cycle
symbiote observe-demo --state state/observation # Learn by choosing observations
symbiote status     # Inspect retained identity and knowledge
symbiote predict    # Use retained models without network requests
symbiote doctor     # Inspect readiness without changing local state
```

Output is readable by default. Add `--json` for scripts and complete receipts.
Use `--state PATH` to keep independent experiments separate, and `--receipts FILE`
to choose the report destination. Default local state is `state/demo`; generated
reports are written under `experiments/local/`. Both are ignored by Git.

Run `demo` twice to observe retained knowledge being rechecked and reused. Run
`status` or `predict` to inspect and use the retained state. Optional experiments
exercise the broader native system:

`observe-demo` starts from empty memory, chooses
bounded queries through the engine's observation interface and stores a
conditional affine model. Repeat the same command to reuse it with zero source
queries. It needs no network, credentials or model service. Keep its state path
separate from `demo`.

| Command | What it runs |
| --- | --- |
| `symbiote research` | Structural learning, verified exchange and isolated controls |
| `symbiote graph-research` | Paired routing tasks; prints a command for retained `route` queries |
| `symbiote network-research` | Two native peer processes with private state and actual restart |
| `symbiote adaptive-research --reproduce` | Full controlled study; allow about 20 minutes, with a 30-minute cap |

Route queries return a conditional certificate or an explicit abstention. To run
supervised peers over TLS, follow the
[identity and credential guide](docs/TLS_DEPLOYMENT.md). The
[configured knowledge service](docs/SERVICE.md) supports explicitly granted
queries and quarantined offers over operator-provisioned TLS. Local evaluation
controls promotion. `symbiote --help` lists every command and option.

Start with `demo`. The full adaptive study owns its local peer processes,
writes fresh temporary state and preserves all
failed or unfinished cases. A recorded setup can be restored for reproducible
control comparisons; it imports no learned knowledge or private keys.

To preserve a stopped owner, use `backup-state`, `verify-backup` and
`restore-state` with its separately saved manifest checksum. The
[backup recipe](docs/OWNER_BACKUPS.md) keeps identity, evaluated knowledge and
receipts together. A configured service additionally needs explicit
[restore approval or certificate rotation](docs/SERVICE_LIFECYCLE.md); copying a
configuration does not activate restored state.

From a Windows checkout, the single entrypoint also supports:

```powershell
.\SYMBIOTE-All-One.ps1 -Run
.\SYMBIOTE-All-One.ps1 -ObserveDemo -State state/observation
.\SYMBIOTE-All-One.ps1 -Research
.\SYMBIOTE-All-One.ps1 -GraphResearch
.\SYMBIOTE-All-One.ps1 -AdaptiveResearch
.\SYMBIOTE-All-One.ps1 -NetworkResearch
.\SYMBIOTE-All-One.ps1 -Doctor
.\SYMBIOTE-All-One.ps1 -Verify
```

## How it works

**SENSE → MODEL → CONNECT → EXCHANGE → VERIFY → LEARN → CONTRIBUTE → MEASURE → REASSESS**

SYMBIOTE treats observations, conditional inferences and unverified hypotheses as
different kinds of information. A received strategy cannot become trusted merely
because a partner supplied it or because it matches a few examples.

1. **Sense and model.** Read authorized structured telemetry and maintain exact
   hypothesis support. Structural reasoning selects queries that maximize
   worst-case elimination of surviving explanations within its declared family.
2. **Exchange and verify.** Negotiate explicit capabilities, scope and resource
   limits. Check received observations against the separate synthetic oracle
   registry before replaying them into the receiver's unrestricted learner.
3. **Learn durably.** Promote evaluated declarative models into a versioned ledger
   with identity, applicability, provenance and evidence. Corruption or an
   unsupported claim fails explicitly.
4. **Contribute, measure and reassess.** Offer useful knowledge to the partner,
   which retains adoption authority. Bind a decision to its exact offer,
   evaluation, promotion, subsequent use and outcome. Measured, estimated and
   unknown costs remain distinct. Durable favorable and unfavorable outcomes
   inform bounded future exploration. Quarantine and promotion alone are not
   partner benefit. Counterexamples revoke invalidated knowledge without
   deleting its history.

The corrective candidate also supports a narrowly authorized capability goal:
transfer a partial routing certificate that the recipient can independently
check and use on a fresh target. That objective is separate from an economic
claim. Unknown partner costs stay unknown; receiver validation and measured
task-window costs determine the outcome. Equivalent knowledge is suppressed,
and changed artifacts, evaluator code or policy invalidate the relevant cached
decision. [Measurement and limits](docs/CORRECTIVE_RELEASE_101.md).

The structural experiment uses two separate learning algorithms: exact hypothesis
enumeration and Gaussian elimination over binary observations. It evaluates
unobserved inputs across configured widths 3–8 and seeds 7, 19, 43 and 101.
Transferred observations supply evidence; hints never silently restrict the
candidate family or authorize a prediction.

Native observation-driven inference uses an incremental exact binary constraint
system while retaining the enumerator as its reference. The compact reasoner
supports widths 1–8; observation promotion also needs a distinct held-out input
(currently widths 2–8). Row-operation counters and enumerated-model checks are explicitly different
work units; a smaller representation alone is not a measured learning advantage.

The local protocol provides mutual authentication, revocation, sequence checks,
bounded JSONL frames and request budgets. It is scoped to trusted loopback use;
the native process experiment uses that same explicit loopback protocol.
A separate [TLS 1.3 API](docs/SECURITY.md) supplies mutual certificate validation,
name/pin identity binding and resource-limited encrypted sessions for configured
library integrations. The supervised runtime can use this transport with explicit operator credentials;
its integration tests use real TLS on loopback. Nonlocal deployment remains a
separate evidence gate.

The native process experiment keeps each peer's identity and ledgers separate
from the controller. Real process restarts use stored models, with actual oracle
counters required to stay zero during retained prediction. [Deployment](docs/DEPLOYED_AGENTS.md)
and [memory lifecycle](docs/MEMORY_LIFECYCLE.md) document supervision, copied-identity
rejection, crash recovery, immutable backups and byte-preserving migration.

## Evidence and limits

| What is checked | Evidence |
| --- | --- |
| v1.1 typed engine, consumer, exact transfer and delivery | [Current release-specific support and qualification table](docs/V11_ENGINE_STATUS.md), [prospective contract](docs/V11_ENGINE_SUPPORT_CONTRACT.md), [fault matrix](docs/V11_FAULT_MATRIX.md) |
| Unreleased main engine evolution | [Registered results and exact evidence](experiments/engine-evolution-002/README.md): exact cached-prefix parity, lower rank-query work, frozen fresh-input reuse and receiver-owned feedback; isolated learner ties and whole-cost gain remains unestablished |
| Corrective v1.0.1 software | [Three-platform CI on source `6025fff`](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/runs/40733730717); qualified native bytes and public installation are separate checks |
| Learning from an authorized observation source | [Source-pinned component checks](docs/CORRECTIVE_RELEASE_101.md#component-evidence): widths 3 and 8, independent held-out inputs, retained predictions and zero source queries after restart |
| Useful normal reciprocal contribution and feedback | [Source-pinned component checks](docs/CORRECTIVE_RELEASE_101.md#component-evidence): two-way independent adoption, actual later use, retained knowledge and harmful feedback changing a later choice |
| Registered 64-cell engineering cohort | [Operational PASS, efficiency NOT_DEMONSTRATED](docs/CORRECTIVE_RELEASE_101.md#registered-engineering-cohort): all participant aggregate costs exceed isolation; each fixed order is cheaper in aggregate and matched controls reproduce coverage |
| Fresh one-host hour | [PASS_LOCAL_HOUR with independent data audit](docs/CORRECTIVE_RELEASE_101.md#fresh-one-host-hour): 120 cycles, measured 3,602,431 ms; server retains two models and client remains unchanged genesis |
| v1.0.1 public binary and archive delivery | PASS_PUBLIC_CORRECTIVE_DELIVERY, [actual receipt index](experiments/v1.0.1/public-delivery.json); exact tag source [`c55fc37`](https://github.com/jacksonjp0311-gif/SYMBIOTE/commit/c55fc37fd6de38d7d1af4088bbdce616f0446470), [release workflow](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/runs/40751115124); broader stable and two-host gates remain open |
| Original BRUTE algorithm preserved exactly | [Byte-identical Python reference](docs/reference/brute/symbolic.py) and [parity receipt](experiments/parity.json): 6,093 cases, 20,843 checkpoints |
| Original two-agent learning and restart | [Genesis verification](experiments/genesis-verification.json), including rejection, drift, rollback and newer-revision recovery |
| Structural learning, held-out predictions and exchange controls | [Reciprocal exchange receipt](experiments/v0.2/reciprocal-exchange.json) and [v0.2 verification](experiments/v0.2/verification.json) |
| Native processes, retained prediction, recovery and migration | [v0.3 software gates](experiments/v0.3/software-verification.json), [deployment verification](experiments/v0.3/deployed-verification.json) and [native exchange receipt](experiments/v0.3/native-process-exchange.json) |
| Complete graph cohort, conditional routes and durable graph learning | [v0.4 graph verification](experiments/v0.4/graph-verification.json), [raw paired cases](experiments/v0.4/graph-exchange.json), and [experiment protocol](docs/RESEARCH_V04_PROTOCOL.md) |
| Native adaptive relationships, exact setup replay and honest controls | [v0.5 engineering verification](experiments/v0.5/engineering-verification.json), [preserved primary HOLD](experiments/v0.5/primary-verification.json), and [methods/results](docs/RESEARCH_V05.md) |
| v0.5.1 local maintenance and continuity | [S5 qualification](docs/LOCAL_QUALIFICATION_V051.md) and [evidence index](experiments/v0.5.1/README.md): 24 TLS cycles, reviewed rotation, denial/regrant, lost reply, owned crash and verified relocation |
| Public v0.5.1 installation and native delivery | [Download/install receipt](experiments/v0.5.1/publication-verification.json): all seven assets verified, four ZIP architectures inspected, actual Windows restart and backup/restore passed |
| Authentication, budgets, integrity and failure recovery | Native unit/integration tests and [cross-platform CI](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/workflows/ci.yml) |
| Scientific interpretations and failed criteria | [Research findings](docs/RESEARCH.md) and [roadmap](docs/ROADMAP.md) |

The new normal-policy fixture separates capability from efficiency. Its local
SENSE-through-first-use windows gain at the expensive observation price and lose
at the cheap price. Full participant cost comparisons lose in both cases;
matched-resource controls reproduce the coverage. Favorable preference is retained,
but does not change that fixture's winning choice; harmful feedback does change
the later choice. [Exact scope and results](docs/CORRECTIVE_RELEASE_101.md#component-evidence).

The published v1.0.1 engine closes its own incoming learning and feedback loop. Return adoption
and use are proved through separately authorized receiver CLI/test-harness
checks; the live outbound `partner_benefits_verified` counter remains zero
without witnessed receiver feedback. A fully autonomous network return-benefit
protocol is not established. Validating a distinct held-out target and then
reusing it does not establish an advantage over answer caching.

The separately registered 64-cell cohort also passes operational reciprocity
while losing its aggregate full-cost comparisons. Neither its fixed-order nor
matched-resource controls establish an exchange-efficiency advantage.

Main now adds the separately authorized receiver-outcome channel and an
independent observation-source embedding. Its frozen fresh-input workload
distinguishes structural reuse from exact answer caching, while isolation ties.
Next, reduce dominant acquisition/control costs and test complete economics of
an exchange reused on fresh tasks. Broader stable qualification remains open.

The v0.5.1 default software gate passed **292 Rust test executions, 53 Python
tests and 6,093 parity cases**. A separately selected ignored test completed the
24-cycle continuity check; 16 named regression repeats are existing tests, not
new tests or independent samples. S5 took 83.969 seconds with 66 root commands.
The earlier S3 and S4 checker failures remain **HOLD**, even though S4's native
phase passed. The same two fixtures, two owners and two evaluated models were
used throughout; this is narrow local recovery evidence, not long-term or
two-host qualification. [Full account](docs/LOCAL_QUALIFICATION_V051.md).

Genesis increased prediction coverage from 32/64 to 64/64 on repeated four-input
tasks; its equal-probe-budget control also reached 64/64. This does not establish
a sample-efficiency advantage for exchange.

The structural experiment studies reuse of authenticated observations under a
trusted synthetic oracle registry and an explicit cost model. Any reciprocal
benefit is limited to those conditions. Acquisition cost is counted for both
participants; exchanged evidence, verification, adoption and predictions also have
declared costs. The learners, oracle implementations and evaluation logic are
separate software components, not independent research teams. Conditional
agreement within an affine family does not prove that an arbitrary external
agent belongs to that family. Repeated laws or predictions must not be counted
as independent discoveries.

The [affine](docs/RESEARCH_V02.md) and [routing](docs/RESEARCH_V04.md) studies
include conditional benefits, cheap-observation controls, harmful exchanges and
withheld predictions. They retain their original formulas, evidence and limits.
Declared participant costs exclude laboratory overhead and establish no general
efficiency or wall-clock advantage.

The v0.5 engineering reproduction runs five native learner roles across four
controls and two prices on the same 24 unfamiliar graphs. It retains two complete
graph contexts and replays 21 predictions per active learner with zero evaluator
requests. Its 64 stored promotions are repetitions across private control profiles.
Normal A+B1 logical cost falls from 110,119 to 107,380 versus isolation; the fixed
control costs 107,176. Cheap-observation exchange costs more than isolation.
Partner scores change, but this trace shows no changed actions from those scores.
The first primary remains HOLD; complete evidence and failed criteria are
[published together](experiments/v0.5/README.md). No wall-clock speedup is claimed.

Stable v1.0 requires broader independent environments, demonstrated reciprocal
benefits after all costs, secure external connections, robust persistent memory
and a documented failure envelope. Version numbers advance after the evidence.
The [release gates](docs/STABLE_RELEASE_GATES.md) record which local lifecycle
checks passed and which deployment, duration and scientific criteria remain open.

## Architecture

Four substantive Cargo crates keep reasoning, authorization, learning and runtime
behavior explicit without fragmenting the system into placeholder packages.

| Path | Responsibility |
| --- | --- |
| `crates/symbiote-reasoning/` | Exact hidden-state and affine inference, conservative graph certificates, active queries, conditional prediction and the value-of-symbiosis decision |
| `crates/symbiote-protocol/` | Authorized local sessions, separate TLS 1.3 API, resource limits, sensors and revocation |
| `crates/symbiote-memory/` | Private identity, evaluated knowledge, operational journals, reciprocal evaluation receipts, idempotency, rollback and lifecycle integrity |
| `crates/symbiote-runtime/` | Typed embedding and native CLI, active learning, exact exchange/outcomes, configured peers, diagnostics and experimental controls |
| `docs/` | Architecture, mathematics, operations, provenance, research and version objectives |
| `docs/assets/` | Original project artwork and its provenance |
| `docs/reference/` | Preserved upstream algorithm used by developer parity checks |
| `experiments/` | Compact checked receipts; local generated runs stay ignored |
| `tests/fixtures/` | Shared original-Python/native fixtures |
| `tests/consumer-engine/` | Separate developer workspace using only the documented typed engine API |
| `tools/` | Installers, verification, packaging and upstream audit utilities |
| `SYMBIOTE-All-One.ps1` | Synchronous Windows build, run, research, test, verify and Git operations |

[Architecture](docs/ARCHITECTURE.md) · [Compatibility](docs/COMPATIBILITY.md) · [Reasoning](docs/REASONING.md) ·
[Protocol](docs/PROTOCOL.md) · [Operations](docs/OPERATIONS.md)

### Published v1 and continuing qualification

The public v1.0.0 source adds a configured native
cognitive runtime, portable query strategies with durable revocation, controlled
three-peer TLS topology, outcome-conditioned exploration and strategy-aware
backup/migration. The runtime can also score a proposed exchange against an
equal-query isolated control and refuses non-positive outbound fixture offers.
The [release audit](docs/V1_RELEASE_AUDIT.md) found incorrect tagged benefit
helpers; v1.0.1 qualifies the corrections separately. These are
bounded engineering checks. Query-transfer protocol 001 remains
`NOT_DEMONSTRATED`. The historical hour on source `31b9418` passed; the cancelled
71/120 attempt remains HOLD. The replacement source's fresh hour records
PASS_LOCAL_HOUR on `6025fff`, with independent data review passing.
Anonymous public native installation, independent component audits and public evidence-archive delivery pass. Neither research question is closed by the value function. [Protocol 002](docs/RESEARCH_V06_PROTOCOL.md)
is preregistered and has not been run.

[Native architecture](docs/NATIVE_ARCHITECTURE.md) ·
[Run your configured agent](docs/LIVE_RUNTIME.md) ·
[Qualification contract](docs/V1_RELEASE_CONTRACT.md)

## Develop and verify

Rust 1.98.1 is the declared minimum and qualification compiler; current stable is
checked separately. Python 3.11+ is needed only for
developer verification against the original Python implementation.

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
python tools/verify.py
cargo doc --workspace --no-deps --locked
```

`Cargo.lock` pins dependencies. Verification reports failures and preserves the
distinction between software correctness, measured fixture outcomes and broader
research claims. [Changelog](CHANGELOG.md).

## Foundation and attribution

SYMBIOTE is a clean derivative of
[BRUTE](https://github.com/jacksonjp0311-gif/Brute/tree/9edbc035792ca75d3a3333b8454e5bf31c706eb1),
pinned at `9edbc035792ca75d3a3333b8454e5bf31c706eb1` from its v0.11.0 era.
BRUTE's selected symbolic algorithm is retained unchanged. Its full SP8/SAT
certification policy is not claimed ported, and its failed sound-transfer gates
remain documented. AEFL contributes independently adapted bounded telemetry and
drift concepts; similarity is not a learning criterion.

All 983 upstream files are classified in the
[migration manifest](docs/upstream-manifest.json). Original repositories,
authorship and scientific evidence remain untouched and accessible through
pinned links. Historical archives and massive generated results stay upstream.

The v1.1 source snapshot is about 9.64 MB across 15 root entries, versus
BRUTE's 574.80 MB and 41 entries: about 98.32% fewer bytes.
[Current footprint](experiments/v1.1.0/footprint.json) excludes Git history, build
caches and local state; [the earlier snapshot](experiments/footprint.json) is
preserved. Full study traces live in checksum-pinned release assets.

New SYMBIOTE code uses the [MIT license](LICENSE). The retained BRUTE reference
has an explicit exception because the inspected upstream supplied no license
declaration; its original rights are preserved. See
[full provenance](docs/PROVENANCE.md) and [artwork provenance](docs/assets/README.md).
