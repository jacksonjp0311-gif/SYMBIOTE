# SYMBIOTE v1.1.0: prospective bounded engine contract

Status: **TARGET / NOT YET QUALIFIED**. Baseline main is
`3239f4e13e44c2a3576069445ceb27a40d32220f`; the packaged release is v1.0.1.
This contract is declared before the new qualification targets open. It does not
change any completed protocol, negative result, HOLD, release asset or tag.
The implementation directive is the owner's Stable Engine Evolution Plan of
2026-10-29. Its critical path is contract, embedding, evidence consistency,
complete learning cycle, reliability, measured optimization, qualification,
then delivery. Implement within the existing four crates.

## Product and support boundary

SYMBIOTE is a Rust-native reasoning and learning engine that acquires authorized
observations, constructs conditional models, independently evaluates inert
knowledge, retains validated capabilities, and adapts permitted decisions using
attributable outcomes. Exactness, persistence, finite execution and inspectable
evidence define this release. It needs neither a language model nor automatic
production-code rewriting. Received data never grants execution authority.

| Dimension | v1.1 acceptance | Status at declaration |
|---|---|---|
| Software correctness | Supported operations return exact conditional answers or explicit failure/abstention; existing BRUTE/affine/graph controls pass | Baseline three-platform CI passed; new gates pending |
| Embedding readiness | A documented typed API and independent consumer complete the lifecycle with no process-wide presentation side effects | Pending |
| Persistence/recovery | Exact identity and committed knowledge retained or explicit bounded failure under declared faults | Existing stopped-owner/crash tests retained; new API gate pending |
| Performance/resources | Complete operation vectors, limits, cold/warm boundaries and instrumentation costs reported | Component optimizations retained; new profile pending |
| Scientific advantage | Reciprocal efficiency requires positive complete measured benefit for each participant against appropriate controls | NOT_DEMONSTRATED; not a software-release blocker |
| Delivery | Installed exact platform artifacts pass behavior, checksum, provenance and public retrieval checks | v1.0.1 qualified separately; v1.1 pending |

Primary stable embedding support is finite affine Boolean inference at widths
1–8, exact query policies, conditional prediction, evaluated retention, outcome
inspection, revocation and stopped-owner verified checkpoint/restore on local
filesystems. Retain existing bounded graph-certificate and Moore reference APIs
and their gates. Do not imply a new general graph embedding contract from the
affine consumer. Unsupported schemas return explicit errors.

Target native platforms are Windows x86_64 MSVC, Linux x86_64 GNU, macOS arm64
and macOS x86_64, each subject to actual installed-candidate acceptance on a
matching runner. A build alone does not qualify an architecture. One host,
explicit identities/grants, supported local filesystems and finite episodes are
the deployment boundary. Independent two-host operation, power-loss durability,
network filesystems and arbitrary remote truth remain unqualified.

The declared minimum Rust version remains 1.98.1 and must be tested, separately
from current stable compatibility. Pin the qualification compiler, lockfile,
features, source manifest and exact executables. Additive public interfaces
target v1.1.0; preserve existing signatures, public struct/enum construction and
schema readers unless a separately reviewed incompatible change is required.
No crates.io publication is implied.

## E0 — baseline and contract

The baseline [CI run 40833650082](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/runs/40833650082)
passed Windows, Linux and macOS on exact main `3239f4e`. Its source-bound
engineering workload is recorded separately at
[Engine Evolution 002](../experiments/engine-evolution-002/README.md): exact
prefix parity, rank learning work 713 versus 28,439 per case, source-off fresh
reuse, isolated ties and receiver-owned retained-case outcomes. Source queries,
wire bytes and larger rank metadata remain in those results. Do not rerun that
closed cohort or the earlier hour and relabel it v1.1 evidence.

Current known limitations include the receiver-role promotion summary omission,
String-based legacy interfaces and CLI output, separate fresh-reuse and transfer
experiments, incomplete whole-operation efficiency, narrow complete-history
proofs, and unqualified broader environments. Preserve initial parallel baseline
failures and their isolated passes; test-only concurrency is not a diagnosis of
an older unexplained timeout. The preserved v1.0.0 audit and research HOLDs remain.

## E1 — documented embedding

Add a small typed facade in `symbiote-runtime`, using the existing reasoner,
evaluator, knowledge store, operational journal and verified backup lifecycle.
The caller owns paths, configuration, explicit authorization, source adapters,
budgets, cancellation and event sink. Distinguish create-new from open-existing.
Expose bounded learning, candidate evaluation, retention, prediction with basis
and applicability, historical/current outcome inspection, revocation, checkpoint,
restore, cancellation and close. Artifacts and deserialized receipts are inert.

The library must not read global stdin, print unsolicited output, change cwd or
global environment, exit the host, silently reset state, or spawn unrelated work.
CLI wrappers own presentation and input-pipe lifecycle. Typed errors distinguish
malformed input, authorization, incompatible schema, uncertainty, contradiction,
revocation, exhausted budget, cancellation and unavailable storage; consumers do
not parse English diagnostics. New error categories must be non-exhaustive or
otherwise versioned for future evolution.

An independent minimal Rust consumer imports only documented engine interfaces
and completes create/open, observe/infer, evaluate/retain, predict, cancel/close,
reopen and retained predict. Two owners in one process have disjoint identities,
paths, events, callbacks and failures; a second writer to one owner is rejected.
Demonstrate no stdout/stdin/cwd/environment side effects. In-process adapters and
sinks are cooperatively cancellable: an arbitrary callback cannot be safely
preempted. Hard termination requires an explicitly supervised adapter process.

## E2 — evidence and counters

Preserve Decision → exact Artifact → Evaluation → Promotion → actual Use →
Outcome, bound to participants, context/schema, original request, evaluator and
policy versions, knowledge anchors and measurement boundary. Reuse existing
feedback and witness validation rather than inventing another success flag.

Add versioned counters for ordinary promotions, receiver-role promotions, total
new promotions, retained reuse, verified capability outcomes and measured
benefits. Derive them from unique committed ledger events within explicit
episode anchors. Identify disjoint roles and subset counts; never add overlapping
quantities. Preserve historical legacy-field semantics. Reads and replay never
create credit. Historical completion remains historical after revocation;
current membership/validity is a separate query.

Regression gates include internally rehashed fabricated receipts, swapped valid
receipts, changed policy/evaluator/source epochs, stale challenges, missing use,
duplicate payload/credit, partial histories, supersession, revocation and restart.
An old valid receipt cannot establish a new interaction's success.

## E3 — one complete learning execution

Use ordinary engine interfaces for two distinct local owners. Acquire individual
authorized observations, infer and validate a model, export its exact artifact,
independently evaluate it at the receiver, promote when justified and freeze.
Restart the receiver before revealing inputs absent from acquisition/validation.
Commit predictions before grading labels, record actual model use, and return
an attributable outcome to the sender. Reconcile once across another restart.
The harness may provision/start/grade; it may not set promotion/success flags.

Demonstrate reverse-direction independently acquired useful knowledge before
claiming bilateral capability. Use optimized isolated structural learners,
exact-answer caches and equal-resource controls. Give isolation the same solver
and rank policy. Include wrong-family/invalid evidence, revocation before use,
interruption before outcome completion and repeated reconciliation. Ties and
negative efficiency are valid results; transfer and fresh reuse must be connected
by the actual same artifact, not by combining separate reports.

## E4–E6 — measurement, research and hardening

Before optimization, record source calls, inference/validation/proof/replay work,
transmitted bytes, durable publication bytes, predictions, outcome processing,
wall time and peak memory. Separate cold setup, warm reuse, ordinary participants,
controls and grading. Report instrumentation overhead and overlapping spans.
Do not convert unlike units without a prospective model or execute an expensive
isolated baseline inside every ordinary operation just to produce a benefit.
Unknown economics remain unknown.

Cache/reuse keys include artifact, schema, source epoch, evaluator, policy and
relevant state anchors. Preserve cold reconstruction, reference checks,
revocation, exact hashes and durable ordering. Profile proof/reconsideration and
whole-history copy costs before changing them. A storage-format migration is a
separate project; do not discard history or increase limits at capacity.

A new, unambiguous research protocol must prospectively register task generation,
costs, horizons, controls, thresholds, stopping rules and bounds. For each actor,
report isolated minus exchange complete costs over the declared fresh-task
horizon, including production/acquisition, independent verification, adoption,
persistence, actual use and outcome closure. Separate cold-start and retained
scenarios. Isolation also retains knowledge. A reciprocal-efficiency claim needs
positive measured benefit for both actors and unchanged correctness. Unknown,
tied or negative results preserve their labels and do not block software release.

Fault matrix: disk-full and permissions, truncated writes, interrupted batch
publication, corrupt/missing/replaced history, concurrent writers, stale locks,
capacity, source/evaluator changes; owned-process termination between decision,
quarantine, prepared evaluation, promotion, use and outcome. Each case restores
exact committed state or returns an explicit bounded failure, with cleanup proof.
No identity reset, unknown-row deletion or invented completed work is permitted.
Derived indexes come only from validated history. Stopped-writer backup precedes
upgrade; older writers refuse unsupported new rows. Restoring an old backup loses
later learning and must say so. Keep existing complete-history proof/frame limits;
reject oversize/incomplete evidence instead of truncating.

## E7–E8 — qualification and public delivery

Run required gates once per candidate unless changes/failures justify focused
repeats: format, all-target strict Clippy, workspace tests and doctests, release
build, cargo doc, BRUTE parity and `tools/verify.py`. Inspect verifier overlap.
Include legacy-consumer compilation, supported feature combinations, exhaustive
reference/property checks and bounded input fuzzing. Never blindly run ignored
registered workloads.

After behavior freezes, register a fresh final-candidate 60-minute/120-cycle
qualification using existing bounded ownership/awake/source guards, actual
restarts and declared recovery events. Reuse the existing qualified supervisor;
pin final source, native/test images, compiler, lockfile and protocol. Preserve
failed attempts. No old campaign is evidence for different executable bytes.

Stage all platform bundles before publication. Execute the installed image on
each claimed platform through learning, retained predictions, cancellation,
verified backup/restore and the supported receiver-outcome path. A pinned native
test driver may exercise the installed image, but driver/image/source identities
must remain separate. Qualify embedding through its independent consumer too.
Native operation needs no Python/model service; development adapters may declare
optional dependencies. Publish checksums, dependency inventory, source/build
bindings and independently verified provenance attestations. Attestation proves
build provenance, not behavior.

Publish only after prepublication gates pass. Anonymously retrieve delivered
bytes, verify pins and repeat public acceptance. On failure, flag that release
and issue a corrected version; never replace an asset or move a tag to hide it.
Use synthetic examples and inspect exports for secrets/operator data. Preserve
original protected records; label sanitized derivatives with separate manifests.
One current release support table, README, API/compatibility docs, examples and
Grok handoff must agree about actual packaged capabilities. Historical tables
remain explicitly historical.

Each milestone records its commit, actual capability, tests, evidence pins,
failures/blockers and next action. Missing environments/permissions remain named.
The finish line is an independent developer completing the documented lifecycle
without undocumented research-harness behavior. Scientific superiority is a
separate, continuing controlled-research question.

References: [Cargo compatibility](https://doc.rust-lang.org/cargo/reference/semver.html),
[minimum Rust contract](https://doc.rust-lang.org/cargo/reference/rust-version.html),
and [GitHub provenance verification](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).
