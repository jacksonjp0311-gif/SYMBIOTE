# Changelog

## Unreleased — post-v1.0.0 corrections

- Independent release audit: four public native bundles and checksums pass;
  the installed Windows executable passes demo, actual restart, offline
  predictions, backup/restore and configured native cognition. Full stable
  qualification remains HOLD; see [the audit](docs/V1_RELEASE_AUDIT.md).
- Future bundle workflows leave new releases in draft until independent delivery
  and qualification checks finish. Existing public tags and assets are preserved.
- Correct the fresh-hour account: the server retained two models; the client
  retained its unchanged genesis. Reconcile release status and source provenance.
- Benefit predicates now require the receiver ledger and exact promotion witness;
  fabricated receipt JSON and recomputed hashes cannot verify adoption or benefit.
  Distinct-source duplicate payloads no longer count as changed capability, and
  the receipt sender must match the promoted record's stored source.
- Replace flag-only `durable_benefit_verified` with
  `retained_benefit_after_store_reopen`, which opens an existing stopped owner and
  checks retained active knowledge. This observes store replay, not process restart.
  Mutual verification requires both directional witnesses and crossed knowledge
  anchors. Receipt schema `/2` stays readable, but unsafe Rust helper signatures
  intentionally change. Resolve release/API compatibility before publishing a
  replacement version; no new release is approved here.

## v1.0.0 — one-host bounded engine — 2026-10-28

Published source: `426f054771395dcbe1b8711d7128b90ef0c704de`. This release
number does not close the stable qualification, deployment or research gates.
The subsequent [audit](docs/V1_RELEASE_AUDIT.md) records tagged API defects and
the remaining reciprocal-contribution and evidence-delivery requirements.

- One-host hour qualification `PASS_LOCAL_HOUR` on source `31b9418`.
  Registration `97af2bda0bae10a4eecfdabb41507f5448ed3e58a802d05c201224738b4861ca`.
  Campaign report `fa582756fe0055ed876d093055a8e03baa0a332ceca58faa82d37e862c96de72`.
  120 cycles, measurement 3,601,880 ms, two retained models, zero scientific
  samples. The cancelled 71/120 run remains HOLD. Two-host deployment and
  final public evidence packaging remain open.
- Reciprocal receipt schema `symbiote.reciprocal-evaluation/2`. A content
  digest is not benefit. The intended contract requires a completed promotion
  between the receiver's anchors, a derived behavior change and a strict stored
  cost improvement. The subsequent audit found that the tagged public predicates
  do not enforce that contract. The width-3 affine cycle remains negative. Protocol
  002 stays `NOT_RUN`. This is not a reciprocal-efficiency result.
- Pre-exchange value decisions. Unqualified gain is not utility zero. Connect
  requires both existing authorizations and does not send knowledge. Negative
  exchange counts saturate. The cognitive runtime records the plan and
  reconciles it before `candidate.submit`. Full-fixture affine and graph
  transfers are deferred; that decline is not a reciprocal-efficiency gain.
  `partner_benefits_verified` stays 0.
- Value-of-symbiosis decisions and receiver-originated reciprocal receipts.
  Benefit requires local evidence, adoption, a behavior change, a strictly
  lower declared cost than the equal-resource isolated control, and no
  certification bypass. The tagged restart flag is a declaration, not proof. Quarantine,
  agreement and promotion are not benefit.
- Width-3 affine mechanism check: all 16 canonical truths take 4 oracle queries
  under independent maximin, fixed basis, a true hint and a bias-flipped hint.
  Hints do not shrink support. Incorrect certificates: 0. The value function
  returns DEFER. This is not query-transfer protocol 001 and not the
  preregistered protocol 002 cohort.
- Configured cognitive episodes emit VALUE and MEASURE records.
  `partner_benefits_verified` stays 0. A non-positive plan does not submit.
- CI run 40545912958 at `4da99383` passed Ubuntu, Windows and macOS.
  CI run 40557119693 at `b7f46a6` also passed all three platforms, including
  `tools/verify.py`. CI run 40558477313 at `b957548` passed the following
  documentation commit on all three platforms. CI run 40584546812 at `9825165`
  passed Ubuntu, Windows and macOS, including `tools/verify.py`. CI run
  40587280975 at `4737640` passed Ubuntu, Windows and macOS, including
  `tools/verify.py`. That run covers the receipt-attribution commit only.
  The cancelled hour remains HOLD.
  Later commits need their own run.
- Configured native cognitive episodes with bounded authorized sensing,
  independent local evaluation, persistent learning and reciprocal inert offers.
- Exact graph query-policy transfer, held-out graph facts, durable strategy
  promotion/revocation and explicit strategy-aware state migration and backup.
- Three owned native TLS peers with per-edge mutual consent, custody-bound
  forwarding, persistent denials and complete declared plaintext admission costs.
- Outcome-conditioned bounded exploration with fresh promotion anchors,
  actual native restarts and neutral-history/equal-budget controls.
- Prospective transfer protocol and a separate once-only one-hour local
  continuity protocol. Focused engineering checks do not substitute for either
  qualification; negative utility and historical HOLDs remain visible.
- Versioned portable source manifests distinguish exact bytes and ordering from
  the historical verification algorithm. Original evidence remains unchanged.

## v0.5.1 — Durable Operations — 2026-10-27

- Verified offline single-owner backup and restore with external manifest pins,
  byte-preserved identity/history, explicit activation dependencies and protected
  incomplete destinations. Native commands retain actual offline predictions.
- Reviewed offline certificate/policy transitions and peer regrant anchored to
  the exact prior policy and journal head. Denials and historical receipts remain
  intact; pending old-policy evaluations cannot acquire new trust during recovery.
- Independent review reproduced and corrected restore activation through copied
  relative configurations, lifecycle capacity below the accepted configuration
  size, and alias/identity ambiguity in local denial and regrant. Authenticated
  artifact grants remain identity-specific; outbound connections remain alias-only.
- Native ZIPs now contain concise platform instructions and versioned absolute
  documentation links, with the same three-file integrity contract.
- Default software gates passed 292 Rust test executions, 53 Python tests and
  6,093 BRUTE parity cases. One separately selected ignored test passed a fixed
  24-cycle same-PC TLS continuity campaign; its 16 named regression repeats are
  existing tests, not new scientific samples.
- S5 local qualification passed in 83.969 seconds with 66 root commands, two
  retained models, four reviewed two-leaf rotations, two denial/regrant pairs,
  one genuinely lost quarantine reply, an owned service crash and verified
  midpoint relocation. S3's output-filename failure and S4's incorrect consumer
  text check remain HOLD; their raw evidence was preserved. See the
  [qualification account](docs/LOCAL_QUALIFICATION_V051.md) and
  [evidence index](experiments/v0.5.1/README.md).
- The v0.5 scientific results are unchanged. This hardening release does not
  establish better partner selection or qualify stable v1.0. Independent
  two-host deployment and long-term reliability remain open. No v0.6 research
  milestone is inferred from this maintenance release.

## v0.5.0 — Adaptive Relationships — 2026-10-27

- Operator-configured native TLS knowledge service with exact grants, durable
  quarantine, local fixture evaluation, persistent denial and idempotent replies.
- Owner-bound operational journal, interrupted evaluation recovery and exact
  historical-promotion checks that detect a surviving journal paired with an
  older knowledge prefix. Historical learning serializers remain unchanged.
- Actual negotiation/RPC byte meters, operation-specific frame ceilings and
  failure-attempt accounting. Rejected knowledge cannot mutate reasoning state.
- Preregistered prospective relationship experiment with five paired learner
  identities, forty private control profiles, eight observation authorities and
  actual process restarts. Independent raw-evidence verification separates
  software completion, utility and persistent learning.
- Fresh temporary study command, configured service guide and explicit stable
  release gates. The first registered 24-world primary ended HOLD after Windows
  socket exhaustion: 136 completed, one failed and 55 not-run cases remain intact.
  A paced engineering reproduction restores the original setup and completes all
  192 cases with independently verified retained learning. It cannot replace that
  primary. Fixed-peer control is still cheaper and cheap-price exchange is harmful;
  no better-selection or speed claim is made. See [the results](docs/RESEARCH_V05.md).

## v0.4.0 — Reciprocal Improvement — 2026-10-27

- Persistent bounded graph knowledge with conditional route certificates,
  explicit abstention, retained proof envelopes and graph-specific evaluation.
- Complete predeclared 81-world routing cohort with independent learner and
  judge algorithms, paired controls, measured costs and all harmful cases retained.
- Actual offline graph replay and public `route` / targeted `predict` commands.
- Supervised native affine peers over explicitly provisioned mutual TLS;
  persistent-ID/certificate grants, no downgrade and acknowledged revocation.
- Strict opaque context registry, stale-authority rejection and bounded child
  startup/replay; legacy affine receipt serialization remains unchanged.
- Embedding example, compatibility policy and bounded native stability campaign.

The routing cohort is one topology with local endpoints. Logical costs exclude
declared laboratory overhead; fixed peer selection and unfamiliar-domain transfer
remain open. This release is a verified research increment, not stable v1.0.

## v0.3.0 — Adaptive Memory — 2026-10-27

- Shared maintenance coordination, native read-only process checks, safe explicit
  stale-lock recovery and byte-preserving audited state-layout migration.
- Policy-versioned promotions reject changed stationary labels and regressions
  hidden outside the newest evaluation subset; historical receipts remain valid.
- Two supervised native agent processes with private identities and ledgers,
  independent oracle/judge APIs, actual restart prediction and measured zero
  restart oracle traffic. Cloned identities and incompatible stored schemas fail.
- Separate TLS 1.3/mutual-certificate API with explicit CA/name/leaf-pin identity
  grants, scopes, deadlines, connection/request budgets, cancellation and revocation.
- Exact positive-cost graph lower bounds and conservative route certification as
  a second embeddable reasoning primitive; operational graph exchange is deferred.
- Atomic native installation with concurrency leases and verified staging.
- Independent reviews reproduced and fixed a first-initialization owner race,
  an identity-alias deployment gap and a revocation-set resource bound.

The process experiment remains one four-bit context using loopback protocol v1.
TLS v2 is independently tested as a library API. Neither delivery implies
unfamiliar-domain transfer, a new efficiency result, or stable v1.0 readiness.

## v0.2.0 — First Symbiosis — 2026-10-27

- Exact Boolean affine reasoning with active maximin observations, explicit
  epistemic status, bounded work and hints that never replace evidence.
- Two distinct native learner implementations, real scoped TCP exchange of
  oracle-attested observations, independent held-out evaluation and executed
  isolated/negative controls under a declared cost model.
- Schema-bound declarative persistent knowledge with separate agent identities,
  unique training/held-out evidence, cost-aware gates, rollback and offline use.
- Readable terminal commands, diagnostics, strict argument validation, original
  banner, professional README and checksum-verified native installers/bundles.
- Legacy exact BRUTE parity and Genesis behavior retained; stable v1.0 criteria
  remain open. Trusted local oracle, affine-family and simulated-cost assumptions
  do not establish unrestricted transfer or autonomous self-improvement.

## v0.1.0 — Genesis — 2026-10-26

- Independent clean Rust derivative of pinned BRUTE v0.11.0-era source; exhaustive
  983-file upstream manifest, attribution, retained exact Python reference and
  immutable research links.
- Exact native Moore prefix support reasoning with contradiction, abstention,
  budgets and reconstruction; 6,093 Python parity cases and 20,843 checkpoints.
- Authenticated/revocable local JSONL agent protocol, explicit capability and
  resource negotiation, bounded telemetry and descriptive drift.
- Persistent identity, versioned finite knowledge, evidence-bound promotion,
  SHA256 receipt ledger, atomic writes and durable rollback.
- Independent LLM-free runtime with two simulated endpoints, evaluated knowledge
  exchange, derived Boolean strategy contributions, partner-controlled adoption,
  separate benefit/cost measurements and separate-process retention checks.
- Wrong-transfer rejection, failed-candidate recovery, drift revocation and
  corruption tests; PowerShell orchestration and reproducible verification.

Limits: four-input fixture learning; the equal-probe control reaches the same
coverage. Partner costs are declared simulation units. Full BRUTE SP8/SAT policy,
general transfer, nonlocal secure transport and autonomous self-improvement are
not established.
