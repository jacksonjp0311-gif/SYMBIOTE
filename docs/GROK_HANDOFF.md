# SYMBIOTE: Grok handoff

**Stable v1.0 is not qualified or published.** Cargo's `1.0.0` is the candidate
version; no stable v1 tag should be inferred from it. The verified public
binary release remains v0.5.1.

## Source-grounded assessment

What is implemented: four crates for exact reasoning, authorized exchange,
durable memory and a configured cognitive runtime. Query policies, three-peer
custody, bounded exploration, backup and migration are in the tree. The new
`symbiosis` and `reciprocal` modules add a participant-specific value function
and a receiver-bound receipt. Benefit now requires a completed promotion
between the receiver's own anchors. A content digest, a caller-supplied sender
net, and a declined value plan cannot verify it. The cognitive episode records
`MEASURE`. `partner_benefits_verified` remains 0.

What verified evidence supports: CI run `40545912958` at
`4da99383e9081767f4f0e08eda671323a76629fa` passed Ubuntu, Windows and macOS.
Frozen research at `ddd63d7954917c949ea1173a90f30343bcb16397` still stands,
including parity, the cognitive promotion/restart control, reciprocal adoption
inside that control, and the negative utility results below. On this Windows
machine, `cargo test --workspace --locked` for the receipt-attribution tree
passed 357 tests and left the 3 registered duration tests ignored. Clippy with
`-D warnings` passed for the workspace crates. An earlier local count of 351
belongs to the tree before this receipt change. Python is not installed here,
so local `tools/verify.py` was not re-run and the committed parity receipt was
not rewritten. CI run `40557119693` at `b7f46a63bd1268458124aaf05cf6097a6d44c841`
then passed Ubuntu, Windows and macOS, including `tools/verify.py`. Run
`40545912958` remains the record for `4da99383` only. A later documentation
commit is not covered by `40557119693`.

What is incomplete: the hour campaign, independent two-host deployment, public
v1 assets, and any reciprocal-efficiency gain. Protocol 002 is preregistered
and not run. The configured `run` path now plans a value decision before
`candidate.submit`. Full-fixture affine and graph transfers are deferred, so
those episodes send no contribution payload. `partner_benefits_verified`
remains 0. CI run `40558477313` passed Ubuntu, Windows and macOS at
`b957548`, including `tools/verify.py`. CI run `40584546812` passed Ubuntu,
Windows and macOS at `9825165`, including `tools/verify.py`. CI run
`40587280975` passed Ubuntu, Windows and macOS at `4737640`, including
`tools/verify.py`. That run covers the receipt-attribution commit and does not
cover a later documentation commit.

The next bottleneck is not more message delivery. Transferred query guidance
on the frozen cohort, and affine hints in the new mechanism check, match cheap
fixed strategies once verification is required. The information bound for a
width-3 affine truth is 4 binary queries. A hint that cannot shrink support
cannot beat that bound. Useful symbiosis has to supply a constraint the
receiver can certify more cheaply than discovering it alone, across tasks the
isolated control does not already solve. Protocol 002 is the preregistered
place to test that. It is not a license to rerun protocol 001.

Highest-value next work, in order:

1. Run the fresh source-frozen hour campaign on a commit whose software gate
   has passed, with a new registration. Do not resume the cancelled run.
   Python is not installed on this PC, so `tools/soak_campaign.py` cannot be
   executed here. Do not shorten the campaign and call it the hour gate.
2. Execute protocol 002 only after a registration pin. Report a negative net
   as negative. Its receipt predicate now names
   `symbiote.reciprocal-evaluation/2`. Status remains `NOT_RUN`.
3. Publish stable v1 only after the declared software gates pass. Two-host
   qualification stays **OPEN_UNAVAILABLE**. Do not claim reciprocal-efficiency
   superiority from the receipt predicate or the width-3 mechanism check.

## Start here

Read [native architecture](NATIVE_ARCHITECTURE.md), [runtime setup](LIVE_RUNTIME.md),
[qualification](V1_QUALIFICATION.md), [release contract](V1_RELEASE_CONTRACT.md),
and the [original research crosswalk](ROADMAP.md). The goal remains a native
reasoning and learning participant; no language model is required.

Four substantive crates implement exact reasoning, authorized protocols,
durable learning and the runtime. New features include configured cognitive
episodes, query-policy learning/revocation, three-peer topology, explicit bounded
exploration, strategy-aware migration/backup and a public Rust runtime API.
The README's original artwork remains in `docs/assets/symbiote-hero.png`.

## What actually passed

- Frozen source `ddd63d7954917c949ea1173a90f30343bcb16397`: 344 Rust tests in
  debug and source-stamped release builds, 92 Python tests, 6,093 original BRUTE
  parity cases/20,843 checkpoints, strict debug/release Clippy and strict rustdoc.
- Cognitive process: two authorized native TLS endpoints; two fresh models;
  restart retains both with zero fresh promotions. Two reciprocal quarantines
  are independently evaluated by their receiving owners, extending each to two
  task families. Quarantine alone is never credited as partner adoption.
- Query-transfer protocol 001 ran once: all 48 cells/192 evaluations independently
  verified; 16 labelled tasks represent eight weighted isomorphism groups.
  **Strong reciprocal efficiency is NOT_DEMONSTRATED.** Its restricted policy
  class is contained in the fixed controls and adds overhead. Do not retune or
  replace this cohort to obtain a gain.
- Three-peer native control: six successful inert hops, retained models after
  restart; aggregate saving **−428 declared work units**, a loss.
- Exploration control: durable outcomes change the next selection A→B, while
  neutral history still chooses A. Equal-observation isolated controls also
  cover the tasks; no efficiency advantage follows.

Compact exact receipts are in [the checkpoint directory](../experiments/checkpoints/v1-20261027/).
Their absolute paths refer to the original PC and are provenance, not portable
activation instructions. Full raw state remains preserved at the locations below.

## Cleanly stopped duration run

The once-only hour attempt was cancelled through its installed handler at the
user's request: **HOLD, 71/120 cycles, 2,133.187 seconds**. Known owned processes
are absent, Windows Job cleanup is verified, source-watch failures are empty,
and source/binary pins are unchanged. The first two rotations, denial/regrant,
lost committed reply, owned crash recovery and midpoint backup/restore completed
before cancellation. This partial run is not an hour PASS.

Report SHA256: `73dd0319d24e16352a92b557ef65b259773101f7696cc1ec381387e062bcd1d3`.
Raw events SHA256: `8770a927791f9f190a533d30400ccea7b10c6c89f716f6851aad2fef94cac4e6`.
Do not resume/regrade this attempt. A future full campaign needs fresh state,
registration, external digest and a clean source freeze.

## Current release-development changes

The release checkout branches from the frozen source. Production Rust, Cargo
and protocol documents remain unchanged. Later changes are verification helpers,
test drivers and documentation:

- Installer tests now build/use release binaries without increasing the size cap
  and reject a binary version different from the workspace.
- macOS verifier fixtures resolve `/var` aliases while preserving strict evidence
  link checks. POSIX cleanup handles already-gone groups without hiding EPERM.
- The Darwin process census at `4da99383` is covered by CI run `40545912958`,
  which passed Ubuntu, Windows and macOS. Preserve the earlier macOS failure at
  `5fd63ad` (run `40537061291`); it was not regraded.
- The public-cognition test driver has a thread-scoped executable selector.
  Only its positive test reads `SYMBIOTE_COGNITION_TEST_BINARY`. Public v1
  assets are still unpublished, so that installed-binary check has not run.
- Value-of-symbiosis and reciprocal receipts are later than `4da99383`. Their
  CI is the run for the commit that contains them, not run `40545912958`.

## Next actions, in order

1. CI for `b7f46a6` passed on Ubuntu, Windows and macOS in run `40557119693`.
   Fix any later failure without weakening gates or frozen receipts.
2. Build source-stamped native and service-test executables from a clean
   commit. Select paths from Cargo JSON, not guessed filenames.
3. Register a fresh `tools/soak_campaign.py` run. Keep source, HEAD and
   executables unchanged throughout its 60-minute/120-cycle envelope. Preserve
   every HOLD, including the cancelled 71/120 run. Repeated cycles are not new
   scientific samples.
4. Update qualification from that campaign's actual result. Keep the v0.5
   primary, S3/S4, protocol 001 and the cancelled hour unchanged.
5. Publish stable v1 only after the declared software gates pass. Two-host
   qualification stays **OPEN_UNAVAILABLE** on this PC's scope.
6. Verify public assets in a temporary directory. Point
   `SYMBIOTE_COGNITION_TEST_BINARY` at the downloaded binary and
   `SYMBIOTE_COGNITION_ARTIFACTS` at a fresh directory. The frozen study
   executable cannot perform that substitution.
7. Execute protocol 002 only from a new registration pin. Do not describe a
   negative or unrun result as a gain.

## Tooling and evidence

`tools/release/` contains byte-pinned evidence packaging helpers and an explicitly
draft publisher. The V3 packager passed 14 disposable interface tests plus narrow
independent review; it requires stopped writers and a separately reviewed manifest
digest. The publisher has only offline/mocked checks, not live qualification.
Do not blindly run its publishing mode. No v1 assets have been published.

Original PC locations:

| Material | Location |
| --- | --- |
| Release checkout | `C:\Users\jacks\Documents\Codex\2026-10-26\codex-master-directive-symbiote-symbiotic-adaptive` |
| Frozen study checkout | `C:\Users\jacks\.codex\worktrees\stable-lifecycle\codex-master-directive-symbiote-symbiotic-adaptive` |
| Frozen builds, cognition and controls | `%TEMP%\sb-a12cfc5f` |
| Transfer receipts and private model histories | `%TEMP%\st-1d858e45` and `%TEMP%\ts-1d858e45` |
| Topology / exploration private states | `%TEMP%\tn-13864655` and `%TEMP%\ep-6c8e23aa` |
| Cancelled duration run | `%TEMP%\sh-c72a15a2` |
| Tool drafts, failure logs and validation | `%TEMP%\symbiote-audit-20261026` |

If a checkpoint archive exists in `experiments/local/grok-handoff`, retain its
manifest/checksums and attach it when using a remote Grok session. Never commit
private TLS keys. Cancelled processes may leave dead writer locks: use documented
`inspect-state`/`recover` checks, not deletion or identity reset.

BRUTE is untouched and pinned at `9edbc035792ca75d3a3333b8454e5bf31c706eb1`.
Keep authorship, original reference bytes, licences and historical scientific
evidence intact. No general intelligence, universal certification, autonomous
self-improvement or transfer-performance breakthrough is established.

## Final preservation note

Full raw roots, both exact qualified executables, failed CI logs and archive-plan
diagnostics were copied into the ignored local directory
`experiments/local/grok-handoff/` before stopping. No checkpoint archive was
created: strict packaging correctly HOLDs because `release-tests.jsonl` is a
mixed Cargo JSON/test transcript rather than pure JSONL. Preserve its original
bytes and SHA; add an explicit reviewed transcript classification instead of
bypassing credential scanning. The failed plan and scanner diagnostic are in
the local handoff directory. Compact receipts and all source are public in Git.
