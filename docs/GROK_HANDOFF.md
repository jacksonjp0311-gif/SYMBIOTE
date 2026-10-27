# SYMBIOTE: Grok handoff

The user requested a clean stop at 9% remaining usage. This checkpoint is ready
for continued development. **Stable v1.0 is not qualified or published.** Cargo's
`1.0.0` is the candidate version; no stable v1 tag should be inferred from it.
The verified public binary release remains v0.5.1.

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
- The latest Darwin fix uses a bounded complete process census to distinguish
  absent/zombie-only groups from active or uncertain ones. Focused checks and
  independent review pass; **real current-head macOS CI is still required**.
  Earlier failed CI process states were not retained, so their cause is not
  retrospectively proven.
- The public-cognition test driver has a thread-scoped executable selector.
  Only its positive test reads `SYMBIOTE_COGNITION_TEST_BINARY`; other threads,
  including duration tests, retain the compiled binary. A new isolation test
  and manifest path/SHA fields need current-head compilation/CI. No local build
  was performed during the frozen hour or after the clean-stop request.

Previous CI `40537061291` at `5fd63adb4d97f304ac67ed54c13a930804ca925b`
passed Windows and Ubuntu; macOS failed one synthetic cancellation check. Preserve
that result. The newly pushed checkpoint's CI must be checked separately.

## Next actions, in order

1. Inspect the new HEAD and CI. Fix genuine failures without weakening gates.
   Run focused tests first; the latest source has reviewed changes that are not
   yet a completed full qualification.
2. Build source-stamped native and service-test executables from a clean commit;
   select their actual paths using Cargo JSON, not guessed filenames.
3. Register a fresh `tools/soak_campaign.py` run. Keep source, HEAD and executables
   unchanged throughout its actual 60-minute/120-cycle envelope. Preserve every
   HOLD. Repeated cycles are not new scientific samples.
4. Update compatibility, qualification, research findings and roadmap from actual
   results. Keep the v0.5 primary, S3/S4 and this cancelled run unchanged.
5. Publish stable v1 only after the declared supported software gates pass.
   Keep independent two-host qualification **OPEN_UNAVAILABLE** until a second
   host is explicitly authorized; this PC is the accepted scope.
6. Verify public assets and install into a temporary directory. Use a newly built
   service-test executable for the exact positive cognitive test, with
   `SYMBIOTE_COGNITION_TEST_BINARY` pointing to the downloaded installed binary and
   `SYMBIOTE_COGNITION_ARTIFACTS` to a fresh directory. Compare the artifact
   manifest's binary SHA to the independent download pin. The old frozen test
   executable cannot perform this substitution.

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
