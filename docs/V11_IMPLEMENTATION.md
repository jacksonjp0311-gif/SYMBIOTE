# v1.1 implementation ledger

Baseline: `3239f4e13e44c2a3576069445ceb27a40d32220f`, public package v1.0.1.
The support contract was committed first at `4ce38ce`; the transfer protocol was
registered in source at `3cc4552`, before its targets were opened. This ledger
records engineering progress, not a substitute for final candidate receipts.

| Stage | Concrete change | Evidence and remaining gate |
|---|---|---|
| E0 | Separate correctness, embedding, recovery, resources, science and delivery contracts; retain four crates | Prospective contract and exact baseline; historical HOLDs unchanged |
| E1 | Typed Engine lifecycle, authorized individual observations, opaque evaluated candidates, event sink, cancellation, independent consumer and native CLI | Focused lifecycle/isolation/source-off reopen checks; final consumer on each platform pending |
| E2 | Role-aware committed counters, actual publication/resource accounting, exact local transfer and native causal outcome reconciliation | Fabrication, duplicate, identity, stale ticket, missing use and revoked model checks; registered integration pending |
| E3 | Separate public-API consumer and controller for actual restart, frozen fresh tasks, isolated/cache/equal-resource controls and once reconciliation | Original b46 primary passes with independent data audits; final-source qualification reproduction pending |
| E4 | Owned-process fault matrix, explicit stale-lock recovery, exact live-ledger guards, engine-writer admission and prevalidated restore | Development fault tests and actual old public Windows writer probe; Linux ENOSPC and final hour pending |
| E5–E6 | Keep existing exact prefix/rank improvements; meter full-operation resources without inventing a baseline | No new efficiency advantage claimed; cheaper-certificate research remains open |
| E7–E8 | Source-CI-gated four-platform staging, installed consumer/native acceptance, compiler/lock/SBOM/provenance and immutable publication tools | Offline tooling tests; final candidate, hour and public acceptance pending |

The original registered E3 primary on `b46ec34` completed in 13.062 seconds with
`PASS_ENGINEERING_ONLY`; optimized structural controls tie and economics remain
unknown. Its immutable registration/report pins are recorded in the prospective
[qualification-reproduction amendment](V11_TRANSFER_PROTOCOL_001.md).
Staging run `40857485434` then exposed a debug test-image size refusal before the
Linux full-filesystem fault and a checker using the wrong longstanding legacy
observation law. Preserve that failed run and its artifacts. The release profile
and independent fixture expectation are corrected without changing engine Rust,
consumer, task specification or budgets. Final source requires separately pinned
qualification; a reproduction uses already opened engineering targets and cannot
be counted as another primary or scientific sample.
The same staging run's Intel Mac source gate timed out at the unchanged
300-second combined compile/test deadline. A separately bounded cold compilation
probe and preserved timeout output now distinguish compilation from warm test
execution. This is an explicit CI boundary change, not proof that an older
unexplained timeout has been fixed. Source `6689822` records 249 seconds of cold
Intel compilation, followed by a passing separately bounded source verifier.
These phase measurements do not diagnose the historical 37-minute event.

Source CI `40860247104` attempt 1 also records two Windows 500-ms response-read
timeouts in legacy fixtures. One explicitly declared full same-source repeat
passes all four jobs on attempt 2. No Rust, test concurrency or runtime limit
changed. Preserve the initial failure; a passing repeat does not diagnose it.

Staging `40862847024` passes the actual Linux ENOSPC fault and installed native /
independent-consumer behavior on Windows, Linux and Apple Silicon before the
pinned signing action rejects an absent CycloneDX `serialNumber`. The release
helper now adds a deterministic, content-bound standard UUID; CycloneDX 1.5,
dependency scope, Rust engine, consumer, lock and task specification are unchanged.
Native behavior is distinct from successful signing and final public delivery.

The new timeout diagnostics subsequently expose a concrete Mac test-helper race
on source `51571ca`: lifecycle startup reads an incomplete readiness notice and
panics before creating its cleanup owner. The test binary reports failure in
0.71 seconds, yet a child retaining the captured stderr pipe can keep collection
waiting until the 300-second timeout. The corrective candidate requires atomic
readiness publication, robust partial-frame parsing, immediate child ownership,
bounded cleanup and retained failure diagnostics. Only the two named test-helper
paths may differ under the prospective reproduction exception; production engine
Rust and all task/budget definitions remain unchanged. This does not diagnose
the separate Windows response-read timeouts or every historical timing anomaly.

## Defects found and corrected before candidate freeze

- Local transfer initially used a work-unit label rejected by the existing
  verifier. The operation failed closed; the unit now has the explicit versioned
  label `engine-gf2-assessment/1`, separate from source calls and bytes.
- Struct/JSON-value serialization ordering initially produced inconsistent
  transfer hashes on reopen. Canonical JSON-value hashing now preserves exact
  replay; restart regression checks cover the binding.
- A generic Windows process-accounting fixture exposed that Job Object extended
  limit information does not supply valid I/O counters. Preserve that fixture's
  original zeros as invalid measurements, not zero I/O. The controller now uses
  BasicAndIOAccounting information; a separate benign I/O probe verified it.
- Live knowledge-file replacement could otherwise let an open object overwrite
  foreign history. Exact opened/published raw bytes are now checked before
  staging and again before rename, including accepted whitespace; mismatches
  hold and poison further mutation without replacing evidence.
- The actual published v1.0.1 executable initially could write into an unmarked
  new-engine store, after which the new engine held on replay. Preserve that
  failed synthetic compatibility probe. The new `EngineOwnerRegistered` receipt
  makes old and generic writers refuse both new and restored engine stores,
  with every owner file unchanged. No original public binary was modified.
- A forged checkpoint's owner/configuration or original path must be rejected
  before destination creation. Restore now validates those conditions before
  publishing any new state, and refuses a live original writer.

These corrections were made before the final source freeze. A failed development
run is not erased by a later pass. Exact generic probe reports, original failing
records, bounded fault results and final qualification pins belong in the public
evidence census; machine-specific credentials and unrelated data do not.

## Final evidence rule

The combined pre-freeze Windows software run passed 462 Rust test executions,
140 packaging/installer/supervisor Python tests, 81 release-tool Python tests,
the retained 6,093-case BRUTE parity control, strict Clippy, debug/release builds
and API documentation. Cargo's workspace test already executes its doc tests;
that overlap is not counted as an additional independent gate. The first format
check failed on unformatted example edits and is preserved; formatting was
applied before the combined pass. Documentation reported two historical bracket
link warnings, corrected as a comment-only edit before final source CI. The final
source and installed platform gates remain separate from this development run.

The final account must identify source SHA, source-manifest SHA, exact compiler,
lockfile, native/consumer/driver SHA, commands actually run, results, failures,
limitations and public artifact pins. Source checks, registered integration,
one-hour operation, signed build origin and anonymous delivery remain distinct.
Do not mark this ledger complete until those receipts exist.
