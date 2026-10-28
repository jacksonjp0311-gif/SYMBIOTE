# v1.0.0 release audit — 2026-10-28

**Overall stable qualification: HOLD.** The public one-host release is real,
and its native delivery and frozen local hour pass their bounded checks. The
tagged benefit-verification APIs have reproducible defects, the configured loop
does not return a contribution in either current family, and the final public
evidence archive is missing. A version number cannot close those requirements.

The audited [v1.0.0 release](https://github.com/jacksonjp0311-gif/SYMBIOTE/releases/tag/v1.0.0)
points to `426f054771395dcbe1b8711d7128b90ef0c704de`. This audit preserves that
tag, its assets, earlier HOLDs and negative research results. Corrective source
on main is separate from the downloaded binaries and needs a qualified patch.

## Results

| Requirement | Result | Evidence and scope |
| --- | --- | --- |
| Release CI | PASS | [Run 40674286304](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/runs/40674286304), all four native targets; Windows reports 357 Rust test executions, 98 Python tests and 6,093 original BRUTE parity cases |
| Public native bytes | PASS | All four ZIPs and SHA256SUMS downloaded anonymously; exact checksum set, GitHub digests, archive layout and CPU headers verified |
| Installed Windows binary | PASS | Exact public executable `88fd14bc693ef93296046e960080aaa8f43eb3cf21cf1514aa53d546755544b5`; source stamp matches the tag; isolated installation without PATH changes |
| Actual reuse and recovery | PASS | First demo promotes two models; a new process reuses both; offline prediction tables, identity and byte-exact backup/restore checked |
| Configured native cognition | PASS within fixture | Actual installed public executable learns two task families; restart promotes zero new models and retains both; no contribution payload is sent |
| Fresh local hour | PASS_LOCAL_HOUR | Read-only independent consumer rerun: 120 cycles, 3,601,880 ms, 483 request keys, 10 starts/stops, verified cleanup and no source-watch failures |
| Benefit verification API | FAIL in tagged source | Fabricated receipts pass public predicates; duplicate payloads can count as changed behavior; a caller flag can claim restart durability |
| Useful configured return contribution | OPEN | Both current full-fixture transfer policies always decline; partner benefit count remains zero |
| Full public evidence delivery | OPEN | Five native assets exist; the evidence archive/checksum pair is absent |
| Independent two-host operation | OPEN_UNAVAILABLE | Authorized scope remains this PC |
| Broader transfer and reciprocal efficiency | UNACHIEVED | Protocol 001 remains NOT_DEMONSTRATED; protocol 002 remains NOT_RUN; topology saving remains −428 declared work units |

Compact receipts: [native delivery](../experiments/v1.0.0/public-delivery-audit.json)
and [hour consumer audit](../experiments/v1.0.0/hour-evidence-audit.json).
These are audit summaries, not substitutes for a public raw-evidence archive.
Actual public-binary execution on Linux/macOS was not repeated locally; their
native build/test/installer evidence comes from the release workflow.

## Reproduced defects and corrections

In the tagged `symbiote-memory::reciprocal` API, a JSON receipt can declare a
completed promotion with invented hashes and positive costs. Recomputing its
ordinary content digest makes `receiver_benefit_verified`,
`durable_benefit_verified` and `mutual_research_success` return true without
creating any ledger. The separate `confirmed_benefit(store, witness)` checks
actual ledger evidence, and the current runtime uses that additional guard.
This audit found no live-path increase of `partner_benefits_verified`.

That ledger-backed path still has two problems: adding the same scope/payload
from another source changes its payload-list digest despite unchanged predictive
capability, and `persisted_after_restart: Some(true)` can be supplied immediately
after promotion without reopening anything. The promotion seal also accepts a
sender that differs from the promoted record's actual source.

Corrections require actual receiver-ledger witnesses for verified predicates,
distinct capability sets for behavior comparison, binding the sender to the
stored source, and an actual stopped-store replay for the bounded durability
check. Such replay is explicitly weaker than an OS-process restart. The receipt
wire schema remains readable. The first source correction changed unsafe helper
signatures; the release follow-up restores those signatures as deprecated,
always-false methods and adds witnessed verification without breaking compilation.
These changes must not retrospectively regrade the release or any experiment.
The regressions and fixes are on main, not in the tagged binaries. Compatibility
is covered by a regression that type-checks the original function signatures.

Four reproducer cases failed before the fix. Afterward, all 12 focused memory
and runtime receipt tests pass, followed by the full Rust workspace suite
(three registered duration tests remain ignored), strict Clippy and formatting.
The original topology invocation reported 2,217.94 seconds. Subsequent Windows
events identify 2,213.6976616 seconds of lid-triggered Modern Standby during that
interval. The corrected fixture checks wall time before accepting an exited
child and after validation/cleanup; three focused tests pass in 1.56 seconds.
[Timing evidence](../experiments/v1.0.0/timing-topology-modern-standby.json)
preserves the incident and its limits. No historical result is regraded.

The earlier hosted Windows CI timeout is a separate incident. Its old log
establishes OS error 10060 during the initial candidate submission but cannot
identify the failed transport phase. [The investigation](../experiments/v1.0.0/windows-ci-timeout-investigation.json)
retains that unresolved cause; neither the local standby finding nor a later
successful CI attempt explains it. New phase diagnostics improve future evidence
without automatically retrying the failed operation.

The configured contribution limitation is not repaired by ignoring transfer
costs. Affine full-fixture utility is `width − 2^width`, and graph utility is
`edges − nodes×(nodes−1) − 1`; both are negative over supported fixtures. A useful
return path needs a genuinely different, predeclared transfer opportunity and
independent receiver evaluation. Do not retune the completed cohorts into a gain.

## Evidence custody and remaining release work

The fresh hour's registered source is `31b9418`; only five documentation files
differ at the public tag. Its 115 selected source files match manifest
`c50d590eb59e1f17b88935f4db10e88bc1b287e9fa672b1b1ee1fc7776160181`.
The server retained two models; the client retained only its unchanged genesis.
Scientific sample count remains zero. The cancelled 71/120 run remains HOLD.

Raw public-audit results and failed attempts are retained under ignored local
`experiments/local/v1-release-audit-20261028/`. The fresh hour remains at
`%TEMP%\sh-31b9418`. Private owner material must pass explicit classification
and credential scanning before any evidence archive is published.

The subsequent custody check could not locate the original `31b9418` hour's
exact executable pair after development builds replaced the target files.
Its original source, registered hashes and raw receipts are retained; a newer
executable must not be substituted for those bytes. The corrective release
therefore requires a new frozen-source hour with separately preserved native
and test executables. The old passing receipt remains historical evidence with
this reproduction limitation.

The preserved draft publisher failed before downloading because it expects a
nonexistent GitHub `creator` field and a workflow-only creator assumption. A
separate read-only audit used its bounded download/install primitives without
that creator gate. An initial installer run also failed under the inherited
PowerShell Core module path; cleanup passed. The successful isolated run let
Windows PowerShell initialize its default modules. Both failures are preserved.

Before approving a stable patch: finish regression and cross-platform checks
for the corrected source, independently evaluate a real useful return transfer,
review and publish the complete evidence package, and execute the replacement
public binaries. Record any new source-duration requirements prospectively.
Future release workflows stage new releases as drafts rather than automatically
publishing after bundle creation. Keep two-host and unmet scientific gates open.

Protocol 002's existing preregistration is unchanged and remains NOT_RUN. Its
flag-only durability and same-record wording need a declared amendment and new
registration before opening targets; the corrected helper API is not evidence
that the existing protocol was executed or satisfied.
