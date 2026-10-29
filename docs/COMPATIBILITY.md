# Compatibility and release boundary

## v1.1.0 engine candidate boundary

The development target adds a typed embedding façade and a separate engine CLI;
qualification remains as recorded in [the current status](V11_ENGINE_STATUS.md)
and [support contract](V11_ENGINE_SUPPORT_CONTRACT.md). Published v1.0.1 remains
the corrective baseline. The historical release descriptions below retain their
original evidence and do not qualify new candidate binaries.

New `Engine` owners append `engine_owner_registered` immediately after their
original identity genesis, declaring namespace `embedding-engine/v1` and
minimum-writer capability `symbiote-engine-writer/1`. The capability names a
writer format first introduced in v1.1.0; it is independent of package SemVer.
The original genesis bytes are preserved. Earlier writers cannot parse the new
event. Current generic legacy writers also refuse an engine-owned namespace;
only explicit compatible engine constructors admit it. This does not migrate
existing legacy owners or make the legacy `observe-demo` command an engine API.

An owned Windows compatibility check used the actual published v1.0.1 executable
with SHA256 `a06c14dae36a14eaa2fd121201849f0417cab7dccb48fddd009fddbfbb27db7c`.
With handles closed, its legacy observation command rejected both a new marked
owner and a checkpoint-restored copy without changing owner files. The current
development legacy writer also rejected the marked owner. This bounded
compatibility check is separate from final candidate installation and platform
qualification; the original public image and historical failing probe remain
unchanged.

Unmarked prototype engine owners return a typed `Hold`; opening them never
registers or rewrites them automatically. Read-only maintenance and checkpoint
validation understand the marker, and restoration preserves it. An older binary
must not be made compatible by deleting the marker or other rows. For rollback,
use a separately verified snapshot accepted by the intended older writer, in a
new destination. That restores the older state and does not retain later learning.

Embedding callers inspect `EngineError.kind` and `committed`, rather than parsing
diagnostic text. Exact knowledge publication limits map to `BudgetExhausted`,
invalid evidence to `Contradiction`, changed or missing live knowledge bytes to
`Hold`, and actual filesystem failures to `Storage`. A failure after a durable
knowledge commit exposes the committed anchor; a failed notification does not
undo that commit. Pending or inconsistent histories may require explicit typed
recovery or remain held. Neither recovery nor checkpoint restoration silently
repairs unknown bytes or rolls back a completed learning event.

## Historical v1.0.0 and v0.5.1 boundary

Public v1.0.0 adds the [runtime API](RUST_API.md), native cognitive profile events
and a separate strategy ledger. Its [release audit](V1_RELEASE_AUDIT.md) records
passing four-platform builds, downloaded bundle integrity, installed Windows
cognition and the frozen one-host hour. Full stable qualification remains HOLD.
The tagged benefit-verification helpers have defects. Corrected main preserves
their signatures as deprecated, fail-closed methods and provides positive
verification only through ledger-witnessed APIs. Receipt schema `/2` is retained.
The older tables below retain their v0.5.1 scope rather than becoming v1 evidence.

The v1 release workflow used Rust 1.99.1 and Python 3.13.16. Local source checks
use Rust 1.98.1, the declared minimum. Public ZIP inspection does not establish
installed Linux/macOS execution on this PC, and store replay does not establish
OS-process restart or independent two-host operation.

**v0.5.1 remains a research preview.** It adds owner backups and an offline
policy lifecycle to v0.5.0's configured services. S5 passed bounded local
qualification on this Windows PC; stable 1.0, independent two-host deployment
and long-term reliability remain open. A software version does not certify
an arbitrary partner, environment, or transferred claim.

## Tested software window

| Surface | Current evidence | Boundary |
| --- | --- | --- |
| Windows binary | v0.5.1 public x86-64 MSVC ZIP downloaded, installed online and used for restart and backup/restore checks on this PC; S5 debug continuity qualified separately | Windows ARM binaries are not supplied; the public executable is distinct from the archived S5 binary |
| Linux binary | v0.5.1 x86-64 GNU bundle built on Ubuntu 22.04 with passing software gates; public ZIP downloaded and inspected | No Linux public-binary execution on this PC; other distributions/libcs and Linux continuity need separate checks |
| macOS binaries | v0.5.1 macOS 15 Apple Silicon and Intel build/test jobs passed; both public ZIPs downloaded and inspected | No macOS public-binary execution on this PC; earlier macOS versions and continuity need separate checks |
| Rust | S5 local Windows checks with 1.98.1; v0.5.1 Ubuntu CI log confirms stable 1.99.1 | A lower minimum compiler version has not been established |
| Python | Development verification and packaging only | Native demos, retained predictions and configured services do not require Python |
| Rust libraries | Four workspace crates, with exact reasoning and explicit scoped interfaces | The v0.x Rust API is not a stable 1.0 API promise; no crates.io publication is implied |

All seven v0.5.1 assets were downloaded publicly and matched their declared
checksums. All four ZIP architectures and their exact native manifest set passed
inspection. The actual Windows binary passed ten commands: version, doctor,
demo, retained prediction, repeat reuse, separate native peers, backup, verify,
restore and restored prediction. Identity and original history bytes survived.
See [public verification](../experiments/v0.5.1/publication-verification.json) and
[release CI](../experiments/v0.5.1/release-ci.json). CI results for another
operating system do not establish a two-machine private-network deployment.

The v0.5.1 default software gate records 292 native test executions, 53 Python
tests and 6,093 parity cases. One ignored test was separately selected for the
24-cycle S5 local continuity campaign; its 16 named regression repeats are not
new tests. The [qualification account](LOCAL_QUALIFICATION_V051.md) and
[evidence index](../experiments/v0.5.1/README.md) pin the exact studied source and
executables. Release executables may have different hashes and must not silently
replace them in an audit. S3/S4 checker HOLDs remain part of the record.

The current software-gate digest sorts native `Path` objects. Windows and POSIX
therefore report different fingerprints for the same 83 normalized source files.
The [ordering receipt](../experiments/v0.5.1/source-fingerprints.json) reproduces
both values and records the initially rejected plain-string sorting hypothesis.
Use the declared platform and algorithm when comparing them; Git source commits
and per-file evidence manifests remain independent byte bindings. Platform test
counts also differ: the observed Ubuntu gate ran 294 native tests and 53 Python
tests; the S5 Windows default gate ran 292 native tests and 53 Python tests.

## Protocol and trust

The original authenticated JSONL protocol is version 1 and restricted to its
declared trusted loopback setting. The configured encrypted API uses
`symbiote/2`, mutually authenticated TLS 1.3, explicit certificate pins,
identities, scope grants and finite transport budgets. The two transports are
distinct; exposing a listening address does not grant inspection or control.

Unknown protocol versions, unknown operations and missing grants fail explicitly.
There is no downgrade negotiation, remote policy administration or remote code
execution. Declarative offers enter quarantine. Local evaluation determines
whether they may become persistent knowledge. A certificate authenticates the
peer binding, not the truth of every statement made by that peer.

A configured TLS failure never falls back to plaintext. Durable artifacts retain
their schema fingerprint and stationary context. A different graph topology,
edge order or cost bounds require a different schema. Drift needs explicit
reassessment and revocation; old observations must not be silently edited.

## Durable formats

| Format | Version | Reading and upgrade rule |
| --- | --- | --- |
| Identity/Genesis ledger | JSONL v1 | Preserve owner and original bytes |
| Knowledge ledger | JSONL v1, typed model events | Preserve promotion, supersession and revocation history; reject unsupported events |
| Operational ledger | JSONL v1, typed service events | Preserve its owner marker, Genesis and exact prior receipt prefix |
| Registered layout | `symbiote.state-layout/1` | Explicit byte-preserving registration; no silent migration |
| Strategy ledger, v1 candidate | JSONL strategy version 1; `symbiote.strategy-owner/1` | Bound to the exact owner's Genesis bytes; validated policy decisions and family-wide counterexamples survive restart |
| Strategy-bearing layout, v1 candidate | `symbiote.state-layout/2` | Explicit `migrate`; preserve original layout and immutable v1/v2 migration backups; incomplete preparations block writers until reviewed resume |
| Cognitive run policy, v1 candidate | `symbiote.cognition-policy/1` | Exact owner/service epoch and narrower finite grants; unfamiliar fields reject |
| Owner backup, v0.5.1 | `symbiote.owner-backup/1` | New destination only; external manifest digest required; same operating system |
| Restore mapping, v0.5.1 | `symbiote.restored-owner/1` | Immutable copied-history mapping; configured activation requires explicit reviewed relocation |

Format version 1 is not permission to ignore unfamiliar events. The v0.5.1
policy lifecycle adds typed operational events that older v0.5 software does not
understand. After such a transition, downgrade of that owner store is unsupported
and must fail closed. Do not remove rows or change version fields to make an old
executable accept it. Keep an independently verified pre-upgrade backup if an
operator needs a rollback option; an older snapshot deliberately restores older
knowledge and must not be described as retaining later learning.

Stop older writers before upgrading; never run two versions against the same
owner. Keep a backup, run `inspect-state`, then use `migrate` for explicit
byte-preserving layout registration. Migration neither relabels evidence nor
promises that an old binary can read new typed graph or operational events.
The public v0.5 configured service has an immutable owner and policy; deleting
`operations.jsonl` or `operations-owner.json` is not an upgrade, rotation or
regrant procedure. The v0.5.1 lifecycle preserves that owner registration
and advances only the audited policy history.

Readers reject unsupported versions, corrupt chains, missing registered files,
incomplete transactions and inconsistent completed-learning anchors. An error is
not authorization to initialize a replacement owner. `recover` is limited to
verified dead writer locks; unknown liveness remains HOLD. It does not terminate
other agents or repair evidence.

JSON receipts declare their schema version. Consumers must check that version
and the implementation release, reject missing required evidence or an unknown
promotion policy, and preserve the original receipts. A new software version
does not broaden the scientific applicability of an older receipt.

The local continuity result covers two fixed fixtures and two retained models.
It validates exact replay of one committed quarantine after a lost reply and an
owned service crash; it does not promise exactly-once effects for arbitrary
external actions. The pending candidate is rejected during reviewed relocation,
without another promotion. Read/predict responses are not durable cached
submission receipts. A later corrected verifier diagnostic cannot change an
older campaign's recorded HOLD into PASS.

Backups cover one stopped owner. Child owners, unknown sidecars and credential
files are refused rather than silently excluded. Public configuration, pinned
truth fixtures, public CA/certificate material and fresh private credentials may
be required for service activation. The original private key is not required for
an approved offline rotation. Same-OS restore is a current limit; cross-OS paths,
network filesystems and sudden power-loss durability are not certified.

## Bounded meaning of stability

The candidate target is reliable exact reasoning and reproducible reciprocal
learning for the declared affine and positive-cost graph families, with durable
history and controlled secure connections. General intelligence, universal
transfer efficiency, arbitrary remote truth, automatic enrollment and unattended
credential renewal remain outside that target. Negative research results stay
part of the release record. See [the stable gates](STABLE_RELEASE_GATES.md) and
[the research roadmap](ROADMAP.md).
