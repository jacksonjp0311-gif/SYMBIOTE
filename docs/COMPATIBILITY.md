# Compatibility and release boundary

The unreleased v1 candidate adds the [public runtime API](RUST_API.md), native
cognitive profile events and a separate strategy ledger. Its minimum compiler
is declared as Rust 1.98.1 and must pass the final 1.98.1 local build. The tables
below retain the published v0.5.1 qualification; they are not candidate results.
Final candidate platform and duration evidence will be recorded separately.

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
