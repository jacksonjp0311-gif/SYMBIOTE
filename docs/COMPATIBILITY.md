# Compatibility and release boundary

The current public release is **v0.5.0, a research preview**. The owner-backup and
offline policy-lifecycle changes on this development branch are not part of that
release. Stable 1.0 qualification remains open. A software version does not certify
an arbitrary partner, environment, or transferred claim.

## Tested software window

| Surface | Current evidence | Boundary |
| --- | --- | --- |
| Windows binary | x86-64 MSVC release, native installation and restart smoke on this Windows host | Windows ARM binaries are not supplied |
| Linux binary | x86-64 GNU, built and tested on Ubuntu 22.04 | Other distributions and libc implementations need separate checks |
| macOS binaries | macOS 15, Apple Silicon and Intel build/test jobs | Earlier macOS releases are not qualified by these jobs |
| Rust | Local Windows checks with 1.98.1; v0.5 release CI with stable 1.99.1 | A lower minimum compiler version has not been established |
| Python | Development verification and packaging only | Native demos, retained predictions and configured services do not require Python |
| Rust libraries | Four workspace crates, with exact reasoning and explicit scoped interfaces | The v0.x Rust API is not a stable 1.0 API promise; no crates.io publication is implied |

Every release ZIP has its own architecture check and checksum. The public
v0.5.0 Windows binary was installed from its actual download, then used for the
two-agent demo, retained offline predictions, repeat reuse and separate native
peer processes. CI results for another operating system do not establish a
two-machine private-network deployment.

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
| Owner backup, development branch | `symbiote.owner-backup/1` | New destination only; external manifest digest required; same operating system |
| Restore mapping, development branch | `symbiote.restored-owner/1` | Immutable copied-history mapping; configured activation requires explicit reviewed relocation |

Format version 1 is not permission to ignore unfamiliar events. The development
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
regrant procedure. The development lifecycle preserves that owner registration
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
