# Engine release status: v1.1.2

**Stable release.** Source,
installed images, current local studies and public delivery have separate
identities; a completed earlier gate does not qualify a replacement image.
The [prospective correction](CORRECTIVE_RELEASE_112.md) changes only explicit,
read-only GitHub metadata authentication and versioned delivery coordinates.
Rust algorithms, embedding APIs, schemas, dependencies and scientific limits
remain unchanged.

## Current qualification

| Gate | Actual source `8aa5f4c` result |
|---|---|
| Source | Frozen `8aa5f4c6ab26f7ccad53935a70414ae1765b57c6`; [official CI 40941750300](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/runs/40941750300), all four first-attempt jobs PASS |
| Local build/source admission | Matching Rust 1.98.1 local build and independent source/build review PASS; this is not remote-platform qualification |
| Replacement candidate | [40945405929](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/runs/40945405929), attempt 1: **PASS (all six jobs, attempt 1)**; all six jobs remain mandatory |
| Four installed images and consumers | **PASS (four installed native and four separate external-consumer lifecycles)**; each target needs its own native/driver/consumer and signed source/build/lock proofs |
| Actual Linux ENOSPC | **PASS_ACTUAL_ENOSPC (Linux errno 28, bounded 1 MiB mount, committed bytes unchanged)**, within the existing isolated mount and failure bounds |
| Transfer compatibility reproduction | **PASS_ENGINEERING_ONLY (registered compatibility reproduction; N=0)**, zero new independent scientific samples; preserve primary/parent pins and unknown economics |
| Fresh Windows-image hour | **PASS_LOCAL_HOUR (120 cycles, measurement 3,602,094 ms, independent closed-data audits)**, 120 cycles/60-minute measurement, source-matched driver, real recovery and independent closed-data audit |
| Archive and origin | **EVIDENCE.zip SHA256 `07d2ea383c4dc2ac9fd34b95d5db4915edfab5151c9b921cff1f707dfd5d513a`; inner manifest `daafc48c29ffad69a9d0ec76209e523757d6446a4b7939b18a72d9fd25f6d069`**; selected raw bytes, exact source/images/roles, immutable manifest/checksum and independent byte/portable-data audits |
| Public delivery | **PASS — four targets, first public attempt**, run **40967471449**, release **428461777**; all four first-attempt public platforms passed |
| Receipt index | **[actual delivery index](https://github.com/jacksonjp0311-gif/SYMBIOTE/blob/main/experiments/v1.1.2/public-delivery.json)**; digest **e076f45f9d5400144577760e10390c826b6a88ab6de3672c176b62b1fd8c2dce** |

[Public run 40967471449](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/runs/40967471449) passed all five jobs in its first attempt. The four-platform acceptance is `919f4650322b0d405a90c2911d66608c12234568ec4df513fa0087acbf07867e`; independent data review is `4d9bf2387258ffc9e3a2bcc00154256f1b56cc9090e02975e93204af21a227d9`. Final publication operation `0b1473258141efe57611b20601ed0cab90223e7c7812ce7301c7b3053eb5078e` passed `PASS_FINAL_PUBLIC_LATEST`. An independent official latest-release read (`e96baa8ebf39953d1e440a49dc0cd7b0debf5dd3eabad980e3551676b009a9d0`) confirms v1.1.2, release 428461777, source `8aa5f4c`, non-draft/non-prerelease, and 35 assets.

Captured reference scopes preserve their review-time wording. The table above and
the delivery index's top-level finalization fields describe the current release.

The immutable v1.1.2 annotated tag was pushed at source `8aa5f4c`: object
`3364bcb5414253327e33a458c12a6a5c5058c8ab`. Its additional
[tag CI 40958132994](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/runs/40958132994)
passed all four jobs in attempt 1. The original source qualification remains
CI 40941750300. Actual public acceptance/finalization is recorded separately;
preparation files are not passing public records. The replacement run was
separately authorized only after preserving failed candidate 40943349352. Its
ARM native/embedding checks passed, then its build-provenance attestation failed
with `InternalError: error fetching tlog entry - (404) Not Found`. The root cause
is not established. No job rerun, source edit or old artifact admission is implied.

LOCAL_E3 may follow exact-source CI/local-build admission while remote jobs are
OPEN. A Windows hour may follow its own actual staged image/signatures and
closed E3 while other platforms remain OPEN. Neither scoped admission means
all-platform PASS. All candidate, signature, fault, study, audit and public gates
must close before their respective publication/finalization steps.

## Supported boundary

The additive `symbiote_runtime::engine` interface and installed `symbiote engine`
commands support explicit initialize/open, authorized observations, exact
inference, independent candidate evaluation, retention, conditional prediction,
inspection/counters/resources, revocation, cooperative cancellation, stopped-owner
recovery and verified checkpoint/restore. The independent consumer has its own
workspace/lock and uses only the public interface. Four substantive crates are
retained; no language model or Python is needed by the native runtime.

Independently validated acquisition covers affine Boolean widths 2–8. Width-one
learning abstains `Uncertain` when no distinct held-out case remains. Graph,
Moore and reference interfaces retain their separately documented bounds.
Incoming artifacts are inert; source identity, permission, applicability and
actual local evaluation are checked before promotion. Local exchange uses two
caller-owned engine handles and explicit grants. The existing TLS service is
separate; this is not a universal remote truth adapter.

Owner markers reject legacy/generic writers before mutation. Unmarked prototype
stores HOLD without automatic migration. Backups require stopped owners and an
external manifest checksum; restored copies retain the same identity and rollback
later learning. Native callbacks are cooperative and cannot be forcibly preempted
in-process. Resource diagnostics report their actual work models, not a universal
currency or a measured complete economic baseline.

## Historical releases and research

[v1.1.1](https://github.com/jacksonjp0311-gif/SYMBIOTE/releases/tag/v1.1.1)
remains permanently FAILED, prerelease/notlatest, with unchanged tag and 35 assets.
Source69 passed its own four source jobs, all six candidate jobs, E3 reproduction
and 120-cycle Windows hour. Three public platforms passed; public Intel stopped
at metadata HTTP 403 before any download/native execution. Its evidence ZIP
`9bd06daf11ba96f25c9d34cafd0c2ca33dcfccdae9947ebdf8ee926ae7956818`
qualifies only those original observations.
[v1.1.0](https://github.com/jacksonjp0311-gif/SYMBIOTE/releases/tag/v1.1.0)
is also an immutable failed prerelease after its checker rejected a metadata
route before downloading or executing its native program. The
[previous stable v1.0.1](../experiments/v1.0.1/public-delivery.json) retains its own
qualification and delivery records. Historical failures and all older studies
retain their original statuses; see [the correction](CORRECTIVE_RELEASE_112.md),
[engine evolution](../experiments/engine-evolution-002/README.md) and
[research findings](RESEARCH.md).

Conditional fresh use and exact once-only receiver-owned outcomes are capability
facts. They do not imply economic benefit. Isolated structural learners tie,
transfer adds replay/journal work, and historical complete-cost comparisons lose.
Reciprocal efficiency is **NOT_DEMONSTRATED**. Two-host validation remains
**OPEN_UNAVAILABLE**, power-loss durability is unqualified, and no generalized
intelligence or autonomous self-improvement claim follows from software release.

[Embedding](ENGINE_EMBEDDING.md) · [CLI](ENGINE_CLI.md) ·
[Fault matrix](V11_FAULT_MATRIX.md) · [Compatibility](COMPATIBILITY.md) ·
[Publication](V11_PUBLICATION.md) · [Roadmap](ROADMAP.md).
