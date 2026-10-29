<p align="center">
  <img src="docs/assets/symbiote-hero.png" alt="SYMBIOTE — interconnected geometric cores exchanging structured knowledge" width="1200">
</p>

# SYMBIOTE

**Symbiotic Adaptive Intelligence**

A Rust-native reasoning and learning engine that acquires authorized observations,
constructs exact conditional models, independently evaluates exchanged knowledge,
and retains validated capabilities across restarts. Its feedback binds decisions
to actual use and outcomes. The native core requires no language model or Python.

[![Verification](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/workflows/ci.yml/badge.svg)](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/jacksonjp0311-gif/SYMBIOTE)](https://github.com/jacksonjp0311-gif/SYMBIOTE/releases)
[![Rust](https://img.shields.io/badge/language-Rust-c98957?logo=rust&logoColor=white)](Cargo.toml)

[Get started](#get-started) · [How it works](#how-it-works) ·
[Evidence](#evidence-and-limits) · [Roadmap](docs/ROADMAP.md) ·
[Embed in Rust](docs/ENGINE_EMBEDDING.md) · [Engine CLI](docs/ENGINE_CLI.md) ·
[Release status](https://github.com/jacksonjp0311-gif/SYMBIOTE/blob/main/docs/V11_ENGINE_STATUS.md)

> **v1.1.2 — Stable release.** A typed Rust engine for authorized learning,
> durable conditional prediction and receiver-owned outcomes. Source
> `8aa5f4c6ab26f7ccad53935a70414ae1765b57c6` passed
> [all four source CI jobs](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/runs/40941750300).
> The separately authorized replacement
> [candidate 40945405929](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/runs/40945405929)
> is **PASS (all six jobs, attempt 1)**. [Current gates](https://github.com/jacksonjp0311-gif/SYMBIOTE/blob/main/docs/V11_ENGINE_STATUS.md) distinguish
> source checks, installed images, E3, the fresh Windows hour and public delivery.
> **PASS — four targets, first public attempt**. Stable/latest status: **v1.1.2 — latest stable**. [v1.1.0](https://github.com/jacksonjp0311-gif/SYMBIOTE/releases/tag/v1.1.0)
> and [v1.1.1](https://github.com/jacksonjp0311-gif/SYMBIOTE/releases/tag/v1.1.1)
> are preserved failed prereleases. Reciprocal efficiency is **NOT_DEMONSTRATED**.

## Get started

Install the v1.1.2 standalone native binary for Windows x64, Linux x64, macOS ARM64 or macOS Intel. No Rust, Python, language model or API key is needed to run it.
Installers verify the selected archive against its SHA256 manifest.

**Windows — PowerShell**

```powershell
git clone https://github.com/jacksonjp0311-gif/SYMBIOTE.git
cd SYMBIOTE
.\tools\install.ps1 -Version v1.1.2 -AddToPath
symbiote --version
symbiote engine --help
```

**Linux or macOS — from the checkout**

```sh
sh tools/install.sh --version v1.1.2
~/.local/bin/symbiote --version
~/.local/bin/symbiote engine --help
```

Native bundles are on the
[release page](https://github.com/jacksonjp0311-gif/SYMBIOTE/releases/tag/v1.1.2).
You can also extract the matching archive and invoke its binary directly.
See [installation and recovery](docs/OPERATIONS.md) for paths and platform details.
For a source build, use `cargo install --path crates/symbiote-runtime --locked`
with Rust 1.98.1 or later.

### Learn, close and reopen

This PowerShell example supplies five individual observations to a new,
explicitly authorized three-bit source. SYMBIOTE chooses its inputs, infers
and independently evaluates a conditional model, then retains it. Every command
closes its owned writers. After the observation file is deleted, the same
`learn` command reopens and reuses the model with **zero source calls**.

Run after the Windows installer above. With a directly extracted binary,
replace `symbiote` with `.\symbiote.exe`. This is the
[tested CLI recipe](docs/ENGINE_CLI.md#windows-quick-start), using the installed
binary on PATH:

```powershell
$root = Join-Path ([IO.Path]::GetTempPath()) ("symbiote-engine-" + [guid]::NewGuid())
[IO.Directory]::CreateDirectory($root) | Out-Null
$utf8 = [Text.UTF8Encoding]::new($false)
$observations = Join-Path $root 'observations.json'
$config = Join-Path $root 'config.json'
$state = Join-Path $root 'owner'
$frames = '[{"sequence":0,"input":0,"output":0},{"sequence":1,"input":1,"output":1},{"sequence":2,"input":2,"output":0},{"sequence":3,"input":4,"output":1},{"sequence":4,"input":3,"output":1}]'
[IO.File]::WriteAllText($observations, $frames, $utf8)
$commitment = (Get-FileHash -LiteralPath $observations -Algorithm SHA256).Hash.ToLowerInvariant()
$configuration = @{
    schema = 'symbiote.engine-config/1'
    authorized_sources = @(@{
        source_id = 'owned-example'; scope = 'owned-example/v1'
        epoch = 'epoch-1'; commitment = $commitment; width = 3
    })
    max_queries_per_episode = 16
    max_gf2_work_per_episode = 10000
    max_duration_ms = 5000
} | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText($config, $configuration, $utf8)
$initialized = symbiote engine init --state $state --config $config | ConvertFrom-Json
$owner = $initialized.inspection.owner
$learned = symbiote engine learn --state $state --owner $owner --config $config --source owned-example --observations $observations | ConvertFrom-Json
$artifact = $learned.result.learning.artifact
symbiote engine predict --state $state --owner $owner --config $config --artifact $artifact --input 6
Remove-Item -LiteralPath $observations
symbiote engine learn --state $state --owner $owner --config $config --source owned-example --observations $observations
```

The prediction for input 6 is 1. The final response must report
`source_access: {"calls":0,"read_bytes":0,"file_opened":false}`.
Operations return structured JSON; success is `status: "PASS"`, and failures
return a nonzero exit with typed `error.kind`. Check both before continuing.
State paths are absolute, and reopened operations require the exact returned
owner and original configuration.

For inspection, cancellation, revocation and verified backup/restore, continue
with the [Engine CLI guide](docs/ENGINE_CLI.md). Restored copies share an identity;
they are not independent agents. Predictions remain conditional on the declared
finite source family, with validated acquisition at widths 2–8 and explicit
abstention when the evidence does not suffice.

## Embed in Rust

For an application, start with the [typed Rust interface](docs/ENGINE_EMBEDDING.md).
The independent consumer uses only that interface and its own Cargo workspace:

```sh
cargo run --locked --manifest-path tests/consumer-engine/Cargo.toml -- --out ABSOLUTE_NEW_DIRECTORY
```

It creates two isolated owners, observes, infers, evaluates, retains and predicts;
then closes, reopens and predicts without consulting the source. It also checks
cancellation, writer exclusion, revocation and verified checkpoint/restore.
The embedding host owns adapters, budgets, paths and event presentation. Callbacks
are cooperative; hard termination requires an explicitly supervised process.

The installed `engine` commands above use the same typed lifecycle.
Engine-owned directories remain distinct from older demonstration stores;
incompatible writers refuse them before changing history.

## Optional demonstrations and research

The typed engine above is the primary learning interface. Older demonstrations
remain available with separate state directories:

```sh
symbiote demo
symbiote observe-demo --state state/observation
symbiote doctor
```

These modes do not open engine-owned directories. `symbiote --help` lists the
finite routing, native-peer and controlled research commands. For configured TLS
peers, use [the live runtime](docs/LIVE_RUNTIME.md) and explicit
[identity and grants](docs/TLS_DEPLOYMENT.md). Partners retain control over
adoption; an exposed API is not authorization. Large research runs are optional,
retain failures and require their declared protocols and resource limits.

The Windows entrypoint supports build, run, test, verify, benchmarks and Git
status. For example, `./SYMBIOTE-All-One.ps1 -Verify` checks a source checkout.
See [operations](docs/OPERATIONS.md) and [owner backups](docs/OWNER_BACKUPS.md).
Engine checkpoint/restore follows the [engine CLI](docs/ENGINE_CLI.md), with
stopped owners and an externally saved manifest checksum.

## How it works

SENSE → MODEL → CONNECT → EXCHANGE → VERIFY → LEARN → CONTRIBUTE → REASSESS.

The engine chooses bounded authorized observations, builds an exact conditional
model and independently evaluates it before durable retention. In a granted
relationship, a partner's artifact remains inert until local validation; receiver
use and outcomes bind to actual ledger events, with no duplicate credit on
restart. Known observations, inference and unverified hypotheses remain distinct.
The native CLI and embedding use the same engine. Optional TLS adapters expose
controlled peers; an API endpoint is not permission to attach.

## Evidence and limits

| Current evidence | Recorded result |
|---|---|
| Source `8aa5f4c` | [CI 40941750300](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/runs/40941750300), all four jobs PASS; [tag CI 40958132994](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/runs/40958132994) also passed |
| Candidate 40945405929 | [All six jobs PASS](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/runs/40945405929): four native and four external-consumer lifecycles, actual bounded Linux ENOSPC |
| Registered compatibility reproduction | PASS_ENGINEERING_ONLY; four directional transfers, 128 fresh conditional uses, four outcomes/reconciliations, restart zero credit; no new independent samples |
| Fresh Windows-image hour | 120 cycles; measured 3,602,094 ms, main listener 3,594,299 ms; independent byte/semantic/boundary audits PASS |
| Evidence archive | ZIP `07d2ea383c4dc2ac9fd34b95d5db4915edfab5151c9b921cff1f707dfd5d513a`; manifest `daafc48c29ffad69a9d0ec76209e523757d6446a4b7939b18a72d9fd25f6d069` |
| Public delivery and stable status | **[PASS — four targets, first public attempt](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/runs/40967471449)**; **v1.1.2 — latest stable**; [actual delivery index](https://github.com/jacksonjp0311-gif/SYMBIOTE/blob/main/experiments/v1.1.2/public-delivery.json) |

Current authority is the [main release status](https://github.com/jacksonjp0311-gif/SYMBIOTE/blob/main/docs/V11_ENGINE_STATUS.md)
and delivery index. The frozen tag's [CLI](https://github.com/jacksonjp0311-gif/SYMBIOTE/blob/v1.1.2/docs/ENGINE_CLI.md)
and [embedding API](https://github.com/jacksonjp0311-gif/SYMBIOTE/blob/v1.1.2/docs/ENGINE_EMBEDDING.md)
document its contract, not later publication outcomes. Native source remains
`8aa5f4c6ab26f7ccad53935a70414ae1765b57c6`; documentation commits do not become
native campaign sources.

Learning support is finite affine acquisition at widths 2–8; width one abstains
when no distinct held-out input remains. Predictions are conditional. Callbacks
are cooperative, restored copies share an identity, two-host validation remains
**OPEN_UNAVAILABLE**, and power-loss durability is unqualified.

The [research record](docs/RESEARCH.md) preserves isolated ties and full-cost
losses. Ordinary transfer used 4,278 versus 2,852 GF(2) work units per owner, with
an extra 1,426-unit restart/idempotence control reported separately. Unknown costs
remain unknown. Receiver-owned capability outcomes are not economic benefit.
Reciprocal efficiency is **NOT_DEMONSTRATED**, with no generalized intelligence
or autonomous self-improvement claim.

Historical v1.1.0/v1.1.1 failed prereleases, the first source-8aa attestation failure and
all earlier studies remain preserved. [Correction and parent archive](docs/CORRECTIVE_RELEASE_112.md),
[engine evolution](experiments/engine-evolution-002/README.md),
[previous stable v1.0.1](experiments/v1.0.1/public-delivery.json),
[BRUTE parity](experiments/parity.json) and [roadmap](docs/ROADMAP.md) keep their
original scopes; a new release number does not regrade old failures.

## Architecture

Four substantive Cargo crates keep reasoning, authorization, learning and runtime
behavior explicit without fragmenting the system into placeholder packages.

| Path | Responsibility |
| --- | --- |
| `crates/symbiote-reasoning/` | Exact hidden-state and affine inference, conservative graph certificates, active queries, conditional prediction and the value-of-symbiosis decision |
| `crates/symbiote-protocol/` | Authorized local sessions, separate TLS 1.3 API, resource limits, sensors and revocation |
| `crates/symbiote-memory/` | Private identity, evaluated knowledge, operational journals, reciprocal evaluation receipts, idempotency, rollback and lifecycle integrity |
| `crates/symbiote-runtime/` | Typed embedding and native CLI, active learning, exact exchange/outcomes, configured peers, diagnostics and experimental controls |
| `docs/` | Architecture, mathematics, operations, provenance, research and version objectives |
| `docs/assets/` | Original project artwork and its provenance |
| `docs/reference/` | Preserved upstream algorithm used by developer parity checks |
| `experiments/` | Compact checked receipts; local generated runs stay ignored |
| `tests/fixtures/` | Shared original-Python/native fixtures |
| `tests/consumer-engine/` | Separate developer workspace using only the documented typed engine API |
| `tools/` | Installers, verification, packaging and upstream audit utilities |
| `SYMBIOTE-All-One.ps1` | Synchronous Windows build, run, research, test, verify and Git operations |

[Architecture](docs/ARCHITECTURE.md) · [Compatibility](docs/COMPATIBILITY.md) · [Reasoning](docs/REASONING.md) ·
[Protocol](docs/PROTOCOL.md) · [Operations](docs/OPERATIONS.md)

## Develop and verify

Rust 1.98.1 is the declared minimum and qualification compiler; current stable is
checked separately. Python 3.11+ is needed only for
developer verification against the original Python implementation.

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
python tools/verify.py
cargo doc --workspace --no-deps --locked
```

`Cargo.lock` pins dependencies. Verification reports failures and preserves the
distinction between software correctness, measured fixture outcomes and broader
research claims. [Changelog](CHANGELOG.md).

## Foundation and attribution

SYMBIOTE is a clean derivative of
[BRUTE](https://github.com/jacksonjp0311-gif/Brute/tree/9edbc035792ca75d3a3333b8454e5bf31c706eb1),
pinned at `9edbc035792ca75d3a3333b8454e5bf31c706eb1` from its v0.11.0 era.
BRUTE's selected symbolic algorithm is retained unchanged. Its full SP8/SAT
certification policy is not claimed ported, and its failed sound-transfer gates
remain documented. AEFL contributes independently adapted bounded telemetry and
drift concepts; similarity is not a learning criterion.

All 983 upstream files are classified in the
[migration manifest](docs/upstream-manifest.json). Original repositories,
authorship and scientific evidence remain untouched and accessible through
pinned links. Historical archives and massive generated results stay upstream.

The historical v1.1.0 source snapshot is about 9.64 MB across 15 root entries, versus
BRUTE's 574.80 MB and 41 entries: about 98.32% fewer bytes.
[That footprint](experiments/v1.1.0/footprint.json) excludes Git history, build
caches and local state; [the earlier snapshot](experiments/footprint.json) is
preserved. Full study traces live in checksum-pinned release assets.

New SYMBIOTE code uses the [MIT license](LICENSE). The retained BRUTE reference
has an explicit exception because the inspected upstream supplied no license
declaration; its original rights are preserved. See
[full provenance](docs/PROVENANCE.md) and [artwork provenance](docs/assets/README.md).
