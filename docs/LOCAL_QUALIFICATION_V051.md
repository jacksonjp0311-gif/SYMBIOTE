# v0.5.1 local software qualification

**S5 passed the frozen local software and 24-cycle continuity campaign on one
Windows PC. This is not stable v1.0 qualification.** Independent-host validation
remains `OPEN_UNAVAILABLE`; long-term reliability and scientific performance
claims remain outside this result. The original v0.5 research primary stays
**HOLD**.

The campaign follows [SYMBIOTE-LOCAL-STABILITY-001](STABILITY_CAMPAIGN_PROTOCOL.md).
It checks native persistence, mutually authenticated local TLS, explicit policy
changes, denied-peer handling and verified owner relocation. It uses the same
two manual affine/graph fixtures throughout, with no new research samples or
adaptive cohort calls.

## Candidate and evidence bindings

| Binding | Recorded value |
| --- | --- |
| S5 source commit | `cd792651d77765532cf39f9d8307ca3bcbb7e0fb` |
| Software-gate source fingerprint | `1b1d2e23dd930ef1b7101409ae5c82bb3277992abe2855d82a50955ab3e4157b` |
| Protocol SHA256 | `8c87d28a898c451083d0893d70dd28d46616523805ab20dc6666d089354f1455` |
| Campaign registration SHA256 | `656a6ad12be1aaee32a5de03e04603fd52bdf21142ec07dcc1dfda9a5569333e` |
| Campaign report SHA256 | `fb9d090970d11b8d58dea31e67adbaf37e6557ffb68f29132ec4d87094aced4d` |
| Native continuity report SHA256 | `11bc5d30c8f0f5d925ef89bc4e638573c345ee4d0133a8a8128393d613f055ac` |
| Independent audit SHA256 | `627f8d59febba02f18129780352dfdaf0c7709ac597f42573e45aec32f97b40a` |

The studied Windows debug CLI reports version `0.5.1` and that exact source
commit. Its SHA256 is
`d3552a7fb2bb5fecfc0a4a62925bc34b067f67987e71e9a6eb22a169d4277b2a`.
The CLI integration executable is pinned to
`081cf42a6b037322a9186786c33fea696a07f7a9c3caf085b00924241a1983b3`;
the service integration executable is pinned to
`3d0001958eb09b07c454f1d307bb672c41a4ac0eeb11ebd303d5beb3b1a31a8c`.
Release installer binaries have their own platform-specific pins and must not
be substituted for the studied executables when auditing these receipts.

The separate software gate passed **292 default native test executions**,
**53 Python tests** and **6,093 BRUTE parity cases**. The campaign then explicitly
selected **one ignored continuity test**. Its 16 named regression executions
repeat existing tests; they are not 16 new tests. The 24 continuity cycles are
observations of repeated software operation, not independent scientific samples.

The saved build binding records an actual Cargo build/test-artifact discovery,
a source-stamped CLI, strict debug/release Clippy and matching source fingerprints
before and after the software gate. SHA256 pins establish which bytes were
used; they are not a reproducible-build attestation.

## Observed continuity

S5 completed in **83.969 seconds**, within the frozen 600-second campaign limit,
with **66 root commands** against a limit of 96. The ignored test's owned command
took **33.484 seconds**, within its 180-second outer limit. Three registration
preflights are recorded separately. The independent audit checked 59 successful
root exits and seven expected negative exits, exact output hashes and byte
limits, and process-tree cleanup. Its evidence inventory was 1,109,460 bytes
against a 64 MiB cap; a 1 MiB final-report reserve and final cancellation/deadline
checks remained mandatory.

| Fixed observation | Result |
| --- | --- |
| Completed mixed-family TLS cycles | 24 of 24 |
| Persistent owner identities | 2 |
| Retained evaluated models | 2: three-bit affine and three-node graph |
| Unique wire request keys | 99: 96 read/predict requests and 3 submissions |
| Client attempts | 100, including exactly one planned duplicate |
| Durable candidate submissions | 3; read/predict replies are not durable cached receipts |
| Actual native listener ready instances | 26 |
| Listener termination | 25 graceful stops, 1 owned kill-and-wait, none left active |
| Reviewed server-leaf rotations | 4, after cycles 4, 8, 16 and 20 |
| Explicit denial/regrant pairs | 2, after cycles 6 and 18 |
| Verified backup/restore relocation | After cycle 12 |

Bootstrap quarantined and locally evaluated two artifacts. Each later cycle
started a new owned listener and performed actual affine and graph read/predict
requests. Exact identity and knowledge bytes, model digests and chronological
operational-history prefixes survived the restarts and midpoint relocation.
The two fixed fixtures are reused; more processes do not imply more discoveries.

The four rotations deliberately alternate **two preprovisioned server leaf
certificates**, while the client keeps its separate leaf. Old server pins are
rejected before application mutation. This demonstrates explicit reviewed
rotation, not automatic certificate issuance or renewal. Denied startup returns
the actual `STOPPED` / `no-authorized-peers` receipt with no listener, requests
or connections; generic exit success was insufficient.

During cycle 10, an authorized TLS proxy obtained a genuine committed
`QUARANTINED` receipt and withheld its first reply past the client deadline. The
owned service was killed and waited, stale locks were explicitly recovered, and
the exact request was retried once. It returned its original receipt without
another quarantine or learning change. The third candidate remained unevaluated.
Midpoint reviewed relocation rejected it exactly once, producing **zero new
promotions**. The two initially validated models remained intact.

## Independent audit and preserved failures

The saved `s5-independent-audit.json` reports
`PASS_BOUNDED_LOCAL_SOFTWARE_AND_CONTINUITY`. The reviewer performed a read-only
audit without native executions or a campaign rerun: 51 identity, knowledge and
operational chains; all 24 raw stdout/TLS request/response/report bindings;
finite predictions and graph paths; exact quarantine/retry provenance; public
certificate pins; denial/regrant receipts; restore mapping and reviewed
consumption; final inventory and credential/link scans. Its cross-check against
the frozen verifier was additional evidence, not the sole audit. The reviewer
used the same PC; this does not close the second-host gate.

| Attempt | Source | Elapsed / root commands | Preserved result |
| --- | --- | --- | --- |
| S3 | `68248001731d5073051d8175c746e83070149b65` | 49.156 s / 65 | **HOLD**: a namespaced test label became an invalid Windows output filename; the ignored test was not launched |
| S4 | `2403b2e852eb916a18d1088ba4c0e09610a5e023` | 82.562 s / 66 | **HOLD**: the native 24-cycle phase passed, but the consumer required an incorrect error-text substring |
| S5 | `cd792651d77765532cf39f9d8307ca3bcbb7e0fb` | 83.969 s / 66 | **PASS** for this bounded same-PC campaign |

Between these attempts, corrections were confined to
`tools/stability_campaign.py` and `tools/test_stability_campaign.py`. The protocol,
limits and native continuity producer stayed unchanged. Candidate CLI source
stamps were rebuilt for each source commit. S3's correction uses safe hashed
output filenames while preserving the original process label and arguments.

S4's relocation changed only the absolute state path in the copied public
policy, so the immutable policy guard correctly fired before the restore guard.
The corrected consumer accepts only the exact expected policy/restore error,
bound to the same owner, recomputed copied-policy digests and CA, verified backup
head and history, and actual reviewed relocation. Parser, credential and foreign
owner failures remain rejected. Ordinary native fixtures exercise both real
guards. A read-only posthoc S4 diagnostic passes the corrected component checks
and rejects nine copied-evidence tamper cases; its SHA256 is
`b57fc10e61731a22470503f8ab05d7d0733807490084c6e9c47b78ca252efa9e`.
That diagnostic **does not regrade S4**. Its original report and entire artifact
tree remain unchanged, as do S3 and the separate v0.5 research primary HOLD.

## Reproduce a new local campaign

Use a clean checkout of the exact S5 candidate and a Rust/Python toolchain. The
following PowerShell commands perform a fresh build, discover the actual test
executables and register a **new** OS-temporary evidence directory. They do not
reuse or overwrite the historical S5 registration. Local toolchain differences
can produce different executable hashes; retain the new registration's pins.

```powershell
$candidate = 'cd792651d77765532cf39f9d8307ca3bcbb7e0fb'
$source = (git rev-parse HEAD).Trim()
if ($source -ne $candidate) { throw 'Use a clean checkout of the pinned S5 candidate.' }
if (git status --porcelain) { throw 'Preserve local changes and use a separate clean checkout.' }
$env:SYMBIOTE_SOURCE_COMMIT = $source
cargo build --workspace --locked
if ($LASTEXITCODE -ne 0) { throw 'Candidate build failed.' }
$build = @(cargo test -p symbiote-runtime --test cli --test service --locked --no-run --message-format=json)
if ($LASTEXITCODE -ne 0) { throw 'Integration executable build failed.' }
$artifacts = @($build | ConvertFrom-Json | Where-Object { $_.reason -eq 'compiler-artifact' -and $_.profile.test -and $_.executable })
$cli = @($artifacts | Where-Object { $_.target.name -eq 'cli' })
$service = @($artifacts | Where-Object { $_.target.name -eq 'service' })
if ($cli.Count -ne 1 -or $service.Count -ne 1) { throw 'Require one actual executable for each selected target.' }
$cliPath = $cli[0].executable
$servicePath = $service[0].executable
$binary = (Resolve-Path './target/debug/symbiote.exe').Path
$output = Join-Path ([System.IO.Path]::GetTempPath()) ('symbiote-local-' + [guid]::NewGuid().ToString('N'))
$registration = python tools/stability_campaign.py register --binary $binary --cli-tests $cliPath --service-tests $servicePath --source-commit $source --artifacts $output
if ($LASTEXITCODE -ne 0) { throw 'Registration failed; preserve its evidence.' }
$registered = $registration | ConvertFrom-Json
$registered | ConvertTo-Json
python tools/stability_campaign.py run --registration $registered.registration --registration-sha256 $registered.registration_sha256
if ($LASTEXITCODE -ne 0) { throw 'Campaign HOLD; preserve the complete directory and do not retry this registration.' }
```

Retain the registration digest separately before `run`. Use the correct native
executable name on another platform; doing so is a new local check, not evidence
that this recorded Windows campaign ran there. The runner freezes source,
protocol, executable pins, checks and limits, and refuses a second start marker.
Do not silently select stale test executables, raise limits or repeat until PASS.

The evidence asset is `SYMBIOTE-v0.5.1-local-qualification.tar.gz`, with
`EVIDENCE_SHA256SUMS` on the
[v0.5.1 release page](https://github.com/jacksonjp0311-gif/SYMBIOTE/releases/tag/v0.5.1).
Its SHA256 is `52fca539bac260bbeae30f87168cea9b3d899e3afc12a9de12f64ae58dfe7de0`; it contains 1,752 files including
`MANIFEST.json` in 18,093,152 compressed bytes. The full extracted
tree was compared byte for byte with its selected sources. The compact
[evidence index](../experiments/v0.5.1/README.md) and
[asset receipt](../experiments/v0.5.1/evidence-archive.json) record the contents
and preserved packaging failures. Verify the checksum before extracting into a
short directory path on Windows; leave historical receipts unchanged.

## Remaining limits

This evidence supports a finite local maintenance and continuity result. It does
not establish long-term availability, two-host communication, generalization,
improved collaborator selection, generalized self-improvement or AGI. The test's
two models and repeated fixture predictions do not expand the v0.5 scientific
sample or reverse its failed criteria. Stable v1.0 remains subject to the
[separate release gates](STABLE_RELEASE_GATES.md).
