# Evidence packaging and public release verification

`package_stability_evidence_v4.py` and `package_v1_evidence_v3.py` are preserved
byte-for-byte. Their SHA256 pins remain `9a2df3fc679ce154469013e02575551d9572e7cee4d2a0eca585e7fc3a780962`
and `74360bb33742fafab379df6efbcb1afdf60ccc47035605dbd2929c89d21612eb`.

Use `package_v1_evidence_v4.py` for a release containing studies from different
source commits. It extends the existing census, exact-byte extraction comparison
and final source revalidation. Compressed archive bytes are checked against the
writer receipt before linking and again through the final hard link; changed
staged bytes are HOLD and no checksum is exposed. It never runs a study or changes a result. Its
configuration schema is `symbiote.v1-evidence-config/2`:

- Each anchor additionally declares `source_commit`: its exact original source
  if `source_commit_pointer` is present, otherwise null. The top-level
  `source_commit` identifies the release being documented; it does not relabel
  historical evidence. Executables remain bound to their own anchored hashes.
- `format_classifications` is an explicit list, normally empty. The supported
  entry is `{ "path": "ABSOLUTE_FILE.jsonl", "sha256": "EXACT_SHA256",
  "format": "cargo-json-and-rust-test-output/1" }`. This preserves mixed Cargo
  JSON and Rust test output under its original filename and exact bytes. Every
  byte is scanned; every JSON line receives decoded credential checks. Human
  lines must match the closed Rust test-output grammar. Invalid JSON,
  unexpected text, unselected classifications and changed pins fail.
- The scanner recognizes one additional public consent declaration only at
  `/details/authorization` in a `symbiote.cognition-event/1` CONNECT event:
  `explicit operator registry and current durable denials`. Other locations,
  schemas, phases, altered values and neighboring secret fields remain rejected.
  The archive contains unchanged original bytes. This is a narrow scanner
  interpretation, not a redaction or a credential-scanning bypass.
- A normal `CAPABILITY_OPPORTUNITY` event under that same schema/location may
  declare exactly `explicit normal quality-goal policy plus current bilateral
  operation grants`. The phase, full string and location must all match;
  adjacent or nested credentials still fail. These public policy declarations
  confer no credential-scanning exemption on other fields.

All inputs must be stopped before planning. First run:

```text
python tools/release/package_v1_evidence_v4.py --config ACTUAL_CONFIG.json --plan-only
```

Review the actual selected roots, per-source anchors, historical outcomes, helper
pins and emitted manifest digest. Then use that independently retained digest:

```text
python tools/release/package_v1_evidence_v4.py --config ACTUAL_CONFIG.json --expected-manifest-sha256 REVIEWED_SHA256
```

Keep failed plans, staged archives and HOLD receipts. Use fresh outputs after a
correction. A package PASS establishes byte preservation and scanning; existing
independent consumers determine experiment or release qualification. A previous
hour cannot qualify changed production code. Missing original executables must
be declared unavailable, never replaced with a later build.

`release_v1_candidate.py` requires an explicit `--tag`, exact `--commit` and
`--release-run-id`. It accepts real GitHub REST `author` metadata, including a
manually authored release, and separately requires successful `release.yml` on
that exact tag/source for a push event, plus workflow-uploaded native assets.
Workflow dispatch is refused because its input tag may differ from the run ref. It never creates or
moves a tag, creates a release, replaces assets or starts a scientific campaign.
Anonymous redirect downloads never carry credentials. Upload mode only adds the
reviewed evidence archive/checksum to an already published release. Final
verification requires the exact seven-asset set, and optional Windows smoke can
bind configured cognition to the actually downloaded executable.

```text
python tools/release/release_v1_candidate.py status --tag v1.0.1 --commit COMMIT40 --release-run-id RUN_ID --out NEW_ABSOLUTE_TEMP_DIRECTORY
```

Use `--help` for upload and verification inputs. Write-mode qualification requires
actual execution and retained receipts; offline tests alone do not establish it.
The restored read-only status path passed against public v1.0.0. The original
failed `creator` lookup remains recorded in `docs/V1_RELEASE_AUDIT.md`.
The isolated Windows installer also removes an inherited PowerShell Core module
path only during its Windows PowerShell child launch and restores it on failure
or success. This prevents the previously observed missing `Get-FileHash` module
without changing the user's saved environment or PATH.

Run the disposable regression fixtures with:

```text
python -m unittest discover -s tools/release -p "test_*.py"
```

These test membership/byte mutation rejection, mixed-format scanning, decoded
credentials, per-source attribution, workflow/source binding, redirects, checksum
sets and native archive shape. Synthetic executable fixtures are never run.

## Replay the extracted corrective evidence

`portable_evidence_replay.py` replays recorded data from an extracted archive.
First verify the archive and retain its `MANIFEST.json` SHA256 independently.
Only use trusted, reviewed consumer code: a self-declared hash is not authority
to execute Python. The adapter validates the complete member census, source
anchors and executable-role digests. It maps original absolute paths through
the pinned manifest, with no fallback to the original host directories.

The final archive uses these mappings:

| Kind | `--collection` | Additional arguments |
| --- | --- | --- |
| `cohort` | `final-reciprocal` | `--registration-anchor final-reciprocal-registration` |
| `normal` | `normal-feedback` | None |
| `hour` | `final-hour` | `--registration-anchor final-hour-registration` |
| `observation` | `active-observation` | The exact observation helper member and SHA below |

Use `--tools-member evidence/preserved-receipts/qp-101-6025fff/qualification-tools`
and `--consumer-sha256 40b4e51e3d08aab461dec395d47983f9faa0ff758a233ebc397eb141f5ed4a54`.
Executable roles default to `final-build-native` and `final-build-service-tests`;
registered cohort/hour source and binary pins must match their original anchors.

```text
python tools/release/portable_evidence_replay.py cohort --archive-root EXTRACTED_ROOT --manifest-sha256 EXTERNAL_MANIFEST_SHA256 --collection final-reciprocal --registration-anchor final-reciprocal-registration --tools-member evidence/preserved-receipts/qp-101-6025fff/qualification-tools --consumer-sha256 40b4e51e3d08aab461dec395d47983f9faa0ff758a233ebc397eb141f5ed4a54 --output NEW_FILE_OUTSIDE_ARCHIVE.json
```

For observation replay, also pass
`--observation-helper evidence/independent-audits/qe-6025fff-rhjvvxuy/audit_observation_6025fff.py`
and `--observation-helper-sha256 6834b3d80feca2e08db63c3779248cbe9304601ebb84c3eacce7e81c0b51b162`.
Every output must be new and outside the extracted corpus. The loader checks
each selected Python dependency's exact bytes immediately before compiling those
bytes; timestamp-valid cached `.pyc` files cannot substitute different code.

This is data-only replay: it launches no native executable or registered study,
modifies no original record and infers no missing result. Public-binary proof
uses `--native-role public-build-native` only after that independently anchored
role exists in the final manifest; it cannot replace the frozen cohort/hour
binary. Public installation and archive delivery remain separate required checks.

## Prospective v1.1 staged platform checks

The [v1.1 support contract](../../docs/V11_ENGINE_SUPPORT_CONTRACT.md) remains a
target until its actual gates pass. `v11-candidate.yml` is a manual staging
workflow. Its `source_commit` input must equal the workflow's own exact HEAD;
it cannot attest an independently selected checkout under a different run source.
It does not create a tag, release or latest-release mutation. The old tag builder
retains its v0/v1.0 path and refuses v1.1+ rebuilds. Final delivery must reuse the
reviewed candidate bytes after qualification.

Qualification uses exactly Rust **1.98.1** with the committed lockfile. Ordinary
CI tests that minimum on three operating systems and tests current stable
compatibility separately. Candidate staging also requires `verification_run_id`:
an actual successful official `ci.yml` push run for the exact source on `main`.
`verify-source-ci` checks its complete three-platform minimum-compiler job set,
documentation steps and separate current-stable compatibility job. Candidate
jobs reuse those source gates; the additional Intel macOS host runs the full
source checks once because it is absent from that CI matrix. Every candidate
host still executes its own installed native and embedding lifecycle.
The candidate matrix builds and executes Windows
x86_64 MSVC, Linux x86_64 GNU, macOS arm64 and macOS x86_64 on matching hosts.
An absent/failed runner remains unqualified; building a file for that target is
insufficient.

`v11_release_checks.py accept` installs the checked local ZIP into a new canonical
OS Temp directory without PATH changes. Its `engine` product commands exercise
typed learning, a new-process zero-source-access reopen, pre-cancellation,
prediction, checkpoint/restore and revocation. The restored owner must retain
its minimum-writer registration; the current legacy observation command must
refuse that owner without changing any committed ledger. The older observation,
backup and restore checks remain separate coverage. It then invokes two exact,
source-matched native service-driver tests with that installed image explicitly
selected: owner-EOF cancellation/RPC budget and receiver-owned outcome/restart.
The driver and native image have distinct byte pins. Closed public artifact
censuses, actual exit/summary evidence and unchanged history are required.
Failures retain streams, process receipts and a HOLD rather than becoming a
platform support claim. `embedding` additionally executes the independently
compiled `tests/consumer-engine` workspace on each host. Its own locked dependency
graph and exact executable are retained separately from the installed runtime
and service-test driver. `stage-acceptance` byte-copies closed exports under the
single portable artifact root and checks complete source/destination censuses.
This is bounded software acceptance, with no economic
advantage or independent scientific samples implied.

`metadata` binds native/bundle bytes, source manifest, compiler version, Cargo
lock, resolved features, release helpers and behavioral proof hashes. It emits a
CycloneDX 1.5 dependency inventory from Cargo's target-filtered normal/build
closure, including workspace components and registry archive checksum properties.
Dev-only dependencies and unidentified system/toolchain libraries are outside
that inventory; it is not reverse engineering or a vulnerability scan. Compiler
flags outside the declared default build are refused.
The existing native source-manifest selection is preserved: it includes the
shared Rust example but excludes the external consumer workspace and nested
release tools. Signed build proof therefore separately pins that workspace's
`Cargo.toml`, `Cargo.lock` and `src/main.rs`, and the actual release helper. The
publication plan separately pins its publisher and loaded transport source.

The workflow separately signs build provenance and the SBOM through the pinned
GitHub `actions/attest` implementation, then invokes GitHub CLI verification with
the expected repository, source digest, signer workflow, signer digest and
predicate type. Raw signing bundles are preserved immediately, before another
signing action can reuse its temporary path. `seal` writes a new target-specific
checksum set for the seven staged files. Hash/seal success alone is not signature
verification. Attestations establish build provenance; they do not establish
behavior, the independent embedding lifecycle or the final 60-minute gate.

The dedicated Linux fault job mounts only its guarded, empty, runner-owned
1 MiB tmpfs and invokes the explicitly named ignored ENOSPC test. The test must
observe kernel error 28, preserve committed ledger bytes and report a typed HOLD
on reopening the interrupted write. The job preserves the stopped volume and
unmounts it on exit. This platform-specific check does not establish disk-full
behavior on Windows or macOS and is never executed by ordinary test discovery.

No final v1.1 campaign is launched by these helpers. Only after behavior freezes
should the existing once-only `soak_campaign.py` register final native/test byte
pins and execute its declared 120-cycle hour with awake/source/cleanup guards.
Preserve each failed attempt and the exact candidate/driver/compiler boundaries.
Before public delivery, independently review all platform receipts and signature
verification results, embedding evidence and the fresh final hour. Then verify
anonymous downloads and repeat acceptance on the delivered images.

`v11_publish.py` consumes an externally SHA-pinned publication plan and twelve
distinct reviewed prepublication gates: exact source CI, native plus embedding
on all four targets, Linux ENOSPC, the registered transfer study and the fresh
hour. It verifies fresh build signatures through an explicitly pinned GitHub CLI
before uploading exact staged files. `stage` creates a draft; `provisional`
publishes those immutable bytes without making them latest. It cannot create or
move Git tags, rebuild native images, overwrite existing assets or silently retry
a failed public qualification. The original public v1.0.1 remains separate.

`v11-public-accept.yml` downloads the original candidate evidence and anonymously
downloads each published target's exact ZIP and signed metadata. `public-accept`
reverifies the ZIP, build metadata and SBOM signatures against the exact source,
candidate run and signer before executing the retained driver or consumer. It
tests the delivered native bytes on each matching host and repeats embedding
acceptance using the original signed-source consumer bytes. Program-under-test
children receive only the selected runtime environment, without inherited CI
tokens or unrelated SYMBIOTE overrides. Raw public `SHA256SUMS` retains its four
ZIP entries; a labelled derived one-host checksum file serves the local installer.

Only a separate externally pinned public-acceptance record covering all four
hosts allows `finalize` to remove the provisional flag and mark this same release
latest. Saved JSON booleans alone do not replace fresh signature verification or
actual native process receipts. All v1.1 platform and publication outcomes remain
prospective until their source-frozen workflows and retained gates have run.
