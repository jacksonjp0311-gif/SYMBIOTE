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
