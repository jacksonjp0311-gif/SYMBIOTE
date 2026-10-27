# v0.5 evidence index

The first protocol-004 primary remains **HOLD**. The completed S2 run is an
**engineering reproduction of the same 24 worlds**, with the original empty
identities and opaque contexts. It is neither a replacement primary nor an
independent sample. Read the [methods, results and limitations](../../docs/RESEARCH_V05.md)
and the [preserved failure account](../../docs/RESEARCH_V05_PRIMARY_HOLD.md).

## Bindings and results

| Item | Primary S1 | Engineering S2 |
| --- | --- | --- |
| Source | `31764625bedd4e58a828078b30b5dfa175218325` | `fc67f2ba74f7fefbf843084579f599b13cd9f7b9` |
| Studied Windows executable SHA256 | `3277e52b8f811a0d0a6596476cd780eefb3661802af397bed4a4f0ae479957c9` | `8cecd947cafafaebd3fdb9f29e480a399f36b67b806b83afb15b49d55c7cf1d6` |
| Registry | 136 completed, 1 failed, 55 not run | 192 completed, no failures or omissions |
| Status | HOLD | PASS for the engineering software/safety run |

Protocol SHA256:
`d3e8454147b67fec510712eac094d0f946e683cd5472e3304ba912f1fea1c567`.
The exact setup companion SHA256 is
`024456d06065859c8d8602b65da4dbbf6a7921667dee551415c7ef5dc9b58c1d`.
It binds the original genesis catalogue, 24 public context/schema mappings,
eight prelude contexts and original source/binary/report references. It imports
no truth labels, learned models, outcomes or keys. S2 regenerated and checked the
same complete frozen environments, with fresh TLS pins and authority epochs.

The 49 private state paths contain 40 learner profiles, eight authorities and one
controller, representing 14 logical identities. Five learner identities are
matched across counterfactual groups while files and authorization remain
separate. Of the 40 learner profiles, 32 actively reason and retain state; eight
are incompatible idle controls. These profiles share the controller and task
worlds and must not be counted as independent research teams.

Each arm and price produced 568 correct held-out predictions out of 1,596,
1,028 abstentions and zero wrong certificates. Normal prospective A+B1 cost
107,380 versus isolated 110,119, fixed-peer 107,176 and uniform 108,632.
Cheap prospective cost 84,797 versus 83,983, 84,594 and 84,802 respectively.
The research report retains separate A/B1 results and every higher-cost or
neutral comparison. Better partner selection was not demonstrated.

The 64 private promotions cover two distinct contexts: world 2 with five nodes
and world 7 with six nodes. Every active learner retained two models and made
21 certified offline predictions with zero additional observation, verification
or assessment calls. Normal A had eight post-restart score effects and zero
action changes; operational score use is not a demonstrated behavioral gain.

S2 took 1,206.891 seconds, including 1,082.893 seconds of admission waits.
It preserved the math, prices, quotas and deadlines and introduced no retry.
Resource timings and OS/process measurements are separate from the declared
participant utility bill; no speedup is claimed.

## Evidence assets

The v0.5 release uses these byte-pinned evidence assets. Download them from the
[release page](https://github.com/jacksonjp0311-gif/SYMBIOTE/releases/tag/v0.5.0)
and check the manifest hashes before extraction. Publication status recorded in
a manifest describes its creation time, before release publication.

| Asset | Contents | Manifest |
| --- | --- | --- |
| `SYMBIOTE-v0.5-primary-004-HOLD.tar.gz` | Original registration, start marker, S1 executable, reports, case receipts and private state; original failures retained | [Primary manifest](primary-evidence-manifest.json) |
| `SYMBIOTE-v0.5-primary-004-HOLD-analysis.json.gz` | Subsequent independent partial-evidence analysis; does not regrade the primary | [Primary manifest](primary-evidence-manifest.json) |
| `SYMBIOTE-v0.5-engineering-004.tar.gz` | Complete S2 engineering directory, studied executable, setup companion, state and both independent review receipts | [Engineering manifest](engineering-evidence-manifest.json) |

The active Git tree retains compact manifests and verification summaries rather
than generated raw ledgers and large reports. Archives preserve their original
bytes. Ordinary installer bundles have different platform-specific executable
hashes; verification below uses each archive's `candidate-symbiote.exe`.

## Verify extracted raw evidence

Use Python and Git from a full SYMBIOTE checkout containing the pinned S1/S2
commits. The following PowerShell commands only inspect extracted evidence and
write new verification receipts. They do not launch another native cohort.
Check archive SHA256 values against the manifests before extraction.

Set these two paths to the extracted directories that contain `report.json`:

```powershell
$primary = (Resolve-Path './evidence/primary').Path
$engineering = (Resolve-Path './evidence/engineering').Path
$verification = Join-Path ([System.IO.Path]::GetTempPath()) ('symbiote-verification-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $verification | Out-Null
```

Verify the original primary first. Its expected result and exit status are
**HOLD/nonzero**; incomplete authority/replay evidence must remain unverified.

```powershell
python tools/verify_adaptive.py `
  --report "$primary/report.json" `
  --registration "$primary/primary-registration.json" `
  --binary "$primary/candidate-symbiote.exe" `
  --artifacts "$primary" `
  --source-root . `
  --output "$verification/primary.json"
```

Verify S2 with the exact companion and preserved original primary. Its expected
engineering result is **PASS/zero**:

```powershell
python tools/verify_adaptive.py `
  --report "$engineering/report.json" `
  --registration "$engineering/reproduction-registration.json" `
  --binary "$engineering/candidate-symbiote.exe" `
  --artifacts "$engineering" `
  --setup "$engineering/reproduction-setup.json" `
  --original-primary "$primary" `
  --original-binary "$primary/candidate-symbiote.exe" `
  --source-root . `
  --output "$verification/engineering.json"
```

The explicit `--artifacts` prefix remaps recorded temporary paths after
extraction. Keep registrations, reports and ledgers unchanged; do not rewrite
paths inside them. Output filenames must be absent because the verifier refuses
to replace an existing verification receipt.

The engineering archive also contains
`independent-original-case-comparison.json`: all 96 completed normal and 40
completed/evaluable cheap primary cases match S2's task inputs, IDs, contexts,
bills, policy decisions and conditional certificates. The comparison normalizes
only fresh authentication identifiers/digests and excludes elapsed overhead.
The primary's failed and not-run cases are never retroactively relabeled.

## Deliberately repeat the fixed engineering setup

This starts another run on the same already observed worlds, with fresh private
state and authentication. It is an explicitly labeled reproduction and takes
about 20 minutes on the recorded host. It supplies no new primary evidence.

```powershell
symbiote adaptive-research --reproduce `
  --setup-catalogue "$engineering/reproduction-setup.json" `
  --setup-sha256 024456d06065859c8d8602b65da4dbbf6a7921667dee551415c7ef5dc9b58c1d `
  --json
```

The runtime creates a new temporary artifact directory and prints its paths.
It refuses nonempty state and existing output files. Without the setup pair,
`--reproduce` creates fresh identity/context entropy and can change the fixed-peer
ordering; do not describe that run as an exact replay of these identities.
Neither command authorizes attachment to an external agent.
