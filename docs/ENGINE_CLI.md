# Use the typed engine from the installed binary

`symbiote engine` calls the documented [embedding API](ENGINE_EMBEDDING.md) in
the ordinary product binary. It needs neither a model service nor Python. These
commands are a caller-owned host for the engine, not another inference algorithm
or research controller. The v1.1 support/qualification status remains defined by
[the release contract](V11_ENGINE_SUPPORT_CONTRACT.md).

Every operation returns one JSON object with schema `symbiote.engine-cli/1`.
Success has `status: "PASS"`; nonzero exits have `status: "ERROR"` and a typed
`error.kind`. Never parse diagnostic English. `--json` is accepted, but already
the default for this command group. `symbiote engine --help` describes the flags.

## Commands

All state paths are absolute. Existing-owner operations require the exact owner
returned by `init` and the original immutable engine configuration.

| Command | Additional required options | Result |
|---|---|---|
| `init --state NEW_DIR` | `--config FILE` | New identity in `inspection.owner`; existing directories are refused |
| `learn --state DIR` | `--owner ID --config FILE --source SOURCE_ID --observations FILE` | `result.learning` and actual `source_access` |
| `predict --state DIR` | `--owner ID --config FILE --artifact ID --input U16` | `result.prediction`, including conditional basis/applicability |
| `inspect --state DIR` | `--owner ID --config FILE` | Inspection, durable counters and resource diagnostics |
| `revoke --state DIR` | `--owner ID --config FILE --artifact ID --reason TEXT` | Explicit revocation anchor |
| `checkpoint --state DIR` | `--owner ID --config FILE --backup NEW_ABSOLUTE_DIR` | Closes the owner before creating `result.checkpoint` |
| `restore --state NEW_DIR` | `--owner ID --config FILE --checkpoint SAVED_JSON --manifest-sha256 EXTERNAL_PIN` | Verified restored owner and explicit rollback receipt |
| `recover --state DIR` | `--owner ID` | Only removes locks whose recorded owner process is proven dead |

`learn --cancelled` pre-cancels the owner-local token. It returns typed
`cancelled` without opening the observation file or beginning new learning.
It does not control another process or remote agent.

Normal opened operations include `inspection`, `counters` and `resources`.
Source/evaluation/capability facts are separate from economic benefit. A failed
close or failed diagnostic is reported rather than being hidden behind success.
Unknown economics remain unknown.

## Authorized observation replay

The explicit replay adapter accepts a bounded JSON array of individual frames:

```json
[
  {"sequence":0,"input":0,"output":0},
  {"sequence":1,"input":1,"output":1},
  {"sequence":2,"input":2,"output":0},
  {"sequence":3,"input":4,"output":1},
  {"sequence":4,"input":3,"output":1}
]
```

This three-bit example is parity of input bits 0 and 2. The engine receives only
the next requested observation, chooses its queries through the existing exact
`rank-basis-min/v1` policy, infers its own conditional model, and checks a distinct
held-out input. It does not receive a precomputed model or table as evidence.

Configure a unique `source_id`, scope, epoch, width and commitment in the ordinary
`EngineConfig`. The commitment **must equal SHA-256 of the exact observation file
bytes**, including whitespace and newline choices. No normalization is performed.
The adapter reads at most 128 KiB and accepts at most 256 unique, ordered,
in-domain binary frames; unknown fields, mismatched selected inputs, repeated
inputs and incorrect sequence/output values are refused. The source must belong
to the caller's explicit configuration; its own claim is not authorization.

The file is loaded lazily on the first actual observation callback. Retained
reuse with the same source/policy has `source_access` equal to
`{"calls":0,"read_bytes":0,"file_opened":false}`, even if that file has been
removed. This is persistent finite structural knowledge; it is not a claim of
general intelligence or an advantage over an appropriate isolated learner.

## Windows quick start

Run from the directory containing the installed `symbiote.exe`. The script
creates an explicit new temporary owner and writes UTF-8 without a byte-order
mark. It uses synthetic local observations, with no network or credentials.

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
$initialized = .\symbiote.exe engine init --state $state --config $config | ConvertFrom-Json
$owner = $initialized.inspection.owner
$learned = .\symbiote.exe engine learn --state $state --owner $owner --config $config --source owned-example --observations $observations | ConvertFrom-Json
$artifact = $learned.result.learning.artifact
.\symbiote.exe engine predict --state $state --owner $owner --config $config --artifact $artifact --input 6
Remove-Item -LiteralPath $observations
.\symbiote.exe engine learn --state $state --owner $owner --config $config --source owned-example --observations $observations
```

The last invocation reopens retained knowledge and needs zero source calls. Its
prediction for input 6 is 1. Each command ends by closing its owned writers.
Automation should check the native exit code and `status` after every command.

## Checkpoint and rollback

Save the entire successful `checkpoint` JSON output to a separate UTF-8 file.
Retain `result.checkpoint.manifest_sha256` independently. Pass that saved file,
the independent hash and expected owner to `restore`; a mismatch is refused
before restoration. A raw serialized `Checkpoint` object is also accepted.

Restoration uses a new directory, starts no network, and explicitly reports
`rollback_discards_later_learning: true`. The original and restored copies have
the same identity: do not operate them as independent agents. The product's
supported local-filesystem, same-OS, finite affine and cooperative-callback limits
are unchanged. Missing/incomplete evidence returns an explicit error/HOLD; these
commands never reset an owner to make recovery appear successful.
