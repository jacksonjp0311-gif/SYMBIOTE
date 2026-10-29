# Independent observation source

This development example learns a conditional Boolean affine model from a separately implemented Python switchbox. The Rust observer receives individual authorized observations; private wiring and a full answer table are never supplied to it. No language model is used.

The published v1.0.1 baseline and evidence remain fixed. This work belongs to [Engine Evolution Protocol 002](../docs/ENGINE_EVOLUTION_PROTOCOL_002.md). Development smoke and registered four-case validation are separate results.

**Development smoke.** From the repository root in PowerShell:

```powershell
cargo build --locked -p symbiote-runtime --bin symbiote --example independent_observer
.\target\debug\examples\independent_observer.exe --version
python -B tools\engine_evolution.py smoke `
  --native .\target\debug\symbiote.exe `
  --observer .\target\debug\examples\independent_observer.exe `
  --out "$env:TEMP\symbiote-observer-smoke-01"
```

Choose an unused output directory. The smoke provisions an independent development case, identities, private grants and evidence. Python's standard library supplies the optional source/supervisor; learning and persistence use the existing Rust crate. This standalone embedding uses `ObservationSource`, `infer_with_policy` and `KnowledgeStore`.

**Source configuration.** Prepare the learner with `symbiote prepare-service --state DIR --json`; put its exact returned identity in `owner`.

| Client field | Required value |
| --- | --- |
| `schema` | `symbiote.independent-source-config/1` |
| `owner` | Prepared learner identity |
| `source_id`, `scope`, `epoch` | Explicitly approved source/context |
| `commitment` | SHA256 of the private canonical wiring opening |
| `width` | `8` for this example |
| `address` | Explicit loopback IP/port from source readiness |
| `token_file` | Absolute path to the separately provisioned private bearer |
| `timeout_ms` | Overall inference deadline, 1–12,000 ms |
| `max_queries` | Admitted call allowance, 1–256 |
| `max_work_units` | GF(2) work ceiling, 1–1,000,000 |

The supervisor owns a separate private source configuration. Its exact fields are `source_id`, `scope`, `epoch`, `commitment`, `width`, `mask`, `bias`, `token_file`, `max_queries`, `lifetime_ms`; its token path may be relative to that configuration. Keep wiring and its commitment opening private until prediction commits. A manually provisioned source starts with:

```powershell
python -B adapters\switchbox_source.py --config PRIVATE_SOURCE_CONFIG --transcript NEW_TRANSCRIPT
```

Keep its owner input pipe open; an owner newline or EOF stops it. Queries cannot request shutdown. Use a fresh source instance for each learning session.

**Wire and bounds.** Each connection carries one newline JSON request and response, at most 4,096 bytes per frame. Request fields are `schema` (`symbiote.switchbox-request/1`), `source_id`, `scope`, `epoch`, zero-based `sequence`, `input`, `token`. Response fields are `schema` (`symbiote.switchbox-response/1`), `source_id`, `scope`, `epoch`, `commitment`, `width`, `sequence`, `input`, binary `output`. Unknown fields, changed bindings and malformed/oversized replies fail closed.

Keep tokens outside public evidence in an owner-controlled directory; Unix token files must exclude group/other access, for example `0600`. The client accepts 16–256 ASCII letters, digits, underscores or hyphens. Tokens never enter receipts/transcripts. Read/write cancellation checks poll at 50 ms within the absolute deadline. `learn --cancel-file PATH` also stops when that file exists. Failed admitted calls consume allowance.

**Freeze → restart → reveal → commit → grade.**

```powershell
.\target\debug\examples\independent_observer.exe learn `
  --source-config PRIVATE_CLIENT_CONFIG --state OWNER_DIR `
  --receipts NEW_FREEZE_RECEIPT --query-policy rank

.\target\debug\examples\independent_observer.exe predict `
  --source-config PRIVATE_CLIENT_CONFIG --state OWNER_DIR `
  --inputs NEW_INPUTS_FILE --receipts NEW_PREDICTION_RECEIPT
```

Learning obtains nine training observations and one distinct validation observation, then promotes through the existing evaluator/store. Identical freeze bytes go to the requested receipt and `OWNER_DIR/freeze.json`, binding owner, source epoch, observations, policy, model and knowledge heads.

Stop the source before the separate prediction process. Reveal inputs after freezing. Input JSON has schema `symbiote.independent-observer-inputs/1`, `freeze_sha256` equal to the original freeze receipt SHA256, and unique `inputs` excluding every training/validation input. Prediction checks the active model, ledger-bound observations and original promotion. It contacts no source, reads no token and leaves learning heads unchanged. Commit the complete prediction receipt before the external grader reveals labels.

Registered validation additionally freezes clean source/executable/protocol pins. `--version` reports the compiled source stamp without state/network access; registration rejects a different stamp.

**Exact optional policy.** `reference` retains the finite-domain scan. `rank` selects `rank-basis-min/v1`: test augmented rows for zero and powers of two, choosing the first outside the observed row span. Once zero is in that span, every integer below the first missing power is a combination of earlier contained rows. This gives exactly the reference's lowest informative input. Hints and width one delegate to the reference scan; widths, support and contradiction semantics remain unchanged.

**Read the cost vector.** Keep acquisition work, source calls, wire bytes, cold replay/prediction work, retained bytes and supervisor work separate. Never sum unlike units or turn lower selector work into whole-agent net savings. Preserve isolation ties, cache abstentions and larger persisted receipts alongside computation savings. Fresh conditional reuse does not establish peer transfer, reciprocal efficiency, broader-domain generalization or independent scientific samples.
