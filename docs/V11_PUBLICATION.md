# Reviewed v1.1 publication

Status: delivery tooling, **not a publication or qualification receipt**. No
command below has been executed against a live release during its unit tests.
The prior v1.0.1 release remains latest until the final explicit promotion.

Current corrective target: **v1.1.1**. The preserved v1.1.1 prerelease failed
public run 40893604489 before any download or native execution and is flagged
permanently. Its tag and 35 assets are unchanged. The
[corrective contract](CORRECTIVE_RELEASE_111.md) requires new images and gates;
its earlier hour is not qualification of a replacement executable.

`tools/release/v11_publish.py` publishes the exact already qualified staged
bytes. It does not rebuild, execute a native image, create/move a Git tag,
delete/replace an asset or silently change an existing release's source. Root
creates the reviewed `v1.1.1` tag separately at the known candidate commit.

The corrective delivery target is **v1.1.1**. The original v1.1.0 public
attempt, source `9016624350e9dcc506b1d0d1cd82e58cadc38882`, is preserved as a
failed prerelease after [public workflow 40893604489](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/runs/40893604489)
failed on all four platforms before downloads. Its tag and 35 assets remain
immutable; it must not be rerun or promoted. The correction requires fresh
source/platform checks, an actual new staged-image hour and new public acceptance.
The v1.0.1 stable release remains latest until that succeeds.

## Stages

Each invocation requires a fresh short absolute OS-temp output directory, the
reviewed plan file and its independently retained SHA-256:

```text
python -B tools/release/v11_publish.py verify --plan PLAN.json --plan-sha256 SHA --out NEW_TEMP
python -B tools/release/v11_publish.py stage --plan PLAN.json --plan-sha256 SHA --out NEW_TEMP
python -B tools/release/v11_publish.py provisional --plan PLAN.json --plan-sha256 SHA --out NEW_TEMP
python -B tools/release/v11_publish.py finalize --plan PLAN.json --plan-sha256 SHA --public-acceptance PUBLIC.json --public-acceptance-sha256 SHA --out NEW_TEMP
python -B tools/release/v11_publish.py flag-failed --plan PLAN.json --plan-sha256 SHA --failed-public-run RUN_ID --out NEW_TEMP
```

`verify` reads/verifies only. `stage` creates or resumes the exact draft, with
prerelease true and latest false. `provisional` publishes those bytes as a public
prerelease, anonymously downloads every asset, and requires v1.0.1 to remain
latest. The separately dispatched `v11-public-accept.yml` tests all four matching
platforms from anonymous downloads, using the original signed candidate driver
and independent consumer; it builds no replacement native images. `finalize`
requires that exact-source official workflow to pass and all four public native
and embedding receipts before stable/latest promotion.

Every mutation preserves the reviewed plan and actual remote metadata in its
output. Exact existing assets can be resumed; a mismatched asset is a HOLD.
Failure preserves partial drafts/public bytes and never repairs their history.

An authenticated tag lookup returning 404 does not establish draft absence.
The publisher reads the fixed repository's owner-visible first page (at most 100
releases); a full or malformed page is HOLD, not permission to create. A unique
matching draft is re-read by its actual ID and checked against the exact source,
body and existing asset digests. Ambiguous, foreign or flagged drafts cannot
create a replacement. After upload, the known ID and every uploaded asset ID are
checked directly; the final check does not depend on draft-by-tag lookup.

A failed public candidate must be explicitly flagged and corrected under a new
version, with no asset replacement or tag movement.
`flag-failed` independently checks an actual failed/timed-out exact-source
official public workflow before adding a permanent failed-release notice and
keeping it a non-latest prerelease. It preserves all asset bytes and the tag.
Ordinary staging/finalization then refuse its altered flagged body; a later
passing receipt cannot silently turn that failed version into a stable release.

## Plan and evidence boundary

The strict `symbiote.v11-publication-plan/1` object declares:

- Fixed repository `jacksonjp0311-gif/SYMBIOTE`, version `v1.1.1`, full
  `candidate_commit`, `candidate_run_id` and official `source_ci_run_id`.
- Actual publisher/transport SHA-256, a pinned absolute GitHub CLI executable
  `{path, bytes, sha256}`, and the locked Cargo digest.
- `assets`: exact `{name, path, bytes, sha256}` records for 33 files: four target
  groups of seven subjects plus their staged checksum file, and global
  `SHA256SUMS` covering exactly the four native ZIPs. Optional `EVIDENCE.zip` and
  `EVIDENCE_SHA256SUMS` are admitted only as a complete pair.
- `platforms`: the four exact target keys, each with `native_sha256`,
  `embedding_sha256` and `driver_sha256`.
- Twelve independently pinned gate records: `source-ci`, `linux-enospc`, `e3`,
  `hour`, and `candidate-native:TARGET`/`candidate-embedding:TARGET` per platform.
- A bounded pinned UTF-8 release `body` file.

Each gate coordinate is `{role, path, bytes, sha256, subject_sha256}`. Its typed
`symbiote.v11-release-gate/1` JSON binds the role, source, candidate run, subject,
actual start/end Unix nanoseconds, passed status, and a nonempty exact file
evidence census. `operator_review` records reviewer, `decision: "ACCEPT"`, scope,
and `evidence_digest`: SHA-256 of the evidence list encoded as sorted-key compact
JSON. The *external plan pin* binds this reviewed assessment; the inner digest
is an integrity coordinate, not an operator signature.

Native/embedding gates must include named raw `native-acceptance` and/or
`embedding-acceptance` receipts with actual source/target/image bindings.
`linux-enospc` requires named `enospc-native` with the real errno-28 result and
actual test image/source. Public gates require both component receipts.
They also require named `public-platform` with the actual source, official
public workflow ID, release ID, plan/ZIP/image pins and exact nested child
receipts. Candidate receipts cannot be relabeled as public evidence.
Gate assessments remain trusted operator judgments of the preserved behavioral
evidence. They are not mathematical proof, and completion is never an efficiency
or generalized-intelligence claim.

Fresh cryptographic checks independently run the pinned `gh attestation verify`
for each ZIP, build record and dependency inventory, plus its distinct CycloneDX
predicate. Source digest, signer workflow/digest, GitHub-hosted runner policy,
current repository identifier, signed run invocation, predicate, timestamp and
subject digest must match. Saved producer `*-verification.json` booleans do not
authorize publication. These checks establish signed build origin, not behavior.
See the [GitHub CLI verification contract](https://cli.github.com/manual/gh_attestation_verify).

Final `symbiote.v11-public-acceptance/1` JSON is pinned separately because public
evidence cannot exist when the original plan is frozen. It binds the original
`publication_plan_sha256`, actual `release_id`, candidate commit, official
`public_run_id`, and `asset_digest` (sorted-key compact JSON SHA-256 of the entire
asset-name-to-digest mapping). Its four `public-native:TARGET` gates carry the
same `public_binding` and original platform hashes. This never rewrites the
initial plan or earlier receipts.

The transport source is raw-read, hashed, compiled and executed without loading
Python bytecode caches; its loaded-source pin must still match before operations.
Authentication is obtained only for named mutation modes from the existing
credential helper, never logged or sent to redirected hosts. The actual programs
under test receive no release credentials. No memory update, workflow dispatch or
live publication is performed on import or by the offline test suite.
