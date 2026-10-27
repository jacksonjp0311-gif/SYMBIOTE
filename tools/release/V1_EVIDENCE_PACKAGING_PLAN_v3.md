# V1 external evidence packaging, byte-revalidation revision 3

Preparation only: no real v1 evidence is collected by creating or testing these
files. Use `package_v1_evidence_v3.py` with the existing strict config template.
Prior adapters, plans, tests, logs and qualified archives remain unchanged. The
exact v4 scanner/writer remains SHA-bound at
`9a2df3fc679ce154469013e02575551d9572e7cee4d2a0eca585e7fc3a780962`.

V2's full path/type census remains in place, including empty directories and
fail-closed listing/link/type checks. The new V3 gate also rehashes every selected
source occurrence and the config after the staged writer returns, immediately
before the final archive link. This includes JSON anchors, registered executable
bytes, individual receipts and all duplicate/aliased sources of one archive
member. It does not accept the staged writer's earlier byte-only PASS as a final
qualification.

The final pass checks expected size before opening, SHA256 and exact byte count
while streaming, and stable per-read metadata. Each read is capped at the expected
size plus one sentinel byte to detect growth. The entire planned final pass is
capped at 40,033 source references and 2 GiB including the config; an over-budget
alias list is HOLD rather than a silently incomplete recheck. These bounds and
planned work are included in the reviewed manifest. No credential exception or
scanner format rule changed. Matching final SHA256 preserves the already scanned
content; the final hash pass makes no new semantic or certificate-trust claim.

## Review and creation

All input writers must first stop. Fill only actual independently retained source,
registration, report, executable and historical-status pins. The template stays
non-executable until those actual values exist. Use a new short OS-temp output
parent outside every input boundary; all extraction and sidecar paths must remain
at most 240 characters.

```text
python package_v1_evidence_v3.py --config ACTUAL_CONFIG.json --plan-only
```

Preserve stdout/stderr. Independently review the exact config/helper pins,
`manifest_sha256`, `tree_census_sha256`, planned final revalidation work, selected
roots and actual historical statuses. After Root authorizes actual packaging:

```text
python package_v1_evidence_v3.py --config ACTUAL_CONFIG.json --expected-manifest-sha256 REVIEWED_64_HEX_DIGEST
```

The staged archive and base verification receipt are retained under exclusive
`attempt/`. Only after the post-stage census and final source hash/size checks
succeed does V3 expose the qualified final archive, manifest, verification receipt
and archive-only `EVIDENCE_SHA256SUMS`. The outer receipt schema is
`symbiote.v1-evidence-packaging/3`. On failure preserve all staged files and the
outer HOLD. Use a fresh output parent for a separately authorized correction;
never overwrite failures or upload staged/partial archives.

Malformed configs never authorize writes to an unvalidated output path. Preserve
caller stderr for failures before output validation. A validated packaging failure
gets a HOLD receipt where writing it is possible. There is no automatic retry or
online upload.

## Limits and evidence meaning

These are sequential checkpoints, not a filesystem snapshot or a lock against
concurrent input writers. An entry added and removed entirely between checkpoints,
or a mutation after the final check, is outside that claim. Stopped writers remain
a required precondition. Existing full archive extraction/byte comparison and
credential checks remain unchanged. Root must preserve original evidence and
independent verifier results; historical HOLDs remain HOLD.

Dedicated tree collections claim the complete recorded file set and directory
census. Explicit files-mode collections claim only selected files. Whole Temp,
audit roots, source checkouts and external private-PKI fixtures are never discovery
targets. Include exact LICENSE and helper/audit provenance as explicit pinned
files. Private credential extensions, complete private-key PEMs and known provider
credentials, including decoded JSON, remain refused; validated public CERTIFICATE
PEMs remain allowed.

No study, endpoint, native binary, generator or campaign runs in the synthetic
interface tests. A local archive does not close the independent two-host gate or
prove stable v1.

## Disposable regressions

`test_package_v1_membership_v3.py` retains the eight membership checks and adds
post-stage same-path/same-size changes to observation, JSON anchor, config,
registered executable and duplicate alias bytes, plus reference/byte-work cap
checks. The positive case still proves deterministic byte-preserving packaging
using inert synthetic executable bytes, with the qualified base digest unchanged.
