# SYMBIOTE local stability campaign 001

Protocol identifier: `SYMBIOTE-LOCAL-STABILITY-001`.

This is a finite, once-only **local software regression and bounded continuity
campaign** on this PC. It combines named regression repeats with one explicitly
selected 24-cycle mixed-family TLS check. It is neither a long-term endurance
qualification nor a new scientific experiment. The independent second-host gate
stays **OPEN_UNAVAILABLE**. Same-host private-IP TLS
does not establish two-host operation, and a local PASS cannot qualify stable
v1.0 by itself.

## Preconditions and frozen identity

Finish the restore-activation, policy-capacity and destination-collision repairs
and their full gates before execution. Perform a fresh actual Cargo build of the
native CLI and the `cli` and `service` integration-test executables from the same
candidate, with the native source stamp set to the selected full source commit.
This runner does not download, install, compile or silently replace executables.
The test executables must be in the candidate profile's `deps` directory; their
compiled native CLI path must refer to the same sibling candidate binary. The
directory layout is a location precondition, not authentication of an embedded
`CARGO_BIN_EXE_symbiote` path. Fresh building is a prerequisite; file hashes alone
are not build attestation. The continuity producer also hashes the native binary
at its compiled path and binds it to the registered native hash.

Registration first preflights `version --json` and both test executables'
`--list --format terse`. These three noncampaign process launches establish the
actual native output and that every selected exact test exists, including the
explicitly ignored continuity test. Require the native name `SYMBIOTE`, version
`0.5.1` and `build_source_commit` equal to the required `--source-commit` value.
Registration then binds the actual binary/test SHA256s, all native Rust/Cargo
source and tools
file hashes, this protocol's exact bytes, fixed acceptance checks and budgets.
The actual source-tree fingerprint covers uncommitted source too; it is not
falsely presented as an older Git commit or reproducible-build attestation.

Retain the registration digest separately. `run` verifies that digest and every
source/executable pin, then creates `campaign-started.json` exclusively. An
existing marker prevents an automatic repeat. Every process, output and final
failure remains recorded. A correction requires a separately reviewed candidate
and new registration, never overwriting or regrading this run.

Registration requires an absent artifact directory under the canonical OS
temporary directory, outside the checkout, with an existing parent. It rejects
another location before creating the artifact directory or its metadata. The
continuity subdirectory must also be absent, even if an existing directory would
be empty. Do not use source, installation or existing owner directories as output.

## Bounds

| Resource | Frozen limit |
|---|---:|
| Campaign execution, including final verification | 600 seconds |
| Ordinary root command | 30 seconds |
| Native four-bit process prototype | 45 seconds |
| One ignored 24-cycle continuity command | 180 seconds within the campaign deadline |
| Aggregate cleanup for each owned command tree | 10 seconds; cleanup overrun is HOLD |
| Root process launches | 96 |
| Separate registration preflight launches | 3 |
| Captured stdout + stderr per process | 2 MiB total; excess terminates the tree and records truncation/HOLD |
| Campaign evidence | 64 MiB |
| Final campaign report reserve within that evidence budget | 1 MiB |
| Windows processes per owned Job Object | 8 |
| Windows aggregate job memory | 256 MiB |

Budgets have no command-line overrides or automatic retries. The single planned
idempotency retry below is a test action, not permission to repeat a failed run.
Actual monotonic elapsed time is reported; OS descheduling is not hidden by
clamping measurements. The
controlled source is not a hostile-process sandbox. Windows launches suspended,
assigns an owned kill-on-close Job Object before resuming the primary thread,
and checks tree cleanup. POSIX uses a separate owned session/process group.
Timeout and cancellation terminate only that owned tree. Abrupt host power loss
and SIGKILL of the POSIX runner are not certified cleanup mechanisms.

Before another command, reserve its full captured-output allowance and the final
report reserve. State snapshots must also leave the final reserve available.
Immediately before PASS, recheck cancellation, the actual 600-second deadline,
evidence size and the encoded final report size. A late cancellation or deadline
overrun cannot become PASS because commands finished earlier. The final report
must fit within 1 MiB and the full evidence plus that report within 64 MiB.

## Manual CLI acceptance

1. Run the four-input `demo` on fresh state. Require exactly two promotions.
   Offline `predict` must retain the same identity and both complete tables with
   zero network requests. A second demo process must reuse both, promote none,
   and leave the complete identity ledger byte-identical.
2. On a separate fresh state, `--fault wrong-artifact` must exit 1 with a retained
   REJECTED receipt and no active artifact. A later correct demo retains that
   identity and promotes both first valid revisions.
3. `--fault drift` on the first state must reject and durably revoke alpha.
   Offline coverage becomes one model. Correct recovery retains identity,
   recovers alpha as revision 2, preserves beta revision 1, and keeps every
   previous receipt as an exact prefix. These are recovery checks, not evidence
   of generalized autonomous self-repair.
4. Use actual `backup-state`, `verify-backup` and `restore-state` commands with
   the separately retained manifest SHA. Require the same owner, exact historical
   bytes and equal actual offline predictions. Restore must report no network
   activation. Occupied-target and deliberately altered-archive commands must
   exit 1 and leave source/restored learning unchanged.
5. Run one clean `network-research` on its fixed manual four-bit affine prototype.
   Require separate native identities/process instances, forged/cross-domain/
   repeated-observation rejection, nonempty retained models, and zero additional
   observe/verify/assess calls on actual restart. Each of startup timeout,
   crash-after-ready and crash-after-promotion runs once on separate owned state.
   Startup must report the child-readiness deadline and actual exact-child
   identity/knowledge genesis, without a fabricated linear child. Crash after
   readiness must leave both distinct child genesis states and no promotion;
   post-promotion crash must leave exactly one committed four-bit model in the
   exact child and none in the linear child, alongside a native transport-stage
   error. Any other exit-1 cause is HOLD. Inspect and recover only proven-dead
   owned locks, preserving identity and knowledge bytes. After the committed
   crash, query the actual nonempty offline model, run one explicit normal
   recovery on that same state, and require reuse, no duplicate promotion, and
   identical predictions. This recovery is separate from the one clean baseline.

Manual state and receipt files stay under the artifact root. Snapshot the state
before faults, after rejected transfer, after drift before recovery, after restore,
and after each native fault before stale-lock recovery. No failed state is erased
as a repair. There are no `research`, `graph-research`, `adaptive-research`,
adaptive-004 or S2 cohort calls.

## Exact named native regressions

Each row executes exactly one prebuilt integration test with `--exact` and
`--test-threads=1`. Zero executed tests is HOLD. These are explicitly labelled
`REGRESSION_REPEAT`, not independent scientific samples or endurance iterations.

| Executable | Exact case | Checked behavior |
|---|---|---|
| cli | `retained_structural_models_are_read_and_used_without_ledger_mutation` | Actual finite affine prediction command and immutable retained model |
| cli | `native_backup_cli_restores_identity_bytes_and_offline_predictions_without_activation` | Native backup/restore and actual offline predictions |
| cli | `native_backup_cli_rejects_live_writer_tampered_manifest_occupied_target_and_registry_pin` | Negative backup boundaries |
| service | `configured_private_ip_service_quarantines_then_locally_evaluates_native_affine_and_graph` | Two manual typed domains, pinned local truth, real retained TLS graph prediction after restart |
| service | `lost_reply_and_actual_service_crash_preserve_one_idempotent_quarantine_receipt` | Real killed-service crash and lost reply, one durable quarantine |
| service | `evaluation_intent_recovery_commits_once_and_retains_original_lost_ack_result` | Deterministic before/after learning-commit cutpoints; publication hooks are modeled interruptions, not additional killed-service events |
| service | `offline_rotation_after_lost_private_key_preserves_identity_and_rejects_old_tls_pin` | Explicit rotation, stable identity and old-pin rejection |
| service | `rotation_retains_denial_and_reviewed_regrant_never_resurrects_old_candidates` | Denial retention, reviewed regrant and terminal old candidates |
| service | `reviewed_verified_restore_relocation_uses_only_destination_when_source_and_old_key_are_gone` | Source-free, explicitly reviewed relocation |
| service | `restored_relative_manifest_requires_review_for_each_restore_even_when_policy_digest_is_unchanged` | Relative-manifest activation bypass and each new restore review |
| service | `moved_unreviewed_restore_cannot_activate_under_original_config_or_consume_foreign_destination` | Moved restore cannot evade approval by returning to the old basename |
| service | `consumed_restore_metadata_cannot_be_deleted_or_rehashed_into_different_paths` | Consumed mapping must remain exact and present |
| service | `nested_unactivated_restores_hold_without_implicitly_approving_ancestor_mappings` | Nested unreviewed restores remain HOLD |
| service | `unregistered_restored_owner_cannot_initialize_service_history_before_review` | Restore cannot bypass approval by initializing a new journal |
| service | `maximum_service_manifest_rotates_maximum_public_snapshots_then_narrows_without_rewriting_history` | Maximum accepted policy remains transitionable without lost history |
| service | `operator_peer_ids_win_alias_collisions_without_changing_authenticated_artifact_grants` | Admin ID/alias collisions preserve actual authenticated grants |

The service fixtures bind only explicitly owned addresses on this same host,
including the available private interface. They do not attach to external agents.
Their original test harnesses own and may remove their temporary private fixtures;
the campaign preserves their exact process stdout/stderr and exit receipts, not
those already-removed directories. Manual CLI state has the stronger retained
artifact coverage described above. No private keys are copied into public
campaign logs by the runner.

## Fixed 24-cycle local TLS continuity check

Execute exactly one additional prebuilt `service` test:

```text
endurance::mixed_family_24_cycle_local_campaign --ignored --exact --test-threads=1
```

Require exactly one test executed and passed. Normal test discovery does not
execute this ignored case. The runner sets `SYMBIOTE_ENDURANCE_ARTIFACTS` to its
fresh absolute `endurance/` subdirectory and applies the 180-second outer command
limit within the remaining 600-second campaign budget. No cycle, budget or
fault count is selected from results. The fixed affine and three-node graph
fixtures are manual software cases, not new adaptive cohorts or research samples.

### Fixed schedule and acceptance

1. Bootstrap one actual native loopback TLS listener. Two authenticated
   `candidate.submit` requests enter quarantine. Stop the listener, evaluate both
   against the pinned local fixtures, and require exactly two promotions: the
   complete three-bit affine model and complete three-node graph model. Retain
   their exact knowledge bytes and two distinct model digests.
2. Execute exactly 24 sequential cycles. Every cycle starts a new owned native
   listener and performs four fresh authenticated requests: affine read, affine
   predict, graph read and graph predict. Require the actual ready PID to match
   the owned child. PID reuse between different cycles is permitted; one PID
   cannot identify two concurrently owned listeners. Check the exact fixture
   predictions, conditional-certificate limits and retained model digests.
   Stop each listener and verify stable owner identity, unchanged knowledge
   bytes and exact chronological prefixes of both operational journals.
3. After cycles **4, 8, 16 and 20**, explicitly transition the server policy and
   client pin/DNS policy between two preprovisioned server leaf certificates.
   Reuse those two leaves; the client retains its own separate leaf. Require
   each old server pin to fail before application mutation on the next cycle.
   This is reviewed rotation, not automatic issuance or renewal.
4. After cycles **6 and 18**, durably deny the sole authorized client, then run
   the denied listener probe. Require the actual runtime receipt
   `symbiote.service-stop/1`, status `STOPPED`, reason `no-authorized-peers`,
   `listener_opened:false`, requests 0 and connections 0. Generic exit success is
   insufficient. Explicitly regrant exactly that peer and retain both receipts.
5. During cycle **10**, send one additional inert affine `candidate.submit` with
   a fresh request key. An authorized TLS proxy must first obtain and preserve
   the genuine committed **QUARANTINED** response, then withhold that reply past
   the client deadline. Require the client error and exactly one durable
   quarantine. Kill and positively wait only the owned live listener, run
   explicit stale-lock recovery, restart, and retry the **exact same request**.
   Require its exact original response and unchanged journal bytes across
   recovery/retry. Leave this third candidate unevaluated: a quarantined receipt
   is not learning and must not produce a third model.
6. After cycle **12**, with the listener stopped, run actual owner backup,
   externally pinned backup verification and restore into a new owner directory.
   Rename the original server state out of its configured source location.
   Unreviewed activation must fail because restore review is required. Perform
   one explicit reviewed relocation using only the destination. It must reject
   the pending cycle-10 candidate exactly once without promotion. Continue
   cycles 13–24 on the restored owner, retaining both original models and all
   preceding history. The client owner persists throughout.

The exact totals are **99 unique `(scope, request_id)` wire keys**: 96 read or
predict requests and three submissions. The planned duplicate makes **100 client
attempts**. Only the three submission keys have durable candidate receipts;
read/predict responses are not claimed to be durable cached replies. There are
**26 actual native ready instances**: bootstrap, 24 cycle starts and one cycle-10
replacement. Require **25 graceful stops and one owned kill-and-wait**, with no
listener left active. The two denied startup probes open no listener and do not
count as ready instances. Retain exactly **two owner identities and two models**
through all checks. Repeated service processes do not add agents or discoveries.

### Evidence and independent checking

The native producer writes `endurance-report.json` with schema
`symbiote.local-endurance/1`, and ordered `events.jsonl`. The enclosing runner
writes `campaign-report.json` with schema `symbiote.local-stability/1` and a
`local_continuity` result. Require the native report's `cycles_expected` and
`cycles_completed` to equal 24, `request_keys_expected` and
`request_keys_recorded` to equal 99, `service_starts_expected`, `service_starts`
and `owned_stops` to equal 26, and `models_retained` to equal 2. Both actual
`native_binary_sha256` and `test_binary_sha256` must match registration. Status
must be PASS and `first_failure` null; the producer's booleans alone are not
acceptance evidence.

Independently bind command-output file hashes to their parsed native receipts,
then bind the actual wire requests, TLS responses and those receipts to the
cycle/report values. Verify `events_sha256`, contiguous event sequence numbers,
monotonic elapsed timestamps, exact owner genesis and knowledge hash chains,
operational history, the single quarantine/retry and its real killed-child
event, the actual midpoint backup/restore/review commands, and the final
inventory's paths, sizes and hashes. Derive start/stop/kill counts from events;
do not infer them from a test's generic success line or summary constants.

Preserve allowlisted owner-state and backup bytes under `owners/` and
`midpoint-backup/`, plus raw stdout/stderr, event history, public policy
snapshots, public certificates and the two public fixture files. The owner
directories are placed in the evidence tree before service registration so a
hard command timeout can leave inspectable history even if no complete native
report is produced. Preserve failures rather than restoring an earlier snapshot
or deleting a failed owner. Private test PKI stays outside the evidence tree.
Do not copy private-key material, `.key`, `.pfx` or `.p12` files, follow links or
silently omit owner/backup files from the reported inventory. The runner checks
the preserved tree for credential material. Evidence may contain public
certificates and owner IDs; that does not authorize network activation.

A failure, timeout or incomplete report remains HOLD, even if earlier cycles
passed. This check establishes only finite same-PC continuity through these
specific transitions. It does not qualify long-term reliability, unattended
certificate renewal, multi-host operation, unfamiliar-domain generalization or
stable v1.0. The 24 cycles are endurance observations, not independent scientific
samples; named tests above retain the separate `REGRESSION_REPEAT` label.

## Result interpretation

PASS requires every positive assertion, each expected negative exit, exact
registered regression execution, all 24 continuity cycles and their raw evidence
checks, process-tree cleanup, unchanged source and executable hashes, complete
receipts and all budgets, including final cancellation/deadline checks. Any
unexpected failure,
timeout, cancellation, missing evidence or mutation is HOLD with no automatic
retry. The host count remains one even when many processes or private IPs appear.
The second-host and longer endurance gates remain open after a local PASS.

```text
python tools/stability_campaign.py register --binary target/debug/symbiote.exe --cli-tests target/debug/deps/cli-EXACT_HASH.exe --service-tests target/debug/deps/service-EXACT_HASH.exe --source-commit FROZEN_FULL_SOURCE_COMMIT --artifacts ABSOLUTE_NEW_OS_TEMP_DIRECTORY
python tools/stability_campaign.py run --registration ABSOLUTE_NEW_OS_TEMP_DIRECTORY/campaign-registration.json --registration-sha256 SEPARATELY_RETAINED_SHA256
```

Use the actual platform executable names from the completed build. Do not guess
or silently choose a newer test binary. Keep all failed and successful campaign
directories as separate evidence.
