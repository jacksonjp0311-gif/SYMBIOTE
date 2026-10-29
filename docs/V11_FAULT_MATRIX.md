# v1.1 embedding fault matrix

Status: **focused software gate passed on this Windows host; final-candidate and
other-platform qualification remain separate**. The tests use synthetic three-bit
affine masks 3 and 5. They do not open the registered transfer targets, change a
closed protocol, or contribute scientific samples. The public release remains
subject to [the support contract](V11_ENGINE_SUPPORT_CONTRACT.md).

## Actual owned-process termination

[engine_faults.rs](../crates/symbiote-runtime/tests/engine_faults.rs) uses only the
documented `engine` interface for learning, transfer and recovery. Its host starts
one exact child test executable, checks the child's synchronized marker against
the owned `Child` handle, phase and nonce, then terminates and waits for that
child. It never discovers an arbitrary PID or accepts a supplied PID as authority.
Markers contain exact owner identity, knowledge anchor and hashes/sizes of the
identity, knowledge and operational ledgers.

Each case first proves recovery refuses the still-live writer with `OwnerBusy`.
After confirmed termination, all three committed ledger hashes must remain
unchanged. `Engine::recover_stopped_owner` must remove dead-writer locks without
changing ledgers or terminating a process. Opening must preserve identity and
exact committed knowledge, or return the declared `Hold` below. No test manually
unlinks a writer lock or repairs, deletes or reinitializes a ledger row.

| Synchronized cut | Expected result after dead-writer recovery | Further assertion |
|---|---|---|
| `EpisodeStarted` | `Hold`: unfinished acquisition | All three committed ledgers preserved |
| `CandidateReady` | `Hold`: acquisition lacks completed retention | No invented completion or promotion |
| `Evaluated` | `Hold`: evaluated candidate not retained | No inferred retry or reset |
| `Retained` | Exact committed reopen | Unavailable source; retained reuse makes zero source calls and no new promotion |
| `Prediction` | Exact committed reopen | Same identity, knowledge and conditional answer |
| Local quarantine, before accept | Exact committed reopen | Receiver remains unpromoted, then independently evaluates and promotes once |
| Local actual use, before outcome closure | Exact committed reopen | Use occurred after an earlier reopen; close that recorded use, reconcile once, restart, and reconcile again without a new event or promotion |

The last two cases recover both distinct owners. Outcome economics stay unknown:
the resumed native outcome has actual use, `verified_benefit == false` and no
measured net. Completion is not converted into an efficiency claim.

The focused execution passed seven cuts in 1,487 ms, within a 1.50-second test
execution. All nine dead-owner recoveries preserved committed ledger bytes. The
two other tests in this integration target are the guarded child entry point and
the publication-obstruction regression below. This timing is diagnostic and is
not a performance benchmark. The retained local software receipt is
`symbiote-e4-faults-generic-1/fault-report.json`, SHA-256
`2828b389c210c3e45d17c6dd6b8e5360cffc6eeec76ee3cf650ac6b95b8a4a1b`.
It is a development receipt, not a final source/executable qualification.

The current focused integration target additionally checks actual OS permission
denial and live foreign-history replacement. Its five Windows tests passed;
the Linux ENOSPC test is compiled only on Linux and remains explicitly ignored
unless the isolated host described below supplies the required mount.

## Publication failure and poisoned ownership

`committed_revoke_with_failed_journal_poison_blocks_unrelated_exchange` creates
two retained capabilities, then obstructs operational publication with an actual
directory/file collision. Revocation commits to the separate knowledge ledger;
its operational completion cannot publish. The API returns `Storage` with the
committed anchor and preserves a poisoned owner. After removing only the test's
path obstruction, even an unrelated still-active capability cannot authorize or
prepare another exchange. Both journals remain unchanged by these denied calls.
Close and reopen return `Hold` for the unmatched committed revocation.

This is an actual operating-system publication failure under a controlled path
obstruction. It is **not** an actual full volume, permission-denied filesystem,
power failure or torn hardware write.

`live_foreign_knowledge_replacement_cannot_be_overwritten_by_retention` prepares
and evaluates through the public API, then replaces the live knowledge file with
the exact legitimate genesis bytes of a different controlled engine. Retention
returns typed integrity `Hold` with no committed anchor or in-memory promotion,
preserves the externally replaced file and both other ledgers, and poisons the
owner so close cannot append a misleading completion/failure row. Reopen refuses
the inconsistent owner. Native capacity failures originate as typed capacity
errors; OS storage failures remain separate. These categories are not inferred
from diagnostic strings.

## Existing complementary gates and limits

| Condition | Existing executable gate | Nature of evidence |
|---|---|---|
| Prepared service evaluation before/after committed learning; lost acknowledgment | `evaluation_intent_recovery_commits_once_and_retains_original_lost_ack_result` in [service.rs](../crates/symbiote-runtime/tests/service.rs) | Controlled durable cutpoints in the existing configured-service format; distinct from the new embedding cuts |
| Actual service crash after quarantine | `lost_reply_and_actual_service_crash_preserve_one_idempotent_quarantine_receipt` | Owned native service process termination and idempotent recovery |
| Missing/replaced history | `missing_registered_service_knowledge_is_not_silently_reinitialized`, `surviving_completed_operations_reject_a_valid_older_learning_prefix` | Controlled file replacement/deletion; explicit refusal, no reset |
| Atomic policy batch before/after publication | `policy_publication_cutpoints_reopen_old_or_complete_new_without_partial_settlement` in [operational.rs](../crates/symbiote-memory/src/operational.rs) | Modeled hook failure/panic, not process kill inside the filesystem syscall |
| Prefix cache publication rollback | `rejected_and_prepublication_failed_appends_do_not_publish_prefixes` | Controlled prepublication failure and exact prefix parity |
| Corruption, truncation, oversized history and concurrent writer | `locks_corruption_truncation_and_failed_write_fail_closed` in [knowledge.rs](../crates/symbiote-memory/src/knowledge.rs) | Actual bounded byte/path fault fixtures; native validation refuses them |
| Completed temporary write but failed publication | `failed_publication_counts_completed_temp_writes_without_claiming_commit` | Actual directory/file publication obstruction; committed bytes/capacity do not advance |
| Partially failing writer | `io_diagnostics_leave_failed_partial_write_bytes_unknown_and_saturate` | Injected `Write` implementation; unknown partial bytes remain unknown |
| Capacity and whitespace rewrite | `capacity_keeps_compact_publication_room_in_a_physically_full_history` | Bounded synthetic file at the native byte limit; physical and canonical publication capacity remain distinct |
| Host callback panic, low inference/reuse budget and changed source epoch | [engine.rs](../crates/symbiote-runtime/tests/engine.rs) | Public API unit fixtures; typed failure or preserved `Hold` |

The additional `actual_permission_denial_preserves_committed_engine_history`
test passed on Windows: making only the owned knowledge file read-only produced
an actual OS `PermissionDenied` write-open probe, native typed `Storage` on
retention, unchanged committed ledger hashes, and `Hold` for the unfinished
episode after permissions were restored. Original permissions are restored by a
guard. On Unix the corresponding test denies directory writes with mode 0500;
privileged bypass reports explicit `UNAVAILABLE_PERMISSION_FAULT`, and setting
`SYMBIOTE_REQUIRE_PERMISSION_FAULT=1` makes such a qualification attempt fail.

Actual ENOSPC/full-volume behavior, independent hosts, network filesystems and
power-loss durability are not established by the Windows execution. Existing
native byte/record/frame limits remain in
force; they are not increased to pass these tests. A fixed cold reconstruction
ceiling may refuse a large valid history with `BudgetExhausted`. A `Hold` requires
explicit inspection/repair or restoration of an independently pinned
stopped-owner checkpoint; recovery does not manufacture missing work.

## Run and preserve evidence

Run the ordinary focused software gate:

```text
cargo test -p symbiote-runtime --test engine_faults
cargo clippy -p symbiote-runtime --test engine_faults -- -D warnings
```

To retain raw markers, child output and owner histories, the **test host** may
set `SYMBIOTE_ENGINE_FAULT_ARTIFACTS` to a new absolute output directory before
running the tests. Existing export directories are refused. Failed tests retain
their temporary evidence. The library itself reads no such environment variable.
Child barrier wait is bounded at 12 seconds; owned termination wait and emergency
cleanup attempts each have a three-second bound. Failure to confirm cleanup
cannot produce a passed receipt. Arbitrary in-process Rust callbacks remain
cooperative; the hard stop in this matrix is supplied by the explicit test host.

## Isolated Linux ENOSPC gate

`actual_linux_disk_full_preserves_committed_state` is **ignored by default** and
has not run on this Windows host. A separate qualification host must provide an
empty, dedicated tmpfs mount, with basename `symbiote-enospc-*`, exact mount source
`symbiote-v11-enospc`, Linux tmpfs magic `1021994`, and filesystem capacity at most
one MiB. The test validates mount information and GNU `stat` filesystem geometry;
it never mounts/unmounts anything. Set `SYMBIOTE_ENOSPC_ROOT` to that mount and
optionally `SYMBIOTE_ENOSPC_RECEIPT` to a new absolute JSON file **outside** it.

The test performs ordinary public inference/evaluation first. It writes only its
own `owned-fill.bin`, at a fixed maximum of two MiB, until the OS actually returns
errno 28/`StorageFull`. Retention must return typed `Storage` with no committed
change. It frees only that fill file, preserves all three ledger hashes, drops
the interrupted owner and requires an exact-history `Hold` on reopen. The
external host owns bounded provisioning, receipt collection and unmount cleanup.
An ordinary directory, a larger filesystem, another mount source, a nonempty
mount, or a missing ENOSPC signal cannot qualify this gate. This test is never a
license to fill the user's normal disk.
