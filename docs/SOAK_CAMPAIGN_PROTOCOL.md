# SYMBIOTE bounded local soak 001

Protocol: `SYMBIOTE-LOCAL-SOAK-001`. This is a new local software qualification;
it does not change the earlier S5 continuity protocol, producer or evidence.
One PC is authorized. Independent two-host validation remains **OPEN_UNAVAILABLE**.
An hour on this PC does not establish production reliability or new intelligence.

## Frozen acceptance and timing

The qualifying native case is `soak::hour_120_cycle_local_soak`, explicitly
ignored during ordinary tests. First bootstrap two evaluated models and two
owner identities, then start the first main TLS listener. Its observed readiness
anchors the measurement clock. Execute exactly 120 four-request cycles at
monotonic due times **30, 60, ... 3,600 seconds**. Each cycle reads and predicts
the same retained three-bit affine and three-node graph models using the actual
native TLS client. Preserve every actual request, reply and command output.

Require final measurement elapsed time at least 3,600 seconds. A slot may begin
at its due time through at most five seconds late. A missed slot is HOLD; no
skipping, compressed catch-up, automatic retry or budget increase is allowed.
The listener stays alive between requests and slots. Poll the owned child while
waiting, normally every 100 ms; report actual gaps, with a five-second maximum.
Write positive `listener-alive` events at least once per second while waiting,
including each slot's first and final checks. The consumer derives observed
idle gaps from these ordered events and actual request boundaries; finer poll
counts are diagnostics, not independent availability proof.
Unexpected exit is HOLD. Report observed ready-to-positive-wait spans and
maintenance gaps; require at least 3,540 seconds of main-listener spans and no
planned maintenance gap over 20 seconds. These are native-harness observations,
not an independent host availability measurement.

| Fixed resource | Limit |
|---|---:|
| Entire root native command, including setup and finish | 3,900 seconds |
| Owned process-tree cleanup after cancellation/timeout | 10 seconds |
| Native CLI command/startup/shutdown wait | 5 seconds each |
| Initial setup | 60 seconds |
| Final verification after the last cycle | 60 seconds |
| Core measurement | at least 3,600 seconds |
| Cycle schedule | 120 slots, 30 seconds apart |
| Start lateness / observed idle poll gap | 5 seconds each |
| Planned maintenance gap | 20 seconds |
| Retained artifact bytes | 64 MiB total; native subtree 60 MiB with a 1 MiB receipt reserve |
| Captured native CLI stdout plus stderr | 256 KiB per command |
| Captured root test stdout plus stderr | 2 MiB |
| Windows Job Object | 8 active processes, 256 MiB aggregate job memory |

The 3,900-second envelope is fixed before registration. Remaining time is a
bounded preparation/finish allowance, not permission to shorten the hour or
increase a failed limit. Actual elapsed time is never clamped. Production
service limits are pinned initially: 1,024 requests/connections per listener,
600,000 ms lifetime, 500 ms protocol timeout, and the existing bounded model work.
The planned process segments stay below the lifetime bound.

## Fixed lifecycle schedule

Use only explicitly owned loopback TLS endpoints and the two preprovisioned
server leaves. No external agent, provider or language model is contacted.

| After/during cycle | Action |
|---|---|
| Before measurement | Two authenticated inert submissions, quarantine, offline fixture evaluation, exactly two promotions |
| After 18, 38, 78, 101 | Stop, explicitly rotate server leaf/client policy pin, restart; reject the stale pin without mutation |
| After 30, 90 | Stop, deny the client, prove denied serve returns STOPPED without a listener, explicitly regrant, restart |
| During 50 | Genuinely commit a third inert quarantine, withhold its reply, positively kill/wait the owned listener, recover dead locks, restart and replay the exact request once |
| After 60 | Stop, backup, verify the manifest pin, restore elsewhere, reject unreviewed activation, explicitly review relocation, reject the pending third candidate, restart |
| After the 120th cycle | Stop, verify retained models, identity, complete history and final evidence |

Main listeners persist between cutpoints. Expected totals are **10 ready
instances** including bootstrap and the crash replacement, **nine graceful
stops plus one owned kill-and-wait**, two owner identities, and two retained
models. Denied startup probes create no listener. There are **483 unique wire
keys**, **484 authorized application-request attempts** including one exact duplicate, and only **three
durable submission keys**. Read/predict replies are not represented as durable
idempotency-cache entries. No additional promotion is permitted after bootstrap.
Report the four separate stale-pin TLS negotiation probes and two denied
startup probes separately; they are not application-request attempts.

The third candidate remains inert and unevaluated until relocation rejects it.
Require one quarantine row, the exact original response on retry, unchanged
journal bytes across crash recovery/replay, and the two original model digests.
Backup/restore must preserve historical bytes and owner identity. Source state
and private PKI are not copied into an active service automatically.

## Registration, execution and evidence

Register only a clean committed candidate with the selected commit equal to
HEAD and the native `build_source_commit` stamp. Preflight the native version
and exact service test listing. Pin the protocol, native/test executable SHA256s
and source contents. New source manifests use relative POSIX names in exact
UTF-8 byte order; do not silently normalize case, Unicode or old receipts.
Test executable location is a fresh-Cargo-build prerequisite, not authentication
of its embedded native path; the native producer must also report the actual
embedded executable hash and match registration.

The runner exclusively creates registration and a once-only started marker.
It does not build, download, update or retry. Source/commit/executable pins are
checked before launch, periodically during the hour and after completion. Source
must stay frozen while the registered campaign runs. On cancellation, timeout,
source mutation, missing evidence or unexpected error, terminate only the owned
tree and record HOLD. Windows uses the existing suspended-before-assignment,
kill-on-close Job Object helper; POSIX uses an owned process group. Host power
loss or an uncatchable runner kill is not a certified cleanup mechanism.

For newly registered candidates, the Windows runner holds a thread-scoped idle
sleep request only during its owned command. It changes neither global power
policy nor display behavior and restores the original thread request afterward.
Explicit lid/suspend remains possible and invalidates qualification: compare
sleep-inclusive GetTickCount64 with sleep-exclusive QueryUnbiasedInterruptTime
at startup, source-watch checks and completion; over 1,000 ms divergence is HOLD.
Clock failure/backward movement and failed request release are also HOLD. Retain
the completed owned process receipt even if the final suspension check fails.
This new wrapper rule does not alter or regrade prior registered campaign bytes.

The clock distinction follows the Win32 documentation for
[sleep-inclusive ticks](https://learn.microsoft.com/en-us/windows/win32/sysinfo/windows-time)
and [unbiased interrupt time](https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryunbiasedinterrupttime).
[Thread execution state](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadexecutionstate)
inhibits idle sleep while respecting an explicit user suspension or lid action.

Use a fresh short OS-temp artifact directory. Store owner ledgers, public
fixtures/policies/certificates, bounded outputs and ordered JSONL events there
before activation. Private fixture keys stay outside it. Failures preserve
already-written state and receipts; a hard kill may prevent the native final
report. Do not claim private temporary-key cleanup in that case.

The independent Python consumer must bind every reported request/reply to
preserved raw native output and ordered events, derive the fixed affine truth
and exact graph paths, validate ledger hashes/owners/prefixes and both historical
promotion anchors, count actual lifecycle instances/keys, and verify timing
nonvacuity and artifact inventories. Producer summary booleans alone cannot
qualify PASS. Unexpected negatives and completed prefixes remain HOLD.
The measurement origin must equal the actual `main-initial` readiness event.
Cycle start/finish fields must equal the first request and last reply event
clocks relative to that origin; all four request/output/reply triples must lie
inside their scheduled 30-second interval. Listener spans and maintenance gaps
must equal matching ordered start/positive-stop event deltas in milliseconds.
The consumer sums those deltas, not reported span counters, for the hour gate.
Shifted origins, compressed operation timestamps followed by idle time, and
inflated span summaries remain rejected even when their JSON digests change.
Periodic source checks also recheck Git HEAD and clean committed status.

## Separately labelled engineering fixture

`soak::short_local_soak_fixture` is a separate ignored test using 12 sequential
cycles without a timed hour. Its cutpoints are rotations 2/4/8/10, denial 3/9,
lost reply 5 and relocation 6. It has the same two owners/models and ten ready
instances, but 51 unique keys and 52 attempts. Its outer limit is 180 seconds.
This mode tests implementation and evidence contracts only. Its report must say
`ENGINEERING_FIXTURE_NOT_HOUR_QUALIFICATION`; it cannot satisfy the hour gate.

The qualifying hour has not run merely because unit tests, this short fixture,
or previous S5 regressions pass. Preserve each attempt and its interpretation.
