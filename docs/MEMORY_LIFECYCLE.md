# Persistent state lifecycle

SYMBIOTE keeps each agent's identity and learning history separate. The Genesis
`ledger.jsonl` and structural `knowledge.jsonl` remain bounded SHA256-linked JSONL
streams. A valid chain detects accidental modification; it is not a signature or
proof that an arbitrary remote agent is honest.

## Ownership and recovery

Both store initialization and maintenance use `maintenance.guard`. A constructor
holds the gate through its cross-ledger identity checks and any first Genesis
commit, then keeps its own `writer.lock` or `knowledge.writer.lock` after that
gate is released. This also prevents concurrent first constructors from creating
the two ledgers with different identities. The same coordination prevents maintenance
from deleting a newly acquired cooperative writer lock between a liveness check
and recovery. Lock removal during normal shutdown checks the exact ownership
bytes before deleting, so it cannot remove a replacement owner's file.

`maintenance::inspect` is read-only. It verifies typed committed ledger snapshots,
identity/layout consistency and the maintenance-audit chain. A corrupt ledger is
an error, not a PASS. Lock state is reported independently; a valid ledger can
still have a live or uncertain writer. Inspection can observe a valid earlier
snapshot while another process atomically commits a new one.

`maintenance::recover` acquires the shared gate and inspects both writer locks
before removing either. It removes only locks whose exact recorded PID has been
proven absent and whose ownership bytes remain unchanged. Any live, malformed,
out-of-range, truncated or uncertain ownership record produces HOLD. PID reuse is
conservative: a different live process with the same PID prevents recovery.

On POSIX, the native check uses `kill(pid, 0)` with a strictly positive PID within
`i32::MAX`; permission failures never establish absence. Windows requests only
SYNCHRONIZE access with `OpenProcess` and performs a zero-timeout wait. The native
calls do not terminate, signal, inspect the memory of, or modify another process.
The only process termination in this crate occurs in tests that retain the handle
of their own explicitly spawned fixture child.

Recovery appends prepared/completed records to `maintenance-audit.jsonl` and never
repairs, truncates or resets a learning ledger. A crash can leave an incomplete
audit operation or private staging file; preserve it for diagnosis. A stale
`maintenance.guard` itself is deliberately not broken automatically. Establish
that all maintenance and writer processes have exited before an operator removes
that exact gate file. There is no recursive cleanup command.

This coordination contract requires cooperative v0.3-or-newer writers. Quiesce
older binaries and manual file tools before maintenance; older releases do not
honor the new gate. Privileged filesystem attackers are outside this model.

## Byte-preserving state-layout migration

`maintenance::migrate` requires quiescent, recovered writer locks. It validates
existing ledgers with the real typed replay validators and adds
`state-layout.json`. Existing v1 JSONL encodings and historical receipt bytes do
not change. This is an additive layout registration, not a claim that the old
receipt data was rewritten into a novel encoding.

The fixed `migration-backup-v1/` directory contains byte-identical source ledgers
and a manifest of their hashes. Its snapshot describes the first registration;
subsequent learning does not overwrite that backup. A matching partial backup can
resume. Different or corrupt backup material, future layout versions, mismatched
identity, missing registered files or a corrupt audit fail explicitly. Repeated
migration validates the registered layout and backup and records that check.

Future incompatible ledger formats must receive their own validated migration;
unknown versions are refused. An unavailable or corrupt ledger never grants
permission to initialize a new identity. Structural-only library stores retain
their own explicit caller-bound identity, but the runtime's normal agent state
also requires its original identity ledger.

## Stationary-context admission policy

New promotions record `policy_version: 2`. Missing policy fields identify legacy
receipts and are omitted when reserialized, preserving their original hashes.
The reader accepts actual v0.1/v0.2 histories with their original admission rules;
new writes must satisfy the stronger policy. Older readers may refuse the new
optional field and must not be used to write an upgraded state.

For an active context, new expected labels must agree with retained accepted
labels. A proposed model must also reproduce all retained validated cases, even
when its latest evaluation uses a different subset. A source cannot hide a
regression by changing evaluation inputs or changing an artifact's name. An
independently detected change of law requires explicit revocation or a newly
authorized context before another version can be promoted. Revocation preserves
old receipts; a later revision requires fresh evaluation.

## Verification boundaries

Focused tests cover real supervised child crashes, both-owner stale recovery,
live-owner refusal, PID boundaries, shared-gate races, partial staging data,
malformed ownership, audit corruption, partial migration resumption, future layout
refusal and byte-identical loading/backups of frozen v0.1/v0.2 receipts. Tests also
cover changed labels and regressions hidden outside the latest evaluation subset.
These are process-crash and local filesystem tests, not a power-loss, privileged
adversary or distributed-lock guarantee.
