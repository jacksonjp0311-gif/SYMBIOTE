# Build, run and recover

Rust stable and Cargo are sufficient for the native process. Python 3.11+ is
needed only for developer reference parity and complete reproduction. Cargo.lock
pins dependencies. The workspace uses serde/serde_json for data and sha2 for
integrity/authentication; it has no agent framework, HTTP stack or LLM SDK.

```powershell
.\SYMBIOTE-All-One.ps1 -Build
.\SYMBIOTE-All-One.ps1 -Run -State state/demo
.\SYMBIOTE-All-One.ps1 -Test
.\SYMBIOTE-All-One.ps1 -Verify -Python C:\Path\To\python.exe
.\SYMBIOTE-All-One.ps1 -Benchmark
.\SYMBIOTE-All-One.ps1 -GitStatus
```

Switches are independent and may be combined. The script uses independent `if`
statements, runs synchronously without Start-Process, preserves UTF-8, prints Git
output and returns to its repository root even on failure. `-Verify` reproduces
format, strict Clippy, all native tests, Python/Rust parity, separate-process
restart/control experiments and compact receipts. It overwrites generated
SYMBIOTE reproduction receipts, never historical upstream research.

Portable native commands:

```text
cargo build --workspace --locked
cargo test --workspace --locked
cargo run --locked -p symbiote-runtime --bin symbiote -- demo --state state/demo
cargo run --locked -p symbiote-runtime --bin symbiote -- predict --state state/demo
cargo run --locked -p symbiote-runtime --bin symbiote -- verify-memory --state state/demo
python tools/verify.py
```

`demo` learns on the first run, and reuses/rechecks the same two models on a second
run. It writes `experiments/local/demo.json` by default. `predict` loads tables and
identity offline. A four-element prediction array is indexed by input codes 0–3.
`benchmark` runs the same controlled experiment; use a fresh `--state DIR` for a
fresh comparison. The PowerShell benchmark switch always creates a fresh path.

Deliberate failures for investigation:

```text
cargo run --locked -p symbiote-runtime --bin symbiote -- demo --state state/reject --fault wrong-artifact
cargo run --locked -p symbiote-runtime --bin symbiote -- demo --state state/demo --fault drift
cargo run --locked -p symbiote-runtime --bin symbiote -- revoke --state state/demo --artifact alpha-table
```

Each failure exits nonzero and displays the cause. Wrong transferred knowledge
does not consume its revision; a later valid candidate can be accepted. Drift or
operator rollback revokes a previously valid revision permanently. A subsequent
demo requests an offer newer than the highest previously accepted revision. The
simulated partner issues that new version, which must pass full evaluation again;
recovery retains identity and the entire revocation history. A real adapter must
likewise obtain a newer version from its partner. Use a fresh state directory for
a separate clean experiment. Do not erase the existing ledger as a repair.

The single-writer lock is `<state>/writer.lock`. If a process terminates abruptly,
the next run fails with an explicit stale-lock message. First establish that the
writer process has exited, preserve its ledger, then remove exactly that lock file
before retrying. Corrupt, oversized or truncated ledgers are rejected; restore a
trusted backup or investigate the original, never silently start empty.

Endpoints are simulated, explicitly authorized local services whose secrets stay
in process memory; no third-party agent is contacted. The v0.1 transport provides
local authentication and capability boundaries, not TLS or confidentiality. See
[protocol](PROTOCOL.md) before adding a transport or external adapter.
