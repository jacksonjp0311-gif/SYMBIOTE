# Retained BRUTE reference

`brute/symbolic.py` is a byte-for-byte copy of `bgr90/symbolic.py` at
BRUTE commit `9edbc035792ca75d3a3333b8454e5bf31c706eb1` (release identity
v0.11.0). Its SHA-256 is
`878a0ee803dec0e5095b561b3110a1c8bc99f6c664f853b137e19fad0cde92eb`.
Original authorship and comments remain intact. The pinned upstream tree has
no LICENSE/COPYING/NOTICE file; no inherited license has been invented.

The Rust port in `crates/symbiote-reasoning` preserves the exact conditional
prefix version space, emission masks, support unions, contradiction handling,
row-budget abstention, retained evidence, and explicit reconstruction.
It adds typed input validation and deterministic set traversal. Python's
arbitrary set iteration and Rust's ordered set can examine a different number
of duplicate successors before a row-budget interruption; that diagnostic
counter is excluded from parity at interruption. Neither implementation uses a
partial result after exhaustion.

From the repository root, run `python tools/parity.py`. Python 3.10 or newer
and Cargo are needed for this development check. The script executes the
unchanged Python source and native Rust on the same JSON fixtures, all 5,832
two-step masked traces at state bounds one and two, and 256 deterministic
longer traces with reconstruction. An independent enumeration of every labelled
complete machine at bounds one and two also checks the exhaustive traces.

The native executable accepts a fixture JSON filename or JSON on stdin:

```powershell
cargo run --locked -p symbiote-reasoning --bin reasoning-fixture -- tests/fixtures/reasoning.json
```

Only this bounded support engine is ported. BRUTE's newer SAT regions, margin
guards, Y1k resynchronization, alarm thresholds, and SP8 certification policy
remain pinned upstream research. A singleton support means every surviving
model in the supplied stationary finite family agrees. It does not prove
arbitrary agents or changing environments obey that family.
