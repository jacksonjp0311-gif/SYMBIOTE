# Supervised native agent processes

The v0.3 development command `symbiote network-research` exercises two separately
running native agents. The earlier `research` experiment remains available with
its original in-process implementation and scientific assumptions.

```text
symbiote network-research --state state/network-demo
symbiote status --state state/network-demo/network/exact
symbiote predict --state state/network-demo/network/linear
symbiote inspect-state --state state/network-demo/network/exact
```

The controller starts the current executable in a restricted internal partner
mode. This experiment uses the explicit `symbiote/1` loopback protocol. The
separate [TLS API](SECURITY.md) is available for configured library integrations;
these deployment results do not assert that the process experiment uses TLS.
One process uses the exact enumerated affine learner and the other uses the
independently implemented Gaussian-elimination learner. Each has a distinct,
durable identity and its own two learning ledgers. The controller's identity is
separate from both children. Private here means separate operational state and
API access; it is not a sandbox against a malicious process with the same host
account's filesystem permissions.

Child configuration travels through bounded stdin, never command arguments or
environment variables. It includes explicit capability grants, allowed task
contexts, a state directory and a maximum lifetime. Tokens use the protocol's OS
cryptographic random provider. Readiness stdout contains only bounded endpoint,
PID, identity and model-count metadata. Configuration and capabilities are never
printed in diagnostics. Only the current executable can be launched; no received
instruction, artifact or role can supply a command to execute.

The controller holds the hidden world implementations and independent truth-table
judge. Children receive neither true coefficients nor a shared authority registry.
They obtain actual observations and verify transferred receipts through pinned,
authenticated local oracle APIs. A received bundle is replayed into the complete
declared hypothesis family. A distinct judge checks the disjoint unseen inputs
before each child promotes a model into its own ledger.

The command terminates both native agents, launches two new native processes,
and checks that private identities and predictions survive. A fresh public
instance nonce identifies each start independently of possible OS PID reuse.
Controller and concurrent child identities must be distinct; copied valid
identity ledgers are rejected without reset or learning. The restarted agents
predict from their persistent models without new observations, adoption or
promotion requests. Existing knowledge is reported as retained rather than new
learning. Actual oracle-operation counters must remain unchanged across restart
and retained prediction, rather than assuming zero new acquisition. The prototype
uses one four-bit affine context and makes no new paired
cost, general transfer or autonomous self-improvement claim.

## Failure and recovery

Startup writes/readiness, pipe frames, logs, RPC deadlines, total child lifetime
and shutdown are bounded. Normal shutdown uses an enum command on owner stdin.
Owner-pipe EOF is reported as a cancellation. A child that misses its stop
deadline is killed only through its owned process handle and then joined. Child
watchdogs also bound startup and lifetime if the controller disappears.
These are supervised bounds under normally functioning OS process and pipe APIs,
not hard real-time guarantees under kernel failure.

Abrupt termination preserves committed ledger bytes and deliberately leaves
writer locks. It does not silently reset state or delete unknown locks.

```text
symbiote network-research --state state/fault-demo --fault crash-after-promotion
symbiote inspect-state --state state/fault-demo/network/exact
symbiote recover --state state/fault-demo/network/exact
symbiote network-research --state state/fault-demo
```

`recover` uses the native process-liveness check and shared maintenance gate. It
refuses live, unknown or malformed ownership, removes only verified-dead locks,
records the operation and preserves all learning ledger bytes. An interrupted
maintenance gate remains HOLD for investigation. For an incomplete startup, use
the same recovery command on the affected child directory. Other explicit
laboratory faults are `startup-timeout` and `crash-after-ready`.

Focused integration tests execute real process separation, authentic receipt
rejection, restart retention, owner cancellation, deadline failure, pre/post-commit
crashes and explicit recovery. Tests do not count process completion as a reward
sample or claim that deployment alone demonstrates reciprocal efficiency.
