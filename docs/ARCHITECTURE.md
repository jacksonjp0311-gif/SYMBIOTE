# Intelligence architecture

The v0.4 operational system has four crates. The reasoning crate contains exact
Moore prefix inference, affine version spaces, conservative positive-cost graph
certificates and a participant-specific value-of-symbiosis decision. The protocol
crate supplies sensors, bounded authenticated local sessions and a separately
versioned TLS 1.3 transport. Memory stores private identities, evaluated
declarative models and receiver-originated reciprocal receipts, with provenance,
applicability, rollback and audited lifecycle operations. Runtime composes these
into native learning experiments and offline queries. A hint still cannot shrink
exact affine support. A content digest does not verify benefit. A completed
ledger promotion can, and a declined value plan still blocks it. That gate is
not a reciprocal-efficiency result.

The graph experiment exchanges independently authenticated edge observations,
chooses further observations through exact route reasoning, and promotes only
maps that pass both fixed held-out route queries. A fresh process uses those
stored maps to produce conditional routes or abstain. Its endpoint cohort shares
one controller. The separate affine deployment runs two actual native peers;
an explicit operator manifest can run that experiment over mutual TLS.
These are complementary results, not evidence that every feature has been tested
in every deployment configuration.

An external Rust consumer can embed the reasoning crate directly:

```text
cargo run -p symbiote-reasoning --example native
```

[Example source](../crates/symbiote-reasoning/examples/native.rs),
[graph experiment protocol](RESEARCH_V04_PROTOCOL.md),
[TLS deployment](TLS_DEPLOYMENT.md), and [compatibility](COMPATIBILITY.md).

## Configured service and prospective relationships

The v0.5 development line adds a native knowledge service with an explicit
operator manifest. Each peer has a pinned TLS identity, permitted operations,
contexts and artifact IDs. Received candidates enter durable quarantine; an
offline operator command evaluates them against a pinned local fixture before
promotion. Remote requests cannot supply an evaluator or execute instructions.
Denial survives restart and takes precedence over pending, uncommitted promotion.
An immutable registration binds the service policy to its persistent identity.
See [the service guide](SERVICE.md) for the operational contract and its limits.

A separate adaptive experiment supervises five private learner profiles and an
independent observation/evaluation authority per control arm and price regime.
The learners receive public graph schemas and authorized observations, while the
controller and judge retain evaluation labels. A prospective policy combines its
current exact route frontier with prior verified outcomes to rank useful offers.
An outcome profile is an operational record, not proof of learning. Only native
knowledge records that pass the held-out promotion gate become retained models.

The experiment compares isolation, a fixed authorized partner, uniform selection
and prospective selection under [an immutable protocol](RESEARCH_V05_PROTOCOL_004.md).
The same five logical identities are paired across forty isolated counterfactual
profiles; files, TLS leaf pins, authority epochs and policies remain separate.
Eight distinct authorities and the controller bring the setup to fourteen unique
identities and forty-nine state paths. This is a controlled consent topology,
not autonomous discovery of external systems.

An operational JSONL journal stores decisions before requests, typed outcomes,
idempotent replies, evaluation intents and retained warmup receipts. Its owner
marker detects loss of either journal component. A registered service whose
knowledge ledger disappears fails HOLD. These checks protect the declared
filesystem failure cases; a privileged actor rewriting every file is outside
the integrity guarantee.

The Genesis design below remains the legacy operational slice. v0.2 additionally
provides exact affine reasoning, scoped protocol connections, two distinct native
learning implementations and a schema-bound held-out knowledge ledger. See
[First Symbiosis](RESEARCH_V02.md) for its trust and evaluation boundaries.

SYMBIOTE v0.1.0 is one independent Rust process with two local simulated services.
The services communicate over real authenticated loopback TCP sockets; simulation
does not replace the wire protocol with direct function calls. Discovery is a
configured allowlist, not public network scanning. Server and client independently
prove possession of a configured capability secret and agree on identity, version,
scope, operations, frames and request budget before exchanging telemetry.

## Cognitive representations

**Known observations:** typed, sequence-checked partner telemetry and authorized
probe responses, retained in a bounded FIFO during each cycle. Feedback is data.
The v0.1 demo includes actions, tool use, task identity, success, resource units,
confidence when published, errors/recovery fields and environmental feedback.

**Conditional inference:** the exact Moore-machine version space inherited from
BRUTE. Each observation removes incompatible canonical prefixes. Support is the
union of all remaining completions; a singleton is conditional on the declared
finite stationary family. Contradiction or work-budget failure cannot become a
certificate. The v0.1 fixture's short trace still leaves every next output possible;
the runtime reports that uncertainty. Hypothesis row count is not complete-world
count. This representation models published behavior rather than reading partner
internals.

**Unverified candidate:** a versioned artifact received through `offer`, carrying
identity, provenance, applicability, revision and a four-input prediction table.
Neither source reputation nor agreement on the observed prefix establishes truth.

**Evaluated knowledge:** independent probe responses check every input in the
declared simulator domain. The evaluator binds raw observations, baseline and
candidate digest. A promotion requires complete correctness, zero regression and
strict improvement over the current prediction coverage. The immutable learning
receipt becomes the source of future task predictions, including after restart.

**Derived contribution:** SYMBIOTE searches a fixed five-expression Boolean grammar
for a rule equivalent to the checked table. It can discover XOR, AND, OR, first-bit
or second-bit structure within that grammar. The recipient reconstructs outputs
and independently validates all four inputs before adoption. No arbitrary code or
instruction is transferred or executed. This is bounded abstraction extraction,
not invention of a general solver.

## State and control

The memory crate stores one bounded SHA256-linked JSONL ledger, including genesis
identity, versioned promotion evidence and revocations. It holds an exclusive writer
lock, validates the complete chain on load, and atomically replaces the ledger after
syncing the proposed state. Failed writes do not mutate in-memory learned state.
Identity is persistent and independent from the partner identities. Aliases cannot
manufacture improvement by relabelling an existing source/scope artifact.

Durable reasoning state consists of the verified finite task models and their
evaluation evidence. The transient hidden-state prefix estimator is rebuilt from
fresh telemetry each run; its entire hypothesis population is not checkpointed.
The `predict` command uses only durable evaluated task models. A new demo rechecks
the complete finite domain before using a retained artifact in a relationship.
Drift invalidates the relevant artifact and emits a failure receipt; it cannot
silently repair evidence or reactivate an older revoked revision.

Sensing and hypothesis updates identify uncovered task inputs. That coverage gap
triggers an exchange. Accepted knowledge changes persistent future predictions.
The return strategy lowers the partner's simulated cost of resolving those inputs.
Reassessment uses both descriptive telemetry drift and full finite counterexample
checks; scalar similarity never changes trust or promotion criteria.

## Budgets and failures

The demo caps each server at 32 requests and 16,384 bytes per frame, uses two-second
socket deadlines, keeps eight telemetry records and bounds the exact reasoner at
4,096 prefixes. The ledger caps records at 4,096 and storage at 4 MiB. Trusted Rust
handlers must terminate: socket timeouts cannot preempt native handler code. The
service is sequential and designed for local simulation, not Internet deployment.

Wrong identity, token, scope, sequence, API version, capability, format or resource
proposal is denied. Connections are revocable and cancellation is exposed by the
protocol client. Runtime failures exit nonzero and remain visible. Recovery never
means resetting corrupted state or rewriting history. A privileged attacker with
filesystem access can rewrite a complete hash chain; it is an audit integrity
mechanism, not a signature or remote truth attestation.

The four crates communicate through typed Rust interfaces, not language-model
prompts. New sensors, transports, tasks and evaluators can be added independently,
but each needs explicit authorization and a new applicability contract.
