# Corrective release 1.0.1

Status: **under qualification**. Source changes, a passing software suite,
one-host continuity and public binary delivery are separate checks. This account
will record their exact source and executable pins when qualification finishes.
The public 1.0.0 tag and its original evidence remain unchanged.

## Correctness and compatibility

The old zero-argument benefit and durability predicates and two-receipt mutual
predicate retain their Rust signatures, are deprecated and return false. Their
inputs cannot establish ledger evidence. Positive verification uses the exact
receiver store, promotion witness and current active record. Revoked or
superseded records cannot verify current benefit. Sender identity must equal
the stored source; duplicate scope/payload sets cannot imply changed capability.

`attributed_benefit` also retains its old signature and fails closed. Use
`bound_attributed_benefit` for an exact causal claim. A feedback chain binds:

**decision → exact artifact → evaluation → promotion → later use → outcome**

The chain carries an exchange ID, both identities, candidate/request digests,
context/schema/policy/fixture versions, knowledge anchors and stored evaluation
evidence. A historical valid receipt cannot be substituted into another exchange.
An outcome closes once; later calls or restarts do not award a second credit.
Current validity and historical events are distinct: revocation preserves the
audit trail rather than rewriting old choices.

The legacy receipt verifies its stored assessment costs. A separate
`bound_scoped_benefit` verifies the finite task-window outcome from the exact
binding and independently selected measurement digest. These claims are not
interchangeable: an unknown legacy baseline remains unknown even when the
separate operational measurement establishes a scoped improvement.

New observation, compact-reasoner and bound-feedback interfaces are additive.
Receipt schema `symbiote.reciprocal-evaluation/2` is unchanged. New typed feedback
records are stored in the existing operational journal; older executables cannot
read an unfamiliar record safely. Stop the owner and make a verified backup
before upgrading. Never delete rows to force a downgrade. See [Rust API](RUST_API.md)
and [compatibility](COMPATIBILITY.md).

## Evidence-conditioned feedback

Baselines have three explicit forms: **measured**, **estimate/bound** and
**unknown**. An unavailable baseline is never silently replaced with zero. New
partial-graph evaluation records include an actual isolated learner control and
actual candidate lookup, validation and adoption work under a versioned declared
cost model. Producing that control is itself charged to the engineering run.

For local feedback, an opaque execution witness is captured before SENSE and
closed after actual retained-model use. The operational task window includes
the observed acquisition bytes, inference/validation, adoption and replay/use
work. Its evidence must match the original single-artifact request. Later
feedback closure and separately executed controls/audits remain in whole-process
accounting and are explicitly outside that finite task window. A positive scoped
net is not a claim of lifetime, wall-clock or complete research-campaign profit.
Missing components leave the relevant measurement unknown.
The counter token binds the owner, exact preceding journal prefix and immediately
following SENSE decision. Capturing counters later cannot omit earlier work
while claiming the same task-window boundary.

Each participant owns its evidence and cost estimates. Authorization is not a
measurement of a partner's economics. The legacy outbound helper no longer
copies local terms into a purported remote value. A recipient validates and
records its own result; absence of a receiver-originated witness stays absence
of verified partner benefit.

Stored outcomes influence the next source choice. Harmful outcomes create a
bounded exploration penalty rather than permanently banning a collaborator;
favorable outcomes can prefer a useful source. Both histories survive replay.
The exact model must have been used and its prediction checked before it can
complete a capability or cost outcome.

## A useful, bounded return path

The old full-fixture affine and graph transfers still fail their economic gate.
The new opportunity uses partial graph knowledge: a source discovers training
routes; a recipient checks only transferred observed edges against its own
authorized source and verifies a fresh route certificate. Unknown edges retain
their declared intervals. The lower-bound proof is unchanged. An additive exact
fallback accepts an observed route only when its cost equals the global optimistic
lower bound; its additional search work is counted.

The frozen adaptive reproduction explicitly calls
`RouteLearner::assess_optimistic_reference`, preserving its original one-search
method, sound abstentions and `nodes * edges` assessment reservation. Ordinary
`assess` keeps the additional witness search and its separately counted work.
No historical cohort quotas, cost units, consumer rules or evidence are changed.

An operator may opt into `capability_contributions` in the normal cognition
policy. Both peers' grants and all existing budgets still apply. A pinned public
task contract specifies a fresh prediction that the recipient's compatible
knowledge union cannot yet certify. This is a capability objective, not an
invented positive economic estimate. The normal engine selects the opportunity;
the receiver retains independent evaluation and adoption authority. A receiver's
inventory is classified as equivalent, complementary, superseding, incompatible
or unknown using schema and payload semantics, not merely a nonempty list.

The preregistered [64-cell engineering protocol](RECIPROCAL_ENGINEERING_PROTOCOL_001.md)
is separate from the normal-policy acceptance fixture and from research Protocol
002. It counts source discovery, transfer, validation, adoption, replay and fresh
prediction, all fixed branch-order controls, equal-query controls and matched-total
resource controls. Its related finite cases are not independent scientific
samples. Negative and control-explained results must be retained.
Protocol 002 remains **NOT_RUN** and requires its declared amendment before
opening targets; none of these engineering checks regrade it.

## Learning from observations

`service::observation::ObservationSource` supplies an explicitly authorized,
bounded observation interface. The engine chooses useful queries, updates exact
hypotheses, rejects contradictions, checks held-out inputs and retains a conditional
model. The configured `symbiote.local-truth/3` backend keeps the operator's truth behind
that interface. Suggestions are not observations. The old complete-fixture
evaluator remains available as a distinct controlled backend.

Run the same engine without TLS setup:

```sh
symbiote observe-demo --state state/observation
symbiote observe-demo --state state/observation
```

The first invocation uses an explicit deterministic three-bit affine source and
stores its observation audit and model. The next invocation replays the model
and answers without consulting that source. This establishes a small persistent
capability within a declared family, not discovery of arbitrary agent behavior.
Configured native tests also cover widths 3 and 8, query exhaustion, cancellation
and rejected evidence. A complete operator fixture is not passed to the learner.

## Exact reasoning and repeated-work limits

The new `CompactAffineLearner` maintains incremental row-reduced equations over
GF(2). With width `w`, consistent rank `r` leaves exactly `2^(w+1-r)` hypotheses.
Support, predictions, contradictions, hints and query tie-breaking are checked
against the preserved enumerator. Width remains 1–8. New row checks, XORs,
insertions and query operations have a separate versioned counter model; they
are not relabeled enumerated model evaluations.

Proposal history is durable and keyed by artifact, recipient context, evaluator
source fingerprint and policy. A rejected source evaluation is reconsidered when
its local knowledge anchor changes or its bounded exploration expiry is reached.
Declined proposals also have bounded expiry. A previously promoted model that was
explicitly revoked or superseded is suppressed until the artifact, evaluator or
policy changes; an unchanged source cannot silently reinstate it. A retained exact model
can be reused without another knowledge read/evaluation. The journal remains
authoritative; rebuilt indexes accelerate lookup without discarding evidence.

## Timing and delivery

Stage diagnostics distinguish computation, lock waiting, I/O, model evaluation,
state replay and shutdown. Some stages overlap and their durations must not be
summed into a task cost. Diagnostics are not placed in a repeated prepared
response whose exact bytes must remain stable.

The historical 37-minute topology invocation overlapped lid-triggered Windows
Modern Standby. Its evidence is [preserved](../experiments/v1.0.0/timing-topology-modern-standby.json).
The earlier Windows CI connection timeout has no established phase/root cause
in its old log. New transport diagnostics distinguish connection, TLS,
negotiation and response phases without changing retry or timeout policy. A later
pass does not regrade either incident.

The new hour wrapper temporarily inhibits idle sleep and detects host suspension;
an explicit lid/suspend event holds the campaign. It changes no global power or
display policy. Source, protocols and executables are pinned before targets open;
qualification cannot resume or replace a failed run silently.

Release evidence must include the sanitized raw records, independent consumers,
exact source/executable manifests and preserved failures. New native releases
stage as drafts. Installed `version --json` and `doctor` report the exact build
source and the external qualification requirement; local health is not an online
release-verification claim. The actual replacement Windows executable must pass
the regressions and normal learning fixtures after anonymous public download.

Independent two-host validation, cross-OS restoration, host power-loss durability,
arbitrary external observation sources and general reciprocal efficiency remain
outside this PC's qualification envelope.
