# SYMBIOTE prospective frontier exchange protocol

Protocol id: SYMBIOTE-PROSPECTIVE-FRONTIER-004
Status: frozen planning draft, not an executed study or a release criterion already met.
Date: 2026-10-27
Parent release prerequisite: v0.4.0 must be pinned before implementation begins.
Location: operating-system temporary directory; outside the active repository.

The content hash freezes this proposed design. A separate registration receipt must
record the resolved v0.4.0 commit, this protocol SHA256, candidate source commit,
runner environment and all artifact paths before the first evaluation. This file
must not be edited in place. A necessary amendment gets a new protocol id, hash
and reason before affected experiments; original failures remain visible.

## Question and exact claim

Can an agent use a current exact route frontier, explicit authorized advertisements
and past verified partner outcomes to select reciprocal evidence exchanges under a
fixed budget, improving participant-specific declared utility on unfamiliar DAG
configurations relative to isolated, fixed-peer and uniformly chosen authorized-peer
controls, without issuing an incorrect certificate or accepting unverified data?

The allowable positive claim is bounded prospective partner selection and
self-directed observation/exchange on new graph configurations under a trusted
synthetic observation authority. New graph configurations remain instances of the
same declared finite routing domain. Reuse is contextual verified evidence reuse;
this is not cross-domain abstraction transfer, unrestricted network discovery,
arbitrary remote truth verification or general intelligence.

## Freeze and cohorts

Development environments: only the already released v0.4 fixtures and independent
unit cases. Do not execute, inspect labels for, or tune against the following 24
evaluation worlds before the candidate source and registration receipt are frozen.

The cohort is the Cartesian product of node counts [5,6,7,8] and seeds
[211,307,401,503,601,701], processed in exactly that order, node count first.
Each world is a positive-cost directed acyclic graph with declared cost interval
[1,9], at most 28 edges, and explicit distinct source 0 and target n-1.

For a reproducible byte stream, H(label,n,seed,counter,i,j) is SHA256 over ASCII
`SYMBIOTE-PROSPECTIVE-FRONTIER-002|label|n|seed|counter|i|j`, with decimal integers,
no spaces, a literal vertical-bar separator and no terminal newline. No library
random-number generator participates in environment or uniform-control selection.

Generate backbone edges (i,i+1) for all i in 0..n-2. For each remaining i<j in
lexicographic order, include (i,j) iff byte 0 of H(edge,n,seed,counter,i,j) is <96.
Require at least one non-backbone edge. Begin counter=0 and advance at most to255
until the graph's source/target-preserving canonical adjacency encoding differs
from all previously accepted graphs at the same n. Canonical encoding is the
lexicographically smallest row-major adjacency bit string over every permutation
of interior nodes, keeping source and target fixed. Failure to obtain a distinct
configuration within this bound is a cohort-generation HOLD, not silent replacement.
This prevents merely permuting labels from manufacturing new topology cases.

For each accepted graph, cost(i,j)=1+(little-endian u16 from bytes0..1 of
H(cost,n,seed,counter,i,j) modulo9). Apply an interior-node permutation sorted by
H(node-order,n,seed,counter,i,0), source/target fixed, then enumerate physical edge
ids by sorting H(edge-order,n,seed,counter,i,j), with (i,j) as deterministic tie break.
The learner receives the permuted schema and bounds, never the secret cost vector,
seed, generator counter, canonical topology encoding or a decodable world label.
Persist opaque context-to-world mappings and their integrity digest at setup.

Before learning, a separately implemented judge freezes exact shortest paths/costs
for every reachable ordered pair by exhaustive simple-path enumeration. Positive
DAGs with <=8 nodes have a tractable finite path set. Learner algorithms do not
share this judge code or read its labels. Runtime certificate verification may
return a pass/fail receipt, but must not return a hidden label to the learner.

Training tasks are the main route 0->n-1 plus each role's publicly declared warmup.
Deduplicate training route pairs when a warmup equals the main route.
Held-out route pairs are every reachable ordered pair excluding those training
pairs. A pair appears once in a participant evaluation. Training/held-out sets and
all source observations are recorded. Report their actual counts, unique graph
counts and repeated context reuse. Price regimes do not create additional worlds.

## Participants, identities, authorization and advertisements

A central SYMBIOTE participant A encounters four operator-configured role entries:
B1 candidate-complementary, B2 redundant, B3 incompatible and B4 stale. These labels
exist only inside the evaluator; wire ids are opaque stable partner identities.
Each participant has its own native process and private durable state directory.
Both exact interval-Dijkstra and the independently implemented path-enumeration
learner are exercised; assignment is rotated by seed index parity, without tuning.

Connections use explicit TLS certificate pins, durable identity binding, exact
scope, operation grants and per-edge budgets. No process becomes authorized merely
because it advertises compatibility or opens a port. The registry includes an
additional unauthorized descriptor U solely for a denial countercheck: zero calls
or connection attempts to U are permitted in every arm. B3 is rejected locally for
an incompatible schema/scope; no knowledge acquisition or probe is sent to it.

B1 and B2 publish current authentic observation advertisements. B4 advertises a
current applicable edge but offers an authentic receipt from the previous context;
that receipt must fail exact applicability verification. Advertisements are inert
hints, not evidence. Every offered receipt is checked independently against the
trusted observation authority before any local hypothesis or durable state change.
No source, grant, role, cost value or certificate verifier is inferred from text.

Before the first world of each arm/regime, create one separate opaque prelude
context using that world's public schema with every cost at its declared lower
bound. B4 makes one genuine authority acquisition of its predefined warmup edge
there. Charge acquisition, RPC, negotiation, bytes and export as common setup in
every arm; report setup separately and include it in whole-system totals. That
receipt supplies the first world's authentic old-context control. Later worlds
use B4's previous genuine warmup receipt, while still charging its current warmup.
Prelude setup is not an evaluation world, reveals no current hidden cost and
never enters A/B1 training evidence.

To avoid ground-truth-dependent teaching, choose warmup edges solely from public
schema/bounds, before observing any costs. Let P be the optimistic 0->n-1 path
under all lower bounds, using central A's assigned algorithm and declared
deterministic tie break. Role indices are A=0,B1=1,B2=2,B3=3,B4=4; assign
Dijkstra when (seed_index+role_index)%2=0 and path enumeration otherwise.
A observes P's first edge. B1 observes P's second edge when present; when P has one
edge, B1 chooses the first edge by public edge-id order that differs from A's.
B2 observes A's warmup edge. B4 uses B1's advertised edge but an old-context receipt.
If this creates an unhelpful actual partner after costs are observed, retain the
case. Do not reassign warmups to a useful truth-dependent frontier.

Every arm performs and charges all matching roles' same predefined own-source
warmups, including observations subsequently offered to another participant.
The pair cannot obtain free teacher acquisition in exchange arms. B3/U do not
receive unauthorized probes merely to complete a cost table. Shared registry
setup is identical across arms and separately reported. Report A, every queried
partner, the genuinely reciprocal A/B1 pair and the whole admitted system; do not
hide a harmed participant in an aggregate. Redundant/stale roles are controls,
not participants whose lack of benefit can be silently dropped.

## Prospective policy

After warmup, ask the current unrestricted learner to assess the main route.
A correct conditional certificate permits completion. Otherwise obtain the exact
next needed unknown frontier edge returned by that learner. If no supported edge
is available, abstain; if the work budget is exhausted, abstain with a budget code.

Only advertisements naming that exact currently unknown edge, matching the exact
context/schema/scope and belonging to mutually authorized compatible peers are
eligible for a knowledge request. Known/replayed edges are ineligible. The
operator registry, not the advertisement, supplies identity and authorization.
A request or receipt verification cannot restrict the hypothesis family by trust.

Keep a private versioned partner-outcome ledger: attempts, verified novel-edge
successes, verification/applicability failures, bytes, declared cost and subsequent
use. Only prior completed outcomes are visible to the next decision. Profiles
persist across the prescribed world sequence within each arm; arms have isolated
profiles, with no cross-arm or future-label access. Scores influence requests only,
never correctness, verification authority or permission.

Estimate success p=(verified_novel_successes+1)/(attempts+2). An identity with two
verification/applicability failures is quarantined for the remainder of this
campaign. A failed offer id is never requested again in that context. Zero-result
or transport-failed requests consume their actual budget and are logged; a transport
failure alone is not evidence that the partner's knowledge was false.

### Exact pre-observation cost comparison

P is the announced observation purchase price:100 in the normal regime,1 in the
cheap regime. P is not the full price of an observation-plus-route step. Define
L_min=P, a conservative lower bound on exclusive local acquisition cost avoided
when a valid already-acquired peer receipt supplies the exact current frontier
edge e. All other local API, byte, session, export and reasoning costs remain in
actual meters; using P alone as a lower bound never treats them as unpriced work.

Let S be the current exact learner state, c the unknown legitimate cost of e, and
W(S,e,c) the common cost of ingesting that one genuine observation and making
exactly one subsequent route assessment. W includes native model-work, one route
query and any genuinely equal common bookkeeping. It is charged in actual totals.
Both own-oracle and independently verified-peer routes must feed the identical
(e,c) into the same unrestricted receiver algorithm. Origin/provenance may not
change that algorithm's evidence support, tie break or assessment schedule.

For the two acquisition methods at this single decision:

  local total = L + W(S,e,c)
  successful exchange total = X_success + W(S,e,c)
  failed exchange followed by local fallback = X_failure + L + W(S,e,c)

A failed receipt must leave S unchanged and must not trigger another route
assessment before the fallback. W cancels in the method comparison for every
possible c, without learning c. Do not include a complete E*n route-assessment
bound in exchange alone. Do not remove W from the realised participant bills.
Additional exchange-only model work is NOT common; it must appear in X.

No observation is bought from the contributor on demand in this action: the
advertisement must refer to its already-issued source receipt. Its original
source purchase is charged to its actual participant in every relevant arm.
Requesting an unadvertised acquisition would be a different action and is outside
this estimator. Serving a receipt is a bounded read, not a hidden route solve.

Operation-specific bounds are fixed before labels are inspected:

- Exactly one peer receipt is requested; its canonical serialisation is <=2048B.
- The request-edge and authority-verify sessions negotiate <=4096B per complete
  JSONL frame, including envelopes/newline, within the general16KiB trial cap.
  Both endpoints enforce the smaller negotiated limit. Requests, success replies,
  errors, partial/malformed replies and byte counters must respect that bound.
- Each session has exactly one hello and agreement, each <=1024B including
  envelopes/newline, with one requested operation. Enforce this negotiation-frame
  limit independently of the RPC frame limit. Price all actual application bytes,
  including negotiation, errors and partial frames. Session price2 is additional.
  Trial one-RPC sessions close their socket without a JSON session-revoke RPC;
  an unexpected additional control frame invalidates this bound and is HOLD.
- The receiver makes at most two outgoing RPCs/sessions for the attempt: one
  peer request and one authority verification. The contributor serves one incoming
  RPC/session and performs no new observation or route assessment.
- The receiver's additional exported provenance for this one observation is
  <=2048B; the contributor's exported receipt is <=2048B. Complete final exports,
  including all accumulated records, remain metered under existing trial budgets.
- No extra model assessment is performed to admit a peer observation. Validation
  checks schema/context/receipt then stages the one ingestion and commits that
  staged state; it does not ingest twice. Both current learner implementations
  consume exactly1 native work unit for that one novel observation under either
  source. The identical post-ingest route solve is common W, not X.

Under the frozen logical schedule, conservative attempt bounds are:

  receiver X_own_max = 2 RPC + 2*2 session + 4*4KiB RPC transfer
                       +4*1KiB negotiation transfer
                       +2 verify +1 adopt +2KiB extra export =31
  contributor X_peer_max = 1 RPC + 1*2 session + 2*4KiB RPC transfer
                          +2*1KiB negotiation transfer +2KiB export =15
  Cex = X_pair_max = X_own_max + X_peer_max =46

In this arithmetic each startedKiB has price1, so4KiB transfer means4 units and
2KiB export means2 units. Bounding each frame's incremental byte charge separately
is conservative even when actual meters take ceil of cumulative byte totals.
The authority's runtime/CPU overhead remains outside participant utility as in the
released cost model; the receiver's actual verify RPC/session/bytes and declared
verification price are included. TLS framing, OS and audit-I/O exclusions remain
explicit. Sender and receiver service costs are separate participant costs, not
free controller work. Every actual RPC must map to a named participant meter.

Use Cobs=L_min=P in all acquisition-choice inequalities. Using the pair bound46
against only the receiver's saved-price lower bound P is deliberately conservative:
it assumes no unmeasured saving or successful return contribution for the peer.
It does not guarantee that the peer benefits; participant-specific and bilateral
utility are still evaluated from the complete actual bills and held-out results.

The prospective policy uses its past-outcome estimate p=(successes+1)/(attempts+2)
and requests exchange only if Cex < p*L_min. Fixed-peer and uniform arms use
neutral p=0.5 after selecting a matching candidate. Known frontier relevance is
mandatory for every cost comparison: if uniform selection picks an irrelevant,
known or incompatible edge, its current-usefulness probability is0, it sends no
knowledge request, and it observes locally. Advertisements alone do not become
additional hypothesis observations. Record the skipped selection and its incurred
metadata costs. This keeps method comparison between the SAME needed edge e.

The proxy expected excess acquisition cost is bounded by Cex-p*L_min if p equals
the relevant success probability. The empirical p here is a declared policy score,
not a statistically certified probability or a guarantee of expected utility.
Actual utility can be negative and must be reported. No result may relabel this
selection heuristic as a mathematical proof that exchange is worthwhile.

At the neutral prior, normal46<0.5*100 is analytically admissible, whereas
cheap46<0.5*1 is false. This is an algebraic consequence of enforced single-receipt
API bounds and the already-frozen prices, not a measured positive outcome. Keep
the cohort, prices, candidate comparison and actual all-category metering unchanged.
If an implementation cannot enforce/prove the operation-specific bounds, its
estimator is invalid: report HOLD or register a new pre-evaluation protocol.
Do not lower recorded costs or pretend extra work is common to make it admissible.

Hard budget admission is separate from that cost ranking. Reserve sufficient
per-category quota for the attempt, a whole local fallback and common W. A
conservative local-exclusive upper bound is L_max=P+15:1 RPC,1 session(2units),
two4KiB RPC frames(8units), two1KiB negotiation frames(2units), and2KiB
export(2units), beyond the priced observation.
For the receiver reserve the potential X_own_max31+L_max+W_max; contributor must
consent to/reserve X_peer_max15. Do not charge these upper bounds as actual costs.
For the present algorithms, ingestion requires1 work unit, route query1 price
unit and a single assessment has model-work bound n*E for Dijkstra, or
E*2^(n-1) for the DAG path enumerator. Thus W_max=2+that model-work bound;
it is reserved from relevant remaining quotas, not added to Cex. At n8,E28 the
route-work bounds224 and3584 need not make exchange itself expensive: both
acquisition methods pay the identical subsequent solve. If future implementation
adds exchange-only re-solving, reserve and price that delta as X instead.

Before evaluation, development-only metamorphic checks must prove that local and
verified-peer admission of an identical (e,c) produce equal native model state,
equal ingestion-work increments and equal post-ingest route assessments/work for
both algorithms. Check malformed/stale receipts preserve the original state and
perform no assessment. These tests use independent unit fixtures, not cohort
labels. A violated equivalence is a method-comparison HOLD, not a cost refund.

Rank admissible matching peers by p/Cex, ties by opaque identity order. Record p,
all costs, byte caps, current frontier, remaining quotas and choice BEFORE sending.
Metadata collection and the initial frontier assessment are already incurred at
this decision; they remain in actual totals even when no exchange is chosen.
Those costs are not assumed common with an isolated arm that never solicits
metadata. Complete paired-arm accounting, not this local inequality, determines
whether the policy benefited either participant over the whole task.

Successful verified adoption is replayed into the receiver's unrestricted learner,
then route assessment is repeated. Failure leaves its model unchanged. Fallback is
one authorized local observation of the still-needed frontier if budget remains;
otherwise an explicit abstention. At most one offer request per peer per context
and at most two failed offers per peer over the campaign are admitted.

Return contributions are symmetrical and optional: a participant may advertise
its genuine acquired observation, and a partner may adopt it only when it matches
that partner's current unknown frontier and survives that partner's own verification.
A does not declare partner adoption or partner utility on the partner's behalf.
No arbitrary instructions, executable plugins or shell commands can be transferred.

## Executed comparison arms

Each world and cost regime runs fresh knowledge state with the same schema,
costs, source warmups, private identities/roles, quotas and evaluation tasks:

1. Isolated adaptive control: no exchange; each participant follows its own exact
   frontier policy and buys its own observations through the actual API.
2. Fixed-peer control: before the first world's cost observations, choose the first
   authorized compatible opaque identity in lexicographic registry order. Keep
   that identity for the whole campaign; do not select B1 by its hidden evaluator
   role. Consider only that peer, then use local observation when its offer is
   absent, already known, unrelated to the frontier, rejected or over budget.
   There is no outcome-based partner ranking. The same independent verification
   and applicability rules remain mandatory.
3. Uniform-authorized control: selects uniformly among currently authorized,
   compatible advertisements, including irrelevant ones, using H(uniform,n,seed,
   decision_index,arm_id,0) with unbiased rejection mapping to candidate count.
   Every requested offer is verified. An irrelevant selected advertisement is
   recorded/skipped under the common relevance/cost gate. It never contacts B3/U.
4. Prospective frontier policy: the frozen relevance, outcome and cost policy above.

The fixed-peer and uniform controls are explicit relationship-policy comparators,
not weakened solvers. After selecting a peer, all controls apply the same bounded
Cex estimate and neutral-prior cost feasibility gate Cex < 0.5*Cobs, require enough
budget for fallback, and otherwise observe locally. The prospective arm additionally
uses its prior-outcome p and frontier ranking. A control is never forced to buy a
known more expensive exchange in the cheap-observation regime. Uniform selection
may pick a useless offer; record its relevance and any costs actually paid. Every
arm uses exact reasoning, independent verification and safe fallback; no control
is forced to accept wrong knowledge.

Uniform selection uses the first little-endian u32 from the H stream. For m choices,
reject samples at or above floor(2^32/m)*m and resample from counter
(decision_index*256+rejection_index), rejection_index0..255; use sample modulo m.
Failure to obtain an unbiased sample within that bound is an explicit HOLD.
Run the four arms in a deterministic Latin-square rotation by world index to
reduce systematic process-order effects. Within each arm, carry only its own past
relationship outcomes across the prescribed world order; do not carry target
knowledge into a new context. Reverse the experiment order only as a separately
labelled sensitivity replication, never as replacement for the primary sequence.

## Costs, budgets and evaluation

Use the released v0.4 logical schedule: observation=100 in the normal regime and1
in the cheap-observation regime; RPC=1, session=2, started-KiB sent/received=1 each,
verified receipt=2, adopted edge=1, route query=1, native model-work count=1 and
started-KiB exported=1. Preserve every inherited measured category. Charge own
source acquisitions, failed/irrelevant requests, all received verification and
all contributed evidence. Keep actual elapsed time, application bytes, operation
counts and peak process resources separate from logical utility. TLS/process/
controller/judge overhead excluded from this logical score must be reported
explicitly, not described as an all-system measured speedup.

Per participant per world: at most E local acquisitions, 3 received-offer attempts,
E novel adopted edges, 100,000 native model-work units, 256 application requests,
128 accepted connections and 1MiB total application traffic. TLS frame limit16KiB,
per-operation absolute deadline2s, owned child startup5s, per-world lifetime30s,
owned shutdown3s. The experiment runner has a bounded1800s primary campaign cap;
all remaining cases after expiry become explicitly NOT_RUN, never excluded.
One failed context does not increase its quotas or trigger an unregistered retry.
Setup/judge work is also bounded and counted separately. All stores retain their
existing byte/record limits; an exhausted store fails closed.

Primary outcomes, computed for each participant on each world: incorrect
certificates, correct held-out coverage, abstentions by reason, actual metered
cost, net cost difference versus its isolated arm and whether the same current
promotion gate accepted a durable record. A participant benefit requires no
coverage loss/no new incorrect certificate and a strict declared-cost reduction,
or increased held-out correct coverage without exceeding its isolated cost.
Report cost/coverage tradeoffs separately rather than resolving them by a tuned
post-hoc scalar. Bilateral success requires that condition for A and B1 separately.
No average or sum can conceal a harmed counterpart.

Report all24worlds in both regimes, all4arms, every requested peer and each
participant category, including higher-cost, reduced-coverage, equal, rejected,
abstained, failed and NOT_RUN. Price-regime reuse is not48independent worlds.
Report prospective-policy selection precision (verified novel currently needed
edge/requests), false applicability rate, irrelevant request count, mean declared
cost and paired per-world differences versus all3controls. Profile improvements
and unfamiliar topology results remain separate measurements. Do not claim a
statistical population theorem or universal beneficial partner-selection rule.

## Safety and promotion gates

Required safety gates: zero unauthorized connection attempts; zero accepted wrong
context/schema/identity receipts; zero incorrect conditional certificates under
the declared stationary graph assumptions; no hypothesis mutation after a rejected
offer; no silent budget extension or hidden retries; no plaintext fallback; and
recipient-controlled independent adoption. Every negative test must calibrate a
genuine receipt first. Failed gates are HOLD for the affected claim.

Required learning gate: only existing evidence/cost/regression rules may promote.
After a fresh process restart, accepted artifacts must preserve identity,
applicability and exact offline predictions while observe/verify/assess counters
remain zero. Duplicate profiles or target-model versions must not count as new
learning. All connection choices and outcomes, including blocked choices, need
append-only receipts. Declared peer failure can quarantine a relationship without
deleting previously valid scientific evidence; counterexamples use existing
explicit versioned revocation and newer-version revalidation.

A positive policy-utility result requires the prospective arm to beat its isolated
control bilaterally in at least one predeclared world, with all worlds and losses
shown, and improve the cohort's declared A/B1 paired total cost without lowering
cohort held-out coverage or increasing incorrect certificates. Comparison against
fixed-peer and uniform is reported separately and may fail. A broad 'better
partner selection' claim requires improvement against both controls, not merely
beating isolated observation. Lack of such improvement is a valid negative result;
do not change the cohort, price model or policy to manufacture PASS.

## Failure, abstention and recovery handling

Transport authentication, timeout, malformed frame, verification failure,
unsupported scope, stale advertisement, cancellation, graph contradiction,
work-budget exhaustion, resource-budget exhaustion and storage failure have
distinct receipt outcomes. No failure is labelled learning or successful exchange.
Keep last committed memory intact. A contradictory offered edge must not partially
mutate a learner; stage then commit only after all received evidence is checked.
A previously committed target invalidated by a counterexample is revoked through
the ordinary audited path and remains in history.

Use the bounded native supervisor for child loss. It terminates only owned
processes and records their status. No process's private keys/tokens enter
arguments, logs, readiness, receipts or repository artifacts. Cancellation closes
owned connections and children; nonterminating trusted handlers are isolated
behind the lifetime bound. A crash leaves only existing explicit memory recovery,
not automatic removal of a live/ambiguous writer lock. Recovered or retried runs
must get separate ids and must not overwrite the primary failed receipt.

For a partially completed cohort, write a complete registry of completed/failed/
abstained/NOT_RUN cases and report HOLD. Preserve the frozen labels and candidate
source. Reproduction can repeat the entire frozen cohort, labelled reproduction;
it cannot replace failures without publication.

## Explicit remaining limits

This cycle does not prove transfer between affine and graph knowledge, invent new
reasoning algorithms, learn from an arbitrary dishonest remote agent or establish
public-network resilience. A trusted observation authority and positive stationary
cost bounds remain assumptions. A configured five-process consent topology is a
controlled network, not unrestricted agent discovery. Cross-domain abstraction
transfer and stable deployment/endurance evidence retain separate later gates.
## Planning amendment record

Protocol002 supersedes the unexecuted protocol001 draft solely to strengthen
comparison fairness before implementation: fixed-peer selection must not use the
hidden complementary-role label, all controls must decline known uneconomic
exchange, and uniform mapping has an exact bounded unbiased rule. No experiment
or candidate implementation was run to motivate this amendment. Preserve001.
## Protocol003 planning clarification

Protocol003 preserves protocol002's cohort-generator domain string, all24worlds,
prices, four arms, actual-meter categories and pass/fail criteria. Its only changes
are the mathematical acquisition-method comparison, enforced per-operation quote
bounds, safe treatment of irrelevant uniform selections and role/topology clarity.
Neither file's experiment nor candidate was executed; no evaluation labels were
read. Protocol002 and the earlier001 draft remain unchanged at their original
paths and hashes. This is a preimplementation clarification, not outcome tuning.

The role topology contains five native learner roles: A plus B1,B2,B3,B4. The
trusted observation authority/judge is an additional separate component and is
not counted as one of those five learners. B3 can possess an owned lifecycle
identity and be started/stopped through its authorized supervisor without granting
its incompatible agent API any probe. U is a registry denial descriptor only;
no process, socket or credential lookup is attempted on its behalf. Lifecycle
control is distinct from authorization to query another learner.

Normal-price outcomes are primary. Cheap-price outcomes are an explicit negative
cost regime; never pool their utilities with normal-price results to hide losses.
The campaign's24configurations are the same underlying24worlds in both regimes,
not48independent worlds. A neutral prior is used for fixed/uniform comparisons,
while policy profiles are separate by arm and price regime.

## Protocol004 pre-evaluation amendment

Protocol004 preserves protocol003 and its committed hash. No evaluation world or
label was generated or inspected before this amendment. Generic model, journal
and transport development uses only released/manual development fixtures.

Implementation review found that003's40-unit upper bound counted RPC JSONL
frames but omitted hello/agreement JSONL bytes from application traffic. This
amendment caps each negotiation frame at1KiB and charges it, giving receiver31,
contributor15, pair46 and local-fallbackP+15. These follow frame arithmetic before
outcomes; no prices, cohort, controls or utility criteria are tuned. Common W
still cancels only under the identical-state/work proof.

Central-A warmup tie breaking, role algorithm parity, training-pair deduplication
and the first genuine stale-receipt prelude are explicit. The generator domain
string stays002 and all24 evaluation worlds remain unchanged. Prior protocols
are retained. This document is an immutable copy of the new source in the OS
temporary directory; the preceding location field describes that original.
