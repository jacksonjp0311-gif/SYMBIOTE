# v0.4 graph-routing experiment protocol

This protocol is fixed before running the cohort. It studies a finite stationary
graph family, not arbitrary agents or general intelligence. The v0.3 affine
experiment remains unchanged. A failed control or incorrect certificate is HOLD.

## Cohort and decisions

Run every one of the **81** assignments of costs `{1,2,3}` to the four ordered
directed edges `0:0→1`, `1:1→3`, `2:0→2`, `3:2→3`. Enumerate assignments in base
three, edge zero least significant. Every edge has declared interval `[1,3]`.
No world is discarded, weighted by success, or selected after seeing its costs.

Two independent implementations participate: optimistic Dijkstra with exact
interval certification, and exhaustive enumeration of simple paths with reverse
edge-order tie breaking. Neither receives the four hidden costs. An independent
Bellman–Ford judge, which never calls either learner, checks actual paths and
shortest costs. The trusted controller owns the hidden costs and receipt registry.
The first graph cohort uses authenticated loopback API endpoints in one native
process. It does not claim process isolation; v0.3 separately demonstrates that.

Before any cost observation, participants advertise the fixed graph fingerprint,
the `0→3` acquisition task, and their distinct first frontiers. The Dijkstra
participant warms up on `0→1` (edge zero); the path enumerator warms up on `0→2`
(edge two). The exchange decision is fixed from this structural complementarity,
before advertisements reveal observations. After warmup, each sends its single
authenticated edge observation to the other, independently verifies the received
envelope through the authority API, then continues observing its chosen unknown
edge until it can certify `0→3` or reaches a budget. The isolated control performs
the identical warmup and continuation without exchange.

Warmup and `0→3` guide acquisition and are **training tasks**. The ordered held-out
route tasks are **`1→3`, `2→3`**. Their judge labels never guide acquisition or
exchange. Report abstention as abstention; do not invent an estimated route cost.
This tests reuse of observed edges across route queries in the same topology,
not transfer across unfamiliar graph topologies.

## Paired controls and budgets

For each world and each learner, execute a fresh isolated arm and a fresh exchange
arm with identical schema, initial empty model, warmup, task order and budgets.
An arm may acquire at most four local observations, spend at most 10,000 model
work units, make 32 participant API requests and 16 authority requests, and send
or receive 64 KiB of application JSON. Received evidence does not replenish these
budgets. Count the partner's acquisitions in its own cost and in the pair total;
shared observations are never treated as free data created by the controller.

Run the entire paired cohort in two declared logical price regimes:

| Component | Normal observation price | Cheap observation control |
|---|---:|---:|
| One local edge acquisition | 100 | 1 |
| One participant API request, including advertisement/offer/adoption | 1 | 1 |
| One authority API request | 1 | 1 |
| One authenticated session negotiation | 2 | 2 |
| Each started KiB of sent application JSON | 1 | 1 |
| Each started KiB of received application JSON | 1 | 1 |
| Each received receipt independently verified | 2 | 2 |
| Each new edge adopted from the partner | 1 | 1 |
| Each route assessment/prediction | 1 | 1 |
| Each learner edge scan/path expansion/accepted observation | 1 | 1 |
| Each started KiB of exported model and complete observation evidence | 1 | 1 |

Count both sending and receiving for each participant. Authority calls include
the request and response JSON and fresh session negotiation. Count final held-out
predictions and model export for both arms. A diagnostic statistics read is an
observer measurement outside the participant trace; it must not alter its state
or silently grant a free participant operation. A shared endpoint connection is
charged once to each fresh arm rather than amortized across worlds.

These units are a predeclared cost model, not time, joules, money, or a benchmark
of machine efficiency. Report raw counts and model work as well as totals. OS
startup, TCP/HMAC framing, the controller, independent judge, audit-ledger I/O and
the separate persistence replay are laboratory overhead outside this modeled
task cost and must be disclosed. Record elapsed execution time separately.

For every world report per-participant and pair totals, certified held-out query
counts, wrong answers, abstentions and budget failures. Classify each comparison
as improved coverage, equal coverage/lower cost, neutral, equal coverage/higher
cost, or lower coverage. Report all classes, including neutral/harmful cheap-cost
outcomes. No universal reciprocal benefit is an acceptance criterion. The two
price regimes reuse the same 81 worlds and are not 162 independent environments.

## Evidence, persistence and negative controls

Each envelope binds `symbiote.graph-observation/1`, fresh `authority_id`, stable
opaque `context`, exact `schema_fingerprint`, persistent `observer_identity`,
unique sequence, receipt ID, edge ID and cost. The registry verifies the complete
envelope, authorized source identity, context and schema. A digest alone cannot
authenticate a new observation. Reject forged, duplicate, wrong-context,
wrong-source and previous-authority receipts. Reject contradictory observations
without changing the previous model. A changed world requires explicit revoke
and reassessment; never silently reset an identity or rewrite old evidence.

Persist evaluated normal-regime exchange models only when they certify **both**
predeclared held-out queries, with complete current-epoch observation envelopes,
distinct held-out query evidence and the declared cost breakdown. A partial map
is reported withheld with its abstentions; never drop an uncovered held-out query
from the promotion gate or acquire more edges in response to its judge label.
Existing equal models are reported already retained, not learned again.
Bind every model to its exact topology/order, interval schema, context and peer.

Release writers, start a fresh copy of the pinned current executable with a
bounded stdin-only forecast request, and compare its actual conditional routes
and abstentions with pre-restart results. This replay has no oracle endpoint or
authority capability. Measure the controller's observation/verification counters
before and after and require zero changes. Preserve private identities and all
ledger bytes. Previous-epoch receipts remain usable as historical provenance and
for local stationary-context forecasts; a fresh authority must refuse them for
new exchange/promotion. New evidence requires charged reacquisition and fresh
verification. A copied owner identity or corrupt ledger is an explicit failure.

## Acceptance and limits

Require all 81 worlds in both regimes, no incorrect certified routes, actual API
receipt checks, the negative controls, durable graph records and actual offline
replay. Report any failed criterion without relabeling it. Finite conditional
certification assumes the declared topology, positive intervals and stationary
observed costs. Receipt authentication assumes the trusted local laboratory
authority. The experiment cannot establish arbitrary remote honesty, malicious
same-user isolation, universal collaborator selection or general intelligence.
