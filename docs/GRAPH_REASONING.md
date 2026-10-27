# Exact graph bounds and conservative route certification

The next stability cycle adds a second reasoning domain beyond Boolean affine
functions. `symbiote_reasoning::planning` models a finite directed graph whose
positive integer edge costs lie in declared intervals. A new observation shrinks
one interval to an exact value. Unknown costs are never filled from a transferred
path hint. This is a native SYMBIOTE extension, not a port of another BRUTE module.

`GraphSchema` validates 2–64 nodes, 1–256 unique directed edges, and costs in
1–1,000. `RouteLearner` retains observations, work budget and a fail-closed status.
Its active rule requests an unobserved edge on the current optimistic shortest
route. Each accepted query adds information; duplicate observations are no-ops.
A changed or out-of-interval value contradicts the stationary model and disables
certification without overwriting the original evidence. A bounded rejected
observation records the counterexample or pending budget-limited update so its
cause remains inspectable.

## Conditional invariant

Let Ω be the product of the remaining declared integer cost intervals. Set every
unobserved edge to its lower bound and compute the exact shortest-path cost L.
For every completion w in Ω, its optimal cost is at least L. If an actual route P
has only observed edge costs and total C=L, then P is optimal in every w in Ω.
This follows because L ≤ OPT(w) ≤ cost(P,w)=C=L.

The implementation checks that sufficient condition and otherwise abstains. This
certification policy is deliberately conservative: an uncertain route could be
optimal in every completion without all its individual costs being observed. No
claim of a complete invariant-route decision procedure is made. Lower-bound
shortest paths and certificates actually returned use exact integer arithmetic.

Route data distinguishes an optimistic interval-based cost from
an observed edge-cost sum through the explicit `cost_basis` field.
All certificates remain conditional on the declared topology, cost intervals and
stationarity. `physical_certificate_authorized` is always false. A real agent's
world is not proven to match that family merely because a few edges agree.

## Verification and integration boundary

An independent Bellman–Ford-style evaluator checks every remaining completion of
all 81 four-edge diamond worlds. Further tests cover relevant-edge exploration,
partial-map certification, contradictions, budget exhaustion, inert hints and
schema limits. Original BRUTE parity is preserved separately.

The module is an embeddable reasoning primitive in the current development branch.
Network exchange, durable graph knowledge and cross-agent measured utility require
their own integration/evaluation gates before a release can claim those features.
