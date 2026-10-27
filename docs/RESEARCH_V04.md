# Reciprocal route-planning experiment

The [fixed protocol](RESEARCH_V04_PROTOCOL.md) was committed as `b0d97ad` before
the cohort ran. The final implementation uses opaque random context labels held
in a strict controller-owned registry. An initial engineering run used enumeration
indices in those labels; review found that deviation, and release evidence was
regenerated after correcting it. Learners did not decode the initial indices,
but that trace is not the release's opaque-context result.

The [raw receipt](../experiments/v0.4/graph-exchange.json) includes every world,
both price regimes, every participant meter, utility comparisons, negative
controls and actual offline process replay. The [independent verifier](../tools/verify_graph.py)
recomputes the cost arithmetic, route labels, coverage and aggregates.

## Observed results

| Measure | Normal observations | Cheap observations |
|---|---:|---:|
| Worlds, reused across price regimes | 81 | 81 |
| Participant comparisons | 162 | 162 |
| Correct held-out routes, either arm | 231/324 | 231/324 |
| Abstentions, either arm | 93 | 93 |
| Incorrect certificates | 0 | 0 |
| Isolated logical cost | 69,093 | 15,930 |
| Exchange logical cost | 54,105 | 15,216 |
| Equal-coverage, lower-cost comparisons | 144 | 144 |
| Equal-coverage, higher-cost comparisons | 18 | 18 |
| Worlds benefiting both participants | 64/81 | 64/81 |

The normal-price arm retained 30 Dijkstra-peer and 39 path-enumerator maps.
The other 93 candidates could not answer both fixed held-out route tasks and were
withheld. Every retained model produces matching routes in a fresh native
process, with measured observation and verification counter changes of zero.
The public `route` command uses these stored models without an oracle endpoint.

Promotion evaluates a persistent change from the recipient's current knowledge;
paired utility separately compares fresh isolated and exchanging learners. Both
learners can obtain the same coverage. Durable retention is therefore not itself
evidence that exchange improves accuracy. All 18 higher-cost comparisons remain
in the cohort; none produces a complete promoted map in this experiment.

## What this establishes

Exact route reasoning chooses costly observations; independently implemented
learners reuse authorized evidence; independently checked maps change future
persistent behavior; a peer receives useful reciprocal observations in the
reported beneficial contexts. This holds within the declared finite stationary
graph family and trusted laboratory authority.

The logical model charges acquisitions, participant and authority API requests,
session negotiations, application bytes, receipt checks, adoption, route queries,
model work and model export. It excludes OS startup, TCP/HMAC framing, controller,
judge, audit-ledger I/O and replay overhead. The result is not a wall-clock,
energy, money or complete computational-cost advantage.

The graph endpoints share a controller process. The separate affine experiment
demonstrates independently supervised peers and configured mutual TLS; those
results do not establish that the graph cohort has been independently deployed.
All 81 worlds share one topology, and both price regimes reuse those worlds.
Fixed warmups and a fixed pair do not demonstrate learned partner selection,
unfamiliar-topology transfer or general autonomy.

## Next test

Select useful exchanges prospectively from a bounded authorized partner registry,
using the current unknown frontier and measured costs. Compare against isolation,
a fixed partner and uniform authorized selection on previously unused topologies.
Retain every failed, harmful and abstaining case. Expand the combined deployment
and stability campaign before considering a stable API release.
