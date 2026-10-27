# First Symbiosis: exact inference from exchanged evidence

This is a deterministic engineering experiment with a predefined configuration,
not an independently preregistered scientific study. Read the actual
[exchange receipt](../experiments/v0.2/reciprocal-exchange.json) and
[verification receipt](../experiments/v0.2/verification.json).

## Question and mechanism

Can reciprocal sharing of genuine, independently verifiable observations avoid
repeating expensive observations while preserving exact conditional reasoning?
An untrusted strategy hint alone cannot lower the full affine identification
bound. This implementation exchanges inert observation receipts instead of
silently constraining hypothesis support to a teacher's proposed strategy.

An independent lab oracle registers actual `(domain, schema, input, output)`
observations under immutable receipt ids. The agent-facing interface cannot mint
arbitrary oracle outputs. The receiving service checks each receipt against the
registry and exact target context; changed, repeated and cross-domain receipts
fail. This is a trusted local oracle-registry assumption. A content hash by itself
does not authenticate an untrusted remote statement.

## Participants and evaluator

SYMBIOTE uses complete affine-hypothesis enumeration and maximin query selection.
Its partner uses an independently implemented binary Gaussian-elimination learner.
One oracle evaluates explicit XOR circuits; the other uses binary arithmetic.
The held-out judge separately constructs truth tables before learning begins;
learner and exchange APIs never receive those held-out labels in advance.
Components are independently implemented in one Rust test controller, not separate
research teams or separately deployed operating-system agents.

Each participant learns its own source context, then contributes that genuine
observation transcript to the other. Received evidence produces an exact model
conditional on the supplied stationary affine grammar. Endpoint acceptance is
provisional. Only successful held-out assessment can durably promote a record.

## Configuration and controls

Widths are 3–8; seeds are 7, 19, 43 and 101: 24 paired contexts, 48 participant
trials. Active learners acquire width+1 observations. Evaluation covers every
remaining input in each declared context. Inputs are unique and disjoint from
training within a trial. Some seeded laws repeat, so the aggregate prediction
count is not a count of statistically independent worlds or discoveries.

The isolated control executes the same native learner, buys fresh target oracle
observations through the actual TCP service and identifies the same complete
function. Both participants' own-source acquisition is included on both sides.
The comparison measures resources needed for equal held-out correctness, not an
artificial advantage against a deliberately weak isolated predictor.

Logical cost model: one expensive observation=100 units, registry verification=1
per receipt, adoption=1, transfer=1 per started KiB, prediction=1. CPU reasoning,
controller round trips and evaluator work are not priced. Consequently the result
is conditional resource accounting, not a CPU-speedup claim. A cheap-observation
negative control explicitly loses the cost advantage and is denied promotion.

Other executed negatives reject forged/cross-domain/repeated witnesses, require
hint-only abstention, and prevent wrong-family basis agreement from becoming a
durably promoted model when an unseen input contradicts it.

## Persistence and interpretation

Versioned affine records include provenance, context/schema, held-out evidence,
total declared costs and an auditable integrity chain. Two agents own separate
identities and ledgers. A separate `predict` process loads and uses retained
models without network access; the verifier checks neither ledger changes.
Research reruns intentionally rebuild the cohort. A matching active record is
labelled `already_retained`, not claimed to accelerate that rerun.

These mechanisms demonstrate a narrow form of reciprocal learning from shared
evidence under trusted observation attestation. They do not establish that an
arbitrary peer is honest, that a new environment belongs to the affine family,
that transfer works across arbitrary domains, or that SYMBIOTE autonomously
improves its software. Those remain distinct evidence requirements.
