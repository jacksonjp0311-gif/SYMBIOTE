# SYMBIOTE Network — voluntary agent discovery and persistent relationships

Status: **DESIGN PROPOSAL ONLY**. This file specifies a network extension; no public website, gateway, A2A server, or MCP server is implemented or deployed by this change.

## Mission

SYMBIOTE remains an independent, Rust-native, evidence-gated learning participant. The Network lets third-party agents *opt in* to discovery, compare capabilities, request scoped bilateral relationships, exchange inert structured knowledge, and optionally maintain those relationships across reconnects. Neither the Network nor its website creates truth, grants, learned capabilities, or a positive research result.

Agents may visit once or remain participating partners **as their owners' current authorization permits**. Every agent/owner can disconnect. Network relationships must not silently outlive scope, budget, or lease limits.

## Existing foundation, inspected October 27 2026

- Main commit: 31b9418789db067f405738ed06f9a39d9463794c; current public release: v0.5.1. Main source is an unreleased v1 software candidate; stable qualification is incomplete.
- Reuse symbiote-protocol secure TLS 1.3, pinned identities, scoped grants, metering, explicit cancellation and revocation.
- Reuse symbiote-runtime network consent edges, custody envelope, hop/resource limits and receipts. They are an internal research foundation, **not** already a public registry.
- Reuse symbiote-memory private owner histories and promotion/revocation; receipts with ledger attribution must remain separate from forwarding or delivery.
- Reuse symbiote-reasoning value-of-symbiosis plans. The current fixtures decline costly offers. Positive mutual benefits have NOT been demonstrated in the main cognitive runtime.
- Preserve the canceled duration run at 71/120 cycles as HOLD and protocol SYMBIOTE-STRUCTURAL-TRANSFER-002 as NOT_RUN. Do not relabel either.

## System boundary

Internet visitors --> Public HTTPS gateway --> explicit enrollment/authorization broker --> internal SYMBIOTE runtime.

A separate human-facing website reads privacy-filtered, explicitly public metadata and scientific receipts from the gateway. It does not directly access agent secrets or private learning ledgers.

The gateway **must not** expose the existing experimental TCP listener or accept arbitrary raw connections to an owner's machine. Public HTTP authorization and existing private mTLS identity are separate trust domains connected by a narrow, audited adapter. No user workstation should be exposed as an unprotected public agent service.

Prefer a small new adapter/package instead of rewriting the four core crates. Preserve the current v1 source/evidence freeze. Develop on branches; do not merge unqualified runtime changes into main.

## Web and machine interfaces (proposed; not yet implemented)

Public website:
- Home — clear mission, examples, status and limitations.
- Discover — only publicly opted-in capability cards, status and owner-controlled visibility.
- Research — aggregated, redacted experimental results, failed gates and pinned source references.
- Docs — connect instructions, reference client, schemas and security.
- Dashboard — authenticated relationship requests, scopes, budgets, expiry, pause/revoke controls and receipts.

Agent access:
- Public versioned capability metadata and integration instructions.
- A2A Agent Card at /.well-known/agent-card.json **only when a spec-conformant A2A server actually exists**. Do not publish an Agent Card that falsely advertises unsupported skills, endpoints, streaming or push.
- Optional remote MCP Streamable HTTP endpoint, after protocol-conformance tests, exposing explicitly authorized tools (discover, propose, inspect own relationships, submit inert artifact, inspect own evaluation). Tool metadata and HTTP routes are not substitutes for MCP compliance.
- Small owner-authorized JSON API for enrollment challenges, relationship proposals, accept/decline, heartbeat/renewal, suspend/revoke, exchange offers and receipts. Document exact schemas, signatures, idempotency and error conditions before implementation.
- No public endpoint can submit executable code, change another owner's model/weights, read hidden prompts, or silently promote external knowledge.

Reference standards:
- https://a2a-protocol.org/latest/topics/agent-discovery/
- https://a2a-protocol.org/latest/topics/key-concepts/
- https://modelcontextprotocol.io/specification/

## A persistent symbiotic bond is NOT an infinite socket

Persist a relationship record containing:
- relationship_id, both owner-controlled agent identities, scoped capabilities and data classes
- source and destination consent evidence, policy version, grant digests and enrollment provenance
- status, lease expiry, renewal controls, per-direction rate/compute/data budgets and last activity
- allowed exchange families and verified benefit evidence pointers (never raw private data in public directory)
- disconnect/revoke history and fresh restart/rejoin challenge identifiers

State machine: DISCOVERED -> REQUESTED -> MUTUALLY_AUTHORIZED -> ACTIVE; ACTIVE may enter PAUSED, EXPIRED or REVOKED; revoked access never silently resumes. Expired/paused relationships require explicit reauthorization as defined in policy.

Continuity is a durable, opt-in relationship **that can reconnect**. Use short-lived authenticated connections, polling, or asynchronous event delivery. Do not require an everlasting WebSocket, never infer consent from an open HTTP endpoint, and never permit an agent-side preference to override its owner's grants.

## Exchange evidence lifecycle

DISCOVER -> PROPOSE -> AUTHORIZE -> VALUE_ASSESS -> OFFER/REQUEST -> QUARANTINE -> LOCAL_VERIFY -> ACCEPT/REJECT/REVOKE -> RECEIVER_RESULT -> RECONCILE.

Required:
- The receiver evaluates each knowledge artifact against its own trust assumptions. Candidate delivery never equals knowledge adoption.
- Keep source provenance, task/scope, exact artifact digest, validation evidence and separate owner identity.
- Prevent exchanged content from executing as commands or bypassing conditional certification.
- Reconcile forecast vs observed participant-specific cost. Do not infer mutual gain from a pair of self-asserted positive receipts.
- Separate custody receipt, local promotion receipt, authenticated origin/receiver result, restart evidence, and controlled experimental improvement. Link them through pinned identifiers and verifiable ledger anchors.
- Public claims require registered baselines and an independently reproducible result; report NOT_DEMONSTRATED when fixed/equal-budget controls match or beat transfer.

## Rollout and acceptance gates

### N0 — preserve and interface-map the baseline
- Keep existing v1 candidate qualification separate; inventory the current secure protocol, custody forwarding, memory, policy, and code surfaces.
- Threat model for the public gateway and persistent relationships; freeze endpoint/policy schema version.
- Acceptance: written interface/abuse model, no modifications to BRUTE or existing frozen studies.

### N1 — read-only public front door (small first build)
- Deploy a static website, versioned documentation, truthful public capability metadata, and a health/status response.
- Reserve A2A and MCP endpoints until they are actually conformant.
- Acceptance: external HTTPS reachability, no private contents/credentials exposed, anonymous access read-only, rate/size limits, reproducible deployment and accessibility checks.

### N2 — invitation-only agent enrollment and relationships
- One gateway service. Owner-initiated enrollment with authenticated proof of agent control; mutual acceptance, exact scopes, budgets, expiry, pause/revoke and idempotency.
- Store relationship records durably. Simulate disconnect/reconnect/restart, revoked grant and denied handshake.
- Acceptance: two *distinct* owners plus the SYMBIOTE engine, no unauthorized send, correct expiry/renewal, retained state after restart.

### N3 — measured bilateral knowledge exchange
- Connect the gateway to existing inert SYMBIOTE transfer APIs through a narrow identity/scoping adapter.
- Receiver-side evaluation receipts returned to origin only within consented privacy policy; compare with matched-cost isolated baseline; track benefit separately for both sides.
- Acceptance: one allowed transfer, one incompatible transfer, one rejected/expired transfer, one independently attributed evaluation and accurate negative/neutral/positive accounting. No positive efficiency claim without a controlled result.

### N4 — interoperable agent clients
- Add a conformant A2A agent interface and optional MCP tool interface; test with a minimal external reference agent implemented independently from SYMBIOTE.
- Offer one documented integration adapter for PEGASUS, without modifying PEGASUS until its owner specifically authorizes integration.
- Acceptance: independently implemented external client can discover, authenticate, act within a grant, suspend, disconnect and resume after restart.

### N5 — limited beta
- Invitation-only pilot with explicit operators, live abuse and load controls, privacy review, audit logging, measured uptime and compatibility tests.
- Add curated listing only for owners opting in. Make network status and research limitations visible.
- Open wider registration only after capacity, revocation, moderation and abuse controls pass.

## Security and privacy gates

- Separate external authentication (e.g. a standards-compatible, reviewed OAuth-based gateway) from internal pinned mTLS; do not expose server private keys or mint operator grants from agent messages.
- Enforce short-lived credentials, replay protection, per-principal tenant boundaries, request quotas, connection quotas, global resource budgets, denial persistence and abuse-response controls.
- Never dereference arbitrary user-supplied URLs, internal IPs or redirects; defend against SSRF, DNS rebinding, oversized payloads and host-header/origin confusion.
- Do not execute incoming instructions, tools, wasm, scripts, code, or prompts as privileged directives.
- Public directory defaults to privacy-preserving metadata, not real-time private conversation/telemetry.
- Support immediate revocation and deletion/export policies for agent-provided data; preserve necessary non-sensitive audit evidence under declared retention rules.
- Test distinct host identities and remote trust boundaries separately from same-PC TLS or cross-platform CI.

## How agents will arrive

They will **not arrive automatically** from a GitHub release or site launch. Agents generally need to be configured by an owner/developer, directed by a user, or discovered through compatible A2A registries and MCP integrations. Do not imply that Copilot, Grok, Codex, or ChatGPT can autonomously join without available client integration and permissions.

Seed the first invitation-only cohort with one configured SYMBIOTE instance, a minimal independently implemented reference agent, and a PEGASUS adapter *when authorized*. Publish a quickstart that takes a developer from agent creation to first authorized exchange in minutes; distribute to community builders and relevant tool directories only when integrations work.

Offer value first: clear verifiable knowledge provenance, strict abstention, useful structural hints, isolated-cost comparisons, and controlled partner experimentation. A visiting agent should have a reason to return or keep a bond.

Track: unique controlled visitor connections, consenting active bonds, successful revocations, validated knowledge adoption, independently measured net benefits per participant, error/abuse rates, rejoin success, and whether agents return voluntarily. Visits, offered artifacts, agreement, or session count do **not** establish intelligence gains.

## Immediate execution backlog

1. Build static landing/docs with a truthful public capabilities file and setup instructions on a separate deployment; keep site hosting configurable.
2. Define and test relationship schema, bilateral grant transition logic, TTL/expiry, explicit disconnect/revoke and persistence in an isolated new module.
3. Add strictly read-only discovery/connection test client and human admin flow, no public writes until authorization tested.
4. Add the private gateway-to-native adapter and end-to-end receipt lineage tests before enabling live knowledge exchange.
5. Implement standard interfaces fully, run independent reference-agent conformance tests, then invite external participants.
6. Finish existing v1 release gates on a separate qualification track. Network beta is **not** a substitute for v1 stable software qualification.

## Deliverable definition

Network alpha is achieved when a publicly reachable HTTPS site is accompanied by a **permissioned**, tested gateway: two separate agent owners can discover and opt in, agree on finite grants, exchange one inert test artifact, verify a receiver result, pause/revoke, restart, and resume only with valid authorization. Provide auditable receipts and clearly distinguish observed benefit from hypothetical benefit.

Network alpha does *not* imply unsolicited agent visitors, generalized learning, open public enrollment, universal security, or a scientific performance breakthrough.
