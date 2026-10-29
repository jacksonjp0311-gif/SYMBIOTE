# SYMBIOTE v1.1.2

SYMBIOTE is a Rust engine that learns from authorized observations, independently
evaluates knowledge, and retains validated models for later use. It runs without
a language model.

Compared with v1.0.1, this engine release adds:

- **A typed embedding API:** caller-owned configuration, observation sources,
  budgets, events and cancellation; separate new/open lifecycle; structured
  errors and conditional prediction or abstention.
- **Native learning and durable reuse:** observation → exact inference →
  independent evaluation → retention → prediction. Reopening a retained model
  can predict without reopening its original observation file.
- **Controlled reciprocal learning:** explicitly authorized local two-owner
  exchange, independent receiver evaluation, fresh model use, receiver-owned
  outcomes and once-only sender reconciliation. Deserialized success claims
  confer no trust.
- **Operational controls:** inspection, revocation, stopped-owner recovery,
  verified checkpoint/restore, writer exclusion, legacy-writer admission guards
  and ledger-derived counters with separate historical and current validity.

Use the native `symbiote engine` commands or embed
`symbiote_runtime::engine`. Start with the versioned
[current README](https://github.com/jacksonjp0311-gif/SYMBIOTE/blob/main/README.md),
[CLI guide](https://github.com/jacksonjp0311-gif/SYMBIOTE/blob/v1.1.2/docs/ENGINE_CLI.md)
and [embedding guide](https://github.com/jacksonjp0311-gif/SYMBIOTE/blob/v1.1.2/docs/ENGINE_EMBEDDING.md).
Choose the bundle for Windows x64, Linux x64, macOS ARM64 or macOS Intel, and
verify its matching checksums and provenance before installation.

## Supported reasoning

Validated façade acquisition covers finite, stationary affine Boolean tasks at
widths **2–8**. Width-one acquisition returns typed `Uncertain`. Predictions
remain conditional on source, family, policy, applicability and evidence.
Existing bounded graph/Moore interfaces retain their documented conditions;
none universally certifies arbitrary external-agent behavior.

Callbacks are cooperative. The engine does not provide hard preemption of
arbitrary embedded code. Checkpoint restore requires stopped ownership and an
external manifest pin; rollback discards learning after the chosen checkpoint.
Unmarked prototype owners hold without automatic migration.

## Actual source-bound qualification

The source for these records is
`8aa5f4c6ab26f7ccad53935a70414ae1765b57c6`.

| Gate | Actual result |
|---|---|
| [Source CI 40941750300](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/runs/40941750300) | All four exact-source MSRV/platform and current-stable jobs passed in attempt 1 |
| [Candidate 40945405929](https://github.com/jacksonjp0311-gif/SYMBIOTE/actions/runs/40945405929) | All six jobs passed: four installed-native lifecycles, four separate external Rust consumers and actual Linux ENOSPC on a dedicated bounded filesystem |
| Transfer compatibility reproduction | Controller closed in 15.328 s (native worker 14.828 s); two already opened cases, four directional transfers, 128 conditional fresh predictions/uses, four completed outcomes and four sender reconciliations; restart added zero reconciliations |
| Fresh staged Windows-image hour | 120 cycles; measured 3,602,094 ms; main listener live 3,594,299 ms; maximum maintenance gap 1,542 ms; native process 3,603.250 s; controller 3,606.328 s |
| Independent closed-hour replay | Passed byte/semantic and boundary audits; source watch unchanged; awake guard released; maximum observed suspension 7 ms |

The Windows hour used staged native
`0f081d8ed4f5b8e4f5b33b9d6eaff53416203f7cfeeebf99ee6511b6751d00dc`
and the separate source-matched local driver
`e442b2ec8c18dbe62235c5692fc396348ea3a30417428240251173e336292aa2`.
The local transfer consumer was
`82a97759eb475fe022c96b5a082c994c2cb9645ba0250f4f4c8a975664d88675`.
Native, CI driver, local driver and consumer images retain separate identities.
Build subjects bind Rust 1.98.1, source, lockfile, features, target, dependency
inventory and behavioral proof hashes.

These are **prepublication software records**, not anonymous public installation
results. The immutable evidence ZIP/checksum pair preserves the selected raw
corpus, readers, provenance and failures. Explicit older dependencies use the
pinned historical v1.1.1 archive; the new package does not claim to copy every
older cohort. Later public acceptance and finalization
records belong in the separate
[delivery index](https://github.com/jacksonjp0311-gif/SYMBIOTE/blob/main/experiments/v1.1.2/public-delivery.json);
they do not replace the prepublication archive. Stable promotion requires actual
anonymous public acceptance on all four platform targets, bound to the original
plan, release, source and asset digest.

## Corrective delivery work

v1.1.2 adds explicit, narrowly scoped read-only GitHub metadata authentication to
the public checker. All release-byte requests and redirects remain anonymous.
Tokens stay out of arguments, evidence and native/driver/consumer child
environments. Default anonymous metadata access remains supported. No new
workflow permission or dependency is introduced.

Relative to the failed v1.1.1 candidate, Rust algorithms, public embedding interfaces,
storage/wire schemas, task fixtures, resource limits and controls remain unchanged. Local package versions and source
stamps have their own identities; binary equality with an older version is not
claimed. The [prospective correction](https://github.com/jacksonjp0311-gif/SYMBIOTE/blob/v1.1.2/docs/CORRECTIVE_RELEASE_112.md)
records the exact changes and qualification requirements.

## Limits and preserved failures

Transferred models were retained and used for correct conditional predictions
in the controlled cases. Optimized isolated controls tied on acquisition, and
complete-operation transfer required extra work. Historical complete-cost losses
remain visible; unknown economics is not benefit credit. Reciprocal efficiency
is **NOT_DEMONSTRATED**, with zero new independent scientific samples or measured
benefit credits. No generalized intelligence, broad autonomous self-improvement
or advantage over strong isolated/cache controls is claimed.

Physical two-host operation, arbitrary adapters, network filesystems, power-loss
durability and broad generalization remain unqualified. The Windows hour is
one-host evidence; Linux ENOSPC does not qualify disk-full behavior on other
operating systems.

[v1.1.0](https://github.com/jacksonjp0311-gif/SYMBIOTE/releases/tag/v1.1.0)
and [v1.1.1](https://github.com/jacksonjp0311-gif/SYMBIOTE/releases/tag/v1.1.1)
remain permanently **FAILED** prereleases with their tags and all assets
unchanged. v1.1.1's public Windows, Linux and ARM checks passed; public Intel
stopped on metadata HTTP 403 before any download/native execution. Neither failure
is regraded as a passing current release.

The first v1.1.2 candidate 40943349352 also remains failed: its ARM native and
embedding checks passed before build provenance attestation returned a tlog-entry
404; root cause is not established. Root authorized one distinct replacement
workflow dispatch on the same frozen source, with new run-bound artifacts and
signatures. It is not a job rerun or old-image admission. Earlier candidate/study
failures remain accessible through the declared historical records. v1.0.1 is the
previous stable until actual new public acceptance and stable promotion.
