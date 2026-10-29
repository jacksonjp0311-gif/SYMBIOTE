# Verified-learning engine evolution: bounded results

**PASS_ENGINEERING_ONLY — unreleased main, 2026-10-29.**
The public v1.0.1 release and its evidence remain unchanged. This result applies
to implementation `bb1b88eaa771be5e201ccfcfe93840c6750eb9d7`, built and pinned
before targets opened. The prospective [engineering protocol](../../docs/ENGINE_EVOLUTION_PROTOCOL_002.md)
was committed first at `03dcddc060f0b701c89c6f96fd6603ae365400bf`.
This is separate from the earlier, still-unrun transfer-research Protocol 002.

The once-only workload finished in **35.015 seconds**, retaining **25,510,241
bytes including saved executables**, within 600 seconds and 128 MiB. All three
contained workload processes completed with verified cleanup and untruncated
output. No campaign retry, budget increase, old cohort/hour rerun or new
independent scientific sample was used.

| Component | Observed outcome | Boundary |
|---|---|---|
| Exact prefix reuse | All 340 distinct prefixes and 680 arm comparisons match; indexed warm reads avoid repeated history serialization/hashing | Cold construction and index memory cost more work/storage; empty-history warm timing loses slightly; this is a digest-accessor comparison |
| Optional exact rank queries | Learning/validation uses 713 rather than 28,439 GF(2) units per case | Ten source calls and 5,300 wire bytes in both arms; rank retains 785 extra bytes; different resource units are not summed |
| Frozen fresh-input reuse | Each structural arm answers 128 distinct case/input pairs correctly after restart, with the source stopped; answer cache abstains on all 128 | Four related affine cases; isolated structural learner ties; no peer artifact transfer in this observation workload |
| Native receiver feedback | One receiver adoption/use, one verified sender outcome and capability gain; restart adds no credit or source queries | One peer/context and retained-case use under operator fixture authority; strict verified economic benefits remain zero |

Cold reopening and fresh prediction consume a further 634–642 GF(2) units in
each structural arm. Receiver restart consumes 39 units despite zero source
queries. Receiver `fresh_promotions` summary remains zero because that counter
does not include this receiver role; the actual knowledge ledger records its
single promotion. These costs and counter limitations are preserved.

The Windows software checks passed 429 Rust test executions, 130 Python tool
tests, 43 release-tool tests, strict all-target Clippy and formatting. BRUTE parity
passes 6,093 cases and 20,843 checkpoints. Five Rust tests remain ignored during
ordinary discovery, including separately registered workloads. The initial
untouched parallel baseline had two native fixture failures; each passed alone
without changing limits. Their logs and the initial formatting rejection remain
in the evidence alongside later checks. A test-only concurrency gate is not a
proven explanation for the older Windows anomaly.

## Evidence and pins

- [summary.json](summary.json): source/executable pins, complete cost vectors,
  per-case results, native receiver counters and software-check account.
- [manifest.json](manifest.json): exact hashes and sizes of every archived file,
  with explicit executable omissions.
- [evidence.zip](evidence.zip): 463 original nonbinary records, 2,407,692 bytes
  before compression, 517,586 bytes compressed. Includes registration, raw
  journals, wire transcripts, commitments, process receipts, build logs, software
  logs, three independent audit receipts and their reader implementations.
- [portable-replay.json](portable-replay.json) and [portable-audits.zip](portable-audits.zip):
  all three relocated data checks passed; exact reader outputs and replay
  supervisors remain separate from the closed original workload.
- [verify_receiver.py](verify_receiver.py): the portable receiver reader. The
  original-host version and its original receipt remain unchanged in the primary archive.

| Binding | SHA256 |
|---|---|
| Registration | `89241bf8b120508053a91966e57c02f70343a1f8a3e8aafe3d8a59ec1b385409` |
| Raw workload report | `a0dcb9752c578041e745489b80198f42011fd788e377eed674e84b7d45f1cf68` |
| Native source manifest: 135 files | `8ce6bde402c8c54b0248c44f6477fbb93376d7c0706260f46bb32ddd7db8e605` |
| Evidence ZIP | `ab61624544dc89a0df920c19d27867e40e91d1d1229cf415b5d3ff182fa312ce` |
| Manifest | `a9fbdeed6fe443feb1dc02c4ddedb2e530f6bf63859f4e765319280d52a415a7` |
| Summary | `6812fb3cd2f5af4cdb0fe0157a66d7b901650fdc82b76e3a76d3d207ae46d604` |

The two receiver executable copies are omitted from this small source-evidence
archive. Their exact bytes were checked during the original audits and remain
saved locally; their hashes are public. This does not distribute or qualify a
new release binary. Tokens, private source configurations and TLS private keys
were never exported. Public certificates, local path strings, identities and
process IDs remain as evidence; their bytes are not rewritten for portability.

## Read the evidence without running the engine

Verify the ZIP and manifest against the pins above, then check every ZIP member's
size and SHA256 against `manifest.json` before extracting to a new directory.
The archive uses relative paths under `run/`, `build/`, `software/` and `audits/`.
The independent prefix and fresh-task readers accept relocated evidence:

```text
python audits/evo2-prefix-audit-bb1b88e.py --run-root run --build-proof build/build-proof.json --output NEW_PREFIX_AUDIT.json
python audits/evo2-fresh-audit-bb1b88e.py --root run --registration-sha256 89241bf8b120508053a91966e57c02f70343a1f8a3e8aafe3d8a59ec1b385409 --build-proof build/build-proof.json --output NEW_FRESH_AUDIT.json
python CHECKOUT/experiments/engine-evolution-002/verify_receiver.py --root run --output NEW_RECEIVER_AUDIT.json
```

These commands read saved data and launch no native process. Omit optional
original-host source/binary checks for the portable archive. The archived
receiver audit is its exact original-host reader; a separate portable reader
and its replay receipt are provided alongside this account. Replaying data
checks the recorded semantics and hash bindings; it is not a new experiment,
an independent clock attestation or proof of an arbitrary endpoint's honesty.
The receiver's portable replay denied access to original paths, process creation
and network APIs, with zero attempts. Original source/executable byte verification
was deliberately not requested for these data-only replays.

## What remains open

The study establishes exact component optimizations, conditional fresh source
reuse and the initial native receiver-feedback loop. It does not establish
complete economic gain, superiority over an isolated learner, unfamiliar-domain
transfer, independent-host operation, power-loss durability or broad stable
qualification. Historical whole-cost cohort losses remain losses.

Next, prospectively test a useful exchange whose independent validation can be
amortized across fresh tasks, with complete participant costs and isolated
adaptive/cache controls. [Engineering account](../../docs/ENGINE_EVOLUTION_002.md)
and [roadmap](../../docs/ROADMAP.md).
