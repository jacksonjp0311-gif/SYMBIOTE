# Upstream provenance and source classification

SYMBIOTE is a clean, independently initialized derivative. Original repositories,
branches, history, results and scientific evidence were not modified. Its Git
history starts independently to avoid importing a very large research archive.

| Source | Pinned identity |
| --- | --- |
| [BRUTE current tree](https://github.com/jacksonjp0311-gif/Brute/tree/9edbc035792ca75d3a3333b8454e5bf31c706eb1) | main `9edbc035792ca75d3a3333b8454e5bf31c706eb1` |
| [BRUTE release](https://github.com/jacksonjp0311-gif/Brute/releases/tag/v0.11.0) | v0.11.0 tag object `f97197b214eae10bb7a98277e60388f52895c5a0`, commit `d8b449d45931145ae9b177a88de3833f54301479` |
| [BGR fork provenance](https://github.com/jacksonjp0311-gif/Brute/blob/9edbc035792ca75d3a3333b8454e5bf31c706eb1/FORK.md) | BGR v0.90.0; annotated tag `bgr-v0.90.0-fork` points to `5e346dd7b8ba65d44e4f6c9e7eee5643d0cf86e8` |
| [AEFL tree](https://github.com/jacksonjp0311-gif/Agentic-Echo-Field-Location/tree/cd432ab4208bbf456ac7b932ed885f2170f680ca) | `cd432ab4208bbf456ac7b932ed885f2170f680ca`; README/spec v1.0; no release tag |

BRUTE identifies its research as BGR/Bitwork Geometric Reasoning. Its pinned
commit author is `Brute <brute@local>`; commit history and all original authorship
remain available through these links. AEFL credits James Paul Jackson; its initial
commit author is James P Jackson. Neither tree contains LICENSE, COPYING or a
declared SPDX license. We preserve that absence, not invent inherited permission.
The owner explicitly directed this derivative and retention of its algorithms;
the retained Python file is not relicensed. New SYMBIOTE source has the root MIT
license, with this explicit reference exception.

The audit inspected all paths and substantive source, parsed 410 BRUTE Python
modules, scanned 78 test files, and catalogued research plans, freezes, alternate
implementations and evidence. Exhaustive file-level decisions and original Git
blob ids are in [upstream-manifest.json](upstream-manifest.json).

| Classification | BRUTE | AEFL | Handling |
| --- | ---: | ---: | --- |
| RETAIN | 0 | 0 | No additional unmodified operational files required |
| REFACTOR | 2 | 0 | Generalist/skill-ledger concepts redesigned, not copied as Python runtime |
| PORT | 1 | 4 | Exact symbolic reasoning; independently adapted AEFL bounded telemetry concepts |
| REFERENCE | 688 | 17 | Access through pinned upstream tree and per-path Git blob ids |
| EXCLUDE | 199 | 72 | Wrappers, unused layout, branding, generated or irrelevant material excluded from active tree |

PORT `bgr90/symbolic.py` additionally has a retained byte-identical reference at
`docs/reference/brute/symbolic.py`, SHA256
`878a0ee803dec0e5095b561b3110a1c8bc99f6c664f853b137e19fad0cde92eb`.
It is the exact parity oracle; no original algorithm is edited to fit Rust.
No original study result is imported as a new SYMBIOTE result.

The REFERENCE classification includes historical result payloads: this means
they remain available upstream, not that they belong in SYMBIOTE's active tree.
The manifest never embeds those payloads. To recover any original file use the
source repository's `/blob/<pinned-commit>/<path>` link, or `git show SHA:path`.
Regenerate the manifest with `tools/audit_upstream.py --brute CHECKOUT --aefl CHECKOUT`;
it refuses checkout revisions different from these pins.

BRUTE's exact upstream Git blobs total 574,798,515 bytes (548.17 MiB), 890 files,
41 root entries. AEFL totals 969,433 bytes, 93 files, 16 root entries. Git blob
sizes are used consistently; Windows CRLF checkout sizes differ. The final
SYMBIOTE footprint is recorded in `experiments/footprint.json`, excluding `.git`,
build outputs and local state. All upstream result archives remain accessible.

## Preserved failures

[BRUTE RELEASE.json](https://github.com/jacksonjp0311-gif/Brute/blob/9edbc035792ca75d3a3333b8454e5bf31c706eb1/RELEASE.json)
reports GST sound transfer FAIL, including three false wrong-family AT
certificates. Correct-library benefits do not erase that counterexample. The
original [study-013 results](https://github.com/jacksonjp0311-gif/Brute/tree/9edbc035792ca75d3a3333b8454e5bf31c706eb1/results/study-013)
and [research plans](https://github.com/jacksonjp0311-gif/Brute/tree/9edbc035792ca75d3a3333b8454e5bf31c706eb1/experiments)
remain unchanged. Historical outcomes are not regraded by this project.
