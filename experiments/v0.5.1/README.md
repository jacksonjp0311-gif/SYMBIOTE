# v0.5.1 local qualification evidence

**S5 passed one bounded same-PC software/continuity campaign.** This is not a
research cohort or stable v1.0 qualification. Independent-host validation stays
`OPEN_UNAVAILABLE`. See the [methods, results and limitations](../../docs/LOCAL_QUALIFICATION_V051.md)
and the frozen [local protocol](../../docs/STABILITY_CAMPAIGN_PROTOCOL.md).

## Recorded result

| Item | S5 |
| --- | --- |
| Candidate source | `cd792651d77765532cf39f9d8307ca3bcbb7e0fb` |
| Software-gate source fingerprint | `1b1d2e23dd930ef1b7101409ae5c82bb3277992abe2855d82a50955ab3e4157b` |
| Registration SHA256 | `656a6ad12be1aaee32a5de03e04603fd52bdf21142ec07dcc1dfda9a5569333e` |
| Campaign report SHA256 | `fb9d090970d11b8d58dea31e67adbaf37e6557ffb68f29132ec4d87094aced4d` |
| Independent audit SHA256 | `627f8d59febba02f18129780352dfdaf0c7709ac597f42573e45aec32f97b40a` |
| Campaign elapsed / root commands | 83.969 seconds / 66 |

The separate default gate passed 292 native test executions, 53 Python tests and
6,093 BRUTE parity cases. The campaign explicitly selected one ignored continuity
test and repeated 16 already-existing named regressions. These repetitions do
not add new test definitions or independent research samples.

The native phase completed 24 cycles using the same three-bit affine and
three-node graph fixtures. It retained two evaluated models and two owner
identities across 26 native listener ready instances: 25 graceful stops and one
owned kill-and-wait. Its 99 unique wire keys comprise 96 read/predict requests and
three durable submissions; one exact retry produced 100 client attempts.
Read/predict replies are not durable cached receipts.

Four reviewed rotations deliberately reused two preprovisioned server leaves;
the client kept its separate leaf. Two denial/regrant pairs opened no listener
while denied. The cycle-10 genuinely committed quarantine lost its first reply,
survived a real owned service crash and replayed its exact original receipt.
Midpoint verified backup/restore required explicit relocation review and rejected
that pending third candidate without new promotion. Both original models and
their exact knowledge bytes survived. This proves neither automatic renewal nor
new learning from the quarantine.

The saved independent audit reports
`PASS_BOUNDED_LOCAL_SOFTWARE_AND_CONTINUITY`. It recomputed raw command/TLS/report
bindings, owner and learning histories, predictions, certificate pins, quarantine
idempotency, relocation and final inventory without running another campaign.
The audit was performed on this same PC and cannot close the second-host gate.

## Preserved attempts

| Attempt | Outcome | Cause |
| --- | --- | --- |
| S3 | **HOLD**, 49.156 s / 65 root commands | Invalid Windows output filename from the namespaced test label; ignored native test not launched |
| S4 | **HOLD**, 82.562 s / 66 root commands | Native 24-cycle phase PASS; consumer rejected the legitimate earlier policy guard because it required a `restor` substring |
| S5 | **PASS**, 83.969 s / 66 root commands | Safe output names and strict policy/restore guard verification |

Only the two Python campaign/verifier test files were corrected between these
attempts; the protocol, bounds and native continuity producer were unchanged.
Each attempt has its own frozen source stamp and registration. S4's later
read-only corrected-verifier diagnostic is not a regrade; its original HOLD and
all original bytes remain preserved. The [v0.5 research primary](../v0.5/README.md)
also remains HOLD and is a separate experiment.

## Release asset

| Asset | Contents | Publication |
| --- | --- | --- |
| `SYMBIOTE-v0.5.1-local-qualification.tar.gz` | Original S3/S4 HOLD and S5 PASS evidence, frozen bindings, raw outputs, native continuity owner histories and independent review receipts | Built and byte-verified |
| `EVIDENCE_SHA256SUMS` | Final published evidence-asset checksum | Archive checksum |

Download from the
[v0.5.1 release page](https://github.com/jacksonjp0311-gif/SYMBIOTE/releases/tag/v0.5.1)
and verify its published checksum before extraction. The archive is
18,093,152 bytes with 1,752 members including `MANIFEST.json`;
SHA256: `52fca539bac260bbeae30f87168cea9b3d899e3afc12a9de12f64ae58dfe7de0`. Its per-file manifest SHA256 is
`f532413c97b0785c1421147bd16ea9219a49355116239aa075d18ef9486788a0`. See the [asset receipt](evidence-archive.json).
The full extracted tree matched its sources byte for byte. Use a short extraction
directory on Windows; the validated extraction paths were at most 226 characters. Preserve original reports,
registrations and paths inside their bytes; do not edit them to fit a new local
directory. Public owner IDs/certificates and allowlisted state are evidence, not
authorization to activate a network service. Private keys are excluded.

For a new local reproduction, follow the [fresh source-stamped Cargo build and
register/run instructions](../../docs/LOCAL_QUALIFICATION_V051.md#reproduce-a-new-local-campaign).
The runner requires an absent OS-temporary artifact directory, pins the actual
built executables and prevents automatic reuse of a started registration. A
downloaded release CLI alone does not supply the prebuilt integration executables
or authenticate their embedded native path. The reproduction uses a new
registration; it must not overwrite or be presented as the historical S5 run.

The limits remain 600 seconds, 96 root commands, 64 MiB evidence and a 1 MiB final
report reserve, with 180 seconds for the ignored continuity command. Cancellation,
timeout, missing evidence or an unexpected failure is HOLD. This finite local
result does not establish long-term reliability, generalization, collaborator
selection gains, autonomous self-improvement or stable v1.0.

## Packaging failures remain recorded

The initial collector held on a public CONNECT consent label, then a read-only
plan held when a Python provenance docstring was parsed as whole JSON. The next
archive extraction held on a 282-character Windows path. Original logs,
configurations and failure receipts are retained; the failed partial archive is
preserved locally with its digest rather than duplicated inside this archive.
The final collector narrowly recognizes the exact public consent context and
empty captured output logs, retains strict ordinary JSON/JSONL and credential
scanning, and uses a short extraction path. These packaging corrections do not
modify the qualified runtime, protocol, scientific evidence or campaign results.
