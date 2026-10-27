# Checkpoint release tooling

These helpers were preserved for the Grok handoff; stable v1 is not published.

- `package_stability_evidence_v4.py`: immutable pinned scanner/writer dependency.
- `package_v1_evidence_v3.py`: reviewed census/byte-revalidation adapter; requires
  stopped inputs and an external reviewed manifest digest. Read its plan first.
- `release_v1_candidate.py`: **draft**, offline/mocked validation only; no live
  public API/install/cognition qualification. Do not assume publishing is ready.

See `docs/GROK_HANDOFF.md` and the colocated source-hash handoff receipt. Preserve
these files' exact bytes: the V3 adapter checks the V4 dependency's SHA256.
