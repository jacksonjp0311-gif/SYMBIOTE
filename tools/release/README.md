# Checkpoint release tooling

These helpers were preserved for the Grok handoff. v1.0.0 is public, but full
stable qualification is HOLD; see `docs/V1_RELEASE_AUDIT.md`.

- `package_stability_evidence_v4.py`: immutable pinned scanner/writer dependency.
- `package_v1_evidence_v3.py`: reviewed census/byte-revalidation adapter; requires
  stopped inputs and an external reviewed manifest digest. Read its plan first.
- `release_v1_candidate.py`: **draft**, write modes remain unqualified. A live
  read attempt failed on its `creator` metadata assumption. Its bounded download
  and Windows smoke primitives were used separately for the read-only audit;
  that does not qualify publication or bypass the missing evidence gate.

See `docs/GROK_HANDOFF.md` and the colocated source-hash handoff receipt. Preserve
these files' exact bytes: the V3 adapter checks the V4 dependency's SHA256.
