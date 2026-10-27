"""Inventory pinned Git blobs; never import archives or rewrite upstream evidence."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

PINS = {
    "brute": ("jacksonjp0311-gif/Brute", "9edbc035792ca75d3a3333b8454e5bf31c706eb1"),
    "aefl": ("jacksonjp0311-gif/Agentic-Echo-Field-Location", "cd432ab4208bbf456ac7b932ed885f2170f680ca"),
}


def classify(name, path):
    if name == "brute":
        if path == "bgr90/symbolic.py":
            return "PORT", "Exact Rust port; original retained verbatim for parity"
        if path in {"bgr60/generalist.py", "bgr60/memory.py"}:
            return "REFACTOR", "Scoped knowledge and receipt concepts redesigned in Rust; no Python runtime"
        if path.startswith(("results/", "experiments/", "tests/", "bgr", "brute/")) or path in {"README.md", "RELEASE.json", "FORK.md", "CHANGELOG.md", "WHITEPAPER.md", "MANIFEST.sha256"} or path.startswith("docs/research/"):
            return "REFERENCE", "Immutable upstream source or historical evidence linked by commit"
        return "EXCLUDE", "Unneeded wrapper, branding, historical document or generated active-tree material"
    if path in {"core/echo_buffer.py", "core/residue_ingest.py", "core/drift_estimator.py", "models/echo_record.py"}:
        return "PORT", "Bounded telemetry concepts adapted independently in Rust"
    if path in {"README.md", "core/README.md", "core/adaptive_coupler.py", "core/coherence_estimator.py", "core/control_loop.py", "core/state_estimator.py", "core/topology_inference.py", "docs/README.md", "docs/architecture/aefl_v1_0.tex", "models/agent_state.py", "models/monitoring_tuple.py", "models/topology_state.py", "tests/README.md", "tests/test_kernel.py", "tests/test_runtime.py", "tests/test_topology.py", "telemetry/metrics.py"}:
        return "REFERENCE", "Architecture or tests inspected; similarity is not utility"
    return "EXCLUDE", "Generated state, wrappers, prompts or unrelated field instance"


def inventory(name, checkout):
    repo, pin = PINS[name]
    actual = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    if actual != pin:
        raise ValueError(f"{name}: unexpected upstream revision {actual}")
    listing = subprocess.check_output(["git", "-C", str(checkout), "ls-tree", "-r", "-z", "--long", pin])
    files = []
    for row in listing.split(b"\0"):
        if not row:
            continue
        meta, raw_path = row.split(b"\t", 1)
        _, kind, oid, size = meta.split()
        if kind != b"blob":
            raise ValueError("unexpected submodule")
        path = raw_path.decode()
        disposition, reason = classify(name, path)
        entry = dict(path=path, git_blob=oid.decode(), bytes=int(size), disposition=disposition, reason=reason)
        if path == "bgr90/symbolic.py" and name == "brute":
            blob = subprocess.check_output(["git", "-C", str(checkout), "cat-file", "blob", oid.decode()])
            entry["sha256"] = hashlib.sha256(blob).hexdigest()
            entry["retained_as"] = "docs/reference/brute/symbolic.py"
        files.append(entry)
    return dict(repository=repo, commit=pin, root_entries=len({f["path"].split("/")[0] for f in files}), file_count=len(files), tracked_bytes=sum(f["bytes"] for f in files), counts={d:sum(f["disposition"] == d for f in files) for d in ["RETAIN", "REFACTOR", "PORT", "REFERENCE", "EXCLUDE"]}, files=files)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--brute", type=Path, required=True)
    p.add_argument("--aefl", type=Path, required=True)
    args = p.parse_args()
    result = dict(schema="symbiote.upstream-manifest/1", sources=[inventory("brute", args.brute), inventory("aefl", args.aefl)])
    out = Path(__file__).resolve().parents[1] / "docs" / "upstream-manifest.json"
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({s["repository"]:{k:s[k] for k in ["file_count", "root_entries", "tracked_bytes", "counts"]} for s in result["sources"]}, indent=2))


if __name__ == "__main__":
    main()
