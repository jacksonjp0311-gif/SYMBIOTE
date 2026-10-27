"""Measure active staged Git blobs, excluding this report to avoid self-reference."""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = "experiments/footprint.json"


def main():
    listing = subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=ROOT)
    entries = []
    for item in listing.split(b"\0"):
        if not item:
            continue
        meta, path = item.split(b"\t", 1)
        path = path.decode()
        if path == REPORT:
            continue
        oid = meta.split()[1].decode()
        entries.append((oid, path))
    sizes = subprocess.check_output(["git", "cat-file", "--batch-check=%(objectsize)"], input="".join(f"{oid}\n" for oid, _ in entries).encode(), cwd=ROOT)
    active_bytes = sum(int(row) for row in sizes.splitlines())
    root_entries = len({path.split("/")[0] for _, path in entries})
    upstream_bytes = 574798515
    result = dict(schema="symbiote.footprint/1", basis="staged Git blobs; excludes report itself, .git, build outputs and local state", upstream_brute_files=890, upstream_brute_root_entries=41, upstream_brute_bytes=upstream_bytes, symbiote_files_excluding_report=len(entries), symbiote_root_entries=root_entries, symbiote_bytes_excluding_report=active_bytes, active_byte_reduction_percent=round(100*(1-active_bytes/upstream_bytes),4), root_entry_reduction_percent=round(100*(1-root_entries/41),2))
    (ROOT / REPORT).write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
