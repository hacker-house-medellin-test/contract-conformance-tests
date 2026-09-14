from __future__ import annotations

import subprocess
import sys
from pathlib import PurePosixPath

TRANSIENT_DIRS = {".typespec-json-schema-validator", ".tjsv", "tmp/tjsv"}
TRANSIENT_NAMES = {"contract-ir.json", "report.json", "report.sarif", "generated.schema.json", "schema-b.json"}
FIXTURE_MARKERS = {"fixture", "fixtures", "testdata", "test-data", "snapshots"}


def tracked_files() -> list[str]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], text=True)
    return [path for path in raw.split("\0") if path]


def find_violations(paths: list[str]) -> list[str]:
    violations: list[str] = []
    for raw in paths:
        normalized = raw.replace("\\", "/")
        path = PurePosixPath(normalized)
        parts = {part.lower() for part in path.parts}
        if parts & FIXTURE_MARKERS:
            continue
        if any(normalized == d or normalized.startswith(f"{d}/") for d in TRANSIENT_DIRS):
            violations.append(raw)
            continue
        if path.name.lower() in TRANSIENT_NAMES:
            violations.append(raw)
    return sorted(set(violations))


def main() -> int:
    violations = find_violations(tracked_files())
    if not violations:
        print("generated evidence hygiene: ok")
        return 0
    print("generated evidence hygiene failed", file=sys.stderr)
    for path in violations:
        print(f"- {path}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
