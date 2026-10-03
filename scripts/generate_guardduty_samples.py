#!/usr/bin/env python3
"""Pin immutable GuardDuty sample templates from the retained native capture."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "testdata/aws/guardduty/native-complete.samples.json"
OUTPUT = ROOT / "internal/services/guardduty/sample_templates.json.gz"


def generated():
    capture = json.loads(SOURCE.read_text())
    templates = []
    for finding in capture["findings"]:
        # Native IDs distinguish resource variants of the same finding type.
        # Keep every variant and pin the exact retained wire payload.
        payload = json.dumps(finding, sort_keys=True, separators=(",", ":")).encode()
        templates.append({"revision": hashlib.sha256(payload).hexdigest(), "finding": finding})
    templates.sort(key=lambda item: (item["finding"]["type"], item["finding"]["id"]))
    document = {"schema": 1, "source": str(SOURCE.relative_to(ROOT)),
                "model": capture["sdk"], "templates": templates}
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return gzip.compress(raw, mtime=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    content = generated()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_bytes() != content:
            raise SystemExit("GuardDuty sample corpus is stale")
    else:
        OUTPUT.write_bytes(content)


if __name__ == "__main__":
    main()
