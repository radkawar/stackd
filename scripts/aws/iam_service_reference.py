#!/usr/bin/env python3
"""Capture AWS service-reference metadata for offline generation; no credentials."""

import concurrent.futures
import datetime
import gzip
import json
from pathlib import Path
import urllib.request

SOURCE = "https://servicereference.us-east-1.amazonaws.com/"
OUTPUT = Path("internal/iam/catalog/data/service_reference.json.gz")


def read_json(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return json.load(response)


def service(entry):
    return read_json(entry["url"])


def main():
    entries = read_json(SOURCE)
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        services = sorted(pool.map(service, entries), key=lambda item: item["Name"])
    output = {"source": SOURCE,
              "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "services": services}
    OUTPUT.write_bytes(gzip.compress(json.dumps(output, separators=(",", ":"), sort_keys=True).encode(), mtime=0))
    print(f"Saved {len(services)} services to {OUTPUT}")


if __name__ == "__main__":
    main()
