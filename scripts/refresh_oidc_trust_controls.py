#!/usr/bin/env python3
"""Generate IAM shared-provider controls from the pinned official AWS source.

The default is offline and deterministic. --refresh-source fetches the official
table, records its content digest, and updates the reviewed source snapshot.
"""

import argparse
import datetime
import hashlib
import html
import json
from pathlib import Path
import re
import subprocess
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "iam/policy/testdata/oidc_trust_controls_source.json"
URL = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc_secure-by-default.html"


def refresh():
    body = urllib.request.urlopen(URL, timeout=30).read()
    tables = re.findall(r"<table.*?</table>", body.decode(), re.S)
    table = next(table for table in tables if "Cognito" in table)
    providers = []
    for row in re.findall(r"<tr>(.*?)</tr>", table, re.S):
        cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
        if len(cells) != 4:
            continue
        name = " ".join(html.unescape(re.sub("<[^>]+>", "", cells[0])).split()).rstrip("*")
        urls = re.findall(r"<code[^>]*>(.*?)</code>", cells[1], re.S)
        claims = re.findall(r"<code[^>]*>(.*?)</code>", cells[3], re.S)
        if len(urls) != len(claims) or not urls:
            raise ValueError("Unrecognized provider table row: " + name)
        for issuer, claim in zip(urls, claims):
            providers.append({"provider": name, "issuer": html.unescape(issuer).strip().removeprefix("https://"), "claim": html.unescape(claim).strip()})
    if len(providers) < 22:
        raise ValueError("Provider table unexpectedly shrank; review the source")
    source = {"source": URL, "captured_at": datetime.datetime.now(datetime.timezone.utc).date().isoformat(), "source_sha256": hashlib.sha256(body).hexdigest(), "providers": providers}
    SOURCE.write_text(json.dumps(source, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh-source", action="store_true")
    parser.add_argument("--check", action="store_true", help="Check generated Go data offline without modifying files")
    args = parser.parse_args()
    if args.check and args.refresh_source:
        parser.error("--check is offline and cannot be combined with --refresh-source")
    if args.refresh_source:
        refresh()
    command = ["go", "run", "./cmd/oidcgen"]
    if args.check:
        command.append("--check")
    subprocess.run(command, cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
