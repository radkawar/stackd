#!/usr/bin/env python3
"""Replay read-only context-key observations against explicitly configured AWS CLI credentials."""

import argparse
import datetime
import json
import pathlib
import re
import subprocess


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    require_account(args.account)
    root = pathlib.Path(__file__).resolve().parents[2]
    fixture = json.loads((root / "internal/services/iam/testdata/context_keys_aws.json").read_text())
    observations = []
    for case in fixture["custom"]:
        request = {"PolicyInputList": [json.dumps(document) for document in case["documents"]]}
        result = subprocess.run(
            ["aws", "iam", "get-context-keys-for-custom-policy", "--cli-input-json", json.dumps(request), "--output", "json", "--no-cli-pager"],
            capture_output=True, text=True, timeout=45, check=False,
        )
        observation = {"name": case["name"], "documents": case["documents"]}
        if result.returncode:
            error = re.search(r"\(([^)]+)\) when calling", result.stderr)
            if not error:
                raise RuntimeError("AWS CLI failed before returning a modeled error: " + result.stderr.strip())
            observation["error_code"] = error.group(1)
        else:
            observation["response"] = json.loads(result.stdout)
        observations.append(observation)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": "Live read-only AWS IAM custom context-key API; no resources created.",
        "custom": observations,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
