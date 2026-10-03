#!/usr/bin/env python3
"""Capture native general-purpose S3 bucket tags on one owned empty bucket."""
import argparse
from collections import Counter
import datetime
import json
import os
from pathlib import Path
import re
import signal
import time
import uuid
import xml.etree.ElementTree as ET

from aws_cli import CLITimeout, ProbeResult, raw_xml, result, run


REGION = "us-east-1"
REFERENCES = [
    "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketTagging.html",
    "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketTagging.html",
    "https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketTagging.html",
    "https://docs.aws.amazon.com/AmazonS3/latest/API/API_Tag.html",
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/CostAllocTagging.html",
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/tagging.html",
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/buckets-tagging-enable-abac.html",
]


def tag(key, value="value"):
    return {"Key": key, "Value": value}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--unicode-separators", action="store_true",
                        help="Append a focused NBSP/EM SPACE/LINE SEPARATOR run to a cleaned capture")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    previous = None
    if args.unicode_separators:
        if not args.output.exists():
            parser.error("separator supplement requires an existing cleaned capture")
        previous = json.loads(args.output.read_text())
        if not all(item.get("cleanup", {}).get("verified") is True
                   for item in [previous] + previous.get("supplemental_runs", [])):
            parser.error("all previous owned cleanup must be verified")
    elif args.output.exists():
        parser.error("output exists; choose a new path")
    environment = dict(os.environ, AWS_DEFAULT_REGION=REGION, AWS_REGION=REGION,
                       AWS_MAX_ATTEMPTS="1", AWS_RETRY_MODE="standard", AWS_PAGER="",
                       AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
    for key in list(environment):
        if key.startswith("AWS_ENDPOINT_URL"):
            del environment[key]
    bucket = "stackd-bucket-tags-" + uuid.uuid4().hex
    counts, http_counts = Counter(), Counter()
    owned = False
    capture = {
        "source": "Native AWS CLI using shared scripts/aws/aws_cli.py typed transport and XML decoder",
        "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "region": REGION, "primary_references": REFERENCES,
        "scope": "One unique owned empty general-purpose bucket; ABAC not enabled; no policies or IAM actors created",
        "bounds": {"cli_timeout_seconds": 40, "connect_timeout_seconds": 10,
                   "read_timeout_seconds": 25, "max_attempts": 1,
                   "max_cli_calls": 180, "cleanup_attempts": 3, "cleanup_poll_seconds": 2},
        "privacy": "Raw account and owned-resource identities are retained for cleanup; publish only an explicitly sanitized copy. Raw debug and credentials are never persisted.",
        "observations": [], "checks": [],
        "uncertainty": [
            "One account/region/run; observed tag order is not a contractual sorting guarantee.",
            "IAM policies, cross-account authorization, bucket ABAC and directory buckets are not exercised.",
            "CLI validation is distinguished by zero observed HTTP requests; it does not establish native rejection.",
            "Empty tag key is rejected by AWS CLI parameter validation before HTTP; native empty-key behavior remains unobserved.",
            "Character examples are not exhaustive Unicode-category coverage.",
        ],
        "cleanup": {"verified": False, "observations": [], "remaining_owned": []},
    }
    if args.unicode_separators:
        capture["case_set"] = "unicode-separators"
        capture["scope"] += "; supplement uses a new bucket, not any previous run's bucket"


    def save():
        capture["request_counts"] = {"cli_calls": dict(counts, total=sum(counts.values())),
                                     "observed_http_requests": dict(http_counts, total=sum(http_counts.values()))}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        payload = capture
        if previous is not None:
            payload = dict(previous, supplemental_runs=previous.get("supplemental_runs", []) + [payload])
        args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")

    def request(label, operation, parameters, *, service="s3api", cleanup=False) -> ProbeResult:
        if not cleanup and sum(counts.values()) >= 170:
            raise RuntimeError("Native request bound reached")
        counts[service + "." + operation] += 1
        started = time.time_ns() // 1_000_000
        statuses = []
        try:
            process = run(service, operation, parameters, environment,
                          options=["--no-paginate", "--debug", "--cli-connect-timeout", "10",
                                   "--cli-read-timeout", "25"], timeout=40)
            response = result(process, debug=True, cli_message=None)
            # Count every HTTP attempt; the shared result owns the final status.
            statuses = [int(code) for code in re.findall(
                r'"(?:GET|PUT|POST|DELETE|HEAD) [^"\r\n]* HTTP/1\.[01]" (\d{3})', process.stderr)]
            xml = raw_xml(process)
            if xml is not None:
                root = ET.fromstring(xml)
                if root.tag.rsplit("}", 1)[-1] == "Error":
                    response["error"] = {node.tag.rsplit("}", 1)[-1]: node.text or "" for node in root}
        except CLITimeout:
            response = {"code": "CLITimeout", "message": "Bounded CLI timeout; native outcome unknown"}
        http_counts[service + "." + operation] += len(statuses)
        row = {"label": label, "service": service, "operation": operation, "input": parameters,
               "request_started_ms": started, "request_finished_ms": time.time_ns() // 1_000_000,
               "observed_http_requests": len(statuses), "http_statuses": statuses, "result": response}
        (capture["cleanup"]["observations"] if cleanup else capture["observations"]).append(row)
        save()
        print(label + ": " + response["code"] + " HTTP=" + str(statuses), flush=True)
        return response

    def require(response):
        if response["code"] != "Success":
            raise RuntimeError("Required native call failed: " + response["code"])
        return response.get("output", {})

    def state(response):
        return {key: response[key] for key in ("code", "output") if key in response}

    def put_case(label, tags, previous):
        response = request(label, "put-bucket-tagging", {"Bucket": bucket, "Tagging": {"TagSet": tags}})
        current = request(label + "-get", "get-bucket-tagging", {"Bucket": bucket})
        if response["code"] not in ("Success", "CLITimeout"):
            capture["checks"].append({"label": label + "-rejection-preserves-state", "passed": state(current) == state(previous)})
            save()
        return current

    def interrupted(signum, frame):
        raise RuntimeError("Interrupted; owned cleanup required")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        identity = require(request("identity", "get-caller-identity", {}, service="sts"))
        account = identity["Account"]
        if account != args.account:
            raise RuntimeError("Native account does not match --account")
        capture["account"] = account
        capture["partition"] = identity["Arn"].split(":")[1]
        capture["authorized_account_verified"] = True
        capture["identity_relationships"] = {"account": account, "bucket": bucket,
                                             "partition": capture["partition"], "region": REGION}
        owned = True  # A timeout can leave a successfully created bucket.
        created = request("create-bucket", "create-bucket", {"Bucket": bucket})
        if created["code"] not in ("Success", "CLITimeout"):
            owned = False
        require(created)
        current = request("get-no-tagset", "get-bucket-tagging", {"Bucket": bucket})
        require(request("delete-no-tagset", "delete-bucket-tagging", {"Bucket": bucket}))
        current = request("get-after-delete-no-tagset", "get-bucket-tagging", {"Bucket": bucket})
        cases = [
            ("put-ordered", [tag("z-last", "z"), tag("a-first", "a"), tag("m-middle", "m")]),
            ("put-replacement", [tag("replacement", "only")]),
            ("put-empty-set", []),
            ("put-baseline", [tag("baseline", "preserved")]),
            ("put-duplicate-keys", [tag("duplicate", "first"), tag("duplicate", "second")]),
            ("put-case-distinct-keys", [tag("Key"), tag("key")]),
            ("put-empty-key", [tag("")]),
            ("put-empty-value", [tag("empty-value", "")]),
            ("put-key-ascii-128", [tag("k" * 128)]),
            ("put-key-ascii-129", [tag("k" * 129)]),
            ("put-value-ascii-256", [tag("value", "v" * 256)]),
            ("put-value-ascii-257", [tag("value", "v" * 257)]),
            ("put-key-bmp-128", [tag("é" * 128)]),
            ("put-key-bmp-129", [tag("é" * 129)]),
            ("put-value-bmp-256", [tag("value", "é" * 256)]),
            ("put-value-bmp-257", [tag("value", "é" * 257)]),
            ("put-key-astral-letter-64", [tag("𐐀" * 64)]),
            ("put-key-astral-letter-65", [tag("𐐀" * 65)]),
            ("put-key-astral-letter-128", [tag("𐐀" * 128)]),
            ("put-key-astral-letter-129", [tag("𐐀" * 129)]),
            ("put-value-astral-letter-128", [tag("value", "𐐀" * 128)]),
            ("put-value-astral-letter-129", [tag("value", "𐐀" * 129)]),
            ("put-value-astral-letter-256", [tag("value", "𐐀" * 256)]),
            ("put-value-astral-letter-257", [tag("value", "𐐀" * 257)]),
            ("put-reserved-aws", [tag("aws:owned")]),
            ("put-reserved-uppercase", [tag("AWS:owned")]),
            ("put-reserved-mixedcase", [tag("aWs:owned")]),
            ("put-aws-prefix-value", [tag("ordinary", "aws:owned")]),
            ("put-allowed-punctuation", [tag("space +-=._:/@", "space +-=._:/@")]),
            ("put-unicode-letters-numbers", [tag("é中١", "é中١")]),
            ("put-50-tags", [tag("key-" + str(index)) for index in range(50)]),
            ("put-51-tags", [tag("key-" + str(index)) for index in range(51)]),
        ]
        for name, character in [("comma", ","), ("exclamation", "!"), ("hash", "#"),
                                ("ampersand", "&"), ("parentheses", "()"), ("brackets", "[]"),
                                ("asterisk", "*"), ("percent", "%"), ("backslash", "\\"),
                                ("emoji", "😀"), ("combining-mark", "e\u0301"),
                                ("tab", "\t"), ("newline", "\n")]:
            cases.append(("put-character-" + name + "-key", [tag("key" + character)]))
            cases.append(("put-character-" + name + "-value", [tag("key", "value" + character)]))
        if args.unicode_separators:
            cases = [("put-separator-baseline", [tag("baseline", "preserved")])]
            for name, character in [("nbsp", "\u00a0"), ("em-space", "\u2003"), ("line-separator", "\u2028")]:
                cases.append(("put-character-" + name + "-key", [tag("key" + character)]))
                cases.append(("put-character-" + name + "-value", [tag("key", "value" + character)]))
        for label, tags in cases:
            current = put_case(label, tags, current)
        current = put_case("put-owner-baseline", [tag("owner", "preserved")], current)
        require(request("get-correct-owner", "get-bucket-tagging", {"Bucket": bucket, "ExpectedBucketOwner": account}))
        mismatch = "000000000000"
        for operation in ("get-bucket-tagging", "put-bucket-tagging", "delete-bucket-tagging"):
            parameters = {"Bucket": bucket, "ExpectedBucketOwner": mismatch}
            if operation == "put-bucket-tagging":
                parameters["Tagging"] = {"TagSet": [tag("wrong-owner", "must-not-replace")]}
            request("wrong-owner-" + operation, operation, parameters)
            checked = request("wrong-owner-" + operation + "-get", "get-bucket-tagging", {"Bucket": bucket})
            capture["checks"].append({"label": "wrong-owner-" + operation + "-preserves-state", "passed": state(checked) == state(current)})
        require(request("delete-with-tags", "delete-bucket-tagging", {"Bucket": bucket, "ExpectedBucketOwner": account}))
        request("get-after-delete-with-tags", "get-bucket-tagging", {"Bucket": bucket})
        capture["completed"] = True
    except BaseException as error:
        capture["failure"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        if owned:
            for attempt in range(3):
                request("delete-owned-bucket-" + str(attempt), "delete-bucket", {"Bucket": bucket}, cleanup=True)
                head = request("verify-head-absent-" + str(attempt), "head-bucket", {"Bucket": bucket}, cleanup=True)
                check = request("verify-tagging-bucket-absent-" + str(attempt), "get-bucket-tagging", {"Bucket": bucket}, cleanup=True)
                if head.get("http_status") == 404 and check["code"] == "NoSuchBucket":
                    owned = False
                    break
                time.sleep(2)
        capture["cleanup"]["remaining_owned"] = [bucket] if owned else []
        capture["cleanup"]["verified"] = not owned
        capture["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
    if owned:
        raise SystemExit("Owned bucket cleanup not verified; inspect capture")
    if "failure" in capture or not all(check["passed"] for check in capture["checks"]):
        raise SystemExit("Capture failed or observed a state-preservation violation; inspect capture")
    print("Capture complete; owned bucket absence verified", flush=True)


if __name__ == "__main__":
    main()
