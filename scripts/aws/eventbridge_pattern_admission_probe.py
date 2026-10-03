#!/usr/bin/env python3
"""Compare wildcard admission and matching with one owned EventBridge rule."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime
import json
import os
from pathlib import Path
import random
import uuid

from aws_cli import call, observe, require_account


def cases():
    for count in [1, 5, 10, 15, 20, 25, 30, 40, 50, 75, 100]:
        yield f"stars-{count}", {"detail": {"value": [{"wildcard": "*a" * count}]}}
    for count in [1, 5, 10, 25, 50, 100]:
        yield f"repeated-sequence-{count}", {"detail": {"value": [{"wildcard": "*" + "abc" * count + "*"}]}}
    for count in [1, 5, 10, 20, 30, 50, 80]:
        for shared in [True, False]:
            patterns = [{"wildcard": "*a" + str(i) + "*" if shared else str(i) + "*x"} for i in range(count)]
            yield f"alternatives-{'shared' if shared else 'disjoint'}-{count}", {"detail": {"value": patterns}}
    for count in [5, 15, 30, 50]:
        yield f"negated-stars-{count}", {"detail": {"value": [{"anything-but": {"wildcard": "*a" * count}}]}}


def boundary_cases():
    def field(items):
        return {"detail": {"value": items}}

    for count in range(4, 8):
        for tail in ["", "*"]:
            yield f"boundary-stars-{count}-tail-{bool(tail)}", field([{"wildcard": "*a" * count + tail}])
    for count in range(6, 11):
        yield f"boundary-repeated-{count}", field([{"wildcard": "*" + "abc" * count + "*"}])
    for count in range(1, 6):
        yield f"boundary-shared-{count}", field([{"wildcard": "*a" + str(i) + "*"} for i in range(count)])
    for count in range(8, 13):
        values = [str(i) + "*x" for i in range(count)]
        yield f"boundary-disjoint-{count}", field([{"wildcard": v} for v in values])
        yield f"boundary-negated-set-{count}", field([{"anything-but": {"wildcard": values}}])
        yield f"boundary-no-stars-{count}", field([{"wildcard": str(i)} for i in range(count)])
        yield f"boundary-or-{count}", {"detail": {"$or": [{"value": [{"wildcard": v}]} for v in values]}}
        yield f"boundary-fields-{count}", {"detail": {str(i): [{"wildcard": "*a*"}] for i in range(count)}}
    for count in [5, 10, 20]:
        yield f"boundary-duplicate-{count}", field([{"wildcard": "*a*"}] * count)
        yield f"boundary-negated-shared-{count}", field([{"anything-but": {"wildcard": ["*a" + str(i) + "*" for i in range(count)]}}])
        yield f"boundary-utf8-{count}", field([{"wildcard": "*" + "🙂" * count + "*"}])
    expensive = [{"wildcard": "*a" * 8}]
    for kind in [False, True, "literal"]:
        first = [{"exists": kind}] if isinstance(kind, bool) else [kind]
        yield f"boundary-before-{kind}", {"aaa": first, "zzz": expensive}
        yield f"boundary-after-{kind}", {"aaa": expensive, "zzz": first}
    yield "boundary-or-different-prefix", {"$or": [{"a": [str(i)], "z": [{"wildcard": str(i) + "*"}]} for i in range(11)]}
    yield "boundary-or-shared-prefix", {"$or": [{"a": ["same"], "z": [{"wildcard": str(i) + "*"}]} for i in range(11)]}
    for count in [2, 3, 4, 10, 11]:
        yield f"boundary-identical-stars-{count}", field([{"wildcard": "*a*"}] * count)
        yield f"boundary-identical-literal-{count}", field([{"wildcard": "literal"}] * count)
        yield f"boundary-identical-negated-{count}", field([{"anything-but": {"wildcard": "*a*"}}] * count)
        yield f"boundary-negated-identical-list-{count}", field([{"anything-but": {"wildcard": ["*a*"] * count}}])
        yield f"boundary-or-common-wildcard-{count}", {"a": [{"wildcard": "*a*"}], "$or": [{"z": [str(i)]} for i in range(count)]}
    for count in [2, 3, 4, 5]:
        yield f"boundary-grouped-shared-{count}", field([{"anything-but": {"wildcard": ["*a" + str(i) + "*" for i in range(count)]}}])
    for count in [3, 4, 5]:
        patterns = ["*a" + str(i) + "*" for i in range(count)]
        yield f"boundary-negated-order-{count}", field([
            {"anything-but": {"wildcard": patterns}}, {"anything-but": {"wildcard": patterns[::-1]}}])
        yield f"boundary-negated-scalar-array-{count}", field([
            {"anything-but": {"wildcard": "*a*"}}, *[{"anything-but": {"wildcard": ["*a*"]}} for _ in range(count-1)]])
    pool = ["a*bc", "a*bb", "ab*b*", "*aba*", "*ab*ad", "*a*a*a", "*abcabc*", "a\\*b*", "a*\\*", "a*\\\\", "ab*c", "abc*d", "*🙂*", "*éé*", "literal"]
    rng = random.Random(1961)
    for index in range(30):
        patterns = rng.choices(pool, k=rng.randint(2, 8))
        yield f"boundary-mixture-{index}", field([{"wildcard": pattern} for pattern in patterns])
        yield f"boundary-mixture-negated-{index}", field([{"anything-but": {"wildcard": patterns}}])
    identities = [
        ("review-identity-cidr-normalized", {"cidr": "10.0.0.0/24"}, {"cidr": "10.0.0.1/24"}),
        ("review-identity-negated-set-order", {"anything-but": ["a", "b"]}, {"anything-but": ["b", "a"]}),
        ("review-identity-negated-scalar-list", {"anything-but": "a"}, {"anything-but": ["a"]}),
        ("review-identity-numeric-literal-equals", 1, {"numeric": ["=", 1]}),
    ]
    for operator in ["prefix", "suffix", "equals-ignore-case", "wildcard"]:
        identities.append(("boundary-negated-identity-" + operator,
            {"anything-but": {operator: "a"}}, {"anything-but": {operator: ["a"]}}))
    for name, left, right in identities:
        yield name, {"$or": [{"a": [term], "z": [{"wildcard": str(i)} for i in range(offset, offset+6)]}
                             for term, offset in [(left, 0), (right, 6)]]}


def read_only(account):
    env = dict(os.environ, AWS_DEFAULT_REGION="us-east-1", AWS_REGION="us-east-1", AWS_MAX_ATTEMPTS="2")
    require_account(account, env)
    path = Path(".stackd/probes/eventbridge/pattern_admission.json")
    fixture = json.loads(path.read_text())
    existing = {row["case"] for row in fixture["observations"]}
    event = fixture["observations"][0]["event"]
    fixture["followup_scope"] = "Read-only TestEventPattern boundary cases; no AWS resources created or changed"

    def capture(item):
        label, pattern = item
        pattern = json.dumps(pattern, separators=(",", ":"), ensure_ascii=False)
        matching = observe("events", "test-event-pattern", {"EventPattern": pattern, "Event": event}, env)
        return {"case": label, "pattern": pattern, "event": event, "matching": matching}

    with ThreadPoolExecutor(max_workers=6) as pool:
        for row in pool.map(capture, [item for item in boundary_cases() if item[0] not in existing]):
            fixture["observations"].append(row)
            path.write_text(json.dumps(fixture, indent=2) + "\n")
            print(row["case"] + ": " + row["matching"]["code"], flush=True)


def main(account):
    env = dict(os.environ, AWS_DEFAULT_REGION="us-east-1", AWS_REGION="us-east-1")
    require_account(account, env)
    name = "stackd-pattern-admission-" + uuid.uuid4().hex[:10]
    path = Path(".stackd/probes/eventbridge/pattern_admission.json")
    fixture = {"retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "scope": "One owned custom bus and rule, no targets or event deliveries", "observations": [], "cleanup": False}
    event = json.dumps({"version": "0", "id": "00000000-0000-4000-8000-000000000001", "detail-type": "probe",
                        "source": "stackd.pattern.probe", "account": "111111111111", "time": "2026-09-13T00:00:00Z",
                        "region": "us-east-1", "resources": [], "detail": {"value": "a" * 512}})

    def save():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(fixture, indent=2) + "\n")

    created = False
    try:
        call("events", "create-event-bus", {"Name": name}, env)
        created = True
        for label, pattern in cases():
            pattern = json.dumps(pattern, separators=(",", ":"))
            admission = observe("events", "put-rule", {"EventBusName": name, "Name": "pattern", "EventPattern": pattern}, env)
            matching = observe("events", "test-event-pattern", {"EventPattern": pattern, "Event": event}, env)
            fixture["observations"].append({"case": label, "pattern": pattern, "event": event, "admission": admission, "matching": matching})
            save()
            print(label + ": " + admission["code"] + " / " + matching["code"], flush=True)
    finally:
        if created:
            call("events", "delete-rule", {"EventBusName": name, "Name": "pattern"}, env)
            call("events", "delete-event-bus", {"Name": name}, env)
        fixture["cleanup"] = True
        save()
        print("cleanup: True", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--read-only", action="store_true")
    args = parser.parse_args()
    if args.read_only:
        read_only(args.account)
    else:
        main(args.account)
