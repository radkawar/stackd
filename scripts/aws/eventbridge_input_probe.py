#!/usr/bin/env python3
"""Capture EventBridge target input admission and real SQS delivery bodies."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime
import json
import os
from pathlib import Path
import time
import uuid

from aws_cli import call, observe


INPUT_FIELDS = ("Input", "InputPath", "InputTransformer")
DETAIL = {"text": "hello", "number": 42, "flag": True, "nothing": None,
          "object": {"first": "one", "second": 2}, "array": ["one", "two", {"x": 3}],
          "items": [{"name": "first"}, {"name": "second"}], "hyphen-key": "dash",
          "under_score": "under", "slash/key": "slash", "dot.key": "dot",
          "quoted": 'say "hello"', "escaped": "line\nslash\\tab\tend"}


def cases():
    rows = []

    def add(name, target_input):
        rows.append({"case": name, "target_input": target_input})

    def transform(name, template, paths=None):
        value = {"InputTemplate": template}
        if paths is not None:
            value["InputPathsMap"] = paths
        add(name, {"InputTransformer": value})

    add("original", {})
    for name, value in [("object", '{ "fixed": true }'), ("array", '[1,"two"]'),
                        ("string", '"constant"'), ("number", '17'), ("null", 'null'),
                        ("invalid", 'not-json'), ("empty", '')]:
        add("input-" + name, {"Input": value})
    paths = [("root", "$"), ("object", "$.detail.object"), ("array", "$.detail.array"),
             ("string", "$.detail.text"), ("number", "$.detail.number"), ("null", "$.detail.nothing"),
             ("missing", "$.detail.missing"), ("index", "$.detail.array[1]"),
             ("nested-index", "$.detail.items[1].name"), ("array-wildcard", "$.detail.items[*].name"),
             ("object-wildcard", "$.detail.object.*"), ("hyphen", "$.detail.hyphen-key"),
             ("underscore", "$.detail.under_score"), ("slash", "$.detail.slash/key"),
             ("bracket-single", "$['detail']['text']"), ("bracket-double", '$["detail"]["text"]'),
             ("bracket-dot-key", "$.detail['dot.key']"), ("recursive", "$..text"),
             ("negative-index", "$.detail.array[-1]"), ("slice", "$.detail.array[0:2]"),
             ("invalid-root", "detail.text"), ("empty", "")]
    for name, path in paths:
        add("path-" + name, {"InputPath": path})
    for name, path in paths:
        if name in {"root", "missing", "index", "array-wildcard", "object-wildcard", "hyphen",
                    "underscore", "slash", "bracket-single", "bracket-double", "bracket-dot-key",
                    "recursive", "negative-index", "slice", "invalid-root", "empty"}:
            transform("map-" + name, '{"value":<value>}', {"value": path})
    transform("typed-values", '{"text":<text>,"number":<number>,"flag":<flag>,"nothing":<nothing>,"object":<object>,"array":<array>}',
              {name: "$.detail." + name for name in ["text", "number", "flag", "nothing", "object", "array"]})
    transform("quoted-values", '{"text":"<text>","number":"<number>","object":"<object>","array":"<array>"}',
              {name: "$.detail." + name for name in ["text", "number", "object", "array"]})
    transform("embedded-values", '"text=<text>; object=<object>; array=<array>"',
              {name: "$.detail." + name for name in ["text", "object", "array"]})
    transform("escaped-string", '{"value":<value>}', {"value": "$.detail.escaped"})
    transform("quoted-string", '{"value":<value>}', {"value": "$.detail.quoted"})
    transform("embedded-quoted-string", '"prefix <value> suffix"', {"value": "$.detail.quoted"})
    transform("escaped-template", '"prefix \\"<value>\\" suffix"', {"value": "$.detail.text"})
    transform("missing-string", '"before <missing> after"', {"missing": "$.detail.missing"})
    transform("missing-object", '{"before":1,"missing":<missing>,"after":2}', {"missing": "$.detail.missing"})
    transform("missing-array", '[1,<missing>,2]', {"missing": "$.detail.missing"})
    transform("undefined-string", '"before <undefined> after"')
    transform("undefined-object", '{"value":<undefined>}')
    transform("placeholder-key", '{"<key>":"value"}', {"key": "$.detail.text"})
    transform("standalone-object", '<value>', {"value": "$.detail.object"})
    transform("standalone-string", '<value>', {"value": "$.detail.text"})
    transform("template-plain", 'hello <value>', {"value": "$.detail.text"})
    transform("template-multiline", '"first <value>"\n"second <value>"', {"value": "$.detail.text"})
    transform("template-empty", '')
    transform("template-null", 'null')
    transform("template-array", '["fixed",<value>]', {"value": "$.detail.number"})
    transform("reserved", '{"name":<aws.events.rule-name>,"arn":<aws.events.rule-arn>,"ingested":<aws.events.event.ingestion-time>,"event":<aws.events.event>,"full":<aws.events.event.json>}')
    transform("reserved-string", '"<aws.events.rule-name> triggered <aws.events.rule-arn>"')
    transform("reserved-event-string", '"event <aws.events.event.json>"')
    transform("reserved-unknown", '{"value":<aws.events.unknown>}')
    transform("reserved-map-key", '{"value":<aws.events.rule-name>}', {"aws.events.rule-name": "$.detail.text"})
    transform("invalid-map-key", '{"value":<bad.key>}', {"bad.key": "$.detail.text"})
    add("input-and-path", {"Input": '{}', "InputPath": "$.detail"})
    add("input-and-transformer", {"Input": '{}', "InputTransformer": {"InputTemplate": '{}'}})
    add("path-and-transformer", {"InputPath": "$.detail", "InputTransformer": {"InputTemplate": '{}'}})
    add("all-input-options", {"Input": '{}', "InputPath": "$.detail", "InputTransformer": {"InputTemplate": '{}'}})
    rows += [
        {"case": "denied-static-input", "target_access": "denied", "target_input": {"Input": '{"attempted":"static"}'}},
        {"case": "denied-transformer", "target_access": "denied", "target_input": {"InputTransformer": {
            "InputPathsMap": {"value": "$.detail.text"}, "InputTemplate": '{"attempted":<value>}'}}},
        {"case": "missing-static-input", "target_access": "missing", "target_input": {"Input": '{"attempted":"missing"}'}},
    ]
    for name, template, paths in [
        ("structured-embedded-object", '{"value":"prefix <value> suffix"}', {"value": "$.detail.object"}),
        ("structured-missing-array", '{"value":[<missing>]}', {"missing": "$.detail.missing"}),
        ("root-array-missing-object", '[{"value":<missing>}]', {"missing": "$.detail.missing"}),
        ("structured-embedded-quoted", '{"value":"prefix <value> suffix"}', {"value": "$.detail.quoted"}),
        ("structured-embedded-escaped", '{"value":"prefix <value> suffix"}', {"value": "$.detail.escaped"}),
        ("root-embedded-escaped", '"prefix <value> suffix"', {"value": "$.detail.escaped"}),
        ("reserved-root-event", '<aws.events.event.json>', {}),
        ("reserved-array-event", '[<aws.events.event.json>]', {}),
    ]:
        rows.append({"case": name, "target_input": {"InputTransformer": {
            "InputTemplate": template, "InputPathsMap": paths}}})
    for name in ["text", "object", "array", "nothing"]:
        transform("root-array-typed-" + name, '[<value>]', {"value": "$.detail." + name})
    for name in ["number", "nothing", "missing"]:
        transform("root-bare-typed-" + name, '<value>', {"value": "$.detail." + name})
    for row in rows:
        if row["case"] in {"invalid-map-key", "reserved-map-key", "template-empty"}:
            row["validation_owner"] = "generated-model"
    return rows


def main(account, followup=False):
    env = dict(os.environ, AWS_DEFAULT_REGION="us-east-1", AWS_REGION="us-east-1", AWS_MAX_ATTEMPTS="2")
    if call("sts", "get-caller-identity", env=env)["Account"] != account:
        raise RuntimeError("Caller account differs from --account")
    prefix = "stackd-event-input-" + uuid.uuid4().hex[:10]
    destination = Path(".stackd/probes/eventbridge/inputs.json")
    fixture = {"retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "documentation": ["https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-transform-target-input.html",
                                 "https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_InputTransformer.html",
                                 "https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_Target.html"],
               "scope": "Uniquely owned custom bus, scenario rules and SQS queues; no existing resources changed",
               "observations": cases(), "updates": [], "cleanup": False}
    observations = fixture["observations"]
    if followup:
        fixture = json.loads(destination.read_text())
        fixture["followup_retrieved_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        fixture["cleanup"] = False
        existing = {row["case"] for row in fixture["observations"]}
        observations = [row for row in cases() if row["case"] not in existing]
        fixture["observations"].extend(observations)
    prior_cleanup = fixture.get("cleanup_details", {})
    if initial := fixture.pop("initial_cleanup", None):
        prior_cleanup = {"rules_deleted": prior_cleanup.get("rules_deleted", 0) + initial["rules_deleted"],
                         "queues_deleted": prior_cleanup.get("queues_deleted", 0) + initial["queues_deleted"],
                         "buses_deleted": int(prior_cleanup.get("bus_deleted", False)) + int(initial["bus_deleted"])}
    rules, queues, registered = {}, {}, set()
    bus = False

    def save():
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(fixture, indent=2) + "\n")

    def queue(name, allow_events=True):
        url = call("sqs", "create-queue", {"QueueName": prefix + "-" + name}, env)["QueueUrl"]
        queues[name] = {"url": url}
        arn = call("sqs", "get-queue-attributes", {"QueueUrl": url, "AttributeNames": ["QueueArn"]}, env)["Attributes"]["QueueArn"]
        queues[name]["arn"] = arn
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnLike": {"aws:SourceArn": f"arn:aws:events:us-east-1:{account}:rule/{prefix}/*"}}}]}
        if allow_events:
            call("sqs", "set-queue-attributes", {"QueueUrl": url, "Attributes": {"Policy": json.dumps(policy)}}, env)
        return queues[name]

    def provision(item):
        index, row = item
        name = f"case-{index:03d}"
        rules[name] = call("events", "put-rule", {"Name": name, "EventBusName": prefix,
            "EventPattern": json.dumps({"source": [prefix], "detail": {"case": [row["case"]]}})}, env)["RuleArn"]
        target_arn = queue(name, row.get("target_access") != "denied")["arn"]
        if row.get("target_access") == "missing":
            target_arn += "-missing"
        row["target_arn"] = target_arn
        target = {"Id": "target", "Arn": target_arn, "DeadLetterConfig": {"Arn": queues["dlq"]["arn"]},
                  "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}, **row["target_input"]}
        row["context"] = {"rule_name": name, "rule_arn": rules[name]}
        row["admission"] = observe("events", "put-targets", {"Rule": name, "EventBusName": prefix, "Targets": [target]}, env)
        row["admission_source"] = "aws-cli" if row["admission"]["code"] == "ParamValidation" else "aws"
        if row["admission"]["code"] == "Success" and not row["admission"]["output"]["FailedEntryCount"]:
            registered.add(name)
            stored = call("events", "list-targets-by-rule", {"Rule": name, "EventBusName": prefix}, env)["Targets"][0]
            row["listed_input"] = {key: stored[key] for key in INPUT_FIELDS if key in stored}
        return row

    def receive(row):
        response = call("sqs", "receive-message", {"QueueUrl": queues[row["context"]["rule_name"]]["url"],
            "WaitTimeSeconds": 1, "MaxNumberOfMessages": 10, "MessageAttributeNames": ["All"]}, env)
        if response.get("Messages"):
            message = response["Messages"][0]
            row["delivery"] = {"kind": "target", "body": message["Body"], "attributes": message.get("MessageAttributes", {})}
            if row["case"] == "reserved":
                row["context"]["ingestion_time"] = json.loads(message["Body"])["ingested"]
        return row

    try:
        call("events", "create-event-bus", {"Name": prefix}, env)
        bus = True
        queue("dlq")
        with ThreadPoolExecutor(max_workers=6) as pool:
            for row in pool.map(provision, enumerate(observations, start=len(fixture["observations"]) - len(observations))):
                print(row["case"] + ": " + row["admission"]["code"], flush=True)
        save()
        time.sleep(8)
        pending = [row for row in observations if row["context"]["rule_name"] in registered]
        for start in range(0, len(pending), 10):
            batch = pending[start:start + 10]
            entries = [{"EventBusName": prefix, "Source": prefix, "DetailType": "input-probe",
                        "Time": "2026-01-02T03:04:05Z", "Detail": json.dumps(dict(DETAIL, case=row["case"]))} for row in batch]
            response = call("events", "put-events", {"Entries": entries}, env)
            if response["FailedEntryCount"]:
                raise RuntimeError("Owned event admission failed: " + json.dumps(response))
            for row, result in zip(batch, response["Entries"]):
                row["event"] = {"version": "0", "id": result["EventId"], "detail-type": "input-probe", "source": prefix,
                    "account": account, "time": "2026-01-02T03:04:05Z", "region": "us-east-1", "resources": [],
                    "detail": dict(DETAIL, case=row["case"])}
        save()
        deadline = time.monotonic() + 90
        while pending and time.monotonic() < deadline:
            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(receive, pending))
            response = call("sqs", "receive-message", {"QueueUrl": queues["dlq"]["url"], "WaitTimeSeconds": 1,
                "MaxNumberOfMessages": 10, "MessageAttributeNames": ["All"]}, env)
            for message in response.get("Messages", []):
                attributes = message.get("MessageAttributes", {})
                rule_arn = attributes.get("RULE_ARN", {}).get("StringValue")
                for row in pending:
                    if row["context"]["rule_arn"] == rule_arn:
                        row["delivery"] = {"kind": "dlq", "body": message["Body"], "attributes": attributes}
                call("sqs", "delete-message", {"QueueUrl": queues["dlq"]["url"], "ReceiptHandle": message["ReceiptHandle"]}, env)
            save()
            finished = [row for row in pending if "delivery" in row]
            for row in finished:
                print(row["case"] + ": " + row["delivery"]["kind"] + " " + repr(row["delivery"]["body"][:120]), flush=True)
            pending = [row for row in pending if "delivery" not in row]
        if pending:
            for row in pending:
                row["delivery"] = {"kind": "unobserved", "window_seconds": 90}
            save()
        if fixture["updates"]:
            fixture["capture_complete"] = True
            return
        name = "updates"
        rules[name] = call("events", "put-rule", {"Name": name, "EventBusName": prefix,
            "EventPattern": json.dumps({"source": [prefix], "detail": {"case": [name]}})}, env)["RuleArn"]
        target_arn = queue(name)["arn"]
        for target_input in [{"Input": '{"fixed":true}'}, {"InputPath": "$.detail.object"},
                             {"InputTransformer": {"InputPathsMap": {"value": "$.detail.text"}, "InputTemplate": '"<value>"'}}, {}]:
            admission = observe("events", "put-targets", {"Rule": name, "EventBusName": prefix,
                "Targets": [{"Id": "target", "Arn": target_arn, **target_input}]}, env)
            registered.add(name)
            stored = call("events", "list-targets-by-rule", {"Rule": name, "EventBusName": prefix}, env)["Targets"][0]
            fixture["updates"].append({"target_input": target_input, "admission": admission,
                "listed_input": {key: stored[key] for key in INPUT_FIELDS if key in stored}})
            save()
        time.sleep(8)
        detail = dict(DETAIL, case=name)
        response = call("events", "put-events", {"Entries": [{"EventBusName": prefix, "Source": prefix,
            "DetailType": "input-probe", "Time": "2026-01-02T03:04:05Z", "Detail": json.dumps(detail)}]}, env)
        if response["FailedEntryCount"]:
            raise RuntimeError("Owned update event admission failed: " + json.dumps(response))
        update = fixture["updates"][-1]
        update["event"] = {"version": "0", "id": response["Entries"][0]["EventId"], "detail-type": "input-probe",
            "source": prefix, "account": account, "time": "2026-01-02T03:04:05Z", "region": "us-east-1",
            "resources": [], "detail": detail}
        update["context"] = {"rule_name": name, "rule_arn": rules[name]}
        deadline = time.monotonic() + 30
        while "delivery" not in update and time.monotonic() < deadline:
            response = call("sqs", "receive-message", {"QueueUrl": queues[name]["url"], "WaitTimeSeconds": 2}, env)
            if response.get("Messages"):
                update["delivery"] = {"kind": "target", "body": response["Messages"][0]["Body"], "attributes": {}}
        if "delivery" not in update:
            raise RuntimeError("Final replacement target delivery was not observed")
        fixture["capture_complete"] = True
    finally:
        errors = []

        def cleanup(service, operation, parameters):
            try:
                response = call(service, operation, parameters, env)
                if response.get("FailedEntryCount"):
                    errors.append(json.dumps(response))
            except RuntimeError as error:
                errors.append(str(error))

        for name in registered:
            cleanup("events", "remove-targets", {"Rule": name, "EventBusName": prefix, "Ids": ["target"]})
        for name in rules:
            cleanup("events", "delete-rule", {"Name": name, "EventBusName": prefix})
        if bus:
            cleanup("events", "delete-event-bus", {"Name": prefix})
        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(lambda owned: cleanup("sqs", "delete-queue", {"QueueUrl": owned["url"]}), queues.values()))
        fixture["cleanup"] = not errors
        fixture["cleanup_details"] = {
            "rules_deleted": prior_cleanup.get("rules_deleted", 0) + len(rules),
            "queues_deleted": prior_cleanup.get("queues_deleted", 0) + len(queues),
            "buses_deleted": prior_cleanup.get("buses_deleted", int(prior_cleanup.get("bus_deleted", False))) + int(bus)}
        if errors:
            fixture["cleanup_errors"] = errors
        save()
        print("cleanup: " + str(fixture["cleanup"]), flush=True)
        if errors:
            raise RuntimeError("; ".join(errors))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--followup", action="store_true")
    args = parser.parse_args()
    main(args.account, followup=args.followup)
