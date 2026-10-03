#!/usr/bin/env python3
"""Capture SQS KMS reuse across role-session names, policies and context."""

import argparse
import datetime
import json
import os
import pathlib
import time
import uuid

from aws_cli import AWSCLIError, call, require_account


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID authorized for this probe")
    args = parser.parse_args()
    caller = require_account(args.account)
    account = caller["Account"]
    prefix = "stackd-cache-" + uuid.uuid4().hex[:10]
    path = pathlib.Path(__file__).resolve().parents[2] / ".stackd/probes/sqs/cache_scope.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "region": "us-east-1", "source": "Owned native AWS IAM role, session policies, KMS key and SQS queues",
        "comparison": "Warm versus fresh queue data-key permissions across role-session names, policy scope, tags and source identity",
        "limitations": "Finite commercial public-endpoint observations; cache placement and policy propagation are not exact timing guarantees",
        "sessions": {}, "observations": [], "owned": {"queues": {}, "policies": []}, "cleanup": {}}
    key_id = None
    role = None
    environments = {}

    def save():
        path.write_text(json.dumps(fixture, indent=2) + "\n")

    def normalized(value):
        text = json.dumps(value).replace(account, "111111111111").replace(prefix, "cache-worker")
        if key_id:
            text = text.replace(key_id, "<key>")
        return json.loads(text)

    def observe(case, label, service, operation, parameters):
        row = {"case": case, "caller": label, "service": service, "operation": operation}
        try:
            output = call(service, operation, parameters, environments.get(label), error_format="json")
        except AWSCLIError as error:
            row["error"] = error.details
            output = None
        else:
            public = json.loads(json.dumps(output))
            for field in ("Plaintext", "CiphertextBlob"):
                public.pop(field, None)
            for message in public.get("Messages", []):
                message.pop("ReceiptHandle", None)
            row["output"] = public
        fixture["observations"].append(normalized(row))
        save()
        return output

    def assume(label, name="shared", **scope):
        parameters = {"RoleArn": role["Arn"], "RoleSessionName": name, "DurationSeconds": 900, **scope}
        for attempt in range(20):
            try:
                assumed = call("sts", "assume-role", parameters)
                break
            except RuntimeError:
                if attempt == 19:
                    raise
                time.sleep(2)
        credentials = assumed["Credentials"]
        environments[label] = dict(os.environ, AWS_ACCESS_KEY_ID=credentials["AccessKeyId"],
            AWS_SECRET_ACCESS_KEY=credentials["SecretAccessKey"], AWS_SESSION_TOKEN=credentials["SessionToken"])
        fixture["sessions"][label] = normalized({"name": name, "scope": scope, "arn": assumed["AssumedRoleUser"]["Arn"]})
        save()

    def exercise(label, queue, case=None):
        case = case or label
        url = fixture["owned"]["queues"][queue]
        observe(case + "_send", label, "sqs", "send-message", {"QueueUrl": url, "MessageBody": case})
        observe(case + "_receive", label, "sqs", "receive-message", {
            "QueueUrl": url, "VisibilityTimeout": 0, "WaitTimeSeconds": 1})

    try:
        key = call("kms", "create-key", {"Description": prefix,
            "Tags": [{"TagKey": "stackd-probe", "TagValue": prefix}]})["KeyMetadata"]
        key_id = key["KeyId"]
        fixture["owned"]["key"] = {"KeyId": key_id, "Arn": key["Arn"]}
        save()
        for label in ("warm", "fresh"):
            url = call("sqs", "create-queue", {"QueueName": prefix + "-" + label,
                "Attributes": {"KmsMasterKeyId": key["Arn"], "KmsDataKeyReusePeriodSeconds": "300", "VisibilityTimeout": "0"}})["QueueUrl"]
            fixture["owned"]["queues"][label] = url
            save()
        queue_resources = [f"arn:aws:sqs:us-east-1:{account}:{prefix}-{label}" for label in ("warm", "fresh")]
        queue_permissions = {"Effect": "Allow", "Action": ["sqs:SendMessage", "sqs:ReceiveMessage"], "Resource": queue_resources}
        key_permissions = {"Effect": "Allow", "Action": ["kms:GenerateDataKey", "kms:Decrypt"], "Resource": key["Arn"]}
        allowed = {"Version": "2012-10-17", "Statement": [queue_permissions, key_permissions]}
        limited = {"Version": "2012-10-17", "Statement": [queue_permissions]}
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": caller["Arn"]},
            "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"]}]}
        role = call("iam", "create-role", {"RoleName": prefix, "AssumeRolePolicyDocument": json.dumps(trust)})["Role"]
        fixture["owned"]["role"] = {"RoleName": prefix, "Arn": role["Arn"], "RoleId": role["RoleId"]}
        save()
        base = {"Version": "2012-10-17", "Statement": allowed["Statement"] + [
            {"Effect": "Deny", "Action": ["kms:GenerateDataKey", "kms:Decrypt"], "Resource": key["Arn"], "Condition": condition}
            for condition in ({"StringLike": {"aws:userid": "*:name-denied"}},
                {"StringEquals": {"aws:PrincipalTag/kms": "denied"}},
                {"StringEquals": {"aws:SourceIdentity": "denied"}})]}
        call("iam", "put-role-policy", {"RoleName": prefix, "PolicyName": "queue-keys", "PolicyDocument": json.dumps(base)})
        policies = {}
        for label, document in (("allowed", allowed), ("limited", limited)):
            policy = call("iam", "create-policy", {"PolicyName": prefix + "-" + label,
                "PolicyDocument": json.dumps(document)})["Policy"]
            policies[label] = policy["Arn"]
            fixture["owned"]["policies"].append(policy["Arn"])
            save()
        assume("unscoped")
        assume("inline_allowed", Policy=json.dumps(allowed))
        assume("inline_limited", Policy=json.dumps(limited))
        assume("inline_same", name="name-denied", Policy=json.dumps(allowed))
        assume("inline_whitespace", name="name-denied", Policy=json.dumps(allowed, indent=2))
        assume("inline_reordered", name="name-denied", Policy=json.dumps({"Statement": list(reversed(allowed["Statement"])), "Version": "2012-10-17"}, indent=2))
        assume("managed_allowed", PolicyArns=[{"arn": policies["allowed"]}])
        assume("managed_limited", PolicyArns=[{"arn": policies["limited"]}])
        assume("managed_same", name="name-denied", PolicyArns=[{"arn": policies["allowed"]}])
        assume("managed_pair", PolicyArns=[{"arn": policies["allowed"]}, {"arn": policies["limited"]}])
        assume("managed_reversed", name="name-denied", PolicyArns=[{"arn": policies["limited"]}, {"arn": policies["allowed"]}])
        assume("name_denied", name="name-denied")
        assume("tag_denied", Tags=[{"Key": "kms", "Value": "denied"}])
        assume("source_denied", SourceIdentity="denied")
        time.sleep(5)
        for label in environments:
            observe(label + "_direct_key", label, "kms", "generate-data-key", {"KeyId": key_id, "KeySpec": "AES_256"})
        # The fresh queue proves that a denied session cannot load a key itself;
        # the warm queue tests whether it shares another session's cached key.
        for label in ("name_denied", "tag_denied", "source_denied", "inline_limited", "managed_limited"):
            exercise(label, "fresh", label + "_fresh")
        # Prime the fresh consumer path with an owner-produced encrypted message.
        call("sqs", "send-message", {"QueueUrl": fixture["owned"]["queues"]["fresh"], "MessageBody": "owner seeded"})
        for label in ("name_denied", "tag_denied", "source_denied", "inline_limited", "managed_limited"):
            observe(label + "_fresh_seeded_receive", label, "sqs", "receive-message", {
                "QueueUrl": fixture["owned"]["queues"]["fresh"], "VisibilityTimeout": 0, "WaitTimeSeconds": 1})
        for label in environments:
            exercise(label, "warm")
        fixture["completed"] = True
    finally:
        for label, url in fixture["owned"]["queues"].items():
            try:
                call("sqs", "delete-queue", {"QueueUrl": url})
                try:
                    call("sqs", "get-queue-url", {"QueueName": prefix + "-" + label}, error_format="json")
                except AWSCLIError as error:
                    result = error.details
                    fixture["cleanup"]["queue_" + label] = result
                else:
                    fixture["cleanup"]["queue_" + label] = "Deletion requested; queue lookup still succeeds"
            except RuntimeError as error:
                fixture["cleanup"]["queue_" + label] = str(error)
            save()
        if role:
            try:
                call("iam", "delete-role-policy", {"RoleName": prefix, "PolicyName": "queue-keys"})
                call("iam", "delete-role", {"RoleName": prefix})
                fixture["cleanup"]["role"] = "Deleted"
            except RuntimeError as error:
                fixture["cleanup"]["role"] = str(error)
            save()
        for arn in fixture["owned"]["policies"]:
            try:
                call("iam", "delete-policy", {"PolicyArn": arn})
                fixture["cleanup"][arn] = "Deleted"
            except RuntimeError as error:
                fixture["cleanup"][arn] = str(error)
            save()
        if key_id:
            try:
                fixture["cleanup"]["key"] = call("kms", "schedule-key-deletion", {"KeyId": key_id, "PendingWindowInDays": 7})
            except RuntimeError as error:
                fixture["cleanup"]["key"] = str(error)
            save()
    print(f"Wrote {path}; {len(fixture['observations'])} observations; cleanup recorded")


if __name__ == "__main__":
    main()
