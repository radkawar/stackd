#!/usr/bin/env python3
"""Capture common KMS rotation behavior using owned temporary keys."""

import base64
import datetime
import json
import os
import pathlib
import time

from aws_cli import call, observe as observe_cli


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    identity = require_account(probe_args.account)
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "source": "Owned AWS KMS rotation keys; synthetic plaintext", "region": os.environ["AWS_DEFAULT_REGION"],
               "keys": [], "observations": [], "cleanup": [], "capture_complete": False}
    path = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/kms/rotation.json'
    ids = []
    alias = "alias/stackd-rotation-" + str(time.time_ns())
    alias_created = False
    managed_id = None
    queue_name = "stackd-managed-rotation-" + str(time.time_ns())

    def save():
        text = json.dumps(fixture, indent=2).replace(identity["Account"], "111111111111").replace(alias, "alias/stackd-rotation-probe").replace(queue_name, "stackd-managed-rotation-probe")
        for index, key in enumerate(ids):
            text = text.replace(key, f"00000000-0000-4000-8000-{index+1:012d}")
        if managed_id:
            text = text.replace(managed_id, "00000000-0000-4000-8000-000000000003")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n")

    def observe(case, operation, params):
        row = {"case": case, "operation": operation}
        row.update(observe_cli("kms", operation, params, paginate=False))
        result = row.get("output")
        if result is not None:
            output = dict(result)
            if "NextMarker" in output:
                output["NextMarker"] = "<opaque pagination marker omitted>"
            row.update(output=output)
        if row["code"] == 'ParamValidation':
            row['source'] = 'AWS CLI validation; request was not sent to AWS'
        if case.endswith("_poll") and fixture["observations"][-1:] == [row]:
            return result
        fixture["observations"].append(row)
        save()
        print(case + ": " + row["code"], flush=True)
        return result

    def wait_for(case, operation, params, complete):
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            result = observe(case, operation, params)
            if result is not None and complete(result):
                return
            time.sleep(5)
        raise RuntimeError("Owned key rotation did not complete within 15 minutes")

    try:
        key = call("kms", "create-key", {"Description": "stackd rotation conformance probe"})["KeyMetadata"]
        ids.append(key["KeyId"])
        fixture["keys"].append(key)
        save()
        print("Owned rotation key: " + key["KeyId"], flush=True)
        p = {"KeyId": key["KeyId"]}
        observe("initial_status", "get-key-rotation-status", p)
        observe("initial_list", "list-key-rotations", p)
        observe("initial_all", "list-key-rotations", dict(p, IncludeKeyMaterial="ALL_KEY_MATERIAL"))
        observe("disable_initial", "disable-key-rotation", p)
        observe("status_disabled_initial", "get-key-rotation-status", p)
        for days in [89, 2561, 90, 2560]:
            observe("enable_" + str(days), "enable-key-rotation", dict(p, RotationPeriodInDays=days))
            if days in [90, 2560]:
                observe("status_" + str(days), "get-key-rotation-status", p)
        observe("enable_default", "enable-key-rotation", p)
        observe("status_default", "get-key-rotation-status", p)
        observe("enable_repeat", "enable-key-rotation", p)
        observe("status_repeat", "get-key-rotation-status", p)
        observe("disable_rotation", "disable-key-rotation", p)
        observe("status_disabled_rotation", "get-key-rotation-status", p)
        observe("enable_custom", "enable-key-rotation", dict(p, RotationPeriodInDays=90))
        observe("status_custom", "get-key-rotation-status", p)
        call("kms", "create-alias", {"AliasName": alias, "TargetKeyId": key["KeyId"]})
        alias_created = True
        for op in ["get-key-rotation-status", "list-key-rotations", "enable-key-rotation", "disable-key-rotation", "rotate-key-on-demand"]:
            observe("alias_" + op, op, {"KeyId": alias})
        encryption_context = {"purpose": "rotation-probe"}
        before = observe("encrypt_before", "encrypt", dict(p, Plaintext=base64.b64encode(b"retained rotation plaintext").decode(), EncryptionContext=encryption_context))
        observe("rotate_first", "rotate-key-on-demand", p)
        observe("rotate_immediate_repeat", "rotate-key-on-demand", p)
        observe("status_after_request", "get-key-rotation-status", p)
        wait_for("rotation_poll", "get-key-rotation-status", p, lambda status: "OnDemandRotationStartDate" not in status)
        observe("describe_rotated", "describe-key", p)
        observe("list_rotated", "list-key-rotations", p)
        observe("all_rotated", "list-key-rotations", dict(p, IncludeKeyMaterial="ALL_KEY_MATERIAL"))
        first = observe("page_first", "list-key-rotations", dict(p, IncludeKeyMaterial="ALL_KEY_MATERIAL", Limit=1))
        if first and "NextMarker" in first:
            observe("page_second", "list-key-rotations", dict(p, IncludeKeyMaterial="ALL_KEY_MATERIAL", Limit=1, Marker=first["NextMarker"]))
        observe("invalid_marker", "list-key-rotations", dict(p, Marker="invalid"))
        observe("decrypt_old", "decrypt", {"CiphertextBlob": before["CiphertextBlob"], "EncryptionContext": encryption_context})
        observe("reencrypt_old", "re-encrypt", {"CiphertextBlob": before["CiphertextBlob"], "DestinationKeyId": key["KeyId"], "SourceEncryptionContext": encryption_context, "DestinationEncryptionContext": encryption_context})
        observe("data_key_rotated", "generate-data-key-without-plaintext", dict(p, KeySpec="AES_256"))
        call("kms", "disable-key", p)
        for op in ["get-key-rotation-status", "list-key-rotations", "enable-key-rotation", "disable-key-rotation", "rotate-key-on-demand"]:
            observe("disabled_" + op, op, p)
        call("kms", "enable-key", p)
        observe("status_reenabled", "get-key-rotation-status", p)
        fixture["cleanup"].append(call("kms", "schedule-key-deletion", dict(p, PendingWindowInDays=7)))
        save()
        for op in ["get-key-rotation-status", "list-key-rotations", "enable-key-rotation", "disable-key-rotation", "rotate-key-on-demand"]:
            observe("deleting_" + op, op, p)
        call("kms", "cancel-key-deletion", p)
        observe("status_canceled_deletion", "get-key-rotation-status", p)
        call("kms", "enable-key", p)
        observe("reenabled_same_period", "enable-key-rotation", dict(p, RotationPeriodInDays=90))
        observe("status_same_period", "get-key-rotation-status", p)
        observe("disable_for_default", "disable-key-rotation", p)
        observe("reenable_omitted_period", "enable-key-rotation", p)
        observe("status_reenable_omitted", "get-key-rotation-status", p)
        observe("second_rotate", "rotate-key-on-demand", p)
        observe("second_pending", "get-key-rotation-status", p)
        observe("disable_key_during_rotation", "disable-key", p)
        observe("disabled_pending", "get-key-rotation-status", p)
        wait_for("disabled_rotation_poll", "get-key-rotation-status", p, lambda status: "OnDemandRotationStartDate" not in status)
        observe("disabled_rotation_list", "list-key-rotations", dict(p, IncludeKeyMaterial="ALL_KEY_MATERIAL"))
        call("kms", "enable-key", p)
        observe("reenabled_pending", "get-key-rotation-status", p)
        observe("reenabled_rotation_list", "list-key-rotations", dict(p, IncludeKeyMaterial="ALL_KEY_MATERIAL"))
        observe("enable_for_conditions", "enable-key-rotation", dict(p, RotationPeriodInDays=90))
        original = call("kms", "get-key-policy", dict(p, PolicyName="default"))["Policy"]
        owner = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::" + identity["Account"] + ":root"}, "Action": "kms:*", "Resource": "*"}
        try:
            for name, condition in [("null", {"Null": {"kms:RotationPeriodInDays": "true"}}), ("numeric", {"NumericGreaterThan": {"kms:RotationPeriodInDays": "100"}})]:
                policy = {"Statement": [owner, {"Effect": "Deny", "Principal": "*", "Action": "kms:EnableKeyRotation", "Resource": "*", "Condition": condition}]}
                call("kms", "put-key-policy", dict(p, PolicyName="default", Policy=json.dumps(policy)))
                observe("condition_" + name + "_omitted", "enable-key-rotation", p)
                observe("condition_" + name + "_90", "enable-key-rotation", dict(p, RotationPeriodInDays=90))
                if name == "numeric":
                    observe("condition_numeric_omitted_when_90", "enable-key-rotation", p)
                observe("condition_" + name + "_180", "enable-key-rotation", dict(p, RotationPeriodInDays=180))
        finally:
            call("kms", "put-key-policy", dict(p, PolicyName="default", Policy=original))
        observe("third_rotate", "rotate-key-on-demand", p)
        observe("third_pending", "get-key-rotation-status", p)
        fixture["cleanup"].append(call("kms", "schedule-key-deletion", dict(p, PendingWindowInDays=7)))
        save()
        observe("deleting_pending", "get-key-rotation-status", p)
        wait_for("deleting_rotation_poll", "list-key-rotations", dict(p, IncludeKeyMaterial="ALL_KEY_MATERIAL"), lambda result: len(result["Rotations"]) >= 4)
        observe("deleting_rotation_status_final", "get-key-rotation-status", p)
        # Unsupported key families share rotation eligibility; one HMAC key
        # captures that boundary without provisioning specialist resources.
        hmac = call("kms", "create-key", {"KeySpec": "HMAC_256", "KeyUsage": "GENERATE_VERIFY_MAC", "Description": "stackd rotation eligibility probe"})["KeyMetadata"]
        ids.append(hmac["KeyId"])
        fixture["keys"].append(hmac)
        save()
        for op in ["get-key-rotation-status", "list-key-rotations", "enable-key-rotation", "disable-key-rotation", "rotate-key-on-demand"]:
            observe("hmac_" + op, op, {"KeyId": hmac["KeyId"]})
        queue = None
        try:
            queue = call("sqs", "create-queue", {"QueueName": queue_name, "Attributes": {"KmsMasterKeyId": "alias/aws/sqs"}})["QueueUrl"]
            call("sqs", "send-message", {"QueueUrl": queue, "MessageBody": "stackd managed rotation probe"})
            metadata = call("kms", "describe-key", {"KeyId": "alias/aws/sqs"})["KeyMetadata"]
            managed_id = metadata["KeyId"]
            fixture["managed_key"] = metadata
            managed = {"KeyId": managed_id}
            observe("managed_sqs_policy", "get-key-policy", dict(managed, PolicyName="default"))
            observe("managed_sqs_status", "get-key-rotation-status", managed)
            observe("managed_sqs_rotations", "list-key-rotations", dict(managed, IncludeKeyMaterial="ALL_KEY_MATERIAL"))
            for op in ["enable-key-rotation", "disable-key-rotation", "rotate-key-on-demand"]:
                observe("managed_sqs_" + op, op, managed)
        finally:
            if queue:
                call("sqs", "delete-queue", {"QueueUrl": queue})
                fixture["managed_key_probe_cleanup"] = {"queue": queue, "state": "Deleted", "managed_key": "AWS-managed alias/aws/sqs remains under AWS ownership; no key deletion API is available."}
        fixture["capture_complete"] = True
    finally:
        if alias_created:
            call("kms", "delete-alias", {"AliasName": alias})
        for key_id in ids:
            current = call("kms", "describe-key", {"KeyId": key_id})["KeyMetadata"]
            if current["KeyState"] != "PendingDeletion":
                fixture["cleanup"].append(call("kms", "schedule-key-deletion", {"KeyId": key_id, "PendingWindowInDays": 7}))
        save()
        print("Owned rotation probe keys are scheduled for deletion", flush=True)


if __name__ == "__main__":
    main()
