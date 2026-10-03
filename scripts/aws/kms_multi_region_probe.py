#!/usr/bin/env python3
"""Capture multi-Region KMS behavior with owned regional keys."""

import base64
import datetime
import json
import os
import pathlib
import time

from aws_cli import AWSCLIError, call


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    account = require_account(probe_args.account)["Account"]
    east, west = "us-east-1", "us-west-2"
    role_name = "AWSServiceRoleForKeyManagementServiceMultiRegionKeys"
    path = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/kms/multi_region.json'
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "source": "Owned AWS multi-Region KMS keys and synthetic plaintext", "regions": [east, west],
               "observations": [], "cleanup": [], "capture_complete": False}
    owned = []
    replacements = {account: "111111111111"}
    alias = "alias/stackd-mrk-" + str(time.time_ns())
    alias_created = False

    def save():
        fixture["regions"] = sorted({east, west} | {region for region, _ in owned})
        data = json.dumps(fixture, indent=2).replace(alias, "alias/stackd-mrk-probe")
        for actual, normalized in replacements.items():
            data = data.replace(actual, normalized)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data + "\n")

    def regional(service, operation, params=None, region=east):
        return call(service, operation, params, dict(os.environ, AWS_DEFAULT_REGION=region), paginate=False, error_format="json")

    def observe(case, operation, params=None, region=east, service="kms"):
        row = {"case": case, "service": service, "operation": operation, "region": region}
        try:
            result = regional(service, operation, params, region)
            if "ReplicaKeyMetadata" in result:
                metadata = result["ReplicaKeyMetadata"]
                replica = (metadata["Arn"].split(":")[3], metadata["KeyId"])
                if replica not in owned:
                    owned.append(replica)
            output = dict(result)
            if "NextMarker" in output:
                output["NextMarker"] = "<omitted>"
            row.update(code="Success", output=output)
        except AWSCLIError as error:
            parsed = error.details
            row.update(code=parsed["Code"], error=parsed)
            if parsed["Code"] == "ParamValidation":
                row["source"] = "AWS CLI validation; request was not sent to AWS"
            result = None
        if case.endswith("_poll") and fixture["observations"][-1:] == [row]:
            return result
        fixture["observations"].append(row)
        save()
        print(case + ": " + row["code"], flush=True)
        return result

    def wait_for(case, operation, params, region, complete):
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            result = observe(case, operation, params, region)
            if result is not None and complete(result):
                return result
            time.sleep(3)
        raise RuntimeError("Owned multi-Region transition did not complete within 15 minutes")

    before_role = observe("service_role_before", "get-role", {"RoleName": role_name}, service="iam")
    try:
        key = regional("kms", "create-key", {"MultiRegion": True, "Description": "stackd multi-Region primary", "Tags": [{"TagKey": "location", "TagValue": "primary"}]})["KeyMetadata"]
        identifier = key["KeyId"]
        replacements[identifier] = "mrk-00000000000000000000000000000001"
        owned.append((east, identifier))
        fixture["primary"] = key
        save()
        print("Owned primary key: " + identifier, flush=True)
        base = {"KeyId": identifier}
        observe("service_role_after", "get-role", {"RoleName": role_name}, service="iam")
        observe("service_role_policies", "list-attached-role-policies", {"RoleName": role_name}, service="iam")
        observe("service_role_public_create", "create-service-linked-role", {"AWSServiceName": "mrk.kms.amazonaws.com"}, service="iam")
        if not before_role:
            result = observe("service_role_delete", "delete-service-linked-role", {"RoleName": role_name}, service="iam")
            if result and "DeletionTaskId" in result:
                task = result["DeletionTaskId"]
                for attempt in range(30):
                    status = observe("service_role_delete_status", "get-service-linked-role-deletion-status", {"DeletionTaskId": task}, service="iam")
                    if status and status["Status"] in ["FAILED", "SUCCEEDED"]:
                        break
                    time.sleep(2)
        observe("primary_initial", "describe-key", base)
        for region in [east, "cn-north-1", "us-invalid-1", "ap-east-1"]:
            observe("replicate_region_" + region, "replicate-key", dict(base, ReplicaRegion=region))
        observe("enable_rotation_primary", "enable-key-rotation", dict(base, RotationPeriodInDays=90))
        before = observe("encrypt_primary_before", "encrypt", dict(base, Plaintext=base64.b64encode(b"multi-Region plaintext").decode(), EncryptionContext={"purpose": "mrk"}))
        replica = observe("replicate_west", "replicate-key", dict(base, ReplicaRegion=west))
        if not replica:
            raise RuntimeError("Owned key replication failed")
        save()
        observe("primary_after_replicate", "describe-key", base)
        observe("replica_initial", "describe-key", base, west)
        observe("replica_initial_rotation", "get-key-rotation-status", base, west)
        wait_for("replica_ready_poll", "describe-key", base, west, lambda out: out["KeyMetadata"]["KeyState"] == "Enabled")
        observe("replica_policy", "get-key-policy", dict(base, PolicyName="default"), west)
        observe("replica_tags", "list-resource-tags", base, west)
        observe("replica_rotation", "get-key-rotation-status", base, west)
        for op in ["enable-key-rotation", "disable-key-rotation", "rotate-key-on-demand"]:
            observe("replica_" + op, op, base, west)
        observe("replicate_existing", "replicate-key", dict(base, ReplicaRegion=west))
        observe("replicate_replica", "replicate-key", dict(base, ReplicaRegion="us-east-2"), west)
        decrypt = {"CiphertextBlob": before["CiphertextBlob"], "EncryptionContext": {"purpose": "mrk"}}
        for name, expected in [("implicit", None), ("id", identifier), ("replica_arn", replica["ReplicaKeyMetadata"]["Arn"]), ("primary_arn", key["Arn"])]:
            params = dict(decrypt)
            if expected:
                params["KeyId"] = expected
            observe("decrypt_replica_" + name, "decrypt", params, west)
        observe("replica_reencrypt_same", "re-encrypt", {"CiphertextBlob": before["CiphertextBlob"], "SourceEncryptionContext": {"purpose": "mrk"}, "DestinationKeyId": identifier}, west)
        observe("disable_primary", "disable-key", base)
        observe("decrypt_replica_primary_disabled", "decrypt", decrypt, west)
        observe("replicate_disabled_primary", "replicate-key", dict(base, ReplicaRegion=west))
        observe("enable_primary", "enable-key", base)
        regional("kms", "create-alias", {"AliasName": alias, "TargetKeyId": identifier})
        alias_created = True
        for op, params in [("replicate-key", {"KeyId": alias, "ReplicaRegion": west}), ("update-primary-region", {"KeyId": alias, "PrimaryRegion": west})]:
            observe("alias_" + op, op, params)
        observe("update_primary_same", "update-primary-region", dict(base, PrimaryRegion=east))
        observe("update_primary_missing", "update-primary-region", dict(base, PrimaryRegion="us-east-2"))
        observe("update_from_replica", "update-primary-region", dict(base, PrimaryRegion=west), west)
        observe("rotate_primary", "rotate-key-on-demand", base)
        wait_for("rotation_complete_poll", "get-key-rotation-status", base, east, lambda out: "OnDemandRotationStartDate" not in out)
        rotated = observe("primary_rotated", "describe-key", base)
        material = rotated["KeyMetadata"]["CurrentKeyMaterialId"]
        wait_for("replica_rotation_sync_poll", "describe-key", base, west, lambda out: out["KeyMetadata"].get("CurrentKeyMaterialId") == material)
        observe("replica_rotation_history", "list-key-rotations", dict(base, IncludeKeyMaterial="ALL_KEY_MATERIAL"), west)
        observe("replica_decrypt_old_material", "decrypt", decrypt, west)
        observe("promote_replica", "update-primary-region", dict(base, PrimaryRegion=west))
        observe("former_primary_updating", "describe-key", base)
        observe("new_primary_updating", "describe-key", base, west)
        wait_for("primary_change_poll", "describe-key", base, west, lambda out: out["KeyMetadata"]["KeyState"] == "Enabled" and out["KeyMetadata"]["MultiRegionConfiguration"]["MultiRegionKeyType"] == "PRIMARY")
        observe("former_primary_final", "describe-key", base)
        observe("new_primary_rotation", "get-key-rotation-status", base, west)
        observe("new_primary_decrypt_old", "decrypt", decrypt, west)
        observe("delete_primary_with_replica", "schedule-key-deletion", dict(base, PendingWindowInDays=7), west)
        observe("primary_waiting_replicas", "describe-key", base, west)
        observe("replica_with_deleting_primary", "decrypt", decrypt)
        observe("primary_cancel_replica_wait", "cancel-key-deletion", base, west)
        observe("primary_after_cancel", "describe-key", base, west)
        observe("promote_disabled_primary", "update-primary-region", dict(base, PrimaryRegion=east), west)
        observe("primary_enable_after_cancel", "enable-key", base, west)
        observe("disable_replica_for_promotion", "disable-key", base)
        observe("promote_disabled_replica", "update-primary-region", dict(base, PrimaryRegion=east), west)
        observe("enable_replica_before_cleanup", "enable-key", base)
        observe("replica_schedule_delete", "schedule-key-deletion", dict(base, PendingWindowInDays=7))
        observe("primary_with_deleting_replica", "describe-key", base, west)
        observe("replicate_deleting_replica", "replicate-key", dict(base, ReplicaRegion=east), west)
        observe("promote_deleting_replica", "update-primary-region", dict(base, PrimaryRegion=east), west)
        fixture["capture_complete"] = True
    finally:
        if alias_created:
            regional("kms", "delete-alias", {"AliasName": alias})
        for region, identifier in owned:
            try:
                status = regional("kms", "schedule-key-deletion", {"KeyId": identifier, "PendingWindowInDays": 7}, region)
            except RuntimeError as error:
                if "KMSInvalidStateException" not in str(error):
                    raise
                status = regional("kms", "describe-key", {"KeyId": identifier}, region)["KeyMetadata"]
            fixture["cleanup"].append({"region": region, "key": status})
            observe("deleting_rotation_" + region, "get-key-rotation-status", base, region)
            policy = observe("deleting_policy_" + region, "get-key-policy", dict(base, PolicyName="default"), region)
            if policy:
                observe("put_deleting_policy_" + region, "put-key-policy", dict(base, Policy=policy["Policy"]), region)
            observe("tag_deleting_" + region, "tag-resource", dict(base, Tags=[{"TagKey": "cleanup-probe", "TagValue": "native"}]), region)
            observe("untag_deleting_" + region, "untag-resource", dict(base, TagKeys=["cleanup-probe"]), region)
        fixture["cleanup"].append({"service_role": role_name, "created_by_probe": not bool(before_role), "retained": "AWS deletion failed because this account owns multi-Region keys; dependent keys remain until their deletion windows expire."})
        save()
        print("Cleanup recorded in " + str(path), flush=True)


if __name__ == "__main__":
    main()
