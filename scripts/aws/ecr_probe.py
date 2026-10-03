#!/usr/bin/env python3
"""Capture private ECR on two owned repositories; no registry-wide mutations.

Run: PYTHONPATH=scripts/aws python3 -P scripts/aws/ecr_probe.py --account ACCOUNT_ID
Tokens and presigned URLs exist only in memory and are never recorded.
"""
import argparse
import base64
import datetime
import gzip
import hashlib
import http.client
import io
import json
import os
import pathlib
import tarfile
import time
import urllib.error
import urllib.request
import uuid

from aws_cli import observe as observe_cli, require_account
from signed_requests import signed_post

ROOT = pathlib.Path(__file__).resolve().parents[2]
REGION = "us-east-1"
CAPTURES = ROOT / ".stackd/probes/ecr"
MEDIA = "application/vnd.oci.image.manifest.v1+json"


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def redact(value):
    if isinstance(value, dict):
        return {key: ("[REDACTED]" if key.lower() in {
            "authorizationtoken", "downloadurl", "password", "secretaccesskey",
            "sessiontoken", "accesskeyid"} else redact(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def request(operation, parameters):
    response = signed_post("api.ecr.us-east-1.amazonaws.com", "ecr", json.dumps(parameters).encode(),
                           {"content-type": "application/x-amz-json-1.1",
                            "x-amz-target": "AmazonEC2ContainerRegistry_V20150921." + operation})
    output = json.loads(response.body)
    if 200 <= response.status < 300:
        return {"code": "Success", "output": output, "http_status": response.status, "request_id": response.request_id}
    return {"code": output["__type"].split("#")[-1], "error": output, "http_status": response.status, "request_id": response.request_id}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="Native AWS account ID that must match the STS caller")
    parser.add_argument("--resume", help="Prior owned capture basename; reuses its two repository names and KMS key")
    args = parser.parse_args()
    account = args.account
    os.environ["AWS_DEFAULT_REGION"] = REGION
    os.environ["AWS_REGION"] = REGION
    os.environ["AWS_MAX_ATTEMPTS"] = "1"
    identity = require_account(account)
    previous = None
    if args.resume:
        if pathlib.Path(args.resume).name != args.resume:
            raise RuntimeError("Resume must name a capture inside .stackd/probes/ecr")
        previous = json.loads((CAPTURES / args.resume).read_text())
        if previous["account"] != account or not previous["owned_prefix"].startswith("stackd-buildowner-ecr-"):
            raise RuntimeError("Refusing unowned capture")
    prefix = previous["owned_prefix"] if previous else "stackd-buildowner-ecr-" + uuid.uuid4().hex[:12]
    suffix = "-resume-" + uuid.uuid4().hex[:6] if previous else ""
    path = CAPTURES / (prefix + suffix + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    fixture = {
        "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": "native AWS private ECR", "account": account, "region": REGION,
        "actor": identity["Arn"], "owned_prefix": prefix,
        "semantic_inventory": "semantic_inventory.json",
        "bounds": {"repositories": 2, "image_bytes": 10485760, "max_wall_seconds": 600,
                   "registry_wide_writes": False, "ec2_guests": 0, "owned_kms_keys": 1,
                   "kms_cost_ceiling_usd": 0.25, "kms_deletion_window_days": 7},
        "observations": [], "cleanup": [], "capture_complete": False,
    }
    if previous:
        fixture["resumes_capture"] = args.resume
    owned = []
    key_id = None
    started = time.monotonic()

    def save():
        path.write_text(json.dumps(redact(fixture), indent=2) + "\n")

    def observe(case, operation, parameters, cleanup=False):
        if not cleanup and time.monotonic() - started > 600:
            raise RuntimeError("ECR capture wall bound reached")
        for attempt in range(3):
            try:
                result = request(operation, parameters)
                break
            except (http.client.RemoteDisconnected, TimeoutError, urllib.error.URLError) as error:
                fixture.setdefault("transport_failures", []).append({"case": case, "attempt": attempt + 1, "type": type(error).__name__})
                save()
                if attempt == 2:
                    raise
                time.sleep(1)
        fixture["cleanup" if cleanup else "observations"].append({
            "case": case, "operation": operation, "parameters": parameters, **redact(result)})
        save()
        print(case + ": " + result["code"], flush=True)
        return result

    def required(case, operation, parameters):
        result = observe(case, operation, parameters)
        if result["code"] != "Success":
            raise RuntimeError(case + " failed: " + result["code"])
        return result["output"]

    def kms(case, operation, parameters, cleanup=False):
        result = observe_cli("kms", operation, parameters, paginate=False)
        fixture["cleanup" if cleanup else "observations"].append({
            "case": case, "operation": "kms:" + operation, "parameters": parameters, **result})
        save()
        print(case + ": " + result["code"], flush=True)
        return result

    def registry(case, repository, suffix, token=None, method="GET", data=None):
        headers = {"Accept": MEDIA}
        if token:
            headers["Authorization"] = "Basic " + token
        if data is not None:
            headers["Content-Type"] = MEDIA
        url = f"https://{account}.dkr.ecr.{REGION}.amazonaws.com/v2/{repository}/{suffix}"
        request = urllib.request.Request(url, headers=headers, method=method, data=data)
        try:
            response = urllib.request.urlopen(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read(10485761)
            row = {"case": case, "operation": "RegistryHTTP", "method": method,
                   "path": f"/v2/{repository}/{suffix}", "authenticated": bool(token),
                   "http_status": response.status,
                   "headers": {k: v for k, v in response.headers.items() if k.lower() in {
                       "content-type", "docker-content-digest", "docker-distribution-api-version"}},
                   "body": body.decode("utf-8", errors="replace")}
        fixture["observations"].append(row)
        save()
        print(case + ": HTTP " + str(row["http_status"]), flush=True)
        return row

    try:
        save()
        if previous:
            key_id = previous["owned_key"]
            metadata = kms("verify_owned_key", "describe-key", {"KeyId": key_id})["output"]["KeyMetadata"]
            if metadata["Description"] != prefix or metadata["AWSAccountId"] != account:
                key_id = None
                raise RuntimeError("Resume key ownership mismatch")
            if metadata["KeyState"] == "PendingDeletion":
                kms("cancel_owned_key_deletion_for_resume", "cancel-key-deletion", {"KeyId": key_id})
                kms("enable_owned_key_for_resume", "enable-key", {"KeyId": key_id})
        else:
            created_key = kms("create_owned_key", "create-key", {"Description": prefix, "Tags": [{"TagKey": "stackd-owner", "TagValue": prefix}]})
            if created_key["code"] != "Success":
                raise RuntimeError("Owned key creation failed")
            key_id = created_key["output"]["KeyMetadata"]["KeyId"]
        fixture["owned_key"] = key_id
        save()
        for name in [prefix + "-images", prefix + "-isolated"]:
            absent = observe("precreate_absence", "DescribeRepositories", {"repositoryNames": [name]})
            if absent["code"] != "RepositoryNotFoundException":
                raise RuntimeError("Refusing to replace an existing repository")
            owned.append(name)
            result = required("create_" + name.rsplit("-", 1)[-1], "CreateRepository", {
                "repositoryName": name, "imageTagMutability": "MUTABLE",
                "imageScanningConfiguration": {"scanOnPush": False},
                "tags": [{"Key": "stackd-owner", "Value": prefix}],
                "encryptionConfiguration": {"encryptionType": "KMS", "kmsKey": key_id} if name.endswith("-images") else {"encryptionType": "AES256"}})
            if result["repository"]["repositoryName"] != name:
                raise RuntimeError("Unexpected repository identity")
            fixture["repositories"] = owned
            save()
        kms("repository_grants", "list-grants", {"KeyId": key_id})
        repository, isolated = owned
        arn = f"arn:aws:ecr:{REGION}:{account}:repository/{repository}"
        observe("create_duplicate", "CreateRepository", {"repositoryName": repository})
        observe("missing_repository", "DescribeRepositories", {"repositoryNames": [prefix + "-absent"]})
        observe("describe_owned", "DescribeRepositories", {"repositoryNames": owned})
        observe("tag_merge", "TagResource", {"resourceArn": arn, "tags": [{"Key": "purpose", "Value": "native-evidence"}]})
        observe("tag_list", "ListTagsForResource", {"resourceArn": arn})
        observe("tag_remove", "UntagResource", {"resourceArn": arn, "tagKeys": ["purpose"]})
        observe("policy_missing", "GetRepositoryPolicy", {"repositoryName": repository})
        observe("lifecycle_missing", "GetLifecyclePolicy", {"repositoryName": repository})
        observe("manifest_invalid", "PutImage", {"repositoryName": repository, "imageManifest": "{}", "imageTag": "bad"})
        tar = io.BytesIO()
        with tarfile.open(fileobj=tar, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            payload = b"stackd owned native ECR layer\n"
            info = tarfile.TarInfo("evidence.txt")
            info.size, info.mtime, info.mode = len(payload), 0, 0o644
            archive.addfile(info, io.BytesIO(payload))
        layer = gzip.compress(tar.getvalue(), mtime=0)
        config = json.dumps({"architecture": "amd64", "os": "linux", "config": {},
                             "rootfs": {"type": "layers", "diff_ids": [digest(tar.getvalue())]},
                             "history": [{"created_by": "stackd native evidence"}]}, separators=(",", ":")).encode()
        fixture["image_bytes"] = {"layer_base64": base64.b64encode(layer).decode(),
                                  "config_utf8": config.decode(), "layer_digest": digest(layer),
                                  "config_digest": digest(config), "total": len(layer) + len(config)}
        for kind, blob in [("layer", layer), ("config", config)]:
            observe(kind + "_missing", "BatchCheckLayerAvailability", {"repositoryName": repository, "layerDigests": [digest(blob)]})
            upload = required(kind + "_initiate", "InitiateLayerUpload", {"repositoryName": repository})
            common = {"repositoryName": repository, "uploadId": upload["uploadId"]}
            required(kind + "_upload", "UploadLayerPart", dict(common, partFirstByte=0, partLastByte=len(blob)-1,
                                                               layerPartBlob=base64.b64encode(blob).decode()))
            required(kind + "_complete", "CompleteLayerUpload", dict(common, layerDigests=[digest(blob)]))
        manifest = {"schemaVersion": 2, "mediaType": MEDIA,
                    "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "size": len(config), "digest": digest(config)},
                    "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "size": len(layer), "digest": digest(layer)}]}
        text = json.dumps(manifest, separators=(",", ":"))
        fixture["image_bytes"]["manifest_utf8"] = text
        put = {"repositoryName": repository, "imageManifest": text, "imageTag": "original"}
        required("put_image", "PutImage", put)
        observe("same_image_same_tag", "PutImage", put)
        observe("digest_mismatch", "PutImage", dict(put, imageTag="wrong-digest", imageDigest="sha256:" + "0" * 64))
        observe("foreign_repository_layers", "PutImage", dict(put, repositoryName=isolated))
        observe("layer_available", "BatchCheckLayerAvailability", {"repositoryName": repository, "layerDigests": [digest(layer), digest(config)]})
        downloaded = required("layer_download_url", "GetDownloadUrlForLayer", {"repositoryName": repository, "layerDigest": digest(layer)})
        with urllib.request.urlopen(downloaded["downloadUrl"], timeout=30) as response:
            actual = response.read(10485761)
        fixture["observations"].append({"case": "downloaded_layer_bytes", "operation": "PresignedLayerGET",
                                        "matches_uploaded": actual == layer, "digest": digest(actual), "bytes": len(actual)})
        auth = required("registry_authorization", "GetAuthorizationToken", {})["authorizationData"][0]
        token = auth["authorizationToken"]
        registry("registry_anonymous", repository, "manifests/original")
        registry("registry_authenticated_manifest", repository, "manifests/original", token)
        registry("registry_manifest_push", repository, "manifests/http-tag", token, "PUT", text.encode())
        registry("registry_tags", repository, "tags/list", token)
        observe("batch_existing_and_missing", "BatchGetImage", {"repositoryName": repository, "imageIds": [{"imageTag": "original"}, {"imageTag": "absent"}]})
        observe("describe_image", "DescribeImages", {"repositoryName": repository})
        observe("immutable", "PutImageTagMutability", {"repositoryName": repository, "imageTagMutability": "IMMUTABLE"})
        changed = json.dumps(dict(manifest, annotations={"org.opencontainers.image.description": "second manifest"}), separators=(",", ":"))
        observe("immutable_retag_same_bytes", "PutImage", put)
        observe("immutable_retag_changed_bytes", "PutImage", dict(put, imageManifest=changed))
        observe("mutable", "PutImageTagMutability", {"repositoryName": repository, "imageTagMutability": "MUTABLE"})
        required("mutable_replace", "PutImage", dict(put, imageManifest=changed))
        policy = json.dumps({"Version": "2012-10-17", "Statement": [{"Sid": "OwnedCurrentDeny", "Effect": "Deny", "Principal": {"AWS": identity["Arn"]}, "Action": ["ecr:BatchGetImage"]}]})
        required("deny_policy_set", "SetRepositoryPolicy", {"repositoryName": repository, "policyText": policy, "force": True})
        observe("deny_policy_get", "GetRepositoryPolicy", {"repositoryName": repository})
        fixture["current_policy_denial_observed"] = False
        for attempt in range(7):
            denied = observe("current_policy_api_" + str(attempt), "BatchGetImage", {"repositoryName": repository, "imageIds": [{"imageTag": "original"}]})
            http = registry("current_policy_existing_token_" + str(attempt), repository, "manifests/original", token)
            if denied["code"] in {"AccessDeniedException", "AccessDenied"} and http["http_status"] == 403:
                fixture["current_policy_denial_observed"] = True
                break
            time.sleep(5)
        observe("deny_policy_delete", "DeleteRepositoryPolicy", {"repositoryName": repository})
        observe("policy_restored", "BatchGetImage", {"repositoryName": repository, "imageIds": [{"imageTag": "original"}]})
        lifecycle = json.dumps({"rules": [
            {"rulePriority": 1, "description": "Protect newest original-tag image", "selection": {"tagStatus": "tagged", "tagPrefixList": ["original"], "countType": "imageCountMoreThan", "countNumber": 1}, "action": {"type": "expire"}},
            {"rulePriority": 2, "description": "Keep newest owned image", "selection": {"tagStatus": "any", "countType": "imageCountMoreThan", "countNumber": 1}, "action": {"type": "expire"}}]})
        observe("lifecycle_put", "PutLifecyclePolicy", {"repositoryName": repository, "lifecyclePolicyText": lifecycle})
        observe("lifecycle_get", "GetLifecyclePolicy", {"repositoryName": repository})
        observe("lifecycle_invalid", "PutLifecyclePolicy", {"repositoryName": repository, "lifecyclePolicyText": json.dumps({"rules": []})})
        observe("lifecycle_invalid_zero_count", "PutLifecyclePolicy", {"repositoryName": repository, "lifecyclePolicyText": lifecycle.replace('"countNumber": 1', '"countNumber": 0')})
        observe("lifecycle_preview_start", "StartLifecyclePolicyPreview", {"repositoryName": repository})
        for attempt in range(13):
            preview = observe("lifecycle_preview_" + str(attempt), "GetLifecyclePolicyPreview", {"repositoryName": repository})
            if preview.get("output", {}).get("status") in {"COMPLETE", "FAILED"}:
                break
            time.sleep(5)
        observe("lifecycle_delete", "DeleteLifecyclePolicy", {"repositoryName": repository})
        observe("basic_scanning_configuration", "PutImageScanningConfiguration", {"repositoryName": repository, "imageScanningConfiguration": {"scanOnPush": False}})
        observe("batch_scanning_configuration", "BatchGetRepositoryScanningConfiguration", {"repositoryNames": owned})
        observe("start_scan_tiny_image", "StartImageScan", {"repositoryName": repository, "imageId": {"imageTag": "original"}})
        for attempt in range(7):
            scan = observe("describe_scan_tiny_image_" + str(attempt), "DescribeImageScanFindings", {"repositoryName": repository, "imageId": {"imageTag": "original"}})
            if scan.get("output", {}).get("imageScanStatus", {}).get("status") not in {"PENDING", "IN_PROGRESS"}:
                break
            time.sleep(5)
        observe("delete_nonempty", "DeleteRepository", {"repositoryName": repository, "force": False})
        image_digest = digest(changed.encode())
        index = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [{"mediaType": MEDIA, "size": len(changed.encode()), "digest": image_digest, "platform": {"architecture": "amd64", "os": "linux"}}]}, separators=(",", ":"))
        observe("manifest_index_put", "PutImage", {"repositoryName": repository, "imageManifest": index, "imageTag": "index"})
        observe("delete_referenced_image", "BatchDeleteImage", {"repositoryName": repository, "imageIds": [{"imageDigest": image_digest}]})
        observe("batch_delete_tag_and_missing", "BatchDeleteImage", {"repositoryName": repository, "imageIds": [{"imageTag": "http-tag"}, {"imageTag": "absent"}]})
        observe("list_after_delete", "ListImages", {"repositoryName": repository})
        fixture["capture_complete"] = True
    except Exception as error:
        fixture["capture_failure"] = {"type": type(error).__name__, "message": str(error) if isinstance(error, RuntimeError) else "Transport/capture exception; diagnostics discarded"}
    finally:
        for repository in reversed(owned):
            try:
                observe("delete_owned", "DeleteRepository", {"repositoryName": repository, "force": True}, cleanup=True)
                observe("verify_absent", "DescribeRepositories", {"repositoryNames": [repository]}, cleanup=True)
            except Exception as error:
                fixture["cleanup"].append({"repository": repository, "failure_type": type(error).__name__})
        fixture["cleanup_verified"] = len([row for row in fixture["cleanup"] if row.get("case") == "verify_absent" and row.get("code") == "RepositoryNotFoundException"]) == len(owned)
        if key_id:
            try:
                grants = kms("verify_grants_retired", "list-grants", {"KeyId": key_id}, cleanup=True)
                fixture["automatic_grant_retirement_verified"] = grants.get("output", {}).get("Grants") == []
                for grant in grants.get("output", {}).get("Grants", []):
                    kms("retire_remaining_owned_grant", "retire-grant", {"KeyId": key_id, "GrantId": grant["GrantId"]}, cleanup=True)
                if grants.get("output", {}).get("Grants"):
                    kms("verify_manual_grant_retirement", "list-grants", {"KeyId": key_id}, cleanup=True)
                kms("schedule_owned_key_deletion", "schedule-key-deletion", {"KeyId": key_id, "PendingWindowInDays": 7}, cleanup=True)
                state = kms("verify_key_pending_deletion", "describe-key", {"KeyId": key_id}, cleanup=True)
                fixture["cleanup_verified"] = fixture["cleanup_verified"] and state.get("output", {}).get("KeyMetadata", {}).get("KeyState") == "PendingDeletion"
            except Exception as error:
                fixture["cleanup_verified"] = False
                fixture["cleanup"].append({"key_id": key_id, "failure_type": type(error).__name__})
        fixture["elapsed_seconds"] = round(time.monotonic() - started, 3)
        save()
        print(str(path.relative_to(ROOT)) + " cleanup_verified=" + str(fixture["cleanup_verified"]), flush=True)
    return 0 if fixture["capture_complete"] and fixture["cleanup_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
