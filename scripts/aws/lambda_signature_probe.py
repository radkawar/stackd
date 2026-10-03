#!/usr/bin/env python3
"""Capture exact-owned native Signer ZIP canonicalization vectors."""
import argparse
import base64
import io
import json
from pathlib import Path
import time
import uuid
import zipfile

import boto3


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    session = boto3.Session(region_name="us-east-1")
    identity = session.client("sts").get_caller_identity()
    if identity["Account"] != args.account:
        raise RuntimeError("Refusing mutation outside authorized probe account")
    token = uuid.uuid4().hex[:12]
    bucket = "stackd-next-lambda-signature-" + token
    profile = "stackd_next_lambda_signature_" + token
    s3, signer = session.client("s3"), session.client("signer")
    result = {"account": identity["Account"], "region": "us-east-1", "bucket": bucket,
              "profile": profile, "requests": [], "vectors": [], "cleanup": {}}
    created_bucket = created_profile = False

    def call(client, operation, **kwargs):
        reply = getattr(client, operation)(**kwargs)
        result["requests"].append({"operation": operation, "requestId": reply.get("ResponseMetadata", {}).get("RequestId")})
        return reply

    try:
        call(s3, "create_bucket", Bucket=bucket)
        created_bucket = True
        call(s3, "put_bucket_tagging", Bucket=bucket, Tagging={"TagSet": [{"Key": "stackd-probe", "Value": token}]})
        call(s3, "put_bucket_versioning", Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
        reply = call(signer, "put_signing_profile", profileName=profile, platformId="AWSLambda-SHA384-ECDSA", tags={"stackd-probe": token})
        created_profile = True
        result["profileVersionArn"] = reply["profileVersionArn"]
        vectors = [("empty-a", [("a", b"")]), ("empty-ab", [("ab", b"")]),
                   ("a-b", [("a", b"b")]), ("ab-c", [("ab", b"c")]),
                   ("a-bc", [("a", b"bc")]), ("multi", [("a", b"b"), ("c", b"d")]),
                   ("directory-unicode-binary", [("dir/", b""), ("dir/\u00e9", bytes(range(256)))])]
        for label, entries in vectors:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
                for name, data in entries:
                    archive.writestr(zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0)), data)
            unsigned = buffer.getvalue()
            uploaded = call(s3, "put_object", Bucket=bucket, Key=label+".zip", Body=unsigned)
            reply = call(signer, "start_signing_job", source={"s3": {"bucketName": bucket, "key": label+".zip", "version": uploaded["VersionId"]}}, destination={"s3": {"bucketName": bucket, "prefix": "signed/"}}, profileName=profile, clientRequestToken=uuid.uuid4().hex)
            deadline = time.monotonic() + 120
            while True:
                job = call(signer, "describe_signing_job", jobId=reply["jobId"])
                if job["status"] != "InProgress":
                    break
                if time.monotonic() > deadline:
                    raise RuntimeError("Owned signing job did not finish")
                time.sleep(1)
            vector = {"label": label, "unsignedZipBase64": base64.b64encode(unsigned).decode(), "job": {k: v for k, v in job.items() if k != "ResponseMetadata"}}
            if job["status"] == "Succeeded":
                location = job["signedObject"]["s3"]
                signed = call(s3, "get_object", Bucket=location["bucketName"], Key=location["key"])["Body"].read()
                vector["signedZipBase64"] = base64.b64encode(signed).decode()
            result["vectors"].append(vector)
    finally:
        if created_profile:
            call(signer, "cancel_signing_profile", profileName=profile)
            result["cleanup"]["profileCancelled"] = True
            result["cleanup"]["retainedSignerHistory"] = "AWS retains signing jobs and cancelled profile versions; no deletion API exists."
        if created_bucket:
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
                objects = [{"Key": obj["Key"], "VersionId": obj["VersionId"]} for field in ("Versions", "DeleteMarkers") for obj in page.get(field, [])]
                if objects:
                    deleted = call(s3, "delete_objects", Bucket=bucket, Delete={"Objects": objects})
                    if deleted.get("Errors"):
                        raise RuntimeError("Owned object cleanup failed")
            call(s3, "delete_bucket", Bucket=bucket)
            result["cleanup"]["bucketDeleted"] = True
        Path(args.output).write_text(json.dumps(result, indent=2, default=str) + "\n")
        print(json.dumps({"fixture": args.output, "cleanup": result["cleanup"], "vectors": [{"label": v["label"], "status": v["job"]["status"]} for v in result["vectors"]]}))


if __name__ == "__main__":
    main()
