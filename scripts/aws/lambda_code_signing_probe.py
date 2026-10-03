#!/usr/bin/env python3
"""Capture one real AWS Lambda Signer envelope with exact-owned cleanup.

AWS Signer Lambda jobs are free; this creates a short-lived versioned S3 bucket.
Signer does not delete job/profile-version history; the profile is cancelled.
"""
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
    bucket = "stackd-next-lambda-signing-" + token
    profile = "stackd_next_lambda_signing_" + token
    s3, signer = session.client("s3"), session.client("signer")
    result = {"account": identity["Account"], "region": "us-east-1", "bucket": bucket,
              "profile": profile, "requests": [], "cleanup": {}}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
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
        code = io.BytesIO()
        with zipfile.ZipFile(code, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("handler.py", "def handler(event, context):\n    return {'signed': True}\n")
        unsigned = code.getvalue()
        result["unsignedZipBase64"] = base64.b64encode(unsigned).decode()
        uploaded = call(s3, "put_object", Bucket=bucket, Key="unsigned.zip", Body=unsigned)
        reply = call(signer, "start_signing_job", source={"s3": {"bucketName": bucket, "key": "unsigned.zip", "version": uploaded["VersionId"]}}, destination={"s3": {"bucketName": bucket, "prefix": "signed/"}}, profileName=profile, clientRequestToken=token)
        job = reply["jobId"]
        result["jobId"] = job
        deadline = time.monotonic() + 120
        while True:
            detail = call(signer, "describe_signing_job", jobId=job)
            if detail["status"] != "InProgress":
                break
            if time.monotonic() > deadline:
                raise RuntimeError("Signer job did not finish within 120 seconds")
            time.sleep(1)
        result["job"] = {k: v for k, v in detail.items() if k != "ResponseMetadata"}
        if detail["status"] != "Succeeded":
            raise RuntimeError("Signer failed: " + detail.get("statusReason", ""))
        location = detail["signedObject"]["s3"]
        signed = call(s3, "get_object", Bucket=location["bucketName"], Key=location["key"])["Body"].read()
        result["signedZipBase64"] = base64.b64encode(signed).decode()
        with zipfile.ZipFile(io.BytesIO(signed)) as archive:
            result["signedEntries"] = archive.namelist()
            result["signature"] = archive.read("META-INF/AWS.SF").decode() if "META-INF/AWS.SF" in archive.namelist() else {name: base64.b64encode(archive.read(name)).decode() for name in archive.namelist() if name != "handler.py"}
    finally:
        if created_profile:
            call(signer, "cancel_signing_profile", profileName=profile)
            result["cleanup"]["profileCancelled"] = True
            result["cleanup"]["retainedSignerHistory"] = "AWS retains signing jobs and cancelled profile versions; no deletion API exists."
        if created_bucket:
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
                objects = [{"Key": v["Key"], "VersionId": v["VersionId"]} for field in ("Versions", "DeleteMarkers") for v in page.get(field, [])]
                if objects:
                    deleted = call(s3, "delete_objects", Bucket=bucket, Delete={"Objects": objects})
                    if deleted.get("Errors"):
                        raise RuntimeError("Owned object cleanup failed")
            call(s3, "delete_bucket", Bucket=bucket)
            result["cleanup"]["bucketDeleted"] = True
        output.write_text(json.dumps(result, indent=2, default=str) + "\n")
        print(json.dumps({"fixture": str(output), "cleanup": result["cleanup"], "jobId": result.get("jobId")}))


if __name__ == "__main__":
    main()
