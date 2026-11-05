#!/usr/bin/env python3
"""Probe native S3 Tables multipart checksums on one uniquely owned table.

Requires boto3 and PyArrow. The output retains owned resource identities for
cleanup; publish only an explicitly sanitized copy, never this raw capture.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import signal
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output exists; choose a new path")
    config = Config(connect_timeout=5, read_timeout=20,
                    retries={"max_attempts": 0}, ignore_configured_endpoint_urls=True)
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    credentials = session.get_credentials().get_frozen_credentials()
    clients = {name: session.client(name, config=config) for name in ("sts", "s3tables", "s3")}
    identity = clients["sts"].get_caller_identity()
    if identity["Account"] != args.account:
        raise RuntimeError("Native account does not match --account")
    # C++ must not discover a local emulator endpoint or unrelated profile.
    for key in list(os.environ):
        if key.startswith("AWS_"):
            del os.environ[key]
    os.environ.update(AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
                      AWS_EC2_METADATA_DISABLED="true", AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
    import pyarrow
    import pyarrow.fs as fs

    name = "stackd-checksum-" + uuid.uuid4().hex
    bucket_arn = f"arn:{identity['Arn'].split(':')[1]}:s3tables:{args.region}:{args.account}:bucket/{name}"
    tables, s3 = clients["s3tables"], clients["s3"]
    table = {"tableBucketARN": bucket_arn, "namespace": "probe", "name": "checksums"}
    namespace = {"tableBucketARN": bucket_arn, "namespace": "probe"}
    bucket = {"tableBucketARN": bucket_arn}
    owned = []
    capture = {
        "source": "Native AWS S3 Tables, boto3 and unchanged PyArrow S3FileSystem",
        "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "profile": args.profile, "account": args.account, "region": args.region,
        "pyarrow_version": pyarrow.__version__, "boto3_version": boto3.__version__,
        "scope": "One unique owned table bucket, namespace and table; nine-byte objects; no policies or IAM changes",
        "primary_references": [
            "https://docs.aws.amazon.com/AmazonS3/latest/developerguide/developing-s3-tables-APIs.html",
            "https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html",
        ],
        "observations": [], "completed": False,
        "cleanup": {"verified": False, "remaining_owned": [], "observations": []},
    }

    def save():
        capture["cleanup"]["remaining_owned"] = [entry[0] for entry in owned]
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + "\n")

    def create(label, create_call, delete_call, get_call):
        # Register ownership before a possibly ambiguous network timeout.
        entry = (label, delete_call, get_call)
        owned.append(entry)
        save()
        try:
            create_call()
        except ClientError as error:
            if error.response["ResponseMetadata"]["HTTPStatusCode"] < 500:
                owned.remove(entry)
            raise
        capture["observations"].append({"operation": label, "code": "Success"})
        save()

    def interrupted(signum, frame):
        raise RuntimeError("Interrupted; owned cleanup required")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)

    try:
        create(bucket_arn, lambda: tables.create_table_bucket(name=name),
               lambda: tables.delete_table_bucket(**bucket), lambda: tables.get_table_bucket(**bucket))
        create(bucket_arn + "/probe", lambda: tables.create_namespace(tableBucketARN=bucket_arn, namespace=["probe"]),
               lambda: tables.delete_namespace(**namespace), lambda: tables.get_namespace(**namespace))
        create(bucket_arn + "/probe/checksums", lambda: tables.create_table(
            **table, format="ICEBERG", metadata={"iceberg": {"schema": {"fields": [
                {"name": "id", "type": "long", "required": False}]}}}),
               lambda: tables.delete_table(**table), lambda: tables.get_table(**table))
        warehouse = tables.get_table_metadata_location(**table)["warehouseLocation"]
        alias = warehouse.removeprefix("s3://").rstrip("/")
        if "/" in alias or not alias.endswith("--table-s3"):
            raise RuntimeError("Unexpected managed table warehouse; refusing an unrelated data-plane write")
        filesystem = fs.S3FileSystem(
            access_key=credentials.access_key, secret_key=credentials.secret_key,
            session_token=credentials.token, region=args.region, connect_timeout=5,
            request_timeout=20, background_writes=False,
            retry_strategy=fs.AwsStandardS3RetryStrategy(max_attempts=1))
        key = "data/pyarrow-checksum-probe"
        with filesystem.open_output_stream(alias + "/" + key) as stream:
            stream.write(b"123456789")
        head = s3.head_object(Bucket=alias, Key=key, ChecksumMode="ENABLED")
        response = s3.get_object(Bucket=alias, Key=key, ChecksumMode="ENABLED")
        with response["Body"] as body:
            received = body.read()
        capture["observations"].append({
            "operation": "pyarrow-multipart-write-and-sdk-read",
            "head": {key: value for key, value in head.items()
                     if key.startswith("Checksum") or key in ("ContentLength", "ETag", "ServerSideEncryption")},
            "bytes_match": received == b"123456789",
            "crc64nvme_matches_known_vector": head.get("ChecksumCRC64NVME") == "rosUhgp5mIg=",
        })
        if received != b"123456789" or head.get("ChecksumCRC64NVME") != "rosUhgp5mIg=":
            raise RuntimeError("Native multipart result differs from the expected CRC64NVME vector")
        key = "data/completion-checksum-probe"
        baseline = b"old bytes"
        previous = s3.put_object(Bucket=alias, Key=key, Body=baseline)
        capture["data_request_headers"] = []

        def capture_headers(request, **kwargs):
            permitted = {"if-match", "if-none-match", "x-amz-checksum-type", "x-amz-mp-object-size"}
            capture["data_request_headers"].append({"method": request.method, "headers": {
                name.lower(): value.decode("ascii") if isinstance(value, bytes) else str(value)
                for name, value in request.headers.items() if name.lower() in permitted}})

        s3.meta.events.register("before-send.s3.CompleteMultipartUpload", capture_headers)
        s3.meta.events.register("before-send.s3.PutObject", capture_headers)
        try:
            replacement = s3.put_object(Bucket=alias, Key=key, Body=b"new bytes")
        except ClientError as error:
            capture["observations"].append({"operation": "unconditional-put-existing",
                                           "code": error.response["Error"]["Code"],
                                           "http_status": error.response["ResponseMetadata"]["HTTPStatusCode"]})
            if error.response["ResponseMetadata"]["HTTPStatusCode"] != 412:
                raise
        else:
            previous, baseline = replacement, b"new bytes"
            capture["observations"].append({"operation": "unconditional-put-existing", "code": "Success"})
        try:
            s3.put_object(Bucket=alias, Key=key, Body=baseline)
        except ClientError as error:
            capture["observations"].append({"operation": "identical-put-existing",
                                           "code": error.response["Error"]["Code"],
                                           "http_status": error.response["ResponseMetadata"]["HTTPStatusCode"]})
            if error.response["ResponseMetadata"]["HTTPStatusCode"] != 412:
                raise
        else:
            capture["observations"].append({"operation": "identical-put-existing", "code": "Success"})
        try:
            invalid_upload = s3.create_multipart_upload(
                Bucket=alias, Key=key, ChecksumAlgorithm="CRC64NVME", ChecksumType="COMPOSITE")
        except ClientError as error:
            capture["observations"].append({"operation": "crc64-composite-initiation",
                                           "code": error.response["Error"]["Code"],
                                           "http_status": error.response["ResponseMetadata"]["HTTPStatusCode"]})
            if error.response["ResponseMetadata"]["HTTPStatusCode"] != 400:
                raise
        else:
            s3.abort_multipart_upload(Bucket=alias, Key=key, UploadId=invalid_upload["UploadId"])
            raise RuntimeError("Native CRC64NVME composite initiation unexpectedly succeeded")
        upload = s3.create_multipart_upload(
            Bucket=alias, Key=key, ChecksumAlgorithm="CRC64NVME", ChecksumType="FULL_OBJECT")
        upload_id = upload["UploadId"]
        try:
            part = s3.upload_part(Bucket=alias, Key=key, UploadId=upload_id,
                                  PartNumber=1, Body=b"123456789", ChecksumCRC64NVME="rosUhgp5mIg=")
            selected = {"PartNumber": 1, "ETag": part["ETag"], "ChecksumCRC64NVME": "rosUhgp5mIg="}
            for label, parts, options, status in [
                ("wrong-part-checksum", [dict(selected, ChecksumCRC64NVME="AAAAAAAAAAA=")], {}, 400),
                ("wrong-full-checksum", [selected], {"ChecksumCRC64NVME": "AAAAAAAAAAA="}, 400),
                ("wrong-checksum-type", [selected], {"ChecksumType": "COMPOSITE"}, 400),
                ("wrong-object-size", [selected], {"MpuObjectSize": 1}, 400),
                ("unsupported-object-size", [selected], {"MpuObjectSize": 9}, 400),
                ("unconditional-complete-existing", [selected], {"ChecksumType": "FULL_OBJECT"}, 412),
                ("if-match-complete-existing", [selected], {"ChecksumType": "FULL_OBJECT", "IfMatch": previous["ETag"]}, 501),
            ]:
                try:
                    s3.complete_multipart_upload(Bucket=alias, Key=key, UploadId=upload_id,
                                                 MultipartUpload={"Parts": parts}, **options)
                except ClientError as error:
                    row = {"operation": label, "code": error.response["Error"]["Code"],
                           "http_status": error.response["ResponseMetadata"]["HTTPStatusCode"]}
                    capture["observations"].append(row)
                    save()
                    if row["http_status"] != status:
                        raise
                else:
                    raise RuntimeError("Native invalid completion unexpectedly succeeded: " + label)
                with s3.get_object(Bucket=alias, Key=key)["Body"] as body:
                    row["previous_bytes_preserved"] = body.read() == baseline
                retained = s3.list_parts(Bucket=alias, Key=key, UploadId=upload_id)["Parts"]
                row["staged_part_retained"] = (
                    len(retained) == 1 and retained[0]["ETag"] == part["ETag"]
                    and retained[0].get("ChecksumCRC64NVME") == "rosUhgp5mIg=")
                if not row["previous_bytes_preserved"] or not row["staged_part_retained"]:
                    raise RuntimeError("Rejected completion changed owned state: " + label)
                save()
        finally:
            try:
                s3.abort_multipart_upload(Bucket=alias, Key=key, UploadId=upload_id)
            except ClientError as error:
                if error.response["Error"]["Code"] != "NoSuchUpload":
                    raise
        key = "data/explicit-completion-probe"
        upload_id = s3.create_multipart_upload(
            Bucket=alias, Key=key, ChecksumAlgorithm="CRC64NVME", ChecksumType="FULL_OBJECT")["UploadId"]
        try:
            part = s3.upload_part(Bucket=alias, Key=key, UploadId=upload_id, PartNumber=1,
                                  Body=b"123456789", ChecksumCRC64NVME="rosUhgp5mIg=")
            completed = s3.complete_multipart_upload(
                Bucket=alias, Key=key, UploadId=upload_id,
                MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": part["ETag"], "ChecksumCRC64NVME": "rosUhgp5mIg="}]},
                ChecksumCRC64NVME="rosUhgp5mIg=", ChecksumType="FULL_OBJECT")
            with s3.get_object(Bucket=alias, Key=key, ChecksumMode="ENABLED")["Body"] as body:
                matches = body.read() == b"123456789"
            capture["observations"].append({
                "operation": "explicit-crc64-full-object-completion",
                "checksum": completed.get("ChecksumCRC64NVME"), "type": completed.get("ChecksumType"),
                "bytes_match": matches})
            if not matches or completed.get("ChecksumCRC64NVME") != "rosUhgp5mIg=" or completed.get("ChecksumType") != "FULL_OBJECT":
                raise RuntimeError("Native explicit completion returned unexpected integrity metadata")
        finally:
            try:
                s3.abort_multipart_upload(Bucket=alias, Key=key, UploadId=upload_id)
            except ClientError as error:
                if error.response["Error"]["Code"] != "NoSuchUpload":
                    raise
        capture["completed"] = True
    except Exception as error:
        capture["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        for entry in list(reversed(owned)):
            label, delete_call, get_call = entry
            row = {"owned": label}
            try:
                try:
                    delete_call()
                except ClientError as error:
                    if error.response["Error"]["Code"] != "NotFoundException":
                        raise
                try:
                    get_call()
                except ClientError as error:
                    if error.response["Error"]["Code"] != "NotFoundException":
                        raise
                    owned.remove(entry)
                    row["absence_verified"] = True
                else:
                    row["absence_verified"] = False
            except Exception as error:
                row["error"] = {"type": type(error).__name__, "message": str(error)}
            capture["cleanup"]["observations"].append(row)
            save()
        capture["cleanup"]["verified"] = not owned
        save()
    if owned:
        raise RuntimeError("Owned cleanup is incomplete; consult the private capture")
    print("Native checksum capture complete; owned cleanup verified")


if __name__ == "__main__":
    main()
