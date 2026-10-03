#!/usr/bin/env python3
"""Capture actual Athena cancellation without CLI startup latency between submit/stop.

One unique workgroup/bucket, one bounded scalar query over generated integers,
zero customer data scans, immediate StopQueryExecution and <=60s terminal wait.
"""
import copy
import json
import time
import uuid

from glue_native_common import Capture, arguments, require
from signed_requests import signed_post


def main():
    cap = Capture(arguments(__doc__), "stackd-athena-cancel-", [
        "https://docs.aws.amazon.com/athena/latest/APIReference/API_StopQueryExecution.html",
        "https://docs.aws.amazon.com/athena/latest/APIReference/API_QueryExecutionStatus.html",
        "https://aws.amazon.com/athena/pricing/",
    ], {"max_calls": 45, "wall_seconds": 150, "max_buckets": 1, "max_workgroups": 1,
        "max_queries": 1, "scan_cutoff_bytes": 10485760, "poll_seconds": 60,
        "max_generated_join_pairs": 100000000, "cost_usd_upper_estimate": 0.01,
        "cost_basis": "No customer data scan or provisioned compute; immediate cancellation; allowance covers tiny result/S3 requests."})
    bucket, group = cap.prefix, cap.prefix + "-wg"
    query = None
    created_bucket = created_group = False
    def api(label, operation, parameters):
        cli_operation = "".join(("-" + char.lower()) if char.isupper() else char for char in operation).lstrip("-")
        if not cap.args.native:
            return cap.request(label, "athena", cli_operation, parameters)
        cap.calls += 1
        start = time.time_ns() // 1_000_000
        response = signed_post("athena.us-east-1.amazonaws.com", "athena", json.dumps(parameters).encode(),
                               {"content-type": "application/x-amz-json-1.1", "x-amz-target": "AmazonAthena." + operation})
        try:
            body = json.loads(response.body)
        except json.JSONDecodeError:
            result = {"code": "NonJSONResponse", "http_status": response.status, "body_utf8": response.body.decode("utf-8", "replace")}
        else:
            result = {"http_status": response.status, "request_id": response.request_id}
            if 200 <= response.status < 300:
                result.update(code="Success", output=body)
            else:
                result.update(code=body.get("__type", "UnknownNativeError").split("#")[-1], error=body)
        cap.capture["observations"].append({"label": label, "service": "athena", "operation": cli_operation,
                                             "input": copy.deepcopy(parameters), "started_ms": start,
                                             "finished_ms": time.time_ns() // 1_000_000, "result": result})
        cap.save()
        print(label + ": " + result["code"], flush=True)
        return result
    try:
        cap.identity()
        created_bucket = True
        require(cap.request("create-bucket", "s3api", "create-bucket", {"Bucket": bucket}))
        created_group = True
        require(cap.request("create-workgroup", "athena", "create-work-group", {"Name": group, "Configuration": {"BytesScannedCutoffPerQuery": 10485760, "PublishCloudWatchMetricsEnabled": False, "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/results/"}}}))
        token = cap.name(uuid.uuid4().hex, "CANCEL_REQUEST_TOKEN")
        query = require(api("start-cancellable-query", "StartQueryExecution", {"WorkGroup": group, "ClientRequestToken": token, "QueryString": "SELECT sum(sin(a.x + b.x)) FROM UNNEST(sequence(1,10000)) a(x) CROSS JOIN UNNEST(sequence(1,10000)) b(x)"}))["QueryExecutionId"]
        cap.name(query, "CANCEL_QUERY_ID")
        require(api("stop-immediately", "StopQueryExecution", {"QueryExecutionId": query}))
        states = []
        for attempt in range(30):
            execution = require(api("state-" + str(attempt), "GetQueryExecution", {"QueryExecutionId": query}))["QueryExecution"]
            states.append(execution["Status"]["State"])
            if states[-1] in ("SUCCEEDED", "FAILED", "CANCELLED"):
                break
            time.sleep(2)
        cap.capture["terminal"] = execution
        cap.capture["transitions"] = states
        api("stop-terminal-again", "StopQueryExecution", {"QueryExecutionId": query})
        api("cancelled-results", "GetQueryResults", {"QueryExecutionId": query})
        cap.capture["completed"] = True
        cap.capture["cancellation_observed"] = states[-1] == "CANCELLED"
        if not cap.capture["cancellation_observed"]:
            raise RuntimeError("Cancellation lost terminal-state race; native state retained")
    except Exception as error:
        cap.capture["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        cap.cleaning = True
        remaining = []
        if query:
            cap.request("cleanup-stop-query", "athena", "stop-query-execution", {"QueryExecutionId": query})
            state = cap.request("cleanup-final-state", "athena", "get-query-execution", {"QueryExecutionId": query})
            if state["code"] != "Success" or state["output"]["QueryExecution"]["Status"]["State"] not in ("SUCCEEDED", "FAILED", "CANCELLED"):
                remaining.append("query:" + query)
        if created_group:
            cap.request("cleanup-workgroup", "athena", "delete-work-group", {"WorkGroup": group, "RecursiveDeleteOption": True})
            if cap.request("verify-workgroup-absent", "athena", "get-work-group", {"WorkGroup": group})["code"] != "InvalidRequestException":
                remaining.append(group)
        if created_bucket:
            listing = cap.request("cleanup-owned-results", "s3api", "list-objects-v2", {"Bucket": bucket, "MaxKeys": 10})
            if listing["code"] == "Success":
                if listing["output"].get("IsTruncated"):
                    remaining.append("object-bound:" + bucket)
                for obj in listing["output"].get("Contents", []):
                    cap.request("cleanup-result-object", "s3api", "delete-object", {"Bucket": bucket, "Key": obj["Key"]})
            cap.request("cleanup-bucket", "s3api", "delete-bucket", {"Bucket": bucket})
            for attempt in range(5):
                absent = cap.request("verify-bucket-absent-" + str(attempt), "s3api", "head-bucket", {"Bucket": bucket})
                if absent["code"] in ("404", "NoSuchBucket", "NotFound"):
                    break
                time.sleep(2)
            else:
                remaining.append(bucket)
        cap.finish(remaining)


if __name__ == "__main__":
    main()
