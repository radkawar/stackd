#!/usr/bin/env python3
"""Native Glue Python-shell -> S3 -> catalog -> Athena -> S3 result consumer.

Use --native only for the bounded owned AWS run; --endpoint-url is an isolated
local replay using explicit test credentials. Failed captures are never replaced.
Use --manifest-only for tiny partitioned CTAS/INSERT calibration with no Glue job.
"""
import json
from pathlib import Path
import tempfile
import time
import uuid

from glue_native_common import Capture, arguments, descriptor, require
import athena_event_capture

REFERENCES = [
    "https://docs.aws.amazon.com/glue/latest/dg/add-job-python.html",
    "https://docs.aws.amazon.com/glue/latest/webapi/API_CreateJob.html",
    "https://docs.aws.amazon.com/glue/latest/webapi/API_GetJobRun.html",
    "https://docs.aws.amazon.com/athena/latest/APIReference/API_StartQueryExecution.html",
    "https://docs.aws.amazon.com/athena/latest/APIReference/API_GetQueryResults.html",
    "https://docs.aws.amazon.com/athena/latest/APIReference/API_StopQueryExecution.html",
    "https://docs.aws.amazon.com/athena/latest/APIReference/API_UpdateWorkGroup.html",
    "https://docs.aws.amazon.com/athena/latest/APIReference/API_DeleteWorkGroup.html",
    "https://docs.aws.amazon.com/athena/latest/APIReference/API_CreatePreparedStatement.html",
    "https://docs.aws.amazon.com/athena/latest/ug/athena-events.html",
    "https://docs.aws.amazon.com/glue/latest/dg/automating-awsglue-with-cloudwatch-events.html",
    "https://aws.amazon.com/glue/pricing/", "https://aws.amazon.com/athena/pricing/",
]
TERMINAL_QUERY = {"SUCCEEDED", "FAILED", "CANCELLED"}
TERMINAL_JOB = {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR", "EXPIRED"}


def manifest_probe(args):
    """Calibrate native writer manifests; retain application mode unchanged."""
    cap = Capture(args, "stackd-manifest-", REFERENCES + [
        "https://docs.aws.amazon.com/athena/latest/ug/querying-ctas.html",
        "https://docs.aws.amazon.com/athena/latest/ug/insert-into.html",
        "https://docs.aws.amazon.com/athena/latest/APIReference/API_QueryExecutionStatistics.html",
    ], {
        "max_calls": 180, "wall_seconds": 600, "cli_timeout_seconds": 30,
        "max_buckets": 1, "max_databases": 1, "max_tables": 1,
        "max_workgroups": 1, "max_iam_roles": 1, "max_jobs": 0,
        "max_query_submissions": 4, "query_bytes_scanned_cutoff": 10485760,
        "query_poll_deadline_seconds": 90, "max_total_object_bytes": 1048576,
        "max_manifest_pages": 8, "cost_usd_upper_estimate": 0.10,
        "cost_basis": "Four tiny Athena queries capped at 10MiB scanned each; <1MiB S3 and bounded catalog/IAM requests. No Glue jobs, compute or customer KMS keys.",
    })
    bucket, db = cap.prefix, cap.prefix.replace("-", "_")
    wg, role = cap.prefix + "-wg", cap.prefix + "-reader"
    for value, replacement in ((db, "stackd_manifest_owned"), (wg, "stackd-manifest-owned-wg"),
                               (role, "stackd-manifest-owned-reader")):
        cap.name(value, replacement)
    resources = {"bucket": False, "database": False, "workgroup": False, "role": False}
    queries = []
    temp = tempfile.TemporaryDirectory(prefix="stackd-manifest-capture-")
    cap.name(temp.name, "OWNED_TEMP")

    def call(label, service, operation, params, **kwargs):
        return cap.request(label, service, operation, params, **kwargs)

    def athena(label, operation, params, **kwargs):
        return call(label, "athena", operation, params, **kwargs)

    def get(label, location, environment=None):
        object_bucket, key = location[5:].split("/", 1)
        if object_bucket != bucket:
            raise RuntimeError("Manifest points outside the owned bucket")
        path = Path(temp.name) / (label + ".data")
        response = call(label, "s3api", "get-object", {"Bucket": bucket, "Key": key},
                        environment=environment, options=["--bucket", bucket, "--key", key, str(path)],
                        cli_input=False)
        if response["code"] == "Success":
            body = path.read_bytes()
            if len(body) > 1048576:
                raise RuntimeError("Manifest object byte bound exceeded")
            text = body.decode("utf-8")
            cap.capture.setdefault("consumers", {})[label] = {
                "body_utf8": text, "byte_count": len(body),
                "normalized_byte_count": len(cap.normalize(text).encode("utf-8")),
                "location": location}
            cap.save()
        return response

    def query(label, sql):
        token = cap.name(uuid.uuid4().hex, label.upper() + "_REQUEST_TOKEN")
        response = require(athena("query-" + label, "start-query-execution", {
            "QueryString": sql, "ClientRequestToken": token, "WorkGroup": wg,
            "QueryExecutionContext": {"Database": db, "Catalog": "AwsDataCatalog"}}))
        query_id = cap.name(response["QueryExecutionId"], label.upper() + "_QUERY_ID")
        queries.append(query_id)
        deadline, states = time.monotonic() + 90, []
        while time.monotonic() < deadline:
            execution = require(athena(label + "-poll-" + str(len(states)), "get-query-execution",
                                       {"QueryExecutionId": query_id}))["QueryExecution"]
            state = execution["Status"]["State"]
            states.append(state)
            if state in TERMINAL_QUERY:
                cap.capture.setdefault("query_terminal", {})[label] = execution
                cap.capture.setdefault("query_transitions", {})[label] = states
                cap.save()
                return query_id, execution
            time.sleep(2)
        raise RuntimeError("Manifest query polling deadline: " + label)

    def results(label, query_id, kind, **kwargs):
        return athena(label, "get-query-results",
                      dict(QueryExecutionId=query_id, QueryResultType=kind, **kwargs))

    def policy(deny=False):
        statements = [
            {"Effect": "Allow", "Action": ["athena:GetQueryExecution", "athena:GetQueryResults"],
             "Resource": f"arn:aws:athena:us-east-1:{cap.account}:workgroup/{wg}"},
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
             "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]},
        ]
        if deny:
            statements.append({"Effect": "Deny", "Action": "s3:GetObject",
                               "Resource": f"arn:aws:s3:::{bucket}/results/*"})
        return json.dumps({"Version": "2012-10-17", "Statement": statements})

    try:
        cap.identity()
        cap.capture["kind"] = "manifest"
        cap.capture["owned_resources"] = {"bucket": bucket, "database": db, "table": "written",
                                          "workgroup": wg, "reader_role": role}
        cap.capture["uncertainty"] = [
            "One account/region and Athena engine version 3; no general writer file ordering guarantee.",
            "Current IAM policy propagation is observed, not assigned a contractual duration.",
            "Native query history cannot be purged; all owned compute is terminal and resources deleted.",
        ]
        resources["bucket"] = True
        require(call("create-bucket", "s3api", "create-bucket", {"Bucket": bucket}))
        resources["database"] = True
        require(call("create-database", "glue", "create-database", {"DatabaseInput": {"Name": db}}))
        resources["workgroup"] = True
        require(athena("create-workgroup", "create-work-group", {
            "Name": wg, "Configuration": {
                "EnforceWorkGroupConfiguration": False, "PublishCloudWatchMetricsEnabled": False,
                "BytesScannedCutoffPerQuery": 10485760,
                "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/results/",
                                        "EncryptionConfiguration": {"EncryptionOption": "SSE_S3"}},
                "EngineVersion": {"SelectedEngineVersion": "Athena engine version 3"}}}))
        sqls = {
            "ctas": f"CREATE TABLE written WITH (format='PARQUET', external_location='s3://{bucket}/data/written/', partitioned_by=ARRAY['p']) AS SELECT * FROM (VALUES (1, 'a'), (2, 'b')) AS t(id,p)",
            "insert": "INSERT INTO written VALUES (3, 'c'), (4, 'd')",
        }
        for label, sql in sqls.items():
            query_id, execution = query(label, sql)
            if execution["Status"]["State"] != "SUCCEEDED":
                raise RuntimeError("Native manifest writer failed: " + label)
            location = execution["Statistics"]["DataManifestLocation"]
            require(get("consume-" + label + "-manifest", location))
            results(label + "-manifest-full", query_id, "DATA_MANIFEST")
            results(label + "-rows-full", query_id, "DATA_ROWS")
            for boundary in (2, 3):
                results(label + "-manifest-limit-" + str(boundary), query_id, "DATA_MANIFEST",
                        MaxResults=boundary)
            page = require(results(label + "-manifest-page-1", query_id, "DATA_MANIFEST", MaxResults=1))
            manifest_token = page.get("NextToken")
            for index in range(2, 9):
                if not page.get("NextToken"):
                    break
                token = cap.name(page["NextToken"], label.upper() + "_MANIFEST_PAGE_" + str(index))
                page = require(results(label + "-manifest-page-" + str(index), query_id, "DATA_MANIFEST",
                                       MaxResults=1, NextToken=token))
            if page.get("NextToken"):
                raise RuntimeError("Manifest page bound exceeded")
            if manifest_token:
                results(label + "-manifest-token-as-rows", query_id, "DATA_ROWS",
                        MaxResults=1, NextToken=manifest_token)
            row_page = require(results(label + "-rows-page-1", query_id, "DATA_ROWS", MaxResults=1))
            if row_page.get("NextToken"):
                token = cap.name(row_page["NextToken"], label.upper() + "_ROWS_PAGE_2")
                results(label + "-rows-page-2", query_id, "DATA_ROWS", MaxResults=1, NextToken=token)
                results(label + "-rows-token-as-manifest", query_id, "DATA_MANIFEST",
                        MaxResults=1, NextToken=token)
        call("written-table", "glue", "get-table", {"DatabaseName": db, "Name": "written"})
        call("written-partitions", "glue", "get-partitions", {"DatabaseName": db, "TableName": "written", "MaxResults": 10})
        selected, execution = query("select", "SELECT id,p FROM written ORDER BY id")
        if execution["Status"]["State"] != "SUCCEEDED":
            raise RuntimeError("Native manifest data consumer failed")
        results("select-rows", selected, "DATA_ROWS")
        results("select-manifest", selected, "DATA_MANIFEST")
        selected_page = require(results("select-rows-page-1", selected, "DATA_ROWS", MaxResults=1))
        if selected_page.get("NextToken"):
            token = cap.name(selected_page["NextToken"], "SELECT_ROWS_PAGE_2")
            results("select-rows-page-2", selected, "DATA_ROWS", MaxResults=1, NextToken=token)
            results("select-rows-token-as-manifest", selected, "DATA_MANIFEST", MaxResults=1, NextToken=token)
            # Writers return no DATA_ROWS records/tokens natively. Retain both
            # cross-query controls rather than inventing a writer rows token.
            for writer in ("ctas", "insert"):
                writer_id = cap.capture["query_terminal"][writer]["QueryExecutionId"]
                label = writer + "-select-rows-token-as-manifest"
                cross = results(label, writer_id, "DATA_MANIFEST", MaxResults=1, NextToken=token)
                if cross["code"] == "Success":
                    # Compute byte positions before owned-name normalization.
                    # A partial URI no longer contains the full name to replace.
                    raw_body = cap.capture["consumers"]["consume-" + writer + "-manifest"]["body_utf8"].encode()
                    cap.capture.setdefault("manifest_body_byte_offsets", {})[label] = [
                        [raw_body.find(cell["VarCharValue"].encode()) if "VarCharValue" in cell else None
                         for cell in row["Data"]] for row in cross["output"]["ResultSet"]["Rows"]]
                    cap.save()
                results(writer + "-select-rows-token-as-rows", writer_id, "DATA_ROWS",
                        MaxResults=1, NextToken=token)
        failed, execution = query("failed", "INSERT INTO written SELECT missing_column, 'e' FROM written")
        if execution["Status"]["State"] != "FAILED":
            raise RuntimeError("Expected invalid-column INSERT to fail")
        results("failed-manifest", failed, "DATA_MANIFEST")
        results("failed-rows", failed, "DATA_ROWS")
        trust = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{cap.account}:root"},
            "Action": "sts:AssumeRole"}]}
        resources["role"] = True
        reader_role = require(call("create-reader-role", "iam", "create-role", {
            "RoleName": role, "AssumeRolePolicyDocument": json.dumps(trust)}))["Role"]
        cap.name(reader_role["RoleId"], "MANIFEST_READER_ROLE_ID")
        require(call("reader-policy-allow", "iam", "put-role-policy", {
            "RoleName": role, "PolicyName": "owned", "PolicyDocument": policy()}))
        reader = cap.assume(reader_role["Arn"])
        ctas_id = cap.capture["query_terminal"]["ctas"]["QueryExecutionId"]
        ctas_location = cap.capture["query_terminal"]["ctas"]["Statistics"]["DataManifestLocation"]
        for attempt in range(12):
            allowed = get("reader-manifest-allow-poll-" + str(attempt), ctas_location, reader)
            if allowed["code"] == "Success":
                break
            time.sleep(5 if args.native else 0)
        require(allowed)
        athena("reader-manifest-allowed", "get-query-results",
               {"QueryExecutionId": ctas_id, "QueryResultType": "DATA_MANIFEST"}, environment=reader)
        require(call("reader-policy-deny", "iam", "put-role-policy", {
            "RoleName": role, "PolicyName": "owned", "PolicyDocument": policy(True)}))
        for attempt in range(12):
            denied = get("reader-manifest-deny-poll-" + str(attempt), ctas_location, reader)
            if denied["code"] == "AccessDenied":
                break
            time.sleep(5 if args.native else 0)
        if denied["code"] != "AccessDenied":
            raise RuntimeError("Current S3 explicit denial was not observed")
        athena("reader-manifest-current-s3-deny", "get-query-results",
               {"QueryExecutionId": ctas_id, "QueryResultType": "DATA_MANIFEST"}, environment=reader)
        cap.capture["completed"] = True
    except Exception as error:
        cap.capture["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        cap.cleaning = True
        remaining = []
        for query_id in queries:
            athena("cleanup-stop-query", "stop-query-execution", {"QueryExecutionId": query_id})
            observed = athena("cleanup-query-state", "get-query-execution", {"QueryExecutionId": query_id})
            if observed["code"] != "Success" or observed["output"]["QueryExecution"]["Status"]["State"] not in TERMINAL_QUERY:
                remaining.append("query:" + query_id)
        if resources["workgroup"]:
            athena("cleanup-delete-workgroup", "delete-work-group", {"WorkGroup": wg, "RecursiveDeleteOption": True})
            if athena("verify-workgroup-absent", "get-work-group", {"WorkGroup": wg})["code"] != "InvalidRequestException":
                remaining.append(wg)
        if resources["database"]:
            call("cleanup-delete-table", "glue", "delete-table", {"DatabaseName": db, "Name": "written"})
            if call("verify-table-absent", "glue", "get-table", {"DatabaseName": db, "Name": "written"})["code"] != "EntityNotFoundException":
                remaining.append(db + ".written")
            call("cleanup-delete-database", "glue", "delete-database", {"Name": db})
            if call("verify-database-absent", "glue", "get-database", {"Name": db})["code"] != "EntityNotFoundException":
                remaining.append(db)
        if resources["bucket"]:
            listing = call("cleanup-list-owned-objects", "s3api", "list-objects-v2", {"Bucket": bucket, "MaxKeys": 100})
            if listing["code"] == "Success":
                if listing["output"].get("IsTruncated"):
                    remaining.append("unexpected-object-bound:" + bucket)
                objects = listing["output"].get("Contents", [])
                if sum(item["Size"] for item in objects) > 1048576:
                    cap.capture["object_byte_bound_exceeded"] = True
                for item in objects:
                    call("cleanup-delete-object", "s3api", "delete-object", {"Bucket": bucket, "Key": item["Key"]})
                call("cleanup-delete-bucket", "s3api", "delete-bucket", {"Bucket": bucket})
            if call("verify-bucket-absent", "s3api", "head-bucket", {"Bucket": bucket})["code"] not in ("404", "NoSuchBucket", "NotFound"):
                remaining.append(bucket)
        if resources["role"]:
            call("cleanup-delete-role-policy", "iam", "delete-role-policy", {"RoleName": role, "PolicyName": "owned"})
            call("cleanup-delete-role", "iam", "delete-role", {"RoleName": role})
            if call("verify-role-absent", "iam", "get-role", {"RoleName": role})["code"] != "NoSuchEntity":
                remaining.append(role)
        cap.finish(remaining)
        temp.cleanup()


def main():
    args = arguments(__doc__, manifest_only=True)
    if args.manifest_only:
        return manifest_probe(args)
    cap = Capture(args, "stackd-analytics-", REFERENCES, {
        "max_calls": 260, "wall_seconds": 1200, "cli_timeout_seconds": 30,
        "max_buckets": 1, "max_total_object_bytes": 1048576, "max_iam_roles": 2,
        "max_databases": 1, "max_tables": 1, "max_workgroups": 2, "max_jobs": 1,
        "max_job_runs": 2, "job_dpu": 0.0625, "job_timeout_minutes": 2, "job_retries": 0,
        "max_query_submissions": 8, "query_bytes_scanned_cutoff": 10485760,
        "query_poll_deadline_seconds": 90, "job_poll_deadline_seconds": 240,
        "cost_usd_upper_estimate": 0.10,
        "cost_basis": "Glue <=2*0.0625 DPU*2/60h*$0.44=$0.001834; Athena <=8*10MiB at $5/TB (<$0.001). Remaining conservative allowance covers <1MiB S3, catalog/API requests. No Spark/crawler/capacity reservation/EC2.",
    })
    bucket = cap.prefix
    db = cap.name(cap.prefix.replace("-", "_"), "stackd_analytics_owned")
    wg, other_wg = cap.prefix + "-wg", cap.prefix + "-other"
    job, execution_role, reader_role = cap.prefix + "-job", cap.prefix + "-execution", cap.prefix + "-reader"
    resources = {"bucket": False, "database": False, "job": False, "roles": [], "workgroups": []}
    runs, queries = [], []
    temp = tempfile.TemporaryDirectory(prefix="stackd-analytics-capture-")
    local = Path(temp.name)
    cap.name(str(local), "OWNED_TEMP")
    def call(label, service, operation, parameters, **kwargs):
        return cap.request(label, service, operation, parameters, **kwargs)
    def glue(label, op, params):
        return call(label, "glue", op, params)
    def athena(label, op, params, **kwargs):
        return call(label, "athena", op, params, **kwargs)
    def put(label, key, body):
        path = local / (label + ".data")
        path.write_bytes(body)
        return require(call(label, "s3api", "put-object", {"Bucket": bucket, "Key": key}, options=["--body", str(path)]))
    def get(label, key, environment=None):
        path = local / (label + ".data")
        response = call(label, "s3api", "get-object", {"Bucket": bucket, "Key": key},
                        environment=environment, options=["--bucket", bucket, "--key", key, str(path)], cli_input=False)
        if response["code"] == "Success":
            body = path.read_bytes()
            if len(body) > 1048576:
                raise RuntimeError("S3 consumer byte bound exceeded")
            cap.capture.setdefault("consumers", {})[label] = {"body_utf8": body.decode("utf-8"), "byte_count": len(body)}
            cap.save()
        return response
    def wait_query(label, query):
        end = time.monotonic() + 90
        states = []
        while time.monotonic() < end:
            output = require(athena(label + "-poll-" + str(len(states)), "get-query-execution", {"QueryExecutionId": query}))
            state = output["QueryExecution"]["Status"]["State"]
            states.append(state)
            if state in TERMINAL_QUERY:
                cap.capture.setdefault("query_transitions", {})[label] = states
                cap.capture.setdefault("query_terminal", {})[label] = output["QueryExecution"]
                cap.save()
                return output["QueryExecution"]
            time.sleep(2)
        raise RuntimeError("Query polling deadline: " + label)
    def start(label, sql, **kwargs):
        token = uuid.uuid4().hex
        cap.name(token, label.upper().replace("-", "_") + "_TOKEN")
        params = {"QueryString": sql, "ClientRequestToken": token, "WorkGroup": wg,
                  "QueryExecutionContext": {"Database": db, "Catalog": "AwsDataCatalog"}}
        params.update(kwargs)
        output = require(athena(label, "start-query-execution", params))
        query = cap.name(output["QueryExecutionId"], label.upper().replace("-", "_") + "_ID")
        queries.append(query)
        return query, params
    def wait_job(label, run_id):
        end = time.monotonic() + 240
        states = []
        while time.monotonic() < end:
            output = require(glue(label + "-poll-" + str(len(states)), "get-job-run", {"JobName": job, "RunId": run_id, "PredecessorsIncluded": True}))
            state = output["JobRun"]["JobRunState"]
            states.append(state)
            if state in TERMINAL_JOB:
                cap.capture.setdefault("job_transitions", {})[label] = states
                cap.capture.setdefault("job_terminal", {})[label] = output["JobRun"]
                cap.save()
                return state
            time.sleep(5)
        raise RuntimeError("Job polling deadline: " + label)
    def reader_policy(deny):
        statements = [
            {"Effect": "Allow", "Action": ["glue:GetDatabase", "glue:GetTable"], "Resource": [f"arn:aws:glue:us-east-1:{cap.account}:catalog", f"arn:aws:glue:us-east-1:{cap.account}:database/{db}", f"arn:aws:glue:us-east-1:{cap.account}:table/{db}/*"]},
            {"Effect": "Deny", "Action": "glue:GetTable", "Resource": f"arn:aws:glue:us-east-1:{cap.account}:table/{db}/sales"},
            {"Effect": "Allow", "Action": ["athena:GetQueryExecution", "athena:GetQueryResults", "athena:GetWorkGroup", "athena:StartQueryExecution"], "Resource": f"arn:aws:athena:us-east-1:{cap.account}:workgroup/{wg}"},
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"], "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]},
        ]
        statements.append({"Effect": "Deny", "Action": "athena:GetQueryResults" if deny == "athena" else "s3:GetObject",
                           "Resource": f"arn:aws:athena:us-east-1:{cap.account}:workgroup/{wg}" if deny == "athena" else f"arn:aws:s3:::{bucket}/results/*"})
        return {"Version": "2012-10-17", "Statement": statements}
    try:
        cap.identity()
        cap.capture["uncertainty"] = [
            "One account and region, Python shell 3.9 only; no Glue Spark or Athena Spark conformance claimed.",
            "IAM role propagation observations are retained; their durations are not contractual.",
            "Athena cancellation races execution; native terminal state is retained, never overwritten as CANCELLED.",
            "Query history and deleted Glue job run history have no native purge API; resource deletion/terminal runs prevent ongoing compute.",
            "No CloudWatch default log groups are created, modified or granted to job role; this run does not prove runtime log delivery.",
            "No Lake Formation grants/defaults, global catalog lists, standing workgroups or IAM policies modified.",
        ]
        athena_event_capture.install(cap, job, db, wg)
        resources["bucket"] = True
        require(call("create-bucket", "s3api", "create-bucket", {"Bucket": bucket}))
        put("put-input", "input/source.csv", b"north,2\nsouth,7\nnorth,3\n")
        producer = Path(__file__).resolve().parents[2] / "testdata/aws/glue/producer.py"
        put("put-producer", "scripts/producer.py", producer.read_bytes())
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        resources["roles"].append(execution_role)
        role_output = require(call("create-execution-role", "iam", "create-role", {"RoleName": execution_role, "AssumeRolePolicyDocument": json.dumps(trust)}))
        cap.name(role_output["Role"]["RoleId"], "EXECUTION_ROLE_ID")
        role_arn = role_output["Role"]["Arn"]
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": [f"arn:aws:s3:::{bucket}/scripts/*", f"arn:aws:s3:::{bucket}/input/*"]},
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket}/data/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"], "Resource": f"arn:aws:s3:::{bucket}"},
        ]}
        require(call("execution-policy", "iam", "put-role-policy", {"RoleName": execution_role, "PolicyName": "owned", "PolicyDocument": json.dumps(policy)}))
        resources["job"] = True
        job_input = {"Name": job, "Role": role_arn, "Command": {"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": f"s3://{bucket}/scripts/producer.py"},
                     "MaxCapacity": 0.0625, "Timeout": 2, "MaxRetries": 0,
                     "ExecutionProperty": {"MaxConcurrentRuns": 1}, "DefaultArguments": {"--library-set": "none", "--bucket": bucket}}
        require(glue("create-job", "create-job", job_input))
        glue("duplicate-job", "create-job", job_input)
        glue("get-job", "get-job", {"JobName": job})
        time.sleep(12 if args.native else 0)
        for mode in ("success", "failure"):
            response = glue("start-job-" + mode, "start-job-run", {"JobName": job, "Arguments": {"--mode": mode}})
            if mode == "failure":
                for attempt in range(12):
                    if response["code"] != "ConcurrentRunsExceededException":
                        break
                    time.sleep(5)
                    response = glue("start-job-failure-slot-release-" + str(attempt), "start-job-run", {"JobName": job, "Arguments": {"--mode": mode}})
            run_output = require(response)
            run_id = cap.name(run_output["JobRunId"], "JOB_" + mode.upper() + "_ID")
            runs.append(run_id)
            if mode == "success":
                concurrent = glue("concurrent-job-run", "start-job-run", {"JobName": job, "Arguments": {"--mode": "success"}})
                if concurrent["code"] == "Success":
                    runs.append(cap.name(concurrent["output"]["JobRunId"], "UNEXPECTED_CONCURRENT_RUN_ID"))
                    raise RuntimeError("Concurrency limit not enforced; stopping at two accepted job runs")
            state = wait_job("job-" + mode, run_id)
            if mode == "success" and state != "SUCCEEDED":
                raise RuntimeError("Real Glue producer did not succeed: " + state)
            if mode == "success":
                require(get("consume-produced-csv", "data/part.csv"))
        glue("get-job-runs", "get-job-runs", {"JobName": job, "MaxResults": 10})
        glue("stop-terminal-and-missing-runs", "batch-stop-job-run", {"JobName": job, "JobRunIds": [runs[0], "jr_" + "0" * 64]})
        glue("update-job-replacement", "update-job", {"JobName": job, "JobUpdate": {"Role": role_arn, "Command": job_input["Command"], "MaxCapacity": 0.0625, "Timeout": 2, "MaxRetries": 0}})
        glue("get-job-after-update", "get-job", {"JobName": job})
        resources["database"] = True
        require(glue("create-database", "create-database", {"DatabaseInput": {"Name": db}}))
        require(glue("create-table", "create-table", {"DatabaseName": db, "TableInput": {"Name": "sales", "TableType": "EXTERNAL_TABLE", "Parameters": {"classification": "csv"}, "StorageDescriptor": descriptor(f"s3://{bucket}/data/"), "PartitionKeys": []}}))
        config = {"EnforceWorkGroupConfiguration": True, "PublishCloudWatchMetricsEnabled": False,
                  "BytesScannedCutoffPerQuery": 10485760, "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/results/", "EncryptionConfiguration": {"EncryptionOption": "SSE_S3"}}, "EngineVersion": {"SelectedEngineVersion": "Athena engine version 3"}}
        resources["workgroups"].append(wg)
        require(athena("create-workgroup", "create-work-group", {"Name": wg, "Configuration": config, "Tags": [{"Key": "owned", "Value": "analytics-probe"}]}))
        athena("duplicate-workgroup", "create-work-group", {"Name": wg})
        athena("get-workgroup", "get-work-group", {"WorkGroup": wg})
        athena("catalog-get-database", "get-database", {"CatalogName": "AwsDataCatalog", "DatabaseName": db})
        athena("catalog-get-table", "get-table-metadata", {"CatalogName": "AwsDataCatalog", "DatabaseName": db, "TableName": "sales"})
        athena("catalog-missing-database", "get-database", {"CatalogName": "AwsDataCatalog", "DatabaseName": db + "_missing"})
        athena("catalog-missing-table", "get-table-metadata", {"CatalogName": "AwsDataCatalog", "DatabaseName": db, "TableName": "missing"})
        resources["workgroups"].append(other_wg)
        require(athena("create-other-workgroup", "create-work-group", {"Name": other_wg}))
        athena("other-workgroup-defaults", "get-work-group", {"WorkGroup": other_wg})
        require(athena("update-other-result", "update-work-group", {"WorkGroup": other_wg, "ConfigurationUpdates": {"ResultConfigurationUpdates": {"OutputLocation": f"s3://{bucket}/other/", "EncryptionConfiguration": {"EncryptionOption": "SSE_S3"}}}}))
        require(athena("remove-other-result", "update-work-group", {"WorkGroup": other_wg, "ConfigurationUpdates": {"ResultConfigurationUpdates": {"RemoveOutputLocation": True, "RemoveEncryptionConfiguration": True}}}))
        athena("other-workgroup-after-remove", "get-work-group", {"WorkGroup": other_wg})
        athena("query-missing-output", "start-query-execution", {"WorkGroup": other_wg, "QueryString": "SELECT 1", "ClientRequestToken": uuid.uuid4().hex})
        aggregate, aggregate_input = start("query-aggregate", "SELECT category, sum(amount) AS total FROM sales GROUP BY category ORDER BY category", ResultConfiguration={"OutputLocation": f"s3://{bucket}/ignored-client/"})
        athena("query-idempotent-retry", "start-query-execution", aggregate_input)
        athena("query-token-mismatch", "start-query-execution", dict(aggregate_input, QueryString="SELECT 999"))
        terminal = wait_query("aggregate", aggregate)
        if terminal["Status"]["State"] != "SUCCEEDED":
            raise RuntimeError("Actual S3 catalog query did not succeed")
        athena("aggregate-results", "get-query-results", {"QueryExecutionId": aggregate})
        page = require(athena("aggregate-results-page-one", "get-query-results", {"QueryExecutionId": aggregate, "MaxResults": 1}))
        for index in range(2, 5):
            if not page.get("NextToken"):
                break
            token = cap.name(page["NextToken"], "RESULT_PAGE_" + str(index) + "_TOKEN")
            page = require(athena("aggregate-results-page-" + str(index), "get-query-results", {"QueryExecutionId": aggregate, "MaxResults": 1, "NextToken": token}))
        location = terminal["ResultConfiguration"]["OutputLocation"]
        key = location.split("/", 3)[3]
        require(get("consume-query-csv", key))
        typed, _ = start("query-types", "SELECT CAST(NULL AS varchar) AS null_value, '' AS empty_value, CAST(12.30 AS decimal(6,2)) AS decimal_value, CAST(7 AS bigint) AS integer_value, true AS flag, DATE '2026-01-02' AS day_value, TIMESTAMP '2026-01-02 03:04:05.123' AS timestamp_value, CAST('hi' AS char(4)) AS char_value, ARRAY[1,2] AS array_value, MAP(ARRAY['a'],ARRAY[3]) AS map_value, CAST(ROW(1,'x') AS ROW(n integer,s varchar)) AS row_value")
        wait_query("types", typed)
        athena("typed-results", "get-query-results", {"QueryExecutionId": typed})
        failed, _ = start("query-failure", "SELECT missing_column FROM sales")
        wait_query("failure", failed)
        athena("failed-results", "get-query-results", {"QueryExecutionId": failed})
        cancelled, _ = start("query-cancel", "SELECT sum(a.x*b.x) FROM UNNEST(sequence(1,1000)) a(x) CROSS JOIN UNNEST(sequence(1,1000)) b(x)")
        athena("cancel-query", "stop-query-execution", {"QueryExecutionId": cancelled})
        wait_query("cancel", cancelled)
        athena("cancel-query-again", "stop-query-execution", {"QueryExecutionId": cancelled})
        athena("cancelled-results", "get-query-results", {"QueryExecutionId": cancelled})
        athena("query-other-workgroup-history", "list-query-executions", {"WorkGroup": other_wg, "MaxResults": 10})
        prepared = {"WorkGroup": wg, "StatementName": "owned_statement", "QueryStatement": "SELECT category FROM sales WHERE amount > ?", "Description": "first"}
        require(athena("create-prepared", "create-prepared-statement", prepared))
        athena("duplicate-prepared", "create-prepared-statement", dict(prepared, Description="duplicate replacement"))
        athena("get-prepared-after-duplicate", "get-prepared-statement", {"WorkGroup": wg, "StatementName": "owned_statement"})
        athena("update-prepared-missing", "update-prepared-statement", {"WorkGroup": wg, "StatementName": "missing", "QueryStatement": "SELECT 1"})
        athena("get-prepared-other-workgroup", "get-prepared-statement", {"WorkGroup": other_wg, "StatementName": "owned_statement"})
        require(athena("update-prepared", "update-prepared-statement", {"WorkGroup": wg, "StatementName": "owned_statement", "QueryStatement": "SELECT amount FROM sales WHERE amount > ?"}))
        athena("get-prepared-updated", "get-prepared-statement", {"WorkGroup": wg, "StatementName": "owned_statement"})
        reader_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{cap.account}:root"}, "Action": "sts:AssumeRole"}]}
        resources["roles"].append(reader_role)
        reader_output = require(call("create-reader-role", "iam", "create-role", {"RoleName": reader_role, "AssumeRolePolicyDocument": json.dumps(reader_trust)}))
        cap.name(reader_output["Role"]["RoleId"], "READER_ROLE_ID")
        require(call("reader-policy-athena-deny", "iam", "put-role-policy", {"RoleName": reader_role, "PolicyName": "owned", "PolicyDocument": json.dumps(reader_policy("athena"))}))
        reader = cap.assume(reader_output["Role"]["Arn"])
        if args.native:
            time.sleep(10)
        call("reader-glue-database", "glue", "get-database", {"Name": db}, environment=reader)
        call("reader-glue-table-denied", "glue", "get-table", {"DatabaseName": db, "Name": "sales"}, environment=reader)
        athena("reader-other-workgroup-denied", "get-work-group", {"WorkGroup": other_wg}, environment=reader)
        athena("reader-athena-results-denied", "get-query-results", {"QueryExecutionId": aggregate}, environment=reader)
        get("reader-s3-results-allowed", key, reader)
        athena("reader-idempotent-no-table-permission", "start-query-execution", aggregate_input, environment=reader)
        require(call("reader-policy-s3-deny", "iam", "put-role-policy", {"RoleName": reader_role, "PolicyName": "owned", "PolicyDocument": json.dumps(reader_policy("s3"))}))
        for attempt in range(12):
            response = get("reader-s3-denial-poll-" + str(attempt), key, reader)
            if response["code"] == "AccessDenied":
                break
            time.sleep(5)
        athena("reader-results-current-s3-deny", "get-query-results", {"QueryExecutionId": aggregate}, environment=reader)
        require(athena("disable-workgroup", "update-work-group", {"WorkGroup": wg, "State": "DISABLED"}))
        athena("query-disabled-workgroup", "start-query-execution", {"WorkGroup": wg, "QueryString": "SELECT 1", "ClientRequestToken": uuid.uuid4().hex})
        athena("get-results-disabled-workgroup", "get-query-results", {"QueryExecutionId": aggregate})
        athena("delete-workgroup-nonrecursive", "delete-work-group", {"WorkGroup": wg, "RecursiveDeleteOption": False})
        athena_event_capture.receive(cap, cap.capture["event_resources"])
        cap.capture["completed"] = True
    except Exception as error:
        cap.capture["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        cap.cleaning = True
        remaining = []
        if cap.capture.get("event_resources") and "native_events" not in cap.capture:
            athena_event_capture.receive(cap, cap.capture["event_resources"])
        for query in queries:
            athena("cleanup-stop-query", "stop-query-execution", {"QueryExecutionId": query})
        for run_id in runs:
            observed = glue("cleanup-job-state", "get-job-run", {"JobName": job, "RunId": run_id})
            if observed["code"] == "Success" and observed["output"]["JobRun"]["JobRunState"] not in TERMINAL_JOB:
                glue("cleanup-stop-job", "batch-stop-job-run", {"JobName": job, "JobRunIds": [run_id]})
                if wait_job("cleanup-stopped-job", run_id) not in TERMINAL_JOB:
                    remaining.append("job-run:" + run_id)
        if resources["job"]:
            glue("cleanup-delete-job", "delete-job", {"JobName": job})
            if glue("verify-job-absent", "get-job", {"JobName": job})["code"] != "EntityNotFoundException":
                remaining.append(job)
        for group in resources["workgroups"]:
            athena("cleanup-delete-workgroup", "delete-work-group", {"WorkGroup": group, "RecursiveDeleteOption": True})
            if athena("verify-workgroup-absent", "get-work-group", {"WorkGroup": group})["code"] != "InvalidRequestException":
                remaining.append(group)
        if resources["database"]:
            glue("cleanup-delete-table", "delete-table", {"DatabaseName": db, "Name": "sales"})
            glue("cleanup-delete-database", "delete-database", {"Name": db})
            if glue("verify-database-absent", "get-database", {"Name": db})["code"] != "EntityNotFoundException":
                remaining.append(db)
        if resources["bucket"]:
            listing = call("cleanup-list-owned-objects", "s3api", "list-objects-v2", {"Bucket": bucket, "MaxKeys": 100})
            if listing["code"] == "Success":
                objects = listing["output"].get("Contents", [])
                if listing["output"].get("IsTruncated"):
                    remaining.append("unexpected-object-bound:" + bucket)
                for obj in objects:
                    call("cleanup-delete-object", "s3api", "delete-object", {"Bucket": bucket, "Key": obj["Key"]})
                call("cleanup-delete-bucket", "s3api", "delete-bucket", {"Bucket": bucket})
            if call("verify-bucket-absent", "s3api", "head-bucket", {"Bucket": bucket})["code"] not in ("404", "NoSuchBucket", "NotFound"):
                remaining.append(bucket)
        for role in reversed(resources["roles"]):
            call("cleanup-delete-role-policy", "iam", "delete-role-policy", {"RoleName": role, "PolicyName": "owned"})
            call("cleanup-delete-role", "iam", "delete-role", {"RoleName": role})
            if call("verify-role-absent", "iam", "get-role", {"RoleName": role})["code"] != "NoSuchEntity":
                remaining.append(role)
        if cap.capture.get("event_resources"):
            remaining.extend(athena_event_capture.cleanup(cap, cap.capture["event_resources"]))
        cap.finish(remaining)
        temp.cleanup()


if __name__ == "__main__":
    main()
