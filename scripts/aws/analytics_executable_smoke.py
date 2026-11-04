"""Run the owned Glue -> S3 -> Athena workflow through the actual stackd binary.

This is owned runtime proof, not a native AWS probe. The caller supplies an
empty private state directory and preinstalled runtime images. Remote Docker
requires explicit controller/native callback routes. No host AWS identity is
forwarded. Receipts, container configuration and logs stay in the private state
directory; do not publish that directory or the retained report.
"""
import argparse
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import tempfile
import tarfile
import time
import urllib.request
from urllib.parse import urlsplit
import uuid

from aws_cli import run, result
from stackd_process import StackdProcess


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Application:
    def __init__(self, args):
        self.args = args
        self.state = Path(args.state_directory).resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        require(not (self.state / "analytics.sqlite").exists(), "state directory already has analytics.sqlite")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
        self.env.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test",
                        AWS_DEFAULT_REGION="us-east-1", AWS_REGION="us-east-1",
                        AWS_ENDPOINT_URL=self.endpoint, AWS_EC2_METADATA_DISABLED="true",
                        AWS_MAX_ATTEMPTS="1", AWS_PAGER="")
        self.controller = StackdProcess(self.state)
        self.owned_containers = set()
        self.athena_containers = {}
        self.query_handles = {}
        self.native_http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.secrets = set()
        self.report = {"endpoint": self.endpoint, "observations": {}, "cleanup": {}, "controllers": self.controller.runs}

    def start(self):
        command = [str(Path(self.args.binary).resolve()), "-listen", f"0.0.0.0:{self.port}",
                   "-public-endpoint", self.endpoint, "-database", str(self.state / "analytics.sqlite"),
                   "-docker-host", self.args.docker_host, "-glue-runtime", "-athena-runtime",
                   "-compute-endpoint", self.args.compute_endpoint.replace("{port}", str(self.port))
                   if self.args.compute_endpoint else f"http://host.docker.internal:{self.port}",
                   "-athena-endpoint-host", self.args.athena_endpoint_host]
        for field, flag in (("glue_spark_image", "-glue-spark-image"),
                            ("glue_python_image", "-glue-python-image"),
                            ("athena_image", "-athena-image"),
                            ("athena_hive_ddl_image", "-athena-hive-ddl-image"),
                            ("athena_callback_listen", "-athena-callback-listen"),
                            ("athena_callback_host", "-athena-callback-host")):
            value = getattr(self.args, field)
            if value:
                command += [flag, value]
        self.controller.start(command, self.endpoint, environment=self.env)

    def check_controllers(self):
        for controller in self.report.get("controllers", []):
            text = Path(controller["log"]).read_text()
            require("DATA RACE" not in text and " ERROR " not in text,
                    f"controller failed: {controller}; inspect retained log")

    def remember_secrets(self, value, sensitive=False):
        if isinstance(value, dict):
            for key, child in value.items():
                self.remember_secrets(child, sensitive or bool(re.search(
                    r"password|secret|token|access.?key|authorization", key, re.I)))
        elif isinstance(value, list):
            for child in value:
                self.remember_secrets(child, sensitive)
        elif sensitive and isinstance(value, str) and value:
            self.secrets.add(value)

    def observe(self, service, operation, parameters=None, env=None, options=()):
        environment = env or self.env
        self.remember_secrets(parameters)
        self.remember_secrets(environment)
        process = run(service, operation, parameters, environment,
                      options=("--no-paginate", "--cli-connect-timeout", "5",
                               "--cli-read-timeout", "30", *options), timeout=40)
        diagnostic = process.stderr
        for secret in sorted(self.secrets, key=len, reverse=True):
            diagnostic = diagnostic.replace(secret, "[REDACTED]")
        diagnostic = re.sub(r"(://)[^/\s@]+@", r"\1[REDACTED]@", diagnostic)
        if process.returncode:
            record = {"service": service, "operation": operation, "exit_status": process.returncode,
                      "stderr": diagnostic}
            with (self.state / "cli-errors.jsonl").open("a") as output:
                output.write(json.dumps(record) + "\n")
        observed = result(subprocess.CompletedProcess((), process.returncode, process.stdout, diagnostic),
                          cli_message=None)
        self.remember_secrets(observed.get("output"))
        return observed

    def call(self, service, operation, parameters=None, env=None, options=()):
        observed = self.observe(service, operation, parameters, env, options)
        require(observed["code"] == "Success", f"{service}:{operation}: {observed.get('code')}: {observed.get('message', '')}")
        if service == "glue" and operation == "start-job-run":
            identity = f"arn:aws:glue:us-east-1:000000000000:job/{parameters['JobName']}/{observed['output']['JobRunId']}/attempt-0"
            self.owned_containers.add("stackd-glue-" + hashlib.sha256(identity.encode()).hexdigest())
        if service == "athena":
            self.remember_athena_receipts()
        return observed["output"]

    def put(self, bucket, key, body):
        with tempfile.NamedTemporaryFile(dir=self.state) as payload:
            payload.write(body)
            payload.flush()
            self.call("s3api", "put-object", {"Bucket": bucket, "Key": key}, options=("--body", payload.name))

    def get(self, bucket, key):
        with tempfile.NamedTemporaryFile(dir=self.state) as payload:
            self.call("s3api", "get-object", options=("--bucket", bucket, "--key", key, payload.name))
            return Path(payload.name).read_bytes()

    def job_state(self, job, run_id):
        return self.call("glue", "get-job-run", {"JobName": job, "RunId": run_id})["JobRun"]

    def await_job(self, job, run_id, expected, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = self.job_state(job, run_id)
            state = value["JobRunState"]
            if state in expected:
                return value
            require(state not in {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR", "EXPIRED"},
                    f"unexpected Glue terminal state {state}: {value.get('ErrorMessage', '')}")
            time.sleep(0.3)
        raise TimeoutError(f"Glue run did not reach {sorted(expected)}")

    def native_container_started(self, name):
        output = subprocess.run(["docker", "--host", self.args.docker_host, "inspect", "--format", "{{.State.StartedAt}}", name],
                                capture_output=True, text=True, timeout=10)
        require(output.returncode == 0, "owned native job container was not found")
        return output.stdout.strip()

    def remember_athena_receipts(self):
        receipts = {}
        directory = self.state / "analytics.sqlite.athena"
        for path in directory.glob("stackd-athena-*.json"):
            try:
                metadata = path.lstat()
                require(path.is_file() and not path.is_symlink() and metadata.st_mode & 0o077 == 0,
                        "Athena ownership receipt is not a private regular file")
                receipt = json.loads(path.read_text())
            except FileNotFoundError:
                continue  # Retirement can unlink a receipt between listing and reading.
            engine = receipt.get("engine", "")
            require(re.fullmatch(r"stackd-athena-[0-9a-f]{64}", engine) is not None
                    and path.name == engine + ".json" and bool(receipt.get("owner"))
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", receipt.get("image", "")) is not None,
                    "invalid Athena ownership receipt")
            self.remember_athena_container(engine, engine, receipt["owner"], receipt["image"])
            parser = receipt.get("parser", "")
            if parser:
                require(re.fullmatch(re.escape(engine) + r"-[0-9a-f]{64}", parser) is not None
                        and re.fullmatch(r"sha256:[0-9a-f]{64}", receipt.get("parserImage", "")) is not None,
                        "invalid Athena parser ownership receipt")
                self.remember_athena_container(parser + "-hiveddl", parser, receipt["owner"], receipt["parserImage"])
            receipts[engine] = receipt
        return receipts

    def remember_athena_container(self, name, execution, owner, image):
        identity = {"execution": execution, "owner": owner, "image": image}
        require(name not in self.athena_containers or self.athena_containers[name] == identity,
                "Athena container ownership identity changed")
        self.athena_containers[name] = identity
        self.owned_containers.add(name)

    def persisted_query_handle(self, query_id):
        database = self.state / "analytics.sqlite"
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=5) as connection:
            row = connection.execute(
                "SELECT engine_id FROM athena_queries WHERE key_scope_partition = ? "
                "AND key_scope_account_id = ? AND key_scope_region = ? AND key_name = ?",
                ("aws", "000000000000", "us-east-1", query_id)).fetchone()
        require(row is not None, "owned Athena query was not persisted")
        handle = row[0]
        if handle:
            require(re.fullmatch(r"stackd-athena-[0-9a-f]{64}/[0-9a-f]{64}", handle) is not None,
                    "invalid persisted Athena execution identity")
            require(query_id not in self.query_handles or self.query_handles[query_id] == handle,
                    "Athena query execution identity changed")
            self.query_handles[query_id] = handle
        return handle

    def inspect_athena_container(self, name, running=False):
        output = subprocess.run(["docker", "--host", self.args.docker_host, "inspect", name],
                                capture_output=True, text=True, timeout=10)
        require(output.returncode == 0, "owned Athena container inspection failed")
        states = json.loads(output.stdout)
        require(len(states) == 1 and states[0].get("Name") == "/" + name,
                "Athena inspection did not select the exact container")
        state = states[0]
        identity = self.athena_containers[name]
        labels = state.get("Config", {}).get("Labels") or {}
        require(labels.get("stackd.athena.execution") == identity["execution"]
                and labels.get("stackd.athena.owner") == identity["owner"]
                and labels.get("stackd.athena.engine") == "trino-476"
                and state.get("Image") == identity["image"],
                "Athena container does not match its ownership receipt")
        if running:
            require(state.get("State", {}).get("Running") is True, "owned Athena engine is not running")
        return state

    def athena_endpoint(self, engine):
        state = self.inspect_athena_container(engine, running=True)
        host_config = state.get("HostConfig", {})
        ports = state.get("NetworkSettings", {}).get("Ports") or {}
        if host_config.get("NetworkMode") == "host":
            require(not host_config.get("PortBindings") and not any(ports.values()),
                    "local Athena engine unexpectedly published ports")
            encoded = [value.split("=", 1)[1] for value in state["Config"].get("Env", [])
                       if value.startswith("STACKD_TRINO_CONFIG=")]
            require(len(encoded) == 1, "owned Athena native configuration is absent")
            # Decode only in memory: the archive can contain private capabilities.
            with tarfile.open(fileobj=io.BytesIO(base64.b64decode(encoded[0], validate=True))) as archive:
                properties = {}
                for filename in ("config.properties", "node.properties"):
                    members = [member for member in archive.getmembers()
                               if member.isfile() and member.name.rsplit("/", 1)[-1] == filename]
                    require(len(members) == 1, "owned Athena native properties are ambiguous")
                    with archive.extractfile(members[0]) as source:
                        properties[filename] = dict(line.strip().split("=", 1)
                            for line in source.read().decode().splitlines()
                            if "=" in line and not line.lstrip().startswith("#"))
            require(properties["node.properties"].get("node.bind-ip") == "127.0.0.1",
                    "local Athena native listener is not loopback-bound")
            port = properties["config.properties"].get("http-server.http.port", "")
            require(port.isdecimal() and 0 < int(port) <= 65535 and int(port) != 8080,
                    "local Athena native port is not an owned ephemeral port")
            host = "127.0.0.1"
            self.report["observations"]["athena_topology"] = "host network; loopback ephemeral native port; no publication"
        else:
            require(self.args.athena_callback_listen and self.args.athena_callback_host
                    and self.args.compute_endpoint,
                    "bridged Athena topology requires explicit callback and Glue compute routes")
            bindings = ports.get("8080/tcp") or []
            configured = host_config.get("PortBindings") or {}
            require(host_config.get("NetworkMode") == "bridge" and len(bindings) == 1
                    and set(configured) == {"8080/tcp"}
                    and len(configured["8080/tcp"]) == 1
                    and configured["8080/tcp"][0].get("HostIp") == "127.0.0.1"
                    and bindings[0].get("HostIp") == "127.0.0.1"
                    and all(not value for key, value in ports.items() if key != "8080/tcp"),
                    "remote Athena engine lacks its exact loopback publication")
            host, port = self.args.athena_endpoint_host, bindings[0].get("HostPort", "")
            require(port.isdecimal() and 0 < int(port) <= 65535, "invalid owned Athena published port")
            self.report["observations"]["athena_topology"] = "bridge network; daemon loopback publication; explicit native route"
        authority = "[" + host + "]" if ":" in host else host
        return "http://" + authority + ":" + port

    def await_native_query(self, query_id, sql):
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            state = self.query_state(query_id)["Status"]["State"]
            require(state not in {"FAILED", "SUCCEEDED", "CANCELLED"},
                    "query terminated before native cancellation proof")
            handle = self.persisted_query_handle(query_id)
            if handle:
                engine, suffix = handle.split("/")
                receipt = self.remember_athena_receipts().get(engine)
                require(receipt is not None and receipt.get("parser") == engine + "-" + suffix,
                        "persisted Athena query does not match its current owned receipt")
                request = urllib.request.Request(self.athena_endpoint(engine) + "/v1/query",
                                                 headers={"X-Trino-User": "athena"})
                try:
                    with self.native_http.open(request, timeout=2) as response:
                        queries = json.load(response)
                    matching = [query for query in queries if query.get("state") == "RUNNING"
                                and query.get("query") == sql and query.get("queryId")]
                    require(len(matching) <= 1, "native cancellation SQL selected multiple queries")
                    if matching:
                        return matching[0]["queryId"]
                except OSError:
                    pass
            time.sleep(0.5)
        raise TimeoutError("native SQL did not become RUNNING")

    def assert_warm_queries(self, workgroup):
        identities = []
        for value in (1, 2):
            require(self.query(f"SELECT {value} AS warm_value", "", workgroup)
                    == [["warm_value"], [str(value)]], "warm Athena query result changed")
            receipts = self.remember_athena_receipts()
            require(len(receipts) == 1, "same-scope sequential SQL did not retain one warm engine")
            receipt = next(iter(receipts.values()))
            self.athena_endpoint(receipt["engine"])
            identities.append(receipt)
        require(all(identities[0][key] == identities[1][key] for key in ("engine", "owner", "image"))
                and identities[0]["parser"] != identities[1]["parser"],
                "sequential SQL did not reuse the exact engine with a fresh query identity")
        self.report["observations"]["athena_warm_identity"] = "same owned engine/image; distinct random query suffixes"

    def query_state(self, query_id):
        value = self.call("athena", "get-query-execution", {"QueryExecutionId": query_id})["QueryExecution"]
        self.persisted_query_handle(query_id)
        return value

    def await_query(self, query_id, expected, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = self.query_state(query_id)
            state = value["Status"]["State"]
            if state in expected:
                return value
            require(state not in {"SUCCEEDED", "FAILED", "CANCELLED"},
                    f"unexpected Athena terminal state {state}: {value['Status'].get('StateChangeReason', '')}")
            time.sleep(0.3)
        raise TimeoutError(f"Athena query did not reach {sorted(expected)}")

    def query(self, sql, database, workgroup):
        query_id = self.call("athena", "start-query-execution", {
            "QueryString": sql, "QueryExecutionContext": {"Database": database},
            "WorkGroup": workgroup})["QueryExecutionId"]
        self.await_query(query_id, {"SUCCEEDED"}, timeout=300)
        result_set = self.call("athena", "get-query-results", {"QueryExecutionId": query_id})["ResultSet"]
        return [[cell.get("VarCharValue") for cell in row["Data"]] for row in result_set["Rows"]]

    def await_crawler(self, name):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            crawler = self.call("glue", "get-crawler", {"Name": name})["Crawler"]
            if crawler["State"] == "READY":
                require(crawler.get("LastCrawl", {}).get("Status") == "SUCCEEDED",
                        f"crawler failed: {crawler.get('LastCrawl')}")
                return crawler
            time.sleep(0.3)
        raise TimeoutError("crawler did not complete")


def exercise_data_lake(app, suffix, bucket, database, role, role_arn, policy, workgroup, created):
    key = app.call("kms", "create-key", {"Description": "Owned analytics runtime smoke"})["KeyMetadata"]
    created.append(("key", key["KeyId"]))
    policy["Statement"] += [
        {"Effect": "Allow", "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"], "Resource": key["Arn"]},
        {"Effect": "Allow", "Action": ["glue:GetDatabase", "glue:GetDatabases", "glue:GetTable", "glue:GetTables", "glue:CreateTable", "glue:UpdateTable", "glue:GetPartition", "glue:GetPartitions", "glue:BatchCreatePartition", "glue:BatchUpdatePartition", "glue:UpdatePartition", "glue:BatchDeletePartition", "glue:DeletePartition", "glue:DeleteTable"],
         "Resource": ["arn:aws:glue:us-east-1:000000000000:catalog",
                      f"arn:aws:glue:us-east-1:000000000000:database/{database}",
                      f"arn:aws:glue:us-east-1:000000000000:table/{database}/*"]}]
    app.call("iam", "put-role-policy", {"RoleName": role, "PolicyName": "analytics", "PolicyDocument": json.dumps(policy)})
    security, spark_job, crawler = ("analytics-" + suffix + ending for ending in ("-security", "-spark", "-crawler"))
    app.call("glue", "create-security-configuration", {"Name": security, "EncryptionConfiguration": {
        "S3Encryption": [{"S3EncryptionMode": "SSE-KMS", "KmsKeyArn": key["Arn"]}],
        "CloudWatchEncryption": {"CloudWatchEncryptionMode": "DISABLED"},
        "JobBookmarksEncryption": {"JobBookmarksEncryptionMode": "DISABLED"}}})
    created.append(("security", security))
    program = b'''import sys\nfrom pyspark.context import SparkContext\nfrom awsglue.context import GlueContext\nfrom awsglue.dynamicframe import DynamicFrame\nfrom awsglue.utils import getResolvedOptions\nargs=getResolvedOptions(sys.argv,['bucket'])\nglue=GlueContext(SparkContext.getOrCreate())\nframe=glue.spark_session.read.schema('label STRING, amount LONG').csv('s3://'+args['bucket']+'/data/')\nglue.write_dynamic_frame.from_options(frame=DynamicFrame.fromDF(frame.coalesce(1),glue,'rows'),connection_type='s3',connection_options={'path':'s3://'+args['bucket']+'/parquet/'},format='parquet')\nprint('analytics-spark-parquet-written',flush=True)\n'''
    app.put(bucket, "scripts/spark.py", program)
    app.call("glue", "create-job", {"Name": spark_job, "Role": role_arn, "GlueVersion": "5.0",
        "Command": {"Name": "glueetl", "PythonVersion": "3", "ScriptLocation": f"s3://{bucket}/scripts/spark.py"},
        "DefaultArguments": {"--bucket": bucket, "--enable-metrics": ""}, "WorkerType": "G.1X",
        "NumberOfWorkers": 2, "Timeout": 5, "MaxRetries": 0, "SecurityConfiguration": security})
    created.append(("job", spark_job))
    run_id = app.call("glue", "start-job-run", {"JobName": spark_job})["JobRunId"]
    app.await_job(spark_job, run_id, {"SUCCEEDED"}, timeout=300)
    objects = app.call("s3api", "list-objects-v2", {"Bucket": bucket, "Prefix": "parquet/"})["Contents"]
    parquet = [item for item in objects if item["Key"].endswith(".parquet")]
    require(len(parquet) == 1, "native single-partition Spark writer did not produce one Parquet object")
    metadata = app.call("s3api", "head-object", {"Bucket": bucket, "Key": parquet[0]["Key"]})
    require(metadata.get("ServerSideEncryption") == "aws:kms" and metadata.get("SSEKMSKeyId") == key["Arn"],
            "Glue security configuration did not reach native S3 writes")
    app.call("glue", "create-crawler", {"Name": crawler, "Role": role_arn, "DatabaseName": database,
        "Targets": {"S3Targets": [{"Path": f"s3://{bucket}/parquet/"}]}})
    created.append(("crawler", crawler))
    app.call("glue", "start-crawler", {"Name": crawler})
    app.await_crawler(crawler)
    tables = app.call("glue", "get-tables", {"DatabaseName": database})["TableList"]
    table = next(table for table in tables if table["StorageDescriptor"]["Location"].rstrip("/") == f"s3://{bucket}/parquet")
    rows = app.query(f'SELECT label, sum(amount) AS total FROM "{table["Name"]}" GROUP BY label ORDER BY label', database, workgroup)
    require(rows == [["label", "total"], ["alpha", "13"], ["beta", "3"]], "crawler Parquet metadata did not produce native SQL rows")
    app.report["observations"]["spark_kms_parquet_crawler_consumer"] = rows
    metrics = app.call("cloudwatch", "get-metric-statistics", {"Namespace": "Glue",
        "MetricName": "glue.driver.aggregate.recordsRead", "Dimensions": [
            {"Name": "JobName", "Value": spark_job}, {"Name": "JobRunId", "Value": run_id},
            {"Name": "Type", "Value": "count"}],
        "StartTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()-3600)),
        "EndTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()+60)),
        "Period": 60, "Statistics": ["Sum"]})
    require(sum(point["Sum"] for point in metrics["Datapoints"]) == 3, "CloudWatch did not retain actual three native input records")
    app.report["observations"]["spark_metric_records_read"] = 3
    app.put(bucket, "partitioned/year=2025/part.json", b'{"label":"prior","amount":4}\n')
    app.put(bucket, "partitioned/year=2026/part.json", b'{"label":"current","amount":9}\n')
    app.call("glue", "update-crawler", {"Name": crawler, "Targets": {"S3Targets": [{"Path": f"s3://{bucket}/partitioned/"}]}})
    app.call("glue", "start-crawler", {"Name": crawler})
    app.await_crawler(crawler)
    tables = app.call("glue", "get-tables", {"DatabaseName": database})["TableList"]
    partitioned = next(table for table in tables if table["StorageDescriptor"]["Location"].rstrip("/") == f"s3://{bucket}/partitioned")
    partitions = app.call("glue", "get-partitions", {"DatabaseName": database, "TableName": partitioned["Name"]})["Partitions"]
    require(sorted(partition["Values"] for partition in partitions) == [["2025"], ["2026"]], "crawler partition values differ from actual S3 layout")
    year_column = partitioned["PartitionKeys"][0]["Name"]
    partition_rows = app.query(f"""SELECT label, amount FROM "{partitioned["Name"]}" WHERE "{year_column}" = '2026'""", database, workgroup)
    require(partition_rows == [["label", "amount"], ["current", "9"]], "native SQL did not consume the crawler-selected JSON partition")
    app.report["observations"]["partitioned_json_consumer"] = partition_rows
    ddl = f"CREATE EXTERNAL TABLE ddl_numbers (label string, amount bigint) ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE LOCATION 's3://{bucket}/data/'"
    app.query(ddl, database, workgroup)
    ddl_rows = app.query("SELECT label, sum(amount) AS total FROM ddl_numbers GROUP BY label ORDER BY label", database, workgroup)
    require(ddl_rows == rows, "native Hive DDL did not produce a readable catalog table")
    app.report["observations"]["hive_ddl_consumer"] = ddl_rows
    app.query(f"CREATE TABLE iceberg_numbers (label string, amount bigint) LOCATION 's3://{bucket}/iceberg/' TBLPROPERTIES ('table_type'='ICEBERG')", database, workgroup)
    app.query("INSERT INTO iceberg_numbers VALUES ('north', 7), ('south', 9)", database, workgroup)
    iceberg_rows = app.query("SELECT label, amount FROM iceberg_numbers ORDER BY label", database, workgroup)
    require(iceberg_rows == [["label", "amount"], ["north", "7"], ["south", "9"]], "native Iceberg write/read did not consume table data")
    app.report["observations"]["iceberg_consumer"] = iceberg_rows


def exercise(app):
    suffix = uuid.uuid4().hex[:12]
    bucket, database, role, job, workgroup = ("analytics-" + suffix + ending for ending in ("-data", "_db", "-role", "-job", "-wg"))
    database = database.replace("-", "_")
    created = []
    try:
        app.start()
        queue = app.call("sqs", "create-queue", {"QueueName": "analytics-" + suffix + "-events"})["QueueUrl"]
        created.append(("queue", queue))
        queue_arn = app.call("sqs", "get-queue-attributes", {"QueueUrl": queue, "AttributeNames": ["QueueArn"]})["Attributes"]["QueueArn"]
        rule = "analytics-" + suffix + "-events"
        rule_arn = app.call("events", "put-rule", {"Name": rule, "EventPattern": json.dumps({"source": ["aws.glue", "aws.athena"]})})["RuleArn"]
        created.append(("rule", rule))
        queue_policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": queue_arn, "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]}
        app.call("sqs", "set-queue-attributes", {"QueueUrl": queue, "Attributes": {"Policy": json.dumps(queue_policy)}})
        target_result = app.call("events", "put-targets", {"Rule": rule, "Targets": [{"Id": "analytics", "Arn": queue_arn}]})
        require(target_result.get("FailedEntryCount", 0) == 0, "analytics event target rejected")
        app.call("s3api", "create-bucket", {"Bucket": bucket})
        created.append(("bucket", bucket))
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        role_arn = app.call("iam", "create-role", {"RoleName": role, "AssumeRolePolicyDocument": json.dumps(trust)})["Role"]["Arn"]
        created.append(("role", role))
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "s3:GetBucketLocation", "s3:AbortMultipartUpload", "s3:ListBucketMultipartUploads", "s3:ListMultipartUploadParts"], "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]}, {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "arn:aws:logs:us-east-1:000000000000:log-group:/aws-glue/*"}]}
        app.call("iam", "put-role-policy", {"RoleName": role, "PolicyName": "analytics", "PolicyDocument": json.dumps(policy)})
        program = b'''import argparse, time\nimport boto3\np=argparse.ArgumentParser(); p.add_argument('--bucket'); p.add_argument('--delay',type=float,default=0); p.add_argument('--fail',default='false'); a,_=p.parse_known_args()\ntime.sleep(a.delay)\nif a.fail == 'true': raise RuntimeError('owned analytics failure')\ns3=boto3.client('s3')\ns3.put_object(Bucket=a.bucket,Key='data/part.csv',Body=b'alpha,2\\nbeta,3\\nalpha,11\\n')\nprint('analytics-job-produced:13',flush=True)\n'''
        app.put(bucket, "scripts/job.py", program)
        app.call("glue", "create-job", {"Name": job, "Role": role_arn, "Command": {"Name": "pythonshell", "PythonVersion": "3", "ScriptLocation": f"s3://{bucket}/scripts/job.py"}, "DefaultArguments": {"--bucket": bucket}, "MaxCapacity": 0.0625, "Timeout": 2, "MaxRetries": 0})
        created.append(("job", job))
        run_id = app.call("glue", "start-job-run", {"JobName": job})["JobRunId"]
        app.await_job(job, run_id, {"SUCCEEDED"})
        actual_data = app.get(bucket, "data/part.csv")
        require(actual_data == b"alpha,2\nbeta,3\nalpha,11\n", "Glue output bytes differ")
        app.report["observations"]["glue_output_sha256"] = hashlib.sha256(actual_data).hexdigest()
        app.call("glue", "create-database", {"DatabaseInput": {"Name": database}})
        created.append(("database", database))
        app.call("glue", "create-table", {"DatabaseName": database, "TableInput": {"Name": "numbers", "TableType": "EXTERNAL_TABLE", "Parameters": {"classification": "csv"}, "StorageDescriptor": {"Columns": [{"Name": "label", "Type": "string"}, {"Name": "amount", "Type": "bigint"}], "Location": f"s3://{bucket}/data/", "InputFormat": "org.apache.hadoop.mapred.TextInputFormat", "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat", "SerdeInfo": {"SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe", "Parameters": {"field.delim": ","}}}}})
        app.call("athena", "create-work-group", {"Name": workgroup, "Configuration": {"EnforceWorkGroupConfiguration": True, "PublishCloudWatchMetricsEnabled": True, "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/results/", "EncryptionConfiguration": {"EncryptionOption": "SSE_S3"}}}})
        created.append(("workgroup", workgroup))
        query_input = {"QueryString": "SELECT label, sum(amount) AS total FROM numbers GROUP BY label ORDER BY label", "QueryExecutionContext": {"Database": database}, "WorkGroup": workgroup, "ClientRequestToken": uuid.uuid4().hex}
        query_id = app.call("athena", "start-query-execution", query_input)["QueryExecutionId"]
        require(app.call("athena", "start-query-execution", query_input)["QueryExecutionId"] == query_id, "query idempotency changed execution ID")
        execution = app.await_query(query_id, {"SUCCEEDED"})
        result_key = execution["ResultConfiguration"]["OutputLocation"].split("/", 3)[3]
        result_bytes = app.get(bucket, result_key)
        require(list(csv.reader(io.StringIO(result_bytes.decode()))) == [["label", "total"], ["alpha", "13"], ["beta", "3"]], "SQL result S3 bytes differ")
        result_output = app.call("athena", "get-query-results", {"QueryExecutionId": query_id})
        rows = [[cell.get("VarCharValue") for cell in row["Data"]] for row in result_output["ResultSet"]["Rows"]]
        require(rows == [["label", "total"], ["alpha", "13"], ["beta", "3"]], "GetQueryResults differs from SQL/S3 consumer")
        app.assert_warm_queries(workgroup)
        app.report["observations"]["query_rows"] = rows
        app.report["observations"]["query_columns"] = result_output["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]
        app.report["observations"]["query_result_sha256"] = hashlib.sha256(result_bytes).hexdigest()
        measured = app.call("cloudwatch", "get-metric-statistics", {"Namespace": "AWS/Athena",
            "MetricName": "ProcessedBytes", "Dimensions": [{"Name": "WorkGroup", "Value": workgroup},
                {"Name": "QueryType", "Value": "DML"}, {"Name": "QueryState", "Value": "SUCCEEDED"}],
            "StartTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()-3600)),
            "EndTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()+60)),
            "Period": 60, "Statistics": ["Sum"]})
        require(sum(point["Sum"] for point in measured["Datapoints"]) == len(actual_data),
                "Athena CloudWatch did not retain actual native scanned input bytes")
        app.report["observations"]["athena_metric_processed_bytes"] = len(actual_data)
        app.call("athena", "create-prepared-statement", {"StatementName": "owned_totals",
            "WorkGroup": workgroup, "QueryStatement": "SELECT label, sum(amount) AS total FROM numbers WHERE label = ? GROUP BY label"})
        prepared_rows = app.query("EXECUTE owned_totals USING 'alpha'", database, workgroup)
        require(prepared_rows == [["label", "total"], ["alpha", "13"]], "retained prepared statement did not execute through native SQL")
        app.report["observations"]["prepared_statement_consumer"] = prepared_rows
        missing_metadata = app.observe("athena", "get-table-metadata", {"CatalogName": "AwsDataCatalog", "DatabaseName": database, "TableName": "missing_table"})
        require(missing_metadata["code"] == "MetadataException", "missing Glue metadata did not retain Athena's native error")
        exercise_data_lake(app, suffix, bucket, database, role, role_arn, policy, workgroup, created)
        user = "analytics-" + suffix + "-reader"
        app.call("iam", "create-user", {"UserName": user})
        created.append(("user", user))
        access = app.call("iam", "create-access-key", {"UserName": user})["AccessKey"]
        created.append(("access-key", (user, access["AccessKeyId"])))
        consumer_env = dict(app.env, AWS_ACCESS_KEY_ID=access["AccessKeyId"], AWS_SECRET_ACCESS_KEY=access["SecretAccessKey"])
        denied_catalog = app.observe("glue", "get-database", {"Name": database}, env=consumer_env)
        require(denied_catalog["code"] == "AccessDeniedException", "unprivileged catalog read was not denied")
        consumer_policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "athena:GetQueryResults", "Resource": f"arn:aws:athena:us-east-1:000000000000:workgroup/{workgroup}"},
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/results/*"}]}
        app.call("iam", "put-user-policy", {"UserName": user, "PolicyName": "analytics-reader", "PolicyDocument": json.dumps(consumer_policy)})
        consumer_result = app.call("athena", "get-query-results", {"QueryExecutionId": query_id}, env=consumer_env)
        require(consumer_result["ResultSet"] == result_output["ResultSet"], "authorized independent consumer saw different rows")
        consumer_policy["Statement"].append({"Effect": "Deny", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/results/*"})
        app.call("iam", "put-user-policy", {"UserName": user, "PolicyName": "analytics-reader", "PolicyDocument": json.dumps(consumer_policy)})
        denied_result = app.observe("athena", "get-query-results", {"QueryExecutionId": query_id}, env=consumer_env)
        require(denied_result["code"] in {"AccessDeniedException", "AccessDenied"}, "GetQueryResults bypassed current S3 denial")
        app.report["observations"]["independent_consumer"] = {"before_policy": denied_catalog["code"], "allowed_rows": rows, "current_s3_deny": denied_result["code"]}
        failed_run = app.call("glue", "start-job-run", {"JobName": job, "Arguments": {"--fail": "true"}})["JobRunId"]
        app.await_job(job, failed_run, {"FAILED"})
        app.report["observations"]["job_failure"] = "FAILED"
        cancelled_run = app.call("glue", "start-job-run", {"JobName": job, "Arguments": {"--delay": "90"}})["JobRunId"]
        app.await_job(job, cancelled_run, {"RUNNING"})
        app.call("glue", "batch-stop-job-run", {"JobName": job, "JobRunIds": [cancelled_run]})
        app.await_job(job, cancelled_run, {"STOPPED"})
        app.report["observations"]["job_cancellation"] = "STOPPED"
        bad_query = app.call("athena", "start-query-execution", {"QueryString": "SELECT * FROM missing_analytics_table", "QueryExecutionContext": {"Database": database}, "WorkGroup": workgroup})["QueryExecutionId"]
        app.await_query(bad_query, {"FAILED"})
        app.report["observations"]["query_failure"] = "FAILED"
        expensive_sql = "SELECT sum(rand()) AS total FROM UNNEST(sequence(1,10000)) a(x) CROSS JOIN UNNEST(sequence(1,10000)) b(y) CROSS JOIN UNNEST(sequence(1,10000)) c(z)"
        cancelled_query = app.call("athena", "start-query-execution", {"QueryString": expensive_sql, "WorkGroup": workgroup})["QueryExecutionId"]
        app.await_query(cancelled_query, {"RUNNING"})
        app.await_native_query(cancelled_query, expensive_sql)
        app.call("athena", "stop-query-execution", {"QueryExecutionId": cancelled_query})
        app.await_query(cancelled_query, {"CANCELLED"})
        app.report["observations"]["query_cancellation"] = "native RUNNING query -> CANCELLED"
        remote_env = dict(app.env, AWS_DEFAULT_REGION="us-west-2", AWS_REGION="us-west-2")
        isolated = app.observe("glue", "get-database", {"Name": database}, env=remote_env)
        require(isolated["code"] == "EntityNotFoundException", "Glue region scope leaked")
        app.report["observations"]["region_isolation"] = isolated["code"]
        deny = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/data/*"}]}
        app.call("iam", "put-role-policy", {"RoleName": role, "PolicyName": "deny-current", "PolicyDocument": json.dumps(deny)})
        denied_run = app.call("glue", "start-job-run", {"JobName": job})["JobRunId"]
        app.await_job(job, denied_run, {"FAILED"})
        app.call("iam", "delete-role-policy", {"RoleName": role, "PolicyName": "deny-current"})
        app.report["observations"]["current_role_policy"] = "FAILED"
        workflow, trigger = "analytics-" + suffix + "-workflow", "analytics-" + suffix + "-trigger"
        app.call("glue", "create-workflow", {"Name": workflow, "DefaultRunProperties": {"purpose": "owned-native-restart"}})
        created.append(("workflow", workflow))
        app.call("glue", "create-trigger", {"Name": trigger, "Type": "ON_DEMAND", "WorkflowName": workflow,
            "Actions": [{"JobName": job, "Arguments": {"--delay": "45"}}]})
        created.append(("trigger", trigger))
        workflow_run = app.call("glue", "start-workflow-run", {"Name": workflow})["RunId"]
        admission_deadline = time.monotonic() + 30
        while True:
            graph = app.call("glue", "get-workflow-run", {"Name": workflow, "RunId": workflow_run, "IncludeGraph": True})["Run"]
            child_runs = [run for node in graph.get("Graph", {}).get("Nodes", []) if node.get("Name") == job
                          for run in node.get("JobDetails", {}).get("JobRuns", [])]
            if child_runs:
                require(len(child_runs) == 1, "workflow admitted duplicate native jobs")
                retained_run = child_runs[0]["Id"]
                break
            require(time.monotonic() < admission_deadline, "workflow did not admit its actual job")
            time.sleep(0.3)
        retained_state = app.await_job(job, retained_run, {"RUNNING"})
        native_job = "stackd-glue-" + hashlib.sha256(f"arn:aws:glue:us-east-1:000000000000:job/{job}/{retained_run}/attempt-{retained_state['Attempt']}".encode()).hexdigest()
        app.owned_containers.add(native_job)
        before_restart = app.native_container_started(native_job)
        app.remember_athena_receipts()
        athena_before_restart = set(app.athena_containers)
        app.controller.stop(kill_on_timeout=True)
        for name in athena_before_restart:
            output = subprocess.run(["docker", "--host", app.args.docker_host, "container", "ls", "--all",
                                     "--filter", "name=^/" + name + "$", "--format", "{{.Names}}"],
                                    capture_output=True, text=True, timeout=10)
            require(output.returncode == 0 and not output.stdout.strip(),
                    "controller shutdown retained an exact owned Athena container")
        require(not app.remember_athena_receipts(), "controller shutdown retained Athena ownership receipts")
        app.start()
        require(app.native_container_started(native_job) == before_restart, "controller restart relaunched customer code")
        app.await_job(job, retained_run, {"SUCCEEDED"})
        app.assert_warm_queries(workgroup)
        require(not athena_before_restart.intersection(app.remember_athena_receipts()),
                "controller restart reused a retired Athena engine incarnation")
        app.report["observations"]["athena_restart_identity"] = "old exact-owned containers/receipts removed; fresh warm incarnation"
        app.report["observations"]["inflight_job_restart"] = "same native container start time; genuine script completed"
        workflow_deadline = time.monotonic() + 30
        while True:
            graph = app.call("glue", "get-workflow-run", {"Name": workflow, "RunId": workflow_run, "IncludeGraph": True})["Run"]
            if graph["Status"] == "COMPLETED":
                require(graph["Statistics"]["SucceededActions"] == 1 and graph["Statistics"]["FailedActions"] == 0,
                        "workflow did not consume the real child outcome")
                break
            require(time.monotonic() < workflow_deadline, "retained workflow did not complete after its native job")
            time.sleep(0.3)
        properties = app.call("glue", "get-workflow-run-properties", {"Name": workflow, "RunId": workflow_run})["RunProperties"]
        require(properties == {"purpose": "owned-native-restart"}, "workflow properties changed after restart")
        app.report["observations"]["workflow_trigger_native_restart"] = "one real succeeded child and retained run properties"
        log_deadline = time.monotonic() + 30
        while True:
            output = app.observe("logs", "get-log-events", {"logGroupName": "/aws-glue/python-jobs/output", "logStreamName": retained_run})
            if output["code"] == "Success" and any("analytics-job-produced:13" in event["message"] for event in output["output"].get("events", [])):
                break
            require(time.monotonic() < log_deadline, "real Glue stdout absent from Logs")
            time.sleep(0.3)
        app.report["observations"]["cloudwatch_logs"] = "analytics-job-produced:13"
        require(app.job_state(job, run_id)["JobRunState"] == "SUCCEEDED", "retained successful job changed")
        require(app.job_state(job, cancelled_run)["JobRunState"] == "STOPPED", "retained cancelled job changed")
        require(app.query_state(query_id)["Status"]["State"] == "SUCCEEDED", "retained successful query changed")
        require(app.get(bucket, result_key) == result_bytes, "retained S3 query result changed")
        require(app.call("athena", "get-query-results", {"QueryExecutionId": query_id})["ResultSet"] == result_output["ResultSet"], "retained result consumer changed")
        app.report["observations"]["sqlite_controller_restart"] = "retained job/query state and exact S3 results"
        events = []
        event_deadline = time.monotonic() + 30
        required_events = {"Glue Job State Change", "Glue Data Catalog Database State Change", "Athena Query State Change"}
        while time.monotonic() < event_deadline:
            messages = app.call("sqs", "receive-message", {"QueueUrl": queue, "MaxNumberOfMessages": 10, "WaitTimeSeconds": 1}).get("Messages", [])
            for message in messages:
                event = json.loads(message["Body"])
                events.append(event)
                app.call("sqs", "delete-message", {"QueueUrl": queue, "ReceiptHandle": message["ReceiptHandle"]})
            types = {event["detail-type"] for event in events}
            job_success = any(event["detail-type"] == "Glue Job State Change" and event["detail"].get("jobRunId") == run_id and event["detail"].get("state") == "SUCCEEDED" for event in events)
            query_success = any(event["detail-type"] == "Athena Query State Change" and event["detail"].get("queryExecutionId") == query_id and event["detail"].get("currentState") == "SUCCEEDED" for event in events)
            if required_events <= types and job_success and query_success:
                break
        require(required_events <= {event["detail-type"] for event in events} and job_success and query_success, "committed analytics lifecycle events did not reach SQS")
        app.report["observations"]["eventbridge_consumer"] = sorted({event["detail-type"] for event in events})
        audits = app.call("cloudtrail", "lookup-events", {"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "StartQueryExecution"}]})["Events"]
        require(any(json.loads(event["CloudTrailEvent"]).get("eventSource") == "athena.amazonaws.com" for event in audits), "Athena API audit absent from CloudTrail")
        require(all(query_input["QueryString"] not in event["CloudTrailEvent"] for event in audits), "CloudTrail exposed query SQL")
        app.report["observations"]["cloudtrail_consumer"] = "Athena StartQueryExecution recorded without SQL text"
    except Exception as error:
        app.report["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        if app.controller.process is not None and app.controller.process.poll() is None:
            for kind, name in reversed(created):
                cleanup_key = kind + ":" + (name[0] if isinstance(name, tuple) else name)
                try:
                    if kind == "access-key":
                        app.call("iam", "delete-access-key", {"UserName": name[0], "AccessKeyId": name[1]})
                    elif kind == "user":
                        app.observe("iam", "delete-user-policy", {"UserName": name, "PolicyName": "analytics-reader"})
                        app.call("iam", "delete-user", {"UserName": name})
                    elif kind == "workgroup":
                        executions = app.call("athena", "list-query-executions", {"WorkGroup": name}).get("QueryExecutionIds", [])
                        for execution_id in executions:
                            if app.query_state(execution_id)["Status"]["State"] in {"RUNNING", "QUEUED"}:
                                app.call("athena", "stop-query-execution", {"QueryExecutionId": execution_id})
                                app.await_query(execution_id, {"CANCELLED", "FAILED", "SUCCEEDED"})
                        app.call("athena", "delete-work-group", {"WorkGroup": name, "RecursiveDeleteOption": True})
                    elif kind == "database":
                        app.call("glue", "delete-database", {"Name": name})
                    elif kind == "crawler":
                        crawler = app.call("glue", "get-crawler", {"Name": name})["Crawler"]
                        if crawler["State"] != "READY":
                            app.call("glue", "stop-crawler", {"Name": name})
                            deadline = time.monotonic() + 30
                            while app.call("glue", "get-crawler", {"Name": name})["Crawler"]["State"] != "READY":
                                require(time.monotonic() < deadline, "owned crawler did not stop for cleanup")
                                time.sleep(0.2)
                        app.call("glue", "delete-crawler", {"Name": name})
                    elif kind == "security":
                        app.call("glue", "delete-security-configuration", {"Name": name})
                    elif kind == "trigger":
                        app.call("glue", "delete-trigger", {"Name": name})
                    elif kind == "workflow":
                        for run in app.call("glue", "get-workflow-runs", {"Name": name}).get("Runs", []):
                            if run["Status"] in {"RUNNING", "STOPPING"}:
                                app.observe("glue", "stop-workflow-run", {"Name": name, "RunId": run["WorkflowRunId"]})
                        app.call("glue", "delete-workflow", {"Name": name})
                    elif kind == "key":
                        app.call("kms", "schedule-key-deletion", {"KeyId": name, "PendingWindowInDays": 7})
                        app.report["cleanup"][cleanup_key] = "scheduled_deletion"
                        continue
                    elif kind == "job":
                        runs = app.call("glue", "get-job-runs", {"JobName": name}).get("JobRuns", [])
                        for execution in runs:
                            if execution["JobRunState"] in {"STARTING", "RUNNING", "STOPPING", "WAITING"}:
                                app.call("glue", "batch-stop-job-run", {"JobName": name, "JobRunIds": [execution["Id"]]})
                                app.await_job(name, execution["Id"], {"STOPPED", "FAILED", "SUCCEEDED", "TIMEOUT"})
                        app.call("glue", "delete-job", {"JobName": name})
                    elif kind == "role":
                        for policy_name in ("deny-current", "analytics"):
                            app.observe("iam", "delete-role-policy", {"RoleName": name, "PolicyName": policy_name})
                        app.call("iam", "delete-role", {"RoleName": name})
                    elif kind == "bucket":
                        while True:
                            contents = app.call("s3api", "list-objects-v2", {"Bucket": name}).get("Contents", [])
                            if not contents:
                                break
                            app.call("s3api", "delete-objects", {"Bucket": name, "Delete": {"Objects": [{"Key": item["Key"]} for item in contents]}})
                        app.call("s3api", "delete-bucket", {"Bucket": name})
                    elif kind == "rule":
                        app.call("events", "remove-targets", {"Rule": name, "Ids": ["analytics"]})
                        app.call("events", "delete-rule", {"Name": name})
                    elif kind == "queue":
                        app.call("sqs", "delete-queue", {"QueueUrl": name})
                    app.report["cleanup"][cleanup_key] = "deleted"
                except Exception as error:
                    app.report["cleanup"][cleanup_key] = type(error).__name__
        try:
            try:
                app.remember_athena_receipts()
            finally:
                app.controller.stop(kill_on_timeout=True)
        finally:
            native_cleanup = {}
            for name in sorted(app.owned_containers):
                output = subprocess.run(["docker", "--host", app.args.docker_host, "container", "ls", "--all",
                                        "--filter", "name=^/" + name + "$", "--format", "{{.Names}}"],
                                        capture_output=True, text=True, timeout=10)
                if output.returncode == 0 and not output.stdout.strip():
                    native_cleanup[name] = "removed"
                elif output.returncode == 0 and output.stdout.strip() == name:
                    cleanup_target = name
                    if name in app.athena_containers:
                        try:
                            cleanup_target = app.inspect_athena_container(name)["Id"]
                            require(re.fullmatch(r"[0-9a-f]{64}", cleanup_target) is not None,
                                    "owned Athena container has no immutable Docker ID")
                        except Exception:
                            native_cleanup[name] = "ownership_inspection_failed"
                            continue
                    removed = subprocess.run(["docker", "--host", app.args.docker_host, "rm", "-f", cleanup_target],
                                             capture_output=True, text=True, timeout=30)
                    native_cleanup[name] = "forced_cleanup" if removed.returncode == 0 else "cleanup_failed"
                else:
                    native_cleanup[name] = "inspection_failed"
            app.report["native_cleanup"] = native_cleanup
            app.report["athena_receipt_cleanup"] = "removed" if not app.remember_athena_receipts() else "retained"
            (app.state / "report.json").write_text(json.dumps(app.report, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    parser.add_argument("--glue-spark-image", default="")
    parser.add_argument("--glue-python-image", default="")
    parser.add_argument("--athena-image", default="")
    parser.add_argument("--athena-hive-ddl-image", default="")
    parser.add_argument("--athena-endpoint-host", default="127.0.0.1",
                        help="controller-reachable route to the Docker daemon's loopback publication")
    parser.add_argument("--athena-callback-listen", default="")
    parser.add_argument("--athena-callback-host", default="")
    parser.add_argument("--compute-endpoint", default="",
                        help="controller AWS endpoint reachable by Glue containers; {port} expands to its chosen port")
    args = parser.parse_args()
    native_route = urlsplit("//" + args.athena_endpoint_host)
    require(bool(native_route.hostname) and native_route.port is None
            and native_route.username is None and native_route.password is None
            and not native_route.path and not native_route.query and not native_route.fragment,
            "Athena endpoint host must be a hostname or bracketed IP without a port")
    args.athena_endpoint_host = native_route.hostname
    if not args.docker_host.startswith("unix://"):
        require(args.athena_callback_listen and args.athena_callback_host and args.compute_endpoint,
                "remote Docker requires explicit Athena callback listen/host and Glue compute endpoint routes")
    app = Application(args)
    exercise(app)
    app.check_controllers()
    require(all(value == ("scheduled_deletion" if name.startswith("key:") else "deleted")
                for name, value in app.report["cleanup"].items()), "owned API resource cleanup failed")
    require(all(value == "removed" for value in app.report["native_cleanup"].values()), "controller left owned native resources requiring forced cleanup")
    require(app.report["athena_receipt_cleanup"] == "removed", "controller retained Athena ownership receipts")
    print(json.dumps(app.report, indent=2))


if __name__ == "__main__":
    main()
