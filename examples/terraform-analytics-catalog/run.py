"""Run current-provider catalog lifecycles and required native consumers.

Prerequisites: build stackd, Terraform 1.15.9, Docker, host psql, and the installed
images listed in coverage.json. Accept compute/glue/AWS-GLUE-LICENSE.txt first.
Install Python requirements from this directory. No runtime is silently skipped.
  python3 examples/terraform-analytics-catalog/run.py --port 14715 \
      --provider-mirror /absolute/path/to/provider-mirror
Only completed stages enter the private report.json. The coverage inventory stays
unverified until this complete workflow is exercised by the integration owner.
"""

import contextlib
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from fastavro import parse_schema, schemaless_reader, schemaless_writer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local import (ACCOUNT, REGION, arguments, client, controller, environment,
                   expect_missing, local_endpoint, require, workspace)

# Reuse the existing analytics query/record helpers. Do not create another
# controller, endpoint-safety boundary, or SQL-result interpretation convention.
_spec = importlib.util.spec_from_file_location("analytics_fixture", Path(__file__).resolve().parents[1] / "terraform-analytics" / "run.py")
analytics = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(analytics)

POSTGRES_IMAGE = "postgres@sha256:639ab7ceb90e13123085b741fb31ef493fba25463002f6da665352e7b534b652"
IMAGES = analytics.IMAGES + analytics.GLUE_IMAGES + (POSTGRES_IMAGE,)
IMPORT_TYPES = {
    "aws_glue_catalog_database", "aws_glue_catalog_table", "aws_glue_classifier",
    "aws_glue_connection", "aws_glue_crawler", "aws_glue_data_catalog_encryption_settings",
    "aws_glue_job", "aws_glue_partition", "aws_glue_partition_index", "aws_glue_registry",
    "aws_glue_resource_policy", "aws_glue_schema", "aws_glue_security_configuration",
    "aws_glue_trigger", "aws_glue_user_defined_function", "aws_glue_workflow",
    "aws_athena_workgroup", "aws_kinesis_account_settings", "aws_kinesis_stream",
}


@contextlib.contextmanager
def postgres(args, root, env, password):
    name = "stackd-tf-catalog-" + uuid.uuid4().hex
    credentials = root / "postgres.env"
    credentials.write_text("POSTGRES_USER=catalog\nPOSTGRES_DB=catalog\nPOSTGRES_PASSWORD=" + password + "\n")
    credentials.chmod(0o600)
    docker = ["docker", "--host", args.docker_host]
    subprocess.run([*docker, "run", "--detach", "--name", name, "--publish", "127.0.0.1::5432",
                    "--env-file", str(credentials), "--pull=never", POSTGRES_IMAGE],
                   check=True, env=env, stdout=subprocess.DEVNULL)
    try:
        inspected = json.loads(subprocess.run([*docker, "inspect", name], check=True,
            env=env, text=True, capture_output=True).stdout)[0]
        port = int(inspected["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostPort"])
        def ready():
            # The image starts a socket-only server during initdb. Published
            # native TCP readiness must wait for the final server, not that one.
            return subprocess.run([*docker, "exec", name, "pg_isready", "--host", "127.0.0.1",
                "--username", "catalog", "--dbname", "catalog"], env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        analytics.await_value(ready, lambda status: status == 0, "owned native PostgreSQL", timeout=60)
        def sql(statement):
            result = subprocess.run([*docker, "exec", "--interactive", name, "psql", "--no-psqlrc",
                "--username", "catalog", "--dbname", "catalog", "--set", "ON_ERROR_STOP=1",
                "--tuples-only", "--no-align"], input=statement, text=True,
                env=env, capture_output=True)
            if result.returncode:
                (root / "postgres-sql-failure.log").write_text(result.stdout + result.stderr)
            result.check_returncode()
            return result.stdout.strip()
        sql("CREATE SCHEMA source; CREATE TABLE source.sales(label text NOT NULL, amount integer NOT NULL); "
            "INSERT INTO source.sales VALUES ('north',4),('north',6),('south',14); "
            "CREATE TABLE source.excluded(secret bytea);")
        yield port, sql
    finally:
        subprocess.run([*docker, "rm", "--force", name], check=True, env=env,
                       stdout=subprocess.DEVNULL)
        credentials.unlink()


def verify_workflow(endpoint, out, revision):
    glue = client("glue", endpoint)
    run_id = glue.start_workflow_run(Name=out["workflow"], RunProperties={"invocation": uuid.uuid4().hex})["RunId"]
    run = analytics.await_value(lambda: glue.get_workflow_run(Name=out["workflow"], RunId=run_id,
        IncludeGraph=True)["Run"], lambda value: value["Status"] in {"COMPLETED", "STOPPED", "ERROR"},
        "real Spark job and native crawler workflow", timeout=720)
    require(run["Status"] == "COMPLETED", f"Native workflow failed: {run}")
    stats = run["Statistics"]
    require(stats["TotalActions"] == 3 and stats["SucceededActions"] == 3 and
            stats["FailedActions"] == 0 and stats["ErroredActions"] == 0,
            f"Workflow did not complete its actual job and both crawlers: {stats}")
    jobs = [node for node in run["Graph"]["Nodes"] if node["Type"] == "JOB"]
    require(len(jobs) == 1 and jobs[0]["JobDetails"]["JobRuns"], "Actual job run was absent from workflow graph")
    job_id = jobs[0]["JobDetails"]["JobRuns"][0]["Id"]
    job = glue.get_job_run(JobName=out["job"], RunId=job_id)["JobRun"]
    require(job["JobRunState"] == "SUCCEEDED" and job["Arguments"]["--WORKFLOW_RUN_ID"] == run_id,
            f"Real Spark job did not receive this workflow run: {job}")
    marker = json.loads(analytics.s3_bytes(client("s3", endpoint), out["bucket"],
                       f"job-results/revision-{revision}.json"))
    require(marker["workflow_run_id"] == run_id and marker["revision"] == revision and
            marker["udf_result"] == ("MIXED" if revision == 1 else "mixed"),
            "Independent execution marker does not contain actual catalog UDF result")
    s3 = client("s3", endpoint)
    selected_objects = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=out["bucket"], Prefix="input/"):
        for obj in page.get("Contents", []):
            if not Path(obj["Key"]).name.startswith("part-"):
                continue
            head = s3.head_object(Bucket=out["bucket"], Key=obj["Key"])
            expected = "aws:kms" if revision == 1 else "AES256"
            require(head.get("ServerSideEncryption") == expected,
                    f"Spark writer did not apply selected security configuration: {head}")
            if revision == 1:
                require(head.get("SSEKMSKeyId") == out["key_arn"], "Spark writer used the wrong real KMS key")
            body = analytics.s3_bytes(s3, out["bucket"], obj["Key"])
            rows = list(csv.reader(io.StringIO(body.decode()), delimiter="|" if revision == 1 else ";"))
            require(rows[0] == ["label", "amount"] and len(rows) >= 2,
                    "Independent S3 consumer did not read native CSV rows")
            selected_objects.append({"key": obj["Key"], "sha256": hashlib.sha256(body).hexdigest(),
                                     "encryption": expected, "rows": rows})
    require(len(selected_objects) == 2, f"Native Spark did not produce both partition objects: {selected_objects}")
    table = glue.get_table(CatalogId=ACCOUNT, DatabaseName=out["database"], Name="csv_input")["Table"]
    require(table["Parameters"]["UPDATED_BY_CRAWLER"] == out["s3_crawler"],
            "Catalog table did not come from the actual S3 crawler")
    partitions = glue.get_partitions(CatalogId=ACCOUNT, DatabaseName=out["database"], TableName="csv_input")["Partitions"]
    require({tuple(partition["Values"]) for partition in partitions} == {("east",), ("west",)},
            "S3 crawler did not discover native partition directories")
    labels = ("NORTH", "SOUTH") if revision == 1 else ("north", "south")
    expected_rows = [["label", "total", "region"], [labels[0], "10", "east"], [labels[1], "14", "west"]]
    inputs = dict(out, catalog="AwsDataCatalog")
    crawler_select = analytics.verify_select(endpoint, inputs,
        "SELECT label, sum(amount) AS total, region FROM csv_input GROUP BY label, region ORDER BY label, region", expected_rows)
    indexed_select = analytics.verify_select(endpoint, inputs,
        "SELECT label, sum(amount) AS total, region FROM indexed GROUP BY label, region ORDER BY label, region", expected_rows)
    indexes = glue.get_partition_indexes(CatalogId=ACCOUNT, DatabaseName=out["database"], TableName="indexed")["PartitionIndexDescriptorList"]
    require(len(indexes) == 1 and indexes[0]["IndexName"] == f"region-{revision}" and
            indexes[0]["IndexStatus"] == "ACTIVE", f"Actual index lifecycle did not complete: {indexes}")
    selected = glue.get_partitions(CatalogId=ACCOUNT, DatabaseName=out["database"], TableName="indexed",
                                   Expression="region = 'east'")["Partitions"]
    require([part["Values"] for part in selected] == [["east"]], "Independent partition expression consumer differs")
    # Typed index state does not imply native acceleration or a performance SLA.
    return {"run_id": run_id, "job_run_id": job_id, "statistics": stats, "udf": marker,
            "spark_objects": selected_objects, "crawler_select": crawler_select,
            "indexed_select": indexed_select, "partition_expression": [part["Values"] for part in selected]}


def verify_postgres(endpoint, out, revision, sql, port, password, root):
    actual = sql("SELECT sum(amount) FROM source.sales;")
    require(actual == ("24" if revision == 1 else "27"), f"Actual PostgreSQL rows differ: {actual}")
    # A separate libpq process authenticates against the credentials used by the
    # Secrets Manager-backed Glue connection. The owner uses its own psql process.
    env = {key: value for key, value in environment().items() if not key.startswith("PG")}
    env.update(HOME=str(root), PGHOST="127.0.0.1", PGPORT=str(port), PGDATABASE="catalog",
               PGUSER="catalog", PGPASSWORD=password, PGSSLMODE="disable", PGGSSENCMODE="disable")
    observed = subprocess.run(["psql", "--no-psqlrc", "--no-password", "--tuples-only", "--no-align",
        "--set", "ON_ERROR_STOP=1", "--command", "SELECT sum(amount) FROM source.sales"],
        env=env, check=True, text=True, capture_output=True).stdout.strip()
    require(observed == actual, "Independent credential-backed PostgreSQL consumer differs")
    glue = client("glue", endpoint)
    table = glue.get_table(CatalogId=ACCOUNT, DatabaseName=out["database"], Name="jdbc_catalog_source_sales")["Table"]
    columns = {column["Name"]: column["Type"] for column in table["StorageDescriptor"]["Columns"]}
    expected = {"label": "string", "amount": "int"}
    if revision == 2:
        expected["revision"] = "int"
    require(columns == expected and table["Parameters"]["connectionName"] == out["connection"],
            f"Actual JDBC discovery differs from live native schema: {table}")
    expect_missing(glue.get_table, {"EntityNotFoundException"}, CatalogId=ACCOUNT,
                   DatabaseName=out["database"], Name="jdbc_catalog_source_excluded")
    return {"native_sum": actual, "catalog_columns": columns, "excluded_table_absent": True}


def verify_schema_records(endpoint, out, revision, earlier=None):
    glue = client("glue", endpoint)
    version = glue.get_schema_version(SchemaId={"SchemaArn": out["schema_arn"]},
                                     SchemaVersionNumber={"LatestVersion": True})
    require(version["Status"] == "AVAILABLE" and version["VersionNumber"] == revision,
            f"Actual schema version update did not complete: {version}")
    writer_schema = parse_schema(json.loads(version["SchemaDefinition"]))
    row = {"label": f"revision-{revision}", "amount": revision * 10}
    encoded = io.BytesIO()
    # AWS's published uncompressed header is 03 00 plus the 16-byte version UUID.
    # See the official AWSSchemaRegistryConstants.java URL in coverage.json.
    encoded.write(b"\x03\x00" + uuid.UUID(version["SchemaVersionId"]).bytes)
    schemaless_writer(encoded, writer_schema, row)
    payload = encoded.getvalue()
    producer = client("kinesis", endpoint)
    sent = producer.put_record(StreamName=out["stream_name"], PartitionKey="schema-registry", Data=payload)
    reader = client("kinesis", endpoint)
    iterator = reader.get_shard_iterator(StreamName=out["stream_name"], ShardId=sent["ShardId"],
        ShardIteratorType="AT_SEQUENCE_NUMBER", StartingSequenceNumber=sent["SequenceNumber"])["ShardIterator"]
    def read():
        nonlocal iterator
        page = reader.get_records(ShardIterator=iterator, Limit=1)
        iterator = page["NextShardIterator"]
        return page["Records"]
    records = analytics.await_value(read, bool, "independent actual Avro Kinesis record")
    received = records[0]["Data"]
    require(received == payload and received[:2] == b"\x03\x00", "Native record changed schema-registry bytes")
    resolved_id = str(uuid.UUID(bytes=received[2:18]))
    resolved = client("glue", endpoint).get_schema_version(SchemaVersionId=resolved_id)
    decoded = schemaless_reader(io.BytesIO(received[18:]), parse_schema(json.loads(resolved["SchemaDefinition"])), writer_schema)
    require(decoded == row, f"Independent registry-backed Avro deserializer differs: {decoded}")
    if earlier is not None:
        old_version = client("glue", endpoint).get_schema_version(SchemaVersionId=earlier["version_id"])
        old_decoded = schemaless_reader(io.BytesIO(earlier["payload"][18:]),
            parse_schema(json.loads(old_version["SchemaDefinition"])), writer_schema)
        require(old_decoded == earlier["row"], "Compatible new reader could not decode prior native record")
    commitment = producer.describe_account_settings()["MinimumThroughputBillingCommitment"]
    require(commitment["Status"] == ("ENABLED" if revision == 1 else "ENABLED_UNTIL_EARLIEST_ALLOWED_END")
            and commitment.get("StartedAt") and commitment.get("EarliestAllowedEndAt"),
            f"Billing commitment did not preserve its real deferred disable boundary: {commitment}")
    stream = producer.describe_stream_summary(StreamName=out["stream_name"])["StreamDescriptionSummary"]
    require(stream["StreamModeDetails"]["StreamMode"] == "ON_DEMAND" and
            stream["WarmThroughput"]["CurrentMiBps"] == revision + 3 and
            stream["OpenShardCount"] == revision + 3,
            f"Native warm-throughput topology did not change: {stream}")
    return {"version_id": resolved_id, "payload": payload, "row": row,
            "evidence": {"version_id": resolved_id, "version": revision, "record": decoded,
                         "sha256": hashlib.sha256(payload).hexdigest(), "sequence_number": sent["SequenceNumber"],
                         "shard_id": sent["ShardId"],
                         "native_shards": stream["OpenShardCount"], "commitment": commitment["Status"]}}


def verify_policy(endpoint, out, credentials, revision):
    reader = boto3.Session(aws_access_key_id=credentials["key"], aws_secret_access_key=credentials["secret"],
        region_name=REGION).client("glue", endpoint_url=local_endpoint(endpoint),
        config=Config(connect_timeout=3, read_timeout=60, proxies={}, retries={"max_attempts": 0}))
    allowed = reader.get_table if revision == 1 else reader.get_database
    denied = reader.get_database if revision == 1 else reader.get_table
    database_args = {"CatalogId": ACCOUNT, "Name": out["database"]}
    table_args = {"CatalogId": ACCOUNT, "DatabaseName": out["database"], "Name": "indexed"}
    allowed(**(table_args if revision == 1 else database_args))
    try:
        denied(**(database_args if revision == 1 else table_args))
    except ClientError as error:
        require(error.response["Error"]["Code"] == "AccessDeniedException", f"Policy failed for the wrong reason: {error}")
    else:
        raise AssertionError("Current resource-policy deny did not override the reader's identity allow")
    return {"revision": revision, "identity_allow_consumed": True, "current_resource_deny_enforced": True}


def password_probe(endpoint, out, name, password, revision):
    glue = client("glue", endpoint)
    if revision == 1:
        glue.create_connection(CatalogId=ACCOUNT, ConnectionInput={"Name": name, "ConnectionType": "JDBC",
            "ConnectionProperties": {"JDBC_CONNECTION_URL": "jdbc:postgresql://127.0.0.1/owned", "USERNAME": "owned", "PASSWORD": password}})
    connection = glue.get_connection(CatalogId=ACCOUNT, Name=name)["Connection"]["ConnectionProperties"]
    hidden = glue.get_connection(CatalogId=ACCOUNT, Name=name, HidePassword=True)["Connection"]["ConnectionProperties"]
    require("PASSWORD" not in hidden and "ENCRYPTED_PASSWORD" not in hidden, "HidePassword leaked a stored credential")
    if revision == 1:
        import base64
        require("PASSWORD" not in connection and "ENCRYPTED_PASSWORD" in connection, "Current encrypted projection was not applied")
        plain = client("kms", endpoint).decrypt(CiphertextBlob=base64.b64decode(connection["ENCRYPTED_PASSWORD"]),
            EncryptionContext={"aws:glue:connection:arn": f"arn:aws:glue:{REGION}:{ACCOUNT}:connection/{name}"})
        require(plain["Plaintext"].decode() == password and plain["KeyId"] == out["key_arn"],
                "Independent real KMS consumer could not decrypt the connection password")
    else:
        require(connection.get("PASSWORD") == password and "ENCRYPTED_PASSWORD" not in connection,
                "Current disabled projection did not decrypt the previously encrypted credential")
    return {"revision": revision, "hidden_projection": True, "current_encryption_projection": True}


def stop_active_work(endpoint, out):
    glue = client("glue", endpoint)
    for run in glue.get_workflow_runs(Name=out["workflow"], IncludeGraph=False)["Runs"]:
        if run["Status"] in {"RUNNING", "STOPPING"}:
            glue.stop_workflow_run(Name=out["workflow"], RunId=run["WorkflowRunId"])
            analytics.await_value(lambda: glue.get_workflow_run(Name=out["workflow"], RunId=run["WorkflowRunId"])["Run"],
                lambda value: value["Status"] not in {"RUNNING", "STOPPING"}, "owned workflow cancellation")


def main():
    parser = arguments(__doc__, 14715)
    parser.add_argument("--provider-mirror", type=Path)
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    args = parser.parse_args()
    require(all(shutil.which(program) for program in ("terraform", "docker", "psql")),
            "Install Terraform, Docker, and host psql first")
    root = workspace(args, "terraform-analytics-catalog")
    root.chmod(0o700)
    source = Path(__file__).resolve().parent
    for name in ("main.tf", "producer.py"):
        shutil.copyfile(source / name, root / name)
    env = environment()
    for image in IMAGES:
        subprocess.run(["docker", "--host", args.docker_host, "image", "inspect", image],
                       check=True, stdout=subprocess.DEVNULL, env=env)
    configuration = "disable_checkpoint = true\n"
    if args.provider_mirror is not None:
        require(args.provider_mirror.is_dir(), "Provider mirror directory does not exist")
        configuration += ("provider_installation {\n  filesystem_mirror {\n    path = " +
            json.dumps(str(args.provider_mirror.resolve())) +
            '\n    include = ["registry.terraform.io/hashicorp/aws"]\n  }\n}\n')
    (root / "terraform.rc").write_text(configuration)
    env["TF_CLI_CONFIG_FILE"] = str(root / "terraform.rc")
    report = {"provider_version": "6.68.0", "fixture": "terraform-analytics-catalog",
              "status": "running", "stages": [], "unexercised": json.loads((source / "coverage.json").read_text()),
              "boto3_version": boto3.__version__, "assertion_failures": []}
    def terraform(*command, capture=False, check=True):
        return analytics.run_terraform(root, env, report, *command, capture=capture, check=check)
    report["terraform_version"] = json.loads(terraform("version", "-json", capture=True).stdout)["terraform_version"]
    def stage(label, evidence=None):
        report["stages"].append({"stage": label, "evidence": evidence})
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print("Completed:", label, flush=True)
    def output(name):
        return json.loads(terraform("output", "-json", name, capture=True).stdout)
    def resources():
        return json.loads(terraform("show", "-json", capture=True).stdout).get("values", {}).get("root_module", {}).get("resources", [])
    def no_changes(label, refresh=False):
        analytics.check_no_changes(terraform, root, stage, report["assertion_failures"], label, refresh)
    out = None
    probe_name = None
    password = secrets.token_urlsafe(32)
    try:
        with postgres(args, root, env, password) as (port, sql):
            with contextlib.ExitStack() as controllers:
                extra = ["-docker-host", args.docker_host, "-athena-runtime", "-kinesis-runtime", "-glue-runtime"]
                endpoint = controllers.enter_context(controller(args, root, extra=extra, containers=True))
                name = "tf-catalog-" + uuid.uuid4().hex[:12]
                glue = client("glue", endpoint)
                catalog_id = ACCOUNT + ":" + name
                glue.create_catalog(Name=name, CatalogInput={"Description": "Actual plain catalog data source"},
                                    Tags={"Fixture": "terraform-analytics-catalog"})
                variables = {"endpoint": endpoint, "name": name, "account_id": ACCOUNT,
                             "plain_catalog_id": catalog_id, "postgres_port": port,
                             "postgres_password": password, "revision": 1}
                (root / "local.auto.tfvars.json").write_text(json.dumps(variables))
                (root / "local.auto.tfvars.json").chmod(0o600)
                try:
                    terraform("init", "-input=false")
                    terraform("apply", "-input=false", "-auto-approve", "-parallelism=2")
                    out = output("catalog")
                    stage("create", [resource["address"] for resource in resources() if resource["mode"] == "managed"])
                    require(out["plain_catalog_id"] == catalog_id, "Plain catalog data source read a different catalog")
                    probe_name = out["connection"] + "-password-probe"
                    stage("revision-1-password-consumer", password_probe(endpoint, out, probe_name, password, 1))
                    stage("revision-1-native-workflow", verify_workflow(endpoint, out, 1))
                    stage("revision-1-native-postgres", verify_postgres(endpoint, out, 1, sql, port, password, root))
                    earlier = verify_schema_records(endpoint, out, 1)
                    stage("revision-1-schema-native-record", earlier["evidence"])
                    stage("revision-1-resource-policy", verify_policy(endpoint, out, output("reader"), 1))
                    analytics.settle_apply_projection(terraform, resources, stage, root, report["assertion_failures"], "create-projection")
                    no_changes("create-refresh", refresh=True)
                    no_changes("create-no-op")
                    imported = []
                    for resource in resources():
                        if resource["mode"] != "managed" or resource["type"] not in IMPORT_TYPES:
                            continue
                        address, identifier = resource["address"], resource["values"]["id"]
                        if resource["type"] == "aws_kinesis_stream":
                            identifier = resource["values"]["name"]
                        snapshot = root / "before-import.tfstate"
                        snapshot.write_text(terraform("state", "pull", capture=True).stdout)
                        terraform("state", "rm", address)
                        try:
                            terraform("import", "-input=false", address, identifier)
                        except BaseException:
                            terraform("state", "push", "-force", str(snapshot))
                            raise
                        imported.append(address)
                    stage("import", imported)
                    terraform("apply", "-input=false", "-auto-approve", "-parallelism=2")
                    no_changes("import-refresh", refresh=True)
                    no_changes("import-no-op")
                    sql("ALTER TABLE source.sales ADD COLUMN revision integer NOT NULL DEFAULT 2; INSERT INTO source.sales(label,amount) VALUES ('bonus',3);")
                    variables["revision"] = 2
                    (root / "local.auto.tfvars.json").write_text(json.dumps(variables))
                    terraform("apply", "-input=false", "-auto-approve", "-parallelism=2")
                    updated = output("catalog")
                    require(updated["stream_arn"] == out["stream_arn"] and updated["schema_arn"] == out["schema_arn"] and
                            updated["registry_arn"] == out["registry_arn"] and updated["job"] == out["job"],
                            "Mutable native owners were replaced instead of updated")
                    require(updated["security"] != out["security"], "Provider ForceNew security configuration was not replaced")
                    out = updated
                    stage("update", {"revision": 2})
                    analytics.settle_apply_projection(terraform, resources, stage, root, report["assertion_failures"], "update-projection")
                    stage("revision-2-password-consumer", password_probe(endpoint, out, probe_name, password, 2))
                    workflow = verify_workflow(endpoint, out, 2)
                    stage("revision-2-native-workflow", workflow)
                    stage("revision-2-native-postgres", verify_postgres(endpoint, out, 2, sql, port, password, root))
                    latest = verify_schema_records(endpoint, out, 2, earlier)
                    stage("revision-2-schema-native-record", latest["evidence"])
                    stage("revision-2-resource-policy", verify_policy(endpoint, out, output("reader"), 2))
                    no_changes("update-refresh", refresh=True)
                    no_changes("update-no-op")
                    controllers.close()
                    shutil.copyfile(root / "stackd.log", root / "stackd-before-reopen.log")
                    endpoint = controllers.enter_context(controller(args, root, extra=extra, containers=True))
                    glue = client("glue", endpoint)
                    require(output("catalog") == out, "Controller reopen changed Terraform output identity")
                    marker = json.loads(analytics.s3_bytes(client("s3", endpoint), out["bucket"],
                                        "job-results/revision-2.json"))
                    require(marker == workflow["udf"], "Controller reopen changed retained native Spark marker bytes")
                    retained_workflow = glue.get_workflow_run(Name=out["workflow"],
                                                             RunId=workflow["run_id"], IncludeGraph=True)["Run"]
                    require(retained_workflow["Status"] == "COMPLETED" and
                            retained_workflow["Statistics"] == workflow["statistics"],
                            "Controller reopen changed completed native workflow state")
                    native_record = analytics.verify_retained_record(endpoint, out["stream_name"],
                        latest["evidence"]["shard_id"], latest["evidence"]["sequence_number"],
                        latest["evidence"]["sha256"])
                    stage("reopen-retained-native", {"record": native_record, "workflow_run_id": workflow["run_id"],
                                                    "spark_marker_unchanged": True})
                    stage("reopen-password-consumer", password_probe(endpoint, out, probe_name, password, 2))
                    stage("reopen-native-workflow", verify_workflow(endpoint, out, 2))
                    stage("reopen-native-postgres", verify_postgres(endpoint, out, 2, sql, port, password, root))
                    stage("reopen-schema-native-record", verify_schema_records(endpoint, out, 2, earlier)["evidence"])
                    stage("reopen-resource-policy", verify_policy(endpoint, out, output("reader"), 2))
                    no_changes("reopen-refresh", refresh=True)
                    no_changes("reopen-no-op")
                finally:
                    try:
                        if out is not None:
                            stop_active_work(endpoint, out)
                    finally:
                        try:
                            if probe_name is not None:
                                try:
                                    glue.delete_connection(CatalogId=ACCOUNT, ConnectionName=probe_name)
                                except ClientError as error:
                                    require(error.response["Error"]["Code"] == "EntityNotFoundException",
                                            f"Owned password-probe cleanup failed: {error}")
                        finally:
                            try:
                                try:
                                    commitment = client("kinesis", endpoint).describe_account_settings()["MinimumThroughputBillingCommitment"]
                                    if commitment["Status"] == "ENABLED":
                                        # This provider has no Delete. Even a failed
                                        # revision-1 run must request its real deferred
                                        # disable before ordinary state teardown.
                                        terraform("apply", "-input=false", "-auto-approve",
                                                  "-target=aws_kinesis_account_settings.capacity", "-var=revision=2")
                                finally:
                                    terraform("destroy", "-input=false", "-auto-approve", "-parallelism=2")
                            finally:
                                glue.delete_catalog(CatalogId=catalog_id)
                require(out is not None, "Apply did not produce catalog outputs")
                require(not [resource for resource in resources() if resource["mode"] == "managed"],
                        "Terraform retained managed resources after destroy")
                expect_missing(glue.get_database, {"EntityNotFoundException"}, CatalogId=ACCOUNT, Name=out["database"])
                expect_missing(glue.get_connection, {"EntityNotFoundException"}, CatalogId=ACCOUNT, Name=out["connection"])
                expect_missing(glue.get_classifier, {"EntityNotFoundException"}, Name=out["classifier"])
                expect_missing(glue.get_workflow, {"EntityNotFoundException"}, Name=out["workflow"])
                expect_missing(glue.get_job, {"EntityNotFoundException"}, JobName=out["job"])
                for crawler in (out["s3_crawler"], out["jdbc_crawler"]):
                    expect_missing(glue.get_crawler, {"EntityNotFoundException"}, Name=crawler)
                expect_missing(glue.get_user_defined_function, {"EntityNotFoundException"},
                               CatalogId=ACCOUNT, DatabaseName=out["database"], FunctionName=out["udf"])
                expect_missing(glue.get_security_configuration, {"EntityNotFoundException"}, Name=out["security"])
                expect_missing(glue.get_schema, {"EntityNotFoundException"}, SchemaId={"SchemaArn": out["schema_arn"]})
                expect_missing(glue.get_registry, {"EntityNotFoundException"}, RegistryId={"RegistryArn": out["registry_arn"]})
                expect_missing(glue.get_resource_policy, {"EntityNotFoundException"})
                expect_missing(glue.get_catalog, {"EntityNotFoundException"}, CatalogId=catalog_id)
                expect_missing(client("kinesis", endpoint).describe_stream_summary,
                               {"ResourceNotFoundException"}, StreamName=out["stream_name"])
                expect_missing(client("athena", endpoint).get_work_group, {"InvalidRequestException"},
                               WorkGroup=out["workgroup"])
                expect_missing(client("s3", endpoint).head_bucket, {"404", "NoSuchBucket", "NotFound"},
                               Bucket=out["bucket"])
                key = client("kms", endpoint).describe_key(KeyId=out["key_arn"])["KeyMetadata"]
                require(key["KeyState"] == "PendingDeletion" and key.get("DeletionDate"),
                        "Ordinary destroy did not schedule real KMS key deletion")
                settings = glue.get_data_catalog_encryption_settings(CatalogId=ACCOUNT)["DataCatalogEncryptionSettings"]["ConnectionPasswordEncryption"]
                require(settings["ReturnConnectionPasswordEncrypted"] is False and not settings.get("AwsKmsKeyId"),
                        "Destroy left active or stale connection encryption settings")
                # The actual pinned provider intentionally implements no Delete
                # for account settings. Early disable retains its 24-hour deadline.
                commitment = client("kinesis", endpoint).describe_account_settings()["MinimumThroughputBillingCommitment"]
                require(commitment["Status"] == "ENABLED_UNTIL_EARLIEST_ALLOWED_END", "Destroy invented a removed billing commitment")
                stage("destroy", {"signed_api_absence": True, "managed_state_empty": True,
                                  "password_settings_reset": True, "provider_noop_delete_commitment": commitment["Status"],
                                  "kms_deletion_scheduled": True})
        stage("controller-stopped-and-native-postgres-removed")
        require(not report["assertion_failures"],
                "Strict refresh assertions failed; inspect retained assertion_failures and plan JSON")
        report["status"] = "passed"
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = str(error)
        raise
    finally:
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Catalog lifecycles and required real consumers complete. Retained private artifacts: {root}")


if __name__ == "__main__":
    main()
