"""Exercise pinned Terraform analytics lifecycles and real Trino/Kafka/S3 consumers.

Run after building stackd and installing the images in docs/runtime-containers.md:
  python3 examples/terraform-analytics/run.py --port 14705
Add --provider-mirror PATH for an offline signed provider mirror.
Add --glue-job only after accepting the retained Glue license and installing both
Glue images. Missing images or failed consumers are errors, never skipped cases.
The owned report records only completed stages. It is not all-resource parity.
"""

import contextlib
import csv
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from urllib.parse import urlsplit
import uuid

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local import (ACCOUNT, arguments, client, controller, environment,
                   expect_missing, require, workspace)

IMAGES = (
    "trinodb/trino@sha256:00125e40d063bc4816d165482f6044872b18b56026fb959d3b28ce1f96ffbbee",
    "apache/spark@sha256:9b0a6c2c860f5e7d18dd5270286fef32a09c7f5a7e2b0dbe5642de8a3a02ab3e",
    "apache/kafka@sha256:ed74d7d115968d5e8b00ba6822ac6a384cbaaf54ca38991828647000d7089b68",
)
GLUE_IMAGES = (
    "public.ecr.aws/glue/aws-glue-libs@sha256:a54bd25fb72c55a2f28d07656a3cda943a042f345cc25f4c2c170667be864f01",
    "public.ecr.aws/lambda/python@sha256:6aa6ba1ae1662df3e7400a25d3293bc464c3a907da13370eec7637128c8eb0a3",
)
# This pinned provider has no Importer on aws_kinesis_stream_consumer. Athena
# database imports cannot recover bucket/workgroup, which are Terraform-only
# query submission settings. Neither limitation is hidden with ignore_changes.
IMPORT_TYPES = {
    "aws_athena_data_catalog", "aws_athena_named_query", "aws_athena_prepared_statement",
    "aws_athena_workgroup", "aws_glue_catalog_database", "aws_glue_catalog_table",
    "aws_glue_partition", "aws_kinesis_stream", "aws_kinesis_resource_policy",
    "aws_kinesis_firehose_delivery_stream", "aws_glue_job",
}


def await_value(read, ready, label, timeout=240):
    deadline = time.monotonic() + timeout
    while True:
        value = read()
        if ready(value):
            return value
        require(time.monotonic() < deadline, f"Timed out waiting for {label}: {value}")
        time.sleep(0.25)


def s3_bytes(s3, bucket, key):
    stream = s3.get_object(Bucket=bucket, Key=key)["Body"]
    try:
        return stream.read()
    finally:
        stream.close()


def location_bytes(s3, bucket, location):
    parsed = urlsplit(location)
    require(parsed.scheme == "s3" and parsed.netloc == bucket and parsed.path.startswith("/"),
            f"Query returned a location outside the owned bucket: {location}")
    return s3_bytes(s3, bucket, parsed.path[1:])


def query(endpoint, outputs, sql, database=None, expected_state="SUCCEEDED"):
    producer = client("athena", endpoint)
    query_id = producer.start_query_execution(
        QueryString=sql, WorkGroup=outputs["workgroup"], ClientRequestToken=uuid.uuid4().hex,
        QueryExecutionContext={"Database": database or outputs["database"], "Catalog": outputs["catalog"]})["QueryExecutionId"]
    reader = client("athena", endpoint)
    execution = await_value(
        lambda: reader.get_query_execution(QueryExecutionId=query_id)["QueryExecution"],
        lambda value: value["Status"]["State"] in {"SUCCEEDED", "FAILED", "CANCELLED"},
        f"actual SQL {query_id}")
    require(execution["Status"]["State"] == expected_state,
            f"Native SQL state differs from {expected_state}: {execution['Status']}")
    return query_id, execution


def result_rows(endpoint, query_id, kind="DATA_ROWS"):
    reader = client("athena", endpoint)
    rows = []
    for page in reader.get_paginator("get_query_results").paginate(
            QueryExecutionId=query_id, QueryResultType=kind, PaginationConfig={"PageSize": 1}):
        rows.extend([[cell.get("VarCharValue") for cell in row["Data"]]
                     for row in page["ResultSet"]["Rows"]])
    return rows


def verify_select(endpoint, outputs, sql, expected, database=None):
    query_id, execution = query(endpoint, outputs, sql, database)
    rows = result_rows(endpoint, query_id)
    require(rows == expected, f"Actual SQL rows differ: {rows}; expected {expected}")
    data = location_bytes(client("s3", endpoint), outputs["bucket"],
                          execution["ResultConfiguration"]["OutputLocation"])
    require(list(csv.reader(io.StringIO(data.decode()))) == expected,
            "Independent S3 consumer differs from paginated Athena rows")
    return {"query_id": query_id, "rows": rows, "s3_sha256": hashlib.sha256(data).hexdigest(),
            "scanned_bytes": execution["Statistics"]["DataScannedInBytes"]}


def verify_manifest(endpoint, outputs, query_id, execution, count):
    location = execution["Statistics"].get("DataManifestLocation")
    require(location, "Real writer did not publish a manifest")
    s3 = client("s3", endpoint)
    manifest = location_bytes(s3, outputs["bucket"], location)
    paths = manifest.decode().splitlines()
    require(paths and result_rows(endpoint, query_id, "DATA_MANIFEST") == [[path] for path in paths],
            "Paginated manifest API differs from independently read S3 manifest")
    require(client("athena", endpoint).get_query_results(QueryExecutionId=query_id).get("UpdateCount") == count,
            "Native writer returned a wrong update count")
    objects = []
    for path in paths:
        data = location_bytes(s3, outputs["bucket"], path)
        require(data.startswith(b"PAR1") and data.endswith(b"PAR1"), "Native writer did not write actual Parquet")
        objects.append({"location": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return {"query_id": query_id, "manifest_location": location, "update_count": count, "objects": objects}


def verify_lake(endpoint, outputs, revision):
    s3 = client("s3", endpoint)
    for region, rows in {"east": [{"label": "north", "amount": 4}, {"label": "north", "amount": 6}],
                         "west": [{"label": "south", "amount": 14}]}.items():
        s3.put_object(Bucket=outputs["bucket"], Key=f"input/region={region}/numbers.json",
                      Body=b"".join(json.dumps(row).encode() + b"\n" for row in rows))
    glue = client("glue", endpoint)
    table = glue.get_table(CatalogId=ACCOUNT, DatabaseName=outputs["database"], Name="numbers")["Table"]
    require(table["Description"].endswith(str(revision)), "Glue table update did not persist")
    partitions = glue.get_partitions(CatalogId=ACCOUNT, DatabaseName=outputs["database"], TableName="numbers")["Partitions"]
    require({tuple(partition["Values"]) for partition in partitions} == {("east",), ("west",)},
            "Terraform did not create both actual Glue partitions")
    require(all(partition["Parameters"]["revision"] == str(revision) for partition in partitions),
            "Glue partition updates did not persist")
    delta = revision - 1
    selected = verify_select(endpoint, outputs, outputs["named_query_sql"],
                             [["label", "total", "region"], ["north", str(10 + delta), "east"], ["south", str(14 + delta), "west"]])
    require(selected["scanned_bytes"] > 0, "SELECT did not scan actual input bytes")
    prepared = verify_select(endpoint, outputs, f"EXECUTE {outputs['prepared_name']} USING 'east'",
                             [["total"], [str(10 + delta)]])
    name = f"written_totals_{revision}"
    database = outputs["written_database"]
    write_root = f"s3://{outputs['bucket']}/written/revision-{revision}/"
    created_id, created = query(endpoint, outputs,
        f"CREATE TABLE {name} WITH (format = 'PARQUET', external_location = '{write_root}', "
        f"partitioned_by = ARRAY['region']) AS SELECT label, sum(amount) AS total, region "
        f"FROM {outputs['database']}.numbers GROUP BY label, region", database)
    ctas = verify_manifest(endpoint, outputs, created_id, created, 2)
    require(any("region=east/" in obj["location"] for obj in ctas["objects"]) and
            any("region=west/" in obj["location"] for obj in ctas["objects"]),
            "CTAS did not produce real partitioned objects")
    inserted_id, inserted = query(endpoint, outputs, f"INSERT INTO {name} VALUES ('bonus', BIGINT '3', 'east')", database)
    insert = verify_manifest(endpoint, outputs, inserted_id, inserted, 1)
    written = verify_select(endpoint, outputs, f"SELECT label, total, region FROM {name} ORDER BY label, region",
                            [["label", "total", "region"], ["bonus", "3", "east"], ["north", "10", "east"], ["south", "14", "west"]], database)
    return {"saved_query": selected, "prepared_query": prepared, "ctas": ctas, "insert": insert, "written_select": written}


def verify_delivery(endpoint, outputs, revision):
    producer = client("kinesis", endpoint)
    payload = (f"kinesis-native-revision-{revision}:" + uuid.uuid4().hex).encode() + b"\n"
    sent = producer.put_record(StreamName=outputs["stream_name"], PartitionKey="owned", Data=payload)
    reader = client("kinesis", endpoint)
    iterator = reader.get_shard_iterator(StreamName=outputs["stream_name"], ShardId=sent["ShardId"],
        ShardIteratorType="AT_SEQUENCE_NUMBER", StartingSequenceNumber=sent["SequenceNumber"])["ShardIterator"]
    def read_records():
        nonlocal iterator
        page = reader.get_records(ShardIterator=iterator, Limit=1)
        iterator = page["NextShardIterator"]
        return page["Records"]
    records = await_value(read_records, bool, "real native Kinesis record")
    require(records[0]["Data"] == payload and records[0]["SequenceNumber"] == sent["SequenceNumber"]
            and records[0]["PartitionKey"] == "owned", "Standard consumer changed native record identity/bytes")
    events = client("kinesis", endpoint).subscribe_to_shard(ConsumerARN=outputs["consumer_arn"],
        ShardId=sent["ShardId"], StartingPosition={"Type": "AT_SEQUENCE_NUMBER", "SequenceNumber": sent["SequenceNumber"]})["EventStream"]
    matched = False
    deadline = time.monotonic() + 240
    try:
        for event in events:
            require(time.monotonic() < deadline, "Enhanced consumer did not deliver the admitted record before its deadline")
            for record in event.get("SubscribeToShardEvent", {}).get("Records", []):
                if record["SequenceNumber"] == sent["SequenceNumber"]:
                    require(record["Data"] == payload, "Enhanced consumer changed record bytes")
                    matched = True
                    break
            if matched:
                break
            require("SubscribeToShardEvent" in event, f"Enhanced consumer failed: {event}")
    finally:
        events.close()
    require(matched, "Enhanced consumer did not receive the actual native record")
    direct = (f"firehose-direct-revision-{revision}:" + uuid.uuid4().hex).encode() + b"\n"
    direct_sent = client("firehose", endpoint).put_record(DeliveryStreamName=outputs["direct_name"], Record={"Data": direct})
    require(direct_sent["RecordId"], "Firehose did not admit the direct record")
    s3 = client("s3", endpoint)
    def find_delivery(prefix, body):
        def read():
            matches = []
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=outputs["bucket"], Prefix=prefix):
                for obj in page.get("Contents", []):
                    raw = s3_bytes(s3, outputs["bucket"], obj["Key"])
                    data = gzip.decompress(raw) if revision == 2 else raw
                    if body in data:
                        matches.append({"key": obj["Key"], "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
            return matches
        return await_value(read, bool, f"real S3 delivery at {prefix}")
    source_objects = find_delivery(f"source/revision-{revision}/", payload)
    direct_objects = find_delivery(f"direct/revision-{revision}/", direct)
    summary = reader.describe_stream_summary(StreamName=outputs["stream_name"])["StreamDescriptionSummary"]
    require(summary["OpenShardCount"] == revision and summary["RetentionPeriodHours"] == (24 if revision == 1 else 48)
            and summary["MaxRecordSizeInKiB"] == (1024 if revision == 1 else 2048),
            "Terraform stream capacity/retention/record-size update did not persist")
    tags = {tag["Key"]: tag["Value"] for tag in reader.list_tags_for_resource(ResourceARN=outputs["consumer_arn"])["Tags"]}
    require(tags["Revision"] == str(revision), "Terraform consumer tag update did not persist")
    return {"shard_id": sent["ShardId"], "sequence_number": sent["SequenceNumber"],
            "record_sha256": hashlib.sha256(payload).hexdigest(), "enhanced_fanout": True,
            "source_objects": source_objects, "direct_objects": direct_objects}


def verify_glue_job(endpoint, outputs, job, revision):
    producer = client("glue", endpoint)
    run_id = producer.start_job_run(JobName=job)["JobRunId"]
    run = await_value(lambda: client("glue", endpoint).get_job_run(JobName=job, RunId=run_id)["JobRun"],
                      lambda value: value["JobRunState"] in {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"},
                      "real Glue Python-shell process")
    require(run["JobRunState"] == "SUCCEEDED", f"Native Glue job failed: {run}")
    data = s3_bytes(client("s3", endpoint), outputs["bucket"], f"glue/revision-{revision}.json")
    require(json.loads(data) == {"producer": "real-glue-python-shell", "revision": revision},
            "Independent S3 consumer differs from the native Glue producer")
    return {"job": job, "run_id": run_id, "state": run["JobRunState"], "output_sha256": hashlib.sha256(data).hexdigest()}


def run_terraform(root, env, report, *command, capture=False, check=True):
    print("terraform", *command, flush=True)
    result = subprocess.run(["terraform", *command], cwd=root, env=env,
                            text=True, capture_output=True)
    commands = report.setdefault("terraform_commands", [])
    log = root / f"terraform-{len(commands) + 1:03d}.log"
    log.write_text(result.stdout + result.stderr)
    commands.append({"command": list(command), "exit": result.returncode, "log": str(log)})
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if not capture:
        print(result.stdout, end="", flush=True)
        print(result.stderr, end="", file=sys.stderr, flush=True)
    if check:
        result.check_returncode()
    return result


def retain_core_refresh_failure(terraform, root, label, plan_file, planned, failures):
    """Retain a strict core failure only when no semantic change is present."""
    require(planned.returncode == 2, f"{label} refresh failed: exit {planned.returncode}")
    projection = json.loads(terraform("show", "-json", plan_file, capture=True).stdout)
    require(not projection.get("resource_drift") and not projection.get("resource_changes") and
            all(change["actions"] == ["no-op"] for change in projection.get("output_changes", {}).values()),
            f"{label} refresh included real resource or output drift")
    evidence = root / (plan_file + ".json")
    evidence.write_text(json.dumps(projection, indent=2) + "\n")
    failure = {"stage": label, "error": f"{label} was not a no-op: exit {planned.returncode}",
               "plan": str(root / plan_file), "json": str(evidence)}
    failures.append(failure)
    print("FAILED strict refresh assertion (run will fail after cleanup):", failure["error"], flush=True)


def check_no_changes(terraform, root, stage, failures, label, refresh=False):
    plan_file = label + ".tfplan"
    planned = terraform("plan", *(["-refresh-only"] if refresh else []), "-input=false",
                        "-detailed-exitcode", "-out=" + plan_file, check=False)
    if refresh and planned.returncode == 2:
        retain_core_refresh_failure(terraform, root, label, plan_file, planned, failures)
        return
    require(planned.returncode == 0, f"{label} was not a no-op: exit {planned.returncode}")
    stage(label)


def verify_retained_record(endpoint, stream, shard, sequence, digest):
    reader = client("kinesis", endpoint)
    iterator = reader.get_shard_iterator(StreamName=stream, ShardId=shard,
        ShardIteratorType="AT_SEQUENCE_NUMBER", StartingSequenceNumber=sequence)["ShardIterator"]
    def read():
        nonlocal iterator
        page = reader.get_records(ShardIterator=iterator, Limit=1)
        iterator = page["NextShardIterator"]
        return page["Records"]
    records = await_value(read, bool, "retained native record after controller reopen")
    require(records[0]["SequenceNumber"] == sequence and
            hashlib.sha256(records[0]["Data"]).hexdigest() == digest,
            "Controller reopen changed retained native record identity or bytes")
    return {"sequence_number": sequence, "sha256": digest, "retained_native_bytes": True}


def verify_reopened_consumers(endpoint, outputs, previous):
    lake = previous["lake"]
    selected = verify_select(endpoint, outputs, outputs["named_query_sql"],
        [["label", "total", "region"], ["north", "11", "east"], ["south", "15", "west"]])
    prepared = verify_select(endpoint, outputs, f"EXECUTE {outputs['prepared_name']} USING 'east'",
                             [["total"], ["11"]])
    written = verify_select(endpoint, outputs,
        "SELECT label, total, region FROM written_totals_2 ORDER BY label, region",
        [["label", "total", "region"], ["bonus", "3", "east"], ["north", "10", "east"], ["south", "14", "west"]],
        outputs["written_database"])
    retained_manifests = {}
    for name, count in (("ctas", 2), ("insert", 1)):
        original = lake[name]
        execution = client("athena", endpoint).get_query_execution(
            QueryExecutionId=original["query_id"])["QueryExecution"]
        retained = verify_manifest(endpoint, outputs, original["query_id"], execution, count)
        require(retained == original, f"Controller reopen changed retained native {name} manifest or Parquet bytes")
        retained_manifests[name] = retained
    delivery = previous["delivery"]
    retained_record = verify_retained_record(endpoint, outputs["stream_name"], delivery["shard_id"],
                                             delivery["sequence_number"], delivery["record_sha256"])
    s3 = client("s3", endpoint)
    for name in ("source_objects", "direct_objects"):
        for obj in delivery[name]:
            data = s3_bytes(s3, outputs["bucket"], obj["key"])
            require(len(data) == obj["bytes"] and hashlib.sha256(data).hexdigest() == obj["sha256"],
                    "Controller reopen changed retained Firehose S3 bytes")
    return {"saved_query": selected, "prepared_query": prepared, "written_select": written,
            "retained_manifests": retained_manifests, "retained_record": retained_record,
            "retained_delivery_objects": True, "fresh_delivery": verify_delivery(endpoint, outputs, 2)}


def settle_apply_projection(terraform, resources, stage, root, failures, label):
    """Admit only observed empty collections and exact separately managed state.

    The pinned provider can create these values as null, then read ordinary empty
    AWS collections or policy/index resources created after their parent. These
    projections cannot admit changed remote settings. All other drift is an error.
    """
    applied = resources()
    plan_file = label + ".tfplan"
    plan = terraform("plan", "-refresh-only", "-input=false", "-detailed-exitcode",
                     "-out=" + plan_file, check=False)
    require(plan.returncode in {0, 2}, f"{label} refresh failed: exit {plan.returncode}")
    if plan.returncode == 0:
        stage(label, [])
        return
    projection = json.loads(terraform("show", "-json", plan_file, capture=True).stdout)
    policies = {}
    indexes = {}
    for resource in applied:
        if resource["mode"] == "managed" and resource["type"] == "aws_iam_role_policy":
            values = resource["values"]
            policies.setdefault(values["role"], []).append(
                {"name": values["name"], "policy": json.loads(values["policy"])})
        elif resource["mode"] == "managed" and resource["type"] == "aws_glue_partition_index":
            values = resource["values"]
            identity = (values["catalog_id"], values["database_name"], values["table_name"])
            indexes.setdefault(identity, []).extend(values["partition_index"])
    def differences(before, after, path=()):
        if before == after:
            return []
        if isinstance(before, dict) and isinstance(after, dict):
            return [difference for key in sorted(before.keys() | after.keys())
                    for difference in differences(before.get(key), after.get(key), (*path, key))]
        if isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
            return [difference for index, (old, new) in enumerate(zip(before, after))
                    for difference in differences(old, new, (*path, index))]
        return [(path, before, after)]
    empty_paths = {
        "aws_athena_database": {("properties",)},
        "aws_glue_catalog_database": {("parameters",)},
        "aws_glue_catalog_table": {("partition_keys", "*", "parameters")},
        "aws_glue_classifier": {("csv_classifier", "*", "custom_datatypes")},
        "aws_glue_connection": {("athena_properties",), ("match_criteria",)},
        "aws_glue_crawler": {("classifiers",), ("jdbc_target", "*", "enable_additional_metadata"),
                             ("s3_target", "*", "exclusions")},
        "aws_glue_job": {("connections",), ("non_overridable_arguments",)},
        "aws_glue_partition": {
            ("storage_descriptor", "*", "additional_locations"),
            ("storage_descriptor", "*", "bucket_columns"),
            ("storage_descriptor", "*", "parameters"),
            ("storage_descriptor", "*", "ser_de_info", "*", "parameters"),
        },
        "aws_glue_trigger": {("actions", "*", "arguments")},
        "aws_kinesis_stream": {("shard_level_metrics",)},
        "aws_s3_object": {("metadata",), ("tags",)},
    }
    evidence = []
    drift = projection.get("resource_drift", [])
    if not drift:
        retain_core_refresh_failure(terraform, root, label, plan_file, plan, failures)
        return
    for resource in drift:
        change = resource["change"]
        require(resource["mode"] == "managed" and change["actions"] == ["update"],
                f"Unexpected {label} refresh action: {resource['address']}: {change['actions']}")
        for path, before, after in differences(change["before"], change["after"]):
            normalized = tuple("*" if isinstance(part, int) else part for part in path)
            kind = "null-to-empty"
            if resource["type"] == "aws_iam_role" and path == ("inline_policy",):
                require(before is None or before == [], f"{label} refresh replaced existing inline policies")
                expected = sorted(policies.get(change["before"]["name"], []), key=lambda policy: policy["name"])
                actual = sorted([{"name": policy["name"], "policy": json.loads(policy["policy"])}
                                 for policy in after], key=lambda policy: policy["name"])
                require(expected and actual == expected,
                        f"{label} refresh imported unknown or changed role policies: {resource['address']}")
                kind = "known-inline-policies"
            elif resource["type"] == "aws_glue_catalog_table" and path == ("partition_index",):
                require(before is None or before == [], f"{label} refresh replaced existing partition indexes")
                values = change["before"]
                identity = (values["catalog_id"], values["database_name"], values["name"])
                expected = sorted(indexes.get(identity, []), key=lambda index: index["index_name"])
                require(expected and sorted(after, key=lambda index: index["index_name"]) == expected,
                        f"{label} refresh imported unknown or changed table indexes: {resource['address']}")
                kind = "known-partition-indexes"
            else:
                require(normalized in empty_paths.get(resource["type"], set()) and
                        before is None and (after == {} or after == []),
                        f"Unexpected {label} refresh difference: {resource['address']} {path}: {before!r} -> {after!r}")
            evidence.append({"address": resource["address"], "path": list(path), "projection": kind})
    for name, change in projection.get("output_changes", {}).items():
        require(change["before"] == change["after"], f"Unexpected output change during {label}: {name}")
    # Apply only this already inspected refresh-only plan. This cannot call an
    # Update API or accept an arbitrary new plan. Subsequent stages remain strict.
    terraform("apply", "-input=false", "-auto-approve", plan_file)
    stage(label, evidence)


def verify_drop_database(endpoint, outputs):
    """Exercise the native Spark AST and real Glue/S3 drop semantics end to end."""
    glue = client("glue", endpoint)
    s3 = client("s3", endpoint)
    name = "drop_semantics_" + uuid.uuid4().hex[:12]
    key = "input/region=east/numbers.json"
    retained = s3_bytes(s3, outputs["bucket"], key)
    created_id, _ = query(endpoint, outputs, f"CREATE DATABASE {name}")
    try:
        source = glue.get_table(CatalogId=ACCOUNT, DatabaseName=outputs["database"], Name="numbers")["Table"]
        descriptor = dict(source["StorageDescriptor"])
        descriptor["Location"] = f"s3://{outputs['bucket']}/input/region=east/"
        glue.create_table(CatalogId=ACCOUNT, DatabaseName=name, TableInput={
            "Name": "kept", "TableType": "EXTERNAL_TABLE", "StorageDescriptor": descriptor,
            "Parameters": source.get("Parameters", {}), "PartitionKeys": []})
        selected = verify_select(endpoint, outputs, "SELECT sum(amount) AS total FROM kept",
                                 [["total"], ["10"]], database=name)
        rejected_id, rejected = query(endpoint, outputs, f"DROP DATABASE {name} RESTRICT",
                                      expected_state="FAILED")
        require("not empty" in rejected["Status"].get("StateChangeReason", "").lower(),
                f"RESTRICT failed for the wrong reason: {rejected['Status']}")
        glue.get_database(CatalogId=ACCOUNT, Name=name)
        glue.get_table(CatalogId=ACCOUNT, DatabaseName=name, Name="kept")
        require(s3_bytes(s3, outputs["bucket"], key) == retained, "RESTRICT changed actual data bytes")
        dropped_id, _ = query(endpoint, outputs, f"DROP DATABASE {name} CASCADE")
        expect_missing(glue.get_database, {"EntityNotFoundException"}, CatalogId=ACCOUNT, Name=name)
        expect_missing(glue.get_table, {"EntityNotFoundException"}, CatalogId=ACCOUNT, DatabaseName=name, Name="kept")
        missing_id, _ = query(endpoint, outputs, f"DROP SCHEMA IF EXISTS {name} CASCADE")
        require(s3_bytes(s3, outputs["bucket"], key) == retained, "Metadata CASCADE deleted actual S3 data")
        return {"create_query": created_id, "actual_select": selected, "restrict_query": rejected_id,
                "cascade_query": dropped_id, "missing_if_exists_query": missing_id,
                "metadata_absent": True, "retained_data_sha256": hashlib.sha256(retained).hexdigest()}
    finally:
        # SDK cleanup remains possible if the native regression itself fails.
        try:
            glue.delete_database(CatalogId=ACCOUNT, Name=name)
        except ClientError as error:
            if error.response["Error"]["Code"] != "EntityNotFoundException":
                raise


def main():
    parser = arguments(__doc__, 14705)
    parser.add_argument("--provider-mirror", type=Path)
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    parser.add_argument("--glue-job", action="store_true", help="Run actual Python shell; requires both installed Glue images and license acceptance")
    args = parser.parse_args()
    require(shutil.which("terraform") and shutil.which("docker"), "Install Terraform and Docker first")
    root = workspace(args, "terraform-analytics")
    root.chmod(0o700)
    source = Path(__file__).resolve().parent
    shutil.copyfile(source / "main.tf", root / "main.tf")
    if args.glue_job:
        shutil.copyfile(source / "glue_job.tf", root / "glue_job.tf")
    env = environment()
    configuration = "disable_checkpoint = true\n"
    if args.provider_mirror is not None:
        require(args.provider_mirror.is_dir(), "Provider mirror directory does not exist")
        configuration += ("provider_installation {\n  filesystem_mirror {\n    path = "
                          + json.dumps(str(args.provider_mirror.resolve()))
                          + '\n    include = ["registry.terraform.io/hashicorp/aws"]\n  }\n}\n')
    (root / "terraform.rc").write_text(configuration)
    env["TF_CLI_CONFIG_FILE"] = str(root / "terraform.rc")
    for image in IMAGES + (GLUE_IMAGES if args.glue_job else ()):
        subprocess.run(["docker", "--host", args.docker_host, "image", "inspect", image],
                       check=True, stdout=subprocess.DEVNULL, env=env)
    report = {"provider_version": "6.68.0", "fixture": "terraform-analytics", "stages": [],
              "unexercised": json.loads((source / "coverage.json").read_text()), "status": "running",
              "assertion_failures": []}
    def terraform(*command, capture=False, check=True):
        return run_terraform(root, env, report, *command, capture=capture, check=check)
    report["terraform_version"] = json.loads(terraform("version", "-json", capture=True).stdout)["terraform_version"]
    def stage(label, evidence=None):
        report["stages"].append({"stage": label, "evidence": evidence})
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print("Completed:", label, flush=True)
    def output():
        return json.loads(terraform("output", "-json", "analytics", capture=True).stdout)
    def resources():
        return json.loads(terraform("show", "-json", capture=True).stdout).get("values", {}).get("root_module", {}).get("resources", [])
    def no_changes(label, refresh=False):
        check_no_changes(terraform, root, stage, report["assertion_failures"], label, refresh)
    extra = ["-docker-host", args.docker_host, "-athena-runtime", "-kinesis-runtime"]
    if args.glue_job:
        extra += ["-glue-runtime"]
    outputs = None
    try:
        with contextlib.ExitStack() as controllers:
            endpoint = controllers.enter_context(controller(args, root, extra=extra, containers=True))
            variables = {"endpoint": endpoint, "name": "tf-analytics-" + uuid.uuid4().hex[:12],
                         "account_id": ACCOUNT, "revision": 1}
            (root / "local.auto.tfvars.json").write_text(json.dumps(variables))
            terraform("init", "-input=false")
            try:
                terraform("apply", "-input=false", "-auto-approve", "-parallelism=2")
                outputs = output()
                stage("create", {"resources": [resource["address"] for resource in resources() if resource["mode"] == "managed"]})
                stage("revision-1-consumers", {"lake": verify_lake(endpoint, outputs, 1), "delivery": verify_delivery(endpoint, outputs, 1)})
                if args.glue_job:
                    job = json.loads(terraform("output", "-json", "glue_job", capture=True).stdout)
                    stage("revision-1-native-glue", verify_glue_job(endpoint, outputs, job, 1))
                stage("native-drop-database", verify_drop_database(endpoint, outputs))
                settle_apply_projection(terraform, resources, stage, root, report["assertion_failures"], "create-projection")
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
                        # Restore this owned state only so finally can destroy every
                        # admitted resource. The failed import remains a hard failure.
                        terraform("state", "push", "-force", str(snapshot))
                        raise
                    imported.append(address)
                stage("import", imported)
                # Import can reset provider-only force_destroy. Reconcile these
                # documented local settings before requiring convergence again.
                terraform("apply", "-input=false", "-auto-approve", "-parallelism=2")
                no_changes("import-refresh", refresh=True)
                no_changes("import-no-op")
                variables["revision"] = 2
                (root / "local.auto.tfvars.json").write_text(json.dumps(variables))
                terraform("apply", "-input=false", "-auto-approve", "-parallelism=2")
                updated = output()
                require(updated["stream_arn"] == outputs["stream_arn"] and updated["consumer_arn"] == outputs["consumer_arn"]
                        and updated["direct_arn"] == outputs["direct_arn"] and updated["source_arn"] == outputs["source_arn"],
                        "Update replaced a mutable stream or consumer")
                require(updated["named_query_id"] != outputs["named_query_id"], "Provider ForceNew named-query update did not replace identity")
                outputs = updated
                stage("update", {"revision": 2})
                stage("revision-2-consumers", {"lake": verify_lake(endpoint, outputs, 2), "delivery": verify_delivery(endpoint, outputs, 2)})
                if args.glue_job:
                    stage("revision-2-native-glue", verify_glue_job(endpoint, outputs, job, 2))
                no_changes("update-refresh", refresh=True)
                no_changes("update-no-op")
                previous = next(item["evidence"] for item in report["stages"]
                                if item["stage"] == "revision-2-consumers")
                controllers.close()
                shutil.copyfile(root / "stackd.log", root / "stackd-before-reopen.log")
                endpoint = controllers.enter_context(controller(args, root, extra=extra, containers=True))
                require(output() == outputs, "Controller reopen changed Terraform output identity")
                stage("reopen-consumers", verify_reopened_consumers(endpoint, outputs, previous))
                if args.glue_job:
                    stage("reopen-native-glue", verify_glue_job(endpoint, outputs, job, 2))
                no_changes("reopen-refresh", refresh=True)
                no_changes("reopen-no-op")
            finally:
                terraform("destroy", "-input=false", "-auto-approve", "-parallelism=2")
            require(not [resource for resource in resources() if resource["mode"] == "managed"],
                    "Terraform retained managed resources after destroy")
            require(outputs is not None, "Apply did not produce analytics outputs")
            expect_missing(client("glue", endpoint).get_database, {"EntityNotFoundException"}, Name=outputs["database"], CatalogId=ACCOUNT)
            expect_missing(client("athena", endpoint).get_database, {"MetadataException", "InvalidRequestException"}, CatalogName="AwsDataCatalog", DatabaseName=outputs["written_database"])
            expect_missing(client("athena", endpoint).get_work_group, {"InvalidRequestException"}, WorkGroup=outputs["workgroup"])
            expect_missing(client("kinesis", endpoint).describe_stream_summary, {"ResourceNotFoundException"}, StreamName=outputs["stream_name"])
            for name in (outputs["direct_name"], outputs["source_name"]):
                expect_missing(client("firehose", endpoint).describe_delivery_stream, {"ResourceNotFoundException"}, DeliveryStreamName=name)
            expect_missing(client("s3", endpoint).head_bucket, {"404", "NoSuchBucket", "NotFound"}, Bucket=outputs["bucket"])
            stage("destroy", {"signed_api_absence": True, "managed_state_empty": True})
        for name in ("stackd-before-reopen.log", "stackd.log"):
            if (root / name).is_file():
                log = (root / name).read_text()
                require("DATA RACE" not in log and " ERROR " not in log, f"Controller logged an error; inspect {root / name}")
        stage("controller-stopped")
        require(not report["assertion_failures"],
                "Strict refresh assertions failed; inspect retained assertion_failures and plan JSON")
        report["status"] = "passed"
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = str(error)
        raise
    finally:
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Pinned analytics lifecycle and real consumers complete. Retained owned artifacts: {root}")


if __name__ == "__main__":
    main()
