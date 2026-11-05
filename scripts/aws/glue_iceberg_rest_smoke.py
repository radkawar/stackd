"""Prove the local Glue Iceberg REST catalog with real PyIceberg and Trino.

Prepare an external Python environment (no stackd dependencies are changed):
  python3 -m venv /tmp/stackd-iceberg-client
  /tmp/stackd-iceberg-client/bin/pip install 'pyiceberg[pyarrow,glue]==0.10.0'

Start stackd with its existing Athena runtime and installed native Trino image,
then run against the controller's explicit local origin:
  /tmp/stackd-iceberg-client/bin/python scripts/aws/glue_iceberg_rest_smoke.py --endpoint http://127.0.0.1:4566 --state-directory /tmp/stackd-smoke/catalog.sqlite.athena

Root SDK/catalog/FileIO calls use only the local test/test identity; the IAM
negative creates an ephemeral fixture-only reader. The fixture creates uniquely
named resources, exercises both client-to-engine directions,
prints public-safe client versions, rows and assertion witnesses, and cleans up
only its owned resources. Native Athena query failures are failures, never mocks.
The state directory must belong to this isolated controller; receipts and Docker
inspection are consumed privately, never printed. Docker CLI access and the
installed pinned Trino and Spark parser images are required.
"""
import argparse
import base64
import json
import hashlib
import io
import pathlib
import subprocess
import re
import time
import tarfile
import uuid
from urllib.parse import urlparse
from urllib.request import ProxyHandler, Request, build_opener

import boto3
import pyarrow as pa
import pyiceberg
from botocore.config import Config
from pyiceberg.catalog.rest import RestCatalog
from pyiceberg.exceptions import BadRequestError
from pyiceberg.schema import Schema
from pyiceberg.types import LongType, NestedField, StringType

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--endpoint", required=True, help="Explicit local stackd HTTP(S) origin")
parser.add_argument("--state-directory", required=True, help="Private Athena ownership directory of this isolated controller")
parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
args = parser.parse_args()
endpoint = args.endpoint.rstrip("/")
state_directory = pathlib.Path(args.state_directory)
region = "us-east-1"
session = boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name=region)
config = Config(retries={"max_attempts": 0}, connect_timeout=5, read_timeout=30, s3={"addressing_style": "path"})
s3 = session.client("s3", endpoint_url=endpoint, config=config)
glue = session.client("glue", endpoint_url=endpoint, config=config)
athena = session.client("athena", endpoint_url=endpoint, config=config)
iam = session.client("iam", endpoint_url=endpoint, config=config)
account = session.client("sts", endpoint_url=endpoint, config=config).get_caller_identity()["Account"]
suffix = uuid.uuid4().hex[:12]
bucket = "iceberg-rest-client-" + suffix
namespace = "iceberg_rest_" + suffix
workgroup = "iceberg-rest-client-" + suffix
catalog = None
created_bucket = created_namespace = created_workgroup = False
created_user = created_policy = False
access_key = None
user = "iceberg-rest-reader-" + suffix
limited_workgroup = workgroup + "-limited"
created_limited_workgroup = False
observations = {}
last_execution = None
last_witness = None
cleanup_errors = []


def owned_engine():
    receipts = list(state_directory.glob("stackd-athena-*.json"))
    assert len(receipts) == 1, "expected exactly one fixture-owned warm engine receipt"
    receipt = json.loads(receipts[0].read_text())
    inspected = subprocess.run(
        ["docker", "--host", args.docker_host, "inspect", receipt["engine"]],
        capture_output=True, text=True, check=False,
    )
    assert inspected.returncode == 0, "owned warm engine inspection failed"
    state = json.loads(inspected.stdout)[0]
    labels = state["Config"]["Labels"]
    assert state["State"]["Running"], "owned warm engine is not running"
    assert labels.get("stackd.athena.execution") == receipt["engine"], "execution ownership mismatch"
    assert labels.get("stackd.athena.owner") == receipt["owner"], "owner mismatch"
    assert labels.get("stackd.athena.engine") == "trino-476", "engine label mismatch"
    assert state["Image"] == receipt["image"], "immutable engine image mismatch"
    assert receipt["parser"].startswith(receipt["engine"] + "-"), "missing fresh query identity"
    return receipt, state


def engine_witness():
    receipt, state = owned_engine()
    return (state["Id"], receipt["owner"], receipt["parser"])


def native_query_reader():
    receipt, state = owned_engine()
    assert (state["Id"], receipt["owner"], receipt["parser"]) == last_witness, "native diagnostic ownership changed"
    if state["HostConfig"]["NetworkMode"] == "host":
        # Read only the owned engine's configuration in memory. Never publish its
        # environment, which also contains the private callback capabilities.
        encoded = next(value.split("=", 1)[1] for value in state["Config"]["Env"]
            if value.startswith("STACKD_TRINO_CONFIG="))
        with tarfile.open(fileobj=io.BytesIO(base64.b64decode(encoded))) as archive:
            member = next(member for member in archive.getmembers() if member.name.endswith("/config.properties"))
            properties = archive.extractfile(member).read().decode("utf-8")
        port = int(next(line.split("=", 1)[1] for line in properties.splitlines()
            if line.startswith("http-server.http.port=")))
    else:
        binding, = state["NetworkSettings"]["Ports"]["8080/tcp"]
        assert binding["HostIp"] == "127.0.0.1", "native diagnostics require the owned loopback endpoint"
        port = int(binding["HostPort"])
    assert 0 < port < 65536, "invalid owned native endpoint port"
    origin = "http://127.0.0.1:" + str(port)
    opener = build_opener(ProxyHandler({}))
    def read_native(path):
        request = Request(origin + path, headers={"X-Trino-User": "athena"})
        with opener.open(request, timeout=10) as response:
            return json.load(response)
    return read_native


def native_s3_denial(read_native, previous_ids, sql):
    # Correlate this one execution, not an older failure with the same SQL. The
    # native error's outer Hive message need not include its nested S3 cause.
    candidates = [item for item in read_native("/v1/query")
        if item["queryId"] not in previous_ids and item["query"] == sql and item["state"] == "FAILED"]
    assert len(candidates) == 1, "expected one new failed native scan"
    query_id = candidates[0]["queryId"]
    assert re.fullmatch(r"[A-Za-z0-9_]+", query_id), "invalid native query identity"
    native = read_native("/v1/query/" + query_id)
    assert native["queryId"] == query_id and native["query"] == sql and native["state"] == "FAILED"
    assert native["session"]["schema"] == namespace, "native failure belongs to another namespace"
    assert native["errorCode"]["name"].lower() in last_execution["Status"]["StateChangeReason"].lower()
    failure = native["failureInfo"]
    while failure:
        if failure.get("type", "").endswith(".s3.model.S3Exception") and "Status Code: 403" in failure.get("message", ""):
            assert "s3://" + bucket + "/scan/lines.txt" in native["failureInfo"]["message"], "native denial references another object"
            return {"native_query_correlated": True, "error_name": native["errorCode"]["name"],
                "cause_type": failure["type"], "http_status": 403}
        failure = failure.get("cause")
    raise AssertionError("failed native query did not contain an S3 403 cause")


def query(sql, client=None, group=None, expected_state="SUCCEEDED", reason_contains=None):
    global last_execution, last_witness
    client = client or athena
    query_id = client.start_query_execution(
        QueryString=sql, QueryExecutionContext={"Catalog": "AwsDataCatalog", "Database": namespace},
        WorkGroup=group or workgroup, ClientRequestToken=uuid.uuid4().hex,
        ResultReuseConfiguration={"ResultReuseByAgeConfiguration": {"Enabled": False}},
    )["QueryExecutionId"]
    deadline = time.monotonic() + 120
    while True:
        execution = client.get_query_execution(QueryExecutionId=query_id)["QueryExecution"]
        state = execution["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        if time.monotonic() >= deadline:
            client.stop_query_execution(QueryExecutionId=query_id)
            raise TimeoutError("Athena query did not complete")
        time.sleep(0.1)
    assert state == expected_state, "Athena " + state + ": " + execution["Status"].get("StateChangeReason", "")
    if reason_contains:
        assert reason_contains.lower() in execution["Status"].get("StateChangeReason", "").lower(), "unexpected native failure category"
    assert execution["Statistics"]["ResultReuseInformation"]["ReusedPreviousResult"] is False
    last_execution = execution
    last_witness = engine_witness()
    if state != "SUCCEEDED":
        return None
    result = client.get_query_results(QueryExecutionId=query_id)
    return [[cell.get("VarCharValue") for cell in row["Data"]] for row in result["ResultSet"]["Rows"]]


def same_engine_fresh_query(previous):
    assert last_witness[:2] == previous[:2], "query did not reuse the owned warm incarnation"
    assert last_witness[2] != previous[2], "query reused a prior query identity"


def rows(table):
    return sorted(table.scan().to_arrow().to_pylist(), key=lambda row: row["id"])


def arrow_rows(ids, labels):
    return pa.table({"id": pa.array(ids, type=pa.int64()), "label": pa.array(labels, type=pa.string())})


def shared_metadata(name, table):
    ordinary = glue.get_table(DatabaseName=namespace, Name=name)["Table"]
    assert ordinary["Parameters"]["table_type"] == "ICEBERG", ordinary
    assert ordinary["Parameters"]["metadata_location"] == table.metadata_location, ordinary
    location = urlparse(table.metadata_location)
    assert location.scheme == "s3" and location.netloc == bucket, table.metadata_location
    stored = json.loads(s3.get_object(Bucket=bucket, Key=location.path.lstrip("/"))["Body"].read())
    assert stored["table-uuid"] == str(table.metadata.table_uuid), stored
    assert stored["current-snapshot-id"] == table.metadata.current_snapshot_id, stored
    assert stored["last-sequence-number"] == table.metadata.last_sequence_number, stored
    return stored

def object_witness(location):
    parsed = urlparse(location)
    assert parsed.scheme == "s3" and parsed.netloc == bucket, "graph escaped fixture-owned bucket"
    response = s3.get_object(Bucket=bucket, Key=parsed.path.lstrip("/"))
    with response["Body"] as body:
        content = body.read()
    return {"sha256": hashlib.sha256(content).hexdigest(), "etag": response["ETag"],
        "version": response.get("VersionId")}


def iceberg_graph(table):
    # Traverse the real PyIceberg-written snapshot Avro, not a prefix listing.
    # Include deleted manifest entries and retained historical metadata: an
    # ordinary catalog drop must preserve all of them, not only live row files.
    kinds = {"metadata": {table.metadata_location}, "manifest_lists": set(),
        "manifests": set(), "data": set(), "deletes": set(), "statistics": set()}
    kinds["metadata"].update(entry.metadata_file for entry in table.metadata.metadata_log)
    for snapshot in table.metadata.snapshots:
        kinds["manifest_lists"].add(snapshot.manifest_list)
        for manifest in snapshot.manifests(table.io):
            kinds["manifests"].add(manifest.manifest_path)
            for entry in manifest.fetch_manifest_entry(table.io, discard_deleted=False):
                kind = "data" if entry.data_file.content == 0 else "deletes"
                kinds[kind].add(entry.data_file.file_path)
    metadata = json.loads(table.metadata.model_dump_json(by_alias=True))
    for field in ("statistics", "partition-statistics"):
        kinds["statistics"].update(entry["statistics-path"] for entry in metadata.get(field, []))
    assert all(kinds[kind] for kind in ("metadata", "manifest_lists", "manifests", "data")), "missing real table artifacts"
    witnesses = {location: object_witness(location) for paths in kinds.values() for location in paths}
    return witnesses, {kind: len(paths) for kind, paths in kinds.items()}


def assert_objects_unchanged(witnesses):
    for location, before in witnesses.items():
        assert object_witness(location) == before, "catalog-only operation changed a retained S3 object"



try:
    s3.create_bucket(Bucket=bucket)
    created_bucket = True
    catalog = RestCatalog("stackd", **{
        "uri": endpoint + "/iceberg", "warehouse": account,
        "rest.sigv4-enabled": "true", "rest.signing-name": "glue", "rest.signing-region": region,
        "client.region": region, "client.access-key-id": "test", "client.secret-access-key": "test",
        "s3.endpoint": endpoint, "s3.region": region,
        "s3.access-key-id": "test", "s3.secret-access-key": "test",
        "s3.force-virtual-addressing": "false", "py-io-impl": "pyiceberg.io.pyarrow.PyArrowFileIO",
    })
    assert catalog.properties["prefix"] == "catalogs/" + account, catalog.properties
    catalog.create_namespace((namespace,), properties={"location": "s3://" + bucket + "/warehouse/"})
    created_namespace = True
    assert catalog.namespace_exists((namespace,))
    schema = Schema(
        NestedField(field_id=1, name="id", field_type=LongType(), required=False),
        NestedField(field_id=2, name="label", field_type=StringType(), required=False),
        schema_id=0,
    )
    # AWS does not support stage-create=true on its ordinary S3 REST catalog.
    # Rejection must not publish an early table or write staging objects.
    try:
        catalog.create_table_transaction((namespace, "staged_events"), schema=schema,
            location="s3://" + bucket + "/warehouse/staged_events")
    except BadRequestError:
        pass
    else:
        raise AssertionError("unsupported native staged create unexpectedly succeeded")
    assert not catalog.table_exists((namespace, "staged_events"))
    assert (namespace, "staged_events") not in catalog.list_tables((namespace,))
    assert s3.list_objects_v2(Bucket=bucket).get("KeyCount", 0) == 0, "rejected staged create wrote S3 objects"
    observations["native_stage_create_rejected"] = True
    observations["invisible_rejected_staging"] = True
    table = catalog.create_table(
        (namespace, "events"), schema=schema,
        location="s3://" + bucket + "/warehouse/events", properties={"format-version": "2"},
    )
    assert catalog.table_exists((namespace, "events"))
    table.append(arrow_rows([1, 2], ["pyiceberg-one", "pyiceberg-two"]))
    table = catalog.load_table((namespace, "events"))
    expected = [{"id": 1, "label": "pyiceberg-one"}, {"id": 2, "label": "pyiceberg-two"}]
    assert rows(table) == expected
    before = shared_metadata("events", table)
    assert before["last-sequence-number"] == 1 and before["refs"]["main"]["snapshot-id"] == before["current-snapshot-id"]
    # The standard multi-table REST extension is not an AWS Glue endpoint.
    response = catalog._session.post(
        endpoint + "/iceberg/v1/catalogs/" + account + "/transactions/commit",
        json={"table-changes": []},
    )
    assert response.status_code == 404, "unsupported multi-table endpoint was accepted"
    assert response.json()["error"]["type"] == "NoSuchResourceException"
    assert catalog.load_table((namespace, "events")).metadata_location == table.metadata_location
    assert shared_metadata("events", table) == before
    observations["native_multitable_commit_rejected"] = True
    athena.create_work_group(Name=workgroup, Configuration={
        "EnforceWorkGroupConfiguration": True,
        "ResultConfiguration": {"OutputLocation": "s3://" + bucket + "/results/"},
    })
    created_workgroup = True
    selected = query('SELECT id, label FROM "events" ORDER BY id')
    assert selected == [["id", "label"], ["1", "pyiceberg-one"], ["2", "pyiceberg-two"]], selected
    query("INSERT INTO events VALUES (3, 'trino-three')")
    table.refresh()
    expected.append({"id": 3, "label": "trino-three"})
    assert rows(table) == expected, rows(table)
    after = shared_metadata("events", table)
    assert after["last-sequence-number"] == 2 and after["current-snapshot-id"] != before["current-snapshot-id"], after
    # Reverse direction: native Trino creates metadata through ordinary Glue;
    # the REST client then loads, reads and commits against that exact table.
    query("CREATE TABLE trino_events (id bigint, label string) LOCATION 's3://" + bucket + "/warehouse/trino_events/' TBLPROPERTIES ('table_type'='ICEBERG')")
    query("INSERT INTO trino_events VALUES (4, 'trino-four')")
    trino_table = catalog.load_table((namespace, "trino_events"))
    assert rows(trino_table) == [{"id": 4, "label": "trino-four"}]
    shared_metadata("trino_events", trino_table)
    trino_table.append(arrow_rows([5], ["pyiceberg-five"]))
    selected = query('SELECT id, label FROM "trino_events" ORDER BY id')
    assert selected == [["id", "label"], ["4", "trino-four"], ["5", "pyiceberg-five"]], selected
    trino_table.refresh()
    stored = shared_metadata("trino_events", trino_table)
    assert stored["refs"]["main"]["snapshot-id"] == stored["current-snapshot-id"]
    # A real Hive-only syntax path must publish ordinary Glue metadata and
    # produce physical S3 input, not an Iceberg metadata-only COUNT shortcut.
    payload = (b"0123456789abcdef" * 4 + b"\n") * 196608
    checksum = base64.b64encode(hashlib.sha256(payload).digest()).decode("ascii")
    s3.put_object(Bucket=bucket, Key="scan/lines.txt", Body=payload,
        ChecksumAlgorithm="SHA256", ChecksumSHA256=checksum)
    checked = s3.get_object(Bucket=bucket, Key="scan/lines.txt", ChecksumMode="ENABLED")
    assert checked["ChecksumSHA256"] == checksum, "S3 checksum header mismatch"
    assert hashlib.sha256(checked["Body"].read()).digest() == base64.b64decode(checksum), "S3 checksum bytes mismatch"
    query("CREATE EXTERNAL TABLE scan_lines (payload string) STORED AS TEXTFILE LOCATION 's3://" + bucket + "/scan/'")
    hive_table = glue.get_table(DatabaseName=namespace, Name="scan_lines")["Table"]
    assert hive_table["StorageDescriptor"]["Location"] == "s3://" + bucket + "/scan/"
    scan_sql = "SELECT sum(length(payload)) AS total FROM scan_lines"
    scan_rows = query(scan_sql)
    assert scan_rows == [["total"], [str(64 * 196608)]], scan_rows
    assert last_execution["Statistics"]["DataScannedInBytes"] > 10485760, "positive query did not physically scan beyond cutoff"
    observations["hive_fallback_real_scan"] = True
    observations["s3_sha256_verified"] = True

    # Keep the SQL, access key, workgroup and engine fixed across policy edits.
    # Only the per-query capability/current caller authority may change.
    iam.create_user(UserName=user)
    created_user = True
    access_key = iam.create_access_key(UserName=user)["AccessKey"]
    actor = session.client("athena", endpoint_url=endpoint, config=config,
        aws_access_key_id=access_key["AccessKeyId"], aws_secret_access_key=access_key["SecretAccessKey"])
    statements = [{"Effect": "Allow", "Action": ["athena:*", "glue:Get*", "s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation", "s3:PutObject"], "Resource": "*"}]
    def set_reader_policy():
        global created_policy
        iam.put_user_policy(UserName=user, PolicyName="fixture-reader",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}))
        created_policy = True
    set_reader_policy()
    previous = last_witness
    assert query(scan_sql, client=actor) == scan_rows
    same_engine_fresh_query(previous)
    previous = last_witness
    statements.append({"Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::" + bucket + "/scan/*"})
    set_reader_policy()
    read_native = native_query_reader()
    previous_native_ids = {item["queryId"] for item in read_native("/v1/query")}
    query(scan_sql, client=actor, expected_state="FAILED")
    observations["warm_native_s3_denial"] = native_s3_denial(read_native, previous_native_ids, scan_sql)
    same_engine_fresh_query(previous)
    previous = last_witness
    statements.pop()
    set_reader_policy()
    assert query(scan_sql, client=actor) == scan_rows
    same_engine_fresh_query(previous)
    observations["warm_same_caller_allow_deny_allow"] = True
    observations["warm_fresh_query_identity"] = True
    observations["result_reuse_disabled"] = True

    # A changed cutoff deliberately rotates the engine. Require the native
    # EXCEEDED_SCAN_LIMIT category, not just the service post-result byte guard.
    athena.create_work_group(Name=limited_workgroup, Configuration={
        "EnforceWorkGroupConfiguration": True, "BytesScannedCutoffPerQuery": 10485760,
        "ResultConfiguration": {"OutputLocation": "s3://" + bucket + "/results/"},
    })
    created_limited_workgroup = True
    # Trino samples physical input while a query is running. This small local
    # scan can otherwise finish between samples and hit only Athena's post-result
    # guard. Materialize its bounded real input before CPU-bearing expansion so
    # the native monitor sees the exceeded cutoff before query completion.
    limited_sql = ("SELECT sum(length(payload) + n) AS total "
        "FROM (SELECT array_agg(payload) AS payloads FROM scan_lines) AS source "
        "CROSS JOIN UNNEST(payloads) AS lines(payload) "
        "CROSS JOIN UNNEST(sequence(1, 1024)) AS expansion(n)")
    query(limited_sql, group=limited_workgroup, expected_state="CANCELLED", reason_contains="EXCEEDED_SCAN_LIMIT")
    observations["uncached_native_scan_limit"] = "EXCEEDED_SCAN_LIMIT"
    # AWS Glue's ordinary S3 catalog must reject purge, unlike S3 Tables.
    # https://docs.aws.amazon.com/glue/latest/dg/iceberg-rest-apis.html#delete-table
    # The native client sends `purgeRequested=True` / `purgeRequested=False`;
    # both retain their genuine SigV4 signatures and ordinary HTTP transport.
    table.refresh()
    retained_graph, graph_counts = iceberg_graph(table)
    ordinary = glue.get_table(DatabaseName=namespace, Name="events")["Table"]
    glue.create_table(DatabaseName=namespace, TableInput={
        "Name": "events_shared", "TableType": ordinary["TableType"],
        "Parameters": ordinary["Parameters"], "StorageDescriptor": ordinary["StorageDescriptor"],
    })
    shared = catalog.load_table((namespace, "events_shared"))
    assert shared.metadata_location == table.metadata_location
    unrelated = "s3://" + bucket + "/warehouse/events/data/not-an-iceberg-file.bin"
    s3.put_object(Bucket=bucket, Key=urlparse(unrelated).path.lstrip("/"), Body=b"unrelated fixture bytes")
    retained_graph[unrelated] = object_witness(unrelated)
    try:
        catalog.purge_table((namespace, "events"))
    except BadRequestError:
        pass
    else:
        raise AssertionError("AWS-unsupported native purge unexpectedly succeeded")
    assert catalog.table_exists((namespace, "events")), "rejected purge removed the table"
    assert shared_metadata("events", table) == shared_metadata("events_shared", shared)
    assert_objects_unchanged(retained_graph)
    catalog.drop_table((namespace, "events"))
    assert not catalog.table_exists((namespace, "events")), "ordinary native drop did not remove catalog entry"
    assert (namespace, "events") not in catalog.list_tables((namespace,))
    assert_objects_unchanged(retained_graph)
    assert rows(catalog.load_table((namespace, "events_shared"))) == expected
    observations["native_s3_purge_rejected_without_effects"] = True
    observations["native_nonpurging_drop_retains_graph"] = graph_counts
    observations["shared_table_and_unrelated_bytes_survive_drop"] = True
    report = {"pyiceberg": pyiceberg.__version__, "pyarrow": pa.__version__,
        "client_to_trino_rows": expected, "trino_to_client_rows": rows(trino_table),
        "shared_glue_head": True, "last_sequence_number": stored["last-sequence-number"],
        "observations": observations}
finally:
    # Attempt every owned cleanup even if one fails, and do not turn cleanup
    # failures into a successful fixture result.
    def cleanup(label, operation):
        try:
            return operation()
        except Exception as error:
            cleanup_errors.append(label + ": " + str(error))
    if created_namespace:
        listed = cleanup("list owned tables", lambda: glue.get_tables(DatabaseName=namespace))
        tables = listed.get("TableList", []) if listed is not None else []
        for table in tables:
            cleanup("table " + table["Name"], lambda table=table: glue.delete_table(DatabaseName=namespace, Name=table["Name"]))
        cleanup("namespace", lambda: glue.delete_database(Name=namespace))
    if created_workgroup:
        cleanup("workgroup", lambda: athena.delete_work_group(WorkGroup=workgroup, RecursiveDeleteOption=True))
    if created_limited_workgroup:
        cleanup("limited workgroup", lambda: athena.delete_work_group(WorkGroup=limited_workgroup, RecursiveDeleteOption=True))
    if access_key is not None:
        cleanup("reader access key", lambda: iam.delete_access_key(UserName=user, AccessKeyId=access_key["AccessKeyId"]))
    if created_policy:
        cleanup("reader policy", lambda: iam.delete_user_policy(UserName=user, PolicyName="fixture-reader"))
    if created_user:
        cleanup("reader user", lambda: iam.delete_user(UserName=user))
    if created_bucket:
        def remove_objects():
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
                for item in page.get("Contents", []):
                    cleanup("object " + item["Key"], lambda item=item: s3.delete_object(Bucket=bucket, Key=item["Key"]))
        cleanup("list/remove owned objects", remove_objects)
        cleanup("bucket", lambda: s3.delete_bucket(Bucket=bucket))
    if cleanup_errors:
        raise AssertionError("owned fixture cleanup failed: " + "; ".join(cleanup_errors))
report["owned_cleanup"] = True
print(json.dumps(report, sort_keys=True))
