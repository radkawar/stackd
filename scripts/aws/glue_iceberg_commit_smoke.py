"""Exercise supported existing-table replacement through real PyIceberg commits.

Prepare an external environment, start an isolated local controller with SQLite
(no Athena/Docker runtime is needed), and run:
  python3 -m venv /tmp/stackd-iceberg-client
  /tmp/stackd-iceberg-client/bin/pip install 'pyiceberg[pyarrow,glue]==0.10.0'
  /tmp/stackd-iceberg-client/bin/python scripts/aws/glue_iceberg_commit_smoke.py --endpoint http://127.0.0.1:4566

PyIceberg 0.10.0 has no high-level replaceTable API: its typed commit_table API
sends the replacement updates used by Java RESTSessionCatalog.replaceTransaction.
This is the supported existing-table UpdateTable path, not stage-create or an
optional multi-table transaction extension. The native Athena smoke separately
checks AWS's staging rejection. Only local test/test credentials and uniquely
owned resources are used. No ambient profile, credentials, or catalog is loaded.

Primary contracts:
https://docs.aws.amazon.com/glue/latest/dg/iceberg-rest-apis.html#create-table
https://docs.aws.amazon.com/glue/latest/dg/iceberg-rest-apis.html#update-table
https://github.com/apache/iceberg/blob/apache-iceberg-1.6.1/core/src/main/java/org/apache/iceberg/rest/RESTSessionCatalog.java
https://github.com/apache/iceberg-python/blob/pyiceberg-0.10.0/pyiceberg/catalog/rest/__init__.py
"""

import argparse
import json
import uuid
from urllib.parse import urlparse

import boto3
import pyarrow as pa
import pyiceberg
from botocore.config import Config
from pyiceberg.catalog.rest import RestCatalog
from pyiceberg.exceptions import CommitFailedException
from pyiceberg.schema import Schema
from pyiceberg.table.update import (
    AddSchemaUpdate,
    AssertCreate,
    AssertLastAssignedFieldId,
    AssertTableUUID,
    RemoveSnapshotRefUpdate,
    SetCurrentSchemaUpdate,
    SetDefaultSortOrderUpdate,
    SetDefaultSpecUpdate,
    SetPropertiesUpdate,
)
from pyiceberg.types import LongType, NestedField, StringType


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True, help="Explicit isolated local stackd HTTP(S) origin")
    args = parser.parse_args()
    endpoint = args.endpoint.rstrip("/")
    origin = urlparse(endpoint)
    if origin.scheme not in ("http", "https") or not origin.hostname or origin.username or origin.password or origin.path or origin.query or origin.fragment:
        raise ValueError("endpoint must be an explicit HTTP(S) origin")
    region = "us-east-1"
    session = boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name=region)
    config = Config(retries={"max_attempts": 0}, connect_timeout=5, read_timeout=30, s3={"addressing_style": "path"})
    s3 = session.client("s3", endpoint_url=endpoint, config=config)
    glue = session.client("glue", endpoint_url=endpoint, config=config)
    account = session.client("sts", endpoint_url=endpoint, config=config).get_caller_identity()["Account"]
    suffix = uuid.uuid4().hex[:12]
    bucket = "iceberg-commit-" + suffix
    namespace = "iceberg_commit_" + suffix
    identifier = (namespace, "events")
    catalog = None
    created_bucket = created_namespace = False
    cleanup_errors = []
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
        catalog.create_namespace((namespace,), {"location": "s3://" + bucket + "/warehouse"})
        created_namespace = True
        table = catalog.create_table(identifier, Schema(
            NestedField(1, "id", LongType(), required=False),
            NestedField(2, "label", StringType(), required=False),
        ), location="s3://" + bucket + "/warehouse/events")
        table.append(pa.table({"id": pa.array([1], type=pa.int64()), "label": pa.array(["original"], type=pa.string())}))
        table.refresh()
        original_pointer = table.metadata_location
        original_uuid = table.metadata.table_uuid
        original_snapshot = table.current_snapshot().snapshot_id
        parsed = urlparse(original_pointer)
        original_bytes = s3.get_object(Bucket=parsed.netloc, Key=parsed.path.lstrip("/"))["Body"].read()
        requirements = (
            AssertTableUUID(uuid=original_uuid),
            AssertLastAssignedFieldId(last_assigned_field_id=table.metadata.last_column_id),
        )
        updates = (
            RemoveSnapshotRefUpdate(ref_name="main"),
            AddSchemaUpdate(schema=Schema(
                NestedField(1, "id", LongType(), required=False),
                NestedField(3, "payload", StringType(), required=False),
                schema_id=1,
            )),
            SetCurrentSchemaUpdate(schema_id=-1),
            SetDefaultSpecUpdate(spec_id=0),
            SetDefaultSortOrderUpdate(sort_order_id=0),
            SetPropertiesUpdate(updates={"owner": "replacement"}),
        )
        catalog.commit_table(table, requirements, updates)
        table.refresh()
        assert table.metadata.table_uuid == original_uuid
        assert table.metadata.current_snapshot_id in (None, -1)
        assert "main" not in table.metadata.refs
        assert [field.name for field in table.schema().fields] == ["id", "payload"]
        assert any(snapshot.snapshot_id == original_snapshot for snapshot in table.metadata.snapshots)
        assert table.scan().to_arrow().num_rows == 0
        replacement_pointer = table.metadata_location
        assert replacement_pointer != original_pointer
        ordinary = glue.get_table(DatabaseName=namespace, Name="events")["Table"]
        assert ordinary["VersionId"] == "2"
        assert ordinary["Parameters"]["metadata_location"] == replacement_pointer
        assert ordinary["Parameters"]["previous_metadata_location"] == original_pointer
        assert [column["Name"] for column in ordinary["StorageDescriptor"]["Columns"]] == ["id", "payload"]
        for rejected_requirements in (requirements, (AssertCreate(),)):
            try:
                catalog.commit_table(table, rejected_requirements, updates)
            except CommitFailedException:
                pass
            else:
                raise AssertionError("stale replacement/assert-create unexpectedly committed")
            table.refresh()
            assert table.metadata_location == replacement_pointer
        assert s3.get_object(Bucket=parsed.netloc, Key=parsed.path.lstrip("/"))["Body"].read() == original_bytes
        table.append(pa.table({"id": pa.array([2], type=pa.int64()), "payload": pa.array(["replacement"], type=pa.string())}))
        table.refresh()
        assert table.scan().to_arrow().to_pylist() == [{"id": 2, "payload": "replacement"}]
        assert table.metadata.last_sequence_number == 2
        assert table.metadata.table_uuid == original_uuid
        print(json.dumps({
            "source": "Independent local native PyIceberg fixture; not an AWS capture",
            "pyiceberg": pyiceberg.__version__, "existing_table_replacement": True,
            "retained_uuid_and_history": True, "reset_main_branch": True,
            "stale_replacement_conflict": True, "assert_create_conflict": True,
            "shared_native_glue_head": True, "post_replacement_rows": [{"id": 2, "payload": "replacement"}],
        }, sort_keys=True))
    finally:
        if created_namespace:
            try:
                for owned in catalog.list_tables((namespace,)):
                    catalog.drop_table(owned)
                catalog.drop_namespace((namespace,))
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        if created_bucket:
            try:
                paginator = s3.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=bucket):
                    for item in page.get("Contents", []):
                        s3.delete_object(Bucket=bucket, Key=item["Key"])
                s3.delete_bucket(Bucket=bucket)
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        if cleanup_errors:
            raise AssertionError("owned fixture cleanup failed: " + ", ".join(cleanup_errors))


if __name__ == "__main__":
    main()
