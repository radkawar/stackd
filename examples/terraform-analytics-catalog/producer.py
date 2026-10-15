"""Run in the installed AWS Glue 5.0 image for this AWS-targeted workflow."""

import argparse
import json
import os
import re

import boto3
from botocore.config import Config
from pyspark.sql import SparkSession

parser = argparse.ArgumentParser()
for name in ("bucket", "database", "catalog-id", "udf-name", "revision", "delimiter",
             "WORKFLOW_NAME", "WORKFLOW_RUN_ID"):
    parser.add_argument("--" + name, required=True)
args, _ = parser.parse_known_args()
revision = int(args.revision)
config = Config(retries={"total_max_attempts": 1}, s3={"addressing_style": "path"})
glue = boto3.client("glue", endpoint_url=os.environ["AWS_ENDPOINT_URL"], config=config)
properties = glue.get_workflow_run_properties(Name=args.WORKFLOW_NAME,
    RunId=args.WORKFLOW_RUN_ID)["RunProperties"]
assert properties["revision"] == args.revision
assert properties["consumer"] == "native-spark-csv"
function = glue.get_user_defined_function(CatalogId=args.catalog_id,
    DatabaseName=args.database, FunctionName=args.udf_name)["UserDefinedFunction"]
assert re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_.$]*", function["ClassName"])
assert not function.get("ResourceUris"), "This fixture uses an installed Hive UDF, not external JARs"
spark = SparkSession.builder.enableHiveSupport().getOrCreate()
try:
    spark.sql("CREATE TEMPORARY FUNCTION catalog_case AS '" + function["ClassName"] + "'")
    udf_rows = spark.sql("SELECT catalog_case('MiXeD') AS transformed").collect()
    expected = "MIXED" if revision == 1 else "mixed"
    assert udf_rows[0]["transformed"] == expected, (function, udf_rows)
    records = {"east": [("North", 4), ("North", 6)], "west": [("South", 14)]}
    writes = []
    for region, rows in records.items():
        frame = spark.createDataFrame(rows, "label string, amount int")
        frame.createOrReplaceTempView("source_rows")
        output = spark.sql("SELECT catalog_case(label) AS label, amount FROM source_rows")
        location = f"s3://{args.bucket}/input/region={region}/"
        # Spark's actual Hadoop S3A writer receives the selected security
        # configuration from the job owner. No client-side output is substituted.
        output.coalesce(1).write.mode("overwrite").option("header", "true").option(
            "sep", args.delimiter).csv(location)
        writes.append({"region": region, "location": location, "rows": len(rows)})
    report = {"revision": revision, "workflow_run_id": args.WORKFLOW_RUN_ID,
              "class_name": function["ClassName"], "udf_result": expected,
              "writes": writes, "workflow_properties": properties}
    # Persist the independent execution marker only after native Spark writes.
    boto3.client("s3", endpoint_url=os.environ["AWS_ENDPOINT_URL"], config=config).put_object(
        Bucket=args.bucket, Key=f"job-results/revision-{revision}.json",
        Body=json.dumps(report).encode(), ContentType="application/json")
    print(json.dumps(report), flush=True)
finally:
    spark.stop()
