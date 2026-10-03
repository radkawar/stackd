"""Glue Python-shell consumer: transform actual S3 input bytes into queryable CSV."""
import argparse
import csv
import io

import botocore.session
from botocore.config import Config

parser = argparse.ArgumentParser()
parser.add_argument("--bucket", required=True)
parser.add_argument("--mode", choices=("success", "failure"), default="success")
args, _ = parser.parse_known_args()
if args.mode == "failure":
    raise RuntimeError("owned intentional producer failure")
s3 = botocore.session.get_session().create_client(
    "s3", config=Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 0}))
body = s3.get_object(Bucket=args.bucket, Key="input/source.csv")["Body"].read()
output = io.StringIO(newline="")
writer = csv.writer(output, lineterminator="\n")
for category, amount in csv.reader(io.StringIO(body.decode("utf-8"))):
    writer.writerow((category, int(amount) * 2))
encoded = output.getvalue().encode("utf-8")
s3.put_object(Bucket=args.bucket, Key="data/part.csv", Body=encoded, ContentType="text/csv")
print("transformed_csv_bytes=" + str(len(encoded)))
