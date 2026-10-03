#!/usr/bin/env python3
"""Read only metric identities for the exact owned job of a completed native capture.

This does not enable metrics or launch a job. Empty discovery is a bounded
observation, not proof that Python shell never emits metrics or that delivery is
immediate. Use --source-capture .stackd/probes/athena/application.json.
"""
import argparse
import json
from pathlib import Path
import re

from glue_native_common import Capture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", required=True, action="store_true")
    parser.add_argument("--account", required=True)
    parser.add_argument("--source-capture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.endpoint_url = None
    if args.output.exists():
        parser.error("Output exists; preserve prior capture")
    source = json.loads(args.source_capture.read_text())
    suffix = source.get("run_suffix", "")
    if source.get("source") != "native AWS" or not source.get("completed") or not source.get("cleanup", {}).get("verified") or not re.fullmatch("[0-9a-f]{16}", suffix):
        parser.error("Need a completed, cleaned owned native application capture")
    if source.get("account") != args.account or source.get("region") != "us-east-1":
        parser.error("Source capture account/region differs from authorized target")
    job = "stackd-analytics-" + suffix + "-job"
    cap = Capture(args, "stackd-glue-metrics-", [
        "https://docs.aws.amazon.com/glue/latest/dg/monitoring-awsglue-with-cloudwatch-metrics.html",
        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_ListMetrics.html",
    ], {"max_calls": 3, "wall_seconds": 60, "created_resources": 0, "cost_usd_upper_estimate": 0.001,
        "scope": "Two exact JobName-filtered namespaces only; no global metric scans, no enablement or compute."})
    cap.identity()
    cap.name(job, "stackd-analytics-owned-job")
    cap.capture["source_capture"] = str(args.source_capture)
    cap.capture["job_run_configuration"] = "Python shell 3.9, --library-set none, no --enable-metrics, no CloudWatch PutMetricData permissions."
    cap.capture["uncertainty"] = ["ListMetrics can lag new metrics by up to 15 minutes; two immediate scoped reads do not establish permanent absence.", "Primary Glue profiler metrics are Spark-task aggregates; do not synthesize these from Python process elapsed time."]
    try:
        for namespace in ("Glue", "AWS/Glue"):
            cap.request("owned-job-metrics-" + namespace.replace("/", "-"), "cloudwatch", "list-metrics", {"Namespace": namespace, "Dimensions": [{"Name": "JobName", "Value": job}]})
        cap.capture["completed"] = True
    finally:
        cap.finish([])


if __name__ == "__main__":
    main()
