#!/usr/bin/env python3
"""Publish and query a small owned CloudWatch metric scope; no metrics can be deleted."""
import argparse
import ast
import datetime
import json
import os
from pathlib import Path
import re
import time
import uuid

from aws_cli import ProbeResult, run, result


REGION = "us-east-1"
MODEL = "clones/aws-sdk-go-v2/codegen/sdk-codegen/aws-models/cloudwatch.json"
REFERENCES = ["PutMetricData", "MetricDatum", "StatisticSet", "GetMetricStatistics",
              "GetMetricData", "MetricStat", "ListMetrics", "EntityMetricData", "Entity"]
STATS = ["SampleCount", "Sum", "Minimum", "Maximum", "Average"]


def timestamp(seconds):
    return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", required=True, type=Path, help="Local JSON capture path (not testdata)")
    parser.add_argument("--max-seconds", type=int, default=720, help="Total execution bound, 120..780 seconds")
    args = parser.parse_args()
    if not 120 <= args.max_seconds <= 780:
        parser.error("--max-seconds must be between 120 and 780")
    if "testdata" in args.output.parts:
        parser.error("Capture outside committed testdata; normalization belongs to integration")
    start = time.monotonic()
    deadline = start + args.max_seconds
    env = dict(os.environ, AWS_DEFAULT_REGION=REGION, AWS_REGION=REGION,
               AWS_MAX_ATTEMPTS="1", AWS_RETRY_MODE="standard", AWS_PAGER="")
    namespace = "Stackd/NativeMetrics/" + uuid.uuid4().hex
    reserved = "AWS/StackdNativeMetrics/" + uuid.uuid4().hex
    anchor = int(time.time() // 60) * 60 - 360
    capture = {
        "source": "native AWS CLI via shared aws_cli.run/result; debug text discarded",
        "retrieved_at": timestamp(time.time()), "region": REGION,
        "primary_references": ["https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_" + name + ".html" for name in REFERENCES],
        "pinned_model": MODEL,
        "scope": {"namespace": namespace, "reserved_namespace": reserved,
                  "maximum_distinct_series": 19, "anchor_seconds": anchor,
                  "publisher": "This finite Python process only; no continuing publisher or other AWS resources"},
        "identity_relationships": {"expected_caller_account": args.account,
                                   "deliberately_wrong_account": "111111111111",
                                   "substitutions": "None: literal owned namespaces, account values, timestamps, tokens, numbers, ordering and field presence retained; caller ARN/UserId discarded"},
        "timing": {"started_ms": time.time_ns() // 1_000_000, "max_seconds": args.max_seconds},
        "request_counts": {"sts": 0, "cloudwatch": 0, "total": 0, "maximum": 250, "automatic_retries": False},
        "observations": [], "expected_numeric_outputs": {},
        "limitations": ["Bounded visibility only, not permanent absence or loss; new ListMetrics entries can take 15 minutes.",
                        "No historical retention/rollup experiment; old accepted timestamps are not polled for delayed ingestion.",
                        "No DeleteMetric API exists. Published samples persist under normal CloudWatch retention.",
                        "CLI-side rejections are non-AWS evidence. HTTP status and failure header are extracted only when exposed by existing CLI debug transport.",
                        "At most 19 series including unexpected admission of invalid namespace/dimensions; no real 500-item ListMetrics pagination can be forced within budget."],
        "cleanup": {"deletable_resources_created": [], "continuing_publishers": False},
    }

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2, ensure_ascii=False) + "\n")

    def request(label, operation, parameters, service="cloudwatch") -> ProbeResult:
        remaining = deadline - time.monotonic()
        if remaining < 8 or capture["request_counts"]["total"] >= 250:
            raise TimeoutError("Owned probe request/time bound reached")
        capture["request_counts"][service] += 1
        capture["request_counts"]["total"] += 1
        started = time.time_ns() // 1_000_000
        process = run(service, operation, parameters, env, options=[
            "--debug", "--no-paginate", "--cli-connect-timeout", "5", "--cli-read-timeout", "20",
        ], timeout=min(30, remaining - 2))
        response = result(process, debug=True)
        headers = {}
        for line in process.stderr.splitlines():
            if "Response headers:" in line:
                try:
                    decoded = ast.literal_eval(line.split("Response headers:", 1)[1].strip())
                except (ValueError, SyntaxError):
                    continue
                headers = {key.lower(): value for key, value in decoded.items()
                           if key.lower() == "content-type" or key.lower().startswith("x-amzn-")}
        if "http_status" not in response:
            statuses = re.findall(r'HTTP/1\.1" (\d{3})', process.stderr)
            if statuses:
                response["http_status"] = int(statuses[-1])
        entry = {"label": label, "service": service, "operation": operation,
                 "input": parameters, "request_started_ms": started,
                 "request_finished_ms": time.time_ns() // 1_000_000, "result": response,
                 "evidence": "non-AWS CLI-side error" if response["code"] == "CLIError" else "AWS response",
                 "response_headers": headers}
        if service == "sts" and response["code"] == "Success":
            response["output"] = {"Account": response["output"]["Account"]}
        capture["observations"].append(entry)
        save()
        print(label + ": " + response["code"], flush=True)
        return response

    def datum(name, offset=0, **fields):
        return dict(MetricName=name, Timestamp=timestamp(anchor + offset), **fields)

    def put(label, rows, **fields):
        return request(label, "put-metric-data", dict(Namespace=namespace, MetricData=rows, **fields))

    def statistics(label, name, **fields):
        parameters = dict(Namespace=namespace, MetricName=name, StartTime=timestamp(anchor),
                          EndTime=timestamp(anchor + 300), Period=60, Statistics=STATS)
        if "ExtendedStatistics" in fields:
            parameters.pop("Statistics")
        parameters.update(fields)
        return request(label, "get-metric-statistics", parameters)

    def query(identifier, name, stat="Sum", period=60, **fields):
        metric = dict(Namespace=namespace, MetricName=name)
        dimensions = fields.pop("Dimensions", None)
        if dimensions is not None:
            metric["Dimensions"] = dimensions
        return dict(Id=identifier, MetricStat=dict(Metric=metric, Period=period, Stat=stat, **fields))

    def data(label, queries, **fields):
        parameters = dict(MetricDataQueries=queries, StartTime=timestamp(anchor),
                          EndTime=timestamp(anchor + 300))
        parameters.update(fields)
        return request(label, "get-metric-data", parameters)

    try:
        identity = request("verify-caller", "get-caller-identity", {}, "sts")
        if identity.get("output", {}).get("Account") != args.account:
            raise RuntimeError("Caller verification failed; no metrics published")
        capture["identity_relationships"]["verified_caller_account"] = args.account
        dims = [{"Name": "A", "Value": "one"}, {"Name": "B", "Value": "two"}]
        capture["scope"]["publication_started_ms"] = time.time_ns() // 1_000_000
        rows = [datum("Scalar", offset, Value=value) for offset, value in zip(range(0, 300, 60), [2, 4, 8, 16, 32])]
        rows += [datum("Weighted", Values=[2, 10], Counts=[2, 3]),
                 datum("DefaultCounts", Values=[2, 4, 6]),
                 datum("Fractional", Values=[2, 10], Counts=[0.5, 1.5]),
                 datum("StatsEligible", StatisticValues=dict(SampleCount=3, Sum=21, Minimum=7, Maximum=7)),
                 datum("StatsSingle", StatisticValues=dict(SampleCount=1, Sum=9, Minimum=9, Maximum=9)),
                 datum("StatsGeneral", StatisticValues=dict(SampleCount=3, Sum=15, Minimum=1, Maximum=9)),
                 datum("Negative", Values=[-1, 3]),
                 datum("Units", Value=1, Unit="Seconds"), datum("Units", Value=1000, Unit="Milliseconds"),
                 datum("Dimensions", Value=3, Dimensions=dims),
                 datum("Dimensions", Value=7, Dimensions=dims[:1]), datum("Dimensions", Value=11)]
        for name, resolution in [("High", 1), ("Standard", 60)]:
            rows += [datum(name, offset, Value=value, StorageResolution=resolution)
                     for offset, value in [(1, 2), (2, 3), (5, 7), (60, 11), (61, 13)]]
        initial = put("publish-baselines", rows)
        if initial["code"] != "Success":
            raise RuntimeError("Baseline publication rejected")
        put("publish-repeat-and-reversed-dimensions", [datum("Scalar", Value=2),
            datum("Dimensions", Value=5, Dimensions=list(reversed(dims)))])
        capture["expected_numeric_outputs"] = {
            "Scalar_sums_by_ascending_minute": [4, 4, 8, 16, 32],
            "Scalar_first_minute": dict(SampleCount=2, Sum=4, Minimum=2, Maximum=2, Average=2),
            "Weighted": dict(SampleCount=5, Sum=34, Minimum=2, Maximum=10, Average=6.8),
            "DefaultCounts": dict(SampleCount=3, Sum=12, Minimum=2, Maximum=6, Average=4),
            "Fractional_if_admitted_without_rounding": dict(SampleCount=2, Sum=16, Minimum=2, Maximum=10, Average=8),
            "Dimensions_exact_two": dict(SampleCount=2, Sum=8), "Dimensions_exact_one_sum": 7,
            "Dimensions_exact_empty_sum": 11,
            "High_second_sums": {"1": 2, "2": 3, "5": 7, "60": 11, "61": 13},
            "High_and_Standard_minute_sums": [12, 24],
            "Units_selected": {"Seconds": 1, "Milliseconds": 1000},
            "math_double_scalar": [8, 8, 16, 32, 64],
            "math_running_scalar_sum": [4, 8, 16, 32, 64],
            "note": "Arithmetic from literal publisher inputs; actual returned observations are authoritative, including admission/rounding differences.",
        }
        invalid_sets = [
            ("missing-value", {}), ("value-and-values", dict(Value=1, Values=[2])),
            ("value-and-statistic", dict(Value=1, StatisticValues=dict(SampleCount=1, Sum=2, Minimum=2, Maximum=2))),
            ("values-and-statistic", dict(Values=[1], StatisticValues=dict(SampleCount=1, Sum=2, Minimum=2, Maximum=2))),
            ("counts-without-values", dict(Counts=[1])), ("counts-length", dict(Values=[1, 2], Counts=[1])),
            ("counts-zero", dict(Values=[1, 2], Counts=[0, 1])), ("counts-negative", dict(Values=[1], Counts=[-1])),
            ("stat-count-zero", dict(StatisticValues=dict(SampleCount=0, Sum=1, Minimum=1, Maximum=1))),
            ("stat-min-above-max", dict(StatisticValues=dict(SampleCount=2, Sum=3, Minimum=2, Maximum=1))),
            ("stat-sum-outside-bounds", dict(StatisticValues=dict(SampleCount=2, Sum=100, Minimum=1, Maximum=2))),
            ("stat-single-inconsistent", dict(StatisticValues=dict(SampleCount=1, Sum=3, Minimum=1, Maximum=2))),
            ("resolution-two", dict(Value=1, StorageResolution=2)), ("value-too-large", dict(Value=2.0 ** 361)),
            ("duplicate-dimension-name", dict(Value=1, Dimensions=[dims[0], dims[0]])),
        ]
        # Budget includes a distinct series if duplicate dimensions are admitted.
        for index, (label, fields) in enumerate(invalid_sets):
            name = "Dimensions" if label == "duplicate-dimension-name" else "Invalid"
            put("admission-" + label, [datum(name, 600 + index * 60, **fields)])
        request("admission-empty-metric-data", "put-metric-data", {"Namespace": namespace, "MetricData": []})
        request("admission-missing-metric-data", "put-metric-data", {"Namespace": namespace})
        request("admission-colon-namespace", "put-metric-data", {"Namespace": ":" + namespace, "MetricData": [datum("Invalid", Value=1)]})
        request("admission-reserved-namespace", "put-metric-data", {"Namespace": reserved, "MetricData": [datum("Reserved", Value=17)]})
        now = time.time()
        for label, at in [("past-valid", now - 14 * 86400 + 120), ("past-too-old", now - 15 * 86400),
                          ("future-valid", now + 7200 - 120), ("future-too-new", now + 10800)]:
            put("timestamp-" + label, [dict(MetricName="Invalid", Timestamp=timestamp(at), Value=19)])
        bad_entity = {"KeyAttributes": {"Type": "NotAValidEntityType", "Name": "owned"}}
        good_entity = {"KeyAttributes": {"Type": "Service", "Name": "stackd-native-metrics-owned", "Environment": "probe"}}
        for index, (label, strict, entity, value) in enumerate([
            ("invalid-strict", True, bad_entity, 101), ("invalid-lenient", False, bad_entity, 103),
            ("valid-strict", True, good_entity, 107), ("missing-strict", None, bad_entity, 109),
            ("missing-keys-lenient", False, {}, 113),
        ]):
            parameters = dict(Namespace=namespace, EntityMetricData=[dict(Entity=entity, MetricData=[datum("Entity", index * 60, Value=value)])])
            if strict is not None:
                parameters["StrictEntityValidation"] = strict
            request("entity-" + label, "put-metric-data", parameters)
        request("entity-lenient-invalid-metric", "put-metric-data", dict(Namespace=namespace, StrictEntityValidation=False,
            EntityMetricData=[dict(Entity=bad_entity, MetricData=[datum("Entity", 240, Value=1, Values=[2])])]))
        capture["scope"]["publication_finished_ms"] = time.time_ns() // 1_000_000
        # Poll only fresh data, bounded to 180 seconds and ten requests.
        visible_deadline = min(deadline - 240, time.monotonic() + 180)
        for attempt in range(10):
            response = statistics("visibility-scalar-" + str(attempt), "Scalar")
            if len(response.get("output", {}).get("Datapoints", [])) == 5 or time.monotonic() >= visible_deadline:
                break
            time.sleep(10)
        for name in ["Scalar", "Weighted", "DefaultCounts", "Fractional", "StatsEligible", "StatsSingle", "StatsGeneral", "Negative", "Units", "Entity"]:
            statistics("statistics-" + name, name)
        for name in ["Weighted", "Fractional", "StatsEligible", "StatsSingle", "StatsGeneral", "Negative"]:
            statistics("percentiles-" + name, name, ExtendedStatistics=["p0", "p50", "p90", "p100"])
        for unit in ["Seconds", "Milliseconds", "Bytes", "None"]:
            statistics("unit-" + unit, "Units", Unit=unit)
        for label, dimensions in [("ordered", dims), ("reversed", list(reversed(dims))), ("subset", dims[:1]),
                                  ("empty", []), ("unpublished-subset", dims[1:]), ("wrong-value", [{"Name": "A", "Value": "wrong"}])]:
            statistics("dimension-" + label, "Dimensions", Dimensions=dimensions)
        for name in ["High", "Standard"]:
            for period in [1, 5, 10, 20, 30, 60]:
                statistics("resolution-" + name + "-" + str(period), name, Period=period, EndTime=timestamp(anchor + 120))
        for label, fields in [
            ("inclusive-exclusive", dict(StartTime=timestamp(anchor + 60), EndTime=timestamp(anchor + 120))),
            ("unaligned-start", dict(StartTime=timestamp(anchor + 61), EndTime=timestamp(anchor + 120))),
            ("unaligned-end", dict(StartTime=timestamp(anchor), EndTime=timestamp(anchor + 61))),
            ("equal-window", dict(StartTime=timestamp(anchor), EndTime=timestamp(anchor))),
            ("reversed-window", dict(StartTime=timestamp(anchor + 120), EndTime=timestamp(anchor))),
            ("invalid-period", dict(Period=7)), ("zero-period", dict(Period=0)),
            ("too-many-buckets", dict(StartTime=timestamp(anchor - 86400), Period=60)),
            ("both-stat-types", dict(Statistics=["Sum"], ExtendedStatistics=["p90"])),
            ("no-stat-types", dict(Statistics=[])), ("invalid-standard", dict(Statistics=["Median"])),
            ("invalid-percentile", dict(ExtendedStatistics=["p101"])),
        ]:
            statistics("window-or-validation-" + label, "Scalar", **fields)
        statistics("extended-trimmed-statistics", "Weighted", ExtendedStatistics=["tm90", "wm90", "tc90", "ts90", "PR(2:10)", "IQM"])
        direct = [query("m", "Scalar")]
        data("data-default-descending", direct)
        data("data-ascending", direct, ScanBy="TimestampAscending")
        for scan in ["TimestampAscending", "TimestampDescending"]:
            fields = dict(ScanBy=scan, MaxDatapoints=2)
            for page in range(5):
                response = data("data-page-" + scan + "-" + str(page), direct, **fields)
                token = response.get("output", {}).get("NextToken")
                if not token:
                    break
                fields["NextToken"] = token
        data("data-resolution", [query("high", "High", period=1), query("standard", "Standard", period=1)], EndTime=timestamp(anchor + 120))
        data("data-extended", [query("p", "Weighted", "p90"), query("trim", "Weighted", "tm90"), query("negative", "Negative", "p90")])
        data("data-units", [query("all", "Units"), query("seconds", "Units", Unit="Seconds"), query("milliseconds", "Units", Unit="Milliseconds"), query("wrong", "Units", Unit="Bytes")])
        data("data-math", [dict(query("m", "Scalar"), ReturnData=False),
             {"Id": "double", "Expression": "m*2", "Label": "double"},
             {"Id": "running", "Expression": "RUNNING_SUM(m)"},
             {"Id": "conditional", "Expression": "IF(m>=8,m,0)"},
             {"Id": "aggregate", "Expression": "SUM([m,m])"},
             {"Id": "filled", "Expression": "FILL(m,0)"}], ScanBy="TimestampAscending")
        data("data-invalid-token", direct, NextToken="invalid-owned-token")
        data("data-duplicate-id", [query("m", "Scalar"), query("m", "Weighted")])
        data("data-expression-and-metric", [dict(query("m", "Scalar"), Expression="1+1")])
        data("data-invalid-expression", [{"Id": "bad", "Expression": "NOT_A_FUNCTION(m)"}, query("m", "Scalar")])
        data("data-invalid-id", [query("Bad", "Scalar")])
        data("data-invalid-stat", [query("m", "Scalar", "not-a-stat")])
        data("data-valid-account", [dict(query("m", "Scalar"), AccountId=args.account)])
        data("data-wrong-account", [dict(query("m", "Scalar"), AccountId="111111111111")])
        for label, fields in [("all", {}), ("subset-name", {"Dimensions": [{"Name": "A"}]}),
                              ("subset-value", {"Dimensions": dims[:1]}), ("wrong-dimension", {"Dimensions": [{"Name": "Z"}]}),
                              ("recent", {"RecentlyActive": "PT3H"}), ("invalid-recent", {"RecentlyActive": "PT1H"}),
                              ("invalid-token", {"NextToken": "invalid-owned-token"}),
                              ("wrong-account", {"OwningAccount": "111111111111", "IncludeLinkedAccounts": True})]:
            request("list-" + label, "list-metrics", dict(Namespace=namespace, **fields))
        # Leave time for terminal reads/final capture. Never interpret timeout as lost metrics.
        for attempt in range(12):
            response = request("list-visibility-" + str(attempt), "list-metrics", dict(Namespace=namespace, MetricName="Dimensions", Dimensions=dims[:1]))
            if len(response.get("output", {}).get("Metrics", [])) >= 2 or deadline - time.monotonic() < 75:
                break
            time.sleep(20)
        request("list-terminal-subset-name", "list-metrics", dict(Namespace=namespace, MetricName="Dimensions", Dimensions=[{"Name": "A"}]))
        request("list-terminal-all", "list-metrics", {"Namespace": namespace})
        statistics("entity-terminal", "Entity")
        statistics("reserved-terminal", "Reserved", Namespace=reserved)
        statistics("colon-namespace-terminal", "Invalid", Namespace=":" + namespace)
        statistics("admitted-validation-terminal", "Invalid", StartTime=timestamp(anchor + 600),
                   EndTime=timestamp(anchor + 1800))
        statistics("admitted-validation-percentiles", "Invalid", StartTime=timestamp(anchor + 600),
                   EndTime=timestamp(anchor + 1800), ExtendedStatistics=["p0", "p50", "p100"])
        capture["completed"] = True
    finally:
        capture["timing"]["finished_ms"] = time.time_ns() // 1_000_000
        capture["timing"]["elapsed_seconds"] = round(time.monotonic() - start, 3)
        admitted = set()
        for observation in capture["observations"]:
            if observation["operation"] != "put-metric-data" or observation["result"]["code"] != "Success":
                continue
            parameters = observation["input"]
            rows = list(parameters.get("MetricData", []))
            for entity in parameters.get("EntityMetricData", []):
                rows.extend(entity.get("MetricData", []))
            for row in rows:
                dimensions = tuple(sorted((item["Name"], item["Value"]) for item in row.get("Dimensions", [])))
                admitted.add((parameters["Namespace"], row["MetricName"], dimensions))
        capture["scope"]["admitted_series_count"] = len(admitted)
        capture["scope"]["admitted_namespaces"] = sorted({item[0] for item in admitted})
        capture["cleanup"].update(finally_executed=True, verified=True,
            residual="Accepted custom metric samples only in scope.admitted_namespaces; CloudWatch has no DeleteMetric API. No deletable AWS resources created; this finite process has stopped publishing.")
        save()
    print(json.dumps({"capture": str(args.output), "requests": capture["request_counts"], "elapsed_seconds": capture["timing"]["elapsed_seconds"]}))


if __name__ == "__main__":
    main()
