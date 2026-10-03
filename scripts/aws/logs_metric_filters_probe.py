#!/usr/bin/env python3
"""Capture bounded native Logs metric-filter controls and real metric publication.

Run from the repository root with one output JSON path. No existing resources are
changed. Custom metrics cannot be deleted; all publishers and the group are removed.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import time
import uuid

from aws_cli import ProbeResult, result, run


REGION = "us-east-1"
MINUTE = 60_000


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("output", type=Path)
    parser.add_argument("--extractors", action="store_true", help="Run only wildcard, undefined selector, and source-log dimension probes")
    args = parser.parse_args()
    prior = json.loads(args.output.read_text()) if args.output.exists() else None
    if prior and (not prior.get("cleanup", {}).get("verified") or prior.get("windows")):
        raise RuntimeError("Only a fully cleaned, pre-publication capture can be resumed")
    if prior and (prior.get("account") != args.account or prior["region"] != REGION):
        raise RuntimeError("Capture account/region does not match --account")
    env = dict(os.environ, AWS_DEFAULT_REGION=REGION, AWS_REGION=REGION,
               AWS_MAX_ATTEMPTS="1", AWS_RETRY_MODE="standard")
    suffix = uuid.uuid4().hex[:16]
    group = "/stackd/native-metric-filters-" + suffix
    namespace = "Stackd/NativeMetricFilters/" + suffix
    started = time.monotonic()
    owned = False
    cleaning = False
    filters = set()
    capture = {
        "source": "Native AWS CLI; actual CloudWatch Logs and CloudWatch responses, no mocks",
        "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "region": REGION, "account": None, "group": group, "namespace": namespace,
        "substitutions": "None in replayable resource inputs; STS Arn/UserId omitted. Actual caller account and deliberately wrong account 999999999999 remain distinct. No debug logs or credentials retained.",
        "references": [
            "https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_" + name + ".html"
            for name in ("PutMetricFilter", "DescribeMetricFilters", "DeleteMetricFilter", "MetricTransformation", "TestMetricFilter", "PutLogEvents")
        ] + ["https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/MonitoringLogData.html",
             "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntaxForMetricFilters.html",
             "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html#regex-expressions"],
        "bounds": {"max_cli_commands": 250, "max_work_seconds": 780,
                   "max_elapsed_seconds_including_cleanup": 900, "max_possible_metric_series": 18,
                   "automatic_retries": False, "poll_interval_seconds": 30},
        "request_counts": {"total": 0, "aws_http_responses": 0, "cli_side_errors": 0},
        "observations": [], "windows": [], "series": [], "positive_points": [],
        "limitations": [
            "Bounded absent data is unresolved, never evidence of permanent loss.",
            "One owned group, fixed streams, one region/account; no transformer or centralized source is installed.",
            "Cross-subscription/metric regex quota is unmeasured: no owned subscription destination is provisioned.",
            "Metric publication is at least once per AWS documentation; observed values do not establish exactly-once guarantees.",
            "Partial ingestion admission/rejection is not metric publication evidence; only returned metric points prove production.",
            "No DeleteMetric API exists. Published custom metrics age out under CloudWatch retention after publishers are removed."],
        "cleanup": {"verified": False}}
    if args.extractors:
        capture["bounds"].update(max_cli_commands=40, max_possible_metric_series=6, poll_interval_seconds=60)
        capture["scope"] = "One fresh group/stream; wildcard metric value/dimensions, undefined space selector and @source.log."
    if prior:
        capture["previous_runs"] = [prior]
        capture["request_counts"] = dict(prior["request_counts"])
        capture["request_counts_scope"] = "Cumulative CLI commands including preserved pre-publication run and grammar recovery requests."

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2, ensure_ascii=False) + "\n")

    def request(label, operation, parameters, service="logs") -> ProbeResult:
        counts = capture["request_counts"]
        maximum = capture["bounds"]["max_cli_commands"]
        work_maximum = 31 if args.extractors else 220
        if counts["total"] >= maximum or (not cleaning and (counts["total"] >= work_maximum or time.monotonic() - started > 780)):
            raise RuntimeError("Native request/time bound reached")
        counts["total"] += 1
        counts[service] = counts.get(service, 0) + 1
        row = {"label": label, "service": service, "operation": operation,
               "input": parameters, "request_started_ms": time.time_ns() // 1_000_000}
        capture["observations"].append(row)
        try:
            process = run(service, operation, parameters, env, options=[
                "--debug", "--no-paginate", "--cli-connect-timeout", "5", "--cli-read-timeout", "10"], timeout=20)
            response = result(process, debug=True, cli_message=None)
            if "http_status" in response:
                counts["aws_http_responses"] += 1
            if response["code"] == "CLIError":
                counts["cli_side_errors"] += 1
                row["evidence_kind"] = "CLI-side rejection, not AWS service evidence"
            else:
                row["evidence_kind"] = "AWS service response"
            if service == "sts":
                response.get("output", {}).pop("Arn", None)
                response.get("output", {}).pop("UserId", None)
            row["result"] = response
        except Exception as error:
            row["transport_error"] = type(error).__name__
            raise
        finally:
            row["request_finished_ms"] = time.time_ns() // 1_000_000
            save()
        print(label + ": " + response["code"], flush=True)
        return response

    def require(response):
        if response["code"] != "Success":
            raise RuntimeError("Required owned operation failed: " + response["code"])
        return response["output"]

    def transformation(metric, value="1", **extra):
        return dict(metricNamespace=namespace, metricName=metric, metricValue=value, **extra)

    def put(label, name, pattern, metric="Control", value="1", transform=None, **extra):
        parameters = dict(logGroupName=group, filterName=name, filterPattern=pattern,
                          metricTransformations=[transform or transformation(metric, value)])
        parameters.update(extra)
        response = request(label, "put-metric-filter", parameters)
        if response["code"] == "Success":
            filters.add(name)
        return response

    def describe(label, **extra):
        return request(label, "describe-metric-filters", dict(logGroupName=group, **extra))

    def remove(name, label=None):
        response = request(label or "delete-" + name, "delete-metric-filter", dict(logGroupName=group, filterName=name))
        if response["code"] in ("Success", "ResourceNotFoundException"):
            filters.discard(name)
        return response

    def ingest(label, stream, rows):
        response = request(label, "put-log-events", dict(logGroupName=group, logStreamName=stream,
                           logEvents=[{"timestamp": timestamp, "message": message} for timestamp, message in sorted(rows)]))
        observed = capture["observations"][-1]
        capture["windows"].append({"label": label, "ingestion_request_started_ms": observed["request_started_ms"],
                                   "ingestion_request_finished_ms": observed["request_finished_ms"],
                                   "event_timestamps_ms": [timestamp for timestamp, _ in sorted(rows)]})
        return response

    def iso(milliseconds):
        return datetime.datetime.fromtimestamp(milliseconds / 1000, datetime.timezone.utc).isoformat()

    def add_series(name, dimensions=None):
        item = {"Namespace": namespace, "MetricName": name}
        if dimensions:
            item["Dimensions"] = [{"Name": key, "Value": value} for key, value in dimensions.items()]
        capture["series"].append(item)

    def query(label, start, end):
        queries = [{"Id": "m" + str(index), "MetricStat": {"Metric": metric, "Period": 60, "Stat": "Sum"}, "ReturnData": True}
                   for index, metric in enumerate(capture["series"])]
        response = request(label, "get-metric-data", {"MetricDataQueries": queries, "StartTime": iso(start),
                           "EndTime": iso(end), "ScanBy": "TimestampAscending", "MaxDatapoints": 100800}, service="cloudwatch")
        for series in response.get("output", {}).get("MetricDataResults", []):
            for timestamp, value in zip(series.get("Timestamps", []), series.get("Values", [])):
                capture["positive_points"].append({"query_label": label, "metric": capture["series"][int(series["Id"][1:])],
                                                    "timestamp": timestamp, "value": value, "stat": "Sum"})
        save()
        return response

    def probe_extractors():
        require(request("create-extractor-stream", "create-log-stream", dict(logGroupName=group, logStreamName="basic")))
        value_pattern = '{ $.kind = "wildcard" && $.items[*].value = * }'
        dimension_pattern = '{ $.kind = "wildcard" && $.items[*].bucket = * }'
        put("wildcard-value-admission", "a-wildcard-value", value_pattern, "WildcardValue", "$.items[*].value")
        put("wildcard-dimension-admission", "b-wildcard-dimension", dimension_pattern,
            transform=transformation("WildcardDimension", dimensions={"Bucket": "$.items[*].bucket"}))
        put("undefined-space-selector-admission", "c-space-missing", "[kind,value]", "SpaceMissing", "$missing")
        put("source-log-dimension-admission", "d-source-log", "SOURCE_LOG", "SourceLog", "29",
            emitSystemFieldDimensions=["@source.log"])
        require(put("baseline-admission", "e-baseline", '{ $.kind = "wildcard" && $.value = * }', "Baseline", "$.value"))
        describe("extractor-control-roundtrip")
        single = '{"kind":"wildcard","value":19,"items":[{"value":7,"bucket":"A"}]}'
        multiple = '{"kind":"wildcard","value":23,"items":[{"value":11,"bucket":"A"},{"value":13,"bucket":"B"}]}'
        for label, pattern, messages in (
            ("matcher-wildcard-value", value_pattern, [single, multiple]),
            ("matcher-wildcard-dimension", dimension_pattern, [single, multiple]),
            ("matcher-space", "[kind,value]", ["SPACE 17", "SPACE 31"])):
            request(label, "test-metric-filter", dict(filterPattern=pattern, logEventMessages=messages))
        time.sleep(12)
        anchor = time.time_ns() // 1_000_000
        capture["clock_anchor_ms"] = anchor
        capture["candidate_design"] = {
            "single": {"event_minute_ms": anchor // MINUTE * MINUTE, "values": [7], "buckets": ["A"], "baseline": 19},
            "multiple": {"event_minute_ms": (anchor + MINUTE) // MINUTE * MINUTE, "values": [11, 13], "buckets": ["A", "B"], "baseline": 23},
            "source_log_value": 29, "undefined_space_values": [17, 31]}
        require(ingest("publish-single-candidates", "basic", [(anchor, single), (anchor + 1, "SPACE 17"), (anchor + 2, "SOURCE_LOG")]))
        require(ingest("publish-multiple-candidates", "basic", [(anchor + MINUTE, multiple), (anchor + MINUTE + 1, "SPACE 31")]))
        request("read-extractor-events", "get-log-events", dict(logGroupName=group, logStreamName="basic", startFromHead=True))
        for name in ("WildcardValue", "SpaceMissing", "Baseline"):
            add_series(name)
        for bucket in ("A", "B"):
            add_series("WildcardDimension", {"Bucket": bucket})
        for attempt in range(5):
            time.sleep(60)
            listed = request("list-extractor-metrics-" + str(attempt), "list-metrics", {"Namespace": namespace}, service="cloudwatch")
            for metric in listed.get("output", {}).get("Metrics", []):
                if not any(metric["MetricName"] == known["MetricName"] and
                           sorted(metric.get("Dimensions", []), key=lambda d: d["Name"]) ==
                           sorted(known.get("Dimensions", []), key=lambda d: d["Name"])
                           for known in capture["series"]):
                    capture["series"].append(metric)
            query("extractor-data-" + str(attempt), anchor - 5 * MINUTE, anchor + 10 * MINUTE)
        for name in ("WildcardValue", "SpaceMissing", "SourceLog"):
            metric = next((item for item in capture["series"] if item["MetricName"] == name), None)
            if metric is not None:
                request("extractor-statistics-" + name, "get-metric-statistics",
                        dict(metric, StartTime=iso(anchor - 5 * MINUTE), EndTime=iso(anchor + 10 * MINUTE),
                             Period=60, Statistics=["Sum", "SampleCount", "Minimum", "Maximum", "Average"]), service="cloudwatch")

    try:
        identity = require(request("verify-caller", "get-caller-identity", {}, service="sts"))
        if identity["Account"] != args.account:
            raise RuntimeError("Unexpected AWS account; no resources created")
        account = capture["account"] = identity["Account"]
        require(request("create-group", "create-log-group", dict(logGroupName=group)))
        owned = True
        if args.extractors:
            probe_extractors()
            return
        require(request("retention-one-day", "put-retention-policy", dict(logGroupName=group, retentionInDays=1)))
        for stream in ("basic", "timestamp", "later"):
            require(request("create-stream-" + stream, "create-log-stream", dict(logGroupName=group, logStreamName=stream)))
        require(put("create-control", "z-control", "NEVER_CONTROL_A"))
        describe("control-created")
        require(put("replace-control", "z-control", "NEVER_CONTROL_B", value="2", transform=transformation("Control", "2", unit="Count")))
        describe("control-replaced")
        put("failed-replacement-pattern", "z-control", "{ $.broken = }")
        describe("control-after-failed-replacement")

        json_messages = ['{"kind":"number","value":7}', '{"kind":"string","value":"11.5"}',
                         '{"kind":"bad","value":"banana"}', '{"kind":"missing"}']
        request("matcher-json-extraction", "test-metric-filter", {"filterPattern": '{ $.kind = * && $.value = * }', "logEventMessages": json_messages})
        request("matcher-space-extraction", "test-metric-filter", {"filterPattern": '[kind = "SPACE", value, bucket]',
                "logEventMessages": ["SPACE 13 A", "SPACE banana A", "SPACE", 'SPACE "17.5" A']})
        for kind, metric in (("number", "JsonNumber"), ("string", "JsonString"), ("bad", "JsonBad")):
            require(put("create-" + kind, "a-" + kind, '{ $.kind = "' + kind + '" && $.value = * }', metric, "$.value"))
            add_series(metric)
        put("create-missing-selector", "a-missing", '{ $.kind = "missing" }', "JsonMissing", "$.value")
        add_series("JsonMissing")
        require(put("create-space", "a-space", '[kind = "SPACE", value, bucket]', "Space", "$value"))
        add_series("Space")
        require(put("create-json-dimension", "b-json-dim", '{ $.kind = "dimension" && $.bucket = * && $.value = * }',
                    transform=transformation("JsonDimension", "$.value", dimensions={"Bucket": "$.bucket"})))
        add_series("JsonDimension", {"Bucket": "A"})
        add_series("JsonDimension", {"Bucket": "B"})
        require(put("create-space-dimension", "b-space-dim", '[kind = "SPACE", value, bucket]',
                    transform=transformation("SpaceDimension", "$value", dimensions={"Bucket": "$bucket"})))
        add_series("SpaceDimension", {"Bucket": "A"})
        require(put("create-default", "c-default", "DEFAULT_MATCH", transform=transformation("Default", "5", defaultValue=3)))
        add_series("Default")
        require(put("create-no-default", "c-no-default", "DEFAULT_MATCH", "NoDefault", "5"))
        add_series("NoDefault")
        require(put("create-timestamp", "d-timestamp", '{ $.kind = "timestamp" && $.value = * }', "Timestamp", "$.value"))
        add_series("Timestamp")
        require(put("create-unit", "d-unit", "UNIT_MATCH", transform=transformation("Unit", "19", unit="Count")))
        add_series("Unit")
        for name, metric, extra in [
            ("e-system", "System", {"emitSystemFieldDimensions": ["@aws.account", "@aws.region"]}),
            ("e-selection-true", "SelectTrue", {"fieldSelectionCriteria": '@aws.account = "' + account + '" AND @aws.region = "' + REGION + '"'}),
            ("e-selection-false", "SelectFalse", {"fieldSelectionCriteria": '@aws.account = "999999999999"'}),
            ("e-transformed", "Transformed", {"applyOnTransformedLogs": True})]:
            put("create-" + name, name, "SYSTEM_MATCH", metric, "23", **extra)
            add_series(metric, {"@aws.account": account, "@aws.region": REGION} if metric == "System" else None)
        describe("publication-filters-roundtrip")
        time.sleep(12)
        anchor = time.time_ns() // 1_000_000
        capture["clock_anchor_ms"] = anchor
        capture["timestamp_value_design"] = {"101": "five minutes before ingestion", "103": "at ingestion", "107": "five minutes after ingestion",
                                             "109": "25 hours old, expected expired with one-day retention", "113": "23 hours old",
                                             "127": "one hour future, accepted candidate", "131": "three hours future, rejected candidate"}
        basic = json_messages + ["SPACE 13 A", "SPACE banana A", "SPACE", 'SPACE "17.5" A',
                                '{"kind":"dimension","bucket":"A","value":29}', '{"kind":"dimension","bucket":"B","value":"31"}',
                                '{"kind":"dimension","value":37}', "DEFAULT_MATCH", "UNIT_MATCH", "SYSTEM_MATCH"]
        require(ingest("publish-basic", "basic", [(anchor + index, message) for index, message in enumerate(basic)]))
        require(ingest("publish-timestamp-offsets", "timestamp", [(anchor + offset * MINUTE, json.dumps({"kind": "timestamp", "value": value}))
                      for offset, value in ((-5, 101), (0, 103), (5, 107))]))
        ingest("publish-partial-expired", "timestamp", [(anchor - hours * 60 * MINUTE, json.dumps({"kind": "timestamp", "value": value}))
               for hours, value in ((25, 109), (23, 113))])
        ingest("publish-partial-future", "timestamp", [(anchor + hours * 60 * MINUTE, json.dumps({"kind": "timestamp", "value": value}))
               for hours, value in ((1, 127), (3, 131))])
        request("read-basic-ingested", "get-log-events", dict(logGroupName=group, logStreamName="basic", startFromHead=True))
        request("read-timestamp-ingested", "get-log-events", dict(logGroupName=group, logStreamName="timestamp", startFromHead=True))
        query("initial-statistics-data", anchor - 26 * 60 * MINUTE, anchor + 4 * 60 * MINUTE)

        # All quota/invalid controls use never-published metric names and patterns.
        for label, extra in [
            ("zero-transformations", {"metricTransformations": []}),
            ("two-transformations", {"metricTransformations": [transformation("Control"), transformation("Control")]}),
            ("bad-value", {"metricTransformations": [transformation("Control", "not-a-number")]}),
            ("invalid-unit", {"metricTransformations": [transformation("Control", unit="Widgets")]}),
            ("default-with-dimensions", {"metricTransformations": [transformation("Control", dimensions={"Bucket": "$.bucket"}, defaultValue=0)]}),
            ("literal-dimension", {"metricTransformations": [transformation("Control", dimensions={"Bucket": "literal"})]}),
            ("unknown-dimension-selector", {"metricTransformations": [transformation("Control", dimensions={"Bucket": "$.missing"})]}),
            ("four-dimensions", {"metricTransformations": [transformation("Control", dimensions={key: "$.bucket" for key in ("A", "B", "C", "D")})]}),
            ("system-invalid", {"emitSystemFieldDimensions": ["@aws.nope"]}),
            ("system-duplicate", {"emitSystemFieldDimensions": ["@aws.account", "@aws.account"]}),
            ("system-plus-three", {"emitSystemFieldDimensions": ["@aws.account"], "metricTransformations": [transformation("Control", dimensions={key: "$.bucket" for key in ("A", "B", "C")})]}),
            ("selection-invalid", {"fieldSelectionCriteria": "nonsense"})]:
            put(label, "z-invalid", '{ $.bucket = "NEVER_BUCKET" }', **extra)
        remove("z-invalid")
        describe("describe-prefix", filterNamePrefix="a-")
        describe("describe-metric-pair", metricName="Space", metricNamespace=namespace)
        describe("describe-name-only", metricName="Space")
        describe("describe-namespace-only", metricNamespace=namespace)
        page = describe("describe-page-one", limit=2)
        if page.get("output", {}).get("nextToken"):
            describe("describe-page-two", limit=2, nextToken=page["output"]["nextToken"])
        describe("describe-invalid-token", nextToken="invalid-owned-token")
        remove("absent", "delete-missing-filter")
        request("put-missing-group", "put-metric-filter", dict(logGroupName=group + "-missing", filterName="missing", filterPattern="", metricTransformations=[transformation("Control")]))
        request("describe-missing-group", "describe-metric-filters", dict(logGroupName=group + "-missing"))
        request("delete-missing-group", "delete-metric-filter", dict(logGroupName=group + "-missing", filterName="missing"))
        put("regex-three-terms", "q-three", '{ $.a = %NEVER_A% && $.b = %NEVER_B% && $.c = %NEVER_C% }', "Quota")
        put("regex-two-terms", "q-two", '{ $.a = %NEVER_A% && $.b = %NEVER_B% }', "Quota")
        for index in range(1, 7):
            put("regex-bearing-filter-" + str(index), "q-" + str(index), "%NEVER_REGEX_" + str(index) + "%", "Quota")
        describe("regex-quota-roundtrip", filterNamePrefix="q-")
        put("regex-replace-existing-at-quota", "q-1", "%NEVER_REGEX_REPLACED%", "Quota")
        remove("q-two")
        put("regex-after-deleting-two-term-filter", "q-after", "%NEVER_REGEX_AFTER%", "Quota")

        # Keep an entire idle minute before a nonmatching-only arrival minute.
        idle_start = ((time.time_ns() // 1_000_000) // MINUTE + 1) * MINUTE
        arrival_time = idle_start + MINUTE + 2000
        capture["windows"].append({"label": "intentional-no-arrivals", "start_ms": idle_start, "end_ms": idle_start + MINUTE})
        time.sleep(max(0, (arrival_time - time.time_ns() // 1_000_000) / 1000))
        require(ingest("publish-nonmatching-arrivals", "later", [(arrival_time, "NONMATCH_ONLY"), (arrival_time + 1, "NONMATCH_ONLY")]))
        require(put("replace-unit", "d-unit", "UNIT_MATCH", transform=transformation("Unit", "41", unit="Bytes")))
        describe("unit-replacement-roundtrip", filterNamePrefix="d-unit")
        require(ingest("publish-after-unit-change", "later", [(time.time_ns() // 1_000_000, "UNIT_MATCH")]))
        for attempt in range(7):
            time.sleep(30)
            query("poll-data-" + str(attempt), anchor - 26 * 60 * MINUTE, anchor + 4 * 60 * MINUTE)
        for metric, unit in (("JsonNumber", None), ("JsonString", None), ("Space", None), ("Default", None), ("Timestamp", None),
                             ("Unit", None), ("Unit", "Count"), ("Unit", "Bytes"), ("Unit", "Seconds")):
            parameters = {"Namespace": namespace, "MetricName": metric, "StartTime": iso(anchor - 26 * 60 * MINUTE),
                          "EndTime": iso(anchor + 4 * 60 * MINUTE), "Period": 300, "Statistics": ["Sum", "SampleCount", "Minimum", "Maximum", "Average"]}
            if unit:
                parameters["Unit"] = unit
            request("statistics-" + metric + "-" + str(unit), "get-metric-statistics", parameters, service="cloudwatch")
        request("list-owned-metrics", "list-metrics", {"Namespace": namespace}, service="cloudwatch")
    finally:
        cleaning = True
        checks = {}
        errors = []
        if owned:
            for name in sorted(filters):
                try:
                    response = remove(name, "cleanup-filter-" + name)
                    checks["filter-" + name] = response["code"] in ("Success", "ResourceNotFoundException")
                except Exception as error:
                    errors.append({"resource": name, "error": type(error).__name__})
            try:
                absent_filters = describe("cleanup-filters-empty")
                checks["filters_empty"] = absent_filters["code"] == "Success" and absent_filters["output"].get("metricFilters") == []
            except Exception as error:
                errors.append({"resource": "filter-list", "error": type(error).__name__})
            try:
                deleted = request("cleanup-group", "delete-log-group", dict(logGroupName=group))
                absent = request("cleanup-group-absent", "describe-log-groups", dict(logGroupNamePrefix=group))
                missing = describe("cleanup-filter-group-missing")
                checks["group_absent"] = deleted["code"] in ("Success", "ResourceNotFoundException") and absent["code"] == "Success" and absent["output"].get("logGroups") == []
                checks["filter_group_missing"] = missing["code"] == "ResourceNotFoundException"
            except Exception as error:
                errors.append({"resource": "group", "error": type(error).__name__})
        capture["cleanup"] = {"verified": owned and bool(checks) and all(checks.values()) and not errors,
                              "checks": checks, "errors": errors,
                              "publisher_state": "No continuing publisher: owned metric filters and group removed when checks pass; no external publisher or worker was created. Previously accepted asynchronous data may still arrive.",
                              "residual": "Custom metric data has no DeleteMetric API and expires according to CloudWatch retention; no ongoing publication or deletable resources remain when verified."}
        capture["elapsed_seconds"] = round(time.monotonic() - started, 3)
        save()
        print(json.dumps({"output": str(args.output), "request_counts": capture["request_counts"], "cleanup_verified": capture["cleanup"]["verified"],
                          "positive_point_observations": len(capture["positive_points"])}), flush=True)
        if owned and not capture["cleanup"]["verified"]:
            raise RuntimeError("Owned cleanup not verified")


if __name__ == "__main__":
    main()
