#!/usr/bin/env python3
"""Finite owned CloudWatch distribution experiment; accepted metrics cannot be deleted."""
import argparse
import datetime
import json
import os
from pathlib import Path
import time
import uuid

from aws_cli import run, result


REGION = "us-east-1"
BASIC = ["SampleCount", "Sum", "Minimum", "Maximum", "Average"]
PERCENTILES = ["p0", "p1", "p10", "p25", "p40", "p50", "p60", "p75", "p90", "p100"]
TRIMMED = ["tm90", "tc90", "ts90", "IQM", "wm90", "TM(25%:75%)", "TC(25%:75%)", "TS(25%:75%)", "WM(25%:75%)", "PR(2:10)"]
FIXED = ["PR(:2)", "PR(:5)", "PR(:10)", "PR(2:10)", "TM(2:10)", "TC(2:10)", "TS(2:10)", "TM(:100%)", "TC(:100%)", "TS(:100%)"]
REFERENCES = ["https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Statistics-definitions.html"] + [
    "https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_" + name + ".html"
    for name in ["MetricDatum", "StatisticSet", "PutMetricData", "GetMetricStatistics", "GetMetricData", "MetricStat"]]


def timestamp(seconds):
    return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).isoformat()


def distributions(anchor):
    rows = []

    def add(name, minute=0, **fields):
        rows.append(dict(MetricName=name, Timestamp=timestamp(anchor + minute * 60), **fields))

    # Count rescaling and independent publications distinguish weighted distributions
    # from sample-index interpolation, rounding, and publication-order effects.
    add("Weighted", Values=[2, 10], Counts=[2, 3])
    add("Weighted", 1, Values=[2, 10], Counts=[20, 30])
    add("Weighted", 2, Values=[2, 10], Counts=[3, 2])
    for value in [10, 2, 10, 2, 10]:
        add("Expanded", Value=value)
    add("Expanded", 1, Values=[10, 2, 10, 2, 10])
    add("Fractional", Values=[2, 10], Counts=[0.2, 0.3])
    add("Fractional", 1, Values=[2, 10], Counts=[0.5, 1.5])
    add("Fractional", 2, Values=[2, 10], Counts=[0.02, 0.03])
    add("Equal", Values=[7, 7, 7], Counts=[1, 1, 1])
    add("Equal", 1, Values=[7], Counts=[2.5])
    add("Uniform", Values=list(range(1, 11)))
    add("Uniform", 1, Values=[1, 3, 7, 11, 23], Counts=[1, 2, 4, 2, 1])
    add("Tight", Values=[9.9, 9.95, 10, 10.05, 10.1])
    add("Tight", 1, Values=[1.99, 2, 2.01], Counts=[1, 2, 1])
    add("Scaled", Values=[20, 100], Counts=[2, 3])
    add("Scaled", 1, Values=[0.2, 1], Counts=[2, 3])
    add("Eligible", StatisticValues=dict(SampleCount=3, Sum=21, Minimum=7, Maximum=7))
    add("Eligible", 1, StatisticValues=dict(SampleCount=2.5, Sum=17.5, Minimum=7, Maximum=7))
    add("Eligible", 2, StatisticValues=dict(SampleCount=1, Sum=9, Minimum=9, Maximum=9))
    add("General", StatisticValues=dict(SampleCount=3, Sum=15, Minimum=1, Maximum=9))
    add("General", 1, StatisticValues=dict(SampleCount=3, Sum=22, Minimum=7, Maximum=7))
    add("General", 2, StatisticValues=dict(SampleCount=1, Sum=3, Minimum=1, Maximum=2))
    add("ZeroEdges", Values=[1, 2, 10, 20], Counts=[0, 2, 3, 0])
    add("ZeroEdges", 1, Values=[1, 20], Counts=[0, 0])
    add("ZeroEdges", 1, Value=5)
    add("Mixed", Values=[2, 10], Counts=[2, 3])
    add("Mixed", StatisticValues=dict(SampleCount=3, Sum=15, Minimum=1, Maximum=9))
    add("Mixed", 1, Values=[2, 10], Counts=[2, 3])
    add("Mixed", 1, StatisticValues=dict(SampleCount=3, Sum=21, Minimum=7, Maximum=7))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-seconds", type=int, default=720)
    parser.add_argument("--follow-up", action="store_true",
                        help="Reuse the exact owned scope in --output; the zero phase publishes once")
    parser.add_argument("--follow-up-phase", choices=["boundaries", "held-out", "zero", "empty-fixed", "zero-bin"], default="boundaries")
    args = parser.parse_args()
    if not 120 <= args.max_seconds <= 720:
        parser.error("--max-seconds must be 120..720")
    if "testdata" in args.output.parts:
        parser.error("Raw output must remain outside testdata")
    started = time.monotonic()
    deadline = started + args.max_seconds
    namespace = "Stackd/NativeStatistics/" + uuid.uuid4().hex
    anchor = int(time.time() // 60) * 60 - 600
    rows = distributions(anchor)
    names = sorted({row["MetricName"] for row in rows} | {"AllZero"})
    env = dict(os.environ, AWS_DEFAULT_REGION=REGION, AWS_REGION=REGION,
               AWS_MAX_ATTEMPTS="1", AWS_RETRY_MODE="standard", AWS_PAGER="")
    capture = dict(source="Native AWS CLI through shared aws_cli.run/result; raw debug logs discarded",
        retrieved_at=timestamp(time.time()), region=REGION, primary_references=REFERENCES,
        identity_relationships=dict(expected_caller_account=args.account),
        scope=dict(namespace=namespace, metric_names=names, maximum_distinct_series=12, anchor_seconds=anchor),
        timing=dict(started_ms=time.time_ns() // 1_000_000, max_seconds=args.max_seconds),
        request_counts=dict(sts=0, cloudwatch=0, total=0, maximum=150, automatic_retries=False, automatic_pagination=False),
        observations=[], cleanup=dict(deletable_resources_created=[], continuing_publishers=False),
        limitations=["Bounded visibility is not proof of permanent absence.",
                     "Quantile and trimmed statistics may be approximate; no undocumented histogram algorithm is assumed.",
                     "Accepted samples cannot be deleted; no alarms, streams, customer resources or account configuration are changed."])
    if args.follow_up:
        capture = json.loads(args.output.read_text())
        if capture["identity_relationships"].get("verified_caller_account") != args.account or capture["region"] != REGION:
            raise RuntimeError("Capture account/region mismatch")
        namespace = capture["scope"]["namespace"]
        anchor = capture["scope"]["anchor_seconds"]
        names = capture["scope"]["metric_names"]
        if not namespace.startswith("Stackd/NativeStatistics/") or len(names) > 12:
            raise RuntimeError("Capture is not a bounded owned statistics scope")
    initial_requests = capture["request_counts"]["total"]

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + "\n")

    def request(label, operation, parameters, service="cloudwatch"):
        remaining = deadline - time.monotonic()
        if remaining < 8 or capture["request_counts"]["total"] >= 150 or (
                args.follow_up and capture["request_counts"]["total"] - initial_requests >=
                (16 if args.follow_up_phase == "zero" else 4 if args.follow_up_phase == "empty-fixed" else 1 if args.follow_up_phase == "zero-bin" else 20)):
            raise TimeoutError("Owned experiment request/time bound reached")
        capture["request_counts"][service] += 1
        capture["request_counts"]["total"] += 1
        entry = dict(label=label, service=service, operation=operation, input=parameters,
                     request_started_ms=time.time_ns() // 1_000_000)
        capture["observations"].append(entry)
        save()
        try:
            process = run(service, operation, parameters, env, options=["--debug", "--no-paginate",
                          "--cli-connect-timeout", "5", "--cli-read-timeout", "20"], timeout=min(30, remaining - 2))
            response = result(process, debug=True)
            if service == "sts" and response["code"] == "Success":
                response["output"] = {"Account": response["output"]["Account"]}
            entry["result"] = response
        except Exception as error:
            entry["result"] = dict(code=type(error).__name__, message="Bounded CLI transport failed; admission unknown for a timed-out publication")
            raise
        finally:
            entry["request_finished_ms"] = time.time_ns() // 1_000_000
            save()
        print(label + ": " + response["code"], flush=True)
        return response

    def queries(stats, selected=names):
        return [dict(Id="q" + str(index), MetricStat=dict(Metric=dict(Namespace=namespace, MetricName=name),
                    Period=60, Stat=stat)) for index, (name, stat) in enumerate((name, stat) for name in selected for stat in stats)]

    def data(label, metric_queries):
        return request(label, "get-metric-data", dict(MetricDataQueries=metric_queries, StartTime=timestamp(anchor),
                       EndTime=timestamp(anchor + 180), ScanBy="TimestampAscending", MaxDatapoints=100800))

    try:
        if not args.follow_up or args.follow_up_phase != "zero-bin":
            identity = request("verify-caller", "get-caller-identity", {}, "sts")
            if identity.get("output", {}).get("Account") != args.account:
                raise RuntimeError("Caller account verification failed; nothing published")
            capture["identity_relationships"]["verified_caller_account"] = args.account
        if args.follow_up:
            if args.follow_up_phase == "zero-bin":
                # Exactly one authorized read; reuse the five verified caller
                # observations already retained for this owned scope.
                bounds = [str(lower) + ":" + str(upper)
                    for lower in [0.99, 1, 1.01, 1.099, 1.1, 1.11] for upper in [1.99, 2, 2.05, 2.15]]
                data("follow-up-zero-count-bin", queries([family + "(" + bound + ")"
                    for bound in bounds for family in ["TM", "TC", "TS", "WM"]], ["ZeroEdges", "Weighted", "Uniform"]))
                return
            if args.follow_up_phase == "empty-fixed":
                end = max(capture["zero_follow_up_anchors"]) + 60
                bounds = ["0:0.5", "0:1", "0.1:0.5", "0.5:1", "1:1.5", "1:2", "0:3", "3:8", "5:6", "8:9",
                          "11:15", "50:70", "100:120", "200:300", ":0.5", ":1", "15:", "0:0", "2:2", "0:0.1"]
                stats = [family + "(" + bound + ")" for bound in bounds for family in ["WM", "TM", "TC", "TS"]]
                for index in range(0, len(stats), 40):
                    request("follow-up-empty-fixed-" + str(index // 40), "get-metric-data",
                        dict(MetricDataQueries=queries(stats[index:index + 40]), StartTime=timestamp(anchor),
                             EndTime=timestamp(end), ScanBy="TimestampAscending", MaxDatapoints=100800))
                request("follow-up-empty-fixed-statistics", "get-metric-statistics", dict(Namespace=namespace,
                    MetricName="Weighted", StartTime=timestamp(anchor), EndTime=timestamp(end), Period=60,
                    ExtendedStatistics=["WM(0:1)", "WM(3:8)", "WM(11:15)", "WM(100:120)",
                                        "WM(0:3)", "WM(0:0)", "WM(2:2)", "WM(0:0.1)"]))
                return
            if args.follow_up_phase == "zero":
                previous = [datetime.datetime.fromisoformat(row["Timestamp"]).timestamp()
                    for observation in capture["observations"] if observation["operation"] == "put-metric-data"
                    for row in observation["input"]["MetricData"]]
                anchor = max(int(time.time() // 60) * 60 - 120, int(max(previous)) + 60)
                fields = {
                    "Weighted": dict(Values=[0, 2, 10], Counts=[1, 2, 3]),
                    "Expanded": dict(Values=[0, 2, 2, 10, 10, 10]),
                    "Fractional": dict(Values=[0, 2, 10], Counts=[0.5, 0.5, 1]),
                    "Equal": dict(Values=[0, 0], Counts=[1, 1]),
                    "Uniform": dict(Values=[0, 1, 2, 3, 4]),
                    "Tight": dict(Values=[0, 0.1, 0.2]),
                    "Scaled": dict(Values=[0, 20, 100], Counts=[1, 2, 3]),
                    "Eligible": dict(Values=[0, 2, 10], Counts=[0, 2, 3]),
                    "General": dict(Values=[0, 0, 5], Counts=[0, 0, 1]),
                    "ZeroEdges": dict(Values=[0, 0], Counts=[0, 0]),
                    "AllZero": dict(Value=0),
                    "Mixed": dict(Value=0),
                }
                zero_rows = [dict(MetricName=name, Timestamp=timestamp(anchor), **fields[name]) for name in names]
                zero_rows.append(dict(MetricName="Mixed", Timestamp=timestamp(anchor),
                    StatisticValues=dict(SampleCount=3, Sum=21, Minimum=7, Maximum=7)))
                capture.setdefault("zero_follow_up_anchors", []).append(anchor)
                response = request("follow-up-publish-zero-distributions", "put-metric-data",
                                   dict(Namespace=namespace, MetricData=zero_rows))
                if response["code"] != "Success":
                    raise RuntimeError("Zero-distribution publication rejected")
                for attempt in range(8):
                    response = data("follow-up-zero-visibility-" + str(attempt), queries(["SampleCount"]))
                    visible = sum(bool(item.get("Values")) for item in response.get("output", {}).get("MetricDataResults", []))
                    if visible == len(names):
                        break
                    time.sleep(8)
                all_stats = list(dict.fromkeys(BASIC + PERCENTILES + TRIMMED + FIXED))
                data("follow-up-zero-distribution-data", queries(all_stats))
                for name, stats in [("Weighted", PERCENTILES), ("Eligible", TRIMMED), ("Equal", FIXED), ("Fractional", TRIMMED)]:
                    request("follow-up-zero-statistics-" + name, "get-metric-statistics", dict(Namespace=namespace,
                        MetricName=name, StartTime=timestamp(anchor), EndTime=timestamp(anchor + 60), Period=60,
                        Statistics=BASIC, ExtendedStatistics=stats))
                data("follow-up-zero-terminal", queries(["p0", "p1", "p25", "p50", "p90", "p100", "tm90",
                     "tc90", "ts90", "wm90", "PR(:0)", "PR(0:2)", "TM(0:2)", "TC(0:2)", "TS(0:2)", "WM(0:2)"]))
                return
            if args.follow_up_phase == "held-out":
                bounds = ["3%:17%", "11%:23%", "26%:39%", "41%:59%", "51%:87%", "25%:40%", "40%:75%", "17%:17%"]
                data("follow-up-winsor-held-out", queries([family + "(" + bound + ")"
                    for bound in bounds for family in ["WM", "TS", "TC"]]))
                return
            percentage_ranges = [":" + str(value) + "%" for value in [10, 25, 40, 50, 60, 75, 90]]
            percentage_ranges += [str(value) + "%:" for value in [10, 25, 40, 50, 60, 75, 90]]
            fixed_ranges = ["1.99:2.02", "2.05:9.97", "9.9:10.05", "2:5", "3:8", ":2.05",
                            "9.97:", "2.14:9.84", ":0", "100:", "7:7", ":7", "7:"]
            for label, ranges, families in [("winsor-percent", percentage_ranges, ["WM", "TS", "TC"]),
                                           ("fixed-range", fixed_ranges, ["WM", "TM", "TS", "TC", "PR"])]:
                stats = [family + "(" + bounds + ")" for bounds in ranges for family in families]
                for index in range(0, len(stats), 30):
                    data("follow-up-" + label + "-" + str(index // 30), queries(stats[index:index + 30]))
            for name in ["Weighted", "Tight"]:
                request("follow-up-statistics-" + name, "get-metric-statistics", dict(Namespace=namespace,
                    MetricName=name, StartTime=timestamp(anchor), EndTime=timestamp(anchor + 180), Period=60,
                    ExtendedStatistics=["WM(:25%)", "WM(25%:)", "TM(2.05:9.97)", "TS(2.05:9.97)",
                                        "TC(2.05:9.97)", "WM(2.05:9.97)", "PR(2.05:9.97)"]))
            return
        initial = request("publish-independent-distributions", "put-metric-data", dict(Namespace=namespace, MetricData=rows))
        if initial["code"] != "Success":
            raise RuntimeError("Primary distributions were rejected")
        request("publish-all-zero-counts", "put-metric-data", dict(Namespace=namespace, MetricData=[
            dict(MetricName="AllZero", Timestamp=timestamp(anchor), Values=[1, 2], Counts=[0, 0]),
            dict(MetricName="AllZero", Timestamp=timestamp(anchor + 60), Values=[0], Counts=[0])]))
        visibility_deadline = min(deadline - 120, time.monotonic() + 180)
        for attempt in range(12):
            response = data("visibility-" + str(attempt), queries(["SampleCount"]))
            visible = sum(bool(item.get("Values")) for item in response.get("output", {}).get("MetricDataResults", []))
            if visible == len(names) or time.monotonic() >= visibility_deadline:
                break
            time.sleep(min(10, max(0, visibility_deadline - time.monotonic())))
        for name in names:
            for group, stats in [("percentile", PERCENTILES), ("trimmed", TRIMMED), ("fixed", FIXED)]:
                request("statistics-" + name + "-" + group, "get-metric-statistics", dict(Namespace=namespace,
                    MetricName=name, StartTime=timestamp(anchor), EndTime=timestamp(anchor + 180), Period=60,
                    Statistics=BASIC, ExtendedStatistics=stats))
        data("data-parity", queries(list(dict.fromkeys(BASIC + PERCENTILES + TRIMMED + FIXED))))
        # Probe distribution boundaries on two independent input distributions, without
        # fitting an assumed sketch. PR and percentile samples retain their raw precision.
        boundary_stats = ["PR(:" + str(value) + ")" for value in [1.97, 1.98, 1.99, 2, 2.01, 2.02, 2.03, 9.8, 9.85, 9.9, 9.95, 10, 10.05, 10.1, 10.15, 10.2]]
        boundary_stats += ["p" + str(value) for value in [0.1, 5, 20, 30, 39, 39.9, 40.1, 41, 55, 70, 80, 95, 99, 99.9]]
        data("data-boundary-sweep", queries(boundary_stats, ["Weighted", "Fractional", "Tight", "ZeroEdges", "Scaled"]))
        time.sleep(min(20, max(0, deadline - time.monotonic() - 40)))
        data("data-terminal-recheck", queries(["SampleCount", "p0", "p50", "p90", "p100", "tm90", "tc90", "PR(:2)"]))
        capture["completed"] = True
    finally:
        admitted = set()
        uncertain = set()
        for observation in capture["observations"]:
            if observation["operation"] != "put-metric-data":
                continue
            code = observation.get("result", {}).get("code")
            target = admitted if code == "Success" else uncertain if code in (None, "CLITimeout") else set()
            target.update(row["MetricName"] for row in observation["input"]["MetricData"])
        capture["scope"].update(admitted_series_count=len(admitted), admitted_metric_names=sorted(admitted),
                                uncertain_metric_names=sorted(uncertain - admitted))
        if args.follow_up:
            capture.setdefault("follow_up_runs", []).append(dict(started_ms=int(time.time() * 1000 - (time.monotonic() - started) * 1000),
                finished_ms=time.time_ns() // 1_000_000, elapsed_seconds=round(time.monotonic() - started, 3),
                requests=capture["request_counts"]["total"] - initial_requests, read_only=args.follow_up_phase != "zero",
                phase=args.follow_up_phase))
        else:
            capture["timing"].update(finished_ms=time.time_ns() // 1_000_000, elapsed_seconds=round(time.monotonic() - started, 3))
        capture["request_counts"]["aws_response_count"] = sum("http_status" in item.get("result", {}) for item in capture["observations"])
        capture["cleanup"].update(finally_executed=True, verified=not uncertain,
            residual_series_count=len(admitted), residual_namespace=namespace,
            residual="Accepted custom metric samples only; no DeleteMetric API exists. No deletable resources were created. This finite process has stopped publishing.")
        save()
    print(json.dumps(dict(capture=str(args.output), requests=capture["request_counts"], elapsed_seconds=capture["timing"]["elapsed_seconds"])))


if __name__ == "__main__":
    main()
