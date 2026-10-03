#!/usr/bin/env python3
"""Capture one owned REST API's service metrics, with real Lambda and bounded publication polls."""
import argparse
import datetime
import json
from pathlib import Path
import shlex
import sys
import time
import uuid

import apigateway_probe
import apigateway_rest_authorizer_probe
from apigateway_probe import Probe, REGION, now
from apigateway_rest_authorizer_probe import collect_logs, create_function, http, put_route


METRICS = ("Count", "4XXError", "5XXError", "Latency", "IntegrationLatency")
STATISTICS = ("Sum", "SampleCount", "Minimum", "Maximum", "Average")
HANDLER = '''import json
import time

def handler(event, context):
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    query = event.get("queryStringParameters") or {}
    status = int(query.get("status", "200"))
    delay_ms = min(100, max(0, int(query.get("delay_ms", "0"))))
    record = {"probe_kind": "backend", "invocation": context.aws_request_id,
        "label": headers.get("x-probe"), "status": status, "delay_ms": delay_ms,
        "api_request_id": event["requestContext"]["requestId"],
        "stage": event["requestContext"]["stage"], "resource": event["resource"],
        "path": event["path"], "method": event["httpMethod"]}
    print(json.dumps(record), flush=True)
    time.sleep(delay_ms / 1000)
    return {"statusCode": status, "headers": {"Content-Type": "application/json"},
        "body": json.dumps(record)}
'''


class MetricsProbe(Probe):
    def save(self):
        actor = {"kind": "capture-owner", "arn": self.data["identity"]["Arn"]}
        for observation in self.data["observations"]:
            observation.setdefault("actor", actor)
        super().save()


def utc(timestamp):
    return datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)


def request(p, label, path, phase):
    if len(p.data["http"]) >= p.data["bounds"]["execution_requests"]:
        raise RuntimeError("REST execution request bound reached")
    return http(p, label, path, phase=phase)


def patch(p, label, stage, operations, required=True):
    return p.call(label, "apigateway", "update_stage", {
        "restApiId": p.data["owned"]["rest_api"], "stageName": stage,
        "patchOperations": operations}, required=required)


def setup(p):
    name = "stackd-restmetrics-" + uuid.uuid4().hex[:10]
    p.data.update(prefix=name, scope="Owned REST default/API/stage and detailed method metrics; no API Gateway logging changes, keys, authorizers or account mutations",
        bounds={"apis": 1, "functions": 1, "roles": 1, "log_groups": 1, "stages": 3,
            "execution_requests": 40, "readiness_requests": 8,
            "metric_polls_per_cohort": 12, "metric_poll_interval_seconds": 30,
            "metric_snapshot_queries_per_cohort": 25, "list_metrics_pages": 2,
            "log_polls": 12, "log_pages_per_poll": 4, "log_poll_interval_seconds": 5,
            "lambda_creation_attempts": 15, "lambda_readiness_attempts": 15},
        documentation=[
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-metrics-and-dimensions.html",
            "https://docs.aws.amazon.com/apigateway/latest/api/API_UpdateStage.html",
            "https://docs.aws.amazon.com/apigateway/latest/api/API_MethodSetting.html"],
        pinned_references={
            "sdk_model": {"repository": "https://github.com/aws/aws-sdk-go-v2",
                "revision": "113bc91bf12edc3af1d3aba1c70be28494d54c2a",
                "path": "codegen/sdk-codegen/aws-models/api-gateway.json",
                "sha256": "3480a6cb853f4d34295f7a88b2121d4e5735683558dfbb8e075c0778db9e1cb9"}},
        documented_inputs={"namespace": "AWS/ApiGateway", "metrics": list(METRICS),
            "default_dimensions": [["ApiName"], ["ApiName", "Stage"]],
            "detailed_dimensions": ["ApiName", "Stage", "Method", "Resource"],
            "rest_control": "UpdateStage methodSettings metricsEnabled via /metrics/enabled (not V2 DetailedMetricsEnabled)",
            "count_statistic": "SampleCount", "error_statistics": "Sum=count; Average=rate",
            "publication": "Documentation says every minute; capture timing is observational only"},
        probe_source=Path(__file__).read_text(), handler_source=HANDLER,
        base_helper_source=Path(apigateway_probe.__file__).read_text(),
        runtime_helper_source=Path(apigateway_rest_authorizer_probe.__file__).read_text(),
        executed_command=shlex.join([sys.executable, *sys.argv]),
        cohorts=[], metric_queries=[], metric_publication=[], invocation_logs=[], uncertainties=[],
        log_start_ms=int(time.time() * 1000))
    p.save()
    function, _ = create_function(p, HANDLER)
    p.data["owned"]["log_group"] = "/aws/lambda/" + name
    api = p.required("create-rest", "apigateway", "create_rest_api", {
        "name": name, "endpointConfiguration": {"types": ["REGIONAL"]}}, own=("rest_api", "id"))["id"]
    p.data["owned"].update(rest_endpoint=f"https://{api}.execute-api.{REGION}.amazonaws.com",
        api_name=name, stages=["default", "on", "off"], resources={})
    root = p.required("get-resources", "apigateway", "get_resources", {"restApiId": api})["items"][0]["id"]
    uri = f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function['FunctionArn']}/invocations"
    p.required("permission-rest", "lambda", "add_permission", {
        "FunctionName": name, "StatementId": "rest", "Action": "lambda:InvokeFunction",
        "Principal": "apigateway.amazonaws.com", "SourceAccount": p.data["account"],
        "SourceArn": f"arn:aws:execute-api:{REGION}:{p.data['account']}:{api}/*"})
    for part in ("sample", "quiet", "guard"):
        resource = p.required("resource-" + part, "apigateway", "create_resource", {
            "restApiId": api, "parentId": root, "pathPart": part})
        if part == "sample":
            resource = p.required("resource-sample-value", "apigateway", "create_resource", {
                "restApiId": api, "parentId": resource["id"], "pathPart": "{value}"})
        p.data["owned"]["resources"][resource["path"]] = resource["id"]
        put_route(p, api, resource["id"], part, "GET", None, uri)
    p.required("guard-require-iam", "apigateway", "update_method", {
        "restApiId": api, "resourceId": p.data["owned"]["resources"]["/guard"], "httpMethod": "GET",
        "patchOperations": [
            {"op": "replace", "path": "/authorizationType", "value": "AWS_IAM"}]})
    deployment = p.required("create-deployment", "apigateway", "create_deployment", {
        "restApiId": api}, own=("deployment", "id"))["id"]
    for stage in p.data["owned"]["stages"]:
        p.required("create-stage-" + stage, "apigateway", "create_stage", {
            "restApiId": api, "stageName": stage, "deploymentId": deployment})
    patch(p, "metrics-on-inherited-with-quiet-off", "on", [
        {"op": "replace", "path": "/*/*/metrics/enabled", "value": "true"},
        {"op": "replace", "path": "/~1quiet/GET/metrics/enabled", "value": "false"}])
    patch(p, "metrics-off-inherited-with-sample-on", "off", [
        {"op": "replace", "path": "/*/*/metrics/enabled", "value": "false"},
        {"op": "replace", "path": "/~1sample~1{value}/GET/metrics/enabled", "value": "true"}])
    patch(p, "metrics-invalid-boolean", "off", [
        {"op": "replace", "path": "/*/*/metrics/enabled", "value": "invalid"}], required=False)
    for stage in p.data["owned"]["stages"]:
        p.required("get-stage-" + stage, "apigateway", "get_stage", {"restApiId": api, "stageName": stage})
    for attempt in range(p.data["bounds"]["readiness_requests"]):
        result = request(p, "ready-" + str(attempt), "/default/sample/ready", "readiness")
        if result.get("status") == 200 and result.get("body", {}).get("probe_kind") == "backend":
            break
        time.sleep(3)
    else:
        raise RuntimeError("REST readiness bound reached")


def dimensions(p, stage=None, resource=None):
    values = {"ApiName": p.data["owned"]["api_name"]}
    if stage:
        values["Stage"] = stage
    if resource:
        values.update(Method="GET", Resource=resource)
    return [{"Name": key, "Value": value} for key, value in sorted(values.items())]


def metric(p, cohort, label, name, dims, purpose):
    parameters = {"Namespace": "AWS/ApiGateway", "MetricName": name, "Dimensions": dims,
        "StartTime": datetime.datetime.fromisoformat(cohort["window"]["start"]),
        "EndTime": datetime.datetime.fromisoformat(cohort["window"]["end"]),
        "Period": 60, "Statistics": list(STATISTICS)}
    query = {"observation_label": label, "cohort": cohort["name"], "purpose": purpose,
        "namespace": parameters["Namespace"], "metric_name": name, "dimensions": dims,
        "window": cohort["window"], "statistics": list(STATISTICS), "unit_filter": None}
    p.data["metric_queries"].append(query)
    result = p.required(label, "cloudwatch", "get_metric_statistics", parameters)
    query["datapoints_present"] = bool(result["Datapoints"])
    query["observed_units"] = sorted({point.get("Unit", "<omitted>") for point in result["Datapoints"]})
    p.save()
    return result


def poll(p, cohort):
    attempt = cohort["polls"]
    if attempt >= p.data["bounds"]["metric_polls_per_cohort"]:
        return False
    cohort["polls"] += 1
    result = metric(p, cohort, f"metrics-{cohort['name']}-poll-{attempt}", "Count",
        dimensions(p, cohort["stage"]), "publication-sentinel")
    samples = sum(point["SampleCount"] for point in result["Datapoints"])
    observation = p.data["observations"][-1]
    p.data["metric_publication"].append({"cohort": cohort["name"], "poll": attempt,
        "observation_label": observation["label"], "observed_at": observation["finished_at"],
        "seconds_after_last_request": (datetime.datetime.fromisoformat(observation["finished_at"]) -
            datetime.datetime.fromisoformat(cohort["finished_at"])).total_seconds(),
        "datapoints_present": bool(result["Datapoints"]), "sample_count": samples})
    complete = samples >= len(cohort["request_labels"])
    if complete:
        cohort["count_complete_observation"] = observation["label"]
    p.save()
    return complete


def cohort(p, stage):
    # Separate real UTC minutes prevent API-level aggregation from mixing cohorts or readiness.
    target = (int(time.time()) // 60 + 1) * 60 + 2
    time.sleep(max(0, target - time.time()))
    start = int(time.time()) // 60 * 60
    value = {"name": "rest-" + stage, "stage": stage, "started_at": now(),
        "window": {"start": utc(start).isoformat(), "end": utc(start + 60).isoformat(), "period": 60},
        "request_labels": [], "polls": 0,
        "settings_observation": "get-stage-" + stage}
    p.data["cohorts"].append(value)
    for suffix, path in (
            ("success", "/sample/alpha"),
            ("delayed-success", "/sample/beta?delay_ms=40"),
            ("backend-4xx", "/sample/gamma?status=400"),
            ("backend-5xx", "/sample/delta?status=503"),
            ("quiet-success", "/quiet"),
            ("gateway-rejection", "/guard")):
        label = value["name"] + "-" + suffix
        value["request_labels"].append(label)
        request(p, label, "/" + stage + path, value["name"])
    value["finished_at"] = now()
    if time.time() >= start + 60:
        raise RuntimeError("Cohort crossed its isolated UTC minute")
    poll(p, value)
    p.save()


def capture_metrics(p):
    for value in p.data["cohorts"]:
        while "count_complete_observation" not in value and value["polls"] < p.data["bounds"]["metric_polls_per_cohort"]:
            if poll(p, value):
                break
            time.sleep(p.data["bounds"]["metric_poll_interval_seconds"])
        if "count_complete_observation" not in value:
            p.data["uncertainties"].append(value["name"] + ": stage Count did not reach cohort request total within publication bound")
        for group, dims in [("api", dimensions(p)), ("stage", dimensions(p, value["stage"]))] + [
                (name, dimensions(p, value["stage"], resource)) for name, resource in
                (("sample", "/sample/{value}"), ("quiet", "/quiet"), ("guard", "/guard"))]:
            for name in METRICS:
                metric(p, value, f"metrics-{value['name']}-{group}-{name}", name, dims, "final-snapshot")
    # Discovery is unnecessary when the documented method dimensions returned actual datapoints.
    detailed = [query for query in p.data["metric_queries"] if query["purpose"] == "final-snapshot"
        and query["metric_name"] == "Count" and query["cohort"] != "rest-default"
        and any(item == {"Name": "Resource", "Value": "/sample/{value}"} for item in query["dimensions"])]
    if not all(query["datapoints_present"] for query in detailed):
        token = None
        for page in range(p.data["bounds"]["list_metrics_pages"]):
            parameters = {"Namespace": "AWS/ApiGateway", "MetricName": "Count", "Dimensions": dimensions(p)}
            if token:
                parameters["NextToken"] = token
            result = p.required("discover-owned-Count-" + str(page), "cloudwatch", "list_metrics", parameters)
            token = result.get("NextToken")
            if not token:
                break
        p.data["uncertainties"].append("At least one configured sample detailed Count series was absent in the bounded snapshot; owned Count discovery retained without another traffic/capture round")
    p.save()


def correlate(p):
    rows = {row["label"]: row for row in p.data["http"]}
    for value in p.data["cohorts"]:
        value["request_witnesses"] = []
        for label in value["request_labels"]:
            row = rows[label]
            records = [entry for entry in p.data["invocation_logs"] if entry["record"].get("label") == label]
            value["request_witnesses"].append({"http_label": label, "http_status": row["result"].get("status"),
                "response_backend_invocation": row["result"].get("body", {}).get("invocation"),
                "backend_log_event_ids": [entry["event_id"] for entry in records],
                "backend_invocations": [entry["record"]["invocation"] for entry in records],
                "noninvocation_scope": None if records else p.data.get("log_collection", {}).get("absence_scope", "Log completeness not established")})
    p.data["totals"] = {"execution_requests": len(p.data["http"]),
        "semantic_requests": sum(len(value["request_labels"]) for value in p.data["cohorts"]),
        "readiness_requests": sum(row["phase"] == "readiness" for row in p.data["http"]),
        "metric_polls": sum(value["polls"] for value in p.data["cohorts"]),
        "metric_snapshot_queries": sum(query["purpose"] == "final-snapshot" for query in p.data["metric_queries"]),
        "get_metric_statistics_calls": sum(row["operation"] == "GetMetricStatistics" for row in p.data["observations"]),
        "list_metrics_calls": sum(row["operation"] == "ListMetrics" for row in p.data["observations"]),
        "backend_log_records": len(p.data["invocation_logs"])}
    p.data["limitations"] = [
        "Absent datapoints mean absent in the named bounded UTC-window query, not permanently disabled or proof of zero",
        "Publication latency is the interval between retained polls, not a deterministic service deadline",
        "Handler delay is an input; observed IntegrationLatency/Latency datapoints are the evidence, not exact-duration assertions",
        "Gateway noninvocation claims are limited to stable paginated owned-function logs with the final backend marker",
        "Only unsigned AWS_IAM rejection was exercised; no custom authorizer, cache, usage-plan/key, throttling, logging or account-level configuration"]
    p.save()


def run(p):
    setup(p)
    for stage in p.data["owned"]["stages"]:
        cohort(p, stage)
    final = next(row["result"]["body"]["invocation"] for row in reversed(p.data["http"])
        if isinstance(row["result"].get("body"), dict) and row["result"]["body"].get("invocation"))
    collect_logs(p, final)
    capture_metrics(p)
    correlate(p)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/apigateway/rest_metrics.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    args = parser.parse_args()
    probe = MetricsProbe(args.output, args.account, args.cleanup_only)
    try:
        if not args.cleanup_only:
            run(probe)
    except BaseException as error:
        probe.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        probe.save()
        raise
    finally:
        try:
            probe.cleanup()
        finally:
            for client in probe.clients.values():
                client.close()


if __name__ == "__main__":
    main()
