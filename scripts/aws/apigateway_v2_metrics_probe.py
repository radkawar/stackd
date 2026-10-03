#!/usr/bin/env python3
"""Capture bounded, owned HTTP/WebSocket service-generated CloudWatch metrics."""
import argparse
import datetime
import json
from pathlib import Path
import time

from botocore.config import Config

from apigateway_probe import REGION, now
from apigateway_rest_authorizer_probe import create_function
from apigateway_websocket_probe import LifecycleProbe

HANDLER = '''import json

def handler(event, context):
    rc = event.get("requestContext", {})
    route = rc.get("routeKey", "")
    query = event.get("queryStringParameters") or {}
    headers = event.get("headers") or {}
    try:
        body = json.loads(event.get("body") or "{}")
    except ValueError:
        body = {}
    marker = body.get("marker") or query.get("marker") or headers.get("x-probe")
    status = 403 if route == "$connect" and query.get("deny") == "yes" else 200
    if route in ("bad", "GET /bad"):
        status = 503
    if route == "GET /client":
        status = 400
    response = {"statusCode": status, "body": json.dumps({"marker": marker,
        "route": route, "invocation_id": context.aws_request_id,
        "connection_id": rc.get("connectionId"), "status": status})}
    print(json.dumps({"probe_kind": "v2-metrics", "marker": marker,
        "invocation_id": context.aws_request_id, "event": event,
        "response": response if route != "GET /raise" else None}), flush=True)
    if route == "GET /raise":
        raise RuntimeError("owned metrics integration failure")
    return response
'''

METRICS = {
    "HTTP": ["4xx", "5xx", "Count", "DataProcessed", "IntegrationLatency", "Latency"],
    "WEBSOCKET": ["ConnectCount", "MessageCount", "IntegrationError", "ClientError", "ExecutionError", "IntegrationLatency"],
}
STATISTICS = ["Sum", "SampleCount", "Minimum", "Maximum", "Average"]


class MetricsProbe(LifecycleProbe):
    def call(self, *args, **kwargs):
        start = len(self.data["observations"])
        try:
            return super().call(*args, **kwargs)
        finally:
            for row in self.data["observations"][start:]:
                row["actor"] = self.data["identity"]
            self.save()

    def execution(self, protocol):
        counts = self.data["execution_counts"]
        if counts[protocol] >= 40:
            raise RuntimeError(protocol + " execution budget exhausted")
        counts[protocol] += 1
        self.save()

    def http(self, *args, **kwargs):
        self.execution("HTTP")
        return super().http(*args, **kwargs)

    def connect(self, *args, **kwargs):
        self.execution("WEBSOCKET")
        return super().connect(*args, **kwargs)

    def send(self, *args, **kwargs):
        self.execution("WEBSOCKET")
        return super().send(*args, **kwargs)

    def cleanup(self):
        api = self.data["owned"].get("plain_http_api")
        absent = True
        if api:
            self.call("cleanup-plain-http-api", "apigatewayv2", "delete_api", {"ApiId": api}, required=False)
            result = self.call("absence-plain-http-api", "apigatewayv2", "get_api", {"ApiId": api}, required=False)
            absent = result["code"] == "NotFoundException"
            self.data["cleanup"]["plain_http_api"] = {"absent": absent}
        super().cleanup()
        self.data["cleanup"]["complete"] = self.data["cleanup"]["complete"] and absent
        self.save()
        if not absent:
            raise RuntimeError("Owned HTTP API cleanup incomplete")


def control(p, protocol, label, method, **inputs):
    return p.required(protocol.lower() + "-" + label, "apigatewayv2", method,
                      {"ApiId": p.data["apis"][protocol]["id"], **inputs})


def setup(p):
    p.data.update(scope="One owned HTTP API and one WebSocket API sharing a real Lambda, role and function log group; no API Gateway logging/account changes",
        probe_source=Path(__file__).read_text(), handler_source=HANDLER,
        documentation=["https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-metrics.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-logging.html"],
        bounds={"apis_per_protocol": 1, "functions": 1, "roles": 1, "log_groups": 1,
            "execution_requests_per_protocol": 40, "metric_polls_per_cohort": 4,
            "metric_poll_interval_seconds": 60, "initial_publication_wait_seconds": 150,
            "list_metrics_scans_per_protocol": 2, "list_metrics_pages_per_scan": 2,
            "log_pages": 3, "cleanup_attempts": 3, "sdk_total_max_attempts": 1,
            "function_create_attempts": 15, "function_ready_attempts": 15},
        apis={}, cohorts=[], metric_queries=[], metric_discovery=[], websocket_observations=[],
        connections={}, expected_invocation_markers=[], execution_counts={"HTTP": 0, "WEBSOCKET": 0},
        log_start_ms=int(time.time() * 1000), limitations=[
            "Absent datapoints are retained as empty arrays, never converted to zeros.",
            "No backend noninvocation claim follows from a gateway response or missing bounded log record.",
            "Publication lag and stage-setting convergence are observations, not timing guarantees.",
            "Minute-separated requests use held sockets; socket receives are client witnesses, not extra inbound messages.",
            "No account-wide CloudWatch dimensions, logs, or logging role are changed or queried."])
    p.save()
    function, _ = create_function(p, HANDLER)
    p.data["owned"]["log_group"] = "/aws/lambda/" + function["FunctionName"]
    for protocol in METRICS:
        values = {"Name": p.data["prefix"] + "-" + protocol.lower(), "ProtocolType": protocol}
        if protocol == "WEBSOCKET":
            values["RouteSelectionExpression"] = "$request.body.action"
        api = p.required("create-" + protocol.lower() + "-api", "apigatewayv2", "create_api", values,
            own=("plain_http_api" if protocol == "HTTP" else "http_api", "ApiId"))
        p.data["apis"][protocol] = {"id": api["ApiId"], "routes": {}}
        p.data["owned"]["plain_http_endpoint" if protocol == "HTTP" else "websocket_endpoint"] = api["ApiEndpoint"]
        p.required("permission-" + protocol.lower(), "lambda", "add_permission", {
            "FunctionName": function["FunctionName"], "StatementId": "metrics-" + protocol.lower(),
            "Action": "lambda:InvokeFunction", "Principal": "apigateway.amazonaws.com",
            "SourceAccount": p.data["account"],
            "SourceArn": f"arn:aws:execute-api:{REGION}:{p.data['account']}:{api['ApiId']}/*"})
        uri = function["FunctionArn"] if protocol == "HTTP" else f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function['FunctionArn']}/invocations"
        integration = control(p, protocol, "integration", "create_integration",
            IntegrationType="AWS_PROXY", IntegrationMethod="POST", IntegrationUri=uri,
            **({"PayloadFormatVersion": "2.0"} if protocol == "HTTP" else {}))
        routes = ["GET /ok", "GET /off", "GET /bad", "GET /client", "GET /iam", "GET /raise"] if protocol == "HTTP" else ["$connect", "one", "two", "off", "bad", "broken"]
        for route in routes:
            target = integration["IntegrationId"]
            if route == "broken":
                broken = control(p, protocol, "broken-integration", "create_integration",
                    IntegrationType="AWS_PROXY", IntegrationMethod="POST",
                    IntegrationUri=uri.replace("/invocations", ":missing/invocations"))
                target = broken["IntegrationId"]
            two_way = protocol == "WEBSOCKET" and route in ("two", "off", "bad", "broken")
            result = control(p, protocol, "route-" + route, "create_route", RouteKey=route,
                AuthorizationType="AWS_IAM" if route == "GET /iam" else "NONE",
                Target="integrations/" + target,
                **({"RouteResponseSelectionExpression": "$default"} if two_way else {}))
            p.data["apis"][protocol]["routes"][route] = result["RouteId"]
            if two_way:
                control(p, protocol, "response-" + route, "create_route_response", RouteId=result["RouteId"], RouteResponseKey="$default")
        deployment = control(p, protocol, "deploy", "create_deployment")
        control(p, protocol, "default-stage", "create_stage", StageName="probe", AutoDeploy=False, DeploymentId=deployment["DeploymentId"])
        control(p, protocol, "get-default-stage", "get_stage", StageName="probe")
    endpoint = p.data["owned"]["websocket_endpoint"].replace("wss://", "https://") + "/probe"
    p.clients["apigatewaymanagementapi"] = p.session.client("apigatewaymanagementapi", endpoint_url=endpoint,
        config=Config(retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30))
    p.save()


def next_minute():
    time.sleep(60 - time.time() % 60 + 2)


def cohort(p, name, http_paths, websocket_action):
    next_minute()
    start = datetime.datetime.now(datetime.timezone.utc).replace(second=0, microsecond=0)
    offsets = {"http": len(p.data["http"]), "websocket_observations": len(p.data["websocket_observations"]),
               "observations": len(p.data["observations"])}
    row = {"name": name, "started_at": now(), "metric_window": {"start": start.isoformat(),
        "end": (start + datetime.timedelta(minutes=1)).isoformat(), "period_seconds": 60},
        "requests": {}, "metric_query_labels": {"HTTP": [], "WEBSOCKET": []}}
    p.data["cohorts"].append(row)
    p.save()
    for index, path in enumerate(http_paths):
        p.http(name + "-http-" + str(index), "plain_http", "/probe/" + path)
    websocket_action()
    row["finished_at"] = now()
    for key, offset in offsets.items():
        row["requests"][key] = [entry["label"] for entry in p.data[key][offset:]]
    row["crossed_metric_window"] = datetime.datetime.now(datetime.timezone.utc) >= start + datetime.timedelta(minutes=1)
    p.save()


def message(p, label, route):
    p.send("held", label + "-send", json.dumps({"action": route, "marker": p.marker(label)}))
    return p.receive("held", label + "-receive", timeout=2)


def execute(p):
    cohort(p, "default-success", ["ok", "ok"], lambda: p.connect("held"))
    if "held" not in p.sockets:
        raise RuntimeError("Initial held WebSocket handshake did not succeed; no extra capture round")
    for protocol in METRICS:
        off = "GET /off" if protocol == "HTTP" else "off"
        control(p, protocol, "detailed-default-route-override", "update_stage", StageName="probe",
            DefaultRouteSettings={"DetailedMetricsEnabled": True}, RouteSettings={off: {"DetailedMetricsEnabled": False}})
        control(p, protocol, "get-detailed-stage", "get_stage", StageName="probe")
    cohort(p, "detailed-success-rejected-connect", ["ok", "off"], lambda: p.connect("rejected", deny=True))
    cohort(p, "backend-status-and-one-way", ["client", "bad"], lambda: [message(p, "one-" + str(i), "one") for i in range(2)])
    responses = []
    cohort(p, "iam-rejection-and-two-way", ["iam", "iam"], lambda: responses.extend(message(p, "two-" + str(i), "two") for i in range(2)))
    connection_id = next((entry.get("json", {}).get("connection_id") for entry in responses if entry.get("json", {}).get("connection_id")), None)
    p.data["held_connection_id"] = connection_id
    def callbacks():
        if not connection_id:
            p.data.setdefault("missing_evidence", []).append("Management callbacks skipped: no witnessed connection ID")
            return
        for index in range(2):
            label = "callback-" + str(index)
            p.execution("WEBSOCKET")
            p.call(label, "apigatewaymanagementapi", "post_to_connection", {
                "ConnectionId": connection_id, "Data": json.dumps({"marker": p.marker(label), "source": "management-owner"}).encode()}, required=False)
            p.receive("held", label + "-receive", timeout=2)
    cohort(p, "success-and-management-outbound", ["ok", "ok"], callbacks)
    cohort(p, "unmatched-and-integration-status-error", ["missing", "missing"], lambda: [message(p, "bad-" + str(i), "bad") for i in range(2)])
    cohort(p, "integration-execution-errors", ["raise"], lambda: message(p, "broken", "broken"))
    cohort(p, "route-override-and-gateway-rejection", ["off", "ok"], lambda: [message(p, "off", "off"), message(p, "unknown", "unknown")])
    p.close("held", "held-close")
    for alias in list(p.sockets):
        p.close(alias, alias + "-close")


def dimensions(values):
    return [{"Name": key, "Value": value} for key, value in sorted(values.items())]


def discover(p, attempt):
    for protocol, api in p.data["apis"].items():
        token = None
        for page in range(2):
            inputs = {"Namespace": "AWS/ApiGateway", "Dimensions": [{"Name": "ApiId", "Value": api["id"]}]}
            if token:
                inputs["NextToken"] = token
            label = f"discover-{protocol.lower()}-{attempt}-{page}"
            result = p.call(label, "cloudwatch", "list_metrics", inputs, required=False)
            p.data["metric_discovery"].append({"protocol": protocol, "observation_label": label})
            if result["code"] != "Success":
                break
            for metric in result["output"].get("Metrics", []):
                if {entry["Name"]: entry["Value"] for entry in metric["Dimensions"]}.get("ApiId") == api["id"]:
                    api.setdefault("discovered_metrics", []).append(metric)
            token = result["output"].get("NextToken")
            if not token:
                break
        if token:
            p.data.setdefault("missing_evidence", []).append(protocol + " ListMetrics page bound reached")
    p.save()


def query_specs(p):
    specs = []
    for protocol, api in p.data["apis"].items():
        sets = [dimensions({"ApiId": api["id"]}), dimensions({"ApiId": api["id"], "Stage": "probe"})]
        for route in api["routes"]:
            if protocol == "HTTP":
                method, resource = route.split(" ", 1)
                sets.append(dimensions({"ApiId": api["id"], "Stage": "probe", "Method": method, "Resource": resource}))
            else:
                sets.append(dimensions({"ApiId": api["id"], "Stage": "probe", "Route": route}))
        for metric in api.get("discovered_metrics", []):
            candidate = dimensions({entry["Name"]: entry["Value"] for entry in metric["Dimensions"]})
            if candidate not in sets:
                sets.append(candidate)
        for ds in sets:
            for metric in METRICS[protocol]:
                specs.append((protocol, metric, ds))
    return specs


def collect_metrics(p):
    end = datetime.datetime.fromisoformat(p.data["cohorts"][-1]["metric_window"]["end"])
    time.sleep(max(0, end.timestamp() + 150 - time.time()))
    start = datetime.datetime.fromisoformat(p.data["cohorts"][0]["metric_window"]["start"])
    for attempt in range(4):
        if attempt in (0, 2):
            discover(p, attempt)
        presence = {protocol: set() for protocol in METRICS}
        for index, (protocol, metric, ds) in enumerate(query_specs(p)):
            label = f"metrics-{attempt}-{index}-{protocol.lower()}-{metric}"
            inputs = {"Namespace": "AWS/ApiGateway", "MetricName": metric, "Dimensions": ds,
                "StartTime": start, "EndTime": end, "Period": 60, "Statistics": STATISTICS}
            result = p.call(label, "cloudwatch", "get_metric_statistics", inputs, required=False)
            points = result.get("output", {}).get("Datapoints", [])
            if len(ds) == 1:
                presence[protocol].update(point["Timestamp"].astimezone(datetime.timezone.utc).isoformat() for point in points)
            query = {"observation_label": label, "protocol": protocol, "poll": attempt + 1,
                "namespace": "AWS/ApiGateway", "metric_name": metric, "dimensions": ds,
                "start": start.isoformat(), "end": end.isoformat(), "period_seconds": 60,
                "statistics": STATISTICS, "empty_series_observed": result["code"] == "Success" and not points,
                "queried_seconds_after_last_cohort_window": time.time() - end.timestamp()}
            p.data["metric_queries"].append(query)
            for row in p.data["cohorts"]:
                row["metric_query_labels"][protocol].append(label)
        needed = {row["metric_window"]["start"] for row in p.data["cohorts"]}
        p.data.setdefault("publication_observations", []).append({"poll": attempt + 1, "at": now(),
            "api_dimension_windows_with_any_datapoint": {key: sorted(value) for key, value in presence.items()}})
        p.save()
        if all(needed <= seen for seen in presence.values()):
            p.data["metric_poll_stop_reason"] = "All executed cohort windows have at least one API-level metric; absent individual series remain absent observations"
            break
        if attempt < 3:
            time.sleep(60)
    else:
        p.data["metric_poll_stop_reason"] = "Four-poll bound reached; missing individual or whole-window series retained without inferred zeros"
    p.save()


def collect_logs(p):
    if "function" not in p.data["owned"]:
        return
    token = None
    records = []
    for page in range(3):
        inputs = {"logGroupName": "/aws/lambda/" + p.data["owned"]["function"], "startTime": p.data["log_start_ms"], "limit": 1000}
        if token:
            inputs["nextToken"] = token
        result = p.call("function-witness-logs-" + str(page), "logs", "filter_log_events", inputs, required=False)
        if result["code"] != "Success":
            break
        for item in result["output"].get("events", []):
            try:
                record = json.loads(item["message"])
            except ValueError:
                continue
            if record.get("probe_kind") == "v2-metrics":
                records.append({"event_id": item["eventId"], "timestamp": item["timestamp"], "record": record})
        token = result["output"].get("nextToken")
        if not token:
            break
    p.data["invocation_logs"] = records
    p.data["log_collection"] = {"pagination_bound_hit": bool(token), "absence_scope": "Bounded owned Lambda log scan, never proof of noninvocation"}
    p.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/apigateway/v2_metrics.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    args = parser.parse_args()
    p = MetricsProbe(args.output, args.account, args.cleanup_only)
    try:
        if not args.cleanup_only:
            setup(p)
            execute(p)
            collect_metrics(p)
    except BaseException as error:
        p.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        p.save()
        raise
    finally:
        try:
            for alias in list(p.sockets):
                p.close(alias, alias + "-finally-close")
            if not args.cleanup_only:
                try:
                    collect_logs(p)
                except Exception as error:
                    p.data["log_collection_error"] = {"type": type(error).__name__, "message": str(error)}
                    p.save()
            for attempt in range(3):
                try:
                    p.cleanup()
                    break
                except Exception as error:
                    p.data.setdefault("cleanup_attempt_errors", []).append({"attempt": attempt + 1, "error": str(error)})
                    p.save()
                    if attempt == 2:
                        raise
                    time.sleep(2)
        finally:
            for client in p.clients.values():
                client.close()


if __name__ == "__main__":
    main()
