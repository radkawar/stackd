#!/usr/bin/env python3
"""Capture an owned native WebSocket API's lifecycle; always remove owned resources."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import platform
import re
import struct
import time
import urllib.parse
import uuid

import botocore
import websocket

from apigateway_probe import Probe, REGION, now
from apigateway_rest_authorizer_probe import create_function

HANDLER = '''import json
import os
import platform

def handler(event, context):
    request = event.get("requestContext", {})
    query = event.get("queryStringParameters") or {}
    body = event.get("body", "")
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        parsed = {}
    marker = query.get("marker") or (parsed.get("marker") if isinstance(parsed, dict) else None)
    if not marker and body.startswith("plain|"):
        marker = body.split("|", 1)[1]
    denied = request.get("eventType") == "CONNECT" and query.get("deny") == "yes"
    response = {"statusCode": 403 if denied else 200,
        "headers": {"content-type": "application/json"},
        "body": json.dumps({"marker": marker, "routeKey": request.get("routeKey"),
            "connectionId": request.get("connectionId"), "received": body,
            "lambdaRequestId": context.aws_request_id, "denied": denied})}
    print(json.dumps({"probe_kind": "websocket-lifecycle", "marker": marker,
        "invocation": context.aws_request_id, "event": event, "response": response,
        "runtime": {"python": platform.python_version(),
            "execution_environment": os.environ.get("AWS_EXECUTION_ENV"),
            "function_version": context.function_version}}))
    return response
'''


class LifecycleProbe(Probe):
    def __init__(self, *args):
        self.sockets = {}
        super().__init__(*args)

    def sanitize(self, value):
        if isinstance(value, dict):
            for key in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
                if isinstance(value.get(key), str) and not value[key].startswith("<redacted-"):
                    self.hide(value[key], key.lower())
            value = {key: "<redacted-email>" if key.lower().endswith("email") else child
                     for key, child in value.items()}
        if isinstance(value, str):
            value = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "<redacted-email>", value)
        return super().sanitize(value)

    def socket_record(self, label, operation, alias, started, request, result):
        row = {"label": label, "operation": operation, "connection": alias,
               "started_at": started, "finished_at": now(), "request": request, "result": result}
        self.data["websocket_observations"].append(row)
        self.save()
        print(label + ": " + str(result.get("status", result.get("outcome"))), flush=True)
        return result

    def connect(self, alias, *, deny=False, phase="semantic"):
        marker = self.marker(alias + "-connect")
        query = [("marker", marker), ("context", "query value"), ("repeat", "first"), ("repeat", "second")]
        if deny:
            query.append(("deny", "yes"))
        url = self.data["owned"]["websocket_endpoint"] + "/probe?" + urllib.parse.urlencode(query)
        headers = {"X-Probe": marker, "X-Context": "header value", "User-Agent": "stackd-native-websocket-lifecycle"}
        request = {"url": url, "headers": headers, "timeout_seconds": 8, "phase": phase}
        started = now()
        sock = websocket.WebSocket()
        try:
            sock.connect(url, header=headers, timeout=8, origin="https://probe.invalid")
            result = {"status": sock.getstatus(), "headers": sock.getheaders(), "outcome": "connected"}
            self.sockets[alias] = sock
        except websocket.WebSocketBadStatusException as error:
            result = {"status": error.status_code, "headers": error.resp_headers,
                      "body": error.resp_body, "outcome": "handshake_rejected"}
            sock.shutdown()
        except Exception as error:
            result = {"outcome": "transport_error", "error_type": type(error).__name__, "error": str(error)}
            sock.shutdown()
        self.data["connections"][alias] = {"marker": marker, "phase": phase, "handshake_status": result.get("status")}
        if result.get("status") == 101 or deny:
            self.data["expected_invocation_markers"].append(marker)
        return self.socket_record(alias + "-connect", "connect", alias, started, request, result)

    def marker(self, label):
        return self.data["prefix"] + ":" + label

    def send(self, alias, label, payload, *, binary=False):
        request = {"opcode": 2 if binary else 1, "timeout_seconds": 8}
        request.update({"base64": base64.b64encode(payload).decode()} if binary else {"text": payload})
        started = now()
        try:
            sock = self.sockets[alias]
            sock.settimeout(8)
            count = sock.send(payload, opcode=request["opcode"])
            result = {"outcome": "sent", "wire_bytes_written": count}
        except Exception as error:
            result = {"outcome": "transport_error", "error_type": type(error).__name__, "error": str(error)}
        return self.socket_record(label, "send", alias, started, request, result)

    def receive(self, alias, label, timeout=2):
        started, deadline = now(), time.monotonic() + timeout
        frames, fragments, message_opcode = [], [], None
        try:
            sock = self.sockets[alias]
            for _ in range(64):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise websocket.WebSocketTimeoutException()
                sock.settimeout(remaining)
                frame = sock.recv_frame()
                data = frame.data.encode() if isinstance(frame.data, str) else frame.data
                frames.append({"opcode": frame.opcode, "fin": bool(frame.fin),
                               "base64": base64.b64encode(data).decode()})
                if frame.opcode == websocket.ABNF.OPCODE_PING:
                    sock.pong(data)
                    frames[-1]["automatic_reply"] = "pong"
                    continue
                if frame.opcode == websocket.ABNF.OPCODE_PONG:
                    continue
                if frame.opcode == websocket.ABNF.OPCODE_CLOSE:
                    result = {"outcome": "frame", **frame_result(frame.opcode, data)}
                    sock.send_close(result["close_code"] or 1000, data[2:])
                    frames[-1]["automatic_reply"] = "close_acknowledgement"
                    break
                if frame.opcode in (websocket.ABNF.OPCODE_TEXT, websocket.ABNF.OPCODE_BINARY):
                    message_opcode = frame.opcode
                fragments.append(data)
                if frame.fin:
                    result = {"outcome": "frame", "reassembled": len(fragments) > 1,
                              **frame_result(message_opcode, b"".join(fragments))}
                    break
            else:
                result = {"outcome": "frame_bound_reached", "max_frames": 64}
        except websocket.WebSocketTimeoutException:
            result = {"outcome": "timeout", "timeout_seconds": timeout,
                      "meaning": "No complete data message or close observed during this bounded receive; not proof of permanent silence."}
        except Exception as error:
            result = {"outcome": "transport_error", "error_type": type(error).__name__, "error": str(error)}
        result["frames"] = frames
        return self.socket_record(label, "receive", alias, started,
                                  {"timeout_seconds": timeout, "max_frames": 64}, result)

    def message(self, alias, label, action=None, *, missing=False, plain=False, phase="semantic"):
        marker = self.marker(label)
        payload = {"marker": marker}
        if not missing:
            payload["action"] = action
        text = "plain|" + marker if plain else json.dumps(payload, separators=(",", ":"))
        sent = self.send(alias, label + "-send", text)
        scenario = {"label": label, "marker": marker, "connection": alias, "phase": phase,
                    "send_label": label + "-send", "receive_label": label + "-receive"}
        self.data["scenarios"].append(scenario)
        if sent["outcome"] == "sent":
            self.data["expected_invocation_markers"].append(marker)
        result = self.receive(alias, label + "-receive")
        scenario["receive_outcome"] = result["outcome"]
        return result

    def close(self, alias, label, code=1000, reason="probe-complete"):
        if alias not in self.sockets:
            return
        sock = self.sockets.pop(alias)
        started = now()
        request = {"opcode": 8, "close_code": code, "close_reason": reason, "timeout_seconds": 2}
        result = {"outcome": "already_closed"}
        try:
            if sock.connected:
                sock.settimeout(2)
                sock.send_close(code, reason.encode())
                try:
                    frame = sock.recv_frame()
                    result = {"outcome": "frame", **frame_result(frame.opcode, frame.data)}
                except websocket.WebSocketTimeoutException:
                    result = {"outcome": "timeout", "timeout_seconds": 2}
        except Exception as error:
            result = {"outcome": "transport_error", "error_type": type(error).__name__, "error": str(error)}
        finally:
            sock.shutdown()
            result["local_socket_closed"] = True
        self.socket_record(label, "close", alias, started, request, result)


def frame_result(opcode, payload):
    data = payload.encode() if isinstance(payload, str) else payload
    result = {"opcode": opcode}
    if opcode == websocket.ABNF.OPCODE_TEXT:
        result["text"] = data.decode("utf-8")
        try:
            result["json"] = json.loads(result["text"])
        except ValueError:
            pass
    else:
        result["base64"] = base64.b64encode(data).decode()
    if opcode == websocket.ABNF.OPCODE_CLOSE:
        result["close_code"] = struct.unpack("!H", data[:2])[0] if len(data) >= 2 else None
        result["close_reason"] = data[2:].decode("utf-8", errors="replace") if len(data) >= 2 else ""
    return result


def snapshot(p, label):
    api = p.data["owned"]["http_api"]
    stage = p.required(label + "-stage", "apigatewayv2", "get_stage", {"ApiId": api, "StageName": "probe"})
    routes = p.required(label + "-routes", "apigatewayv2", "get_routes", {"ApiId": api})
    deployments = p.required(label + "-deployments", "apigatewayv2", "get_deployments", {"ApiId": api})
    p.data["configuration_snapshots"].append({"label": label, "at": now(), "stage": stage,
                                               "routes": routes["Items"], "deployments": deployments["Items"]})
    p.save()


def deploy(p, label, *, first=False):
    api = p.data["owned"]["http_api"]
    deployment = p.required(label + "-create-deployment", "apigatewayv2", "create_deployment",
        {"ApiId": api, "Description": label})
    parameters = {"ApiId": api, "StageName": "probe", "DeploymentId": deployment["DeploymentId"]}
    if first:
        parameters["AutoDeploy"] = False
    p.required(label + "-stage", "apigatewayv2", "create_stage" if first else "update_stage", parameters)
    p.data["deployments"][label] = deployment["DeploymentId"]
    snapshot(p, label)


def ready_connection(p, phase, action=None, expected_route=None):
    attempts, interval, consecutive_needed = (24, 5, 3) if action is not None else (12, 2, 1)
    evidence = {"phase": phase, "started_at": now(), "attempts": [], "max_attempts": attempts,
                "interval_seconds": interval, "consecutive_successes_required": consecutive_needed,
                "requirement": "HTTP 101" if action is None else "HTTP 101 plus marker-correlated route response"}
    p.data["readiness"].append(evidence)
    consecutive = 0
    for attempt in range(attempts):
        alias = phase + "-connection-" + str(attempt)
        result = p.connect(alias, phase="readiness")
        entry = {"connection": alias, "handshake_status": result.get("status")}
        evidence["attempts"].append(entry)
        success = result.get("status") == 101
        if success and action is not None:
            label = phase + "-route-ready-" + str(attempt)
            response = p.message(alias, label, action, phase="readiness")
            entry["response"] = response
            success = (response.get("json", {}).get("marker") == p.marker(label)
                       and response.get("json", {}).get("routeKey") == expected_route)
        entry["ready"] = success
        consecutive = consecutive + 1 if success else 0
        if consecutive >= consecutive_needed:
            evidence.update(ready=True, connection=alias, finished_at=now())
            p.save()
            return alias
        p.close(alias, alias + "-readiness-sample-close")
        p.save()
        time.sleep(interval)
    evidence.update(ready=False, finished_at=now())
    p.save()
    raise RuntimeError("WebSocket readiness bound reached for " + phase)


def run(p):
    p.data.update(scope="One owned WEBSOCKET API: actual Lambda lifecycle, routing, route responses, deployment retention and close frames; no management IAM or account-level changes",
        protocol="WEBSOCKET", owned_api_slot="http_api is the existing Probe cleanup key for any API Gateway v2 API",
        bounds={"apis": 1, "functions": 1, "roles": 1, "log_groups": 1, "stages": 1, "deployments": 3,
            "handshake_readiness_attempts": 12, "handshake_readiness_interval_seconds": 2,
            "deployment_readiness_attempts": 24, "deployment_readiness_interval_seconds": 5,
            "deployment_consecutive_successes_required": 3, "connect_timeout_seconds": 8,
            "send_timeout_seconds": 8, "receive_timeout_seconds": 2, "log_attempts": 24,
            "log_pages_per_attempt": 4, "log_interval_seconds": 3, "cleanup_attempts": 3,
            "sdk_total_max_attempts": 1, "function_create_attempts": 15, "function_ready_attempts": 15},
        probe_source=Path(__file__).read_text(), handler_source=HANDLER,
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        runtime_versions={"python": platform.python_version(), "websocket-client": websocket.__version__,
                          "botocore": botocore.__version__, "lambda_requested": "python3.13"},
        documentation=[
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-overview.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-route-response.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-route-keys-connect-disconnect.html"],
        limitations=["$disconnect is documented best-effort and runs after closure; observed invocations do not guarantee future delivery.",
            "No ten-minute idle or two-hour lifetime test; no throughput, oversized-message, or service restart tests.",
            "Timeouts bound individual receives and log capture; they do not prove permanent absence.",
            "Control-plane DEPLOYED is not data-plane readiness; three consecutive fresh-socket successes bound readiness without proving global convergence.",
            "No WebSocket authorizer or management API IAM claims; connect denial is the Lambda integration returning 403."],
        websocket_observations=[], connections={}, scenarios=[], readiness=[], expected_invocation_markers=[],
        configuration_snapshots=[], deployments={}, log_start_ms=int(time.time() * 1000))
    p.save()
    function, _ = create_function(p, HANDLER)
    api = p.required("create-websocket-api", "apigatewayv2", "create_api",
        {"Name": p.data["prefix"], "ProtocolType": "WEBSOCKET", "RouteSelectionExpression": "$request.body.action"},
        own=("http_api", "ApiId"))
    p.data["owned"]["websocket_endpoint"] = api["ApiEndpoint"]
    p.data["owned"]["log_group"] = "/aws/lambda/" + p.data["owned"]["function"]
    p.required("lambda-invocation-permission", "lambda", "add_permission",
        {"FunctionName": function["FunctionName"], "StatementId": "websocket-lifecycle",
         "Action": "lambda:InvokeFunction", "Principal": "apigateway.amazonaws.com",
         "SourceAccount": p.data["account"],
         "SourceArn": f"arn:aws:execute-api:{REGION}:{p.data['account']}:{api['ApiId']}/*"})
    integration = p.required("create-websocket-integration", "apigatewayv2", "create_integration",
        {"ApiId": api["ApiId"], "IntegrationType": "AWS_PROXY", "IntegrationMethod": "POST",
         "IntegrationUri": f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function['FunctionArn']}/invocations"})
    routes = {}
    for route in ("$connect", "$disconnect", "$default", "echo"):
        routes[route] = p.required("create-route-" + route, "apigatewayv2", "create_route",
            {"ApiId": api["ApiId"], "RouteKey": route, "AuthorizationType": "NONE",
             "Target": "integrations/" + integration["IntegrationId"]})["RouteId"]
    p.data["route_ids"] = routes
    deploy(p, "d1-one-way", first=True)
    original = ready_connection(p, "d1")
    p.connect("lambda-denied", deny=True)
    for label, action, kwargs in (
            ("d1-custom-json", "echo", {}), ("d1-explicit-default", "$default", {}),
            ("d1-unmatched-action", "unknown", {}), ("d1-missing-action", None, {"missing": True}),
            ("d1-non-json", None, {"plain": True})):
        p.message(original, label, action, **kwargs)
    for route in ("$default", "echo"):
        p.required("enable-route-response-" + route, "apigatewayv2", "update_route",
            {"ApiId": api["ApiId"], "RouteId": routes[route], "RouteResponseSelectionExpression": "$default"})
        p.required("create-route-response-" + route, "apigatewayv2", "create_route_response",
            {"ApiId": api["ApiId"], "RouteId": routes[route], "RouteResponseKey": "$default"})
        p.required("get-route-responses-" + route, "apigatewayv2", "get_route_responses",
            {"ApiId": api["ApiId"], "RouteId": routes[route]})
    snapshot(p, "responses-not-deployed")
    p.message(original, "response-config-existing-before-deploy", "echo")
    undeployed = ready_connection(p, "responses-not-deployed")
    p.message(undeployed, "response-config-new-before-deploy", "unknown")
    p.close(undeployed, "response-config-new-peer-close")
    deploy(p, "d2-two-way")
    second = ready_connection(p, "d2", "echo", "echo")
    p.message(original, "d2-original-custom", "echo")
    p.message(original, "d2-original-default", "unknown")
    p.message(second, "d2-fresh-custom", "echo")
    p.message(second, "d2-fresh-default", "unknown")
    p.required("rename-custom-route", "apigatewayv2", "update_route",
        {"ApiId": api["ApiId"], "RouteId": routes["echo"], "RouteKey": "changed"})
    snapshot(p, "rename-not-deployed")
    p.message(second, "rename-existing-old-key-before-deploy", "echo")
    p.message(second, "rename-existing-new-key-before-deploy", "changed")
    pre_rename = ready_connection(p, "rename-not-deployed")
    p.message(pre_rename, "rename-fresh-old-key-before-deploy", "echo")
    p.message(pre_rename, "rename-fresh-new-key-before-deploy", "changed")
    p.close(pre_rename, "rename-fresh-peer-close")
    deploy(p, "d3-renamed-route")
    third = ready_connection(p, "d3", "changed", "changed")
    for alias, generation in ((original, "d1"), (second, "d2"), (third, "d3")):
        p.message(alias, "d3-" + generation + "-old-key", "echo")
        p.message(alias, "d3-" + generation + "-new-key", "changed")
    p.message(third, "d3-missing-action", missing=True)
    p.message(third, "d3-non-json", plain=True)
    p.close(original, "d1-peer-close", reason="peer-close-d1")
    p.close(second, "d2-peer-close", reason="peer-close-d2")
    p.close(third, "d3-peer-close", reason="peer-close-d3")
    binary = ready_connection(p, "binary")
    p.send(binary, "binary-input-send", b"\x00\x01\xffwebsocket-binary", binary=True)
    p.receive(binary, "binary-input-receive", timeout=5)
    p.close(binary, "binary-local-cleanup")
    snapshot(p, "final")


def collect_logs(p):
    if "function" not in p.data["owned"]:
        return
    collected = {}
    previous = None
    for attempt in range(24):
        token = None
        for page in range(4):
            parameters = {"logGroupName": "/aws/lambda/" + p.data["owned"]["function"],
                          "startTime": p.data["log_start_ms"], "limit": 1000}
            if token:
                parameters["nextToken"] = token
            result = p.call(f"lifecycle-logs-{attempt}-{page}", "logs", "filter_log_events", parameters, required=False)
            if result["code"] != "Success":
                break
            for item in result["output"].get("events", []):
                collected[item["eventId"]] = item
            next_token = result["output"].get("nextToken")
            if not next_token or next_token == token:
                token = None
                break
            token = next_token
        records = []
        for item in sorted(collected.values(), key=lambda value: (value["timestamp"], value["eventId"])):
            try:
                value = json.loads(item["message"])
            except ValueError:
                continue
            if value.get("probe_kind") == "websocket-lifecycle":
                records.append({"timestamp": item["timestamp"], "event_id": item["eventId"],
                                "log_stream": item["logStreamName"], "record": value})
        p.data["invocation_logs"] = records
        p.data["runtime_log_records"] = [item for item in collected.values() if item["message"].startswith("INIT_START")]
        seen = {item["record"].get("marker") for item in records}
        missing = sorted(set(p.data["expected_invocation_markers"]) - seen)
        connects = {item["record"]["event"]["requestContext"]["connectionId"] for item in records
                    if item["record"]["event"]["requestContext"]["eventType"] == "CONNECT"
                    and item["record"]["response"]["statusCode"] == 200}
        disconnects = {item["record"]["event"]["requestContext"]["connectionId"] for item in records
                       if item["record"]["event"]["requestContext"]["eventType"] == "DISCONNECT"}
        current = sorted(collected)
        stable = current == previous
        p.data["log_collection"] = {"attempts": attempt + 1, "missing_expected_markers": missing,
            "successful_connects_without_observed_disconnect": sorted(connects - disconnects),
            "stable_consecutive_snapshots": 2 if stable else 1, "pagination_bound_hit": bool(token),
            "absence_scope": "Bounded owned-function logs only. Disconnect delivery remains best-effort."}
        p.save()
        if not missing and connects <= disconnects and stable and attempt >= 2 and not token:
            return
        previous = current
        time.sleep(3)


def summarize(p):
    records = p.data.get("invocation_logs", [])
    by_marker = {}
    by_connection = {}
    for item in records:
        record = item["record"]
        by_marker.setdefault(record.get("marker"), []).append(item)
        connection = record["event"]["requestContext"]["connectionId"]
        by_connection.setdefault(connection, []).append(item)
    for alias, connection in p.data.get("connections", {}).items():
        matches = by_marker.get(connection["marker"], [])
        connection["connect_log_event_ids"] = [item["event_id"] for item in matches]
        if matches:
            native_id = matches[0]["record"]["event"]["requestContext"]["connectionId"]
            connection["connection_id"] = native_id
            connection["disconnect_log_event_ids"] = [item["event_id"] for item in by_connection[native_id]
                if item["record"]["event"]["requestContext"]["eventType"] == "DISCONNECT"]
    receives = {row["label"]: row for row in p.data.get("websocket_observations", []) if row["operation"] == "receive"}
    for scenario in p.data.get("scenarios", []):
        matches = by_marker.get(scenario["marker"], [])
        scenario["lambda_log_event_ids"] = [item["event_id"] for item in matches]
        scenario["selected_routes"] = [item["record"]["event"]["requestContext"]["routeKey"] for item in matches]
        scenario["lambda_response_statuses"] = [item["record"]["response"]["statusCode"] for item in matches]
        received = receives.get(scenario["receive_label"], {}).get("result", {})
        scenario["frame_marker_matches"] = received.get("json", {}).get("marker") == scenario["marker"]
        scenario["frame_invocation_matches_log"] = any(received.get("json", {}).get("lambdaRequestId") == item["record"]["invocation"] for item in matches)
    p.data["socket_cleanup"] = {"remaining_open_aliases": sorted(p.sockets), "complete": not p.sockets}
    p.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/apigateway/websocket_lifecycle.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--append-capture", action="store_true",
                        help="Preserve a completely cleaned prior capture before running fresh owned infrastructure")
    args = parser.parse_args()
    if args.cleanup_only and args.append_capture:
        parser.error("--cleanup-only and --append-capture are mutually exclusive")
    p = LifecycleProbe(args.output, args.account, args.cleanup_only or args.append_capture)
    if args.append_capture:
        previous = p.data
        if previous.get("protocol") != "WEBSOCKET" or not previous.get("cleanup", {}).get("complete"):
            raise RuntimeError("Can append only to a fully cleaned WebSocket lifecycle capture")
        earlier = previous.pop("prior_captures", [])
        p.data = {"service": "apigateway", "account": args.account, "region": REGION,
            "identity": previous["identity"], "captured_at": now(),
            "prefix": "stackd-apigw-" + uuid.uuid4().hex[:10],
            "owned": {}, "observations": [], "http": [], "tokens": {}, "cleanup": {},
            "sdk": previous["sdk"], "prior_captures": earlier + [previous]}
    try:
        if not args.cleanup_only:
            run(p)
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
                summarize(p)
            for attempt in range(3):
                try:
                    p.cleanup()
                    break
                except Exception as error:
                    p.data.setdefault("cleanup_attempt_errors", []).append({"attempt": attempt, "error": str(error)})
                    p.save()
                    if attempt == 2:
                        raise
                    time.sleep(2)
        finally:
            for client in p.clients.values():
                client.close()
    if not args.cleanup_only and (p.data.get("log_collection_error") or p.data.get("log_collection", {}).get("missing_expected_markers")):
        raise RuntimeError("Lambda log evidence incomplete; owned resources were cleaned")


if __name__ == "__main__":
    main()
