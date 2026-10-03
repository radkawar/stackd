#!/usr/bin/env python3
"""Capture owned native WebSocket management, IAM scopes and payload boundaries."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import platform
import re
import struct
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import boto3
import botocore
from botocore.config import Config
import websocket

import apigateway_probe as base
import apigateway_rest_authorizer_probe as helpers
from apigateway_probe import Probe, REGION, now
from apigateway_rest_authorizer_probe import create_function, role_trust


HANDLER = '''import json
import os
import platform

def handler(event, context):
    body = event.get("body", "")
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        payload = {}
    marker = (event.get("queryStringParameters") or {}).get("probe") or payload.get("marker")
    record = {"probe_kind": "websocket-management", "marker": marker,
        "invocation": context.aws_request_id, "event": event,
        "runtime": platform.python_version(), "execution_environment": os.environ.get("AWS_EXECUTION_ENV")}
    print(json.dumps(record, separators=(",", ":")))
    return {"statusCode": 200, "body": json.dumps(record)}
'''


class ManagementProbe(Probe):
    def sanitize(self, value):
        if isinstance(value, dict):
            for key in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
                if isinstance(value.get(key), str) and not value[key].startswith("<redacted-"):
                    self.hide(value[key], key.lower())
            value = {key: "<redacted-email>" if key.lower().endswith("email") else child
                     for key, child in value.items()}
        if isinstance(value, str) and "@" in value:
            value = re.sub(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}", "<redacted-email>", value)
        return super().sanitize(value)

    def call(self, *args, **kwargs):
        index = len(self.data["observations"])
        try:
            return super().call(*args, **kwargs)
        finally:
            for row in self.data["observations"][index:]:
                row["actor"] = getattr(self, "actor", self.data["identity"])
                row["phase"] = getattr(self, "phase", "setup")
            self.save()

    def cleanup(self):
        self.phase = "cleanup"
        self.actor = self.data["identity"]
        for alias in list(getattr(self, "sockets", {})):
            close_socket(self, alias, "cleanup-socket-" + alias)
        owned = self.data["owned"]
        extra = []
        if "websocket_api" in owned:
            deletion = self.call("cleanup-websocket-api", "apigatewayv2", "delete_api",
                {"ApiId": owned["websocket_api"]}, required=False)
            absent = self.call("absence-websocket-api", "apigatewayv2", "get_api",
                {"ApiId": owned["websocket_api"]}, required=False)
            extra.append(absent["code"] == "NotFoundException")
            self.data["cleanup"]["websocket_api"] = {"delete_code": deletion["code"], "absent": extra[-1]}
        if "caller_role" in owned:
            self.call("cleanup-caller-policy", "iam", "delete_role_policy",
                {"RoleName": owned["caller_role"], "PolicyName": "probe-management"}, required=False)
            deletion = self.call("cleanup-caller-role", "iam", "delete_role",
                {"RoleName": owned["caller_role"]}, required=False)
            absent = self.call("absence-caller-role", "iam", "get_role",
                {"RoleName": owned["caller_role"]}, required=False)
            extra.append(absent["code"] == "NoSuchEntity")
            self.data["cleanup"]["caller_role"] = {"delete_code": deletion["code"], "absent": extra[-1]}
        try:
            super().cleanup()
        finally:
            self.data["cleanup"]["complete"] = self.data["cleanup"].get("complete", False) and all(extra)
            self.save()
        if not self.data["cleanup"]["complete"]:
            raise RuntimeError("Owned management cleanup remains incomplete")


def socket_row(p, label, operation, alias, started, request, result):
    row = {"label": label, "operation": operation, "connection": alias,
        "started_at": started, "finished_at": now(), "request": request, "result": result,
        "phase": getattr(p, "phase", "semantic")}
    p.data["websocket_observations"].append(row)
    p.save()
    return row


def connect_socket(p, alias, stage="dev"):
    marker = p.data["prefix"] + ":" + alias
    url = p.data["owned"]["websocket_endpoint"] + "/" + stage + "?" + urllib.parse.urlencode({"probe": marker})
    started = now()
    try:
        sock = websocket.create_connection(url, timeout=5, enable_multithread=True,
            header=["User-Agent: stackd-native-management-probe"])
        p.sockets[alias] = sock
        result = {"code": "Connected", "http_status": sock.getstatus(), "headers": sock.getheaders()}
    except websocket.WebSocketBadStatusException as error:
        result = {"code": type(error).__name__, "http_status": error.status_code,
            "headers": error.resp_headers, "body": error.resp_body}
    except (websocket.WebSocketException, OSError) as error:
        result = {"code": type(error).__name__, "error": str(error)}
    socket_row(p, "connect-" + alias, "connect", alias, started, {"url": url, "timeout_seconds": 5}, result)
    if result["code"] != "Connected":
        return None
    started = now()
    text = json.dumps({"action": "identify", "marker": marker})
    sock.send(text)
    socket_row(p, "identify-send-" + alias, "send", alias, started,
        {"opcode": 1, "text": text, "timeout_seconds": 5}, {"code": "Sent"})
    frames = receive(p, alias, "identify-receive-" + alias, timeout=5)
    message = bytearray()
    text_message = False
    for frame in frames:
        if frame["opcode"] == 1:
            text_message = True
        if text_message and frame["opcode"] in (0, 1):
            message.extend(frame["text"].encode() if "text" in frame else base64.b64decode(frame["base64"]))
            if frame["fin"]:
                record = json.loads(message)
                connection_id = record["event"]["requestContext"]["connectionId"]
                p.data["connections"][alias] = {"id": connection_id, "stage": stage,
                    "marker": marker, "lambda_record": record}
                p.save()
                return connection_id
    return None


def receive(p, alias, label, timeout=2, max_frames=128):
    sock = p.sockets[alias]
    started = now()
    deadline = time.monotonic() + timeout
    frames = []
    result = {"code": "FrameLimit", "frames": frames}
    for _ in range(max_frames):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            result["code"] = "Timeout"
            break
        sock.settimeout(remaining)
        try:
            frame = sock.recv_frame()
        except websocket.WebSocketTimeoutException:
            result["code"] = "Timeout"
            break
        except (websocket.WebSocketException, OSError) as error:
            result.update(code=type(error).__name__, error=str(error))
            break
        data = frame.data.encode() if isinstance(frame.data, str) else frame.data
        item = {"opcode": frame.opcode, "fin": bool(frame.fin), "payload_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}
        if frame.opcode == websocket.ABNF.OPCODE_TEXT:
            try:
                item["text"] = data.decode("utf-8")
            except UnicodeDecodeError:
                item["base64"] = base64.b64encode(data).decode()
        else:
            item["base64"] = base64.b64encode(data).decode()
        if frame.opcode == websocket.ABNF.OPCODE_CLOSE:
            item["close_code"] = struct.unpack("!H", data[:2])[0] if len(data) >= 2 else None
            item["close_reason"] = data[2:].decode("utf-8", errors="replace") if len(data) >= 2 else ""
            sock.send_close(item["close_code"] or 1000)
            result["code"] = "Close"
        elif frame.opcode == websocket.ABNF.OPCODE_PING:
            sock.pong(data)
        elif frame.fin and frame.opcode in (0, 1, 2):
            result["code"] = "Message"
        frames.append(item)
        if result["code"] in ("Close", "Message"):
            break
    socket_row(p, label, "receive", alias, started,
        {"timeout_seconds": timeout, "max_frames": max_frames}, result)
    return frames


def close_socket(p, alias, label):
    sock = p.sockets.pop(alias, None)
    if sock is None:
        return
    started = now()
    request = {"close_code": 1000, "close_reason": "probe-complete", "timeout_seconds": 2}
    try:
        sock.close(status=1000, reason=b"probe-complete", timeout=2)
        result = {"code": "Closed", "connected": sock.connected,
            "peer_close_capture": "See preceding receive observation when server initiated closure"}
    except (websocket.WebSocketException, OSError) as error:
        result = {"code": type(error).__name__, "error": str(error)}
    finally:
        sock.shutdown()
    socket_row(p, label, "close", alias, started, request, result)


def management_client(p, endpoint, credentials=None):
    values = {} if credentials is None else {"aws_access_key_id": credentials["AccessKeyId"],
        "aws_secret_access_key": credentials["SecretAccessKey"], "aws_session_token": credentials["SessionToken"]}
    client = p.session.client("apigatewaymanagementapi", endpoint_url=endpoint, **values,
        config=Config(retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=10))
    p.management_clients.append(client)
    return client


def management(p, label, method, connection_id, data=None, actor="owner", stage="dev"):
    client, identity = p.actors[actor]
    if stage != "dev":
        client = p.stage_clients[stage]
    p.clients["apigatewaymanagementapi"] = client
    p.actor = identity
    parameters = {"ConnectionId": connection_id}
    if data is not None:
        parameters["Data"] = data
    raw = {}
    sent_headers = {}
    def capture_request(request, **kwargs):
        for key, value in request.headers.items():
            if key.lower() in ("content-type", "content-length", "x-amz-content-sha256"):
                sent_headers[key] = value.decode() if isinstance(value, bytes) else value
    def capture(http_response, parsed, **kwargs):
        raw.update(http_status=http_response.status_code, headers=dict(http_response.headers),
            body_base64=base64.b64encode(http_response.content).decode())
    client.meta.events.register("after-call.apigatewaymanagementapi", capture)
    client.meta.events.register("before-send.apigatewaymanagementapi", capture_request)
    try:
        result = p.call(label, "apigatewaymanagementapi", method, parameters, required=False)
        p.data["observations"][-1].update(endpoint=client.meta.endpoint_url, raw_response=raw,
            request_headers=sent_headers)
        p.save()
        return result
    finally:
        client.meta.events.unregister("after-call.apigatewaymanagementapi", capture)
        client.meta.events.unregister("before-send.apigatewaymanagementapi", capture_request)
        p.actor = p.data["identity"]


def assume_actor(p, label, role, statements):
    parameters = {"RoleArn": role["Arn"], "RoleSessionName": "ws-" + label, "DurationSeconds": 900,
        "Policy": json.dumps({"Version": "2012-10-17", "Statement": statements})}
    previous_phase = p.phase
    p.phase = "readiness"
    try:
        for attempt in range(15):
            result = p.call("assume-" + label + "-" + str(attempt), "sts", "assume_role", parameters, required=False)
            if result["code"] == "Success":
                break
            if result["code"] != "AccessDenied":
                raise RuntimeError("Unexpected STS result: " + result["code"])
            time.sleep(2)
        else:
            raise RuntimeError("STS readiness did not converge for " + label)
    finally:
        p.phase = previous_phase
    output = result["output"]
    identity = {"Account": p.data["account"], **output["AssumedRoleUser"], "policy": parameters["Policy"]}
    p.actors[label] = (management_client(p, p.data["owned"]["management_endpoint"], output["Credentials"]), identity)
    p.data["actors"][label] = identity
    p.save()


def unsigned(p, label, method, connection_id):
    url = p.data["owned"]["management_endpoint"] + "/@connections/" + urllib.parse.quote(connection_id, safe="")
    started = now()
    request = urllib.request.Request(url, data=b"unsigned" if method == "POST" else None, method=method)
    try:
        response = urllib.request.urlopen(request, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(65536)
        result = {"status": response.status, "headers": list(response.headers.items()),
            "body_base64": base64.b64encode(body).decode()}
        try:
            result["body"] = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            pass
    p.data["http"].append({"label": label, "method": method, "url": url, "authorization": "none",
        "started_at": started, "finished_at": now(), "timeout_seconds": 10, "result": result})
    p.save()


def collect_logs(p):
    wanted = {entry["marker"] for entry in p.data["connections"].values()}
    if p.data.get("activity_marker"):
        wanted.add(p.data["activity_marker"])
    previous = None
    p.phase = "evidence"
    for attempt in range(15):
        events, token = [], None
        for page in range(4):
            parameters = {"logGroupName": "/aws/lambda/" + p.data["owned"]["function"],
                "startTime": p.data["log_start_ms"], "limit": 1000}
            if token:
                parameters["nextToken"] = token
            output = p.required(f"logs-{attempt}-{page}", "logs", "filter_log_events", parameters)
            events.extend(output.get("events", []))
            token = output.get("nextToken")
            if not token:
                break
        if token:
            raise RuntimeError("Log collection exceeded four pages")
        records = []
        seen = set()
        for event in events:
            try:
                value = json.loads(event["message"])
            except ValueError:
                continue
            if value.get("probe_kind") != "websocket-management":
                continue
            cid = value["event"]["requestContext"]["connectionId"]
            aliases = [alias for alias, entry in p.data["connections"].items() if entry["id"] == cid]
            records.append({"timestamp": event["timestamp"], "event_id": event["eventId"],
                "record": value, "connection_aliases": aliases})
            if value["event"]["requestContext"]["eventType"] == "MESSAGE":
                seen.add(value.get("marker"))
        ids = sorted(item["event_id"] for item in records)
        p.data["invocation_logs"] = records
        p.data["log_collection"] = {"wanted_markers": sorted(wanted), "seen_message_markers": sorted(seen),
            "attempts": attempt + 1, "complete": wanted <= seen and ids == previous,
            "stable_consecutive_snapshots": 2, "poll_interval_seconds": 3}
        p.save()
        if p.data["log_collection"]["complete"]:
            return
        previous = ids
        time.sleep(3)
    raise RuntimeError("Bounded actual Lambda log capture did not stabilize")


def run(p):
    p.phase = "setup"
    p.sockets, p.management_clients, p.actors, p.stage_clients = {}, [], {}, {}
    p.data.update(mode="websocket-management", scope="Owned WebSocket management operations, scoped STS callers and raw frames",
        bounds={"apis": 1, "functions": 1, "roles": 2, "function_log_groups": 1, "stages": 2,
            "connect_attempts": 15, "sts_attempts": 15, "authority_readiness_attempts": 20,
            "socket_timeout_seconds": 5, "payload_receive_seconds": 2, "receive_frames": 128,
            "sdk_attempts": 1, "log_attempts": 15, "log_pages_per_poll": 4},
        probe_source=Path(__file__).read_text(), base_helper_source=Path(base.__file__).read_text(),
        resource_helper_source=Path(helpers.__file__).read_text(), handler_source=HANDLER,
        sdk={"boto3": boto3.__version__, "botocore": botocore.__version__, "websocket_client": websocket.__version__,
            "python": platform.python_version()}, log_start_ms=int(time.time() * 1000),
        websocket_observations=[], connections={}, actors={}, invocation_logs=[], owned={},
        documentation=[
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-control-access-iam.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-control-access-using-iam-policies-to-invoke-api.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-how-to-call-websocket-api-connections.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-execution-service-websocket-limits-table.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-route-response.html"],
        retry_contract="Setup/positive authority readiness are separate from single-shot semantic operations. IAM session policies are immutable; the underlying role policy is never updated during scenarios.",
        authority_contract="Lambda execution role has only log writes; Lambda resource policy permits API Gateway invocation. A separate caller role has ManageConnections for this owned API only; STS session policies further constrain it.")
    p.save()
    function, _ = create_function(p, HANDLER)
    api = p.required("create-websocket-api", "apigatewayv2", "create_api",
        {"Name": p.data["prefix"], "ProtocolType": "WEBSOCKET", "RouteSelectionExpression": "$request.body.action"},
        own=("websocket_api", "ApiId"))
    api_id = api["ApiId"]
    p.data["owned"].update(websocket_endpoint=api["ApiEndpoint"],
        management_endpoint=f"https://{api_id}.execute-api.{REGION}.amazonaws.com/dev")
    source = f"arn:aws:execute-api:{REGION}:{p.data['account']}:{api_id}"
    p.required("permission-integration", "lambda", "add_permission",
        {"FunctionName": function["FunctionName"], "StatementId": "owned-websocket", "Action": "lambda:InvokeFunction",
            "Principal": "apigateway.amazonaws.com", "SourceArn": source + "/*/*", "SourceAccount": p.data["account"]})
    integration = p.required("create-integration", "apigatewayv2", "create_integration",
        {"ApiId": api_id, "IntegrationType": "AWS_PROXY", "IntegrationMethod": "POST", "TimeoutInMillis": 5000,
            "IntegrationUri": f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function['FunctionArn']}/invocations"})
    for route_key in ("$connect", "$disconnect", "$default", "activity"):
        route = p.required("route-" + route_key, "apigatewayv2", "create_route",
            {"ApiId": api_id, "RouteKey": route_key, "AuthorizationType": "NONE", "Target": "integrations/" + integration["IntegrationId"]})
        if route_key == "$default":
            p.required("route-response-default", "apigatewayv2", "create_route_response",
                {"ApiId": api_id, "RouteId": route["RouteId"], "RouteResponseKey": "$default"})
    deployment = p.required("deploy-websocket", "apigatewayv2", "create_deployment", {"ApiId": api_id})
    for stage in ("dev", "other"):
        p.required("stage-" + stage, "apigatewayv2", "create_stage",
            {"ApiId": api_id, "StageName": stage, "DeploymentId": deployment["DeploymentId"]})
    caller = p.required("create-caller-role", "iam", "create_role",
        {"RoleName": p.data["prefix"] + "-caller", "AssumeRolePolicyDocument": role_trust({"AWS": p.data["identity"]["Arn"]})},
        own=("caller_role", "Role.RoleName"))["Role"]
    allow = {"Effect": "Allow", "Action": "execute-api:ManageConnections", "Resource": source + "/*"}
    p.required("caller-policy", "iam", "put_role_policy", {"RoleName": caller["RoleName"], "PolicyName": "probe-management",
        "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [allow]})})
    p.actors["owner"] = (management_client(p, p.data["owned"]["management_endpoint"]), p.data["identity"])
    for stage in ("other", "absent"):
        p.stage_clients[stage] = management_client(p, p.data["owned"]["management_endpoint"].rsplit("/", 1)[0] + "/" + stage)
    p.phase = "readiness"
    for attempt in range(15):
        alias = "ready-" + str(attempt)
        primary = connect_socket(p, alias)
        if primary:
            break
        close_socket(p, alias, "readiness-close-" + alias)
        time.sleep(2)
    else:
        raise RuntimeError("WebSocket deployment did not become ready")
    p.data["primary_connection_alias"] = alias
    assume_actor(p, "allow", caller, [allow])
    for attempt in range(20):
        result = management(p, "allow-ready-" + str(attempt), "get_connection", primary, actor="allow")
        if result["code"] == "Success":
            break
        time.sleep(3)
    else:
        raise RuntimeError("Positive ManageConnections caller authority did not converge")
    p.phase = "semantic"
    peer = connect_socket(p, "peer")
    if not peer:
        raise RuntimeError("Peer socket could not be identified")
    management(p, "owner-get-live", "get_connection", primary)
    for method in ("GET", "POST", "DELETE"):
        unsigned(p, "unsigned-" + method.lower(), method, primary)
    assume_actor(p, "missing", caller, [{"Effect": "Allow", "Action": "execute-api:Invoke", "Resource": source + "/*"}])
    assume_actor(p, "deny", caller, [allow, {**allow, "Effect": "Deny"}])
    for actor in ("missing", "deny"):
        for method in ("get_connection", "post_to_connection", "delete_connection"):
            management(p, actor + "-" + method, method, primary,
                data=b"must-not-deliver" if method == "post_to_connection" else None, actor=actor)
    receive(p, alias, "denied-requests-no-frame")
    assume_actor(p, "get-only", caller, [{**allow, "Resource": source + "/dev/GET/@connections/*"}])
    management(p, "get-only-get", "get_connection", primary, actor="get-only")
    management(p, "get-only-post", "post_to_connection", primary, b"wrong-verb", actor="get-only")
    management(p, "get-only-delete", "delete_connection", primary, actor="get-only")
    assume_actor(p, "stage-mismatch", caller, [{**allow, "Resource": source + "/other/*"}])
    management(p, "stage-scope-mismatch", "get_connection", primary, actor="stage-mismatch")
    fake_api_source = source.rsplit(":", 1)[0] + ":0000000000"
    assume_actor(p, "api-mismatch", caller, [{**allow, "Resource": fake_api_source + "/*"}])
    management(p, "api-scope-mismatch", "get_connection", primary, actor="api-mismatch")
    assume_actor(p, "documented-path", caller, [{**allow, "Resource": [source + "/dev/" + verb + "/@connections" for verb in ("GET", "POST")]}])
    management(p, "documented-path-get", "get_connection", primary, actor="documented-path")
    documented_post = management(p, "documented-path-post", "post_to_connection", primary, b"documented-path", actor="documented-path")
    if documented_post["code"] == "Success":
        receive(p, alias, "documented-path-delivery")
    assume_actor(p, "exact-id", caller, [{**allow, "Resource": [source + "/dev/" + verb + "/@connections/" + primary for verb in ("GET", "POST", "DELETE")]}])
    management(p, "exact-id-get-target", "get_connection", primary, actor="exact-id")
    management(p, "exact-id-get-peer", "get_connection", peer, actor="exact-id")
    exact_post = management(p, "exact-id-post-target", "post_to_connection", primary, b"exact-id-target", actor="exact-id")
    if exact_post["code"] == "Success":
        receive(p, alias, "exact-id-target-delivery")
    management(p, "exact-id-post-peer", "post_to_connection", peer, b"must-not-deliver-peer", actor="exact-id")
    management(p, "exact-id-delete-peer", "delete_connection", peer, actor="exact-id")
    receive(p, "peer", "exact-id-peer-no-frame")
    assume_actor(p, "template-path", caller, [{**allow, "Resource": [
        source + "/dev/" + verb + "/@connections/{connectionId}" for verb in ("GET", "POST", "DELETE")]}])
    management(p, "template-path-get-target", "get_connection", primary, actor="template-path")
    management(p, "template-path-get-peer", "get_connection", peer, actor="template-path")
    template_post = management(p, "template-path-post-peer", "post_to_connection", peer, b"literal-template", actor="template-path")
    if template_post["code"] == "Success":
        receive(p, "peer", "template-path-peer-delivery")
    for label, payload in (("text", b"native plain text"), ("utf8", "native \u2603".encode()),
            ("binary", b"\x00\xff\xfe\x80native"), ("empty", b"")):
        result = management(p, "allow-post-" + label, "post_to_connection", primary, payload, actor="allow")
        if result["code"] == "Success":
            receive(p, alias, "allow-post-" + label + "-frames")
        management(p, "after-" + label + "-get", "get_connection", primary)
    time.sleep(1)
    management(p, "activity-get-without-traffic", "get_connection", primary)
    activity_marker = p.data["prefix"] + ":activity-client-one-way"
    text = json.dumps({"action": "activity", "marker": activity_marker})
    started = now()
    p.sockets[alias].send(text)
    socket_row(p, "activity-client-one-way-send", "send", alias, started,
        {"opcode": 1, "text": text, "timeout_seconds": 5}, {"code": "Sent"})
    receive(p, alias, "activity-client-one-way-no-response")
    management(p, "activity-get-after-client", "get_connection", primary)
    p.data["activity_marker"] = activity_marker
    for size in (32768, 32769, 131072, 131073):
        boundary_alias = "payload-" + str(size)
        connection_id = connect_socket(p, boundary_alias)
        if not connection_id:
            raise RuntimeError("Payload connection could not be identified")
        management(p, "payload-" + str(size) + "-post", "post_to_connection", connection_id, b"x" * size, actor="allow")
        receive(p, boundary_alias, "payload-" + str(size) + "-frames")
        management(p, "payload-" + str(size) + "-survival", "get_connection", connection_id)
        close_socket(p, boundary_alias, "payload-" + str(size) + "-close")
    other_control = connect_socket(p, "other-stage-control", stage="other")
    if not other_control:
        raise RuntimeError("Other stage positive control could not be identified")
    management(p, "other-stage-control-get", "get_connection", other_control, stage="other")
    close_socket(p, "other-stage-control", "other-stage-control-close")
    other_target = connect_socket(p, "wrong-stage-target")
    if not other_target:
        raise RuntimeError("Stage-ownership connection could not be identified")
    management(p, "other-stage-get", "get_connection", other_target, stage="other")
    cross_post = management(p, "other-stage-post", "post_to_connection", other_target, b"cross-stage", stage="other")
    if cross_post["code"] == "Success":
        receive(p, "wrong-stage-target", "other-stage-post-frames")
    management(p, "other-stage-delete", "delete_connection", other_target, stage="other")
    receive(p, "wrong-stage-target", "other-stage-delete-frames")
    management(p, "other-stage-target-survival", "get_connection", other_target)
    close_socket(p, "wrong-stage-target", "wrong-stage-target-close")
    delete_control = connect_socket(p, "allow-delete-control")
    if not delete_control:
        raise RuntimeError("Delete positive control could not be identified")
    management(p, "allow-delete-control", "delete_connection", delete_control, actor="allow")
    receive(p, "allow-delete-control", "allow-delete-control-frames")
    close_socket(p, "allow-delete-control", "allow-delete-control-close")
    management(p, "absent-stage-get", "get_connection", primary, stage="absent")
    for method in ("get_connection", "post_to_connection", "delete_connection"):
        management(p, "malformed-id-" + method, method, "AAAAAAAAAAAAAAA=",
            data=b"malformed" if method == "post_to_connection" else None)
    missing_id = ("A" if primary[0] != "A" else "B") + primary[1:]
    p.data["missing_id_derivation"] = {"id": missing_id,
        "source": "First character of owned native connection ID changed; no connection opened with this ID"}
    for method in ("get_connection", "post_to_connection", "delete_connection"):
        management(p, "missing-id-" + method, method, missing_id,
            data=b"missing" if method == "post_to_connection" else None)
        management(p, "denied-missing-id-" + method, method, missing_id,
            data=b"denied-missing" if method == "post_to_connection" else None, actor="missing")
    unsigned(p, "unsigned-missing-get", "GET", missing_id)
    management(p, "exact-id-delete-target", "delete_connection", primary, actor="exact-id")
    receive(p, alias, "exact-id-delete-target-frames")
    if management(p, "after-exact-delete-get", "get_connection", primary)["code"] == "Success":
        management(p, "template-path-delete-target", "delete_connection", primary, actor="template-path")
        receive(p, alias, "template-path-delete-target-frames")
    if management(p, "after-template-delete-get", "get_connection", primary)["code"] == "Success":
        management(p, "allow-delete-target", "delete_connection", primary, actor="allow")
        receive(p, alias, "allow-delete-target-frames")
    for method in ("get_connection", "post_to_connection", "delete_connection"):
        management(p, "deleted-id-" + method, method, primary,
            data=b"deleted" if method == "post_to_connection" else None)
    close_socket(p, alias, "deleted-target-local-close")
    close_socket(p, "peer", "peer-client-close")
    for method in ("get_connection", "post_to_connection", "delete_connection"):
        management(p, "client-closed-id-" + method, method, peer,
            data=b"client-closed" if method == "post_to_connection" else None)
    collect_logs(p)
    p.data["completed_at"] = now()
    p.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/apigateway/websocket_management.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--repeat-capture", action="store_true",
        help="Retain a cleaned capture and provision a fresh owned attempt")
    args = parser.parse_args()
    if args.repeat_capture:
        previous = json.loads(args.output.read_text())
        if args.cleanup_only or not previous.get("cleanup", {}).get("complete"):
            parser.error("--repeat-capture requires a capture with verified complete cleanup")
        if previous["account"] != args.account or previous["region"] != REGION:
            parser.error("Previous capture account/region does not match")
        with tempfile.TemporaryDirectory(prefix="stackd-ws-management-") as directory:
            probe = ManagementProbe(Path(directory) / "capture.json", args.account, False)
        probe.path = args.output
        probe.data["prior_captures"] = [previous]
        probe.save()
    else:
        probe = ManagementProbe(args.output, args.account, args.cleanup_only)
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
            for client in [*probe.clients.values(), *getattr(probe, "management_clients", [])]:
                client.close()


if __name__ == "__main__":
    main()
