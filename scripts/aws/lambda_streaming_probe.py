#!/usr/bin/env python3
"""Capture native Lambda streaming and delete every uniquely owned resource.

Reproduce from the repository root with native AWS credentials:
  python3 -m venv /tmp/stackd-streaming-sdk
  /tmp/stackd-streaming-sdk/bin/pip install boto3==1.43.94
  /tmp/stackd-streaming-sdk/bin/python scripts/aws/lambda_streaming_probe.py --account ACCOUNT_ID
  /tmp/stackd-streaming-sdk/bin/python scripts/aws/lambda_streaming_probe.py --account ACCOUNT_ID --custom-runtime
  /tmp/stackd-streaming-sdk/bin/python scripts/aws/lambda_streaming_probe.py --account ACCOUNT_ID --timeout-runtime

The supplements require Go. Timeout mode captures only two-second timeouts and recovery.

Uses boto3's modeled event-stream transport, not a hand-written wire protocol.
Payload bytes are base64; compare concatenated_payload_base64, not chunk splits.
"""
import argparse
import base64
import datetime
import hashlib
import io
import json
import os
import pathlib
import secrets
import subprocess
import tempfile
import time
import zipfile

import boto3
import botocore
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


HANDLER = '''const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
exports.streaming = awslambda.streamifyResponse(async (event, stream, context) => {
    stream.setContentType("application/x-stackd-stream");
    console.log("PROBE_START", event.token, context.awsRequestId, context.functionVersion);
    if (event.mode === "throw_before") throw new Error("probe-before");
    if (event.mode === "large") {
        const {once} = require("node:events");
        const block = Buffer.alloc(65536, 120);
        for (let sent = 0; sent < event.bytes; sent += block.length) {
            if (!stream.write(block.subarray(0, Math.min(block.length, event.bytes - sent)))) {
                await once(stream, "drain");
            }
        }
        stream.end();
    } else if (event.mode === "empty") {
        stream.end();
    } else {
        stream.write(Buffer.from([65, 0, 255, 10]));
        await sleep(event.mode === "disconnect" ? 3000 : 150);
        if (event.mode === "throw_after") throw new Error("probe-after");
        stream.write(JSON.stringify({version: context.functionVersion,
            invokedArn: context.invokedFunctionArn, token: event.token}));
        stream.end();
    }
    console.log("PROBE_COMPLETE", event.token, context.awsRequestId, context.functionVersion);
});
exports.plain = async (event, context) => {
    console.log("PROBE_PLAIN", event.token, context.awsRequestId);
    return {plain: true, version: context.functionVersion, token: event.token};
};
'''

CUSTOM_RUNTIME = r'''package main
import (
    "bytes"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "time"
)
func main() {
    endpoint := "http://" + os.Getenv("AWS_LAMBDA_RUNTIME_API") + "/2018-06-01/runtime/invocation/"
    bootID := time.Now().UnixNano()
    for {
        next, err := http.Get(endpoint + "next")
        if err != nil { panic(err) }
        var event struct { Mode, Token string }
        err = json.NewDecoder(next.Body).Decode(&event)
        next.Body.Close()
        if err != nil { panic(err) }
        id := next.Header.Get("Lambda-Runtime-Aws-Request-Id")
        body := []byte(`{"errorType":"Probe.Explicit","errorMessage":"explicit-runtime-error","stackTrace":[]}`)
        var request *http.Request
        if event.Mode == "error_before" {
            request, err = http.NewRequest("POST", endpoint + id + "/error", bytes.NewReader(body))
            request.Header.Set("Content-Type", "application/json")
            request.Header.Set("Lambda-Runtime-Function-Error-Type", "Unhandled")
        } else {
            reader, writer := io.Pipe()
            request, err = http.NewRequest("POST", endpoint + id + "/response", reader)
            request.ContentLength = -1
            request.TransferEncoding = []string{"chunked"}
            request.Close = true
            request.Header.Set("Content-Type", "application/x-explicit-trailer")
            request.Header.Set("Lambda-Runtime-Function-Response-Mode", "streaming")
            if event.Mode == "trailer" {
                request.Trailer = http.Header{
                    "Lambda-Runtime-Function-Error-Type": []string{"Probe.Explicit"},
                    "Lambda-Runtime-Function-Error-Body": []string{base64.StdEncoding.EncodeToString(body)},
                }
            }
            go func() {
                if event.Mode != "timeout_before" {
                    payload := "prefix"
                    if event.Mode == "recovery" { payload = "recovered" }
                    writer.Write([]byte(payload))
                }
                if event.Mode == "timeout_before" || event.Mode == "timeout_after" {
                    time.Sleep(10 * time.Second)
                } else {
                    time.Sleep(150 * time.Millisecond)
                }
                writer.Close()
            }()
        }
        if err != nil { panic(err) }
        metadata, _ := json.Marshal(map[string]any{"path": request.URL.Path,
            "headers": request.Header, "trailers": request.Trailer,
            "transfer_encoding": request.TransferEncoding, "boot_id": bootID, "mode": event.Mode})
        fmt.Println("PROBE_RUNTIME_REQUEST", event.Token, string(metadata))
        response, err := http.DefaultClient.Do(request)
        if err != nil { panic(err) }
        responseBody, _ := io.ReadAll(response.Body)
        response.Body.Close()
        fmt.Println("PROBE_RUNTIME_ACCEPTED", event.Token, response.StatusCode, string(responseBody))
    }
}
'''


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def safe(value):
    if isinstance(value, bytes):
        if len(value) > 65536:
            return {"sha256": hashlib.sha256(value).hexdigest(), "length": len(value)}
        return {"base64": base64.b64encode(value).decode(), "length": len(value)}
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [safe(item) for item in value]
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/lambda/streaming.json"))
    supplements = parser.add_mutually_exclusive_group()
    supplements.add_argument("--custom-runtime", action="store_true", help="Append explicit provided.al2023 Runtime API evidence to an existing Node capture")
    supplements.add_argument("--timeout-runtime", action="store_true", help="Append only provided.al2023 two-second timeout and recovery evidence")
    args = parser.parse_args()
    custom_runtime = args.custom_runtime or args.timeout_runtime
    previous = json.loads(args.output.read_text()) if custom_runtime else None
    prefix = "stackd-lambda-stream-" + secrets.token_hex(6)
    config = Config(connect_timeout=10, read_timeout=190, retries={"total_max_attempts": 1})
    session = boto3.Session(region_name=args.region)
    clients = {name: session.client(name, config=config) for name in ("sts", "iam", "lambda", "logs", "cloudwatch")}
    archive = io.BytesIO()
    artifact = {"source_utf8": HANDLER}
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as package:
        if custom_runtime:
            with tempfile.TemporaryDirectory(prefix="stackd-streaming-bootstrap-") as temporary:
                directory = pathlib.Path(temporary)
                (directory / "main.go").write_text(CUSTOM_RUNTIME)
                command = ["go", "build", "-trimpath", "-ldflags=-s -w", "-o", "bootstrap", "main.go"]
                subprocess.run(command, cwd=directory, env=dict(os.environ, GOOS="linux", GOARCH="amd64", CGO_ENABLED="0", GOWORK="off"), check=True)
                binary = (directory / "bootstrap").read_bytes()
                entry = zipfile.ZipInfo("bootstrap", (2026, 1, 1, 0, 0, 0))
                entry.external_attr = 0o100755 << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                package.writestr(entry, binary)
                artifact = {"source_utf8": CUSTOM_RUNTIME, "binary_sha256": hashlib.sha256(binary).hexdigest(),
                            "build_command": command, "build_environment": {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0", "GOWORK": "off"},
                            "compiler": subprocess.check_output(["go", "version"], text=True).strip()}
        else:
            package.writestr(zipfile.ZipInfo("entry.js", (2026, 1, 1, 0, 0, 0)), HANDLER)
    if custom_runtime:
        artifact["zip"] = safe(archive.getvalue())
    else:
        artifact["zip_base64"] = base64.b64encode(archive.getvalue()).decode()
    capture = {
        "source": "Native AWS HTTPS through boto3 modeled InvokeWithResponseStream transport",
        "region": args.region, "prefix": prefix, "started_at": now().isoformat(),
        "runtime": "provided.al2023" if custom_runtime else "nodejs22.x",
        "sdk": {"boto3": boto3.__version__, "botocore": botocore.__version__},
        "endpoints": {name: client.meta.endpoint_url for name, client in clients.items()},
        "reproduction": __doc__,
        "documentation": [
            "https://docs.aws.amazon.com/lambda/latest/api/API_InvokeWithResponseStream.html",
            "https://docs.aws.amazon.com/lambda/latest/dg/configuration-response-streaming.html",
            "https://docs.aws.amazon.com/lambda/latest/dg/config-rs-write-functions.html",
            "https://docs.aws.amazon.com/lambda/latest/dg/runtimes-custom.html#runtimes-custom-response-streaming",
        ],
        "artifact": artifact,
        "observations": [], "cleanup": [], "workflow_complete": False, "cleanup_verified": False,
        "comparison_contract": "Concatenate PayloadChunk.Payload bytes; individual chunk boundaries and timings are observations, not stable assertions.",
        "uncertainties": ["One native size-limit invocation does not establish stable chunking or exact bandwidth scheduling.",
                          "A single bounded CloudWatch metric read may precede metric publication; absent data is not zero."],
    }
    if args.timeout_runtime:
        capture["configuration"] = {
            "Runtime": "provided.al2023", "Handler": "bootstrap", "Timeout": 2,
            "MemorySize": 128, "Architectures": ["x86_64"],
            "source_selection": "CUSTOM_RUNTIME; timeout_before/timeout_after sleep 10 seconds without closing the streaming response; recovery closes normally",
        }
        capture["uncertainties"] = [
            "Chunk boundaries, request IDs, bootstrap IDs and elapsed times are observations, not stable assertions.",
            "Recovery proves a new bootstrap process by logged boot_id, not replacement of the entire execution environment.",
        ]

    def call(label, service, operation, parameters, cleanup=False):
        row = {"label": label, "service": service, "operation": operation,
               "input": safe(parameters), "started_at": now().isoformat()}
        try:
            response = getattr(clients[service], operation)(**parameters)
            row["result"] = {"code": "Success", "output": safe(response)}
        except ClientError as error:
            row["result"] = {"code": error.response["Error"]["Code"], "error": safe(error.response)}
        capture["cleanup" if cleanup else "observations"].append(row)
        print(label + ": " + row["result"]["code"], flush=True)
        return row["result"]

    def require(result):
        if result["code"] != "Success":
            raise RuntimeError(json.dumps(result))
        return result["output"]

    def ready(label):
        for attempt in range(60):
            response = require(call(label + "_" + str(attempt), "lambda", "get_function_configuration", {"FunctionName": prefix}))
            if response["State"] == "Active" and response.get("LastUpdateStatus", "Successful") == "Successful":
                return
            if response["State"] == "Failed" or response.get("LastUpdateStatus") == "Failed":
                raise RuntimeError("Native function deployment failed")
            time.sleep(2)
        raise RuntimeError("Native function deployment did not settle")

    def invoke(label, mode="success", streaming=True, disconnect=False, size=0, **options):
        token = prefix + "-" + label
        payload = {"mode": mode, "token": token, "bytes": size}
        parameters = {"FunctionName": prefix, "Payload": json.dumps(payload).encode(), "LogType": "Tail", **options}
        row = {"label": label, "operation": "invoke_with_response_stream" if streaming else "invoke",
               "input": {**safe(parameters), "payload_json": payload}, "started_at": now().isoformat()}
        capture["observations"].append(row)
        start = time.monotonic()
        def sent(request, **kwargs):
            row["request_url"] = request.url
            row["request_headers"] = {
                key: value.decode() if isinstance(value, bytes) else value
                for key, value in request.headers.items()
                if key.lower() in ("x-amz-invocation-type", "x-amz-log-type", "content-type")
            }
        event_name = "before-send.lambda." + ("InvokeWithResponseStream" if streaming else "Invoke")
        clients["lambda"].meta.events.register(event_name, sent, unique_id=label)
        try:
            response = getattr(clients["lambda"], row["operation"])(**parameters)
        except (BotoCoreError, ClientError) as error:
            row["result"] = ({"code": error.response["Error"]["Code"], "error": safe(error.response)}
                             if isinstance(error, ClientError)
                             else {"code": type(error).__name__, "error": str(error)})
            print(label + ": " + row["result"]["code"], flush=True)
            return row
        finally:
            clients["lambda"].meta.events.unregister(event_name, unique_id=label)
        stream = response.pop("EventStream" if streaming else "Payload", None)
        row["result"] = {"code": "Success", "output": safe(response)}
        row["headers_received_seconds"] = time.monotonic() - start
        chunks = []
        digest = hashlib.sha256()
        payload_length = event_count = 0
        if streaming:
            row["events"] = []
            if stream is not None:
                row["wire_events"] = []
                parse_event = stream._parse_event

                def capture_event(message):
                    # The SDK still decodes/verifies frames and parses modeled events.
                    # Retain its decoded frame to expose unmodeled native fields.
                    if not size or message.headers.get(":event-type") != "PayloadChunk":
                        row["wire_events"].append({"headers": safe(message.headers), "payload": safe(message.payload)})
                    return parse_event(message)

                stream._parse_event = capture_event
                try:
                    for event in stream:
                        event_count += 1
                        if not size or "PayloadChunk" not in event:
                            row["events"].append({"elapsed_seconds": time.monotonic() - start, "event": safe(event)})
                        if "PayloadChunk" in event:
                            chunk = event["PayloadChunk"].get("Payload", b"")
                            digest.update(chunk)
                            payload_length += len(chunk)
                            if not size:
                                chunks.append(chunk)
                            if disconnect and chunk:
                                row["client_disconnected_at"] = now().isoformat()
                                break
                        if "InvokeComplete" in event and event["InvokeComplete"].get("LogResult"):
                            row["log_tail_utf8"] = base64.b64decode(event["InvokeComplete"]["LogResult"]).decode("utf-8", errors="replace")
                except (BotoCoreError, ClientError) as error:
                    row["transport_error"] = {"type": type(error).__name__, "message": str(error)}
                finally:
                    stream.close()
        elif stream is not None:
            try:
                chunks.append(stream.read())
            except (BotoCoreError, ClientError) as error:
                row["transport_error"] = {"type": type(error).__name__, "message": str(error)}
            finally:
                stream.close()
            if response.get("LogResult"):
                row["log_tail_utf8"] = base64.b64decode(response["LogResult"]).decode("utf-8", errors="replace")
        if not streaming:
            payload_length = sum(map(len, chunks))
            for chunk in chunks:
                digest.update(chunk)
        if not size or not streaming:
            row["concatenated_payload_base64"] = base64.b64encode(b"".join(chunks)).decode()
        row["payload_length"] = payload_length
        row["payload_sha256"] = digest.hexdigest()
        row["event_count"] = event_count
        row["total_seconds"] = time.monotonic() - start
        print(label + ": " + json.dumps({"response": safe(response), "events": row.get("events", []),
              "payload_length": payload_length, "total_seconds": row["total_seconds"]}), flush=True)
        if not custom_runtime:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(capture, indent=2) + "\n")
        return row

    role_name = prefix + "-role"
    role_created = policy_created = function_attempted = False
    start_time = now()
    identity = require(call("identity", "sts", "get_caller_identity", {}))
    capture["account"] = identity["Account"]
    if identity["Account"] != args.account:
        raise RuntimeError("Probe is restricted to the explicitly authorized native account")
    try:
        role = require(call("create_role", "iam", "create_role", {
            "RoleName": role_name, "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})
        }))["Role"]["Arn"]
        role_created = True
        require(call("put_logs_policy", "iam", "put_role_policy", {
            "RoleName": role_name, "PolicyName": "owned-logs", "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": f"arn:aws:logs:{args.region}:{identity['Account']}:log-group:/aws/lambda/{prefix}:*"}]})
        }))
        policy_created = True
        function_attempted = True
        for attempt in range(20):
            created = call("create_function_" + str(attempt), "lambda", "create_function", {
                "FunctionName": prefix, "Role": role, "Runtime": capture["runtime"],
                "Handler": "bootstrap" if custom_runtime else "entry.streaming",
                "Code": {"ZipFile": archive.getvalue()}, "Timeout": 2 if args.timeout_runtime else 180, "MemorySize": 128,
            })
            if created["code"] == "Success":
                break
            if created["code"] != "InvalidParameterValueException" or "cannot be assumed" not in json.dumps(created):
                require(created)
            time.sleep(3)
        else:
            raise RuntimeError("Execution role trust did not propagate")
        ready("ready_streaming")
        if args.timeout_runtime:
            for mode in ("timeout_after", "timeout_before"):
                invoke(mode + "_streaming", mode)
                invoke("recovery_after_" + mode + "_streaming", "recovery")
                invoke(mode + "_ordinary", mode, streaming=False)
                invoke("recovery_after_" + mode + "_ordinary", "recovery", streaming=False)
            capture["workflow_complete"] = True
            return
        if args.custom_runtime:
            for mode in ("trailer", "error_before"):
                invoke("explicit_" + mode + "_streaming", mode)
                invoke("explicit_" + mode + "_ordinary", mode, streaming=False)
            capture["workflow_complete"] = True
            return
        version = require(call("publish_streaming", "lambda", "publish_version", {"FunctionName": prefix}))["Version"]
        for mode in ("success", "empty", "throw_before", "throw_after"):
            invoke(mode, mode)
        invoke("without_log_tail", LogType="None")
        invoke("ordinary_invoke_streaming_handler", streaming=False)
        invoke("ordinary_throw_before", "throw_before", streaming=False)
        invoke("ordinary_throw_after", "throw_after", streaming=False)
        invoke("seven_mib_streaming", "large", size=7 * 1024 * 1024)
        invoke("seven_mib_ordinary", "large", streaming=False, size=7 * 1024 * 1024)
        invoke("dry_run", InvocationType="DryRun")
        invoke("invalid_event_type", InvocationType="Event")
        disconnected = invoke("disconnect", "disconnect", disconnect=True)
        if "client_disconnected_at" not in disconnected:
            raise RuntimeError("Disconnect case did not receive payload bytes")
        marker = prefix + "-disconnect"
        completion = None
        for attempt in range(20):
            observed_logs = call("disconnect_logs_" + str(attempt), "logs", "filter_log_events", {
                "logGroupName": "/aws/lambda/" + prefix, "filterPattern": '"PROBE_COMPLETE" "' + marker + '"',
                "startTime": int(start_time.timestamp() * 1000),
            })
            logs = {} if observed_logs["code"] == "ResourceNotFoundException" else require(observed_logs)
            matching = [event for event in logs.get("events", []) if marker in event["message"]]
            if matching:
                completion = matching
                break
            time.sleep(2)
        if not completion:
            raise RuntimeError("No invocation-specific completion log after client disconnect")
        capture["disconnect_execution_continued"] = {
            "client_disconnected_at": disconnected["client_disconnected_at"], "completion_logs": completion,
            "proof": "Client closed EventStream after first nonempty payload; handler logged matching PROBE_COMPLETE after its 3000 ms delay.",
        }
        invoke("over_200_mib_streaming", "large", size=201 * 1024 * 1024)
        require(call("select_plain_handler", "lambda", "update_function_configuration", {"FunctionName": prefix, "Handler": "entry.plain"}))
        ready("ready_plain")
        invoke("plain_handler_streaming_api")
        invoke("qualified_streaming_version", Qualifier=version)
        require(call("create_alias", "lambda", "create_alias", {"FunctionName": prefix, "Name": "selected", "FunctionVersion": version}))
        invoke("qualified_streaming_alias", Qualifier="selected")
        for metric in ("Invocations", "Errors", "Duration"):
            call("metric_" + metric, "cloudwatch", "get_metric_statistics", {
                "Namespace": "AWS/Lambda", "MetricName": metric,
                "Dimensions": [{"Name": "FunctionName", "Value": prefix}],
                "StartTime": start_time - datetime.timedelta(minutes=1), "EndTime": now() + datetime.timedelta(minutes=1),
                "Period": 60, "Statistics": ["Sum", "SampleCount"],
            })
        capture["workflow_complete"] = True
    finally:
        errors = []

        def clean(label, service, operation, parameters, allowed=("Success",)):
            try:
                result = call(label, service, operation, parameters, cleanup=True)
                if result["code"] not in allowed:
                    errors.append({"label": label, "result": result})
                return result
            except Exception as error:
                errors.append({"label": label, "error": str(error)})
                return None

        if function_attempted:
            clean("delete_function_and_versions_aliases", "lambda", "delete_function", {"FunctionName": prefix}, ("Success", "ResourceNotFoundException"))
            clean("absent_function", "lambda", "get_function_configuration", {"FunctionName": prefix}, ("ResourceNotFoundException",))
            clean("absent_versions", "lambda", "list_versions_by_function", {"FunctionName": prefix}, ("ResourceNotFoundException",))
            clean("absent_aliases", "lambda", "list_aliases", {"FunctionName": prefix}, ("ResourceNotFoundException",))
        if policy_created:
            clean("delete_logs_policy", "iam", "delete_role_policy", {"RoleName": role_name, "PolicyName": "owned-logs"})
            clean("absent_logs_policy", "iam", "get_role_policy", {"RoleName": role_name, "PolicyName": "owned-logs"}, ("NoSuchEntity",))
        if role_created:
            clean("delete_role", "iam", "delete_role", {"RoleName": role_name})
            clean("absent_role", "iam", "get_role", {"RoleName": role_name}, ("NoSuchEntity",))
        if function_attempted:
            # Native log delivery can recreate a group after immediate deletion.
            # Tear down IAM first, then allow pending delivery to settle.
            time.sleep(20)
            clean("delete_logs_after_delivery_settles", "logs", "delete_log_group", {"logGroupName": "/aws/lambda/" + prefix}, ("Success", "ResourceNotFoundException"))
            time.sleep(5)
            groups = clean("absent_logs_after_delivery_settles", "logs", "describe_log_groups", {"logGroupNamePrefix": "/aws/lambda/" + prefix})
            if groups and groups.get("output", {}).get("logGroups"):
                errors.append("Owned log group remains")
        capture["cleanup_verified"] = not errors
        capture["cleanup_errors"] = errors
        capture["finished_at"] = now().isoformat()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        if previous is not None:
            previous["timeout_runtime" if args.timeout_runtime else "custom_runtime"] = capture
            if not args.timeout_runtime:
                previous["workflow_complete"] = previous["workflow_complete"] and capture["workflow_complete"]
                previous["cleanup_verified"] = previous["cleanup_verified"] and capture["cleanup_verified"]
        args.output.write_text(json.dumps(previous if previous is not None else capture, indent=2) + "\n")
        if errors:
            raise RuntimeError("Owned resource cleanup failed: " + json.dumps(errors))


if __name__ == "__main__":
    main()
