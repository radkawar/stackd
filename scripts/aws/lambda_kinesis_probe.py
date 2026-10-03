#!/usr/bin/env python3
"""Capture owned native Kinesis/Lambda workflows and verify complete cleanup."""
import argparse
import base64
import datetime
import gzip
import hashlib
import io
import json
import os
import pathlib
import secrets
import tempfile
import time
import zipfile

from aws_cli import observe, run


HANDLER = '''import base64
import json
import time

def invoke(event, context):
    started = time.time()
    decoded = []
    failures = []
    for record in event["Records"]:
        raw = base64.b64decode(record["kinesis"]["data"])
        try:
            item = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            item = {"raw_base64": record["kinesis"]["data"]}
        decoded.append(item)
        if item.get("bad"):
            failures.append({"itemIdentifier": record["kinesis"]["sequenceNumber"]})
        time.sleep(item.get("delay", 0))
    response = {"batchItemFailures": failures}
    print("KINESIS_PROBE " + json.dumps({"request_id": context.aws_request_id, "invoked_arn": context.invoked_function_arn, "started": started, "finished": time.time(), "event": event, "decoded": decoded, "response": response}, separators=(",", ":")), flush=True)
    return response
'''


def aggregate(items, partition_key="owned-key", hash_keys=None):
    """Encode the published KPL AggregatedRecord protobuf and MD5 envelope."""
    def varint(value):
        encoded = bytearray()
        while value > 127:
            encoded.append((value & 127) | 128)
            value >>= 7
        return bytes(encoded) + bytes([value])

    def field(number, value):
        return varint((number << 3) | 2) + varint(len(value)) + value

    payload = field(1, partition_key.encode())
    if hash_keys is not None:
        for key in hash_keys:
            payload += field(2, str(key).encode())
    for index, item in enumerate(items):
        record = b"\x08\x00"
        if hash_keys is not None:
            record += b"\x10" + varint(index)
        payload += field(3, record + field(3, json.dumps(item).encode()))
    return b"\xf3\x89\x9a\xc2" + payload + hashlib.md5(payload).digest()


def compact_blobs(capture):
    """Intern large exact strings using the existing probe_blob_ref convention."""
    blobs = capture.setdefault("blobs", {})

    def encode(value):
        if isinstance(value, str) and len(value) > 65536:
            raw = value.encode()
            digest = hashlib.sha256(raw).hexdigest()
            blobs[digest] = {"encoding": "gzip+base64", "data": base64.b64encode(gzip.compress(raw, mtime=0)).decode(),
                             "utf8_bytes": len(raw), "sha256": digest}
            return {"probe_blob_ref": digest}
        if isinstance(value, dict):
            return {key: encode(item) for key, item in value.items()}
        if isinstance(value, list):
            return [encode(item) for item in value]
        return value

    for key in list(capture):
        if key not in ("blobs", "prior_runs"):
            capture[key] = encode(capture[key])
    if blobs:
        capture["encoding"] += " probe_blob_ref expands to the UTF-8 string obtained by base64-decoding then gzip-decompressing blobs[id].data; verify utf8_bytes and sha256 before use. In particular an input Data reference expands to the original base64 string, not the raw Kinesis record bytes."
    else:
        capture.pop("blobs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/lambda/kinesis_source.json"))
    parser.add_argument("--only", choices=("all", "authorization", "delivery", "followup", "hash_range", "aggregation", "topology", "reshard", "destination", "oversized"), default="all")
    parser.add_argument("--oversized-retries", type=int, default=0, help="MaximumRetryAttempts for the oversized record contrast")
    args = parser.parse_args()
    env = dict(os.environ, AWS_REGION="us-east-1", AWS_DEFAULT_REGION="us-east-1", AWS_MAX_ATTEMPTS="2")
    prefix = "stackd-kinesislambda-" + secrets.token_hex(6)
    role_name, log_group = prefix + "-role", "/aws/lambda/" + prefix
    capture = {"source": "Native AWS public endpoints through scripts/aws/aws_cli.py", "region": "us-east-1", "prefix": prefix,
               "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "mode": args.only,
               "documentation": ["https://docs.aws.amazon.com/lambda/latest/dg/with-kinesis.html", "https://docs.aws.amazon.com/lambda/latest/dg/services-kinesis-create.html", "https://docs.aws.amazon.com/lambda/latest/dg/services-kinesis-batchfailurereporting.html", "https://raw.githubusercontent.com/awslabs/amazon-kinesis-producer/master/aws/kinesis/protobuf/messages.proto"],
               "additional_documentation": ["https://docs.aws.amazon.com/streams/latest/dev/large-records.html", "https://docs.aws.amazon.com/streams/latest/dev/kinesis-using-sdk-java-after-resharding.html", "https://docs.aws.amazon.com/lambda/latest/dg/kinesis-on-failure-destination.html"],
               "handler_source": HANDLER, "observations": [], "delivery": {}, "cleanup": [], "limitations": ["IAM policy changes and Lambda polling are eventually consistent; bounded samples do not establish an AWS propagation SLA.", "This capture does not exercise cross-account access, encrypted streams, parallelization, or tumbling windows."]}
    if args.output.exists():
        previous = json.loads(args.output.read_text())
        capture["prior_runs"] = previous.pop("prior_runs", []) + [previous]
    owned = {"role": False, "logs": False, "stream": False, "function": False, "policies": set(), "mappings": [], "consumer": None, "queue": None}
    events = {}

    def now():
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + "\n")

    def record(label, service, operation, parameters, cleanup=False):
        started = now()
        if len(parameters.get("Data", "")) > 100000:
            # Linux limits a single argv element; preserve the same native JSON
            # through a temporary file, without changing the shared CLI transport.
            with tempfile.TemporaryDirectory(prefix=prefix) as directory:
                request_file = pathlib.Path(directory) / "request.json"
                request_file.write_text(json.dumps(parameters))
                process = run(service, operation, env=env, options=["--cli-input-json", "file://" + str(request_file),
                              "--cli-error-format", "json", "--cli-connect-timeout", "10", "--cli-read-timeout", "30"], timeout=60)
            if process.returncode == 0:
                result = {"code": "Success", "output": json.loads(process.stdout or "{}")}
            elif process.returncode in (252, 254):
                error = json.loads(process.stderr)
                result = {"code": error["Code"], "error": error}
            else:
                raise RuntimeError(service + ":" + operation + ": " + process.stderr)
        else:
            result = observe(service, operation, parameters, env)
        if service == "sqs" and operation == "receive-message":
            for message in result.get("output", {}).get("Messages", []):
                message.pop("ReceiptHandle", None)
        capture["cleanup" if cleanup else "observations"].append({"label": label, "service": service, "operation": operation, "input": parameters, "started_at": started, "finished_at": now(), "result": result})
        # Track every accepted create, including unexpectedly accepted negative cases.
        if service == "lambda" and operation == "create-event-source-mapping" and result["code"] == "Success":
            owned["mappings"].append(result["output"]["UUID"])
        save()
        print(label + ": " + result["code"], flush=True)
        return result

    def require(result):
        if result["code"] != "Success":
            raise RuntimeError(json.dumps(result))
        return result["output"]

    def policy(name, statements):
        require(record("policy_" + name, "iam", "put-role-policy", {"RoleName": role_name, "PolicyName": name, "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": statements})}))
        owned["policies"].add(name)

    def settle(uuid, state, label, cleanup=False):
        for attempt in range(80):
            result = record(label + "_" + str(attempt), "lambda", "get-event-source-mapping", {"UUID": uuid}, cleanup)
            if state == "absent" and result["code"] == "ResourceNotFoundException":
                return
            if require(result)["State"] == state:
                return result["output"]
            time.sleep(3)
        raise RuntimeError("Mapping did not settle: " + label)

    def remove(uuid, label):
        settle(uuid, "Disabled", label + "_disabled")
        require(record(label + "_delete", "lambda", "delete-event-source-mapping", {"UUID": uuid}))
        settle(uuid, "absent", label + "_absent")
        owned["mappings"].remove(uuid)

    def update(uuid, enabled, label):
        require(record(label, "lambda", "update-event-source-mapping", {"UUID": uuid, "Enabled": enabled}))
        settle(uuid, "Enabled" if enabled else "Disabled", label + "_ready")

    def stream_ready(label):
        for attempt in range(80):
            out = require(record(label + "_" + str(attempt), "kinesis", "describe-stream", {"StreamName": prefix}))["StreamDescription"]
            if out["StreamStatus"] == "ACTIVE":
                return out
            time.sleep(2)
        raise RuntimeError("Stream did not become ACTIVE")

    def put(phase, ordinal, hash_key=None, data=None, **values):
        payload = data if data is not None else json.dumps({"phase": phase, "ordinal": ordinal, **values}).encode()
        request = {"StreamName": prefix, "PartitionKey": "owned-key", "Data": base64.b64encode(payload).decode()}
        if hash_key is not None:
            request["ExplicitHashKey"] = str(hash_key)
        return require(record(phase + "_put_" + str(ordinal), "kinesis", "put-record", request))

    def routing_ready(label, topology):
        # ACTIVE metadata can precede actual PutRecord routing changes.
        shards = [shard for shard in topology["Shards"] if "EndingSequenceNumber" not in shard["SequenceNumberRange"]]
        consecutive = 0
        for attempt in range(60):
            matched = True
            for key in (0, 2 ** 128 - 1):
                expected = next(shard["ShardId"] for shard in shards if int(shard["HashKeyRange"]["StartingHashKey"]) <= key <= int(shard["HashKeyRange"]["EndingHashKey"]))
                observed = put("routing", label + "_" + str(attempt) + "_" + str(key), key)
                matched = matched and observed["ShardId"] == expected
            consecutive = consecutive + 1 if matched else 0
            if consecutive == 2:
                return
            time.sleep(3)
        raise RuntimeError("PutRecord routing did not converge: " + label)

    def scan(label):
        out = require(record(label, "logs", "filter-log-events", {"logGroupName": log_group, "filterPattern": '"KINESIS_PROBE"'}))
        for event in out.get("events", []):
            events[event["eventId"]] = event

    def matching(phase):
        parsed = [json.loads(event["message"].split("KINESIS_PROBE ", 1)[1]) for event in events.values()]
        return [event for event in parsed if event["invoked_arn"].endswith(":" + phase)]

    def collect(phase, minimum=1, timeout=150, quiet=10, label=None, ordinal=None):
        deadline, satisfied, attempt = time.monotonic() + timeout, None, 0
        def complete(found):
            return len(found) >= minimum and (ordinal is None or any(item.get("ordinal") == ordinal for invocation in found for item in invocation["decoded"]))
        while time.monotonic() < deadline:
            scan((label or phase) + "_logs_" + str(attempt))
            if complete(matching(phase)):
                if satisfied is None:
                    satisfied = time.monotonic()
                if time.monotonic() - satisfied >= quiet:
                    break
            time.sleep(3)
            attempt += 1
        found = matching(phase)
        capture["delivery"][label or phase] = {"invocations": found, "ended_at": now(), "bounded_wait_seconds": timeout, "minimum_invocations_observed": complete(found)}
        if not complete(found):
            capture["limitations"].append("No sufficient invocation evidence within bounded wait: " + (label or phase))
        save()
        return found

    def configure(phase, source=None, **settings):
        require(record(phase + "_alias", "lambda", "create-alias", {"FunctionName": prefix, "Name": phase, "FunctionVersion": version}))
        request = {"FunctionName": prefix + ":" + phase, "EventSourceArn": source or stream,
                   "StartingPosition": "TRIM_HORIZON", "Enabled": False, "BatchSize": 4,
                   "MaximumBatchingWindowInSeconds": 2, "MaximumRetryAttempts": 1,
                   "MaximumRecordAgeInSeconds": 600,
                   "FilterCriteria": {"Filters": [{"Pattern": json.dumps({"data": {"phase": [phase]}})}]}}
        request.update(settings)
        created = require(record(phase + "_create", "lambda", "create-event-source-mapping", request))
        uuid = created["UUID"]
        settle(uuid, "Enabled" if request["Enabled"] else "Disabled", phase + "_ready")
        return uuid

    identity = require(record("identity_before_writes", "sts", "get-caller-identity", {}))
    if identity["Account"] != args.account:
        raise RuntimeError("Refusing writes outside explicitly authorized account")
    capture["actor"] = identity
    account = identity["Account"]
    stream = f"arn:aws:kinesis:us-east-1:{account}:stream/{prefix}"
    try:
        require(record("create_log_group", "logs", "create-log-group", {"logGroupName": log_group}))
        owned["logs"] = True
        role = require(record("create_role", "iam", "create-role", {"RoleName": role_name, "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})}))["Role"]["Arn"]
        owned["role"] = True
        policy("owned-logs", [{"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": f"arn:aws:logs:us-east-1:{account}:log-group:{log_group}:*"}])
        require(record("create_stream", "kinesis", "create-stream", {"StreamName": prefix, "ShardCount": 1}))
        owned["stream"] = True
        stream_ready("stream_ready")
        consumer = require(record("register_consumer", "kinesis", "register-stream-consumer", {"StreamARN": stream, "ConsumerName": prefix}))["Consumer"]["ConsumerARN"]
        owned["consumer"] = consumer
        for attempt in range(40):
            out = require(record("consumer_ready_" + str(attempt), "kinesis", "describe-stream-consumer", {"ConsumerARN": consumer}))["ConsumerDescription"]
            if out["ConsumerStatus"] == "ACTIVE":
                break
            time.sleep(2)
        else:
            raise RuntimeError("Consumer did not become ACTIVE")
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr(zipfile.ZipInfo("entry.py", (2026, 1, 1, 0, 0, 0)), HANDLER)
        request = {"FunctionName": prefix, "Role": role, "Runtime": "python3.12", "Handler": "entry.invoke", "Code": {"ZipFile": base64.b64encode(archive.getvalue()).decode()}, "Timeout": 15, "MemorySize": 128}
        for attempt in range(30):
            result = record("create_function_" + str(attempt), "lambda", "create-function", request)
            if result["code"] == "Success":
                owned["function"] = True
                break
            if "cannot be assumed" not in json.dumps(result):
                require(result)
            time.sleep(3)
        if not owned["function"]:
            raise RuntimeError("Role propagation timed out")
        for attempt in range(40):
            if require(record("function_ready_" + str(attempt), "lambda", "get-function-configuration", {"FunctionName": prefix}))["State"] == "Active":
                break
            time.sleep(2)
        version = require(record("publish_handler", "lambda", "publish-version", {"FunctionName": prefix}))["Version"]
        base = {"FunctionName": prefix, "EventSourceArn": stream, "StartingPosition": "TRIM_HORIZON", "Enabled": False}
        result = record("missing_source_permissions", "lambda", "create-event-source-mapping", base)
        if result["code"] == "Success":
            remove(result["output"]["UUID"], "missing_source_permissions")
        actions = ["DescribeStream", "DescribeStreamSummary", "GetRecords", "GetShardIterator", "ListShards", "SubscribeToShard", "DescribeStreamConsumer"]
        allow = [{"Effect": "Allow", "Action": ["kinesis:" + action for action in actions], "Resource": [stream, consumer]}]
        policy("owned-source", allow)
        time.sleep(15)
        if args.only in ("all", "authorization"):
            for action in actions + ["ListStreams"]:
                policy("owned-source", allow + [{"Effect": "Deny", "Action": "kinesis:" + action, "Resource": "*"}])
                time.sleep(12)
                for kind, source in (("stream", stream), ("consumer", consumer)):
                    label = "deny_" + action + "_" + kind
                    result = record(label, "lambda", "create-event-source-mapping", {**base, "EventSourceArn": source})
                    if result["code"] == "Success":
                        remove(result["output"]["UUID"], label)
            policy("owned-source", allow)
            time.sleep(15)
            cases = [("missing_start", {k: v for k, v in base.items() if k != "StartingPosition"}),
                     ("timestamp_missing", {**base, "StartingPosition": "AT_TIMESTAMP"}),
                     ("timestamp_future", {**base, "StartingPosition": "AT_TIMESTAMP", "StartingPositionTimestamp": time.time() + 3600}),
                     ("timestamp_trim", {**base, "StartingPositionTimestamp": time.time() - 60}),
                     ("timestamp_latest", {**base, "StartingPosition": "LATEST", "StartingPositionTimestamp": time.time() - 60}),
                     ("batch_101_zero_window", {**base, "BatchSize": 101}),
                     ("consumer_defaults", {**base, "EventSourceArn": consumer}), ("stream_defaults", base)]
            for label, request in cases:
                result = record("admission_" + label, "lambda", "create-event-source-mapping", request)
                if result["code"] == "Success":
                    remove(result["output"]["UUID"], label)
        if args.only in ("all", "followup"):
            phase = "partial_bisect"
            uuid = configure(phase, FunctionResponseTypes=["ReportBatchItemFailures"], BisectBatchOnFunctionError=True)
            for ordinal in range(1, 5):
                put(phase, ordinal, bad=ordinal == 2)
            update(uuid, True, phase + "_enable")
            collect(phase, minimum=2)
            update(uuid, False, phase + "_disable")
            remove(uuid, phase)
            for phase, source in (("kpl_invalid_standard", stream), ("kpl_invalid_consumer", consumer)):
                cut = time.time()
                uuid = configure(phase, source, StartingPosition="AT_TIMESTAMP", StartingPositionTimestamp=cut,
                                 FilterCriteria={}, BatchSize=1, MaximumBatchingWindowInSeconds=0)
                payload = aggregate([{"phase": phase, "ordinal": 1}])
                malformed = payload[:-1] + bytes([payload[-1] ^ 1])
                put(phase, "bad_checksum", data=malformed)
                put(phase, "truncated_magic", data=b"\xf3\x89\x9a\xc2")
                update(uuid, True, phase + "_enable")
                collect(phase, minimum=2)
                update(uuid, False, phase + "_disable")
                remove(uuid, phase)
        if args.only in ("all", "delivery"):
            for phase, source, report in [("partial_off", stream, False), ("partial_on", stream, True), ("consumer_partial", consumer, True)]:
                uuid = configure(phase, source, FunctionResponseTypes=["ReportBatchItemFailures"] if report else [])
                for ordinal in range(1, 5):
                    put(phase, ordinal, bad=ordinal == 2)
                update(uuid, True, phase + "_enable")
                collect(phase, minimum=2 if report else 1)
                update(uuid, False, phase + "_disable")
                remove(uuid, phase)
            phase = "timestamp"
            put(phase, 0)
            time.sleep(3)
            cut = time.time()
            capture["timestamp_cut"] = cut
            time.sleep(3)
            put(phase, 1)
            uuid = configure(phase, StartingPosition="AT_TIMESTAMP", StartingPositionTimestamp=cut)
            update(uuid, True, phase + "_enable")
            collect(phase)
            update(uuid, False, phase + "_disable")
            remove(uuid, phase)
            phase = "latest"
            put(phase, 0)
            uuid = configure(phase, StartingPosition="LATEST", Enabled=True, BatchSize=1, MaximumBatchingWindowInSeconds=0)
            time.sleep(70)
            put(phase, 1)
            collect(phase)
            update(uuid, False, phase + "_disable")
            time.sleep(15)
            put(phase, 2)
            collect(phase, minimum=0, quiet=15, timeout=25, label="latest_while_disabled")
            update(uuid, True, phase + "_reenable")
            put(phase, 3)
            collect(phase, minimum=3, label="latest_reenabled")
            update(uuid, False, phase + "_disable_final")
            remove(uuid, phase)
        if args.only in ("all", "delivery", "aggregation", "reshard"):
            for phase, source in (("kpl_standard", stream), ("kpl_consumer", consumer)):
                uuid = configure(phase, source, StartingPosition="AT_TIMESTAMP", StartingPositionTimestamp=time.time(), FilterCriteria={})
                put(phase, "aggregate", data=aggregate([{"phase": phase, "ordinal": i} for i in range(1, 4)]))
                update(uuid, True, phase + "_enable")
                collect(phase)
                update(uuid, False, phase + "_disable")
                remove(uuid, phase)
        if args.only in ("all", "delivery", "topology", "reshard"):
            # Build closed-parent ancestry with actual records before enabling the poller.
            phase = "topology"
            parent = stream_ready("topology_initial")["Shards"][0]["ShardId"]
            put(phase, "parent", 0, delay=2)
            require(record("split_parent", "kinesis", "split-shard", {"StreamName": prefix, "ShardToSplit": parent, "NewStartingHashKey": str(2 ** 127)}))
            split = stream_ready("split_ready")
            children = [shard for shard in split["Shards"] if "EndingSequenceNumber" not in shard["SequenceNumberRange"]]
            routing_ready("split", split)
            put(phase, "left", 0, delay=2)
            put(phase, "right", 2 ** 128 - 1, delay=2)
            require(record("merge_children", "kinesis", "merge-shards", {"StreamName": prefix, "ShardToMerge": children[0]["ShardId"], "AdjacentShardToMerge": children[1]["ShardId"]}))
            routing_ready("merge", stream_ready("merge_ready"))
            put(phase, "merged", 0)
            uuid = configure(phase, BatchSize=1, MaximumBatchingWindowInSeconds=0)
            update(uuid, True, phase + "_enable")
            collect(phase, minimum=4, timeout=240)
            update(uuid, False, phase + "_disable")
            remove(uuid, phase)
        if args.only in ("all", "hash_range", "reshard"):
            topology = stream_ready("hash_initial")
            parent = next(shard["ShardId"] for shard in topology["Shards"] if "EndingSequenceNumber" not in shard["SequenceNumberRange"])
            require(record("hash_split_parent", "kinesis", "split-shard", {"StreamName": prefix, "ShardToSplit": parent, "NewStartingHashKey": str(2 ** 127)}))
            routing_ready("hash_split", stream_ready("hash_split_ready"))
            for phase, source in (("hash_standard", stream), ("hash_consumer", consumer)):
                uuid = configure(phase, source, BatchSize=10, StartingPosition="AT_TIMESTAMP", StartingPositionTimestamp=time.time(), FilterCriteria={})
                put(phase, "control", 0, data=aggregate([{"phase": phase, "ordinal": "control"}], hash_keys=[0]))
                items = [{"phase": phase, "ordinal": ordinal} for ordinal in ("mixed_in_first", "mixed_out", "mixed_in_last")]
                put(phase, "mixed", 0, data=aggregate(items, hash_keys=[0, 2 ** 128 - 1, 0]))
                put(phase, "sentinel", 0)
                update(uuid, True, phase + "_enable")
                collect(phase, quiet=20)
                update(uuid, False, phase + "_disable")
                remove(uuid, phase)
        if args.only in ("all", "destination", "oversized"):
            owned["queue"] = require(record("create_destination", "sqs", "create-queue", {"QueueName": prefix + "-failure", "Attributes": {"MessageRetentionPeriod": "3600"}}))["QueueUrl"]
            queue_arn = require(record("destination_arn", "sqs", "get-queue-attributes", {"QueueUrl": owned["queue"], "AttributeNames": ["QueueArn"]}))["Attributes"]["QueueArn"]
            policy("owned-destination", [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}])
            time.sleep(15)
            capture["destination_messages"] = []
            seen_messages = set()
            phases = [("consumer_destination", consumer), ("standard_destination", stream)]
            if args.only in ("all", "oversized"):
                require(record("set_max_record_size", "kinesis", "update-max-record-size", {"StreamARN": stream, "MaxRecordSizeInKiB": 10240}))
                require(record("max_record_size", "kinesis", "describe-stream-summary", {"StreamARN": stream}))
                stream_ready("max_record_size_ready")
                phases = ([] if args.only == "oversized" else phases) + [("consumer_oversized", consumer), ("standard_oversized", stream)]
            for phase, source in phases:
                oversized = phase.endswith("_oversized")
                uuid = configure(phase, source, BatchSize=1, MaximumBatchingWindowInSeconds=0,
                                 MaximumRetryAttempts=args.oversized_retries if oversized else 0, MaximumRecordAgeInSeconds=60 if oversized else 600,
                                 FunctionResponseTypes=["ReportBatchItemFailures"], DestinationConfig={"OnFailure": {"Destination": queue_arn}})
                if oversized:
                    # Warm first, so the large record does not simply age out
                    # during eventually consistent poller creation.
                    put(phase, 0)
                    update(uuid, True, phase + "_enable")
                    for attempt in range(60):
                        scan(phase + "_warm_logs_" + str(attempt))
                        if matching(phase):
                            break
                        if attempt % 4 == 0:
                            put(phase, 0)
                        time.sleep(5)
                    else:
                        raise RuntimeError("No warm poller observed before oversized record: " + phase)
                    collect(phase, timeout=20, quiet=3)
                    payload = {"phase": phase, "ordinal": 1, "padding": ""}
                    payload["padding"] = "x" * (5 * 1024 * 1024 - len(json.dumps(payload).encode()))
                    encoded = json.dumps(payload).encode()
                    capture.setdefault("oversized_payloads", {})[phase] = {"raw_bytes": len(encoded), "base64_bytes": len(base64.b64encode(encoded)), "sha256": hashlib.sha256(encoded).hexdigest()}
                    failed_sequence = put(phase, 1, data=encoded)["SequenceNumber"]
                    capture["oversized_payloads"][phase]["sequence_number"] = failed_sequence
                    put(phase, 2)
                    collect(phase, minimum=2, timeout=180, label=phase + "_after_large", ordinal=2)
                else:
                    failed_sequence = put(phase, 1, bad=True)["SequenceNumber"]
                    update(uuid, True, phase + "_enable")
                    collect(phase)
                found = False
                for attempt in range(24):
                    received = require(record(phase + "_destination_" + str(attempt), "sqs", "receive-message",
                                              {"QueueUrl": owned["queue"], "MaxNumberOfMessages": 10, "WaitTimeSeconds": 5, "VisibilityTimeout": 1, "MessageSystemAttributeNames": ["All"]}))
                    for message in received.get("Messages", []):
                        if message["MessageId"] not in seen_messages:
                            capture["destination_messages"].append(message)
                            seen_messages.add(message["MessageId"])
                        body = json.loads(message["Body"])
                        found = found or (body.get("requestContext", {}).get("functionArn", "").endswith(":" + phase)
                                          and body.get("KinesisBatchInfo", {}).get("startSequenceNumber") == failed_sequence)
                    save()
                    if found:
                        break
                    time.sleep(2)
                if not found:
                    capture["limitations"].append("No failure destination message in bounded window: " + phase)
                update(uuid, False, phase + "_disable")
                remove(uuid, phase)
        capture["workflow_complete"] = True
    except Exception as error:
        capture["workflow_error"] = str(error)
        raise
    finally:
        capture["log_events"] = list(events.values())
        errors = []

        def clean(label, service, operation, parameters, allowed=("Success",)):
            try:
                result = record(label, service, operation, parameters, True)
                if result["code"] not in allowed:
                    errors.append({"label": label, "result": result})
                return result
            except Exception as error:
                errors.append({"label": label, "error": str(error)})
                return {}

        for uuid in list(owned["mappings"]):
            clean("delete_mapping", "lambda", "delete-event-source-mapping", {"UUID": uuid}, ("Success", "ResourceNotFoundException"))
            try:
                settle(uuid, "absent", "mapping_absent", cleanup=True)
            except Exception as error:
                errors.append(str(error))
        if owned["function"]:
            clean("delete_function", "lambda", "delete-function", {"FunctionName": prefix})
            clean("function_absent", "lambda", "get-function-configuration", {"FunctionName": prefix}, ("ResourceNotFoundException",))
        if owned["consumer"]:
            clean("deregister_consumer", "kinesis", "deregister-stream-consumer", {"ConsumerARN": owned["consumer"]}, ("Success", "ResourceNotFoundException"))
            for attempt in range(60):
                result = record("consumer_absent_" + str(attempt), "kinesis", "describe-stream-consumer", {"ConsumerARN": owned["consumer"]}, True)
                if result["code"] == "ResourceNotFoundException":
                    break
                time.sleep(2)
            else:
                errors.append("Consumer remains")
        if owned["stream"]:
            clean("delete_stream", "kinesis", "delete-stream", {"StreamName": prefix, "EnforceConsumerDeletion": True})
            for attempt in range(90):
                result = record("stream_absent_" + str(attempt), "kinesis", "describe-stream-summary", {"StreamName": prefix}, True)
                if result["code"] == "ResourceNotFoundException":
                    break
                time.sleep(2)
            else:
                errors.append("Stream remains")
        if owned["queue"]:
            clean("delete_destination", "sqs", "delete-queue", {"QueueUrl": owned["queue"]})
            clean("destination_absent", "sqs", "get-queue-url", {"QueueName": prefix + "-failure"}, ("AWS.SimpleQueueService.NonExistentQueue",))
        if owned["logs"]:
            clean("delete_logs", "logs", "delete-log-group", {"logGroupName": log_group}, ("Success", "ResourceNotFoundException"))
            result = clean("logs_absent", "logs", "describe-log-groups", {"logGroupNamePrefix": log_group})
            if result.get("output", {}).get("logGroups"):
                errors.append("Log group remains")
        for name in sorted(owned["policies"]):
            clean("delete_policy_" + name, "iam", "delete-role-policy", {"RoleName": role_name, "PolicyName": name})
            clean("policy_absent_" + name, "iam", "get-role-policy", {"RoleName": role_name, "PolicyName": name}, ("NoSuchEntity",))
        if owned["role"]:
            clean("delete_role", "iam", "delete-role", {"RoleName": role_name})
            clean("role_absent", "iam", "get-role", {"RoleName": role_name}, ("NoSuchEntity",))
        capture["cleanup_errors"] = errors
        capture["cleanup_verified"] = not errors
        capture["finished_at"] = now()
        # Preserve all native log fields once, replacing repeated polling copies.
        for row in capture["observations"]:
            if row["service"] == "logs" and row["operation"] == "filter-log-events":
                for index, event in enumerate(row["result"].get("output", {}).get("events", [])):
                    if event.get("eventId") in events and events[event["eventId"]] == event:
                        row["result"]["output"]["events"][index] = {"event_id_ref": event["eventId"]}
        capture["encoding"] = "event_id_ref expands losslessly to this run's log_events object with the same eventId. All other native output fields are retained except opaque SQS ReceiptHandle capabilities."
        compact_blobs(capture)
        save()
        if errors:
            raise RuntimeError("Owned resource cleanup failed: " + json.dumps(errors))


if __name__ == "__main__":
    main()
