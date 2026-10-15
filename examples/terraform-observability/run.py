"""Exercise retained observability owners with Terraform AWS 6.68.0 and real consumers.

No runtime is simulated. --stream-runtime requires a prepared real Kinesis Docker
backend. SSM document reads do not claim official-agent command execution.
"""

from datetime import datetime, timedelta, timezone
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import shutil
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler
import uuid
import zipfile

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local import (ACCOUNT, arguments, client, controller, environment,
                   expect_missing, require, workspace)

HTTP = build_opener(ProxyHandler({}))
SIGNATURE = "META_INF/aws_signer_signature_v1.0.SF"


def poll(label, callback, seconds=90):
    deadline = time.monotonic() + seconds
    while True:
        result = callback()
        if result:
            return result
        require(time.monotonic() < deadline, f"Timed out: {label}")
        time.sleep(0.25)


def body(s3, bucket, key):
    stream = s3.get_object(Bucket=bucket, Key=key)["Body"]
    try:
        return stream.read()
    finally:
        stream.close()


def clock(endpoint, advance=None):
    data = None if advance is None else json.dumps({"advance": advance}).encode()
    request = Request(endpoint + "/_stackd/clock", data=data,
                      headers={"Content-Type": "application/json"})
    with HTTP.open(request, timeout=30) as response:
        result = json.load(response)
    if advance is not None:
        with HTTP.open(Request(endpoint + "/_stackd/jobs/drain?limit=4096", data=b""), timeout=60) as response:
            json.load(response)
    return datetime.fromisoformat(result["time"].replace("Z", "+00:00"))


def signing_consumer(endpoint, root, output):
    signer, s3 = client("signer", endpoint), client("s3", endpoint)
    job = signer.describe_signing_job(jobId=output["signing_job"])
    require(job["status"] == "Succeeded", f"Signing failed: {job}")
    location = job["signedObject"]["s3"]
    signed = body(s3, location["bucketName"], location["key"])
    digest = hashlib.sha384()
    with zipfile.ZipFile(io.BytesIO(signed)) as archive:
        require(archive.read("payload.bin") == b"actual unsigned source\x00\xff", "Signing changed source bytes")
        signature = archive.read(SIGNATURE)
        for entry in archive.infolist():
            if entry.filename != SIGNATURE:
                digest.update(entry.filename.encode("utf-8"))
                digest.update(archive.read(entry))
    (root / "signature.pem").write_bytes(signature)
    (root / "detached-content.bin").write_bytes(digest.digest())
    # Trust comes from the authoritative owner in this private, owned database,
    # never from a certificate selected from the untrusted signature envelope.
    with sqlite3.connect(f"file:{root / 'stackd.sqlite'}?mode=ro", uri=True) as database:
        row = database.execute("SELECT certificate FROM signer_authorities WHERE partition=? AND account_id=? AND region=?", ("aws", ACCOUNT, "us-east-1")).fetchone()
    require(row is not None, "Signer did not retain an actual signing authority")
    (root / "signer-root.der").write_bytes(row[0])
    subprocess.run(["openssl", "x509", "-inform", "DER", "-in", str(root / "signer-root.der"), "-out", str(root / "signer-root.pem")], check=True)
    verify = ["openssl", "cms", "-verify", "-binary", "-inform", "PEM", "-in", str(root / "signature.pem"), "-content", str(root / "detached-content.bin"), "-CAfile", str(root / "signer-root.pem"), "-purpose", "any", "-attime", str(int(clock(endpoint).timestamp())), "-out", str(root / "verified-content.bin")]
    subprocess.run(verify, check=True)
    require((root / "verified-content.bin").read_bytes() == digest.digest(), "CMS verification changed detached content")
    (root / "detached-content.bin").write_bytes(b"wrong digest")
    rejected = subprocess.run(verify, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    require(rejected.returncode != 0, "Modified source digest passed cryptographic verification")
    print("Consumer: real signed ZIP bytes, authoritative local CA, valid CMS and tamper rejection", flush=True)
    return hashlib.sha256(signed).hexdigest()


def certificate_consumer(endpoint, root, output):
    acm = client("acm", endpoint)
    imported = acm.get_certificate(CertificateArn=output["certificate"])
    require(imported["Certificate"] == (root / "certificate.pem").read_text(), "Imported ACM certificate bytes changed")
    exported = acm.export_certificate(CertificateArn=output["requested_certificate"], Passphrase=b"local-export-passphrase")
    (root / "issued.pem").write_text(exported["Certificate"])
    (root / "issued-root.pem").write_text(exported["CertificateChain"])
    (root / "issued-encrypted-key.pem").write_text(exported["PrivateKey"])
    subprocess.run(["openssl", "verify", "-CAfile", str(root / "issued-root.pem"), "-attime", str(int(clock(endpoint).timestamp())), str(root / "issued.pem")], check=True)
    subprocess.run(["openssl", "pkey", "-in", str(root / "issued-encrypted-key.pem"), "-passin", "stdin", "-out", str(root / "issued-key.pem")], input=b"local-export-passphrase\n", check=True)
    (root / "issued-key.pem").chmod(0o600)
    # A real local TLS handshake consumes the exported key and owner certificate.
    listener = ThreadingHTTPServer(("127.0.0.1", 0), Payload)
    listener.payload = b"real certificate consumer"
    listener.requests = 0
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / "issued.pem", root / "issued-key.pem")
    listener.socket = context.wrap_socket(listener.socket, server_side=True)
    worker = threading.Thread(target=listener.serve_forever, daemon=True)
    worker.start()
    try:
        trust = ssl.create_default_context(cafile=str(root / "issued-root.pem"))
        import socket
        with socket.create_connection(listener.server_address, timeout=5) as connection:
            with trust.wrap_socket(connection, server_hostname="tls." + output["name"] + ".example.test") as connection:
                connection.sendall(b"GET / HTTP/1.0\r\nHost: fixture\r\n\r\n")
                response = bytearray()
                while True:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    response.extend(chunk)
        require(response.endswith(listener.payload), "TLS consumer did not receive real response bytes")
    finally:
        listener.shutdown()
        listener.server_close()
        worker.join()
    print("Consumer: DNS-issued X.509 chain, encrypted key export and verified TLS bytes", flush=True)


class Payload(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests += 1
        payload = self.server.payload
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


def consumers(endpoint, root, output, stream, target, protected, previous=False):
    revision = output["revision"]
    logs, metrics, ssm, xray, s3, config, gd = [client(service, endpoint) for service in ("logs", "cloudwatch", "ssm", "xray", "s3", "config", "guardduty")]
    now = clock(endpoint)
    group = logs.describe_log_groups(logGroupNamePrefix=output["log_group"])["logGroups"]
    require(len(group) == 1 and group[0]["deletionProtectionEnabled"] == protected, "Deletion protection state differs from Terraform")
    require(group[0]["metricFilterCount"] == 1, "Terraform log-group data source did not receive the actual filter count")
    dashboard = json.loads(metrics.get_dashboard(DashboardName=output["dashboard"])["DashboardBody"])
    require(dashboard["widgets"][0]["properties"]["title"] == revision, "Dashboard owner lost actual updated document")
    iterator = None
    stream_record = None
    if stream:
        kinesis = client("kinesis", endpoint)
        shards = kinesis.list_shards(StreamName=stream["name"])["Shards"]
        require(len(shards) == 1, "Native log consumer needs one real shard")
        iterator = kinesis.get_shard_iterator(StreamName=stream["name"], ShardId=shards[0]["ShardId"], ShardIteratorType="LATEST")["ShardIterator"]
    message = json.dumps({"revision": revision, "bytes": "retained-log"}, sort_keys=True)
    logs.put_log_events(logGroupName=output["log_group"], logStreamName=output["log_stream"], logEvents=[{"timestamp": int(now.timestamp() * 1000), "message": message}])
    require(any(row["message"] == message for row in logs.get_log_events(logGroupName=output["log_group"], logStreamName=output["log_stream"])["events"]), "Independent log reader lost original message bytes")
    if protected:
        expect_missing(logs.delete_log_group, {"ValidationException"}, logGroupName=output["log_group"])
        require(any(row["message"] == message for row in logs.get_log_events(logGroupName=output["log_group"], logStreamName=output["log_stream"])["events"]), "Rejected delete changed retained log bytes")
        events = client("cloudtrail", endpoint).lookup_events(LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "PutLogGroupDeletionProtection"}])["Events"]
        require(any(event["EventName"] == "PutLogGroupDeletionProtection" for event in events), "Protection update did not commit its management audit event")
    samples = metrics.get_metric_statistics(Namespace=output["name"], MetricName="Events", StartTime=now - timedelta(minutes=1), EndTime=now + timedelta(minutes=1), Period=60, Statistics=["Sum"])["Datapoints"]
    require(sum(row.get("Sum", 0) for row in samples) >= 1, "Log metric filter did not publish an actual metric sample")
    if stream:
        def consume_stream():
            nonlocal iterator
            records = kinesis.get_records(ShardIterator=iterator)
            iterator = records["NextShardIterator"]
            for record in records["Records"]:
                value = json.loads(gzip.decompress(record["Data"]))
                if any(event["message"] == message for event in value.get("logEvents", [])):
                    return value
            return None
        stream_record = poll("actual compressed Logs subscription record", consume_stream)
        require(stream_record["logGroup"] == output["log_group"]
                and stream_record["logStream"] == output["log_stream"],
                "Native subscription record identifies a different Logs owner")
        print(f"Consumer: native Kinesis gzip record for {stream_record['logGroup']} "
              f"with {len(stream_record['logEvents'])} original log events", flush=True)
    for kind, name in output["parameters"].items():
        value = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]
        expected = revision + ",bytes" if kind == "StringList" else revision
        require(value["Value"] == expected and value["Type"] == kind, "Parameter owner returned different live value/type")
        if kind == "SecureString":
            encrypted = ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"]["Value"]
            require(encrypted != expected, "SecureString returned plaintext on ciphertext read")
        if previous:
            history = ssm.get_parameter_history(Name=name, WithDecryption=True)["Parameters"]
            require(any(row["Value"].startswith("initial") for row in history), "Parameter update lost original version")
    document = json.loads(ssm.get_document(Name=output["document"], DocumentVersion="$LATEST")["Content"])
    require(document["description"] == revision, "Versioned SSM document does not contain updated content")
    setting = ssm.get_service_setting(SettingId="arn:aws:ssm:us-east-1:" + ACCOUNT + ":servicesetting/ssm/parameter-store/default-parameter-tier")["ServiceSetting"]
    require(setting["SettingValue"] == ("Standard" if revision == "initial" else "Advanced"), "Service setting did not change current tier authority")
    require(not ssm.describe_instance_information()["InstanceInformationList"], "Isolated fixture unexpectedly found a managed agent")
    trace = "1-" + format(int(now.timestamp()), "08x") + "-" + uuid.uuid4().hex[:24]
    segment = {"trace_id": trace, "id": uuid.uuid4().hex[:16], "name": output["name"], "start_time": now.timestamp() - 0.1, "end_time": now.timestamp(), "annotations": {"revision": revision}, "http": {"request": {"method": "GET", "url": "http://fixture/"}, "response": {"status": 200}}}
    require(not xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment)]).get("UnprocessedTraceSegments"), "XRay rejected actual trace document")
    read = xray.batch_get_traces(TraceIds=[trace])["Traces"]
    require(len(read) == 1 and json.loads(read[0]["Segments"][0]["Document"])["annotations"]["revision"] == revision, "Trace consumer lost real segment annotations")
    require(any(row["SamplingRule"]["RuleName"] == output["sampling_rule"] for row in xray.get_sampling_rules()["SamplingRuleRecords"]), "Sampling rule missing from actual read")
    group = xray.get_group(GroupARN=output["xray_group"])["Group"]
    summaries = xray.get_trace_summaries(StartTime=now - timedelta(minutes=1), EndTime=now + timedelta(minutes=1), FilterExpression=group["FilterExpression"])["TraceSummaries"]
    require(any(row["Id"] == trace for row in summaries), "XRay group filter did not select the actual trace")
    target.payload = b"actual upstream HTTP bytes:" + revision.encode()
    url = endpoint + "/_stackd/execute-api/" + output["api_id"] + "/live/"
    with HTTP.open(url, timeout=10) as response:
        require(response.read() == target.payload, "WAF-associated API did not forward actual upstream bytes")
    before = target.requests
    for headers in ({"x-fixture": "block"}, {"x-client-ip": "192.0.2.1"}):
        try:
            HTTP.open(Request(url, headers=headers), timeout=10)
        except HTTPError as error:
            require(error.code == 403, f"WAF denial returned {error.code}")
        else:
            raise RuntimeError("WAF rule did not block the real HTTP request")
    require(target.requests == before, "WAF forwarded a blocked request to the real upstream")
    standalone = endpoint + "/_stackd/execute-api/" + output["api_id"] + "/standalone/"
    with HTTP.open(standalone, timeout=10) as response:
        require(response.read() == target.payload, "Standalone-rule ACL lost actual upstream bytes")
    before = target.requests
    try:
        HTTP.open(Request(standalone, headers={"x-managed": revision}), timeout=10)
    except HTTPError as error:
        require(error.code == 403, f"Standalone WAF rule returned {error.code}")
    else:
        raise RuntimeError("Terraform standalone WAF rule did not block a matching real request")
    require(target.requests == before, "Standalone WAF rule forwarded a blocked request")
    found = config.list_discovered_resources(resourceType="AWS::S3::Bucket")["resourceIdentifiers"]
    require(any(row["resourceId"] == output["bucket"] for row in found), "Config did not record current bucket owner")
    history = config.get_resource_config_history(resourceType="AWS::S3::Bucket", resourceId=output["bucket"])["configurationItems"]
    require(history and history[0]["tags"]["Fixture"] == output["name"], "Config history did not capture actual owner tags")
    aggregate = config.get_aggregate_resource_config(ConfigurationAggregatorName=output["aggregator"], ResourceIdentifier={"SourceAccountId": ACCOUNT, "SourceRegion": "us-east-1", "ResourceType": "AWS::S3::Bucket", "ResourceId": output["bucket"]})["ConfigurationItem"]
    require(aggregate["tags"]["Fixture"] == output["name"], "Config aggregator did not read the actual authorized source item")
    evaluations = config.get_compliance_details_by_config_rule(ConfigRuleName=output["config_rule"])["EvaluationResults"]
    require(any(row["ComplianceType"] == "COMPLIANT" and row["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"] == output["bucket"] for row in evaluations), "Managed Config rule did not evaluate the actual bucket tags")
    config.deliver_config_snapshot(deliveryChannelName=output["channel"])
    # The source request is an actual successful API call, not a sample finding.
    s3.put_bucket_tagging(Bucket=output["bucket"], Tagging={"TagSet": [{"Key": "Fixture", "Value": output["name"]}, {"Key": "Revision", "Value": revision}]})
    findings = gd.list_findings(DetectorId=output["detector"])["FindingIds"]
    require(findings, "GuardDuty did not evaluate actual root-credential API evidence")
    actual = gd.get_findings(DetectorId=output["detector"], FindingIds=findings[:50])["Findings"]
    require(any(row["Type"] == "Policy:IAMUser/RootCredentialUsage" for row in actual), "GuardDuty findings lack actual root credential evidence")
    require(gd.get_ip_set(DetectorId=output["detector"], IpSetId=output["trusted_list"].split(":")[-1])["Status"] == "ACTIVE", "Trusted IP list was not actually ingested")
    require(gd.get_threat_intel_set(DetectorId=output["detector"], ThreatIntelSetId=output["threat_list"].split(":")[-1])["Status"] == "ACTIVE", "Threat list was not actually ingested")
    clock(endpoint, "1m")
    def alarms_evaluated():
        alarms = metrics.describe_alarms(AlarmNames=[output["metric_alarm"], output["composite_alarm"]])
        rows = alarms.get("MetricAlarms", []) + alarms.get("CompositeAlarms", [])
        return len(rows) == 2 and all(row["StateValue"] == "ALARM" for row in rows)
    poll("metric and composite evaluation from real log sample", alarms_evaluated)
    clock(endpoint, "0s" if previous else "5m")
    def evidence_objects():
        objects = s3.list_objects_v2(Bucket=output["bucket"])["Contents"]
        trail, snapshot = [], []
        for item in objects:
            key = item["Key"]
            if key.startswith("trail/") and key.endswith(".json.gz"):
                trail.extend(json.loads(gzip.decompress(body(s3, output["bucket"], key)))["Records"])
            if key.startswith("config/") and "ConfigSnapshot" in key and key.endswith(".json.gz"):
                snapshot.extend(json.loads(gzip.decompress(body(s3, output["bucket"], key))).get("configurationItems", []))
        return (trail, snapshot) if trail and snapshot else None
    trail, snapshot = poll("actual CloudTrail and Config gzip S3 evidence", evidence_objects)
    require(any(row["eventName"] == "PutParameter" for row in trail), "CloudTrail gzip lacks real Parameter Store API event")
    require(any(row["resourceId"] == output["bucket"] for row in snapshot), "Config snapshot lacks actual bucket observation")
    def exported_findings():
        objects = s3.list_objects_v2(Bucket=output["signing_bucket"]).get("Contents", [])
        for item in objects:
            if "/GuardDuty/" not in item["Key"] or not item["Key"].endswith(".jsonl.gz"):
                continue
            metadata = s3.head_object(Bucket=output["signing_bucket"], Key=item["Key"])
            require(metadata.get("ServerSideEncryption") == "aws:kms", "GuardDuty export is not encrypted by the real KMS owner")
            rows = [json.loads(line) for line in gzip.decompress(body(s3, output["signing_bucket"], item["Key"])).splitlines()]
            if any(row.get("type") == "Policy:IAMUser/RootCredentialUsage" for row in rows):
                return rows
        return None
    poll("actual KMS-encrypted GuardDuty finding export", exported_findings)
    print("Consumer: original log bytes, extracted metrics, retained SSM versions/ciphertext, real trace, WAF packet denial, GuardDuty evidence and gzip trail/config", flush=True)
    certificate_consumer(endpoint, root, output)
    return {"revision": revision, "trace_id": trace, "signing_sha256": signing_consumer(endpoint, root, output), "trail_records": len(trail), "config_items": len(snapshot), "finding_count": len(findings),
            "native_log_record": stream_record}


def main():
    parser = arguments(__doc__, 14741)
    parser.add_argument("--provider-mirror", type=Path)
    parser.add_argument("--stream-runtime", action="store_true", help="Use the real, prepared Kinesis Docker backend for Logs subscription delivery")
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    args = parser.parse_args()
    require(shutil.which("terraform") and shutil.which("openssl"), "Install Terraform 1.15.9 and OpenSSL first")
    root = workspace(args, "terraform-observability")
    root.chmod(0o700)
    for source in Path(__file__).resolve().parent.glob("*.tf"):
        shutil.copyfile(source, root / source.name)
    env = environment()
    rc = "disable_checkpoint = true\n"
    if args.provider_mirror:
        require(args.provider_mirror.is_dir(), "Provider mirror does not exist")
        rc += "provider_installation {\n filesystem_mirror {\n path = " + json.dumps(str(args.provider_mirror.resolve())) + '\n include = ["registry.terraform.io/hashicorp/aws"]\n }\n}\n'
    (root / "terraform.rc").write_text(rc)
    env["TF_CLI_CONFIG_FILE"] = str(root / "terraform.rc")
    name = "obs-" + uuid.uuid4().hex[:12]
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=" + name + ".example.test", "-addext", "subjectAltName=DNS:" + name + ".example.test", "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth", "-keyout", str(root / "private-key.pem"), "-out", str(root / "certificate.pem")], check=True)
    (root / "private-key.pem").chmod(0o600)
    with zipfile.ZipFile(root / "source.zip", "w") as archive:
        archive.writestr("payload.bin", b"actual unsigned source\x00\xff")
    target = ThreadingHTTPServer(("127.0.0.1", args.port + 2), Payload)
    target.payload, target.requests = b"initial upstream", 0
    worker = threading.Thread(target=target.serve_forever, daemon=True)
    worker.start()
    variables = {"name": name, "revision": "initial", "protected": False, "certificate": (root / "certificate.pem").read_text(), "private_key": (root / "private-key.pem").read_text(), "source_zip": str(root / "source.zip"), "target_url": f"http://127.0.0.1:{args.port + 2}/", "stream_runtime": args.stream_runtime}
    initial_time = datetime.now(timezone.utc).isoformat()
    extra = ["-dns-listen", f"127.0.0.1:{args.port + 1}", "-clock-start", initial_time]
    if args.stream_runtime:
        extra += ["-docker-host", args.docker_host, "-kinesis-runtime"]
    endpoint = f"http://127.0.0.1:{args.port}"
    variables["endpoint"] = endpoint
    evidence = {"provider": "6.68.0", "stream_runtime": args.stream_runtime,
                "stages": [], "consumers": [], "failures": [], "cleanup": "not attempted"}

    def tfvars():
        path = root / "local.auto.tfvars.json"
        path.write_text(json.dumps(variables))
        path.chmod(0o600)

    def terraform(*command, capture=False, check=True):
        print("terraform", *command, flush=True)
        process = subprocess.Popen(["terraform", *command], cwd=root, env=env, text=True,
                                   stdout=subprocess.PIPE if capture else None,
                                   stderr=subprocess.PIPE if capture else None)
        while process.poll() is None:
            try:
                stdout, stderr = process.communicate(timeout=1)
                break
            except subprocess.TimeoutExpired:
                clock(endpoint, "1s")
        else:
            stdout, stderr = process.communicate()
        result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        if check and result.returncode:
            raise subprocess.CalledProcessError(result.returncode, command, stdout, stderr)
        return result

    def output(key):
        return json.loads(terraform("output", "-json", key, capture=True).stdout)

    def noop(refresh=False):
        command = ["plan", "-input=false", "-detailed-exitcode"]
        if refresh:
            command.append("-refresh-only")
        result = terraform(*command, check=False)
        require(result.returncode == 0, f"No-op {'refresh' if refresh else 'plan'} failed: {result.returncode}")

    def destroy():
        evidence["cleanup"] = "attempted"
        variables["protected"] = False
        tfvars()
        # Protection must be explicitly disabled before destructive cleanup.
        try:
            client("logs", endpoint).put_log_group_deletion_protection(logGroupIdentifier="/" + name + "/application", deletionProtectionEnabled=False)
        except ClientError as error:
            require(error.response["Error"]["Code"] == "ResourceNotFoundException", str(error))
        terraform("destroy", "-input=false", "-auto-approve")
        if "native_acl_arn" in variables:
            waf = client("wafv2", endpoint)
            actual = waf.get_web_acl(Name=name + "-standalone", Scope="REGIONAL", Id=native["Id"])
            require(not actual["WebACL"].get("Rules"), "Terraform destroy retained its standalone WAF rule")
            waf.delete_web_acl(Name=name + "-standalone", Scope="REGIONAL", Id=native["Id"], LockToken=actual["LockToken"])
        evidence["cleanup"] = "Terraform destroy and native ACL delete completed"

    try:
        tfvars()
        with controller(args, root, extra=extra):
            try:
                waf = client("wafv2", endpoint)
                native = waf.create_web_acl(Name=name + "-standalone", Scope="REGIONAL", DefaultAction={"Allow": {}}, Rules=[], VisibilityConfig={"CloudWatchMetricsEnabled": True, "MetricName": name + "-standalone", "SampledRequestsEnabled": True})["Summary"]
                variables["native_acl_arn"] = native["ARN"]
                tfvars()
                terraform("init", "-input=false")
                terraform("apply", "-input=false", "-auto-approve")
                value, stream = output("application"), output("stream")
                evidence["stages"].append("create/read")
                evidence["consumers"].append(consumers(endpoint, root, value, stream, target, False))
                policy = json.loads(output("provider_policy_document"))
                require(len(policy["Statement"]) == 2, "Provider-local policy data source did not compute both operation statements")
                state = json.loads(terraform("show", "-json", capture=True).stdout)
                owned_prefixes = ("aws_cloudwatch_", "aws_cloudtrail", "aws_config_", "aws_guardduty_", "aws_wafv2_", "aws_xray_", "aws_ssm_", "aws_acm_", "aws_signer_")
                for resource in state["values"]["root_module"]["resources"]:
                    kind, address, values = resource["type"], resource["address"], resource["values"]
                    if resource["mode"] != "managed" or not kind.startswith(owned_prefixes) or kind == "aws_acm_certificate_validation":
                        continue
                    identifier = values.get("id")
                    if kind in ("aws_cloudwatch_log_stream", "aws_cloudwatch_log_metric_filter"):
                        identifier = values["log_group_name"] + ":" + values["name"]
                    elif kind == "aws_cloudwatch_log_subscription_filter":
                        identifier = values["log_group_name"] + "|" + values["name"]
                    elif kind in ("aws_wafv2_ip_set", "aws_wafv2_web_acl"):
                        identifier = values["id"] + "/" + values["name"] + "/" + values["scope"]
                    elif kind == "aws_wafv2_web_acl_rule":
                        identifier = values["web_acl_arn"] + "," + values["name"]
                    elif kind == "aws_xray_resource_policy":
                        identifier = values["policy_name"]
                    require(identifier, "No import identity for " + address)
                    terraform("state", "rm", address)
                    terraform("import", "-input=false", address, identifier)
                evidence["stages"].append("import")
                noop()
                variables.update(revision="updated", protected=True)
                tfvars()
                terraform("apply", "-input=false", "-auto-approve")
                value, stream = output("application"), output("stream")
                evidence["consumers"].append(consumers(endpoint, root, value, stream, target, True, previous=True))
                noop(refresh=True)
                noop()
                evidence["stages"].append("update/refresh/no-op")
            except BaseException as error:
                evidence["failures"].append({"stage": "lifecycle", "error": str(error)})
                try:
                    destroy()
                except BaseException as cleanup_error:
                    evidence["cleanup"] = "failed"
                    evidence["failures"].append({"stage": "cleanup", "error": str(cleanup_error)})
                    raise error from cleanup_error
                raise
        with controller(args, root, extra=extra):
            try:
                value = output("application")
                noop(refresh=True)
                noop()
                require(client("logs", endpoint).describe_log_groups(logGroupNamePrefix=value["log_group"])["logGroups"][0]["deletionProtectionEnabled"], "Restart lost actual deletion protection")
                require(client("ssm", endpoint).get_parameter(Name=value["parameters"]["SecureString"], WithDecryption=True)["Parameter"]["Value"] == "updated", "Restart lost live encrypted parameter")
                signing_consumer(endpoint, root, value)
                evidence["stages"].append("SQLite restart/refresh")
            finally:
                destroy()
            expect_missing(client("logs", endpoint).get_log_events, {"ResourceNotFoundException"}, logGroupName=value["log_group"], logStreamName=value["log_stream"])
            for name_ in value["parameters"].values():
                expect_missing(client("ssm", endpoint).get_parameter, {"ParameterNotFound"}, Name=name_)
            expect_missing(client("acm", endpoint).describe_certificate, {"ResourceNotFoundException"}, CertificateArn=value["certificate"])
            expect_missing(client("s3", endpoint).head_bucket, {"404", "NoSuchBucket", "NotFound"}, Bucket=value["bucket"])
            require(not client("guardduty", endpoint).list_detectors()["DetectorIds"], "Destroy retained detector")
            require(client("signer", endpoint).get_signing_profile(profileName=value["profile"])["status"] == "Canceled", "Signer profile was not canceled")
            # AWS jobs are immutable; provider deletion is deliberately state-only.
            require(client("signer", endpoint).describe_signing_job(jobId=value["signing_job"])["status"] == "Succeeded", "Destroy rewrote immutable signing history")
            state = json.loads(terraform("show", "-json", capture=True).stdout)
            require(not state.get("values", {}).get("root_module", {}).get("resources"), "Terraform state retained resources after destroy")
            evidence["stages"].append("destroy/native absence/state empty")
            evidence["cleanup"] = "signed absence and empty state verified"
    finally:
        target.shutdown()
        target.server_close()
        worker.join()
        (root / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Completed observability lifecycle stages: {evidence['stages']}; private artifacts: {root}")


if __name__ == "__main__":
    main()
