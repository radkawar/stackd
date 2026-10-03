"""Bounded transport and evidence recording shared by the Glue/Athena probes.

AWS CLI credentials/debug buffers stay in memory. This is capture tooling, not a
service implementation. Native mutations require an exact account match; local
replays require an explicit loopback endpoint and never inherit AWS credentials.
"""
import argparse
import datetime
import copy
import json
import os
from pathlib import Path
import signal
import time
from urllib.parse import urlparse
import uuid

from aws_cli import CLITimeout, result, run

REGION = "us-east-1"
SOURCES = {
    "aws_sdk_go_v2": "113bc91bf12edc3af1d3aba1c70be28494d54c2a",
}


def arguments(description, *, member_account=False):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--account", help="Required native AWS account; local replay uses 000000000000")
    if member_account:
        parser.add_argument("--member-account", help="Required native account for other-catalog reads")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--native", action="store_true")
    target.add_argument("--endpoint-url")
    args = parser.parse_args()
    if args.native and not args.account:
        parser.error("--native requires --account")
    if member_account:
        if args.native and not args.member_account:
            parser.error("--native requires --member-account")
        if args.endpoint_url and not args.member_account:
            args.member_account = "111111111111"
    if args.endpoint_url and args.account not in (None, "000000000000"):
        parser.error("Local replay account must be 000000000000")
    if args.endpoint_url:
        args.account = "000000000000"
    if args.output.exists():
        parser.error("Capture exists; use a fresh output path to preserve failed captures")
    if args.endpoint_url:
        parsed = urlparse(args.endpoint_url)
        if parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
            parser.error("Replay endpoint must be explicit loopback HTTP")
    return args


class Capture:
    def __init__(self, args, prefix, references, bounds):
        self.args = args
        self.suffix = uuid.uuid4().hex[:16]
        self.prefix = prefix + self.suffix
        self.substitutions = [] if args.native else [(self.prefix, prefix + "owned"), (self.prefix.upper(), (prefix + "owned").upper())]
        self.environment = dict(os.environ, AWS_DEFAULT_REGION=REGION, AWS_REGION=REGION,
                                AWS_MAX_ATTEMPTS="1", AWS_RETRY_MODE="standard", AWS_PAGER="",
                                AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
        for key in list(self.environment):
            if key.startswith("AWS_ENDPOINT_URL"):
                del self.environment[key]
        if args.endpoint_url:
            for key in ("AWS_PROFILE", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"):
                self.environment.pop(key, None)
            self.environment.update(AWS_ACCESS_KEY_ID="000000000000", AWS_SECRET_ACCESS_KEY="test",
                                    AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
                                    AWS_EC2_METADATA_DISABLED="true")
        self.started = time.monotonic()
        self.calls = 0
        self.cleaning = False
        self.capture = {
            "source": "native AWS" if args.native else "explicit local replay",
            "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "region": REGION, "run_suffix": self.suffix, "source_revisions": SOURCES,
            "primary_references": references, "bounds": bounds,
            "normalization": ("Private native capture retains account and owned resource IDs; passwords redacted; credentials/debug output never persisted."
                              if args.native else "Owned names, account/caller/role/query/run IDs and pagination tokens replaced consistently; timestamps, field presence, list order, errors and data bytes retained. Credentials/debug output never persisted."),
            "observations": [], "cleanup": {"verified": False, "observations": [], "remaining_owned": []},
            "completed": False,
        }
        def interrupt(signum, frame):
            raise RuntimeError("Interrupted; entering owned cleanup")
        signal.signal(signal.SIGTERM, interrupt)
        signal.signal(signal.SIGINT, interrupt)

    def normalize(self, value):
        if isinstance(value, dict):
            return {key: ("REDACTED_PRESENT" if item else item) if key in ("PASSWORD", "ENCRYPTED_PASSWORD")
                    else self.normalize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.normalize(item) for item in value]
        if isinstance(value, str):
            for old, new in sorted(self.substitutions, key=lambda item: -len(item[0])):
                value = value.replace(old, new)
        return value

    def name(self, value, replacement):
        if not self.args.native or replacement == "SYNTHETIC_PASSWORD_REDACTED":
            self.substitutions.append((value, replacement))
        self.save()
        return value

    def save(self):
        self.capture["cli_calls"] = self.calls
        self.capture["elapsed_seconds"] = round(time.monotonic() - self.started, 3)
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        self.args.output.write_text(json.dumps(self.normalize(self.capture), indent=2) + "\n")

    def request(self, label, service, operation, parameters, *, environment=None, options=(), cli_input=True):
        if not self.cleaning and (self.calls >= self.capture["bounds"]["max_calls"] or
                                 time.monotonic() - self.started > self.capture["bounds"]["wall_seconds"]):
            raise RuntimeError("Native request/time bound reached")
        self.calls += 1
        extra = ["--no-paginate", "--cli-error-format", "json", "--cli-connect-timeout", "5", "--cli-read-timeout", "20"]
        if self.args.endpoint_url:
            extra += ["--endpoint-url", self.args.endpoint_url]
        start = time.time_ns() // 1_000_000
        try:
            process = run(service, operation, parameters if cli_input else None, environment or self.environment,
                          options=extra + list(options), timeout=30)
            if process.returncode:
                try:
                    error = json.loads(process.stderr)
                except json.JSONDecodeError:
                    response = result(process, cli_message=None)
                else:
                    response = {"code": error.get("Code", "CLIError"), "error": error}
            else:
                response = result(process)
        except CLITimeout:
            response = {"code": "CLITimeout", "message": "Bounded CLI timeout; native outcome unknown"}
        if not self.args.native and service == "sts" and operation == "get-caller-identity" and response["code"] == "Success":
            identity = response["output"]
            self.substitutions += [(identity["Account"], "123456789012"),
                                   (identity["Arn"], "arn:aws:iam::123456789012:user/owned-caller"),
                                   (identity["UserId"], "OWNEDCALLERID")]
        row = {"label": label, "service": service, "operation": operation, "input": copy.deepcopy(parameters),
               "started_ms": start, "finished_ms": time.time_ns() // 1_000_000, "result": copy.deepcopy(response)}
        target = self.capture["cleanup"]["observations"] if self.cleaning else self.capture["observations"]
        target.append(row)
        self.save()
        print(label + ": " + response["code"], flush=True)
        return response

    def identity(self):
        identity = require(self.request("identity", "sts", "get-caller-identity", {}))
        if identity["Account"] != self.args.account:
            raise RuntimeError("Caller account differs from --account")
        self.account = identity["Account"]
        self.caller = identity["Arn"]
        self.capture["account"] = self.account
        self.save()

    def assume(self, role):
        # Deliberately bypass recording: STS response contains credential secrets.
        extra = ["--cli-connect-timeout", "5", "--cli-read-timeout", "20"]
        if self.args.endpoint_url:
            extra += ["--endpoint-url", self.args.endpoint_url]
        for attempt in range(12):
            self.calls += 1
            process = run("sts", "assume-role", {"RoleArn": role, "RoleSessionName": "owned-probe", "DurationSeconds": 900},
                          self.environment, options=extra, timeout=30)
            response = result(process)
            self.capture.setdefault("role_acquisition", []).append({"attempt": attempt + 1, "code": response["code"]})
            self.save()
            if response["code"] == "Success":
                credentials = response["output"]["Credentials"]
                environment = dict(self.environment, AWS_ACCESS_KEY_ID=credentials["AccessKeyId"],
                                   AWS_SECRET_ACCESS_KEY=credentials["SecretAccessKey"],
                                   AWS_SESSION_TOKEN=credentials["SessionToken"])
                environment.pop("AWS_PROFILE", None)
                return environment
            if response["code"] != "AccessDenied":
                raise RuntimeError("Role acquisition failed: " + response["code"])
            time.sleep(5)
        raise RuntimeError("Owned IAM propagation deadline expired")

    def finish(self, remaining):
        self.capture["cleanup"]["remaining_owned"] = remaining
        self.capture["cleanup"]["verified"] = not remaining
        self.save()
        if remaining:
            raise RuntimeError("Owned cleanup incomplete; inspect capture")


def require(response):
    if response["code"] != "Success":
        raise RuntimeError("Required native operation failed: " + response["code"])
    return response.get("output", {})


def descriptor(location):
    return {"Columns": [{"Name": "category", "Type": "string"}, {"Name": "amount", "Type": "int"}],
            "Location": location, "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
            "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
            "SerdeInfo": {"SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                          "Parameters": {"field.delim": ",", "serialization.format": ","}}}
