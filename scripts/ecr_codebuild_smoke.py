#!/usr/bin/env python3
"""Exercise a local SQLite stackd with real Docker, ECR and CodeBuild bytes.

Prerequisites: boto3, Docker CLI/socket, locally installed busybox:1.38.0 and
the pinned compute/docker.ToolkitImage (the credential proxy), plus a parent-built
stackd. Lambda telemetry helpers are not required.
This script never downloads images or contacts AWS.

Example (run only after the integrating owner has assembled authorization):
  python3 -B -P scripts/ecr_codebuild_smoke.py \
    --binary /absolute/path/bin/stackd \
    --state-dir /tmp/stackd-buildowner-smoke-unique --port 18479

Only uniquely named resources are created/deleted. The SQLite DB, private server
log and nonsecret evidence.json remain in state-dir. --keep-resources preserves
cloud resources/local image tags for diagnosis; the controller still stops and
its temporary Docker credentials are always removed.
"""

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile


REGION = "us-east-1"
ACCOUNT = "000000000000"
BASE_IMAGE = "busybox:1.38.0"
TOOLKIT_IMAGE = "nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61"
TERMINAL = {"SUCCEEDED", "FAILED", "FAULT", "STOPPED", "TIMED_OUT"}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def local_environment(endpoint):
    blocked = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}
    result = {key: value for key, value in os.environ.items()
              if not key.upper().startswith(("AWS_", "DOCKER_"))
              and key.upper() not in blocked}
    result.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test",
                  AWS_DEFAULT_REGION=REGION, AWS_REGION=REGION,
                  AWS_EC2_METADATA_DISABLED="true", AWS_ENDPOINT_URL=endpoint,
                  AWS_CONFIG_FILE=os.devnull, AWS_SHARED_CREDENTIALS_FILE=os.devnull,
                  NO_PROXY="*", DOCKER_BUILDKIT="0")
    return result


def policy(statements):
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def source_archive(marker, role_arn):
    payload = "source bytes from " + marker + "\n"
    script = r'''set -eu
umask 077
credentials=/tmp/stackd-buildowner-credentials.json
trap 'rm -f "$credentials"' EXIT
fetch_credentials() {
    if wget -q -O "$credentials" "$AWS_CONTAINER_CREDENTIALS_FULL_URI" 2>/dev/null; then
        printf 'unauthenticated metadata request unexpectedly succeeded\n' >&2
        exit 1
    fi
    wget -q -O "$credentials" --header "Authorization: $AWS_CONTAINER_AUTHORIZATION_TOKEN" "$AWS_CONTAINER_CREDENTIALS_FULL_URI"
    credential_role=$(sed -n 's/.*"RoleArn"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$credentials")
    test "$credential_role" = "$(cat expected-role.txt)"
    for field in AccessKeyId SecretAccessKey Token Expiration; do
        grep -q "\"$field\"[[:space:]]*:[[:space:]]*\"[^\"][^\"]*\"" "$credentials"
    done
    credential_key=$(sed -n 's/.*"AccessKeyId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$credentials")
    if [ "$1" = before ]; then
        first_credential_key=$credential_key
    else
        test "$credential_key" != "$first_credential_key"
        unset first_credential_key
    fi
    rm -f "$credentials"
    unset credential_role credential_key
    printf 'STACKD_METADATA:%s\n' "$1"
}
fetch_credentials before
cmp /stackd-buildowner-image-marker expected-image.txt
mkdir -p output
case "$RUN_CASE" in
  failure)
    printf 'command exited 17\n' > output/failure.txt
    printf 'STACKD_FAILURE:%s\n' "$RUN_CASE"
    printf 'STACKD_READY:%s\n' "$RUN_CASE"
    sleep 8
    exit 17
    ;;
  cancel)
    printf 'STACKD_READY:%s\n' "$RUN_CASE"
    sleep 30
    printf 'STACKD_FORBIDDEN:cancel\n'
    ;;
  timeout)
    printf 'STACKD_READY:%s\n' "$RUN_CASE"
    sleep 360
    printf 'STACKD_FORBIDDEN:timeout\n'
    ;;
  isolate-a|isolate-b)
    printf '%s\n' "$RUN_CASE" > /tmp/stackd-buildowner-isolation
    printf 'STACKD_READY:%s\n' "$RUN_CASE"
    sleep 8
    test "$(cat /tmp/stackd-buildowner-isolation)" = "$RUN_CASE"
    ;;
  restart)
    od -An -N16 -tx1 /dev/urandom | tr -d ' \n' > output/process.txt
    printf '\n' >> output/process.txt
    printf 'STACKD_RESTART_READY:%s\n' "$(cat output/process.txt)"
    sleep 45
    fetch_credentials after-restart
    ;;
esac
cat /stackd-buildowner-image-marker > output/result.txt
tr 'a-z' 'A-Z' < payload.txt >> output/result.txt
printf '%s\n%s\n' "$RUN_CASE" "$CODEBUILD_BUILD_ID" >> output/result.txt
printf 'STACKD_COMPLETE:%s\n' "$RUN_CASE"
'''
    spec = {"version": "0.2", "phases": {
        "build": {"commands": ["sh build.sh"], "finally": [
            'printf "STACKD_FINALLY:%s\\n" "$RUN_CASE"']},
        "post_build": {"commands": [
            'printf "STACKD_POST:%s:%s\\n" "$RUN_CASE" "$CODEBUILD_BUILD_SUCCEEDING"']}},
        "artifacts": {"files": ["output/*.txt"]}}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in {"buildspec.yml": json.dumps(spec), "build.sh": script,
                           "payload.txt": payload, "expected-image.txt": marker + "\n",
                           "expected-role.txt": role_arn + "\n"}.items():
            archive.writestr(name, data)
    return buffer.getvalue(), payload


class Smoke:
    def __init__(self, args, boto3, config, client_error):
        self.args = args
        self.client_error = client_error
        self.endpoint = "http://127.0.0.1:" + str(args.port)
        self.compute_endpoint = "http://host.docker.internal:" + str(args.port)
        self.env = local_environment(self.endpoint)
        self.prefix = "stackd-buildowner-" + secrets.token_hex(6)
        self.state = Path(args.state_dir).resolve()
        self.owns_state = False
        self.binary = Path(args.binary).resolve()
        self.config = config(signature_version="v4", retries={"max_attempts": 0},
                             connect_timeout=3, read_timeout=15, proxies={},
                             s3={"addressing_style": "path"},
                             request_checksum_calculation="when_required",
                             response_checksum_validation="when_required")
        self.session = boto3.Session(aws_access_key_id="test", aws_secret_access_key="test",
                                     region_name=REGION)
        self.clients = {name: self.client(name) for name in ("sts", "iam", "s3", "ecr", "codebuild", "logs", "events", "sqs")}
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.process = None
        self.server_log = None
        self.docker_config = None
        self.created = set()
        self.build_ids = []
        self.image_tags = set()
        self.container_names = set()
        self.events = []
        self.secret_values = []
        self.cleanup_errors = []
        self.bucket = self.role = self.project = self.user = self.prefix
        self.repository = self.prefix + "/blobs/uploads/app/manifests/nested"
        self.group = "/aws/codebuild/" + self.prefix
        self.marker = self.prefix + "-known-image-bytes"
        self.token = None
        self.registry_path = None
        self.replica_client = None

    def client(self, name, session=None):
        return (session or self.session).client(name, endpoint_url=self.endpoint,
                                               region_name=REGION, config=self.config)

    def note(self, case, **details):
        event = {"case": case, **details}
        self.events.append(event)
        print(json.dumps(event, sort_keys=True), flush=True)
        self.save()

    def save(self):
        document = {"endpoint": self.endpoint, "owned_prefix": self.prefix,
                    "observations": self.events, "cleanup_errors": self.cleanup_errors}
        (self.state / "evidence.json").write_text(json.dumps(document, indent=2) + "\n")

    def safe_error(self, error):
        if isinstance(error, self.client_error):
            return error.operation_name + ":" + error.response["Error"]["Code"]
        text = str(error)
        for secret in self.secret_values:
            text = text.replace(secret, "[redacted]")
        return type(error).__name__ + ": " + text[:1200]

    def command(self, arguments, *, stdin=None, timeout=180, check=True):
        result = subprocess.run(arguments, input=stdin, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, cwd=self.state, env=self.env,
                                timeout=timeout, check=False)
        if check and result.returncode:
            # Never echo Docker login input, SDK credentials, or arbitrary process output.
            raise RuntimeError(Path(arguments[0]).name + " command failed with exit "
                               + str(result.returncode) + " (captured output withheld)")
        return result

    def docker(self, *arguments, **kwargs):
        return self.command(["docker", "--host", self.args.docker_host,
                             "--config", self.docker_config.name, *arguments], **kwargs)

    def prepare(self):
        require(self.state.name.startswith("stackd-buildowner"),
                "state-dir basename must start with stackd-buildowner")
        require(self.binary.is_file() and os.access(self.binary, os.X_OK),
                "--binary must name an executable parent-built stackd")
        require(not self.state.exists(), "state-dir must not already exist; retained state is never overwritten")
        require(shutil.which("docker") is not None, "Docker CLI must already be installed")
        with socket.socket() as listener:
            listener.bind(("0.0.0.0", self.args.port))
        self.state.mkdir(mode=0o700, parents=True)
        self.owns_state = True
        self.docker_config = tempfile.TemporaryDirectory(prefix=self.prefix + "-docker-", dir=self.state)
        (Path(self.docker_config.name) / "config.json").write_text('{"auths":{}}\n')
        self.docker("version", "--format", "{{.Server.Version}}")
        self.fleet_image = json.loads(self.docker("image", "inspect", BASE_IMAGE).stdout)[0]["Id"]
        require(self.docker("image", "inspect", TOOLKIT_IMAGE, check=False).returncode == 0,
                "missing locally installed metadata toolkit: " + TOOLKIT_IMAGE)
        self.server_log = (self.state / "stackd.log").open("ab", buffering=0)
        self.note("prerequisites", base_image=BASE_IMAGE, metadata_image=TOOLKIT_IMAGE,
                  docker_host=self.args.docker_host, database=str(self.state / "stackd.sqlite"))

    def start(self):
        arguments = [str(self.binary), "-database", str(self.state / "stackd.sqlite"),
                     "-listen", "0.0.0.0:" + str(self.args.port),
                     "-public-endpoint", self.endpoint, "-compute-endpoint", self.compute_endpoint,
                     "-docker-host", self.args.docker_host, "-codebuild-runtime", "-codebuild-fleet-image", self.fleet_image]
        if self.args.ecr_scanner:
            arguments += ["-ecr-scanner", str(Path(self.args.ecr_scanner).resolve()),
                          "-ecr-scanner-cache", str(Path(self.args.ecr_scanner_cache).resolve())]
        self.process = subprocess.Popen(arguments, cwd=self.state, env=self.env,
                                        stdin=subprocess.DEVNULL, stdout=self.server_log,
                                        stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            require(self.process.poll() is None, "stackd exited before readiness; inspect private stackd.log")
            try:
                with self.http.open(self.endpoint + "/_stackd/health", timeout=1) as response:
                    if response.status == 200:
                        identity = self.clients["sts"].get_caller_identity()
                        require(identity["Account"] == ACCOUNT and identity["Arn"] == "arn:aws:iam::" + ACCOUNT + ":root",
                                "explicit test/test identity did not resolve to local root")
                        return
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                pass
            time.sleep(0.2)
        raise RuntimeError("local stackd readiness deadline exceeded")

    def stop(self, *, crash=False):
        if self.process is None:
            return
        process, self.process = self.process, None
        if process.poll() is not None:
            require(process.returncode == 0, "stackd exited unexpectedly; inspect private stackd.log")
            return
        process.kill() if crash else process.terminate()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
            raise RuntimeError("stackd did not shut down gracefully")
        if not crash:
            require(process.returncode == 0, "stackd graceful shutdown failed; inspect private stackd.log")

    def api_denied(self, call, **arguments):
        try:
            call(**arguments)
        except self.client_error as error:
            require(error.response["Error"]["Code"] in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"},
                    "expected authorization denial, got " + error.response["Error"]["Code"])
            return error.response["Error"]["Code"]
        raise RuntimeError("request unexpectedly bypassed current policy")

    def registry_get(self):
        request = urllib.request.Request(self.endpoint + "/v2/" + self.registry_path + "/manifests/owned",
                                        headers={"Authorization": "Basic " + self.token,
                                                 "Accept": "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json"})
        try:
            with self.http.open(request, timeout=10) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    def user_policy(self, deny=None):
        statements = [{"Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*"},
                      {"Effect": "Allow", "Action": "ecr:*", "Resource": self.repository_arn},
                      {"Effect": "Allow", "Action": ["codebuild:StartBuild", "codebuild:BatchGetBuilds"],
                       "Resource": [self.project_arn, "arn:aws:codebuild:" + REGION + ":" + ACCOUNT + ":build/" + self.project + ":*"]},
                      {"Effect": "Allow", "Action": "iam:PassRole", "Resource": self.role_arn}]
        if deny:
            statements.append({"Effect": "Deny", "Action": deny, "Resource": "*"})
        self.clients["iam"].put_user_policy(UserName=self.user, PolicyName="owned", PolicyDocument=policy(statements))

    def setup_image(self):
        iam, ecr = self.clients["iam"], self.clients["ecr"]
        repository = ecr.create_repository(repositoryName=self.repository)["repository"]
        self.created.add("repository")
        self.repository_arn = repository["repositoryArn"]
        uri = repository["repositoryUri"]
        require(uri.startswith("127.0.0.1:" + str(self.args.port) + "/"), "ECR advertised a nonlocal registry")
        self.registry_path = uri.split("/", 1)[1]
        self.image = uri + ":owned"
        self.local_image = self.prefix + ":owned"
        self.role_arn = "arn:aws:iam::" + ACCOUNT + ":role/" + self.role
        self.project_arn = "arn:aws:codebuild:" + REGION + ":" + ACCOUNT + ":project/" + self.project
        iam.create_user(UserName=self.user)
        self.created.add("user")
        self.user_policy()
        key = iam.create_access_key(UserName=self.user)["AccessKey"]
        self.access_key = key["AccessKeyId"]
        self.created.add("access_key")
        self.secret_values += [key["SecretAccessKey"]]
        user_session = self.session.__class__(aws_access_key_id=key["AccessKeyId"],
                                              aws_secret_access_key=key["SecretAccessKey"], region_name=REGION)
        self.user_build = self.client("codebuild", user_session)
        token = self.client("ecr", user_session).get_authorization_token()["authorizationData"][0]
        require(token["proxyEndpoint"] == self.endpoint, "ECR token advertised a nonlocal endpoint")
        self.token = token["authorizationToken"]
        username, password = base64.b64decode(self.token).decode().split(":", 1)
        self.secret_values += [self.token, password]
        require(username == "AWS", "unexpected ECR login username")
        self.docker("login", "127.0.0.1:" + str(self.args.port), "--username", username,
                    "--password-stdin", stdin=(password + "\n").encode())
        context = self.state / "image-context"
        context.mkdir(mode=0o700)
        (context / "marker").write_text(self.marker + "\n")
        (context / "Dockerfile").write_text("FROM " + BASE_IMAGE + "\nCOPY marker /stackd-buildowner-image-marker\n")
        self.image_tags.add(self.local_image)
        self.docker("build", "--pull=false", "--network=none", "--label", "stackd.buildowner=" + self.prefix,
                    "--tag", self.local_image, str(context))
        self.image_tags.add(self.image)
        self.docker("tag", self.local_image, self.image)
        self.docker("push", self.image)
        images = ecr.describe_images(repositoryName=self.repository, imageIds=[{"imageTag": "owned"}])["imageDetails"]
        require(len(images) == 1, "owned ECR tag did not resolve uniquely")
        self.image_digest = images[0]["imageDigest"]
        status, body = self.registry_get()
        require(status == 200 and "sha256:" + hashlib.sha256(body).hexdigest() == self.image_digest,
                "registry manifest bytes disagree with ECR digest")
        self.pull_and_run()
        self.user_policy("ecr:BatchGetImage")
        status, body = self.registry_get()
        require(status == 403, "retained ECR token bypassed new deny policy")
        errors = json.loads(body).get("errors", [])
        require(any(error.get("code") == "DENIED" for error in errors), "registry did not return authorization denial")
        self.docker("image", "rm", self.image)
        denied = self.docker("pull", self.image, check=False)
        require(denied.returncode != 0, "Docker pull bypassed current registry policy")
        self.user_policy()
        self.pull_and_run()
        self.note("authenticated_ecr_push_pull_current_policy", digest=self.image_digest,
                  repository_uri=uri, verified_image_bytes=self.marker, denied_http_status=status)

    def pull_and_run(self):
        exists = self.docker("image", "inspect", self.image, check=False)
        if exists.returncode == 0:
            self.docker("image", "rm", self.image)
        require(self.docker("image", "inspect", self.image, check=False).returncode != 0,
                "owned local registry tag survived deletion")
        self.docker("pull", self.image)
        name = self.prefix + "-image-" + secrets.token_hex(3)
        self.container_names.add(name)
        output = self.docker("run", "--rm", "--pull=never", "--network=none", "--name", name,
                             self.image, "cat", "/stackd-buildowner-image-marker").stdout
        require(output == (self.marker + "\n").encode(), "pulled image did not execute known owned bytes")
        self.container_names.discard(name)

    def setup_project(self):
        iam, s3, cb = self.clients["iam"], self.clients["s3"], self.clients["codebuild"]
        s3.create_bucket(Bucket=self.bucket)
        self.created.add("bucket")
        archive, self.payload = source_archive(self.marker, self.role_arn)
        s3.put_object(Bucket=self.bucket, Key="source.zip", Body=archive)
        trust = policy([{"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}])
        role = iam.create_role(RoleName=self.role, AssumeRolePolicyDocument=trust)["Role"]
        self.created.add("role")
        require(role["Arn"] == self.role_arn, "unexpected owned role ARN")
        role_statements = [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"], "Resource": "arn:aws:s3:::" + self.bucket + "/*"},
            {"Effect": "Allow", "Action": ["s3:GetBucketLocation", "s3:GetBucketAcl", "s3:ListBucket"], "Resource": "arn:aws:s3:::" + self.bucket},
            {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "arn:aws:logs:" + REGION + ":" + ACCOUNT + ":log-group:" + self.group + ":*"},
            {"Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*"},
            {"Effect": "Allow", "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"], "Resource": self.repository_arn}]
        iam.put_role_policy(RoleName=self.role, PolicyName="owned", PolicyDocument=policy(role_statements))
        self.clients["logs"].create_log_group(logGroupName=self.group)
        self.created.add("log_group")
        cb.create_project(name=self.project, serviceRole=self.role_arn,
                          source={"type": "S3", "location": self.bucket + "/source.zip"},
                          artifacts={"type": "S3", "location": self.bucket, "path": "artifacts",
                                     "name": "default.zip", "packaging": "ZIP", "namespaceType": "NONE"},
                          environment={"type": "LINUX_CONTAINER", "image": self.image,
                                       "computeType": "BUILD_GENERAL1_SMALL", "imagePullCredentialsType": "SERVICE_ROLE"},
                          logsConfig={"cloudWatchLogs": {"status": "ENABLED", "groupName": self.group, "streamName": "owned"}},
                          timeoutInMinutes=5, queuedTimeoutInMinutes=5, concurrentBuildLimit=3)
        self.created.add("project")

    def start_build(self, case, *, user=False):
        build = (self.user_build if user else self.clients["codebuild"]).start_build(
            projectName=self.project,
            environmentVariablesOverride=[{"name": "RUN_CASE", "value": case, "type": "PLAINTEXT"}],
            artifactsOverride={"type": "S3", "location": self.bucket, "path": "artifacts",
                               "name": case + ".zip", "packaging": "ZIP", "namespaceType": "NONE"})["build"]
        self.build_ids.append(build["id"])
        require(build["projectName"] == self.project, "StartBuild returned another project")
        return build["id"]

    def build(self, build_id):
        result = self.clients["codebuild"].batch_get_builds(ids=[build_id])
        require(not result.get("buildsNotFound") and len(result.get("builds", [])) == 1,
                "owned build disappeared")
        build = result["builds"][0]
        require(build["id"] == build_id, "BatchGetBuilds returned another build")
        return build

    def logs(self, build):
        details = build.get("logs", {})
        if not details.get("groupName") or not details.get("streamName"):
            return ""
        messages, token = [], None
        while True:
            arguments = {"logGroupName": details["groupName"], "logStreamName": details["streamName"], "startFromHead": True}
            if token:
                arguments["nextToken"] = token
            try:
                response = self.clients["logs"].get_log_events(**arguments)
            except self.client_error as error:
                if error.response["Error"]["Code"] == "ResourceNotFoundException":
                    return ""
                raise
            messages.extend(event["message"] for event in response.get("events", []))
            following = response.get("nextForwardToken")
            if not following or following == token:
                return "\n".join(messages)
            token = following

    def wait(self, build_id, expected=None, log_prefix=None, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            build = self.build(build_id)
            if build["buildStatus"] in TERMINAL and (log_prefix or build["buildStatus"] != expected):
                self.note("unexpected_build_result", build_id=build_id, status=build["buildStatus"],
                          phases=[{"type": phase.get("phaseType"), "status": phase.get("phaseStatus"),
                                   "contexts": [{"code": context.get("statusCode"),
                                                 "message": self.safe_error(RuntimeError(context.get("message", "")))}
                                                for context in phase.get("contexts", [])]}
                                  for phase in build.get("phases", [])],
                          owned_command_log=self.safe_error(RuntimeError(self.logs(build)[-3000:])))
            if log_prefix:
                lines = self.logs(build).splitlines()
                matching = [line for line in lines if line.startswith(log_prefix)]
                if matching:
                    require(build["buildStatus"] == "IN_PROGRESS", "build finished before live-process observation")
                    return build, matching[0]
            elif build["buildStatus"] in TERMINAL:
                require(build["buildStatus"] == expected and build.get("buildComplete") is True,
                        "build ended " + build["buildStatus"] + ", expected " + str(expected))
                return build
            if log_prefix and build["buildStatus"] in TERMINAL:
                raise RuntimeError("build ended before required command output: " + build["buildStatus"])
            time.sleep(0.5)
        raise RuntimeError("build observation deadline exceeded for " + build_id)

    def artifact(self, build, case):
        expected_location = "arn:aws:s3:::" + self.bucket + "/artifacts/" + case + ".zip"
        require(build.get("artifacts", {}).get("location") == expected_location,
                "build artifact location did not identify the owned S3 ZIP")
        response = self.clients["s3"].get_object(Bucket=self.bucket, Key="artifacts/" + case + ".zip")
        with response["Body"] as stream:
            data = stream.read()
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            require(len(set(archive.namelist())) == len(archive.namelist()), "artifact ZIP contains duplicate entries")
            return {name: archive.read(name) for name in archive.namelist()}

    def success(self, build_id, case, process_nonce=None):
        build = self.wait(build_id, "SUCCEEDED")
        files = self.artifact(build, case)
        expected = (self.marker + "\n" + self.payload.upper() + case + "\n" + build_id + "\n").encode()
        expected_files = {"output/result.txt": expected}
        if process_nonce is not None:
            expected_files["output/process.txt"] = (process_nonce + "\n").encode()
        require(files == expected_files, "S3 artifact bytes disagree with image/source/command/build identity")
        lines = self.logs(build).splitlines()
        require(lines.count("STACKD_COMPLETE:" + case) == 1, "CloudWatch Logs did not contain exactly one command completion")
        require(lines.count("STACKD_METADATA:before") == 1,
                "workload did not authenticate metadata acquisition with the owned role")
        if process_nonce is not None:
            require(lines.count("STACKD_METADATA:after-restart") == 1,
                    "running workload could not reacquire role credentials after controller restart")
        self.note("build_" + case, build_id=build_id, status=build["buildStatus"],
                  artifact_sha256=hashlib.sha256(expected).hexdigest())
        return build

    def native_container(self, build):
        ids = self.docker("ps", "-aq", "--filter", "label=stackd.codebuild.arn=" + build["arn"]).stdout.decode().split()
        require(ids, "no native containers found for exact owned build ARN")
        containers = json.loads(self.docker("inspect", *ids).stdout)
        main = [container for container in containers
                if container["Config"]["Labels"].get("stackd.codebuild.metadata") != "true"
                and container["Config"]["Labels"].get("stackd.codebuild.source") != "true"]
        require(len(main) == 1, "expected exactly one native workload container for owned build ARN")
        return main[0]

    def native_exit_code(self, native):
        # Completed containers are deleted by the controller. Docker's actual
        # die event preserves the process exit status without retaining them.
        output = self.docker("events", "--since", native["State"]["StartedAt"],
                             "--until", str(time.time()), "--filter", "container=" + native["Id"],
                             "--filter", "event=die", "--format", "{{json .}}", timeout=10).stdout
        events = [json.loads(line) for line in output.splitlines()]
        require(len(events) == 1 and events[0]["Actor"]["ID"] == native["Id"],
                "Docker did not retain exactly one die event for the owned process")
        return int(events[0]["Actor"]["Attributes"]["exitCode"])

    def exercise_builds(self):
        successful = self.start_build("success", user=True)
        self.success(successful, "success")
        self.user_policy("codebuild:StartBuild")
        code = self.api_denied(self.user_build.start_build, projectName=self.project)
        self.user_policy()
        self.note("current_caller_policy_denial", error_code=code)
        iam = self.clients["iam"]
        iam.put_role_policy(RoleName=self.role, PolicyName="deny-source",
                            PolicyDocument=policy([{"Effect": "Deny", "Action": "s3:GetObject",
                                                    "Resource": "arn:aws:s3:::" + self.bucket + "/source.zip"}]))
        self.created.add("deny_source")
        denied_id = self.start_build("denied-source")
        denied = self.wait(denied_id, "FAILED")
        require(any(phase.get("phaseType") == "DOWNLOAD_SOURCE" and phase.get("phaseStatus") == "FAILED"
                    for phase in denied.get("phases", [])), "revoked source access did not fail DOWNLOAD_SOURCE")
        require("STACKD_COMPLETE:denied-source" not in self.logs(denied).splitlines(),
                "source-denied build executed customer commands")
        try:
            self.clients["s3"].head_object(Bucket=self.bucket, Key="artifacts/denied-source.zip")
        except self.client_error as error:
            require(error.response["ResponseMetadata"]["HTTPStatusCode"] == 404,
                    "source-denied artifact check failed for a reason other than missing object")
        else:
            raise RuntimeError("source-denied build published an artifact")
        iam.delete_role_policy(RoleName=self.role, PolicyName="deny-source")
        self.created.remove("deny_source")
        self.note("current_execution_role_policy_denial", build_id=denied_id, failed_phase="DOWNLOAD_SOURCE")
        failed = self.start_build("failure")
        running, _ = self.wait(failed, log_prefix="STACKD_READY:failure")
        native = self.native_container(running)
        require(native["State"]["Running"] is True, "failure command was not observed running")
        failure = self.wait(failed, "FAILED")
        require("STACKD_FAILURE:failure" in self.logs(failure).splitlines(), "failed command output absent from Logs")
        require("STACKD_COMPLETE:failure" not in self.logs(failure).splitlines(), "failed command continued to success")
        require(any(phase.get("phaseType") == "BUILD" and phase.get("phaseStatus") == "FAILED"
                    for phase in failure.get("phases", [])), "nonzero command did not fail BUILD phase")
        require(self.native_exit_code(native) == 17, "native process did not actually exit 17")
        failure_lines = self.logs(failure).splitlines()
        require(failure_lines.count("STACKD_FINALLY:failure") == 1
                and failure_lines.count("STACKD_POST:failure:0") == 1,
                "failed BUILD did not execute finally and POST_BUILD with failing status")
        require(self.artifact(failure, "failure") == {"output/failure.txt": b"command exited 17\n"},
                "failed BUILD did not publish its real artifact bytes")
        for phase_type in ("POST_BUILD", "UPLOAD_ARTIFACTS"):
            require(any(phase.get("phaseType") == phase_type and phase.get("phaseStatus") == "SUCCEEDED"
                        for phase in failure.get("phases", [])),
                    "failed BUILD did not finish " + phase_type)
        self.note("command_failure", build_id=failed, native_exit_code=17)
        left, right = self.start_build("isolate-a"), self.start_build("isolate-b")
        self.wait(left, log_prefix="STACKD_READY:isolate-a")
        self.wait(right, log_prefix="STACKD_READY:isolate-b")
        require(self.build(left)["buildStatus"] == self.build(right)["buildStatus"] == "IN_PROGRESS",
                "isolation builds did not overlap")
        require(self.native_container(self.build(left))["Id"] != self.native_container(self.build(right))["Id"],
                "parallel builds shared a container")
        owned_ids = []
        for build_id in (left, right):
            owned_ids.extend(self.docker("ps", "-q", "--filter", "label=stackd.codebuild.arn=" + self.build(build_id)["arn"]).stdout.decode().split())
        memory = self.docker("stats", "--no-stream", "--format", "{{json .}}", *owned_ids).stdout
        self.note("overlapping_native_memory", containers=[
            {"id": row["ID"], "memory": row["MemUsage"]}
            for row in (json.loads(line) for line in memory.splitlines())])
        self.success(left, "isolate-a")
        self.success(right, "isolate-b")
        cancel = self.start_build("cancel")
        running, _ = self.wait(cancel, log_prefix="STACKD_READY:cancel")
        native = self.native_container(running)
        require(native["State"]["Running"] is True, "cancellable process was not observed running")
        self.clients["codebuild"].stop_build(id=cancel)
        stopped = self.wait(cancel, "STOPPED")
        exit_code = self.native_exit_code(native)
        require(exit_code != 0, "StopBuild did not terminate the real sleeping process")
        require("STACKD_FORBIDDEN:cancel" not in self.logs(stopped).splitlines(), "cancelled process reached forbidden command")
        self.note("real_process_cancel", build_id=cancel, native_exit_code=exit_code)
        timed_id = self.start_build("timeout")
        running, _ = self.wait(timed_id, log_prefix="STACKD_READY:timeout")
        native = self.native_container(running)
        timed = self.wait(timed_id, "FAILED", timeout=340)
        require(any(phase.get("phaseType") == "BUILD" and phase.get("phaseStatus") == "TIMED_OUT"
                    and any(context.get("statusCode") == "BUILD_TIMED_OUT" for context in phase.get("contexts", []))
                    for phase in timed.get("phases", [])), "timeout did not retain native phase outcome")
        require(self.native_exit_code(native) != 0, "timeout did not stop the real sleeping process")
        require("STACKD_FORBIDDEN:timeout" not in self.logs(timed).splitlines(),
                "timed-out process continued to completion")
        self.note("real_process_timeout", build_id=timed_id, status=timed["buildStatus"],
                  timeout_minutes=5, phase_status="TIMED_OUT")
        self.restart_build(successful)

    def restart_build(self, completed_id):
        build_id = self.start_build("restart")
        before, line = self.wait(build_id, log_prefix="STACKD_RESTART_READY:")
        nonce = line.split(":", 1)[1]
        require(len(nonce) == 32 and all(char in "0123456789abcdef" for char in nonce), "native process nonce was malformed")
        native_before = self.native_container(before)
        self.stop(crash=self.args.restart_mode == "crash")
        self.start()
        retained = self.clients["codebuild"].batch_get_projects(names=[self.project])
        require([project["name"] for project in retained["projects"]] == [self.project], "SQLite project did not survive restart")
        native_after = self.native_container(self.build(build_id))
        require(native_after["Id"] == native_before["Id"] and native_after["State"]["StartedAt"] == native_before["State"]["StartedAt"],
                "controller restart replaced or restarted the native build process")
        self.success(build_id, "restart", process_nonce=nonce)
        require(self.logs(self.build(build_id)).splitlines().count(line) == 1, "restart duplicated pre-restart command logs")
        self.success(completed_id, "success")
        status, body = self.registry_get()
        require(status == 200 and "sha256:" + hashlib.sha256(body).hexdigest() == self.image_digest,
                "retained ECR token/manifest failed after SQLite restart")
        self.pull_and_run()
        self.user_policy("ecr:BatchGetImage")
        require(self.registry_get()[0] == 403, "restored ECR token ignored changed current policy")
        self.user_policy()
        self.note("retained_sqlite_live_process_restart", build_id=build_id,
                  restart_mode=self.args.restart_mode, native_container_id=native_after["Id"],
                  process_nonce=nonce, retained_manifest_digest=self.image_digest)

    def wait_fleet(self, arn, expected):
        for _ in range(120):
            response = self.clients["codebuild"].batch_get_fleets(names=[arn])
            fleets = response.get("fleets", [])
            if expected == "DELETED" and response.get("fleetsNotFound") == [arn]:
                require(not self.docker("ps", "-aq", "--filter", "label=stackd.codebuild.fleet=" + arn).stdout.strip(),
                        "deleted fleet retained native capacity")
                return
            if fleets:
                status = fleets[0]["status"]["statusCode"]
                require(status != "CREATE_FAILED", "native fleet capacity creation failed")
                if status == expected:
                    return fleets[0]
            time.sleep(.25)
        raise RuntimeError("fleet observation deadline")

    def exercise_controls(self):
        cb = self.clients["codebuild"]
        old = None
        for _ in range(2):
            fleet = cb.create_fleet(name=self.prefix, baseCapacity=1, environmentType="LINUX_CONTAINER",
                                    computeType="BUILD_GENERAL1_SMALL")["fleet"]
            arn = fleet["arn"]
            self.fleet_arn = arn
            self.created.add("fleet")
            require(arn.endswith(":" + fleet["id"]) and len(fleet["id"]) == 36, "fleet ARN lacks UUID incarnation")
            self.wait_fleet(arn, "ACTIVE")
            require(arn in cb.list_fleets()["fleets"], "fleet listing lost incarnation")
            ids = self.docker("ps", "-q", "--filter", "label=stackd.codebuild.fleet=" + arn).stdout.decode().split()
            require(len(ids) == 1, "ACTIVE fleet did not own a real idle container")
            if old is not None:
                require(arn != old, "fleet recreation reused ARN")
                response = cb.batch_get_fleets(names=[old, arn])
                require(response.get("fleetsNotFound") == [old] and [f["arn"] for f in response["fleets"]] == [arn],
                        "stale fleet ARN resolved to replacement")
                try:
                    cb.delete_fleet(arn=old)
                except self.client_error as error:
                    require(error.response["Error"]["Code"] == "ResourceNotFoundException", "wrong stale fleet error")
                else:
                    raise RuntimeError("stale ARN deleted replacement fleet")
            cb.delete_fleet(arn=arn)
            self.wait_fleet(arn, "DELETED")
            self.created.remove("fleet")
            old = arn
        token = secrets.token_urlsafe(24)
        self.secret_values.append(token)
        try:
            cb.import_source_credentials(serverType="GITHUB", authType="PERSONAL_ACCESS_TOKEN",
                                         token=token, username="not-valid")
        except self.client_error as error:
            require(error.response["Error"]["Code"] == "InvalidInputException", "wrong username rejection")
        else:
            raise RuntimeError("source credential username contract was not enforced")
        credential = cb.import_source_credentials(serverType="BITBUCKET", authType="BASIC_AUTH",
                                                  token=token, username=self.prefix)
        self.source_credential_arn = credential["arn"]
        self.created.add("source_credential")
        listed = cb.list_source_credentials()["sourceCredentialsInfos"]
        require(any(row["arn"] == credential["arn"] and row["serverType"] == "BITBUCKET" for row in listed),
                "imported source credential metadata absent")
        require(token not in json.dumps(listed), "source credential listing leaked token")
        cb.delete_source_credentials(arn=credential["arn"])
        self.created.remove("source_credential")
        self.note("fleet_incarnation_and_source_credentials", stale_fleet_arn=old,
                  real_idle_capacity=True, invalid_username_rejected=True, credential_metadata_lifecycle=True)
        spec = {"version": "0.2", "phases": {"build": {"commands": ["printf 'native artifact bytes\\n' > result.txt"]}},
                "artifacts": {"files": ["result.txt"], "name": "native-$(printf artifact).zip"}}
        build = cb.start_build(projectName=self.project, sourceTypeOverride="NO_SOURCE", sourceLocationOverride="",
                               buildspecOverride=json.dumps(spec),
                               artifactsOverride={"type": "S3", "location": self.bucket, "path": "artifacts",
                                                  "name": "ignored.zip", "packaging": "ZIP",
                                                  "namespaceType": "NONE", "overrideArtifactName": True})["build"]
        self.build_ids.append(build["id"])
        final = self.wait(build["id"], "SUCCEEDED")
        require(self.artifact(final, "native-artifact") == {"result.txt": b"native artifact bytes\n"},
                "shell-expanded artifact name or native bytes changed")
        self.note("shell_expanded_artifact_name", build_id=build["id"], object_key="artifacts/native-artifact.zip")

    def exercise_runtime_selection(self):
        if not self.args.runtime_image:
            return
        native_image = json.loads(self.docker("image", "inspect", self.args.runtime_image).stdout)[0]
        spec = {"version": "0.2", "phases": {
            "install": {"runtime-versions": {"java": "corretto17"}},
            "build": {"commands": ["java -version 2> runtime.txt", "cat runtime.txt"]}},
            "artifacts": {"files": ["runtime.txt"]}}
        build = self.clients["codebuild"].start_build(
            projectName=self.project, imageOverride=self.args.runtime_image,
            sourceTypeOverride="NO_SOURCE", sourceLocationOverride="", buildspecOverride=json.dumps(spec),
            artifactsOverride={"type": "S3", "location": self.bucket, "path": "artifacts",
                               "name": "runtime.zip", "packaging": "ZIP", "namespaceType": "NONE"})["build"]
        self.build_ids.append(build["id"])
        final = self.wait(build["id"], "SUCCEEDED")
        version = self.artifact(final, "runtime")["runtime.txt"].decode()
        require("Corretto" in version and 'version "17.' in version,
                "selected runtime did not execute actual Corretto 17")
        self.note("official_runtime_selection", build_id=build["id"], image_id=native_image["Id"],
                  image=self.args.runtime_image, version=version.strip())

    def exercise_sdk(self):
        if not self.args.sdk_image:
            return
        self.docker("image", "inspect", self.args.sdk_image)
        image = self.image.rsplit(":", 1)[0] + ":sdk"
        self.image_tags.add(image)
        self.docker("tag", self.args.sdk_image, image)
        self.docker("push", image, timeout=300)
        s3, iam, cb = self.clients["s3"], self.clients["iam"], self.clients["codebuild"]
        s3.put_object(Bucket=self.bucket, Key="sdk-input", Body=b"policy-sensitive-sdk-bytes")
        program = r'''import boto3,json,time
from botocore.exceptions import ClientError
s3=boto3.client("s3")
identity=boto3.client("sts").get_caller_identity()
assert ":assumed-role/__ROLE__/" in identity["Arn"],identity["Arn"]
assert s3.get_object(Bucket="__BUCKET__",Key="sdk-input")["Body"].read()==b"policy-sensitive-sdk-bytes"
s3.put_object(Bucket="__BUCKET__",Key="sdk-ready",Body=b"ready")
for _ in range(300):
    try:
        s3.get_object(Bucket="__BUCKET__",Key="sdk-gate")["Body"].close()
        break
    except ClientError as error:
        assert error.response["Error"]["Code"]=="NoSuchKey",error.response["Error"]["Code"]
        time.sleep(.2)
else:
    raise RuntimeError("SDK gate deadline")
try:
    s3.get_object(Bucket="__BUCKET__",Key="sdk-input")
except ClientError as error:
    assert error.response["Error"]["Code"]=="AccessDenied",error.response["Error"]["Code"]
else:
    raise RuntimeError("Current role denial was not enforced")
with open("identity.json","w") as output:
    json.dump({"roleArn":identity["Arn"],"currentPolicyDenied":True},output)
print("REAL-SDK-ROLE-AND-DENIAL-OK",flush=True)
'''.replace("__ROLE__", self.role).replace("__BUCKET__", self.bucket)
        encoded = base64.b64encode(program.encode()).decode()
        command = "python -c \"import base64;exec(base64.b64decode('" + encoded + "'))\""
        buildspec = json.dumps({"version": "0.2", "phases": {"build": {"commands": [command]}},
                                "artifacts": {"files": ["identity.json"]}})
        build = cb.start_build(projectName=self.project, imageOverride=image,
                               sourceTypeOverride="NO_SOURCE", sourceLocationOverride="",
                               buildspecOverride=buildspec,
                               artifactsOverride={"type": "S3", "location": self.bucket, "path": "artifacts",
                                                  "name": "sdk.zip", "packaging": "ZIP", "namespaceType": "NONE"})["build"]
        self.build_ids.append(build["id"])
        for _ in range(300):
            try:
                s3.get_object(Bucket=self.bucket, Key="sdk-ready")["Body"].close()
                break
            except self.client_error as error:
                require(error.response["Error"]["Code"] == "NoSuchKey", "unexpected SDK gate error")
                require(self.build(build["id"])["buildStatus"] == "IN_PROGRESS",
                        "SDK build failed before policy gate")
                time.sleep(.2)
        else:
            raise RuntimeError("SDK ready deadline")
        iam.put_role_policy(RoleName=self.role, PolicyName="sdk-denial",
                            PolicyDocument=policy([{"Effect": "Deny", "Action": "s3:GetObject",
                                                    "Resource": "arn:aws:s3:::" + self.bucket + "/sdk-input"}]))
        self.created.add("sdk_denial")
        s3.put_object(Bucket=self.bucket, Key="sdk-gate", Body=b"go")
        final = self.wait(build["id"], "SUCCEEDED")
        require("REAL-SDK-ROLE-AND-DENIAL-OK" in self.logs(final).splitlines(), "SDK proof marker missing")
        proof = json.loads(self.artifact(final, "sdk")["identity.json"])
        require(proof["currentPolicyDenied"] is True, "SDK did not observe current role denial")
        self.note("real_sdk_container_credentials", build_id=build["id"], image=image, **proof)

    def replication_status(self, digest, expected):
        ecr = self.clients["ecr"]
        for _ in range(120):
            response = ecr.describe_image_replication_status(
                repositoryName=self.repository, imageId={"imageDigest": digest})
            statuses = response.get("replicationStatuses", [])
            if statuses and all(row["status"] != "IN_PROGRESS" for row in statuses):
                require(len(statuses) == 1 and statuses[0]["status"] == expected,
                        "replication ended in unexpected state: " + json.dumps(statuses))
                return statuses[0]
            time.sleep(.25)
        raise RuntimeError("replication observation deadline")

    def exercise_replication(self):
        ecr = self.clients["ecr"]
        destination, region = "111111111111", "us-west-2"
        session = self.session.__class__(aws_access_key_id=destination, aws_secret_access_key="test", region_name=region)
        replica = session.client("ecr", endpoint_url=self.endpoint, region_name=region, config=self.config)
        self.replica_client = replica
        ecr.put_replication_configuration(replicationConfiguration={"rules": [{
            "destinations": [{"region": region, "registryId": destination}],
            "repositoryFilters": [{"filter": self.repository, "filterType": "PREFIX_MATCH"}]}]})
        self.created.add("replication")
        manifest = ecr.batch_get_image(repositoryName=self.repository,
                                       imageIds=[{"imageDigest": self.image_digest}])["images"][0]["imageManifest"]
        ecr.put_image(repositoryName=self.repository, imageManifest=manifest, imageTag="replica-no-grant")
        self.replication_status(self.image_digest, "FAILED")
        grant = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::" + ACCOUNT + ":root"},
                 "Action": ["ecr:CreateRepository", "ecr:ReplicateImage"], "Resource": "*"}
        replica.put_registry_policy(policyText=policy([grant]))
        self.created.add("replica_policy")
        ecr.put_image(repositoryName=self.repository, imageManifest=manifest, imageTag="replica-a")
        ecr.put_image(repositoryName=self.repository, imageManifest=manifest, imageTag="replica-b")
        self.replication_status(self.image_digest, "COMPLETE")
        self.created.add("replica_repository")
        copied = replica.batch_get_image(repositoryName=self.repository,
                                         imageIds=[{"imageTag": "replica-b"}])["images"][0]
        require(copied["imageManifest"] == manifest and copied["imageId"]["imageDigest"] == self.image_digest,
                "cross-account replica manifest bytes changed")
        for descriptor in json.loads(manifest)["layers"]:
            response = replica.get_download_url_for_layer(repositoryName=self.repository,
                                                          layerDigest=descriptor["digest"])
            with self.http.open(response["downloadUrl"], timeout=30) as stream:
                body = stream.read()
            require("sha256:" + hashlib.sha256(body).hexdigest() == descriptor["digest"],
                    "replication did not retain actual layer bytes")
        details = replica.describe_images(repositoryName=self.repository,
                                           imageIds=[{"imageDigest": self.image_digest}])["imageDetails"][0]
        require({"replica-a", "replica-b"}.issubset(details["imageTags"]), "replication lost accepted tags")
        replica.put_registry_policy(policyText=policy([grant, {
            "Effect": "Deny", "Principal": "*", "Action": "ecr:ReplicateImage", "Resource": "*"}]))
        ecr.put_image(repositoryName=self.repository, imageManifest=manifest, imageTag="replica-denied")
        self.replication_status(self.image_digest, "FAILED")
        result = replica.batch_get_image(repositoryName=self.repository, imageIds=[{"imageTag": "replica-denied"}])
        require(not result.get("images") and result["failures"][0]["failureCode"] == "ImageNotFound",
                "replication bypassed current destination policy")
        self.note("cross_account_replication", digest=self.image_digest, destination=destination, region=region,
                  layer_bytes_verified=True, initial_missing_grant_denied=True, changed_policy_denied=True)

    def exercise_scanning(self):
        if not self.args.scan_layout:
            return
        sqs, events = self.clients["sqs"], self.clients["events"]
        self.scan_queue = sqs.create_queue(QueueName=self.prefix)["QueueUrl"]
        self.created.add("scan_queue")
        queue_arn = sqs.get_queue_attributes(QueueUrl=self.scan_queue, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        rule_arn = events.put_rule(Name=self.prefix, EventPattern=json.dumps({
            "source": ["aws.ecr"], "detail-type": ["ECR Image Scan"],
            "detail": {"repository-name": [self.repository], "scan-status": ["COMPLETE"]}}))["RuleArn"]
        self.created.add("scan_rule")
        sqs.set_queue_attributes(QueueUrl=self.scan_queue, Attributes={"Policy": policy([{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}])})
        require(events.put_targets(Rule=self.prefix, Targets=[{"Id": "scan", "Arn": queue_arn}])["FailedEntryCount"] == 0,
                "scan EventBridge target admission failed")
        layout = Path(self.args.scan_layout).resolve()
        descriptor = json.loads((layout / "index.json").read_text())["manifests"][0]
        def blob(digest):
            algorithm, encoded = digest.split(":", 1)
            require(algorithm == "sha256" and len(encoded) == 64
                    and all(char in "0123456789abcdef" for char in encoded), "invalid OCI digest")
            data = (layout / "blobs" / algorithm / encoded).read_bytes()
            require(hashlib.sha256(data).hexdigest() == encoded, "OCI input digest mismatch")
            return data
        manifest = blob(descriptor["digest"])
        image = json.loads(manifest)
        ecr = self.clients["ecr"]
        for part in [image["config"], *image["layers"]]:
            body = blob(part["digest"])
            upload = ecr.initiate_layer_upload(repositoryName=self.repository)["uploadId"]
            ecr.upload_layer_part(repositoryName=self.repository, uploadId=upload, partFirstByte=0,
                                  partLastByte=len(body)-1, layerPartBlob=body)
            ecr.complete_layer_upload(repositoryName=self.repository, uploadId=upload, layerDigests=[part["digest"]])
        ecr.put_image(repositoryName=self.repository, imageManifest=manifest.decode(), imageTag="scan-native")
        ecr.start_image_scan(repositoryName=self.repository, imageId={"imageTag": "scan-native"})
        for _ in range(240):
            result = ecr.describe_image_scan_findings(repositoryName=self.repository,
                                                     imageId={"imageTag": "scan-native"}, maxResults=1000)
            status = result["imageScanStatus"]["status"]
            if status not in {"PENDING", "IN_PROGRESS"}:
                require(status == "COMPLETE", "real scanner failed: " + json.dumps(result["imageScanStatus"]))
                break
            time.sleep(.5)
        else:
            raise RuntimeError("real scanner observation deadline")
        findings = result["imageScanFindings"]
        match = [row for row in findings["findings"] if row["name"] == "CVE-2023-42364"
                 and {item["key"]: item.get("value") for item in row.get("attributes", [])}.get("package_name") == "busybox"]
        require(match and findings.get("vulnerabilitySourceUpdatedAt"),
                "real Alpine scan did not expose native database finding")
        try:
            ecr.start_image_scan(repositoryName=self.repository, imageId={"imageTag": "scan-native"})
        except self.client_error as error:
            require(error.response["Error"]["Code"] == "LimitExceededException", "wrong repeated-scan rejection")
        else:
            raise RuntimeError("manual scan interval not enforced")
        for _ in range(30):
            messages = sqs.receive_message(QueueUrl=self.scan_queue, MaxNumberOfMessages=1, WaitTimeSeconds=1).get("Messages", [])
            if messages:
                event = json.loads(messages[0]["Body"])
                require(event["source"] == "aws.ecr" and event["detail-type"] == "ECR Image Scan"
                        and event["resources"] == [self.repository_arn]
                        and event["detail"]["image-digest"] == descriptor["digest"]
                        and event["detail"]["finding-severity-counts"] == findings["findingSeverityCounts"],
                        "consumed scan event disagrees with actual scanner result")
                sqs.delete_message(QueueUrl=self.scan_queue, ReceiptHandle=messages[0]["ReceiptHandle"])
                self.note("scan_eventbridge_sqs_delivery", event_id=event["id"], digest=descriptor["digest"])
                break
        else:
            raise RuntimeError("native scan EventBridge event was not delivered to SQS")
        self.note("real_scanner_api", manifest_digest=descriptor["digest"], scanner="Trivy 0.74.0",
                  finding="CVE-2023-42364", severity_counts=findings["findingSeverityCounts"],
                  database_updated_at=findings["vulnerabilitySourceUpdatedAt"].isoformat())
        ecr.put_image_scanning_configuration(repositoryName=self.repository, imageScanningConfiguration={"scanOnPush": True})
        context = self.state / "scan-image-context"
        context.mkdir(mode=0o700)
        (context / "Dockerfile").write_text("FROM " + self.local_image + "\nLABEL stackd.scan-negative=" + self.prefix + "\n")
        negative_image = self.image.rsplit(":", 1)[0] + ":scan-no-packages"
        self.image_tags.add(negative_image)
        self.docker("build", "--pull=false", "--network=none", "--tag", negative_image, str(context))
        self.docker("push", negative_image)
        negative_digest = ecr.describe_images(repositoryName=self.repository,
                                              imageIds=[{"imageTag": "scan-no-packages"}])["imageDetails"][0]["imageDigest"]
        for _ in range(240):
            result = ecr.describe_image_scan_findings(repositoryName=self.repository,
                                                     imageId={"imageTag": "scan-no-packages"})
            status = result["imageScanStatus"]
            if status["status"] not in {"PENDING", "IN_PROGRESS"}:
                require(status["status"] == "FAILED" and "UnsupportedImageError" in status.get("description", ""),
                        "package-less native image received a fake clean scan")
                break
            time.sleep(.5)
        else:
            raise RuntimeError("scan-on-push observation deadline")
        ecr.put_image_scanning_configuration(repositoryName=self.repository, imageScanningConfiguration={"scanOnPush": False})
        self.note("native_scan_on_push_failure", digest=negative_digest, status=status["status"],
                  reason="UnsupportedImageError")

    def delete_replication_role(self):
        iam = self.clients["iam"]
        task = iam.delete_service_linked_role(RoleName="AWSServiceRoleForECRReplication")["DeletionTaskId"]
        for _ in range(120):
            response = iam.get_service_linked_role_deletion_status(DeletionTaskId=task)
            if response["Status"] == "SUCCEEDED":
                self.note("replication_role_api_deletion", status="SUCCEEDED")
                return
            if response["Status"] == "FAILED":
                reason = response.get("Reason", {}).get("Reason", "")
                require("active sessions" in reason, "unexpected owned replication role deletion failure: " + reason)
                self.note("replication_role_api_deletion_blocked", status="FAILED",
                          reason=reason, evidence_scope="local IAM authority, not native AWS calibration",
                          cleanup="whole owned local fixture after process shutdown; no session revocation")
                return
            time.sleep(.25)
        raise RuntimeError("owned replication role deletion deadline")

    def wait_build_cleanup(self):
        for build_id in self.build_ids:
            arn = "arn:aws:codebuild:" + REGION + ":" + ACCOUNT + ":build/" + build_id
            for _ in range(120):
                if not self.docker("ps", "-aq", "--filter", "label=stackd.codebuild.arn=" + arn).stdout.strip():
                    break
                time.sleep(.25)
            else:
                raise RuntimeError("owned native build resources remain after API deletion")
        self.note("native_build_cleanup", owned_build_count=len(self.build_ids), remaining_containers=0)

    def cleanup(self):
        def attempt(label, function, *args, **kwargs):
            try:
                return function(*args, **kwargs)
            except Exception as error:
                self.cleanup_errors.append(label + ": " + self.safe_error(error))
                return None

        cb, iam, s3 = self.clients["codebuild"], self.clients["iam"], self.clients["s3"]
        if not self.args.keep_resources and self.process is not None and self.process.poll() is None:
            for build_id in self.build_ids:
                build = attempt("read owned build", self.build, build_id)
                if build and build["buildStatus"] not in TERMINAL:
                    attempt("stop owned build", cb.stop_build, id=build_id)
                    attempt("wait owned stop", self.wait, build_id, "STOPPED", timeout=30)
            if self.build_ids:
                deleted = attempt("delete owned builds", cb.batch_delete_builds, ids=self.build_ids)
                if deleted and deleted.get("buildsNotDeleted"):
                    self.cleanup_errors.append("CodeBuild retained owned build records")
                attempt("wait owned native cleanup", self.wait_build_cleanup)
            if "project" in self.created:
                attempt("delete owned project", cb.delete_project, name=self.project)
            if "fleet" in self.created:
                attempt("delete owned fleet", cb.delete_fleet, arn=self.fleet_arn)
                attempt("wait owned fleet release", self.wait_fleet, self.fleet_arn, "DELETED")
            if "source_credential" in self.created:
                attempt("delete owned source credentials", cb.delete_source_credentials, arn=self.source_credential_arn)
            if "scan_rule" in self.created:
                attempt("remove scan target", self.clients["events"].remove_targets, Rule=self.prefix, Ids=["scan"])
                attempt("delete scan rule", self.clients["events"].delete_rule, Name=self.prefix)
            if "scan_queue" in self.created:
                attempt("delete scan queue", self.clients["sqs"].delete_queue, QueueUrl=self.scan_queue)
            if "replication" in self.created:
                attempt("disable owned replication", self.clients["ecr"].put_replication_configuration,
                        replicationConfiguration={"rules": []})
            if "replica_repository" in self.created:
                attempt("delete replica repository", self.replica_client.delete_repository,
                        repositoryName=self.repository, force=True)
            if "replica_policy" in self.created:
                attempt("delete replica policy", self.replica_client.delete_registry_policy)
            if "repository" in self.created:
                attempt("delete owned repository", self.clients["ecr"].delete_repository, repositoryName=self.repository, force=True)
            if "replication" in self.created:
                attempt("delete owned replication role", self.delete_replication_role)
            if "log_group" in self.created:
                attempt("delete owned logs", self.clients["logs"].delete_log_group, logGroupName=self.group)
            if "bucket" in self.created:
                try:
                    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=self.bucket):
                        for item in page.get("Contents", []):
                            s3.delete_object(Bucket=self.bucket, Key=item["Key"])
                    s3.delete_bucket(Bucket=self.bucket)
                except Exception as error:
                    self.cleanup_errors.append("delete owned bucket: " + self.safe_error(error))
            if "deny_source" in self.created:
                attempt("delete owned deny policy", iam.delete_role_policy, RoleName=self.role, PolicyName="deny-source")
            if "sdk_denial" in self.created:
                attempt("delete SDK deny policy", iam.delete_role_policy, RoleName=self.role, PolicyName="sdk-denial")
            if "role" in self.created:
                attempt("delete owned role policy", iam.delete_role_policy, RoleName=self.role, PolicyName="owned")
                attempt("delete owned role", iam.delete_role, RoleName=self.role)
            if "access_key" in self.created:
                attempt("delete owned access key", iam.delete_access_key, UserName=self.user, AccessKeyId=self.access_key)
            if "user" in self.created:
                attempt("delete owned user policy", iam.delete_user_policy, UserName=self.user, PolicyName="owned")
                attempt("delete owned user", iam.delete_user, UserName=self.user)
        elif self.created and not self.args.keep_resources:
            self.cleanup_errors.append("controller unavailable; owned cloud resources remain in retained SQLite")
        attempt("stop owned controller", self.stop)
        if self.docker_config is not None:
            if not self.args.keep_resources:
                for name in self.container_names:
                    attempt("remove owned image-check container", self.docker, "rm", "-f", name)
                for tag in sorted(self.image_tags):
                    if self.docker("image", "inspect", tag, check=False).returncode == 0:
                        attempt("remove owned image tag", self.docker, "image", "rm", tag)
            self.docker_config.cleanup()
        if self.server_log:
            self.server_log.close()
        if self.owns_state and not self.args.keep_resources and not self.cleanup_errors:
            # This directory was created exclusively by prepare(). Keep public
            # evidence, not retained sessions, credentials or workload state.
            for path in self.state.iterdir():
                if path.name == "evidence.json":
                    continue
                if path.is_dir() and not path.is_symlink():
                    attempt("remove owned local directory", shutil.rmtree, path)
                else:
                    attempt("remove owned local file", path.unlink)
            if not self.cleanup_errors:
                self.note("owned_local_fixture_teardown", retained_files=["evidence.json"],
                          native_workloads_stopped=True, iam_authority_bypassed=False)
        if self.owns_state:
            self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True, help="absolute parent-built stackd executable")
    parser.add_argument("--state-dir", required=True, help="new owned directory, basename starts stackd-buildowner")
    parser.add_argument("--port", required=True, type=int, help="unique unused local TCP port")
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock", choices=["unix:///var/run/docker.sock"])
    parser.add_argument("--restart-mode", choices=["graceful", "crash"], default="graceful")
    parser.add_argument("--sdk-image", help="locally installed Python/boto3 image for real in-container current-policy proof")
    parser.add_argument("--runtime-image", help="installed official CodeBuild image with actual Corretto 17 runtime manifest")
    parser.add_argument("--ecr-scanner", help="pinned local Trivy executable for actual scanner API proof")
    parser.add_argument("--ecr-scanner-cache", help="existing offline Trivy database cache")
    parser.add_argument("--scan-layout", help="existing real Alpine OCI layout for scanner API proof")
    parser.add_argument("--keep-resources", action="store_true", help="preserve owned resources for diagnosis, not credentials")
    args = parser.parse_args()
    require(1024 <= args.port <= 65535, "--port must be an unprivileged TCP port")
    require(bool(args.ecr_scanner) == bool(args.ecr_scanner_cache) == bool(args.scan_layout),
            "scanner proof requires --ecr-scanner, --ecr-scanner-cache and --scan-layout together")
    # Imports occur after --help; no implicit package installation or AWS tool fallback.
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError

    os.umask(0o077)
    smoke = Smoke(args, boto3, Config, ClientError)
    passed = False
    try:
        smoke.prepare()
        smoke.start()
        smoke.setup_image()
        smoke.setup_project()
        smoke.exercise_controls()
        smoke.exercise_runtime_selection()
        smoke.exercise_sdk()
        smoke.exercise_scanning()
        smoke.exercise_replication()
        smoke.exercise_builds()
        passed = True
    except Exception as error:
        if smoke.owns_state:
            smoke.note("failure", error=smoke.safe_error(error))
        else:
            print(smoke.safe_error(error), file=sys.stderr)
    finally:
        smoke.cleanup()
    if smoke.owns_state:
        smoke.note("result", passed=passed and not smoke.cleanup_errors,
                   resources_preserved=args.keep_resources, cleanup_errors=smoke.cleanup_errors)
    return 0 if passed and not smoke.cleanup_errors else 1


if __name__ == "__main__":
    sys.exit(main())
