#!/usr/bin/env python3
"""Real owned EKS/k3d -> GuardDuty SDK smoke, with CloudWatch logging disabled.

Run: python3 scripts/guardduty_eks_smoke/main.py --binary /absolute/stackd \
    --k3d /absolute/k3d --evidence /tmp/guardduty-eks-evidence.json
Requires Python boto3, Go (using this repository's SDK modules), AWS CLI, kubectl,
Docker, k3d v5.8.3, and the runtime's pinned k3s images plus busybox:1.37.0
(or --image). No AWS endpoints are used.
The controller uses an isolated SQLite database and private runtime directory.
Anonymous grants are confined to an owned namespace and read-only access to that
namespace's metadata, then revoked before the fixture is restored.
"""
import argparse
from contextlib import contextmanager
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import socket
import sqlite3
import ssl
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


REGION = "us-east-1"
EXEC_TYPE = "Execution:Kubernetes/ExecInKubeSystemPod"
GRANT_TYPE = "Policy:Kubernetes/AnonymousAccessGranted"
RBAC_GROUP = "rbac.authorization.k8s.io"
AUDIT_POLICY_HASH_FIELD = "AuditPolicyHash"
FEATURES = ("S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "EBS_MALWARE_PROTECTION",
            "RDS_LOGIN_EVENTS", "LAMBDA_NETWORK_LOGS", "RUNTIME_MONITORING",
            "AI_PROTECTION", "AI_ANALYST")


def require(condition, detail):
    if not condition:
        raise AssertionError(detail)


class Smoke:
    def __init__(self, args):
        self.args = args
        if args.evidence.exists():
            raise RuntimeError("Refusing to overwrite existing evidence")
        self.root = Path(tempfile.mkdtemp(prefix="stackd-guardduty-eks-"))
        self.prefix = "gd-eks-" + uuid.uuid4().hex[:10]
        self.account = f"{uuid.uuid4().int % 10**12:012d}"
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith("AWS_") and k not in ("KUBECONFIG", "DOCKER_CONTEXT")}
        self.env.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test",
                        AWS_DEFAULT_REGION=REGION, AWS_EC2_METADATA_DISABLED="true", AWS_PAGER="",
                        AWS_CONFIG_FILE=str(self.root / "aws-config"),
                        AWS_SHARED_CREDENTIALS_FILE=str(self.root / "aws-credentials"),
                        KUBECONFIG=str(self.root / "kubeconfig"), DOCKER_HOST=args.docker_host)
        session = boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION)
        config = Config(signature_version="v4", ignore_configured_endpoint_urls=True,
                        retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=60)
        self.clients = {name: session.client(name, endpoint_url=self.endpoint, config=config)
                        for name in ("ec2", "iam", "eks", "guardduty", "logs")}
        self.process = None
        self.log = open(self.root / "controller.log", "ab")
        self.owned = {"subnets": []}
        self.native_dir = None
        self.native_id = None
        self.detector = None
        self.evidence = {"scope": "Actual local EKS/k3d audit operations; no sample findings or injected webhook events",
                         "account": self.account, "region": REGION, "prefix": self.prefix,
                         "diagnosticDirectory": str(self.root), "observations": {}, "cleanup": []}
        self.save()

    def save(self):
        self.args.evidence.parent.mkdir(parents=True, exist_ok=True)
        self.args.evidence.write_text(json.dumps(self.evidence, indent=2, default=str) + "\n")

    def call(self, service, operation, **request):
        return getattr(self.clients[service], operation)(**request)

    def command(self, argv, stdin=None, timeout=180, cwd=None):
        result = subprocess.run(argv, env=self.env, input=stdin, text=True, capture_output=True, timeout=timeout, cwd=cwd)
        if result.returncode:
            raise RuntimeError(f"{argv[:4]}: {result.stderr[-4000:]}")
        return result.stdout

    def kube(self, *args, stdin=None, native=False):
        config = self.native_dir / "admin.kubeconfig" if native else self.root / "kubeconfig"
        return self.command(["kubectl", "--kubeconfig", str(config), "--request-timeout=90s", *args], stdin)

    def wait(self, label, fn, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = fn()
            if result:
                return result
            time.sleep(1)
        raise TimeoutError(label)

    def start(self):
        self.process = subprocess.Popen([
            str(self.args.binary), "-listen", f"127.0.0.1:{self.port}", "-account-id", self.account,
            "-database", str(self.root / "state.db"), "-docker-host", self.args.docker_host,
            "-compute-endpoint", f"http://host.docker.internal:{self.port}",
            "-eks-state-directory", str(self.root / "kubernetes"), "-eks-k3d", str(self.args.k3d),
        ], env=self.env, stdout=self.log, stderr=self.log)
        def ready():
            if self.process.poll() is not None:
                raise RuntimeError((self.root / "controller.log").read_text()[-6000:])
            try:
                with urllib.request.urlopen(self.endpoint + "/_stackd/health", timeout=1) as response:
                    return response.status == 200
            except OSError:
                return False
        self.wait("controller startup", ready, 60)

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
                raise RuntimeError("controller did not stop gracefully")
            require(self.process.returncode == 0, f"controller exit {self.process.returncode}")
        self.process = None

    def active(self):
        cluster = self.call("eks", "describe_cluster", name=self.prefix)["cluster"]
        require(cluster["status"] != "FAILED", cluster.get("health", cluster["status"]))
        return cluster if cluster["status"] == "ACTIVE" else None

    def no_cloudwatch(self):
        cluster = self.call("eks", "describe_cluster", name=self.prefix)["cluster"]
        configured = cluster.get("logging", {}).get("clusterLogging", [])
        require(not any(row.get("enabled") for row in configured), configured)
        groups = self.call("logs", "describe_log_groups", logGroupNamePrefix=f"/aws/eks/{self.prefix}/cluster")
        require(not groups.get("logGroups"), groups)
        return {"clusterLogging": configured, "logGroups": []}

    def findings(self):
        ids, token = [], None
        while True:
            request = {"DetectorId": self.detector, "MaxResults": 50}
            if token:
                request["NextToken"] = token
            page = self.call("guardduty", "list_findings", **request)
            ids.extend(page["FindingIds"])
            token = page.get("NextToken")
            if not token:
                break
        rows = []
        for offset in range(0, len(ids), 50):
            rows.extend(self.call("guardduty", "get_findings", DetectorId=self.detector,
                                  FindingIds=ids[offset:offset + 50])["Findings"])
        return sorted(rows, key=lambda row: row["Id"])

    def snapshot(self):
        return {row["Id"]: {key: row[key] for key in ("Id", "Arn", "Type", "CreatedAt", "UpdatedAt", "Resource", "Service")}
                for row in self.findings() if row["Resource"]["ResourceType"] == "EKSCluster"}

    def unchanged(self, expected, seconds=5):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            actual = self.snapshot()
            require(actual == expected, {"expected": expected, "actual": actual})
            time.sleep(0.5)

    def audit(self, marker, username=None):
        # Read authentic retained webhook frames only; never manufacture or replay them.
        path = self.native_dir / "audit.events"
        if not path.exists():
            return None
        with path.open("rb") as stream:
            while True:
                prefix = stream.read(4)
                if len(prefix) != 4:
                    return None
                size = struct.unpack(">I", prefix)[0]
                body = stream.read(size)
                if len(body) != size:
                    return None
                for event in json.loads(body)["items"]:
                    effective = event.get("impersonatedUser", event.get("user", {}))
                    if (marker in event.get("requestURI", "") and event.get("stage") == "ResponseComplete"
                            and (username is None or effective.get("username") == username)):
                        result = {key: event[key] for key in ("auditID", "level", "stage", "stageTimestamp", "verb", "requestURI",
                                                              "user", "impersonatedUser", "sourceIPs", "userAgent",
                                                              "objectRef", "responseStatus") if key in event}
                        result["responseObjectPresent"] = "responseObject" in event
                        request = event.get("requestObject")
                        if event.get("verb") in ("delete", "deletecollection") and isinstance(request, dict):
                            # DeleteOptions only: never retain deleted objects or secret payloads.
                            result["requestObject"] = {
                                key: request[key] for key in ("apiVersion", "kind", "dryRun") if key in request}
                        response = event.get("responseObject", {})
                        if (event.get("verb") == "create" and 200 <= event.get("responseStatus", {}).get("code", 0) < 300
                                and response.get("apiVersion") == RBAC_GROUP + "/v1"
                                and response.get("kind") in ("RoleBinding", "ClusterRoleBinding")):
                            # Retain only native RBAC evidence, never arbitrary response bodies or secret values.
                            result["responseObject"] = {key: response[key] for key in ("apiVersion", "kind", "roleRef", "subjects")}
                            result["responseObject"]["metadata"] = {
                                key: response["metadata"][key] for key in ("name", "namespace", "uid") if key in response["metadata"]}
                        return result

    def completed_audit(self, marker, username=None):
        return self.wait("native ResponseComplete audit: " + marker, lambda: self.audit(marker, username))

    @staticmethod
    def finding_object(kind, audit):
        obj = audit.get("objectRef", {})
        if kind == GRANT_TYPE and not obj.get("name"):
            return {**obj, "name": audit["responseObject"]["metadata"]["name"]}
        return obj

    def finding_for(self, kind, audit):
        obj = self.finding_object(kind, audit)
        matches = [row for row in self.findings() if row["Type"] == kind
                   and row.get("Service", {}).get("Action", {}).get("KubernetesApiCallAction", {}).get("RequestUri") == audit["requestURI"]]
        if kind == GRANT_TYPE:
            matches = [row for row in matches
                       if row["Service"]["Action"]["KubernetesApiCallAction"].get("ResourceName") == obj["name"]
                       and row["Service"]["Action"]["KubernetesApiCallAction"].get("Namespace", "") == obj.get("namespace", "")
                       and row["Service"]["Action"]["KubernetesApiCallAction"].get("Resource") == obj["resource"]]
        if not matches:
            return None
        require(len(matches) == 1, matches)
        finding = matches[0]
        resource = finding["Resource"]
        require(resource["ResourceType"] == "EKSCluster", resource)
        require(resource["EksClusterDetails"]["Arn"] == self.cluster["arn"], resource)
        require(resource["EksClusterDetails"]["Name"] == self.prefix, resource)
        user = resource["KubernetesDetails"]["KubernetesUserDetails"]
        effective = audit.get("impersonatedUser", audit["user"])
        projected = user.get("ImpersonatedUser", user)
        require(projected["Username"] == effective["username"], {"audit": audit, "user": user})
        require(sorted(projected.get("Groups", [])) == sorted(effective.get("groups", [])), user)
        action = finding["Service"]["Action"]
        require(action["ActionType"] == "KUBERNETES_API_CALL", action)
        details = action["KubernetesApiCallAction"]
        require(details["Verb"] == audit["verb"] and details["StatusCode"] == audit["responseStatus"]["code"], details)
        for api_key, audit_key in (("Namespace", "namespace"), ("Resource", "resource"), ("ResourceName", "name"), ("Subresource", "subresource")):
            require(details.get(api_key, "") == obj.get(audit_key, ""), details)
        require(details.get("SourceIps") == audit["sourceIPs"], details)
        require(details.get("UserAgent") == audit["userAgent"], details)
        require("AwsApiCallAction" not in action and "RuntimeDetails" not in finding["Service"], finding)
        if kind == GRANT_TYPE:
            native = audit["responseObject"]
            additional = json.loads(finding["Service"]["AdditionalInfo"]["Value"])
            require(additional.get("roleRef") == native["roleRef"], {"native": native, "additional": additional})
            require(self.binding_subjects(additional.get("subjects", [])) == self.binding_subjects(native["subjects"]),
                    {"native": native, "additional": additional})
        return finding

    @staticmethod
    def binding_subjects(subjects):
        return [{key: subject.get(key, "") for key in ("apiGroup", "kind", "name", "namespace")} for subject in subjects]

    def create_binding(self, binding, label, dry_run=False, cleanup_bindings=None):
        marker = self.prefix + "-" + label + "-" + uuid.uuid4().hex[:8]
        options = ["--dry-run=server"] if dry_run else []
        created = json.loads(self.kube("create", "--field-manager", marker, "-f", "-", "-o", "json", *options,
                                       native=True, stdin=json.dumps(binding)))
        if cleanup_bindings is not None and not dry_run:
            cleanup_bindings.append({"apiVersion": created["apiVersion"], "kind": created["kind"],
                                     "metadata": {key: created["metadata"][key] for key in ("name", "namespace")
                                                  if key in created["metadata"]}})
        audit = self.completed_audit(marker)
        require(audit["verb"] == "create" and audit["responseStatus"]["code"] == 201, audit)
        require(audit["level"] == "RequestResponse", audit)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(audit["requestURI"]).query)
        require(query.get("dryRun", []) == (["All"] if dry_run else []), audit)
        native = audit["responseObject"]
        require(native["apiVersion"] == binding["apiVersion"] and native["kind"] == binding["kind"], native)
        if not dry_run:
            require(native["metadata"]["uid"] == created["metadata"]["uid"], {"created": created, "audit": audit})
        name = native["metadata"]["name"]
        require(name == created["metadata"]["name"], {"created": created, "audit": audit})
        if binding["metadata"].get("name"):
            require(name == binding["metadata"]["name"], native)
        else:
            prefix = binding["metadata"]["generateName"]
            require(name.startswith(prefix) and name != prefix, native)
        require(not audit["objectRef"].get("name") or audit["objectRef"]["name"] == name, audit)
        require(native["metadata"].get("namespace", "") == binding["metadata"].get("namespace", ""), native)
        require(audit["objectRef"].get("namespace", "") == binding["metadata"].get("namespace", ""), audit)
        require(native["roleRef"] == binding["roleRef"], native)
        require(self.binding_subjects(native["subjects"]) == self.binding_subjects(binding["subjects"]), native)
        return audit

    def denied_binding(self, binding):
        marker = self.prefix + "-denied-" + uuid.uuid4().hex[:8]
        username = self.prefix + "-unprivileged"
        result = subprocess.run([
            "kubectl", "--kubeconfig", str(self.native_dir / "admin.kubeconfig"), "--request-timeout=90s",
            "--as", username, "--as-group", "system:authenticated", "create", "--field-manager", marker, "-f", "-",
        ], env=self.env, input=json.dumps(binding), text=True, capture_output=True, timeout=180)
        audit = self.completed_audit(marker, username)
        require(result.returncode != 0 and audit["verb"] == "create" and audit["responseStatus"]["code"] == 403, audit)
        require(audit["impersonatedUser"]["username"] == username, audit)
        absent = self.kube("get", "rolebinding", binding["metadata"]["name"], "-n", self.prefix,
                           "--ignore-not-found", "-o", "json", native=True)
        require(not absent.strip(), "RBAC-denied binding was persisted")
        return audit

    def exec_pod(self, namespace, marker):
        output = self.kube("exec", "-n", namespace, self.prefix, "--", "printf", "%s", marker)
        require(output == marker, output)
        return self.completed_audit(marker)

    def setup(self):
        self.start()
        vpc = self.call("ec2", "create_vpc", CidrBlock="10.246.0.0/16")["Vpc"]["VpcId"]
        self.owned["vpc"] = vpc
        for index in (1, 2):
            subnet = self.call("ec2", "create_subnet", VpcId=vpc, CidrBlock=f"10.246.{index}.0/24",
                               AvailabilityZone=REGION + ("a" if index == 1 else "b"))["Subnet"]["SubnetId"]
            self.owned["subnets"].append(subnet)
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        role = self.call("iam", "create_role", RoleName=self.prefix, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
        self.owned["role"] = self.prefix
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["ec2:DescribeSubnets", "ec2:DescribeSecurityGroups"], "Resource": "*"}]}
        self.call("iam", "put_role_policy", RoleName=self.prefix, PolicyName="networks", PolicyDocument=json.dumps(policy))
        self.owned["rolePolicy"] = True
        self.call("eks", "create_cluster", name=self.prefix, version="1.32", roleArn=role,
                  resourcesVpcConfig={"subnetIds": self.owned["subnets"]}, accessConfig={"authenticationMode": "CONFIG_MAP"},
                  logging={"clusterLogging": [{"types": ["api", "audit", "authenticator", "controllerManager", "scheduler"], "enabled": False}]})
        self.owned["cluster"] = self.prefix
        with sqlite3.connect((self.root / "state.db").as_uri() + "?mode=ro", uri=True) as database:
            rows = database.execute("SELECT id FROM eks_cluster WHERE name=?", (self.prefix,)).fetchall()
        require(len(rows) == 1, rows)
        self.native_id = rows[0][0]
        self.native_dir = self.root / "kubernetes" / hashlib.sha256(self.native_id.encode()).hexdigest()
        self.cluster = self.wait("EKS cluster ACTIVE", self.active, 600)
        owner = json.loads((self.native_dir / "owner.json").read_text())
        require(owner["ID"] == self.native_id, "native ownership mismatch")
        self.native_name = owner["Name"]
        self.command(["aws", "--endpoint-url", self.endpoint, "--region", REGION, "eks", "update-kubeconfig",
                      "--name", self.prefix, "--kubeconfig", str(self.root / "kubeconfig")])
        self.kube("create", "namespace", self.prefix)
        for namespace in (self.prefix, "kube-system"):
            pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": self.prefix, "namespace": namespace},
                   "spec": {"automountServiceAccountToken": False, "containers": [{"name": "proof", "image": self.args.image,
                             "command": ["sh", "-c", "sleep 3600"]}]}}
            self.kube("apply", "-f", "-", stdin=json.dumps(pod))
            self.kube("wait", "-n", namespace, "--for=condition=Ready", "pod/" + self.prefix, "--timeout=150s")
        self.detector = self.call("guardduty", "create_detector", Enable=True,
                                 Features=[{"Name": name, "Status": "ENABLED" if name == "EKS_AUDIT_LOGS" else "DISABLED"}
                                           for name in FEATURES])["DetectorId"]
        detector = self.call("guardduty", "get_detector", DetectorId=self.detector)
        require(detector["Status"] == "ENABLED", detector)
        statuses = {row["Name"]: row["Status"] for row in detector["Features"]}
        require(statuses.get("EKS_AUDIT_LOGS") == "ENABLED", statuses)
        for name in FEATURES:
            if name != "EKS_AUDIT_LOGS":
                require(statuses.get(name) == "DISABLED", {name: statuses.get(name)})
        self.evidence["observations"]["detector"] = detector
        self.evidence["observations"]["cloudWatchBefore"] = self.no_cloudwatch()
        self.save()

    def owned_native_server(self):
        owner = json.loads((self.native_dir / "owner.json").read_text())
        require(owner["ID"] == self.native_id and owner["DockerHost"] == self.args.docker_host,
                "refusing native fixture mutation with mismatched ownership")
        name = "k3d-" + owner["Name"] + "-server-0"
        containers = json.loads(self.command(["docker", "inspect", name]))
        require(len(containers) == 1, "expected exactly one owned control plane")
        container = containers[0]
        labels = container["Config"]["Labels"]
        require(container["Name"] == "/" + name
                and labels.get("stackd.eks.owner") == owner["Token"]
                and labels.get("stackd.eks.id") == self.native_id
                and labels.get("k3d.cluster") == owner["Name"],
                "refusing native fixture mutation on unowned Docker control plane")
        return container["Id"]

    def native_ready(self, native=True):
        kubeconfig = self.native_dir / "admin.kubeconfig" if native else self.root / "kubeconfig"
        probe = subprocess.run([
            "kubectl", "--kubeconfig", str(kubeconfig),
            "--request-timeout=5s", "get", "--raw", "/readyz",
        ], env=self.env, text=True, capture_output=True, timeout=15)
        return probe.returncode == 0 and probe.stdout.strip() == "ok"

    def read_native_private(self, name):
        require(stat.S_IMODE(self.native_dir.lstat().st_mode) == 0o700
                and not self.native_dir.is_symlink(), "native state directory is not private")
        path = self.native_dir / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
                "native state file is not private: " + name)
        return path.read_bytes()

    def write_native_private(self, name, content):
        self.read_native_private(name)
        descriptor, pending = tempfile.mkstemp(prefix=".guardduty-", dir=self.native_dir)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(pending, self.native_dir / name)
        finally:
            Path(pending).unlink(missing_ok=True)

    @contextmanager
    def retained_policy_upgrade(self, findings_before):
        server = self.owned_native_server()
        owner = json.loads(self.read_native_private("owner.json"))
        original_policy = self.read_native_private("audit-policy.yaml")
        original_hash = hashlib.sha256(original_policy).hexdigest()
        require(owner.get(AUDIT_POLICY_HASH_FIELD) == original_hash, "initial loaded audit policy hash missing")
        identity = {key: owner[key] for key in ("ID", "Name", "Token", "DockerHost")}
        container = json.loads(self.command(["docker", "inspect", server]))[0]
        require(any(mount.get("Source") == str(self.native_dir / "audit-policy.yaml")
                    and mount.get("Destination") == "/etc/stackd/audit-policy.yaml"
                    and mount.get("RW") is False for mount in container["Mounts"]),
                "policy fixture requires the exact-owned read-only host policy mount")
        pods_before = {namespace: json.loads(self.kube(
            "get", "pod", self.prefix, "-n", namespace, "-o", "json", native=True))["metadata"]["uid"]
                       for namespace in (self.prefix, "kube-system")}
        metadata_policy = b"apiVersion: audit.k8s.io/v1\nkind: Policy\nomitStages: [RequestReceived]\nrules:\n- level: Metadata\n"
        fixture = {"nativeClusterID": self.native_id, "containerID": server,
                   "policyHashBefore": original_hash, "metadataPolicyHash": hashlib.sha256(metadata_policy).hexdigest(),
                   "podUIDsBefore": pods_before, "restored": False, "requestResponseProven": False}
        self.evidence["observations"]["retainedAuditPolicyUpgrade"] = fixture
        self.save()

        def verified():
            require(self.owned_native_server() == server, "audit policy upgrade replaced the owned control plane")
            current = json.loads(self.read_native_private("owner.json"))
            require({key: current[key] for key in identity} == identity, "audit policy upgrade changed native ownership")
            return current

        try:
            verified()
            unchanged_started = container["State"]["StartedAt"]
            self.stop()
            self.start()
            self.wait("EKS reattached with unchanged audit policy", self.active, 300)
            self.wait("authenticated proxy reattached", lambda: self.native_ready(native=False), 300)
            require(verified().get(AUDIT_POLICY_HASH_FIELD) == original_hash, "unchanged audit policy stamp changed")
            require(json.loads(self.command(["docker", "inspect", server]))[0]["State"]["StartedAt"] == unchanged_started,
                    "unchanged audit policy unnecessarily restarted the control plane")
            self.unchanged(findings_before)
            fixture["unchangedPolicyNoRestart"] = True
            self.write_native_private("audit-policy.yaml", metadata_policy)
            self.command(["docker", "restart", "--time", "30", server])
            self.wait("native API ready with retained metadata-only policy", self.native_ready, 180)
            metadata_started = json.loads(self.command(["docker", "inspect", server]))[0]["State"]["StartedAt"]
            role = {"apiVersion": RBAC_GROUP + "/v1", "kind": "Role",
                    "metadata": {"name": "policy-upgrade-proof", "namespace": self.prefix},
                    "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]}
            binding = {"apiVersion": RBAC_GROUP + "/v1", "kind": "RoleBinding",
                       "metadata": {"name": "policy-upgrade-proof", "namespace": self.prefix},
                       "roleRef": {"apiGroup": RBAC_GROUP, "kind": "Role", "name": role["metadata"]["name"]},
                       "subjects": [{"apiGroup": RBAC_GROUP, "kind": "User", "name": self.prefix + "-ordinary-user"}]}
            marker = self.prefix + "-metadata-policy-" + uuid.uuid4().hex[:8]
            try:
                self.kube("create", "-f", "-", native=True, stdin=json.dumps(role))
                created = json.loads(self.kube("create", "--field-manager", marker, "-f", "-", "-o", "json",
                                               native=True, stdin=json.dumps(binding)))
                audit = self.completed_audit(marker)
                require(audit["verb"] == "create" and audit["responseStatus"]["code"] == 201
                        and audit["level"] == "Metadata" and not audit["responseObjectPresent"], audit)
                require(created["metadata"]["name"] == binding["metadata"]["name"], "wrong metadata-only binding")
                self.unchanged(findings_before)
                fixture["metadataOnlyBinding"] = {"audit": audit, "uid": created["metadata"]["uid"],
                                                  "findingsUnchanged": True}
            finally:
                self.kube("delete", "-f", "-", "--ignore-not-found", native=True,
                          stdin=json.dumps({"apiVersion": "v1", "kind": "List", "items": [binding, role]}))
            self.stop()
            current = verified()
            require(current.pop(AUDIT_POLICY_HASH_FIELD, None) == original_hash, "audit policy hash changed before legacy transition")
            self.write_native_private("owner.json", (json.dumps(current) + "\n").encode())
            require(self.read_native_private("audit-policy.yaml") == metadata_policy, "metadata-only policy was not retained")
            fixture["removedHashField"] = AUDIT_POLICY_HASH_FIELD
            fixture["metadataServerStartedAt"] = metadata_started
            self.save()
            self.start()
            cluster = self.wait("EKS reattached after retained audit policy upgrade", self.active, 300)
            # ACTIVE is retained API state; reconciliation and proxy attachment are asynchronous.
            self.wait("authenticated proxy after policy upgrade", lambda: self.native_ready(native=False), 300)
            require(cluster["arn"] == self.cluster["arn"] and cluster["endpoint"] == self.cluster["endpoint"], cluster)
            current = verified()
            require(current.get(AUDIT_POLICY_HASH_FIELD) == original_hash, "Ensure did not persist the loaded audit policy hash")
            require(self.read_native_private("audit-policy.yaml") == original_policy, "Ensure did not replace metadata-only audit policy")
            upgraded_started = json.loads(self.command(["docker", "inspect", server]))[0]["State"]["StartedAt"]
            require(upgraded_started != metadata_started, "Ensure did not restart the retained control plane")
            self.wait("native API ready after retained audit policy upgrade", self.native_ready, 180)
            pods_after = {namespace: json.loads(self.kube(
                "get", "pod", self.prefix, "-n", namespace, "-o", "json", native=True))["metadata"]["uid"]
                          for namespace in pods_before}
            require(pods_before == pods_after, {"before": pods_before, "after": pods_after})
            fixture.update(policyHashAfter=current[AUDIT_POLICY_HASH_FIELD], upgradedServerStartedAt=upgraded_started,
                           podUIDsAfter=pods_after, clusterARN=cluster["arn"], clusterEndpoint=cluster["endpoint"])
            self.unchanged(findings_before, 10)
            yield fixture
        finally:
            try:
                current = verified()
                if (not fixture["requestResponseProven"]
                        or self.read_native_private("audit-policy.yaml") != original_policy
                        or current.get(AUDIT_POLICY_HASH_FIELD) != original_hash):
                    # Restore only the policy and its stamp, never stale owner state or unrelated configuration.
                    self.stop()
                    verified()
                    self.write_native_private("audit-policy.yaml", original_policy)
                    self.command(["docker", "restart", "--time", "30", server])
                    self.wait("native API ready after audit policy fixture restoration", self.native_ready, 180)
                    current = verified()
                    current[AUDIT_POLICY_HASH_FIELD] = original_hash
                    self.write_native_private("owner.json", (json.dumps(current) + "\n").encode())
                    self.start()
                    self.wait("EKS reattached after audit policy fixture restoration", self.active, 300)
                    self.wait("authenticated proxy after fixture restoration", lambda: self.native_ready(native=False), 300)
                    fixture["fallbackRestoration"] = True
                fixture["restored"] = True
            finally:
                self.save()

    @contextmanager
    def anonymous_native_fixture(self):
        # Only this exact-owned fixture opts into anonymous authentication.
        # The additive drop-in preserves the runtime's existing audit arguments.
        server = self.owned_native_server()
        filename = "99-guardduty-anonymous-" + uuid.uuid4().hex + ".yaml"
        destination = "/etc/rancher/k3s/config.yaml.d/" + filename
        configuration = "kube-apiserver-arg+:\n- anonymous-auth=true\n"
        local = self.root / filename
        local.write_text(configuration)
        local.chmod(0o600)
        fixture = {"nativeClusterID": self.native_id, "containerID": server,
                   "dropIn": destination, "configuration": configuration,
                   "scope": "Owned native loopback API only; production defaults and IAM proxy unchanged",
                   "installed": False, "restored": False}
        self.evidence["observations"]["anonymousNativeFixture"] = fixture
        self.save()

        def verified():
            actual = self.owned_native_server()
            require(actual == server, "owned fixture control-plane identity changed")
            return actual

        self.command(["docker", "exec", verified(), "test", "!", "-e", destination])
        self.command(["docker", "exec", verified(), "test", "!", "-L", destination])
        try:
            self.command(["docker", "exec", verified(), "mkdir", "-p", "/etc/rancher/k3s/config.yaml.d"])
            self.command(["docker", "cp", str(local), verified() + ":" + destination])
            fixture["installed"] = True
            self.save()
            self.command(["docker", "restart", "--time", "30", verified()])
            self.wait("native API ready with scoped anonymous fixture", self.native_ready, 180)
            yield
        finally:
            try:
                self.command(["docker", "exec", verified(), "rm", "-f", destination])
                self.command(["docker", "restart", "--time", "30", verified()])
                self.wait("native API ready after anonymous fixture restoration", self.native_ready, 180)
                self.command(["docker", "exec", verified(), "test", "!", "-e", destination])
                fixture["restored"] = True
            finally:
                local.unlink(missing_ok=True)
                self.save()

    def anonymous(self):
        configuration = json.loads(self.kube("config", "view", "--raw", "--minify", "-o", "json", native=True))
        cluster = configuration["clusters"][0]["cluster"]
        endpoint = cluster["server"]
        parsed = urllib.parse.urlsplit(endpoint)
        require(parsed.scheme == "https" and ipaddress.ip_address(parsed.hostname).is_loopback,
                "Anonymous proof requires the exact-owned loopback native API endpoint")
        context = ssl.create_default_context(cadata=base64.b64decode(cluster["certificate-authority-data"]).decode())
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        with self.anonymous_native_fixture():
            evidence = self.anonymous_requests(opener, endpoint)
        request = urllib.request.Request(endpoint + f"/api/v1/namespaces/{self.prefix}/secrets/dummy-secret")
        try:
            with opener.open(request, timeout=30) as response:
                raise AssertionError(f"native anonymous authentication survived fixture restoration: {response.status}")
        except urllib.error.HTTPError as error:
            require(error.code == 401, str(error))
        self.evidence["observations"]["anonymousNativeFixture"]["restoredAnonymousStatus"] = 401
        self.save()
        return evidence

    def anonymous_delete_options(self, opener, endpoint, dry_run, query_dry_run=False):
        path = f"/api/v1/namespaces/{self.prefix}/configmaps/deletion-precedence-proof"
        if query_dry_run:
            path += "?dryRun=All"
        options = {"apiVersion": "v1", "kind": "DeleteOptions"}
        if dry_run:
            options["dryRun"] = ["All"]
        request = urllib.request.Request(endpoint + path, method="DELETE", data=json.dumps(options).encode(),
                                         headers={"Content-Type": "application/json",
                                                  "User-Agent": "stackd-guardduty-anonymous-delete-options-smoke"})
        with opener.open(request, timeout=30) as response:
            require(response.status == 200, response.status)
            json.load(response)
        audit = self.completed_audit(path, "system:anonymous")
        require(audit["user"]["username"] == "system:anonymous" and "impersonatedUser" not in audit, audit)
        require(audit["verb"] == "delete" and audit["responseStatus"]["code"] == 200
                and audit["level"] == "Request" and not audit["responseObjectPresent"], audit)
        native_options = audit.get("requestObject", {})
        require(native_options.get("kind") == "DeleteOptions", audit)
        require(native_options.get("dryRun", []) == options.get("dryRun", []),
                {"submittedOptions": options, "nativeAudit": audit})
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(audit["requestURI"]).query)
        require(query.get("dryRun", []) == (["All"] if query_dry_run else []), audit)
        return audit

    def durable_delete_options(self, audit, dry_run):
        with sqlite3.connect((self.root / "state.db").as_uri() + "?mode=ro", uri=True) as database:
            rows = database.execute(
                "SELECT sequence,delete_options_observed,dry_run FROM kubernetes_audit_events "
                "WHERE partition=? AND account_id=? AND region=? AND cluster_id=? "
                "AND audit_id=? AND stage=? AND request_uri=?",
                ("aws", self.account, REGION, self.native_id, audit["auditID"], audit["stage"], audit["requestURI"])).fetchall()
        require(len(rows) == 1, {"auditID": audit["auditID"], "durableRows": rows})
        sequence, observed, effective_dry_run = rows[0]
        require(observed == 1 and effective_dry_run == int(dry_run),
                {"audit": audit, "deleteOptionsObserved": observed, "dryRun": effective_dry_run})
        return {"sequence": sequence, "deleteOptionsObserved": bool(observed), "dryRun": bool(effective_dry_run)}

    def anonymous_requests(self, opener, endpoint):
        self.kube("create", "secret", "generic", "dummy-secret", "-n", self.prefix, "--from-literal=proof=non-sensitive-smoke-value", native=True)
        for name in ("deletion-proof", "deletion-precedence-proof"):
            self.kube("create", "configmap", name, "-n", self.prefix, "--from-literal=proof=owned", native=True)
        role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "anonymous-proof", "namespace": self.prefix},
                "rules": [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["dummy-secret"], "verbs": ["get"]},
                          {"apiGroups": [""], "resources": ["pods"], "verbs": ["list"]},
                          {"apiGroups": [""], "resources": ["configmaps"],
                           "resourceNames": ["deletion-proof", "deletion-precedence-proof"], "verbs": ["delete"]}]}
        ordinary_subject = {"kind": "User", "apiGroup": RBAC_GROUP, "name": self.prefix + "-ordinary-user"}
        binding = {"apiVersion": RBAC_GROUP + "/v1", "kind": "RoleBinding", "metadata": {"name": "anonymous-proof", "namespace": self.prefix},
                   "roleRef": {"apiGroup": RBAC_GROUP, "kind": "Role", "name": role["metadata"]["name"]},
                   "subjects": [ordinary_subject, {"kind": "User", "apiGroup": RBAC_GROUP, "name": "system:anonymous"}]}
        cluster_role = {"apiVersion": RBAC_GROUP + "/v1", "kind": "ClusterRole",
                        "metadata": {"name": self.prefix + "-namespace-reader"},
                        "rules": [{"apiGroups": [""], "resources": ["namespaces"], "resourceNames": [self.prefix], "verbs": ["get"]}]}
        cluster_binding = {"apiVersion": RBAC_GROUP + "/v1", "kind": "ClusterRoleBinding",
                           "metadata": {"name": self.prefix + "-unauthenticated"},
                           "roleRef": {"apiGroup": RBAC_GROUP, "kind": "ClusterRole", "name": cluster_role["metadata"]["name"]},
                           "subjects": [{"kind": "Group", "apiGroup": RBAC_GROUP, "name": "system:unauthenticated"}, ordinary_subject]}
        ordinary_binding = {**binding, "metadata": {"name": "ordinary-proof", "namespace": self.prefix},
                            "subjects": [ordinary_subject]}
        denied_binding = {**binding, "metadata": {"name": "denied-proof", "namespace": self.prefix}}
        dry_run_binding = {**binding, "metadata": {"name": "dry-run-proof", "namespace": self.prefix}}
        generated_binding = {**binding, "metadata": {"generateName": self.prefix + "-generated-", "namespace": self.prefix}}
        generated_cleanup = []
        evidence = {"grants": {}}
        try:
            self.kube("create", "-f", "-", native=True,
                      stdin=json.dumps({"apiVersion": "v1", "kind": "List", "items": [role, cluster_role]}))
            before = self.snapshot()
            ordinary_audit = self.create_binding(ordinary_binding, "ordinary-binding")
            self.unchanged(before)
            evidence["ordinarySubjectNegative"] = {"audit": ordinary_audit, "findingsUnchanged": True}
            denied_audit = self.denied_binding(denied_binding)
            self.unchanged(before)
            evidence["deniedCreateNegative"] = {"audit": denied_audit, "bindingAbsent": True, "findingsUnchanged": True}
            dry_run_audit = self.create_binding(dry_run_binding, "dry-run-binding", dry_run=True)
            absent = self.kube("get", "rolebinding", dry_run_binding["metadata"]["name"], "-n", self.prefix,
                               "--ignore-not-found", "-o", "json", native=True)
            require(not absent.strip(), "server dry-run binding was persisted")
            self.unchanged(before)
            evidence["serverDryRunNegative"] = {"audit": dry_run_audit, "bindingAbsent": True, "findingsUnchanged": True}
            for resource, grant, granted_role in (("RoleBinding", binding, role), ("ClusterRoleBinding", cluster_binding, cluster_role),
                                                  ("GeneratedRoleBinding", generated_binding, role)):
                grant_audit = self.create_binding(grant, resource.lower(),
                                                  cleanup_bindings=generated_cleanup if resource == "GeneratedRoleBinding" else None)
                grant_finding = self.wait(GRANT_TYPE + " " + resource, lambda: self.finding_for(GRANT_TYPE, grant_audit))
                require(grant_finding["Service"]["Count"] == 1, grant_finding)
                evidence["grants"][resource] = {"audit": grant_audit, "finding": grant_finding,
                                                "binding": grant, "role": granted_role}
            configmap = json.loads(self.kube("get", "configmap", "deletion-precedence-proof", "-n", self.prefix,
                                            "-o", "json", native=True))
            body_dry_run = self.anonymous_delete_options(opener, endpoint, dry_run=True)
            survived = json.loads(self.kube("get", "configmap", "deletion-precedence-proof", "-n", self.prefix,
                                           "-o", "json", native=True))
            require(survived["metadata"]["uid"] == configmap["metadata"]["uid"]
                    and not survived["metadata"].get("deletionTimestamp"), "body dry-run deleted the owned configmap")
            impact_type = "Impact:Kubernetes/SuccessfulAnonymousAccess"
            dry_run_finding = self.wait("successful anonymous dry-run API access",
                                        lambda: self.finding_for(impact_type, body_dry_run))
            additional = json.loads(dry_run_finding["Service"]["AdditionalInfo"]["Value"])
            require(additional["deleteOptions"] == {"observed": True, "dryRun": True}, additional)
            evidence["deleteOptions"] = {
                "bodyDryRunAccess": {"audit": body_dry_run, "finding": dry_run_finding,
                                    "configMapUID": survived["metadata"]["uid"],
                                    "durableOptions": self.durable_delete_options(body_dry_run, True),
                                    "objectSurvived": True,
                                    "boundary": "Successful API access, not deletion proof; AWS dry-run eligibility is uncalibrated"}}
            precedence_audit = self.anonymous_delete_options(opener, endpoint, dry_run=False, query_dry_run=True)
            absent = self.kube("get", "configmap", "deletion-precedence-proof", "-n", self.prefix,
                               "--ignore-not-found", "-o", "json", native=True)
            require(not absent.strip(), "DeleteOptions body did not override dryRun query")
            precedence_finding = self.wait("body-over-query native deletion finding",
                                           lambda: self.finding_for(impact_type, precedence_audit))
            require(precedence_finding["Id"] == dry_run_finding["Id"]
                    and precedence_finding["Service"]["Count"] == dry_run_finding["Service"]["Count"] + 1,
                    "repeated successful API access did not advance the existing finding")
            evidence["deleteOptions"]["bodyOverridesQuery"] = {
                "audit": precedence_audit, "finding": precedence_finding, "objectAbsent": True,
                "durableOptions": self.durable_delete_options(precedence_audit, False)}
            for category, method, suffix in (("CredentialAccess", "GET", "secrets/dummy-secret"),
                                             ("Discovery", "GET", "pods"), ("Impact", "DELETE", "configmaps/deletion-proof")):
                path = f"/api/v1/namespaces/{self.prefix}/{suffix}"
                request = urllib.request.Request(endpoint + path, method=method, headers={"User-Agent": "stackd-guardduty-anonymous-smoke"})
                with opener.open(request, timeout=30) as response:
                    require(response.status == 200, response.status)
                    body = json.load(response)
                if category == "CredentialAccess":
                    require(body["metadata"]["name"] == "dummy-secret", "wrong secret")
                elif category == "Discovery":
                    require(any(row["metadata"]["name"] == self.prefix for row in body["items"]), "owned pod missing")
                audit = self.completed_audit(path, "system:anonymous")
                require(audit["user"]["username"] == "system:anonymous" and "impersonatedUser" not in audit, audit)
                kind = category + ":Kubernetes/SuccessfulAnonymousAccess"
                finding = self.wait(kind, lambda: self.finding_for(kind, audit))
                evidence[category] = {"audit": audit, "finding": finding}
        finally:
            # Revoke all anonymous grants before removing their exact-owned roles.
            self.kube("delete", "-f", "-", "--ignore-not-found", native=True,
                      stdin=json.dumps({"apiVersion": "v1", "kind": "List",
                                        "items": [cluster_binding, binding, ordinary_binding, denied_binding, dry_run_binding, *generated_cleanup]}))
            self.kube("delete", "-f", "-", "--ignore-not-found", native=True,
                      stdin=json.dumps({"apiVersion": "v1", "kind": "List", "items": [cluster_role, role]}))
        absent = self.kube("get", "clusterrolebinding", cluster_binding["metadata"]["name"],
                           "--ignore-not-found", "-o", "json", native=True)
        require(not absent.strip(), "unauthenticated cluster grant survived revocation")
        evidence["clusterGrantRevoked"] = True
        request = urllib.request.Request(endpoint + f"/api/v1/namespaces/{self.prefix}/secrets/dummy-secret")
        try:
            with opener.open(request, timeout=30) as response:
                raise AssertionError(f"anonymous grant survived revocation: {response.status}")
        except urllib.error.HTTPError as error:
            require(error.code == 403, str(error))
        evidence["scopedGrantRevoked"] = True
        return evidence

    def verify_go_sdk(self, live_audit, live_finding):
        rows = [{"audit": live_audit, "finding": live_finding}]
        rows.extend(self.evidence["observations"]["anonymous"][category]
                    for category in ("CredentialAccess", "Discovery", "Impact"))
        rows.append(self.evidence["observations"]["anonymous"]["deleteOptions"]["bodyOverridesQuery"])
        rows.extend(self.evidence["observations"]["restart"]["anonymousGrants"].values())
        expected = []
        for row in rows:
            audit, finding = row["audit"], row["finding"]
            effective = audit.get("impersonatedUser", audit["user"])
            obj = self.finding_object(finding["Type"], audit)
            expected.append({
                "ID": finding["Id"], "Type": finding["Type"], "Count": finding["Service"]["Count"],
                "Username": effective["username"], "Groups": effective.get("groups", []),
                "URI": audit["requestURI"], "Verb": audit["verb"], "Status": audit["responseStatus"]["code"],
                "Namespace": obj.get("namespace", ""), "Resource": obj.get("resource", ""),
                "Name": obj.get("name", ""), "Subresource": obj.get("subresource", ""),
                "SourceIPs": audit["sourceIPs"], "UserAgent": audit["userAgent"],
            })
            if finding["Type"] == GRANT_TYPE:
                expected[-1]["RoleRef"] = audit["responseObject"]["roleRef"]
                expected[-1]["Subjects"] = self.binding_subjects(audit["responseObject"]["subjects"])
            if audit["verb"] in ("delete", "deletecollection") and audit["level"] in ("Request", "RequestResponse"):
                options = audit.get("requestObject")
                dry_run = options.get("dryRun", []) if options is not None else urllib.parse.parse_qs(
                    urllib.parse.urlsplit(audit["requestURI"]).query).get("dryRun", [])
                expected[-1]["DeleteOptions"] = {"observed": True, "dryRun": bool(dry_run)}
        root = Path(__file__).resolve().parents[2]
        stdout = self.command([
            "go", "run", "./scripts/guardduty_eks_smoke/sdk",
            "-endpoint", self.endpoint, "-account", self.account, "-region", REGION,
            "-detector", self.detector, "-cluster-arn", self.cluster["arn"], "-cluster-name", self.prefix,
        ], stdin=json.dumps(expected), timeout=300, cwd=root)
        result = json.loads(stdout)
        require(result.get("passed") is True and result.get("signed") is True, result)
        return {"stdout": stdout, "result": result}

    def run(self):
        self.setup()
        observed = self.evidence["observations"]
        before = self.snapshot()
        negative = self.exec_pod(self.prefix, self.prefix + "-negative")
        self.unchanged(before)
        observed["nonSystemExecNegative"] = negative
        audit = self.exec_pod("kube-system", self.prefix + "-positive")
        finding = self.wait(EXEC_TYPE, lambda: self.finding_for(EXEC_TYPE, audit))
        require(finding["Service"]["Count"] == 1, finding)
        observed["systemExec"] = {"audit": audit, "finding": finding}
        self.save()
        for gate in ("feature", "detector"):
            before = self.snapshot()
            request = {"Features": [{"Name": "EKS_AUDIT_LOGS", "Status": "DISABLED"}]} if gate == "feature" else {"Enable": False}
            self.call("guardduty", "update_detector", DetectorId=self.detector, **request)
            ignored = self.exec_pod("kube-system", self.prefix + "-disabled-" + gate)
            self.unchanged(before)
            request = {"Features": [{"Name": "EKS_AUDIT_LOGS", "Status": "ENABLED"}]} if gate == "feature" else {"Enable": True}
            self.call("guardduty", "update_detector", DetectorId=self.detector, **request)
            self.unchanged(before)
            resumed = self.exec_pod("kube-system", self.prefix + "-resumed-" + gate)
            next_finding = self.wait("new event after " + gate, lambda: self.finding_for(EXEC_TYPE, resumed))
            require(next_finding["Id"] == finding["Id"] and next_finding["Service"]["Count"] == finding["Service"]["Count"] + 1,
                    {"before": finding, "after": next_finding})
            observed[gate + "Gate"] = {"ignoredAudit": ignored, "resumedAudit": resumed, "finding": next_finding, "noReplay": True}
            finding = next_finding
            self.save()
        observed["anonymous"] = self.anonymous()
        self.save()
        before = self.snapshot()
        with self.retained_policy_upgrade(before) as upgrade:
            observed["restart"] = {"findingsBefore": before, "findingsAfter": self.snapshot(),
                                   "podUID": upgrade["podUIDsAfter"]["kube-system"]}
            durable_after = {}
            for scenario, boundary in observed["anonymous"]["deleteOptions"].items():
                durable = self.durable_delete_options(boundary["audit"], boundary["durableOptions"]["dryRun"])
                require(durable == boundary["durableOptions"], "effective DeleteOptions changed across controller restart")
                durable_after[scenario] = durable
            observed["restart"]["durableDeleteOptions"] = durable_after
            restored_grants = {}
            for resource, grant in observed["anonymous"]["grants"].items():
                restored = self.finding_for(GRANT_TYPE, grant["audit"])
                require(restored is not None and restored["Id"] == grant["finding"]["Id"]
                        and restored["Service"]["Count"] == grant["finding"]["Service"]["Count"], restored)
                restored_grants[resource] = {"audit": grant["audit"], "finding": restored}
            observed["restart"]["anonymousGrants"] = restored_grants
            audit = self.exec_pod("kube-system", self.prefix + "-after-restart")
            after = self.wait("live finding after restart", lambda: self.finding_for(EXEC_TYPE, audit))
            require(after["Id"] == finding["Id"] and after["Service"]["Count"] == finding["Service"]["Count"] + 1, after)
            observed["restart"]["liveAudit"] = audit
            observed["restart"]["liveFinding"] = after
            grant = observed["anonymous"]["grants"]["RoleBinding"]
            try:
                self.kube("create", "-f", "-", native=True, stdin=json.dumps(grant["role"]))
                grant_audit = self.create_binding(grant["binding"], "binding-after-restart")
                live_grant = self.wait("live anonymous grant after restart", lambda: self.finding_for(GRANT_TYPE, grant_audit))
                require(live_grant["Id"] == grant["finding"]["Id"]
                        and live_grant["Service"]["Count"] == grant["finding"]["Service"]["Count"] + 1, live_grant)
                observed["restart"]["liveBinding"] = {"audit": grant_audit, "finding": live_grant}
                restored_grants["RoleBinding"] = observed["restart"]["liveBinding"]
                upgrade["requestResponseProven"] = True
                upgrade["requestResponseAudit"] = grant_audit
                upgrade["findingID"] = live_grant["Id"]
                upgrade["findingCountBefore"] = grant["finding"]["Service"]["Count"]
                upgrade["findingCountAfter"] = live_grant["Service"]["Count"]
            finally:
                self.kube("delete", "-f", "-", "--ignore-not-found", native=True, stdin=json.dumps(grant["binding"]))
                self.kube("delete", "-f", "-", "--ignore-not-found", native=True, stdin=json.dumps(grant["role"]))
        observed["goSDK"] = self.verify_go_sdk(audit, after)
        observed["cloudWatchAfter"] = self.no_cloudwatch()
        self.evidence["passed"] = True
        self.save()

    def cleanup(self):
        errors = []
        def perform(label, fn):
            try:
                fn()
                self.evidence["cleanup"].append({"action": label, "ok": True})
                return True
            except Exception as error:
                errors.append(label + ": " + str(error))
                self.evidence["cleanup"].append({"action": label, "error": str(error)})
                return False
            finally:
                self.save()
        if self.owned.get("cluster"):
            def remove_cluster():
                if self.process is None or self.process.poll() is not None:
                    self.start()
                self.call("eks", "delete_cluster", name=self.prefix)
                def absent():
                    try:
                        self.call("eks", "describe_cluster", name=self.prefix)
                        return False
                    except ClientError as error:
                        if error.response["Error"]["Code"] == "ResourceNotFoundException":
                            return True
                        raise
                self.wait("owned EKS deletion", absent, 300)
            perform("delete owned EKS cluster", remove_cluster)
        if self.detector:
            perform("delete detector", lambda: self.call("guardduty", "delete_detector", DetectorId=self.detector))
        if self.owned.get("rolePolicy"):
            perform("delete role policy", lambda: self.call("iam", "delete_role_policy", RoleName=self.prefix, PolicyName="networks"))
        if self.owned.get("role"):
            perform("delete role", lambda: self.call("iam", "delete_role", RoleName=self.prefix))
        for subnet in self.owned["subnets"]:
            perform("delete subnet " + subnet, lambda subnet=subnet: self.call("ec2", "delete_subnet", SubnetId=subnet))
        if self.owned.get("vpc"):
            perform("delete VPC", lambda: self.call("ec2", "delete_vpc", VpcId=self.owned["vpc"]))
        perform("stop controller", self.stop)
        if self.native_id:
            def native_absent():
                for resource in ("container", "network", "volume"):
                    flags = ["-a"] if resource == "container" else []
                    remaining = self.command(["docker", resource, "ls", *flags, "-q", "--filter", f"label=stackd.eks.id={self.native_id}"])
                    require(not remaining.strip(), {"resource": resource, "remaining": remaining})
            if not perform("verify exact-owned native resources absent", native_absent):
                def fallback():
                    owner = json.loads((self.native_dir / "owner.json").read_text())
                    require(owner["ID"] == self.native_id and owner["DockerHost"] == self.args.docker_host,
                            "refusing cleanup with mismatched native ownership")
                    self.command([str(self.args.k3d), "cluster", "delete", owner["Name"]], timeout=180)
                perform("fallback delete exact-owned k3d cluster", fallback)
                perform("verify fallback native cleanup", native_absent)
        self.log.close()
        if errors:
            self.evidence["passed"] = False
            self.evidence["cleanupErrors"] = errors
        if self.evidence.get("passed"):
            shutil.rmtree(self.root)
            self.evidence["diagnosticDirectoryRemoved"] = True
        self.save()
        return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--k3d", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    parser.add_argument("--image", default="busybox:1.37.0")
    args = parser.parse_args()
    args.binary = args.binary.resolve(strict=True)
    args.k3d = args.k3d.resolve(strict=True)
    for program in ("aws", "kubectl", "docker", "go"):
        if not shutil.which(program):
            parser.error("required executable missing: " + program)
    smoke = Smoke(args)
    try:
        smoke.run()
    except BaseException as error:
        smoke.evidence["passed"] = False
        smoke.evidence["failure"] = str(error)
        smoke.save()
        raise
    finally:
        errors = smoke.cleanup()
    if errors:
        raise RuntimeError("Cleanup failed: " + "; ".join(errors))
    print(json.dumps({"passed": True, "evidence": str(args.evidence), "cluster": smoke.prefix}))


if __name__ == "__main__":
    main()
