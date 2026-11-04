#!/usr/bin/env python3
"""Fresh native AWS Load Balancer Controller v2.14.1 packet-path proof.

Requires Linux Docker/network privileges, prebuilt stackd and ALB relay binaries,
installed k3d v5.8.3, kubectl, Helm, AWS CLI, OpenSSL, dig and Python boto3.
The native k3s/tools/network images and both workload images must already exist
on the selected daemon. No retained controller, cluster or cloud resource is used.
The pinned upstream chart and IAM document are fetched over verified HTTPS unless
explicit local copies are supplied. All raw diagnostics, state and generated TLS
material stay in the new mode-0700 state directory. Only generic assertions and
versions go to stdout/--output; never publish the private state directory.

Example (binaries must be built by the integration owner):
  python3 scripts/eks_lbc_smoke.py --binary ./stackd \
    --elbv2-node-executable ./stackd-elbv2-node --k3d /usr/local/bin/k3d \
    --state-directory /tmp/new-owned-ingress --output /tmp/ingress-result.json

A failed target health or HTTP assertion fails the fixture, even if Helm succeeds.
Cleanup runs on failure, reports its own failures, and never replaces the original
private diagnostic. This fixture deliberately does not claim private ECR pulls,
SQL/TLS consumer evidence, external managed nodes, or host route-table mutation.

Native prerequisite witnesses and closed-vocabulary failure classifications are
public-safe; raw EKS health messages and owned-node logs remain private. Failure
capture never adopts resources or relaxes native ownership/packet-path checks.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tarfile
import time
import traceback
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, ConnectionClosedError, EndpointConnectionError

from dns_http_client import opener, query


CHART_URL = "https://aws.github.io/eks-charts/aws-load-balancer-controller-1.14.1.tgz"
POLICY_URL = "https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.14.1/docs/install/iam_policy.json"
CONTROLLER_IMAGE = "public.ecr.aws/eks/aws-load-balancer-controller:v2.14.1"
BACKEND_IMAGE = "public.ecr.aws/docker/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
K3S_IMAGE = "rancher/k3s:v1.33.5-k3s1@sha256:fd4740667b7033055c27d424d0d2d660bf66cedbdb225d68e0eab6dd48aa0fd2"
TOOLS_IMAGE = "ghcr.io/k3d-io/k3d-tools@sha256:c5ceb2b9e8ff2cf55917b0bee8bc9c54fe1483a16366b734117e2cfac1417bed"
TOOLS_TAG = "ghcr.io/k3d-io/k3d-tools:5.8.3"
NETWORK_IMAGE = "nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61"
BODY = b"native-ingress-backend\n"


class FixtureFailure(RuntimeError):
    pass


class Smoke:
    def __init__(self, args):
        self.args = args
        self.state = args.state_directory.resolve()
        self.state.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.prefix = "lbc-proof-" + uuid.uuid4().hex[:10]
        self.account = f"{uuid.uuid4().int % 10**12:012d}"
        self.region = args.region
        self.namespace = self.prefix
        self.process = None
        self.log = (self.state / "controller.log").open("ab")
        self.diagnostics = (self.state / "diagnostics.log").open("a")
        self.phase = "prerequisites"
        self.clients = {}
        self.owned = {"vpcs": [], "subnets": [], "groups": [], "roles": [],
                      "lbs": [], "tgs": [], "native": [], "image_tags": []}
        self.result = {"controller_version": "v2.14.1", "chart_version": "1.14.1", "assertions": {}, "passed": False}
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith("AWS_") and k not in ("KUBECONFIG", "DOCKER_HOST")}
        self.env.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test",
                        AWS_DEFAULT_REGION=self.region, AWS_REGION=self.region,
                        AWS_EC2_METADATA_DISABLED="true", AWS_PAGER="",
                        AWS_CONFIG_FILE=str(self.state / "aws-config"),
                        AWS_SHARED_CREDENTIALS_FILE=str(self.state / "aws-credentials"),
                        KUBECONFIG=str(self.state / "kubeconfig"),
                        DOCKER_HOST=args.docker_host, NO_PROXY="*", no_proxy="*")
        self.endpoint = None
        self.dns = None
        self.ca = self.state / "ca.pem"
        self.key = self.state / "server.key"
        self.cert = self.state / "server.pem"
        self.started = False
        self.cluster_created = False
        self.namespace_created = False
        self.helm_attempted = False
        self.lb = self.tg = self.pod = self.native = None

    def private(self, name, value):
        path = self.state / name
        path.write_text(value)
        path.chmod(0o600)
        return path

    def command(self, argv, *, stdin=None, env=None, timeout=180, combined=False):
        try:
            result = subprocess.run([str(v) for v in argv], input=stdin, env=env or self.env,
                                    text=True, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            def captured(value):
                return value.decode(errors="replace") if isinstance(value, bytes) else value
            self.diagnostics.write(json.dumps({"command": [str(v) for v in argv], "timeout": timeout,
                "stdout": captured(error.stdout), "stderr": captured(error.stderr)}) + "\n")
            self.diagnostics.flush()
            raise
        # Commands may contain tokens; the entire record is private, never evidence.
        self.diagnostics.write(json.dumps({"command": [str(v) for v in argv],
                                          "status": result.returncode,
                                          "stdout": result.stdout, "stderr": result.stderr}) + "\n")
        self.diagnostics.flush()
        if result.returncode:
            raise FixtureFailure("command failed in " + self.phase)
        return result.stdout + result.stderr if combined else result.stdout

    def client(self, service):
        if service not in self.clients:
            self.clients[service] = boto3.client(service, endpoint_url=self.endpoint,
                region_name=self.region, aws_access_key_id="test", aws_secret_access_key="test",
                verify=str(self.ca), config=Config(retries={"max_attempts": 0},
                                                   connect_timeout=5, read_timeout=60, proxies={}))
        return self.clients[service]

    def api(self, service, operation, **kwargs):
        try:
            return getattr(self.client(service), operation)(**kwargs)
        except Exception:
            self.diagnostics.write("API failure: " + service + "." + operation + "\n" + traceback.format_exc())
            self.diagnostics.flush()
            raise

    def wait(self, label, fn, accept=bool, seconds=240):
        deadline = time.monotonic() + seconds
        while True:
            value = fn()
            if accept(value):
                return value
            if time.monotonic() >= deadline:
                self.diagnostics.write(label + " last observation: " + repr(value) + "\n")
                self.diagnostics.flush()
                raise FixtureFailure(label + " deadline exceeded")
            time.sleep(2)

    def assertion(self, name, condition=True):
        if not condition:
            raise FixtureFailure(name)
        self.result["assertions"][name] = True

    def kube(self, *args, stdin=None, timeout=180):
        # Endpoint override belongs to ordinary AWS clients, not the STS token
        # presign inside the kubeconfig exec plugin. This never disables TLS.
        env = dict(self.env, AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
        return self.command(["kubectl", "--request-timeout=60s", *args],
                            stdin=stdin, env=env, timeout=timeout)

    def kube_json(self, *args):
        return json.loads(self.kube(*args, "-o", "json"))

    def apply(self, *objects):
        self.kube("apply", "-f", "-", stdin=json.dumps({"apiVersion": "v1", "kind": "List", "items": objects}))

    @staticmethod
    def free_port():
        with socket.socket() as sock:
            sock.bind(("0.0.0.0", 0))
            return sock.getsockname()[1]

    def prepare(self):
        gateway = self.args.gateway_host
        if gateway is None:
            bridge = json.loads(self.command(["docker", "network", "inspect", "bridge"]))[0]
            gateway = bridge["IPAM"]["Config"][0]["Gateway"]
        ipaddress.IPv4Address(gateway)
        self.gateway = gateway
        port = self.args.port or self.free_port()
        dns_port = self.args.dns_port or self.free_port()
        while dns_port == port:
            dns_port = self.free_port()
        self.endpoint = f"https://{gateway}:{port}"
        self.dns = f"127.0.0.1:{dns_port}"
        self.port = port
        self.command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                      "-subj", "/CN=native-ingress-fixture", "-addext", "basicConstraints=critical,CA:TRUE",
                      "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                      "-keyout", self.state / "ca.key", "-out", self.ca])
        self.command(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                      "-subj", "/CN=native-ingress-fixture", "-keyout", self.key,
                      "-out", self.state / "server.csr"])
        extensions = self.private("server.ext", f"subjectAltName=IP:{gateway},IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=critical,CA:FALSE\n")
        self.command(["openssl", "x509", "-req", "-in", self.state / "server.csr", "-CA", self.ca,
                      "-CAkey", self.state / "ca.key", "-CAcreateserial", "-days", "2",
                      "-extfile", extensions, "-out", self.cert])
        self.env["AWS_CA_BUNDLE"] = str(self.ca)
        self.env["AWS_ENDPOINT_URL"] = self.endpoint
        self.chart = self.state / "controller-chart.tgz"
        if self.args.chart:
            self.chart.write_bytes(self.args.chart.read_bytes())
        else:
            self.fetch(CHART_URL, self.chart)
        with tarfile.open(self.chart) as archive:
            raw = archive.extractfile("aws-load-balancer-controller/Chart.yaml").read().decode()
        metadata = dict(line.split(":", 1) for line in raw.splitlines() if ":" in line and not line.startswith(" "))
        self.assertion("pinned_upstream_chart", metadata.get("version", "").strip(" \"'") == "1.14.1"
                       and metadata.get("appVersion", "").strip(" \"'") == "v2.14.1")
        policy_path = self.state / "upstream-policy.json"
        if self.args.iam_policy:
            policy_path.write_bytes(self.args.iam_policy.read_bytes())
        else:
            self.fetch(POLICY_URL, policy_path)
        self.policy = self.controller_policy(json.loads(policy_path.read_text()))
        self.controller_image = self.installed_image(self.args.controller_image, controller=True)
        self.backend_image = self.installed_image(self.args.backend_image)
        self.result["assertions"]["installed_immutable_images"] = True
        self.native_prerequisites()

    def native_prerequisites(self):
        witnesses = self.result.setdefault("native_prerequisites", {})
        version = self.command([self.args.k3d.resolve(), "version"])
        witnesses["k3d_version_matches"] = "k3d version v5.8.3\n" in version
        if not witnesses["k3d_version_matches"]:
            raise FixtureFailure("native runtime requires k3d v5.8.3")
        for name, image in (("k3s_image_installed", K3S_IMAGE), ("tools_image_installed", TOOLS_IMAGE),
                            ("network_image_installed", NETWORK_IMAGE)):
            witnesses[name] = False
            try:
                metadata = json.loads(self.command(["docker", "image", "inspect", image]))[0]
            except FixtureFailure:
                raise FixtureFailure("required native prerequisite missing: " + name) from None
            witnesses[name] = bool(metadata.get("Id"))
        witnesses["tools_tag_matches_pinned_image"] = False
        try:
            tools = json.loads(self.command(["docker", "image", "inspect", TOOLS_TAG, TOOLS_IMAGE]))
        except FixtureFailure:
            raise FixtureFailure("required native tools version tag is missing") from None
        witnesses["tools_tag_matches_pinned_image"] = len(tools) == 2 and tools[0]["Id"] == tools[1]["Id"]
        if not witnesses["tools_tag_matches_pinned_image"]:
            raise FixtureFailure("native tools version tag differs from pinned image")

    @staticmethod
    def classify_native_failure(message):
        # Match fixed public source/engine diagnostics; never serialize any part
        # of the original message (which can contain paths, tokens and IDs).
        text = message.lower()
        classes = {
            "native_container_ownership_rejected": ("refusing native cluster with unowned or unexpected containers",),
            "native_tools_ownership_rejected": ("refusing unowned k3d tools node",),
            "native_network_ownership_rejected": ("refusing unowned native network", "ambiguous owned network"),
            "native_volume_ownership_rejected": ("refusing unowned image volume",),
            "native_api_binding_mismatch": ("native api binding differs",),
            "native_worker_transport_drift": ("worker overlay endpoint differs from retained ownership",
                                               "native worker overlay configuration mount is absent"),
            "native_ecr_mount_ownership_rejected": ("retained worker ecr mount differs from its immutable read-only ownership",),
            "native_owned_state_unexpected_file": ("refusing to remove unexpected resource file",),
            "storage_probe_invalid": ("docker storage probe",),
            "storage_reserve_exceeds_capacity": ("capacity must exceed twice the native storage reserve",),
            "native_image_unavailable": ("no such image", "unable to find image", "pull access denied", "manifest unknown"),
            "docker_api_version_mismatch": ("client version", "minimum supported api version",),
            "native_permission_denied": ("permission denied", "operation not permitted"),
            "native_disk_full": ("no space left on device",),
            "native_netfilter_chain_unavailable": ("no chain/target/match", "chain does not exist"),
            "native_bootstrap_deadline": ("context deadline exceeded", "timed out", "timeout reached"),
            "native_cgroup_unavailable": ("failed to find memory cgroup", "failed to find cpu cgroup"),
            "native_runtime_unavailable": ("kubernetes runtime is unavailable",),
        }
        return sorted(name for name, patterns in classes.items() if any(pattern in text for pattern in patterns))

    def capture_cluster_failure(self, cluster, stage):
        report = self.result.setdefault("native_cluster_failures", {}).setdefault(stage, {})
        issues = cluster.get("health", {}).get("issues", [])
        message = "\n".join(str(issue.get("message", "")) for issue in issues)
        report["matched_error_classes"] = self.classify_native_failure(message) or ["unclassified_native_error"]
        report["health_reports_cluster_unreachable"] = any(issue.get("code") == "ClusterUnreachable" for issue in issues)
        try:
            self.private("failed-cluster-" + stage + ".json", json.dumps(cluster, default=str))
            receipts = list((self.state / "eks").glob("*/owner.json"))
            report["unique_native_receipt"] = len(receipts) == 1
            if len(receipts) != 1:
                return
            receipt = json.loads(receipts[0].read_text())
            token = receipt.get("Token", "")
            report["native_receipt_identity_valid"] = (receipt.get("Version") == 1 and len(token) == 64
                and all(value in "0123456789abcdef" for value in token)
                and receipt.get("Name") == "stackd-" + token[:24] and bool(receipt.get("ID")))
            if not report["native_receipt_identity_valid"]:
                return
            if not any(row["ID"] == receipt["ID"] for row in self.owned["native"]):
                self.owned["native"].append(receipt)
            report["storage_policy_persisted"] = bool(receipt.get("StoragePolicy"))
            identifiers = self.command(["docker", "container", "ls", "-aq", "--no-trunc",
                                       "--filter", "label=k3d.cluster=" + receipt["Name"]]).split()
            report["native_containers_present"] = bool(identifiers)
            if not identifiers:
                return
            nodes = json.loads(self.command(["docker", "inspect", *identifiers]))
            report["nodes"] = []
            for node in nodes:
                kind = next((kind for kind in ("server", "agent", "tools")
                    if node["Name"] == "/k3d-" + receipt["Name"] + ("-tools" if kind == "tools" else "-" + kind + "-0")), "unexpected")
                configuration = node.get("Config", {})
                labels = configuration.get("Labels") or {}
                expected = TOOLS_TAG if kind == "tools" else K3S_IMAGE
                configured_image = configuration.get("Image", "")
                state = node.get("State", {})
                report["nodes"].append({"kind": kind, "running": state.get("Running") is True,
                    "restarted": node.get("RestartCount", 0) > 0,
                    "configured_image_matches": configured_image == expected,
                    "configured_image_matches_after_normalization": configured_image.removeprefix("docker.io/") == expected,
                    "owner_labels_required": kind in ("server", "agent"),
                    "owner_labels_match": labels.get("stackd.eks.id") == receipt["ID"]
                        and labels.get("stackd.eks.owner") == token,
                    "attached_to_receipt_network": receipt["Name"] in node.get("NetworkSettings", {}).get("Networks", {})})
                witness = report["nodes"][-1]
                if kind == "server":
                    bindings = node.get("HostConfig", {}).get("PortBindings", {}).get("6443/tcp") or []
                    expected_host = receipt.get("WorkerAdvertiseHost") or "127.0.0.1"
                    witness["native_api_binding_matches"] = (len(bindings) == 1
                        and bindings[0].get("HostIp") == expected_host
                        and bindings[0].get("HostPort") == str(receipt.get("NativePort")))
                    witness["control_plane_agent_disabled"] = "--disable-agent" in (configuration.get("Cmd") or [])
                if kind == "tools":
                    witness["owned_image_volume_mounted"] = any(
                        mount.get("Name") == "k3d-" + receipt["Name"] + "-images"
                        and mount.get("Destination") == "/k3d/images" for mount in node.get("Mounts", []))
                if kind in ("server", "agent") and labels.get("stackd.eks.owner") == token and labels.get("stackd.eks.id") == receipt["ID"]:
                    expected_mounts = [("entrypoint", "/bin/k3d-entrypoint.sh", "control-plane-entrypoint.sh")]
                    if kind == "server":
                        expected_mounts.extend([("audit_policy", "/etc/stackd/audit-policy.yaml", "audit-policy.yaml"),
                            ("audit_webhook", "/etc/stackd/audit-webhook.kubeconfig", "audit-webhook.kubeconfig")])
                    elif receipt.get("WorkerAdvertiseHost"):
                        expected_mounts.append(("overlay_config", "/etc/rancher/k3s/stackd-flannel.json", "stackd-flannel.json"))
                    witness["mounts"] = []
                    for purpose, destination, filename in expected_mounts:
                        matching = [mount for mount in node.get("Mounts", []) if mount.get("Destination") == destination]
                        mount = matching[0] if len(matching) == 1 else {}
                        source = mount.get("Source", "")
                        expected_source = receipts[0].parent / filename
                        witness["mounts"].append({"purpose": purpose, "present_once": len(matching) == 1,
                            "bind": mount.get("Type") == "bind", "read_only": mount.get("RW") is False,
                            "lexical_source_matches": source == str(expected_source),
                            "canonical_source_matches": bool(source) and Path(source).resolve() == expected_source.resolve()})
                # Node logs are private. Only fixed-vocabulary classifications
                # are added to the public report, never excerpts or identifiers.
                if kind in ("server", "agent") and labels.get("stackd.eks.owner") == token:
                    output = self.command(["docker", "logs", "--tail", "80", node["Id"]], timeout=15, combined=True)
                    message += "\n" + output
            report["matched_error_classes"] = self.classify_native_failure(message) or ["unclassified_native_error"]
        except Exception:
            report["diagnostic_capture_incomplete"] = True
            self.diagnostics.write("Private native failure capture:\n" + traceback.format_exc())
            self.diagnostics.flush()

    @staticmethod
    def fetch(url, path):
        with urllib.request.urlopen(url, context=ssl.create_default_context(), timeout=45) as response:
            if response.geturl().split(":", 1)[0] != "https":
                raise FixtureFailure("upstream download redirected away from HTTPS")
            path.write_bytes(response.read())

    def installed_image(self, reference, controller=False):
        image = json.loads(self.command(["docker", "image", "inspect", reference]))[0]
        if "@sha256:" not in reference:
            repository = reference.rsplit(":", 1)[0]
            digests = [v for v in image.get("RepoDigests", []) if v.startswith(repository + "@sha256:")]
            if len(digests) != 1:
                raise FixtureFailure("an installed immutable image reference is required")
            reference += "@" + digests[0].split("@", 1)[1]
        digest = reference.rsplit("@sha256:", 1)[-1]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise FixtureFailure("invalid immutable image reference")
        if controller and not reference.startswith(CONTROLLER_IMAGE + "@sha256:"):
            raise FixtureFailure("controller image must be the pinned upstream v2.14.1")
        return reference

    def image_alias(self, reference, component, version):
        # Docker's archive format can discard a registry's multi-platform index
        # digest. Give this exact already-pinned local content a fixture-only tag
        # for import; Never prevents any registry fallback or tag refresh.
        alias = self.prefix + "/" + component + ":" + version
        self.command(["docker", "image", "tag", reference, alias])
        self.owned["image_tags"].append(alias)
        return alias

    def import_images(self):
        # The native server deliberately uses --disable-agent, so it has no
        # containerd socket. k3d's all-node importer waits there indefinitely.
        # Import the pinned archive only into the exact-owned workload agent.
        identifiers = self.command(["docker", "container", "ls", "-q", "--no-trunc",
            "--filter", "label=stackd.eks.id=" + self.native["ID"],
            "--filter", "label=stackd.eks.owner=" + self.native["Token"]]).split()
        expected = {"/k3d-" + self.native["Name"] + "-agent-0"}
        nodes = json.loads(self.command(["docker", "inspect", *identifiers]))
        nodes = [node for node in nodes if node["Name"] in expected]
        if len(nodes) != 1 or any(
            node["Config"]["Labels"].get("stackd.eks.id") != self.native["ID"] or
            node["Config"]["Labels"].get("stackd.eks.owner") != self.native["Token"] or
            node["Config"]["Labels"].get("k3d.cluster") != self.native["Name"] for node in nodes):
            raise FixtureFailure("refusing image import into a foreign native node")
        archive = self.state / "fixture-images.tar"
        destination = "/tmp/" + self.prefix + "-images.tar"
        try:
            self.command(["docker", "image", "save", "--output", archive,
                          self.controller_image, self.backend_image], timeout=120)
            for node in nodes:
                self.command(["docker", "cp", archive, node["Id"] + ":" + destination], timeout=120)
                try:
                    self.command(["docker", "exec", node["Id"], "ctr", "--namespace", "k8s.io",
                                  "images", "import", destination], timeout=120)
                finally:
                    self.command(["docker", "exec", node["Id"], "rm", "-f", destination])
        finally:
            archive.unlink(missing_ok=True)

    @staticmethod
    def controller_policy(upstream):
        # Preserve ordinary upstream resources/conditions. Remove only permissions
        # for explicitly disabled optional integrations and SG management; do not
        # replace upstream tag conditions with an administrator policy.
        statements = []
        for original in upstream["Statement"]:
            actions = original["Action"]
            if isinstance(actions, str):
                actions = [actions]
            actions = [action for action in actions if
                       action.startswith("elasticloadbalancing:") and action != "elasticloadbalancing:SetWebAcl"
                       or action.startswith("ec2:Describe")
                       or action in ("iam:CreateServiceLinkedRole", "ec2:GetCoipPoolUsage", "ec2:GetSecurityGroupsForVpc")]
            if actions:
                statement = dict(original, Action=actions)
                statements.append(statement)
        return {"Version": "2012-10-17", "Statement": statements}

    def start(self):
        argv = [self.args.binary.resolve(), "-listen", f"0.0.0.0:{self.port}", "-tls",
                "-tls-cert", self.cert, "-tls-key", self.key, "-account-id", self.account,
                "-database", self.state / "state.sqlite", "-docker-host", self.args.docker_host,
                "-public-endpoint", self.endpoint, "-compute-endpoint", self.endpoint,
                "-eks-state-directory", self.state / "eks", "-eks-k3d", self.args.k3d.resolve(),
                "-eks-storage-reserve-gib", str(self.args.storage_reserve_gib),
                "-eks-listen-host", "0.0.0.0", "-eks-endpoint-host", self.gateway,
                "-elbv2-node-executable", self.args.elbv2_node_executable.resolve(),
                "-dns-listen", self.dns]
        self.process = subprocess.Popen([str(v) for v in argv], env=self.env, stdout=self.log, stderr=self.log)
        self.started = True
        def ready():
            if self.process.poll() is not None:
                raise FixtureFailure("fresh controller exited; private controller.log contains the reason")
            try:
                return self.api("sts", "get_caller_identity")["Account"] == self.account
            except (EndpointConnectionError, ConnectionClosedError):
                return False
        self.wait("verified HTTPS controller", ready, seconds=90)

    def stop(self):
        process, self.process = self.process, None
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=90)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=30)
                raise FixtureFailure("fixture controller required forced shutdown")
            if process.returncode:
                raise FixtureFailure("controller shutdown failed")


    def role(self, suffix, trust, policy):
        name = self.prefix + "-" + suffix
        arn = self.api("iam", "create_role", RoleName=name,
                       AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
        self.owned["roles"].append(name)
        self.api("iam", "put_role_policy", RoleName=name, PolicyName="fixture",
                 PolicyDocument=json.dumps(policy))
        return arn

    def network(self, foreign=False):
        cidr = "10.228.0.0/16" if foreign else "10.227.0.0/16"
        vpc = self.api("ec2", "create_vpc", CidrBlock=cidr)["Vpc"]["VpcId"]
        self.owned["vpcs"].append(vpc)
        subnets = []
        base = "10.228" if foreign else "10.227"
        for index, zone in enumerate((self.region + "a", self.region + "b"), 1):
            subnet = self.api("ec2", "create_subnet", VpcId=vpc, CidrBlock=f"{base}.{index}.0/24",
                              AvailabilityZone=zone)["Subnet"]["SubnetId"]
            self.owned["subnets"].append(subnet)
            subnets.append(subnet)
        group = self.api("ec2", "create_security_group", VpcId=vpc,
                         GroupName=self.prefix + ("-foreign" if foreign else "-frontend"),
                         Description="Independent native ingress fixture")["GroupId"]
        self.owned["groups"].append(group)
        self.api("ec2", "authorize_security_group_ingress", GroupId=group, IpPermissions=self.ingress_permission())
        return vpc, subnets, group

    @staticmethod
    def ingress_permission():
        return [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]

    def provision(self):
        self.phase = "cluster provisioning"
        self.vpc, self.subnets, self.sg = self.network()
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
                 "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
                  "Action": ["ec2:DescribeSubnets", "ec2:DescribeSecurityGroups"], "Resource": "*"}]}
        role = self.role("cluster", trust, policy)
        self.api("eks", "create_cluster", name=self.prefix, roleArn=role, version="1.33",
                 resourcesVpcConfig={"subnetIds": self.subnets},
                 accessConfig={"authenticationMode": "CONFIG_MAP"}, clientRequestToken=uuid.uuid4().hex)
        self.cluster_created = True
        def active():
            cluster = self.api("eks", "describe_cluster", name=self.prefix)["cluster"]
            if cluster["status"] == "FAILED":
                self.capture_cluster_failure(cluster, "create")
                raise FixtureFailure("native EKS cluster failed")
            return cluster if cluster["status"] == "ACTIVE" else None
        self.cluster = self.wait("native cluster ACTIVE", active, seconds=360)
        # Kubeconfig exec generates a standard signed STS token with its original
        # AWS hostname; only update-kubeconfig's DescribeCluster uses our endpoint.
        self.command(["aws", "--endpoint-url", self.endpoint, "--region", self.region,
                      "eks", "update-kubeconfig", "--name", self.prefix,
                      "--kubeconfig", self.state / "kubeconfig"])
        receipts = list((self.state / "eks").glob("*/owner.json"))
        if len(receipts) != 1:
            raise FixtureFailure("fresh cluster has no unique native ownership receipt")
        self.native = json.loads(receipts[0].read_text())
        self.owned["native"].append(self.native)
        self.controller_image = self.image_alias(self.controller_image, "controller", "v2.14.1")
        self.backend_image = self.image_alias(self.backend_image, "backend", "1.37.0")
        self.kube("wait", "node", "--all", "--for=condition=Ready", "--timeout=180s", timeout=210)
        self.import_images()
        self.assertion("fresh_same_vpc_two_az_cluster")
        self.phase = "IRSA and upstream controller"
        issuer = self.cluster["identity"]["oidc"]["issuer"]
        if not issuer.startswith("https://"):
            raise FixtureFailure("OIDC issuer is not HTTPS")
        context = ssl.create_default_context(cafile=str(self.ca))
        parsed_issuer = urlsplit(issuer)
        request = urllib.request.Request(self.endpoint + parsed_issuer.path + "/.well-known/openid-configuration",
                                         headers={"Host": parsed_issuer.netloc})
        local_https = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                 urllib.request.HTTPSHandler(context=context))
        with local_https.open(request, timeout=30) as response:
            discovery = json.load(response)
        self.assertion("verified_https_oidc_issuer", discovery["issuer"] == issuer)
        provider = self.api("iam", "create_open_id_connect_provider", Url=issuer,
                            ClientIDList=["sts.amazonaws.com"])["OpenIDConnectProviderArn"]
        self.owned["provider"] = provider
        key = issuer.removeprefix("https://")
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
                 "Principal": {"Federated": provider}, "Action": "sts:AssumeRoleWithWebIdentity",
                 "Condition": {"StringEquals": {key + ":aud": "sts.amazonaws.com",
                     key + ":sub": "system:serviceaccount:" + self.namespace + ":controller"}}}]}
        role = self.role("controller", trust, self.policy)
        self.apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": self.namespace}})
        self.namespace_created = True
        self.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "fixture-ca", "namespace": self.namespace},
                    "data": {"ca.pem": self.ca.read_text()}})
        repository, image_tag = self.controller_image.rsplit(":", 1)
        values = {"replicaCount": 1, "fullnameOverride": "fixture-controller", "clusterName": self.prefix,
                  "region": self.region, "vpcId": self.vpc, "image": {"repository": repository,
                  "tag": image_tag, "pullPolicy": "Never"},
                  "serviceAccount": {"create": True, "name": "controller",
                                     "annotations": {"eks.amazonaws.com/role-arn": role}},
                  "watchNamespace": self.namespace, "ingressClass": "fixture-alb",
                  "createIngressClassResource": True,
                  "ingressClassParams": {"create": True, "name": "fixture-alb"},
                  "enableShield": False, "enableWaf": False, "enableWafv2": False,
                  "enableBackendSecurityGroup": False, "enableManageBackendSecurityGroupRules": False,
                  "enableServiceMutatorWebhook": False, "enableEndpointSlices": True,
                  "controllerConfig": {"featureGates": {"EnableRGTAPI": False}},
                  "syncPeriod": "20s", "awsMaxRetries": 2,
                  "awsApiEndpoints": ",".join(service + "=" + self.endpoint for service in
                      ("EC2", "Elastic Load Balancing v2", "STS", "ACM", "Resource Groups Tagging API")),
                  "env": {"AWS_CA_BUNDLE": "/fixture-ca/ca.pem", "AWS_ENDPOINT_URL": self.endpoint,
                          "AWS_ENDPOINT_URL_STS": self.endpoint, "AWS_EC2_METADATA_DISABLED": "true"},
                  "extraVolumes": [{"name": "fixture-ca", "configMap": {"name": "fixture-ca"}}],
                  "extraVolumeMounts": [{"name": "fixture-ca", "mountPath": "/fixture-ca", "readOnly": True}]}
        values_path = self.private("helm-values.json", json.dumps(values))
        self.helm_attempted = True
        self.command(["helm", "upgrade", "--install", "fixture-controller", self.chart,
                      "--namespace", self.namespace, "--values", values_path, "--wait", "--timeout", "240s"],
                     env=dict(self.env, AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true"), timeout=270)
        controller = self.kube_json("get", "pods", "-n", self.namespace,
                                    "-l", "app.kubernetes.io/name=aws-load-balancer-controller")["items"]
        self.assertion("upstream_controller_ready", len(controller) == 1 and self.ready(controller[0]))
        environment = {e["name"]: e.get("value") for e in controller[0]["spec"]["containers"][0].get("env", [])}
        self.assertion("controller_uses_exact_irsa", environment.get("AWS_ROLE_ARN") == role
                       and bool(environment.get("AWS_WEB_IDENTITY_TOKEN_FILE"))
                       and not {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"}.intersection(environment))
        self.irsa_negatives(role)

    @staticmethod
    def ready(pod):
        return pod.get("status", {}).get("phase") == "Running" and any(
            row["type"] == "Ready" and row["status"] == "True" for row in pod.get("status", {}).get("conditions", []))

    def irsa_negatives(self, role):
        for name, audience, serviceaccount in (("wrong_audience_denied", "fixture.invalid", "controller"),
                                               ("wrong_subject_denied", "sts.amazonaws.com", "other")):
            if serviceaccount == "other":
                self.apply({"apiVersion": "v1", "kind": "ServiceAccount",
                            "metadata": {"name": "other", "namespace": self.namespace}})
            token = self.kube("create", "token", serviceaccount, "-n", self.namespace,
                              "--audience=" + audience, "--duration=10m").strip()
            try:
                self.api("sts", "assume_role_with_web_identity", RoleArn=role,
                         RoleSessionName="fixture-negative", WebIdentityToken=token, DurationSeconds=900)
            except ClientError as error:
                self.assertion(name, error.response["Error"]["Code"] in
                               ("AccessDenied", "AccessDeniedException", "InvalidIdentityToken", "IDPRejectedClaim"))
            else:
                raise FixtureFailure(name)

    def workload(self):
        self.phase = "controller ingress reconciliation"
        metadata = {"name": "backend", "namespace": self.namespace}
        deployment = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": metadata,
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "fixture-backend"}},
            "template": {"metadata": {"labels": {"app": "fixture-backend"}}, "spec": {"containers": [{
                "name": "backend", "image": self.backend_image, "imagePullPolicy": "Never",
                "command": ["sh", "-ec", "mkdir -p /www; printf 'native-ingress-backend\\n' > /www/index.html; exec httpd -f -p 8080 -h /www"],
                "ports": [{"containerPort": 8080}], "readinessProbe": {"httpGet": {"path": "/", "port": 8080},
                "initialDelaySeconds": 1, "periodSeconds": 2}}]}}}}
        service = {"apiVersion": "v1", "kind": "Service", "metadata": metadata,
            "spec": {"type": "ClusterIP", "selector": {"app": "fixture-backend"},
                     "ports": [{"name": "http", "port": 80, "targetPort": 8080}]}}
        self.host = "backend.fixture.invalid"
        ingress = {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {
            "name": "backend", "namespace": self.namespace, "annotations": {
                "alb.ingress.kubernetes.io/scheme": "internal", "alb.ingress.kubernetes.io/target-type": "ip",
                "alb.ingress.kubernetes.io/subnets": ",".join(self.subnets),
                "alb.ingress.kubernetes.io/security-groups": self.sg,
                "alb.ingress.kubernetes.io/manage-backend-security-group-rules": "false",
                "alb.ingress.kubernetes.io/healthcheck-path": "/",
                "alb.ingress.kubernetes.io/healthcheck-interval-seconds": "5",
                "alb.ingress.kubernetes.io/healthcheck-timeout-seconds": "2",
                "alb.ingress.kubernetes.io/healthy-threshold-count": "2",
                "alb.ingress.kubernetes.io/unhealthy-threshold-count": "2",
                "alb.ingress.kubernetes.io/target-group-attributes": "deregistration_delay.timeout_seconds=0"}},
            "spec": {"ingressClassName": "fixture-alb", "rules": [{"host": self.host, "http": {"paths": [{
                "path": "/", "pathType": "Prefix", "backend": {"service": {"name": "backend", "port": {"number": 80}}}}]}}]}}
        self.apply(deployment, service)
        self.kube("rollout", "status", "deployment/backend", "-n", self.namespace, "--timeout=180s", timeout=210)
        self.pod = self.kube_json("get", "pods", "-n", self.namespace, "-l", "app=fixture-backend")["items"][0]
        self.assertion("actual_ready_backend_pod", self.ready(self.pod))
        self.pod_ip = self.pod["status"]["podIP"]
        def endpoints():
            rows = self.kube_json("get", "endpointslices", "-n", self.namespace,
                                  "-l", "kubernetes.io/service-name=backend")["items"]
            return [endpoint for row in rows for endpoint in row.get("endpoints", [])
                    if endpoint.get("conditions", {}).get("ready") is True
                    and self.pod_ip in endpoint.get("addresses", [])
                    and endpoint.get("targetRef", {}).get("kind") == "Pod"
                    and endpoint["targetRef"].get("uid") == self.pod["metadata"]["uid"]]
        self.wait("Ready EndpointSlice Pod targetRef", endpoints)
        self.assertion("clusterip_endpointslice_pod_targetref")
        self.apply(ingress)
        def binding():
            bindings = self.kube_json("get", "targetgroupbindings", "-n", self.namespace)["items"]
            matching = [row for row in bindings if row["spec"].get("serviceRef", {}).get("name") == "backend"]
            return matching[0] if len(matching) == 1 else None
        self.binding = self.wait("controller-created TargetGroupBinding", binding)
        self.tg = self.binding["spec"]["targetGroupARN"]
        groups = self.api("elbv2", "describe_target_groups", TargetGroupArns=[self.tg])["TargetGroups"]
        self.assertion("controller_created_ip_targetgroup_tgb", len(groups) == 1 and groups[0]["TargetType"] == "ip"
                       and groups[0]["VpcId"] == self.vpc and self.binding["spec"]["targetType"] == "ip")
        def load_balancer():
            current = self.api("elbv2", "describe_target_groups", TargetGroupArns=[self.tg])["TargetGroups"][0]
            if not current.get("LoadBalancerArns"):
                return None
            return self.api("elbv2", "describe_load_balancers", LoadBalancerArns=current["LoadBalancerArns"])["LoadBalancers"][0]
        self.lb = self.wait("controller ALB association", load_balancer)
        self.remember_controller_resources()
        self.assertion("controller_created_alb", self.lb["VpcId"] == self.vpc
                       and set(self.lb["SecurityGroups"]) == {self.sg}
                       and {row["SubnetId"] for row in self.lb["AvailabilityZones"]} == set(self.subnets))
        listeners = self.api("elbv2", "describe_listeners", LoadBalancerArn=self.lb["LoadBalancerArn"])["Listeners"]
        matching = [row for row in listeners if row["Port"] == 80 and row["Protocol"] == "HTTP"]
        self.assertion("controller_created_listener", len(matching) == 1)
        rules = self.api("elbv2", "describe_rules", ListenerArn=matching[0]["ListenerArn"])["Rules"]
        self.assertion("controller_created_host_rule", any(
            any(condition.get("Field") == "host-header" and self.host in
                condition.get("HostHeaderConfig", {}).get("Values", condition.get("Values", []))
                for condition in rule.get("Conditions", [])) and
            any(action.get("TargetGroupArn") == self.tg or any(target.get("TargetGroupArn") == self.tg
                for target in action.get("ForwardConfig", {}).get("TargetGroups", [])) for action in rule.get("Actions", []))
            for rule in rules))
        self.wait_healthy()
        self.assertion("actual_pod_target_healthy")
        self.wait("authoritative ALB DNS", lambda: self.resolves(self.lb))
        self.assertion("authoritative_alb_dns_udp_tcp")
        self.wait("host HTTP reaches actual backend", lambda: self.http(self.lb), seconds=180)
        self.assertion("host_http_backend_body")

    def resolves(self, lb):
        udp = query(self.dns, lb["DNSName"])
        tcp = query(self.dns, lb["DNSName"], tcp=True)
        return udp == tcp and udp["status"] == "NOERROR" and bool(udp["records"]) and all(
            row["type"] == "A" for row in udp["records"])

    def remember_controller_resources(self):
        for operation, key, dest, arn_key in (("describe_load_balancers", "LoadBalancers", "lbs", "LoadBalancerArn"),
                                               ("describe_target_groups", "TargetGroups", "tgs", "TargetGroupArn")):
            for row in self.api("elbv2", operation)[key]:
                if row.get("VpcId") != getattr(self, "vpc", None):
                    continue
                arn = row[arn_key]
                tags = self.api("elbv2", "describe_tags", ResourceArns=[arn])["TagDescriptions"][0]["Tags"]
                if any(tag["Key"] == "elbv2.k8s.aws/cluster" and tag["Value"] == self.prefix for tag in tags):
                    if arn not in self.owned[dest]:
                        self.owned[dest].append(arn)

    def health(self, tg=None):
        return self.api("elbv2", "describe_target_health", TargetGroupArn=tg or self.tg)["TargetHealthDescriptions"]

    def wait_healthy(self):
        return self.wait("actual Ready Pod healthy target", self.health,
                         lambda rows: len(rows) == 1 and rows[0]["Target"]["Id"] == self.pod_ip
                         and rows[0]["Target"]["Port"] == 8080 and rows[0]["TargetHealth"]["State"] == "healthy")

    def http(self, lb, expected=BODY, host=None):
        # Explicit authoritative DNS is used only for socket selection. The Host
        # header must match the controller-created rule, not a fixed-response ALB.
        name = lb["DNSName"]
        request = urllib.request.Request("http://" + name + "/", headers={"Host": host or self.host, "Connection": "close"})
        try:
            with opener(self.dns).open(request, timeout=6) as response:
                return response.status == 200 and response.read(4096) == expected
        except (OSError, urllib.error.HTTPError):
            return False

    def deny_window(self, label, lb=None):
        lb = lb or self.lb
        self.wait(label, lambda: not self.http(lb), seconds=90)
        for _ in range(3):
            if self.http(lb):
                raise FixtureFailure(label + " leaked backend response")
            time.sleep(2)

    def negatives(self):
        self.phase = "security-group packet deny and restore"
        self.api("ec2", "revoke_security_group_ingress", GroupId=self.sg, IpPermissions=self.ingress_permission())
        try:
            self.deny_window("frontend SG denies host HTTP")
            self.assertion("frontend_sg_deny")
        finally:
            self.api("ec2", "authorize_security_group_ingress", GroupId=self.sg, IpPermissions=self.ingress_permission())
        self.wait("frontend SG restore", lambda: self.http(self.lb))
        self.assertion("frontend_sg_restore")
        self.phase = "security-group Pod egress deny and restore"
        permissions = self.api("ec2", "describe_security_groups", GroupIds=[self.sg])["SecurityGroups"][0]["IpPermissionsEgress"]
        if not permissions:
            raise FixtureFailure("fresh frontend SG has no baseline egress permission")
        self.api("ec2", "revoke_security_group_egress", GroupId=self.sg, IpPermissions=permissions)
        try:
            self.deny_window("SG egress denies ALB to Pod")
            self.wait("SG egress denies target health", self.health,
                      lambda rows: bool(rows) and all(row["TargetHealth"]["State"] != "healthy" for row in rows))
            self.assertion("sg_egress_pod_packet_and_health_deny")
        finally:
            self.api("ec2", "authorize_security_group_egress", GroupId=self.sg, IpPermissions=permissions)
        self.wait_healthy()
        self.wait("SG egress restore backend HTTP", lambda: self.http(self.lb))
        self.assertion("sg_egress_restore")
        self.phase = "NACL packet deny and restore"
        acls = self.api("ec2", "describe_network_acls", Filters=[{"Name": "vpc-id", "Values": [self.vpc]}])["NetworkAcls"]
        acl_ids = {acl["NetworkAclId"] for acl in acls for association in acl.get("Associations", [])
                   if association.get("SubnetId") in self.subnets}
        if not acl_ids:
            raise FixtureFailure("no current ALB subnet NACL associations")
        changed = []
        try:
            for acl in acl_ids:
                self.api("ec2", "create_network_acl_entry", NetworkAclId=acl, RuleNumber=1, Protocol="6",
                         RuleAction="deny", Egress=True, CidrBlock=self.pod_ip + "/32",
                         PortRange={"From": 8080, "To": 8080})
                changed.append(acl)
            self.deny_window("NACL denies ALB to Pod")
            self.wait("NACL denies target health", self.health,
                      lambda rows: bool(rows) and all(row["TargetHealth"]["State"] != "healthy" for row in rows))
            self.assertion("nacl_pod_packet_and_health_deny")
        finally:
            for acl in changed:
                self.api("ec2", "delete_network_acl_entry", NetworkAclId=acl, RuleNumber=1, Egress=True)
        self.wait_healthy()
        self.wait("NACL restore backend HTTP", lambda: self.http(self.lb))
        self.assertion("nacl_restore")
        self.foreign_scope()

    def foreign_scope(self):
        self.phase = "foreign VPC packet isolation"
        vpc, subnets, sg = self.network(foreign=True)
        foreign = self.api("elbv2", "create_load_balancer", Name=self.prefix + "-foreign", Type="application",
                           Scheme="internal", Subnets=subnets, SecurityGroups=[sg])["LoadBalancers"][0]
        self.owned["lbs"].append(foreign["LoadBalancerArn"])
        tg = self.api("elbv2", "create_target_group", Name=self.prefix + "-foreign", Protocol="HTTP", Port=8080,
                      VpcId=vpc, TargetType="ip", HealthCheckProtocol="HTTP", HealthCheckPath="/",
                      HealthCheckIntervalSeconds=5, HealthCheckTimeoutSeconds=2,
                      HealthyThresholdCount=2, UnhealthyThresholdCount=2)["TargetGroups"][0]["TargetGroupArn"]
        self.owned["tgs"].append(tg)
        self.api("elbv2", "create_listener", LoadBalancerArn=foreign["LoadBalancerArn"], Protocol="HTTP", Port=80,
                 DefaultActions=[{"Type": "forward", "TargetGroupArn": tg}])
        self.api("elbv2", "register_targets", TargetGroupArn=tg,
                 Targets=[{"Id": self.pod_ip, "Port": 8080, "AvailabilityZone": "all"}])
        self.wait("foreign VPC target unhealthy", lambda: self.health(tg),
                  lambda rows: len(rows) == 1 and rows[0]["TargetHealth"]["State"] == "unhealthy")
        self.wait("foreign ALB authoritative DNS", lambda: self.resolves(foreign))
        self.deny_window("foreign VPC cannot reach owned Pod", foreign)
        self.wait_healthy()
        self.assertion("foreign_vpc_target_and_packet_deny")
        self.assertion("original_vpc_unaffected", self.http(self.lb))

    def retained(self):
        self.phase = "retained controller reconciliation"
        pod_uid = self.pod["metadata"]["uid"]
        arn = self.lb["LoadBalancerArn"]
        self.stop()
        self.start()
        def attached():
            try:
                return bool(self.kube("get", "--raw", "/version"))
            except FixtureFailure:
                return False
        self.wait("retained Kubernetes API attached", attached, seconds=120)
        self.kube("rollout", "restart", "deployment/fixture-controller", "-n", self.namespace)
        self.kube("rollout", "status", "deployment/fixture-controller", "-n", self.namespace,
                  "--timeout=180s", timeout=210)
        self.wait_healthy()
        self.wait("retained host HTTP", lambda: self.http(self.lb))
        pod = self.kube_json("get", "pod", self.pod["metadata"]["name"], "-n", self.namespace)
        self.assertion("retained_same_backend_pod", pod["metadata"]["uid"] == pod_uid and self.ready(pod))
        binding = self.kube_json("get", "targetgroupbinding", self.binding["metadata"]["name"], "-n", self.namespace)
        current = self.api("elbv2", "describe_load_balancers", LoadBalancerArns=[arn])["LoadBalancers"][0]
        self.assertion("retained_same_alb_tg_tgb", binding["spec"]["targetGroupARN"] == self.tg
                       and current["DNSName"] == self.lb["DNSName"])
        self.assertion("retained_reconcile_backend_body")

    def cleanup(self):
        self.phase = "exact owned cleanup"
        failures = []
        def attempt(label, fn):
            try:
                fn()
            except Exception:
                failures.append(label)
                self.diagnostics.write("Cleanup failure: " + label + "\n" + traceback.format_exc())
                self.diagnostics.flush()
        if not self.started:
            return failures
        if self.process is None or self.process.poll() is not None:
            attempt("restart fixture controller for cleanup", self.start)
        # Capture only resources carrying this fresh controller's upstream cluster
        # tag in its exact VPC, including partial reconciliation before readiness.
        if hasattr(self, "vpc"):
            attempt("capture partial owned ALB resources", self.remember_controller_resources)
        if self.namespace_created:
            attempt("delete fixture ingress", lambda: self.kube("delete", "ingress", "backend", "-n", self.namespace,
                    "--ignore-not-found", "--wait=true", "--timeout=120s", timeout=150))
        if self.helm_attempted:
            attempt("uninstall fixture chart", lambda: self.command(["helm", "uninstall", "fixture-controller",
                "--namespace", self.namespace, "--ignore-not-found", "--wait", "--timeout", "120s"],
                env=dict(self.env, AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true"), timeout=150))
        # Manual fallback is limited to recorded fixture ARNs, never tag-only bulk
        # deletion, another account, a retained deployment, or arbitrary Docker IDs.
        def remove_lb(arn):
            self.absent_api("elbv2", "delete_load_balancer", ("LoadBalancerNotFound",), LoadBalancerArn=arn)
            def gone():
                try:
                    self.api("elbv2", "describe_load_balancers", LoadBalancerArns=[arn])
                    return False
                except ClientError as error:
                    if error.response["Error"]["Code"] == "LoadBalancerNotFound":
                        return True
                    raise
            self.wait("exact fixture ALB deleted", gone, seconds=180)
        for arn in self.owned["lbs"]:
            attempt("delete exact fixture ALB", lambda arn=arn: remove_lb(arn))
        for arn in self.owned["tgs"]:
            attempt("delete exact fixture target group", lambda arn=arn: self.absent_api("elbv2", "delete_target_group",
                    ("TargetGroupNotFound",), TargetGroupArn=arn))
        if self.namespace_created:
            attempt("delete fixture namespace", lambda: self.kube("delete", "namespace", self.namespace,
                    "--ignore-not-found", "--wait=true", "--timeout=120s", timeout=150))
        if self.cluster_created:
            attempt("delete fixture cluster", lambda: self.api("eks", "delete_cluster", name=self.prefix))
            def cluster_gone():
                try:
                    current = self.api("eks", "describe_cluster", name=self.prefix)["cluster"]
                    if current["status"] == "DELETING" and current.get("health", {}).get("issues"):
                        self.deleting_cluster = current
                    return False
                except ClientError as error:
                    if error.response["Error"]["Code"] == "ResourceNotFoundException":
                        return True
                    raise
            attempt("wait fixture cluster removed", lambda: self.wait("fixture cluster deleted", cluster_gone, seconds=300))
            if "wait fixture cluster removed" in failures and hasattr(self, "deleting_cluster"):
                self.capture_cluster_failure(self.deleting_cluster, "delete")
        for receipt in self.owned["native"]:
            for kind, argv in (("containers", ["docker", "ps", "-aq"]),
                               ("volumes", ["docker", "volume", "ls", "-q"]),
                               ("networks", ["docker", "network", "ls", "-q"])):
                def no_native(argv=argv, receipt=receipt):
                    if self.command([*argv, "--filter", "label=stackd.eks.id=" + receipt["ID"]]).strip():
                        raise FixtureFailure("owned native resources remain")
                attempt("verify owned native " + kind + " removed", no_native)
        if self.owned.get("provider"):
            attempt("delete exact OIDC provider", lambda: self.api("iam", "delete_open_id_connect_provider",
                    OpenIDConnectProviderArn=self.owned["provider"]))
        for name in self.owned["roles"]:
            attempt("delete exact inline role policy", lambda name=name: self.api("iam", "delete_role_policy",
                    RoleName=name, PolicyName="fixture"))
            attempt("delete exact role", lambda name=name: self.api("iam", "delete_role", RoleName=name))
        for vpc in self.owned["vpcs"]:
            attempt("wait exact VPC interfaces removed", lambda vpc=vpc: self.wait("fixture ENIs deleted",
                    lambda: self.api("ec2", "describe_network_interfaces", Filters=[{"Name": "vpc-id", "Values": [vpc]}])["NetworkInterfaces"],
                    accept=lambda rows: not rows, seconds=180))
        for group in self.owned["groups"]:
            attempt("delete exact frontend SG", lambda group=group: self.api("ec2", "delete_security_group", GroupId=group))
        for subnet in reversed(self.owned["subnets"]):
            attempt("delete exact subnet", lambda subnet=subnet: self.api("ec2", "delete_subnet", SubnetId=subnet))
        for vpc in reversed(self.owned["vpcs"]):
            attempt("delete exact VPC", lambda vpc=vpc: self.api("ec2", "delete_vpc", VpcId=vpc))
        for alias in self.owned["image_tags"]:
            attempt("delete fixture-only image tag", lambda alias=alias: self.command(["docker", "image", "rm", alias]))
        if self.lb:
            def dns_gone():
                return all(query(self.dns, self.lb["DNSName"], tcp=tcp)["status"] == "NXDOMAIN" for tcp in (False, True))
            attempt("verify removed ALB DNS", lambda: self.wait("owned ALB DNS deleted", dns_gone, seconds=60))
        self.result["assertions"]["exact_owned_cleanup"] = not failures
        return failures

    def absent_api(self, service, operation, absent_codes, **kwargs):
        try:
            return self.api(service, operation, **kwargs)
        except ClientError as error:
            if error.response["Error"]["Code"] not in absent_codes:
                raise

    def execute(self):
        failure = None
        failure_reason = None
        cleanup_failures = []
        try:
            self.prepare()
            self.start()
            self.assertion("verified_https_aws_endpoint")
            self.provision()
            self.workload()
            self.negatives()
            self.retained()
        except BaseException as error:
            failure = self.phase
            # Public reason strings are ours or SDK error codes, never raw API
            # messages, resource identifiers, tokens, paths or subprocess output.
            if isinstance(error, FixtureFailure):
                failure_reason = str(error)
            elif isinstance(error, ClientError):
                failure_reason = error.response["Error"]["Code"]
            else:
                failure_reason = type(error).__name__
            self.diagnostics.write("Original failure:\n" + traceback.format_exc())
            self.diagnostics.flush()
        finally:
            try:
                cleanup_failures = self.cleanup()
            except BaseException:
                cleanup_failures.append("unexpected cleanup error")
                self.diagnostics.write("Unexpected cleanup failure:\n" + traceback.format_exc())
            try:
                self.stop()
            except BaseException:
                cleanup_failures.append("controller stop")
                self.diagnostics.write("Controller stop failure:\n" + traceback.format_exc())
            self.log.close()
            self.diagnostics.close()
        self.result["passed"] = failure is None and not cleanup_failures
        if failure:
            self.result["failed_phase"] = failure
            self.result["failed_check"] = failure_reason
        if cleanup_failures:
            self.result["cleanup_failures"] = cleanup_failures
        if not self.result["passed"]:
            self.result["diagnostics"] = "Original errors and raw observations are in the supplied private state directory; do not publish it."
        self.args.output.write_text(json.dumps(self.result, indent=2) + "\n")
        print(json.dumps(self.result, indent=2))
        return 0 if self.result["passed"] else 1


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--elbv2-node-executable", type=Path, required=True)
    parser.add_argument("--k3d", type=Path, required=True)
    parser.add_argument("--state-directory", type=Path, required=True, help="new private directory; must not exist")
    parser.add_argument("--output", type=Path, required=True, help="generic assertion JSON only")
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    parser.add_argument("--gateway-host", help="IPv4 host address reachable from fresh Docker workers; defaults to bridge gateway")
    parser.add_argument("--port", type=int, help="fresh HTTPS listen port; defaults to a free port")
    parser.add_argument("--dns-port", type=int, help="fresh authoritative DNS port; defaults to a free port")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--storage-reserve-gib", type=int, default=4,
                        help="fresh fixture node reserve; production default is tested separately")
    parser.add_argument("--chart", type=Path, help="offline copy of the official 1.14.1 chart")
    parser.add_argument("--iam-policy", type=Path, help="offline copy of the official v2.14.1 IAM policy")
    parser.add_argument("--controller-image", default=CONTROLLER_IMAGE,
                        help="installed upstream v2.14.1 image; tag is resolved to its local repository digest")
    parser.add_argument("--backend-image", default=BACKEND_IMAGE, help="installed shell/httpd-capable immutable BusyBox image")
    args = parser.parse_args()
    if args.storage_reserve_gib <= 0:
        parser.error("--storage-reserve-gib must be positive")
    if args.output.resolve().is_relative_to(args.state_directory.resolve()):
        parser.error("--output must be outside the private state directory")
    try:
        smoke = Smoke(args)
    except FileExistsError:
        parser.error("--state-directory must not already exist")
    # SIGTERM follows the same finally cleanup path as an ordinary interruption.
    def interrupted(*_):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    return smoke.execute()


if __name__ == "__main__":
    sys.exit(main())
