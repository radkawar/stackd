"""Current-provider EKS controls with real k3d Kubernetes DNS, pods and service bytes."""

import base64
import json
from pathlib import Path
import random
import ssl
import subprocess
import sys
from urllib.parse import urlsplit
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compute import Terraform, client, environment, parser, require


def main():
    options = parser(__doc__)
    options.add_argument("--pod-image", default="busybox:1.36.1", help="Installed BusyBox image with httpd and wget; imported offline into owned k3d")
    options.add_argument("--k3d", type=Path, default=Path(__file__).resolve().parents[3] / "bin/k3d-v5.8.3")
    args = options.parse_args()
    require(not args.endpoint, "The complete lifecycle requires a fixture-owned controller for reopen")
    require(args.k3d.is_file(), "Install the pinned k3d v5.8.3 executable first")
    fixture = Terraform(args, Path(__file__).resolve().parent)
    name = "tf-eks-" + uuid.uuid4().hex[:12]
    namespace = name
    octet = random.SystemRandom().randrange(130, 220)
    extra = ("-docker-host", args.docker_host, "-eks-state-directory", str(fixture.root / "eks"),
             "-eks-k3d", str(args.k3d.resolve()), "-eks-listen-host", "127.0.0.1",
             "-eks-endpoint-host", "127.0.0.1")
    env = environment()
    env["DOCKER_HOST"] = args.docker_host
    kubeconfig = fixture.directory / "kubeconfig.json"

    def command(*argv, content=None):
        result = subprocess.run(argv, input=content, env=env, check=False,
                                text=True, capture_output=True)
        if result.returncode:
            print(result.stdout, end="", file=sys.stderr)
            print(result.stderr, end="", file=sys.stderr)
            result.check_returncode()
        return result.stdout

    def kubectl(*argv, content=None):
        return command("kubectl", "--kubeconfig", str(kubeconfig), "--context", "stackd",
                       "--request-timeout=60s", *argv, content=content)

    command("docker", "image", "inspect", args.pod_image)
    outputs = None
    owned_nodes = []
    with fixture.endpoint(extra=extra, containers=True) as endpoint:
        fixture.configure(endpoint=endpoint, name=name, revision="create",
                          vpc_cidr=f"10.{octet}.0.0/16", subnet_a_cidr=f"10.{octet}.0.0/24",
                          subnet_b_cidr=f"10.{octet}.1.0/24")
        fixture.command("init", "-input=false")

        def credentials():
            # Short-lived credentials have a separate read-only state. Their
            # timestamp changes must not alter the infrastructure plan.
            token = fixture.authenticate(
                "eks/authentication.tf", name=name)["token"]["value"]
            public = urlsplit(outputs["endpoint"])
            require(public.scheme == "https" and public.hostname == "127.0.0.1" and public.port,
                    "Kubernetes endpoint is not the owned local TLS proxy")
            document = {"apiVersion": "v1", "kind": "Config", "current-context": "stackd",
                        "clusters": [{"name": "stackd", "cluster": {
                            "server": outputs["endpoint"], "certificate-authority-data": outputs["ca"]}}],
                        "contexts": [{"name": "stackd", "context": {"cluster": "stackd", "user": "stackd"}}],
                        "users": [{"name": "stackd", "user": {"token": token}}]}
            kubeconfig.write_text(json.dumps(document))
            kubeconfig.chmod(0o600)
            # All requests go only to this owned TLS proxy. Changing the URL
            # inside a token must never cause a request to that token's host.
            encoded = token.removeprefix("k8s-aws-v1.")
            signed_url = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode()
            wrong_host = urlsplit(signed_url)._replace(netloc="attacker.invalid").geturl()
            wrong_host_token = "k8s-aws-v1." + base64.urlsafe_b64encode(wrong_host.encode()).decode().rstrip("=")
            context = ssl.create_default_context(cadata=base64.b64decode(outputs["ca"]).decode())
            for negative in ("not-an-eks-token", wrong_host_token):
                request = Request(outputs["endpoint"] + "/api/v1/nodes",
                                  headers={"Authorization": "Bearer " + negative})
                try:
                    with urlopen(request, context=context, timeout=30):
                        raise RuntimeError("Native Kubernetes admitted an invalid token")
                except HTTPError as error:
                    require(error.code == 401, "Invalid token was not rejected by native EKS authentication")
                    require(json.load(error)["reason"] == "Unauthorized", "Unexpected token-denial response")
            print("Consumed real TLS authentication: malformed and wrong-host tokens rejected", flush=True)

        def workload(revision):
            labels = {"app": "echo"}
            documents = [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}},
                         {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "echo", "namespace": namespace},
                          "spec": {"replicas": 1, "selector": {"matchLabels": labels},
                                   "template": {"metadata": {"labels": {**labels, "revision": revision}}, "spec": {"containers": [{
                                       "name": "echo", "image": args.pod_image, "imagePullPolicy": "Never",
                                       "command": ["/bin/sh", "-c", "mkdir -p /www; printf '%s\\n' \"$REVISION\" >/www/index.html; printf 'EKS:%s\\n' \"$REVISION\"; exec httpd -f -p 8080 -h /www"],
                                       "env": [{"name": "REVISION", "value": revision}],
                                       "ports": [{"containerPort": 8080}], "readinessProbe": {
                                           "httpGet": {"path": "/", "port": 8080}, "periodSeconds": 2}}]}}}},
                         {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "echo", "namespace": namespace},
                          "spec": {"selector": labels, "ports": [{"port": 8080, "targetPort": 8080}]}},
                         {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "consumer", "namespace": namespace},
                          "spec": {"containers": [{"name": "consumer", "image": args.pod_image,
                                                       "imagePullPolicy": "Never", "command": ["sleep", "3600"]}]}}]
            kubectl("apply", "-f", "-", content=json.dumps({"apiVersion": "v1", "kind": "List", "items": documents}))
            try:
                kubectl("rollout", "status", "deployment/echo", "-n", namespace, "--timeout=180s")
                kubectl("wait", "--for=condition=Ready", "pod/consumer", "-n", namespace, "--timeout=180s")
            except subprocess.CalledProcessError:
                # Read the actual failed workload before ordinary cluster
                # teardown removes its pods and events. Keep the failure.
                for resource in ("pods", "events"):
                    try:
                        diagnostic = kubectl("get", resource, "-n", namespace, "-o", "json")
                    except subprocess.CalledProcessError as error:
                        diagnostic = error.stdout + error.stderr
                    artifact = fixture.directory / (resource + "-failure.log")
                    artifact.write_text(diagnostic)
                    artifact.chmod(0o600)
                    print(diagnostic, file=sys.stderr)
                raise
            body = kubectl("exec", "consumer", "-n", namespace, "--", "wget", "-q", "-O", "-", "http://echo:8080/")
            require(body == revision + "\n", "Independent Kubernetes pod received wrong DNS-routed service bytes")
            current = json.loads(kubectl("get", "pods", "-n", namespace,
                                        "-l", "app=echo,revision=" + revision, "-o", "json"))["items"]
            ready = [pod for pod in current if not pod["metadata"].get("deletionTimestamp")
                     and any(condition["type"] == "Ready" and condition["status"] == "True"
                             for condition in pod["status"].get("conditions", []))]
            require(len(ready) == 1, "Expected one actual ready customer pod for the deployed revision")
            logs = kubectl("logs", ready[0]["metadata"]["name"], "-c", "echo", "-n", namespace)
            require("EKS:" + revision in logs, "Customer Kubernetes process did not print deployed revision")
            print(f"Consumed real Kubernetes {revision}: native pod logs and independent pod DNS/HTTP bytes", flush=True)

        try:
            fixture.command("apply", "-input=false", "-auto-approve")
            outputs = fixture.output()
            require(name in outputs["listed_clusters"], "EKS cluster list omitted the real cluster")
            credentials()
            nodes = json.loads(kubectl("get", "nodes", "-o", "json"))["items"]
            require(len(nodes) == 1, "Expected the native baseline worker, not invented EC2 workers")
            node_name = nodes[0]["metadata"]["name"]
            require(node_name.startswith("k3d-stackd-") and node_name.endswith("-agent-0"), "Unexpected native baseline node identity")
            native_name = node_name[len("k3d-"):-len("-agent-0")]
            native = json.loads(command("docker", "inspect", node_name))[0]
            labels = native["Config"]["Labels"]
            require(labels.get("k3d.cluster") == native_name and labels.get("stackd.eks.owner", "")[:24] == native_name[len("stackd-"):]
                    and labels.get("stackd.eks.id") and native["State"]["Running"], "Native worker ownership does not match the admitted cluster")
            owned_nodes.append(native["Id"])
            # Export one installed platform. k3d's all-platform import can
            # report success after missing content and a server without ctr.
            # Import real bytes into only the verified native worker.
            image_archive = fixture.directory / "native-pod-image.tar"
            with image_archive.open("wb") as exported:
                subprocess.run(
                    ["docker", "image", "save", "--platform", "linux/amd64", args.pod_image],
                    env=env, stdout=exported, check=True)
            image_archive.chmod(0o600)
            with image_archive.open("rb") as exported:
                imported = subprocess.run(
                    ["docker", "exec", "-i", node_name, "ctr", "--namespace", "k8s.io",
                     "images", "import", "--platform", "linux/amd64", "-"],
                    env=env, stdin=exported, text=True, capture_output=True)
            image_log = fixture.directory / "native-image-import.log"
            image_log.write_text(imported.stdout + imported.stderr)
            image_log.chmod(0o600)
            if imported.returncode:
                print(imported.stdout + imported.stderr, file=sys.stderr)
            imported.check_returncode()
            workload("create")
            fixture.no_change("create")
            fixture.reimport("aws_eks_cluster.compute", name)
            fixture.command("apply", "-input=false", "-auto-approve")
            fixture.no_change("import")
            fixture.configure(revision="update")
            fixture.command("apply", "-input=false", "-auto-approve")
            outputs = fixture.output()
            credentials()
            workload("update")
            fixture.no_change("update")
            fixture.reopen()
            outputs = fixture.output()
            credentials()
            workload("update")
            fixture.no_change("reopen")
            kubectl("delete", "namespace", namespace, "--wait=true", "--timeout=120s")
        finally:
            # Cluster deletion owns all remaining Kubernetes objects and native
            # containers, including a partially created customer namespace.
            fixture.destroy()
            from local import expect_missing
            expect_missing(client("eks", endpoint).describe_cluster, {"ResourceNotFoundException"}, name=name)
            remaining = command("docker", "ps", "-aq").split()
            require(not set(owned_nodes).intersection(remaining), "Owned native Kubernetes worker remains after destroy")
            for suffix in ("cluster", "access"):
                expect_missing(client("iam", endpoint).get_role, {"NoSuchEntity"}, RoleName=name + "-" + suffix)
            print("Completed EKS API and exact native worker cleanup checks", flush=True)
    print(f"Completed EKS fixture. Private artifacts: {fixture.directory}", flush=True)


if __name__ == "__main__":
    main()
