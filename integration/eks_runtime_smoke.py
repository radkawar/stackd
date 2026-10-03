#!/usr/bin/env python3
"""Exact-owned EKS CLI/Kubernetes/restart proof; no native AWS mutations."""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request

from eks_access_smoke import exercise_access
import eks_logging_smoke as logging_workflow
from eks_addons_smoke import exercise_addons
from eks_fargate_smoke import exercise_fargate


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--k3d", required=True)
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="stackd-eks-workflow-"))
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}"
    account = "314159265358"
    cluster = "eks-owned-workflow"
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_") and k != "KUBECONFIG"}
    env.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test", AWS_DEFAULT_REGION="us-east-1", AWS_EC2_METADATA_DISABLED="true", AWS_PAGER="", KUBECONFIG=str(root / "kubeconfig"))
    env["AWS_CONFIG_FILE"] = str(root / "aws-config")
    env["AWS_SHARED_CREDENTIALS_FILE"] = str(root / "aws-credentials")
    process = None
    log = open(root / "controller.log", "ab")
    observed = {}
    native_id = None

    def command(argv, who=None, success=True, stdin=None, timeout=90):
        p = subprocess.run(argv, env=who or env, input=stdin, text=True, capture_output=True, timeout=timeout)
        if success and p.returncode:
            raise RuntimeError(f"{' '.join(argv[:5])}: {p.stderr[-4000:]}")
        if not success and p.returncode == 0:
            raise RuntimeError(f"unexpected permission success: {' '.join(argv)}")
        return p.stdout if success else p.stderr

    def aws(service, op, *flags, who=None, success=True):
        result = command(["aws", "--endpoint-url", endpoint, "--region", "us-east-1", service, op, *flags, "--output", "json"], who, success)
        return json.loads(result) if success and result.strip() else result

    def kube(*flags, who=None, success=True, stdin=None, timeout=120):
        return command(["kubectl", "--request-timeout=90s", *flags], who, success, stdin, timeout)

    def wait_for(fn, seconds=300):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            result = fn()
            if result:
                return result
            time.sleep(1)
        raise RuntimeError("workflow readiness deadline exceeded")

    def start():
        nonlocal process
        process = subprocess.Popen([args.binary, "-listen", f"127.0.0.1:{port}", "-account-id", account, "-database", str(root / "state.db"), "-docker-host", args.docker_host, "-compute-endpoint", f"http://host.docker.internal:{port}", "-eks-state-directory", str(root / "kubernetes"), "-eks-k3d", args.k3d], env=env, stdout=log, stderr=log)
        def ready():
            if process.poll() is not None:
                raise RuntimeError((root / "controller.log").read_text()[-6000:])
            try:
                return urllib.request.urlopen(endpoint + "/_stackd/health", timeout=1).status == 200
            except OSError:
                return False
        wait_for(ready, 60)

    def stop():
        nonlocal process
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=60)
            if process.returncode != 0:
                raise RuntimeError(f"controller exit {process.returncode}")
        process = None

    def active():
        c = aws("eks", "describe-cluster", "--name", cluster)["cluster"]
        if c["status"] == "FAILED":
            raise RuntimeError(json.dumps(c.get("health")))
        return c if c["status"] == "ACTIVE" else None

    def restart():
        stop()
        start()
        wait_for(active)
        def attached():
            probe = subprocess.run(["kubectl", "--request-timeout=3s", "get", "--raw", "/version"], env=env, text=True, capture_output=True, timeout=10)
            return probe.returncode == 0
        wait_for(attached, 120)

    try:
        start()
        vpc = aws("ec2", "create-vpc", "--cidr-block", "10.246.0.0/16")["Vpc"]["VpcId"]
        subnet_ids = []
        for cidr, zone in [("10.246.1.0/24", "us-east-1a"), ("10.246.2.0/24", "us-east-1b")]:
            subnet_ids.append(aws("ec2", "create-subnet", "--vpc-id", vpc, "--cidr-block", cidr, "--availability-zone", zone)["Subnet"]["SubnetId"])
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        role = aws("iam", "create-role", "--role-name", "eks-workflow", "--assume-role-policy-document", json.dumps(trust))["Role"]["Arn"]
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["ec2:DescribeSubnets", "ec2:DescribeSecurityGroups"], "Resource": "*"}]}
        aws("iam", "put-role-policy", "--role-name", "eks-workflow", "--policy-name", "networks", "--policy-document", json.dumps(policy))
        create_flags = ["--name", cluster, "--role-arn", role, "--resources-vpc-config", json.dumps({"subnetIds": subnet_ids}), "--access-config", "authenticationMode=CONFIG_MAP", "--client-request-token", "stable-create-token", "--tags", "purpose=owned-workflow"] + logging_workflow.create_flags()
        first = aws("eks", "create-cluster", *create_flags)["cluster"]
        replay = aws("eks", "create-cluster", *create_flags)["cluster"]
        assert first["arn"] == replay["arn"] and first["createdAt"] == replay["createdAt"]
        # Native ID is retained control intent, never inferred from unrelated Docker names.
        import sqlite3
        with sqlite3.connect(root / "state.db") as db:
            observed["isolatedSchemaVersion"] = db.execute("PRAGMA user_version").fetchone()[0]
            rows = db.execute("SELECT id FROM eks_cluster").fetchall()
            assert len(rows) == 1
            native_id = rows[0][0]
        docker_env = dict(env, DOCKER_HOST=args.docker_host)
        server = wait_for(lambda: command(["docker", "ps", "--filter", f"label=stackd.eks.id={native_id}", "--filter", "name=server-0", "--format", "{{.ID}}"], docker_env).strip())
        assert len(server.splitlines()) == 1
        command(["docker", "pause", server], docker_env)
        try:
            assert aws("eks", "describe-cluster", "--name", cluster)["cluster"]["status"] == "CREATING"
            aws("cloudwatch", "put-metric-alarm", "--alarm-name", "native-isolation", "--namespace", "EKSRegression", "--metric-name", "NativeEffectBlocked", "--statistic", "Maximum", "--period", "10", "--evaluation-periods", "1", "--threshold", "1", "--comparison-operator", "GreaterThanThreshold", "--treat-missing-data", "breaching")
            def alarm_fired():
                return aws("cloudwatch", "describe-alarms", "--alarm-names", "native-isolation")["MetricAlarms"][0]["StateValue"] == "ALARM"
            observed["alarmProgressWhileNativePaused"] = bool(wait_for(alarm_fired, 30))
            assert aws("eks", "describe-cluster", "--name", cluster)["cluster"]["status"] == "CREATING"
        finally:
            command(["docker", "unpause", server], docker_env)
        current = wait_for(active)
        observed["clusterStatus"] = current["status"]
        observed["endpoint"] = current["endpoint"]
        observed["certificateAuthorityPresent"] = bool(current["certificateAuthority"]["data"])
        command(["aws", "--endpoint-url", endpoint, "--region", "us-east-1", "eks", "update-kubeconfig", "--name", cluster, "--kubeconfig", str(root / "kubeconfig")])
        exercise_access(aws, kube, env, cluster, account, command, restart, observed)
        exercise_fargate(aws, kube, cluster, subnet_ids, wait_for, restart, observed)
        for label, token_cluster, region, token_env in [
            ("wrongClusterDenied", "different-cluster", "us-east-1", env),
            ("unboundAccountDenied", cluster, "us-east-1", dict(env, AWS_ACCESS_KEY_ID="271828182845")),
        ]:
            token = json.loads(command(["aws", "eks", "get-token", "--cluster-name", token_cluster, "--region", region], token_env))["status"]["token"]
            denied = kube("--token", token, "get", "namespaces", success=False)
            observed[label] = "Unauthorized" in denied or "must be logged in" in denied
            assert observed[label], denied
        for label, region, token_env in [
            ("otherSTSRegionAccepted", "us-west-2", env),
            ("globalSTSHostAccepted", "us-east-1", dict(env, AWS_STS_REGIONAL_ENDPOINTS="legacy")),
            ("FIPSSTSHostAccepted", "us-east-1", dict(env, AWS_USE_FIPS_ENDPOINT="true")),
            ("dualStackSTSHostAccepted", "us-east-1", dict(env, AWS_USE_DUALSTACK_ENDPOINT="true")),
        ]:
            token = json.loads(command(["aws", "eks", "get-token", "--cluster-name", cluster, "--region", region], token_env))["status"]["token"]
            observed[label] = "kube-system" in kube("--token", token, "get", "namespaces")
            assert observed[label]
        federation = aws("sts", "get-federation-token", "--name", "restricted", "--duration-seconds", "3600", "--policy", json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}))["Credentials"]
        federated_env = dict(env, AWS_ACCESS_KEY_ID=federation["AccessKeyId"], AWS_SECRET_ACCESS_KEY=federation["SecretAccessKey"], AWS_SESSION_TOKEN=federation["SessionToken"])
        token = json.loads(command(["aws", "eks", "get-token", "--cluster-name", cluster, "--region", "us-east-1"], federated_env))["status"]["token"]
        denied = kube("--token", token, "get", "namespaces", success=False)
        observed["federatedIssuerPrivilegeDenied"] = "Unauthorized" in denied or "must be logged in" in denied
        assert observed["federatedIssuerPrivilegeDenied"], denied
        kube("create", "namespace", "blue")
        kube("create", "namespace", "green")
        user = aws("iam", "create-user", "--user-name", "eks-developer")["User"]["Arn"]
        key = aws("iam", "create-access-key", "--user-name", "eks-developer")["AccessKey"]
        developer = dict(env, AWS_ACCESS_KEY_ID=key["AccessKeyId"], AWS_SECRET_ACCESS_KEY=key["SecretAccessKey"])
        aws("eks", "create-access-entry", "--cluster-name", cluster, "--principal-arn", user)
        edit_policy = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSEditPolicy"
        aws("eks", "associate-access-policy", "--cluster-name", cluster, "--principal-arn", user, "--policy-arn", edit_policy, "--access-scope", "type=namespace,namespaces=blue")
        workload = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "echo", "namespace": "blue"}, "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "echo"}}, "template": {"metadata": {"labels": {"app": "echo"}}, "spec": {"containers": [{"name": "echo", "image": "busybox:1.37.0", "command": ["sh", "-c", "mkdir -p /www; echo actual-eks-pod-output > /www/index.html; httpd -f -p 8080 -h /www"], "ports": [{"containerPort": 8080}]}]}}}}
        kube("apply", "-f", "-", who=developer, stdin=json.dumps(workload))
        kube("rollout", "status", "deployment/echo", "-n", "blue", "--timeout=180s", who=developer, timeout=210)
        pod = json.loads(kube("get", "pods", "-n", "blue", "-o", "json", who=developer))["items"][0]
        observed["podUIDBeforeRestart"] = pod["metadata"]["uid"]
        observed["podPhase"] = pod["status"]["phase"]
        observed["podOutput"] = kube("exec", "-n", "blue", "deployment/echo", "--", "cat", "/www/index.html", who=developer).strip()
        assert observed["podOutput"] == "actual-eks-pod-output"
        kube("expose", "deployment", "echo", "-n", "blue", "--port=8080", who=developer)
        observed["serviceResponse"] = kube("get", "--raw", "/api/v1/namespaces/blue/services/echo:8080/proxy/").strip()
        assert observed["serviceResponse"] == "actual-eks-pod-output"
        observed["namespaceDenied"] = "Forbidden" in kube("get", "pods", "-n", "green", who=developer, success=False)
        assert observed["namespaceDenied"]
        # Direct Kubernetes authorization is separate from EKS IAM API permission.
        observed["iamControlDenied"] = "AccessDenied" in aws("eks", "describe-cluster", "--name", cluster, who=developer, success=False)
        assert observed["iamControlDenied"]
        cached = json.loads(command(["aws", "eks", "get-token", "--cluster-name", cluster, "--region", "us-east-1"], developer))["status"]["token"]
        time.sleep(62)
        observed["cachedTokenAfter60Seconds"] = "echo" in kube("--token", cached, "get", "pods", "-n", "blue", who=developer)
        assert observed["cachedTokenAfter60Seconds"]
        aws("iam", "update-access-key", "--user-name", "eks-developer", "--access-key-id", key["AccessKeyId"], "--status", "Inactive")
        observed["inactiveCredentialDenied"] = bool(kube("--token", cached, "get", "pods", "-n", "blue", who=developer, success=False))
        aws("iam", "update-access-key", "--user-name", "eks-developer", "--access-key-id", key["AccessKeyId"], "--status", "Active")
        kube("--token", cached, "get", "pods", "-n", "blue", who=developer)
        observed["controlPlaneLogging"] = logging_workflow.capture_logging(aws, wait_for, cluster, user)
        observed["auditWebhookSource"] = logging_workflow.assert_webhook_source(root / "kubernetes", native_id, observed["controlPlaneLogging"], command, docker_env, server, wait_for)
        observed["loggingConfigurationUpdate"] = logging_workflow.disable_and_reenable(aws, kube, wait_for, cluster)
        logging_workflow.upgrade(aws, kube, wait_for, cluster, observed)
        # Controller replacement must preserve the same real pod, not recreate it.
        restart()
        observed["versionAfterRestart"] = logging_workflow.assert_recovered_version(kube, observed["nativeVersionUpgrade"]["after"])
        exercise_addons(aws, kube, cluster, wait_for, restart, observed)
        after = json.loads(kube("get", "pods", "-n", "blue", "-o", "json", who=developer))["items"][0]
        observed["podUIDAfterRestart"] = after["metadata"]["uid"]
        assert observed["podUIDBeforeRestart"] == observed["podUIDAfterRestart"]
        observed["serviceAfterRestart"] = kube("get", "--raw", "/api/v1/namespaces/blue/services/echo:8080/proxy/").strip()
        assert observed["serviceAfterRestart"] == "actual-eks-pod-output"
        aws("iam", "delete-access-key", "--user-name", "eks-developer", "--access-key-id", key["AccessKeyId"])
        aws("iam", "delete-user", "--user-name", "eks-developer")
        recreated = aws("iam", "create-user", "--user-name", "eks-developer")["User"]["Arn"]
        assert recreated == user
        key = aws("iam", "create-access-key", "--user-name", "eks-developer")["AccessKey"]
        developer = dict(env, AWS_ACCESS_KEY_ID=key["AccessKeyId"], AWS_SECRET_ACCESS_KEY=key["SecretAccessKey"])
        observed["recreatedPrincipalDenied"] = bool(kube("get", "pods", "-n", "blue", who=developer, success=False))
        aws("eks", "delete-access-entry", "--cluster-name", cluster, "--principal-arn", user)
        aws("eks", "create-access-entry", "--cluster-name", cluster, "--principal-arn", user)
        aws("eks", "associate-access-policy", "--cluster-name", cluster, "--principal-arn", user, "--policy-arn", edit_policy, "--access-scope", "type=namespace,namespaces=blue")
        kube("get", "pods", "-n", "blue", who=developer)
        aws("eks", "disassociate-access-policy", "--cluster-name", cluster, "--principal-arn", user, "--policy-arn", edit_policy)
        observed["revokedPolicyDenied"] = "Forbidden" in kube("get", "pods", "-n", "blue", who=developer, success=False)
        assert observed["revokedPolicyDenied"]
        kube("create", "rolebinding", "developer-view", "-n", "blue", "--clusterrole=view", "--group=developers")
        aws("eks", "update-access-entry", "--cluster-name", cluster, "--principal-arn", user, "--kubernetes-groups", "developers")
        observed["mutableGroupGranted"] = "echo" in kube("get", "pods", "-n", "blue", who=developer)
        assert observed["mutableGroupGranted"]
        aws("eks", "update-access-entry", "--cli-input-json", json.dumps({"clusterName": cluster, "principalArn": user, "kubernetesGroups": []}))
        observed["mutableGroupRevoked"] = "Forbidden" in kube("get", "pods", "-n", "blue", who=developer, success=False)
        assert observed["mutableGroupRevoked"]
        aws("eks", "delete-access-entry", "--cluster-name", cluster, "--principal-arn", user)
        observed["deletedEntryDenied"] = bool(kube("get", "pods", "-n", "blue", who=developer, success=False))
        update = aws("eks", "update-cluster-config", "--name", cluster, "--deletion-protection")["update"]["id"]
        wait_for(lambda: aws("eks", "describe-update", "--name", cluster, "--update-id", update)["update"]["status"] == "Successful")
        aws("eks", "delete-cluster", "--name", cluster, success=False)
        update = aws("eks", "update-cluster-config", "--name", cluster, "--no-deletion-protection")["update"]["id"]
        wait_for(lambda: aws("eks", "describe-update", "--name", cluster, "--update-id", update)["update"]["status"] == "Successful")
        aws("eks", "delete-cluster", "--name", cluster)
        wait_for(lambda: cluster not in aws("eks", "list-clusters")["clusters"])
        observed["clusterDeleted"] = True
        stop()
        docker_env = dict(env, DOCKER_HOST=args.docker_host)
        remaining = command(["docker", "ps", "-a", "--filter", f"label=stackd.eks.id={native_id}", "--format", "{{.ID}}"], docker_env).strip()
        observed["ownedContainersAfterDelete"] = remaining.splitlines()
        assert not remaining
        for kind in ["network", "volume"]:
            remaining = command(["docker", kind, "ls", "--filter", f"label=stackd.eks.id={native_id}", "--format", "{{.Name}}"], docker_env).strip()
            observed[f"owned{kind.title()}sAfterDelete"] = remaining.splitlines()
            assert not remaining
        Path(args.evidence).write_text(json.dumps(observed, indent=2) + "\n")
        print(json.dumps(observed, indent=2))
        shutil.rmtree(root)
    except BaseException as error:
        observed["failure"] = {"type": type(error).__name__, "message": str(error)}
        observed["diagnosticDirectory"] = str(root)
        Path(args.evidence).write_text(json.dumps(observed, indent=2) + "\n")
        raise
    finally:
        stop()
        log.close()
        if root.exists():
            print(f"retained exact-owned diagnostic directory: {root}")


if __name__ == "__main__":
    main()
