"""Real EKS logging/version assertions shared by the exact-owned executable probe.

No mock API or generated log messages: observations come from kubectl and Logs.
The parent probe owns process restart, exact resource cleanup and evidence files.
"""
import json
import re
import time


CATEGORIES = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
PREFIXES = {
    "api": "kube-apiserver-",
    "audit": "kube-apiserver-audit-",
    "authenticator": "authenticator-",
    "controllerManager": "kube-controller-manager-",
    "scheduler": "kube-scheduler-",
}


def create_flags():
    return ["--kubernetes-version", "1.32", "--logging", json.dumps({
        "clusterLogging": [{"types": CATEGORIES, "enabled": True}]
    })]


def log_events(aws, cluster):
    events = []
    token = None
    while True:
        flags = ["--log-group-name", f"/aws/eks/{cluster}/cluster"]
        if token:
            flags.extend(["--next-token", token])
        result = aws("logs", "filter-log-events", *flags)
        events.extend(result.get("events", []))
        following = result.get("nextToken")
        if not following or following == token:
            return events
        token = following


def wait_update(aws, wait_for, cluster, update_id):
    def completed():
        update = aws("eks", "describe-update", "--name", cluster,
                     "--update-id", update_id)["update"]
        if update["status"] in ("Failed", "Cancelled"):
            raise AssertionError(update)
        return update if update["status"] == "Successful" else None
    return wait_for(completed, 420)


def capture_logging(aws, wait_for, cluster, principal):
    caller = aws("iam", "get-user", "--user-name", principal.rsplit("/", 1)[-1])["User"]
    assert caller["Arn"] == principal, caller
    expected_uid = f"aws-iam-authenticator:{principal.split(':')[4]}:{caller['UserId']}"
    def delivered():
        events = log_events(aws, cluster)
        by_category = {category: [] for category in CATEGORIES}
        mapped = None
        mapped_message = None
        authenticated = None
        for event in events:
            stream = event["logStreamName"]
            for category, prefix in PREFIXES.items():
                if re.fullmatch(re.escape(prefix) + "[0-9a-f]{32}", stream):
                    by_category[category].append(event)
                    break
            try:
                message = json.loads(event["message"])
            except (ValueError, TypeError):
                continue
            if message.get("auditID") and message.get("impersonatedUser", {}).get("username") == principal:
                if message.get("stage") == "ResponseComplete" and "/namespaces/blue/" in message.get("requestURI", ""):
                    mapped = message
                    mapped_message = event["message"]
            if message.get("msg") == "access granted" and message.get("username") == principal:
                authenticated = message
        if not all(by_category.values()) or mapped is None or authenticated is None:
            return None
        # A real Kubernetes audit event must preserve both the native transport
        # identity and the IAM-mapped impersonated user; never overwrite user.
        assert mapped["user"]["username"] != mapped["impersonatedUser"]["username"], mapped
        assert mapped["impersonatedUser"]["uid"] == expected_uid, mapped
        assert mapped["impersonatedUser"]["extra"]["arn"] == [principal], mapped
        return {
            "streams": {category: sorted({event["logStreamName"] for event in rows}) for category, rows in by_category.items()},
            "mappedAudit": mapped,
            "mappedAuditMessage": mapped_message,
            "iamAuthenticator": authenticated,
            "nativeSources": {category: rows[0]["message"] for category, rows in by_category.items() if category not in ("audit", "authenticator")},
        }
    return wait_for(delivered, 180)


def native_version(kube):
    server = json.loads(kube("get", "--raw", "/version"))["gitVersion"]
    nodes = json.loads(kube("get", "nodes", "-o", "json"))["items"]
    assert not any(node["metadata"]["name"].endswith("-server-0") for node in nodes), nodes
    owned = [node for node in nodes if node["metadata"]["name"].startswith("k3d-stackd-") and node["metadata"]["name"].endswith("-agent-0")]
    assert len(owned) == 1, nodes
    return {"apiServer": server, "kubelet": owned[0]["status"]["nodeInfo"]["kubeletVersion"], "nodeUID": owned[0]["metadata"]["uid"]}


def upgrade(aws, kube, wait_for, cluster, observed):
    def workloads():
        pods = json.loads(kube("get", "pods", "-n", "blue", "-o", "json"))["items"]
        return {pod["metadata"]["name"]: {
            "uid": pod["metadata"]["uid"],
            "node": pod["spec"]["nodeName"],
            "containers": {container["name"]: {
                "id": container["containerID"],
                "restarts": container["restartCount"],
                "startedAt": container["state"]["running"]["startedAt"],
            } for container in pod["status"]["containerStatuses"]},
        } for pod in pods}

    before = native_version(kube)
    assert before["apiServer"] == before["kubelet"] == "v1.32.8+k3s1", before
    config = aws("eks", "describe-cluster", "--name", cluster)["cluster"]
    evidence = {"before": before, "workloadsBefore": workloads()}
    observed["nativeVersionUpgrade"] = evidence
    try:
        update = aws("eks", "update-cluster-version", "--name", cluster, "--kubernetes-version", "1.33")["update"]
        evidence["update"] = update
        evidence["update"] = wait_update(aws, wait_for, cluster, update["id"])
        after = native_version(kube)
        evidence["after"] = after
        evidence["workloadsAfter"] = workloads()
        # AWS upgrades the control plane separately from the data plane.
        assert after["apiServer"].startswith("v1.33."), after
        assert after["kubelet"] == before["kubelet"] and after["nodeUID"] == before["nodeUID"], (before, after)
        current = aws("eks", "describe-cluster", "--name", cluster)["cluster"]
        assert current["version"] == "1.33" and current["endpoint"] == config["endpoint"]
        assert current["certificateAuthority"] == config["certificateAuthority"]
        assert evidence["workloadsBefore"] == evidence["workloadsAfter"], evidence
        assert kube("exec", "-n", "blue", "deployment/echo", "--", "cat", "/www/index.html").strip() == "actual-eks-pod-output"
        return evidence
    except BaseException:
        for label, command in [
            ("nodesAtFailure", ("get", "nodes", "-o", "json")),
            ("podsAtFailure", ("get", "pods", "-n", "blue", "-o", "json")),
            ("eventsAtFailure", ("get", "events", "-n", "blue", "-o", "json")),
        ]:
            try:
                evidence[label] = json.loads(kube(*command))
            except Exception as capture_error:
                evidence[label] = {"captureError": str(capture_error)}
        raise


def assert_recovered_version(kube, expected):
    actual = native_version(kube)
    assert actual == expected, (actual, expected)
    return actual


def disable_and_reenable(aws, kube, wait_for, cluster):
    def configure(enabled):
        update = aws("eks", "update-cluster-config", "--name", cluster, "--logging", json.dumps({
            "clusterLogging": [{"types": ["audit", "authenticator"], "enabled": enabled}]
        }))["update"]
        return wait_update(aws, wait_for, cluster, update["id"])
    configure(False)
    kube("create", "configmap", "audit-disabled-proof", "-n", "blue", "--from-literal=state=disabled")
    # This bounded quiet interval follows observed successful disable; search only
    # for the unique operation performed afterwards, not unrelated prior events.
    time.sleep(5)
    assert not any("audit-disabled-proof" in event["message"] for event in log_events(aws, cluster))
    configure(True)
    kube("create", "configmap", "audit-enabled-proof", "-n", "blue", "--from-literal=state=enabled")
    found = wait_for(lambda: next((event for event in log_events(aws, cluster) if "audit-enabled-proof" in event["message"] and event["logStreamName"].startswith("kube-apiserver-audit-")), None), 120)
    kube("delete", "configmap", "audit-disabled-proof", "audit-enabled-proof", "-n", "blue")
    return {"disabledMarkerAbsent": True, "reenabledAudit": json.loads(found["message"])}


def assert_webhook_source(runtime_dir, native_id, logging_evidence, command,
                          docker_env, server, wait_for):
    """Prove observed CloudWatch bytes came from accepted native webhook payload."""
    import hashlib
    from pathlib import Path
    import struct

    directory = Path(runtime_dir) / hashlib.sha256(native_id.encode()).hexdigest()
    owner = json.loads((directory / "owner.json").read_text())
    assert owner["ID"] == native_id
    message = logging_evidence["mappedAuditMessage"].encode()
    audit_id = logging_evidence["mappedAudit"]["auditID"]

    def acknowledged_frame():
        retained = (directory / "audit.events").read_bytes()
        offset = 0
        while offset + 4 <= len(retained):
            size = struct.unpack_from(">I", retained, offset)[0]
            end = offset + 4 + size
            if end > len(retained):
                return None
            body = retained[offset + 4:end]
            if message in body:
                envelope = json.loads(body)
                assert envelope["apiVersion"] == "audit.k8s.io/v1"
                assert envelope["kind"] == "EventList"
                assert any(event["auditID"] == audit_id for event in envelope["items"])
                cursor = json.loads((directory / "log-cursor.json").read_text())
                if cursor["AuditOffset"] >= end:
                    return {"frameStart": offset, "frameEnd": end,
                            "acknowledgedByteCursor": cursor["AuditOffset"]}
            offset = end
        return None

    frame = wait_for(acknowledged_frame, 30)
    native_command = command(["docker", "inspect", "--format",
                              "{{json .Config.Cmd}}", server], docker_env)
    assert "audit-log-path=" not in native_command, native_command
    # The old audit stdout feed must not exist. Only the original webhook body
    # and its acknowledged frame can establish this capture's ingestion path.
    assert audit_id not in command(["docker", "logs", server], docker_env)
    return {"auditID": audit_id, "originalWebhookPayloadRetained": True,
            "duplicateStdoutBackendAbsent": True, **frame}
