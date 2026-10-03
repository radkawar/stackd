"""Real aws-auth, migration, wildcard RBAC and impersonation executable proof."""
import base64
import json
import ssl
import urllib.error
import urllib.request


def exercise_access(aws, kube, env, cluster, account, command, restart, observed):
    def denied(*args, who, unauthorized=False):
        result = kube(*args, who=who, success=False)
        expected = ("Unauthorized" in result or "must be logged in" in result) if unauthorized else "Forbidden" in result
        assert expected, result

    def pods(namespace, who, *flags):
        kube(*flags, "get", "pods", "-n", namespace, "-o", "json", who=who)

    def user_credentials(name):
        arn = aws("iam", "create-user", "--user-name", name)["User"]["Arn"]
        key = aws("iam", "create-access-key", "--user-name", name)["AccessKey"]
        return arn, key, dict(env, AWS_ACCESS_KEY_ID=key["AccessKeyId"], AWS_SECRET_ACCESS_KEY=key["SecretAccessKey"])

    def recreate_user(name, key):
        aws("iam", "delete-access-key", "--user-name", name, "--access-key-id", key["AccessKeyId"])
        aws("iam", "delete-user", "--user-name", name)
        return user_credentials(name)

    def wait_update(mode):
        import time
        update = aws("eks", "update-cluster-config", "--name", cluster, "--access-config", "authenticationMode=" + mode)["update"]["id"]
        for _ in range(180):
            status = aws("eks", "describe-update", "--name", cluster, "--update-id", update)["update"]["status"]
            if status == "Successful":
                return
            assert status == "InProgress", status
            time.sleep(1)
        raise RuntimeError("authentication mode update timed out")

    assert aws("eks", "describe-cluster", "--name", cluster)["cluster"]["accessConfig"]["authenticationMode"] == "CONFIG_MAP"
    assert "Invalid" in aws("eks", "list-access-entries", "--cluster-name", cluster, success=False)
    for namespace in ["access-dev-one", "access-prod"]:
        kube("create", "namespace", namespace)
    kube("create", "rolebinding", "legacy-view", "-n", "access-dev-one", "--clusterrole=view", "--group=legacy-view")
    user, key, reader = user_credentials("eks-access-reader")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"}, "Action": "sts:AssumeRole"}]}
    role = aws("iam", "create-role", "--role-name", "eks-access-path-role", "--path", "/team/", "--assume-role-policy-document", json.dumps(trust))["Role"]["Arn"]
    session = aws("sts", "assume-role", "--role-arn", role, "--role-session-name", "role-session")["Credentials"]
    role_reader = dict(env, AWS_ACCESS_KEY_ID=session["AccessKeyId"], AWS_SECRET_ACCESS_KEY=session["SecretAccessKey"], AWS_SESSION_TOKEN=session["SessionToken"])
    pathless = role.replace(":role/team/", ":role/")

    def mapping(groups=("legacy-view",), mapped_role=pathless):
        config = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "aws-auth", "namespace": "kube-system"}, "data": {
            "mapUsers": json.dumps([{"userarn": user, "username": "legacy-reader", "groups": list(groups)}]),
            "mapRoles": json.dumps([{"rolearn": mapped_role, "username": "role:{{SessionNameRaw}}", "groups": ["legacy-view"]}]),
        }}
        kube("apply", "-f", "-", stdin=json.dumps(config))

    mapping()
    pods("access-dev-one", reader)
    denied("get", "pods", "-n", "access-prod", who=reader)
    pods("access-dev-one", role_reader)
    mapping(mapped_role=role)
    denied("get", "pods", "-n", "access-dev-one", who=role_reader, unauthorized=True)
    mapping(groups=())
    denied("get", "pods", "-n", "access-dev-one", who=reader)
    mapping()
    user, key, reader = recreate_user("eks-access-reader", key)
    pods("access-dev-one", reader)
    uid = json.loads(kube("get", "configmap", "aws-auth", "-n", "kube-system", "-o", "json"))["metadata"]["uid"]
    restart()
    assert json.loads(kube("get", "configmap", "aws-auth", "-n", "kube-system", "-o", "json"))["metadata"]["uid"] == uid
    pods("access-dev-one", reader)
    observed["awsAuthCurrentRolePathAndRestart"] = True

    wait_update("API_AND_CONFIG_MAP")
    entries = aws("eks", "list-access-entries", "--cluster-name", cluster)["accessEntries"]
    assert entries == [f"arn:aws:iam::{account}:root"], entries
    aws("eks", "create-access-entry", "--cluster-name", cluster, "--principal-arn", user, "--username", "api-reader")
    denied("get", "pods", "-n", "access-dev-one", who=reader)
    user, key, reader = recreate_user("eks-access-reader", key)
    denied("get", "pods", "-n", "access-dev-one", who=reader, unauthorized=True)
    aws("eks", "delete-access-entry", "--cluster-name", cluster, "--principal-arn", user)
    pods("access-dev-one", reader)
    aws("eks", "create-access-entry", "--cluster-name", cluster, "--principal-arn", user, "--username", "api-reader")
    edit = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSEditPolicy"

    def scope(namespaces):
        aws("eks", "associate-access-policy", "--cluster-name", cluster, "--principal-arn", user, "--policy-arn", edit, "--access-scope", json.dumps({"type": "namespace", "namespaces": namespaces}))

    scope(["access-dev-*"])
    pods("access-dev-one", reader)
    denied("get", "pods", "-n", "access-prod", who=reader)
    kube("create", "namespace", "access-dev-later")
    pods("access-dev-later", reader)
    scope(["access-dev-one"])
    denied("get", "pods", "-n", "access-dev-later", who=reader)
    scope(["does-not-exist-*"])
    denied("get", "pods", "-n", "access-dev-one", who=reader)
    scope(["access-dev-*"])
    observed["apiPrecedenceCurrentIdentityAndWildcardDiscovery"] = True

    # Edit lacks delegation permission. Cluster-admin can delegate, but an
    # unbound target still cannot list namespaces (native AWS capture).
    denied("--as=access-target", "get", "pods", "-n", "access-dev-one", who=reader)
    target_denial = kube("--as=access-target", "get", "namespaces", who=env, success=False)
    assert 'User "access-target"' in target_denial and "cannot list" in target_denial, target_denial
    objects = [
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": "access-impersonator"}, "rules": [
            {"apiGroups": [""], "resources": ["users"], "verbs": ["impersonate"], "resourceNames": ["access-target"]},
            {"apiGroups": [""], "resources": ["groups"], "verbs": ["impersonate"], "resourceNames": ["access-target-view"]},
            {"apiGroups": ["authentication.k8s.io"], "resources": ["uids"], "verbs": ["impersonate"], "resourceNames": ["access-uid"]},
            {"apiGroups": ["authentication.k8s.io"], "resources": ["userextras/example.com/project"], "verbs": ["impersonate"], "resourceNames": ["read"]},
        ]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "access-impersonator"}, "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "access-impersonator"}, "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "Group", "name": "api-impersonators"}]},
    ]
    kube("apply", "-f", "-", stdin=json.dumps({"apiVersion": "v1", "kind": "List", "items": objects}))
    kube("create", "rolebinding", "target-view", "-n", "access-dev-one", "--clusterrole=view", "--user=access-target", "--group=access-target-view")
    # The EKS-only administrator may impersonate a bound user without its own
    # native RBAC impersonation binding. Its policy must not follow the target.
    pods("access-dev-one", env, "--as=access-target")
    denied("--as=access-target", "get", "secrets", "-n", "access-dev-one", who=env)
    observed["eksPolicyDelegationWithoutTargetPolicyInheritance"] = True
    aws("eks", "update-access-entry", "--cluster-name", cluster, "--principal-arn", user, "--kubernetes-groups", "api-impersonators")
    pods("access-dev-one", reader, "--as=access-target", "--as-group=access-target-view", "--as-uid=access-uid")
    denied("--as=access-target", "--as-group=system:masters", "get", "pods", "-n", "access-dev-one", who=reader)
    denied("--as=access-target", "--as-uid=wrong-uid", "get", "pods", "-n", "access-dev-one", who=reader)
    denied("--as=other-target", "get", "pods", "-n", "access-dev-one", who=reader)
    # The caller has edit authority here. The target has view only.
    kube("get", "secrets", "-n", "access-dev-one", who=reader)
    denied("--as=access-target", "get", "secrets", "-n", "access-dev-one", who=reader)
    denied("--as=access-target", "get", "pods", "-n", "access-dev-later", who=reader)

    current = aws("eks", "describe-cluster", "--name", cluster)["cluster"]
    tls = ssl.create_default_context(cadata=base64.b64decode(current["certificateAuthority"]["data"]).decode())

    def raw(headers, path="/api/v1/namespaces/access-dev-one/pods"):
        token = json.loads(command(["aws", "eks", "get-token", "--cluster-name", cluster, "--region", "us-east-1"], reader))["status"]["token"]
        request = urllib.request.Request(current["endpoint"] + path, headers=dict(headers, Authorization="Bearer " + token))
        try:
            with urllib.request.urlopen(request, context=tls, timeout=30) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    assert raw({"Impersonate-User": "access-target", "Impersonate-Extra-example.com%2Fproject": "read"}) == 200
    assert raw({"Impersonate-User": "access-target", "Impersonate-Extra-example.com%2Fproject": "write"}) == 403
    assert raw({"Impersonate-Group": "access-target-view"}) == 403
    assert raw({"X-Remote-User": "system:admin", "X-Remote-Group": "system:masters", "X-Forwarded-User": "system:admin"}, "/api/v1/namespaces/access-prod/secrets") == 403
    aws("eks", "update-access-entry", "--cli-input-json", json.dumps({"clusterName": cluster, "principalArn": user, "kubernetesGroups": []}))
    denied("--as=access-target", "get", "pods", "-n", "access-dev-one", who=reader)
    observed["nativeImpersonationUserGroupUIDExtrasAndTargetRBAC"] = True

    wait_update("API")
    denied("get", "pods", "-n", "access-dev-one", who=role_reader, unauthorized=True)
    restart()
    pods("access-dev-later", reader)
    denied("--as=access-target", "get", "pods", "-n", "access-dev-one", who=reader)
    assert "Invalid" in aws("eks", "update-cluster-config", "--name", cluster, "--access-config", "authenticationMode=API_AND_CONFIG_MAP", success=False)
    aws("eks", "disassociate-access-policy", "--cluster-name", cluster, "--principal-arn", user, "--policy-arn", edit)
    denied("get", "pods", "-n", "access-dev-one", who=reader)
    aws("eks", "delete-access-entry", "--cluster-name", cluster, "--principal-arn", user)
    aws("iam", "delete-access-key", "--user-name", "eks-access-reader", "--access-key-id", key["AccessKeyId"])
    aws("iam", "delete-user", "--user-name", "eks-access-reader")
    aws("iam", "delete-role", "--role-name", "eks-access-path-role")
    observed["authenticationMigrationAndRestartRevocation"] = True
