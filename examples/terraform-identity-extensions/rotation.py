"""Actual Lambda rotation and retained application-password consumers.

This application is a fixture consumer, not an AWS service replacement. It stores
an authenticated password in a private SQLite database and changes it atomically.
"""
import contextlib
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import threading
import time
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener
import zipfile

from local import client, environment, expect_missing, require

HTTP = build_opener(ProxyHandler({}))
HERE = Path(__file__).resolve().parent


def private_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def prepare(root, port, docker_host):
    directory = root / "rotation"
    directory.mkdir(mode=0o700)
    config = {"username": "fixture-consumer", "password": secrets.token_urlsafe(36),
              "port": port, "docker_host": docker_host}
    private_json(directory / "application.json", config)
    salt = secrets.token_bytes(32)
    digest = hashlib.pbkdf2_hmac("sha256", config["password"].encode(), salt, 100_000)
    with sqlite3.connect(directory / "application.sqlite") as database:
        database.execute("CREATE TABLE credential (username TEXT PRIMARY KEY, salt BLOB NOT NULL, digest BLOB NOT NULL)")
        database.execute("INSERT INTO credential VALUES (?, ?, ?)", (config["username"], salt, digest))
    (directory / "application.sqlite").chmod(0o600)
    with zipfile.ZipFile(root / "rotation.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        member = zipfile.ZipInfo("rotation_handler.py", (2026, 1, 1, 0, 0, 0))
        member.external_attr = 0o100644 << 16
        archive.writestr(member, (HERE / "rotation_handler.py").read_bytes())
    return {"rotation_app_user": config["username"], "rotation_app_password": config["password"],
            "rotation_app_endpoint": f"http://host.docker.internal:{port}"}


@contextlib.contextmanager
def startup(root):
    directory = root / "rotation"
    config = json.loads((directory / "application.json").read_text())

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Passwords and request bodies must not enter a public log.

        def do_POST(self):
            status, result = 400, {"error": "InvalidRequest"}
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 8192 or self.path not in {"/authenticate", "/change-password"}:
                    raise ValueError("Invalid application request")
                payload = json.loads(self.rfile.read(length))
                username, password = payload["username"], payload["password"]
                if not isinstance(username, str) or not isinstance(password, str):
                    raise ValueError("Invalid credential")
                with sqlite3.connect(directory / "application.sqlite", timeout=10) as database:
                    database.execute("BEGIN IMMEDIATE")
                    row = database.execute("SELECT salt, digest FROM credential WHERE username=?", (username,)).fetchone()
                    valid = row is not None and hmac.compare_digest(
                        hashlib.pbkdf2_hmac("sha256", password.encode(), row[0], 100_000), row[1])
                    if not valid:
                        status, result = 401, {"authenticated": False}
                    elif self.path == "/authenticate":
                        status, result = 200, {"authenticated": True}
                    else:
                        replacement = payload["new_password"]
                        if not isinstance(replacement, str) or not 20 <= len(replacement) <= 1024:
                            raise ValueError("Invalid replacement password")
                        salt = secrets.token_bytes(32)
                        digest = hashlib.pbkdf2_hmac("sha256", replacement.encode(), salt, 100_000)
                        database.execute("UPDATE credential SET salt=?, digest=? WHERE username=?", (salt, digest, username))
                        status, result = 200, {"changed": True}
            except (ValueError, KeyError, TypeError, json.JSONDecodeError):
                pass
            body = json.dumps(result).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    # A concrete owned listener is required for Docker's host gateway. Bind fails
    # rather than reusing an existing application or selecting a remote service.
    server = ThreadingHTTPServer(("0.0.0.0", config["port"]), Handler)
    server.daemon_threads = False
    thread = threading.Thread(target=server.serve_forever, name="owned-rotation-consumer")
    thread.start()
    try:
        yield
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
        require(not thread.is_alive(), "Owned application listener did not stop")


def authenticate(root, payload, expected=True):
    config = json.loads((root / "rotation/application.json").read_text())
    request = Request(f"http://127.0.0.1:{config['port']}/authenticate", data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"})
    try:
        with HTTP.open(request, timeout=10) as response:
            result = json.load(response)
        require(expected and result["authenticated"], "Application accepted an unexpected password")
    except HTTPError as error:
        require(not expected and error.code == 401, f"Application password check failed: HTTP{error.code}")



def native(root, out, kind):
    config = json.loads((root / "rotation/application.json").read_text())
    arguments = ["ps", "--all"] if kind == "containers" else ["volume", "ls"]
    return subprocess.check_output(
        ["docker", "--host", config["docker_host"], *arguments, "--quiet",
         "--filter", "label=io.stackd.function=" + out["function_arn"]],
        env=environment(), text=True).split()

def verify(endpoint, out, revision, root):
    manager, kms, functions, iam, logs = (client(name, endpoint) for name in
                                        ("secretsmanager", "kms", "lambda", "iam", "logs"))
    deadline, current = time.monotonic() + 240, None
    while time.monotonic() < deadline:
        current = manager.get_secret_value(SecretId=out["secret"])
        payload = json.loads(current["SecretString"])
        metadata = manager.describe_secret(SecretId=out["secret"])
        if payload.get("revision") == revision and metadata.get("LastRotatedDate"):
            break
        time.sleep(0.5)
    else:
        raise RuntimeError("Real four-step rotation did not complete; inspect owned stackd.log and Lambda logs")
    require(payload["token"] == current["VersionId"], "finishSecret did not promote its actual pending credential")
    prefix = f"arn:aws:sts::{out['function_arn'].split(':')[4]}:assumed-role/{out['role']}/"
    require(payload["execution_arn"].startswith(prefix), "Secret bytes lack the real Lambda-role execution receipt")
    authenticate(root, payload)
    directory = root / "rotation"
    seed = json.loads((directory / "application.json").read_text())
    authenticate(root, seed, expected=False)
    prior_path = directory / "evidence.json"
    prior = json.loads(prior_path.read_text()) if prior_path.exists() else None
    if prior is not None:
        retained = manager.get_secret_value(SecretId=out["secret"], VersionId=prior["version"])
        require(retained["SecretString"] == prior["bytes"], "Reopen/update changed historical encrypted password bytes")
        authenticate(root, json.loads(prior["bytes"]), expected=prior["version"] == current["VersionId"])
    require(metadata["RotationLambdaARN"] == out["function_arn"] and metadata["RotationEnabled"], "Rotation ownership changed")
    require(metadata["RotationRules"]["AutomaticallyAfterDays"] == (30 if revision == "v1" else 31), "Rotation schedule update was not retained")

    def probe():
        response = functions.invoke(FunctionName=out["function"], InvocationType="RequestResponse",
                                    Payload=json.dumps({"Probe": True}).encode())
        try:
            body = response["Payload"].read()
        finally:
            response["Payload"].close()
        return response, body

    response, body = probe()
    require(not response.get("FunctionError") and json.loads(body)["authenticated"], "Current Lambda role cannot consume actual password bytes")
    kms.disable_key(KeyId=out["key"])
    try:
        expect_missing(manager.get_secret_value, {"DecryptionFailure"}, SecretId=out["secret"])
        response, body = probe()
        require(response.get("FunctionError") and b"DecryptionFailure" in body, "Disabled KMS key did not reject real Lambda secret decryption")
    finally:
        kms.enable_key(KeyId=out["key"])
    deny = "owned-current-rotation-deny"
    iam.put_role_policy(RoleName=out["role"], PolicyName=deny, PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "secretsmanager:GetSecretValue", "Resource": out["secret"]}]}))
    try:
        response, body = probe()
        require(response.get("FunctionError") and b"AccessDenied" in body, "Current explicit role deny did not stop a warm real Lambda consumer")
    finally:
        iam.delete_role_policy(RoleName=out["role"], PolicyName=deny)
    response, body = probe()
    require(not response.get("FunctionError") and json.loads(body)["authenticated"], "Role/key restoration did not recover real Lambda consumption")

    # Real function output is independently projected through its log owner.
    stages = set()
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        for row in logs.filter_log_events(logGroupName=out["log_group"]).get("events", []):
            text = row.get("message", "")
            start = text.find('{"rotation_step"')
            if start >= 0:
                try:
                    receipt = json.loads(text[start:])
                except json.JSONDecodeError:
                    continue
                if receipt.get("token") == current["VersionId"] and receipt.get("execution_arn", "").startswith(prefix):
                    stages.add(receipt["rotation_step"])
        if stages == {"createSecret", "setSecret", "testSecret", "finishSecret"}:
            break
        time.sleep(0.5)
    require(stages == {"createSecret", "setSecret", "testSecret", "finishSecret"}, f"Missing real callback execution logs: {stages}")
    containers, volumes = native(root, out, "containers"), native(root, out, "volumes")
    require(containers and volumes, "Real Lambda callbacks left no owned runtime containers or volumes")
    private_json(prior_path, {"version": current["VersionId"], "bytes": current["SecretString"], "revision": revision,
                              "stages": sorted(stages), "restored_consumer": True,
                              "containers": sorted(set(containers) | set(prior.get("containers", []) if prior else [])),
                              "volumes": sorted(set(volumes) | set(prior.get("volumes", []) if prior else []))})
    print(f"Rotation consumer complete: {revision}; real Lambda role, four callbacks, changed application password, KMS/current-IAM denial", flush=True)


def imports(resources):
    names = {"aws_kms_key.rotation", "aws_secretsmanager_secret.rotation", "aws_secretsmanager_secret_version.seed",
             "aws_iam_role.rotation", "aws_iam_role_policy.rotation", "aws_cloudwatch_log_group.rotation",
             "aws_lambda_function.rotation", "aws_lambda_permission.rotation", "aws_secretsmanager_secret_rotation.rotation"}
    result = {}
    for item in resources:
        if item["address"] not in names:
            continue
        values = item["values"]
        identifier = values["id"]
        if item["type"] == "aws_lambda_permission":
            identifier = values["function_name"] + "/" + values["statement_id"]
        result[item["address"]] = identifier
    return result


def verify_deleted(endpoint, out, root):
    expect_missing(client("secretsmanager", endpoint).describe_secret, {"ResourceNotFoundException"}, SecretId=out["secret"])
    expect_missing(client("lambda", endpoint).get_function, {"ResourceNotFoundException"}, FunctionName=out["function"])
    expect_missing(client("iam", endpoint).get_role, {"NoSuchEntity"}, RoleName=out["role"])
    expect_missing(client("logs", endpoint).describe_log_streams, {"ResourceNotFoundException"}, logGroupName=out["log_group"])
    metadata = client("kms", endpoint).describe_key(KeyId=out["key"])["KeyMetadata"]
    require(metadata["KeyState"] == "PendingDeletion", "Rotation key teardown falsely removed or kept an enabled key")
    # The non-AWS application deliberately retains its last credential until its
    # owned process/database are closed; Terraform secret deletion is not an app reset.
    retained = json.loads((root / "rotation/evidence.json").read_text())
    authenticate(root, json.loads(retained["bytes"]))
    deadline = time.monotonic() + 180
    while True:
        containers, volumes = native(root, out, "containers"), native(root, out, "volumes")
        if not containers and not volumes:
            break
        require(time.monotonic() < deadline, f"Deleted Lambda still owns native resources: {containers}, {volumes}")
        time.sleep(0.5)
    private_json(root / "rotation/native-absence.json",
                 {"function_arn": out["function_arn"], "containers": containers, "volumes": volumes,
                  "retained_container_ids": retained["containers"], "retained_volumes": retained["volumes"]})
    print("Rotation teardown complete: secret/function/role/logs absent; real KMS deletion scheduled", flush=True)
