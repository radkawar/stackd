#!/usr/bin/env python3
"""Focused local Docker/API reproductions for CodeBuild review corrections.

Run with python3 -P, an explicit prebuilt stackd and a fresh owned state directory.
Reuses the existing smoke lifecycle, never contacts AWS, and records only fake
credential-presence booleans. --before records the three expected old failures.
"""
import argparse
import base64
import functools
import http.client
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import socketserver
import sqlite3
import ssl
import threading
import time
import zipfile

spec = importlib.util.spec_from_file_location("build_smoke", Path(__file__).with_name("ecr_codebuild_smoke.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


def eventually(check, description, timeout=40):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(.1)
    raise RuntimeError("observation deadline: " + description)


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect("/var/run/docker.sock")


class DockerProxy(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def forward(self):
        gate = self.server
        if self.command == "DELETE" and gate.source_id and gate.source_id in self.path:
            if gate.hold:
                gate.removal_requested.set()
                gate.release.wait(30)
                try:
                    self.send_error(500, "owned controlled removal interruption")
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            if gate.fail_removal:
                gate.removal_requested.set()
                self.send_error(500, "owned controlled removal failure")
                return
        native = UnixHTTP("localhost", timeout=180)
        try:
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            native.request(self.command, self.path, body=body,
                           headers={k: v for k, v in self.headers.items()
                                    if k.lower() not in {"connection", "host", "transfer-encoding"}})
            response = native.getresponse()
            data = response.read()
            self.send_response(response.status)
            for k, v in response.getheaders():
                if k.lower() not in {"connection", "content-length", "transfer-encoding"}:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            native.close()

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = forward


class ProxyServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    source_id = ""
    hold = False
    fail_removal = False


class GitServer(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.headers.get("Authorization") != self.server.authorization:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="owned-codebuild-review"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/repo/.git/info/refs"):
            self.server.requested.set()
            if not self.server.release.wait(90):
                self.send_error(504)
                return
        try:
            super().do_GET()
        except (BrokenPipeError, ConnectionResetError):
            pass


class Review(base.Smoke):
    def docker(self, *arguments, **kwargs):
        # Only the controller uses the interruptible Engine transport. Fixture
        # creation/inspection talks directly to the real daemon.
        return self.command(["docker", "--host", "unix:///var/run/docker.sock",
                             "--config", self.docker_config.name, *arguments], **kwargs)

    def setup(self):
        self.role_arn = "arn:aws:iam::" + base.ACCOUNT + ":role/" + self.role
        self.repository_arn = "arn:aws:ecr:" + base.REGION + ":" + base.ACCOUNT + ":repository/unused"
        self.image = base.BASE_IMAGE
        self.setup_project()
        cb = self.clients["codebuild"]
        cb.update_project(name=self.project, source={"type": "NO_SOURCE", "buildspec": self.output_spec(False)})
        self.secret = self.client("secretsmanager").create_secret(Name=self.prefix, SecretString=json.dumps({"username": "owned", "password": "fake-local-review-token"}))["ARN"]
        self.clients["iam"].put_role_policy(RoleName=self.role, PolicyName="source-review", PolicyDocument=base.policy([
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": self.secret}]))

    def source_admission(self):
        cb = self.clients["codebuild"]
        capture = json.loads((Path(__file__).resolve().parents[1] / "testdata/aws/codebuild/stackd-source-authority-4cc3e6fa3b3d.json").read_text())
        observations = []
        def rejected(call, **parameters):
            try:
                call(**parameters)
            except self.client_error as error:
                base.require(error.response["Error"]["Code"] == "InvalidInputException", "unexpected source admission error")
                return
            raise RuntimeError("foreign public source authority admitted")
        for row in capture["observations"]:
            if row["operation"] != "UpdateProject" or row["parameters"]["source"]["type"] == "NO_SOURCE":
                continue
            source = row["parameters"]["source"]
            before = cb.batch_get_projects(names=[self.project])["projects"][0]["source"]
            if row["code"] == "Success":
                cb.update_project(name=self.project, source=source)
            else:
                rejected(cb.update_project, name=self.project, source=source)
                base.require(cb.batch_get_projects(names=[self.project])["projects"][0]["source"] == before, "rejected update changed source")
            observations.append({"case": row["case"], "code": row["code"]})
        for provider in ("GITHUB", "BITBUCKET", "GITLAB"):
            source = {"type": provider, "location": "https://foreign.example.invalid/owner/repository.git"}
            rejected(cb.create_project, name=self.project + "-invalid", serviceRole=self.role_arn,
                     source=source, artifacts={"type": "NO_ARTIFACTS"},
                     environment={"type": "LINUX_CONTAINER", "image": base.BASE_IMAGE, "computeType": "BUILD_GENERAL1_SMALL"})
            rejected(cb.start_build, projectName=self.project, sourceTypeOverride=provider, sourceLocationOverride=source["location"])
        base.require(not cb.list_builds_for_project(projectName=self.project)["ids"], "rejected source created a build")
        cb.update_project(name=self.project, source={"type": "NO_SOURCE", "buildspec": self.output_spec(False)})
        self.note("source_authority_api_admission", native_update_cases=observations,
                  foreign_create_and_start_providers=["GITHUB", "BITBUCKET", "GITLAB"],
                  rejected_code="InvalidInputException", imported_provider_credentials=0, remote_requests=0)

    def output_spec(self, selected):
        return json.dumps({"version": "0.2", "phases": {"build": {"commands": [
            "mkdir -p dist node_modules/.bin", "printf 'ordinary selected bytes\\n' > dist/result.txt",
            "ln -s /proc/1/environ node_modules/.bin/tool"]}},
            "artifacts": {"files": ["node_modules/.bin/tool" if selected else "dist/result.txt"]}})

    def begin(self, **kwargs):
        build = self.clients["codebuild"].start_build(projectName=self.project, **kwargs)["build"]
        self.build_ids.append(build["id"])
        return build

    def terminal(self, build):
        return eventually(lambda: (b if (b := self.build(build["id"]))["buildStatus"] in base.TERMINAL else None), "terminal build")

    def cleanup_pending(self, build):
        with sqlite3.connect(self.state / "stackd.sqlite") as db:
            return db.execute("select cleanup_pending from codebuild_builds where build_id=?", (build["id"],)).fetchone()[0]

    def owned(self, build):
        return self.docker("ps", "-aq", "--filter", "label=stackd.codebuild.arn=" + build["arn"]).stdout.decode().split()

    def artifacts(self):
        for selected in (False, True):
            build = self.begin(buildspecOverride=self.output_spec(selected))
            result = self.terminal(build)
            contexts = [c.get("message", "") for p in result["phases"] for c in p.get("contexts", [])]
            expected = "FAILED" if selected or self.args.before else "SUCCEEDED"
            base.require(result["buildStatus"] == expected, "unexpected symlink artifact result")
            if expected == "FAILED":
                base.require(any("links and special files" in c for c in contexts), "missing explicit unsupported-link error")
            else:
                body = self.clients["s3"].get_object(Bucket=self.bucket, Key="artifacts/default.zip")["Body"].read()
                with zipfile.ZipFile(io.BytesIO(body)) as archive:
                    base.require(archive.namelist() == ["dist/result.txt"] and archive.read("dist/result.txt") == b"ordinary selected bytes\n", "incorrect actual artifact bytes")
            self.note("selected_link" if selected else "unrelated_link", status=result["buildStatus"], contexts=contexts,
                      actual_s3_bytes_verified=expected == "SUCCEEDED")

    def git_fixture(self):
        certdir = self.state / "git-fixture"
        certdir.mkdir()
        self.command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=host.docker.internal", "-addext", "subjectAltName=DNS:host.docker.internal", "-keyout", str(certdir / "key.pem"), "-out", str(certdir / "cert.crt")])
        (certdir / "Dockerfile").write_text("FROM " + base.TOOLKIT_IMAGE + "\nCOPY cert.crt /usr/local/share/ca-certificates/owned-review.crt\nRUN update-ca-certificates\n")
        self.git_image = self.prefix + ":git-review"
        self.image_tags.add(self.git_image)
        self.docker("build", "--pull=false", "--network=none", "-t", self.git_image, str(certdir))
        repo = certdir / "repo"
        self.command(["git", "init", str(repo)])
        (repo / "result.txt").write_text("admitted fleet bytes\n")
        self.command(["git", "-C", str(repo), "add", "result.txt"])
        self.command(["git", "-C", str(repo), "-c", "user.name=Owned Review", "-c", "user.email=owned@example.invalid", "commit", "-m", "Owned source"])
        self.command(["git", "-C", str(repo), "update-server-info"])
        # Dumb HTTP serves the real Git object database, not generated build results.
        self.git = http.server.ThreadingHTTPServer(("0.0.0.0", 0), functools.partial(GitServer, directory=str(certdir)))
        self.git.authorization = "Basic " + base64.b64encode(b"owned:fake-local-review-token").decode()
        self.git.requested, self.git.release = threading.Event(), threading.Event()
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(certdir / "cert.crt", certdir / "key.pem")
        self.git.socket = tls.wrap_socket(self.git.socket, server_side=True)
        threading.Thread(target=self.git.serve_forever, daemon=True).start()
        self.git_url = "https://host.docker.internal:" + str(self.git.server_port) + "/repo/.git"
        self.clients["codebuild"].update_project(name=self.project,
            source={"type": "GITHUB_ENTERPRISE", "location": self.git_url, "auth": {"type": "SECRETS_MANAGER", "resource": self.secret},
                    "buildspec": json.dumps({"version": "0.2", "phases": {"build": {"commands": ["cat result.txt"]}}, "artifacts": {"files": ["result.txt"]}})},
            environment={"type": "LINUX_CONTAINER", "image": self.git_image, "computeType": "BUILD_GENERAL1_SMALL", "imagePullCredentialsType": "SERVICE_ROLE"})

    def staged(self, build):
        base.require(self.git.requested.wait(30), "real Git never reached controlled authenticated slow server")
        ids = self.owned(build)
        base.require(len(ids) == 1, "expected only source staging container")
        native = json.loads(self.docker("inspect", ids[0]).stdout)[0]
        base.require(native["State"]["Running"] and native["Config"]["Labels"].get("stackd.codebuild.source") == "true", "not a live source process")
        base.require("GIT_SOURCE_PASSWORD=fake-local-review-token" in native["Config"]["Env"], "source token absent")
        base.require(self.build(build["id"])["currentPhase"] == "DOWNLOAD_SOURCE", "source not admitted")
        return native["Id"]

    def crash_source(self, proxy):
        build = self.begin()
        proxy.source_id = self.staged(build)
        proxy.hold = True
        stop_errors = []
        def request_stop():
            try:
                self.clients["codebuild"].stop_build(id=build["id"])
            except Exception as error:
                stop_errors.append(type(error).__name__)
        caller = threading.Thread(target=request_stop)
        caller.start()
        base.require(proxy.removal_requested.wait(10), "cancellation did not attempt native staging removal")
        self.stop(crash=True)
        caller.join(timeout=20)
        base.require(not caller.is_alive(), "disconnected StopBuild caller remained")
        proxy.hold, proxy.fail_removal = False, True
        proxy.release.set()
        proxy.removal_requested.clear()
        self.start()
        result = self.terminal(build)
        base.require(result["buildStatus"] == "STOPPED", "stopped build not recovered")
        if self.args.before:
            eventually(lambda: self.cleanup_pending(build) == 0, "old cleanup marked complete")
            base.require(self.owned(build), "old orphan did not survive")
        else:
            base.require(proxy.removal_requested.wait(10), "recovery never removed staging")
            base.require(self.cleanup_pending(build) == 1 and self.owned(build), "real removal error lost cleanup intent")
        retained = json.loads(self.docker("inspect", proxy.source_id).stdout)[0]
        base.require(retained["State"]["Running"], "controlled Git process exited before cleanup observation")
        self.note("source_crash_reopen_removal_error", status=result["buildStatus"], cleanup_pending=bool(self.cleanup_pending(build)),
                  owned_staging_remaining=bool(self.owned(build)), fake_token_present_before_crash=True,
                  source_process_running=retained["State"]["Running"],
                  controller_signal="SIGKILL", disconnected_stop_errors=stop_errors)
        proxy.fail_removal = False
        if self.args.before:
            self.docker("rm", "-f", proxy.source_id)
        else:
            eventually(lambda: not self.owned(build) and not self.cleanup_pending(build), "staging and credentials removed")
        self.note("source_crash_cleanup", controller_removed=not self.args.before, remaining_containers=len(self.owned(build)))
        self.git.release.set()

    def fleet_drain(self):
        self.git.requested.clear()
        self.git.release.clear()
        cb = self.clients["codebuild"]
        self.fleet_arn = cb.create_fleet(name=self.prefix, baseCapacity=1, environmentType="LINUX_CONTAINER", computeType="BUILD_GENERAL1_SMALL")["fleet"]["arn"]
        self.created.add("fleet")
        self.wait_fleet(self.fleet_arn, "ACTIVE")
        build = self.begin(fleetOverride={"fleetArn": self.fleet_arn})
        self.staged(build)
        cb.delete_fleet(arn=self.fleet_arn)
        if self.args.before:
            self.wait_fleet(self.fleet_arn, "DELETED")
            self.created.discard("fleet")
        else:
            self.wait_fleet(self.fleet_arn, "DELETING")
            time.sleep(1)
            base.require(cb.batch_get_fleets(names=[self.fleet_arn])["fleets"][0]["status"]["statusCode"] == "DELETING", "admitted source lost its fleet")
        self.git.release.set()
        result = self.terminal(build)
        expected = "FAILED" if self.args.before else "SUCCEEDED"
        self.note("admitted_source_fleet_observed", status=result["buildStatus"],
                  contexts=[c.get("message", "") for p in result["phases"] for c in p.get("contexts", [])])
        base.require(result["buildStatus"] == expected, "admitted fleet build did not drain")
        contexts = [c.get("message", "") for p in result["phases"] for c in p.get("contexts", [])]
        if self.args.before:
            base.require(any("fleet capacity does not exist" in c.lower() for c in contexts), "unexpected fleet failure")
        else:
            body = self.clients["s3"].get_object(Bucket=self.bucket, Key="artifacts/default.zip")["Body"].read()
            with zipfile.ZipFile(io.BytesIO(body)) as archive:
                base.require(archive.read("result.txt") == b"admitted fleet bytes\n", "fleet artifact changed")
        self.wait_fleet(self.fleet_arn, "DELETED")
        self.created.discard("fleet")
        self.note("admitted_source_fleet_deletion", status=result["buildStatus"], contexts=contexts, fleet_deleted_after_drain=not self.args.before)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--before", action="store_true")
    parser.add_argument("--skip-artifacts", action="store_true")
    args = parser.parse_args()
    args.docker_host = "unix:///var/run/docker.sock"
    args.lambda_telemetry_directory = str(Path(args.binary).resolve().parent)
    args.ecr_scanner = None
    args.keep_resources = False
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError
    os.umask(0o077)
    smoke = Review(args, boto3, Config, ClientError)
    proxy = None
    passed = False
    try:
        smoke.prepare()
        proxy = ProxyServer(str(smoke.state / "docker.sock"), DockerProxy)
        proxy.removal_requested, proxy.release = threading.Event(), threading.Event()
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        args.docker_host = "unix://" + str(smoke.state / "docker.sock")
        smoke.start()
        smoke.setup()
        if not args.before:
            smoke.source_admission()
        if not args.skip_artifacts:
            smoke.artifacts()
        smoke.git_fixture()
        smoke.crash_source(proxy)
        smoke.fleet_drain()
        passed = True
    except Exception as error:
        if smoke.owns_state:
            smoke.note("failure", error=smoke.safe_error(error))
        else:
            raise
    finally:
        if hasattr(smoke, "git"):
            smoke.git.release.set()
            smoke.git.shutdown()
            smoke.git.server_close()
        if proxy:
            proxy.hold = proxy.fail_removal = False
            proxy.release.set()
        args.docker_host = "unix:///var/run/docker.sock"
        if hasattr(smoke, "secret") and smoke.process:
            smoke.client("secretsmanager").delete_secret(SecretId=smoke.secret, ForceDeleteWithoutRecovery=True)
            smoke.clients["iam"].delete_role_policy(RoleName=smoke.role, PolicyName="source-review")
        smoke.cleanup()
        if proxy:
            proxy.shutdown()
            proxy.server_close()
    smoke.note("result", passed=passed and not smoke.cleanup_errors, mode="before" if args.before else "after", cleanup_errors=smoke.cleanup_errors)
    return 0 if passed and not smoke.cleanup_errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
