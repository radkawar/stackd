"""Observe a source edit through real Docker-backed signed Lambda invocations."""

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local import (ACCOUNT, REGION, arguments, client, controller, expect_missing,
                   require, workspace)

STORAGE = "ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc"
RUNTIMES = {
    "x86_64": "public.ecr.aws/lambda/python@sha256:e369e098d9db9eafa3238fe827e4756e2016159908b9426b78e2051c08f647e3",
    "arm64": "public.ecr.aws/lambda/python@sha256:6a1d5d5815a9e754969f1c14f0f6a3ef14a8b094db25e16c1ad5bccc4ee4b99e",
}


def wait_active(lambdas, name):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        config = lambdas.get_function_configuration(FunctionName=name)
        require(config["State"] != "Failed", f"Runtime preparation failed: {config}")
        if config["State"] == "Active":
            return config
        time.sleep(0.5)
    raise RuntimeError("Function never became Active")


def main():
    parser = arguments(__doc__, 14663)
    parser.add_argument("--docker-host", default=os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock"))
    parser.add_argument("--architecture", choices=RUNTIMES, default="x86_64")
    parser.add_argument("--desktop", action="store_true", help="Use Docker Desktop Runtime API callback DNS")
    args = parser.parse_args()
    require(args.docker_host.startswith("unix:///"),
            "This bind-mount example requires a local Linux/ Desktop Unix Docker socket")
    docker = ["docker", "--host", args.docker_host]
    # Inspection is deliberate: missing images are prerequisites, never implicit pulls.
    for image in (STORAGE, RUNTIMES[args.architecture]):
        inspected = json.loads(subprocess.check_output(docker + ["image", "inspect", image], text=True))[0]
        require(inspected["Os"] == "linux", f"Not a Linux image: {image}")
        if image == RUNTIMES[args.architecture]:
            architecture = "amd64" if args.architecture == "x86_64" else "arm64"
            require(inspected["Architecture"] == architecture,
                    f"Image architecture does not match {args.architecture}")
    helpers = args.stackd.resolve().parent
    helper = helpers / f"lambda-telemetry-{'amd64' if args.architecture == 'x86_64' else 'arm64'}"
    require(helper.is_file(), f"Missing Linux telemetry helper {helper}; run make build")
    root = workspace(args, "lambda-reload")
    code = root / "code"
    code.mkdir(mode=0o755)
    source = (Path(__file__).resolve().parent / "handler.py").read_text()
    handler = code / "handler.py"
    handler.write_text(source)
    handler.chmod(0o644)
    name = "stackd-reload-" + uuid.uuid4().hex[:12]
    arn = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{name}"
    extra = ["-docker-host", args.docker_host, "-lambda-runtime",
             "-compute-endpoint", f"http://host.docker.internal:{args.port}",
             "-lambda-telemetry-directory", str(helpers),
             "-lambda-hot-reload-code", f"{arn}={code}"]
    if args.desktop:
        extra += ["-lambda-callback-host", "host.docker.internal"]
    with controller(args, root, extra, containers=True) as endpoint:
        iam, lambdas = client("iam", endpoint), client("lambda", endpoint)
        role_created = function_created = False
        try:
            role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17", "Statement": [{"Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))["Role"]
            role_created = True
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
                # Distinguish the uploaded artifact from the mounted live source.
                package.writestr("handler.py", source.replace('MESSAGE = "first"', 'MESSAGE = "uploaded"'))
            lambdas.create_function(FunctionName=name, Role=role["Arn"], Runtime="python3.12",
                                    Handler="handler.invoke", Architectures=[args.architecture],
                                    Code={"ZipFile": archive.getvalue()}, Timeout=15, MemorySize=256)
            function_created = True
            before = wait_active(lambdas, name)
            require(before["FunctionArn"] == arn, "Created function ARN differs from mount mapping")

            def invoke():
                response = lambdas.invoke(FunctionName=name, InvocationType="RequestResponse",
                                          Payload=json.dumps({"message": "signed SDK request"}).encode())
                stream = response["Payload"]
                try:
                    payload = stream.read()
                finally:
                    stream.close()
                require(response["StatusCode"] == 200 and not response.get("FunctionError"),
                        f"Actual Lambda runtime error: {response.get('FunctionError')} {payload!r}")
                result = json.loads(payload)
                require(result["echo"] == "signed SDK request" and result["function_arn"] == arn
                        and result["function_version"] == "$LATEST", f"Unexpected invocation: {result}")
                return result

            first = invoke()
            require(first["message"] == "first", f"Live mount did not replace uploaded code: {first}")
            warm = invoke()
            require(warm == first, "Unchanged source did not retain the warm runtime and /tmp")
            # Atomic publication happens only in the new owned directory, never in this checkout.
            changed = code / "handler.next"
            changed.write_text(source.replace('MESSAGE = "first"', 'MESSAGE = "second-edited"'))
            changed.chmod(0o644)
            changed.replace(handler)
            deadline = time.monotonic() + 30
            while True:
                time.sleep(0.6)  # Watcher coalesces notifications for 500 ms; invocation is the proof.
                second = invoke()
                if second["message"] == "second-edited":
                    break
                require(time.monotonic() < deadline, f"Source edit was not observed by the runtime: {second}")
            require(second["boot_id"] != first["boot_id"], "Source changed without real runtime reinitialization")
            require(second["tmp_id"] == first["tmp_id"], "Reload lost keeper-owned /tmp")
            after = lambdas.get_function_configuration(FunctionName=name)
            for field in ("FunctionArn", "CodeSha256", "RevisionId", "LastModified"):
                require(after[field] == before[field], f"Reload mutated AWS deployment field {field}")
            evidence = {"before": first, "after": second,
                        "unchanged_deployment": {field: after[field] for field in
                            ("FunctionArn", "CodeSha256", "RevisionId", "LastModified")}}
            (root / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
            print(json.dumps(evidence, indent=2), flush=True)
        finally:
            if function_created:
                lambdas.delete_function(FunctionName=name)
                expect_missing(lambdas.get_function, {"ResourceNotFoundException"}, FunctionName=name)
            if role_created:
                iam.delete_role(RoleName=name)
                expect_missing(iam.get_role, {"NoSuchEntity"}, RoleName=name)
    print(f"Real reload and resource deletion complete; controller stopped. Owned artifacts: {root}")


if __name__ == "__main__":
    main()
