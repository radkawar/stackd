"""Pinned Terraform Lambda/ECR apply, real consumers, refresh, import, update, destroy.

Requires official Terraform 1.15.9 or later, boto3, AWS provider 6.68.0 and installed
Lambda runtime/storage images plus telemetry helpers. Terraform creates its own
service-trusted execution role, policy and log group and destroys them after
the function. All runtime and Terraform evidence starts unverified.
"""
import base64
import contextlib
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import uuid
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from local import (ACCOUNT, arguments, client, controller, environment, expect_missing,
                   local_endpoint, require, workspace)

HERE = Path(__file__).resolve().parent
STORAGE = "ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc"
RUNTIMES = {
    "x86_64": "public.ecr.aws/lambda/python@sha256:e369e098d9db9eafa3238fe827e4756e2016159908b9426b78e2051c08f647e3",
    "arm64": "public.ecr.aws/lambda/python@sha256:6a1d5d5815a9e754969f1c14f0f6a3ef14a8b094db25e16c1ad5bccc4ee4b99e",
}


def package(root, revision):
    source = (HERE / "handler.py").read_text().replace('CODE_REVISION = "first"', f'CODE_REVISION = "{revision}"')
    # Stable ZIP timestamps make repeated Terraform plans meaningful.
    with zipfile.ZipFile(root / "function.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        member = zipfile.ZipInfo("handler.py", (2026, 1, 1, 0, 0, 0))
        member.external_attr = 0o100644 << 16
        archive.writestr(member, source)
    if not (root / "layer.zip").exists():
        with zipfile.ZipFile(root / "layer.zip", "w", zipfile.ZIP_DEFLATED) as archive:
            member = zipfile.ZipInfo("python/fixture_layer.py", (2026, 1, 1, 0, 0, 0))
            member.external_attr = 0o100644 << 16
            archive.writestr(member, 'LAYER_VALUE = "native-layer-bytes"\n')


def push_image(endpoint, repository, revision):
    """Real AWS blob uploads and OCI manifest publication; no empty repository."""
    ecr = client("ecr", endpoint)
    payload = b"native OCI binary consumer\x00\xff\n" + revision.encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        member = tarfile.TarInfo("payload.bin")
        member.size, member.mode, member.mtime = len(payload), 0o644, 0
        archive.addfile(member, io.BytesIO(payload))
    tar = buffer.getvalue()
    layer = gzip.compress(tar, mtime=0)
    digest = lambda data: "sha256:" + hashlib.sha256(data).hexdigest()
    config = json.dumps({"architecture": "amd64", "os": "linux",
                         "rootfs": {"type": "layers", "diff_ids": [digest(tar)]},
                         "config": {}, "history": []}, sort_keys=True, separators=(",", ":")).encode()

    def upload(blob):
        upload_id = ecr.initiate_layer_upload(repositoryName=repository)["uploadId"]
        ecr.upload_layer_part(repositoryName=repository, uploadId=upload_id,
                              partFirstByte=0, partLastByte=len(blob)-1, layerPartBlob=blob)
        completed = ecr.complete_layer_upload(repositoryName=repository, uploadId=upload_id,
                                              layerDigests=[digest(blob)])
        require(completed["layerDigest"] == digest(blob), "Layer upload returned the wrong digest")
        return digest(blob)

    config_digest, layer_digest = upload(config), upload(layer)
    manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                           "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                                      "digest": config_digest, "size": len(config)},
                           "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                                       "digest": layer_digest, "size": len(layer)}]},
                          sort_keys=True, separators=(",", ":"))
    image = ecr.put_image(repositoryName=repository, imageManifest=manifest, imageTag="dev-current")["image"]
    require(image["imageId"]["imageDigest"] == digest(manifest.encode()), "Published manifest digest mismatch")
    return {"digest": digest(manifest.encode()), "payload_base64": base64.b64encode(payload).decode(),
            "manifest": manifest, "revision": revision}


def main():
    parser = arguments(__doc__, 14707)
    parser.add_argument("--provider-mirror", type=Path, help="Filesystem mirror containing pinned AWS 6.68.0; no direct download")
    parser.add_argument("--endpoint", help="Existing parent-owned loopback controller; this runner never stops it")
    parser.add_argument("--docker-host", default=os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock"))
    parser.add_argument("--architecture", choices=RUNTIMES, default="x86_64")
    parser.add_argument("--desktop", action="store_true")
    args = parser.parse_args()
    require(shutil.which("terraform"), "Install official Terraform 1.15.9 or later first")
    env = environment()
    version = json.loads(subprocess.check_output(["terraform", "version", "-json"], env=env, text=True))
    require(tuple(map(int, version["terraform_version"].split("."))) >= (1, 15, 9),
            "This fixture requires official Terraform 1.15.9 or later")
    root = workspace(args, "terraform-lambda-ecr")
    root.chmod(0o700)  # State, role metadata and registry credentials are private.
    shutil.copyfile(HERE / "main.tf", root / "main.tf")
    shutil.copyfile(HERE.parent / ".terraform.lock.hcl", root / ".terraform.lock.hcl")
    cli = "disable_checkpoint = true\n"
    if args.provider_mirror is not None:
        require(args.provider_mirror.is_dir(), "Provider filesystem mirror is missing")
        cli += ("provider_installation {\n  filesystem_mirror {\n    path = "
                + json.dumps(str(args.provider_mirror.resolve()))
                + '\n    include = ["registry.terraform.io/hashicorp/aws"]\n  }\n}\n')
    (root / "terraform.rc").write_text(cli)
    env["TF_CLI_CONFIG_FILE"] = str(root / "terraform.rc")
    extra = ["-docker-host", args.docker_host, "-lambda-runtime",
             "-compute-endpoint", f"http://host.docker.internal:{args.port}",
             "-lambda-telemetry-directory", str(args.stackd.resolve().parent)]
    if args.desktop:
        extra += ["-lambda-callback-host", "host.docker.internal"]
    if args.endpoint is None:
        for image in (STORAGE, RUNTIMES[args.architecture]):
            inspected = json.loads(subprocess.check_output(["docker", "--host", args.docker_host,
                                                           "image", "inspect", image], text=True, env=env))[0]
            require(inspected["Os"] == "linux", f"Not a Linux runtime prerequisite: {image}")
            if image == RUNTIMES[args.architecture]:
                require(inspected["Architecture"] == ("amd64" if args.architecture == "x86_64" else "arm64"),
                        "Installed runtime has the wrong architecture")
        helper = args.stackd.resolve().parent / ("lambda-telemetry-amd64" if args.architecture == "x86_64" else "lambda-telemetry-arm64")
        require(helper.is_file(), f"Missing installed runtime helper: {helper}")

    def terraform(*command, capture=False, check=True):
        print("terraform", *command, flush=True)
        try:
            return subprocess.run(["terraform", *command], cwd=root, env=env, check=check,
                                  text=True, capture_output=capture)
        finally:
            for pattern in ("*.tfstate*", "*.tfplan", "*.json", "terraform.rc"):
                for path in root.glob(pattern):
                    if path.is_file():
                        path.chmod(0o600)

    require(args.endpoint is None, "This lifecycle requires an owned controller for reopen")
    with contextlib.ExitStack() as runtime:
        endpoint = runtime.enter_context(controller(args, root, extra=extra, containers=True))
        identity = client("sts", endpoint).get_caller_identity()
        require(identity["Account"] == ACCOUNT, f"Expected local fixture account {ACCOUNT}: {identity}")
        variables = {"endpoint": endpoint, "name": "stackd-lambda-ecr-" + uuid.uuid4().hex[:12],
                     "architecture": args.architecture, "revision": "first", "include_image": False}

        def save_variables():
            (root / "local.auto.tfvars.json").write_text(json.dumps(variables))
            (root / "local.auto.tfvars.json").chmod(0o600)

        def outputs():
            output = json.loads(terraform("output", "-json", "application", capture=True).stdout)
            path = root / (output["revision"] + "-outputs.json")
            path.write_text(json.dumps(output, indent=2) + "\n")
            path.chmod(0o600)
            return output, path

        def consumer(output_path, image_path, previous_path=None):
            command = [sys.executable, str(HERE / "consumer.py"), endpoint, str(output_path), str(image_path)]
            if previous_path is not None:
                command.append(str(previous_path))
            authentication = root / "authentication"
            authentication.mkdir(mode=0o700, exist_ok=True)
            shutil.copyfile(HERE / "authentication.tf", authentication / "main.tf")
            shutil.copyfile(HERE.parent / ".terraform.lock.hcl", authentication / ".terraform.lock.hcl")
            variables = authentication / "local.auto.tfvars.json"
            variables.write_text(json.dumps({"endpoint": endpoint}))
            variables.chmod(0o600)
            prefix = "-chdir=" + str(authentication)
            terraform(prefix, "init", "-input=false")
            terraform(prefix, "apply", "-input=false", "-auto-approve")
            auth = json.loads(terraform(prefix, "output", "-json", capture=True).stdout)["authorization"]["value"]
            require(auth["proxy_endpoint"] == endpoint, "Terraform registry credentials left the owned endpoint")
            require(base64.b64decode(auth["authorization_token"]).decode() == "AWS:" + auth["password"],
                    "Terraform registry credentials do not match their native token bytes")
            document = json.loads(output_path.read_text())
            document["authorization"] = auth
            output_path.write_text(json.dumps(document))
            output_path.chmod(0o600)
            subprocess.run(command, env=env, check=True)

        plan_failures = []

        def no_change(stage, refresh=False):
            command = ["plan", "-input=false", "-detailed-exitcode", "-out=" + stage + ".tfplan"]
            if refresh:
                command.append("-refresh-only")
            plan = terraform(*command, check=False)
            if plan.returncode != 0:
                failure = f"{stage} must be a no-change plan, got exit {plan.returncode}"
                plan_failures.append(failure)
                print("FAILED assertion: " + failure, flush=True)
            else:
                print("Completed no-change assertion: " + stage, flush=True)
            if refresh and plan.returncode == 0:
                terraform("apply", "-input=false", "-auto-approve", stage + ".tfplan")

        save_variables()
        package(root, "first")
        terraform("init", "-input=false")
        last = None
        try:
            print("STAGE create ZIP/layer/config/alias/URL and ECR owners", flush=True)
            terraform("apply", "-input=false", "-auto-approve")
            initial, _ = outputs()
            last = initial
            first_image = push_image(endpoint, initial["repository"], "first")
            first_image_path = root / "first-image.json"
            first_image_path.write_text(json.dumps(first_image, indent=2) + "\n")
            first_image_path.chmod(0o600)
            variables["include_image"] = True
            save_variables()
            terraform("apply", "-input=false", "-auto-approve")
            first, first_path = outputs()
            last = first
            print("STAGE independent Lambda and OCI byte consumers", flush=True)
            consumer(first_path, first_image_path)
            print("STAGE refresh and no-change plan", flush=True)
            no_change("first-refresh", refresh=True)
            no_change("first-noop")
            print("STAGE native import into existing HCL and reconciliation", flush=True)
            for address, identifier in (
                    ("aws_lambda_alias.live", first["function_name"] + "/" + first["alias"]),
                    ("aws_lambda_layer_version.library", first["layer_arn"]),
                    ("aws_lambda_function_event_invoke_config.application", first["function_name"] + ":" + first["alias"]),
                    ("aws_lambda_runtime_management_config.application", first["function_name"] + ",$LATEST"),
                    ("aws_ecr_repository.application", first["repository"]),
                    ("aws_ecr_repository_policy.application", first["repository"]),
                    ("aws_ecr_lifecycle_policy.application", first["repository"])):
                backup = terraform("state", "pull", capture=True).stdout
                backup_path = root / "before-import.tfstate"
                backup_path.write_text(backup)
                backup_path.chmod(0o600)
                terraform("state", "rm", address)
                try:
                    terraform("import", "-input=false", address, identifier)
                except BaseException:
                    terraform("state", "push", "-force", str(backup_path))
                    raise
            terraform("apply", "-input=false", "-auto-approve")
            no_change("import-noop")
            print("STAGE update ZIP bytes/config/alias and real OCI manifest", flush=True)
            variables["revision"] = "second"
            save_variables()
            package(root, "second")
            terraform("apply", "-input=false", "-auto-approve")
            second_image = push_image(endpoint, first["repository"], "second")
            second_image_path = root / "second-image.json"
            second_image_path.write_text(json.dumps(second_image, indent=2) + "\n")
            second_image_path.chmod(0o600)
            terraform("apply", "-input=false", "-auto-approve")
            second, second_path = outputs()
            last = second
            require(second["version"] != first["version"], "Code update did not publish a new immutable version")
            consumer(second_path, second_image_path, first_path)
            ecr = client("ecr", endpoint)
            old = ecr.batch_get_image(repositoryName=first["repository"], imageIds=[{"imageDigest": first_image["digest"]}])
            require(not old.get("failures") and old["images"][0]["imageManifest"] == first_image["manifest"],
                    "Replacing a mutable tag changed the prior digest's manifest")
            deleted = ecr.batch_delete_image(repositoryName=first["repository"], imageIds=[{"imageDigest": first_image["digest"]}])
            require(not deleted.get("failures"), f"Actual image deletion failed: {deleted}")
            no_change("second-refresh", refresh=True)
            no_change("second-noop")
            print("STAGE reopen owned controller and consume retained real bytes", flush=True)
            runtime.close()
            endpoint = runtime.enter_context(controller(args, root, extra=extra, containers=True))
            consumer(second_path, second_image_path, first_path)
            no_change("reopen-refresh", refresh=True)
            no_change("reopen-noop")
        finally:
            print("STAGE destroy all Terraform-owned resources, including IAM", flush=True)
            terraform("destroy", "-input=false", "-auto-approve")
            expect_missing(client("lambda", endpoint).get_function, {"ResourceNotFoundException"},
                           FunctionName=variables["name"])
            expect_missing(client("ecr", endpoint).describe_repositories, {"RepositoryNotFoundException"},
                           repositoryNames=[variables["name"] + "/application"])
            if last is not None:
                expect_missing(client("lambda", endpoint).get_layer_version, {"ResourceNotFoundException"},
                               LayerName=last["layer_name"], VersionNumber=last["layer_version"])
            state = json.loads(terraform("show", "-json", capture=True).stdout)
            resources = state.get("values", {}).get("root_module", {}).get("resources", [])
            require(not [resource for resource in resources if resource["mode"] == "managed"], "Managed resources remain after destroy")
            expect_missing(client("iam", endpoint).get_role, {"NoSuchEntity"},
                           RoleName=variables["name"] + "-execution")
            groups = client("logs", endpoint).describe_log_groups(logGroupNamePrefix="/aws/lambda/" + variables["name"])["logGroups"]
            require(not [group for group in groups if group["logGroupName"] == "/aws/lambda/" + variables["name"]],
                    "Owned runtime log group remains after destroy")
            print("Completed signed Lambda/layer/ECR/IAM/log-group absence and empty Terraform state checks", flush=True)
        require(not plan_failures, "; ".join(plan_failures))
    print(f"Lifecycle complete. Sensitive artifacts retained in private owned directory: {root}", flush=True)


if __name__ == "__main__":
    main()
