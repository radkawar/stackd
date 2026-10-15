"""Terraform commands only. Controller and credential safety live in examples/local.py."""

import contextlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local import (ACCOUNT, arguments, client, controller, environment,
                   local_endpoint, require, workspace)


def parser(description):
    result = arguments(description, 14707)
    result.add_argument("--endpoint", help="Use a caller-owned loopback controller; do not stop it")
    result.add_argument("--provider-mirror", type=Path)
    result.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    return result


class Terraform:
    def __init__(self, args, source):
        self.args = args
        self.account = getattr(args, "account_id", ACCOUNT)
        self.root = workspace(args, "terraform-compute-" + source.name)
        self.directory = self.root / "terraform"
        self.directory.mkdir(mode=0o700)
        shutil.copyfile(source / "main.tf", self.directory / "main.tf")
        shutil.copyfile(Path(__file__).with_name(".terraform.lock.hcl"),
                        self.directory / ".terraform.lock.hcl")
        self.env = environment()
        configuration = "disable_checkpoint = true\n"
        if args.provider_mirror:
            require(args.provider_mirror.is_dir(), "Provider mirror directory does not exist")
            configuration += ('provider_installation {\n  filesystem_mirror {\n    path = '
                              + json.dumps(str(args.provider_mirror.resolve()))
                              + '\n    include = ["registry.terraform.io/hashicorp/aws"]\n  }\n}\n')
        config = self.directory / "terraform.rc"
        config.write_text(configuration)
        self.env["TF_CLI_CONFIG_FILE"] = str(config)
        require(shutil.which("terraform"), "Install official Terraform 1.15.9 or later first")
        version = json.loads(self.command("version", "-json", capture=True).stdout)
        require(tuple(map(int, version["terraform_version"].split("."))) >= (1, 15, 9),
                "This fixture requires official Terraform 1.15.9 or later")
        self.values = {}
        self.plan_failures = []

    def authenticate(self, filename, **values):
        directory = self.root / "authentication"
        directory.mkdir(mode=0o700, exist_ok=True)
        source = Path(__file__).resolve().parent / filename
        shutil.copyfile(Path(__file__).with_name(".terraform.lock.hcl"),
                        directory / ".terraform.lock.hcl")
        shutil.copyfile(source, directory / "main.tf")
        variables = directory / "local.auto.tfvars.json"
        variables.write_text(json.dumps(values))
        variables.chmod(0o600)
        prefix = "-chdir=" + str(directory)
        self.command(prefix, "init", "-input=false")
        self.command(prefix, "apply", "-input=false", "-auto-approve")
        return json.loads(self.command(prefix, "output", "-json", capture=True).stdout)

    def command(self, *args, capture=False, check=True):
        print("terraform", *args, flush=True)
        return subprocess.run(["terraform", *args], cwd=self.directory, env=self.env,
                              text=True, capture_output=capture, check=check)

    def configure(self, **values):
        self.values.update(values)
        path = self.directory / "local.auto.tfvars.json"
        path.write_text(json.dumps(self.values))
        path.chmod(0o600)

    def output(self):
        return json.loads(self.command("output", "-json", "compute", capture=True).stdout)

    def no_change(self, stage):
        for mode in ("-refresh-only", None):
            args = ["plan", "-input=false", "-detailed-exitcode",
                    "-out=" + stage + ("-refresh" if mode else "-ordinary") + ".tfplan"]
            if mode:
                args.append(mode)
            result = self.command(*args, check=False)
            if result.returncode != 0:
                failure = f"{stage} {mode or 'plan'} was not a no-change plan: {result.returncode}"
                self.plan_failures.append(failure)
                print("FAILED assertion: " + failure, flush=True)
            else:
                print(f"Completed {stage}: {mode or 'ordinary'} no-change plan", flush=True)

    def assert_plans(self):
        require(not self.plan_failures, "; ".join(self.plan_failures))

    def reimport(self, resource, identity):
        # Keep the prior state before removing its binding. The live resource is
        # never deleted by state rm. Finally cleanup uses the restored binding.
        backup = self.command("state", "pull", capture=True).stdout
        path = self.directory / "before-import.tfstate"
        path.write_text(backup)
        path.chmod(0o600)
        self.command("state", "rm", resource)
        try:
            self.command("import", "-input=false", resource, identity)
        except BaseException:
            self.command("state", "push", "-force", str(path))
            raise
        print(f"Completed import: {resource}", flush=True)

    def destroy(self):
        self.command("destroy", "-input=false", "-auto-approve")
        state = json.loads(self.command("show", "-json", capture=True).stdout)
        resources = state.get("values", {}).get("root_module", {}).get("resources", [])
        require(not any(row.get("mode") == "managed" for row in resources),
                "Managed Terraform resources remain after destroy")
        print("Completed destroy: no managed Terraform resources remain", flush=True)

    def reopen(self):
        require(not self.args.endpoint, "Reopen requires a fixture-owned controller")
        self._runtime.close()
        endpoint = self._runtime.enter_context(
            controller(self.args, self.root, extra=self._extra,
                       containers=self._containers, account=self.account))
        print("Completed reopen: same owned database and endpoint", flush=True)
        return endpoint

    @contextlib.contextmanager
    def endpoint(self, extra=(), containers=False):
        if self.args.endpoint:
            endpoint = local_endpoint(self.args.endpoint)
            identity = client("sts", endpoint).get_caller_identity()
            require(identity["Account"] == self.account, "Caller-owned controller must use the explicit fixture account")
            yield endpoint
            self.assert_plans()
            return
        self._extra, self._containers = extra, containers
        with contextlib.ExitStack() as self._runtime:
            endpoint = self._runtime.enter_context(
                controller(self.args, self.root, extra=extra,
                           containers=containers, account=self.account))
            yield endpoint
            self.assert_plans()
