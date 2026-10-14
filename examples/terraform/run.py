"""Run init/apply, signed byte/message assertions, no-op apply and destroy."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local import (arguments, controller, environment, require, verify_application,
                   verify_deleted, workspace)


def main():
    parser = arguments(__doc__, 14661)
    parser.add_argument("--provider-mirror", type=Path, help="Prepared filesystem provider mirror; disables direct downloads")
    args = parser.parse_args()
    require(shutil.which("terraform"), "Install Terraform >= 1.5, < 2 first")
    root = workspace(args, "terraform")
    source = Path(__file__).resolve().parent
    for name in ("main.tf", ".terraform.lock.hcl"):
        shutil.copyfile(source / name, root / name)
    env = environment()
    # Do not inherit a CLI development-provider override or a remote backend.
    cli_config = root / "terraform.rc"
    configuration = "disable_checkpoint = true\n"
    if args.provider_mirror is not None:
        require(args.provider_mirror.is_dir(), "Provider mirror directory does not exist")
        configuration += ("provider_installation {\n  filesystem_mirror {\n    path = "
                          + json.dumps(str(args.provider_mirror.resolve()))
                          + '\n    include = ["registry.terraform.io/hashicorp/aws"]\n  }\n}\n')
    cli_config.write_text(configuration)
    env["TF_CLI_CONFIG_FILE"] = str(cli_config)

    def terraform(*command, capture=False, check=True):
        print("terraform", *command, flush=True)
        return subprocess.run(["terraform", *command], cwd=root, env=env,
                              check=check, text=True, capture_output=capture)

    with controller(args, root) as endpoint:
        (root / "local.auto.tfvars.json").write_text(json.dumps({
            "endpoint": endpoint, "name": "stackd-tf-" + uuid.uuid4().hex[:12]}))
        terraform("init", "-input=false", "-lockfile=readonly")
        outputs = None
        try:
            terraform("apply", "-input=false", "-auto-approve")
            outputs = json.loads(terraform("output", "-json", "application", capture=True).stdout)
            (root / "outputs.json").write_text(json.dumps(outputs, indent=2) + "\n")
            verify_application(endpoint, outputs, "v1")
            # detailed-exitcode: 0 = no drift, 1 = error, 2 = planned change.
            plan = terraform("plan", "-input=false", "-detailed-exitcode", "-out=noop.tfplan", check=False)
            require(plan.returncode == 0, f"Repeated plan was not a no-op: exit {plan.returncode}")
            terraform("apply", "-input=false", "-auto-approve", "noop.tfplan")
            verify_application(endpoint, outputs, "v1")
        finally:
            terraform("destroy", "-input=false", "-auto-approve")
        if outputs is not None:
            verify_deleted(endpoint, outputs)
        state = json.loads(terraform("show", "-json", capture=True).stdout)
        require(not state.get("values", {}).get("root_module", {}).get("resources"),
                "Terraform state still contains resources after destroy")
    print(f"Terraform lifecycle complete; controller stopped. Retained only owned artifacts: {root}")


if __name__ == "__main__":
    main()
