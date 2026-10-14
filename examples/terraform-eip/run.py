"""Exercise Terraform AWS v6.68.0 EIP allocate/read/refresh/destroy locally."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local import (arguments, client, controller, environment, expect_missing,
                   require, workspace)


def main():
    parser = arguments(__doc__, 14664)
    parser.add_argument("--provider-mirror", type=Path, help="Prepared filesystem provider mirror; disables direct downloads")
    args = parser.parse_args()
    require(shutil.which("terraform"), "Install Terraform >= 1.5, < 2 first")
    root = workspace(args, "terraform-eip")
    shutil.copyfile(Path(__file__).resolve().parent / "main.tf", root / "main.tf")
    env = environment()
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
            "endpoint": endpoint, "name": "stackd-eip-" + uuid.uuid4().hex[:12]}))
        # Exact source pin; native init checks publisher checksums and retains
        # the generated lock in this owned workspace, never in the checkout.
        terraform("init", "-input=false")
        ec2 = client("ec2", endpoint)
        outputs = None

        def verify_addresses():
            allocation_ids = [address["allocation_id"] for address in outputs]
            require(len(set(allocation_ids)) == 2, "Terraform did not allocate two independent EIPs")
            addresses = ec2.describe_addresses(AllocationIds=allocation_ids)["Addresses"]
            require(len(addresses) == 2, "Allocated EIPs missing from DescribeAddresses")
            by_id = {address["AllocationId"]: address for address in addresses}
            attributes = []
            for page in ec2.get_paginator("describe_addresses_attribute").paginate(
                    AllocationIds=allocation_ids, Attribute="domain-name", PaginationConfig={"PageSize": 1}):
                attributes.extend(page["Addresses"])
            require(len(attributes) == 2, "Attribute paginator did not return both EIPs")
            attributes_by_id = {address["AllocationId"]: address for address in attributes}
            for output in outputs:
                allocation_id = output["allocation_id"]
                require(output["public_ip"] == by_id[allocation_id]["PublicIp"], "Terraform public IP differs from native state")
                attribute = attributes_by_id[allocation_id]
                require(attribute["PublicIp"] == output["public_ip"], "Attribute public IP differs from allocation")
                require(not attribute.get("PtrRecord") and not attribute.get("PtrRecordUpdate"), "Unexpected fabricated reverse DNS state")
                require(not output["ptr_record"], "Provider reported a custom PTR record for an unset EIP")
            print("Verified Terraform EIP outputs and signed SDK attribute pagination", flush=True)

        try:
            terraform("apply", "-input=false", "-auto-approve")
            outputs = json.loads(terraform("output", "-json", "addresses", capture=True).stdout)
            (root / "outputs.json").write_text(json.dumps(outputs, indent=2) + "\n")
            verify_addresses()
            refresh = terraform("plan", "-refresh-only", "-input=false", "-detailed-exitcode", "-out=refresh.tfplan", check=False)
            require(refresh.returncode == 0, f"EIP refresh was not a no-op: exit {refresh.returncode}")
            terraform("apply", "-input=false", "-auto-approve", "refresh.tfplan")
            refreshed = json.loads(terraform("output", "-json", "addresses", capture=True).stdout)
            require(refreshed == outputs, "Refresh changed EIP identity or default domain state")
            plan = terraform("plan", "-input=false", "-detailed-exitcode", "-out=noop.tfplan", check=False)
            require(plan.returncode == 0, f"Repeated plan was not a no-op: exit {plan.returncode}")
            verify_addresses()
        finally:
            terraform("destroy", "-input=false", "-auto-approve")
        if outputs is not None:
            for output in outputs:
                expect_missing(ec2.describe_addresses, {"InvalidAllocationID.NotFound"},
                               AllocationIds=[output["allocation_id"]])
                expect_missing(ec2.describe_addresses_attribute, {"InvalidAllocationID.NotFound"},
                               AllocationIds=[output["allocation_id"]], Attribute="domain-name")
        require(not ec2.describe_addresses_attribute()["Addresses"], "Fresh owned EIP scope still contains allocations")
        state = json.loads(terraform("show", "-json", capture=True).stdout)
        require(not state.get("values", {}).get("root_module", {}).get("resources"),
                "Terraform state still contains resources after destroy")
    print(f"Terraform v6.68.0 EIP lifecycle complete; controller stopped. Retained owned artifacts: {root}")


if __name__ == "__main__":
    main()
