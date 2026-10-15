"""Run pinned Terraform storage controls with real independent consumers.

Build bin/stackd separately. Prepare Terraform1.15.9, AWS6.68.0 filesystem mirror,
boto3 and the exact native prerequisites in each module's limits JSON. This
runner uses examples/local.py for the environment, credentials, owned workspace
and controller. It never contacts native AWS or reuses a controller/database.

S3 and DynamoDB are the default modules. Optional EBS requires a prepared raw
Linux HVM guest and actual QEMU/KVM host; use --services ebs and the explicit
image/firmware options. No images or packages are downloaded. Reports contain
only completed checks and credential-free command metadata. All source inventory
claims remain unverified until the corresponding actual run completes. State,
variables and captured output stay in the private run root; do not publish them.
"""
import importlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local import ACCOUNT, REGION, arguments, controller, environment, require, workspace


def main():
    parser = arguments(__doc__, 14714)
    parser.add_argument("--services", default="s3,dynamodb", help="Unique comma-separated s3,dynamodb,ebs modules")
    parser.add_argument("--account-id", default=ACCOUNT, help="Twelve-digit local owner for this isolated run")
    parser.add_argument("--provider-mirror", type=Path, required=True, help="Prepared AWS6.68.0 mirror; no direct installation")
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock", help="Owned host's local rootful Linux Docker Engine")
    parser.add_argument("--guest-image", type=Path, help="Prepared raw Linux x86_64 HVM disk with cloud-init/Python3/NVMe; EBS only")
    parser.add_argument("--guest-boot-mode", choices=("legacy-bios", "uefi"), default="legacy-bios")
    parser.add_argument("--guest-instance-type", default="t3.small")
    parser.add_argument("--ec2-bios", type=Path, help="Installed legacy BIOS firmware for the EBS guest")
    parser.add_argument("--ec2-uefi-code", type=Path, help="Installed UEFI code matching the supplied guest")
    parser.add_argument("--ec2-uefi-vars", type=Path, help="Installed UEFI variable template, copied by the native owner")
    parser.add_argument("--ebs-vpc-cidr", help="Optional unoccupied native guest /24 network")
    args = parser.parse_args()
    selected = args.services.split(",")
    require(selected and len(selected) == len(set(selected)) and set(selected) <= {"s3", "dynamodb", "ebs"}, "Select unique supported modules")
    require(len(args.account_id) == 12 and args.account_id.isascii() and args.account_id.isdigit(), "Select a twelve-digit local account ID")
    require(shutil.which("terraform"), "Install Terraform1.15.9 first")
    require(args.provider_mirror.is_dir(), "Prepared provider mirror does not exist")
    native = bool(set(selected) & {"dynamodb", "ebs"})
    if native:
        require(shutil.which("docker"), "Install Docker and the pinned native prerequisites before running")
    if "ebs" in selected:
        require(args.guest_image is not None and args.guest_image.is_file(), "EBS needs an existing prepared raw Linux HVM guest image")
        firmware = (args.ec2_bios,) if args.guest_boot_mode == "legacy-bios" else (args.ec2_uefi_code, args.ec2_uefi_vars)
        require(all(path is not None and path.is_file() for path in firmware), "Select existing firmware matching the guest boot mode")

    # QEMU's owned QMP socket must fit Linux's short Unix-domain path limit.
    root = workspace(args, "ebs-controls" if "ebs" in selected else "terraform-storage-controls")
    root.chmod(0o700)
    config = root / "terraform.rc"
    config.write_text("disable_checkpoint = true\nprovider_installation {\n filesystem_mirror {\n path = " + json.dumps(str(args.provider_mirror.resolve())) + "\n include = [\"registry.terraform.io/hashicorp/aws\"]\n }\n}\n")
    config.chmod(0o600)
    env = environment()
    env["TF_CLI_CONFIG_FILE"] = str(config)
    report = {"terraform": "1.15.9", "provider": "6.68.0", "provider_source_revision": "c9b83d813022cdd05fc955480b07e269c6e18023", "services": selected, "status": "running", "stages": [], "commands": [], "inventory_defaults": "unverified"}
    stages = report["stages"]
    callbacks = []
    owned_ddb = set()
    owned_kinesis = set()

    def terraform(command, cwd, check=True):
        result = subprocess.run(["terraform", *command], cwd=cwd, env=env, text=True, capture_output=True)
        prefix = Path(cwd) / f"terraform-{len(report['commands']):03d}-{command[0]}"
        for suffix, text in ((".stdout", result.stdout), (".stderr", result.stderr)):
            path = Path(str(prefix) + suffix)
            path.write_text(text)
            path.chmod(0o600)
        report["commands"].append({"command": ["terraform", *command], "workspace": Path(cwd).name, "returncode": result.returncode})
        # Preserve identities even if an initial apply fails and its module
        # destroys the stream before returning a cleanup callback.
        capture_databases()
        if check:
            require(result.returncode == 0, f"Terraform {command[0]} failed (exit {result.returncode}); private workspace: {cwd}")
        return result

    def capture_databases():
        if "dynamodb" not in selected or not (root / "stackd.sqlite").is_file():
            return
        # These identities come from this owned SQLite installation, not a
        # global Docker before/after difference that can include other runs.
        with sqlite3.connect((root / "stackd.sqlite").as_uri() + "?mode=ro", uri=True) as database:
            owned_ddb.update(row[0] for row in database.execute("SELECT id FROM dynamodb_databases"))
            owned_kinesis.update(row[0] for row in database.execute("SELECT engine_id FROM kinesis_streams"))
        report["owned_native_identifiers"] = {
            "dynamodb": sorted(owned_ddb), "kinesis": sorted(owned_kinesis)}

    def docker(command):
        result = subprocess.run(["docker", "--host", args.docker_host, *command], env=env, text=True, capture_output=True, check=True)
        report["commands"].append({"command": ["docker", "--host", args.docker_host, *command], "returncode": result.returncode})
        return result.stdout

    def cleanup(endpoint):
        errors = []
        capture_databases()
        for _, _, destroy in reversed(callbacks):
            try:
                destroy(endpoint)
            except BaseException as error:
                errors.append(error)
        callbacks.clear()
        if errors:
            raise errors[0]
        # Keep the controller alive for retirement on failure paths as well.
        if "dynamodb" in selected:
            deadline = time.monotonic() + 90
            while True:
                leftovers = []
                labels = ["label=stackd.dynamodb.id=" + identifier for identifier in owned_ddb]
                labels.extend("label=stackd.kinesis.id=" + identifier for identifier in owned_kinesis)
                for label in labels:
                    leftovers.extend(docker(["ps", "-aq", "--filter", label]).split())
                    leftovers.extend(docker(["volume", "ls", "-q", "--filter", label]).split())
                if not leftovers:
                    break
                require(time.monotonic() < deadline, "Exact-owned DynamoDB/Kinesis containers/volumes remain: " + ",".join(leftovers))
                time.sleep(0.5)
            stages.append({"stage": "exact-owned-native-dynamodb-kinesis-cleanup", "status": "passed"})

    extra = ["-clock-start", "2031-01-01T00:00:00Z"]
    if native:
        extra.extend(["-docker-host", args.docker_host])
    if "dynamodb" in selected:
        extra.extend(["-dynamodb-runtime", "-kinesis-runtime"])
    if "ebs" in selected:
        extra.extend(["-ec2-state-directory", str(root / "ec2")])
        if args.guest_boot_mode == "legacy-bios":
            extra.extend(["-ec2-bios", str(args.ec2_bios.resolve())])
        else:
            extra.extend(["-ec2-uefi-code", str(args.ec2_uefi_code.resolve()), "-ec2-uefi-vars", str(args.ec2_uefi_vars.resolve())])
    name = "stackd-controls-" + uuid.uuid4().hex[:12]

    try:
        require(json.loads(terraform(["version", "-json"], root).stdout)["terraform_version"] == "1.15.9", "Exact Terraform1.15.9 is required")
        with controller(args, root, extra=extra, containers="ebs" in selected, account=args.account_id) as endpoint:
            variables = {"name": name, "endpoint": endpoint, "region": REGION, "account_id": args.account_id}
            try:
                for module_name in selected:
                    directory = root / module_name
                    directory.mkdir(mode=0o700)
                    module = importlib.import_module(module_name)
                    callbacks.append((module_name, *module.run(args, directory, endpoint, terraform, variables, stages)))
                    capture_databases()
                if "dynamodb" in selected:
                    require(owned_ddb, "No exact-owned real DynamoDB database identity exists")
            except BaseException:
                cleanup(endpoint)
                raise
        # Saved SQLite service time takes precedence over clock-start, so the
        # same controller resumes the deterministic timeline, not time zero.
        with controller(args, root, extra=extra, containers="ebs" in selected, account=args.account_id) as endpoint:
            try:
                # S3's real tiering consumer advances service time by 92days.
                # Check restored/replicated DDB data before that long interval.
                order = {"dynamodb": 0, "ebs": 1, "s3": 2}
                for _, verify, _ in sorted(callbacks, key=lambda callback: order[callback[0]]):
                    verify(endpoint)
                stages.append({"stage": "sqlite-controller-reopen-real-control-consumers", "status": "passed"})
            finally:
                cleanup(endpoint)
        report["status"] = "passed"
    except BaseException as error:
        report["status"] = "failed"
        report["error_type"] = type(error).__name__
        raise
    finally:
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Completed actual storage control stages; controller stopped. Private artifacts:", root)


if __name__ == "__main__":
    main()
