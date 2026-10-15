"""Run one pinned-provider native-engine lifecycle in an isolated owned namespace.

Prepare dependencies with requirements.txt and docs/runtime-containers.md first.
Example: python examples/terraform-engines/run.py cache --provider-mirror /prepared/mirror
The runner never downloads engine images, changes daemon settings, or adopts an existing server.
Kafka creates and removes only its owned EC2 bridges and packet policy on a prepared Linux Docker host.
Terraform state, local credentials, TLS keys, logs and the owned database remain in a private run directory.
"""

import importlib.util
import fcntl
import ipaddress
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import uuid
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local import arguments, controller, environment, require, workspace

SOURCE = Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE))


def network_reservation(args, root, release=False):
    """Persist one unused CIDR per owned workspace, fencing parallel runners."""
    registry = SOURCE.parents[1] / ".stackd" / "native-engine-cidr-reservations.json"
    lock = registry.with_suffix(".lock")
    with lock.open("a") as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        leases = json.loads(registry.read_text()) if registry.exists() else {}
        identifiers = subprocess.check_output(
            ["docker", "--host", args.docker_host, "network", "ls", "--format", "{{.ID}}"],
            text=True, env=environment()).split()
        native = json.loads(subprocess.check_output(
            ["docker", "--host", args.docker_host, "network", "inspect", *identifiers],
            text=True, env=environment())) if identifiers else []
        pools = [ipaddress.ip_network(configuration["Subnet"]) for network in native
                 for configuration in (network.get("IPAM", {}).get("Config") or [])
                 if configuration.get("Subnet")]
        key = str(root.resolve())
        if release:
            if key in leases:
                cidr = ipaddress.ip_network(leases[key])
                require(not any(cidr.overlaps(pool) for pool in pools if pool.version == 4),
                        "Owned network CIDR remains attached; retain its allocation fence")
                del leases[key]
        else:
            require(key not in leases, "Workspace already has a retained network allocation")
            retained = [ipaddress.ip_network(value) for value in leases.values()]
            candidates = list(range(30, 210))
            secrets.SystemRandom().shuffle(candidates)
            for octet in candidates:
                cidr = ipaddress.ip_network(f"10.{octet}.0.0/16")
                if not any(cidr.overlaps(pool) for pool in [*pools, *retained] if pool.version == 4):
                    leases[key] = str(cidr)
                    (root / "network-cidr").write_text(str(cidr) + "\n")
                    break
            else:
                raise RuntimeError("No unused native-engine CIDR remains; preserve existing networks")
        registry.write_text(json.dumps(leases, indent=2) + "\n")
        registry.chmod(0o600)
        return int(leases[key].split(".")[1]) if not release else None


def main():
    parser = arguments(__doc__, 14706)
    parser.add_argument("engine", choices=("cache", "memorydb", "mq", "search", "kafka"))
    parser.add_argument("--provider-mirror", type=Path, help="Prepared signed hashicorp/aws6.68.0 filesystem mirror")
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    parser.add_argument("--java", type=Path, help="Installed matching JDK java executable for MQ")
    args = parser.parse_args()
    require(shutil.which("terraform"), "Install Terraform1.15.9 first")
    require(json.loads(subprocess.check_output(["terraform", "version", "-json"], text=True))["terraform_version"] == "1.15.9",
            "This retained fixture requires Terraform1.15.9 and AWS provider6.68.0")
    root = workspace(args, "terraform-engines-" + args.engine)
    root.chmod(0o700)
    account = str(secrets.randbelow(900_000_000_000) + 100_000_000_000)
    (root / "account-id").write_text(account + "\n")
    source = SOURCE / args.engine
    shutil.copyfile(source / "main.tf", root / "main.tf")
    env = environment()
    configuration = "disable_checkpoint = true\n"
    if args.provider_mirror is not None:
        require(args.provider_mirror.is_dir(), "Provider mirror directory does not exist")
        configuration += ("provider_installation {\n filesystem_mirror {\n path = "
                          + json.dumps(str(args.provider_mirror.resolve()))
                          + '\n include = ["registry.terraform.io/hashicorp/aws"]\n }\n}\n')
    config = root / "terraform.rc"
    config.write_text(configuration)
    env["TF_CLI_CONFIG_FILE"] = str(config)
    native_password = secrets.token_urlsafe(32)
    (root / "native-password").write_text(native_password + "\n")
    (root / "native-password").chmod(0o600)
    spec = importlib.util.spec_from_file_location("engine_fixture", source / "fixture.py")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    flags = fixture.prepare(args, root)
    name = "tfeng-" + uuid.uuid4().hex[:12]
    variables = {"endpoint": f"http://127.0.0.1:{args.port}", "name": name, "revision": "v1"}
    if args.engine == "search":
        variables["account_id"] = account
    if args.engine in {"cache", "memorydb", "mq", "kafka"}:
        variables["password"] = native_password
    if args.engine in {"cache", "kafka"}:
        variables["network_octet"] = network_reservation(args, root)
    variable_file = root / "local.auto.tfvars.json"
    variable_file.write_text(json.dumps(variables))
    variable_file.chmod(0o600)

    def terraform(*command, capture=False, check=True):
        print("terraform", *command, flush=True)
        return subprocess.run(["terraform", *command], cwd=root, env=env,
                              check=check, text=True, capture_output=capture)

    def outputs():
        return json.loads(terraform("output", "-json", "application", capture=True).stdout)

    def no_drift():
        result = terraform("plan", "-input=false", "-detailed-exitcode", "-out=noop.tfplan", check=False)
        require(result.returncode == 0, f"Terraform plan is not a no-op: exit {result.returncode}")

    imported_addresses = set()

    def import_resources():
        imports = json.loads(terraform("output", "-json", "imports", capture=True).stdout)
        for address, identifier in imports.items():
            if address not in imported_addresses:
                terraform("import", "-input=false", "-state=import.tfstate", address, str(identifier))
                imported_addresses.add(address)
        def state_ids(*state):
            document = json.loads(terraform("show", "-json", *state, capture=True).stdout)
            resources = document.get("values", {}).get("root_module", {}).get("resources", [])
            return {resource["address"]: resource["values"]["id"] for resource in resources
                    if resource.get("mode") == "managed"}
        imported, current = state_ids("import.tfstate"), state_ids()
        for address in imports:
            require(imported.get(address) == current.get(address), f"Imported resource identity changed: {address}")
        print("Completed: independent-state resource import", flush=True)

    initialized = False
    created = False
    application = None
    try:
        with controller(args, root, extra=flags, account=account) as endpoint:
            terraform("init", "-input=false")
            initialized = True
            if hasattr(fixture, "before_apply"):
                fixture.before_apply(endpoint, root, terraform, variables)
            terraform("apply", "-input=false", "-auto-approve")
            created = True
            application = outputs()
            fixture.consume(endpoint, application, root, "v1", False)
            print("Completed: apply and independent native consumer", flush=True)
            import_resources()
            terraform("apply", "-refresh-only", "-input=false", "-auto-approve")
            no_drift()
            variables["revision"] = "v2"
            variable_file.write_text(json.dumps(variables))
            terraform("apply", "-input=false", "-auto-approve")
            application = outputs()
            fixture.consume(endpoint, application, root, "v2", True)
            no_drift()
            import_resources()
            print("Completed: refresh, real update and no-op plan", flush=True)
        with controller(args, root, extra=flags, account=account) as endpoint:
            if hasattr(fixture, "ready"):
                fixture.ready(endpoint, application, root)
            terraform("apply", "-refresh-only", "-input=false", "-auto-approve")
            reopened = outputs()
            require(reopened == application, "Controller reopen changed Terraform output identity")
            fixture.consume(endpoint, reopened, root, "v2", True)
            no_drift()
            print("Completed: SQLite/controller reopen and retained native bytes", flush=True)
    finally:
        if initialized:
            # Reopen this exact database to destroy even after partial apply failure.
            # Never delete Docker objects by name prefix or touch another controller.
            with controller(args, root, extra=flags, account=account) as endpoint:
                try:
                    if application is not None and hasattr(fixture, "ready"):
                        fixture.ready(endpoint, application, root)
                    if application is not None and hasattr(fixture, "cleanup"):
                        fixture.cleanup(endpoint, application, root)
                finally:
                    terraform("destroy", "-input=false", "-auto-approve")
                if application is not None and hasattr(fixture, "deleted"):
                    fixture.deleted(endpoint, application, root)
                state = json.loads(terraform("show", "-json", capture=True).stdout)
                resources = state.get("values", {}).get("root_module", {}).get("resources", [])
                require(not any(resource.get("mode") == "managed" for resource in resources),
                        "Managed Terraform resources remain after destroy")
                print("Completed: exact-owned destroy and empty managed Terraform state", flush=True)
                if args.engine in {"cache", "kafka"}:
                    network_reservation(args, root, release=True)
                if application is not None and hasattr(fixture, "retire_roles"):
                    with urlopen(endpoint + "/_stackd/clock", timeout=30) as response:
                        retained_time = json.load(response)
                    (root / "cleanup-service-time.json").write_text(json.dumps(retained_time))
            if application is not None and hasattr(fixture, "retire_roles"):
                # Only accelerate role-session expiration after all exact consumers
                # and Terraform-managed resources have demonstrably gone.
                start = max(datetime.now(timezone.utc),
                            datetime.fromisoformat(retained_time["time"].replace("Z", "+00:00")))
                cleanup_flags = [*flags, "-clock-start", start.isoformat()]
                with controller(args, root, extra=cleanup_flags, account=account) as endpoint:
                    fixture.retire_roles(endpoint, application, root)
    require(created, "Terraform resources were not created")
    print(f"Native {args.engine} lifecycle complete; private owned artifacts: {root}")


if __name__ == "__main__":
    main()
